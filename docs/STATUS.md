# Implementation status

Snapshot of what is built, measured, and pending in the `vulnpipe`
reproducibility package. Companion to [`IMPLEMENTATION.md`](IMPLEMENTATION.md)
(which explains *how* each piece works); this file is the *where we are*.

_Last updated: 2026-06-15._

## TL;DR

The contract, corpus, metrics, two SAST tools, and the local-LLM detection
runner are implemented and have produced real numbers on a 500-snippet Juliet
corpus. On that corpus a single local LLM (DeepSeek-Coder 6.7B, zero-shot)
already beats both SAST tools on F1 by a wide margin. The hybrid SAST→LLM
stage — the thesis centerpiece — is the next build.

## What works end-to-end

| Component | State | Notes |
|---|---|---|
| Contract (`schemas`, `io`, `config`) | ✅ | binary-`verdict` `Finding` + ground-truth `Snippet`, JSONL round-trip |
| Corpus — Juliet | ✅ | download → CWE-map → method extract → balance → label; **500 snippets** committed |
| Corpus — Defects4J | ⬜ | stub; needs Defects4J framework + JDK 11 |
| Metrics + stats | ✅ | P/R/FPR/F1, HIS, McNemar, bootstrap F1 CI (stats not yet *applied* to results) |
| SAST — PMD (vanilla + custom) | ✅ | containerized, `pmdcode/pmd:7.25.0` |
| SAST — Semgrep (taint) | ✅ | containerized, `semgrep/semgrep:1.103.0` |
| SAST — SonarQube / CodeQL / SpotBugs | ⬜ | SonarQube fits plumbing; CodeQL/SpotBugs need a compilable corpus |
| LLM runner (Ollama) | ✅ | zero-shot / cot / few-shot; majority vote; tokens + timing captured |
| LLM — CodeLlama run | 🚧 | model pulled, full run not yet executed |
| LLM — CoT / few-shot runs | 🚧 | code ready, runs not yet executed |
| Hybrid pipeline (static-augmented) | ⬜ | **next** — LLM confirms/rejects SAST alerts |
| Figures (Venn, PR, cost-vs-F1) | ⬜ | not started |

## Results to date (500-snippet Juliet, committed under `findings/` + `metrics/`)

| tool | P | R | FPR | F1 | TP | FP | TN | FN |
|---|---|---|---|---|---|---|---|---|
| pmd-vanilla | 0.00 | 0.00 | 0.00 | 0.00 | 0 | 0 | 250 | 250 |
| pmd-custom | 0.56 | 0.64 | 0.50 | 0.59 | 159 | 126 | 124 | 91 |
| semgrep | 0.92 | 0.39 | 0.04 | 0.54 | 97 | 9 | 241 | 153 |
| deepseek-coder 6.7b (zero-shot) | 0.85 | 0.88 | 0.16 | **0.87** | 221 | 40 | 210 | 29 |

**Reading of the table (the narrative the thesis is assembling):**

- `pmd-vanilla` — built-in rules detect **none** of these CWEs (coverage gap,
  architectural: PMD has no taint engine in any version).
- `pmd-custom` vs `semgrep` run the **same sink set**, isolating taint
  analysis: PMD's syntactic rules maximize recall (0.64) at FPR 0.50; Semgrep's
  taint engine collapses FP 126→9 (FPR 0.04) but loses recall (cross-method
  flows missed by intra-procedural taint over one-method snippets). The classic
  SAST precision/recall dichotomy — neither wins on F1.
- `deepseek zero-shot` — a single local LLM balances both (R 0.88 **and**
  FPR 0.16) for F1 0.87, beating both SAST tools. Cost: ~2.7 s/snippet vs a
  one-shot SAST batch, and 40 false positives remain.

These are point estimates. Significance (McNemar) and F1 confidence intervals
(bootstrap) are implemented but **not yet run** on these tools — a quick
follow-up.

## Where the artifacts live

```
corpus/juliet.jsonl                                  ground truth (500 snippets)
findings/pmd-vanilla_perSnippet.jsonl                SAST verdicts
findings/pmd-custom_perSnippet.jsonl
findings/semgrep_perSnippet.jsonl
findings/deepseek-coder_6.7b-instruct__zero-shot_perSnippet.jsonl   voted LLM verdicts
findings/llm_runs/<tool>_runs.jsonl                  raw per-run LLM outputs
metrics/per_tool.csv                                 latest scored table
```

`findings/scan/` (materialized `.java`), `*.sarif`, and `data/` (raw Juliet
download) are git-ignored — regenerable and large.

## Reproduce

```bash
cd implementation
python -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
pytest                                               # 30 tests, all offline

vulnpipe corpus build --only juliet                  # needs network (first run)
vulnpipe sast run --tool pmd --variant both          # needs Docker
vulnpipe sast run --tool semgrep                      # needs Docker

ollama serve &                                        # needs Ollama + pulled model
ollama pull deepseek-coder:6.7b-instruct
vulnpipe llm run --model deepseek-coder:6.7b-instruct --strategy zero-shot

vulnpipe metrics --findings findings/*_perSnippet.jsonl
```

A full LLM pass over 500 snippets is ~20 min on this machine, one model at a
time (shared Ollama server). That runtime is exactly why the `findings/` jsonl
are committed rather than regenerated.

## Decisions locked

- **One binary-`verdict` contract** for every detector → apples-to-apples.
- **Containerized, pinned SAST** (no local toolchain drift).
- **Materialize one method per snippet** as `final class S { … }` — parses
  without compiling; fine for source-AST tools (PMD, Semgrep), but is the
  reason SpotBugs/CodeQL (bytecode/build-graph) need a separate compilable
  corpus.
- **PMD dual-variant** (vanilla = coverage gap, custom = high-FP failure mode)
  and **PMD-custom ⇄ Semgrep same-sinks** comparison are deliberate, to make
  the SAST trade-off legible.
- **LLM economics tracked** (tokens, wall-clock) for the cost-vs-F1 analysis;
  cost in USD is None (local models).

## Open questions for the hybrid stage (next build)

- Which SAST feeds the confirmer: `pmd-custom` alone (recall 0.64, 126 FP to
  prune) or the **union** of pmd-custom ∪ semgrep (higher recall, more to
  prune)?
- Confirmer scope: LLM may only **reject** SAST alerts, or also **add** its own
  detections (changes whether recall can exceed the SAST input's).
- Which model + strategy as the confirmer (deepseek zero-shot is the current
  best baseline).

The **HIS** metric (`(F1_hybrid − max(F1_sast, F1_llm)) / max(...)`) will
quantify whether the hybrid beats its best component. Note the bar is high:
the standalone LLM already sits at F1 0.87.
