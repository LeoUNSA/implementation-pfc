# vulnpipe

Reproducibility package for the PFC thesis *"Static Analysis vs. LLMs for
Automated Detection of SQL Injection (CWE-89) and Path Traversal (CWE-22)
Vulnerabilities in Java: A Hybrid Pipeline."*

Implements the empirical pipeline described in `../propuesta.md` §6 and
`../pipeline_outputs.md`: corpus construction → SAST → LLM → CodeBERT →
hybrid SAST→LLM filter → metrics.

**Deep dive:** see [`docs/IMPLEMENTATION.md`](docs/IMPLEMENTATION.md) for how
the contract, corpus/dataset handling, containerised SAST, and metrics work.

## The unifying contract

Every detector — rule-based SAST, fine-tuned classifier, generative LLM —
is coerced into emitting the **same atomic record**, a `Finding`, with a
binary `verdict`. The corpus emits `Snippet` records carrying the ground
truth. Metrics join detector `Finding`s to corpus `Snippet`s on
`snippet_id`. This single contract (`src/vulnpipe/schemas.py`) is what makes
the three detector families comparable apples-to-apples.

## Install

```bash
cd implementation
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
# Build the Juliet corpus (downloads the NIST archive on first run).
vulnpipe corpus build --only juliet

# Run PMD (vanilla built-in rules + custom CWE-89/22 ruleset) over the corpus.
# Needs Docker; pulls the pinned pmdcode/pmd image on first run.
vulnpipe sast run --tool pmd --variant both

# Run Semgrep (taint-mode ruleset) over the corpus. Pulls semgrep/semgrep.
vulnpipe sast run --tool semgrep

# Run a local LLM over the corpus (needs `ollama serve` + the model pulled).
vulnpipe llm run --model deepseek-coder:6.7b-instruct --strategy zero-shot
vulnpipe llm run --model codellama:7b-instruct --strategy cot --limit 50

# Compute metrics for one or more findings files against the ground truth.
vulnpipe metrics --findings findings/pmd-vanilla_perSnippet.jsonl \
                            findings/pmd-custom_perSnippet.jsonl \
                            findings/semgrep_perSnippet.jsonl
```

## Phase status

| Phase | Status |
|---|---|
| Core contract (`schemas`, `io`, `config`) | ✅ implemented |
| Corpus — Juliet | ✅ implemented |
| Corpus — Defects4J | 🚧 stub (needs Defects4J framework + JDK 11) |
| Metrics & stats (P/R/F1/FPR, HIS, McNemar, bootstrap) | ✅ implemented |
| SAST — PMD (vanilla + custom ruleset, containerized) | ✅ implemented |
| SAST — Semgrep (taint-mode ruleset, containerized) | ✅ implemented |
| SAST runners (SonarQube, CodeQL, SpotBugs) | 🚧 SonarQube/Semgrep-style share plumbing; SpotBugs/CodeQL need a compilable corpus |
| LLM runners (Ollama: DeepSeekCoder, CodeLlama) | ✅ backend + runner (zero-shot/cot/few-shot) |
| CodeBERT fine-tune | ⬜ not started |
| Hybrid pipeline | ⬜ not started |
| Figures (Venn, PR curve, cost-vs-F1) | ⬜ not started |

## Layout

```
src/vulnpipe/
  schemas.py   Snippet + Finding dataclasses (the contract)
  config.py    config.yaml loader
  io.py        JSONL read/write
  corpus/      juliet.py, defects4j.py (stub), build.py
  sast/        base.py, container.py, materialize.py, pmd.py, semgrep.py
  llm/         base.py, prompts.py, mock.py, ollama.py, run.py
  metrics/     join.py, compute.py
  cli.py       `vulnpipe ...` entry point
rulesets/      pmd_cwe89_cwe22.xml      (custom PMD XPath rules, syntactic)
               semgrep_cwe89_cwe22.yml  (Semgrep taint rules, same sinks)
```

## SAST baseline results (500-snippet Juliet corpus)

| tool | P | R | FPR | F1 | TP | FP | TN | FN | note |
|---|---|---|---|---|---|---|---|---|---|
| pmd-vanilla | 0.00 | 0.00 | 0.00 | 0.00 | 0 | 0 | 250 | 250 | built-in `security.xml` has no CWE-89/22 rules — coverage gap |
| pmd-custom | 0.56 | 0.64 | 0.50 | 0.59 | 159 | 126 | 124 | 91 | syntactic sinks, no taint → high false-positive rate |
| semgrep | 0.92 | 0.39 | 0.04 | 0.54 | 97 | 9 | 241 | 153 | same sinks, **taint mode** → FP 126→9, but cross-method flows missed |

The PMD-custom vs Semgrep pair runs the *same sink set*; the only variable
is taint reachability. The result is the textbook SAST precision/recall
dichotomy: PMD-custom maximizes recall (0.64) at FPR 0.50; Semgrep's taint
analysis collapses FPR to 0.04 (precision 0.92) but recall drops to 0.39
(intra-procedural taint + one-method-per-snippet materialization miss
flows that cross helper methods). Neither dominates on F1 — exactly the gap
the hybrid SAST→LLM stage is designed to close (high-recall PMD alerts
filtered by an LLM confirmer; the HIS metric will quantify the gain).
