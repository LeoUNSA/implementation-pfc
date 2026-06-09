# vulnpipe

Reproducibility package for the PFC thesis *"Static Analysis vs. LLMs for
Automated Detection of SQL Injection (CWE-89) and Path Traversal (CWE-22)
Vulnerabilities in Java: A Hybrid Pipeline."*

Implements the empirical pipeline described in `../propuesta.md` §6 and
`../pipeline_outputs.md`: corpus construction → SAST → LLM → CodeBERT →
hybrid SAST→LLM filter → metrics.

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

# Compute metrics for a findings file against the corpus ground truth.
vulnpipe metrics --findings findings/sast_perSnippet.jsonl
```

## Phase status

| Phase | Status |
|---|---|
| Core contract (`schemas`, `io`, `config`) | ✅ implemented |
| Corpus — Juliet | ✅ implemented |
| Corpus — Defects4J | 🚧 stub (needs Defects4J framework + JDK 11) |
| Metrics & stats (P/R/F1/FPR, HIS, McNemar, bootstrap) | ✅ implemented |
| SAST runners (SonarQube, CodeQL, SpotBugs, PMD) | 🚧 interface only |
| LLM runners (Ollama: DeepSeekCoder, CodeLlama) | 🚧 interface + mock |
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
  sast/        base.py (runner protocol + aggregation rule)
  llm/         base.py, mock.py, prompts.py
  metrics/     join.py, compute.py
  cli.py       `vulnpipe ...` entry point
```
