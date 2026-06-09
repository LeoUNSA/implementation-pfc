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

# Run PMD (vanilla built-in rules + custom CWE-89/22 ruleset) over the corpus.
# Needs Docker; pulls the pinned pmdcode/pmd image on first run.
vulnpipe sast run --tool pmd --variant both

# Compute metrics for one or more findings files against the ground truth.
vulnpipe metrics --findings findings/pmd-vanilla_perSnippet.jsonl \
                            findings/pmd-custom_perSnippet.jsonl
```

## Phase status

| Phase | Status |
|---|---|
| Core contract (`schemas`, `io`, `config`) | ✅ implemented |
| Corpus — Juliet | ✅ implemented |
| Corpus — Defects4J | 🚧 stub (needs Defects4J framework + JDK 11) |
| Metrics & stats (P/R/F1/FPR, HIS, McNemar, bootstrap) | ✅ implemented |
| SAST — PMD (vanilla + custom ruleset, containerized) | ✅ implemented |
| SAST runners (SonarQube, CodeQL, SpotBugs) | 🚧 share PMD's container plumbing |
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
  sast/        base.py, container.py, materialize.py, pmd.py
  llm/         base.py, mock.py, prompts.py
  metrics/     join.py, compute.py
  cli.py       `vulnpipe ...` entry point
rulesets/      pmd_cwe89_cwe22.xml  (custom PMD XPath rules)
```

## PMD baseline result (500-snippet Juliet corpus)

| tool | P | R | FPR | F1 | note |
|---|---|---|---|---|---|
| pmd-vanilla | 0.00 | 0.00 | 0.00 | 0.00 | built-in `security.xml` has no CWE-89/22 rules — coverage gap |
| pmd-custom | 0.56 | 0.64 | 0.50 | 0.59 | syntactic sinks, no taint → high false-positive rate (FPR 0.50) |

`pmd-custom`'s 50 % false-positive rate is the rule-based SAST failure
mode the hybrid LLM-confirmer stage is designed to reduce (the HIS metric
will quantify the improvement).
