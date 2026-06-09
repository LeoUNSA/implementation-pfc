# vulnpipe — Implementation Guide

How the pipeline is built, how the corpus and datasets are handled, and how
each detector is forced into a single comparable shape. Companion to the
research proposal (`../../propuesta.md` §6) and the artifact walkthrough
(`../../pipeline_outputs.md`). For build/run commands and current phase
status see `../README.md`.

---

## 1. The problem this code solves

The thesis compares three radically different families of vulnerability
detectors on the same Java code:

- **Rule-based SAST** (PMD, SonarQube, CodeQL, SpotBugs+FindSecBugs) — emit a
  *list of issues* (file, line, rule).
- **Generative LLMs** (DeepSeekCoder, CodeLlama via Ollama) — emit *free
  text*.
- **A fine-tuned classifier** (CodeBERT) — emits a *softmax probability*.

Their native outputs are incomparable. The entire implementation is
organised around one idea: **coerce every detector into the same atomic
record with a binary verdict**, then score them all the same way. That
record is the *contract* (§2). Everything else is plumbing that produces or
consumes it.

The two target weakness classes are **CWE-89 (SQL Injection)** and
**CWE-22 (Path Traversal)**.

---

## 2. The contract (`src/vulnpipe/schemas.py`)

Three dataclasses. Their field names are the immutable interface every other
module agrees on.

### `Snippet` — the ground-truth unit
```
snippet_id  unique key; the join key for the whole pipeline
cwe         "89" | "22"  (canonical / thesis CWE id)
label       1 = vulnerable, 0 = safe   ← the gold standard
code        the Java source fragment (method ± context)
file        original source filename
line        1-based offending line (optional)
```
Produced only by the corpus stage. It is the **only** carrier of ground
truth; every detector output is later joined to it on `snippet_id`.

### `Finding` — one detector's verdict on one snippet
```
snippet_id, tool, verdict (1/0)        ← the only fields metrics require
cwe, line, rule_id                     localisation / provenance (optional)
confidence                             e.g. CodeBERT softmax (optional)
explanation                            free text, kept for qualitative use
elapsed_ms                             wall-clock, for the CI/CD-realism metric
tokens_in / tokens_out / cost_usd      LLM economics (optional)
prompt_strategy / run_idx              LLM run bookkeeping (optional)
```
Emitted by **every** detector family. `verdict` is the single field the
metrics layer depends on; everything else is an optional extra.

### `Issue` — a raw SAST alert (pre-aggregation)
One row per emitted alert (file, line, rule). A SAST tool emits a *list* of
these; they are aggregated into one per-snippet `Finding` (§5.4). Kept
distinct because one snippet can carry several issues.

`from_dict` tolerates unknown columns, so heterogeneous JSONL files load
without breaking. `to_dict`/`write_jsonl` drop `None` fields to keep files
compact.

---

## 3. Storage and configuration

- **JSONL everywhere** (`io.py`): one JSON object per line. Corpus →
  `corpus/*.jsonl`; detector outputs → `findings/*_perSnippet.jsonl`;
  metrics → `metrics/*.csv`.
- **`config.yaml`** is the single source of truth for paths, dataset URLs,
  sampling sizes, the CWE mapping, the pinned container image, and metric
  parameters. `config.py` discovers it by walking up from the cwd, validates
  required keys, and resolves `paths.*` to absolute directories.
- **What is committed vs. regenerable** (`.gitignore`): `corpus/*.jsonl` is
  committed (it *is* the ground truth). `data/` (raw downloads), `findings/`,
  `metrics/`, `figures/` are gitignored — all reproducible from
  `vulnpipe corpus build` + the detector runs.

---

## 4. Dataset and corpus handling

### 4.1 Datasets

| Dataset | Role | Status |
|---|---|---|
| **NIST Juliet (Java) v1.3** | primary corpus — synthetic, labelled, balanced | ✅ implemented |
| **Defects4J v2.0** | validation set — ~50 real bugs | 🚧 stub (needs Perl framework + JDK 11) |
| **CVEfixes** | optional severity cross-reference | not started |

### 4.2 Juliet pipeline (`corpus/juliet.py`)

1. **Download** the official NIST archive (76 MB) into `data/` on first run;
   cached thereafter. Verified to be a valid zip. URL is in `config.yaml`.
2. **Extract** into `data/juliet/` once (an `.extracted` marker makes it
   idempotent).
3. **Filter by CWE — with a mapping.** Juliet Java has **no `CWE22_`
   directory**; Path Traversal is split into `CWE23_Relative_Path_Traversal`
   and `CWE36_Absolute_Path_Traversal`, both children of CWE-22. The config
   `cwe_map` records this:
   ```yaml
   cwe_map:
     "89": ["89"]
     "22": ["23", "36"]
   ```
   File matching uses the Juliet prefixes; the stored `Snippet.cwe` keeps the
   **canonical** thesis id (`"22"`/`"89"`). Without this mapping, half the
   corpus silently vanishes — a bug we hit and fixed.
4. **Extract methods.** Each Juliet test case exposes a `bad()` method (the
   vulnerable path → `label=1`) and one or more `good*()` methods (the fixed
   paths → `label=0`). Method boundaries come from `corpus/javaparse.py`
   (tree-sitter-java, with a brace-matching fallback). Each snippet's `code`
   is the method ± `context_lines` (default 20) lines of surrounding context.
5. **Balanced, stratified, deterministic sample.** Quotas are split evenly
   per CWE and per label, shuffled under a fixed `seed`, so re-runs are
   identical. Pools smaller than their quota are taken whole (no
   oversampling/duplication).

**Result of the current corpus:** 500 snippets, perfectly balanced —
125 per (CWE, label) cell (CWE-89 vuln/safe, CWE-22 vuln/safe).

### 4.3 Why method extraction is tricky

Parsing an *already-sliced* fragment is unreliable: a method ± 20-line slice
has unbalanced braces, and a stricter parser mis-bounds methods on it. So for
any task needing a clean method (e.g. SAST materialization, §5.2) we go back
to the **original full file** (balanced → reliable) and brace-scan forward
from the method's start line to a complete body.

---

## 5. SAST layer (`src/vulnpipe/sast/`)

### 5.1 Containerised execution (`container.py`)

Every SAST tool runs the same way, so the docker plumbing is factored out:

```
docker run --rm -v <scan_dir>:/src [-v <rulesets>:/rules:ro] <pinned-image> <cmd>
```

- `ensure_docker()` checks the CLI and a reachable daemon, failing with a
  clear message otherwise.
- `run_container()` builds the `docker run`, bind-mounts the scan directory,
  and returns `(returncode, stdout, stderr, elapsed_ms)`.
- `parse_sarif()` reads the tool's SARIF report into `Issue` records. The
  snippet id is the SARIF artifact basename minus `.java`. A `rule_cwe`
  mapping decides which rule ids count as CWE-89/22; with `only_mapped=True`
  (default), unrelated rules (e.g. PMD's crypto rules) are dropped so they
  cannot inflate counts.

**There is no Dockerfile.** We pull prebuilt public images and pin them by
version tag for reproducibility (e.g. `pmdcode/pmd:7.25.0`, verified to equal
`:latest` at time of writing). A custom Dockerfile will only be needed where
no good official image exists or where a specific JDK must be pinned
(SpotBugs / Defects4J want JDK 11; the host has JDK 26).

### 5.2 Snippet materialisation (`materialize.py`)

SAST tools scan files, not JSONL rows. Each snippet is written to
`findings/scan/<snippet_id>.java`, wrapped so it parses:
```java
final class S { <the snippet's method> }
```
The method is extracted from the **original full source** when available
(reliable), falling back to brace-scanning the slice. PMD does AST analysis
without compilation, so undefined symbols (helper classes, unresolved types)
are harmless. The filename is the join key back to the corpus when the SARIF
report is parsed. Stale `.java` files are cleared before each run so the scan
set matches the current corpus exactly.

### 5.3 PMD runner (`pmd.py`) — two variants

PMD is a **code-quality linter with no taint/dataflow engine**. It matches
AST patterns; it cannot trace untrusted data from source to sink. That fact
drives the two variants, which share *all* plumbing (materialise → docker →
SARIF → aggregate) and differ only in ruleset + rule→CWE map:

| | **pmd-vanilla** | **pmd-custom** |
|---|---|---|
| Ruleset | built-in `category/java/security.xml` | `rulesets/pmd_cwe89_cwe22.xml` (hand-authored) |
| Rules | 2 crypto rules only | `SqlInjectionConcatExec`, `PathTraversalFileSink` |
| rule→CWE map | empty → nothing maps to 89/22 | `→ "89"`, `→ "22"` |
| Detects CWE-89/22? | No, by construction | Yes, syntactically |
| Purpose | quantify PMD's **coverage gap** | illustrate the **high-FP failure mode** |

**Vanilla** exists to report, honestly, that out-of-the-box PMD detects none
of these vulnerabilities (recall 0). This is architectural, not a version
issue: no PMD version adds taint-based SQLi/path detection by default.

**Custom** is a deliberately *syntactic* ruleset: it flags a known sink whose
argument is not a string literal, e.g.

```
//MethodCall[@MethodName=('executeQuery','executeUpdate','execute',...)
             and ArgumentList[@Size>0] and not(ArgumentList/StringLiteral)]
//ConstructorCall[ClassType[@SimpleName=('File','FileInputStream',...)]
                  and ArgumentList[@Size>0] and not(ArgumentList/StringLiteral)]
```

Lacking dataflow, it cannot distinguish a sanitised query from an injectable
one, so it **over-approximates** — high recall, many false positives. The
XPath was written against PMD's real AST (verified with `pmd ast-dump`), not
guessed. This is documented as a hand-authored ruleset, not stock PMD.

PMD exit codes are handled explicitly: `0` clean, `4` violations found, `5`
recoverable parse errors (those files default to a safe verdict and a warning
is printed), anything else is a hard failure.

### 5.4 Aggregation (`base.py`)

`aggregate_to_finding` collapses a snippet's `Issue` list into one binary
`Finding`:

> a snippet is **vulnerable** iff it carries at least one issue mapped to a
> target CWE.

`aggregate_findings` (in `pmd.py`) then guarantees **one finding per corpus
snippet** — snippets with no issue get an explicit safe verdict, so recall is
never inflated by missing rows. Total batch wall-clock is attached to each
finding for the timing metric.

The `SASTRunner` protocol in `base.py` defines the interface the remaining
tools (SonarQube/CodeQL/SpotBugs) will implement; they reuse `container.py`
and `aggregate_to_finding` unchanged.

---

## 6. LLM layer (`src/vulnpipe/llm/`) — interfaces + mock

Real models run later (locally via Ollama). For now the contract is fixed:

- `LLMBackend` protocol: `complete(prompt) -> str`.
- `parse_verdict()`: lenient parser — extracts the first balanced `{...}`
  JSON block (models wrap JSON in prose/fences), falls back to keyword
  scanning, defaults to *safe* when nothing parses.
- `prompts.py`: the four strategies from the proposal — zero-shot, CoT,
  few-shot, and **static-augmented** (the hybrid core: the SAST alert is
  injected so the LLM acts as a confirmer rather than a cold detector).
- `MockBackend`: deterministic keyword heuristic, so the LLM phase and its
  tests run offline with no model installed. Real `OllamaBackend` /
  `OpenAIBackend` slot in behind the same protocol.

---

## 7. Metrics layer (`src/vulnpipe/metrics/`)

Pure functions over the binary-verdict contract — no detector code required,
fully unit-tested on synthetic findings.

- `join.py`: `confusion_by_tool()` joins every `*_perSnippet.jsonl` to the
  ground truth on `snippet_id` and derives TP/FP/TN/FN per tool. Snippets
  absent from a tool's findings count as **negative** (not flagged), so
  missing rows can't inflate recall; findings for unknown snippets are
  dropped.
- `compute.py`: Precision, Recall (TPR), FPR, F1; the **Hybrid Improvement
  Score** `HIS = (F1_hybrid − max(F1_sast, F1_llm)) / max(F1_sast, F1_llm)`;
  **paired McNemar** (exact binomial under 25 discordant pairs, χ² with
  continuity correction otherwise); and a **percentile bootstrap** 95 % CI on
  F1 (1000 resamples, fixed seed). α = 0.05.

Output shape: `metrics/per_tool.csv` with
`tool, precision, recall, fpr, f1, tp, fp, tn, fn`.

---

## 8. CLI (`src/vulnpipe/cli.py`)

Stdlib `argparse`, exposed as the `vulnpipe` console script.

```bash
vulnpipe corpus build --only juliet                  # build the labelled corpus
vulnpipe sast run --tool pmd --variant both           # run PMD vanilla + custom
vulnpipe metrics --findings A.jsonl B.jsonl [...]     # score (tools merged by 'tool')
```

---

## 9. Current empirical result (500-snippet Juliet corpus)

| tool | P | R | FPR | F1 |
|---|---|---|---|---|
| pmd-vanilla | 0.00 | 0.00 | 0.00 | 0.00 |
| pmd-custom | 0.56 | 0.64 | 0.50 | 0.59 |

`pmd-vanilla` confirms the coverage gap; `pmd-custom`'s 50 % false-positive
rate is exactly the rule-based-SAST failure mode the hybrid LLM-confirmer is
designed to reduce. The HIS metric will later quantify that reduction.

---

## 10. Reproducibility and environment notes

- Python in a venv (Arch's system Python is externally managed / PEP 668).
- Container images pinned by version tag, not `latest`.
- Deterministic seeds for corpus sampling and bootstrap.
- Known environment gaps for later phases: `mvn` and `ollama` not installed;
  JDK 26 on host vs JDK 11 expected by SpotBugs + Defects4J.

---

## 11. Module map

```
src/vulnpipe/
  schemas.py        Snippet / Finding / Issue — the contract
  config.py         config.yaml loader + path resolution
  io.py             JSONL read/write
  corpus/
    juliet.py       download → extract → CWE-map → method extract → balance
    javaparse.py    tree-sitter-java method extraction (+ brace fallback)
    defects4j.py    stub (validation set, deferred)
    build.py        orchestrator → corpus/<dataset>.jsonl
  sast/
    base.py         SASTRunner protocol + issues→verdict aggregation
    container.py    docker run + SARIF parsing
    materialize.py  snippets → parseable .java files
    pmd.py          PMD vanilla + custom variants
  llm/
    base.py         LLMBackend protocol + verdict parser
    mock.py         deterministic offline backend
    prompts.py      4 prompting strategies
  metrics/
    join.py         findings → confusion counts
    compute.py      P/R/F1/FPR, HIS, McNemar, bootstrap CI
  cli.py            `vulnpipe` entry point
rulesets/
  pmd_cwe89_cwe22.xml   custom PMD XPath rules
```
