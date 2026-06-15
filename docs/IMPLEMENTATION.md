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
and `aggregate_to_finding` unchanged. The Semgrep runner below already does.

### 5.5 Semgrep runner (`semgrep.py`) — taint mode

Semgrep is the **deliberate opposite of PMD-custom**: the same sink set, but a
real **taint engine** (sources → propagation → sinks, with sanitizers). It
reuses every piece of the PMD plumbing — `materialize`, `container.run_container`,
`container.parse_sarif`, and `pmd.aggregate_findings` are imported directly —
so the *only* variable between the two tools is taint reachability. That makes
the precision/FPR delta a clean measurement of what dataflow buys.

`rulesets/semgrep_cwe89_cwe22.yml` has two `mode: taint` rules:

| | **SQL Injection** | **Path Traversal** |
|---|---|---|
| id | `sqli-taint-jdbc` | `path-traversal-taint-file` |
| sinks | `executeQuery/executeUpdate/execute/addBatch/prepareStatement/prepareCall` | `new File/FileInputStream/.../RandomAccessFile`, `Paths.get` |
| sources | `System.getenv`, `getParameter`, `readLine`, `nextLine`, `getString`, `args[i]`, … | same untrusted-input set |
| sanitizers | `Integer.parseInt`, allow-list `replaceAll` | `getCanonicalPath`, `normalize`, `..`-stripping |

The same sinks PMD flags structurally only fire here if a tainted source
*reaches* them unsanitized, so sanitized/constant calls — PMD-custom's false
positives — are suppressed.

Two integration details worth noting (both cost a debugging round, now
encoded in tests):

1. **The image has no `semgrep` entrypoint** (unlike `pmdcode/pmd`), so the
   command is `["semgrep", "scan", ...]`, not just `["scan", ...]`.
2. **SARIF rule ids are namespaced.** A single-file ruleset's ids appear in
   SARIF as `rules.<id>` (e.g. `rules.sqli-taint-jdbc`), not the bare `id:`.
   `RULE_CWE` maps the namespaced form; `test_sast.py` pins this so a future
   Semgrep version that changes the convention fails loudly.

Exit codes: `0` = ran (findings or not, since `--error` is unused), `1` =
blocking findings, `>=2` = error (hard fail). Run flags include `--metrics off`
(no telemetry) and `--disable-version-check` for offline reproducibility.

**Caveat (documented, not hidden):** Semgrep's taint here is intra-procedural
and we materialise one method per snippet, so Juliet flows that cross helper
methods are invisible → recall is traded for precision. That is the expected
SAST trade-off the thesis measures (see §9), not a defect.

---

## 6. LLM layer (`src/vulnpipe/llm/`)

Local generative models, run through the same binary-`Finding` contract as
every other detector.

- `LLMBackend` protocol: `complete(prompt) -> str`.
- `parse_verdict()`: lenient parser — extracts the first balanced `{...}`
  JSON block (models wrap JSON in prose/fences), falls back to keyword
  scanning, defaults to *safe* when nothing parses (a non-committal model is
  not a detection).
- `prompts.py`: the four strategies from the proposal — zero-shot, CoT,
  few-shot, and **static-augmented** (the hybrid core: the SAST alert is
  injected so the LLM acts as a confirmer rather than a cold detector).
- `MockBackend`: deterministic keyword heuristic, so the LLM phase and its
  tests run offline with no model installed.
- `OllamaBackend` (`ollama.py`): the real backend. POSTs to a running
  `ollama serve` at `/api/generate` (`stream:false`). Returns a `GenResult`
  carrying the text **plus** `prompt_eval_count` / `eval_count` (token
  economics) and `total_duration` (ns → ms wall-clock). `force_json` sets
  Ollama's `format:"json"` constraint so output is guaranteed parseable —
  disabled only for CoT, which must emit reasoning prose before its JSON.
  `is_available()` / `installed_models()` let the CLI fail fast with a clear
  message when the server is down or the model was not pulled.

### 6.1 Detection runner (`run.py`)

Drives one `(model, strategy)` pair over the corpus:

1. Build the prompt for each snippet (`zero-shot` / `cot` / `few-shot`;
   `static-augmented` is the hybrid phase, refused here).
2. Query the model `runs` times and parse each reply to a `Verdict`.
3. **Majority-vote** the runs into one per-snippet `Finding` (the metrics
   input). Self-consistency only differs when `temperature > 0`, so at
   `temp = 0` the runner collapses to a single deterministic run regardless of
   `runs_per_snippet`.

Two outputs per run: `findings/<tool>_perSnippet.jsonl` (voted, one row per
snippet — what `metrics` consumes) and `findings/llm_runs/<tool>_runs.jsonl`
(every individual run with `run_idx`, for self-consistency analysis). The
`tool` field is `<model>__<strategy>` (model tag sanitized: `:`/`/` → `_`), so
each pair is scored as its own detector. `few-shot` draws one vulnerable + one
safe in-context example deterministically from the corpus and holds them out of
the eval set. Cost is always None (local models are free); tokens and
wall-clock come straight from the Ollama response.

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
vulnpipe sast run --tool semgrep                      # run Semgrep (taint mode)
vulnpipe llm run --model deepseek-coder:6.7b-instruct --strategy zero-shot
vulnpipe metrics --findings A.jsonl B.jsonl [...]     # score (tools merged by 'tool')
```

---

## 9. Current empirical result (500-snippet Juliet corpus)

| tool | P | R | FPR | F1 | TP | FP | TN | FN |
|---|---|---|---|---|---|---|---|---|
| pmd-vanilla | 0.00 | 0.00 | 0.00 | 0.00 | 0 | 0 | 250 | 250 |
| pmd-custom | 0.56 | 0.64 | 0.50 | 0.59 | 159 | 126 | 124 | 91 |
| semgrep | 0.92 | 0.39 | 0.04 | 0.54 | 97 | 9 | 241 | 153 |

`pmd-vanilla` confirms the coverage gap. `pmd-custom` and `semgrep` run the
**same sink set**, isolating the effect of taint analysis: PMD-custom maximizes
recall (0.64) at a punishing FPR (0.50, 126 false positives); Semgrep's taint
engine cuts false positives to 9 (FPR 0.04, precision 0.92) but loses recall
(0.39) because intra-procedural taint over one-method snippets misses
cross-method flows. This is the classic SAST precision/recall dichotomy — no
tool wins on F1, and the gap is exactly what the hybrid SAST→LLM stage targets
(filter PMD-custom's high-recall alerts with an LLM confirmer; the HIS metric
will quantify the gain).

---

## 10. Reproducibility and environment notes

- Python in a venv (Arch's system Python is externally managed / PEP 668).
- Container images pinned by version tag, not `latest`.
- Deterministic seeds for corpus sampling and bootstrap.
- Known environment gaps for later phases: `mvn` and `ollama` not installed;
  JDK 26 on host vs JDK 11 expected by SpotBugs + Defects4J.
- **Compilation fork.** PMD and Semgrep analyse *source* AST, so they accept
  the non-compiling `final class S { <method> }` wrapper directly. Bytecode/
  build-graph tools (SpotBugs+FindSecBugs need `.class` files; CodeQL needs a
  build database) cannot — they will require a separate *compilable* corpus
  variant or a full Juliet build. This is why Semgrep was the natural next
  runner and SpotBugs/CodeQL are deferred behind that extra step.

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
    semgrep.py      Semgrep taint-mode runner (reuses pmd aggregation)
  llm/
    base.py         LLMBackend protocol + verdict parser
    prompts.py      4 prompting strategies
    mock.py         deterministic offline backend
    ollama.py       real local backend (/api/generate) + GenResult
    run.py          detection runner (prompt → vote → per-snippet Finding)
  metrics/
    join.py         findings → confusion counts
    compute.py      P/R/F1/FPR, HIS, McNemar, bootstrap CI
  cli.py            `vulnpipe` entry point
rulesets/
  pmd_cwe89_cwe22.xml      custom PMD XPath rules (syntactic)
  semgrep_cwe89_cwe22.yml  Semgrep taint rules (same sinks)
```
