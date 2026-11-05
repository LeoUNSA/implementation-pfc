"""OWASP Benchmark v1.2 (Java) → labelled corpus.

Each test case is one servlet file labelled in ``expectedresults-1.2.csv``
(``real vulnerability`` true/false). We keep the ``sqli`` (CWE-89) and
``pathtraver`` (CWE-22) categories; the unit of analysis is the whole file,
so every detector sees the complete flow.

Before storing, the code is neutralised: comments are stripped (several
carry hints such as "which is safe"), and the test name and the servlet
path, which encodes the category (``/sqli-00/...``), are replaced.

Fetch the data once (sparse clone, ~2740 files):

    git clone --depth 1 --filter=blob:none --sparse \
        https://github.com/OWASP-Benchmark/BenchmarkJava.git data/owasp-benchmark
    git -C data/owasp-benchmark sparse-checkout set \
        src/main/java/org/owasp/benchmark/testcode src/main/java/org/owasp/benchmark/helpers \
        src/main/java/org/owasp/benchmark/service
"""

from __future__ import annotations

import csv
import re
from pathlib import Path

from vulnpipe.config import Config
from vulnpipe.corpus.sanitize import strip_comments
from vulnpipe.schemas import SAFE, VULNERABLE, Snippet

CATEGORY_CWE = {"sqli": "89", "pathtraver": "22"}
TESTCODE = Path("src/main/java/org/owasp/benchmark/testcode")

_TEST_NAME = re.compile(r"BenchmarkTest\d+")
_SERVLET_PATH = re.compile(r'@WebServlet\(value\s*=\s*"[^"]*"\)')
_CATEGORY_PATH = re.compile(r"/(?:sqli|pathtraver)-\d+/")
# Constant values in the false-positive traps ("safe!", "alsosafe", ...):
# the literal being constant is what matters, not the word "safe".
_SAFE_LITERAL = re.compile(r'"(?:more|also)?safe!?"', re.I)


def neutralise(code: str) -> str:
    code = strip_comments(code)
    code = _SERVLET_PATH.sub('@WebServlet(value = "/app/TestCase")', code)
    code = _CATEGORY_PATH.sub("/app/", code)
    code = _SAFE_LITERAL.sub('"constant"', code).replace('" SafeStuff"', '" SomeStuff"')
    for narrative in ('"This_should_always_happen"', '"This should never happen"'):
        code = code.replace(narrative, '"fixed_value"')
    return _TEST_NAME.sub("TestCase", code)


def read_expected(csv_path: Path) -> list[tuple[str, str, int]]:
    """Return (test_name, cwe, label) for the target categories."""
    rows = []
    with csv_path.open(encoding="utf-8") as fh:
        for rec in csv.reader(fh):
            if not rec or rec[0].startswith("#"):
                continue
            name, category, real = rec[0].strip(), rec[1].strip(), rec[2].strip()
            if category in CATEGORY_CWE:
                label = VULNERABLE if real == "true" else SAFE
                rows.append((name, CATEGORY_CWE[category], label))
    return rows


def build(cfg: Config) -> list[Snippet]:
    root = cfg.path("data") / cfg.corpus_cfg.get("owasp", {}).get("dir", "owasp-benchmark")
    csv_path = root / "expectedresults-1.2.csv"
    if not csv_path.is_file():
        raise FileNotFoundError(f"{csv_path} missing; see vulnpipe.corpus.owasp docstring")

    snippets = []
    for name, cwe, label in read_expected(csv_path):
        src = (root / TESTCODE / f"{name}.java").read_text(encoding="utf-8")
        snippets.append(
            Snippet(
                snippet_id=f"owasp_CWE{cwe}__{name}",
                cwe=cwe,
                label=label,
                code=neutralise(src),
                file=f"{name}.java",
                line=1,
            )
        )
    return snippets
