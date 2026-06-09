from pathlib import Path

from vulnpipe.corpus.javaparse import extract_methods, slice_with_context
from vulnpipe.corpus.juliet import balanced_sample, iter_testcase_files, snippets_from_file
from vulnpipe.llm.base import parse_verdict
from vulnpipe.llm.mock import MockBackend
from vulnpipe.schemas import SAFE, VULNERABLE, Snippet

FIXTURE = Path(__file__).parent / "fixtures" / "juliet" / "CWE89_SQL_Injection__fixture_01.java"


def test_extract_methods_finds_bad_and_good():
    src = FIXTURE.read_text(encoding="utf-8")
    names = {m.name for m in extract_methods(src)}
    assert {"bad", "goodG2B"} <= names


def test_slice_includes_context():
    src = FIXTURE.read_text(encoding="utf-8")
    bad = next(m for m in extract_methods(src) if m.name == "bad")
    code, start = slice_with_context(src, bad, context_lines=2)
    assert "executeQuery" in code
    assert start >= 1


def test_snippets_from_file_labels():
    snippets = snippets_from_file("89", FIXTURE, context_lines=3)
    by_label = {}
    for s in snippets:
        by_label.setdefault(s.label, []).append(s)
    assert any(s.snippet_id.endswith("__bad") for s in by_label[VULNERABLE])
    assert all(s.cwe == "89" for s in snippets)
    assert SAFE in by_label and VULNERABLE in by_label


def test_balanced_sample_is_deterministic():
    pool = (
        [Snippet(f"v{i}", "89", VULNERABLE, "x", "f") for i in range(20)]
        + [Snippet(f"s{i}", "89", SAFE, "x", "f") for i in range(20)]
    )
    a = [s.snippet_id for s in balanced_sample(pool, 5, 5, seed=42)]
    b = [s.snippet_id for s in balanced_sample(pool, 5, 5, seed=42)]
    assert a == b
    assert len(a) == 10


def test_mock_backend_and_parser():
    code = 'String q = "select * from users"; st.executeQuery(q);'
    mock = MockBackend()
    v = parse_verdict(mock.complete(f"Is this safe? CODE:\n{code}"))
    assert v.verdict == VULNERABLE

    safe_code = "int x = 1 + 2;"
    v2 = parse_verdict(mock.complete(f"CODE:\n{safe_code}"))
    assert v2.verdict == SAFE


def test_iter_testcase_files_maps_juliet_prefix_to_canonical_cwe(tmp_path):
    # Path Traversal lives in CWE23/CWE36 in Juliet but is canonical CWE-22.
    (tmp_path / "CWE23_Relative_Path_Traversal__x_01.java").write_text("class A{}")
    (tmp_path / "CWE36_Absolute_Path_Traversal__y_01.java").write_text("class B{}")
    (tmp_path / "CWE89_SQL_Injection__z_01.java").write_text("class C{}")
    (tmp_path / "CWE79_XSS__w_01.java").write_text("class D{}")  # out of scope
    prefix_map = {"89": "89", "23": "22", "36": "22"}
    found = {(cwe, p.name) for cwe, p in iter_testcase_files(tmp_path, prefix_map)}
    cwes = {cwe for cwe, _ in found}
    assert cwes == {"22", "89"}          # CWE-79 excluded
    assert sum(1 for cwe, _ in found if cwe == "22") == 2  # CWE23 + CWE36


def test_parse_verdict_tolerates_prose_and_fences():
    txt = 'Sure! Here is my answer:\n```json\n{"verdict": "vulnerable", "cwe": "89"}\n```'
    v = parse_verdict(txt)
    assert v.verdict == VULNERABLE and v.cwe == "89"
