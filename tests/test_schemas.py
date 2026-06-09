import pytest

from vulnpipe.schemas import Finding, Issue, Snippet


def test_snippet_roundtrip():
    s = Snippet(snippet_id="x", cwe="89", label=1, code="code", file="a.java", line=42)
    assert Snippet.from_dict(s.to_dict()) == s


def test_finding_roundtrip_with_extras():
    f = Finding(
        snippet_id="x", tool="gpt", verdict=1, cwe="89", line=3,
        tokens_in=10, tokens_out=4, cost_usd=0.001,
        prompt_strategy="cot", run_idx=2,
    )
    assert Finding.from_dict(f.to_dict()) == f


def test_from_dict_ignores_unknown_columns():
    f = Finding.from_dict({"snippet_id": "x", "tool": "t", "verdict": 0, "junk": 99})
    assert f.tool == "t" and f.verdict == 0


def test_invalid_label_rejected():
    with pytest.raises(ValueError):
        Snippet(snippet_id="x", cwe="89", label=2, code="", file="a")


def test_invalid_verdict_rejected():
    with pytest.raises(ValueError):
        Finding(snippet_id="x", tool="t", verdict=7)


def test_issue_roundtrip():
    iss = Issue(snippet_id="x", tool="sonarqube", rule_id="S3649", cwe="89", line=5)
    assert Issue.from_dict(iss.to_dict()) == iss
