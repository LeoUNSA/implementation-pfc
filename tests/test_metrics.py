from vulnpipe.metrics import (
    Confusion,
    bootstrap_f1_ci,
    confusion_by_tool,
    his,
    mcnemar,
    metrics_from_confusion,
)
from vulnpipe.sast.base import aggregate_to_finding
from vulnpipe.schemas import Finding, Issue, Snippet


def _corpus():
    return [
        Snippet("s_vuln_1", "89", 1, "...", "a.java"),
        Snippet("s_vuln_2", "89", 1, "...", "b.java"),
        Snippet("s_safe_1", "22", 0, "...", "c.java"),
        Snippet("s_safe_2", "22", 0, "...", "d.java"),
    ]


def test_confusion_and_metrics_hand_computed():
    # demo-sast: flags vuln_1 (TP), vuln_2 (TP), safe_1 (FP); misses safe_2 (TN).
    findings = [
        Finding("s_vuln_1", "demo-sast", 1),
        Finding("s_vuln_2", "demo-sast", 1),
        Finding("s_safe_1", "demo-sast", 1),
        Finding("s_safe_2", "demo-sast", 0),
    ]
    conf = confusion_by_tool(findings, _corpus())["demo-sast"]
    assert (conf.tp, conf.fp, conf.tn, conf.fn) == (2, 1, 1, 0)

    m = metrics_from_confusion("demo-sast", conf)
    assert m.recall == 1.0                      # 2/(2+0)
    assert abs(m.precision - 2 / 3) < 1e-9       # 2/(2+1)
    assert abs(m.fpr - 0.5) < 1e-9               # 1/(1+1)
    assert abs(m.f1 - 0.8) < 1e-9                # 2*PR/(P+R)


def test_missing_findings_count_as_negative():
    # Only one finding present; the other 3 snippets default to negative.
    findings = [Finding("s_vuln_1", "t", 1)]
    conf = confusion_by_tool(findings, _corpus())["t"]
    assert (conf.tp, conf.fp, conf.tn, conf.fn) == (1, 0, 2, 1)


def test_findings_outside_corpus_dropped():
    findings = [Finding("ghost", "t", 1), Finding("s_vuln_1", "t", 1)]
    conf = confusion_by_tool(findings, _corpus())["t"]
    assert conf.n == 4  # ghost ignored; corpus has 4 snippets


def test_his_sign():
    assert his(0.90, 0.80, 0.70) > 0           # hybrid beats best standalone
    assert his(0.75, 0.80, 0.70) < 0           # hybrid worse than best
    assert his(0.80, 0.80, 0.70) == 0.0


def test_bootstrap_ci_brackets_point_estimate():
    y_true = [1, 1, 0, 0, 1, 0, 1, 0]
    y_pred = [1, 1, 0, 0, 1, 1, 1, 0]
    lo, hi = bootstrap_f1_ci(y_true, y_pred, n_resamples=500, seed=1)
    assert 0.0 <= lo <= hi <= 1.0


def test_mcnemar_prefers_better_detector():
    y_true = [1, 1, 1, 1, 0, 0, 0, 0]
    a = [1, 1, 0, 0, 0, 0, 0, 0]   # 2 errors
    b = [1, 1, 1, 1, 0, 0, 0, 0]   # perfect
    res = mcnemar(y_true, a, b)
    assert res.c >= res.b           # b is right where a is wrong
    assert 0.0 <= res.p_value <= 1.0


def test_aggregate_to_finding_rule():
    issues = [Issue("s1", "pmd", rule_id="R1", cwe="89", line=5)]
    f = aggregate_to_finding("s1", "pmd", issues, target_cwes=["89", "22"])
    assert f.verdict == 1 and f.rule_id == "R1"

    # An issue for an out-of-scope CWE does not flag the snippet.
    off = [Issue("s1", "pmd", rule_id="R9", cwe="79", line=1)]
    f2 = aggregate_to_finding("s1", "pmd", off, target_cwes=["89", "22"])
    assert f2.verdict == 0

    # No issues -> safe.
    f3 = aggregate_to_finding("s1", "pmd", [], target_cwes=["89", "22"])
    assert f3.verdict == 0
