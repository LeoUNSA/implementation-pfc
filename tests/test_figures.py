from vulnpipe.figures import figure_data
from vulnpipe.schemas import Finding, Snippet


def _corpus():
    return [
        Snippet("s_vuln_1", "89", 1, "...", "a.java"),
        Snippet("s_vuln_2", "89", 1, "...", "b.java"),
        Snippet("s_safe_1", "22", 0, "...", "c.java"),
        Snippet("s_safe_2", "22", 0, "...", "d.java"),
    ]


def test_figure_data_metrics_and_tp_sets():
    findings = [
        # llm: flags both vulns (TP) + one safe (FP); reports tokens.
        Finding("s_vuln_1", "llm", 1, tokens_out=10, elapsed_ms=100.0),
        Finding("s_vuln_2", "llm", 1, tokens_out=20, elapsed_ms=200.0),
        Finding("s_safe_1", "llm", 1, tokens_out=30, elapsed_ms=300.0),
        Finding("s_safe_2", "llm", 0, tokens_out=40, elapsed_ms=400.0),
        # sast: flags only vuln_1 (TP); no token cost.
        Finding("s_vuln_1", "sast", 1),
    ]
    rows = {r.tool: r for r in figure_data(findings, _corpus())}

    llm = rows["llm"]
    assert llm.recall == 1.0
    assert abs(llm.precision - 2 / 3) < 1e-9
    assert llm.tp_ids == {"s_vuln_1", "s_vuln_2"}
    assert abs(llm.mean_tokens_out - 25.0) < 1e-9   # (10+20+30+40)/4

    sast = rows["sast"]
    assert sast.tp_ids == {"s_vuln_1"}
    # SAST reports no tokens -> mean is None (pinned to x=0 in the plot).
    assert sast.mean_tokens_out is None


def test_figure_data_orders_tools():
    findings = [Finding("s_vuln_1", "zeta", 1), Finding("s_vuln_1", "alpha", 1)]
    rows = figure_data(findings, _corpus())
    assert [r.tool for r in rows] == ["alpha", "zeta"]
