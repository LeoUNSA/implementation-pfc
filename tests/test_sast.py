import json

from vulnpipe.sast.container import parse_sarif
from vulnpipe.sast.materialize import wrap_snippet
from vulnpipe.sast.pmd import VARIANTS, aggregate_findings
from vulnpipe.schemas import Issue, Snippet


def test_wrap_snippet_is_balanced_and_contains_method():
    code = (
        "package x;\n"
        "import java.sql.*;\n"
        "public class CWE89_x {\n"
        "    public void bad(String u, Connection c) throws Exception {\n"
        '        c.createStatement().executeQuery("a" + u);\n'
        "    }\n"
    )  # deliberately unbalanced slice (no closing brace for the class)
    s = Snippet("juliet_CWE89__x__bad", "89", 1, code, "x.java")
    wrapped = wrap_snippet(s)
    assert wrapped.count("{") == wrapped.count("}")   # balanced now
    assert "executeQuery" in wrapped
    assert wrapped.startswith("final class S")


def test_parse_sarif_maps_and_filters(tmp_path):
    sarif = {
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "SqlInjectionConcatExec",
                        "message": {"text": "sqli"},
                        "locations": [
                            {"physicalLocation": {
                                "artifactLocation": {"uri": "juliet_CWE89__a__bad.java"},
                                "region": {"startLine": 5},
                            }}
                        ],
                    },
                    {   # unmapped rule -> dropped when only_mapped
                        "ruleId": "SomeStyleRule",
                        "message": {"text": "style"},
                        "locations": [
                            {"physicalLocation": {
                                "artifactLocation": {"uri": "juliet_CWE89__a__bad.java"},
                                "region": {"startLine": 1},
                            }}
                        ],
                    },
                ]
            }
        ]
    }
    p = tmp_path / "r.sarif"
    p.write_text(json.dumps(sarif), encoding="utf-8")
    issues = parse_sarif(p, "pmd-custom", VARIANTS["custom"].rule_cwe, only_mapped=True)
    assert len(issues) == 1
    assert issues[0].cwe == "89" and issues[0].snippet_id == "juliet_CWE89__a__bad"


def test_aggregate_findings_covers_full_corpus():
    corpus = [
        Snippet("s1", "89", 1, "x", "a.java"),
        Snippet("s2", "89", 0, "x", "b.java"),
    ]
    issues = [Issue("s1", "pmd-custom", rule_id="SqlInjectionConcatExec", cwe="89", line=5)]
    findings = aggregate_findings(corpus, "pmd-custom", issues, ["89", "22"], elapsed_ms=123.0)
    by_id = {f.snippet_id: f for f in findings}
    assert len(findings) == 2                 # every snippet gets a verdict
    assert by_id["s1"].verdict == 1
    assert by_id["s2"].verdict == 0           # no issue -> safe
    assert by_id["s1"].elapsed_ms == 123.0


def test_vanilla_variant_has_empty_cwe_map():
    # vanilla cannot map any rule to a target CWE -> recall 0 by construction.
    assert VARIANTS["vanilla"].rule_cwe == {}


def test_semgrep_sarif_uses_namespaced_rule_ids(tmp_path):
    # Semgrep namespaces a single-file ruleset's ids under "rules.", so the
    # SARIF ruleId is "rules.<id>" — the map must match that, not the bare id.
    from vulnpipe.sast.semgrep import RULE_CWE

    assert RULE_CWE == {
        "rules.sqli-taint-jdbc": "89",
        "rules.path-traversal-taint-file": "22",
    }
    sarif = {
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "rules.sqli-taint-jdbc",
                        "message": {"text": "sqli"},
                        "locations": [
                            {"physicalLocation": {
                                "artifactLocation": {"uri": "juliet_CWE89__a__bad.java"},
                                "region": {"startLine": 100},
                            }}
                        ],
                    },
                    {   # bare (un-namespaced) id must NOT map -> dropped
                        "ruleId": "sqli-taint-jdbc",
                        "message": {"text": "sqli"},
                        "locations": [
                            {"physicalLocation": {
                                "artifactLocation": {"uri": "juliet_CWE89__b__bad.java"},
                                "region": {"startLine": 1},
                            }}
                        ],
                    },
                ]
            }
        ]
    }
    p = tmp_path / "semgrep.sarif"
    p.write_text(json.dumps(sarif), encoding="utf-8")
    issues = parse_sarif(p, "semgrep", RULE_CWE, only_mapped=True)
    assert len(issues) == 1
    assert issues[0].cwe == "89" and issues[0].snippet_id == "juliet_CWE89__a__bad"


def test_parse_text_traces_reads_source_steps_and_sink():
    from vulnpipe.sast.semgrep import parse_text_traces

    text = """
    /src/owasp_CWE89__BenchmarkTest00008.java
   ❯❯❱ rules.sqli-taint-jdbc
          SQL Injection (CWE-89): untrusted input reaches a JDBC execute method.

           29┆ java.sql.CallableStatement statement = connection.prepareCall(sql);

          Taint comes from:

           22┆ param = request.getHeader("TestCase");

          Taint flows through these intermediate variables:

           22┆ param = request.getHeader("TestCase");

           25┆ String sql = "{call " + param + "}";

                This is how taint reaches the sink:

           29┆ java.sql.CallableStatement statement = connection.prepareCall(sql);

            ⋮┆----------------------------------------
           30┆ java.sql.ResultSet rs = statement.executeQuery();
"""
    t = parse_text_traces(text)["owasp_CWE89__BenchmarkTest00008"]
    assert t == {"source": [22], "steps": [22, 25], "sink": [29, 30]}


def test_spotbugs_report_maps_bug_patterns_to_cases(tmp_path):
    from vulnpipe.sast.spotbugs import parse_report

    pkg = "org.owasp.benchmark"
    report = tmp_path / "spotbugsXml.xml"
    report.write_text(f"""<BugCollection>
      <BugInstance type="SQL_INJECTION_JDBC"><ShortMessage>sqli</ShortMessage>
        <Class classname="{pkg}.testcode.BenchmarkTest00008$Test"/><SourceLine start="41"/></BugInstance>
      <BugInstance type="PATH_TRAVERSAL_IN">
        <Class classname="{pkg}.testcode.BenchmarkTest00001"/><SourceLine start="45"/></BugInstance>
      <BugInstance type="PATH_TRAVERSAL_IN"><Class classname="{pkg}.helpers.Utils"/></BugInstance>
      <BugInstance type="SERVLET_PARAMETER"><Class classname="{pkg}.testcode.BenchmarkTest00001"/></BugInstance>
    </BugCollection>""")
    ids = {"BenchmarkTest00001": "a", "BenchmarkTest00008": "b"}
    got = [(i.snippet_id, i.cwe, i.line) for i in parse_report(report, ids)]
    assert got == [("b", "89", 41), ("a", "22", 45)]  # helper class and unrelated pattern dropped


def test_codeql_sarif_keeps_only_tagged_rules_and_in_case_path_lines(tmp_path):
    import json

    from vulnpipe.sast.codeql import parse_sarif

    def loc(name, line):
        return {"physicalLocation": {"artifactLocation": {"uri": f"src/x/{name}.java"},
                                     "region": {"startLine": line}}}

    def result(rule, case, path):
        return {"ruleId": rule, "message": {"text": "m"}, "locations": [loc(case, path[-1][1])],
                "codeFlows": [{"threadFlows": [{"locations": [{"location": loc(*p)} for p in path]}]}]}

    case = "BenchmarkTest00002"
    sarif = tmp_path / "codeql.sarif"
    sarif.write_text(json.dumps({"runs": [{
        "tool": {"driver": {"rules": [
            {"id": "java/sql-injection", "properties": {"tags": ["security", "external/cwe/cwe-089"]}},
            {"id": "java/xss", "properties": {"tags": ["external/cwe/cwe-079"]}}]}},
        "results": [
            result("java/sql-injection", case, [("SeparateClassRequest", 31), (case, 22), (case, 30), (case, 44)]),
            result("java/xss", case, [(case, 22), (case, 50)]),
        ]}]}))
    issues, traces = parse_sarif(sarif, {case: "s"})
    assert [(i.snippet_id, i.cwe, i.line) for i in issues] == [("s", "89", 44)]
    assert traces == {"s": {"source": [22], "steps": [30], "sink": [44]}}  # helper-class step skipped


def test_sonarqube_rows_keep_only_cwe_rules_inside_cases():
    from vulnpipe.sast.sonarqube import to_issues

    rows = [
        {"ruleKey": "java:S2077", "component": "p:src/x/BenchmarkTest00002.java", "line": 44},  # hotspot
        {"rule": "java:S2077", "component": "p:src/x/Utils.java", "line": 9},                    # helper
        {"ruleKey": "java:S1989", "component": "p:src/x/BenchmarkTest00002.java", "line": 3},   # other rule
    ]
    got = to_issues(rows, {"java:S2077": "89"}, {"BenchmarkTest00002": "s"})
    assert [(i.snippet_id, i.cwe, i.line) for i in got] == [("s", "89", 44)]
