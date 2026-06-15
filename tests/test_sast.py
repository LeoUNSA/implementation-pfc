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
