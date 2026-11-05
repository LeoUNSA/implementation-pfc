"""SpotBugs + FindSecBugs over the compiled corpus.

Uses the benchmark's own ``findsecbugs`` Maven profile (SpotBugs with the
FindSecBugs plugin, effort Max, threshold Low, SECURITY category). The XML
report names the class of each bug, which is the case it belongs to.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Sequence

from vulnpipe.config import Config
from vulnpipe.sast import project
from vulnpipe.sast.pmd import aggregate_findings
from vulnpipe.schemas import Finding, Issue, Snippet

TOOL = "findsecbugs"
# Bug-pattern prefix -> CWE. SQL_* covers FindSecBugs' taint detectors
# (SQL_INJECTION_JDBC, ...) and SpotBugs' own non-constant-SQL detectors;
# PATH_TRAVERSAL_* is FindSecBugs, PT_* is SpotBugs.
PREFIX_CWE = (("SQL_", "89"), ("PATH_TRAVERSAL_", "22"), ("PT_", "22"))


def parse_report(xml_path: Path, ids: dict[str, str]) -> list[Issue]:
    """``ids`` maps a case's class name to its snippet id; other classes are dropped."""
    issues = []
    for bug in ET.parse(xml_path).getroot().iter("BugInstance"):
        kind = bug.get("type", "")
        cwe = next((c for prefix, c in PREFIX_CWE if kind.startswith(prefix)), None)
        cls = bug.find("Class")
        if cwe is None or cls is None:
            continue
        case = cls.get("classname", "").rsplit(".", 1)[-1].split("$")[0]  # Outer$Inner -> Outer
        if case not in ids:
            continue
        line = bug.find("SourceLine")
        start = line.get("start") if line is not None else None
        issues.append(Issue(snippet_id=ids[case], tool=TOOL, rule_id=kind, cwe=cwe,
                            line=int(start) if start else None,
                            message=bug.findtext("ShortMessage")))
    return issues


def run_spotbugs(cfg: Config, corpus: Sequence[Snippet]) -> list[Finding]:
    proj = project.write_project(cfg, corpus)
    elapsed_ms = project.maven(cfg, proj, ["clean", "-Pfindsecbugs", "compile"])
    issues = parse_report(proj / "target/spotbugsXml.xml", project.snippet_ids(corpus))
    return aggregate_findings(corpus, TOOL, issues, cfg.cwes, elapsed_ms)


def run(cfg: Config, corpus: Sequence[Snippet]) -> dict[str, Path]:
    from vulnpipe.io import write_jsonl

    findings = run_spotbugs(cfg, corpus)
    out = cfg.ensure_path("findings") / f"{TOOL}_perSnippet.jsonl"
    write_jsonl(out, findings)
    print(f"[{TOOL}] {len(findings)} snippets, {sum(f.verdict == 1 for f in findings)} flagged vulnerable -> {out}")
    return {TOOL: out}
