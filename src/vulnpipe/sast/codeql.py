"""CodeQL over the compiled corpus, with its dataflow paths.

The database is built by tracing the Maven build inside the build container
(the CodeQL bundle is mounted from ``data/tools/codeql``) and analysed with
the default code-scanning suite. A rule counts for CWE-89 or CWE-22 when
its own metadata carries that CWE tag, so no rule list is hand-picked.

Fetch the bundle once (pinned in ``sast.codeql.version``):

    mkdir -p data/tools && cd data/tools
    curl -LO https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.4/codeql-bundle-java-linux64.tar.zst
    tar --zstd -xf codeql-bundle-java-linux64.tar.zst
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

from vulnpipe.config import Config
from vulnpipe.sast import project
from vulnpipe.sast.pmd import aggregate_findings
from vulnpipe.schemas import Finding, Issue, Snippet

TOOL = "codeql"
SUITE = "codeql/java-queries:codeql-suites/java-code-scanning.qls"
# CWE-23 and CWE-36 are the relative/absolute children of CWE-22.
TAG_CWE = {"external/cwe/cwe-089": "89", "external/cwe/cwe-022": "22",
           "external/cwe/cwe-023": "22", "external/cwe/cwe-036": "22"}
CODEQL = "/opt/codeql/codeql"


def _rule_cwe(run: dict) -> dict[str, str]:
    tool = run.get("tool", {})
    out = {}
    for comp in (tool.get("driver", {}), *tool.get("extensions", [])):
        for rule in comp.get("rules", []):
            tags = rule.get("properties", {}).get("tags", [])
            cwe = next((TAG_CWE[t] for t in tags if t in TAG_CWE), None)
            if cwe:
                out[rule["id"]] = cwe
    return out


def _loc(location: dict) -> tuple[str, int | None]:
    phys = location.get("physicalLocation", {})
    return (Path(phys.get("artifactLocation", {}).get("uri", "")).stem,
            phys.get("region", {}).get("startLine"))


def parse_sarif(sarif_path: Path, ids: dict[str, str]) -> tuple[list[Issue], dict[str, dict[str, list[int]]]]:
    """Issues plus, per snippet, the path lines that fall inside the case's
    own file: ``{"source": [...], "steps": [...], "sink": [...]}`` (the same
    shape as the Semgrep traces). Steps through helper classes are skipped,
    since the confirmer only sees the case."""
    issues: list[Issue] = []
    traces: dict[str, dict[str, list[int]]] = {}
    for run in json.loads(sarif_path.read_text(encoding="utf-8")).get("runs", []):
        rule_cwe = _rule_cwe(run)
        for res in run.get("results", []):
            cwe = rule_cwe.get(res.get("ruleId", ""))
            case, line = _loc((res.get("locations") or [{}])[0])
            if cwe is None or case not in ids:
                continue
            sid = ids[case]
            issues.append(Issue(snippet_id=sid, tool=TOOL, rule_id=res["ruleId"], cwe=cwe, line=line,
                                message=res.get("message", {}).get("text")))
            for flow in res.get("codeFlows", [])[:1]:
                path = [_loc(l.get("location", {})) for l in flow["threadFlows"][0]["locations"]]
                lines = [n for c, n in path if c == case and n]
                if not lines:
                    continue
                t = traces.setdefault(sid, {"source": [], "steps": [], "sink": []})
                ends = (lines[0], lines[-1])
                mid = [n for n in lines[1:-1] if n not in ends]
                for mode, ns in (("source", lines[:1]), ("steps", mid), ("sink", lines[-1:])):
                    t[mode] += [n for n in dict.fromkeys(ns) if n not in t[mode]]
    return issues, traces


def run_codeql(cfg: Config, corpus: Sequence[Snippet]) -> list[Finding]:
    bundle = cfg.path("data") / "tools" / "codeql"
    if not (bundle / "codeql").is_file():
        raise FileNotFoundError(f"{bundle}/codeql missing; see vulnpipe.sast.codeql docstring")
    proj = project.write_project(cfg, corpus)
    mounts = {bundle: "/opt/codeql:ro"}
    build = " ".join(["mvn", *project.MVN_FLAGS, "clean", "compile"])
    elapsed_ms = project.maven(cfg, proj, [], mounts, command=[
        CODEQL, "database", "create", "/src/codeql-db", "--language=java", "--overwrite",
        "--source-root=/src", f"--command={build}"])
    elapsed_ms += project.maven(cfg, proj, [], mounts, command=[
        CODEQL, "database", "analyze", "/src/codeql-db", SUITE, "--format=sarif-latest",
        "--output=/src/codeql.sarif", "--threads=0"], timeout=7200)

    issues, traces = parse_sarif(proj / "codeql.sarif", project.snippet_ids(corpus))
    scan_dir = cfg.ensure_path("findings") / "scan"
    scan_dir.mkdir(exist_ok=True)
    (scan_dir / "codeql_traces.json").write_text(json.dumps(traces), encoding="utf-8")
    return aggregate_findings(corpus, TOOL, issues, cfg.cwes, elapsed_ms)


def run(cfg: Config, corpus: Sequence[Snippet]) -> dict[str, Path]:
    from vulnpipe.io import write_jsonl

    findings = run_codeql(cfg, corpus)
    out = cfg.ensure_path("findings") / f"{TOOL}_perSnippet.jsonl"
    write_jsonl(out, findings)
    print(f"[{TOOL}] {len(findings)} snippets, {sum(f.verdict == 1 for f in findings)} flagged vulnerable -> {out}")
    return {TOOL: out}
