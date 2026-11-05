"""SonarQube Community over the compiled corpus.

Starts a throwaway server container, analyses the project with the Maven
scanner and reads the results back through the web API. The Community
edition has no taint analysis, so injection findings arrive as *security
hotspots*; both hotspots and vulnerability issues are collected. A rule
counts for CWE-89 or CWE-22 when the server's own rule metadata tags it
with that CWE.
"""

from __future__ import annotations

import base64
import json
import subprocess
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Sequence

from vulnpipe.config import Config
from vulnpipe.sast import container, project
from vulnpipe.sast.pmd import aggregate_findings
from vulnpipe.schemas import Finding, Issue, Snippet

TOOL = "sonarqube"
DEFAULT_IMAGE = "sonarqube:10.7.0-community"
SCANNER = "org.sonarsource.scanner.maven:sonar-maven-plugin:4.0.0.4121:sonar"
NAME = "vulnpipe-sonar"  # container, network and project key
URL = "http://127.0.0.1:9000"
# CWE-23 and CWE-36 are the relative/absolute children of CWE-22.
CWE_QUERY = {"89": "89", "22": "22,23,36"}
_AUTH = {"Authorization": "Basic " + base64.b64encode(b"admin:admin").decode()}


def _api(path: str, post: bool = False, **params) -> dict:
    url = f"{URL}/api/{path}"
    data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(url, data=data, headers=_AUTH) if post else \
        urllib.request.Request(f"{url}?{data.decode()}", headers=_AUTH)
    with urllib.request.urlopen(req, timeout=60) as resp:
        body = resp.read()
    return json.loads(body) if body else {}


def _wait(what: str, ready, timeout: int = 600) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if ready():
                return
        except OSError:
            pass  # server not accepting connections yet
        if not subprocess.run(["docker", "ps", "-q", "-f", f"name={NAME}"],
                              capture_output=True, text=True).stdout.strip():
            raise RuntimeError("SonarQube server container exited; run the image by hand to see its log")
        time.sleep(5)
    raise TimeoutError(f"SonarQube: {what} not ready after {timeout}s")


def _pages(path: str, key: str, **params) -> list[dict]:
    rows, page = [], 1
    while True:
        chunk = _api(path, ps=500, p=page, **params).get(key, [])
        rows += chunk
        if len(chunk) < 500:
            return rows
        page += 1


def to_issues(rows: Sequence[dict], rule_cwe: dict[str, str], ids: dict[str, str]) -> list[Issue]:
    """Hotspot or issue rows -> ``Issue`` (rows of other rules or outside the cases are dropped)."""
    issues = []
    for row in rows:
        rule = row.get("ruleKey") or row.get("rule", "")
        case = Path(row.get("component", "")).stem
        if rule in rule_cwe and case in ids:
            issues.append(Issue(snippet_id=ids[case], tool=TOOL, rule_id=rule, cwe=rule_cwe[rule],
                                line=row.get("line"), message=row.get("message")))
    return issues


def run_sonarqube(cfg: Config, corpus: Sequence[Snippet]) -> list[Finding]:
    image = cfg.raw.get("sast", {}).get("sonarqube", {}).get("image", DEFAULT_IMAGE)
    proj = project.write_project(cfg, corpus)
    project.maven(cfg, proj, ["clean", "compile"])

    container.ensure_docker()
    subprocess.run(["docker", "network", "create", NAME], capture_output=True)  # ok if it exists
    subprocess.run(["docker", "rm", "-f", NAME], capture_output=True)
    # The server's data lives in memory: it is throwaway, and its embedded
    # Elasticsearch refuses to create indexes on a disk that is over 90 % full.
    subprocess.run(["docker", "run", "-d", "--rm", "--name", NAME, "--network", NAME,
                    "-p", "127.0.0.1:9000:9000", "-e", "SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true",
                    "--tmpfs", "/opt/sonarqube/data:rw,exec,size=4g,mode=1777", image],
                   check=True, capture_output=True)
    try:
        _wait("server", lambda: _api("system/status").get("status") == "UP")
        token = _api("user_tokens/generate", post=True, name=f"vulnpipe-{int(time.time())}")["token"]
        elapsed_ms = project.maven(
            cfg, proj, [SCANNER, f"-Dsonar.host.url=http://{NAME}:9000", f"-Dsonar.token={token}",
                        f"-Dsonar.projectKey={NAME}"], docker_args=["--network", NAME])
        _wait("analysis report", lambda: not _api("ce/component", component=NAME).get("queue")
              and _api("ce/component", component=NAME).get("current", {}).get("status") == "SUCCESS")

        rule_cwe = {r["key"]: cwe for cwe, q in CWE_QUERY.items()
                    for r in _pages("rules/search", "rules", languages="java", cwe=q, f="name")}
        rows = _pages("hotspots/search", "hotspots", projectKey=NAME) + \
            _pages("issues/search", "issues", componentKeys=NAME, types="VULNERABILITY")
    finally:
        subprocess.run(["docker", "rm", "-f", NAME], capture_output=True)
        subprocess.run(["docker", "network", "rm", NAME], capture_output=True)

    (proj / "sonarqube.json").write_text(json.dumps({"rules": rule_cwe, "rows": rows}), encoding="utf-8")
    issues = to_issues(rows, rule_cwe, project.snippet_ids(corpus))
    return aggregate_findings(corpus, TOOL, issues, cfg.cwes, elapsed_ms)


def run(cfg: Config, corpus: Sequence[Snippet]) -> dict[str, Path]:
    from vulnpipe.io import write_jsonl

    findings = run_sonarqube(cfg, corpus)
    out = cfg.ensure_path("findings") / f"{TOOL}_perSnippet.jsonl"
    write_jsonl(out, findings)
    print(f"[{TOOL}] {len(findings)} snippets, {sum(f.verdict == 1 for f in findings)} flagged vulnerable -> {out}")
    return {TOOL: out}
