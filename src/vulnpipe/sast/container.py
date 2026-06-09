"""Generic containerized SAST invocation + SARIF parsing.

Every SAST tool runs the same way: ``docker run --rm`` with the scan
directory bind-mounted, producing a SARIF report we parse into ``Issue``
records. This module factors out the docker plumbing and the SARIF reader
so each concrete runner (PMD now; CodeQL/SpotBugs/SonarQube later) only
supplies its image, command, and a rule→CWE mapping.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Sequence

from vulnpipe.schemas import Issue


class DockerNotAvailable(RuntimeError):
    pass


def ensure_docker() -> None:
    if shutil.which("docker") is None:
        raise DockerNotAvailable("docker not found on PATH")
    proc = subprocess.run(
        ["docker", "info"], capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise DockerNotAvailable("docker daemon not reachable; is it running?")


def run_container(
    image: str,
    args: Sequence[str],
    mounts: dict[Path, str],
    timeout: int = 1800,
) -> tuple[int, str, str, float]:
    """Run ``docker run --rm`` with bind mounts. Returns (rc, stdout, stderr,
    elapsed_ms). ``mounts`` maps host path → container path (mounted ro)."""
    ensure_docker()
    cmd = ["docker", "run", "--rm"]
    for host, container in mounts.items():
        cmd += ["-v", f"{Path(host).resolve()}:{container}"]
    cmd += [image, *args]

    start = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return proc.returncode, proc.stdout, proc.stderr, elapsed_ms


def parse_sarif(
    sarif_path: Path,
    tool: str,
    rule_cwe: dict[str, str],
    only_mapped: bool = True,
) -> list[Issue]:
    """Parse a SARIF report into ``Issue`` records.

    ``rule_cwe`` maps a SARIF ruleId to a canonical CWE. When ``only_mapped``
    (default), issues whose rule is not in the map are dropped — so a tool's
    unrelated rules (e.g. PMD's crypto rules) never inflate CWE-89/22 counts.
    The snippet_id is the SARIF artifact basename without ``.java``.
    """
    if not sarif_path.exists():
        return []
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    issues: list[Issue] = []

    for run in data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId") or ""
            cwe = rule_cwe.get(rule_id)
            if only_mapped and cwe is None:
                continue

            locs = result.get("locations", [])
            uri = None
            line = None
            if locs:
                phys = locs[0].get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri")
                line = phys.get("region", {}).get("startLine")
            if not uri:
                continue
            snippet_id = Path(uri).name
            if snippet_id.endswith(".java"):
                snippet_id = snippet_id[: -len(".java")]

            msg = result.get("message", {})
            issues.append(
                Issue(
                    snippet_id=snippet_id,
                    tool=tool,
                    rule_id=rule_id,
                    cwe=cwe,
                    line=int(line) if isinstance(line, int) else None,
                    severity=result.get("level"),
                    message=msg.get("text") if isinstance(msg, dict) else None,
                )
            )
    return issues
