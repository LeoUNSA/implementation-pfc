"""Semgrep SAST runner (containerized, taint mode).

The deliberate counterpart to ``sast.pmd``. PMD's custom ruleset is purely
syntactic (no dataflow), which over-approximates and yields a high false
positive rate. Semgrep runs the *same sink set* in **taint mode**: a sink is
reported only when an untrusted source reaches it and no sanitizer
intervenes (``rulesets/semgrep_cwe89_cwe22.yml``). Comparing the two isolates
the contribution of dataflow analysis to precision / FPR.

Reuses all of ``sast.container`` and ``sast.materialize``: one ``.java`` per
snippet, one Semgrep run over the directory, SARIF parsed and aggregated to
one ``Finding`` per snippet via the shared ``sast.base`` rule.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from vulnpipe.config import Config
from vulnpipe.sast import container
from vulnpipe.sast.materialize import build_source_index, materialize
from vulnpipe.sast.pmd import aggregate_findings  # shared per-snippet aggregator
from vulnpipe.schemas import Finding, Snippet

DEFAULT_IMAGE = "semgrep/semgrep:1.103.0"
TOOL = "semgrep"
RULESET_CONTAINER_PATH = "/rules/semgrep_cwe89_cwe22.yml"

# Semgrep namespaces a single-file ruleset's ids under ``rules.`` in its
# SARIF output, so the SARIF ruleId is ``rules.<id>`` (not the bare ``id:``).
RULE_CWE: dict[str, str] = {
    "rules.sqli-taint-jdbc": "89",
    "rules.path-traversal-taint-file": "22",
}


def _image(cfg: Config) -> str:
    sast = cfg.raw.get("sast")
    if isinstance(sast, dict):
        return sast.get("semgrep", {}).get("image", DEFAULT_IMAGE)
    return DEFAULT_IMAGE


def run(cfg: Config, corpus: Sequence[Snippet]) -> dict[str, Path]:
    """Run Semgrep over the corpus, writing ``findings/semgrep_perSnippet.jsonl``.

    Returns ``{tool: path}`` (single entry) for symmetry with ``pmd.run``.
    """
    from vulnpipe.io import write_jsonl

    findings = run_semgrep(cfg, corpus)
    out = cfg.ensure_path("findings") / f"{TOOL}_perSnippet.jsonl"
    write_jsonl(out, findings)
    n_flag = sum(1 for f in findings if f.verdict == 1)
    print(f"[{TOOL}] {len(findings)} snippets, {n_flag} flagged vulnerable -> {out}")
    return {TOOL: out}


def run_semgrep(cfg: Config, corpus: Sequence[Snippet]) -> list[Finding]:
    """Materialize, scan with Semgrep, return one ``Finding`` per snippet."""
    image = _image(cfg)
    target_cwes = cfg.cwes

    scan_dir = cfg.ensure_path("findings") / "scan"
    source_index = build_source_index([cfg.path("data") / "juliet"])

    def resolve(s: Snippet) -> str | None:
        p = source_index.get(s.file)
        return p.read_text(encoding="utf-8", errors="replace") if p else None

    materialize(corpus, scan_dir, resolve_source=resolve)

    sarif_name = "semgrep.sarif"
    mounts = {scan_dir: "/src", cfg.root / "rulesets": "/rules:ro"}
    args = [
        "semgrep",  # image has no semgrep entrypoint; invoke the binary
        "scan",
        "--config", RULESET_CONTAINER_PATH,
        "--sarif",
        "--output", f"/src/{sarif_name}",
        "--metrics", "off",
        "--disable-version-check",
        "--quiet",
        "/src",
    ]
    rc, out, err, elapsed_ms = container.run_container(image, args, mounts)
    # Semgrep exit codes: 0 = ran (with or without findings, no --error),
    # 1 = blocking findings (only with --error, unused here), >=2 = error.
    if rc not in (0, 1):
        raise RuntimeError(
            f"Semgrep failed (rc={rc}).\nstdout:\n{out}\nstderr:\n{err}"
        )

    issues = container.parse_sarif(
        scan_dir / sarif_name, TOOL, RULE_CWE, only_mapped=True
    )
    return aggregate_findings(corpus, TOOL, issues, target_cwes, elapsed_ms)
