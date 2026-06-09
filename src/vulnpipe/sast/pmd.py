"""PMD SAST runner (containerized).

Two variants, sharing all plumbing:

* ``pmd-vanilla`` — PMD's built-in ``category/java/security.xml``. PMD has
  no taint engine and that ruleset targets only crypto, so recall on
  CWE-89/22 is ~0. Run to honestly quantify the coverage gap.
* ``pmd-custom`` — our hand-authored syntactic ruleset
  (``rulesets/pmd_cwe89_cwe22.xml``). Over-approximates, illustrating the
  high-false-positive SAST failure mode the hybrid stage mitigates.

Both materialize the corpus to one ``.java`` per snippet, run PMD once over
the directory, parse the SARIF report, and aggregate to one ``Finding`` per
snippet via the shared ``sast.base`` rule.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from vulnpipe.config import Config
from vulnpipe.sast import container
from vulnpipe.sast.base import aggregate_to_finding
from vulnpipe.sast.materialize import build_source_index, materialize
from vulnpipe.schemas import Finding, Issue, Snippet

DEFAULT_IMAGE = "pmdcode/pmd:7.25.0"


@dataclass(frozen=True)
class PmdVariant:
    tool: str
    ruleset: str            # path inside the container
    rule_cwe: dict[str, str]
    needs_rules_mount: bool  # whether to bind-mount our rulesets dir


VARIANTS: dict[str, PmdVariant] = {
    "vanilla": PmdVariant(
        tool="pmd-vanilla",
        ruleset="category/java/security.xml",  # built-in classpath resource
        rule_cwe={},                            # no built-in rule maps to 89/22
        needs_rules_mount=False,
    ),
    "custom": PmdVariant(
        tool="pmd-custom",
        ruleset="/rules/pmd_cwe89_cwe22.xml",
        rule_cwe={
            "SqlInjectionConcatExec": "89",
            "PathTraversalFileSink": "22",
        },
        needs_rules_mount=True,
    ),
}


def _image(cfg: Config) -> str:
    return (
        cfg.raw.get("sast", {}).get("pmd", {}).get("image", DEFAULT_IMAGE)
        if isinstance(cfg.raw.get("sast"), dict)
        else DEFAULT_IMAGE
    )


def run_variant(
    cfg: Config,
    corpus: Sequence[Snippet],
    variant_key: str,
) -> list[Finding]:
    """Materialize, scan with one PMD variant, and return per-snippet findings."""
    variant = VARIANTS[variant_key]
    target_cwes = cfg.cwes
    image = _image(cfg)

    scan_dir = cfg.ensure_path("findings") / "scan"
    # Resolve each snippet to its original (balanced) Juliet source for
    # reliable method extraction; falls back to the slice when absent.
    source_index = build_source_index([cfg.path("data") / "juliet"])

    def resolve(s: Snippet) -> str | None:
        p = source_index.get(s.file)
        return p.read_text(encoding="utf-8", errors="replace") if p else None

    materialize(corpus, scan_dir, resolve_source=resolve)

    sarif_name = f"pmd_{variant_key}.sarif"
    mounts = {scan_dir: "/src"}
    if variant.needs_rules_mount:
        mounts[cfg.root / "rulesets"] = "/rules:ro"

    args = [
        "check",
        "-d", "/src",
        "-R", variant.ruleset,
        "-f", "sarif",
        "-r", f"/src/{sarif_name}",
        "--no-fail-on-violation",
        "--no-progress",
        "--no-cache",
    ]
    rc, out, err, elapsed_ms = container.run_container(image, args, mounts)
    # PMD exit codes: 0 = clean, 4 = violations found, 5 = recoverable
    # processing errors (some files failed to parse but the run completed),
    # 1/2 = usage/config error.
    if rc not in (0, 4, 5):
        raise RuntimeError(
            f"PMD ({variant.tool}) failed (rc={rc}).\nstdout:\n{out}\nstderr:\n{err}"
        )
    if rc == 5:
        print(f"[{variant.tool}] warning: PMD reported recoverable parse "
              f"errors on some files (they default to a safe verdict).")

    issues = container.parse_sarif(
        scan_dir / sarif_name, variant.tool, variant.rule_cwe, only_mapped=True
    )

    return aggregate_findings(corpus, variant.tool, issues, target_cwes, elapsed_ms)


def aggregate_findings(
    corpus: Sequence[Snippet],
    tool: str,
    issues: Sequence[Issue],
    target_cwes: Sequence[str],
    elapsed_ms: float | None = None,
) -> list[Finding]:
    """One ``Finding`` per corpus snippet (snippets with no issue → safe).

    ``elapsed_ms`` (total batch wall-clock) is attached to every finding so
    the CI/CD-realism metric has a per-tool timing.
    """
    by_snippet: dict[str, list[Issue]] = {}
    for iss in issues:
        by_snippet.setdefault(iss.snippet_id, []).append(iss)

    findings: list[Finding] = []
    for s in corpus:
        f = aggregate_to_finding(
            s.snippet_id, tool, by_snippet.get(s.snippet_id, []), target_cwes
        )
        f.elapsed_ms = elapsed_ms
        findings.append(f)
    return findings


def run(cfg: Config, corpus: Sequence[Snippet], variant: str = "both") -> dict[str, Path]:
    """Run the requested PMD variant(s), writing ``findings/<tool>_perSnippet.jsonl``.

    ``variant`` is "vanilla", "custom", or "both". Returns ``{tool: path}``.
    """
    from vulnpipe.io import write_jsonl

    keys = ("vanilla", "custom") if variant == "both" else (variant,)
    findings_dir = cfg.ensure_path("findings")
    written: dict[str, Path] = {}

    for key in keys:
        findings = run_variant(cfg, corpus, key)
        tool = VARIANTS[key].tool
        out = findings_dir / f"{tool}_perSnippet.jsonl"
        write_jsonl(out, findings)
        n_flag = sum(1 for f in findings if f.verdict == 1)
        print(f"[{tool}] {len(findings)} snippets, {n_flag} flagged vulnerable -> {out}")
        written[tool] = out

    return written
