"""SAST runner interface and the issues→verdict aggregation rule.

A SAST tool natively emits a *list of issues* (file, line, rule), not a
per-snippet label. The pipeline converts that list to the binary contract
with one rule (``pipeline_outputs.md`` §2a):

    A snippet is flagged vulnerable iff the tool emits at least one issue
    inside it whose rule maps to one of the target CWEs.

Concrete runners (SonarQube via REST, CodeQL via SARIF, SpotBugs+
FindSecBugs via XML, PMD via XML) are deferred to a later increment; they
only need to implement ``SASTRunner`` and return ``Issue`` lists — the
aggregation here turns those into comparable ``Finding`` records.
"""

from __future__ import annotations

from typing import Iterable, Protocol, Sequence

from vulnpipe.schemas import SAFE, VULNERABLE, Finding, Issue, Snippet


class SASTRunner(Protocol):
    """Contract every concrete SAST tool must satisfy."""

    name: str

    def run(self, snippet: Snippet) -> list[Issue]:
        """Return the raw issues the tool emits for ``snippet`` (possibly empty)."""
        ...


def aggregate_to_finding(
    snippet_id: str,
    tool: str,
    issues: Sequence[Issue],
    target_cwes: Iterable[str],
    elapsed_ms: float | None = None,
) -> Finding:
    """Collapse a snippet's issues into one binary ``Finding``.

    Verdict is VULNERABLE iff ≥1 issue maps to a target CWE. Issues with no
    CWE are treated as relevant (a security ruleset hit), matching the
    conservative reading that any emitted security alert counts.
    """
    targets = {str(c) for c in target_cwes}
    relevant = [
        iss for iss in issues if iss.cwe is None or str(iss.cwe) in targets
    ]
    verdict = VULNERABLE if relevant else SAFE

    # Carry the first relevant issue's localisation/provenance, if any.
    rule_id = relevant[0].rule_id if relevant else None
    line = relevant[0].line if relevant else None
    cwe = next((iss.cwe for iss in relevant if iss.cwe), None)
    if elapsed_ms is None and issues:
        elapsed_ms = issues[0].elapsed_ms

    return Finding(
        snippet_id=snippet_id,
        tool=tool,
        verdict=verdict,
        cwe=cwe,
        line=line,
        rule_id=rule_id,
        explanation=relevant[0].message if relevant else None,
        elapsed_ms=elapsed_ms,
    )
