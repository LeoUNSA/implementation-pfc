"""Join detector findings to ground truth and derive confusion counts.

Every ``*_perSnippet.jsonl`` file has at most one row per (snippet, tool).
This module joins those rows to the corpus ground truth on ``snippet_id``
and produces TP/FP/TN/FN per tool — the input to ``compute``.

A snippet absent from a tool's findings is treated as a **negative**
verdict (the detector did not flag it), so recall is not silently inflated
by missing rows.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from vulnpipe.metrics.compute import Confusion
from vulnpipe.schemas import VULNERABLE, Finding, Snippet


def _truth_map(corpus: Iterable[Snippet]) -> dict[str, int]:
    truth: dict[str, int] = {}
    for s in corpus:
        if s.snippet_id in truth and truth[s.snippet_id] != s.label:
            raise ValueError(
                f"conflicting ground-truth labels for snippet {s.snippet_id!r}"
            )
        truth[s.snippet_id] = s.label
    return truth


def join_to_truth(
    findings: Iterable[Finding], corpus: Iterable[Snippet]
) -> dict[str, dict[str, int]]:
    """Return ``{tool: {snippet_id: verdict}}`` restricted to known snippets.

    Findings whose ``snippet_id`` is not in the corpus are dropped (a
    detector cannot be scored on a snippet with no ground truth).
    """
    truth = _truth_map(corpus)
    by_tool: dict[str, dict[str, int]] = defaultdict(dict)
    for f in findings:
        if f.snippet_id in truth:
            by_tool[f.tool][f.snippet_id] = f.verdict
    return dict(by_tool)


def confusion_by_tool(
    findings: Iterable[Finding], corpus: Iterable[Snippet]
) -> dict[str, Confusion]:
    """Compute a ``Confusion`` per tool over the full corpus.

    Missing (snippet, tool) verdicts default to negative (0).
    """
    corpus = list(corpus)
    truth = _truth_map(corpus)
    verdicts_by_tool = join_to_truth(findings, corpus)

    result: dict[str, Confusion] = {}
    for tool, verdicts in verdicts_by_tool.items():
        c = Confusion()
        for sid, gold in truth.items():
            pred = verdicts.get(sid, 0)  # not flagged -> negative
            if gold == VULNERABLE and pred == VULNERABLE:
                c.tp += 1
            elif gold != VULNERABLE and pred == VULNERABLE:
                c.fp += 1
            elif gold != VULNERABLE and pred != VULNERABLE:
                c.tn += 1
            else:
                c.fn += 1
        result[tool] = c
    return result
