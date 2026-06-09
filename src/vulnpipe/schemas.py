"""The unifying contract.

Two record types flow through the entire pipeline:

* ``Snippet`` — one labelled code fragment from the corpus. The *only*
  carrier of ground truth. Produced by ``vulnpipe.corpus``.
* ``Finding`` — one detector's verdict on one snippet. Every detector
  family (SAST, LLM, CodeBERT, hybrid) is coerced into emitting this same
  record so the metrics stage can compare them apples-to-apples.

These field names are the immutable contract — see ``pipeline_outputs.md``
§0. Both types round-trip through JSONL via ``vulnpipe.io``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from typing import Any, Optional

# Verdict / label convention shared by every record in the pipeline.
VULNERABLE = 1
SAFE = 0


def _coerce(cls: type, row: dict[str, Any]) -> dict[str, Any]:
    """Keep only keys that are declared fields of ``cls``.

    Tolerates extra columns from heterogeneous JSONL sources without
    raising, so a Finding file with detector-specific extras still loads.
    """
    known = {f.name for f in fields(cls)}
    return {k: v for k, v in row.items() if k in known}


@dataclass
class Snippet:
    """A labelled code fragment — the ground-truth unit.

    ``label`` is the gold standard (1 = vulnerable, 0 = safe). ``line`` is
    1-based and optional (None for snippet-level labels with no single
    offending line).
    """

    snippet_id: str
    cwe: str
    label: int
    code: str
    file: str
    line: Optional[int] = None

    def __post_init__(self) -> None:
        if self.label not in (SAFE, VULNERABLE):
            raise ValueError(f"label must be 0 or 1, got {self.label!r}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, row: dict[str, Any]) -> "Snippet":
        return cls(**_coerce(cls, row))


@dataclass
class Finding:
    """One detector's binary verdict on one snippet.

    ``verdict`` (1/0) is the single field every downstream metric depends
    on. Everything else is an optional extra that some detectors provide
    and others leave None:

    * ``cwe``, ``line``, ``rule_id`` — localisation / provenance.
    * ``confidence`` — 0..1, e.g. CodeBERT softmax.
    * ``explanation`` — free text, kept for qualitative analysis only.
    * ``elapsed_ms`` — wall-clock, for the CI/CD-realism metric.
    * ``tokens_in`` / ``tokens_out`` / ``cost_usd`` — LLM economics.
    * ``prompt_strategy`` / ``run_idx`` — LLM run bookkeeping (run_idx is
      1..N for majority voting).
    """

    snippet_id: str
    tool: str
    verdict: int
    cwe: Optional[str] = None
    line: Optional[int] = None
    rule_id: Optional[str] = None
    confidence: Optional[float] = None
    explanation: Optional[str] = None
    elapsed_ms: Optional[float] = None
    tokens_in: Optional[int] = None
    tokens_out: Optional[int] = None
    cost_usd: Optional[float] = None
    prompt_strategy: Optional[str] = None
    run_idx: Optional[int] = None

    def __post_init__(self) -> None:
        if self.verdict not in (SAFE, VULNERABLE):
            raise ValueError(f"verdict must be 0 or 1, got {self.verdict!r}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, row: dict[str, Any]) -> "Finding":
        return cls(**_coerce(cls, row))


@dataclass
class Issue:
    """A *raw* SAST issue, pre-aggregation (one row per emitted alert).

    SAST tools natively emit a list of these; ``vulnpipe.sast.base``
    aggregates them into a per-snippet ``Finding``. Kept distinct from
    ``Finding`` because one snippet may carry several issues.
    """

    snippet_id: str
    tool: str
    rule_id: str
    cwe: Optional[str] = None
    line: Optional[int] = None
    severity: Optional[str] = None
    message: Optional[str] = None
    elapsed_ms: Optional[float] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, row: dict[str, Any]) -> "Issue":
        return cls(**_coerce(cls, row))
