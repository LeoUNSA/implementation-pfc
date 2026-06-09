"""LLM backend interface and structured-verdict parsing.

A generative model returns free-form text. The pipeline forces a
structured JSON answer (``pipeline_outputs.md`` §2b) and parses it into a
``Verdict`` carrying the binary label plus economics. ``parse_verdict`` is
deliberately lenient: real model output often wraps JSON in prose or
fences, so it extracts the first balanced ``{...}`` block before parsing.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Optional, Protocol

from vulnpipe.schemas import SAFE, VULNERABLE


@dataclass
class Verdict:
    """A parsed model answer for one (snippet, prompt) call."""

    verdict: int                       # 1 vulnerable / 0 safe
    cwe: Optional[str] = None
    line: Optional[int] = None
    reason: Optional[str] = None
    tokens_in: Optional[int] = None
    tokens_out: Optional[int] = None
    elapsed_ms: Optional[float] = None
    cost_usd: Optional[float] = None
    raw: Optional[str] = None          # original text, kept for auditing


class LLMBackend(Protocol):
    """Contract every concrete model backend must satisfy."""

    name: str

    def complete(self, prompt: str) -> str:
        """Return the model's raw text response to ``prompt``."""
        ...


_VULN_WORDS = {"vulnerable", "vuln", "yes", "true", "confirm", "1"}
_SAFE_WORDS = {"safe", "secure", "no", "false", "reject", "0", "none"}


def _first_json_object(text: str) -> Optional[dict]:
    """Extract and parse the first balanced ``{...}`` block in ``text``."""
    start = text.find("{")
    while start != -1:
        depth = 0
        for i in range(start, len(text)):
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start : i + 1])
                    except json.JSONDecodeError:
                        break
        start = text.find("{", start + 1)
    return None


def _label_from_str(s: str) -> Optional[int]:
    s = s.strip().lower()
    if s in _VULN_WORDS:
        return VULNERABLE
    if s in _SAFE_WORDS:
        return SAFE
    return None


def parse_verdict(text: str) -> Verdict:
    """Parse a model response into a ``Verdict``.

    Tries structured JSON first (keys ``verdict``/``decision``), then falls
    back to scanning the text for an affirmative/negative keyword. Defaults
    to SAFE when nothing parses — a non-committal model is not a detection.
    """
    obj = _first_json_object(text)
    if obj is not None:
        label = None
        for key in ("verdict", "decision", "label", "answer"):
            if key in obj:
                val = obj[key]
                label = val if isinstance(val, int) else _label_from_str(str(val))
                break
        if label is None:
            label = SAFE
        line = obj.get("line")
        return Verdict(
            verdict=label,
            cwe=str(obj["cwe"]) if obj.get("cwe") not in (None, "null") else None,
            line=int(line) if isinstance(line, int) else None,
            reason=obj.get("reason") or obj.get("explanation"),
            raw=text,
        )

    # No JSON — keyword fallback over the whole response.
    low = text.lower()
    if any(re.search(rf"\b{re.escape(w)}\b", low) for w in _VULN_WORDS):
        return Verdict(verdict=VULNERABLE, raw=text)
    return Verdict(verdict=SAFE, raw=text)
