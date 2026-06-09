"""The four prompting strategies evaluated in the thesis (propuesta §6.4).

Each builder returns a complete prompt string. ``static_augmented`` is the
core of the hybrid pipeline: it injects the SAST tool's alert into the
prompt so the LLM acts as a semantic confirmer rather than a cold detector.
"""

from __future__ import annotations

from typing import Optional, Sequence

_SYSTEM = (
    "You are a Java security auditor. Decide whether the snippet contains a "
    "SQL Injection (CWE-89) or Path Traversal (CWE-22) vulnerability."
)

_JSON_SPEC = (
    'Respond ONLY with a JSON object:\n'
    '{ "verdict": "vulnerable" | "safe", "cwe": "89" | "22" | null, '
    '"line": <int or null>, "reason": "<short justification>" }'
)


def zero_shot(code: str) -> str:
    return f"{_SYSTEM}\n\n{_JSON_SPEC}\n\nCODE:\n{code}"


def cot(code: str) -> str:
    return (
        f"{_SYSTEM}\n\nReason step by step before concluding, then "
        f"give your final answer.\n\n{_JSON_SPEC}\n\nCODE:\n{code}"
    )


def few_shot(code: str, examples: Sequence[tuple[str, str]]) -> str:
    """``examples`` is a sequence of (example_code, json_answer) pairs drawn
    from the train split (typically one safe, one vulnerable)."""
    shots = "\n\n".join(
        f"CODE:\n{ex_code}\nANSWER:\n{ex_answer}" for ex_code, ex_answer in examples
    )
    return f"{_SYSTEM}\n\n{_JSON_SPEC}\n\n{shots}\n\nCODE:\n{code}"


def static_augmented(
    code: str, tool: str, cwe: str, line: Optional[int]
) -> str:
    """Hybrid core: confirm/reject a specific SAST alert."""
    where = f"line {line}" if line is not None else "this code"
    return (
        f"{tool} flagged a possible CWE-{cwe} at {where} of the following "
        f"code. Confirm or reject the finding.\n\n"
        f'Respond ONLY with JSON:\n'
        f'{{ "decision": "confirm" | "reject", "reason": "..." }}\n\n'
        f"CODE:\n{code}"
    )


BUILDERS = {
    "zero-shot": zero_shot,
    "cot": cot,
    "few-shot": few_shot,
    "static-augmented": static_augmented,
}
