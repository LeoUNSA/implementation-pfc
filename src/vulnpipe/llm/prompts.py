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


_CWE_NAME = {"89": "SQL Injection", "22": "Path Traversal"}


def trace_confirm(code: str, cwe: str, trace: dict[str, list[int]], hints: bool = True) -> str:
    """Hybrid core with the alert's dataflow trace and line-numbered code.

    The trace only covers the lines on the tainted path; the full code stays
    in the prompt because what makes an alert false (a branch that overwrites
    the value, a sanitizer) is usually off that path. ``analysis`` comes
    before ``verdict`` so the model reasons before it commits. ``hints=False``
    drops the list of typical false-alarm causes (ablation).
    """
    lines = code.splitlines()
    numbered = "\n".join(f"{i:>3}: {l}" for i, l in enumerate(lines, 1))

    def show(ns: list[int]) -> str:
        return "\n".join(f"  {n}: {lines[n - 1].strip()}" for n in ns if 0 < n <= len(lines))

    return (
        f"{_SYSTEM}\n\n"
        f"A taint analyzer reported a possible CWE-{cwe} ({_CWE_NAME.get(cwe, '')}) "
        f"in the code below. Its reported path is:\n"
        f"Source:\n{show(trace['source'])}\n"
        f"Through:\n{show(trace['steps'])}\n"
        f"Sink:\n{show(trace['sink'])}\n\n"
        "Taint analyzers report many false alarms. Follow the value that "
        "actually arrives at the sink at run time"
        + (": it may be replaced by a constant, chosen by a condition whose "
           "outcome is fixed, sanitized, or taken from a different element "
           "than the tainted one" if hints else "")
        + '. Answer "vulnerable" only if user-controlled data reaches the sink '
        "unsanitized.\n\n"
        "Respond ONLY with a JSON object:\n"
        '{ "analysis": "<2-3 sentences: which value reaches the sink and why>", '
        '"verdict": "vulnerable" | "safe" }\n\n'
        f"CODE:\n{numbered}"
    )


BUILDERS = {
    "zero-shot": zero_shot,
    "cot": cot,
    "few-shot": few_shot,
    "static-augmented": static_augmented,
}
