"""Deterministic mock LLM backend.

Lets the LLM phase and its tests run with no model installed. Its verdict
is a fixed function of the prompt text (a keyword heuristic), so the same
prompt always yields the same answer — reproducible, free, offline. Real
backends (Ollama for DeepSeekCoder / CodeLlama, OpenAI) replace it later
behind the same ``LLMBackend`` interface.
"""

from __future__ import annotations

import json

# Tokens that, if present in the snippet, the mock treats as vulnerable.
# Chosen to fire on the obvious sink patterns in the target CWEs.
_VULN_HINTS = (
    "executeQuery",
    "executeUpdate",
    "createStatement",
    "Statement",
    '"select ',
    "select * from",
    "new File(",
    "FileInputStream",
    "FileReader",
    "../",
)


class MockBackend:
    name = "mock-llm"

    def complete(self, prompt: str) -> str:
        low = prompt.lower()
        vulnerable = any(h.lower() in low for h in _VULN_HINTS)
        # Honour both the detection spec and the confirm/reject spec.
        if "confirm" in low and "reject" in low:
            decision = "confirm" if vulnerable else "reject"
            return json.dumps({"decision": decision, "reason": "mock heuristic"})
        verdict = "vulnerable" if vulnerable else "safe"
        return json.dumps(
            {"verdict": verdict, "cwe": None, "line": None, "reason": "mock heuristic"}
        )
