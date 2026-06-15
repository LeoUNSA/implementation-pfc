"""Ollama backend — local generative models behind the ``LLMBackend`` contract.

Talks to a running ``ollama serve`` (default ``http://localhost:11434``) via
the ``/api/generate`` endpoint. ``complete`` satisfies the protocol (text in,
text out); ``generate`` returns the richer ``GenResult`` the runner needs to
fill a ``Finding``'s economics (token counts + wall-clock). Cost is always
None — these models run locally and are free.

``force_json`` sets Ollama's ``format: "json"`` constraint so the model is
guaranteed to emit parseable JSON; the runner disables it for chain-of-thought
prompts that must emit prose reasoning before the JSON answer.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

DEFAULT_HOST = "http://localhost:11434"


@dataclass
class GenResult:
    text: str
    tokens_in: Optional[int] = None
    tokens_out: Optional[int] = None
    elapsed_ms: Optional[float] = None


class OllamaError(RuntimeError):
    pass


class OllamaBackend:
    """One pinned local model served by Ollama."""

    def __init__(
        self,
        model: str,
        host: str = DEFAULT_HOST,
        temperature: float = 0.0,
        num_predict: int = 512,
        timeout: int = 300,
    ) -> None:
        self.model = model
        self.name = model
        self.host = host.rstrip("/")
        self.temperature = temperature
        self.num_predict = num_predict
        self.timeout = timeout

    def generate(self, prompt: str, force_json: bool = True) -> GenResult:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": self.num_predict,
            },
        }
        if force_json:
            payload["format"] = "json"

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.host}/api/generate",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as e:
            raise OllamaError(
                f"Ollama request failed for model {self.model!r}: {e}. "
                f"Is `ollama serve` running and the model pulled?"
            ) from e

        # total_duration is nanoseconds; convert to ms.
        dur_ns = body.get("total_duration")
        elapsed_ms = dur_ns / 1e6 if isinstance(dur_ns, (int, float)) else None
        return GenResult(
            text=body.get("response", ""),
            tokens_in=body.get("prompt_eval_count"),
            tokens_out=body.get("eval_count"),
            elapsed_ms=elapsed_ms,
        )

    def complete(self, prompt: str) -> str:
        return self.generate(prompt, force_json=False).text


def is_available(host: str = DEFAULT_HOST, timeout: int = 5) -> bool:
    """True if an Ollama server answers at ``host``."""
    try:
        with urllib.request.urlopen(f"{host.rstrip('/')}/api/version", timeout=timeout):
            return True
    except urllib.error.URLError:
        return False


def installed_models(host: str = DEFAULT_HOST, timeout: int = 5) -> list[str]:
    """Names of models the server has pulled (``/api/tags``)."""
    try:
        with urllib.request.urlopen(f"{host.rstrip('/')}/api/tags", timeout=timeout) as r:
            tags = json.loads(r.read().decode("utf-8"))
    except urllib.error.URLError:
        return []
    return [m.get("name", "") for m in tags.get("models", [])]
