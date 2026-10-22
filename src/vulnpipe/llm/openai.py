"""OpenAI backend (GPT-4o-mini) behind the same ``generate`` contract as Ollama.

Uses the Chat Completions endpoint through ``urllib`` (no SDK dependency).
The key comes from ``OPENAI_API_KEY``. ``force_json`` maps to
``response_format: json_object``; our prompts already mention JSON, which that
mode requires. Token counts are recorded so the dollar cost can be computed
afterwards from the published price.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

from vulnpipe.llm.ollama import DEFAULT_HOST, GenResult, OllamaBackend

API_URL = "https://api.openai.com/v1/chat/completions"
_RETRYABLE = {429, 500, 502, 503, 504}


def is_openai_model(model: str) -> bool:
    return model.startswith(("gpt-", "o1", "o3", "o4"))


class OpenAIBackend:
    def __init__(self, model: str, temperature: float = 0.0, max_tokens: int = 512,
                 api_key: str | None = None, timeout: int = 120, retries: int = 5) -> None:
        self.model = model
        self.name = model
        self.temperature = temperature
        self.max_tokens = max_tokens  # same budget as Ollama's num_predict
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.timeout = timeout
        self.retries = retries

    def generate(self, prompt: str, force_json: bool = True) -> GenResult:
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "seed": 42,
        }
        if force_json:
            payload["response_format"] = {"type": "json_object"}
        req = urllib.request.Request(
            API_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.api_key}"},
            method="POST",
        )
        for attempt in range(self.retries):
            start = time.perf_counter()
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
                break
            except urllib.error.HTTPError as e:
                if e.code not in _RETRYABLE or attempt == self.retries - 1:
                    raise RuntimeError(f"OpenAI request failed: {e.code} {e.read()[:300]!r}") from e
                time.sleep(2 ** attempt)
        usage = body.get("usage", {})
        return GenResult(
            text=body["choices"][0]["message"]["content"] or "",
            tokens_in=usage.get("prompt_tokens"),
            tokens_out=usage.get("completion_tokens"),
            elapsed_ms=(time.perf_counter() - start) * 1000.0,
        )

    def complete(self, prompt: str) -> str:
        return self.generate(prompt, force_json=False).text


def backend_for(model: str, host: str = DEFAULT_HOST, temperature: float = 0.0):
    """OpenAI for ``gpt-*``/``o*`` models, the local Ollama server otherwise."""
    if is_openai_model(model):
        return OpenAIBackend(model, temperature=temperature)
    return OllamaBackend(model, host=host, temperature=temperature)
