"""LLM layer. Interface + prompt templates + deterministic mock this
increment; real local Ollama backends (DeepSeekCoder, CodeLlama) wired
when models are pulled."""

from vulnpipe.llm.base import LLMBackend, Verdict, parse_verdict
from vulnpipe.llm.mock import MockBackend
from vulnpipe.llm import prompts

__all__ = ["LLMBackend", "Verdict", "parse_verdict", "MockBackend", "prompts"]
