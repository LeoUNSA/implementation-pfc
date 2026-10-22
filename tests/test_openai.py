import io
import json

from vulnpipe.llm import openai as oa
from vulnpipe.llm.ollama import OllamaBackend


def test_backend_for_routes_by_model_name():
    assert isinstance(oa.backend_for("gpt-4o-mini"), oa.OpenAIBackend)
    assert isinstance(oa.backend_for("deepseek-coder:6.7b-instruct"), OllamaBackend)


def test_generate_sends_json_mode_and_reads_usage(monkeypatch):
    sent = {}

    def fake_urlopen(req, timeout):
        sent.update(json.loads(req.data))
        body = {"choices": [{"message": {"content": '{"verdict": "safe"}'}}],
                "usage": {"prompt_tokens": 120, "completion_tokens": 9}}
        return io.BytesIO(json.dumps(body).encode())

    monkeypatch.setattr(oa.urllib.request, "urlopen", fake_urlopen)
    gen = oa.OpenAIBackend("gpt-4o-mini", api_key="k").generate("Respond in JSON")

    assert sent["response_format"] == {"type": "json_object"}
    assert sent["temperature"] == 0.0
    assert gen.text == '{"verdict": "safe"}'
    assert (gen.tokens_in, gen.tokens_out) == (120, 9)
