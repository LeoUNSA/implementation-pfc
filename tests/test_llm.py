import json

from vulnpipe.config import Config
from vulnpipe.llm import run as llm_run
from vulnpipe.llm.base import Verdict, parse_verdict
from vulnpipe.schemas import SAFE, VULNERABLE, Snippet


def test_parse_verdict_json_and_keyword():
    assert parse_verdict('{"verdict": "vulnerable", "cwe": "89"}').verdict == VULNERABLE
    assert parse_verdict('prose... {"decision": "reject"}').verdict == SAFE
    assert parse_verdict("clearly vulnerable here").verdict == VULNERABLE
    assert parse_verdict("nothing conclusive").verdict == SAFE  # defaults safe


def test_vote_majority():
    v = lambda x: Verdict(verdict=x)
    assert llm_run._vote([v(1), v(1), v(0)]) == VULNERABLE
    assert llm_run._vote([v(1), v(0), v(0)]) == SAFE
    assert llm_run._vote([v(0), v(0)]) == SAFE
    assert llm_run._vote([v(1), v(1)]) == VULNERABLE  # tie -> vulnerable (n_vuln*2>=n)


def test_tool_name_sanitizes_model_tag():
    assert llm_run._tool_name("deepseek-coder:6.7b-instruct", "zero-shot") == \
        "deepseek-coder_6.7b-instruct__zero-shot"


def test_fewshot_examples_held_out():
    corpus = [
        Snippet("v1", "89", VULNERABLE, "CODE_VULN", "a.java"),
        Snippet("s1", "89", SAFE, "CODE_SAFE", "b.java"),
        Snippet("v2", "22", VULNERABLE, "CODE_OTHER", "c.java"),
    ]
    ex = llm_run._pick_fewshot_examples(corpus)
    assert len(ex) == 2
    held = llm_run._held_out(corpus, ex)
    # the two example snippets' code must not appear in the eval set
    assert all(s.code not in {c for c, _ in ex} for s in held)
    assert len(held) == 1 and held[0].snippet_id == "v2"


class _FakeBackend:
    """Returns 'vulnerable' iff the prompt mentions executeQuery — offline."""

    def __init__(self, model, host=None, temperature=0.0, **kw):
        self.name = model

    def generate(self, prompt, force_json=True):
        from vulnpipe.llm.ollama import GenResult

        vuln = "executequery" in prompt.lower()
        body = json.dumps({"verdict": "vulnerable" if vuln else "safe", "cwe": "89" if vuln else None})
        return GenResult(text=body, tokens_in=10, tokens_out=5, elapsed_ms=1.0)


def test_run_end_to_end_offline(tmp_path, monkeypatch):
    monkeypatch.setattr(llm_run, "OllamaBackend", _FakeBackend)
    cfg = Config(
        root=tmp_path,
        raw={
            "cwes": ["89", "22"],
            "paths": {"corpus": "corpus", "findings": "findings"},
            "corpus": {}, "metrics": {},
            "llm": {"temperature": 0.0, "runs_per_snippet": 3},
        },
    )
    corpus = [
        Snippet("a", "89", VULNERABLE, "x.executeQuery(q);", "a.java"),
        Snippet("b", "89", SAFE, "int x = 1;", "b.java"),
    ]
    out = llm_run.run(cfg, corpus, model="fake:1b", strategy="zero-shot")
    rows = [json.loads(l) for l in out.read_text().splitlines()]
    by = {r["snippet_id"]: r for r in rows}
    assert by["a"]["verdict"] == VULNERABLE and by["a"]["tool"] == "fake_1b__zero-shot"
    assert by["b"]["verdict"] == SAFE
    assert by["a"]["prompt_strategy"] == "zero-shot"
    # temp 0 collapses to a single run despite runs_per_snippet=3
    runs_file = tmp_path / "findings" / "llm_runs" / "fake_1b__zero-shot_runs.jsonl"
    run_rows = [json.loads(l) for l in runs_file.read_text().splitlines()]
    assert len(run_rows) == 2  # 2 snippets x 1 run
