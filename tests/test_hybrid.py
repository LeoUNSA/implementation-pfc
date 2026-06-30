import json

import vulnpipe.hybrid.run as hybrid_run
from vulnpipe.config import Config
from vulnpipe.hybrid.run import sast_candidates
from vulnpipe.schemas import SAFE, VULNERABLE, Finding, Snippet


def _cfg(tmp_path):
    return Config(
        root=tmp_path,
        raw={
            "cwes": ["89", "22"],
            "paths": {"corpus": "corpus", "findings": "findings"},
            "corpus": {}, "metrics": {},
            "llm": {"temperature": 0.0, "runs_per_snippet": 3},
        },
    )


def test_sast_candidates_union_first_wins():
    findings = [
        Finding("a", "pmd-custom", VULNERABLE, cwe="89", line=3),
        Finding("a", "semgrep", VULNERABLE, cwe="89", line=9),  # dup -> ignored
        Finding("b", "pmd-custom", SAFE),                        # not a candidate
        Finding("c", "semgrep", VULNERABLE, cwe="22", line=7),
    ]
    cand = sast_candidates(findings)
    assert set(cand) == {"a", "c"}
    assert cand["a"].tool == "pmd-custom" and cand["a"].line == 3  # first seen wins
    assert cand["c"].cwe == "22"


def test_confirm_vote_tie_rejects():
    v = lambda x: __import__("vulnpipe.llm.base", fromlist=["Verdict"]).Verdict(verdict=x)
    assert hybrid_run._confirm_vote([v(1), v(1), v(0)]) == VULNERABLE
    assert hybrid_run._confirm_vote([v(1), v(0)]) == SAFE  # tie -> reject (strict >)
    assert hybrid_run._confirm_vote([v(0), v(0)]) == SAFE


def test_tool_name_encodes_config():
    name = hybrid_run._tool_name(["semgrep", "pmd-custom"], "deepseek-coder:6.7b", "reject")
    assert name == "hybrid__pmd-custom+semgrep__deepseek-coder_6.7b__reject"


class _FakeBackend:
    """Confirms (verdict vulnerable) iff the snippet code mentions executeQuery."""

    def __init__(self, model, host=None, temperature=0.0, **kw):
        self.name = model

    def generate(self, prompt, force_json=True):
        from vulnpipe.llm.ollama import GenResult

        confirm = "executequery" in prompt.lower()
        body = json.dumps({"decision": "confirm" if confirm else "reject"})
        return GenResult(text=body, tokens_in=8, tokens_out=4, elapsed_ms=2.0)


def test_reject_scope_prunes_false_positive(tmp_path, monkeypatch):
    monkeypatch.setattr(hybrid_run, "OllamaBackend", _FakeBackend)
    cfg = _cfg(tmp_path)
    corpus = [
        Snippet("a", "89", VULNERABLE, "x.executeQuery(q);", "a.java"),  # real, SAST flags -> confirmed
        Snippet("b", "89", SAFE, "int x = 1;", "b.java"),                # FP, SAST flags -> pruned
        Snippet("c", "89", VULNERABLE, "y.executeQuery(z);", "c.java"),  # real, SAST misses -> stays safe (reject)
    ]
    sast = [
        Finding("a", "pmd-custom", VULNERABLE, cwe="89", line=1),
        Finding("b", "pmd-custom", VULNERABLE, cwe="89", line=1),  # false positive
    ]
    out = hybrid_run.run(cfg, corpus, sast, model="fake:1b", scope="reject")
    by = {r["snippet_id"]: r for r in (json.loads(l) for l in out.read_text().splitlines())}
    assert by["a"]["verdict"] == VULNERABLE          # confirmed
    assert by["b"]["verdict"] == SAFE                # pruned FP
    assert by["c"]["verdict"] == SAFE                # never seen by LLM in reject scope
    assert by["a"]["tool"] == "hybrid__pmd-custom__fake_1b__reject"
    assert by["c"]["explanation"] == "no SAST candidate"


def test_augment_scope_recovers_sast_negative(tmp_path, monkeypatch):
    monkeypatch.setattr(hybrid_run, "OllamaBackend", _FakeBackend)
    cfg = _cfg(tmp_path)
    corpus = [
        Snippet("c", "89", VULNERABLE, "y.executeQuery(z);", "c.java"),  # SAST misses; augment catches it
    ]
    out = hybrid_run.run(cfg, corpus, [], model="fake:1b", scope="augment")
    by = {r["snippet_id"]: r for r in (json.loads(l) for l in out.read_text().splitlines())}
    assert by["c"]["verdict"] == VULNERABLE          # cold zero-shot recovered it
    assert by["c"]["tool"] == "hybrid____fake_1b__augment"
