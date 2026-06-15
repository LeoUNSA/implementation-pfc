"""LLM detection runner — drive a local model over the corpus.

For each snippet: build a prompt (one of the direct-detection strategies),
query the model ``runs`` times, parse each response into a ``Verdict``, and
**majority-vote** them into one per-snippet ``Finding`` (the metrics input).
The raw per-run findings are also written for self-consistency analysis.

Strategies handled here are the *cold-detector* ones: ``zero-shot``, ``cot``,
``few-shot``. The ``static-augmented`` strategy is the hybrid pipeline (it
needs a SAST alert as input) and lives in its own phase, not here.

Token counts and wall-clock come straight from the Ollama response; cost is
None (local model). The ``tool`` field encodes model + strategy so the metrics
stage treats each (model, strategy) pair as its own detector.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Sequence

from vulnpipe.config import Config
from vulnpipe.llm import prompts
from vulnpipe.llm.base import Verdict, parse_verdict
from vulnpipe.llm.ollama import OllamaBackend
from vulnpipe.schemas import SAFE, VULNERABLE, Finding, Snippet

# Strategies this runner can drive directly (static-augmented = hybrid phase).
DIRECT_STRATEGIES = ("zero-shot", "cot", "few-shot")
# Chain-of-thought must emit prose before JSON, so JSON-mode is disabled for it.
_FORCE_JSON = {"zero-shot": True, "cot": False, "few-shot": True}


def _tool_name(model: str, strategy: str) -> str:
    safe = model.replace(":", "_").replace("/", "_")
    return f"{safe}__{strategy}"


def _build_prompt(
    strategy: str, code: str, examples: Sequence[tuple[str, str]]
) -> str:
    if strategy == "few-shot":
        return prompts.few_shot(code, examples)
    return prompts.BUILDERS[strategy](code)


def _pick_fewshot_examples(corpus: Sequence[Snippet]) -> list[tuple[str, str]]:
    """One vulnerable + one safe snippet as in-context shots.

    Drawn deterministically (first of each class) so the choice is
    reproducible; callers exclude them from the eval set via ``_held_out``.
    """
    vuln = next((s for s in corpus if s.label == VULNERABLE), None)
    safe = next((s for s in corpus if s.label == SAFE), None)
    shots: list[tuple[str, str]] = []
    if vuln:
        shots.append((vuln.code, '{ "verdict": "vulnerable", "cwe": "%s", "line": null, "reason": "example" }' % vuln.cwe))
    if safe:
        shots.append((safe.code, '{ "verdict": "safe", "cwe": null, "line": null, "reason": "example" }'))
    return shots


def _held_out(corpus: Sequence[Snippet], examples: Sequence[tuple[str, str]]) -> list[Snippet]:
    ex_code = {c for c, _ in examples}
    return [s for s in corpus if s.code not in ex_code]


def _vote(verdicts: Sequence[Verdict]) -> int:
    n_vuln = sum(1 for v in verdicts if v.verdict == VULNERABLE)
    return VULNERABLE if n_vuln * 2 >= len(verdicts) and n_vuln > 0 else SAFE


def run(
    cfg: Config,
    corpus: Sequence[Snippet],
    model: str,
    strategy: str = "zero-shot",
    runs: Optional[int] = None,
    temperature: Optional[float] = None,
    limit: Optional[int] = None,
    host: str = "http://localhost:11434",
) -> Path:
    """Run one (model, strategy) over the corpus → ``findings/<tool>_perSnippet.jsonl``."""
    from vulnpipe.io import write_jsonl

    if strategy not in DIRECT_STRATEGIES:
        raise ValueError(
            f"strategy {strategy!r} not a direct-detection strategy "
            f"(static-augmented is the hybrid phase). Choose from {DIRECT_STRATEGIES}."
        )

    llm_cfg = cfg.llm_cfg
    temp = temperature if temperature is not None else float(llm_cfg.get("temperature", 0.0))
    # Multiple runs only differ when temperature > 0; collapse to 1 otherwise.
    cfg_runs = int(runs if runs is not None else llm_cfg.get("runs_per_snippet", 1))
    n_runs = cfg_runs if temp > 0 else 1

    backend = OllamaBackend(model, host=host, temperature=temp)
    tool = _tool_name(model, strategy)

    examples: list[tuple[str, str]] = []
    eval_set = list(corpus)
    if strategy == "few-shot":
        examples = _pick_fewshot_examples(corpus)
        eval_set = _held_out(corpus, examples)
    if limit is not None:
        eval_set = eval_set[:limit]

    force_json = _FORCE_JSON[strategy]
    per_snippet: list[Finding] = []
    per_run: list[Finding] = []

    print(f"[{tool}] {len(eval_set)} snippets x {n_runs} run(s), temp={temp}")
    for i, s in enumerate(eval_set, 1):
        prompt = _build_prompt(strategy, s.code, examples)
        verdicts: list[Verdict] = []
        tin = tout = 0
        elapsed = 0.0
        for r in range(1, n_runs + 1):
            gen = backend.generate(prompt, force_json=force_json)
            v = parse_verdict(gen.text)
            verdicts.append(v)
            tin += gen.tokens_in or 0
            tout += gen.tokens_out or 0
            elapsed += gen.elapsed_ms or 0.0
            per_run.append(
                Finding(
                    snippet_id=s.snippet_id, tool=tool, verdict=v.verdict,
                    cwe=v.cwe, line=v.line, explanation=v.reason,
                    elapsed_ms=gen.elapsed_ms, tokens_in=gen.tokens_in,
                    tokens_out=gen.tokens_out, prompt_strategy=strategy, run_idx=r,
                )
            )
        final = _vote(verdicts)
        # cwe from the first vulnerable vote (localisation is best-effort).
        cwe = next((v.cwe for v in verdicts if v.verdict == VULNERABLE and v.cwe), None)
        reason = next((v.reason for v in verdicts if v.reason), None)
        per_snippet.append(
            Finding(
                snippet_id=s.snippet_id, tool=tool, verdict=final, cwe=cwe,
                explanation=reason, elapsed_ms=elapsed, tokens_in=tin,
                tokens_out=tout, prompt_strategy=strategy,
            )
        )
        if i % 25 == 0:
            print(f"  {i}/{len(eval_set)}")

    findings_dir = cfg.ensure_path("findings")
    out = findings_dir / f"{tool}_perSnippet.jsonl"
    write_jsonl(out, per_snippet)
    runs_dir = findings_dir / "llm_runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(runs_dir / f"{tool}_runs.jsonl", per_run)

    n_flag = sum(1 for f in per_snippet if f.verdict == VULNERABLE)
    print(f"[{tool}] {len(per_snippet)} snippets, {n_flag} flagged vulnerable -> {out}")
    return out
