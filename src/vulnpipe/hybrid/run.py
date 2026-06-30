"""Drive the hybrid SAST→LLM pipeline over the corpus.

The SAST stage has already run and written ``*_perSnippet.jsonl`` candidate
findings. This stage:

1. **Unions** one or more SAST findings files into a candidate set — a
   snippet is a candidate iff at least one input tool flagged it vulnerable.
   Each candidate carries the flagging tool's CWE/line as provenance for the
   confirmation prompt.
2. For every candidate, queries the LLM with the ``static-augmented`` prompt
   (confirm/reject the specific alert). Majority-vote over ``runs`` when the
   temperature is > 0, mirroring the direct LLM runner.
3. Emits one per-snippet ``Finding``:
   * candidate **confirmed** → ``verdict = 1``
   * candidate **rejected**  → ``verdict = 0``  (the FP-pruning the hybrid is for)
   * not a candidate → ``verdict = 0`` (``reject`` scope) — the LLM never
     sees it, so the hybrid's recall is bounded above by the SAST input's.

The ``scope`` knob (``pipeline_outputs.md`` / STATUS open question) controls
that last case. ``reject`` (default) is the pure confirmer: the LLM may only
*prune* SAST alerts, never add its own. ``augment`` additionally runs a cold
zero-shot detection on the SAST-negative snippets, letting the hybrid recover
vulnerabilities SAST missed (recall can then exceed the SAST input's, at the
cost of more LLM calls).

The ``tool`` field encodes the full configuration so the metrics stage treats
each hybrid variant as its own detector, e.g.
``hybrid__pmd-custom+semgrep__deepseek-coder_6.7b-instruct__reject``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Sequence

from vulnpipe.config import Config
from vulnpipe.llm import prompts
from vulnpipe.llm.base import Verdict, parse_verdict
from vulnpipe.llm.ollama import OllamaBackend
from vulnpipe.schemas import SAFE, VULNERABLE, Finding, Snippet

SCOPES = ("reject", "augment")


def _model_tag(model: str) -> str:
    return model.replace(":", "_").replace("/", "_")


def _sast_tag(tools: Sequence[str]) -> str:
    return "+".join(sorted(tools))


def _tool_name(sast_tools: Sequence[str], model: str, scope: str) -> str:
    return f"hybrid__{_sast_tag(sast_tools)}__{_model_tag(model)}__{scope}"


def sast_candidates(
    sast_findings: Sequence[Finding],
) -> dict[str, Finding]:
    """Union SAST findings into ``{snippet_id: representative Finding}``.

    A snippet is a candidate iff some input tool gave it ``verdict == 1``.
    The representative carries that tool's ``cwe``/``line``/``tool`` so the
    confirmation prompt can reference a concrete alert. When several tools
    flag the same snippet, the first one seen (input order) wins as the
    representative — the union itself, not provenance detail, is what matters.
    """
    candidates: dict[str, Finding] = {}
    for f in sast_findings:
        if f.verdict == VULNERABLE and f.snippet_id not in candidates:
            candidates[f.snippet_id] = f
    return candidates


def _confirm_vote(verdicts: Sequence[Verdict]) -> int:
    """Majority vote over confirm/reject decisions (tie → reject)."""
    n_confirm = sum(1 for v in verdicts if v.verdict == VULNERABLE)
    return VULNERABLE if n_confirm * 2 > len(verdicts) else SAFE


def _query(
    backend: OllamaBackend, prompt: str, n_runs: int, force_json: bool
) -> tuple[int, list[Verdict], int, int, float]:
    """Run a prompt ``n_runs`` times → (voted verdict, verdicts, tin, tout, ms)."""
    verdicts: list[Verdict] = []
    tin = tout = 0
    elapsed = 0.0
    for _ in range(n_runs):
        gen = backend.generate(prompt, force_json=force_json)
        verdicts.append(parse_verdict(gen.text))
        tin += gen.tokens_in or 0
        tout += gen.tokens_out or 0
        elapsed += gen.elapsed_ms or 0.0
    return _confirm_vote(verdicts), verdicts, tin, tout, elapsed


def run(
    cfg: Config,
    corpus: Sequence[Snippet],
    sast_findings: Sequence[Finding],
    model: str,
    scope: str = "reject",
    runs: Optional[int] = None,
    temperature: Optional[float] = None,
    limit: Optional[int] = None,
    host: str = "http://localhost:11434",
) -> Path:
    """Run the hybrid pipeline → ``findings/hybrid__..._perSnippet.jsonl``.

    ``sast_findings`` is the merged candidate input (one or more SAST tools'
    per-snippet findings). ``scope`` is ``reject`` (confirmer only) or
    ``augment`` (also cold-detect SAST-negatives).
    """
    from vulnpipe.io import write_jsonl

    if scope not in SCOPES:
        raise ValueError(f"scope must be one of {SCOPES}, got {scope!r}")

    llm_cfg = cfg.llm_cfg
    temp = temperature if temperature is not None else float(llm_cfg.get("temperature", 0.0))
    cfg_runs = int(runs if runs is not None else llm_cfg.get("runs_per_snippet", 1))
    n_runs = cfg_runs if temp > 0 else 1

    backend = OllamaBackend(model, host=host, temperature=temp)

    candidates = sast_candidates(sast_findings)
    sast_tools = sorted({f.tool for f in sast_findings})
    tool = _tool_name(sast_tools, model, scope)

    eval_set = list(corpus)
    if limit is not None:
        eval_set = eval_set[:limit]

    n_cand = sum(1 for s in eval_set if s.snippet_id in candidates)
    print(
        f"[{tool}] {len(eval_set)} snippets, {n_cand} SAST candidate(s) to confirm, "
        f"scope={scope}, temp={temp}"
    )

    per_snippet: list[Finding] = []
    n_calls = 0
    for i, s in enumerate(eval_set, 1):
        cand = candidates.get(s.snippet_id)
        if cand is not None:
            # Confirmer path: confirm or reject this specific SAST alert.
            cwe = cand.cwe or (s.cwe if s.cwe in ("89", "22") else "89")
            prompt = prompts.static_augmented(s.code, cand.tool, str(cwe), cand.line)
            verdict, _, tin, tout, ms = _query(backend, prompt, n_runs, force_json=True)
            n_calls += n_runs
            per_snippet.append(
                Finding(
                    snippet_id=s.snippet_id, tool=tool, verdict=verdict,
                    cwe=str(cwe) if verdict == VULNERABLE else None,
                    line=cand.line if verdict == VULNERABLE else None,
                    rule_id=cand.rule_id, prompt_strategy="static-augmented",
                    explanation=f"confirmer over {cand.tool} alert",
                    elapsed_ms=ms, tokens_in=tin, tokens_out=tout,
                )
            )
        elif scope == "augment":
            # Recover SAST-negatives via a cold zero-shot detection.
            prompt = prompts.zero_shot(s.code)
            verdict, vs, tin, tout, ms = _query(backend, prompt, n_runs, force_json=True)
            n_calls += n_runs
            cwe = next((v.cwe for v in vs if v.verdict == VULNERABLE and v.cwe), None)
            per_snippet.append(
                Finding(
                    snippet_id=s.snippet_id, tool=tool, verdict=verdict, cwe=cwe,
                    prompt_strategy="zero-shot", explanation="augment: cold detect",
                    elapsed_ms=ms, tokens_in=tin, tokens_out=tout,
                )
            )
        else:
            # reject scope: SAST said safe, LLM never consulted → safe.
            per_snippet.append(
                Finding(
                    snippet_id=s.snippet_id, tool=tool, verdict=SAFE,
                    prompt_strategy="static-augmented", explanation="no SAST candidate",
                )
            )
        if i % 25 == 0:
            print(f"  {i}/{len(eval_set)} ({n_calls} LLM call(s))")

    findings_dir = cfg.ensure_path("findings")
    out = findings_dir / f"{tool}_perSnippet.jsonl"
    write_jsonl(out, per_snippet)

    n_flag = sum(1 for f in per_snippet if f.verdict == VULNERABLE)
    n_pruned = n_cand - n_flag if scope == "reject" else None
    msg = f"[{tool}] {len(per_snippet)} snippets, {n_flag} vulnerable"
    if n_pruned is not None:
        msg += f" ({n_pruned} SAST candidate(s) pruned by the LLM)"
    print(f"{msg} -> {out}")
    return out
