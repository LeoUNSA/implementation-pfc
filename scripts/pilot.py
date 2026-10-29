"""Pilot a confirmer configuration on a fixed balanced sample before a full run.

Sample: N true and N false Semgrep alerts on OWASP (seed fixed). For each
prompt variant it reports how often the model says "vulnerable" on each half:
TPR on the true alerts, FPR on the false ones. A useful confirmer needs
TPR - FPR (Youden's J) clearly above 0; J near 0 means the answer does not
depend on the code. Usage:
    .venv/bin/python scripts/pilot.py --model deepseek-coder:6.7b-instruct --variants trace zero-shot
"""

import argparse
import json
import random
from pathlib import Path

from vulnpipe.llm import prompts
from vulnpipe.llm.base import _first_json_object, parse_verdict
from vulnpipe.llm.openai import backend_for
from vulnpipe.sast.semgrep import parse_text_traces

ROOT = Path(__file__).resolve().parent.parent
F = ROOT / "findings/owasp"


def build(variant, s, alert, trace):
    cwe = alert["cwe"]
    if variant == "trace":
        return prompts.trace_confirm(s["code"], cwe, trace)
    if variant == "trace-nohints":
        return prompts.trace_confirm(s["code"], cwe, trace, hints=False)
    if variant == "confirm":  # the prompt of the first full hybrid run
        return prompts.static_augmented(s["code"], "semgrep", cwe, alert.get("line"))
    return prompts.zero_shot(s["code"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--variants", nargs="+", default=["trace"])
    ap.add_argument("--n", type=int, default=30, help="alerts per class")
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()

    corpus = {s["snippet_id"]: s for s in map(json.loads, open(ROOT / "corpus/owasp.jsonl"))}
    alerts = {r["snippet_id"]: r for r in map(json.loads, open(F / "semgrep_perSnippet.jsonl"))
              if r["verdict"] == 1}
    traces = parse_text_traces((F / "scan/semgrep_traces.txt").read_text())
    rng = random.Random(a.seed)
    sample = []
    for label in (1, 0):
        ids = sorted(k for k in alerts if corpus[k]["label"] == label)
        sample += rng.sample(ids, a.n)

    backend = backend_for(a.model)
    out_dir = F / "pilot"
    out_dir.mkdir(exist_ok=True)
    for variant in a.variants:
        out = out_dir / f"{a.model.replace(':', '_')}__{variant}.jsonl"
        # Resumable: answers already in the file are kept and not asked again.
        rows = [json.loads(l) for l in open(out)] if out.exists() else []
        done = {r["snippet_id"] for r in rows}
        with open(out, "a") as fh:
            for k in sample:
                if k in done:
                    continue
                gen = backend.generate(build(variant, corpus[k], alerts[k], traces[k]))
                row = {"snippet_id": k, "label": corpus[k]["label"],
                       "verdict": parse_verdict(gen.text).verdict,
                       "json_ok": _first_json_object(gen.text) is not None,
                       "tokens_out": gen.tokens_out, "raw": gen.text}
                rows.append(row)
                fh.write(json.dumps(row) + "\n")
                fh.flush()
        tpr = sum(r["verdict"] for r in rows if r["label"] == 1) / a.n
        fpr = sum(r["verdict"] for r in rows if r["label"] == 0) / a.n
        bad = sum(not r["json_ok"] for r in rows)
        print(f"{a.model} {variant:10s} TPR={tpr:.2f} FPR={fpr:.2f} J={tpr - fpr:+.2f} "
              f"unparsed={bad}/{len(rows)} -> {out.name}", flush=True)


if __name__ == "__main__":
    main()
