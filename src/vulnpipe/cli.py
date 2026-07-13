"""``vulnpipe`` command-line entry point.

Subcommands:
  corpus build [--only juliet|defects4j]   build the labelled corpus
  metrics --findings PATH [--corpus PATH]  score findings vs ground truth
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from vulnpipe import config as config_mod


def _cmd_corpus(args: argparse.Namespace) -> int:
    from vulnpipe.corpus.build import build

    cfg = config_mod.load(args.config)
    build(cfg, only=args.only)
    return 0


def _cmd_sast(args: argparse.Namespace) -> int:
    from vulnpipe.io import load_records
    from vulnpipe.schemas import Snippet

    cfg = config_mod.load(args.config)
    corpus_path = (
        Path(args.corpus) if args.corpus else cfg.path("corpus") / "juliet.jsonl"
    )
    if not corpus_path.exists():
        print(f"error: corpus not found: {corpus_path}", file=sys.stderr)
        print("run `vulnpipe corpus build --only juliet` first.", file=sys.stderr)
        return 1
    corpus = load_records(corpus_path, Snippet.from_dict)

    if args.tool == "pmd":
        from vulnpipe.sast import pmd

        pmd.run(cfg, corpus, variant=args.variant)
    elif args.tool == "semgrep":
        from vulnpipe.sast import semgrep

        semgrep.run(cfg, corpus)
    else:
        print(f"error: SAST tool {args.tool!r} not implemented yet", file=sys.stderr)
        return 1
    return 0


def _cmd_llm(args: argparse.Namespace) -> int:
    from vulnpipe.io import load_records
    from vulnpipe.llm import run as llm_run
    from vulnpipe.llm.ollama import installed_models, is_available
    from vulnpipe.schemas import Snippet

    cfg = config_mod.load(args.config)
    if not is_available(args.host):
        print(f"error: no Ollama server at {args.host}", file=sys.stderr)
        print("start it with `ollama serve`.", file=sys.stderr)
        return 1
    have = installed_models(args.host)
    if args.model not in have:
        print(f"error: model {args.model!r} not pulled. Have: {have}", file=sys.stderr)
        print(f"pull it with `ollama pull {args.model}`.", file=sys.stderr)
        return 1

    corpus_path = (
        Path(args.corpus) if args.corpus else cfg.path("corpus") / "juliet.jsonl"
    )
    if not corpus_path.exists():
        print(f"error: corpus not found: {corpus_path}", file=sys.stderr)
        return 1
    corpus = load_records(corpus_path, Snippet.from_dict)

    llm_run.run(
        cfg, corpus, model=args.model, strategy=args.strategy,
        runs=args.runs, temperature=args.temperature, limit=args.limit,
        host=args.host,
    )
    return 0


def _cmd_hybrid(args: argparse.Namespace) -> int:
    from vulnpipe.hybrid import run as hybrid_run
    from vulnpipe.io import load_records
    from vulnpipe.llm.ollama import installed_models, is_available
    from vulnpipe.schemas import Finding, Snippet

    cfg = config_mod.load(args.config)
    if not is_available(args.host):
        print(f"error: no Ollama server at {args.host}", file=sys.stderr)
        print("start it with `ollama serve`.", file=sys.stderr)
        return 1
    have = installed_models(args.host)
    if args.model not in have:
        print(f"error: model {args.model!r} not pulled. Have: {have}", file=sys.stderr)
        print(f"pull it with `ollama pull {args.model}`.", file=sys.stderr)
        return 1

    corpus_path = (
        Path(args.corpus) if args.corpus else cfg.path("corpus") / "juliet.jsonl"
    )
    if not corpus_path.exists():
        print(f"error: corpus not found: {corpus_path}", file=sys.stderr)
        return 1
    corpus = load_records(corpus_path, Snippet.from_dict)

    sast_findings: list[Finding] = []
    for fpath in args.sast:
        if not Path(fpath).exists():
            print(f"error: SAST findings not found: {fpath}", file=sys.stderr)
            print("run `vulnpipe sast run ...` first.", file=sys.stderr)
            return 1
        sast_findings.extend(load_records(fpath, Finding.from_dict))

    hybrid_run.run(
        cfg, corpus, sast_findings, model=args.model, scope=args.scope,
        runs=args.runs, temperature=args.temperature, limit=args.limit,
        host=args.host,
    )
    return 0


def _cmd_metrics(args: argparse.Namespace) -> int:
    from vulnpipe.io import load_records
    from vulnpipe.metrics import (
        aligned_predictions,
        bootstrap_f1_ci,
        confusion_by_tool,
        his,
        mcnemar,
        metrics_from_confusion,
    )
    from vulnpipe.schemas import Finding, Snippet

    cfg = config_mod.load(args.config)
    corpus_path = (
        Path(args.corpus)
        if args.corpus
        else cfg.path("corpus") / "juliet.jsonl"
    )
    if not corpus_path.exists():
        print(f"error: corpus not found: {corpus_path}", file=sys.stderr)
        print("run `vulnpipe corpus build --only juliet` first.", file=sys.stderr)
        return 1

    corpus = load_records(corpus_path, Snippet.from_dict)
    findings = []
    for fpath in args.findings:
        findings.extend(load_records(fpath, Finding.from_dict))
    confusions = confusion_by_tool(findings, corpus)

    rows = [metrics_from_confusion(tool, c) for tool, c in sorted(confusions.items())]

    # Bootstrap 95% F1 CI per tool over the paired (truth, prediction) arrays.
    mcfg = cfg.raw.get("metrics", {})
    n_resamples = int(mcfg.get("bootstrap_resamples", 1000))
    alpha = float(mcfg.get("alpha", 0.05))
    _, y_true, y_pred = aligned_predictions(findings, corpus)
    for m in rows:
        if m.tool in y_pred:
            lo, hi = bootstrap_f1_ci(
                y_true, y_pred[m.tool], n_resamples=n_resamples, alpha=alpha
            )
            m.f1_ci_low, m.f1_ci_high = lo, hi

    out_dir = cfg.ensure_path("metrics")
    out_path = out_dir / "per_tool.csv"
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(
            ["tool", "precision", "recall", "fpr", "f1",
             "f1_ci_low", "f1_ci_high", "tp", "fp", "tn", "fn"]
        )
        for m in rows:
            w.writerow(
                [
                    m.tool,
                    f"{m.precision:.4f}",
                    f"{m.recall:.4f}",
                    f"{m.fpr:.4f}",
                    f"{m.f1:.4f}",
                    f"{m.f1_ci_low:.4f}" if m.f1_ci_low is not None else "",
                    f"{m.f1_ci_high:.4f}" if m.f1_ci_high is not None else "",
                    m.tp,
                    m.fp,
                    m.tn,
                    m.fn,
                ]
            )
    print(f"wrote {out_path}")
    for m in rows:
        ci = (
            f" CI[{m.f1_ci_low:.3f},{m.f1_ci_high:.3f}]"
            if m.f1_ci_low is not None
            else ""
        )
        print(f"  {m.tool:48s} P={m.precision:.3f} R={m.recall:.3f} F1={m.f1:.3f}{ci}")

    # Optional hybrid comparison: HIS triad + pairwise McNemar significance.
    if args.compare:
        f1 = {m.tool: m.f1 for m in rows}
        sast, llm, hyb = args.compare
        missing = [t for t in args.compare if t not in f1]
        if missing:
            print(f"error: --compare tool(s) not in findings: {missing}", file=sys.stderr)
            return 1
        score = his(f1[hyb], f1[sast], f1[llm])
        best = max(f1[sast], f1[llm])
        print("\nHybrid Improvement Score (HIS)")
        print(f"  SAST={sast} F1={f1[sast]:.3f} | LLM={llm} F1={f1[llm]:.3f} | "
              f"HYBRID={hyb} F1={f1[hyb]:.3f}")
        print(f"  best component F1={best:.3f}  ->  HIS={score:+.4f}  "
              f"({'hybrid wins' if score > 0 else 'no improvement'})")
        print("\nMcNemar (paired, vs ground truth)")
        for a, b in ((hyb, sast), (hyb, llm)):
            r = mcnemar(y_true, y_pred[a], y_pred[b])
            sig = "significant" if r.p_value < alpha else "n.s."
            print(f"  {a} vs {b}: b={r.b} c={r.c} stat={r.statistic:.3f} "
                  f"p={r.p_value:.4g} ({sig} @ a={alpha})")
    return 0


def _cmd_figures(args: argparse.Namespace) -> int:
    from vulnpipe.figures import make_all
    from vulnpipe.io import load_records
    from vulnpipe.schemas import Finding, Snippet

    cfg = config_mod.load(args.config)
    corpus_path = (
        Path(args.corpus) if args.corpus else cfg.path("corpus") / "juliet.jsonl"
    )
    if not corpus_path.exists():
        print(f"error: corpus not found: {corpus_path}", file=sys.stderr)
        return 1
    corpus = load_records(corpus_path, Snippet.from_dict)

    findings: list = []
    for fpath in args.findings:
        if not Path(fpath).exists():
            print(f"error: findings not found: {fpath}", file=sys.stderr)
            return 1
        findings.extend(load_records(fpath, Finding.from_dict))

    out_dir = Path(args.out) if args.out else cfg.ensure_path("figures")
    venn = tuple(args.venn) if args.venn else None
    try:
        written = make_all(findings, corpus, out_dir, venn=venn, fmt=args.format)
    except ImportError as e:
        print(f"error: figure extras missing ({e}). "
              f"install with `pip install -e '.[figures]'`.", file=sys.stderr)
        return 1
    for path in written:
        print(f"wrote {path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vulnpipe", description=__doc__)
    p.add_argument("--config", default=None, help="path to config.yaml")
    sub = p.add_subparsers(dest="command", required=True)

    corpus = sub.add_parser("corpus", help="corpus construction")
    corpus_sub = corpus.add_subparsers(dest="corpus_command", required=True)
    cbuild = corpus_sub.add_parser("build", help="build labelled corpus")
    cbuild.add_argument(
        "--only", choices=["juliet", "defects4j"], default=None,
        help="build a single dataset (default: all implemented)",
    )
    cbuild.set_defaults(func=_cmd_corpus)

    sast = sub.add_parser("sast", help="run a SAST tool over the corpus")
    sast_sub = sast.add_subparsers(dest="sast_command", required=True)
    srun = sast_sub.add_parser("run", help="run a SAST tool")
    srun.add_argument("--tool", choices=["pmd", "semgrep"], default="pmd")
    srun.add_argument(
        "--variant", choices=["vanilla", "custom", "both"], default="both",
        help="PMD variant(s) to run (ignored for semgrep)",
    )
    srun.add_argument("--corpus", default=None, help="ground-truth jsonl (default: corpus/juliet.jsonl)")
    srun.set_defaults(func=_cmd_sast)

    llm = sub.add_parser("llm", help="run a local LLM over the corpus")
    llm_sub = llm.add_subparsers(dest="llm_command", required=True)
    lrun = llm_sub.add_parser("run", help="run one (model, strategy) detector")
    lrun.add_argument("--model", required=True, help="Ollama model tag, e.g. deepseek-coder:6.7b-instruct")
    lrun.add_argument(
        "--strategy", choices=["zero-shot", "cot", "few-shot"], default="zero-shot",
        help="prompting strategy (static-augmented is the hybrid phase)",
    )
    lrun.add_argument("--runs", type=int, default=None, help="queries per snippet (majority vote; needs temp>0)")
    lrun.add_argument("--temperature", type=float, default=None, help="sampling temperature (default: config)")
    lrun.add_argument("--limit", type=int, default=None, help="only the first N snippets (smoke test)")
    lrun.add_argument("--host", default="http://localhost:11434", help="Ollama server URL")
    lrun.add_argument("--corpus", default=None, help="ground-truth jsonl (default: corpus/juliet.jsonl)")
    lrun.set_defaults(func=_cmd_llm)

    hybrid = sub.add_parser("hybrid", help="run the hybrid SAST->LLM pipeline")
    hybrid_sub = hybrid.add_subparsers(dest="hybrid_command", required=True)
    hrun = hybrid_sub.add_parser("run", help="confirm/reject SAST alerts with an LLM")
    hrun.add_argument(
        "--sast", required=True, nargs="+",
        help="one or more SAST *_perSnippet.jsonl files (unioned as candidates)",
    )
    hrun.add_argument("--model", required=True, help="Ollama model tag (the confirmer)")
    hrun.add_argument(
        "--scope", choices=["reject", "augment"], default="reject",
        help="reject = confirmer only; augment = also cold-detect SAST-negatives",
    )
    hrun.add_argument("--runs", type=int, default=None, help="queries per snippet (majority vote; needs temp>0)")
    hrun.add_argument("--temperature", type=float, default=None, help="sampling temperature (default: config)")
    hrun.add_argument("--limit", type=int, default=None, help="only the first N snippets (smoke test)")
    hrun.add_argument("--host", default="http://localhost:11434", help="Ollama server URL")
    hrun.add_argument("--corpus", default=None, help="ground-truth jsonl (default: corpus/juliet.jsonl)")
    hrun.set_defaults(func=_cmd_hybrid)

    metrics = sub.add_parser("metrics", help="score findings vs ground truth")
    metrics.add_argument(
        "--findings", required=True, nargs="+",
        help="one or more *_perSnippet.jsonl paths (tools merged by 'tool' field)",
    )
    metrics.add_argument("--corpus", default=None, help="ground-truth jsonl (default: corpus/juliet.jsonl)")
    metrics.add_argument(
        "--compare", nargs=3, metavar=("SAST", "LLM", "HYBRID"),
        help="three tool names: print HIS + pairwise McNemar significance",
    )
    metrics.set_defaults(func=_cmd_metrics)

    figures = sub.add_parser("figures", help="render PR / cost-vs-F1 / Venn figures")
    figures.add_argument(
        "--findings", required=True, nargs="+",
        help="one or more *_perSnippet.jsonl paths",
    )
    figures.add_argument("--corpus", default=None, help="ground-truth jsonl (default: corpus/juliet.jsonl)")
    figures.add_argument("--out", default=None, help="output dir (default: figures/)")
    figures.add_argument(
        "--venn", nargs=3, metavar=("SAST", "LLM", "HYBRID"), default=None,
        help="three tool names for the true-positive Venn diagram",
    )
    figures.add_argument("--format", default="pdf", choices=["pdf", "png"], help="figure file format")
    figures.set_defaults(func=_cmd_figures)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
