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


def _cmd_metrics(args: argparse.Namespace) -> int:
    from vulnpipe.io import load_records
    from vulnpipe.metrics import (
        confusion_by_tool,
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
    findings = load_records(args.findings, Finding.from_dict)
    confusions = confusion_by_tool(findings, corpus)

    rows = [metrics_from_confusion(tool, c) for tool, c in sorted(confusions.items())]

    out_dir = cfg.ensure_path("metrics")
    out_path = out_dir / "per_tool.csv"
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["tool", "precision", "recall", "fpr", "f1", "tp", "fp", "tn", "fn"])
        for m in rows:
            w.writerow(
                [
                    m.tool,
                    f"{m.precision:.4f}",
                    f"{m.recall:.4f}",
                    f"{m.fpr:.4f}",
                    f"{m.f1:.4f}",
                    m.tp,
                    m.fp,
                    m.tn,
                    m.fn,
                ]
            )
    print(f"wrote {out_path}")
    for m in rows:
        print(f"  {m.tool:24s} P={m.precision:.3f} R={m.recall:.3f} F1={m.f1:.3f}")
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

    metrics = sub.add_parser("metrics", help="score findings vs ground truth")
    metrics.add_argument("--findings", required=True, help="*_perSnippet.jsonl path")
    metrics.add_argument("--corpus", default=None, help="ground-truth jsonl (default: corpus/juliet.jsonl)")
    metrics.set_defaults(func=_cmd_metrics)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
