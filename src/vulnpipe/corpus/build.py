"""Corpus build orchestrator → ``corpus/<dataset>.jsonl``."""

from __future__ import annotations

from pathlib import Path

from vulnpipe.config import Config
from vulnpipe.io import write_jsonl

_DATASETS = ("juliet", "defects4j")


def build(cfg: Config, only: str | None = None) -> dict[str, Path]:
    """Build the requested datasets, writing one JSONL per dataset.

    ``only`` selects a single dataset ("juliet" / "defects4j"); None builds
    all implemented ones. Returns ``{dataset: output_path}``.
    """
    targets = (only,) if only else _DATASETS
    corpus_dir = cfg.ensure_path("corpus")
    written: dict[str, Path] = {}

    for name in targets:
        if name == "juliet":
            from vulnpipe.corpus import juliet

            snippets = juliet.build(cfg)
        elif name == "defects4j":
            from vulnpipe.corpus import defects4j

            snippets = defects4j.build(cfg)  # raises NotImplementedError (stub)
        else:
            raise ValueError(f"unknown dataset {name!r}; choose from {_DATASETS}")

        out = corpus_dir / f"{name}.jsonl"
        n = write_jsonl(out, snippets)
        n_vuln = sum(1 for s in snippets if s.label == 1)
        print(f"[{name}] wrote {n} snippets ({n_vuln} vulnerable) -> {out}")
        written[name] = out

    return written
