"""Load and validate ``config.yaml``.

Resolves the config path relative to the project root (the directory
containing ``config.yaml``) so the CLI works from any cwd. Path fields are
returned as absolute ``Path`` objects rooted at the project root.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


def find_project_root(start: Path | None = None) -> Path:
    """Walk upward from ``start`` (default cwd) to find ``config.yaml``."""
    start = (start or Path.cwd()).resolve()
    for d in (start, *start.parents):
        if (d / "config.yaml").is_file():
            return d
    raise FileNotFoundError(
        "config.yaml not found in cwd or any parent. Run from the "
        "implementation/ directory or pass an explicit path."
    )


@dataclass
class Config:
    root: Path
    raw: dict[str, Any]

    # ----- typed convenience accessors -----
    @property
    def cwes(self) -> list[str]:
        return [str(c) for c in self.raw["cwes"]]

    def path(self, key: str) -> Path:
        """Absolute path for a ``paths.<key>`` entry (created on access)."""
        rel = self.raw["paths"][key]
        p = (self.root / rel).resolve()
        return p

    def ensure_path(self, key: str) -> Path:
        p = self.path(key)
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def corpus_cfg(self) -> dict[str, Any]:
        return self.raw["corpus"]

    @property
    def metrics_cfg(self) -> dict[str, Any]:
        return self.raw["metrics"]

    @property
    def llm_cfg(self) -> dict[str, Any]:
        return self.raw["llm"]


_REQUIRED_TOP = {"cwes", "paths", "corpus", "metrics", "llm"}


def load(path: str | Path | None = None) -> Config:
    """Load config from an explicit file, or discover the project root."""
    if path is not None:
        cfg_path = Path(path).resolve()
        root = cfg_path.parent
    else:
        root = find_project_root()
        cfg_path = root / "config.yaml"

    with open(cfg_path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    missing = _REQUIRED_TOP - raw.keys()
    if missing:
        raise ValueError(f"config.yaml missing required keys: {sorted(missing)}")

    return Config(root=root, raw=raw)
