"""JSONL read/write helpers.

JSONL (one JSON object per line) is the storage format for every corpus
and findings artifact. None-valued optional fields are dropped on write to
keep files compact; missing fields reappear as None on read via each
dataclass's ``from_dict``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, TypeVar

T = TypeVar("T")


def read_jsonl(path: str | Path) -> Iterator[dict[str, Any]]:
    """Yield one dict per non-blank line."""
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


def load_records(path: str | Path, factory: Callable[[dict[str, Any]], T]) -> list[T]:
    """Read a JSONL file into a list of dataclass instances via ``factory``.

    ``factory`` is typically ``Snippet.from_dict`` / ``Finding.from_dict``.
    """
    return [factory(row) for row in read_jsonl(path)]


def write_jsonl(path: str | Path, rows: Iterable[Any]) -> int:
    """Write dataclass instances (or dicts) to JSONL. Returns row count.

    Accepts anything exposing ``to_dict()`` or a plain dict. Parent
    directories are created as needed. None values are stripped.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            obj = row.to_dict() if hasattr(row, "to_dict") else dict(row)
            obj = {k: v for k, v in obj.items() if v is not None}
            fh.write(json.dumps(obj, ensure_ascii=False))
            fh.write("\n")
            n += 1
    return n
