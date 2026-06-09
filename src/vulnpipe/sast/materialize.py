"""Materialize corpus snippets as standalone, parseable ``.java`` files.

A corpus ``Snippet.code`` is a method ± context slice of a Juliet file, so
its braces don't balance — PMD's parser (JavaCC, stricter than tree-sitter)
would reject it, and re-parsing the slice mis-bounds methods. We therefore
prefer the **original full source file** (balanced → reliable parse), locate
the snippet's method by name, brace-scan it to a complete body, and wrap it:

    final class S { <method> }

This always parses. PMD does AST-level analysis with no compilation, so
undefined symbols (helper classes, unresolved types) are harmless. One file
per snippet, named ``<snippet_id>.java`` — the basename is the join key back
to the corpus when parsing the SARIF report.

If the original source is unavailable, we fall back to brace-scanning the
slice itself (less reliable, but keeps materialization working corpus-only).
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Iterable, Optional

from vulnpipe.corpus.javaparse import extract_methods
from vulnpipe.schemas import Snippet

# A resolver maps a snippet to its full original source text (or None).
SourceResolver = Callable[[Snippet], Optional[str]]


def _method_name_of(snippet_id: str) -> str | None:
    """Recover the source method name from a Juliet snippet id (``..__<method>``)."""
    return snippet_id.rsplit("__", 1)[-1] if "__" in snippet_id else None


def _brace_complete_method(source: str, name_hint: str | None) -> str | None:
    """Return the full text of the chosen method, brace-balanced.

    Picks the method whose name matches ``name_hint`` (else the first method),
    then scans forward from its start line counting braces until balanced —
    so the body is complete even if the parser mis-reported the end line.
    """
    methods = extract_methods(source)
    if not methods:
        return None
    chosen = None
    if name_hint:
        chosen = next((m for m in methods if m.name == name_hint), None)
    if chosen is None:
        chosen = methods[0]

    lines = source.splitlines()
    start = chosen.start_line - 1
    depth = 0
    started = False
    end = start
    for j in range(start, len(lines)):
        for ch in lines[j]:
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
        end = j
        if started and depth == 0:
            break
    if not started or depth != 0:
        return None  # could not balance — caller falls back
    return "\n".join(lines[start : end + 1])


def wrap_snippet(snippet: Snippet, full_source: str | None = None) -> str:
    """Return parseable Java for one snippet: its method wrapped in a class.

    Prefers ``full_source`` (the original file) for reliable extraction;
    falls back to the snippet's own slice, then to the raw slice verbatim.
    """
    name_hint = _method_name_of(snippet.snippet_id)

    body = None
    if full_source is not None:
        body = _brace_complete_method(full_source, name_hint)
    if body is None:
        body = _brace_complete_method(snippet.code, name_hint)
    if body is None:
        body = snippet.code  # last resort; may not parse (logged via PMD errors)

    return f"final class S {{\n{body}\n}}\n"


def build_source_index(roots: Iterable[Path]) -> dict[str, Path]:
    """Map ``<basename.java>`` → path for every ``CWE*.java`` under ``roots``.

    Juliet test-case filenames are unique, so a basename index is sufficient
    to recover a snippet's original (balanced) source from its ``file`` field.
    """
    index: dict[str, Path] = {}
    for root in roots:
        if not root.exists():
            continue
        for p in root.rglob("CWE*.java"):
            index.setdefault(p.name, p)
    return index


def materialize(
    snippets: Iterable[Snippet],
    scan_dir: Path,
    resolve_source: SourceResolver | None = None,
) -> dict[str, Path]:
    """Write each snippet to ``scan_dir/<snippet_id>.java``.

    ``resolve_source`` (optional) returns a snippet's full original source for
    reliable method extraction. Returns ``{snippet_id: path}``. Stale ``.java``
    files are cleared first so a re-run reflects exactly the current corpus.
    """
    scan_dir.mkdir(parents=True, exist_ok=True)
    for old in scan_dir.glob("*.java"):
        old.unlink()

    mapping: dict[str, Path] = {}
    for s in snippets:
        full = resolve_source(s) if resolve_source else None
        path = scan_dir / f"{s.snippet_id}.java"
        path.write_text(wrap_snippet(s, full), encoding="utf-8")
        mapping[s.snippet_id] = path
    return mapping
