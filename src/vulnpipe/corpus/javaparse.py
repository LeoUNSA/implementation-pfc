"""Java method extraction.

Returns, for a source string, a list of ``Method(name, start_line,
end_line)`` (1-based, inclusive). Prefers tree-sitter-java (robust on
Python 3.14); falls back to a brace-matching scanner if the native parser
is unavailable, so corpus construction never hard-depends on a wheel.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Method:
    name: str
    start_line: int  # 1-based, inclusive
    end_line: int    # 1-based, inclusive


# --------------------------------------------------------------------------
# tree-sitter backend
# --------------------------------------------------------------------------
_parser = None
_TS_TRIED = False


def _get_ts_parser():
    """Lazily build a tree-sitter Java parser, tolerating API differences
    across tree-sitter 0.21–0.23. Returns None if unavailable."""
    global _parser, _TS_TRIED
    if _TS_TRIED:
        return _parser
    _TS_TRIED = True
    try:
        import tree_sitter_java as tsjava
        from tree_sitter import Language, Parser

        lang_ptr = tsjava.language()
        try:
            language = Language(lang_ptr)            # tree-sitter >= 0.22
        except TypeError:
            language = Language(lang_ptr, "java")    # tree-sitter 0.21
        try:
            _parser = Parser(language)               # >= 0.22
        except TypeError:
            _parser = Parser()                       # 0.21
            _parser.set_language(language)
    except Exception:
        _parser = None
    return _parser


def _extract_treesitter(source: str) -> list[Method] | None:
    parser = _get_ts_parser()
    if parser is None:
        return None
    data = source.encode("utf-8")
    tree = parser.parse(data)
    methods: list[Method] = []

    def walk(node) -> None:
        if node.type == "method_declaration":
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                name = data[name_node.start_byte : name_node.end_byte].decode(
                    "utf-8", "replace"
                )
                methods.append(
                    Method(
                        name=name,
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                    )
                )
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return methods


# --------------------------------------------------------------------------
# brace-matching fallback
# --------------------------------------------------------------------------
# Matches a method signature line: <modifiers> returnType name(...) {
_SIG = re.compile(
    r"^[ \t]*(?:(?:public|private|protected|static|final|synchronized|"
    r"abstract|native)\s+)*[\w<>\[\]\.,\s\?]+?\s+(\w+)\s*\([^;{]*\)\s*"
    r"(?:throws\s+[\w\.,\s]+)?\{",
)


def _extract_bracematch(source: str) -> list[Method]:
    lines = source.splitlines()
    methods: list[Method] = []
    i = 0
    n = len(lines)
    while i < n:
        m = _SIG.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        # Brace-balance from this line to the matching close.
        depth = 0
        started = False
        end = i
        for j in range(i, n):
            for ch in lines[j]:
                if ch == "{":
                    depth += 1
                    started = True
                elif ch == "}":
                    depth -= 1
            end = j
            if started and depth == 0:
                break
        methods.append(Method(name=name, start_line=i + 1, end_line=end + 1))
        i = end + 1
    return methods


def extract_methods(source: str) -> list[Method]:
    """Extract method declarations, preferring tree-sitter."""
    ts = _extract_treesitter(source)
    if ts is not None:
        return ts
    return _extract_bracematch(source)


def slice_with_context(source: str, m: Method, context_lines: int) -> tuple[str, int]:
    """Return (code, start_line) for method ``m`` plus ±context_lines lines.

    ``start_line`` is the 1-based first line of the returned slice.
    """
    lines = source.splitlines()
    lo = max(0, m.start_line - 1 - context_lines)
    hi = min(len(lines), m.end_line + context_lines)
    return "\n".join(lines[lo:hi]), lo + 1
