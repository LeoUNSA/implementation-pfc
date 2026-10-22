"""Remove label hints from benchmark code before any detector sees it.

Synthetic benchmarks leak their ground truth through comments (Juliet's
``POTENTIAL FLAW`` / ``FIX``, OWASP's ``condition 'B', which is safe``) and
identifiers. SAST tools ignore both; an LLM reads them. Stripping them keeps
the comparison about the technique, not the hints.
"""

from __future__ import annotations

import re

# Strings first so a "//" or "/*" inside a literal is not taken for a comment.
_TOKEN = re.compile(
    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*.*?\*/', re.S
)


def strip_comments(code: str) -> str:
    """Drop // and /* */ comments (string-aware) and the blank lines left behind."""
    out = _TOKEN.sub(lambda m: m.group(0) if m.group(0)[0] in "\"'" else "", code)
    return "\n".join(line.rstrip() for line in out.splitlines() if line.strip())
