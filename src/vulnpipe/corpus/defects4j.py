"""Defects4J ingestion — DEFERRED STUB (validation set, ~50 real bugs).

Planned flow (later increment):
  1. Clone the Defects4J framework + project repos.
  2. Filter to security-related bugs touching CWE-89 / CWE-22.
  3. `defects4j checkout` the buggy version of each selected bug.
  4. Extract the method ±context_lines around the fix location, label
     vulnerable (buggy) and emit ``Snippet`` records matching the same
     schema as Juliet.

Blocked on: the Defects4J framework requires Perl + JDK 11; the dev
machine currently has JDK 26 (compatibility to be resolved then).
"""

from __future__ import annotations

from vulnpipe.config import Config
from vulnpipe.schemas import Snippet


def build(cfg: Config) -> list[Snippet]:  # pragma: no cover - stub
    raise NotImplementedError(
        "Defects4J ingestion is deferred (needs the Defects4J framework + "
        "JDK 11). Use `vulnpipe corpus build --only juliet` for now."
    )
