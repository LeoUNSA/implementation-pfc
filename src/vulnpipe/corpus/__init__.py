"""Corpus construction — the only producer of ground-truth ``Snippet``s.

Juliet (synthetic, labelled) is the primary corpus and is fully
implemented here. Defects4J (real bugs) is the validation set and is a
documented stub this increment (see ``defects4j.py``)."""

from vulnpipe.corpus.build import build

__all__ = ["build"]
