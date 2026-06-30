"""Hybrid SAST→LLM pipeline — the thesis centerpiece.

Static analysis is the *candidate generator*; an LLM is the *semantic
confirmer*. Only the snippets a SAST tool flags are sent to the model,
which confirms or rejects each alert (``static-augmented`` prompting). The
output is the same per-snippet ``Finding`` contract every other detector
emits, so it scores against ground truth identically.
"""

from vulnpipe.hybrid.run import sast_candidates

__all__ = ["sast_candidates"]
