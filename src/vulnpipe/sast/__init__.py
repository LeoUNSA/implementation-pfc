"""Static analysis layer. Container-based runners normalize to ``Finding``.

PMD (vanilla + custom) is implemented; SonarQube/CodeQL/SpotBugs share the
same ``container`` + ``aggregate_to_finding`` plumbing and follow later."""

from vulnpipe.sast.base import SASTRunner, aggregate_to_finding

__all__ = ["SASTRunner", "aggregate_to_finding"]
