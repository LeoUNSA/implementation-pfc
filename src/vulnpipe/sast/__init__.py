"""Static analysis layer. Interface + aggregation rule this increment;
concrete SonarQube/CodeQL/SpotBugs/PMD runners deferred (see plan)."""

from vulnpipe.sast.base import SASTRunner, aggregate_to_finding

__all__ = ["SASTRunner", "aggregate_to_finding"]
