"""Metrics & statistics — joins detector findings to ground truth and
computes P/R/F1/FPR, the Hybrid Improvement Score, McNemar, and bootstrap
confidence intervals."""

from vulnpipe.metrics.compute import (
    Confusion,
    ToolMetrics,
    bootstrap_f1_ci,
    his,
    mcnemar,
    metrics_from_confusion,
)
from vulnpipe.metrics.compute import McNemarResult
from vulnpipe.metrics.join import (
    aligned_predictions,
    confusion_by_tool,
    join_to_truth,
)

__all__ = [
    "Confusion",
    "ToolMetrics",
    "McNemarResult",
    "bootstrap_f1_ci",
    "his",
    "mcnemar",
    "metrics_from_confusion",
    "aligned_predictions",
    "confusion_by_tool",
    "join_to_truth",
]
