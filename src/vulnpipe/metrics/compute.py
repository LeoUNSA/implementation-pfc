"""Detector-agnostic metrics and significance tests.

Pure functions over the binary-verdict contract — no detector code
required. Definitions follow ``propuesta.md`` §6.6 / §6.7.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import numpy as np
from scipy import stats


@dataclass
class Confusion:
    """Confusion-matrix counts for one detector (positive = vulnerable)."""

    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def n(self) -> int:
        return self.tp + self.fp + self.tn + self.fn


@dataclass
class ToolMetrics:
    tool: str
    precision: float
    recall: float
    fpr: float
    f1: float
    tp: int
    fp: int
    tn: int
    fn: int
    f1_ci_low: float | None = None
    f1_ci_high: float | None = None


def _safe_div(num: float, den: float) -> float:
    return num / den if den else 0.0


def metrics_from_confusion(tool: str, c: Confusion) -> ToolMetrics:
    """Precision, recall (TPR), FPR and F1 from confusion counts."""
    precision = _safe_div(c.tp, c.tp + c.fp)
    recall = _safe_div(c.tp, c.tp + c.fn)
    fpr = _safe_div(c.fp, c.fp + c.tn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    return ToolMetrics(
        tool=tool,
        precision=precision,
        recall=recall,
        fpr=fpr,
        f1=f1,
        tp=c.tp,
        fp=c.fp,
        tn=c.tn,
        fn=c.fn,
    )


def his(f1_hybrid: float, f1_sast: float, f1_llm: float) -> float:
    """Hybrid Improvement Score (the thesis's central quantitative claim).

        HIS = (F1_hybrid - max(F1_sast, F1_llm)) / max(F1_sast, F1_llm)

    HIS > 0 ⟺ the hybrid beats the better of the two standalone approaches.
    """
    best = max(f1_sast, f1_llm)
    if best == 0:
        return 0.0
    return (f1_hybrid - best) / best


def _f1_from_labels(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    return _safe_div(2 * precision * recall, precision + recall)


def bootstrap_f1_ci(
    y_true: Sequence[int],
    y_pred: Sequence[int],
    n_resamples: int = 1000,
    alpha: float = 0.05,
    seed: int = 42,
) -> tuple[float, float]:
    """Percentile bootstrap CI for F1 over paired (truth, prediction) arrays.

    Resamples snippet indices with replacement ``n_resamples`` times and
    returns the ``(alpha/2, 1-alpha/2)`` percentiles of the F1 distribution.
    """
    y_true = np.asarray(y_true, dtype=int)
    y_pred = np.asarray(y_pred, dtype=int)
    if y_true.shape != y_pred.shape:
        raise ValueError("y_true and y_pred must have equal length")
    n = len(y_true)
    if n == 0:
        return (0.0, 0.0)

    rng = np.random.default_rng(seed)
    f1s = np.empty(n_resamples, dtype=float)
    for i in range(n_resamples):
        idx = rng.integers(0, n, size=n)
        f1s[i] = _f1_from_labels(y_true[idx], y_pred[idx])
    lo = float(np.percentile(f1s, 100 * alpha / 2))
    hi = float(np.percentile(f1s, 100 * (1 - alpha / 2)))
    return (lo, hi)


@dataclass
class McNemarResult:
    b: int          # detector A correct, B wrong
    c: int          # detector A wrong, B correct
    statistic: float
    p_value: float


def mcnemar(
    y_true: Sequence[int],
    pred_a: Sequence[int],
    pred_b: Sequence[int],
    correction: bool = True,
) -> McNemarResult:
    """Paired McNemar test comparing two detectors on the same snippets.

    Builds the discordant pair counts (b, c) over correctness against
    ``y_true`` and applies the χ²(1) test. Uses Edwards' continuity
    correction by default; falls back to an exact binomial p-value when the
    discordant total is small (b + c < 25), as is standard.
    """
    y_true = np.asarray(y_true, dtype=int)
    a_ok = np.asarray(pred_a, dtype=int) == y_true
    b_ok = np.asarray(pred_b, dtype=int) == y_true

    b = int(np.sum(a_ok & ~b_ok))
    c = int(np.sum(~a_ok & b_ok))
    n = b + c

    if n == 0:
        return McNemarResult(b=b, c=c, statistic=0.0, p_value=1.0)

    if n < 25:
        # Exact binomial (two-sided), more reliable for few discordant pairs.
        p = float(min(1.0, 2 * stats.binom.cdf(min(b, c), n, 0.5)))
        stat = float(min(b, c))
        return McNemarResult(b=b, c=c, statistic=stat, p_value=p)

    diff = abs(b - c) - (1 if correction else 0)
    stat = float(diff * diff) / n
    p = float(stats.chi2.sf(stat, df=1))
    return McNemarResult(b=b, c=c, statistic=stat, p_value=p)
