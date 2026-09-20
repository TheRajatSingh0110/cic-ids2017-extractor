"""Online summary statistics matching Apache Commons Math ``SummaryStatistics``.

CICFlowMeter computes its means/standard-deviations/variance with Commons Math's
`SummaryStatistics` (bias-corrected i.e. sample statistics, n-1 denominator).

Unlike Commons Math (which can yield NaN for empty one-value series) this online
accumulator is hardened per project requirements: every accessor returns a real
number, and 0.0 whenever there is not enough data.  No NaN/Inf can be produced.
"""

from __future__ import annotations

import math

__all__ = ["OnlineStats"]


class OnlineStats:
    """Online mean / (sample) variance / (sample) std / min / max accumulator."""

    __slots__ = ("_count", "_sum", "_sum_sq", "_min", "_max")

    def __init__(self) -> None:
        self._count = 0
        self._sum = 0.0
        self._sum_sq = 0.0
        self._min: float = math.inf
        self._max: float = -math.inf

    def add(self, value: float) -> None:
        """Add one observation."""
        v = float(value)
        self._count += 1
        self._sum += v
        self._sum_sq += v * v
        if v < self._min:
            self._min = v
        if v > self._max:
            self._max = v

    # -- count/sum ----------------------------------------------------- #
    @property
    def n(self) -> int:
        return self._count

    def get_sum(self) -> float:
        return self._sum

    # -- mean (0.0 when empty) ----------------------------------------- #
    def mean(self) -> float:
        if self._count > 0:
            return self._sum / self._count
        return 0.0

    # -- sample variance (n-1 denominator), 0.0 when n < 2 ------------- #
    def variance(self) -> float:
        if self._count < 2:
            return 0.0
        mean = self._sum / self._count
        var = (self._sum_sq / self._count) - (mean * mean)
        return var * (self._count / (self._count - 1))  # bias correction

    # -- sample standard deviation ------------------------------------- #
    def std(self) -> float:
        return math.sqrt(max(0.0, self.variance()))

    # -- min / max (0.0 when empty) ------------------------------------ #
    def min(self) -> float:
        return 0.0 if self._count == 0 else self._min

    def max(self) -> float:
        return 0.0 if self._count == 0 else self._max

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"OnlineStats(n={self._count}, sum={self._sum:.4f}, "
            f"mean={self.mean():.4f}, std={self.std():.4f})"
        )