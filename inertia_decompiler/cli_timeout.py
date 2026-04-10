from __future__ import annotations

import math
import sys


def _default_recovery_timeout(configured_timeout: int, *, explicit_timeout: bool) -> int:
    if configured_timeout <= 0:
        return 5
    if configured_timeout <= 5:
        return configured_timeout
    return 5


class _AdaptivePerByteTimeoutModel:
    def __init__(self, configured_timeout: int, *, explicit_timeout: bool, margin: float = 1.5):
        self.configured_timeout = max(1, configured_timeout)
        self.explicit_timeout = explicit_timeout
        self.margin = max(1.0, float(margin))
        self._samples: list[tuple[int, float]] = []

    def observe_success(self, byte_count: int, elapsed: float) -> None:
        if byte_count <= 0 or elapsed <= 0:
            return
        self._samples.append((byte_count, float(elapsed)))
        if len(self._samples) > 64:
            self._samples = self._samples[-64:]

    def _seed_rate(self) -> tuple[float, float]:
        if not self._samples:
            return (0.05, 0.5)
        rates = [elapsed / max(1, byte_count) for byte_count, elapsed in self._samples]
        overheads = [max(0.0, elapsed - (rate * byte_count)) for (byte_count, elapsed), rate in zip(self._samples, rates)]
        rate = sum(rates) / len(rates)
        overhead = sum(overheads) / len(overheads) if overheads else 0.5
        return max(0.005, rate), max(0.0, overhead)

    def timeout_for_byte_count(self, byte_count: int) -> int:
        if self.explicit_timeout:
            return self.configured_timeout
        rate, overhead = self._seed_rate()
        estimate = self.margin * (overhead + rate * max(1, byte_count))
        return max(2, min(180, math.ceil(max(2.0, estimate))))


def _stdout_is_interactive() -> bool:
    stream = getattr(sys, "stdout", None)
    try:
        return bool(stream is not None and hasattr(stream, "isatty") and stream.isatty())
    except Exception:
        return False
