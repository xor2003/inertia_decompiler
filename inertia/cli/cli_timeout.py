"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

import math
import sys

_MEDIUM_FUNCTION_TIMEOUT_FLOOR: int = 150
_LARGE_FUNCTION_TIMEOUT_FLOOR: int = 240
_COLD_CLEAN_WORKER_TIMEOUT_FLOOR: int = 240
PARALLEL_CLEAN_WORKER_TIMEOUT_CAP: int = 360


def _default_recovery_timeout(configured_timeout: int, *, explicit_timeout: bool) -> int:
    """Return the recovery budget selected by CLI timeout policy."""
    if configured_timeout <= 0:
        return 5
    if not explicit_timeout:
        return max(5, configured_timeout)
    return configured_timeout


class _AdaptivePerByteTimeoutModel:
    """Estimate serial function budgets from size and successful run evidence."""

    def __init__(self, configured_timeout: int, *, explicit_timeout: bool, margin: float = 1.5) -> None:
        """Initialize a bounded timing model for one serial function sweep."""
        self.configured_timeout = max(1, configured_timeout)
        self.explicit_timeout = explicit_timeout
        self.margin = max(1.0, float(margin))
        self._samples: list[tuple[int, float]] = []

    def observe_success(self, byte_count: int, elapsed: float) -> None:
        """Record one successful recovery timing sample."""
        if byte_count <= 0 or elapsed <= 0:
            return
        self._samples.append((byte_count, float(elapsed)))
        if len(self._samples) > 64:
            self._samples = self._samples[-64:]

    def _seed_rate(self) -> float:
        """Return a conservative observed seconds-per-byte rate."""
        if not self._samples:
            return 0.05
        rates = [elapsed / max(1, byte_count) for byte_count, elapsed in self._samples]
        return max(0.005, max(rates))

    def timeout_for_byte_count(self, byte_count: int) -> int:
        """Return the timeout budget for a function with the given byte count."""
        base = max(1, int(self.configured_timeout))
        if self.explicit_timeout:
            return base
        static_floor = base
        if byte_count >= 520:
            static_floor = _LARGE_FUNCTION_TIMEOUT_FLOOR
        elif byte_count >= 280:
            static_floor = _MEDIUM_FUNCTION_TIMEOUT_FLOOR
        observed_budget = math.ceil(self._seed_rate() * max(0, byte_count) * self.margin)
        return max(base, static_floor, observed_budget)


def build_parallel_clean_worker_timeout_model(
    configured_timeout: int,
    *,
    explicit_timeout: bool,
) -> _AdaptivePerByteTimeoutModel:
    """Build the bounded timeout model for fresh parallel worker processes.

    A clean worker pays interpreter, project, and whole-program evidence setup
    before function-size-dependent work begins. The default sweep policy must
    cover that measured cold cost, while an explicit user timeout remains
    authoritative.
    """
    effective_timeout = (
        configured_timeout
        if explicit_timeout
        else max(configured_timeout, _COLD_CLEAN_WORKER_TIMEOUT_FLOOR)
    )
    return _AdaptivePerByteTimeoutModel(
        effective_timeout,
        explicit_timeout=explicit_timeout,
        margin=1.5,
    )


def retry_timeout_after_failed_attempt(
    configured_timeout: int,
    *,
    elapsed_seconds: float | None,
    timed_out: bool,
    explicit_timeout: bool,
) -> int:
    """Return a retry budget derived from the failed attempt's measured cost."""
    configured = max(1, configured_timeout)
    if explicit_timeout:
        return configured
    retry_timeout = max(configured, _COLD_CLEAN_WORKER_TIMEOUT_FLOOR)
    if timed_out and elapsed_seconds is not None and math.isfinite(elapsed_seconds):
        retry_timeout = max(retry_timeout, math.ceil(elapsed_seconds) + 30)
    return min(retry_timeout, PARALLEL_CLEAN_WORKER_TIMEOUT_CAP)


def _stdout_is_interactive() -> bool:
    """Return whether stdout is an interactive terminal."""
    stream = sys.stdout
    try:
        return bool(stream is not None and hasattr(stream, "isatty") and stream.isatty())
    except Exception:
        return False
