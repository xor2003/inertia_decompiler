# cython: language_level=3, infer_types=True
"""Select bounded non-optimized fallback policy without creating semantic proof.

Layer: CLI/fallback/reporting.
Responsibility: decide when bounded non-optimized fallback lanes are allowed.
"""

from __future__ import annotations
import typing
import cython

from inertia.cli.slice_recovery import BoundedSliceVerdict


@cython.ccall
def allows_heavy_fallbacks_for_run(
    *,
    interactive_stdout: cython.bint,
    max_functions: cython.longlong,
    addr_requested: cython.bint,
) -> cython.bint:
    """Return whether the run is in a heavy-fallback lane."""
    return interactive_stdout or max_functions <= 0 or addr_requested


@cython.ccall
def bounded_non_optimized_attempt_timeout(timeout: cython.longlong) -> cython.longlong:
    """Return the per-attempt timeout for bounded non-optimized slice recovery."""
    return max(2, min(timeout, 4) + 3)


@cython.ccall
def describe_non_optimized_unavailable(
    *,
    allow_heavy_fallbacks: cython.bint,
    skip_heavy_fallbacks_for_result: cython.bint,
    interactive_stdout: cython.bint,
    max_functions: cython.longlong,
    addr_requested: cython.bint,
    result_status: object,
    failure_stage: object,
    nonopt_failure_detail: object,
) -> object:
    """Compute one deterministic reason string for why non-opt fallback is unavailable."""
    if not allow_heavy_fallbacks:
        if isinstance(nonopt_failure_detail, str) and nonopt_failure_detail.strip():
            return nonopt_failure_detail
        lane_detail = (
            f"interactive_stdout={interactive_stdout}, max_functions={max_functions}, "
            f"addr={'set' if addr_requested else 'unset'}"
        )
        return f"heavy fallback lane disabled for sweep mode ({lane_detail})"
    if skip_heavy_fallbacks_for_result:
        stage_detail = f"stage={failure_stage or 'unknown'}"
        return f"{result_status} result keeps heavy fallback lane closed ({stage_detail})"
    return nonopt_failure_detail


@cython.ccall
def sidecar_verdict_closes_non_optimized_lane(verdict: object) -> cython.bint:
    """Return whether a dead sidecar verdict makes the later non-opt lane redundant."""
    if verdict is None:
        return False
    if verdict.can_widen_locally:
        return False
    return verdict.stage == "recover" and verdict.stop_family == "timeout"
