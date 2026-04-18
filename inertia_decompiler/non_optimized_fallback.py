from __future__ import annotations

from inertia_decompiler.slice_recovery import BoundedSliceVerdict


def allows_heavy_fallbacks_for_run(
    *,
    interactive_stdout: bool,
    max_functions: int,
    addr_requested: bool,
) -> bool:
    """Return whether the run is in a heavy-fallback lane."""
    return interactive_stdout or max_functions <= 0 or addr_requested


def bounded_non_optimized_attempt_timeout(timeout: int) -> int:
    """Return the per-attempt timeout for bounded non-optimized slice recovery."""
    return max(2, min(timeout, 4) + 3)


def describe_non_optimized_unavailable(
    *,
    allow_heavy_fallbacks: bool,
    skip_heavy_fallbacks_for_result: bool,
    interactive_stdout: bool,
    max_functions: int,
    addr_requested: bool,
    result_status: str,
    failure_stage: str | None,
    nonopt_failure_detail: str | None,
) -> str | None:
    """Compute one deterministic reason string for why non-opt fallback is unavailable."""
    if not allow_heavy_fallbacks:
        lane_detail = (
            f"interactive_stdout={interactive_stdout}, max_functions={max_functions}, "
            f"addr={'set' if addr_requested else 'unset'}"
        )
        return f"heavy fallback lane disabled for sweep mode ({lane_detail})"
    if skip_heavy_fallbacks_for_result:
        stage_detail = f"stage={failure_stage or 'unknown'}"
        return f"{result_status} result keeps heavy fallback lane closed ({stage_detail})"
    return nonopt_failure_detail


def sidecar_verdict_closes_non_optimized_lane(verdict: BoundedSliceVerdict | None) -> bool:
    """Return whether a dead sidecar verdict makes the later non-opt lane redundant."""
    if verdict is None:
        return False
    if verdict.can_widen_locally:
        return False
    return verdict.stage == "recover" and verdict.stop_family == "timeout"
