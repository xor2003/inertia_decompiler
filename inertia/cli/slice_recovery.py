# cython: language_level=3, infer_types=True
"""Run bounded slice recovery attempts and record their outcomes.

Layer: CLI/fallback/reporting.
Responsibility: orchestrate bounded slice fallback attempts without accepting them as semantic proof.
"""

from __future__ import annotations
import typing
import cython

import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import asdict, dataclass, replace
from typing import Any
import dataclasses
import operator

SliceRecoverCallable = typing.TypeAliasType("SliceRecoverCallable", Callable[[Any], tuple[Any, Any]])
SliceRecoveryRunner = typing.TypeAliasType("SliceRecoveryRunner", Callable[
    [str, Callable[[], "SliceRecoveryAttemptOutcome"], Callable[[], "SliceRecoveryAttemptTrace"]],
    "SliceRecoveryAttemptOutcome",
])


@dataclasses.dataclass(frozen=True)
class SliceRecoveryAttemptTrace:
    """Timing and failure-stage trace for one slice recovery attempt."""

    failure_stage: object
    build_ms: int | None = None
    recover_ms: int | None = None
    decompile_ms: int | None = None


@dataclasses.dataclass(frozen=True)
class BoundedSliceVerdict:
    """Structured retry verdict for a bounded slice recovery attempt."""

    stage: object
    stop_family: object
    can_widen_locally: cython.bint
    can_retry_with_fresh_project: cython.bint


@dataclasses.dataclass(frozen=True)
class SliceRecoveryAttemptOutcome:
    """Outcome payload and retry metadata for one slice recovery attempt."""

    attempt_name: object
    status: object
    payload: object
    partial_payload: object = None
    snapshot: object = None
    attempt_trace: SliceRecoveryAttemptTrace | None = None
    verdict: BoundedSliceVerdict | None = None

    def __iter__(self) -> Iterator[str]:
        """Iterate status and payload for legacy tuple-unpacking callers."""
        yield self.status
        yield self.payload

    def __len__(self) -> cython.longlong:
        """Return the legacy tuple-compatible item count."""
        return 2

    def __getitem__(self, index: cython.longlong) -> object:
        """Return status or payload for legacy tuple-indexing callers."""
        if index == 0:
            return self.status
        if index == 1:
            return self.payload
        raise IndexError(index)

    def __eq__(self, other: object) -> cython.bint:
        """Compare with either another outcome or a legacy status/payload tuple."""
        if isinstance(other, tuple):
            return (self.status, self.payload) == other
        if isinstance(other, SliceRecoveryAttemptOutcome):
            return operator.eq(asdict(self), asdict(other))
        return NotImplemented


@cython.ccall
def _build_bounded_slice_verdict(
    trace: object,
    *,
    status: object,
    partial_payload: object,
) -> BoundedSliceVerdict:
    stage = trace.failure_stage if trace is not None else None
    normalized_status = status.strip().lower()
    if normalized_status == "ok":
        return BoundedSliceVerdict(
            stage=stage,
            stop_family="ok",
            can_widen_locally=False,
            can_retry_with_fresh_project=False,
        )
    if normalized_status == "timeout":
        if partial_payload is not None:
            return BoundedSliceVerdict(
                stage=stage,
                stop_family="partial-timeout",
                can_widen_locally=False,
                can_retry_with_fresh_project=False,
            )
        return BoundedSliceVerdict(
            stage=stage,
            stop_family="timeout",
            can_widen_locally=True,
            can_retry_with_fresh_project=True,
        )
    if normalized_status == "empty":
        return BoundedSliceVerdict(
            stage=stage,
            stop_family="empty",
            can_widen_locally=True,
            can_retry_with_fresh_project=False,
        )
    return BoundedSliceVerdict(
        stage=stage,
        stop_family=normalized_status or "error",
        can_widen_locally=True,
        can_retry_with_fresh_project=stage in {"build", "recover", "decompile"},
    )


def _stabilize_bounded_slice_verdict(
    prior_outcomes: Sequence[SliceRecoveryAttemptOutcome],
    verdict: BoundedSliceVerdict,
) -> BoundedSliceVerdict:
    if verdict.stop_family in {None, "ok", "empty"}:
        return verdict
    repeated_family = any(
        prior.verdict is not None
        and operator.eq(prior.verdict.stage, verdict.stage)
        and operator.eq(prior.verdict.stop_family, verdict.stop_family)
        for prior in iter(prior_outcomes)
    )
    if not repeated_family or not verdict.can_widen_locally:
        return verdict
    return BoundedSliceVerdict(
        stage=verdict.stage,
        stop_family=verdict.stop_family,
        can_widen_locally=False,
        can_retry_with_fresh_project=verdict.can_retry_with_fresh_project,
    )


def build_default_slice_recovery_attempts(
    start: cython.longlong,
    end: cython.longlong,
    *,
    entry: int | None = None,
    pick_function_lean: Callable[..., tuple[Any, Any]],
    pick_function: Callable[..., tuple[Any, Any]],
) -> tuple[tuple[str, SliceRecoverCallable], ...]:
    """Build attempts that recover ``entry`` while bounding reads to ``start:end``."""
    recovery_entry = start if entry is None else entry
    if not start <= recovery_entry < end:
        raise ValueError("slice recovery entry must be inside the bounded region")
    region = [(start, end)]
    return (
        (
            "lean",
            lambda slice_project: pick_function_lean(
                slice_project,
                recovery_entry,
                regions=region,
                data_references=False,
                extend_far_calls=False,
            ),
        ),
        (
            "full-no-refs",
            lambda slice_project: pick_function(
                slice_project,
                recovery_entry,
                regions=region,
                data_references=False,
                force_smart_scan=False,
            ),
        ),
        (
            "full-with-refs",
            lambda slice_project: pick_function(
                slice_project,
                recovery_entry,
                regions=region,
                data_references=True,
                force_smart_scan=False,
            ),
        ),
    )


def run_bounded_slice_recovery(
    attempts: Sequence[tuple[str, SliceRecoverCallable]],
    *,
    build_slice_project: Callable[[], Any],
    inherit_runtime_policy: Callable[[Any], None],
    decompile: Callable[[str, Any, Any, Any], SliceRecoveryAttemptOutcome],
    describe_exception: Callable[[Exception], str],
    run_attempt: SliceRecoveryRunner | None = None,
) -> tuple[SliceRecoveryAttemptOutcome, ...]:
    """Run bounded slice recovery attempts until success or a stable stop verdict."""
    outcome: object
    attempt_name: object
    recover: object
    outcomes: list[SliceRecoveryAttemptOutcome] = []
    for attempt_name, recover in attempts:
        trace_state: dict[str, int | str | None] = {
            "failure_stage": "build",
            "build_ms": None,
            "recover_ms": None,
            "decompile_ms": None,
        }

        def _trace_snapshot() -> SliceRecoveryAttemptTrace:
            return SliceRecoveryAttemptTrace(
                failure_stage=str(trace_state["failure_stage"]),  # noqa: B023
                build_ms=trace_state["build_ms"] if isinstance(trace_state["build_ms"], int) else None,  # noqa: B023
                recover_ms=trace_state["recover_ms"] if isinstance(trace_state["recover_ms"], int) else None,  # noqa: B023
                decompile_ms=trace_state["decompile_ms"] if isinstance(trace_state["decompile_ms"], int) else None,  # noqa: B023
            )

        def _run_one_attempt() -> SliceRecoveryAttemptOutcome:
            try:
                started = time.perf_counter()
                slice_project = build_slice_project()
                trace_state["build_ms"] = round((time.perf_counter() - started) * 1000)  # noqa: B023
                inherit_runtime_policy(slice_project)
                trace_state["failure_stage"] = "recover"  # noqa: B023
                started = time.perf_counter()
                cfg, func = recover(slice_project)  # noqa: B023
                trace_state["recover_ms"] = round((time.perf_counter() - started) * 1000)  # noqa: B023
            except Exception as ex:
                return SliceRecoveryAttemptOutcome(
                    attempt_name=attempt_name,  # noqa: B023
                    status="error",
                    payload=f"{attempt_name} recovery: {describe_exception(ex)}",  # noqa: B023
                    attempt_trace=_trace_snapshot(),
                )
            trace_state["failure_stage"] = "decompile"  # noqa: B023
            started = time.perf_counter()
            outcome = decompile(attempt_name, slice_project, cfg, func)  # noqa: B023
            trace_state["decompile_ms"] = round((time.perf_counter() - started) * 1000)  # noqa: B023
            return replace(outcome, attempt_trace=_trace_snapshot())

        outcome = (
            run_attempt(attempt_name, _run_one_attempt, _trace_snapshot)
            if run_attempt is not None
            else _run_one_attempt()
        )
        if outcome is None:
            outcome = SliceRecoveryAttemptOutcome(
                attempt_name=attempt_name,
                status="error",
                payload=f"{attempt_name} bounded attempt returned no outcome",
            )
        trace = outcome.attempt_trace if outcome.attempt_trace is not None else _trace_snapshot()
        verdict = (
            outcome.verdict
            if outcome.verdict is not None
            else _build_bounded_slice_verdict(
                trace,
                status=outcome.status,
                partial_payload=outcome.partial_payload,
            )
        )
        outcome = replace(
            outcome,
            attempt_trace=trace,
            verdict=_stabilize_bounded_slice_verdict(outcomes, verdict),
        )
        outcomes.append(outcome)
        if outcome.status == "ok":
            break
        if outcome.verdict is not None and not outcome.verdict.can_widen_locally:
            break
    return tuple(outcomes)


def bounded_slice_runner_timeout(
    *,
    timeout: cython.longlong,
    attempt_count: cython.longlong,
    per_attempt_timeout_cap: cython.longlong,
    setup_slack: cython.longlong = 1,
    max_timeout: cython.longlong,
) -> cython.longlong:
    """Compute the timeout budget for bounded slice recovery attempts."""
    per_attempt_timeout = max(1, min(timeout, per_attempt_timeout_cap))
    return max(2, min(attempt_count * (per_attempt_timeout + setup_slack), max_timeout))
