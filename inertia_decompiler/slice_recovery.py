from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Sequence


SliceRecoverCallable = Callable[[Any], tuple[Any, Any]]


@dataclass(frozen=True)
class SliceRecoveryAttemptOutcome:
    attempt_name: str
    status: str
    payload: str
    partial_payload: str | None = None
    snapshot: dict[str, object] | None = None


def build_default_slice_recovery_attempts(
    start: int,
    end: int,
    *,
    pick_function_lean: Callable[..., tuple[Any, Any]],
    pick_function: Callable[..., tuple[Any, Any]],
) -> tuple[tuple[str, SliceRecoverCallable], ...]:
    region = [(start, end)]
    return (
        (
            "lean",
            lambda slice_project: pick_function_lean(
                slice_project,
                start,
                regions=region,
                data_references=False,
                extend_far_calls=False,
            ),
        ),
        (
            "full-no-refs",
            lambda slice_project: pick_function(
                slice_project,
                start,
                regions=region,
                data_references=False,
                force_smart_scan=False,
            ),
        ),
        (
            "full-with-refs",
            lambda slice_project: pick_function(
                slice_project,
                start,
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
) -> tuple[SliceRecoveryAttemptOutcome, ...]:
    outcomes: list[SliceRecoveryAttemptOutcome] = []
    for attempt_name, recover in attempts:
        try:
            slice_project = build_slice_project()
            inherit_runtime_policy(slice_project)
            cfg, func = recover(slice_project)
        except Exception as ex:  # noqa: BLE001
            outcomes.append(
                SliceRecoveryAttemptOutcome(
                    attempt_name=attempt_name,
                    status="error",
                    payload=f"{attempt_name} recovery: {describe_exception(ex)}",
                )
            )
            continue
        outcome = decompile(attempt_name, slice_project, cfg, func)
        outcomes.append(outcome)
        if outcome.status == "ok":
            break
    return tuple(outcomes)


def bounded_slice_runner_timeout(
    *,
    timeout: int,
    attempt_count: int,
    per_attempt_timeout_cap: int,
    setup_slack: int = 1,
    max_timeout: int,
) -> int:
    per_attempt_timeout = max(1, min(timeout, per_attempt_timeout_cap))
    return max(2, min(attempt_count * (per_attempt_timeout + setup_slack), max_timeout))
