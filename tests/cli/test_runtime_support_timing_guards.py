from __future__ import annotations

import inspect
import signal
import threading
import time

import inertia.structuring.decompiler_structuring_stage as decompiler_structuring_stage
import inertia.lowering.stack_lowering_from_facts as stack_lowering_from_facts
import pytest

import inertia.validation.tail_validation as tail_validation
import inertia.cli.analysis_timeout as analysis_timeout_support
from inertia.cli.runtime_support import (
    AnalysisTimeout,
    guard_angr_structuring_codegen_internal_timing,
    guard_angr_tail_validation_collection_timing,
    run_with_timeout_in_daemon_thread,
)


def test_process_alarm_timeout_does_not_leave_daemon_work_running():
    thread_name = "process-alarm-timeout-regression"

    with pytest.raises(AnalysisTimeout):
        run_with_timeout_in_daemon_thread(
            lambda: time.sleep(60),
            timeout=1,
            thread_name_prefix=thread_name,
            prefer_process_alarm=True,
        )

    assert all(thread.name != thread_name for thread in threading.enumerate())


def test_process_alarm_defers_timeout_inside_finalizer(monkeypatch: pytest.MonkeyPatch) -> None:
    retries: list[tuple[int, float]] = []

    def record_retry(timer: int, seconds: float) -> tuple[float, float]:
        retries.append((timer, seconds))
        return (0.0, 0.0)

    def __del__() -> None:
        frame = inspect.currentframe()
        assert frame is not None
        analysis_timeout_support.raise_timeout(signal.SIGALRM, frame)

    monkeypatch.setattr(analysis_timeout_support.signal, "setitimer", record_retry)

    __del__()

    assert retries == [(signal.ITIMER_REAL, analysis_timeout_support._FINALIZER_RETRY_SECONDS)]


def test_guard_structuring_timing_preserves_stack_lowering_from_facts_signature(monkeypatch):
    recorded: list[tuple[object, tuple[object, ...], dict[str, object]]] = []

    def _fake_lower_stack_accesses_from_alias_facts_8616(codegen, alias_facts, **kwargs):
        recorded.append((codegen, (alias_facts,), kwargs))
        return "ok"

    monkeypatch.setattr(
        stack_lowering_from_facts,
        "lower_stack_accesses_from_alias_facts_8616",
        _fake_lower_stack_accesses_from_alias_facts_8616,
    )

    with guard_angr_structuring_codegen_internal_timing():
        result = stack_lowering_from_facts.lower_stack_accesses_from_alias_facts_8616(
            "cg",
            ["fact"],
            validation_clone=True,
        )

    assert result == "ok"
    assert recorded == [("cg", (["fact"],), {"validation_clone": True})]


def test_tail_validation_timing_guard_forwards_boundary_fingerprint(monkeypatch):
    recorded: list[tuple[object, object, str, str | None]] = []
    original_stage_collect = decompiler_structuring_stage.collect_x86_16_tail_validation_summary

    def _fake_collect(
        project: object,
        codegen: object,
        *,
        mode: str,
        boundary_fingerprint: str | None = None,
    ) -> str:
        recorded.append((project, codegen, mode, boundary_fingerprint))
        return "summary"

    monkeypatch.setenv("INERTIA_DEBUG_TIMING", "1")
    monkeypatch.setattr(tail_validation, "collect_x86_16_tail_validation_summary", _fake_collect)
    project = object()
    codegen = object()

    with guard_angr_tail_validation_collection_timing():
        result = decompiler_structuring_stage.collect_x86_16_tail_validation_summary(
            project,
            codegen,
            mode="live_out",
            boundary_fingerprint="boundary-1",
        )

    assert result == "summary"
    assert recorded == [(project, codegen, "live_out", "boundary-1")]
    assert decompiler_structuring_stage.collect_x86_16_tail_validation_summary is original_stage_collect
