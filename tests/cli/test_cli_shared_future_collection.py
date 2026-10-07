"""Layer: Tests.

Responsibility: verify shared-worker collection uses its own task map, retains
worker failures, and propagates emission failures without requiring DOS tools.
"""

from concurrent.futures import Future
from types import SimpleNamespace

import pytest

from inertia.cli import cli_core
from inertia.cli.work_items import FunctionWorkItem, FunctionWorkResult


@pytest.mark.parametrize("worker_error", [False, True])
def test_shared_collector_uses_its_own_future_map(
    monkeypatch: pytest.MonkeyPatch, worker_error: bool,
) -> None:
    """Shared workers need no isolated-worker map or timeout table."""
    function = SimpleNamespace(addr=0x1000, name="sample")
    item = FunctionWorkItem(1, object(), function)
    future: Future[FunctionWorkResult] = Future()
    result = FunctionWorkResult(1, "ok", "payload", "worker debug", function, item.function_cfg)
    if worker_error:
        future.set_exception(ValueError("worker failed"))
    else:
        future.set_result(result)
    run = cli_core._MainCliRun8616(
        args=SimpleNamespace(timeout=2, addr=None),
        future_map={future: item}, done={future}, pending={future},
        result_map={}, emitted_indexes=set(), decompiled=0, failed=0,
    )
    emitted: list[FunctionWorkResult] = []

    def emit(
        work_item: FunctionWorkItem, work_result: FunctionWorkResult, **kwargs: object,
    ) -> tuple[int, int]:
        assert work_item is item
        emitted.append(work_result)
        return (0, 1) if worker_error else (1, 0)

    monkeypatch.setattr(cli_core, "_emit_function_result", emit)
    assert run._phase_serial_fork_batch_8616_else_8616_part0_8616_b1_zb1_w1() is None
    assert run.item_by_future is None and run.timeout_by_index is None
    assert run.pending == set() and run.emitted_indexes == {1}
    assert run.result_map[1] is emitted[0]
    assert (run.decompiled, run.failed) == ((0, 1) if worker_error else (1, 0))
    if worker_error:
        assert emitted[0].status == "error" and "worker failed" in emitted[0].payload
    else:
        assert emitted[0] is result


@pytest.mark.parametrize("emission_failure", [False, True])
@pytest.mark.parametrize("through_wait_loop", [False, True])
def test_shared_budget_sweep_collects_completed_pending_futures(
    monkeypatch: pytest.MonkeyPatch, emission_failure: bool, through_wait_loop: bool,
) -> None:
    """An expired sweep collects ready work without waiting on unfinished work."""
    function = SimpleNamespace(addr=0x1000, name="sample")
    item = FunctionWorkItem(1, object(), function)
    unfinished_item = FunctionWorkItem(2, object(), function)
    ready: Future[FunctionWorkResult] = Future()
    unfinished: Future[FunctionWorkResult] = Future()
    result = FunctionWorkResult(1, "ok", "payload", "debug", function, item.function_cfg)
    ready.set_result(result)
    run = cli_core._MainCliRun8616(
        args=SimpleNamespace(timeout=2, addr=0x1000 if emission_failure else None, binary="unused"),
        sweep_deadline=0.0,
        future_map={ready: item, unfinished: unfinished_item}, done=None,
        pending={ready, unfinished}, result_map={}, emitted_indexes=set(),
        decompiled=0, failed=0,
    )

    def emit(
        work_item: FunctionWorkItem, work_result: FunctionWorkResult, **kwargs: object,
    ) -> tuple[int, int]:
        assert work_item is item and work_result is result
        return (0, 1) if emission_failure else (1, 0)

    monkeypatch.setattr(cli_core, "_emit_function_result", emit)
    summaries: list[object] = []
    monkeypatch.setattr(
        cli_core, "_emit_tail_validation_console_summary",
        lambda *args, **kwargs: summaries.append(kwargs["binary_path"]),
    )
    monkeypatch.setattr(cli_core.time, "monotonic", lambda: 10.0)
    if through_wait_loop:
        assert run._phase_serial_fork_batch_8616_else_8616_part0_8616_b1_zb1() == (
            2 if emission_failure else None
        )
    else:
        assert run._phase_serial_fork_batch_8616_else_8616_part0_8616_b1_zb1_w0() == (
            True, 2 if emission_failure else None,
        )
    assert run.result_map == {1: result} and run.emitted_indexes == {1}
    assert run.pending == set() and run.has_expired_futures
    assert not unfinished.done()
    assert summaries == (["unused"] if emission_failure else [])
