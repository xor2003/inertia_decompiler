"""Layer: Tests.

Responsibility: preserve ranked function task accounting and existing recovery
identity when CLI display limits require replacing the recovered queue.
"""

from types import SimpleNamespace

import pytest

from inertia.cli import cli_core
from inertia.cli.work_items import FunctionWorkItem


def test_limited_ranked_queue_keeps_existing_and_placeholder_tasks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rebuilding a limited ranked queue must not silently discard its tasks."""
    function = SimpleNamespace(addr=0x1000, name="existing")
    existing = FunctionWorkItem(7, object(), function, recovery_addr=0x1000)
    original_tasks = [existing]
    placeholder = SimpleNamespace(addr=0x2000, name="placeholder")
    run = cli_core._MainCliRun8616(
        args=SimpleNamespace(max_functions=1), function_tasks=original_tasks,
        ranked_binary_offsets=[0x1000, 0x2000],
    )
    monkeypatch.setattr(cli_core, "_library_ranked_task_gate_8616", lambda *args: True)
    monkeypatch.setattr(cli_core, "_make_placeholder_function", lambda *args: placeholder)
    assert run._phase_build_tasks_8616_else_8616_part0_8616_o1() is None
    assert original_tasks == [existing]
    assert len(run.function_tasks) == run.shown_total == 2
    first, second = run.function_tasks
    assert first.index == 1 and first.function is function
    assert first.function_cfg is existing.function_cfg and first.recovery_addr == 0x1000
    assert second.index == 2 and second.function is placeholder
    assert second.function_cfg is None and second.recovery_addr == 0x2000
