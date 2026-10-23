from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass

from inertia.cli.function_worker_policy import (
    CLEAN_PROCESS_WORKER_CAP_8616,
    CleanProcessOverride8616,
    FunctionWorkerMode8616,
    clean_process_override_8616,
    dependency_ordered_function_work_8616,
    prioritize_clean_function_work_8616,
    select_function_worker_policy_8616,
)


@dataclass(frozen=True, slots=True)
class _WorkItem:
    """Minimal deterministic clean-worker scheduling fixture."""

    index: int
    function: object


def _policy(**overrides: object):
    inputs: dict[str, object] = {
        "isolation_required": True,
        "sidecar_available": False,
        "full_sweep": True,
        "include_library_functions": False,
        "posix_available": True,
        "function_count": 20,
        "shared_worker_count": 7,
        "clean_process_override": CleanProcessOverride8616.DEFAULT,
    }
    inputs.update(overrides)
    return select_function_worker_policy_8616(**inputs)  # type: ignore[arg-type]


def test_pure_binary_whole_file_uses_bounded_clean_processes_by_default() -> None:
    policy = _policy()

    assert policy.mode is FunctionWorkerMode8616.CLEAN_PROCESS
    assert policy.workers == CLEAN_PROCESS_WORKER_CAP_8616


def test_sidecar_whole_file_uses_clean_processes_to_bound_native_state() -> None:
    policy = _policy(sidecar_available=True)

    assert policy.mode is FunctionWorkerMode8616.CLEAN_PROCESS
    assert policy.workers == CLEAN_PROCESS_WORKER_CAP_8616


def test_explicit_clean_process_override_supports_sidecar_runs() -> None:
    policy = _policy(
        sidecar_available=True,
        clean_process_override=CleanProcessOverride8616.ENABLED,
    )

    assert policy.mode is FunctionWorkerMode8616.CLEAN_PROCESS
    assert policy.workers == CLEAN_PROCESS_WORKER_CAP_8616


def test_explicit_disable_preserves_single_shared_worker() -> None:
    policy = _policy(clean_process_override=CleanProcessOverride8616.DISABLED)

    assert policy.mode is FunctionWorkerMode8616.SHARED
    assert policy.workers == 1


def test_clean_process_mode_is_bounded_by_functions_and_cpu_budget() -> None:
    assert _policy(function_count=2).workers == 2
    assert _policy(function_count=200).workers == CLEAN_PROCESS_WORKER_CAP_8616


def test_non_x86_policy_preserves_shared_worker_selection() -> None:
    policy = _policy(isolation_required=False, function_count=3, shared_worker_count=7)

    assert policy.mode is FunctionWorkerMode8616.SHARED
    assert policy.workers == 3


def test_clean_process_override_parser_returns_typed_states() -> None:
    assert clean_process_override_8616(None) is CleanProcessOverride8616.DEFAULT
    assert clean_process_override_8616("yes") is CleanProcessOverride8616.ENABLED
    assert clean_process_override_8616("0") is CleanProcessOverride8616.DISABLED
    assert clean_process_override_8616("unexpected") is CleanProcessOverride8616.DEFAULT


def test_clean_function_work_prioritizes_complexity_and_stable_index() -> None:
    costs = {
        "small": (2, 40),
        "large": (42, 320),
        "tie_late": (20, 180),
        "tie_early": (20, 180),
    }
    items = (
        _WorkItem(4, "small"),
        _WorkItem(3, "tie_late"),
        _WorkItem(1, "large"),
        _WorkItem(2, "tie_early"),
    )

    scheduled = prioritize_clean_function_work_8616(
        items,
        function_complexity=lambda function: costs[str(function)],
    )

    assert tuple(item.index for item in scheduled) == (1, 2, 3, 4)


@dataclass(frozen=True)
class _CallFunction:
    """Already recovered direct calls; no discovery work is permitted."""

    addr: int
    targets: tuple[int | None, ...] = ()

    def get_call_sites(self) -> tuple[int, ...]:
        return tuple(range(len(self.targets)))

    def get_call_target(self, callsite: int) -> int | None:
        return self.targets[callsite]


def test_dependency_order_preserves_items_and_input_order() -> None:
    caller = _WorkItem(1, _CallFunction(100, (200, 300)))
    middle = _WorkItem(2, _CallFunction(200, (300,)))
    leaf = _WorkItem(3, _CallFunction(300))
    items = [caller, middle, leaf]
    ordered = dependency_ordered_function_work_8616(items)
    assert ordered == (leaf, middle, caller)
    assert items == [caller, middle, leaf]
    assert all(actual is expected for actual, expected in zip(ordered, (leaf, middle, caller), strict=True))


def test_dependency_order_stable_recursive_components() -> None:
    items = (_WorkItem(4, _CallFunction(400, (400,))),
             _WorkItem(2, _CallFunction(200, (300,))),
             _WorkItem(1, _CallFunction(100, (200,))),
             _WorkItem(3, _CallFunction(300, (200,))))
    assert tuple(item.index for item in dependency_ordered_function_work_8616(items)) == (2, 3, 1, 4)


def test_dependency_order_unknown_ambiguous_and_placeholder_targets() -> None:
    items = (_WorkItem(1, _CallFunction(100, (None, 999, 200))),
             _WorkItem(3, _CallFunction(200)),
             _WorkItem(2, _CallFunction(200)),
             _WorkItem(4, object()))
    assert tuple(item.index for item in dependency_ordered_function_work_8616(items)) == (1, 2, 3, 4)
    assert dependency_ordered_function_work_8616(()) == ()


def test_dependency_order_uses_explicit_native_hints_for_placeholders() -> None:
    from types import SimpleNamespace

    items = (_WorkItem(1, SimpleNamespace(addr=100)),
             _WorkItem(2, SimpleNamespace(addr=200)),
             _WorkItem(3, SimpleNamespace(addr=300)))
    ordered = dependency_ordered_function_work_8616(items, caller_targets={100: (200, 300)})
    assert tuple(item.index for item in ordered) == (2, 3, 1)
    assert tuple(item.index for item in items) == (1, 2, 3)


def test_cold_worker_policy_defers_graph_dependency() -> None:
    """Basic worker policy stays light; dependency ordering loads its graph owner."""
    script = """
import sys
import inertia.cli.function_worker_policy as policy
assert "networkx" not in sys.modules
assert policy.clean_process_override_8616(None) is policy.CleanProcessOverride8616.DEFAULT
assert "networkx" not in sys.modules
assert policy.dependency_ordered_function_work_8616(()) == ()
assert "networkx" in sys.modules
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
