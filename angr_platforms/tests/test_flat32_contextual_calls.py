"""Native nested-call controls for root-bound composition and shared budgets."""

from pathlib import Path
from typing import Any

import pytest
from test_flat32_comparator_lane import BASE, DriverLane, _project
from test_flat32_comparator_lane import lane as lane
from test_flat32_stack_domain_cli import TEXT_BASE, _driver_args, _install_fixture, pe32_bytes

from tools.dosunit import flat32_call_execution as execution
from tools.dosunit.flat32_call_composition import (
    CallCompositionLimits,
    compare_functions_with_calls,
    summarize_with_calls,
)
from tools.dosunit.flat32_call_contracts import CallCompositionRefusal

FUNCTIONS = {BASE: 13, BASE + 13: 6, BASE + 19: 7}


def _code(offset: int = 0x100, value: int = 42) -> str:
    """Root derives EAX from ESP; two calls reach a dword store through EAX."""
    return (
        "89e0 05" + (offset & 0xFFFFFFFF).to_bytes(4, "little").hex()
        + " e801000000 c3 e801000000 c3 c700"
        + value.to_bytes(4, "little").hex() + " c3"
    )


def _result(lane: DriverLane, oracle: str, candidate: str) -> dict[str, Any]:
    """Compare all retained register, memory and return effects using real Z3."""
    with lane.adapter.installed(region=True):
        return compare_functions_with_calls(
            _project(oracle, BASE), _project(candidate, BASE),
            oracle_entry=BASE, candidate_entry=BASE,
            oracle_functions=FUNCTIONS, candidate_functions=FUNCTIONS,
            outputs=lane.adapter.GPRS, timeout_ms=10000,
        )


def test_nested_store_uses_proved_root_pointer_without_assumption(lane: DriverLane) -> None:
    """Caller-computed disjointness survives a nested call boundary."""
    result = _result(lane, _code(), _code())
    assert result["status"] == "passed", result
    assert "assumptions" not in result
    assert result["return_targets_proved"] == 4


def test_nested_store_mutation_remains_observable(lane: DriverLane) -> None:
    """Root-bound inlining must not hide the nested callee's memory write."""
    result = _result(lane, _code(), _code(value=43))
    assert result["status"] == "failed", result


@pytest.mark.parametrize("offset", (-4, -8))
def test_nested_store_cannot_overwrite_either_return_slot(lane: DriverLane, offset: int) -> None:
    """Inner and outer return-address corruption still prevents continuation."""
    result = _result(lane, _code(offset), _code(offset))
    assert result["status"] == "refused", result
    assert result["reason"].startswith("call_return_target")


@pytest.mark.parametrize("budget", (3, 4))
def test_retry_shares_inline_budget_and_reuses_lifted_blocks(lane: DriverLane, budget: int) -> None:
    """Both attempts are charged; retry reuses the same five lifted blocks."""
    with lane.adapter.installed(region=True):
        if budget == 3:
            with pytest.raises(CallCompositionRefusal, match="call_inline_budget"):
                summarize_with_calls(
                    _project(_code(), BASE), entry=BASE, functions=FUNCTIONS,
                    outputs=lane.adapter.GPRS, limits=CallCompositionLimits(max_inlined_calls=budget),
                )
        else:
            summary = summarize_with_calls(
                _project(_code(), BASE), entry=BASE, functions=FUNCTIONS,
                outputs=lane.adapter.GPRS, limits=CallCompositionLimits(max_inlined_calls=budget),
            )
            assert summary["root_bound_retry"] is True
            assert summary["blocks_lifted"] == 5  # root/continuation, wrapper/continuation, leaf
            assert summary["inlined_calls"] == 4
            assert summary["return_targets_proved"] == len(summary["call_sites"]) == 2


def test_second_call_does_not_reuse_first_contextual_summary(lane: DriverLane) -> None:
    """The same callee at a later callsite must consume that site's pointer."""
    root = bytearray()
    root_size = 25
    for offset in (0x100, -8):
        root.extend(bytes.fromhex("89e0 05") + (offset & 0xFFFFFFFF).to_bytes(4, "little"))
        displacement = root_size - (len(root) + 5)
        root.extend(b"\xe8" + displacement.to_bytes(4, "little", signed=True))
    root.extend(bytes.fromhex("c3 e801000000 c3 c7002a000000 c3"))
    functions = {BASE: root_size, BASE + root_size: 6, BASE + root_size + 6: 7}
    code = root.hex()
    with lane.adapter.installed(region=True):
        result = compare_functions_with_calls(
            _project(code, BASE), _project(code, BASE), oracle_entry=BASE, candidate_entry=BASE,
            oracle_functions=functions, candidate_functions=functions,
            outputs=lane.adapter.GPRS, timeout_ms=10000,
        )
    assert result["status"] == "refused"
    assert result["reason"].startswith("call_return_target")


def test_root_return_failure_does_not_repeat_identical_work(lane: DriverLane, monkeypatch: pytest.MonkeyPatch) -> None:
    """Root return checks already include caller state and cannot benefit from retry."""
    from test_flat32_stack_domain import STORE_CODE, STORE_FUNCTIONS

    original = execution._compose_function
    root_calls = []

    def counted(session, entry, active, depth, **kwargs):
        if depth == 0:
            root_calls.append(entry)
        return original(session, entry, active, depth, **kwargs)

    monkeypatch.setattr(execution, "_compose_function", counted)
    with lane.adapter.installed(region=True), pytest.raises(CallCompositionRefusal, match="call_return_target"):
        summarize_with_calls(
            _project(STORE_CODE, BASE), entry=BASE, functions=STORE_FUNCTIONS,
            outputs=lane.adapter.GPRS,
        )
    assert root_calls == [BASE]


@pytest.mark.parametrize("offset,value,expected", ((0x100, 42, "passed"), (0x100, 43, "failed"), (-8, 42, "refused")))
def test_public_pe32_contextual_call_result(
    lane: DriverLane, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    offset: int, value: int, expected: str,
) -> None:
    """Both public adapters retain success, store mismatch and bad-return refusal."""
    boundaries = {
        "f": (TEXT_BASE, TEXT_BASE + 12),
        "callee": (TEXT_BASE + 13, TEXT_BASE + 18),
        "leaf": (TEXT_BASE + 19, TEXT_BASE + 25),
    }
    oracle, candidate = _install_fixture(lane, monkeypatch, tmp_path, _code(offset), boundaries)
    candidate.write_bytes(pe32_bytes(bytes.fromhex(_code(offset, value))))
    symbols = {name: lane.catalog.Symbol(start, end - start + 1, "T") for name, (start, end) in boundaries.items()}
    monkeypatch.setattr(lane.z3cmp32, "nm_symbols", lambda _path: symbols)
    args = _driver_args(lane, tmp_path, oracle, candidate, None)
    with lane.adapter.installed(region=True):
        report = lane.z3cmp32.compare(args)
    assert len(report["results"]) == 1
    row = report["results"][0]
    assert row["status"] == expected, row
    if expected == "passed":
        assert not row.get("assumptions")
