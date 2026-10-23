"""Must return values are independent and coherent across overlapping lanes."""

from types import SimpleNamespace

import pytest

from inertia.ir import real16_invocation_domain as owner
from tests.ir.test_raw_callee_scoped_call_chain import _collect
from tests.ir.test_raw_callee_scoped_call_chain import calls_with_pending_helper as calls_with_pending_helper
from tests.ir.test_raw_callee_scoped_call_chain import calls_with_unconditional_helper as calls_with_unconditional_helper

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize(
    ("states", "expected"),
    [
        ([{"ax": 0}, {"ax": 0}], {"ax": 0, "al": 0, "ah": 0}),
        ([{"ax": 0x1234}, {"al": 0x34, "ah": 0x12}], {"ax": 0x1234, "al": 0x34, "ah": 0x12}),
        ([{"eax": 0x11223344}, {"eax": 0x55663344}], {"ax": 0x3344, "al": 0x44, "ah": 0x33}),
        ([{"ax": 1}, {}], {}),
        ([{"ax": 1}, {"ax": 2}], {"ah": 0}),
        ([{"sp": 128, "ax": 0}, {"ax": 0}], {"ax": 0, "al": 0, "ah": 0}),
        ([{"ip": 3, "eip": 3, "cs": 256, "flags": 0, "ax": 0}], {"ax": 0, "al": 0, "ah": 0}),
    ],
)
def test_return_must_meet(states: list[dict[str, int]], expected: dict[str, int]) -> None:
    """Only independently known matching lanes survive every return."""
    callee = SimpleNamespace(return_block_addrs=tuple(range(len(states))))
    exits = {i: owner._PathState8616(s, owner.PathMemory8616()) for i, s in enumerate(states)}
    assert owner._post_call_registers_8616(callee, exits) == expected


def test_missing_exit_keeps_all_returns_unknown() -> None:
    """An uncovered return prevents all callee result transport."""
    callee = SimpleNamespace(return_block_addrs=(0, 1))
    assert owner._post_call_registers_8616(callee, {0: owner._PathState8616({"ax": 0}, owner.PathMemory8616())}) == {}


def test_partial_return_invalidates_stale_containing_view() -> None:
    """Partial writes drop stale containing constants via the lane owner."""
    proof = SimpleNamespace(preserved_registers_for=lambda scope: ("cs", "eax"))
    callee = SimpleNamespace(return_block_addrs=(0, 1))
    exits = {
        0: owner._PathState8616({"al": 0}, owner.PathMemory8616()),
        1: owner._PathState8616({"al": 0}, owner.PathMemory8616()),
    }
    regs = {"cs": 256, "eax": 0x12345678}
    assert owner._reconcile_call_exit_8616(proof, None, callee, exits, regs, owner.PathMemory8616()) is None
    assert regs == {"cs": 256, "al": 0}


def test_simulated_ax_zero_reaches_next_call(calls_with_unconditional_helper: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    """A source-bound helper result reaches the next call without a MOV."""
    states = []
    original = owner._census_invocation_8616

    def capture(ctx: owner._PathCensusContext8616, *args: object, **kwargs: object) -> object:
        result = original(ctx, *args, **kwargs)
        if ctx.callsite_addr == 0x1046 and ctx.callsite_call_state is not None:
            states.append(dict(ctx.callsite_call_state))
        return result

    states = []
    monkeypatch.setattr(owner, "_census_invocation_8616", capture)
    records = _collect(calls_with_unconditional_helper)
    assert len(records) == 2 and all(record.failure is None for record in records)
    assert states and all(state.get("ax") == 0 for state in states)


def test_straight_line_caller_adds_no_speculative_call_walk(
    calls_with_pending_helper: tuple,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No branch can consume call-effect refinement in a straight-line caller."""
    speculative_calls = 0
    original = owner._feasibility_call_scratch_8616

    def observed(*args: object, **kwargs: object) -> bool:
        """Count actual speculative effects without changing their behavior."""
        nonlocal speculative_calls
        speculative_calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(owner, "_feasibility_call_scratch_8616", observed)
    records = _collect(calls_with_pending_helper)
    assert len(records) == 2 and all(record.failure is None for record in records)
    assert speculative_calls == 0
