"""Full-state composition through proved symbolic physical successors."""
from __future__ import annotations

import pytest
from test_real16_symbolic_call_control import _relative

from tools.dosunit.real16_call_contracts import (
    ComposeSession,
    FunctionCtx,
    Real16CallLimits,
    Real16CallRefusal,
    initial_state,
)
from tools.dosunit.real16_call_execution import _compose_ip_targets


def _context(head=0x200):
    blocks = {}
    for delta, value in ((0x10, 1), (0x20, 2)):
        blocks[delta] = {"source": {"jumpkind": "Ijk_Ret"}, "outputs": {
            "ax": {"op": "const", "width": 16, "value": hex(value)},
            "control_ip": {"op": "const", "width": 32, "value": "0xbabe"},
        }}
    return FunctionCtx("case", "case", head, blocks, 0x24, "0" * 64)


def _compose(ctx, term, declared, *, expired=False):
    block = {"function_entry": {"linear": hex(ctx.entry_linear)},
             "source": {"transfer": {"kind": "direct_successors", "successors": [
                 {"linear": hex(address)} for address in declared]}}}
    state = initial_state()
    state["control_ip"] = term
    session = ComposeSession.with_deadline(Real16CallLimits(), 3000)
    if expired:
        session.stats["deadline"] = 0.0
    result = _compose_ip_targets(session, {"case": ctx}, ctx, state, term, block,
                                 frozenset({0}), frozenset({ctx.entry_linear}), 0)
    return result


def test_symbolic_successor_composes_complete_state():
    result = _compose(_context(), _relative(0x200, 13), [0x210])
    assert result["ax"] == {"op": "const", "width": 16, "value": "0x1"}
    assert set(result) == set(initial_state())
    for name in set(result) - {"ax", "control_ip"}:
        assert result[name] == initial_state()[name]


def test_symbolic_conditional_arms_preserve_predicate_and_both_effects():
    predicate = {"op": "eq", "width": 1, "args": [
        {"op": "input", "name": "ax", "width": 16},
        {"op": "const", "width": 16, "value": "0x0"}]}
    term = {"op": "ite", "width": 32,
            "args": [predicate, _relative(0x200, 13), _relative(0x200, 29)]}
    result = _compose(_context(), term, [0x210, 0x220])
    assert set(result) == set(initial_state())
    assert result["ax"]["op"] == "ite"
    assert result["ax"]["args"] == [predicate,
        {"op": "const", "width": 16, "value": "0x1"},
        {"op": "const", "width": 16, "value": "0x2"}]


@pytest.mark.parametrize("symbolic", [False, True])
def test_distant_metadata_cannot_alias_local_successor(symbolic):
    term = _relative(0x200, 13) if symbolic else {"op": "const", "width": 32, "value": "0x210"}
    with pytest.raises(Real16CallRefusal, match="successor_outside_region"):
        _compose(_context(), term, [0x10210])


def test_opaque_arm_cannot_disappear_from_conditional_composition():
    term = {"op": "ite", "width": 32, "args": [
        {"op": "const", "width": 1, "value": "0x1"},
        _relative(0x200, 13), {"op": "input", "name": "bx", "width": 32}]}
    with pytest.raises(Real16CallRefusal, match="unsupported_control_transfer"):
        _compose(_context(), term, [0x210])


def test_alias_dependent_wrap_refuses_fixed_successor():
    with pytest.raises(Real16CallRefusal, match="unsupported_control_transfer"):
        _compose(_context(0x22330), _relative(0x22330, 13), [0x22340])


def test_symbolic_successor_cannot_restart_expired_budget():
    with pytest.raises(Real16CallRefusal, match="compose_budget_exceeded"):
        _compose(_context(), _relative(0x200, 13), [0x210], expired=True)


def test_word_literal_cannot_supply_full_loaded_control():
    with pytest.raises(Real16CallRefusal, match="unsupported_control_transfer"):
        _compose(_context(), {"op": "const", "width": 16, "value": "0x210"}, [0x210])
