"""Universal CS-alias controls for direct-call target admission."""
from __future__ import annotations

import time

import pytest

from tools.dosunit.contracts.proof_contracts import ProofStatus
from tools.dosunit.compare.real16_call_contracts import (
    ComposeSession,
    FunctionCtx,
    Real16CallLimits,
    Real16CallRefusal,
)
from tools.dosunit.compare.real16_call_control import checked_call_site
from tools.dosunit.compare.real16_control_resolution import ControlResolutionReason, prove_control_destination


def _relative(head: int, displacement: int) -> dict:
    """Build the exact architectural near16 destination with live CS."""
    base = {"op": "shl", "width": 32, "args": [
        {"op": "zext", "width": 32, "args": [{"op": "input", "name": "cs", "width": 16}]},
        {"op": "const", "width": 8, "value": "0x4"}]}
    offset = {"op": "trunc", "width": 16, "args": [
        {"op": "sub", "width": 32, "args": [
            {"op": "const", "width": 32, "value": hex(head + 3)}, base]}]}
    target = {"op": "add", "width": 16, "args": [offset,
        {"op": "const", "width": 16, "value": hex(displacement & 0xFFFF)}]}
    return {"op": "add", "width": 32, "args": [base,
        {"op": "zext", "width": 32, "args": [target]}]}


def _case(head: int, target: int, term: dict, *, entry: int | None = None) -> tuple:
    root = head if entry is None else entry
    ctx = FunctionCtx("case", "case", root, {0: {}, head + 3 - root: {}}, head + 4 - root, "0" * 64)
    block = {"source": {"transfer": {"kind": "direct_call",
        "target": {"linear": hex(target)}, "fallthrough": {"linear": hex(head + 3)}}}}
    return ctx, block, {"control_ip": term}


@pytest.mark.parametrize("head,displacement,target", [(0x200, 13, 0x210), (0x210, -19, 0x200)])
def test_symbolic_call_target_proved_for_every_entry_alias(head, displacement, target):
    ctx, block, state = _case(head, target, _relative(head, displacement), entry=0x200)
    session = ComposeSession.with_deadline(Real16CallLimits(), 3000)
    deadline = session.stats["deadline"]
    site = checked_call_site(ctx, 0, block, state, session=session)
    assert site.target == target
    assert session.stats["deadline"] == deadline


@pytest.mark.parametrize("head,displacement,target", [
    (0x200, 13, 0x211), (0x22330, 29, 0x22350), (0x210, -19, 0x200),
])
def test_wrong_or_alias_dependent_target_refused(head, displacement, target):
    ctx, block, state = _case(head, target, _relative(head, displacement))
    with pytest.raises(Real16CallRefusal, match="call_target_mismatch"):
        checked_call_site(ctx, 0, block, state,
                          session=ComposeSession.with_deadline(Real16CallLimits(), 3000))


@pytest.mark.parametrize("target", [-1, 0x100000000])
def test_metadata_target_outside_full_control_width_is_refused(target):
    ctx, block, state = _case(0x200, target, _relative(0x200, 13))
    with pytest.raises(Real16CallRefusal, match="call_target_mismatch"):
        checked_call_site(ctx, 0, block, state,
                          session=ComposeSession.with_deadline(Real16CallLimits(), 3000))


def test_symbolic_target_without_shared_budget_still_refused():
    ctx, block, state = _case(0x200, 0x210, _relative(0x200, 13))
    with pytest.raises(Real16CallRefusal, match="unsupported_call"):
        checked_call_site(ctx, 0, block, state)


def test_expired_shared_budget_cannot_be_replenished():
    ctx, block, state = _case(0x200, 0x210, _relative(0x200, 13))
    session = ComposeSession(Real16CallLimits(), {"deadline": time.monotonic() - 1})
    with pytest.raises(Real16CallRefusal, match="compose_budget_exceeded"):
        checked_call_site(ctx, 0, block, state, session=session)


@pytest.mark.parametrize("term", [{"op": "input", "name": "ip", "width": 16},
                                  {"op": "const", "value": "0x210", "width": 16}])
def test_word_control_cannot_supply_full_loaded_target(term):
    ctx, block, state = _case(0x200, 0x210, term)
    with pytest.raises(Real16CallRefusal, match="unsupported_call"):
        checked_call_site(ctx, 0, block, state,
                          session=ComposeSession.with_deadline(Real16CallLimits(), 3000))


@pytest.mark.parametrize("entry", [-1, 0x10FFF0])
def test_unrepresentable_entry_cannot_supply_vacuous_target_proof(entry):
    proof = prove_control_destination(_relative(0x200, 13), 0x210, entry,
                                      deadline=time.monotonic() + 3, max_solver_ms=1000)
    assert proof.status is ProofStatus.UNKNOWN
    assert proof.reason is ControlResolutionReason.DOMAIN
    assert proof.domain is None


def test_solver_unknown_is_retained_as_typed_refusal(monkeypatch):
    monkeypatch.setattr("tools.dosunit.compare.real16_control_resolution.prove_terms_equal",
                        lambda *args, **kwargs: ProofStatus.UNKNOWN)
    proof = prove_control_destination(_relative(0x200, 13), 0x210, 0x200,
                                      deadline=time.monotonic() + 3, max_solver_ms=1000)
    assert proof.status is ProofStatus.UNKNOWN
    assert proof.reason is ControlResolutionReason.UNKNOWN


def test_solver_completion_after_deadline_cannot_publish_proof(monkeypatch):
    observed = iter([10.0, 12.0])
    monkeypatch.setattr("tools.dosunit.compare.real16_control_resolution.time.monotonic", lambda: next(observed))
    monkeypatch.setattr("tools.dosunit.compare.real16_control_resolution.prove_terms_equal",
                        lambda *args, **kwargs: ProofStatus.PROVED)
    proof = prove_control_destination(_relative(0x200, 13), 0x210, 0x200,
                                      deadline=11.0, max_solver_ms=1000)
    assert proof.status is ProofStatus.UNKNOWN
    assert proof.reason is ControlResolutionReason.DEADLINE


@pytest.mark.parametrize("name,width", [("control_ip", 32), ("ip", 32), ("control_ip", 16)])
def test_call_binding_cannot_promote_a_logical_ip_to_physical_control(name, width):
    """A callee correspondence cannot erase physical target or width errors."""
    from tools.dosunit.compare.straightline_ssa import _with_call_bound_control_outputs

    original = {"op": "const", "width": width, "value": "0x1230"}
    function = {"outputs": {name: dict(original)}, "assignments": []}
    call = {"raw": "0x11230", "resolved": {"entry": {"linear": "0x11230", "ip": "0x1230"}}}
    result, applied = _with_call_bound_control_outputs(function, call=call, target_value=0xAABBCCDD)
    assert result["outputs"][name] == original
    assert applied == []


@pytest.mark.parametrize("name,width,value", [
    ("control_ip", 32, "0x11230"), ("ip", 32, "0x11230"), ("ip", 16, "0x1230"),
])
def test_call_binding_retains_proved_targets_in_their_control_domain(name, width, value):
    """Correct DWORD physical and WORD logical projections retain correspondence."""
    from tools.dosunit.compare.straightline_ssa import _with_call_bound_control_outputs

    function = {"outputs": {name: {"op": "const", "width": width, "value": value}}, "assignments": []}
    call = {"raw": "0x11230", "resolved": {"entry": {"linear": "0x11230", "ip": "0x1230"}}}
    result, applied = _with_call_bound_control_outputs(function, call=call, target_value=0xAABBCCDD)
    assert int(result["outputs"][name]["value"], 16) == 0xAABBCCDD & ((1 << width) - 1)
    assert result["outputs"][name]["width"] == width
    assert applied == [name]
