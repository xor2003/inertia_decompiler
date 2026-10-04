"""Solver-free structural controls for literal indirect-call budget admission.

Synthetic catalog records isolate discovery/ownership bounds. Callee validation
is replaced by a sentinel context; these are not binary-equivalence evidence.
"""
from __future__ import annotations

import pytest

from tools.dosunit import real16_call_contracts as contracts
from tools.dosunit import real16_call_control as control
from tools.dosunit import real16_call_evidence as evidence
from tools.dosunit import real16_call_execution as execution
from tools.dosunit import real16_call_indirect as indirect
from tools.dosunit import straightline_ssa as S
from tools.dosunit.proof_contracts import ProofStatus
from tools.dosunit.real16_call_contracts import ComposeSession, FunctionCtx, Real16CallLimits, Real16CallRefusal


def catalog(entries):
    return {"functions": [{"function": {"id": f"owner{index}"},
                           "function_entry": {"linear": entry}}
                          for index, entry in enumerate(entries)]}


def session_for(entries, **limits):
    session = ComposeSession.with_deadline(Real16CallLimits(**limits), 10000)
    session.indirect_resolver = evidence.IndirectTargetResolver(catalog(entries))
    return session


@pytest.fixture(autouse=True)
def no_solver_or_body_validation(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("budget control reached solver/native callee execution")

    def synthetic_context(name, parts, *, io_model=None):
        """Budget-only fixtures declare no external I/O contract."""
        assert io_model is None
        return FunctionCtx(name, name, parts[0]["function_entry"]["linear"], {}, 0, "synthetic")

    monkeypatch.setattr(indirect, "prove_terms_equal", forbidden)
    monkeypatch.setattr(execution, "_walk", forbidden)
    monkeypatch.setattr(evidence, "_group_context", synthetic_context)


def test_literal_target_charges_live_arm_cap():
    session = session_for([42], max_indirect_call_targets=0)
    with pytest.raises(Real16CallRefusal) as raised:
        indirect._closed_targets(session, 0, {"op": "const", "width": 32, "value": "0x2a"}, None)
    assert raised.value.reason == "compose_budget_exceeded"
    assert raised.value.detail == {"counter": "indirect_call_targets", "limit": 0}


def test_literal_target_exact_cap_skips_candidate_enumeration(monkeypatch):
    session = session_for([42], max_indirect_call_targets=1, max_indirect_call_candidates=0)
    monkeypatch.setattr(evidence.IndirectTargetResolver, "candidate_entries",
                        lambda *args: pytest.fail("literal target enumerated candidates"))
    assert indirect._closed_targets(session, 0, {"op": "const", "width": 32, "value": "0x2a"}, None) == [42]


@pytest.mark.parametrize("prebuilt", [False, True])
def test_literal_resolution_obeys_deadline_with_or_without_index(prebuilt):
    session = session_for([42])
    if prebuilt:
        assert session.indirect_resolver.candidate_entries(session) == [42]
    session.stats["deadline"] = -1.0
    with pytest.raises(S.LowerFailure) as raised:
        indirect._resolve_callee(session, {}, 42)
    assert raised.value.reason == "compose_budget_exceeded"


def test_literal_resolution_avoids_whole_candidate_index():
    session = session_for(range(100), max_indirect_call_candidates=0)
    assert indirect._resolve_callee(session, {}, 99).entry_linear == 99
    assert session.indirect_resolver._by_entry is None


def test_literal_ambiguous_ownership_stops_after_second_match(monkeypatch):
    session = session_for([42] * 100)
    observed = []
    original = evidence.part_entry_linear

    def count(part):
        observed.append(part)
        return original(part)

    monkeypatch.setattr(evidence, "part_entry_linear", count)
    with pytest.raises(Real16CallRefusal) as raised:
        indirect._resolve_callee(session, {}, 42)
    assert raised.value.reason == "call_target_unmapped"
    assert len(raised.value.detail["owners"]) == 2
    assert len(observed) == 2


def test_literal_scan_checks_deadline_between_entries(monkeypatch):
    session = session_for([1, 2, 42])
    original = evidence.part_entry_linear
    observed = []

    def expire(part):
        observed.append(part)
        session.stats["deadline"] = -1.0
        return original(part)

    monkeypatch.setattr(evidence, "part_entry_linear", expire)
    with pytest.raises(S.LowerFailure):
        indirect._resolve_callee(session, {}, 42)
    assert len(observed) == 1


def test_literal_missing_owner_still_refuses():
    session = session_for([1, 2])
    with pytest.raises(Real16CallRefusal) as raised:
        indirect._resolve_callee(session, {}, 42)
    assert raised.value.reason == "call_target_unmapped"
    assert raised.value.detail["owners"] == []


def test_execution_fallback_propagates_deadline():
    session = session_for([42])
    session.admit_indirect_calls = True
    session.stats["deadline"] = -1.0
    with pytest.raises(S.LowerFailure):
        execution.compose_entry(session, {}, 42, frozenset(), 0)


def test_prebuilt_index_is_reused_without_rescan(monkeypatch):
    session = session_for([1, 42])
    assert session.indirect_resolver.candidate_entries(session) == [1, 42]
    monkeypatch.setattr(evidence, "part_entry_linear", lambda *args: pytest.fail("unexpected rescan"))
    assert indirect._resolve_callee(session, {}, 42).entry_linear == 42


@pytest.mark.parametrize(("deadline", "expected_ms"), [(0.5, None), (1.125, 125)])
def test_restore_cs_uses_shared_remaining_deadline(monkeypatch, deadline, expected_ms):
    session = session_for([42])
    session.stats["deadline"] = deadline
    monkeypatch.setattr(contracts.time, "monotonic", lambda: 1.0)
    observed = []

    def proved(left, right, timeout_ms):
        observed.append(timeout_ms)
        return ProofStatus.PROVED

    monkeypatch.setattr(control, "prove_terms_equal", proved)
    state = {"cs": {"op": "const", "width": 16, "value": "0x1"}}
    callee = {"cs": {"op": "const", "width": 16, "value": "0x2"}}
    if expected_ms is None:
        with pytest.raises(Real16CallRefusal) as raised:
            control.restore_cs(session, state, callee, 42)
        assert raised.value.reason == "compose_budget_exceeded"
        assert raised.value.detail == {"counter": "deadline"}
        assert observed == []
        assert session.cs_preserved_proved == 0
    else:
        control.restore_cs(session, state, callee, 42)
        assert observed == [expected_ms]
        assert session.cs_preserved_proved == 1
