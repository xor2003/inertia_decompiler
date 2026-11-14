"""Nested selector collection inherits local deadlines without renewing its parent."""

import time
from types import SimpleNamespace

import pytest

from inertia.ir import declared_selector_call_preservation as collection_owner
from inertia.ir import declared_selector_invariant as owner
from inertia.ir import entry_domain_call_preservation as entry_owner
from inertia.ir import real16_invocation_domain as census
from inertia.ir.core import IRInstr
from inertia.ir.direct_evidence_deadline import active_direct_evidence_deadline_8616
from inertia.ir.segment_call_preservation import (
    segment_call_deadline_scope_8616,
    segment_call_dependency_traversal_scope_8616,
)

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize("parent_seconds", [10.0, 50.0])
@pytest.mark.parametrize("outcome", ["missing", "deadline", "exception"])
def test_scoped_collection_inherits_deadline_and_restores_parent(monkeypatch, parent_seconds, outcome):
    """Native imports and census loops share the tighter bound on every exit."""
    now = time.monotonic()
    clock = [now]
    local = now + 20.0
    parent = now + parent_seconds
    original_project = now + 40.0
    effective = min(local, parent, original_project)
    project = SimpleNamespace(_inertia_direct_evidence_deadline_8616=original_project)
    observed = []
    record_calls = []
    monkeypatch.setattr(owner, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(owner, "_caller_premise_surface_8616", lambda *_args: None)

    class Collection:
        def collect(self):
            observed.append((active_direct_evidence_deadline_8616(project),
                             census._census_deadline_8616(), traversal.census_deadline))
            if outcome == "exception":
                raise ValueError("nested producer failed")
            if outcome == "deadline":
                clock[0] = effective + 1.0

        def record(self, _head, _callsite):
            record_calls.append(True)
            return None

    with segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.census_deadline = parent
        budget = owner._Budget(local, 100)
        obligations = []

        def resolve():
            return owner._resolve_callsite(
                project, 0x1000, IRInstr("CALL", None, (), addr=0x1000),
                b"\xe8\xfd\x00", budget, obligations, {}, scoped_calls=Collection(),
            )

        if outcome == "exception":
            with pytest.raises(ValueError, match="nested producer failed"):
                resolve()
        else:
            assert resolve() == (0x1100, frozenset())
        assert traversal.census_deadline == parent
        assert active_direct_evidence_deadline_8616(project) == original_project
        assert census._census_deadline_8616() == parent
        assert observed == [(effective, effective, parent)]
        if outcome == "deadline":
            assert not record_calls
            assert any(item.kind is owner.ObligationKind.DEADLINE_EXCEEDED for item in budget.obligations)
            assert not any(item.kind is owner.ObligationKind.CALLEE_MISSING for item in obligations)


def test_nested_deadline_never_loosens_or_resets_work():
    """Inner caps restore the outer operation, preserving request time and work."""
    now = time.monotonic()
    project = SimpleNamespace(_inertia_direct_evidence_deadline_8616=now + 45.0)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.census_deadline = now + 50.0
        traversal.census_work_units = 7
        with segment_call_deadline_scope_8616(project, now + 30.0):
            assert census._census_deadline_8616() == now + 30.0
            with segment_call_deadline_scope_8616(project, now + 40.0):
                assert census._census_deadline_8616() == now + 30.0
                traversal.census_work_units += 2
            with pytest.raises(ValueError, match="inner failure"), segment_call_deadline_scope_8616(project, now + 10.0):
                assert census._census_deadline_8616() == now + 10.0
                raise ValueError("inner failure")
            assert census._census_deadline_8616() == now + 30.0
            assert active_direct_evidence_deadline_8616(project) == now + 30.0
        assert traversal.census_work_units == 9
        assert traversal.census_deadline == now + 50.0
        assert census._census_deadline_8616() == now + 50.0
        assert active_direct_evidence_deadline_8616(project) == now + 45.0


def test_nested_expiry_reaches_retry_and_collection_consumers():
    """Retry and shared-work collection stop locally, then recover the parent cap."""
    now = time.monotonic()
    project = SimpleNamespace(_inertia_direct_evidence_deadline_8616=now + 40.0)
    premise = SimpleNamespace(failure=census.Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.census_deadline = now + 50.0
        with segment_call_deadline_scope_8616(project, now - 1.0):
            assert entry_owner._raw_boot_census_retry_expired_8616(premise)
            assert not collection_owner._charge_collection_8616(project, 0)
        assert not entry_owner._raw_boot_census_retry_expired_8616(premise)
        assert collection_owner._charge_collection_8616(project, 0)
        assert traversal.census_deadline == now + 50.0
