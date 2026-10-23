"""Scoped selector composition over native call-frame and branch evidence."""

from dataclasses import replace

import pytest

from inertia.ir import declared_selector_invariant as selector
from inertia.ir import entry_domain_call_preservation as entry
from inertia.ir.native_import_surface_cache import native_import_request_8616
from inertia.ir.real16_invocation_domain import DeclaredFunctionEntryLink8616
from tests.ir.test_forward_declared_call_scope import _forward_world

pytestmark = pytest.mark.decompiler


def _prove(world, **limits):
    project, _boot, artifact, boundary, _resolver, admission = world
    source = entry._invocation_premise_source_8616(project)
    assert source is not None
    with native_import_request_8616():
        return selector.prove_declared_selector_invariant_8616(
            project, source, DeclaredFunctionEntryLink8616(admission, artifact, boundary), **limits)


@pytest.mark.parametrize("guarded", [False, True])
def test_native_repeated_calls_retain_distinct_conditional_callee_proofs(guarded):
    world = _forward_world(guarded=guarded)
    result = _prove(world)
    assert result.status is selector.InvariantStatus.PROVEN_CONDITIONAL, result.obligations
    records = result.scoped_call_preservations
    assert len(records) == 2
    assert {record.callsite_addr for record in records} == {0x1043, 0x1046}
    assert records[0].callee.state.invocation_scope is not records[1].callee.state.invocation_scope
    for record in records:
        assert record.required_scope is not None
        assert record.complete_for(record.required_scope)
        assert not record.complete_for(None)


@pytest.mark.parametrize("known_argument", [False, True])
def test_unknown_or_reachable_service_stays_unproved(known_argument):
    result = _prove(_forward_world(0, guarded=True, known_argument=known_argument))
    assert result.status is selector.InvariantStatus.REFUSED
    assert result.obligations


@pytest.mark.parametrize("address, data", [(0x1040, b"\x90"), (0x1051, b"\xff\xe2")])
def test_changed_native_bytes_never_mint_selector_authority(address, data):
    world = _forward_world()
    world[0].loader.memory.store(address, data)
    result = _prove(world)
    assert result.status is selector.InvariantStatus.REFUSED
    assert result.obligations


def test_changed_declared_authority_refuses():
    world = list(_forward_world())
    admission = world[-1]
    world[-1] = replace(admission, spec=replace(admission.spec, entry_offset=0x41))
    result = _prove(world)
    assert result.status is selector.InvariantStatus.REFUSED
    assert any(row.kind is selector.ObligationKind.DECLARED_AUTHORITY_STALE for row in result.obligations)


def test_existing_work_limit_is_not_renewed_for_scoped_callees():
    result = _prove(_forward_world(), work_limit=0)
    assert result.status is selector.InvariantStatus.REFUSED
    assert any(row.kind is selector.ObligationKind.BUDGET_EXCEEDED for row in result.obligations)


def test_selector_collector_preserves_original_invocation_authority():
    from inertia.ir.declared_selector_call_preservation import collect_declared_selector_call_preservations_8616

    world = _forward_world()
    result = _prove(world)
    assert result.status is selector.InvariantStatus.PROVEN_CONDITIONAL, result.obligations
    collected = collect_declared_selector_call_preservations_8616(world[0], result)
    assert len(collected) == 2
    assert all(row is original for row, original in zip(collected, result.scoped_call_preservations, strict=True))
    assert all(row.complete_for(row.required_scope) for row in collected)
    assert all(row.selector_projection is None and not row.complete for row in collected)


@pytest.mark.parametrize("argument, known_argument, expected", [
    (1, True, selector.InvariantStatus.PROVEN_CONDITIONAL),
    (0, True, selector.InvariantStatus.REFUSED),
    (1, False, selector.InvariantStatus.REFUSED),
])
def test_pending_relative_edge_requires_authenticated_unreachability(argument, known_argument, expected):
    world = _forward_world(argument, known_argument=known_argument,
                           helper_bytes=bytes.fromhex("5985c07402ffe1ebe7"))
    result = _prove(world)
    assert result.status is expected, result.obligations
    if expected is selector.InvariantStatus.PROVEN_CONDITIONAL:
        assert len(result.scoped_call_preservations) == 2
        for record in result.scoped_call_preservations:
            callee = record.callee
            projection = callee.coverage.scoped_view.cfg_projection_for(callee.state.invocation_scope)
            assert projection is not None
            pending = {addr for addr, rows in projection.pending.items() if rows}
            assert pending and pending <= projection.unreachable_block_addrs
            assert all(block.instrs for block in callee.coverage.artifact.blocks)


def test_foreign_indirect_error_branch_remains_unsupported():
    result = _prove(_forward_world(helper_bytes=bytes.fromhex("5985c07402ffe1ffe2")))
    assert result.status is selector.InvariantStatus.REFUSED
