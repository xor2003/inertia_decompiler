"""Weak selector scope never substitutes for a real caller/callee simulation."""
from dataclasses import replace
from types import SimpleNamespace
from typing import cast

import pytest

from inertia.ir import real16_invocation_domain as owner
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr
from inertia.ir.declared_selector_invariant import (
    Cohort,
    DeclaredSegmentInvariant,
    DeclaredSelectorCallsite8616,
    InvariantStatus,
)
from inertia.ir.entry_domain_call_preservation import (
    EntryDomainCallPreservation8616,
    Real16InvocationSource8616,
)
from inertia.ir.real16_path_memory8616 import PathMemory8616
from inertia.ir.segment_effect_closure import SegmentEffectClosureResult8616

pytestmark = pytest.mark.decompiler


@pytest.fixture
def surface():
    """Retained identities with mocked expensive producers, never a proof fixture."""
    project = object()
    boot = object()
    row = IRInstr('CALL', None, (), addr=0x1020)
    block = IRBlock(0x1020, (row,))
    artifact = IRFunctionArtifact(0x1020, (block,))
    boundary = SimpleNamespace(project=project)
    admission = object()
    link = owner.DeclaredFunctionEntryLink8616(admission, artifact, boundary)
    source = Real16InvocationSource8616(boot, None, object())
    cohort = Cohort(1, 1, 1, 0)
    scope = DeclaredSegmentInvariant(
        InvariantStatus.PROVEN_CONDITIONAL, cohort, cohort, cohort, (), (), (), (),
        1, {'cs': 0x100}, 1, 1, 0x1020, admission,
        project=project, source=source, root_link=link,
    )
    projection = DeclaredSelectorCallsite8616(scope, block, row, 0x1020, 0x1040, 0x1023, 0x100)
    callee_artifact = IRFunctionArtifact(0x1040)
    callee = SegmentEffectClosureResult8616(
        SimpleNamespace(artifact=callee_artifact), object(), None, (), (), 1, 1, 1, 1, 0,
    )
    record = EntryDomainCallPreservation8616(
        artifact, boundary, block, row, object(), None, callee, None,
        0x1020, 0x1040, None, 1, 1, 1, 1, 0, selector_binding=projection,
    )
    ctx = SimpleNamespace(project=project, boot=boot, chain=link, selector=0x100,
                          callsite_addr=0x1090, prefix_capture_requested=True)
    return ctx, artifact, block, row, record, scope


def test_selector_scope_is_separate_and_requires_exact_root(surface):
    ctx, artifact, _block, _row, record, scope = surface
    assert owner._ctx_consuming_scope_8616(ctx, artifact, record) is None
    assert owner._selector_scope_for_proof_8616(record) is scope
    ctx.chain = replace(ctx.chain)
    assert owner._ctx_consuming_scope_8616(ctx, artifact, record) is owner._CTX_SCOPE_REFUSE_8616


@pytest.mark.parametrize('field', ['project', 'boot', 'selector'])
def test_foreign_incoming_authority_refuses(surface, field):
    ctx, artifact, _block, _row, record, _scope = surface
    setattr(ctx, field, object())
    assert owner._ctx_consuming_scope_8616(ctx, artifact, record) is owner._CTX_SCOPE_REFUSE_8616


def test_weak_record_never_uses_universal_complete(surface, monkeypatch):
    _ctx, _artifact, _block, _row, record, scope = surface
    monkeypatch.setattr(EntryDomainCallPreservation8616, 'complete_for', lambda *_: pytest.fail('universalized'))
    monkeypatch.setattr(EntryDomainCallPreservation8616, 'complete_for_selector', lambda self, actual: actual is scope)
    consumed = owner._consume_entry_call_record_8616(record, None, project_registers=False, selector_scope=scope)
    assert consumed is not None and consumed.selector_scope is scope and consumed.scope is None
    assert owner._consume_entry_call_record_8616(record, cast(owner.Real16InvocationDomain8616, object()),
        project_registers=False, selector_scope=scope) is None


def test_weak_boundary_still_runs_real_callee_simulation(surface, monkeypatch):
    ctx, artifact, block, row, record, scope = surface
    consumed = owner._ConsumedCallBoundary8616(record, None, ('cs',), scope)
    monkeypatch.setattr(owner, '_consume_cross_call_boundary_8616', lambda *_: consumed)
    calls = []
    def simulate(actual_ctx, actual_record, seed):
        calls.append((actual_ctx, actual_record, seed))
        return owner.Real16InvocationFailure8616.CALLEE_WRITE_UNPROVEN
    monkeypatch.setattr(owner, '_simulate_callee_8616', simulate)
    registers = {'cs': 0x100, 'sp': 0x200, 'ax': 7}
    memory = PathMemory8616()
    assert owner._cross_call_8616(ctx, artifact, block, row, registers, memory) is owner.Real16InvocationFailure8616.CALLEE_WRITE_UNPROVEN
    assert len(calls) == 1 and calls[0][2].registers == registers


def test_changed_live_cs_refuses_before_simulation(surface, monkeypatch):
    ctx, artifact, block, row, record, scope = surface
    consumed = owner._ConsumedCallBoundary8616(record, None, ('cs',), scope)
    monkeypatch.setattr(owner, '_consume_cross_call_boundary_8616', lambda *_: consumed)
    monkeypatch.setattr(owner, '_simulate_callee_8616', lambda *_: pytest.fail('foreign CS'))
    assert owner._cross_call_8616(ctx, artifact, block, row, {'cs': 0x101}, PathMemory8616()) is owner.Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN


def test_weak_scope_disables_prefix_publication(surface):
    ctx, artifact, block, row, record, scope = surface
    owner._record_prefix_call_8616(ctx, artifact, block, row,
        owner._ConsumedCallBoundary8616(record, None, ('cs',), scope))
    assert not ctx.prefix_capture_requested


def test_weak_record_cannot_consume_conditional_callee(surface):
    """A selector premise cannot authenticate a callee's full invocation state."""
    from inertia.ir.entry_domain_call_preservation import _callee_complete_in_scope_8616

    _ctx, _artifact, _block, _row, record, _scope = surface
    conditional = replace(record.callee, state=SimpleNamespace(invocation_scope=object()))
    assert not _callee_complete_in_scope_8616(record, conditional)


def test_late_weak_authentication_refuses_effect_transport(surface, monkeypatch):
    """Simulation success cannot bypass fresh selector reauthentication."""
    _ctx, _artifact, _block, _row, record, scope = surface
    monkeypatch.setattr(EntryDomainCallPreservation8616, 'preserved_registers_for_selector', lambda *_: ())
    registers = {'cs': 0x100, 'sp': 0x200, 'ax': 7}
    memory = PathMemory8616(known={0x2000: 12})
    assert owner._reconcile_call_exit_8616(record, None, record.callee, {}, registers, memory,
        selector_scope=scope) is owner.Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN
    assert registers == {'cs': 0x100, 'sp': 0x200, 'ax': 7}
    assert memory.known == {0x2000: 12}


def test_bare_proof_api_refuses_to_drop_weak_provenance(surface, monkeypatch):
    ctx, artifact, block, row, record, scope = surface
    monkeypatch.setattr(owner, '_consume_call_boundary_8616', lambda *_: owner._ConsumedCallBoundary8616(
        record, None, ('cs',), scope))
    assert owner._call_boundary_proof_8616(ctx, artifact, block, row) is None
