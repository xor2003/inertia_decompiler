"""Check conditional CFG transport through actual-MZ segment closure.

Layer: tests.
Responsibility: retain the authentic raw body and scope across coverage,
state and closure; reject missing scope or conflicting retained views.
"""
from __future__ import annotations

from dataclasses import replace

import tools.dosunit.tests.test_x86_16_scoped_native_inputs as native
import inertia.ir.ir_boundary_cfg as ir_boundary_cfg
import inertia.ir.real16_invocation_domain as real16_invocation_domain
import inertia.ir.segment_call_preservation as segment_call_preservation
import inertia.ir.segment_effect_closure as segment_effect_closure
import inertia.ir.segment_state as segment_state
from tools.dosunit.tests.test_x86_16_scoped_native_inputs import LEAF, _view, world  # noqa: F401


def test_native_conditional_closure_retains_raw_calls_and_scope(world: tuple) -> None:  # noqa: F811
    """Close an admitted edge under its entry without publishing universal proof."""
    view, scope, artifact = _view(world)
    coverage = ir_boundary_cfg.prove_scoped_ir_boundary_coverage_8616(
        view.boundary.project, view.boundary, artifact, view,
    )
    assert coverage.complete_for(scope)
    state = segment_state.build_x86_16_segment_state_artifact(
        artifact, invocation_scope=scope, scoped_view=view,
    )
    assert state.source_artifact is artifact
    assert state.scoped_view is view
    prove = segment_effect_closure.prove_segment_effect_closure_8616
    closure = prove(coverage, state)
    assert closure.failure is None, closure.failure
    assert closure.complete_for(scope)
    assert not closure.complete
    assert not closure.complete_for(replace(scope, boot=object()))
    assert closure.callsite_addrs == tuple(sorted({
        ins.addr for block in artifact.blocks for ins in block.instrs if ins.op == 'CALL'
    }))
    projection = view.cfg_projection_for(scope)
    assert projection is not None
    assert closure.return_block_addrs == tuple(sorted(
        addr for addr, successors in projection.successors.items() if not successors
    ))
    assert not prove(coverage, replace(state, scoped_view=None)).complete_for(scope)
    assert not prove(coverage, replace(state, scoped_view=replace(view))).complete_for(scope)
    assert not prove(coverage, replace(state, invocation_scope=None)).complete_for(scope)
    assert not prove(coverage, replace(state, source_artifact=replace(artifact))).complete_for(scope)
    assert not replace(closure, raw_fact_count=True).complete_for(scope)
    assert not replace(closure, return_block_addrs=()).complete_for(scope)


def test_native_byte_change_revokes_retained_closure(world: tuple) -> None:  # noqa: F811
    """A changed native dependency revokes the retained coverage and closure."""
    view, scope, artifact = _view(world)
    coverage = ir_boundary_cfg.prove_scoped_ir_boundary_coverage_8616(
        view.boundary.project, view.boundary, artifact, view,
    )
    state = segment_state.build_x86_16_segment_state_artifact(
        artifact, invocation_scope=scope, scoped_view=view,
    )
    closure = segment_effect_closure.prove_segment_effect_closure_8616(coverage, state)
    assert closure.complete_for(scope)
    view.boundary.project.loader.memory.store(LEAF, b'\x90')
    assert not closure.complete_for(scope)


def test_native_scoped_caller_preservation_keeps_its_condition(world: tuple) -> None:  # noqa: F811
    """Compose the retained leaf summary without losing the caller's CFG premise."""
    view, scope, artifact = _view(world)
    project = view.boundary.project
    coverage = ir_boundary_cfg.prove_scoped_ir_boundary_coverage_8616(
        project, view.boundary, artifact, view,
    )
    records = native._records(project, artifact, view.boundary)
    assert len(records) == 1
    record = records[0]
    assert record.callee is not None
    assert record.required_scope is not None
    proof = segment_call_preservation.prove_segment_call_preservation_8616(
        coverage, record.callee, record.index, record.callsite_addr,
        invocation=record.required_scope,
    )
    assert proof.failure is None, proof.failure
    assert proof.required_scope is record.required_scope
    assert proof.complete_for(scope)
    assert not proof.complete
    assert 'cs' in proof.preserved_registers_for(scope)
    state = segment_state.build_x86_16_segment_state_artifact(
        artifact, invocation_scope=scope, scoped_view=view, call_preservations=(proof,),
    )
    assert state.summary['classified_call_count'] == 1
    closure = segment_effect_closure.prove_segment_effect_closure_8616(coverage, state)
    assert closure.complete_for(scope)
    assert not closure.complete
    assert not proof.complete_for(replace(scope, boot=object()))


def test_native_scoped_closure_crosses_its_authentic_parent_call(world: tuple) -> None:  # noqa: F811
    """Consume an in-flight callee closure only over its independently proven edge."""
    view, scope, artifact = _view(world)
    project = view.boundary.project
    coverage = ir_boundary_cfg.prove_scoped_ir_boundary_coverage_8616(
        project, view.boundary, artifact, view,
    )
    (record,) = native._records(project, artifact, view.boundary)
    assert record.callee is not None and record.required_scope is not None
    nested = segment_call_preservation.prove_segment_call_preservation_8616(
        coverage, record.callee, record.index, record.callsite_addr,
        invocation=record.required_scope,
    )
    assert nested.complete_for(scope)
    state = segment_state.build_x86_16_segment_state_artifact(
        artifact, invocation_scope=scope, scoped_view=view, call_preservations=(nested,),
    )
    closure = segment_effect_closure.prove_segment_effect_closure_8616(coverage, state)
    assert closure.complete_for(scope)
    assert scope.coverage is None
    assert scope.chain is not None
    parent = scope.chain.parent
    assert parent.coverage is not None
    crosses = real16_invocation_domain.real16_scope_crosses_call_8616
    assert crosses(parent, scope, parent.coverage, native.STUB)
    assert not crosses(None, scope, parent.coverage, native.STUB)
    assert not crosses(parent, scope, parent.coverage, native.STUB + 1)
    assert not crosses(replace(parent, boot=object()), scope, parent.coverage, native.STUB)
    proof = segment_call_preservation.prove_segment_call_preservation_8616(
        parent.coverage, closure, world[4], native.STUB, invocation=parent,
    )
    assert proof.failure is None, proof.failure
    assert proof.complete_for(parent)
    assert not proof.complete
    assert not proof.complete_for(scope)
    assert 'cs' in proof.preserved_registers_for(parent)
