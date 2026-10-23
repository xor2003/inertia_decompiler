"""Canonical attachment retains explicit, authenticated conditional state."""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from inertia.ir.function_ir_registry import registered_function_ir_artifact_8616
from inertia.ir.scoped_function_ir_view import prove_scoped_function_ir_view_8616
from inertia.ir.segment_state import apply_x86_16_segment_state_artifact
from tests.ir.test_declared_entry_scoped_view import native_scope as native_scope

pytestmark = pytest.mark.decompiler


def test_cleared_previous_state_is_an_unscoped_miss():
    codegen = SimpleNamespace(_inertia_segment_state_artifact=None)
    assert not apply_x86_16_segment_state_artifact(object(), codegen)
    assert codegen._inertia_segment_state_artifact is None


def test_foreign_previous_state_is_rejected_explicitly():
    foreign = object()
    codegen = SimpleNamespace(_inertia_segment_state_artifact=foreign)
    with pytest.raises(TypeError, match="retained segment state"):
        apply_x86_16_segment_state_artifact(object(), codegen)
    assert codegen._inertia_segment_state_artifact is foreign


def test_apply_retains_authenticated_declared_scope(native_scope):
    project,link,scope,proof = native_scope
    view = prove_scoped_function_ir_view_8616(link.artifact,link.boundary,proof,invocation_scope=scope)
    assert view.failure is None
    before = registered_function_ir_artifact_8616(project,link.artifact.function_addr)
    codegen = SimpleNamespace(_inertia_vex_ir_artifact=link.artifact)
    assert not apply_x86_16_segment_state_artifact(project,codegen,invocation_scope=scope,scoped_view=view)
    state = codegen._inertia_segment_state_artifact
    assert state.source_artifact is link.artifact
    assert state.invocation_scope is scope
    assert state.scoped_view is view
    assert state.summary['scoped_view_bound']
    assert registered_function_ir_artifact_8616(project,link.artifact.function_addr) == before


def test_default_apply_remains_unscoped(native_scope):
    project,link,_scope,_proof = native_scope
    codegen = SimpleNamespace(_inertia_vex_ir_artifact=link.artifact)
    apply_x86_16_segment_state_artifact(project,codegen)
    state = codegen._inertia_segment_state_artifact
    assert state.source_artifact is link.artifact
    assert state.invocation_scope is None and state.scoped_view is None
    assert not state.summary['scoped_view_bound']


@pytest.mark.parametrize('mutation',['scope','view','artifact','declaration','native'])
def test_invalid_explicit_context_never_attaches_unscoped_state(native_scope,mutation):
    project,link,scope,proof = native_scope
    view = prove_scoped_function_ir_view_8616(link.artifact,link.boundary,proof,invocation_scope=scope)
    assert view.failure is None
    artifact = link.artifact
    if mutation == 'scope':
        scope = None
    elif mutation == 'view':
        view = None
    elif mutation == 'artifact':
        artifact = replace(artifact)
    elif mutation == 'declaration':
        admission = replace(link.admission,spec=replace(link.admission.spec,entry_offset=0x21))
        scope = replace(scope,chain=replace(link,admission=admission))
    else:
        project.loader.memory.store(0x1022,b'\x90')
    codegen = SimpleNamespace(_inertia_vex_ir_artifact=artifact)
    with pytest.raises(ValueError):
        apply_x86_16_segment_state_artifact(project,codegen,invocation_scope=scope,scoped_view=view)
    assert not hasattr(codegen,'_inertia_segment_state_artifact')


def test_default_refresh_preserves_consumed_conditional_scope(native_scope):
    from inertia.validation.tail_validation import collect_x86_16_tail_validation_summary
    project, link, scope, proof = native_scope
    view = prove_scoped_function_ir_view_8616(link.artifact, link.boundary, proof, invocation_scope=scope)
    codegen = SimpleNamespace(_inertia_vex_ir_artifact=link.artifact)
    apply_x86_16_segment_state_artifact(project, codegen, invocation_scope=scope, scoped_view=view)
    before = codegen._inertia_segment_state_artifact
    collect_x86_16_tail_validation_summary(project, codegen)
    apply_x86_16_segment_state_artifact(project, codegen)
    after = codegen._inertia_segment_state_artifact
    assert after is not before
    assert after.invocation_scope is scope and after.scoped_view is view
    assert after.source_artifact is link.artifact
    assert after.summary['scoped_view_bound']


@pytest.mark.parametrize('mutation', ['artifact', 'missing_artifact', 'native', 'scope', 'detached_scope'])
def test_default_refresh_refuses_stale_retained_condition(native_scope, mutation):
    project, link, scope, proof = native_scope
    view = prove_scoped_function_ir_view_8616(link.artifact, link.boundary, proof, invocation_scope=scope)
    codegen = SimpleNamespace(_inertia_vex_ir_artifact=link.artifact)
    apply_x86_16_segment_state_artifact(project, codegen, invocation_scope=scope, scoped_view=view)
    state = codegen._inertia_segment_state_artifact
    if mutation == 'artifact':
        codegen._inertia_vex_ir_artifact = replace(link.artifact)
    elif mutation == 'missing_artifact':
        del codegen._inertia_vex_ir_artifact
    elif mutation == 'native':
        project.loader.memory.store(0x1022, b'\x90')
    elif mutation == 'scope':
        codegen._inertia_segment_state_artifact = replace(state, invocation_scope=replace(scope, source_sha256='0' * 64))
    else:
        codegen._inertia_segment_state_artifact = replace(state, invocation_scope=None, scoped_view=None)
    retained = codegen._inertia_segment_state_artifact
    with pytest.raises(ValueError):
        apply_x86_16_segment_state_artifact(project, codegen)
    assert codegen._inertia_segment_state_artifact is retained
