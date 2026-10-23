"""Typed unproved declared entries retain the raw graph without a premise.

A valid declaration whose entry-domain proof produced no scope keeps its
authenticated raw artifact under ``UnprovedDeclaredEntry8616`` and is
consumed through the ordinary unscoped branches. Invalid admissions,
mutation, and removed declarations remain hard failures; nothing publishes
universal authority from the unproved state.
"""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from inertia.ir.declared_entry_pipeline import (
    DeclaredEntryPipeline8616,
    DeclaredEntryPremise8616,
    UnprovedDeclaredEntry8616,
    _retained_input_8616,
)
from inertia.ir.entry_domain_call_preservation import install_real16_invocation_source_8616
from inertia.ir.function_ir_registry import registered_function_ir_artifact_8616
from inertia.ir.scoped_function_ir_view import ScopedFunctionIRViewFailure8616
from inertia.pipeline.errors import PipelineHardError
from tests.ir.test_declared_entry_pipeline_attach import (
    _run_full_prefix,
    _run_initial_callbacks,
)
from tests.ir.test_declared_entry_pipeline_attach import installed_leaf as installed_leaf

pytestmark = pytest.mark.decompiler


def _refuse_scope(*args, **kwargs):
    """Force the optional entry-domain premise to produce no scope."""
    return None


@pytest.fixture
def unproved_leaf(installed_leaf, monkeypatch):
    """A valid declared leaf whose premise proof is unavailable."""
    monkeypatch.setattr(
        "inertia.ir.declared_entry_pipeline.prove_fresh_real16_declared_function_entry_domain_8616",
        _refuse_scope,
    )
    return installed_leaf


def test_unproved_entry_retains_raw_artifact_and_ordinary_refresh(unproved_leaf):
    """The typed non-proof record attaches raw IR; segment state stays unscoped."""
    project, codegen, _ = unproved_leaf
    before = registered_function_ir_artifact_8616(project, 0x1020)
    _run_initial_callbacks(project, codegen)
    entry = codegen._inertia_declared_entry_pipeline_8616
    assert type(entry) is UnprovedDeclaredEntry8616
    assert entry.premise is DeclaredEntryPremise8616.UNKNOWN_REFUSE
    assert entry.view.failure is ScopedFunctionIRViewFailure8616.SCOPE_ABSENT
    assert entry.view.source_artifact is entry.bundle.artifact
    state = codegen._inertia_segment_state_artifact
    assert state.invocation_scope is None
    assert state.scoped_view is None
    assert state.source_artifact is entry.bundle.artifact is codegen._inertia_vex_ir_artifact
    assert registered_function_ir_artifact_8616(project, 0x1020) == before


def test_unproved_entry_second_consume_keeps_identical_record(unproved_leaf):
    """The consumed non-proof record is identity-retained, never re-prepared."""
    project, codegen, _ = unproved_leaf
    _run_initial_callbacks(project, codegen)
    entry = codegen._inertia_declared_entry_pipeline_8616
    _run_initial_callbacks(project, codegen)
    assert codegen._inertia_declared_entry_pipeline_8616 is entry


def test_unproved_entry_full_prefix_keeps_raw_semantics(unproved_leaf, monkeypatch):
    """Unproved input never builds or publishes a semantic projection."""
    from inertia.semantics import call_stack_effect_pipeline as owner

    project, codegen, _ = unproved_leaf
    _run_full_prefix(project, codegen)
    entry = codegen._inertia_declared_entry_pipeline_8616
    assert type(entry) is UnprovedDeclaredEntry8616
    raw_ssa = codegen._inertia_vex_ir_function_ssa
    monkeypatch.setattr(owner, 'build_semantic_function_ssa_8616',
                        lambda *args, **kwargs: pytest.fail('unproved semantic construction'))
    assert owner.apply_x86_16_call_stack_effects_8616(project, codegen) is False
    assert codegen._inertia_vex_ir_function_ssa is raw_ssa
    assert codegen._inertia_vex_ir_artifact is entry.bundle.artifact
    assert not hasattr(codegen, '_inertia_call_semantic_projection_8616')


def test_scoped_call_input_returns_none_for_unproved_entry(unproved_leaf):
    """The Semantics constructor dispatches to no-scoped-input, never AttributeError."""
    from inertia.semantics.scoped_call_projection import scoped_call_semantic_input_8616

    project, codegen, _ = unproved_leaf
    _run_initial_callbacks(project, codegen)
    source_ir = codegen._inertia_vex_ir_artifact
    function = project.kb.functions.function(addr=source_ir.function_addr, create=False)
    assert scoped_call_semantic_input_8616(project, codegen, function, source_ir) is None


def test_clinic_scoped_control_rejects_unproved_entry(unproved_leaf):
    """The private scoped Clinic consumers refuse a non-proof entry loudly."""
    from inertia.frontend.x86_16.clinic_scoped_control import (
        prepare_clinic_scoped_partition_8616,
        transport_clinic_scoped_control_8616,
    )

    project, codegen, _ = unproved_leaf
    _run_initial_callbacks(project, codegen)
    entry = codegen._inertia_declared_entry_pipeline_8616
    clinic = SimpleNamespace()
    with pytest.raises(TypeError):
        prepare_clinic_scoped_partition_8616(clinic, entry)
    with pytest.raises(TypeError):
        transport_clinic_scoped_control_8616(clinic, entry)


@pytest.mark.parametrize('mutation', ['native', 'declaration', 'frame'])
def test_invalid_declared_premise_still_refuses(unproved_leaf, mutation):
    """The unproved leg never rescues a forged declaration or changed native."""
    project, codegen, source = unproved_leaf
    if mutation == 'native':
        project.loader.memory.store(0x1021, b'\x35')
    else:
        admission = source.function_entries[0]
        spec = replace(admission.spec, memory=()) if mutation == 'frame' else replace(
            admission.spec, native_sha256='0' * 64)
        invalid = replace(source, function_entries=(replace(admission, spec=spec),))
        project._inertia_real16_invocation_source_8616 = invalid
    with pytest.raises(PipelineHardError):
        _run_initial_callbacks(project, codegen)
    assert not hasattr(codegen, '_inertia_segment_state_artifact')


def test_removed_consumed_declaration_cannot_fall_back(unproved_leaf):
    """A consumed unproved declaration cannot silently revert to unscoped."""
    project, codegen, _ = unproved_leaf
    _run_initial_callbacks(project, codegen)
    install_real16_invocation_source_8616(project, None)
    with pytest.raises(PipelineHardError, match='declaration changed'):
        _run_initial_callbacks(project, codegen)


def test_unproved_entry_never_publishes_universal_authority(unproved_leaf):
    """No project registry gains universal IR/SSA from the unproved state."""
    from inertia.ir.function_ssa_registry import registered_function_ssa_artifact_8616

    project, codegen, _ = unproved_leaf
    before_ir = registered_function_ir_artifact_8616(project, 0x1020)
    before_ssa = registered_function_ssa_artifact_8616(project, 0x1020)
    _run_full_prefix(project, codegen)
    assert registered_function_ir_artifact_8616(project, 0x1020) == before_ir
    assert registered_function_ssa_artifact_8616(project, 0x1020) == before_ssa


def test_malformed_retained_input_still_typeerrors(installed_leaf):
    """A foreign retained record remains a typed failure, not a fallback."""
    _project, codegen, _source = installed_leaf
    codegen._inertia_declared_entry_pipeline_8616 = object()
    with pytest.raises(TypeError):
        _retained_input_8616(codegen)


def test_proven_leaf_contract_unchanged(installed_leaf):
    """The proven record keeps its scope/view contract and typed status."""
    project, codegen, _ = installed_leaf
    _run_initial_callbacks(project, codegen)
    entry = codegen._inertia_declared_entry_pipeline_8616
    assert type(entry) is DeclaredEntryPipeline8616
    assert entry.premise is DeclaredEntryPremise8616.PROVEN_CONDITIONAL
    state = codegen._inertia_segment_state_artifact
    assert state.invocation_scope is entry.scope
    assert state.scoped_view is entry.view


def test_unproved_premise_cannot_be_relabelled(unproved_leaf):
    """The record type determines its diagnostic status."""
    project, codegen, _ = unproved_leaf
    _run_initial_callbacks(project, codegen)
    entry = codegen._inertia_declared_entry_pipeline_8616
    with pytest.raises(TypeError):
        replace(entry, premise=DeclaredEntryPremise8616.PROVEN_CONDITIONAL)
    function = project.kb.functions.function(addr=0x1020, create=False)
    assert function.info['x86_16_declared_entry']['premise'] == 'unknown_refuse'
    assert function.info['x86_16_declared_entry']['failure'] == entry.view.failure.value


def test_unproved_semantics_rejects_replaced_raw_source(unproved_leaf):
    """Private continuation cannot consume a different raw body."""
    from inertia.semantics.call_stack_effect_pipeline import apply_x86_16_call_stack_effects_8616

    project, codegen, _ = unproved_leaf
    _run_initial_callbacks(project, codegen)
    entry = codegen._inertia_declared_entry_pipeline_8616
    codegen._inertia_declared_entry_pipeline_8616 = replace(
        entry, bundle=replace(entry.bundle, artifact=replace(entry.bundle.artifact)))
    with pytest.raises(PipelineHardError, match='authenticated raw source'):
        apply_x86_16_call_stack_effects_8616(project, codegen)


def test_unproved_entry_rejects_failed_boot_replay(unproved_leaf):
    """Unavailable proof cannot rescue a boot that fails source replay."""
    project, codegen, source = unproved_leaf
    project._inertia_real16_invocation_source_8616 = replace(source, boot_recompute=lambda _: None)
    with pytest.raises(PipelineHardError):
        _run_initial_callbacks(project, codegen)
