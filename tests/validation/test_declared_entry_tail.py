"""Declared entry conditions survive the actual tail boundary."""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from inertia.ir.scoped_function_ir_view import prove_scoped_function_ir_view_8616
from inertia.ir.segment_state import apply_x86_16_segment_state_artifact
from inertia.validation.tail_validation import (
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
    extract_x86_16_tail_validation_snapshot,
    persist_x86_16_tail_validation_snapshot,
    x86_16_tail_validation_result_passed,
)
from tests.ir.test_declared_entry_pipeline_attach import (
    _run_full_prefix,
)
from tests.ir.test_declared_entry_pipeline_attach import (
    installed_leaf as installed_leaf,
)
from tests.ir.test_declared_entry_scoped_view import native_scope as native_scope

pytestmark = pytest.mark.decompiler


def test_complete_prefix_keeps_conditional_tail_receipt(installed_leaf):
    project, codegen, _ = installed_leaf
    _run_full_prefix(project, codegen)
    before = collect_x86_16_tail_validation_summary(project, codegen)
    result = compare_x86_16_tail_validation_summaries(before, before)
    assert result['status'] == 'conditional'
    assert not x86_16_tail_validation_result_passed(result)
    assert result['entry_premise']['payload']['declaration']['assumption'] == 'declared_function_entry'


@pytest.mark.parametrize('mutation', ['projection', 'ir', 'ssa', 'native'])
def test_projected_tail_receipt_rejects_detached_or_stale_outputs(installed_leaf, mutation):
    project, codegen, _ = installed_leaf
    _run_full_prefix(project, codegen)
    before = collect_x86_16_tail_validation_summary(project, codegen)
    assert before.entry_premise.status.value == 'conditional'
    if mutation == 'projection':
        del codegen._inertia_call_semantic_projection_8616
    elif mutation == 'ir':
        codegen._inertia_vex_ir_artifact = replace(codegen._inertia_vex_ir_artifact)
    elif mutation == 'ssa':
        codegen._inertia_vex_ir_function_ssa = replace(codegen._inertia_vex_ir_function_ssa)
    else:
        project.loader.memory.store(0x1021, b'\x35')
    after = collect_x86_16_tail_validation_summary(project, codegen)
    assert after.entry_premise.status.value == 'refused'
    assert compare_x86_16_tail_validation_summaries(before, after)['status'] == 'refused'


@pytest.fixture
def attached(native_scope):
    project, link, scope, proof = native_scope
    view = prove_scoped_function_ir_view_8616(link.artifact, link.boundary, proof, invocation_scope=scope)
    codegen = SimpleNamespace(_inertia_vex_ir_artifact=link.artifact)
    apply_x86_16_segment_state_artifact(project, codegen, invocation_scope=scope, scoped_view=view)
    return project, codegen


def test_actual_scope_is_conditional_and_survives_snapshot(attached):
    project, codegen = attached
    before = collect_x86_16_tail_validation_summary(project, codegen)
    result = compare_x86_16_tail_validation_summaries(before, before)
    assert result['status'] == 'conditional'
    assert not x86_16_tail_validation_result_passed(result)
    assert result['entry_premise']['payload']['declaration']['assumption'] == 'declared_function_entry'
    info = {}
    persist_x86_16_tail_validation_snapshot(function_info=info, codegen=codegen, stage='structuring', validation=result)
    snapshot = extract_x86_16_tail_validation_snapshot(info)
    assert snapshot['structuring']['entry_premise'] == result['entry_premise']
    assert snapshot['structuring']['status'] == 'conditional'


@pytest.mark.parametrize('mutation', ['missing', 'scope', 'native'])
def test_stale_or_missing_condition_refuses(attached, mutation):
    project, codegen = attached
    before = collect_x86_16_tail_validation_summary(project, codegen)
    state = codegen._inertia_segment_state_artifact
    if mutation == 'missing':
        del codegen._inertia_segment_state_artifact
    elif mutation == 'scope':
        codegen._inertia_segment_state_artifact = replace(state, invocation_scope=replace(state.invocation_scope, source_sha256='0' * 64))
    else:
        project.loader.memory.store(0x1022, b'\x90')
    after = collect_x86_16_tail_validation_summary(project, codegen)
    result = compare_x86_16_tail_validation_summaries(before, after)
    assert result['status'] == 'refused'
    assert not x86_16_tail_validation_result_passed(result)


@pytest.mark.parametrize('mutation', ['missing', 'changed', 'stable'])
def test_snapshot_cannot_erase_or_corrupt_condition(attached, mutation):
    project, codegen = attached
    summary = collect_x86_16_tail_validation_summary(project, codegen)
    result = compare_x86_16_tail_validation_summaries(summary, summary)
    info = {}
    persist_x86_16_tail_validation_snapshot(function_info=info, codegen=codegen, stage='structuring', validation=result)
    stored = info['x86_16_tail_validation']['structuring']
    if mutation == 'missing':
        del stored['entry_premise']
    elif mutation == 'changed':
        stored['entry_premise']['payload']['domain']['entry_segment'] += 1
    else:
        stored['status'] = 'stable'
    extracted = extract_x86_16_tail_validation_snapshot(info)['structuring']
    assert extracted['status'] == ('conditional' if mutation == 'stable' else 'refused')
    assert not x86_16_tail_validation_result_passed(extracted)


def test_boundary_fingerprint_binds_declaration(attached):
    from inertia.validation.tail_validation import fingerprint_x86_16_tail_validation_boundary
    project, codegen = attached
    before = fingerprint_x86_16_tail_validation_boundary(project, codegen)
    state = codegen._inertia_segment_state_artifact
    codegen._inertia_segment_state_artifact = replace(state, invocation_scope=replace(state.invocation_scope, source_sha256='0' * 64))
    assert fingerprint_x86_16_tail_validation_boundary(project, codegen) != before


@pytest.mark.parametrize('mutation', ['missing', 'scope', 'native'])
def test_real_ast_summary_cache_never_reuses_changed_entry(attached, mutation):
    from tests.validation.test_x86_16_tail_validation import _codegen, _DummyCodegen
    project, attached_codegen = attached
    codegen = _codegen([], _DummyCodegen())
    codegen._inertia_segment_state_artifact = attached_codegen._inertia_segment_state_artifact
    codegen._inertia_vex_ir_artifact = attached_codegen._inertia_vex_ir_artifact
    before = collect_x86_16_tail_validation_summary(project, codegen, boundary_fingerprint='same-ast')
    same = collect_x86_16_tail_validation_summary(project, codegen, boundary_fingerprint='same-ast')
    assert same is before
    assert codegen._inertia_tail_validation_last_summary_cache_hit
    state = codegen._inertia_segment_state_artifact
    if mutation == 'missing':
        del codegen._inertia_segment_state_artifact
    elif mutation == 'scope':
        codegen._inertia_segment_state_artifact = replace(state, invocation_scope=replace(state.invocation_scope, source_sha256='0' * 64))
    else:
        project.loader.memory.store(0x1022, b'\x90')
    after = collect_x86_16_tail_validation_summary(project, codegen, boundary_fingerprint='same-ast')
    assert not codegen._inertia_tail_validation_last_summary_cache_hit
    assert compare_x86_16_tail_validation_summaries(before, after)['status'] == 'refused'


def test_detached_scoped_state_refuses_even_self_comparison(attached):
    project, codegen = attached
    state = codegen._inertia_segment_state_artifact
    codegen._inertia_segment_state_artifact = replace(state, invocation_scope=None, scoped_view=None)
    summary = collect_x86_16_tail_validation_summary(project, codegen)
    assert compare_x86_16_tail_validation_summaries(summary, summary)['status'] == 'refused'
