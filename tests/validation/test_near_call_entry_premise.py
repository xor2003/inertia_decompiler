"""Native near-call premises stay conditional at the validation boundary."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from inertia.ir.segment_state import build_x86_16_segment_state_artifact
from inertia.ir.vex_import import (
    prove_scoped_x86_16_ir_function_view_8616,
    raw_x86_16_import_bundle_for_artifact_8616,
)
from inertia.validation.declared_entry_premise import (
    EntryPremiseStatus8616,
    collect_entry_premise_8616,
    entry_premise_cache_identity_8616,
    valid_entry_premise_projection_8616,
)
from inertia.validation.tail_validation import (
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
    x86_16_tail_validation_result_passed,
)
from tests.ir.test_near_call_scoped_view import _native_pending_view_surface

pytestmark = pytest.mark.decompiler


def _attached() -> tuple[object, SimpleNamespace]:
    """Build the real private view and scoped segment state over native bytes."""
    surface, scope = _native_pending_view_surface()
    bundle = raw_x86_16_import_bundle_for_artifact_8616(
        surface.project, surface.boundary, surface.artifact,
    )
    assert bundle is not None
    view = prove_scoped_x86_16_ir_function_view_8616(
        surface.project, bundle, surface.boundary, near_call_scope=scope,
    )
    assert view.failure is None, view.detail
    state = build_x86_16_segment_state_artifact(
        surface.artifact, near_call_scope=scope, scoped_view=view,
    )
    return surface.project, SimpleNamespace(
        _inertia_vex_ir_artifact=surface.artifact,
        _inertia_segment_state_artifact=state,
    )


def test_native_near_call_receipt_preserves_distinct_authority() -> None:
    """A native incoming edge is explicit conditional evidence, not a declaration."""
    project, codegen = _attached()
    receipt = collect_entry_premise_8616(project, codegen)
    assert receipt is not None
    assert receipt.status is EntryPremiseStatus8616.CONDITIONAL
    serialized = receipt.to_dict()
    assert valid_entry_premise_projection_8616(serialized)
    assert serialized['payload']['authority'] == 'native_near_call'
    assert 'declaration' not in serialized['payload']
    serialized['payload']['near_call']['selector_high'] += 1
    assert not valid_entry_premise_projection_8616(serialized)
    summary = collect_x86_16_tail_validation_summary(project, codegen)
    compared = compare_x86_16_tail_validation_summaries(summary, summary)
    assert compared['status'] == 'conditional'
    assert not x86_16_tail_validation_result_passed(compared)


def test_receipt_cache_identity_detects_foreign_same_value_scope() -> None:
    """Equal diagnostic coordinates do not authenticate a replacement scope."""
    _, codegen = _attached()
    before = entry_premise_cache_identity_8616(codegen)
    state = codegen._inertia_segment_state_artifact
    codegen._inertia_segment_state_artifact = replace(state, near_call_scope=replace(state.near_call_scope))
    assert entry_premise_cache_identity_8616(codegen) != before


def test_cached_tail_rechecks_changed_incoming_call() -> None:
    """Changing the external incoming instruction invalidates a cached tail."""
    from tests.validation.test_x86_16_tail_validation import _codegen, _DummyCodegen

    project, attached = _attached()
    codegen = _codegen([], _DummyCodegen())
    codegen._inertia_vex_ir_artifact = attached._inertia_vex_ir_artifact
    codegen._inertia_segment_state_artifact = attached._inertia_segment_state_artifact
    before = collect_x86_16_tail_validation_summary(project, codegen, boundary_fingerprint='same-ast')
    same = collect_x86_16_tail_validation_summary(project, codegen, boundary_fingerprint='same-ast')
    assert same is before
    project.loader.memory.store(0x1001, b'\x00')
    after = collect_x86_16_tail_validation_summary(project, codegen, boundary_fingerprint='same-ast')
    assert after is not before
    assert compare_x86_16_tail_validation_summaries(before, after)['status'] == 'refused'


@pytest.mark.parametrize('mutation', ['scope', 'source', 'native', 'projection'])
def test_near_call_receipt_rejects_stale_or_unsupported_projection(mutation: str) -> None:
    """Fresh conditional proof cannot be reused after its bindings are changed."""
    project, codegen = _attached()
    state = codegen._inertia_segment_state_artifact
    if mutation == 'scope':
        codegen._inertia_segment_state_artifact = replace(state, near_call_scope=replace(state.near_call_scope))
    elif mutation == 'source':
        codegen._inertia_vex_ir_artifact = replace(state.source_artifact)
    elif mutation == 'native':
        project.loader.memory.store(0x1011, b'\x00')
    else:
        codegen._inertia_call_semantic_projection_8616 = object()
    receipt = collect_entry_premise_8616(project, codegen)
    assert receipt is not None
    assert receipt.status is EntryPremiseStatus8616.REFUSED
