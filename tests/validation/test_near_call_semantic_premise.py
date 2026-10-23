"""A private semantic projection retains its native conditional entry."""

from dataclasses import replace

import pytest

from inertia.ir.entry_projection_mode import EntryProjectionMode8616
from inertia.semantics.call_stack_effect_pipeline import (
    CallSemanticProjection8616,
    build_semantic_function_ssa_8616,
)
from inertia.semantics.scoped_call_projection import ScopedCallSemanticInput8616, scoped_call_blocks_8616
from inertia.validation.declared_entry_premise import (
    EntryPremiseStatus8616,
    collect_entry_premise_8616,
)
from tests.validation.test_near_call_entry_premise import _attached

pytestmark = pytest.mark.decompiler


def test_native_near_call_semantic_projection_stays_conditional() -> None:
    """Owned semantic transforms may consume the same exact native scope."""
    project, codegen = _attached()
    state = codegen._inertia_segment_state_artifact
    scope, view = state.near_call_scope, state.scoped_view
    projected = view.cfg_projection_for(scope, mode=EntryProjectionMode8616.CALL_TARGETS)
    assert projected is not None
    source = state.source_artifact
    semantic_input = ScopedCallSemanticInput8616(
        project, view.boundary, source,
        replace(source, blocks=scoped_call_blocks_8616(projected), refusals=()), scope, view,
    )
    effects, outputs, ssa = build_semantic_function_ssa_8616(
        project, view.boundary, ir_artifact=semantic_input.input_ir,
    )
    projection = CallSemanticProjection8616(source, effects, outputs, ssa, semantic_input)
    assert projection.complete
    codegen._inertia_vex_ir_artifact = outputs.function
    codegen._inertia_vex_ir_function_ssa = ssa
    codegen._inertia_call_semantic_projection_8616 = projection
    receipt = collect_entry_premise_8616(project, codegen)
    assert receipt is not None
    assert receipt.status is EntryPremiseStatus8616.CONDITIONAL
    # Equal serialized coordinates cannot replace the authenticated scope.
    codegen._inertia_call_semantic_projection_8616 = replace(
        projection, scoped_input=replace(semantic_input, scope=replace(scope)),
    )
    refused = collect_entry_premise_8616(project, codegen)
    assert refused is not None
    assert refused.status is EntryPremiseStatus8616.REFUSED
