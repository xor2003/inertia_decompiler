"""Subview materialization must preserve published stack coordinate bindings."""

from copy import copy
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CAssignment, CStatements
from angr_platforms.X86_16.analysis.stack_frame_ir import (
    BPFrameCoordinateEvidence8616,
    FrameAccessArtifact,
    FrameCoordinateStats8616,
    FrameCoordinateStatus8616,
)
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)
from angr_platforms.X86_16.widening.stack_subview_projection import (
    materialize_contained_stack_subviews_8616,
)
from angr_platforms.X86_16.widening.stack_subview_proof import (
    StackObjectViewResolutionKind8616,
    resolve_stack_object_view_8616,
)
from test_x86_16_stack_subview_projection import (
    FUNCTION_ADDR,
    _attach_word_proof,
    _constant,
    _DummyCodegen,
    _stack_var,
)


@pytest.mark.parametrize("lane", [0, 1])
@pytest.mark.parametrize("saved_frame", [False, True])
@pytest.mark.parametrize("clone", [False, True])
def test_subview_proof_uses_bound_machine_coordinate(lane, saved_frame, clone):
    codegen = _DummyCodegen()
    word = _stack_var(-4, 2, "word", codegen)
    bp_offset = lane if saved_frame else -2 + lane
    view = _stack_var(bp_offset - 2, 1, "view", codegen)
    view.variable.ident = "view_identity"
    for cvar, bp, size in ((word, -2, 2), (view, bp_offset, 1)):
        record_stack_variable_coordinate_projection_8616(
            codegen, variable=cvar.variable, cvar=cvar, bp_offset=bp,
            entry_sp_offset=bp - 2, size=size,
        )
    if clone:
        view.variable = copy(view.variable)
    assignment = CAssignment(view, _constant(0xAB, codegen), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=FUNCTION_ADDR, statements=CStatements([assignment], codegen=codegen),
        variables_in_use={word.variable: word, view.variable: view},
    )
    codegen._inertia_vex_ir_frame = FrameAccessArtifact(
        bp_coordinate=BPFrameCoordinateEvidence8616(
            status=FrameCoordinateStatus8616.PROVEN, bp_entry_sp_delta=-2,
            stats=FrameCoordinateStats8616(1, 1, 1, 1, 0),
        ),
    )
    _attach_word_proof(codegen, -2, view_offsets=(0, 1))
    artifact = codegen._inertia_stack_memory_object_widening_artifact

    result = resolve_stack_object_view_8616(codegen, codegen.cfunc, artifact, view)
    changed = materialize_contained_stack_subviews_8616(codegen)

    if saved_frame:
        assert result.kind is StackObjectViewResolutionKind8616.NOT_CANDIDATE
        assert not changed
        assert codegen.cfunc.statements.statements[0] is assignment
        assert assignment.lhs is view
    else:
        assert result.kind is StackObjectViewResolutionKind8616.ACCEPTED
        assert result.proof.owner is word
        assert result.proof.relative_offset == lane
        assert changed
