"""Local coordinate bindings cannot establish a function-wide frame delta."""

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.analysis.stack_frame_ir import (
    BPFrameCoordinateEvidence8616,
    FrameAccessArtifact,
    FrameCoordinateStats8616,
    FrameCoordinateStatus8616,
)
from angr_platforms.X86_16.ir.native_stack_anchor import NATIVE_ENTRY_SP_ANCHOR_TAG8616
from angr_platforms.X86_16.lowering import stack_address_coordinates
from angr_platforms.X86_16.lowering.stack_frame_projection import entry_sp_offset_for_machine_bp_range_8616
from angr_platforms.X86_16.lowering.stack_lowering_from_facts import materialize_stack_cvar_at_offset_from_facts_8616
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
    stack_variable_coordinate_registry_8616,
)
from test_x86_16_stack_word_load_materialization import _Codegen


@pytest.mark.parametrize("frame_delta", [None, -2])
@pytest.mark.parametrize("requested_offset", [0, -6, -8])
def test_stack_coordinate_binding_does_not_extrapolate_frame(frame_delta, requested_offset):
    codegen = SimpleNamespace()
    if frame_delta is not None:
        codegen._inertia_vex_ir_frame = FrameAccessArtifact(
            bp_coordinate=BPFrameCoordinateEvidence8616(
                status=FrameCoordinateStatus8616.PROVEN,
                bp_entry_sp_delta=frame_delta,
                stats=FrameCoordinateStats8616(1, 1, 1, 1, 0),
            ),
        )
    record_stack_variable_coordinate_projection_8616(
        codegen, variable=SimStackVariable(0, 1, base="bp"), cvar=object(),
        bp_offset=0, entry_sp_offset=0, size=1,
    )

    result = entry_sp_offset_for_machine_bp_range_8616(codegen, requested_offset, 1)

    expected = (0 if requested_offset == 0 else
                requested_offset + frame_delta if frame_delta is not None else None)
    assert result == expected


@pytest.mark.parametrize("tagged", [False, True])
def test_native_stack_anchor_does_not_need_a_machine_bp_frame(tagged):
    codegen = _Codegen(None)
    variable = structured_c.CVariable(SimStackVariable(42, 1, base="bp"), codegen=codegen)
    reference = structured_c.CUnaryOp(
        "Reference", variable, codegen=codegen,
        tags={NATIVE_ENTRY_SP_ANCHOR_TAG8616: -6} if tagged else {},
    )
    offset = stack_address_coordinates.native_entry_sp_offset_for_anchor_8616(reference)
    assert offset == (-6 if tagged else None)


def test_native_stack_materialization_does_not_publish_a_bp_relation():
    codegen = _Codegen(None)
    codegen.cfunc = SimpleNamespace(addr=0x1000, variables_in_use={}, unified_local_vars={}, arg_list=())
    result = materialize_stack_cvar_at_offset_from_facts_8616(
        codegen, -5, 1, publish_machine_bp=False,
    )
    assert isinstance(result, structured_c.CVariable)
    assert result.variable.offset == -5
    assert stack_variable_coordinate_registry_8616(codegen).projections == ()
