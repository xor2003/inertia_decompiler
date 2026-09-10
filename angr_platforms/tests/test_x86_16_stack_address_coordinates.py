from __future__ import annotations

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
from angr_platforms.X86_16.lowering.real_mode_linear import _stack_offset_from_expr_8616
from angr_platforms.X86_16.lowering.stack_address_coordinates import (
    absolute_machine_bp_offset_from_wrapped_anchor_8616,
    machine_bp_offset_for_entry_sp_anchor_8616,
)
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)


class _Codegen(SimpleNamespace):
    def next_ident(self, name: str) -> str:
        return name

    def next_node_idx(self) -> int:
        return 1


def _frame() -> FrameAccessArtifact:
    return FrameAccessArtifact(
        bp_coordinate=BPFrameCoordinateEvidence8616(
            status=FrameCoordinateStatus8616.PROVEN,
            bp_entry_sp_delta=-2,
            detail="push bp; mov bp, sp",
            stats=FrameCoordinateStats8616(1, 1, 1, 1, 0),
        )
    )


def test_unprojected_stack_reference_uses_proven_entry_sp_anchor() -> None:
    codegen = _Codegen(_inertia_vex_ir_frame=_frame())
    variable = SimStackVariable(-2, 1, base="bp", name="frame_anchor")
    cvar = structured_c.CVariable(variable, codegen=codegen)
    reference = structured_c.CUnaryOp("Reference", cvar, codegen=codegen)

    assert machine_bp_offset_for_entry_sp_anchor_8616(codegen, reference) == 0


@pytest.mark.parametrize("entry_offset", [-2, 0])
def test_native_anchor_provenance_preserves_source_coordinate(entry_offset):
    codegen = _Codegen(_inertia_vex_ir_frame=_frame())
    variable = SimStackVariable(entry_offset, 1, base="bp", name="anchor")
    cvar = structured_c.CVariable(variable, codegen=codegen)
    reference = structured_c.CUnaryOp(
        "Reference", cvar, codegen=codegen,
        tags={"inertia_native_entry_sp_anchor_8616": entry_offset},
    )

    assert _stack_offset_from_expr_8616(reference, None, codegen) == entry_offset + 2


@pytest.mark.parametrize("entry_offset", [-2, 0])
@pytest.mark.parametrize("bound", [False, True])
def test_stack_expression_resolver_requires_coordinate_binding(entry_offset, bound):
    codegen = _Codegen(_inertia_vex_ir_frame=_frame())
    variable = SimStackVariable(entry_offset, 1, base="bp", name="anchor")
    cvar = structured_c.CVariable(variable, codegen=codegen)
    reference = structured_c.CUnaryOp("Reference", cvar, codegen=codegen)
    if bound:
        record_stack_variable_coordinate_projection_8616(
            codegen,
            variable=variable,
            cvar=cvar,
            bp_offset=entry_offset + 2,
            entry_sp_offset=entry_offset,
            size=1,
        )

    # A frame delta alone does not identify the variable's coordinate domain.
    expected = entry_offset + 2 if bound else entry_offset
    assert _stack_offset_from_expr_8616(reference, None, codegen) == expected


def test_projected_stack_reference_keeps_coordinate_registry_ownership() -> None:
    codegen = _Codegen(_inertia_vex_ir_frame=_frame())
    variable = SimStackVariable(-2, 1, base="bp", name="projected")
    cvar = structured_c.CVariable(variable, codegen=codegen)
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=variable,
        cvar=cvar,
        bp_offset=-2,
        entry_sp_offset=-2,
        size=1,
    )
    reference = structured_c.CUnaryOp("Reference", cvar, codegen=codegen)

    assert machine_bp_offset_for_entry_sp_anchor_8616(codegen, reference) is None


def test_wrapped_absolute_bp_offset_does_not_double_count_frame_anchor() -> None:
    codegen = _Codegen()
    variable = SimStackVariable(-2, 1, base="bp", name="frame_anchor")
    cvar = structured_c.CVariable(variable, codegen=codegen)
    reference = structured_c.CUnaryOp("Reference", cvar, codegen=codegen)

    assert absolute_machine_bp_offset_from_wrapped_anchor_8616(
        reference,
        0xFFFE,
        {-2},
    ) == -2
    assert absolute_machine_bp_offset_from_wrapped_anchor_8616(
        reference,
        4,
        {4},
    ) is None
