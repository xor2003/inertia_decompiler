"""Regress machine-BP identity in structured def-use validation."""

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.lowering.stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    record_stack_variable_coordinate_projection_8616,
)
from archinfo import ArchX86

from inertia.validation.validation_dataflow import validate_structured_def_use_8616


def _codegen() -> SimpleNamespace:
    return SimpleNamespace(
        project=SimpleNamespace(arch=ArchX86()),
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )


def _word_cvar(variable: SimStackVariable, codegen: SimpleNamespace) -> CVariable:
    return CVariable(
        variable,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _validate_with_machine_bp_coordinates(
    codegen: SimpleNamespace,
    root: CStatements,
):
    return validate_structured_def_use_8616(
        root,
        stack_variable_offset_resolver=lambda variable: machine_bp_offset_for_stack_variable_8616(
            codegen,
            variable,
        ),
    )


def test_def_use_accepts_projected_assignment_and_snapshot_clone_read() -> None:
    codegen = _codegen()
    assigned_variable = SimStackVariable(
        -4,
        2,
        base="bp",
        name="err",
        ident="is_3",
    )
    assigned = _word_cvar(assigned_variable, codegen)
    read = _word_cvar(
        SimStackVariable(-4, 2, base="bp", name="err", ident="is_3"),
        codegen,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=assigned_variable,
        cvar=assigned,
        bp_offset=-2,
        entry_sp_offset=-4,
        size=2,
        display_name="err",
    )
    root = CStatements(
        [
            CAssignment(
                assigned,
                CConstant(1, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            read,
        ],
        codegen=codegen,
    )

    report = _validate_with_machine_bp_coordinates(codegen, root)

    assert report.passed
    assert report.materialized_count == 1


def test_def_use_refuses_unrelated_raw_bp_slot_at_projected_numeric_offset() -> None:
    codegen = _codegen()
    projected_variable = SimStackVariable(
        -4,
        2,
        base="bp",
        name="err",
        ident="is_3",
    )
    projected = _word_cvar(projected_variable, codegen)
    raw_bp_read = _word_cvar(
        SimStackVariable(-4, 2, base="bp", name="index", ident="is_4"),
        codegen,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=projected_variable,
        cvar=projected,
        bp_offset=-2,
        entry_sp_offset=-4,
        size=2,
        display_name="err",
    )
    root = CStatements(
        [
            CAssignment(
                projected,
                CConstant(1, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            raw_bp_read,
        ],
        codegen=codegen,
    )

    report = _validate_with_machine_bp_coordinates(codegen, root)

    assert report.failure_count == 1
    assert report.semantic_issue_tokens() == (
        "uninitialized-read:stack-local:SS:BP-0x4:size2",
    )
