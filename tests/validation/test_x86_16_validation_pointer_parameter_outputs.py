from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CIndexedVariable,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)

from inertia.validation.validation_pointer_parameter_output_contracts import (
    PointerParameterOutputIssueKind8616,
    PointerParameterWriteRequirement8616,
)
from inertia.validation.validation_pointer_parameter_outputs import (
    validate_pointer_parameter_write_requirements_8616,
)


class _Codegen(SimpleNamespace):
    def next_ident(self, name: str) -> str:
        return name

    def next_idx(self, _name: str) -> int:
        return 1

    def next_node_idx(self) -> int:
        return 1


def _surface():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _Codegen(project=project)
    short_type = SimTypeShort(False).with_arch(project.arch)
    left = SimStackVariable(2, 2, base="bp", name="left")
    right = SimStackVariable(4, 2, base="bp", name="right")
    left_cvar = CVariable(left, variable_type=short_type, codegen=codegen)
    right_cvar = CVariable(right, variable_type=short_type, codegen=codegen)
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=left,
        cvar=left_cvar,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=right,
        cvar=right_cvar,
        bp_offset=6,
        entry_sp_offset=4,
        size=2,
    )
    return project, codegen, short_type, left_cvar, right_cvar


def _indexed(cvar, type_, codegen):
    return CIndexedVariable(
        cvar,
        CConstant(0, type_, codegen=codegen),
        variable_type=type_,
        codegen=codegen,
    )


def _requirements():
    return (
        PointerParameterWriteRequirement8616(0, 4, 0, 2),
        PointerParameterWriteRequirement8616(1, 6, 0, 2),
    )


def test_pointer_output_validation_accepts_distinct_parameter_writes() -> None:
    project, codegen, type_, left, right = _surface()
    root = CStatements(
        [
            CAssignment(
                _indexed(left, type_, codegen),
                _indexed(right, type_, codegen),
                codegen=codegen,
            ),
            CAssignment(
                _indexed(right, type_, codegen),
                CConstant(1, type_, codegen=codegen),
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )

    report = validate_pointer_parameter_write_requirements_8616(
        project,
        codegen,
        root,
        _requirements(),
    )

    assert report.passed is True
    assert report.materialized_count == 2


def test_pointer_output_validation_rejects_collapsed_second_parameter() -> None:
    project, codegen, type_, left, right = _surface()
    root = CStatements(
        [
            CAssignment(
                _indexed(left, type_, codegen),
                _indexed(right, type_, codegen),
                codegen=codegen,
            ),
            CAssignment(
                _indexed(left, type_, codegen),
                CConstant(1, type_, codegen=codegen),
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )

    report = validate_pointer_parameter_write_requirements_8616(
        project,
        codegen,
        root,
        _requirements(),
    )

    assert report.passed is False
    assert report.materialized_count == 1
    assert report.issues[0].kind is PointerParameterOutputIssueKind8616.MISSING_WRITE
    assert report.issues[0].requirement.logical_index == 1
