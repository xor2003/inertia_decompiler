from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.stack_prototype_materialization import (
    FunctionParameterWidthFact8616,
)
from inertia.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)

from inertia.validation.validation_calls import validate_function_parameters_8616


class _Codegen:
    """Minimal third-party codegen boundary for parameter validation."""

    def __init__(self) -> None:
        self.project = SimpleNamespace(arch=Arch86_16())
        self._next_index = 0

    def next_idx(self, _kind: str) -> int:
        """Return one deterministic C-AST index."""
        self._next_index += 1
        return self._next_index

    def next_node_idx(self) -> int:
        """Return one deterministic C-AST node index."""
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        """Preserve the requested test identity."""
        return name


def test_parameter_validation_uses_machine_bp_coordinates() -> None:
    """Match BP facts to projected entry-SP variables without slot shifting."""
    codegen = _Codegen()
    parameter_types = (
        SimTypeShort(False).with_arch(codegen.project.arch),
        SimTypeChar(False).with_arch(codegen.project.arch),
    )
    variables = (
        SimStackVariable(2, 2, base="bp", name="value", ident="arg_0"),
        SimStackVariable(4, 1, base="bp", name="mode", ident="arg_1"),
    )
    arguments = tuple(
        CVariable(variable, variable_type=type_, codegen=codegen)
        for variable, type_ in zip(variables, parameter_types, strict=True)
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=arguments,
        functy=SimTypeFunction(
            list(parameter_types),
            SimTypeShort(False),
        ).with_arch(codegen.project.arch),
    )
    codegen._inertia_function_parameter_width_facts_8616 = (
        FunctionParameterWidthFact8616(stack_offset=4, width_bytes=2),
        FunctionParameterWidthFact8616(stack_offset=6, width_bytes=1),
    )
    for variable, argument, bp_offset in zip(
        variables,
        arguments,
        (4, 6),
        strict=True,
    ):
        record_stack_variable_coordinate_projection_8616(
            codegen,
            variable=variable,
            cvar=argument,
            bp_offset=bp_offset,
            entry_sp_offset=variable.offset,
            size=variable.size,
        )

    report = validate_function_parameters_8616(codegen.project, codegen)

    assert report.passed
    assert report.classified_fact_count == 2
    assert report.materialized_count == 2


def test_parameter_validation_uses_final_prototype_before_arg_list_exists() -> None:
    """Validate byte arguments from the typed ABI layout during structuring."""
    codegen = _Codegen()
    parameter_types = (
        SimTypeChar(True).with_arch(codegen.project.arch),
        SimTypeChar(False).with_arch(codegen.project.arch),
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=(),
        functy=SimTypeFunction(
            list(parameter_types),
            SimTypeChar(True),
        ).with_arch(codegen.project.arch),
    )
    codegen._inertia_function_parameter_width_facts_8616 = (
        FunctionParameterWidthFact8616(stack_offset=4, width_bytes=1),
        FunctionParameterWidthFact8616(stack_offset=6, width_bytes=1),
    )

    report = validate_function_parameters_8616(codegen.project, codegen)

    assert report.passed
    assert report.classified_fact_count == 2
    assert report.materialized_count == 2
