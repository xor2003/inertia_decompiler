"""Validate proven pointer-parameter writes against final structured C.

Layer: Tail validation.
Responsibility: require each Types/Lowering-proven pointer output to remain a
write through the same logical function parameter in the final C AST.
Consumes typed pointer-output and stack-coordinate facts. It never recovers,
rewrites, or renders semantics.

Package ownership contract (canonical inertia/validation package):
Layer: Validation.
Owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.analyses.decompiler.structured_codegen.c import unpack_typeref
from angr.sim_type import SimType
from angr.sim_variable import SimStackVariable
from archinfo import Arch

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.lowering.pointer_parameter_outputs import pointer_parameter_output_evidence_8616
from inertia.lowering.stack_variable_coordinates import machine_bp_offset_for_stack_variable_8616

from .validation_pointer_parameter_output_contracts import (
    PointerParameterOutputIssue8616,
    PointerParameterOutputIssueKind8616,
    PointerParameterOutputValidationReport8616,
    PointerParameterWriteRequirement8616,
)


class _CFunctionSurface8616(Protocol):
    """Third-party C-function fields used by this read-only validator."""

    addr: int
    arg_list: Sequence[object] | None


class _CodegenSurface8616(Protocol):
    """Third-party codegen fields used by this read-only validator."""

    cfunc: _CFunctionSurface8616 | None


class _ProjectSurface8616(Protocol):
    """Project architecture used to resolve final C type widths."""

    arch: Arch


def _strip_casts_8616(node: object) -> object:
    """Return the expression beneath transparent structured-C casts."""
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    return node


def _constant_int_8616(node: object) -> int | None:
    """Return one exact structured-C integer constant."""
    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CConstant):
        return None
    value = node.value
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _type_width_8616(project: object, type_: object) -> int | None:
    """Return one architecture-bound structured-C type width in bytes."""
    if not isinstance(type_, SimType):
        return None
    try:
        arch = cast(_ProjectSurface8616, project).arch
        bits = unpack_typeref(type_).with_arch(arch).size
    except (AttributeError, TypeError, ValueError):
        return None
    if (
        not isinstance(bits, int)
        or not isinstance(arch.byte_width, int)
        or arch.byte_width <= 0
        or bits <= 0
        or bits % arch.byte_width != 0
    ):
        return None
    return bits // arch.byte_width


def _argument_index_8616(
    codegen: object,
    node: object,
    requirements_by_stack_offset: dict[int, int],
) -> int | None:
    """Resolve one C variable to its evidence-owned logical argument index."""
    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CVariable):
        return None
    variable = node.variable
    if not isinstance(variable, SimStackVariable):
        return None
    stack_offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
    return requirements_by_stack_offset.get(stack_offset) if stack_offset is not None else None


def _pointer_expression_8616(
    codegen: object,
    node: object,
    requirements_by_stack_offset: dict[int, int],
) -> tuple[int, int] | None:
    """Resolve a pointer argument expression and constant byte displacement."""
    node = _strip_casts_8616(node)
    direct = _argument_index_8616(codegen, node, requirements_by_stack_offset)
    if direct is not None:
        return direct, 0
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "Add":
        return None
    for pointer, displacement in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        logical_index = _argument_index_8616(
            codegen,
            pointer,
            requirements_by_stack_offset,
        )
        constant = _constant_int_8616(displacement)
        if logical_index is not None and constant is not None:
            return logical_index, constant
    return None


def _helper_target_8616(node: structured_c.CFunctionCall) -> str | None:
    """Return the exact third-party helper target name when available."""
    target = node.callee_target
    if isinstance(target, str):
        return target.upper()
    callee = node.callee_func
    return callee.name.upper() if callee is not None and isinstance(callee.name, str) else None


def _pointer_lvalue_range_8616(
    project: object,
    codegen: object,
    lvalue: object,
    requirements_by_stack_offset: dict[int, int],
) -> tuple[int, int, int] | None:
    """Classify one final lvalue as a logical pointer-parameter byte range."""
    node = _strip_casts_8616(lvalue)
    field_offset = 0
    field_width: int | None = None
    pointer_field = False
    while isinstance(node, structured_c.CVariableField):
        offset = node.field.offset
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            return None
        field_offset += offset
        field_width = _type_width_8616(project, node.field.type)
        pointer_field = pointer_field or node.var_is_ptr
        node = _strip_casts_8616(node.variable)
    if isinstance(node, structured_c.CIndexedVariable):
        logical_index = _argument_index_8616(
            codegen,
            node.variable,
            requirements_by_stack_offset,
        )
        index = _constant_int_8616(node.index)
        element_width = _type_width_8616(project, node.type)
        width = field_width if field_width is not None else element_width
        if logical_index is None or index is None or element_width is None or width is None:
            return None
        return logical_index, index * element_width + field_offset, width
    if pointer_field:
        logical_index = _argument_index_8616(
            codegen,
            node,
            requirements_by_stack_offset,
        )
        if logical_index is not None and field_width is not None:
            return logical_index, field_offset, field_width
    if not isinstance(node, structured_c.CFunctionCall):
        return None
    target = _helper_target_8616(node)
    helper_widths = {
        "MEM_U8": (0, 1),
        "MEM_U16": (0, 2),
        "MEM_U32": (0, 4),
        "SEG_U8": (1, 1),
        "SEG_U16": (1, 2),
        "SEG_U32": (1, 4),
    }
    helper = helper_widths.get(target or "")
    args = tuple(node.args or ())
    if helper is None or helper[0] >= len(args):
        return None
    pointer = _pointer_expression_8616(
        codegen,
        args[helper[0]],
        requirements_by_stack_offset,
    )
    return (*pointer, helper[1]) if pointer is not None else None


def validate_pointer_parameter_write_requirements_8616(
    project: object,
    codegen: object,
    root: object,
    requirements: tuple[PointerParameterWriteRequirement8616, ...],
) -> PointerParameterOutputValidationReport8616:
    """Validate normalized requirements against exact final AST write owners."""
    requirements_by_stack_offset = {
        requirement.stack_offset: requirement.logical_index
        for requirement in requirements
    }
    interface_valid = len(requirements_by_stack_offset) == len(requirements)
    available: Counter[tuple[int, int]] = Counter()
    if interface_valid:
        for node in _iter_c_nodes_deep_8616(root):
            if not isinstance(node, structured_c.CAssignment):
                continue
            write = _pointer_lvalue_range_8616(
                project,
                codegen,
                node.lhs,
                requirements_by_stack_offset,
            )
            if write is None:
                continue
            logical_index, relative_offset, width = write
            available.update(
                (logical_index, relative_offset + byte_index)
                for byte_index in range(width)
            )
    issues: list[PointerParameterOutputIssue8616] = []
    materialized = 0
    for requirement in requirements:
        if not interface_valid:
            issues.append(
                PointerParameterOutputIssue8616(
                    PointerParameterOutputIssueKind8616.INTERFACE_UNAVAILABLE,
                    requirement,
                )
            )
            continue
        required_bytes = tuple(
            (requirement.logical_index, requirement.relative_offset + byte_index)
            for byte_index in range(requirement.width)
        )
        if all(available[item] > 0 for item in required_bytes):
            available.subtract(required_bytes)
            materialized += 1
            continue
        issues.append(
            PointerParameterOutputIssue8616(
                PointerParameterOutputIssueKind8616.MISSING_WRITE,
                requirement,
            )
        )
    return PointerParameterOutputValidationReport8616(
        raw_fact_count=len(requirements),
        normalized_fact_count=len(requirements),
        classified_fact_count=len(requirements) if interface_valid else 0,
        materialized_count=materialized,
        failure_count=len(issues),
        issues=tuple(issues),
    )


def validate_pointer_parameter_outputs_8616(
    project: object,
    codegen: object,
    root: object,
) -> PointerParameterOutputValidationReport8616:
    """Validate every complete published pointer-output contract for a function."""
    boundary = cast(_CodegenSurface8616, codegen)
    try:
        cfunc = boundary.cfunc
    except AttributeError:
        return PointerParameterOutputValidationReport8616()
    if cfunc is None:
        return PointerParameterOutputValidationReport8616()
    try:
        function_addr = cfunc.addr
    except AttributeError:
        return PointerParameterOutputValidationReport8616()
    if not isinstance(function_addr, int):
        return PointerParameterOutputValidationReport8616()
    evidence = pointer_parameter_output_evidence_8616(project, function_addr)
    if evidence is None or not evidence.complete:
        return PointerParameterOutputValidationReport8616()
    requirements = tuple(
        PointerParameterWriteRequirement8616(
            logical_index=fact.logical_index,
            stack_offset=fact.argument_storage.offset,
            relative_offset=fact.output_view.relative_offset,
            width=fact.output_view.width,
        )
        for fact in evidence.facts
    )
    return validate_pointer_parameter_write_requirements_8616(
        project,
        codegen,
        root,
        requirements,
    )


__all__ = [
    "PointerParameterOutputIssue8616",
    "PointerParameterOutputIssueKind8616",
    "PointerParameterOutputValidationReport8616",
    "PointerParameterWriteRequirement8616",
    "validate_pointer_parameter_outputs_8616",
    "validate_pointer_parameter_write_requirements_8616",
]
