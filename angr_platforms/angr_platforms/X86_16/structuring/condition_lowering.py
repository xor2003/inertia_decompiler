"""Lower typed condition/value IR into structured-codegen C AST nodes.

Layer: Structuring.
Responsibility: owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol, cast

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..ir.condition_ir import (
    ConditionIR,
    condition_compare_symbol_8616,
    is_condition_compare_family_8616,
)
from ..ir.core import (
    SEGMENTED_LOAD_ADDRESS_TAG_8616,
    AddressStatus,
    IRAddress,
    IRBinaryValue,
    IRCondition,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from ..lowering.condition_stack_operands import materialize_typed_condition_stack_operand_8616
from ..lowering.condition_stack_value import condition_stack_operand_tags_8616
from ..lowering.gp_register_state import runtime_gp_name_for_variable_8616
from ..lowering.stack_variable_binding import StackVariableBinding, stable_stack_binding_tags_8616
from ..widening.segmented_load_identity import segmented_load_identity_8616
from .condition_binary_value import materialize_binary_ir_value_8616
from .condition_stack_views import materialize_condition_stack_declaration_view_8616
from .indexed_condition_values import materialize_indexed_segmented_condition_value_8616

if TYPE_CHECKING:
    from angr.analyses.decompiler.structured_codegen.c import CConstant, CExpression

__all__ = [
    "SameBlockRegisterAssignment8616",
    "SameBlockRegisterAssignmentIndex8616",
    "SameBlockRegisterProjectionResult8616",
    "SameBlockRegisterProjectionStats8616",
    "SameBlockRegisterProjectionVerdict8616",
    "attach_condition_segment_access_provenance_8616",
    "build_same_block_register_assignment_index_8616",
    "condition_op_to_structured_kind_8616",
    "condition_origin_tags_8616",
    "condition_segment_access_tags_8616",
    "lower_ir_value_to_c_expr_8616",
    "lower_typed_condition_to_c_expr_8616",
    "materialize_binary_ir_value_8616",
    "materialize_condition_stack_declaration_view_8616",
    "materialize_indexed_segmented_condition_value_8616",
    "materialize_same_block_register_projection_8616",
    "materialize_typed_condition_stack_operand_8616",
    "stable_stack_condition_binding_tags_8616",
]

_SOURCE_INSTRUCTION_ADDRS_TAG_8616 = "inertia_source_instruction_addrs"


class _CodegenFunctionBoundary8616(Protocol):
    """Third-party structured-codegen surface exposing its active C function."""

    cfunc: object


class _CFunctionStatementsBoundary8616(Protocol):
    """Third-party C function surface exposing structured statements."""

    statements: object


class _CFunctionBodyBoundary8616(Protocol):
    """Third-party C function surface exposing an optional body root."""

    body: object


class _CFunctionAddressBoundary8616(Protocol):
    """Third-party C function surface exposing its address."""

    addr: object


class SameBlockRegisterProjectionVerdict8616(StrEnum):
    """Typed outcome of one same-block condition-register projection."""

    MATERIALIZED = "materialized"
    NO_CANDIDATE = "no_candidate"
    UNKNOWN_REFUSE = "unknown_refuse"


@dataclass(frozen=True, slots=True)
class SameBlockRegisterProjectionStats8616:
    """Closed evidence counters for a same-block register projection."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class SameBlockRegisterProjectionResult8616:
    """Return one projected expression with its typed evidence accounting."""

    expression: object | None
    verdict: SameBlockRegisterProjectionVerdict8616
    stats: SameBlockRegisterProjectionStats8616


@dataclass(frozen=True, slots=True)
class SameBlockRegisterAssignment8616:
    """One tagged register assignment available to typed condition lowering."""

    instruction_addr: int
    lhs: object
    rhs: object
    register_offset: int
    register_size: int
    use_stored_value: bool = False


@dataclass(frozen=True, slots=True)
class SameBlockRegisterAssignmentIndex8616:
    """Immutable per-AST index of tagged register assignments by CFG block."""

    assignments_by_block: tuple[
        tuple[int, tuple[SameBlockRegisterAssignment8616, ...]],
        ...,
    ]

    def assignments_for_block(
        self,
        block_addr: int,
    ) -> tuple[SameBlockRegisterAssignment8616, ...]:
        """Return assignments indexed for one exact CFG block address."""
        for indexed_block, assignments in self.assignments_by_block:
            if indexed_block == block_addr:
                return assignments
        return ()


def _make_c_constant_8616(value: int, codegen: object, signed: bool = False) -> CConstant:
    """Create a structured-codegen CConstant node."""
    from angr.analyses.decompiler.structured_codegen.c import CConstant
    from angr.sim_type import SimTypeShort

    return CConstant(int(value), SimTypeShort(signed), codegen=codegen)


def _register_offset_size_for_value_8616(value: IRValue, project: object) -> tuple[int, int]:
    """Read register metadata through the dynamic third-party angr project boundary."""
    arch = getattr(project, "arch", None)
    registers = getattr(arch, "registers", {}) if arch is not None else {}
    if isinstance(value.name, str) and value.name in registers:
        reg_offset, reg_size = registers[value.name]
        return int(reg_offset), int(value.size or reg_size or 2)
    return int(value.offset), int(value.size or 2)


def build_same_block_register_assignment_index_8616(
    codegen: object,
) -> SameBlockRegisterAssignmentIndex8616:
    """Index the current C AST once for same-block register projections."""
    from angr.analyses.decompiler.structured_codegen.c import CAssignment, CVariable
    from angr.sim_variable import SimRegisterVariable

    roots: list[object] = []
    try:
        cfunc = cast(_CodegenFunctionBoundary8616, codegen).cfunc
    except AttributeError:
        cfunc = None
    if cfunc is not None:
        roots.append(cfunc)
        with contextlib.suppress(AttributeError):
            roots.append(cast(_CFunctionStatementsBoundary8616, cfunc).statements)
        with contextlib.suppress(AttributeError):
            roots.append(cast(_CFunctionBodyBoundary8616, cfunc).body)

    indexed: dict[int, list[SameBlockRegisterAssignment8616]] = {}
    seen_nodes: set[int] = set()
    for root in roots:
        for node in _iter_c_nodes_deep_8616(root):
            if id(node) in seen_nodes:
                continue
            seen_nodes.add(id(node))
            if not isinstance(node, CAssignment):
                continue
            tags = node.tags if node.tags is not None else {}
            instruction_addr = tags.get("ins_addr")
            block_addr = tags.get("vex_block_addr")
            if (
                not isinstance(instruction_addr, int)
                or not isinstance(block_addr, int)
                or not isinstance(node.lhs, CVariable)
            ):
                continue
            variable = node.lhs.variable
            runtime_name = runtime_gp_name_for_variable_8616(variable)
            if isinstance(variable, SimRegisterVariable):
                register_offset, register_size = int(variable.reg), int(variable.size)
            elif runtime_name is not None:
                # This typed ABI destination is mutable storage, not an SSA RHS.
                register_offset, register_size = cast(Any, codegen).project.arch.registers[runtime_name]
            else:
                continue
            indexed.setdefault(block_addr, []).append(
                SameBlockRegisterAssignment8616(
                    instruction_addr=instruction_addr,
                    lhs=node.lhs,
                    rhs=node.rhs,
                    register_offset=register_offset,
                    register_size=register_size,
                    use_stored_value=runtime_name is not None,
                )
            )
    return SameBlockRegisterAssignmentIndex8616(
        assignments_by_block=tuple(
            (block_addr, tuple(assignments))
            for block_addr, assignments in sorted(indexed.items())
        )
    )


def lower_ir_value_to_c_expr_8616(
    value: IRValue | IRBinaryValue,
    project: object,
    codegen: object,
    *,
    resolve_register_name: bool = False,
) -> object | None:
    """Convert typed IR value evidence into a structured-codegen C expression."""
    if isinstance(value, IRBinaryValue):
        return materialize_binary_ir_value_8616(value, codegen, lambda operand: lower_ir_value_to_c_expr_8616(
            operand, project, codegen, resolve_register_name=resolve_register_name,
        ))
    return _ir_value_to_cvar_8616(value, project, codegen, resolve_register_name=resolve_register_name)


def materialize_same_block_register_projection_8616(
    value: IRValue,
    condition: ConditionIR,
    project: object,
    codegen: object,
    *,
    assignment_index: SameBlockRegisterAssignmentIndex8616 | None = None,
) -> SameBlockRegisterProjectionResult8616:
    """Project a condition subregister from its unique same-block assignment.

    The source assignment must precede the condition producer in the exact VEX
    block and fully contain the requested byte view. A later partial overlap or
    multiple assignments at the same instruction are explicit refusals.
    """
    from angr.analyses.decompiler.structured_codegen.c import (
        CBinaryOp,
        CConstant,
        CExpression,
        CFunctionCall,
    )
    from angr.sim_type import SimTypeShort

    if value.space is not MemSpace.REG:
        return SameBlockRegisterProjectionResult8616(
            None,
            SameBlockRegisterProjectionVerdict8616.NO_CANDIDATE,
            SameBlockRegisterProjectionStats8616(),
        )
    bind_addr = condition.operand_bind_insn
    if not isinstance(bind_addr, int):
        bind_addr = condition.producer_insn
    if not isinstance(bind_addr, int) or not isinstance(condition.block_addr, int):
        return SameBlockRegisterProjectionResult8616(
            None,
            SameBlockRegisterProjectionVerdict8616.UNKNOWN_REFUSE,
            SameBlockRegisterProjectionStats8616(raw_fact_count=1, failure_count=1),
        )

    requested_offset, requested_size = _register_offset_size_for_value_8616(
        value,
        project,
    )
    requested_end = requested_offset + requested_size
    active_index = assignment_index or build_same_block_register_assignment_index_8616(
        codegen
    )
    candidates = [
        assignment
        for assignment in active_index.assignments_for_block(condition.block_addr)
        if assignment.instruction_addr < bind_addr
        and requested_offset < assignment.register_offset + assignment.register_size
        and assignment.register_offset < requested_end
    ]

    if not candidates:
        return SameBlockRegisterProjectionResult8616(
            None,
            SameBlockRegisterProjectionVerdict8616.NO_CANDIDATE,
            SameBlockRegisterProjectionStats8616(raw_fact_count=1),
        )
    latest_addr = max(candidate.instruction_addr for candidate in candidates)
    latest = tuple(
        candidate
        for candidate in candidates
        if candidate.instruction_addr == latest_addr
    )
    normalized = len(latest)
    if len(latest) != 1:
        return SameBlockRegisterProjectionResult8616(
            None,
            SameBlockRegisterProjectionVerdict8616.UNKNOWN_REFUSE,
            SameBlockRegisterProjectionStats8616(
                raw_fact_count=len(candidates),
                normalized_fact_count=normalized,
                failure_count=1,
            ),
        )
    candidate = latest[0]
    lhs = candidate.lhs
    rhs = candidate.rhs
    written_offset = candidate.register_offset
    written_size = candidate.register_size
    if not (
        written_offset <= requested_offset
        and requested_end <= written_offset + written_size
    ):
        return SameBlockRegisterProjectionResult8616(
            None,
            SameBlockRegisterProjectionVerdict8616.UNKNOWN_REFUSE,
            SameBlockRegisterProjectionStats8616(
                raw_fact_count=len(candidates),
                normalized_fact_count=1,
                failure_count=1,
            ),
        )
    source = (
        lhs
        if candidate.use_stored_value or any(
            isinstance(child, CFunctionCall)
            for child in _iter_c_nodes_deep_8616(rhs)
        )
        else rhs
    )
    if not isinstance(source, CExpression):
        return SameBlockRegisterProjectionResult8616(
            None,
            SameBlockRegisterProjectionVerdict8616.UNKNOWN_REFUSE,
            SameBlockRegisterProjectionStats8616(
                raw_fact_count=len(candidates),
                normalized_fact_count=1,
                classified_fact_count=1,
                failure_count=1,
            ),
        )
    expression: CExpression = source
    shift_bits = (requested_offset - written_offset) * 8
    if shift_bits:
        expression = CBinaryOp(
            "Shr",
            expression,
            CConstant(shift_bits, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
    if requested_size < written_size:
        expression = CBinaryOp(
            "And",
            expression,
            CConstant(
                (1 << (requested_size * 8)) - 1,
                SimTypeShort(False),
                codegen=codegen,
            ),
            codegen=codegen,
        )
    return SameBlockRegisterProjectionResult8616(
        expression,
        SameBlockRegisterProjectionVerdict8616.MATERIALIZED,
        SameBlockRegisterProjectionStats8616(
            raw_fact_count=len(candidates),
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
        ),
    )


def stable_stack_condition_binding_tags_8616(
    bp_offset: int,
    size: int,
    *,
    name: str | None = None,
) -> dict[str, object]:
    """Return exact stack-slot tags for one proven ConditionIR operand."""
    binding = StackVariableBinding(bp_offset, size, var_name=name)
    return {str(key): value for key, value in stable_stack_binding_tags_8616(binding).items()}


def condition_origin_tags_8616(condition: ConditionIR | IRCondition) -> dict[str, object]:
    """Return C-AST provenance tags for a typed branch condition."""
    tags: dict[str, object] = {"typed_condition": True}
    if not isinstance(condition, ConditionIR):
        return tags
    src_insn = condition.src_insn
    block_addr = condition.block_addr
    producer_insn = condition.producer_insn
    if isinstance(src_insn, int) and isinstance(block_addr, int):
        tags["ins_addr"] = src_insn
        tags["vex_block_addr"] = block_addr
    if isinstance(producer_insn, int):
        tags["condition_producer_insn"] = producer_insn
    return tags


def condition_segment_access_tags_8616(
    operand: IRValue,
    helper: str,
) -> dict[str, object]:
    """Return typed tags for a segment access already proven by ConditionIR."""
    if operand.space not in {MemSpace.DS, MemSpace.ES, MemSpace.SS}:
        raise ValueError("condition segment access requires a segmented IRValue")
    width = max(1, int(operand.memory_access_size or operand.size or 2))
    tags: dict[str, object] = {
        "inertia_x86_16_runtime_segment_helper": helper,
        SEGMENTED_LOAD_ADDRESS_TAG_8616: IRAddress(
            space=operand.space,
            offset=int(operand.offset) & 0xFFFF,
            size=width,
            status=AddressStatus.STABLE,
            segment_origin=SegmentOrigin.PROVEN,
        ),
    }
    if isinstance(operand.memory_access_insn, int):
        tags[_SOURCE_INSTRUCTION_ADDRS_TAG_8616] = (operand.memory_access_insn,)
    return tags


def _condition_segment_accesses_8616(
    value: object,
) -> tuple[IRValue, ...]:
    """Return segmented leaves carrying exact access provenance."""
    if isinstance(value, IRBinaryValue):
        return (
            *_condition_segment_accesses_8616(value.lhs),
            *_condition_segment_accesses_8616(value.rhs),
        )
    if (
        isinstance(value, IRValue)
        and value.space in {MemSpace.DS, MemSpace.ES, MemSpace.SS}
        and isinstance(value.memory_access_insn, int)
    ):
        return (value,)
    return ()


def attach_condition_segment_access_provenance_8616(
    expression: CExpression,
    condition: ConditionIR,
) -> int:
    """Carry exact operand access provenance onto matching segment helpers.

    The condition producer defines flags and is not necessarily a memory load.
    This boundary therefore matches typed operand addresses and refuses absent
    or ambiguous access evidence instead of borrowing CMP/JCC provenance.
    """
    from angr.analyses.decompiler.structured_codegen.c import CFunctionCall

    sources_by_access: dict[tuple[MemSpace, int, int], set[int]] = {}
    for operand in (
        *_condition_segment_accesses_8616(condition.lhs),
        *_condition_segment_accesses_8616(condition.rhs),
    ):
        key = (
            operand.space,
            int(operand.offset) & 0xFFFF,
            max(1, int(operand.memory_access_size or operand.size or 2)),
        )
        sources_by_access.setdefault(key, set()).add(cast(int, operand.memory_access_insn))

    tagged_count = 0
    for candidate in _iter_c_nodes_deep_8616(expression):
        if not isinstance(candidate, CFunctionCall):
            continue
        boundary = cast(Any, candidate)  # mutable tags are an angr C-AST boundary
        tags = boundary.tags
        identity = segmented_load_identity_8616(candidate)
        if not isinstance(tags, dict) or identity is None:
            continue
        sources = sources_by_access.get(
            (identity.space, identity.offset, identity.width),
            set(),
        )
        if len(sources) != 1:
            continue
        exact_sources = tuple(sorted(sources))
        if tags.get(_SOURCE_INSTRUCTION_ADDRS_TAG_8616) == exact_sources:
            continue
        updated_tags = dict(tags)
        updated_tags[_SOURCE_INSTRUCTION_ADDRS_TAG_8616] = exact_sources
        boundary.tags = updated_tags
        tagged_count += 1
    return tagged_count


def _ir_value_to_cvar_8616(
    value: IRValue,
    project: object,
    codegen: object,
    *,
    resolve_register_name: bool = False,
    signed: bool = False,
    condition_width_bits: int | None = None,
) -> object:
    """Convert an IRValue to a CVariable node for structured codegen."""
    from angr.analyses.decompiler.structured_codegen.c import CVariable
    from angr.sim_variable import SimRegisterVariable, SimStackVariable

    if value.space == MemSpace.CONST:
        return _make_c_constant_8616(int(value.const or 0), codegen)

    if value.space == MemSpace.REG:
        register_name = value.name if isinstance(value.name, str) else None
        try:
            cfunc = cast(_CodegenFunctionBoundary8616, codegen).cfunc
            function_region = cast(_CFunctionAddressBoundary8616, cfunc).addr
        except AttributeError:
            function_region = None
        if resolve_register_name:
            reg_offset, reg_size = _register_offset_size_for_value_8616(value, project)
        else:
            reg_offset, reg_size = int(value.offset), int(value.size or 2)
        var = SimRegisterVariable(
            reg_offset,
            reg_size,
            ident=f"inertia-register-{register_name}" if register_name else None,
            region=function_region if isinstance(function_region, int) else None,
            name=register_name,
        )
        return CVariable(variable=var, codegen=codegen)

    if value.space == MemSpace.SS:
        size = max(1, int(value.size or 2))
        if isinstance(condition_width_bits, int) and condition_width_bits > 0:
            condition_size = max(1, (condition_width_bits + 7) // 8)
            if size > condition_size:
                size = condition_size
        tags = condition_stack_operand_tags_8616(value, size)
        lowered = materialize_typed_condition_stack_operand_8616(
            codegen,
            base="bp",
            offset=int(value.offset),
            size=size,
            name=f"stack_{abs(int(value.offset)):x}",
            signed=signed,
            prefer_signed_local_storage=signed,
            tags=tags,
        )
        return lowered if lowered is not None else CVariable(
            variable=SimStackVariable(offset=value.offset, size=size, base="bp"),
            codegen=codegen,
            tags=tags,
        )

    # Fallback: unnamed register variable
    var = SimRegisterVariable(0, value.size or 2)
    return CVariable(variable=var, codegen=codegen)


def lower_typed_condition_to_c_expr_8616(
    recovered: object,  # RecoveredCondition
    project: object,
    codegen: object,
) -> object | None:
    """Convert a RecoveredCondition into a structured-codegen C expression node.

    Returns a CBinaryOp (for comparisons) or CUnaryOp (for Not) node, or None.
    """
    from ..semantics.condition_recovery import RecoveredCondition

    if not isinstance(recovered, RecoveredCondition):
        return None

    condition = recovered.condition
    return _lower_condition_ir_to_c_expr_8616(condition, project, codegen)


def _lowered_condition_arg_8616(
    condition: IRCondition,
    index: int,
    project: object,
    codegen: object,
) -> object:
    """Lower one IRValue operand using the condition's signedness and width."""
    return _ir_value_to_cvar_8616(
        condition.args[index],
        project,
        codegen,
        signed=condition.is_signed,
        condition_width_bits=condition.width_bits,
    )


def _lower_zero_test_8616(
    condition: IRCondition,
    angr_op: str,
    project: object,
    codegen: object,
) -> object | None:
    """Lower a zero/nonzero test to a comparison against constant zero."""
    from angr.analyses.decompiler.structured_codegen.c import CBinaryOp

    if not condition.args or not isinstance(condition.args[0], IRValue):
        return None
    lhs = _lowered_condition_arg_8616(condition, 0, project, codegen)
    zero = _make_c_constant_8616(0, codegen)
    return cast(object, CBinaryOp(
        angr_op, lhs, zero,
        codegen=codegen,
        tags=condition_origin_tags_8616(condition),
    ))


def _lower_compare_family_8616(
    condition: IRCondition,
    project: object,
    codegen: object,
) -> object | None:
    """Lower a typed compare-family condition to its angr binary operator."""
    from angr.analyses.decompiler.structured_codegen.c import CBinaryOp

    sym = condition_compare_symbol_8616(condition.op)
    if sym is None:
        return None
    lhs = _lowered_condition_arg_8616(condition, 0, project, codegen)
    rhs = _lowered_condition_arg_8616(condition, 1, project, codegen)
    # Map to angr structured-codegen CBinaryOp operator names
    angr_op = _condition_ir_op_to_angr_binary_op_8616(sym)
    if angr_op is None:
        return None
    return cast(object, CBinaryOp(
        angr_op, lhs, rhs,
        codegen=codegen,
        tags=condition_origin_tags_8616(condition),
    ))


def _lower_not_8616(
    condition: IRCondition,
    project: object,
    codegen: object,
) -> object | None:
    """Lower a not condition wrapping a nested IRCondition."""
    from angr.analyses.decompiler.structured_codegen.c import CUnaryOp

    inner = condition.args[0]
    if isinstance(inner, IRCondition):
        inner_expr = _lower_condition_ir_to_c_expr_8616(inner, project, codegen)
        if inner_expr is not None:
            return cast(object, CUnaryOp(
                "Not",
                cast("CExpression", inner_expr),
                codegen=codegen,
                tags=condition_origin_tags_8616(condition),
            ))
    return None


def _lower_generic_compare_8616(
    condition: IRCondition,
    project: object,
    codegen: object,
) -> object | None:
    """Lower a generic compare as a nonzero difference test."""
    from angr.analyses.decompiler.structured_codegen.c import CBinaryOp

    lhs = _lowered_condition_arg_8616(condition, 0, project, codegen)
    rhs = _lowered_condition_arg_8616(condition, 1, project, codegen)
    return cast(object, CBinaryOp(
        "CmpNE", lhs, rhs,
        codegen=codegen,
        tags=condition_origin_tags_8616(condition),
    ))


def _binary_ir_operands_8616(condition: IRCondition) -> bool:
    """Check that the condition carries two IRValue operands."""
    return (
        len(condition.args) >= 2
        and isinstance(condition.args[0], IRValue)
        and isinstance(condition.args[1], IRValue)
    )


def _lower_condition_ir_to_c_expr_8616(
    condition: IRCondition,
    project: object,
    codegen: object,
) -> object | None:
    """Lower a typed IRCondition to a structured-codegen C expression."""
    op = condition.op

    # Zero/nonzero tests
    if op == "zero":
        return _lower_zero_test_8616(condition, "CmpEQ", project, codegen)
    if op == "nonzero":
        return _lower_zero_test_8616(condition, "CmpNE", project, codegen)

    # Binary comparisons
    if is_condition_compare_family_8616(op) and _binary_ir_operands_8616(condition):
        return _lower_compare_family_8616(condition, project, codegen)

    # Not
    if op == "not" and len(condition.args) >= 1:
        return _lower_not_8616(condition, project, codegen)

    # Compare (generic)
    if op == "compare" and _binary_ir_operands_8616(condition):
        return _lower_generic_compare_8616(condition, project, codegen)

    return None


def condition_op_to_structured_kind_8616(op: str) -> str:
    """Map a ConditionOp to the kind string used in structured-codegen node kinds."""
    if op == "zero":
        return "CmpEQ"
    if op == "nonzero":
        return "CmpNE"
    if op in {"eq", "ne"}:
        return f"Cmp{op.upper()}"
    if op in {"slt", "ult"}:
        return "CmpLT"
    if op in {"sgt", "ugt"}:
        return "CmpGT"
    if op in {"sle", "ule"}:
        return "CmpLE"
    if op in {"sge", "uge"}:
        return "CmpGE"
    return "CmpNE"


_ANGr_BINARY_OP_MAP_8616: dict[str, str] = {
    "==": "CmpEQ",
    "!=": "CmpNE",
    "<": "CmpLT",
    ">": "CmpGT",
    "<=": "CmpLE",
    ">=": "CmpGE",
}


def _condition_ir_op_to_angr_binary_op_8616(symbol: str) -> str | None:
    """Map a condition op symbol ('==', '!=' etc.) to angr CBinaryOp operator name."""
    return _ANGr_BINARY_OP_MAP_8616.get(symbol)
