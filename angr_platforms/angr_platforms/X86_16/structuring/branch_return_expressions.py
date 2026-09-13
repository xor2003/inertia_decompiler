"""Materialize branch-leaf return expressions from typed semantic effects.

Layer: Structuring.
Responsibility: bind a structured return body to CFG branch leaves whose
typed return effects materialize the same C expression.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.

Instruction decoding stays behind the existing semantic return-effect
classifier. This module only adapts those effects to active typed stack objects
and refuses leaves whose return expression cannot be proved.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CExpression,
    CReturn,
    CStatements,
)
from angr.sim_type import SimTypeLong, SimTypeShort

from ..c_ast_utils import _same_c_expression_8616
from ..ir.condition_ir import ConditionIR
from ..ir.core import IRValue, MemSpace
from .condition_lowering import lower_ir_value_to_c_expr_8616
from .return_chains import (
    BranchTargetReturnBlockResult8616,
    BranchTargetReturnScanCallbacks8616,
    branch_target_return_expr_8616,
    scan_branch_target_return_block_8616,
)
from .return_path_preservation import branch_target_imm_8616 as branch_target_imm_8616
from .return_path_preservation import return_path_preserves_return_registers_8616


class _BlockFactory8616(Protocol):
    """Dynamic angr block-factory boundary used by branch-leaf scanning."""

    def block(self, addr: int, *, opt_level: int = 0) -> object:
        """Return a decoded block beginning at one CFG address."""


class _Project8616(Protocol):
    """Dynamic angr project boundary used by branch-leaf scanning."""

    factory: _BlockFactory8616


@dataclass(frozen=True, slots=True)
class _StackReturnSlice8616:
    """Keep one typed BP-relative return slice until DX:AX is combined."""

    offset: int
    size: int


def _signed_i16_8616(value: int) -> int:
    """Normalize one decoded immediate to its signed 16-bit value."""
    normalized = value & 0xFFFF
    return normalized - 0x10000 if normalized & 0x8000 else normalized


def branch_target_preserves_return_registers_8616(
    project: object,
    target_addr: int,
    *,
    max_depth: int = 4,
) -> bool:
    """Prove a bounded jump path reaches return without changing AX or DX."""
    typed_project = cast(_Project8616, project)
    return return_path_preserves_return_registers_8616(
        int(target_addr),
        lambda addr: typed_project.factory.block(addr, opt_level=0),
        max_depth=max_depth,
    )


def _stack_ir_value_8616(value: _StackReturnSlice8616, *, size: int | None = None) -> IRValue:
    """Build one typed stack value from a classified return slice."""
    return IRValue(
        space=MemSpace.SS,
        name="bp",
        offset=value.offset,
        size=value.size if size is None else size,
    )


def recover_branch_target_return_expression_8616(
    project: object,
    codegen: object,
    target_addr: int,
) -> CExpression | None:
    """Recover one CFG leaf return expression from classified semantic effects."""
    typed_project = cast(_Project8616, project)

    def _lower_stack(value: _StackReturnSlice8616, *, size: int | None = None) -> CExpression | None:
        lowered = lower_ir_value_to_c_expr_8616(
            _stack_ir_value_8616(value, size=size), project, codegen
        )
        return lowered if isinstance(lowered, CExpression) else None

    def _combine(ax_value: object | None, dx_value: object | None) -> CExpression | None:
        if isinstance(ax_value, _StackReturnSlice8616):
            if dx_value is None:
                return _lower_stack(ax_value)
            if (
                isinstance(dx_value, _StackReturnSlice8616)
                and dx_value.offset == ax_value.offset + 2
            ):
                return _lower_stack(ax_value, size=4)
            return None
        if not isinstance(ax_value, CExpression):
            return None
        if dx_value is None:
            return ax_value
        if isinstance(ax_value, CConstant) and isinstance(dx_value, CConstant):
            combined = ((int(dx_value.value or 0) & 0xFFFF) << 16) | (
                int(ax_value.value or 0) & 0xFFFF
            )
            if combined & 0x80000000:
                combined -= 0x100000000
            return CConstant(combined, SimTypeLong(True), codegen=codegen)
        return None

    def _reg_imm(value: int) -> CExpression:
        return CConstant(_signed_i16_8616(value), SimTypeShort(True), codegen=codegen)

    def _stack_load(offset: int, size: int) -> _StackReturnSlice8616:
        return _StackReturnSlice8616(offset, size)

    def _ax_alu_imm(ax_value: object, op: str, value: int) -> CExpression | None:
        expression = _combine(ax_value, None)
        if expression is None:
            return None
        immediate = CConstant(_signed_i16_8616(value), SimTypeShort(False), codegen=codegen)
        return CBinaryOp(op, expression, immediate, codegen=codegen)

    def _ax_incdec(ax_value: object, op: str) -> CExpression | None:
        expression = _combine(ax_value, None)
        if expression is None:
            return None
        return CBinaryOp(op, expression, CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen)

    callbacks = BranchTargetReturnScanCallbacks8616(
        branch_target_imm=branch_target_imm_8616,
        combine_return_expr=_combine,
        materialize_reg_imm=_reg_imm,
        materialize_stack_load=_stack_load,
        materialize_direct_global_load=lambda _offset, _size: None,
        materialize_ax_alu_imm=_ax_alu_imm,
        materialize_ax_incdec=_ax_incdec,
    )

    def _load_block(addr: int) -> object:
        return typed_project.factory.block(addr, opt_level=0)

    def _scan_block(block: object) -> BranchTargetReturnBlockResult8616:
        return scan_branch_target_return_block_8616(block, callbacks)

    result = branch_target_return_expr_8616(target_addr, _load_block, _scan_block)
    return result if isinstance(result, CExpression) else None


def sole_return_expression_8616(body: object) -> CExpression | None:
    """Return the expression from one body containing exactly one return."""
    statement = sole_return_statement_8616(body)
    return statement.retval if statement is not None and isinstance(statement.retval, CExpression) else None


def binary_return_arm_polarity_8616(
    condition: ConditionIR,
    true_body: object,
    false_body: object,
    recover: Callable[[int], CExpression | None],
) -> bool | None:
    """Orient sole-return arms by distinct binary-proven successor values.

    Cloned shared epilogues have the same statement origin. Their return values
    may distinguish the paths, but only when both complete binary paths agree.
    """
    true_value = sole_return_expression_8616(true_body)
    false_value = sole_return_expression_8616(false_body)
    if true_value is None or false_value is None:
        return None
    taken, fallthrough = condition.taken_target, condition.fallthrough_target
    if taken is None or fallthrough is None or taken == fallthrough:
        return None
    taken_value, fallthrough_value = recover(taken), recover(fallthrough)
    if taken_value is None or fallthrough_value is None:
        return None
    if _same_c_expression_8616(taken_value, fallthrough_value):
        return None
    direct = _same_c_expression_8616(true_value, taken_value) and _same_c_expression_8616(false_value, fallthrough_value)
    inverse = _same_c_expression_8616(true_value, fallthrough_value) and _same_c_expression_8616(false_value, taken_value)
    return direct if direct != inverse else None


def sole_return_statement_8616(body: object) -> CReturn | None:
    """Return one body-owned return statement, including an empty placeholder."""
    current = body
    for _depth in range(8):
        if isinstance(current, CReturn):
            return current
        if not isinstance(current, CStatements):
            return None
        statements = tuple(current.statements or ())
        if len(statements) != 1:
            return None
        current = statements[0]
    return None
