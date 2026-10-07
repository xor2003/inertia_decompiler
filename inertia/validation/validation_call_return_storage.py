"""Project stored call-return conditions into tail-validation identities.

Layer: Tail Validation.
Responsibility: canonicalize existing typed condition and call-return stack
storage evidence for before/after comparison.
Forbidden: semantic recovery, AST mutation, source/COD/assembly inspection, or
acceptance of incomplete and ambiguous evidence.

Package ownership contract (canonical inertia/validation package):
Layer: Validation.
Owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CUnaryOp,
    CVariable,
)
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from inertia.semantics.callsite_summary import (
    CallsiteReturnUseKind8616,
    CallsiteSummary8616,
    structured_callsite_addr_8616,
)
from archinfo import Arch

from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import IRValue, MemSpace
from inertia.lowering.call_return_stack_conditions import (
    StoredCallReturnConditionEvidence8616,
    StoredCallReturnConditionKind8616,
    classify_stored_call_return_condition_8616,
)

__all__ = [
    "DirectCallReturnConditionProjection8616",
    "StoredCallReturnComparison8616",
    "StoredCallReturnConditionKind8616",
    "StoredCallReturnConditionProjection8616",
    "direct_call_return_condition_projection_8616",
    "stored_call_return_condition_projection_8616",
]


class StoredCallReturnComparison8616(StrEnum):
    """Structured comparison orientation preserved by Validation."""

    EQUAL_ZERO = "CmpEQ"
    NOT_EQUAL_ZERO = "CmpNE"


class _StoredReturnProject8616(Protocol):
    """Project surface required to verify a physical register view."""

    arch: Arch


class _DirectReturnCodegen8616(Protocol):
    """Owned typed call and condition evidence consumed by Validation."""

    _inertia_typed_conditions: object
    _inertia_callsite_summary_inventory_8616: dict[int, CallsiteSummary8616]
    _inertia_callsite_summaries: dict[int, CallsiteSummary8616]


@dataclass(frozen=True, slots=True)
class DirectCallReturnConditionProjection8616:
    """Validation identity for one exact direct-call return predicate."""

    comparison: StoredCallReturnComparison8616
    jcc_addr: int
    block_addr: int
    callsite_addr: int
    target_addr: int

    @property
    def call_identity(self) -> str:
        """Return the exact machine callsite and canonical target identity."""
        return f"callsite:{self.callsite_addr:#x}:addr:{self.target_addr:#x}"

    @property
    def fingerprint(self) -> str:
        """Return the canonical direct-call zero-test fingerprint."""
        return f"{self.comparison.value}({self.call_identity},const:0)"


@dataclass(frozen=True, slots=True)
class StoredCallReturnConditionProjection8616:
    """Validation identity derived from one exact typed storage transfer."""

    kind: StoredCallReturnConditionKind8616
    comparison: StoredCallReturnComparison8616
    jcc_addr: int
    block_addr: int
    stack_offset: int
    width: int

    @property
    def stack_location(self) -> str:
        """Return the canonical segmented stack identity."""
        sign = "+" if self.stack_offset >= 0 else "-"
        return f"stack_slot:SS:BP{sign}0x{abs(self.stack_offset):x}:size{self.width}"

    @property
    def fingerprint(self) -> str:
        """Return the canonical zero-test fingerprint."""
        return f"{self.comparison.value}({self.stack_location},const:0)"


def _canonical_stack_offset_8616(offset: int) -> int:
    """Normalize one 16-bit BP displacement to its signed identity."""
    normalized = offset & 0xFFFF
    return normalized - 0x10000 if normalized >= 0x8000 else normalized


def _direct_return_summary_8616(
    codegen: _DirectReturnCodegen8616,
    *,
    block_addr: int,
) -> CallsiteSummary8616 | None:
    """Return the unique exact callsite whose return reaches one branch block."""
    inventory = codegen._inertia_callsite_summary_inventory_8616
    if not isinstance(inventory, dict):
        raise TypeError("callsite summary inventory must be a dict")
    matches = tuple(
        summary
        for summary in inventory.values()
        if isinstance(summary, CallsiteSummary8616)
        and summary.return_addr == block_addr
        and summary.return_used is True
        and summary.return_use_kind is CallsiteReturnUseKind8616.CONDITION
        and isinstance(summary.target_addr, int)
        and isinstance(summary.return_register, str)
    )
    return matches[0] if len(matches) == 1 else None


def _direct_return_fact_8616(
    project: _StoredReturnProject8616,
    codegen: _DirectReturnCodegen8616,
    summary: CallsiteSummary8616,
    *,
    jcc_addr: int,
    block_addr: int,
) -> ConditionIR | None:
    """Return the unique typed zero test of one exact call return register."""
    conditions = codegen._inertia_typed_conditions
    if not isinstance(conditions, (list, tuple)):
        return None
    matches = tuple(
        condition
        for condition in conditions
        if isinstance(condition, ConditionIR)
        and condition.src_insn == jcc_addr
        and condition.block_addr == block_addr
    )
    if len(matches) != 1 or summary.return_register is None:
        return None
    condition = matches[0]
    register = project.arch.registers.get(summary.return_register.lower())
    if register is None or condition.op not in {"eq", "ne", "zero", "nonzero"}:
        return None

    def _is_return_register(value: object) -> bool:
        return (
            isinstance(value, IRValue)
            and value.space is MemSpace.REG
            and (int(value.offset), int(value.size or register[1]))
            == (int(register[0]), int(register[1]))
        )

    def _is_zero(value: object) -> bool:
        return isinstance(value, IRValue) and value.space is MemSpace.CONST and value.const == 0

    if condition.op in {"zero", "nonzero"}:
        return condition if _is_return_register(condition.lhs) else None
    return condition if (
        (_is_return_register(condition.lhs) and _is_zero(condition.rhs))
        or (_is_zero(condition.lhs) and _is_return_register(condition.rhs))
    ) else None


def _direct_structured_comparison_8616(
    project: _StoredReturnProject8616,
    codegen: _DirectReturnCodegen8616,
    condition: object,
    summary: CallsiteSummary8616,
) -> StoredCallReturnComparison8616 | None:
    """Validate and preserve one structured direct-call zero-test orientation."""
    node = condition
    inverted = False
    while isinstance(node, CUnaryOp) and node.op == "Not":
        inverted = not inverted
        node = node.operand
    if not isinstance(node, CBinaryOp) or node.op not in {"CmpEQ", "CmpNE"}:
        return None
    zeroes = tuple(
        operand
        for operand in (node.lhs, node.rhs)
        if isinstance(operand, CConstant) and operand.value == 0
    )
    values = tuple(operand for operand in (node.lhs, node.rhs) if operand not in zeroes)
    if len(zeroes) != 1 or len(values) != 1 or summary.return_register is None:
        return None
    value = values[0]
    storage_matches = False
    if isinstance(value, CVariable) and isinstance(value.variable, SimRegisterVariable):
        register = project.arch.registers.get(summary.return_register.lower())
        storage_matches = register is not None and (
            int(value.variable.reg),
            int(value.variable.size),
        ) == (int(register[0]), int(register[1]))
    elif isinstance(value, CFunctionCall):
        summaries = codegen._inertia_callsite_summaries
        if not isinstance(summaries, dict):
            raise TypeError("structured callsite summary map must be a dict")
        bound_summary = summaries.get(id(value))
        storage_matches = (
            bound_summary == summary
            and structured_callsite_addr_8616(value) == summary.callsite_addr
        )
    if not storage_matches:
        return None
    equal = node.op == "CmpEQ"
    if inverted:
        equal = not equal
    return (
        StoredCallReturnComparison8616.EQUAL_ZERO
        if equal
        else StoredCallReturnComparison8616.NOT_EQUAL_ZERO
    )


def direct_call_return_condition_projection_8616(
    project: object,
    codegen: object | None,
    *,
    jcc_addr: int,
    block_addr: int,
    structured_condition: object,
) -> DirectCallReturnConditionProjection8616 | None:
    """Project one proven direct-call return condition for validation.

    The projection deliberately identifies the call by machine callsite and
    callee rather than by rendered arguments. Argument values and classes are
    validated by their separate exact-callsite contracts.
    """
    if codegen is None:
        return None
    typed_project = cast(_StoredReturnProject8616, project)
    typed_codegen = cast(_DirectReturnCodegen8616, codegen)
    try:
        summary = _direct_return_summary_8616(typed_codegen, block_addr=block_addr)
    except AttributeError:
        return None
    if summary is None:
        return None
    fact = _direct_return_fact_8616(
        typed_project,
        typed_codegen,
        summary,
        jcc_addr=jcc_addr,
        block_addr=block_addr,
    )
    if fact is None:
        return None
    comparison = _direct_structured_comparison_8616(
        typed_project,
        typed_codegen,
        structured_condition,
        summary,
    )
    if comparison is None or summary.target_addr is None:
        return None
    return DirectCallReturnConditionProjection8616(
        comparison=comparison,
        jcc_addr=jcc_addr,
        block_addr=block_addr,
        callsite_addr=summary.callsite_addr,
        target_addr=summary.target_addr,
    )


def _structured_comparison_8616(
    project: object,
    condition: object,
    evidence: StoredCallReturnConditionEvidence8616,
) -> StoredCallReturnComparison8616 | None:
    """Preserve an exact structured zero-test orientation over proven storage."""
    node = condition
    inverted = False
    while isinstance(node, CUnaryOp) and node.op == "Not":
        inverted = not inverted
        node = node.operand
    if not isinstance(node, CBinaryOp) or node.op not in {"CmpEQ", "CmpNE"}:
        return None
    constants = tuple(
        operand
        for operand in (node.lhs, node.rhs)
        if isinstance(operand, CConstant) and operand.value == 0
    )
    variables = tuple(
        operand
        for operand in (node.lhs, node.rhs)
        if isinstance(operand, CVariable)
    )
    if len(constants) != 1 or len(variables) != 1:
        return None
    variable = variables[0].variable
    store = evidence.stack_store
    storage_matches = (
        isinstance(variable, SimStackVariable)
        and variable.base == "bp"
        and isinstance(variable.offset, int)
        and _canonical_stack_offset_8616(variable.offset) == _canonical_stack_offset_8616(store.dst_offset)
        and int(variable.size) == store.width
    )
    if isinstance(variable, SimRegisterVariable):
        register = cast(_StoredReturnProject8616, project).arch.registers.get(store.source_register_name)
        storage_matches = (
            register is not None
            and int(variable.reg) == int(register[0])
            and int(variable.size) == int(register[1]) == store.width
        )
    if not storage_matches:
        return None
    equal = node.op == "CmpEQ"
    if inverted:
        equal = not equal
    return (
        StoredCallReturnComparison8616.EQUAL_ZERO
        if equal
        else StoredCallReturnComparison8616.NOT_EQUAL_ZERO
    )


def stored_call_return_condition_projection_8616(
    project: object,
    codegen: object | None,
    *,
    jcc_addr: int,
    block_addr: int,
    structured_condition: object | None = None,
) -> StoredCallReturnConditionProjection8616 | None:
    """Project one proven call-return stack condition for validation.

    The callsite summary and typed branch fact are authoritative upstream
    evidence. Validation only joins their exact machine identities so a stale
    structured register carrier cannot resolve through a later assignment.
    """
    evidence = classify_stored_call_return_condition_8616(
        project,
        codegen,
        jcc_addr=jcc_addr,
        block_addr=block_addr,
    )
    if evidence is None:
        return None
    comparison = (
        _structured_comparison_8616(project, structured_condition, evidence)
        if structured_condition is not None
        else None
    )
    if structured_condition is not None and comparison is None:
        return None
    if comparison is None:
        comparison = (
            StoredCallReturnComparison8616.EQUAL_ZERO
            if evidence.kind is StoredCallReturnConditionKind8616.ZERO
            else StoredCallReturnComparison8616.NOT_EQUAL_ZERO
        )
    return StoredCallReturnConditionProjection8616(
        kind=evidence.kind,
        comparison=comparison,
        jcc_addr=jcc_addr,
        block_addr=block_addr,
        stack_offset=_canonical_stack_offset_8616(evidence.stack_store.dst_offset),
        width=evidence.stack_store.width,
    )
