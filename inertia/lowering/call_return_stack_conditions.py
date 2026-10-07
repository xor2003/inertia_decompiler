"""Classify exact zero tests of call returns stored in stack objects.

Layer: Types/Lowering.
Responsibility: join one typed branch fact to one exact call-return stack-store
contract for downstream Structuring and Validation consumers.
Consumes alias, widening, and typed facts. Performs no AST mutation.
Do not recover semantics from COD, source, assembly, or rendered C text.
Ambiguous or incomplete inventories are explicit refusals.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from inertia.semantics.callsite_summary import CallsiteSummary8616, callsite_summary_inventory_8616
from archinfo import Arch

from inertia.ir.condition_ir import ConditionIR, ConditionRegisterBindingIR
from inertia.ir.core import IRValue, MemSpace

from .call_return_stack_stores import (
    CallReturnStackStoreEvidence8616,
    classify_call_return_stack_store_8616,
)

__all__ = [
    "StoredCallReturnConditionEvidence8616",
    "StoredCallReturnConditionKind8616",
    "classify_stored_call_return_condition_8616",
]


class StoredCallReturnConditionKind8616(StrEnum):
    """Exact zero-test relation applied to the return register."""

    ZERO = "zero"
    NONZERO = "nonzero"


@dataclass(frozen=True, slots=True)
class StoredCallReturnConditionEvidence8616:
    """One exact typed condition and its call-return stack storage."""

    kind: StoredCallReturnConditionKind8616
    condition: ConditionIR
    stack_store: CallReturnStackStoreEvidence8616


class _StoredReturnProject8616(Protocol):
    """Project surface required to resolve exact register storage."""

    arch: Arch


class _StoredReturnCodegen8616(Protocol):
    """Owned typed condition evidence consumed by the classifier."""

    _inertia_typed_conditions: object


def _is_exact_register_8616(value: object, register: tuple[int, int]) -> bool:
    """Return whether an IR value is the exact register slice."""
    return (
        isinstance(value, IRValue)
        and value.space is MemSpace.REG
        and int(value.offset) == register[0]
        and int(value.size or register[1]) == register[1]
    )


def _is_zero_constant_8616(value: object) -> bool:
    """Return whether an IR value is the exact integer zero."""
    return isinstance(value, IRValue) and value.space is MemSpace.CONST and value.const == 0


def _canonical_stack_offset_8616(offset: int) -> int:
    """Normalize one 16-bit BP displacement to its signed identity."""
    normalized = offset & 0xFFFF
    return normalized - 0x10000 if normalized >= 0x8000 else normalized


def _is_exact_return_storage_8616(
    value: object,
    register: tuple[int, int],
    store: CallReturnStackStoreEvidence8616,
    register_bindings: tuple[ConditionRegisterBindingIR, ...],
) -> bool:
    """Match either the return register or its exact projected stack store."""
    if _is_exact_register_8616(value, register):
        return True
    stack_matches = (
        isinstance(value, IRValue)
        and value.space is MemSpace.SS
        and value.name == "bp"
        and isinstance(value.offset, int)
        and _canonical_stack_offset_8616(value.offset) == _canonical_stack_offset_8616(store.dst_offset)
        and int(value.size or store.width) == store.width
    )
    if not stack_matches:
        return False
    bindings = tuple(
        binding
        for binding in register_bindings
        if binding.register_name == store.source_register_name
        and binding.value == value
    )
    return len(bindings) == 1


def _condition_kind_8616(
    condition: ConditionIR,
    register: tuple[int, int],
    store: CallReturnStackStoreEvidence8616,
) -> StoredCallReturnConditionKind8616 | None:
    """Classify a zero test of the return register or its exact stack store."""
    if condition.width_bits != register[1] * 8:
        return None
    if condition.op in {"zero", "nonzero"}:
        if not _is_exact_return_storage_8616(
            condition.lhs,
            register,
            store,
            condition.register_bindings,
        ):
            return None
        if condition.rhs is not None and not _is_zero_constant_8616(condition.rhs):
            return None
        return (
            StoredCallReturnConditionKind8616.ZERO
            if condition.op == "zero"
            else StoredCallReturnConditionKind8616.NONZERO
        )
    if condition.op not in {"eq", "ne"}:
        return None
    operands = ((condition.lhs, condition.rhs), (condition.rhs, condition.lhs))
    if not any(
        _is_exact_return_storage_8616(
            lhs,
            register,
            store,
            condition.register_bindings,
        )
        and _is_zero_constant_8616(rhs)
        for lhs, rhs in operands
    ):
        return None
    return (
        StoredCallReturnConditionKind8616.ZERO
        if condition.op == "eq"
        else StoredCallReturnConditionKind8616.NONZERO
    )


def classify_stored_call_return_condition_8616(
    project: object,
    codegen: object | None,
    *,
    jcc_addr: int,
    block_addr: int,
) -> StoredCallReturnConditionEvidence8616 | None:
    """Join one exact condition to one exact value-return stack store."""
    if codegen is None:
        return None
    typed_codegen = cast(_StoredReturnCodegen8616, codegen)
    try:
        raw_conditions = typed_codegen._inertia_typed_conditions
    except AttributeError:
        return None
    if not isinstance(raw_conditions, (tuple, list)):
        raise TypeError("typed condition inventory must be a tuple or list")
    conditions = tuple(
        condition
        for condition in raw_conditions
        if isinstance(condition, ConditionIR)
        and condition.src_insn == jcc_addr
        and condition.block_addr == block_addr
    )
    if len(conditions) != 1:
        return None
    stores = tuple(
        evidence
        for summary in callsite_summary_inventory_8616(codegen).values()
        if isinstance(summary, CallsiteSummary8616)
        and summary.return_addr == block_addr
        and (evidence := classify_call_return_stack_store_8616(summary)) is not None
    )
    if len(stores) != 1:
        return None
    typed_project = cast(_StoredReturnProject8616, project)
    register = typed_project.arch.registers.get(stores[0].source_register_name)
    if register is None or int(register[1]) != stores[0].width:
        return None
    kind = _condition_kind_8616(
        conditions[0],
        (int(register[0]), int(register[1])),
        stores[0],
    )
    if kind is None:
        return None
    return StoredCallReturnConditionEvidence8616(
        kind=kind,
        condition=conditions[0],
        stack_store=stores[0],
    )
