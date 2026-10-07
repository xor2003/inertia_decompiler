"""Recognize syntax projections of one stack word from two byte views.

Layer: Types/Lowering.
Responsibility: expose a typed C-AST shape for ``low | (high << 8)`` without
assigning storage identity. Alias-backed consumers must independently prove
that both views belong to one exact word before replacing the expression.
Do not infer semantics from names, rendered C, assembly, COD, or source text.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen import c as structured_c

from .runtime_memory_helpers import (
    SegmentedMemoryReadHelper8616,
    segmented_memory_read_helper_8616,
)

type StackWordByteOperand8616 = (
    structured_c.CVariable | structured_c.CUnaryOp | structured_c.CFunctionCall
)


@dataclass(frozen=True, slots=True)
class StackWordRecomposition8616:
    """One syntax-only low/high byte recomposition candidate."""

    low: StackWordByteOperand8616
    high: StackWordByteOperand8616


def _strip_casts_8616(node: object) -> object:
    """Remove syntax-only casts around one byte projection."""
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    return node


def _constant_value_8616(node: object) -> int | None:
    """Return the integer carried by one exact C constant."""
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CConstant) and isinstance(node.value, int):
        return node.value
    return None


def _masked_operand_8616(node: object) -> object:
    """Remove one exact low-byte mask from a projection operand."""
    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "And":
        return node
    if _constant_value_8616(node.lhs) == 0xFF:
        return _strip_casts_8616(node.rhs)
    if _constant_value_8616(node.rhs) == 0xFF:
        return _strip_casts_8616(node.lhs)
    return node


def _byte_operand_8616(node: object) -> StackWordByteOperand8616 | None:
    """Return one typed byte variable, dereference, or segmented read."""
    candidate = _masked_operand_8616(node)
    if isinstance(candidate, structured_c.CVariable):
        return candidate
    if isinstance(candidate, structured_c.CUnaryOp) and candidate.op == "Dereference":
        return candidate
    if (
        isinstance(candidate, structured_c.CFunctionCall)
        and segmented_memory_read_helper_8616(candidate)
        is SegmentedMemoryReadHelper8616.SEG_U8
    ):
        return candidate
    return None


def _high_operand_8616(node: object) -> StackWordByteOperand8616 | None:
    """Return a byte variable or dereference shifted into the high byte."""
    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CBinaryOp):
        return None
    operand: object | None = None
    if node.op == "Shl" and _constant_value_8616(node.rhs) == 8:
        operand = node.lhs
    elif node.op == "Mul":
        if _constant_value_8616(node.lhs) == 0x100:
            operand = node.rhs
        elif _constant_value_8616(node.rhs) == 0x100:
            operand = node.lhs
    return _byte_operand_8616(operand) if operand is not None else None


def recognize_stack_word_recomposition_8616(
    node: object,
) -> StackWordRecomposition8616 | None:
    """Return one low/high candidate without assigning semantic ownership."""
    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "Or":
        return None
    for low_node, high_node in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        low = _byte_operand_8616(low_node)
        high = _high_operand_8616(high_node)
        if low is not None and high is not None:
            return StackWordRecomposition8616(low, high)
    return None


__all__ = [
    "StackWordByteOperand8616",
    "StackWordRecomposition8616",
    "recognize_stack_word_recomposition_8616",
]
