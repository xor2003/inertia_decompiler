"""Typed scalar projection adapter: conversion truth for typed IR value reads.

Layer: IR.
Responsibility: own the single typed decision over scalar operand decorations —
whether a read is an identity pass-through, an earned re-decoration of its
producer, or an explicit integer conversion with declared source/target bits
and signedness — plus the backend operation-name and conversion decoding
tables. This adapter describes operations only; lane arithmetic stays in
``constant_flow`` so no consumer copies a second conversion truth.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .core import IRInstr, IRValue, MemSpace


class ScalarBinaryKind8616(StrEnum):
    """Generic pure bitvector operation kind; consumers never see backend names."""

    ADD = "Add"
    SUB = "Sub"
    AND = "And"
    OR = "Or"
    XOR = "Xor"
    SHL = "Shl"
    SHR = "Shr"


_SUPPORTED_BITS_8616 = frozenset({1, 8, 16, 32, 64})

_SCALAR_BINARY_OPS_8616: dict[str, tuple[ScalarBinaryKind8616, int]] = {
    f"Iop_{kind}{bits}": (kind, bits)
    for kind in ScalarBinaryKind8616 for bits in (8, 16, 32, 64)
}
_SCALAR_CONVERSIONS_8616: dict[str, tuple[int, int, bool]] = {
    f"Iop_{source}{sign}to{target}": (source, target, sign == "S")
    for source in (1, 8, 16, 32, 64) for target in (1, 8, 16, 32, 64)
    for sign in (("U", "S") if source < target else ("",)) if source != target
}


class ScalarProjectionKind8616(StrEnum):
    """How one typed scalar read relates to its producer definition."""

    IDENTITY = "identity"
    EARNED_REDECORATION = "earned_redecoration"
    CONVERSION = "conversion"


@dataclass(frozen=True, slots=True)
class ScalarProjection8616:
    """Pure projection decision for one scalar read of a produced definition.

    ``IDENTITY`` and ``EARNED_REDECORATION`` pass the producer value through
    unchanged; ``CONVERSION`` declares an exact integer conversion from
    ``source_bits`` to ``target_bits`` with ``signed`` extension semantics.
    ``target_bits`` always equals the read width: no implicit widening or
    truncation is manufactured here.
    """

    kind: ScalarProjectionKind8616
    source_bits: int
    target_bits: int
    signed: bool = False


@dataclass(frozen=True, slots=True)
class ScalarBinaryOp8616:
    """One registered pure bitvector operation decoded for consumers."""

    kind: ScalarBinaryKind8616
    bits: int


def scalar_active_unary_projection_8616(
    value: IRValue, *, proven_operand_bits: int | None = None,
) -> ScalarProjection8616 | None:
    """Authenticate a pending unary conversion without changing its operand identity.

    Captured references already name computed results and cannot carry a pending
    operation. The declaration must agree with both operand and result widths;
    compatibility decorations may corroborate it but never supply lineage.
    A caller may supply ``proven_operand_bits`` only from an exact reaching
    producer's authoritative result width; byte storage alone cannot prove a
    captured one-bit result.
    """
    unary = value.active_unary
    if unary is None or value.source_tmp is not None:
        return None
    if value.size != (unary.result_bits + 7) // 8:
        return None
    if value.expr is not None and value.expr != (unary.op,):
        return None
    operand = unary.operand
    operand_bits = operand.size * 8 if operand.active_unary is None else operand.active_unary.result_bits
    if proven_operand_bits is not None:
        if operand.active_unary is not None and operand_bits != proven_operand_bits:
            return None
        operand_bits = proven_operand_bits
    if operand.size != (operand_bits + 7) // 8:
        return None
    decision = scalar_read_projection_8616(
        read_expr=(unary.op,),
        read_bits=unary.result_bits,
        produced=(),
        produced_bits=operand_bits,
    )
    if decision is None or decision.kind is not ScalarProjectionKind8616.CONVERSION:
        return None
    return decision


def scalar_binary_operation_8616(op: str) -> ScalarBinaryOp8616 | None:
    """Decode one backend operation name into typed kind/bits, or refuse."""
    decoded = _SCALAR_BINARY_OPS_8616.get(op)
    if decoded is None:
        return None
    return ScalarBinaryOp8616(kind=decoded[0], bits=decoded[1])


def scalar_produced_decoration_8616(instruction: IRInstr) -> tuple[str, ...]:
    """Return the exact producing decoration one instruction earns.

    MOV copies its source decoration; supported operations carry their own
    label; register+register Add also retains both operand names; LOAD retains
    its memory label. These labels validate later re-decoration, never compute
    a value or establish producer lineage.
    """
    args = instruction.args
    if instruction.op == "MOV" and len(args) == 1 and isinstance(args[0], IRValue):
        return args[0].expr or ()
    if instruction.op == "LOAD":
        return ("load",)
    operation = scalar_binary_operation_8616(instruction.op)
    if operation is not None and len(args) == 2:
        left, right = args
        if operation.kind is not ScalarBinaryKind8616.ADD:
            return (instruction.op,)
        if not isinstance(left, IRValue) or not isinstance(right, IRValue):
            return (instruction.op,)
        if (left.space is MemSpace.REG and right.space is MemSpace.REG
                and left.name is not None and right.name is not None):
            return (instruction.op, left.name, right.name)
        return (instruction.op,)
    return ()


def scalar_read_projection_8616(
    *,
    read_expr: tuple[str, ...] | None,
    read_bits: int,
    produced: tuple[str, ...],
    produced_bits: int,
) -> ScalarProjection8616 | None:
    """Decide how one decorated scalar read projects from its producer.

    This is a pure decoration/width decision over supplied metadata; it does
    NOT prove that a producer exists, that ``produced`` was honestly earned,
    or any def-use lineage — caller-side engines own those proofs.

    An undecorated read claims no conversion and passes through at the
    retained width. A decoration equal to the producer's earned ``produced``
    label is the re-decoration of this very definition and also passes
    through. Any other decoration must be exactly one conversion whose
    declared source width equals the retained definition's width; a
    conversion matching only the target width is unearned, and unsupported
    or multiple labels refuse. The final width check never manufactures an
    implicit widening or truncation, and impossible bit widths refuse.
    """
    if read_bits not in _SUPPORTED_BITS_8616 or produced_bits not in _SUPPORTED_BITS_8616:
        return None
    expr = read_expr or ()
    if expr and expr != produced:
        if len(expr) != 1:
            return None
        conversion = _SCALAR_CONVERSIONS_8616.get(expr[0])
        if conversion is None or conversion[0] != produced_bits:
            return None
        _source, target, signed = conversion
        if target != read_bits:
            return None
        return ScalarProjection8616(
            ScalarProjectionKind8616.CONVERSION, produced_bits, target, signed,
        )
    if produced_bits != read_bits:
        return None
    kind = (
        ScalarProjectionKind8616.EARNED_REDECORATION
        if expr
        else ScalarProjectionKind8616.IDENTITY
    )
    return ScalarProjection8616(kind, produced_bits, read_bits)


__all__ = [
    "ScalarBinaryKind8616",
    "ScalarBinaryOp8616",
    "ScalarProjection8616",
    "ScalarProjectionKind8616",
    "scalar_active_unary_projection_8616",
    "scalar_binary_operation_8616",
    "scalar_produced_decoration_8616",
    "scalar_read_projection_8616",
]
