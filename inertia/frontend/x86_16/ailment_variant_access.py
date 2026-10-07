"""Layer: Frontend/angr compatibility.

Responsibility: describe native AIL payloads after concrete variant checks.
Rust-backed AIL markers implement runtime isinstance without static narrowing.
These field views bridge that boundary; they do not prove storage identity,
return semantics, or types. Consumers must check the native variant first.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol, cast

from angr import ailment


class AilAssignment8616(Protocol):
    """Payload of a checked native Assignment statement."""

    dst: object
    src: object


class AilRegister8616(Protocol):
    """Register offset and width of a checked native Register expression."""

    reg_offset: int
    bits: int


class AilTmp8616(Protocol):
    """Temporary index of a checked native Tmp expression."""

    tmp_idx: int


class AilConst8616(Protocol):
    """Constant payload, whose numeric kind still needs checking."""

    value: object


class AilOperands8616(Protocol):
    """Native operand collection, exposed only after a capability check."""

    operands: Sequence[object]


class AilBinaryOp8616(AilOperands8616, Protocol):
    """Opcode and operands of a checked native BinaryOp expression."""

    op: str


class AilBasePointerOffset8616(Protocol):
    """Unclassified base and displacement of a native BasePointerOffset."""

    base: object
    offset: object


class AilStackBaseOffset8616(Protocol):
    """Stack displacement and provenance tags, not a proof of BP identity."""

    offset: object
    tags: Mapping[str, object]


class AilLoad8616(Protocol):
    """Address, width and tags of a checked native Load expression."""

    addr: object
    bits: int
    tags: Mapping[str, object]


def register_assignment_source_8616(stmt: object, *, reg_offset: int, reg_size: int) -> object | None:
    """Read a source only for an exact native register destination and width."""
    if not isinstance(stmt, ailment.Stmt.Assignment):
        return None
    assignment = cast(AilAssignment8616, stmt)
    if not isinstance(assignment.dst, ailment.Expr.Register):
        return None
    dst = cast(AilRegister8616, assignment.dst)
    if dst.reg_offset != reg_offset or dst.bits != reg_size * 8:
        return None
    return assignment.src


def tmp_assignment_source_8616(stmt: object, *, tmp_idx: int) -> object | None:
    """Read a source only for an exact native temporary destination."""
    if not isinstance(stmt, ailment.Stmt.Assignment):
        return None
    assignment = cast(AilAssignment8616, stmt)
    if not isinstance(assignment.dst, ailment.Expr.Tmp):
        return None
    if cast(AilTmp8616, assignment.dst).tmp_idx != tmp_idx:
        return None
    return assignment.src


def ail_const_value_8616(expr: object) -> int | None:
    """Read integer constants without accepting other native expression kinds."""
    if isinstance(expr, ailment.Expr.Const):
        value = cast(AilConst8616, expr).value
        return int(value) if isinstance(value, int) else None
    return None
