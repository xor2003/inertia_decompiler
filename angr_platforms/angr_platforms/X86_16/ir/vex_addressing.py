"""Lift VEX address expressions into typed IR addresses.

Layer: IR.
Responsibility: owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Address decomposition must retain the original register-read temporary; binding
only its name later can select a register version modified by the same instruction.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from typing import Any, Protocol, cast

from .core import AddressStatus, IRAddress, IRCondition, IRValue, MemSpace, SegmentOrigin

__all__ = [
    "block_segment_hints",
    "expr_to_address",
]


def _infer_address_space(base: tuple[str, ...]) -> tuple[MemSpace, AddressStatus, SegmentOrigin]:
    if not base:
        return MemSpace.UNKNOWN, AddressStatus.UNKNOWN, SegmentOrigin.UNKNOWN
    if any(name in {"bp", "sp"} for name in base):
        return MemSpace.SS, AddressStatus.STABLE, SegmentOrigin.PROVEN
    return MemSpace.DS, AddressStatus.PROVISIONAL, SegmentOrigin.DEFAULTED


class _CapstoneInsnBoundary(Protocol):
    """External Capstone instruction attributes used for segment hints."""

    mnemonic: object


class _CapstoneBlockBoundary(Protocol):
    """External block attributes used to read Capstone instruction metadata."""

    capstone: object


class _CapstoneInsnListBoundary(Protocol):
    """External Capstone container exposing decoded instruction objects."""

    insns: Iterable[_CapstoneInsnBoundary]


class _VexConstBoundary(Protocol):
    """External VEX constant wrapper exposing an integer-like value."""

    value: object


class _VexExprBoundary(Protocol):
    """External VEX expression attributes used by address lifting."""

    tag: object
    tmp: object
    op: object
    args: Iterable[object]
    con: _VexConstBoundary


def _parse_string_family(mnemonic: str) -> str | None:
    text = mnemonic.strip().lower()
    if not text:
        return None
    parts = text.split()
    base = parts[-1]
    for family in ("movs", "stos", "scas", "cmps", "lods", "ins", "outs"):
        if base.startswith(family):
            return family
    return None


type SegmentHintMap = dict[tuple[str, ...], tuple[MemSpace, AddressStatus, SegmentOrigin]]


@dataclass(frozen=True, slots=True)
class _AddressParts8616:
    """Lossless segmented components recovered from a VEX linear address."""

    segment: str | None = None
    base: tuple[str, ...] = ()
    offset: int = 0
    base_values: tuple[IRValue, ...] = ()


def _vex_tag(expr: object) -> str:
    try:
        tag = cast(_VexExprBoundary, expr).tag
    except AttributeError:
        return ""
    return str(tag or "")


def _external_int(value: object, default: int = 0) -> int:
    try:
        return int(cast(Any, value))
    except (TypeError, ValueError):
        return default


def _vex_tmp(expr: object) -> int:
    return _external_int(cast(_VexExprBoundary, expr).tmp)


def _vex_op(expr: object) -> str:
    try:
        op = cast(_VexExprBoundary, expr).op
    except AttributeError:
        return ""
    return str(op or "")


def _vex_args(expr: object) -> tuple[object, ...]:
    try:
        args = cast(_VexExprBoundary, expr).args
    except AttributeError:
        return ()
    return tuple(args or ())


def _vex_const_value(expr: object) -> int:
    try:
        value = cast(_VexExprBoundary, expr).con.value
    except AttributeError:
        return 0
    return _external_int(value)


def block_segment_hints(block: object) -> SegmentHintMap:
    """Infer segment defaults from external Capstone string-instruction metadata."""
    try:
        capstone = cast(_CapstoneBlockBoundary, block).capstone
        insns = tuple(cast(_CapstoneInsnListBoundary, capstone).insns or ())
    except AttributeError:
        insns = ()
    hints: SegmentHintMap = {}
    for insn in insns:
        try:
            mnemonic = insn.mnemonic
        except AttributeError:
            mnemonic = ""
        family = _parse_string_family(str(mnemonic))
        if family in {"movs", "stos", "scas", "cmps", "ins"}:
            hints[("di",)] = (MemSpace.ES, AddressStatus.STABLE, SegmentOrigin.PROVEN)
        if family in {"movs", "lods", "cmps", "outs"}:
            hints.setdefault(("si",), (MemSpace.DS, AddressStatus.PROVISIONAL, SegmentOrigin.DEFAULTED))
    return hints


def _address_from_parts(
    base: tuple[str, ...],
    offset: int = 0,
    *,
    size: int = 0,
    expr: tuple[str, ...] | None = None,
    segment_hints: SegmentHintMap | None = None,
    explicit_segment: str | None = None,
    base_values: tuple[IRValue, ...] = (),
) -> IRAddress:
    """Retain captured base reads separately from their folded displacement."""
    explicit_spaces = {"ss": MemSpace.SS, "ds": MemSpace.DS, "es": MemSpace.ES}
    if explicit_segment in explicit_spaces:
        space = explicit_spaces[explicit_segment]
        status = AddressStatus.STABLE
        segment_origin = SegmentOrigin.PROVEN
    else:
        hinted = None if segment_hints is None else segment_hints.get(base)
        if hinted is not None:
            space, status, segment_origin = hinted
        else:
            space, status, segment_origin = _infer_address_space(base)
    return IRAddress(
        space=space,
        base=base,
        offset=offset,
        size=size,
        status=status,
        segment_origin=segment_origin,
        expr=expr,
        base_values=base_values or tuple(
            IRValue(MemSpace.REG, name=name, size=2) for name in base
        ),
    )


@dataclass(frozen=True, slots=True)
class _VexAddressContext8616:
    """Shared external-expression inputs for one address lift."""

    tmps: Mapping[int, IRValue]
    conditions: Mapping[int, IRCondition]
    expr_to_value: Callable[[object, Mapping[int, IRValue], Mapping[int, IRCondition]], IRValue]
    size: int = 0
    segment_hints: SegmentHintMap | None = None
    tmp_exprs: Mapping[int, object] | None = None


def _vex_unknown_8616(ctx: _VexAddressContext8616, expr_tag: tuple[str, ...]) -> IRAddress:
    """Return an unknown-space address tagged with the refused expression."""
    return IRAddress(
        MemSpace.UNKNOWN,
        size=ctx.size,
        status=AddressStatus.UNKNOWN,
        segment_origin=SegmentOrigin.UNKNOWN,
        expr=expr_tag,
    )


def _pure_segment_8616(parts: _AddressParts8616) -> str | None:
    """Return the segment register when the parts are a bare segment read."""
    if parts.segment is None and parts.offset == 0 and len(parts.base) == 1:
        register = parts.base[0]
        if register in {"cs", "ds", "es", "ss"}:
            return register
    return None


def _wrapped_displacement_8616(value: int, op: str) -> int:
    """Wrap a 16-bit displacement into its signed machine offset."""
    if "16" in op:
        value &= 0xFFFF
        return value - 0x10000 if value >= 0x8000 else value
    return value


def _combine_add_8616(
    left: _AddressParts8616,
    right: _AddressParts8616,
    op: str,
) -> _AddressParts8616 | None:
    """Merge two decomposed sides of an Add into one address part."""
    if left.segment is not None and right.segment is not None:
        return None
    segment = left.segment or right.segment
    base = (*left.base, *right.base)
    if len(base) > 2 or any(name in {"cs", "ds", "es", "ss"} for name in base):
        return None
    left_offset = _wrapped_displacement_8616(left.offset, op) if not left.base and left.segment is None else left.offset
    right_offset = (
        _wrapped_displacement_8616(right.offset, op) if not right.base and right.segment is None else right.offset
    )
    return _AddressParts8616(
        segment=segment, base=base, offset=left_offset + right_offset,
        base_values=(*left.base_values, *right.base_values),
    )


def _decompose_rdtmp_8616(
    ctx: _VexAddressContext8616,
    current: object,
    seen_tmps: frozenset[int],
) -> _AddressParts8616 | None:
    """Decompose one register/constant temporary read into address parts."""
    tmp_id = _vex_tmp(current)
    if ctx.tmp_exprs is not None and tmp_id not in seen_tmps:
        defining_expr = ctx.tmp_exprs.get(tmp_id)
        if defining_expr is not None:
            decomposed = _decompose_address_8616(ctx, defining_expr, seen_tmps | {tmp_id})
            if decomposed is not None:
                if _vex_tag(defining_expr) == "Iex_Get":
                    decomposed = replace(decomposed, base_values=tuple(
                        replace(value, source_tmp=tmp_id) for value in decomposed.base_values
                    ))
                return decomposed
    tmp_value = ctx.tmps.get(tmp_id)
    if tmp_value is None:
        return None
    if tmp_value.space == MemSpace.REG and tmp_value.name is not None:
        return _AddressParts8616(
            base=(tmp_value.name,), offset=tmp_value.offset,
            base_values=(IRValue(MemSpace.REG, name=tmp_value.name, size=2),),
        )
    if tmp_value.space == MemSpace.CONST and tmp_value.const is not None:
        return _AddressParts8616(offset=int(tmp_value.const))
    return None


def _is_const_offset_8616(parts: _AddressParts8616, offset: int) -> bool:
    """Return whether the parts are a bare constant offset."""
    return parts.segment is None and not parts.base and parts.offset == offset


def _segment_part_8616(parts: _AddressParts8616) -> _AddressParts8616 | None:
    """Return a segment-only part when the side is a pure segment register."""
    segment = _pure_segment_8616(parts)
    return None if segment is None else _AddressParts8616(segment=segment)


def _decompose_binop_8616(
    ctx: _VexAddressContext8616,
    current: object,
    seen_tmps: frozenset[int],
) -> _AddressParts8616 | None:
    """Decompose one VEX binary operator into combined address parts."""
    op = _vex_op(current)
    args = _vex_args(current)
    if len(args) != 2:
        return None
    left = _decompose_address_8616(ctx, args[0], seen_tmps)
    right = _decompose_address_8616(ctx, args[1], seen_tmps)
    if left is None or right is None:
        return None
    if "Shl" in op and _is_const_offset_8616(right, 4):
        return _segment_part_8616(left)
    if "Mul" in op:
        if _is_const_offset_8616(right, 16):
            return _segment_part_8616(left)
        if _is_const_offset_8616(left, 16):
            return _segment_part_8616(right)
    if "Add" in op:
        return _combine_add_8616(left, right, op)
    if "Sub" in op and right.segment is None and not right.base:
        displacement = _wrapped_displacement_8616(right.offset, op)
        return _AddressParts8616(
            segment=left.segment,
            base=left.base,
            offset=left.offset - displacement,
            base_values=left.base_values,
        )
    return None


def _decompose_address_8616(
    ctx: _VexAddressContext8616,
    current: object,
    seen_tmps: frozenset[int] = frozenset(),
) -> _AddressParts8616 | None:
    """Decompose one VEX expression into segmented address parts."""
    current_tag = _vex_tag(current)
    if current_tag == "Iex_RdTmp":
        return _decompose_rdtmp_8616(ctx, current, seen_tmps)
    if current_tag == "Iex_Get":
        value = ctx.expr_to_value(current, ctx.tmps, ctx.conditions)
        return None if value.name is None else _AddressParts8616(
            base=(value.name,), offset=value.offset, base_values=(replace(value, offset=0),),
        )
    if current_tag == "Iex_Const":
        return _AddressParts8616(offset=_vex_const_value(current))
    if current_tag == "Iex_Unop":
        op = _vex_op(current)
        args = _vex_args(current)
        if len(args) == 1 and "to" in op:
            return _decompose_address_8616(ctx, args[0], seen_tmps)
        return None
    if current_tag != "Iex_Binop":
        return None
    return _decompose_binop_8616(ctx, current, seen_tmps)


def _address_from_rdtmp_8616(ctx: _VexAddressContext8616, expr: object) -> IRAddress:
    """Lift one register temporary read into a typed IR address."""
    tmp_id = _vex_tmp(expr)
    tmp_value = ctx.tmps.get(tmp_id)
    if tmp_value is None:
        return _vex_unknown_8616(ctx, ("rdtmp", f"t{tmp_id}"))
    if tmp_value.space == MemSpace.REG and tmp_value.name is not None:
        return _address_from_parts(
            (tmp_value.name,),
            tmp_value.offset,
            size=ctx.size,
            expr=("register_base", tmp_value.name),
            segment_hints=ctx.segment_hints,
        )
    if tmp_value.expr and tmp_value.expr[:1] == ("Iop_Add16",) and len(tmp_value.expr) == 3:
        return _address_from_parts(
            (tmp_value.expr[1], tmp_value.expr[2]), 0, size=ctx.size, expr=tmp_value.expr, segment_hints=ctx.segment_hints
        )
    return _vex_unknown_8616(ctx, ("tmp_expr", tmp_value.name or "tmp"))


def _address_from_binop_8616(ctx: _VexAddressContext8616, expr: object) -> IRAddress:
    """Lift one undecomposed VEX binary expression into a typed IR address."""
    op = _vex_op(expr)
    args = _vex_args(expr)
    if len(args) != 2:
        return _vex_unknown_8616(ctx, (op,))
    left = ctx.expr_to_value(args[0], ctx.tmps, ctx.conditions)
    right = ctx.expr_to_value(args[1], ctx.tmps, ctx.conditions)
    if (
        "Add" in op
        and left.space == MemSpace.REG
        and right.space == MemSpace.CONST
        and right.const is not None
        and left.name
    ):
        return _address_from_parts(
            (left.name,),
            left.offset + int(right.const),
            size=ctx.size,
            expr=(op, left.name),
            segment_hints=ctx.segment_hints,
        )
    if (
        "Sub" in op
        and left.space == MemSpace.REG
        and right.space == MemSpace.CONST
        and right.const is not None
        and left.name
    ):
        return _address_from_parts(
            (left.name,),
            left.offset - int(right.const),
            size=ctx.size,
            expr=(op, left.name),
            segment_hints=ctx.segment_hints,
        )
    if "Add" in op and left.space == MemSpace.REG and right.space == MemSpace.REG and left.name and right.name:
        return _address_from_parts(
            tuple(sorted((left.name, right.name))),
            0,
            size=ctx.size,
            expr=(op, left.name, right.name),
            segment_hints=ctx.segment_hints,
        )
    return _vex_unknown_8616(ctx, (op,))


def expr_to_address(
    expr: object,
    tmps: Mapping[int, IRValue],
    conditions: Mapping[int, IRCondition],
    *,
    expr_to_value: Callable[[object, Mapping[int, IRValue], Mapping[int, IRCondition]], IRValue],
    size: int = 0,
    segment_hints: SegmentHintMap | None = None,
    tmp_exprs: Mapping[int, object] | None = None,
) -> IRAddress:
    """Lift one external VEX address expression into the typed IR address model."""
    ctx = _VexAddressContext8616(
        tmps, conditions, expr_to_value,
        size=size, segment_hints=segment_hints, tmp_exprs=tmp_exprs,
    )
    parts = _decompose_address_8616(ctx, expr)
    if parts is not None and (parts.segment is not None or parts.base):
        expr_parts = ("segmented_linear", parts.segment or "default", *parts.base)
        return _address_from_parts(
            parts.base,
            parts.offset,
            size=size,
            expr=expr_parts,
            segment_hints=segment_hints,
            explicit_segment=parts.segment,
            base_values=parts.base_values,
        )

    tag = _vex_tag(expr)
    if tag == "Iex_RdTmp":
        return _address_from_rdtmp_8616(ctx, expr)
    if tag == "Iex_Get":
        value = expr_to_value(expr, tmps, conditions)
        return _address_from_parts(
            () if value.name is None else (value.name,),
            value.offset,
            size=size,
            expr=("register_get", value.name or ""),
            segment_hints=segment_hints,
        )
    if tag == "Iex_Const":
        return IRAddress(
            MemSpace.UNKNOWN,
            offset=_vex_const_value(expr),
            size=size,
            status=AddressStatus.UNKNOWN,
            segment_origin=SegmentOrigin.UNKNOWN,
            expr=("absolute_const",),
        )
    if tag == "Iex_Binop":
        return _address_from_binop_8616(ctx, expr)
    return _vex_unknown_8616(ctx, (tag or "addr_expr",))
