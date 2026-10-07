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

from .core import (
    AddressStatus,
    IRActiveUnary8616,
    IRAddress,
    IRCondition,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from .scalar_value_projection import (
    ScalarProjection8616,
    ScalarProjectionKind8616,
    scalar_read_projection_8616,
)

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


_UNARY_FOLD_DEPTH_LIMIT_8616 = 8
_UNARY_COMPLEMENT_OPS_8616: dict[str, int] = {
    f"Iop_Not{bits}": bits for bits in (8, 16, 32, 64)
}


def _unary_conversion_8616(unary: IRActiveUnary8616, operand_bits: int) -> ScalarProjection8616 | None:
    """Authenticate an active unary as an exact conversion via the adapter.

    The scalar-projection adapter owns the single conversion-name truth;
    ``produced=()`` forces the declaration path so the op's declared source
    width must equal the operand's actual width and the declared target must
    equal the authoritative VEX result width.
    """
    decision = scalar_read_projection_8616(
        read_expr=(unary.op,),
        read_bits=unary.result_bits,
        produced=(),
        produced_bits=operand_bits,
    )
    if decision is None or decision.kind is not ScalarProjectionKind8616.CONVERSION:
        return None
    return decision


def _fold_const_conversion_8616(
    operand: IRValue, decision: ScalarProjection8616, size: int,
) -> IRValue | None:
    """Fold one exact-constant operand through an authenticated conversion."""
    const = operand.const
    if operand.source_tmp is not None or const is None or const < 0:
        return None
    low_mask = (1 << decision.source_bits) - 1
    if const & ~low_mask:
        return None
    if decision.target_bits < decision.source_bits:
        folded = const & ((1 << decision.target_bits) - 1)
    elif decision.signed and const & (1 << (decision.source_bits - 1)):
        folded = const | (((1 << decision.target_bits) - 1) & ~low_mask)
    else:
        folded = const
    return IRValue(MemSpace.CONST, const=folded, size=size)


def _fold_unary_operand_8616(unary: IRActiveUnary8616, operand: IRValue, size: int) -> IRValue | None:
    """Fold one authenticated unary over a resolved operand.

    Over an exact constant the operation folds to its exact integer at the
    declared widths. Over a symbolic operand only unsigned widening passes
    the operand through unchanged — it preserves the numeric value; sign
    extension and truncation alter it and refuse.
    """
    decision = _unary_conversion_8616(unary, operand.size * 8)
    if decision is not None:
        if operand.space is MemSpace.CONST and operand.const is not None and operand.offset == 0:
            return _fold_const_conversion_8616(operand, decision, size)
        if decision.signed or decision.target_bits <= decision.source_bits:
            return None
        return operand
    bits = _UNARY_COMPLEMENT_OPS_8616.get(unary.op)
    if bits is None or unary.result_bits != bits or operand.size * 8 != bits:
        return None
    if operand.space is not MemSpace.CONST or operand.const is None or operand.offset != 0:
        return None
    mask = (1 << bits) - 1
    if operand.const < 0 or operand.const & ~mask:
        return None
    return IRValue(MemSpace.CONST, const=(~operand.const) & mask, size=size)


def _resolved_active_operand_8616(value: IRValue, depth: int) -> IRValue | None:
    """Resolve one operand to a view carrying no pending unary operation.

    A ``source_tmp``-pinned value names an already-computed definition and
    passes through with capture identity intact; a pending ``active_unary``
    must be consumed here, never read from the projected REG/CONST fields.
    Contradictory or unsupported operations refuse instead of guessing.
    """
    if (value.index is not None or value.call_output is not None
            or (value.space is MemSpace.CONST and value.source_tmp is not None)):
        # CONST is a producer projection, not the captured result.
        return None
    unary = value.active_unary
    if unary is None:
        return value
    if value.source_tmp is not None or depth >= _UNARY_FOLD_DEPTH_LIMIT_8616:
        return None
    if value.expr is not None and value.expr != (unary.op,):
        return None
    operand = _resolved_active_operand_8616(unary.operand, depth + 1)
    if operand is None:
        return None
    return _fold_unary_operand_8616(unary, operand, value.size)


def _base_capture_8616(value: IRValue) -> IRValue:
    """Return the address-base evidence view of one operand.

    The ``offset`` field is displacement provenance folded into the address
    offset (unpinned) or inside the captured temporary definition (pinned);
    the retained base value keeps the rest of the operand's typed identity —
    including ``source_tmp`` — so later consumers bind the exact captured
    version rather than the register's current contents.
    """
    return replace(value, offset=0)


def _operand_displacement_8616(value: IRValue) -> int:
    """Return the offset contribution of one base operand.

    A pinned operand's offset is provenance inside its captured temporary
    result; adding it again would replay arithmetic already consumed by the
    capture. Only unpinned operands contribute their displacement.
    """
    return 0 if value.source_tmp is not None else value.offset


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
    if tmp_value is None or tmp_value.active_unary is not None:
        return None
    if tmp_value.space == MemSpace.REG and tmp_value.name is not None:
        return _AddressParts8616(
            base=(tmp_value.name,), offset=_operand_displacement_8616(tmp_value),
            base_values=(_base_capture_8616(tmp_value),),
        )
    if (tmp_value.space == MemSpace.CONST and tmp_value.const is not None
            and tmp_value.source_tmp is None):
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
        if value.active_unary is not None:
            return None
        return None if value.name is None else _AddressParts8616(
            base=(value.name,), offset=value.offset, base_values=(replace(value, offset=0),),
        )
    if current_tag == "Iex_Const":
        return _AddressParts8616(offset=_vex_const_value(current))
    if current_tag == "Iex_Unop":
        args = _vex_args(current)
        # A genuine producer can establish a constant; a captured reference's
        # display literal cannot establish the value of that capture.
        resolved = _resolved_active_operand_8616(
            ctx.expr_to_value(current, ctx.tmps, ctx.conditions), 0,
        )
        if (resolved is not None and resolved.space is MemSpace.CONST
                and resolved.source_tmp is None and resolved.const is not None):
            return _AddressParts8616(offset=resolved.const)
        if len(args) != 1 or not _zero_extension_8616(ctx, current, args[0]):
            return None
        return _decompose_address_8616(ctx, args[0], seen_tmps)
    if current_tag != "Iex_Binop":
        return None
    return _decompose_binop_8616(ctx, current, seen_tmps)


def _zero_extension_8616(ctx: _VexAddressContext8616, current: object, operand_expr: object) -> bool:
    """Whether one Unop is an exact value-preserving zero extension.

    Only unsigned widening keeps every decomposed lane exact; sign extension
    and truncation change the numeric offset or base. The conversion name and
    widths are authenticated by the scalar-projection adapter against the
    converted operand width and the authoritative VEX result width — never
    the rendered operation text alone.
    """
    operand = ctx.expr_to_value(operand_expr, ctx.tmps, ctx.conditions)
    wrapper = ctx.expr_to_value(current, ctx.tmps, ctx.conditions)
    result_bits = (
        wrapper.active_unary.result_bits
        if wrapper.active_unary is not None
        else wrapper.size * 8
    )
    decision = scalar_read_projection_8616(
        read_expr=(_vex_op(current),),
        read_bits=result_bits,
        produced=(),
        produced_bits=operand.size * 8,
    )
    return (
        decision is not None
        and decision.kind is ScalarProjectionKind8616.CONVERSION
        and not decision.signed
        and decision.target_bits > decision.source_bits
    )


def _address_from_rdtmp_8616(ctx: _VexAddressContext8616, expr: object) -> IRAddress:
    """Lift one register temporary read into a typed IR address."""
    tmp_id = _vex_tmp(expr)
    tmp_value = ctx.tmps.get(tmp_id)
    if tmp_value is None:
        return _vex_unknown_8616(ctx, ("rdtmp", f"t{tmp_id}"))
    if tmp_value.active_unary is not None:
        return _vex_unknown_8616(ctx, ("active_tmp", f"t{tmp_id}"))
    if tmp_value.space == MemSpace.REG and tmp_value.name is not None:
        return _address_from_parts(
            (tmp_value.name,),
            _operand_displacement_8616(tmp_value),
            size=ctx.size,
            expr=("register_base", tmp_value.name),
            segment_hints=ctx.segment_hints,
            base_values=(_base_capture_8616(tmp_value),),
        )
    if tmp_value.expr and tmp_value.expr[:1] == ("Iop_Add16",) and len(tmp_value.expr) == 3:
        return _address_from_parts(
            (tmp_value.expr[1], tmp_value.expr[2]), 0, size=ctx.size, expr=tmp_value.expr,
            segment_hints=ctx.segment_hints, base_values=(_base_capture_8616(tmp_value),),
        )
    return _vex_unknown_8616(ctx, ("tmp_expr", tmp_value.name or "tmp"))


def _address_from_binop_8616(ctx: _VexAddressContext8616, expr: object) -> IRAddress:
    """Lift one undecomposed VEX binary expression into a typed IR address.

    Both operands are resolved to views carrying no pending unary operation:
    exact constants fold, value-preserving zero extensions pass through, and
    anything else produces a typed unknown rather than projecting guessed
    REG/CONST fields. Base values keep their temporary capture identity so
    consumers bind the captured register version, not current storage.
    """
    op = _vex_op(expr)
    args = _vex_args(expr)
    if len(args) != 2:
        return _vex_unknown_8616(ctx, (op,))
    left = _resolved_active_operand_8616(
        ctx.expr_to_value(args[0], ctx.tmps, ctx.conditions), 0,
    )
    right = _resolved_active_operand_8616(
        ctx.expr_to_value(args[1], ctx.tmps, ctx.conditions), 0,
    )
    if left is None or right is None:
        return _vex_unknown_8616(ctx, (op, "active_operand"))
    if (
        "Add" in op
        and left.space == MemSpace.REG
        and right.space == MemSpace.CONST
        and right.const is not None
        and left.name
    ):
        return _address_from_parts(
            (left.name,),
            _operand_displacement_8616(left) + _wrapped_displacement_8616(int(right.const), op),
            size=ctx.size,
            expr=(op, left.name),
            segment_hints=ctx.segment_hints,
            base_values=(_base_capture_8616(left),),
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
            _operand_displacement_8616(left) - _wrapped_displacement_8616(int(right.const), op),
            size=ctx.size,
            expr=(op, left.name),
            segment_hints=ctx.segment_hints,
            base_values=(_base_capture_8616(left),),
        )
    if "Add" in op and left.space == MemSpace.REG and right.space == MemSpace.REG and left.name and right.name:
        ordered = sorted((left, right), key=lambda operand: operand.name or "")
        return _address_from_parts(
            (ordered[0].name or "", ordered[1].name or ""),
            _operand_displacement_8616(left) + _operand_displacement_8616(right),
            size=ctx.size,
            expr=(op, left.name, right.name),
            segment_hints=ctx.segment_hints,
            base_values=(_base_capture_8616(ordered[0]), _base_capture_8616(ordered[1])),
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
