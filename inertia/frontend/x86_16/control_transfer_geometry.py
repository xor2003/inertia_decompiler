"""Typed closed near-transfer coordinate checks under authenticated CS.

Layer: frontend x86_16.

Responsibility: bind byte-bound control coordinates to the original
exact CFG under a known CS. Bytes supply displacement geometry only;
the control class comes from the canonical IR row op and the resolved
CALL target from the callsite index — never rendered text, names, or an
opcode default-preserve table. Far, indirect, system, operand/address-32
and malformed forms are typed ``REFUSED``; near RET is
``RETURN_OBLIGATION`` (CS preservation only — no return offset, frame,
or ESP fact is established).
"""

from __future__ import annotations

from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from enum import StrEnum

_SHIFT = 4
_WORD_SPAN = 0x10000
_PHYSICAL_LIMIT = 0x100000
_LEGACY_PREFIXES = frozenset({0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0xF0, 0xF2, 0xF3})
_SIZE_PREFIXES = frozenset({0x66, 0x67})


class ControlKind8616(StrEnum):
    """The control lane one bound instruction occupies."""

    CALL = "call"
    JMP = "jmp"
    CJMP = "cjmp"
    RET = "ret"
    FALLTHROUGH = "fallthrough"


class ControlVerdict8616(StrEnum):
    """Whether coordinate binding closed, stayed an obligation, or refused."""

    CLOSED = "closed"
    RETURN_OBLIGATION = "return_obligation"
    REFUSED = "refused"


@dataclass(frozen=True, slots=True)
class ControlCheck8616:
    """One typed coordinate verdict with the bound target and fallthrough."""

    verdict: ControlVerdict8616
    kind: ControlKind8616
    addr: int
    target: int | None
    fallthrough: int | None
    detail: str


def _refused(kind: ControlKind8616, addr: int, detail: str) -> ControlCheck8616:
    """One honest refusal row; unknown control never preserves by default."""
    return ControlCheck8616(ControlVerdict8616.REFUSED, kind, addr, None, None, detail)


def _opcode_index(encoded: bytes) -> tuple[int, str | None]:
    """Return the opcode byte index, or the typed size-prefix refusal."""
    index = 0
    while index < len(encoded):
        if encoded[index] == 0xF0:
            return index, "unsupported_lock_control"
        if encoded[index] in _SIZE_PREFIXES:
            return index, "operand_or_address_size_prefix"
        if encoded[index] in _LEGACY_PREFIXES:
            index += 1
            continue
        return index, None
    return index, "prefix_only"


def _ip_target(addr: int, size: int, displacement: int, csbase: int) -> int:
    """IP-relative target with 16-bit wrap, projected back to linear."""
    return csbase + ((addr - csbase + size + displacement) & 0xFFFF)


def _fetch_fits(addr: int, size: int, csbase: int) -> str | None:
    """The whole encoded instruction must sit in the CS window below 1MiB."""
    if type(addr) is not int or type(size) is not int or size <= 0:
        return "invalid_fetch_extent"
    if not csbase <= addr or addr + size > csbase + _WORD_SPAN:
        return "fetch_outside_cs_window"
    if addr + size > _PHYSICAL_LIMIT:
        return "fetch_a20_ambiguous"
    return None


def _wrapped_or_refused(addr: int, size: int, disp: int, csbase: int) -> tuple[int, str | None]:
    """Compute one wrapped IP target; refuse when the target is A20-ambiguous."""
    target = _ip_target(addr, size, disp, csbase)
    if target >= _PHYSICAL_LIMIT:
        return 0, "target_a20_ambiguous"
    return target, ""


def _single_byte_branch(
    addr: int, encoded: bytes, index: int, csbase: int,
    forms: dict[int, int],
) -> tuple[int, str | None]:
    """Decode ``opcode + displacement`` forms where disp follows the opcode."""
    width = forms.get(encoded[index])
    if width is None or len(encoded) - index != width + 1:
        return 0, "unsupported_near_form"
    disp = int.from_bytes(encoded[index + 1:index + 1 + width], "little", signed=True)
    return _wrapped_or_refused(addr, len(encoded), disp, csbase)


@dataclass(frozen=True, slots=True)
class _ControlContext8616:
    """Validated shared geometry for one control-instruction check."""

    addr: int
    encoded: bytes
    index: int
    kind: ControlKind8616
    csbase: int
    fallthrough: int
    successors: tuple[int, ...] | None
    call_target: int | None
    census_addrs: AbstractSet[int]


def _agree(ctx: _ControlContext8616, want: set[int]) -> str | None:
    """Require the candidate edges to match CFG or retained census exactly."""
    if ctx.successors is None:
        return None if want <= set(ctx.census_addrs) else "edge_not_retained"
    return None if frozenset(ctx.successors) == frozenset(want) else "cfg_mismatch"


def _check_call(ctx: _ControlContext8616) -> ControlCheck8616:
    """An E8 CALL binds its wrapped target to the mapped callee target."""
    target, bad = _single_byte_branch(ctx.addr, ctx.encoded, ctx.index,
                                      ctx.csbase, {0xE8: 2})
    if bad:
        return _refused(ctx.kind, ctx.addr, bad)
    if ctx.call_target is None or target != ctx.call_target:
        return _refused(ctx.kind, ctx.addr, "call_target_mismatch")
    if ctx.fallthrough not in ctx.census_addrs:
        return _refused(ctx.kind, ctx.addr, "call_fallthrough_unbound")
    return ControlCheck8616(ControlVerdict8616.CLOSED, ctx.kind,
                            ctx.addr, target, ctx.fallthrough, "e8_bound")


def _check_jmp(ctx: _ControlContext8616) -> ControlCheck8616:
    """A direct near JMP's wrapped target must equal the sole CFG edge."""
    target, bad = _single_byte_branch(ctx.addr, ctx.encoded, ctx.index,
                                      ctx.csbase, {0xE9: 2, 0xEB: 1})
    if bad:
        return _refused(ctx.kind, ctx.addr, bad)
    miss = _agree(ctx, {target})
    if miss is not None:
        return _refused(ctx.kind, ctx.addr, miss)
    return ControlCheck8616(ControlVerdict8616.CLOSED, ctx.kind,
                            ctx.addr, target, None, "near_jmp_bound")


def _check_cjmp(ctx: _ControlContext8616) -> ControlCheck8616:
    """A conditional near branch must bind BOTH wrapped edges exactly."""
    if ctx.encoded[ctx.index] == 0x0F:
        if (ctx.index + 1 >= len(ctx.encoded)
                or not 0x80 <= ctx.encoded[ctx.index + 1] <= 0x8F
                or len(ctx.encoded) - ctx.index != 4):
            return _refused(ctx.kind, ctx.addr, "unsupported_near_form")
        disp = int.from_bytes(ctx.encoded[ctx.index + 2:ctx.index + 4],
                              "little", signed=True)
        target, bad = _wrapped_or_refused(ctx.addr, len(ctx.encoded),
                                          disp, ctx.csbase)
    else:
        target, bad = _single_byte_branch(
            ctx.addr, ctx.encoded, ctx.index, ctx.csbase,
            dict.fromkeys((*range(0x70, 0x80), *range(0xE0, 0xE4)), 1))
    if bad:
        return _refused(ctx.kind, ctx.addr, bad)
    miss = _agree(ctx, {target, ctx.fallthrough})
    if miss is not None:
        return _refused(ctx.kind, ctx.addr, miss)
    return ControlCheck8616(ControlVerdict8616.CLOSED, ctx.kind,
                            ctx.addr, target, ctx.fallthrough, "near_cjmp_bound")


def _check_ret(ctx: _ControlContext8616) -> ControlCheck8616:
    """A near RET retains only CS preservation; frame/SP stay obligations."""
    opcode = ctx.encoded[ctx.index]
    if not ((opcode == 0xC3 and len(ctx.encoded) - ctx.index == 1)
            or (opcode == 0xC2 and len(ctx.encoded) - ctx.index == 3)):
        return _refused(ctx.kind, ctx.addr, "far_or_indirect_ret")
    return ControlCheck8616(ControlVerdict8616.RETURN_OBLIGATION,
                            ctx.kind, ctx.addr, None, None, "near_ret_cs_only")


_KINDS = {
    "CALL": ControlKind8616.CALL,
    "JMP": ControlKind8616.JMP,
    "CJMP": ControlKind8616.CJMP,
    "RET": ControlKind8616.RET,
}

_HANDLERS = {
    "CALL": _check_call,
    "JMP": _check_jmp,
    "CJMP": _check_cjmp,
    "RET": _check_ret,
}


def check_control_transfer_8616(
    *,
    addr: int,
    encoded: bytes,
    known_cs: int,
    ir_op: str,
    successors: tuple[int, ...] | None,
    call_target: int | None,
    census_addrs: AbstractSet[int],
) -> ControlCheck8616:
    """Bind one control instruction's coordinates to exact CFG evidence.

    ``successors`` is the owning block's original ``successor_addrs``;
    ``None`` marks a pending terminal with no CFG claim, where every
    candidate edge must land on a retained fetched instruction. Both
    conditional guards are kept: a missing taken or fallthrough edge is
    a refusal, never an assumed successor.
    """
    kind = _KINDS.get(ir_op, ControlKind8616.CALL)
    if type(known_cs) is not int or not 0 <= known_cs <= 0xFFFF:
        return _refused(kind, addr, "cs_unbound")
    csbase = known_cs << _SHIFT
    fit = _fetch_fits(addr, len(encoded), csbase)
    if fit is not None:
        return _refused(kind, addr, fit)
    index, refusal = _opcode_index(encoded)
    if refusal is not None or index >= len(encoded):
        return _refused(kind, addr, refusal or "empty_encoding")
    fallthrough = _ip_target(addr, len(encoded), 0, csbase)
    if kind in (ControlKind8616.CALL, ControlKind8616.CJMP) and fallthrough >= _PHYSICAL_LIMIT:
        return _refused(kind, addr, "fallthrough_a20_ambiguous")
    ctx = _ControlContext8616(addr, encoded, index, kind, csbase, fallthrough,
                              successors, call_target, census_addrs)
    handler = _HANDLERS.get(ir_op)
    if handler is None:
        return _refused(kind, addr, "unsupported_control_op")
    return handler(ctx)


def check_block_fallthrough_8616(
    *,
    last_addr: int,
    last_size: int,
    successors: tuple[int, ...],
    census_addrs: AbstractSet[int],
    known_cs: int,
) -> ControlCheck8616:
    """A non-control terminal's only edge is the exact native end address."""
    kind = ControlKind8616.FALLTHROUGH
    if type(known_cs) is not int or not 0 <= known_cs <= 0xFFFF:
        return _refused(kind, last_addr, "cs_unbound")
    csbase = known_cs << _SHIFT
    fit = _fetch_fits(last_addr, last_size, csbase)
    if fit is not None:
        return _refused(kind, last_addr, fit)
    end = _ip_target(last_addr, last_size, 0, csbase)
    if end >= _PHYSICAL_LIMIT:
        return _refused(kind, last_addr, "fallthrough_a20_ambiguous")
    if frozenset(successors) != frozenset({end}) or end not in census_addrs:
        return _refused(kind, last_addr, "fallthrough_mismatch")
    return ControlCheck8616(ControlVerdict8616.CLOSED, kind,
                            last_addr, None, end, "implicit_fallthrough_bound")
