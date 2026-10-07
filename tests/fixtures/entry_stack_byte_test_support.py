"""Shared synthetic IR fixtures for entry-stack-byte tests.

Layer: Alias test support.
Responsibility: provide typed, binary-free proof fixtures.

Builds typed IRFunctionArtifact entry-block prefixes for the Alias
entry-stack-byte proof and snapshot-owner tests. All fixtures are cheap and
binary-free; the native POINT.EXE replay stays in external diagnostics.
"""

from __future__ import annotations

from inertia.ir.core import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRRefusal,
    IRValue,
    MemSpace,
    SegmentOrigin,
)

from inertia.alias.entry_stack_byte_contracts import (
    EntryStackByteProof8616,
    EntryStackByteRefusalKind8616,
)

ENTRY_8616: int = 0x105BC


def _tmp(tmp_id: int, size: int = 2) -> IRValue:
    """A TMP value carrying its producer identity."""
    return IRValue(MemSpace.TMP, name=f"t{tmp_id}", size=size, source_tmp=tmp_id)


def _reg(
    name: str,
    size: int = 2,
    *,
    offset: int = 0,
    expr: tuple[str, ...] | None = None,
    source_tmp: int | None = None,
) -> IRValue:
    """A REG value with optional displacement/decorations."""
    return IRValue(MemSpace.REG, name=name, offset=offset, size=size, expr=expr, source_tmp=source_tmp)


def _const(value: int, size: int = 2) -> IRValue:
    """A CONST operand."""
    return IRValue(MemSpace.CONST, const=value, size=size)


def _mov(dst: IRValue, src: IRValue) -> IRInstr:
    """A scalar MOV instruction."""
    return IRInstr(op="MOV", dst=dst, args=(src,), size=src.size or dst.size, addr=ENTRY_8616)


def _binop(op: str, tmp_id: int, left: IRValue, right: IRValue) -> IRInstr:
    """A word-width binary VEX op producing a tmp."""
    return IRInstr(op=op, dst=_tmp(tmp_id), args=(left, right), size=2, addr=ENTRY_8616)


def _load(tmp_id: int, address: IRAddress, size: int = 1) -> IRInstr:
    """A LOAD into a tmp destination."""
    return IRInstr(op="LOAD", dst=_tmp(tmp_id, size), args=(address,), size=size, addr=ENTRY_8616)


def _ss_addr(
    offset: int,
    size: int,
    *,
    base_tmp: int | None = 0,
    base_offset: int = 0,
    base_expr: tuple[str, ...] | None = None,
    space: MemSpace = MemSpace.SS,
    status: AddressStatus = AddressStatus.STABLE,
    origin: SegmentOrigin = SegmentOrigin.PROVEN,
) -> IRAddress:
    """An SS address whose base is the sp register, optionally tmp-captured."""
    base_values: tuple[IRValue, ...] = ()
    if base_tmp is not None:
        base_values = (
            _reg("sp", offset=base_offset, expr=base_expr, source_tmp=base_tmp),
        )
    return IRAddress(
        space=space,
        base=("sp",),
        offset=offset,
        size=size,
        status=status,
        segment_origin=origin,
        base_values=base_values,
    )


def _block(
    instrs: list[IRInstr],
    *,
    addr: int = ENTRY_8616,
    refusals: tuple[IRRefusal, ...] = (),
) -> IRBlock:
    """A single IR block."""
    return IRBlock(addr=addr, instrs=tuple(instrs), refusals=refusals)


def _artifact(
    instrs: list[IRInstr],
    *,
    function_addr: int = ENTRY_8616,
    block_addr: int = ENTRY_8616,
    refusals: tuple[IRRefusal, ...] = (),
) -> IRFunctionArtifact:
    """A single-block function artifact at ``function_addr``."""
    block = _block(instrs, addr=block_addr, refusals=refusals)
    return IRFunctionArtifact(function_addr=function_addr, blocks=(block,))


def _capture() -> IRInstr:
    """Word-exact ``t0 = sp`` producer."""
    return _mov(_tmp(0), _reg("sp"))


def _refusal_kinds(proof: EntryStackByteProof8616) -> list[EntryStackByteRefusalKind8616]:
    """Return the ordered typed refusal kinds of one proof."""
    return [refusal.kind for refusal in proof.refusals]
