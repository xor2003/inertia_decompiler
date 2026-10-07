"""Match captured logical memory operands to exact execution IR sites.

Layer: IR.
Responsibility: extract instruction-owned LOAD/STORE operations and construct
atomic wide or ordered-byte execution candidates. This module does not assign
capture ordinals, publish artifacts, infer aliases, or perform widening.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass

from .core import IRAddress, IRBlock
from .logical_memory_capture import IRLogicalMemoryCaptureRecord8616
from .logical_memory_contracts import (
    IRLogicalMemoryFailureKind8616,
    IRMemoryAccessKind8616,
    IRMemoryExecutionSlice8616,
)


@dataclass(frozen=True, slots=True)
class RawLogicalMemorySite8616:
    """One LOAD or STORE retained at an exact imported instruction index."""

    instr_index: int
    kind: IRMemoryAccessKind8616
    address: IRAddress | None
    instr_size: int


@dataclass(frozen=True, slots=True)
class LogicalMemoryExecutionCandidate8616:
    """One atomic wide operation or ordered byte run for a capture."""

    start_position: int
    end_position: int
    address: IRAddress
    slices: tuple[IRMemoryExecutionSlice8616, ...]


def _is_direct_address(address: IRAddress) -> bool:
    """Return whether an offset is direct rather than register-relative."""
    return not address.base or address.base == (address.space.value,)


def _offset_with_delta(address: IRAddress, address_bits: int, delta: int) -> int:
    """Advance one offset using architectural wrap only for direct addresses."""
    offset = int(address.offset) + delta
    if _is_direct_address(address):
        return offset & ((1 << address_bits) - 1)
    return offset


def _sized_address(
    address: IRAddress,
    address_bits: int,
    delta: int,
    size: int,
) -> IRAddress:
    """Copy an exact raw address with normalized offset and requested width."""
    return IRAddress(
        space=address.space,
        base=address.base,
        offset=_offset_with_delta(address, address_bits, delta),
        size=size,
        status=address.status,
        segment_origin=address.segment_origin,
        expr=address.expr,
        version=address.version,
        base_values=address.base_values,
    )


def _same_segment_base(left: IRAddress, right: IRAddress) -> bool:
    """Compare typed segment/base identity without rendered-expression matching."""
    return left.space is right.space and left.base == right.base


def raw_logical_memory_sites_8616(
    block: IRBlock,
    insn_addr: int,
) -> tuple[RawLogicalMemorySite8616, ...]:
    """Collect only exact LOAD/STORE operations owned by one instruction."""
    sites: list[RawLogicalMemorySite8616] = []
    for instr_index, instruction in enumerate(block.instrs):
        if instruction.addr != insn_addr or instruction.op not in {"LOAD", "STORE"}:
            continue
        kind = (
            IRMemoryAccessKind8616.READ
            if instruction.op == "LOAD"
            else IRMemoryAccessKind8616.WRITE
        )
        address = instruction.args[0] if instruction.args else None
        sites.append(
            RawLogicalMemorySite8616(
                instr_index=instr_index,
                kind=kind,
                address=address if isinstance(address, IRAddress) else None,
                instr_size=instruction.size,
            )
        )
    return tuple(sites)


def _wide_candidate(
    capture: IRLogicalMemoryCaptureRecord8616,
    site: RawLogicalMemorySite8616,
    position: int,
) -> LogicalMemoryExecutionCandidate8616 | None:
    """Expand one exact wide raw operation into deterministic byte slices."""
    address = site.address
    capture_address = capture.address
    address_bits = capture.address_bits
    block_addr = capture.block_addr
    insn_addr = capture.insn_addr
    assert capture_address is not None
    assert address_bits is not None
    assert block_addr is not None
    assert insn_addr is not None
    width = capture_address.size
    if (
        site.kind is not capture.kind
        or address is None
        or address.space is not capture_address.space
        or address.size != width
        or site.instr_size not in {0, width}
    ):
        return None
    slices = tuple(
        IRMemoryExecutionSlice8616(
            block_addr=block_addr,
            instr_index=site.instr_index,
            insn_addr=insn_addr,
            source_byte_offset=byte_offset,
            address=_sized_address(address, address_bits, byte_offset, 1),
        )
        for byte_offset in range(width)
    )
    return LogicalMemoryExecutionCandidate8616(
        position,
        position,
        _sized_address(address, address_bits, 0, width),
        slices,
    )


def _byte_candidate(
    capture: IRLogicalMemoryCaptureRecord8616,
    sites: tuple[RawLogicalMemorySite8616, ...],
    start_position: int,
) -> LogicalMemoryExecutionCandidate8616 | None:
    """Combine exactly one capture-width ordered run of byte raw operations."""
    capture_address = capture.address
    address_bits = capture.address_bits
    block_addr = capture.block_addr
    insn_addr = capture.insn_addr
    assert capture_address is not None
    assert address_bits is not None
    assert block_addr is not None
    assert insn_addr is not None
    width = capture_address.size
    selected = sites[start_position : start_position + width]
    if len(selected) != width:
        return None
    if any(
        site.kind is not capture.kind
        or site.address is None
        or site.address.size != 1
        or site.instr_size not in {0, 1}
        for site in selected
    ):
        return None
    addresses = tuple(site.address for site in selected)
    if not all(isinstance(address, IRAddress) for address in addresses):
        return None
    typed_addresses = tuple(address for address in addresses if isinstance(address, IRAddress))
    first = typed_addresses[0]
    if first.space is not capture_address.space:
        return None
    if any(not _same_segment_base(first, address) for address in typed_addresses):
        return None
    if any(
        _offset_with_delta(first, address_bits, byte_offset)
        != _offset_with_delta(address, address_bits, 0)
        for byte_offset, address in enumerate(typed_addresses)
    ):
        return None
    slices = tuple(
        IRMemoryExecutionSlice8616(
            block_addr=block_addr,
            instr_index=site.instr_index,
            insn_addr=insn_addr,
            source_byte_offset=byte_offset,
            address=_sized_address(address, address_bits, 0, 1),
        )
        for byte_offset, (site, address) in enumerate(
            zip(selected, typed_addresses, strict=True)
        )
    )
    return LogicalMemoryExecutionCandidate8616(
        start_position,
        start_position + width - 1,
        _sized_address(first, address_bits, 0, width),
        slices,
    )


def logical_memory_execution_candidates_8616(
    capture: IRLogicalMemoryCaptureRecord8616,
    sites: tuple[RawLogicalMemorySite8616, ...],
) -> tuple[LogicalMemoryExecutionCandidate8616, ...]:
    """Enumerate all exact wide or byte-run owners for one valid capture."""
    assert capture.address is not None
    candidates: list[LogicalMemoryExecutionCandidate8616] = []
    for position, site in enumerate(sites):
        wide = _wide_candidate(capture, site, position)
        if wide is not None:
            candidates.append(wide)
        if capture.address.size > 1:
            byte_run = _byte_candidate(capture, sites, position)
            if byte_run is not None:
                candidates.append(byte_run)
    return tuple(candidates)


def logical_memory_candidate_failure_8616(
    capture: IRLogicalMemoryCaptureRecord8616,
    sites: tuple[RawLogicalMemorySite8616, ...],
) -> tuple[IRLogicalMemoryFailureKind8616, str]:
    """Classify why no complete exact execution candidate exists."""
    if not sites:
        return (
            IRLogicalMemoryFailureKind8616.MISSING_EXECUTION_SLICES,
            "capture instruction has no raw LOAD or STORE operations",
        )
    matching_kind = tuple(site for site in sites if site.kind is capture.kind)
    if not matching_kind:
        return (
            IRLogicalMemoryFailureKind8616.ACCESS_KIND_CONFLICT,
            "raw operation kind does not match the typed capture kind",
        )
    addressed = tuple(site for site in matching_kind if site.address is not None)
    if not addressed:
        return (
            IRLogicalMemoryFailureKind8616.INVALID_ADDRESS,
            "matching raw operations have no typed address argument",
        )
    assert capture.address is not None
    matching_segment = tuple(
        site
        for site in addressed
        if site.address is not None and site.address.space is capture.address.space
    )
    if not matching_segment:
        return (
            IRLogicalMemoryFailureKind8616.SEGMENT_CONFLICT,
            "raw operation segment does not match the captured segment",
        )
    families = {
        (site.address.space, site.address.base)
        for site in matching_segment
        if site.address is not None
    }
    if capture.address.size > 1 and len(families) > 1:
        return (
            IRLogicalMemoryFailureKind8616.SEGMENT_CONFLICT,
            "raw byte operations disagree on segment/base identity",
        )
    return (
        IRLogicalMemoryFailureKind8616.BYTE_COVERAGE_CONFLICT,
        "raw operations do not provide one exact width and contiguous byte coverage",
    )


__all__ = [
    "LogicalMemoryExecutionCandidate8616",
    "RawLogicalMemorySite8616",
    "logical_memory_candidate_failure_8616",
    "logical_memory_execution_candidates_8616",
    "raw_logical_memory_sites_8616",
]
