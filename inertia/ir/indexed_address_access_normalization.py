"""Normalize frontend memory micro-operations to indexed machine accesses.

Layer: IR.
Responsibility: owns typed Value, Address, Condition, instruction facts, and lossless
normalization. This module groups only exact same-instruction byte accesses.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from .core import IRAddress, IRInstr, MemSpace
from .indexed_address_contracts import IndexedAddressFailureKind8616
from .ssa_function import SSAFunctionArtifact

__all__ = [
    "IndexedAddressAccessNormalization8616",
    "NormalizedIndexedAddressAccess8616",
    "normalize_indexed_address_accesses_8616",
]


@dataclass(frozen=True, slots=True)
class NormalizedIndexedAddressAccess8616:
    """One indexed machine access or one exact normalization refusal."""

    block_addr: int
    instr_index: int
    instr_addr: int
    op: str
    address: IRAddress
    access_size: int
    raw_fact_count: int
    member_instr_indices: tuple[int, ...]
    failure: IndexedAddressFailureKind8616 | None = None

    @property
    def complete(self) -> bool:
        """Return whether this record owns one nonempty raw access group."""
        return bool(
            self.block_addr >= 0
            and self.instr_index >= 0
            and self.instr_addr >= 0
            and self.op in {"LOAD", "STORE"}
            and self.address.space in {MemSpace.DS, MemSpace.ES}
            and self.address.base
            and self.access_size > 0
            and self.raw_fact_count > 0
            and len(self.member_instr_indices) == self.raw_fact_count
            and self.member_instr_indices == tuple(sorted(set(self.member_instr_indices)))
            and self.instr_index in self.member_instr_indices
        )


@dataclass(frozen=True, slots=True)
class IndexedAddressAccessNormalization8616:
    """Closed raw-to-machine indexed access normalization artifact."""

    accesses: tuple[NormalizedIndexedAddressAccess8616, ...]
    raw_fact_count: int
    normalized_fact_count: int
    coalesced_fact_count: int

    @property
    def closed(self) -> bool:
        """Return whether every raw micro-operation has one grouped owner."""
        return bool(
            self.raw_fact_count
            == self.normalized_fact_count + self.coalesced_fact_count
            and self.normalized_fact_count == len(self.accesses)
            and all(access.complete for access in self.accesses)
        )


def _indexed_address_8616(instruction: IRInstr) -> IRAddress | None:
    """Return the indexed DS/ES address carried by one IR memory operation."""
    address = instruction.args[0] if instruction.args else None
    if (
        instruction.op not in {"LOAD", "STORE"}
        or instruction.addr is None
        or not isinstance(address, IRAddress)
        or address.space not in {MemSpace.DS, MemSpace.ES}
        or not address.base
    ):
        return None
    return address


def _base_value_key_8616(address: IRAddress) -> tuple[tuple[object, ...], ...]:
    """Return a hashable exact identity for dynamic address terms."""
    return tuple(
        (
            value.space,
            value.name,
            value.offset,
            value.size,
            value.version,
            value.source_tmp,
        )
        for value in address.base_values
    )


def _group_key_8616(instruction: IRInstr, address: IRAddress) -> tuple[object, ...]:
    """Return the machine-site and segmented-base identity for one micro-op."""
    return (
        instruction.addr,
        instruction.op,
        address.space,
        address.base,
        _base_value_key_8616(address),
        address.status,
        address.segment_origin,
    )


def _exact_little_endian_pair_8616(
    entries: tuple[tuple[int, IRInstr, IRAddress], ...],
) -> tuple[int, IRInstr, IRAddress] | None:
    """Return the low-byte entry for one exact contiguous word micro-op pair."""
    if len(entries) != 2:
        return None
    ordered = tuple(sorted(entries, key=lambda item: (item[2].offset, item[0])))
    low, high = ordered
    # Truncating VEX store micro-ops retain the source carrier width in legacy
    # IR. Exact same-instruction adjacency, not that carrier width, proves the
    # pair owns one little-endian 16-bit machine access.
    if (
        low[1].size != low[2].size
        or high[1].size != high[2].size
        or low[1].size != high[1].size
        or low[1].size not in {1, 2}
        or high[2].offset != low[2].offset + 1
    ):
        return None
    return low


def _normalize_group_8616(
    block_addr: int,
    entries: tuple[tuple[int, IRInstr, IRAddress], ...],
) -> NormalizedIndexedAddressAccess8616:
    """Normalize one exact machine-site group or retain a typed refusal."""
    first_index, first_instruction, first_address = min(entries, key=lambda item: item[0])
    instr_addr = first_instruction.addr
    if instr_addr is None or any(item[1].addr != instr_addr for item in entries):
        raise ValueError("indexed-address group requires one known machine instruction")
    if len(entries) == 1:
        return NormalizedIndexedAddressAccess8616(
            block_addr,
            first_index,
            instr_addr,
            first_instruction.op,
            first_address,
            first_instruction.size,
            1,
            (first_index,),
        )
    low = _exact_little_endian_pair_8616(entries)
    if low is not None:
        low_index, low_instruction, low_address = low
        return NormalizedIndexedAddressAccess8616(
            block_addr,
            low_index,
            instr_addr,
            low_instruction.op,
            replace(low_address, size=2),
            2,
            len(entries),
            tuple(sorted(item[0] for item in entries)),
        )
    return NormalizedIndexedAddressAccess8616(
        block_addr,
        first_index,
        instr_addr,
        first_instruction.op,
        first_address,
        first_instruction.size,
        len(entries),
        tuple(sorted(item[0] for item in entries)),
        IndexedAddressFailureKind8616.ACCESS_MICRO_OP_CONFLICT,
    )


def normalize_indexed_address_accesses_8616(
    artifact: SSAFunctionArtifact,
) -> IndexedAddressAccessNormalization8616:
    """Group exact indexed frontend micro-operations by machine instruction."""
    accesses: list[NormalizedIndexedAddressAccess8616] = []
    raw_count = 0
    for block in sorted(artifact.blocks, key=lambda item: item.addr):
        groups: dict[tuple[object, ...], list[tuple[int, IRInstr, IRAddress]]] = {}
        for instr_index, instruction in enumerate(block.instrs):
            address = _indexed_address_8616(instruction)
            if address is None:
                continue
            raw_count += 1
            groups.setdefault(_group_key_8616(instruction, address), []).append(
                (instr_index, instruction, address)
            )
        accesses.extend(
            _normalize_group_8616(block.addr, tuple(entries))
            for entries in groups.values()
        )
    ordered = tuple(sorted(accesses, key=lambda item: (item.block_addr, item.instr_index)))
    result = IndexedAddressAccessNormalization8616(
        ordered,
        raw_count,
        len(ordered),
        raw_count - len(ordered),
    )
    if not result.closed:
        raise ValueError("indexed-address micro-op normalization did not close")
    return result
