"""Classify call clobbers that can reach typed stack-memory loads.

Layer: IR.
Responsibility: propagate Semantics-owned call effects through the function CFG
and identify exact stack ranges whose loads may observe an unproven call write.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
This module does not infer call effects, aliases, C variables, or types.
"""

from __future__ import annotations

from collections.abc import Mapping

from .core import IRAddress, IRCallStackEffect8616
from .ssa import SSABlock
from .ssa_memory_contracts import MemoryRangeKey8616
from .ssa_memory_ranges import memory_range_key_8616, stack_memory_access_8616

__all__ = ["call_clobbered_load_ranges_8616"]


def _call_clobber_cells_8616(
    ordered_blocks: tuple[SSABlock, ...],
    ordered_range_keys: tuple[MemoryRangeKey8616, ...],
    range_addresses: Mapping[MemoryRangeKey8616, IRAddress],
    cells_by_range: Mapping[
        MemoryRangeKey8616,
        tuple[MemoryRangeKey8616, ...],
    ],
) -> dict[tuple[int, int], frozenset[MemoryRangeKey8616]]:
    """Collect the cells each CALL may clobber, keyed by exact site."""
    call_clobbered_cells: dict[
        tuple[int, int],
        frozenset[MemoryRangeKey8616],
    ] = {}
    for block in ordered_blocks:
        for instruction_index, instruction in enumerate(block.instrs):
            if instruction.op != "CALL":
                continue
            effect = instruction.call_stack_effect or IRCallStackEffect8616()
            call_clobbered_cells[(block.addr, instruction_index)] = frozenset(
                cell
                for range_key in ordered_range_keys
                if not effect.preserves(range_addresses[range_key])
                for cell in cells_by_range[range_key]
            )
    return call_clobbered_cells


def _propagate_block_clobbers_8616(
    block: SSABlock,
    predecessor_map: Mapping[int, tuple[int, ...]],
    call_clobbered_cells: Mapping[
        tuple[int, int],
        frozenset[MemoryRangeKey8616],
    ],
    cells_by_range: Mapping[
        MemoryRangeKey8616,
        tuple[MemoryRangeKey8616, ...],
    ],
    range_addresses: Mapping[MemoryRangeKey8616, IRAddress],
    exit_clobbered_cells: dict[int, frozenset[MemoryRangeKey8616]],
    refused_ranges: set[MemoryRangeKey8616],
) -> bool:
    """Run one forward clobber transfer for a block; report any exit change."""
    current_cells: set[MemoryRangeKey8616] = set()
    for predecessor in predecessor_map.get(block.addr, ()):
        current_cells.update(exit_clobbered_cells.get(predecessor, ()))
    for instruction_index, instruction in enumerate(block.instrs):
        if instruction.op == "CALL":
            current_cells.update(
                call_clobbered_cells[(block.addr, instruction_index)]
            )
            continue
        address = stack_memory_access_8616(instruction)
        range_key = memory_range_key_8616(address) if address is not None else None
        if range_key is None or range_key not in range_addresses:
            continue
        cells = cells_by_range[range_key]
        if instruction.op == "STORE":
            current_cells.difference_update(cells)
        elif instruction.op == "LOAD" and any(
            cell in current_cells for cell in cells
        ):
            refused_ranges.add(range_key)
    current_exit = frozenset(current_cells)
    if exit_clobbered_cells[block.addr] == current_exit:
        return False
    exit_clobbered_cells[block.addr] = current_exit
    return True


def call_clobbered_load_ranges_8616(
    blocks: tuple[SSABlock, ...],
    predecessor_map: Mapping[int, tuple[int, ...]],
    range_addresses: Mapping[MemoryRangeKey8616, IRAddress],
    cells_by_range: Mapping[
        MemoryRangeKey8616,
        tuple[MemoryRangeKey8616, ...],
    ],
) -> frozenset[MemoryRangeKey8616]:
    """Return ranges with a possible call write reaching a subsequent load.

    An unproven call effect is an unknown memory definition, not a reason to
    reject unrelated lifetimes of the same stack slot. A complete store kills
    that definition. CFG joins union possible clobbers, and loop backedges are
    iterated to a fixed point so a call after a load can still affect the next
    iteration.
    """
    ordered_blocks = tuple(sorted(blocks, key=lambda item: item.addr))
    ordered_range_keys = tuple(sorted(range_addresses))
    call_clobbered_cells = _call_clobber_cells_8616(
        ordered_blocks,
        ordered_range_keys,
        range_addresses,
        cells_by_range,
    )

    exit_clobbered_cells: dict[int, frozenset[MemoryRangeKey8616]] = {
        block.addr: frozenset() for block in ordered_blocks
    }
    refused_ranges: set[MemoryRangeKey8616] = set()
    cell_count = len({cell for cells in cells_by_range.values() for cell in cells})
    iteration_limit = max(1, len(ordered_blocks) * max(1, cell_count) + 1)
    for _iteration in range(iteration_limit):
        changed = False
        for block in ordered_blocks:
            changed |= _propagate_block_clobbers_8616(
                block,
                predecessor_map,
                call_clobbered_cells,
                cells_by_range,
                range_addresses,
                exit_clobbered_cells,
                refused_ranges,
            )
        if not changed:
            break
    else:
        # A bounded fixed-point failure cannot justify retaining any range.
        refused_ranges.update(ordered_range_keys)
    return frozenset(refused_ranges)
