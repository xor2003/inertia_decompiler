"""Build function-level SSA for exact segmented stack-memory ranges.

Layer: IR.
Responsibility: version proven `SS:BP+offset` loads/stores and create memory
phi inputs without naming locals or inferring C types.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import replace

from .core import IRAddress, IRAtom, IRCallStackEffect8616, IRCondition, IRInstr, IRRefusal
from .logical_memory_contracts import IRLogicalMemoryArtifact8616
from .ssa import SSABlock
from .ssa_memory_call_liveness import call_clobbered_load_ranges_8616
from .ssa_memory_contracts import (
    MemoryRangeKey8616,
    SSACallStackEffectSite8616,
    SSAFunctionMemoryResult8616,
    SSAMemoryAccess8616,
    SSAMemoryAccessKind8616,
    SSAMemoryAccessSlice8616,
    SSAMemoryBinding8616,
    SSAMemoryIncomingValue8616,
    SSAMemoryPhiNode8616,
    SSAMemoryStats8616,
)
from .ssa_memory_ranges import (
    StackCoordinateAgreement8616,
    build_stack_memory_cell_layout_8616,
    close_refused_stack_ranges_8616,
    collect_stack_memory_accesses_8616,
    memory_range_key_8616,
    stack_coordinate_agreement_8616,
    stack_memory_access_8616,
    versioned_memory_address_8616,
)

__all__ = ["build_x86_16_function_memory_ssa"]


def _rewrite_atom_8616(
    atom: IRAtom,
    versions: dict[MemoryRangeKey8616, int],
    accepted_ranges: frozenset[MemoryRangeKey8616],
    cells_by_range: dict[MemoryRangeKey8616, tuple[MemoryRangeKey8616, ...]],
) -> IRAtom:
    """Rewrite a one-cell memory atom to its reaching version."""
    if isinstance(atom, IRCondition):
        return IRCondition(
            op=atom.op,
            args=tuple(
                _rewrite_atom_8616(item, versions, accepted_ranges, cells_by_range)
                for item in atom.args
            ),
            expr=atom.expr,
            width_bits=atom.width_bits,
        )
    if not isinstance(atom, IRAddress):
        return atom
    key = memory_range_key_8616(atom)
    if key not in accepted_ranges:
        return atom
    cells = cells_by_range[key]
    return (
        versioned_memory_address_8616(atom, versions[cells[0]])
        if len(cells) == 1
        else atom
    )


def build_x86_16_function_memory_ssa(
    function_addr: int,
    blocks: tuple[SSABlock, ...],
    predecessor_map: dict[int, tuple[int, ...]],
    logical_memory: IRLogicalMemoryArtifact8616 | None = None,
) -> SSAFunctionMemoryResult8616:
    """Version canonical stack cells and join reaching definitions to a fixed point."""
    if logical_memory is not None and (
        logical_memory.function_addr != function_addr or not logical_memory.closed
    ):
        raise ValueError("memory SSA requires closed function-owned logical memory")
    accesses = collect_stack_memory_accesses_8616(blocks)
    coordinate_conflict = stack_coordinate_agreement_8616(blocks) is StackCoordinateAgreement8616.CONFLICT
    layout = build_stack_memory_cell_layout_8616(() if coordinate_conflict else accesses)
    range_addresses = {item.key: item.address for item in layout.ranges}
    cells_by_range = {
        item.key: tuple((cell.space.value, cell.base, cell.offset, cell.size) for cell in item.cells)
        for item in layout.ranges
    }
    cell_addresses = {
        (cell.space.value, cell.base, cell.offset, cell.size): cell for cell in layout.cells
    }
    call_effects = tuple(
        SSACallStackEffectSite8616(
            block.addr,
            instr_index,
            instruction.addr,
            instruction.call_stack_effect or IRCallStackEffect8616(),
        )
        for block in sorted(blocks, key=lambda item: item.addr)
        for instr_index, instruction in enumerate(block.instrs)
        if instruction.op == "CALL"
    )
    call_refused_ranges = call_clobbered_load_ranges_8616(
        blocks,
        predecessor_map,
        range_addresses,
        cells_by_range,
    )
    refused_ranges = close_refused_stack_ranges_8616(
        set(range_addresses) if not layout.complete else set(call_refused_ranges),
        cells_by_range,
    )
    refusals = tuple(
        IRRefusal(
            kind=(
                StackCoordinateAgreement8616.CONFLICT
                if coordinate_conflict and memory_range_key_8616(address) is not None
                else
                "stack_memory_cell_layout_incomplete"
                if not layout.complete and memory_range_key_8616(address) is not None
                else "unknown_call_stack_effect"
                if memory_range_key_8616(address) in refused_ranges
                else "unproven_stack_range"
            ),
            detail=f"refused SS range base={address.base!r} offset={address.offset} size={address.size}",
            block_addr=block_addr,
        )
        for block_addr, _index, address in accesses
        if memory_range_key_8616(address) is None
        or memory_range_key_8616(address) not in range_addresses
        or memory_range_key_8616(address) in refused_ranges
    )
    accepted_ranges = frozenset(key for key in range_addresses if key not in refused_ranges)
    accepted_cells = tuple(
        sorted(
            {
                cell_key
                for key in accepted_ranges
                for cell_key in cells_by_range[key]
            }
        )
    )
    store_versions: dict[tuple[int, int, MemoryRangeKey8616], int] = {}
    next_version = 1
    for block in sorted(blocks, key=lambda item: item.addr):
        for index, instruction in enumerate(block.instrs):
            address = stack_memory_access_8616(instruction)
            key = memory_range_key_8616(address) if address is not None else None
            if instruction.op == "STORE" and key in accepted_ranges:
                for cell_key in cells_by_range[key]:
                    store_versions[(block.addr, index, cell_key)] = next_version
                    next_version += 1

    join_keys = tuple(
        (block_addr, cell_key)
        for block_addr, predecessors in sorted(predecessor_map.items())
        if len(predecessors) > 1
        for cell_key in accepted_cells
    )
    phi_versions = {item: next_version + index for index, item in enumerate(join_keys)}
    entry_versions = {
        (block.addr, cell_key): 0 for block in blocks for cell_key in accepted_cells
    }
    exit_versions = dict(entry_versions)
    last_store = {
        (block.addr, cell_key): max(
            (
                version
                for (store_block, _index, store_cell), version in store_versions.items()
                if store_block == block.addr and store_cell == cell_key
            ),
            default=0,
        )
        for block in blocks
        for cell_key in accepted_cells
    }
    iteration_limit = max(1, len(blocks) * max(1, len(accepted_cells)) + 1)
    for _iteration in range(iteration_limit):
        changed = False
        for block in sorted(blocks, key=lambda item: item.addr):
            for cell_key in accepted_cells:
                predecessor_versions = {
                    exit_versions[(predecessor, cell_key)]
                    for predecessor in predecessor_map.get(block.addr, ())
                    if (predecessor, cell_key) in exit_versions
                }
                entry = (
                    0
                    if not predecessor_versions
                    else next(iter(predecessor_versions))
                    if len(predecessor_versions) == 1
                    else phi_versions[(block.addr, cell_key)]
                )
                exit_version = last_store[(block.addr, cell_key)] or entry
                if (
                    entry_versions[(block.addr, cell_key)] != entry
                    or exit_versions[(block.addr, cell_key)] != exit_version
                ):
                    entry_versions[(block.addr, cell_key)] = entry
                    exit_versions[(block.addr, cell_key)] = exit_version
                    changed = True
        if not changed:
            break
    else:
        iteration_refusals = tuple(
            IRRefusal(
                kind="stack_memory_ssa_iteration_limit",
                detail=(
                    "stack-memory SSA did not reach its deterministic fixed point; "
                    f"refused SS range base={address.base!r} offset={address.offset} size={address.size}"
                ),
                block_addr=block_addr,
            )
            for block_addr, _index, address in accesses
            if memory_range_key_8616(address) in accepted_ranges
        )
        return SSAFunctionMemoryResult8616(
            blocks=blocks,
            bindings=(),
            phi_nodes=(),
            refusals=refusals + iteration_refusals,
            stats=SSAMemoryStats8616(
                raw_fact_count=len(accesses) + len(layout.overlaps),
                normalized_fact_count=len(layout.overlaps),
                classified_fact_count=len(layout.overlaps),
                materialized_count=len(layout.overlaps),
                failure_count=len(accesses),
            ),
            overlaps=layout.overlaps,
            call_effects=call_effects,
            logical_memory=logical_memory,
        )

    bindings: list[SSAMemoryBinding8616] = []
    versioned_accesses: list[SSAMemoryAccess8616] = []
    rewritten_blocks: list[SSABlock] = []
    materialized_count = len(layout.overlaps)
    for block in sorted(blocks, key=lambda item: item.addr):
        current = {
            cell_key: entry_versions[(block.addr, cell_key)] for cell_key in accepted_cells
        }
        rewritten_instrs: list[IRInstr] = []
        for index, instruction in enumerate(block.instrs):
            args = tuple(
                _rewrite_atom_8616(atom, current, accepted_ranges, cells_by_range)
                for atom in instruction.args
            )
            address = stack_memory_access_8616(instruction)
            key = memory_range_key_8616(address) if address is not None else None
            if key is not None and address is not None and key in accepted_ranges:
                materialized_count += 1
                cell_keys = cells_by_range[key]
                if instruction.op == "STORE":
                    for cell_key in cell_keys:
                        current[cell_key] = store_versions[(block.addr, index, cell_key)]
                slices = tuple(
                    SSAMemoryAccessSlice8616(
                        cell_addresses[cell_key].offset - address.offset,
                        versioned_memory_address_8616(
                            cell_addresses[cell_key], current[cell_key]
                        ),
                    )
                    for cell_key in cell_keys
                )
                access = SSAMemoryAccess8616(
                    SSAMemoryAccessKind8616.STORE
                    if instruction.op == "STORE"
                    else SSAMemoryAccessKind8616.LOAD,
                    block.addr,
                    index,
                    address,
                    slices,
                )
                if not access.complete:
                    raise RuntimeError("stack-memory SSA produced an incomplete byte view")
                versioned_accesses.append(access)
                if len(slices) == 1:
                    args = (versioned_memory_address_8616(address, current[cell_keys[0]]), *args[1:])
                if instruction.op == "STORE":
                    bindings.extend(
                        SSAMemoryBinding8616(block.addr, index, item.address)
                        for item in slices
                    )
            rewritten_instrs.append(
                replace(instruction, args=args)
            )
        rewritten_blocks.append(
            SSABlock(
                addr=block.addr,
                instrs=tuple(rewritten_instrs),
                bindings=block.bindings,
                refusals=block.refusals,
            )
        )

    phi_nodes = tuple(
        SSAMemoryPhiNode8616(
            block_addr=block_addr,
            key=cell_key,
            target=versioned_memory_address_8616(
                cell_addresses[cell_key], phi_versions[(block_addr, cell_key)]
            ),
            incoming=tuple(
                SSAMemoryIncomingValue8616(
                    predecessor,
                    versioned_memory_address_8616(
                        cell_addresses[cell_key], exit_versions[(predecessor, cell_key)]
                    ),
                )
                for predecessor in predecessor_map[block_addr]
            ),
        )
        for block_addr, cell_key in join_keys
        if len(
            {
                exit_versions[(predecessor, cell_key)]
                for predecessor in predecessor_map[block_addr]
            }
        )
        > 1
    )
    return SSAFunctionMemoryResult8616(
        blocks=tuple(rewritten_blocks),
        bindings=tuple(bindings),
        phi_nodes=phi_nodes,
        refusals=refusals,
        stats=SSAMemoryStats8616(
            raw_fact_count=len(accesses) + len(layout.overlaps),
            normalized_fact_count=materialized_count,
            classified_fact_count=materialized_count,
            materialized_count=materialized_count,
            failure_count=len(refusals),
        ),
        overlaps=layout.overlaps,
        accesses=tuple(versioned_accesses),
        call_effects=call_effects,
        logical_memory=logical_memory,
    )
