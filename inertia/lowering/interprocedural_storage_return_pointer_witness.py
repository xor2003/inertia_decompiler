"""Select the exact caller use that witnesses a pointer return trial.

Layer: Types/Lowering.
Responsibility: project complete register-alias or Alias-versioned stack-spill
pointer evidence to one physical return-use site. It does not classify pointer
semantics, inspect generated C, or repair calls and signatures.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from inertia.semantics.caller_return_use_contracts import CallerReturnUseFact8616

from inertia.alias.domains import register_domain_for_name, register_view_for_name
from inertia.ir.core import IRValue, MemSpace
from inertia.ir.logical_memory_register_transfer_contracts import LogicalMemoryRegisterTransferKind8616
from inertia.ir.ssa_function import SSAFunctionArtifact

from .interprocedural_storage_contracts import StorageIdentity8616, StorageUseEvidence8616
from .interprocedural_storage_return_type_contracts import ReturnPointerUseEvidence8616


def _register_matches_output_8616(
    value: IRValue,
    output_storages: tuple[StorageIdentity8616, ...],
) -> bool:
    """Return whether one exact register is an output storage view."""
    return value.space is MemSpace.REG and any(
        value.size == storage.width
        and register_domain_for_name(value.name)
        == register_domain_for_name(storage.register)
        and register_view_for_name(value.name)
        == register_view_for_name(storage.register)
        for storage in output_storages
    )


def pointer_return_witness_use_8616(
    artifact: SSAFunctionArtifact,
    fact: CallerReturnUseFact8616,
    pointer_use: ReturnPointerUseEvidence8616,
    output_storages: tuple[StorageIdentity8616, ...],
) -> tuple[tuple[StorageUseEvidence8616, ...] | None, bool]:
    """Select one exact register alias or stack-spill witness site."""
    aliases = tuple(
        step
        for step in pointer_use.aliases
        if step.instr_addr == fact.witness_instruction_addr
    )
    if len(aliases) == 1:
        alias = aliases[0]
        return (
            (
                StorageUseEvidence8616(
                    block_addr=alias.block_addr,
                    instr_index=alias.instr_index,
                    instr_addr=alias.instr_addr,
                    callsite_addr=fact.callsite_addr,
                ),
            ),
            False,
        )
    if aliases:
        return None, True

    spills = tuple(
        transfer
        for transfer in pointer_use.stack_transfers
        if transfer.source.kind is LogicalMemoryRegisterTransferKind8616.SPILL
        and transfer.source.register_site.instr_addr == fact.witness_instruction_addr
        and _register_matches_output_8616(
            transfer.source.register,
            output_storages,
        )
    )
    if len(spills) != 1:
        return None, bool(spills)
    site = spills[0].source.register_site
    if not 0 <= site.instr_index < len(
        next(
            (block.instrs for block in artifact.blocks if block.addr == site.block_addr),
            (),
        )
    ):
        return None, True
    return (
        (
            StorageUseEvidence8616(
                block_addr=site.block_addr,
                instr_index=site.instr_index,
                instr_addr=site.instr_addr,
                callsite_addr=fact.callsite_addr,
            ),
        ),
        False,
    )


__all__ = ["pointer_return_witness_use_8616"]
