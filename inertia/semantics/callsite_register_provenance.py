"""Recover exact register sources at decoded instruction boundaries.

Layer: Recovery metadata.
Responsibility: collect decoded register-transfer facts and delegate cross-CFG
source identity to the Alias owner. Callsite recovery is a compatibility
consumer of the generic instruction-boundary proof.
Forbidden: source/COD/rendered-C inference or semantic materialization.

Package ownership contract (canonical inertia/semantics package):
Layer: Semantics.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from typing import Protocol, cast

from inertia.alias.call_register_roles import call_role_preserves_register_8616
from inertia.alias.register_reaching_source import (
    RegisterBlockTransfer8616,
    RegisterBlockTransferKind8616,
    RegisterReachingSourceResult8616,
    callsite_source_reads_memory_8616,
    resolve_register_reaching_source_8616,
)
from inertia.frontend.x86_16.frontend_instruction_kinds import is_x86_16_call_mnemonic_8616
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from inertia.semantics.call_register_roles import (
    build_callsite_register_role_fact_8616,
)
from inertia.semantics.register_value_preservation import (
    decoded_instruction_preserves_register_value_8616,
)

from .callsite_register_instruction_facts import (
    DecodedInstructionFactSurface8616,
    instruction_writes_memory_8616,
    instruction_writes_register_8616,
    register_replacement_source_8616,
    register_storage_snapshot_source_8616,
)
from .register_source_block_inventory import (
    RegisterSourceBlockInventory8616,
    collect_register_source_block_inventory_8616,
)

__all__ = (
    "recover_callsite_register_source_8616",
    "recover_register_source_before_instruction_8616",
)


class _Function8616(Protocol):
    """angr function fields consumed by exact register-source recovery."""

    addr: int
    project: object


def _call_instruction_preserves_register_8616(
    project: object,
    instruction: DecodedInstructionFactSurface8616,
    register: str,
    caller_inventory: RegisterSourceBlockInventory8616 | None,
) -> bool:
    """Prove one call instruction leaves ``register`` intact.

    The decision delegates to the canonical Alias consumer over the exact
    call register-role fact: complete may-clobber evidence may preserve a
    register; unknown, refused or spoiled bits always kill. Caller-dead,
    input and result roles never stand in for preservation.
    """
    try:
        callsite_addr = instruction.address
    except AttributeError:
        callsite_addr = None
    if not isinstance(callsite_addr, int) or isinstance(callsite_addr, bool):
        callsite_addr = None
    target = resolve_direct_call_target_from_instruction_8616(
        project,
        instruction,
    )
    fact = build_callsite_register_role_fact_8616(
        project,
        callsite_addr=callsite_addr,
        target_addr=target,
        caller_inventory=caller_inventory,
    )
    return call_role_preserves_register_8616(fact, register)


def _register_write_transfer_8616(
    instruction: DecodedInstructionFactSurface8616,
    register: str,
) -> tuple[RegisterBlockTransferKind8616, tuple[object, ...] | None] | None:
    """Classify one non-call register write as replace, kill, or untouched."""
    if not instruction_writes_register_8616(instruction, register):
        return None
    if decoded_instruction_preserves_register_value_8616(instruction, register):
        return None
    replacement = register_replacement_source_8616(instruction, register)
    if replacement is None:
        return RegisterBlockTransferKind8616.KILL, None
    return RegisterBlockTransferKind8616.REPLACE, replacement


def _block_transfer_8616(
    project: object,
    instructions: tuple[DecodedInstructionFactSurface8616, ...],
    register: str,
    caller_inventory: RegisterSourceBlockInventory8616 | None = None,
) -> tuple[RegisterBlockTransferKind8616, tuple[object, ...] | None, bool]:
    """Collect one ordered block-prefix transfer from decoded instructions."""
    kind = RegisterBlockTransferKind8616.PRESERVE
    source: tuple[object, ...] | None = None
    clobbers_memory_sources = False
    for instruction in instructions:
        mnemonic = instruction.mnemonic.lower()
        writes_memory = instruction_writes_memory_8616(instruction) or is_x86_16_call_mnemonic_8616(mnemonic)
        if writes_memory:
            if kind is RegisterBlockTransferKind8616.REPLACE and callsite_source_reads_memory_8616(source):
                kind = RegisterBlockTransferKind8616.KILL
                source = None
            elif kind is RegisterBlockTransferKind8616.PRESERVE:
                clobbers_memory_sources = True
        storage_source = register_storage_snapshot_source_8616(instruction, register)
        if storage_source is not None:
            kind = RegisterBlockTransferKind8616.REPLACE
            source = storage_source
            clobbers_memory_sources = False
            continue
        if is_x86_16_call_mnemonic_8616(mnemonic):
            if not _call_instruction_preserves_register_8616(
                project, instruction, register, caller_inventory
            ):
                kind = RegisterBlockTransferKind8616.KILL
                source = None
                clobbers_memory_sources = False
            continue
        write_transfer = _register_write_transfer_8616(instruction, register)
        if write_transfer is None:
            continue
        kind, source = write_transfer
        clobbers_memory_sources = False
    return kind, source, clobbers_memory_sources


def recover_register_source_before_instruction_8616(
    function: object,
    *,
    instruction_addr: int,
    register: str,
) -> RegisterReachingSourceResult8616:
    """Prove one register source reaches an exact instruction on every path."""
    boundary = cast(_Function8616, function)
    try:
        project = boundary.project
        entry_addr = boundary.addr
    except (AttributeError, TypeError):
        return resolve_register_reaching_source_8616((), entry_addr=0, sink_addr=0)
    inventory = collect_register_source_block_inventory_8616(function)
    if not inventory.complete or inventory.function_addr != entry_addr:
        return resolve_register_reaching_source_8616(
            (),
            entry_addr=entry_addr,
            sink_addr=0,
        )
    transfers: list[RegisterBlockTransfer8616] = []
    sink_addr: int | None = None
    for block in inventory.blocks:
        prefix: list[DecodedInstructionFactSurface8616] = []
        for instruction in cast(tuple[DecodedInstructionFactSurface8616, ...], block.instructions):
            if instruction.address == instruction_addr:
                if sink_addr is not None:
                    return resolve_register_reaching_source_8616(
                        (),
                        entry_addr=entry_addr,
                        sink_addr=0,
                    )
                sink_addr = block.block_addr
                break
            prefix.append(instruction)
        kind, source, clobbers_memory_sources = _block_transfer_8616(
            project,
            tuple(prefix),
            register,
            caller_inventory=inventory,
        )
        transfers.append(
            RegisterBlockTransfer8616(
                block.block_addr,
                block.predecessors,
                kind,
                source,
                clobbers_memory_sources,
            )
        )
    if sink_addr is None:
        return resolve_register_reaching_source_8616((), entry_addr=entry_addr, sink_addr=0)
    return resolve_register_reaching_source_8616(
        tuple(transfers),
        entry_addr=entry_addr,
        sink_addr=sink_addr,
    )


def recover_callsite_register_source_8616(
    function: object,
    *,
    push_instruction_addr: int,
    register: str,
) -> RegisterReachingSourceResult8616:
    """Prove one register source reaches an exact argument PUSH on every path."""
    return recover_register_source_before_instruction_8616(
        function,
        instruction_addr=push_instruction_addr,
        register=register,
    )
