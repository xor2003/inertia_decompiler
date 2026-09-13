"""Prove exact register-definition identity at a condition boundary.

Layer: Alias.
Responsibility: join decoded register writes over the complete function CFG,
retaining a definition only when it reaches the requested boundary on all paths.
No AST inspection, expression substitution, or rendered-code recovery belongs here.
Owns storage identity across register-definition joins.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from ..callsite_register_instruction_facts import DecodedInstructionFactSurface8616
from ..frontend_instruction_kinds import is_x86_16_call_mnemonic_8616
from ..register_source_block_inventory import RegisterSourceBlockInventory8616
from ..semantics.register_value_preservation import decoded_register_bit_effects_8616
from .register_reaching_source import (
    RegisterBlockTransfer8616,
    RegisterBlockTransferKind8616,
    RegisterReachingSourceResult8616,
    RegisterReachingSourceVerdict8616,
    resolve_register_reaching_source_8616,
)


@dataclass(frozen=True, slots=True)
class ConditionRegisterDefinition8616:
    """One exact definition address and the Alias join's evidence ledger."""

    instruction_addr: int | None
    evidence: RegisterReachingSourceResult8616


def _transfer_kind(
    instruction: DecodedInstructionFactSurface8616,
    register: str,
    size: int,
    candidate_addrs: frozenset[int],
) -> RegisterBlockTransferKind8616:
    """Refuse unknown/partial writes; calls need an explicit result candidate."""
    effects = decoded_register_bit_effects_8616(instruction, register)
    is_call = is_x86_16_call_mnemonic_8616(instruction.mnemonic.lower())
    full_write = effects is not None and effects[1] == (1 << (size * 8)) - 1
    represented_definition = instruction.address in candidate_addrs
    if represented_definition and (full_write or is_call):
        return RegisterBlockTransferKind8616.REPLACE
    if is_call or effects is None or effects[1]:
        return RegisterBlockTransferKind8616.KILL
    return RegisterBlockTransferKind8616.PRESERVE


def _result(evidence: RegisterReachingSourceResult8616) -> ConditionRegisterDefinition8616:
    """Expose the definition coordinate only for a proven Alias source."""
    source = evidence.source
    address = (
        source[1]
        if evidence.verdict is RegisterReachingSourceVerdict8616.PROVEN
        and source is not None
        else None
    )
    return ConditionRegisterDefinition8616(
        address if isinstance(address, int) else None,
        evidence,
    )


def resolve_condition_register_definition_8616(
    inventory: RegisterSourceBlockInventory8616,
    *,
    instruction_addr: int,
    register: str,
    size: int,
    candidate_addrs: frozenset[int],
) -> ConditionRegisterDefinition8616:
    """Resolve a represented full-register definition, never nearest address.

    Query prefixes are separate sinks. Original blocks retain their full effects,
    including writes after the query that can reach it on a later loop iteration.
    Unknown call effects and unrepresented writes conservatively kill identity.
    """
    refused = resolve_register_reaching_source_8616((), entry_addr=0, sink_addr=0)
    if not inventory.complete or size <= 0:
        return _result(refused)
    sink_addr = max(block.block_addr for block in inventory.blocks) + 1
    transfers: list[RegisterBlockTransfer8616] = []
    prefix: RegisterBlockTransfer8616 | None = None
    entry_addr = inventory.function_addr
    for block in inventory.blocks:
        kind = RegisterBlockTransferKind8616.PRESERVE
        source: tuple[object, ...] | None = None
        for instruction in cast(tuple[DecodedInstructionFactSurface8616, ...], block.instructions):
            if instruction.address == instruction_addr:
                if prefix is not None:
                    return _result(refused)
                prefix = RegisterBlockTransfer8616(sink_addr, block.predecessors, kind, source)
                if block.block_addr == inventory.function_addr:
                    # The first entry has unknown state even when a backedge exists.
                    entry_addr = sink_addr
            effect = _transfer_kind(instruction, register, size, candidate_addrs)
            if effect is RegisterBlockTransferKind8616.PRESERVE:
                continue
            kind = effect
            source = (
                ("definition", instruction.address)
                if kind is RegisterBlockTransferKind8616.REPLACE
                else None
            )
        transfers.append(RegisterBlockTransfer8616(block.block_addr, block.predecessors, kind, source))
    if prefix is None:
        return _result(refused)
    transfers.append(prefix)
    return _result(resolve_register_reaching_source_8616(
        tuple(transfers), entry_addr=entry_addr, sink_addr=sink_addr,
    ))
