"""Prepare and join Alias-versioned stack carriers for pointer flow.

Layer: Types/Lowering.
Responsibility: consume the authoritative Alias and Widening artifacts, index
proven word/register transfers, and retain only identical stack carriers on
every CFG predecessor. It does not trace byte values or infer storage identity.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass

from inertia.alias.stack_memory_ssa import build_x86_16_stack_memory_ssa_alias_artifact
from inertia.ir.ssa_function import SSAFunctionArtifact
from inertia.widening.stack_word_register_transfers import (
    StackWordRegisterTransfer8616,
    StackWordStorageVersion8616,
    build_stack_word_register_transfer_artifact_8616,
)

from .interprocedural_storage_return_pointer_block import PointerCarrier8616


@dataclass(frozen=True, slots=True)
class PointerStackTransferContext8616:
    """Indexed stack/register transfers and their closed-evidence status."""

    by_instruction_addr: dict[int, tuple[StackWordRegisterTransfer8616, ...]]
    complete: bool


def build_pointer_stack_transfer_context_8616(
    artifact: SSAFunctionArtifact,
) -> PointerStackTransferContext8616:
    """Build exact Alias then Widening evidence for one caller SSA artifact."""
    alias = build_x86_16_stack_memory_ssa_alias_artifact(artifact)
    widened = build_stack_word_register_transfer_artifact_8616(alias)
    return PointerStackTransferContext8616(
        widened.by_instruction_addr(),
        widened.complete,
    )


def join_pointer_stack_carriers_8616(
    predecessors: tuple[int, ...],
    outputs: dict[int, dict[StackWordStorageVersion8616, PointerCarrier8616]],
) -> tuple[dict[StackWordStorageVersion8616, PointerCarrier8616], bool]:
    """Join only exact stack carriers present unchanged on every predecessor."""
    if not predecessors or any(predecessor not in outputs for predecessor in predecessors):
        return {}, True
    key_sets = tuple(set(outputs[predecessor]) for predecessor in predecessors)
    common = set.intersection(*key_sets)
    conflict = bool(set.union(*key_sets) - common)
    joined: dict[StackWordStorageVersion8616, PointerCarrier8616] = {}
    for key in sorted(
        common,
        key=lambda item: (repr(item.storage.identity), item.versions),
    ):
        carriers = tuple(outputs[predecessor][key] for predecessor in predecessors)
        if any(carrier != carriers[0] for carrier in carriers[1:]):
            conflict = True
            continue
        joined[key] = carriers[0]
    return joined, conflict


__all__ = [
    "PointerStackTransferContext8616",
    "build_pointer_stack_transfer_context_8616",
    "join_pointer_stack_carriers_8616",
]
