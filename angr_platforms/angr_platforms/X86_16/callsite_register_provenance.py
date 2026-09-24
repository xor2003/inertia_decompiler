"""Recover exact register sources at decoded instruction boundaries.

Layer: Recovery metadata.
Responsibility: collect decoded register-transfer facts and delegate cross-CFG
source identity to the Alias owner. Callsite recovery is a compatibility
consumer of the generic instruction-boundary proof.
Forbidden: source/COD/rendered-C inference or semantic materialization.
"""

from __future__ import annotations

from typing import Protocol, cast

from angr.errors import SimEngineError

from .alias.register_reaching_source import (
    RegisterBlockTransfer8616,
    RegisterBlockTransferKind8616,
    RegisterReachingSourceResult8616,
    callsite_source_reads_memory_8616,
    resolve_register_reaching_source_8616,
)
from .analysis_helpers import resolve_direct_call_target_from_instruction_8616
from .callsite_register_instruction_facts import (
    DecodedInstructionFactSurface8616,
    instruction_writes_memory_8616,
    instruction_writes_register_8616,
    register_replacement_source_8616,
    register_storage_snapshot_source_8616,
)
from .frontend_instruction_kinds import is_x86_16_call_mnemonic_8616
from .frontend_instruction_reachability import decoded_block_instructions_8616
from .register_source_block_inventory import (
    collect_register_source_block_inventory_8616,
)
from .semantics.call_register_effects import (
    SyntheticCallRegisterEffectVerdict8616,
    classify_synthetic_call_register_effect_8616,
)
from .semantics.register_value_preservation import (
    decoded_instruction_preserves_register_value_8616,
)
from .synthetic_call_stub_evidence import is_synthetic_call_stub_8616

__all__ = (
    "recover_callsite_register_source_8616",
    "recover_register_source_before_instruction_8616",
)


class _FunctionManager8616(Protocol):
    """Exact function lookup used for direct-callee proofs."""

    def function(self, *, addr: int, create: bool = False) -> object | None:
        """Return an existing function at ``addr``."""


class _KnowledgeBase8616(Protocol):
    """angr knowledge-base fields used by direct-callee proofs."""

    functions: _FunctionManager8616


class _Project8616(Protocol):
    """angr project fields consumed by register transfer collection."""

    kb: _KnowledgeBase8616


class _Function8616(Protocol):
    """angr function fields consumed by exact register-source recovery."""

    addr: int
    project: _Project8616


class _CalleeFunction8616(Protocol):
    """Direct-callee function block ownership used by leaf proofs."""

    block_addrs_set: set[int]


def _leaf_block_addrs_8616(
    project: _Project8616,
    target: int,
) -> tuple[int, ...] | None:
    """Resolve the callee's owned block set or the single direct target."""
    try:
        callee = project.kb.functions.function(addr=target, create=False)
    except (AttributeError, TypeError):
        callee = None
    if callee is None:
        return (target,)
    try:
        block_addrs = tuple(sorted(cast(_CalleeFunction8616, callee).block_addrs_set))
    except (AttributeError, TypeError):
        return None
    return block_addrs or (target,)


def _leaf_block_body_preserves_register_8616(
    instructions: tuple[DecodedInstructionFactSurface8616, ...],
    register: str,
) -> bool:
    """Require every pre-return instruction to leave ``register`` untouched."""
    for candidate in instructions[:-1]:
        mnemonic = candidate.mnemonic.lower()
        if is_x86_16_call_mnemonic_8616(mnemonic) or mnemonic.startswith(("j", "loop")):
            return False
        if instruction_writes_register_8616(candidate, register):
            return False
    return True


def _direct_leaf_call_preserves_register_8616(
    project: _Project8616,
    target: int | None,
    register: str,
) -> bool:
    """Prove a direct one-block leaf callee does not write ``register``.

    A direct target remains machine evidence when CFG function discovery omits
    its leaf stub. In that case decode the exact target as one basic block and
    retain the same terminal-return and no-write requirements.
    """
    if not isinstance(target, int):
        return False
    if is_synthetic_call_stub_8616(project, target):
        return False
    block_addrs = _leaf_block_addrs_8616(project, target)
    if block_addrs is None or len(block_addrs) != 1:
        return False
    try:
        instructions = decoded_block_instructions_8616(
            project,
            block_addrs[0],
            opt_level=0,
        )
    except (AttributeError, SimEngineError, TypeError, ValueError):
        return False
    if not instructions or instructions[-1].mnemonic.lower() not in {"ret", "retf", "retw"}:
        return False
    return _leaf_block_body_preserves_register_8616(instructions, register)


def _synthetic_call_preserves_register_8616(
    project: _Project8616,
    callsite_addr: int,
    target: int | None,
    register: str,
) -> bool:
    """Consume the registered MS C ABI only for an exact synthetic target."""
    effect = classify_synthetic_call_register_effect_8616(
        project,
        callsite_addr=callsite_addr,
        target_addr=target,
        register=register,
    )
    return (
        effect.closes_evidence
        and effect.verdict is SyntheticCallRegisterEffectVerdict8616.PRESERVED
    )


def _call_instruction_preserves_register_8616(
    project: _Project8616,
    instruction: DecodedInstructionFactSurface8616,
    register: str,
) -> bool:
    """Prove one call instruction leaves ``register`` intact."""
    target = resolve_direct_call_target_from_instruction_8616(
        project,
        instruction,
    )
    return _direct_leaf_call_preserves_register_8616(
        project,
        target,
        register,
    ) or _synthetic_call_preserves_register_8616(
        project,
        instruction.address,
        target,
        register,
    )


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
    project: _Project8616,
    instructions: tuple[DecodedInstructionFactSurface8616, ...],
    register: str,
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
            if not _call_instruction_preserves_register_8616(project, instruction, register):
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
