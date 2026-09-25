"""Prove register values transferred by logical word memory operands.

Layer: IR.
Responsibility: trace one closed 16-bit logical read or write through exact
byte-lane SSA definitions to one full-word register value. The proof retains
machine and SSA sites and refuses transformed, incomplete, or ambiguous paths.
Owns typed Value and instruction facts only; Alias owns storage identity and
Widening binds these value proofs to versioned storage.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass

from .core import IRAddress, IRInstr, IRValue, MemSpace
from .indexed_address_contracts import IndexedAddressDefinitionSite8616
from .logical_memory_contracts import IRLogicalMemoryAccess8616, IRMemoryAccessKind8616
from .logical_memory_register_transfer_contracts import (
    LogicalMemoryRegisterTransfer8616,
    LogicalMemoryRegisterTransferFailure8616,
    LogicalMemoryRegisterTransferKind8616,
    LogicalMemoryRegisterTransferRefusal8616,
)
from .logical_memory_value_trace import trace_logical_word_load_8616
from .scalar_definitions import (
    ScalarDefinition8616,
    ScalarDefinitionIndex8616,
    build_scalar_definition_index_8616,
    reaching_scalar_definitions_8616,
)
from .ssa_function import SSAFunctionArtifact


@dataclass(frozen=True, slots=True)
class _LaneTrace8616:
    """Internal byte-lane path to one full-word register root."""

    register: IRValue | None
    path: tuple[IndexedAddressDefinitionSite8616, ...]
    saw_extract: bool
    saw_shift: bool
    failure: LogicalMemoryRegisterTransferFailure8616 | None = None


def _site_8616(definition: ScalarDefinition8616) -> IndexedAddressDefinitionSite8616 | None:
    """Return the exact site for one scalar definition."""
    instruction = definition.instruction
    if instruction.addr is None:
        return None
    return IndexedAddressDefinitionSite8616(
        definition.block_addr,
        definition.instr_index,
        instruction.addr,
        instruction.op,
    )


def _unique_definition_8616(
    definitions: ScalarDefinitionIndex8616,
    value: IRValue,
    *,
    block_addr: int,
    before_index: int,
) -> tuple[ScalarDefinition8616 | None, LogicalMemoryRegisterTransferFailure8616 | None]:
    """Resolve one exact preceding same-block scalar definition."""
    candidates = reaching_scalar_definitions_8616(
        definitions,
        value,
        block_addr=block_addr,
        before_index=before_index,
    )
    if not candidates:
        return None, LogicalMemoryRegisterTransferFailure8616.VALUE_DEFINITION_MISSING
    if len(candidates) != 1:
        return None, LogicalMemoryRegisterTransferFailure8616.VALUE_DEFINITION_CONFLICT
    return candidates[0], None


def _trace_store_lane_8616(
    value: IRValue,
    definitions: ScalarDefinitionIndex8616,
    *,
    block_addr: int,
    before_index: int,
    saw_extract: bool = False,
    saw_shift: bool = False,
    path: tuple[IndexedAddressDefinitionSite8616, ...] = (),
    depth: int = 0,
) -> _LaneTrace8616:
    """Trace one stored byte through exact truncation and high-byte shift."""
    if depth > 16:
        return _LaneTrace8616(
            None,
            path,
            saw_extract,
            saw_shift,
            LogicalMemoryRegisterTransferFailure8616.VALUE_DEFINITION_CONFLICT,
        )
    definition, failure = _unique_definition_8616(
        definitions,
        value,
        block_addr=block_addr,
        before_index=before_index,
    )
    if definition is None:
        return _LaneTrace8616(None, path, saw_extract, saw_shift, failure)
    site = _site_8616(definition)
    instruction = definition.instruction
    if site is None:
        return _LaneTrace8616(
            None,
            path,
            saw_extract,
            saw_shift,
            LogicalMemoryRegisterTransferFailure8616.EXECUTION_SITE_CONFLICT,
        )
    next_path = (*path, site)
    if instruction.op == "MOV" and len(instruction.args) == 1:
        source = instruction.args[0]
        destination = instruction.dst
        if not isinstance(source, IRValue) or destination is None:
            return _LaneTrace8616(
                None,
                next_path,
                saw_extract,
                saw_shift,
                LogicalMemoryRegisterTransferFailure8616.VALUE_OPERATION_UNSUPPORTED,
            )
        if (
            source.space is MemSpace.REG
            and source.size == destination.size == 2
            and bool(source.name)
        ):
            return _LaneTrace8616(source, next_path, saw_extract, saw_shift)
        extracts_low = destination.size == 1 and source.size == 1 and source.expr == ("Iop_16to8",)
        if destination.size != source.size or (source.expr == ("Iop_16to8",) and not extracts_low):
            return _LaneTrace8616(
                None,
                next_path,
                saw_extract,
                saw_shift,
                LogicalMemoryRegisterTransferFailure8616.VALUE_OPERATION_UNSUPPORTED,
            )
        return _trace_store_lane_8616(
            source,
            definitions,
            block_addr=block_addr,
            before_index=definition.instr_index,
            saw_extract=saw_extract or extracts_low,
            saw_shift=saw_shift,
            path=next_path,
            depth=depth + 1,
        )
    if instruction.op == "Iop_Shr16" and not saw_shift:
        source = _shr16_high_byte_source_8616(instruction)
        if source is not None:
            return _trace_store_lane_8616(
                source,
                definitions,
                block_addr=block_addr,
                before_index=definition.instr_index,
                saw_extract=saw_extract,
                saw_shift=True,
                path=next_path,
                depth=depth + 1,
            )
    return _LaneTrace8616(
        None,
        next_path,
        saw_extract,
        saw_shift,
        LogicalMemoryRegisterTransferFailure8616.VALUE_OPERATION_UNSUPPORTED,
    )


def _shr16_high_byte_source_8616(instruction: IRInstr) -> IRValue | None:
    """Return the shifted source for one exact ``word >> 8`` step."""
    if len(instruction.args) != 2:
        return None
    source, amount = instruction.args
    if (
        isinstance(source, IRValue)
        and isinstance(amount, IRValue)
        and amount.space is MemSpace.CONST
        and amount.const == 8
        and instruction.size == source.size == 2
    ):
        return source
    return None


def _same_address_8616(left: IRAddress, right: IRAddress) -> bool:
    """Compare canonical logical addresses without SSA versions."""
    return (
        left.space is right.space
        and left.base == right.base
        and left.offset == right.offset
        and left.size == right.size
        and left.status is right.status
        and left.segment_origin is right.segment_origin
    )


def _trace_spill_8616(
    artifact: SSAFunctionArtifact,
    access: IRLogicalMemoryAccess8616,
    definitions: ScalarDefinitionIndex8616,
) -> LogicalMemoryRegisterTransfer8616 | LogicalMemoryRegisterTransferRefusal8616:
    """Prove both stored byte lanes originate from one full register."""
    block = next((item for item in artifact.blocks if item.addr == access.key.block_addr), None)
    if block is None:
        return LogicalMemoryRegisterTransferRefusal8616(
            access,
            LogicalMemoryRegisterTransferFailure8616.BLOCK_MISSING,
            "logical write block is absent from the SSA artifact",
        )
    traces: list[_LaneTrace8616] = []
    for lane, execution in enumerate(access.execution_slices):
        if not 0 <= execution.instr_index < len(block.instrs):
            failure = LogicalMemoryRegisterTransferFailure8616.EXECUTION_SITE_CONFLICT
            return LogicalMemoryRegisterTransferRefusal8616(access, failure, "write slice index is outside its block")
        instruction = block.instrs[execution.instr_index]
        value = instruction.args[1] if instruction.op == "STORE" and len(instruction.args) == 2 else None
        if instruction.addr != access.key.insn_addr or not isinstance(value, IRValue):
            failure = LogicalMemoryRegisterTransferFailure8616.EXECUTION_SITE_CONFLICT
            return LogicalMemoryRegisterTransferRefusal8616(access, failure, "write slice does not identify one STORE value")
        trace = _trace_store_lane_8616(
            value,
            definitions,
            block_addr=block.addr,
            before_index=execution.instr_index,
        )
        expected_shift = lane == 1
        if trace.failure is not None or trace.register is None or not trace.saw_extract or trace.saw_shift != expected_shift:
            failure = trace.failure or LogicalMemoryRegisterTransferFailure8616.VALUE_OPERATION_UNSUPPORTED
            return LogicalMemoryRegisterTransferRefusal8616(access, failure, f"stored byte lane {lane} lacks exact word projection")
        traces.append(trace)
    registers = tuple(trace.register for trace in traces)
    if len(registers) != 2 or registers[0] != registers[1] or registers[0] is None:
        return LogicalMemoryRegisterTransferRefusal8616(
            access,
            LogicalMemoryRegisterTransferFailure8616.REGISTER_CONFLICT,
            "stored byte lanes do not share one full-register source",
        )
    register_sites = tuple(trace.path[-1] for trace in traces if trace.path)
    if len(register_sites) != 2 or register_sites[0] != register_sites[1]:
        return LogicalMemoryRegisterTransferRefusal8616(
            access,
            LogicalMemoryRegisterTransferFailure8616.REGISTER_CONFLICT,
            "stored byte lanes do not share one full-register definition site",
        )
    return LogicalMemoryRegisterTransfer8616(
        LogicalMemoryRegisterTransferKind8616.SPILL,
        access,
        registers[0],
        register_sites[0],
        tuple(site for trace in traces for site in trace.path),
    )


def _word_register_destination_8616(instruction: IRInstr) -> bool:
    """Return whether the MOV writes a named 16-bit register."""
    destination = instruction.dst
    return (
        destination is not None
        and destination.space is MemSpace.REG
        and destination.size == 2
        and bool(destination.name)
    )


def _reload_mov_candidate_8616(instruction: IRInstr, insn_addr: int) -> bool:
    """Return whether the instruction is a word-register MOV at the read site."""
    return (
        instruction.addr == insn_addr
        and instruction.op == "MOV"
        and _word_register_destination_8616(instruction)
        and len(instruction.args) == 1
        and isinstance(instruction.args[0], IRValue)
    )


def _trace_reload_8616(
    artifact: SSAFunctionArtifact,
    access: IRLogicalMemoryAccess8616,
    definitions: ScalarDefinitionIndex8616,
) -> LogicalMemoryRegisterTransfer8616 | LogicalMemoryRegisterTransferRefusal8616:
    """Prove one full register receives exactly this logical word read."""
    block = next((item for item in artifact.blocks if item.addr == access.key.block_addr), None)
    if block is None:
        return LogicalMemoryRegisterTransferRefusal8616(
            access,
            LogicalMemoryRegisterTransferFailure8616.BLOCK_MISSING,
            "logical read block is absent from the SSA artifact",
        )
    candidates: list[LogicalMemoryRegisterTransfer8616] = []
    for instr_index, instruction in enumerate(block.instrs):
        if not _reload_mov_candidate_8616(instruction, access.key.insn_addr):
            continue
        destination = instruction.dst
        source_definition, _failure = _unique_definition_8616(
            definitions,
            instruction.args[0],
            block_addr=block.addr,
            before_index=instr_index,
        )
        if source_definition is None or source_definition.instruction.op != "Iop_Or16":
            continue
        trace = trace_logical_word_load_8616(
            source_definition.instruction,
            definitions,
            artifact.logical_memory,
            function_addr=artifact.function_addr,
            block_addr=block.addr,
            before_index=source_definition.instr_index,
        )
        site = _site_8616(source_definition)
        move_site = IndexedAddressDefinitionSite8616(block.addr, instr_index, access.key.insn_addr, instruction.op)
        if trace.complete and trace.source is not None and site is not None and _same_address_8616(trace.source, access.address):
            candidates.append(
                LogicalMemoryRegisterTransfer8616(
                    LogicalMemoryRegisterTransferKind8616.RELOAD,
                    access,
                    destination,
                    move_site,
                    (*trace.definition_path, site, move_site),
                )
            )
    if len(candidates) == 1 and candidates[0].complete:
        return candidates[0]
    failure = (
        LogicalMemoryRegisterTransferFailure8616.REGISTER_CONFLICT
        if len(candidates) > 1
        else LogicalMemoryRegisterTransferFailure8616.VALUE_DEFINITION_MISSING
    )
    return LogicalMemoryRegisterTransferRefusal8616(access, failure, "logical read lacks one exact full-register destination")


def trace_logical_word_register_transfer_8616(
    artifact: SSAFunctionArtifact,
    access: IRLogicalMemoryAccess8616,
    definitions: ScalarDefinitionIndex8616 | None = None,
) -> LogicalMemoryRegisterTransfer8616 | LogicalMemoryRegisterTransferRefusal8616:
    """Trace one logical word, reusing an exact scalar index when supplied."""
    if not access.complete:
        return LogicalMemoryRegisterTransferRefusal8616(
            access,
            LogicalMemoryRegisterTransferFailure8616.ACCESS_INCOMPLETE,
            "logical memory access is incomplete",
        )
    if access.address.size != 2 or len(access.execution_slices) != 2:
        return LogicalMemoryRegisterTransferRefusal8616(
            access,
            LogicalMemoryRegisterTransferFailure8616.ACCESS_WIDTH_UNSUPPORTED,
            "only exact two-byte logical operands are register-transfer candidates",
        )
    active_definitions = (
        definitions
        if definitions is not None
        else build_scalar_definition_index_8616(artifact)
    )
    if access.kind is IRMemoryAccessKind8616.WRITE:
        return _trace_spill_8616(artifact, access, active_definitions)
    return _trace_reload_8616(artifact, access, active_definitions)


def trace_logical_word_register_transfers_8616(
    artifact: SSAFunctionArtifact,
    accesses: tuple[IRLogicalMemoryAccess8616, ...],
) -> tuple[
    LogicalMemoryRegisterTransfer8616 | LogicalMemoryRegisterTransferRefusal8616,
    ...,
]:
    """Trace a batch of logical words through one shared scalar index."""
    if not accesses:
        return ()
    definitions = build_scalar_definition_index_8616(artifact)
    return tuple(
        trace_logical_word_register_transfer_8616(
            artifact,
            access,
            definitions,
        )
        for access in accesses
    )


__all__ = [
    "LogicalMemoryRegisterTransfer8616",
    "LogicalMemoryRegisterTransferFailure8616",
    "LogicalMemoryRegisterTransferKind8616",
    "LogicalMemoryRegisterTransferRefusal8616",
    "trace_logical_word_register_transfer_8616",
    "trace_logical_word_register_transfers_8616",
]
