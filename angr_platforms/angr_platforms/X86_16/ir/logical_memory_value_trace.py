"""Trace byte-composed scalar values through closed logical-memory evidence.

Layer: IR.
Responsibility: prove that one little-endian ``low | (high << 8)`` scalar value
comes from every execution slice of exactly one closed logical word read. This
module retains exact SSA definition sites and refuses absent, open, mismatched,
or ambiguous logical-memory evidence.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass

from .core import IRAddress, IRInstr, IRValue, MemSpace
from .indexed_address_contracts import (
    IndexedAddressDefinitionSite8616,
    IndexedAddressFailureKind8616,
)
from .logical_memory_contracts import (
    IRLogicalMemoryAccess8616,
    IRLogicalMemoryArtifact8616,
    IRMemoryAccessKind8616,
    IRMemoryExecutionSlice8616,
)
from .scalar_definitions import (
    ScalarDefinition8616,
    ScalarDefinitionIndex8616,
    reaching_scalar_definitions_8616,
    scalar_definition_key_8616,
)


@dataclass(frozen=True, slots=True)
class LogicalMemoryValueTrace8616:
    """One logical word-read source trace or one typed refusal."""

    source: IRAddress | None
    definition_path: tuple[IndexedAddressDefinitionSite8616, ...]
    failure: IndexedAddressFailureKind8616 | None

    @property
    def complete(self) -> bool:
        """Return whether this trace has one source and a closed path."""
        return bool(
            self.source is not None
            and self.failure is None
            and self.definition_path
            and all(site.complete for site in self.definition_path)
        )


@dataclass(frozen=True, slots=True)
class _ByteLoadTrace8616:
    """Internal path from one composition operand to one byte LOAD."""

    definition: ScalarDefinition8616 | None
    path: tuple[IndexedAddressDefinitionSite8616, ...]
    failure: IndexedAddressFailureKind8616 | None


def _definition_site_8616(
    definition: ScalarDefinition8616,
) -> IndexedAddressDefinitionSite8616 | None:
    """Return the exact machine and SSA site for one definition."""
    instruction = definition.instruction
    if instruction.addr is None:
        return None
    return IndexedAddressDefinitionSite8616(
        definition.block_addr,
        definition.instr_index,
        instruction.addr,
        instruction.op,
    )


def _trace_mov_to_byte_load_8616(
    value: IRValue,
    definitions: ScalarDefinitionIndex8616,
    *,
    block_addr: int,
    before_index: int,
    path: tuple[IndexedAddressDefinitionSite8616, ...] = (),
    seen: frozenset[tuple[str, str | None, int, int, int | None]] = frozenset(),
) -> _ByteLoadTrace8616:
    """Trace one exact value through MOV definitions to one byte LOAD."""
    key = scalar_definition_key_8616(value)
    if key in seen:
        return _ByteLoadTrace8616(
            None,
            path,
            IndexedAddressFailureKind8616.INDEX_DEFINITION_CONFLICT,
        )
    candidates = reaching_scalar_definitions_8616(
        definitions,
        value,
        block_addr=block_addr,
        before_index=before_index,
    )
    if not candidates:
        return _ByteLoadTrace8616(
            None,
            path,
            IndexedAddressFailureKind8616.INDEX_DEFINITION_MISSING,
        )
    if len(candidates) != 1:
        return _ByteLoadTrace8616(
            None,
            path,
            IndexedAddressFailureKind8616.INDEX_DEFINITION_CONFLICT,
        )
    definition = candidates[0]
    site = _definition_site_8616(definition)
    if site is None:
        return _ByteLoadTrace8616(
            None,
            path,
            IndexedAddressFailureKind8616.INDEX_SOURCE_UNPROVEN,
        )
    next_path = (*path, site)
    instruction = definition.instruction
    address = instruction.args[0] if instruction.args else None
    if (
        instruction.op == "LOAD"
        and instruction.size == 1
        and isinstance(address, IRAddress)
        and address.size == 1
    ):
        return _ByteLoadTrace8616(definition, next_path, None)
    if instruction.op != "MOV" or len(instruction.args) != 1:
        return _ByteLoadTrace8616(
            None,
            next_path,
            IndexedAddressFailureKind8616.INDEX_EXPRESSION_UNSUPPORTED,
        )
    argument = instruction.args[0]
    if not isinstance(argument, IRValue):
        return _ByteLoadTrace8616(
            None,
            next_path,
            IndexedAddressFailureKind8616.INDEX_EXPRESSION_UNSUPPORTED,
        )
    return _trace_mov_to_byte_load_8616(
        argument,
        definitions,
        block_addr=block_addr,
        before_index=definition.instr_index,
        path=next_path,
        seen=seen | {key},
    )


def _execution_site_8616(
    definition: ScalarDefinition8616,
) -> tuple[int, int, int] | None:
    """Return one exact execution-site identity for a byte LOAD definition."""
    instruction = definition.instruction
    if instruction.addr is None:
        return None
    return definition.block_addr, definition.instr_index, instruction.addr


def _slice_site_8616(execution_slice: IRMemoryExecutionSlice8616) -> tuple[int, int, int]:
    """Return the exact site identity retained by one logical execution slice."""
    return (
        execution_slice.block_addr,
        execution_slice.instr_index,
        execution_slice.insn_addr,
    )


def _slice_matches_load_8616(
    execution_slice: IRMemoryExecutionSlice8616,
    definition: ScalarDefinition8616,
) -> bool:
    """Return whether one slice and byte LOAD have the same site and address."""
    instruction = definition.instruction
    address = instruction.args[0] if instruction.args else None
    return bool(
        isinstance(address, IRAddress)
        and _execution_site_8616(definition) == _slice_site_8616(execution_slice)
        and address.space is execution_slice.address.space
        and address.base == execution_slice.address.base
        and address.offset == execution_slice.address.offset
        and address.size == execution_slice.address.size == 1
        and address.status is execution_slice.address.status
        and address.segment_origin is execution_slice.address.segment_origin
    )


def _matching_logical_reads_8616(
    logical_memory: IRLogicalMemoryArtifact8616,
    *,
    function_addr: int,
    low_definition: ScalarDefinition8616,
    high_definition: ScalarDefinition8616,
) -> tuple[IRLogicalMemoryAccess8616, ...]:
    """Return complete logical word reads owning exactly both byte LOAD sites."""
    definitions = (low_definition, high_definition)
    matches: list[IRLogicalMemoryAccess8616] = []
    for access in logical_memory.accesses:
        if (
            not access.complete
            or access.key.function_addr != function_addr
            or access.kind is not IRMemoryAccessKind8616.READ
            or access.address.size != 2
            or len(access.execution_slices) != len(definitions)
        ):
            continue
        if all(
            _slice_matches_load_8616(execution_slice, definition)
            for execution_slice, definition in zip(
                access.execution_slices,
                definitions,
                strict=True,
            )
        ):
            matches.append(access)
    return tuple(matches)


def _proven_shift_definition_8616(
    definitions: ScalarDefinitionIndex8616,
    shifted_value: IRValue,
    *,
    block_addr: int,
    before_index: int,
    low_path: tuple[IndexedAddressDefinitionSite8616, ...],
) -> tuple[ScalarDefinition8616, IndexedAddressDefinitionSite8616] | LogicalMemoryValueTrace8616:
    """Return the unique proven definition behind the shifted half."""
    shift_candidates = reaching_scalar_definitions_8616(
        definitions,
        shifted_value,
        block_addr=block_addr,
        before_index=before_index,
    )
    if not shift_candidates:
        return LogicalMemoryValueTrace8616(
            None,
            low_path,
            IndexedAddressFailureKind8616.INDEX_DEFINITION_MISSING,
        )
    if len(shift_candidates) != 1:
        return LogicalMemoryValueTrace8616(
            None,
            low_path,
            IndexedAddressFailureKind8616.INDEX_DEFINITION_CONFLICT,
        )
    shift_definition = shift_candidates[0]
    shift_site = _definition_site_8616(shift_definition)
    if shift_site is None:
        return LogicalMemoryValueTrace8616(
            None,
            low_path,
            IndexedAddressFailureKind8616.INDEX_SOURCE_UNPROVEN,
        )
    return shift_definition, shift_site


def trace_logical_word_load_8616(
    instruction: IRInstr,
    definitions: ScalarDefinitionIndex8616,
    logical_memory: IRLogicalMemoryArtifact8616 | None,
    *,
    function_addr: int,
    block_addr: int,
    before_index: int,
) -> LogicalMemoryValueTrace8616:
    """Prove one exact ``low | (high << 8)`` logical word-read value."""
    if instruction.op != "Iop_Or16" or instruction.size != 2 or len(instruction.args) != 2:
        return LogicalMemoryValueTrace8616(
            None,
            (),
            IndexedAddressFailureKind8616.INDEX_EXPRESSION_UNSUPPORTED,
        )
    low_value, shifted_value = instruction.args
    if not isinstance(low_value, IRValue) or not isinstance(shifted_value, IRValue):
        return LogicalMemoryValueTrace8616(
            None,
            (),
            IndexedAddressFailureKind8616.INDEX_EXPRESSION_UNSUPPORTED,
        )
    low_trace = _trace_mov_to_byte_load_8616(
        low_value,
        definitions,
        block_addr=block_addr,
        before_index=before_index,
    )
    if low_trace.failure is not None or low_trace.definition is None:
        return LogicalMemoryValueTrace8616(None, low_trace.path, low_trace.failure)

    resolved = _proven_shift_definition_8616(
        definitions,
        shifted_value,
        block_addr=block_addr,
        before_index=before_index,
        low_path=low_trace.path,
    )
    if isinstance(resolved, LogicalMemoryValueTrace8616):
        return resolved
    shift_definition, shift_site = resolved
    path_through_shift = (*low_trace.path, shift_site)
    shift_instruction = shift_definition.instruction
    if shift_instruction.op != "Iop_Shl16" or len(shift_instruction.args) != 2:
        return LogicalMemoryValueTrace8616(
            None,
            path_through_shift,
            IndexedAddressFailureKind8616.INDEX_EXPRESSION_UNSUPPORTED,
        )
    high_value, amount = shift_instruction.args
    if (
        not isinstance(high_value, IRValue)
        or not isinstance(amount, IRValue)
        or amount.space is not MemSpace.CONST
        or amount.const != 8
    ):
        return LogicalMemoryValueTrace8616(
            None,
            path_through_shift,
            IndexedAddressFailureKind8616.INDEX_EXPRESSION_UNSUPPORTED,
        )
    high_trace = _trace_mov_to_byte_load_8616(
        high_value,
        definitions,
        block_addr=block_addr,
        before_index=shift_definition.instr_index,
    )
    full_path = (*path_through_shift, *high_trace.path)
    if high_trace.failure is not None or high_trace.definition is None:
        return LogicalMemoryValueTrace8616(None, full_path, high_trace.failure)
    if (
        logical_memory is None
        or logical_memory.function_addr != function_addr
        or not logical_memory.closed
    ):
        return LogicalMemoryValueTrace8616(
            None,
            full_path,
            IndexedAddressFailureKind8616.INDEX_SOURCE_UNPROVEN,
        )
    matches = _matching_logical_reads_8616(
        logical_memory,
        function_addr=function_addr,
        low_definition=low_trace.definition,
        high_definition=high_trace.definition,
    )
    if len(matches) != 1:
        failure = (
            IndexedAddressFailureKind8616.INDEX_DEFINITION_CONFLICT
            if len(matches) > 1
            else IndexedAddressFailureKind8616.INDEX_SOURCE_UNPROVEN
        )
        return LogicalMemoryValueTrace8616(None, full_path, failure)
    return LogicalMemoryValueTrace8616(matches[0].address, full_path, None)


__all__ = ["LogicalMemoryValueTrace8616", "trace_logical_word_load_8616"]
