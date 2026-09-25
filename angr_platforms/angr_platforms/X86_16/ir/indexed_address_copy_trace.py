"""Trace normalized indexed STORE byte lanes to exact LOAD definitions.

Layer: IR.
Responsibility: prove same-block scalar SSA paths through exact moves, low-byte
extraction, and the canonical high-byte shift. Mixed, transformed, or missing
paths become typed refusals; aggregate and Alias meaning are out of scope.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass

from .core import IRInstr, IRValue, MemSpace
from .indexed_address_contracts import IndexedAddressFailureKind8616
from .indexed_address_copy_contracts import (
    IndexedAddressCopyFailureKind8616,
    IndexedAddressCopyLane8616,
    IndexedAddressCopyStep8616,
    IndexedAddressCopyStepKind8616,
    IndexedAddressCopyValuePath8616,
)
from .logical_memory_contracts import IRLogicalMemoryArtifact8616
from .logical_memory_value_trace import (
    LogicalMemoryValueTrace8616,
    trace_logical_word_load_8616,
)
from .scalar_definitions import (
    ScalarDefinition8616,
    ScalarDefinitionIndex8616,
    reaching_scalar_definitions_8616,
    scalar_definition_key_8616,
)
from .ssa import SSABlock


@dataclass(frozen=True, slots=True)
class IndexedAddressCopyPathRefusal8616:
    """One typed refusal produced while tracing a STORE byte lane."""

    failure: IndexedAddressCopyFailureKind8616
    detail: str


@dataclass(frozen=True, slots=True)
class _ValueTrace8616:
    """Internal exact scalar source trace or one typed refusal."""

    entry: ScalarDefinition8616 | None
    load: ScalarDefinition8616 | None
    steps: tuple[IndexedAddressCopyStep8616, ...]
    refusal: IndexedAddressCopyPathRefusal8616 | None
    logical_source: LogicalMemoryValueTrace8616 | None


def _failed_trace_8616(
    failure: IndexedAddressCopyFailureKind8616,
    detail: str,
) -> _ValueTrace8616:
    """Return one failed trace without partial semantic evidence."""
    return _ValueTrace8616(
        None,
        None,
        (),
        IndexedAddressCopyPathRefusal8616(failure, detail),
        None,
    )


def _logical_copy_failure_8616(
    failure: IndexedAddressFailureKind8616 | None,
) -> IndexedAddressCopyFailureKind8616:
    """Map authoritative logical-value refusals into the copy contract."""
    if failure is IndexedAddressFailureKind8616.INDEX_DEFINITION_MISSING:
        return IndexedAddressCopyFailureKind8616.VALUE_DEFINITION_MISSING
    if failure is IndexedAddressFailureKind8616.INDEX_DEFINITION_CONFLICT:
        return IndexedAddressCopyFailureKind8616.LOGICAL_MEMORY_EVIDENCE_CONFLICT
    if failure is IndexedAddressFailureKind8616.INDEX_EXPRESSION_UNSUPPORTED:
        return IndexedAddressCopyFailureKind8616.VALUE_OPERATION_UNSUPPORTED
    return IndexedAddressCopyFailureKind8616.LOGICAL_MEMORY_EVIDENCE_UNPROVEN


def _unique_definition_8616(
    value: IRValue,
    definitions: ScalarDefinitionIndex8616,
    *,
    block_addr: int,
    before_index: int,
) -> ScalarDefinition8616 | _ValueTrace8616:
    """Resolve one exact reaching definition inside the owning SSA block."""
    candidates = reaching_scalar_definitions_8616(
        definitions,
        value,
        block_addr=block_addr,
        before_index=before_index,
    )
    if not candidates:
        return _failed_trace_8616(
            IndexedAddressCopyFailureKind8616.VALUE_DEFINITION_MISSING,
            "stored value has no exact preceding same-block SSA definition",
        )
    if len(candidates) != 1:
        return _failed_trace_8616(
            IndexedAddressCopyFailureKind8616.VALUE_DEFINITION_CONFLICT,
            "stored value has multiple preceding same-block SSA definitions",
        )
    return candidates[0]


def _step_kind_8616(
    definition: ScalarDefinition8616,
    source_expression: IRValue,
    source_definition: ScalarDefinition8616,
) -> tuple[IndexedAddressCopyStepKind8616 | None, int | None]:
    """Classify one operation only when it preserves a known byte lane."""
    instruction = definition.instruction
    destination = instruction.dst
    source = source_definition.instruction.dst
    if destination is None or source is None:
        return None, None
    if instruction.op == "MOV":
        if destination.size == source.size > 0:
            return IndexedAddressCopyStepKind8616.MOVE, None
        if (
            destination.size == 1
            and source.size == 2
            and source_expression.expr == ("Iop_16to8",)
        ):
            return IndexedAddressCopyStepKind8616.LOW_BYTE_EXTRACT, None
        return None, None
    if instruction.op == "Iop_Shr16" and len(instruction.args) == 2:
        amount = instruction.args[1]
        if (
            isinstance(amount, IRValue)
            and amount.space is MemSpace.CONST
            and amount.const == 8
            and destination.size == source.size == 2
        ):
            return IndexedAddressCopyStepKind8616.HIGH_BYTE_SHIFT, 8
    return None, None


def _load_source_trace_8616(definition: ScalarDefinition8616) -> _ValueTrace8616:
    """Return the terminal trace for one exact LOAD definition."""
    instruction = definition.instruction
    if instruction.dst is None or instruction.addr is None:
        return _failed_trace_8616(
            IndexedAddressCopyFailureKind8616.VALUE_OPERATION_UNSUPPORTED,
            "source LOAD lacks exact value or instruction identity",
        )
    return _ValueTrace8616(definition, definition, (), None, None)


def _copy_source_expression_8616(instruction: IRInstr) -> IRValue | None:
    """Return the copied source value for exact MOV/Shr16 copy operations."""
    source_expression: IRValue | None = None
    if (
        instruction.op == "MOV" and len(instruction.args) == 1
    ) or (
        instruction.op == "Iop_Shr16" and len(instruction.args) == 2
    ):
        argument = instruction.args[0]
        source_expression = argument if isinstance(argument, IRValue) else None
    return source_expression


def _or16_logical_source_trace_8616(
    definition: ScalarDefinition8616,
    definitions: ScalarDefinitionIndex8616,
    logical_memory: IRLogicalMemoryArtifact8616 | None,
    *,
    function_addr: int,
    block_addr: int,
) -> _ValueTrace8616:
    """Trace one ``Iop_Or16`` definition through closed logical word evidence."""
    instruction = definition.instruction
    logical_source = trace_logical_word_load_8616(
        instruction,
        definitions,
        logical_memory,
        function_addr=function_addr,
        block_addr=block_addr,
        before_index=definition.instr_index,
    )
    if not logical_source.complete:
        failure = _logical_copy_failure_8616(logical_source.failure)
        detail = (
            "logical word source lacks closed exact value evidence"
            if logical_source.failure is None
            else f"logical word source refused {logical_source.failure.value}"
        )
        return _failed_trace_8616(failure, detail)
    return _ValueTrace8616(
        definition,
        definition,
        (),
        None,
        logical_source,
    )


def _trace_value_to_load_8616(
    value: IRValue,
    definitions: ScalarDefinitionIndex8616,
    logical_memory: IRLogicalMemoryArtifact8616 | None,
    *,
    function_addr: int,
    block_addr: int,
    before_index: int,
    seen: frozenset[tuple[str, str | None, int, int, int | None]] = frozenset(),
) -> _ValueTrace8616:
    """Trace one value backward through exact copy-lane definitions."""
    key = scalar_definition_key_8616(value)
    if key in seen:
        return _failed_trace_8616(
            IndexedAddressCopyFailureKind8616.VALUE_DEFINITION_CONFLICT,
            "stored value definition path contains a cycle",
        )
    resolved = _unique_definition_8616(
        value,
        definitions,
        block_addr=block_addr,
        before_index=before_index,
    )
    if isinstance(resolved, _ValueTrace8616):
        return resolved
    definition = resolved
    instruction = definition.instruction
    if instruction.op == "LOAD":
        return _load_source_trace_8616(definition)
    if instruction.op == "Iop_Or16":
        return _or16_logical_source_trace_8616(
            definition,
            definitions,
            logical_memory,
            function_addr=function_addr,
            block_addr=block_addr,
        )
    source_expression = _copy_source_expression_8616(instruction)
    if source_expression is None:
        return _failed_trace_8616(
            IndexedAddressCopyFailureKind8616.VALUE_OPERATION_UNSUPPORTED,
            f"value path operation {instruction.op!r} is not an exact copy operation",
        )
    source_trace = _trace_value_to_load_8616(
        source_expression,
        definitions,
        logical_memory,
        function_addr=function_addr,
        block_addr=block_addr,
        before_index=definition.instr_index,
        seen=seen | {key},
    )
    if source_trace.refusal is not None or source_trace.entry is None:
        return source_trace
    source_definition = source_trace.entry
    kind, constant = _step_kind_8616(
        definition,
        source_expression,
        source_definition,
    )
    destination = instruction.dst
    source_destination = source_definition.instruction.dst
    if kind is None or destination is None or source_destination is None:
        failure = (
            IndexedAddressCopyFailureKind8616.VALUE_WIDTH_CONFLICT
            if instruction.op in {"MOV", "Iop_Shr16"}
            else IndexedAddressCopyFailureKind8616.VALUE_OPERATION_UNSUPPORTED
        )
        return _failed_trace_8616(
            failure,
            f"operation {instruction.op!r} does not preserve a supported copy lane",
        )
    if instruction.addr is None:
        return _failed_trace_8616(
            IndexedAddressCopyFailureKind8616.VALUE_OPERATION_UNSUPPORTED,
            "value path operation lacks machine instruction identity",
        )
    step = IndexedAddressCopyStep8616(
        definition.block_addr,
        definition.instr_index,
        instruction.addr,
        instruction.op,
        kind,
        destination,
        source_expression,
        source_destination,
        constant,
    )
    if not step.complete:
        return _failed_trace_8616(
            IndexedAddressCopyFailureKind8616.VALUE_WIDTH_CONFLICT,
            "typed value-path step is internally inconsistent",
        )
    return _ValueTrace8616(
        definition,
        source_trace.load,
        (step, *source_trace.steps),
        None,
        source_trace.logical_source,
    )


def _member_instruction_8616(
    block: SSABlock,
    instr_index: int,
) -> IRInstr | None:
    """Return one exact indexed STORE member without dynamic lookup."""
    if not 0 <= instr_index < len(block.instrs):
        return None
    instruction = block.instrs[instr_index]
    if instruction.op != "STORE" or len(instruction.args) != 2:
        return None
    return instruction


def trace_indexed_store_member_8616(
    block: SSABlock,
    instr_index: int,
    lane: IndexedAddressCopyLane8616,
    definitions: ScalarDefinitionIndex8616,
    logical_memory: IRLogicalMemoryArtifact8616 | None,
    *,
    function_addr: int,
) -> IndexedAddressCopyValuePath8616 | IndexedAddressCopyPathRefusal8616:
    """Trace one normalized STORE member to its exact LOAD endpoint."""
    instruction = _member_instruction_8616(block, instr_index)
    value = None if instruction is None else instruction.args[1]
    if not isinstance(value, IRValue):
        return IndexedAddressCopyPathRefusal8616(
            IndexedAddressCopyFailureKind8616.STORE_VALUE_UNSUPPORTED,
            "indexed STORE member has no scalar value",
        )
    trace = _trace_value_to_load_8616(
        value,
        definitions,
        logical_memory,
        function_addr=function_addr,
        block_addr=block.addr,
        before_index=instr_index,
    )
    if trace.refusal is not None or trace.load is None:
        return trace.refusal or IndexedAddressCopyPathRefusal8616(
            IndexedAddressCopyFailureKind8616.VALUE_OPERATION_UNSUPPORTED,
            "indexed STORE value path is incomplete",
        )
    load_instruction = trace.load.instruction
    if load_instruction.dst is None or load_instruction.addr is None:
        return IndexedAddressCopyPathRefusal8616(
            IndexedAddressCopyFailureKind8616.VALUE_OPERATION_UNSUPPORTED,
            "source LOAD endpoint is incomplete",
        )
    path = IndexedAddressCopyValuePath8616(
        instr_index,
        trace.load.block_addr,
        trace.load.instr_index,
        load_instruction.addr,
        lane,
        value,
        load_instruction.dst,
        trace.steps,
        trace.logical_source,
    )
    if not path.complete:
        return IndexedAddressCopyPathRefusal8616(
            IndexedAddressCopyFailureKind8616.SPLIT_LANE_CONFLICT,
            f"STORE member does not prove the required {lane.value} value lane",
        )
    return path


__all__ = [
    "IndexedAddressCopyPathRefusal8616",
    "trace_indexed_store_member_8616",
]
