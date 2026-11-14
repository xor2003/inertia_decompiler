# cython: language_level=3, infer_types=True
"""Collect versioned indexed segmented-memory evidence from function SSA.

Layer: IR.
Responsibility: trace each indexed DS/ES LOAD or STORE through exact same-block
SSA definitions to one stable ``SS:BP`` source and retain the full proof path.
Ambiguous, cross-block, unversioned, or unsupported expressions become typed
refusals. This module does not infer aliases, loop bounds, arrays, C types, or
rendered expressions.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass

from .core import AddressStatus, IRAddress, IRInstr, IRValue, MemSpace, SegmentOrigin
from .indexed_address_access_normalization import normalize_indexed_address_accesses_8616
from .indexed_address_contracts import (
    IndexedAddressAccessKind8616,
    IndexedAddressDefinitionSite8616,
    IndexedAddressEvidence8616,
    IndexedAddressFact8616,
    IndexedAddressFailureKind8616,
    IndexedAddressRefusal8616,
    IndexedAddressStats8616,
)
from .logical_memory_contracts import IRLogicalMemoryArtifact8616
from .logical_memory_value_trace import trace_logical_word_load_8616
from .scalar_definitions import (
    ScalarDefinition8616,
    ScalarDefinitionIndex8616,
    build_scalar_definition_index_8616,
    reaching_scalar_definitions_8616,
    scalar_definition_key_8616,
)
from .ssa_function import SSAFunctionArtifact
import dataclasses
import operator


@dataclasses.dataclass(frozen=True, )
class _TraceResult8616:
    """Internal successful source trace or one typed refusal."""

    source: IRAddress | None
    shift: cython.longlong
    path: object
    failure: IndexedAddressFailureKind8616 | None


@cython.ccall
def _path_site_8616(
    definition: ScalarDefinition8616,
) -> IndexedAddressDefinitionSite8616 | None:
    """Return one exact path site when machine identity is available."""
    instruction = definition.instruction
    if instruction.addr is None:
        return None
    return IndexedAddressDefinitionSite8616(
        definition.block_addr,
        definition.instr_index,
        instruction.addr,
        instruction.op,
    )


@cython.ccall
def _stable_bp_address_8616(address: IRAddress) -> cython.bint:
    """Return whether the address is a proven stable BP-relative cell."""
    return (
        address.space is MemSpace.SS
        and address.base == ("bp",)
        and address.status is AddressStatus.STABLE
        and address.segment_origin is SegmentOrigin.PROVEN
    )


@cython.ccall
def _stable_stack_source_8616(instruction: IRInstr) -> IRAddress | None:
    """Return an exact BP-relative source for one width-coherent SSA LOAD."""
    address = instruction.args[0] if instruction.args else None
    if instruction.op != "LOAD" or not isinstance(address, IRAddress):
        return None
    if (
        not _stable_bp_address_8616(address)
        or address.size <= 0
        or operator.ne(instruction.size, address.size)
    ):
        return None
    return address


@cython.ccall
def _index_continuation_8616(
    instruction: IRInstr,
    shift: cython.longlong,
    next_path: object,
) -> object:
    """Return the next traced value and shift for exact copy/shift ops."""
    next_value: object
    next_value = None
    next_shift = shift
    if instruction.op == "MOV" and len(instruction.args) == 1:
        argument = instruction.args[0]
        next_value = argument if isinstance(argument, IRValue) else None
    elif instruction.op.startswith("Iop_Shl") and len(instruction.args) == 2:
        argument, amount = instruction.args
        if (
            isinstance(argument, IRValue)
            and isinstance(amount, IRValue)
            and amount.space is MemSpace.CONST
            and amount.const is not None
        ):
            next_value = argument
            next_shift += int(amount.const)
            if not 0 <= next_shift <= 4:
                return _TraceResult8616(
                    None,
                    next_shift,
                    next_path,
                    IndexedAddressFailureKind8616.INDEX_SHIFT_UNSUPPORTED,
                )
    if next_value is None:
        return _TraceResult8616(
            None,
            shift,
            next_path,
            IndexedAddressFailureKind8616.INDEX_EXPRESSION_UNSUPPORTED,
        )
    return next_value, next_shift


@cython.ccall
def _trace_index_source_8616(
    value: IRValue,
    definitions: ScalarDefinitionIndex8616,
    logical_memory: IRLogicalMemoryArtifact8616 | None,
    *,
    function_addr: cython.longlong,
    block_addr: cython.longlong,
    before_index: cython.longlong,
    shift: cython.longlong = 0,
    path: object = (),
    seen: object = frozenset(),
) -> _TraceResult8616:
    """Trace one versioned index through proven scalar definitions."""
    site: object
    source: object
    key = scalar_definition_key_8616(value)
    if key in seen:
        return _TraceResult8616(
            None, shift, path, IndexedAddressFailureKind8616.INDEX_DEFINITION_CONFLICT
        )
    candidates = reaching_scalar_definitions_8616(
        definitions,
        value,
        block_addr=block_addr,
        before_index=before_index,
    )
    if not candidates:
        return _TraceResult8616(
            None, shift, path, IndexedAddressFailureKind8616.INDEX_DEFINITION_MISSING
        )
    if len(candidates) != 1:
        return _TraceResult8616(
            None, shift, path, IndexedAddressFailureKind8616.INDEX_DEFINITION_CONFLICT
        )
    definition = candidates[0]
    site = _path_site_8616(definition)
    if site is None:
        return _TraceResult8616(
            None, shift, path, IndexedAddressFailureKind8616.INDEX_SOURCE_UNPROVEN
        )
    next_path = (*path, site)
    source = _stable_stack_source_8616(definition.instruction)
    if source is not None:
        if operator.ne(source.size, value.size):
            return _TraceResult8616(
                None,
                shift,
                next_path,
                IndexedAddressFailureKind8616.INDEX_SOURCE_UNPROVEN,
            )
        return _TraceResult8616(source, shift, next_path, None)

    instruction = definition.instruction
    if instruction.op == "Iop_Or16":
        logical_trace = trace_logical_word_load_8616(
            instruction,
            definitions,
            logical_memory,
            function_addr=function_addr,
            block_addr=block_addr,
            before_index=definition.instr_index,
        )
        return _TraceResult8616(
            logical_trace.source,
            shift,
            tuple(next_path) + tuple(logical_trace.definition_path),
            logical_trace.failure,
        )
    continued = _index_continuation_8616(instruction, shift, next_path)
    if isinstance(continued, _TraceResult8616):
        return continued
    next_value, next_shift = continued
    return _trace_index_source_8616(
        next_value,
        definitions,
        logical_memory,
        function_addr=function_addr,
        block_addr=block_addr,
        before_index=definition.instr_index,
        shift=next_shift,
        path=next_path,
        seen=seen | {key},
    )


@cython.ccall
def _candidate_failure_8616(
    address: IRAddress,
    access_size: cython.longlong,
) -> IndexedAddressFailureKind8616 | None:
    """Validate address and access fields before tracing index provenance."""
    if (
        address.status is not AddressStatus.STABLE
        or address.segment_origin is not SegmentOrigin.PROVEN
        or address.size <= 0
    ):
        return IndexedAddressFailureKind8616.ADDRESS_UNPROVEN
    if operator.ne(access_size, address.size):
        return IndexedAddressFailureKind8616.ACCESS_WIDTH_CONFLICT
    if len(address.base) != 1 or len(address.base_values) != 1:
        return IndexedAddressFailureKind8616.MULTIPLE_DYNAMIC_TERMS
    index_value = address.base_values[0]
    if operator.ne(address.base, (index_value.name,)):
        return IndexedAddressFailureKind8616.ADDRESS_UNPROVEN
    if (
        index_value.space is not MemSpace.REG
        or index_value.name is None
        or index_value.version is None
    ):
        return IndexedAddressFailureKind8616.INDEX_VALUE_UNVERSIONED
    return None


@cython.ccall
def collect_indexed_address_evidence_8616(
    artifact: SSAFunctionArtifact,
) -> IndexedAddressEvidence8616:
    """Collect every indexed DS/ES access as a fact or typed refusal."""
    failure: object
    trace: object
    access: object
    definitions = build_scalar_definition_index_8616(artifact)
    normalization = normalize_indexed_address_accesses_8616(artifact)
    facts: list[IndexedAddressFact8616] = []
    refusals: list[IndexedAddressRefusal8616] = []
    for access in normalization.accesses:
        address = access.address
        failure = access.failure or _candidate_failure_8616(address, access.access_size)
        trace = None
        if failure is None:
            trace = _trace_index_source_8616(
                address.base_values[0],
                definitions,
                artifact.logical_memory,
                function_addr=artifact.function_addr,
                block_addr=access.block_addr,
                before_index=access.instr_index,
            )
            failure = trace.failure
        if failure is not None or trace is None or trace.source is None:
            refusals.append(
                IndexedAddressRefusal8616(
                    artifact.function_addr,
                    access.block_addr,
                    access.instr_index,
                    access.instr_addr,
                    address,
                    failure or IndexedAddressFailureKind8616.INDEX_SOURCE_UNPROVEN,
                )
            )
            continue
        kind = (
            IndexedAddressAccessKind8616.LOAD
            if access.op == "LOAD"
            else IndexedAddressAccessKind8616.STORE
        )
        fact = IndexedAddressFact8616(
            artifact.function_addr,
            access.block_addr,
            access.instr_index,
            access.instr_addr,
            kind,
            address,
            address.base_values[0],
            trace.source,
            trace.shift,
            trace.path,
        )
        if not fact.complete:
            refusals.append(
                IndexedAddressRefusal8616(
                    artifact.function_addr,
                    access.block_addr,
                    access.instr_index,
                    access.instr_addr,
                    address,
                    IndexedAddressFailureKind8616.INDEX_SOURCE_UNPROVEN,
                )
            )
            continue
        facts.append(fact)
    classified = len(facts) + len(refusals)
    return IndexedAddressEvidence8616(
        artifact.function_addr,
        tuple(facts),
        tuple(refusals),
        IndexedAddressStats8616(
            normalization.raw_fact_count,
            normalization.normalized_fact_count,
            classified,
            len(facts),
            len(refusals),
            normalization.coalesced_fact_count,
        ),
    )


__all__ = ["collect_indexed_address_evidence_8616"]
