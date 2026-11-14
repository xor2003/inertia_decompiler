# cython: language_level=3, infer_types=True
"""Join exact caller word values into a path-correlated far callback value.

Layer: Types/Lowering.
Responsibility: consume IR logical READ/WRITE and callee ABI proofs to classify
one direct far callback argument by CFG predecessor. This owner does not infer
a four-byte caller storage object or mutate a generated C call.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum

from inertia.ir.core import MemSpace
from inertia.ir.logical_memory_contracts import IRLogicalMemoryAccess8616, IRMemoryAccessKind8616
from inertia.ir.logical_memory_write_value import LogicalWordWriteValueArtifact8616
from inertia.ir.logical_word_read_reaching_value import (
    LogicalWordReadIncomingValue8616,
    LogicalWordReadValueFact8616,
    trace_logical_word_read_values_8616,
)
from inertia.ir.ssa_function import SSAFunctionArtifact
from inertia.semantics.callsite_summary import CallsiteSummary8616

from .call_argument_shape import exact_far_callback_call_shape_evidence_8616
from .function_pointer_parameter_evidence import FunctionPointerParameterFact8616
import dataclasses
import operator
import builtins


class FarCallbackCallValueFailureKind8616(StrEnum):
    """Why one binary far-callback candidate has no closed caller Value proof."""

    ABI_NOT_PROVEN = "abi_not_proven"
    MISSING_PUSH_IDENTITY = "missing_push_identity"
    MISSING_WORD_READ = "missing_word_read"
    WORD_VALUE_UNPROVEN = "word_value_unproven"
    PATH_MISMATCH = "path_mismatch"


@dataclasses.dataclass(frozen=True, )
class FarCallbackPathValue8616:
    """One CFG predecessor's exact far offset/segment and their IR origins."""

    source_block_addr: int | None
    offset: cython.longlong
    segment: cython.longlong
    offset_incoming: LogicalWordReadIncomingValue8616
    segment_incoming: LogicalWordReadIncomingValue8616

    @property
    def complete(self) -> cython.bint:
        """Keep path correlation and both word values visible after publication."""
        return bool(
            self.source_block_addr == self.offset_incoming.source_block_addr
            == self.segment_incoming.source_block_addr
            and operator.eq(self.offset, self.offset_incoming.constant)
            and operator.eq(self.segment, self.segment_incoming.constant)
            and 0 <= self.offset <= 0xFFFF
            and 0 <= self.segment <= 0xFFFF
        )


@dataclasses.dataclass(frozen=True, )
class FarCallbackCallValueProof8616:
    """Closed two-word caller Value proof and the exact callee ABI witness."""

    caller: CallsiteSummary8616
    callee_fact: FunctionPointerParameterFact8616
    callee_indirect_calls: object
    offset_read: LogicalWordReadValueFact8616
    segment_read: LogicalWordReadValueFact8616
    paths: object
    logical_widths: object

    @property
    def complete(self) -> cython.bint:
        """Recheck machine PUSHs, two READs, ABI, and all predecessor pairs."""
        callee_addr: object
        shape: object
        callee_addr = self.caller.target_addr
        if callee_addr is None:
            return False
        shape = exact_far_callback_call_shape_evidence_8616(
            self.caller,
            callee_addr=callee_addr,
            callee_fact=self.callee_fact,
            callee_indirect_calls=self.callee_indirect_calls,
        )
        if shape is None or operator.ne(shape.widths, self.logical_widths):
            return False
        if not self.offset_read.complete or not self.segment_read.complete:
            return False
        if not _push_read_matches_8616(self.caller, 2, self.offset_read.load):
            return False
        if not _push_read_matches_8616(self.caller, 1, self.segment_read.load):
            return False
        if operator.ne(self.offset_read.load.key.function_addr, self.segment_read.load.key.function_addr):
            return False
        offsets = self.offset_read.incoming
        segments = self.segment_read.incoming
        expected = tuple(
            FarCallbackPathValue8616(offset.source_block_addr, offset.constant,
                                     segment.constant, offset, segment)
            for offset, segment in builtins.iter(zip(offsets, segments, strict=True))
        ) if operator.eq(len(offsets), len(segments)) else ()
        return bool(
            expected
            and operator.eq(tuple(item.source_block_addr for item in iter(offsets)), tuple(item.source_block_addr for item in iter(segments)))
            and operator.eq(self.paths, expected)
            and all(path.complete for path in iter(self.paths))
        )


@dataclasses.dataclass(frozen=True, )
class FarCallbackCallValueRefusal8616:
    """Typed refusal for one direct-far callsite candidate."""

    callsite_addr: cython.longlong
    kind: FarCallbackCallValueFailureKind8616


@dataclasses.dataclass(frozen=True, )
class FarCallbackCallValueResult8616:
    """One candidate's five-counter proof or explicit non-result."""

    callsite_addr: cython.longlong
    proof: FarCallbackCallValueProof8616 | None
    refusal: FarCallbackCallValueRefusal8616 | None
    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong

    @property
    def closed(self) -> cython.bint:
        """Require exactly one complete result or one reason-coded refusal."""
        return bool(
            self.callsite_addr >= 0
            and self.raw_fact_count == 1
            and operator.eq(self.raw_fact_count, self.materialized_count + self.failure_count)
            and self.raw_fact_count >= self.normalized_fact_count >= self.classified_fact_count
            and operator.eq(self.classified_fact_count, self.materialized_count)
            and ((self.proof is not None and self.proof.complete and self.refusal is None
                  and operator.eq(self.proof.caller.callsite_addr, self.callsite_addr)
                  and self.materialized_count == 1 and self.failure_count == 0)
                 or (self.proof is None and self.refusal is not None
                     and operator.eq(self.refusal.callsite_addr, self.callsite_addr)
                     and self.materialized_count == 0 and self.failure_count == 1))
        )


@cython.ccall
def _push_read_matches_8616(
    caller: CallsiteSummary8616, index: cython.longlong, read: IRLogicalMemoryAccess8616,
) -> cython.bint:
    """Match a selected logical READ to one decoded BP-word PUSH operand."""
    sources = caller.push_arg_sources
    addresses = caller.push_arg_instruction_addrs
    if len(sources) != 3 or len(addresses) != 3:
        return False
    source = sources[index]
    if not isinstance(source, tuple) or len(source) != 3:
        return False
    kind, offset, width = source
    return bool(
        kind == "bp" and isinstance(offset, int) and not isinstance(offset, bool)
        and width == 2 and read.complete
        and read.kind is IRMemoryAccessKind8616.READ
        and operator.eq(read.key.insn_addr, addresses[index])
        and read.address.space is MemSpace.SS
        and read.address.base == ("bp",)
        and operator.eq(read.address.offset, offset) and operator.eq(read.address.size, width)
    )


def _word_read_for_push_8616(
    artifact: SSAFunctionArtifact, caller: CallsiteSummary8616, index: cython.longlong,
) -> IRLogicalMemoryAccess8616 | None:
    """Select exactly one IR word READ at the decoded PUSH instruction."""
    logical_memory: object
    logical_memory = artifact.logical_memory
    if logical_memory is None or not logical_memory.closed:
        return None
    matches = tuple(
        access for access in iter(logical_memory.accesses)
        if operator.eq(access.key.function_addr, artifact.function_addr)
        and _push_read_matches_8616(caller, index, access)
    )
    return matches[0] if len(matches) == 1 else None


@cython.ccall
def _refuse_8616(
    caller: CallsiteSummary8616,
    kind: FarCallbackCallValueFailureKind8616,
    *,
    normalized: cython.bint,
) -> FarCallbackCallValueResult8616:
    """Close one candidate without manufacturing an unknown callback value."""
    return FarCallbackCallValueResult8616(
        caller.callsite_addr, None, FarCallbackCallValueRefusal8616(caller.callsite_addr, kind),
        1, int(normalized), 0, 0, 1,
    )


def prove_far_callback_call_path_values_8616(
    artifact: SSAFunctionArtifact,
    writes: LogicalWordWriteValueArtifact8616,
    caller: CallsiteSummary8616,
    *,
    callee_fact: FunctionPointerParameterFact8616,
    callee_indirect_calls: object,
) -> FarCallbackCallValueResult8616:
    """Join exact offset/segment LOAD values only on the same incoming path."""
    callee_addr: object
    offset_fact: object
    offset_load: object
    segment_fact: object
    segment_load: object
    shape: object
    callee_addr = caller.target_addr
    shape = None if callee_addr is None else exact_far_callback_call_shape_evidence_8616(
        caller, callee_addr=callee_addr, callee_fact=callee_fact,
        callee_indirect_calls=callee_indirect_calls,
    )
    if shape is None:
        return _refuse_8616(caller, FarCallbackCallValueFailureKind8616.ABI_NOT_PROVEN,
                            normalized=False)
    push_sites = caller.push_arg_instruction_addrs
    if len(push_sites) != 3 or not (
        push_sites[0] < push_sites[1] < push_sites[2] < caller.callsite_addr
    ):
        return _refuse_8616(caller, FarCallbackCallValueFailureKind8616.MISSING_PUSH_IDENTITY,
                            normalized=True)
    segment_load = _word_read_for_push_8616(artifact, caller, 1)
    offset_load = _word_read_for_push_8616(artifact, caller, 2)
    if segment_load is None or offset_load is None:
        return _refuse_8616(caller, FarCallbackCallValueFailureKind8616.MISSING_WORD_READ,
                            normalized=True)
    offset_result = trace_logical_word_read_values_8616(artifact, writes, offset_load)
    segment_result = trace_logical_word_read_values_8616(artifact, writes, segment_load)
    offset_fact, segment_fact = offset_result.fact, segment_result.fact
    if not offset_result.closed or not segment_result.closed or offset_fact is None or segment_fact is None:
        return _refuse_8616(caller, FarCallbackCallValueFailureKind8616.WORD_VALUE_UNPROVEN,
                            normalized=True)
    offsets, segments = offset_fact.incoming, segment_fact.incoming
    if operator.ne(tuple(item.source_block_addr for item in iter(offsets)), tuple(
        item.source_block_addr for item in iter(segments)
    )):
        return _refuse_8616(caller, FarCallbackCallValueFailureKind8616.PATH_MISMATCH,
                            normalized=True)
    paths = tuple(
        FarCallbackPathValue8616(offset.source_block_addr, offset.constant,
                                 segment.constant, offset, segment)
        for offset, segment in builtins.iter(zip(offsets, segments, strict=True))
    )
    proof = FarCallbackCallValueProof8616(
        caller, callee_fact, callee_indirect_calls, offset_fact, segment_fact,
        paths, shape.widths,
    )
    if not proof.complete:
        return _refuse_8616(caller, FarCallbackCallValueFailureKind8616.PATH_MISMATCH,
                            normalized=True)
    return FarCallbackCallValueResult8616(caller.callsite_addr, proof, None, 1, 1, 1, 1, 0)


__all__ = [
    "FarCallbackCallValueFailureKind8616", "FarCallbackCallValueProof8616",
    "FarCallbackCallValueRefusal8616", "FarCallbackCallValueResult8616",
    "FarCallbackPathValue8616", "prove_far_callback_call_path_values_8616",
]
