# cython: language_level=3, infer_types=True
"""Compose exact modular word values of canonical memory-offset terms.

Layer: IR.
Responsibility: bind one memory-use address to its SSA instruction, trace each
word-sized base through the existing scalar owner, and retain their sum modulo
65536. This is a numeric low-word projection, not full effective-address width,
segment equality, pointer representation, object extent or Alias disjointness.
Owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum

from .core import AddressStatus, IRAddress, IRInstr, IRValue, MemSpace, SegmentOrigin
from .scalar_affine_contracts import ScalarAffineTerm8616, ScalarAffineTrace8616
from .scalar_affine_trace import trace_scalar_affine_expression_8616
from .ssa_function import SSAFunctionArtifact
import dataclasses
import operator


class MemoryOffsetWordFailure8616(StrEnum):
    """Typed non-results for one exact numeric memory-offset projection."""

    USE_SITE_UNPROVEN = "use_site_unproven"
    ADDRESS_UNPROVEN = "address_unproven"
    VALUE_TRACE_REFUSED = "value_trace_refused"


@dataclasses.dataclass(frozen=True, )
class MemoryOffsetWordValue8616:
    """Retained exact use, component traces and atomic word-value accounting."""

    artifact: SSAFunctionArtifact
    block_addr: cython.longlong
    instr_index: cython.longlong
    instruction: IRInstr | None
    address: IRAddress
    traces: object
    constant: int | None
    terms: object
    failure: MemoryOffsetWordFailure8616 | None
    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong

    @property
    def complete(self) -> cython.bint:
        """Recheck the exact use and component evidence, never just counters."""
        constant: object
        current: object
        counts = (self.raw_fact_count, self.normalized_fact_count,
                  self.classified_fact_count, self.materialized_count, self.failure_count)
        if self.failure is not None or counts != (1, 1, 1, 1, 0):
            return False
        if any(type(count) is not int for count in iter(counts)):
            return False
        if type(self.constant) is not int or any(type(term.coefficient) is not int for term in iter(self.terms)):
            return False
        current = _memory_use_8616(self.artifact, self.block_addr, self.instr_index, self.address)
        if current is None or current is not self.instruction or not _canonical_word_bases_8616(self.address):
            return False
        traces, constant, terms = _traced_sum_8616(self.artifact, self.block_addr, self.instr_index, self.address)
        return bool(constant is not None and operator.eq(self.traces, traces)
                    and operator.eq(self.constant, constant) and operator.eq(self.terms, terms))


def _memory_use_8616(
    artifact: SSAFunctionArtifact, block_addr: cython.longlong, instr_index: cython.longlong, address: IRAddress,
) -> IRInstr | None:
    """Require the identical memory operand at one exact artifact instruction."""
    if type(block_addr) is not int or type(instr_index) is not int:
        return None
    blocks = tuple(block for block in iter(artifact.blocks) if operator.eq(block.addr, block_addr))
    if len(blocks) != 1 or blocks[0].refusals or not 0 <= instr_index < len(blocks[0].instrs):
        return None
    instruction = blocks[0].instrs[instr_index]
    if instruction.op not in {"LOAD", "STORE"} or not instruction.args or instruction.args[0] is not address:
        return None
    if operator.ne(instruction.size, address.size):
        return None
    return instruction


def _canonical_word_bases_8616(address: IRAddress) -> cython.bint:
    """Consume only canonical segmented sums with exact bare word roots."""
    if address.space not in {MemSpace.SS, MemSpace.DS, MemSpace.ES}:
        return False
    if address.status is not AddressStatus.STABLE or address.segment_origin is not SegmentOrigin.PROVEN:
        return False
    if type(address.offset) is not int or address.size <= 0 or not 1 <= len(address.base_values) <= 2:
        return False
    if operator.ne(address.base, tuple(value.name for value in iter(address.base_values))):
        return False
    if operator.ne(address.expr, ("segmented_linear", address.space.value, ) + tuple(address.base)):
        return False
    return all(_bare_word_register_8616(value) for value in iter(address.base_values))


@cython.ccall
def _bare_word_register_8616(value: IRValue) -> cython.bint:
    """Reject hidden conversions/index metadata and malformed SSA identities."""
    if value.space is not MemSpace.REG or value.size != 2 or not value.name:
        return False
    if type(value.version) is not int or value.version < 0:
        return False
    plain_metadata = value.offset == 0 and value.const is None and value.expr is None
    return plain_metadata and value.index is None and value.index_shift == 0


def _traced_sum_8616(
    artifact: SSAFunctionArtifact, block_addr: cython.longlong, instr_index: cython.longlong, address: IRAddress,
) -> tuple[tuple[ScalarAffineTrace8616, ...], int | None, tuple[ScalarAffineTerm8616, ...]]:
    """Compose values without merging distinct loads of the same stack storage."""
    trace: object
    traces = tuple(trace_scalar_affine_expression_8616(
        artifact, value, block_addr=block_addr, before_index=instr_index,
    ) for value in iter(address.base_values))
    constant = address.offset
    terms: list[ScalarAffineTerm8616] = []
    for trace in traces:
        if not trace.complete or trace.expression is None:
            return traces, None, ()
        constant += trace.expression.constant
        terms.extend(trace.expression.terms)
    return traces, constant & 0xffff, tuple(terms)


@cython.ccall
def trace_memory_offset_word_value_8616(
    artifact: SSAFunctionArtifact, address: IRAddress, *, block_addr: cython.longlong, instr_index: cython.longlong,
) -> MemoryOffsetWordValue8616:
    """Retain one complete low-word sum or one typed nonpublishing refusal."""
    constant: object
    failure: object
    instruction: object
    instruction = _memory_use_8616(artifact, block_addr, instr_index, address)
    traces: tuple[ScalarAffineTrace8616, ...] = ()
    constant = None
    terms: tuple[ScalarAffineTerm8616, ...] = ()
    failure = None
    if instruction is None:
        failure = MemoryOffsetWordFailure8616.USE_SITE_UNPROVEN
    elif not _canonical_word_bases_8616(address):
        failure = MemoryOffsetWordFailure8616.ADDRESS_UNPROVEN
    else:
        traces, constant, terms = _traced_sum_8616(artifact, block_addr, instr_index, address)
        if constant is None:
            failure = MemoryOffsetWordFailure8616.VALUE_TRACE_REFUSED
    accepted = int(failure is None)
    return MemoryOffsetWordValue8616(
        artifact, block_addr, instr_index, instruction, address, traces, constant, terms,
        failure, 1, 1, accepted, accepted, 1 - accepted,
    )
