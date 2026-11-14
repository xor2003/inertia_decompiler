# cython: language_level=3, infer_types=True
"""Project closed logical-memory reads into typed scalar values.

Layer: IR.
Responsibility: convert one exact byte-executed logical word-read trace into a
typed scalar storage value while preserving its segmented address identity.
Unknown, open, ambiguous, or non-stack evidence is refused without guessing.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from .core import AddressStatus, IRAddress, IRInstr, IRValue, MemSpace
from .logical_memory_contracts import IRLogicalMemoryArtifact8616
from .logical_memory_value_trace import trace_logical_word_load_8616
from .scalar_definitions import ScalarDefinitionIndex8616


@cython.ccall
def _stable_stack_word_source_8616(source: IRAddress) -> cython.bint:
    """Return whether the source is one stable SS word."""
    return (
        source.space is MemSpace.SS
        and source.status is AddressStatus.STABLE
        and len(source.base) == 1
        and source.size == 2
    )


@cython.ccall
def project_logical_stack_word_value_8616(
    instruction: IRInstr,
    definitions: ScalarDefinitionIndex8616,
    logical_memory: IRLogicalMemoryArtifact8616 | None,
    *,
    function_addr: cython.longlong,
    block_addr: cython.longlong,
    before_index: cython.longlong,
) -> IRValue | None:
    """Return one proven stack word represented by byte-executed IR."""
    source: object
    trace = trace_logical_word_load_8616(
        instruction,
        definitions,
        logical_memory,
        function_addr=function_addr,
        block_addr=block_addr,
        before_index=before_index,
    )
    source = trace.source
    if not trace.complete or source is None:
        return None
    if not _stable_stack_word_source_8616(source) or instruction.addr is None:
        return None
    base = source.base[0].lower()
    if base not in {"bp", "sp"}:
        return None
    return IRValue(
        MemSpace.SS,
        name=base,
        offset=source.offset,
        size=source.size,
        memory_access_insn=instruction.addr,
    )


__all__ = ["project_logical_stack_word_value_8616"]
