"""Keep logical-memory execution sites coherent after typed IR insertion.

Layer: IR.
Responsibility: rebase exact logical-memory execution-slice indexes after a
known prefix is inserted into an IR block, and verify that each rebased site
still names the original machine instruction and memory operation. This module
does not infer memory semantics, Alias identity, widths, or rendered C.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from enum import StrEnum

from inertia.pipeline.errors import PipelineHardError

from .core import IRBlock
from .logical_memory_contracts import (
    IRLogicalMemoryArtifact8616,
    IRMemoryAccessKind8616,
    IRMemoryExecutionSlice8616,
)


class LogicalMemoryRebaseFailure8616(StrEnum):
    """Stable reason an IR insertion cannot retain a logical execution site."""

    NEGATIVE_PREFIX = "negative_prefix"
    BLOCK_MISSING = "block_missing"
    SITE_OUT_OF_RANGE = "site_out_of_range"
    MACHINE_INSTRUCTION_MISMATCH = "machine_instruction_mismatch"
    OPERATION_MISMATCH = "operation_mismatch"


def _rebase_execution_slice_8616(
    execution_slice: IRMemoryExecutionSlice8616,
    *,
    kind: IRMemoryAccessKind8616,
    prefix_lengths: Mapping[int, int],
    blocks: Mapping[int, IRBlock],
) -> IRMemoryExecutionSlice8616:
    """Rebase and validate one exact execution slice."""
    prefix_length = int(prefix_lengths.get(execution_slice.block_addr, 0))
    if prefix_length < 0:
        failure = LogicalMemoryRebaseFailure8616.NEGATIVE_PREFIX
    else:
        block = blocks.get(execution_slice.block_addr)
        if block is None:
            failure = LogicalMemoryRebaseFailure8616.BLOCK_MISSING
        else:
            rebased_index = execution_slice.instr_index + prefix_length
            if rebased_index >= len(block.instrs):
                failure = LogicalMemoryRebaseFailure8616.SITE_OUT_OF_RANGE
            else:
                instruction = block.instrs[rebased_index]
                expected_op = "LOAD" if kind is IRMemoryAccessKind8616.READ else "STORE"
                if instruction.addr != execution_slice.insn_addr:
                    failure = LogicalMemoryRebaseFailure8616.MACHINE_INSTRUCTION_MISMATCH
                elif instruction.op != expected_op:
                    failure = LogicalMemoryRebaseFailure8616.OPERATION_MISMATCH
                else:
                    return replace(execution_slice, instr_index=rebased_index)
    raise PipelineHardError(
        "logical-memory execution slice could not be rebased after IR insertion",
        layer="ir",
        details={
            "failure": failure,
            "block_addr": execution_slice.block_addr,
            "instr_index": execution_slice.instr_index,
            "prefix_length": prefix_length,
        },
    )


def rebase_logical_memory_prefix_insertions_8616(
    logical_memory: IRLogicalMemoryArtifact8616 | None,
    *,
    prefix_lengths: Mapping[int, int],
    rewritten_blocks: tuple[IRBlock, ...],
) -> IRLogicalMemoryArtifact8616 | None:
    """Return logical-memory evidence rebased onto prefix-extended IR blocks."""
    if logical_memory is None or not logical_memory.accesses or not any(prefix_lengths.values()):
        return logical_memory
    blocks = {block.addr: block for block in rewritten_blocks}
    accesses = tuple(
        replace(
            access,
            execution_slices=tuple(
                _rebase_execution_slice_8616(
                    execution_slice,
                    kind=access.kind,
                    prefix_lengths=prefix_lengths,
                    blocks=blocks,
                )
                for execution_slice in access.execution_slices
            ),
        )
        for access in logical_memory.accesses
    )
    rebased = replace(logical_memory, accesses=accesses)
    if logical_memory.closed and not rebased.closed:
        raise PipelineHardError(
            "logical-memory evidence became incomplete after IR insertion",
            layer="ir",
        )
    return rebased


__all__ = [
    "LogicalMemoryRebaseFailure8616",
    "rebase_logical_memory_prefix_insertions_8616",
]
