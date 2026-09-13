"""Project logical memory operand widths into frame-access evidence.

Layer: IR.
Responsibility: consume exact logical-to-execution bindings before summarizing
frame accesses. This does not infer storage identity, widen objects, or mutate
the byte-safe execution IR. Unknown bindings retain their raw access evidence.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator

from .core import AddressStatus, IRAddress, IRFunctionArtifact, IRInstr, MemSpace
from .logical_memory_contracts import IRLogicalMemoryAccess8616, IRMemoryAccessKind8616


def _matches_execution(
    access: IRLogicalMemoryAccess8616,
    instructions: dict[tuple[int, int], IRInstr],
) -> bool:
    """Require each recorded byte to refer to the current raw instruction."""
    expected_op = "LOAD" if access.kind is IRMemoryAccessKind8616.READ else "STORE"
    for part in access.execution_slices:
        instruction = instructions.get((part.block_addr, part.instr_index))
        if instruction is None or instruction.op != expected_op or instruction.addr != part.insn_addr:
            return False
        if not instruction.args or instruction.args[0] != part.address:
            return False
    return True


def frame_memory_accesses_8616(artifact: IRFunctionArtifact) -> Iterator[tuple[IRAddress, int]]:
    """Yield logical operands once and retain every uncovered raw SS access.

    A word executed through two independent byte accesses remains a word-sized
    machine operand. Independent byte instructions must never be combined.
    """
    instructions = {(block.addr, index): instruction for block in artifact.blocks
                    for index, instruction in enumerate(block.instrs)}
    logical = artifact.logical_memory
    candidates: tuple[IRLogicalMemoryAccess8616, ...] = ()
    if logical is not None and logical.closed and logical.function_addr == artifact.function_addr:
        candidates = tuple(access for access in logical.accesses
                           if access.key.function_addr == artifact.function_addr and access.address.space is MemSpace.SS)
    owners = Counter((part.block_addr, part.instr_index) for access in candidates for part in access.execution_slices)
    covered: set[tuple[int, int]] = set()
    for access in candidates:
        unique = all(owners[(part.block_addr, part.instr_index)] == 1 for part in access.execution_slices)
        if not unique or not _matches_execution(access, instructions):
            continue
        covered.update((part.block_addr, part.instr_index) for part in access.execution_slices)
        yield access.address, access.address.size
    for site, instruction in instructions.items():
        if site in covered:
            continue
        for value in instruction.args:
            if isinstance(value, IRAddress) and value.space is MemSpace.SS:
                yield value, int(value.size or instruction.size or 0)


def stable_bp_memory_ranges_8616(artifact: IRFunctionArtifact) -> tuple[IRAddress, ...]:
    """Retain both logical operands and their raw cells for call-effect consumers.

    A caller may query preservation of a single execution byte or of its whole
    logical operand. Neither view replaces the other at a call boundary.
    """
    ranges = {
        address for block in artifact.blocks for instruction in block.instrs
        if instruction.op in {"LOAD", "STORE"} and instruction.args
        and isinstance((address := instruction.args[0]), IRAddress)
    }
    ranges.update(address for address, _size in frame_memory_accesses_8616(artifact))
    return tuple(sorted((address for address in ranges
                         if address.space is MemSpace.SS and address.base == ("bp",)
                         and address.status is AddressStatus.STABLE and address.size > 0),
                        key=lambda item: (item.offset, item.size)))
