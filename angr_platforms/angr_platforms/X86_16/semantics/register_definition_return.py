"""Prove an exact register definition reaches a return along a unique CFG path.

Layer: Semantics.
Responsibility: retain the machine return identity after a register definition
without deriving storage identity or treating a rendered return as evidence.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..ir.core import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from .register_value_preservation import register_value_family_8616, register_value_projection_8616

_BITS_PER_BYTE = 8


@dataclass(frozen=True, slots=True)
class RegisterReturnPath8616:
    """One definition's preserved value path, not ownership of all shared returns.

    Other predecessors may enter the final block with different values. A C
    consumer must independently prove which return projection owns this path.
    """

    definition_addr: int
    register: str
    block_addrs: tuple[int, ...]
    return_addr: int


def _writes_family(instruction: IRInstr, family: frozenset[str]) -> bool:
    """Read register overlap from the authoritative architectural family."""
    destination = instruction.dst
    return (isinstance(destination, IRValue) and destination.space is MemSpace.REG
            and destination.name in family)


def _definition_index(block: IRBlock, address: int, register: str) -> int | None:
    """Require one correctly sized, explicit definition at the machine address."""
    family = register_value_family_8616(register)
    indices = [index for index, instruction in enumerate(block.instrs)
               if instruction.addr == address and _writes_family(instruction, family)]
    projection = register_value_projection_8616(register, register)
    if len(indices) != 1 or projection is None:
        return None
    index = indices[0]
    instruction = block.instrs[index]
    destination = instruction.dst
    assert destination is not None
    known_definition = instruction.op in {"MOV", "LOAD"} or instruction.op.startswith("Iop_")
    if (destination.name != register or destination.size * _BITS_PER_BYTE != projection[1]
            or not known_definition):
        return None
    return index


def _preserved_tail(block: IRBlock, start: int, register: str) -> bool:
    """Refuse clobbers and unknown transfers, including same-address effects."""
    family = register_value_family_8616(register)
    for index in range(start, len(block.instrs)):
        instruction = block.instrs[index]
        if _writes_family(instruction, family):
            return False
        if instruction.op == "RET":
            return index == len(block.instrs) - 1 and not block.successor_addrs
        known_effect = instruction.op in {"MOV", "LOAD", "STORE"} or instruction.op.startswith("Iop_")
        if not known_effect:
            return False
    return True


def unchanged_register_return_path_8616(
    artifact: IRFunctionArtifact, definition_addr: int, register: str,
) -> RegisterReturnPath8616 | None:
    """Prove a finite single-successor path from a definition to its exact return.

    The IR CFG owns block transfers. Explicit unmodeled transfer instructions,
    branches, calls, clobbers, refusals, duplicate blocks and cycles refuse.
    A shared epilogue is allowed, but this proves only the selected input path.
    """
    blocks = {block.addr: block for block in artifact.blocks}
    owners = [block for block in artifact.blocks
              if any(instruction.addr == definition_addr for instruction in block.instrs)]
    if artifact.refusals or len(blocks) != len(artifact.blocks) or len(owners) != 1:
        return None
    block = owners[0]
    index = _definition_index(block, definition_addr, register)
    if index is None:
        return None
    start = index + 1
    path: list[int] = []
    while block.addr not in path:
        if block.refusals or not _preserved_tail(block, start, register):
            return None
        path.append(block.addr)
        if block.instrs and block.instrs[-1].op == "RET":
            return_addr = block.instrs[-1].addr
            return (RegisterReturnPath8616(definition_addr, register, tuple(path), return_addr)
                    if return_addr is not None else None)
        if len(block.successor_addrs) != 1 or block.successor_addrs[0] not in blocks:
            return None
        block = blocks[block.successor_addrs[0]]
        start = 0
    return None


def unchanged_register_return_site_8616(
    artifact: IRFunctionArtifact, definition_addr: int, register: str,
) -> int | None:
    """Project the exact return site without claiming C storage/path ownership."""
    proof = unchanged_register_return_path_8616(artifact, definition_addr, register)
    return None if proof is None else proof.return_addr
