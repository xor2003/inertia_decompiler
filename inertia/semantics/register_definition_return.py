# cython: language_level=3, infer_types=True
"""Prove an exact register definition reaches a return along a unique CFG path.

Layer: Semantics.
Responsibility: retain the machine return identity after a register definition
without deriving storage identity or treating a rendered return as evidence.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass

from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace

from .register_value_preservation import register_value_family_8616, register_value_projection_8616
import dataclasses
import operator
import builtins

_BITS_PER_BYTE = 8


@dataclasses.dataclass(frozen=True, )
class RegisterReturnPath8616:
    """One definition's preserved value path, not ownership of all shared returns.

    Other predecessors may enter the final block with different values. A C
    consumer must independently prove which return projection owns this path.
    """

    definition_addr: cython.longlong
    register: object
    block_addrs: object
    return_addr: cython.longlong


@cython.ccall
def _writes_family(instruction: IRInstr, family: object) -> cython.bint:
    """Read register overlap from the authoritative architectural family."""
    destination = instruction.dst
    return (isinstance(destination, IRValue) and destination.space is MemSpace.REG
            and destination.name in family)


@cython.ccall
def _definition_index(block: IRBlock, address: cython.longlong, register: object) -> int | None:
    """Require one correctly sized, explicit definition at the machine address."""
    destination: object
    projection: object
    family = register_value_family_8616(register)
    indices = [index for index, instruction in builtins.iter(enumerate(block.instrs))
               if operator.eq(instruction.addr, address) and _writes_family(instruction, family)]
    projection = register_value_projection_8616(register, register)
    if len(indices) != 1 or projection is None:
        return None
    index = indices[0]
    instruction = block.instrs[index]
    destination = instruction.dst
    assert destination is not None
    known_definition = instruction.op in {"MOV", "LOAD"} or instruction.op.startswith("Iop_")
    if (operator.ne(destination.name, register) or operator.ne(destination.size * _BITS_PER_BYTE, projection[1])
            or not known_definition):
        return None
    return index


@cython.ccall
def _preserved_tail(block: IRBlock, start: cython.longlong, register: object) -> cython.bint:
    """Refuse clobbers and unknown transfers, including same-address effects."""
    family = register_value_family_8616(register)
    for index in range(start, len(block.instrs)):
        instruction = block.instrs[index]
        if _writes_family(instruction, family):
            return False
        if instruction.op == "RET":
            return operator.eq(index, len(block.instrs) - 1) and not block.successor_addrs
        known_effect = instruction.op in {"MOV", "LOAD", "STORE"} or instruction.op.startswith("Iop_")
        if not known_effect:
            return False
    return True


def unchanged_register_return_path_8616(
    artifact: IRFunctionArtifact, definition_addr: cython.longlong, register: object,
) -> RegisterReturnPath8616 | None:
    """Prove a finite single-successor path from a definition to its exact return.

    The IR CFG owns block transfers. Explicit unmodeled transfer instructions,
    branches, calls, clobbers, refusals, duplicate blocks and cycles refuse.
    A shared epilogue is allowed, but this proves only the selected input path.
    """
    index: object
    return_addr: object
    blocks = {block.addr: block for block in iter(artifact.blocks)}
    owners = [block for block in iter(artifact.blocks)
              if any(operator.eq(instruction.addr, definition_addr) for instruction in iter(block.instrs))]
    if artifact.refusals or operator.ne(len(blocks), len(artifact.blocks)) or len(owners) != 1:
        return None
    block = owners[0]
    index = _definition_index(block, definition_addr, register)
    if index is None:
        return None
    start = index + 1
    path: list[cython.longlong] = []
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


@cython.ccall
def unchanged_register_return_site_8616(
    artifact: IRFunctionArtifact, definition_addr: cython.longlong, register: object,
) -> int | None:
    """Project the exact return site without claiming C storage/path ownership."""
    proof: object
    proof = unchanged_register_return_path_8616(artifact, definition_addr, register)
    return None if proof is None else proof.return_addr
