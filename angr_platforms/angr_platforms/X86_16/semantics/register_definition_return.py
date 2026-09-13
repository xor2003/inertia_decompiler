"""Prove an exact register definition reaches a same-block return unchanged.

Layer: Semantics.
Responsibility: retain the machine return identity after a register definition
without deriving storage identity or treating a rendered return as evidence.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from ..ir.core import IRBlock, IRFunctionArtifact, IRValue, MemSpace
from .register_value_preservation import register_value_family_8616


def unchanged_register_return_site_8616(
    artifact: IRFunctionArtifact, definition_addr: int, register: str,
) -> int | None:
    """Prove one unambiguous block-local definition/return pair, or refuse.

    Calls, additional register writes, branches and missing returns refuse.
    This proves value flow only, not a C return convention or storage binding.
    """
    blocks: list[IRBlock] = [block for block in artifact.blocks
              if any(instruction.addr == definition_addr for instruction in block.instrs)]
    if len(blocks) != 1 or blocks[0].refusals:
        return None
    family = register_value_family_8616(register)
    definition_seen = False
    for instruction in blocks[0].instrs:
        destination = instruction.dst
        writes_register = (isinstance(destination, IRValue)
                           and destination.space is MemSpace.REG and destination.name in family)
        if instruction.addr == definition_addr:
            if writes_register:
                assert isinstance(destination, IRValue)
                if definition_seen or destination.name != register:
                    return None
                definition_seen = True
            continue
        if not definition_seen:
            continue
        if writes_register or instruction.op in {"CALL", "JMP", "CJMP"}:
            return None
        if instruction.op == "RET":
            return instruction.addr
        if instruction.op not in {"MOV", "LOAD", "STORE"} and not instruction.op.startswith("Iop_"):
            return None
    return None
