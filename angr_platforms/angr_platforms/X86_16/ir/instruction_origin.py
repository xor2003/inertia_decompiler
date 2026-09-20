"""Retain exact VEX statement and memory-address identity in typed IR.

Layer: IR.
Responsibility: owns typed Value, Address, Condition, instruction facts, and lossless
normalization of source statement provenance.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass

from pyvex.expr import Load, RdTmp
from pyvex.stmt import Store, WrTmp


@dataclass(frozen=True, slots=True)
class IRInstructionOrigin8616:
    """Source identity, not permission to replay current register contents.

    Temporary IDs are local to the original VEX block. Consumers must match
    both block and statement, then validate the retained expression. Synthetic
    instructions have no origin; do not attribute them to a nearby statement.
    """

    block_addr: int
    statement_index: int
    address_tmp: int | None = None

    def to_dict(self) -> dict[str, int | None]:
        """Serialize source coordinates without deriving them from names."""
        return {
            "block_addr": self.block_addr,
            "statement_index": self.statement_index,
            "address_tmp": self.address_tmp,
        }


def vex_instruction_origin_8616(
    statement: object, *, block_addr: int, statement_index: int,
) -> IRInstructionOrigin8616:
    """Capture a statement's exact address temporary at the pyvex boundary."""
    address = None
    if isinstance(statement, WrTmp) and isinstance(statement.data, Load):
        address = statement.data.addr
    elif isinstance(statement, Store):
        address = statement.addr
    return IRInstructionOrigin8616(
        block_addr,
        statement_index,
        address.tmp if isinstance(address, RdTmp) else None,
    )
