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

    When ``is_block_next`` is set, the instruction is the imported block
    terminal and ``statement_index`` is the statement count — the position at
    which the block's ``next`` expression is evaluated — not a statement index
    suitable for indexing ``statements``. ``block_next_tmp`` then retains the
    exact temporary that ``next`` reads, or ``None`` when ``next`` is not a
    temporary read.

    When ``is_instruction_mark`` is set, the instruction is a proven
    no-effect machine instruction minted at an ``Ist_IMark`` boundary rather
    than at an effect statement; ``statement_index`` is that mark's exact
    position in ``statements``. The mark carries no effect statement and the
    field is never set for ordinary instruction facts.
    """

    block_addr: int
    statement_index: int
    address_tmp: int | None = None
    is_block_next: bool = False
    block_next_tmp: int | None = None
    is_instruction_mark: bool = False

    def to_dict(self) -> dict[str, int | bool | None]:
        """Serialize source coordinates without deriving them from names."""
        return {
            "block_addr": self.block_addr,
            "statement_index": self.statement_index,
            "address_tmp": self.address_tmp,
            "is_block_next": self.is_block_next,
            "block_next_tmp": self.block_next_tmp,
            "is_instruction_mark": self.is_instruction_mark,
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


def vex_imark_origin_8616(
    *, block_addr: int, statement_index: int,
) -> IRInstructionOrigin8616:
    """Capture an ``Ist_IMark`` statement's exact position as origin provenance.

    This origin belongs to a proven no-effect instruction: it names the mark
    boundary, not a data-flow statement, so ``address_tmp`` and
    ``block_next_tmp`` stay unset. A consumer treating the origin as an
    effect-statement coordinate would misattribute the fact.
    """
    return IRInstructionOrigin8616(
        block_addr,
        statement_index,
        is_instruction_mark=True,
    )


def vex_block_next_origin_8616(
    next_expr: object, *, block_addr: int, statement_count: int,
) -> IRInstructionOrigin8616:
    """Capture the block ``next`` expression identity at the pyvex boundary.

    ``next`` is evaluated after every statement; its recorded position is the
    statement count, never an index into the statement list. When ``next``
    reads a temporary, ``block_next_tmp`` is that exact temporary identity so
    consumers can bind the retained control operand to this block.
    """
    return IRInstructionOrigin8616(
        block_addr,
        statement_count,
        is_block_next=True,
        block_next_tmp=next_expr.tmp if isinstance(next_expr, RdTmp) else None,
    )
