"""Retain exact native arithmetic-producer links to stack-register writes.

Layer: IR.
Responsibility: publish existing AIL/VEX source identity before SSA folding,
including separate CFG occurrences. This is dataflow provenance, not argument
ownership, stack balancing, Alias proof, or permission to remove an effect.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

import networkx as nx
from angr.ailment.block import Block
from angr.ailment.expression import BinaryOp, Const, Register
from angr.ailment.statement import Assignment

_BINARY_OPERAND_COUNT: int = 2


class StackPointerArithmetic8616(StrEnum):
    """Native arithmetic operation whose exact source is retained."""

    ADD = "Add"
    SUB = "Sub"


@dataclass(frozen=True, slots=True)
class StackPointerProducer8616:
    """One source producer consumed by one physical SP-write occurrence."""

    instruction_addr: int
    vex_block_addr: int
    producer_index: int
    write_index: int
    register_offset: int
    width_bits: int
    operation: StackPointerArithmetic8616
    amount: int
    block_addr: int
    block_index: int | None
    statement_index: int


@dataclass(frozen=True, slots=True)
class StackPointerProvenance8616:
    """Closed census of published links; failures leave native code unchanged.

    Materialized counts refer only to publishing IR facts, not deleting code.
    A downstream consumer must independently prove ownership and safe use closure.
    """

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    projections: tuple[StackPointerProducer8616, ...]


def _source_key_8616(tags: Mapping[str, object]) -> tuple[int, int, int] | None:
    """Read an exact non-negative native instruction/block/statement key."""
    values = tuple(tags.get(name) for name in ("ins_addr", "vex_block_addr", "vex_stmt_idx"))
    if any(type(value) is not int or value < 0 for value in values):
        return None
    return cast(tuple[int, int, int], values)


def _projection_8616(
    block: Block, position: int, statement: Assignment,
) -> StackPointerProducer8616 | None:
    """Link a directly consumed tagged arithmetic value, never nearby indices."""
    source = statement.src
    if not isinstance(source, BinaryOp) or source.op not in {"Add", "Sub"}:
        return None
    if not isinstance(statement.dst, Register) or len(source.operands) != _BINARY_OPERAND_COUNT:
        return None
    amount = source.operands[1]
    if not (
        isinstance(amount, Const) and type(amount.value) is int
        and source.bits == statement.dst.bits == amount.bits
        and source.bits in {16, 32}
    ):
        return None
    producer, write = _source_key_8616(source.tags), _source_key_8616(statement.tags)
    if producer is None or write is None or producer[:2] != write[:2]:
        return None
    return StackPointerProducer8616(
        instruction_addr=write[0], vex_block_addr=write[1],
        producer_index=producer[2], write_index=write[2],
        register_offset=statement.dst.reg_offset, width_bits=source.bits,
        operation=StackPointerArithmetic8616(source.op), amount=amount.value,
        block_addr=block.addr, block_index=block.idx, statement_index=position,
    )


def collect_stack_pointer_provenance_8616(
    graph: nx.DiGraph[Block], *, sp_offset: int,
) -> StackPointerProvenance8616:
    """Publish SP arithmetic links without changing the graph or merging paths."""
    raw = 0
    projections: list[StackPointerProducer8616] = []
    for block in sorted(graph, key=lambda node: (node.addr, -1 if node.idx is None else node.idx)):
        for position, statement in enumerate(block.statements):
            if not (
                isinstance(statement, Assignment) and isinstance(statement.dst, Register)
                and statement.dst.reg_offset == sp_offset
            ):
                continue
            raw += 1
            projection = _projection_8616(block, position, statement)
            if projection is not None:
                projections.append(projection)
    count = len(projections)
    return StackPointerProvenance8616(raw, count, count, count, raw - count, tuple(projections))
