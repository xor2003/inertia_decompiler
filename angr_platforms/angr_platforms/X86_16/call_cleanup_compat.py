"""Project proven callee argument cleanup into native scalar stack state.

Layer: Frontend/IR adapter.
Responsibility: materialize Semantics-owned near RET-immediate effects after
returning source calls whose machine frames were already consumed. This is
not argument recovery or DCE. Unknown, far and wide returns remain unchanged.
The narrow SP write preserves upper ESP through native subregister SSA.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

import networkx as nx
from angr import Project
from angr.ailment import Expr, Stmt
from angr.ailment.block import Block
from angr.ailment.manager import Manager

from .semantics.call_return_segment import callee_return_evidence_8616
from .semantics.terminal_return_contract import TerminalReturnFrameKind8616


@dataclass(frozen=True, slots=True)
class CalleeCleanupFact8616:
    """Exact call target and agreed binary cleanup consumed by one SP write."""

    callsite_addr: int
    target_addr: int
    cleanup_bytes: int
    operand_bits: int


@dataclass(frozen=True, slots=True)
class CalleeCleanupReport8616:
    """Call census; unselected calls retain their original representation."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    facts: tuple[CalleeCleanupFact8616, ...]


def materialize_callee_cleanup_8616(
    project: object, graph: nx.DiGraph[Block], manager: Manager,
    accepted_calls: tuple[int, ...], *, sp_offset: int,
) -> CalleeCleanupReport8616:
    """Apply each proven narrow near-return cleanup once, after its call.

    Only terminal, uniquely projected calls with a fallthrough edge qualify.
    The caller passes the exact accepted machine-frame census, not a guessed
    calling convention. Synthetic effects carry a typed marker and callsite
    address, never a fabricated VEX producer identity. Counts describe newly
    inserted effects; zero-cleanup and already-applied calls are unselected.
    """
    calls = [
        (block, statement)
        for block in graph for statement in block.statements
        if isinstance(statement, Stmt.SideEffectStatement) and isinstance(statement.expr, Expr.Call)
    ]
    occurrences = Counter(statement.tags.get("ins_addr") for _block, statement in calls)
    facts: list[CalleeCleanupFact8616] = []
    if isinstance(project, Project) and project.arch.name == "86_16":
        for block, statement in calls:
            address = statement.tags.get("ins_addr")
            if address not in accepted_calls or occurrences[address] != 1:
                continue
            if block.statements[-1] is not statement:
                continue
            if not any(node.addr == block.addr + block.original_size for node in graph.successors(block)):
                continue
            target = statement.expr.target
            if not isinstance(target, Expr.Const) or not isinstance(target.value, int):
                continue
            evidence = callee_return_evidence_8616(project, target.value)
            amount = evidence.consistent_cleanup
            if not amount or evidence.consistent_return_operand_bits != 16:
                continue
            if evidence.consistent_return_frame_kind is not TerminalReturnFrameKind8616.NEAR:
                continue
            fact = CalleeCleanupFact8616(address, target.value, amount, 16)
            read = Expr.Register(manager.next_atom(), sp_offset, 16)
            constant = Expr.Const(manager.next_atom(), amount, 16)
            value = Expr.BinaryOp(manager.next_atom(), "Add", (read, constant), False, bits=16)
            write = Expr.Register(manager.next_atom(), sp_offset, 16)
            block.statements.append(Stmt.Assignment(
                manager.next_atom(), write, value, ins_addr=address, inertia_callee_cleanup=fact,
            ))
            facts.append(fact)
    count = len(facts)
    return CalleeCleanupReport8616(len(calls), count, count, count, len(calls) - count, tuple(facts))
