"""Prove structured-condition ownership from typed CFG addresses.

Layer: Structuring.
Responsibility: bind a structured condition container to its exact branch or
to a CFG-proven linear preheader that reaches that branch without crossing a
different typed condition.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.

This module does not recover condition meaning or inspect rendered C. It only
answers whether existing address and CFG evidence establishes ownership.
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CFunctionCall,
    CMultiStatementExpression,
)

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..ir.condition_ir import ConditionIR
from .condition_chain_provenance import condition_chain_provenance_8616

_MAX_PREHEADER_BLOCKS = 24


def select_composite_preheader_root_8616(
    node_addr: int | None,
    expression: object,
    origin: ConditionIR | None,
    conditions: tuple[ConditionIR, ...],
    successors: dict[int, tuple[int, ...]],
) -> ConditionIR | None:
    """Select an entry-owned composite root, not a descendant's origin tag.

    This selects a candidate only. The caller must still prove the entire CFG
    condition chain and its body endpoints before replacing any expression.
    Unknown statement effects and non-condition paths to the origin refuse.
    """
    if node_addr is None or origin is None or not requires_composite_condition_ownership_8616(expression):
        return None
    if not any(fact is origin for fact in conditions):
        return None
    if any(isinstance(node, (CFunctionCall, CMultiStatementExpression, CDirtyExpression))
           for node in _iter_c_nodes_deep_8616(expression)):
        return None
    blocks = frozenset(fact.block_addr for fact in conditions if isinstance(fact.block_addr, int))
    candidates = tuple(fact for fact in conditions if structured_node_owns_condition_fact_8616(
        node_addr, fact, successors, blocks,
    ))
    if len(candidates) != 1 or candidates[0] is origin:
        return None
    root = candidates[0]
    pending = [root.block_addr]
    visited: set[int] = set()
    while pending:
        address = pending.pop()
        if not isinstance(address, int) or address in visited or address not in blocks:
            continue
        if address == origin.block_addr:
            return root
        visited.add(address)
        pending.extend(successors.get(address, ()))
    return None


def _is_neutral_logical_root_8616(expression: object) -> bool:
    """Recognize a literal Boolean identity around one direct predicate."""
    if not isinstance(expression, CBinaryOp) or expression.op not in {"LogicalAnd", "LogicalOr"}:
        return False
    neutral = 1 if expression.op == "LogicalAnd" else 0
    return any(
        isinstance(operand, CConstant) and operand.value == neutral
        for operand in (expression.lhs, expression.rhs)
    )


def requires_composite_condition_ownership_8616(expression: object) -> bool:
    """Refuse single-fact replacement of wrapped logical or statement-bearing guards.

    One descendant's JCC tag cannot establish ownership of the full compound
    predicate. CFG-chain materialization must account for every constituent.
    A direct ``1 && predicate`` or ``0 || predicate`` has only one effective
    predicate. Nested identities remain refused: their enclosing polarity
    wrapper needs its own ownership proof.
    """
    provenance = condition_chain_provenance_8616(expression)
    if provenance is not None and len(provenance.jcc_addrs) > 1:
        return True
    neutral_root = expression if _is_neutral_logical_root_8616(expression) else None
    return any(
        isinstance(node, CMultiStatementExpression)
        or (
            isinstance(node, CBinaryOp)
            and node.op in {"LogicalAnd", "LogicalOr"}
            and node is not neutral_root
        )
        for node in _iter_c_nodes_deep_8616(expression)
    )


def structured_node_owns_condition_fact_8616(
    node_addr: int | None,
    condition: ConditionIR,
    successors: dict[int, tuple[int, ...]],
    condition_blocks: frozenset[int],
) -> bool:
    """Accept exact ownership or an unambiguous linear CFG preheader path."""
    if node_addr is None:
        return True
    if node_addr == condition.src_insn or node_addr == condition.block_addr:
        return True
    if not isinstance(condition.block_addr, int) or node_addr not in successors:
        return False

    current = node_addr
    visited: set[int] = set()
    while current not in visited and len(visited) < _MAX_PREHEADER_BLOCKS:
        visited.add(current)
        next_addrs = successors.get(current, ())
        if len(next_addrs) != 1:
            return False
        current = next_addrs[0]
        if current == condition.block_addr:
            return True
        if current in condition_blocks:
            return False
    return False
