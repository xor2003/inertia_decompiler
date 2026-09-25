"""Classify typed condition ownership of structured loop exits.

Layer: Structuring.
Responsibility: identify exact condition-chain and pretest exits in the current
loop scope so one binary condition fact is not represented again as a
loop-header guard.

Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence. Do not perform alias-state ownership, widening,
type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CBreak,
    CDoWhileLoop,
    CExpression,
    CForLoop,
    CIfBreak,
    CIfElse,
    CStatements,
    CWhileLoop,
)

from ..c_ast_utils import (
    _iter_c_node_children_8616,
    _structured_codegen_node_8616,
    _structured_slot_names_8616,
)


class CompositeLoopExitOwnershipStatus8616(Enum):
    """Typed ownership verdict for one loop-condition fact."""

    NONE = "none"
    UNIQUE = "unique"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True, slots=True)
class CompositeLoopExitOwnership8616:
    """Exact composite loop-exit matches for one instruction/block identity."""

    key: tuple[int, int]
    status: CompositeLoopExitOwnershipStatus8616
    matching_exit_count: int
    owned_pretest_guard: CIfBreak | CIfElse | None


class _TaggedExpression8616(Protocol):
    """Dynamic angr expression tag surface at the Structuring boundary."""

    tags: dict[str, object]


def _iter_current_loop_scope_nodes_8616(body: object) -> Iterator[object]:
    """Iterate one loop body without descending into nested loop bodies."""
    loop_types = (CForLoop, CWhileLoop, CDoWhileLoop)
    pending = [body]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if not _structured_codegen_node_8616(current):
            continue
        current_id = id(current)
        if current_id in seen:
            continue
        seen.add(current_id)
        yield current
        if current is not body and isinstance(current, loop_types):
            continue
        seen_values: set[int] = set()
        for attr in _structured_slot_names_8616(current):
            try:
                # Dynamic third-party angr C-AST boundary slots are runtime-named.
                value = getattr(current, attr)
            except Exception:
                continue
            if _structured_codegen_node_8616(value):
                pending.append(value)
            elif isinstance(value, (dict, list, tuple, set)):
                pending.extend(_iter_c_node_children_8616(value, seen_values))


def _reaches_loop_header_8616(
    successors: Mapping[int, tuple[int, ...]],
    start: int,
    header: int,
) -> bool:
    """Return whether an exact shared-body target can re-enter the loop."""
    pending = [start]
    visited: set[int] = set()
    while pending:
        address = pending.pop()
        if address == header:
            return True
        if address in visited:
            continue
        visited.add(address)
        pending.extend(successors.get(address, ()))
    return False


def _condition_chain_exit_8616(
    node: object,
    key: tuple[int, int],
    successors: Mapping[int, tuple[int, ...]],
) -> CExpression | None:
    """Return one exact CFG-proven condition-chain exit expression."""
    if isinstance(node, CIfBreak):
        condition = node.condition
    elif isinstance(node, CIfElse) and node.else_node is None:
        pairs = tuple(node.condition_and_nodes)
        if len(pairs) != 1:
            return None
        condition, _body = pairs[0]
    else:
        return None
    boundary = cast(_TaggedExpression8616, condition)
    try:
        tags = boundary.tags
    except AttributeError:
        return None
    if not _shared_body_chain_reusable_8616(tags, key, successors):
        return None
    return condition


def _shared_body_chain_reusable_8616(
    tags: dict[str, object],
    key: tuple[int, int],
    successors: Mapping[int, tuple[int, ...]],
) -> bool:
    """Return whether tags prove the exact materialized chain exit target."""
    target = tags.get("inertia_structuring_shared_body_target_8616")
    return (
        tags.get("inertia_structuring_shared_body_condition_chain_materialized_8616") is True
        and tags.get("ins_addr") == key[0]
        and tags.get("vex_block_addr") == key[1]
        and isinstance(target, int)
        and target in successors
        and not _reaches_loop_header_8616(successors, target, key[1])
    )


def _condition_tag_pairs_8616(condition_owner: object) -> frozenset[tuple[int, int]]:
    """Return exact JCC/block identities retained by one condition owner."""
    pairs: set[tuple[int, int]] = set()
    for node in _iter_current_loop_scope_nodes_8616(condition_owner):
        boundary = cast(_TaggedExpression8616, node)
        try:
            tags = boundary.tags
        except AttributeError:
            continue
        ins_addr = tags.get("ins_addr")
        block_addr = tags.get("vex_block_addr")
        if isinstance(ins_addr, int) and isinstance(block_addr, int):
            pairs.add((ins_addr, block_addr))
    return frozenset(pairs)


def _typed_pretest_exit_8616(
    node: object,
    key: tuple[int, int],
    successors: Mapping[int, tuple[int, ...]],
) -> CExpression | None:
    """Return one exact pretest break whose JCC has one exit edge."""
    if isinstance(node, CIfBreak):
        condition = node.condition
    elif isinstance(node, CIfElse) and node.else_node is None:
        pairs = tuple(node.condition_and_nodes)
        if len(pairs) != 1:
            return None
        condition, body = pairs[0]
        if isinstance(body, CStatements):
            statements = tuple(body.statements or ())
            body = statements[0] if len(statements) == 1 else None
        if not isinstance(body, CBreak):
            return None
    else:
        return None
    if not isinstance(condition, CExpression):
        return None
    if _condition_tag_pairs_8616(node) != {key}:
        return None
    targets = successors.get(key[1], ())
    if len(targets) != 2:
        return None
    reentry_count = sum(
        _reaches_loop_header_8616(successors, target, key[1]) for target in targets
    )
    return condition if reentry_count == 1 else None


def classify_composite_loop_exit_ownership_8616(
    body: object,
    key: tuple[int, int],
    successors: Mapping[int, tuple[int, ...]],
    *,
    leading_break_guard: CIfBreak | CIfElse | None = None,
) -> CompositeLoopExitOwnership8616:
    """Classify exact CFG-owned loop exits that consume ``key``."""
    matched_expression_ids: set[int] = set()
    for node in _iter_current_loop_scope_nodes_8616(body):
        expression = _condition_chain_exit_8616(node, key, successors)
        if expression is not None:
            matched_expression_ids.add(id(expression))
    pretest_expression = (
        _typed_pretest_exit_8616(leading_break_guard, key, successors)
        if leading_break_guard is not None
        else None
    )
    if pretest_expression is not None:
        matched_expression_ids.add(id(pretest_expression))
    matching_exit_count = len(matched_expression_ids)
    status = (
        CompositeLoopExitOwnershipStatus8616.NONE
        if matching_exit_count == 0
        else CompositeLoopExitOwnershipStatus8616.UNIQUE
        if matching_exit_count == 1
        else CompositeLoopExitOwnershipStatus8616.AMBIGUOUS
    )
    return CompositeLoopExitOwnership8616(
        key=key,
        status=status,
        matching_exit_count=matching_exit_count,
        owned_pretest_guard=leading_break_guard if pretest_expression is not None else None,
    )
