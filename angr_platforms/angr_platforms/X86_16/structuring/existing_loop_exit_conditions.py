"""Bind existing break predicates to exact natural-loop exit evidence.

Layer: Structuring.
Responsibility: orient a single typed condition at an existing loop break using
the enclosing loop's proven header and unique CFG exit destination. Never infer
an exit from break-statement source tags or from rendered expressions.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen.c import (
    CBreak,
    CConstant,
    CDoWhileLoop,
    CExpression,
    CForLoop,
    CIfBreak,
    CIfElse,
    CStatements,
    CWhileLoop,
)

from ..c_ast_utils import _iter_c_nodes_deep_8616, _same_c_expression_8616
from ..condition_call_effects import classify_condition_call_effects_8616
from ..ir.condition_ir import ConditionIR
from ..pipeline.errors import PipelineHardError
from .condition_ownership import requires_composite_condition_ownership_8616
from .loop_break_topology import LoopBreakTopology8616
from .loop_condition_identity import is_owned_loop_continuation_8616
from .multi_arm_condition_ownership import first_statement_block_8616
from .natural_loop_topology import LoopTopologyVerdict8616, NaturalLoopTopology8616


@dataclass(frozen=True, slots=True)
class ExistingLoopExitStats8616:
    """Closed evidence counts for existing single-predicate loop exits."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    changed_count: int = 0


def _sole_break_8616(body: object) -> bool:
    """Require a plain break without executed setup or another statement."""
    while isinstance(body, CStatements) and len(body.statements) == 1:
        body = body.statements[0]
    return type(body) is CBreak


def _local_guards_8616(node: object) -> Iterator[tuple[CIfBreak | CIfElse, CExpression]]:
    """Walk this loop's guards, stopping at nested loops and switch scopes."""
    if isinstance(node, CStatements):
        for statement in node.statements:
            yield from _local_guards_8616(statement)
    elif isinstance(node, CIfBreak):
        yield node, node.condition
    elif isinstance(node, CIfElse):
        if len(node.condition_and_nodes) == 1 and node.else_node is None:
            condition, body = node.condition_and_nodes[0]
            if _sole_break_8616(body):
                yield node, condition
        for _, body in node.condition_and_nodes:
            yield from _local_guards_8616(body)
        yield from _local_guards_8616(node.else_node)


def _posttest_loop_owner_8616(
    node: CDoWhileLoop, block: int, topology: LoopBreakTopology8616,
) -> NaturalLoopTopology8616 | None:
    """Bind a bottom-tested loop by body entry and exact continuation backedge."""
    header = first_statement_block_8616(node.body)
    targets = {topology.resolve_target(target) for source, target in topology.edges if source == block}
    owners: list[NaturalLoopTopology8616] = []
    for loop in topology.loops:
        if loop.verdict is not LoopTopologyVerdict8616.PROVEN or loop.header != header or block not in loop.body:
            continue
        continuation = loop.header if block == loop.latch else loop.latch
        exits = {target for _, target in loop.exit_edges}
        if targets == {continuation, *exits}:
            owners.append(loop)
    return owners[0] if len(owners) == 1 else None


def _loop_owner_8616(
    node: CWhileLoop | CForLoop | CDoWhileLoop, topology: LoopBreakTopology8616,
) -> NaturalLoopTopology8616 | None:
    """Match a bound guard or an unconditional loop's exact header and entry.

    A constant guard has no JCC identity. Require independent statement-entry
    provenance agreeing with the loop's header, then the unique proven CFG
    region; a copied loop tag alone cannot establish the break's scope.
    """
    condition = node.condition
    if isinstance(condition, CExpression) and is_owned_loop_continuation_8616(condition):
        block = condition.tags["vex_block_addr"]
        if isinstance(node, CDoWhileLoop):
            return _posttest_loop_owner_8616(node, block, topology)
    elif isinstance(node, CWhileLoop) and isinstance(condition, CConstant) and condition.value == 1:
        block = first_statement_block_8616(node.body)
        if block is None or node.tags.get("ins_addr") != block:
            return None
    else:
        return None
    owners = tuple(
        loop for loop in topology.loops
        if loop.verdict is LoopTopologyVerdict8616.PROVEN and loop.header == block
    )
    return owners[0] if len(owners) == 1 else None


def _exit_polarity_8616(
    fact: ConditionIR, loop: NaturalLoopTopology8616, topology: LoopBreakTopology8616,
) -> bool | None:
    """Prove whether taken or fallthrough reaches the loop's sole exit."""
    block = fact.block_addr
    taken, fallthrough = fact.taken_target, fact.fallthrough_target
    if block not in loop.body or taken == fallthrough:
        return None
    targets = {target for source, target in topology.edges if source == block}
    if targets != {taken, fallthrough}:
        return None
    if taken is None or fallthrough is None:
        return None
    taken = topology.resolve_target(taken)
    fallthrough = topology.resolve_target(fallthrough)
    exits = {target for _, target in loop.exit_edges}
    if len(exits) != 1:
        return None
    exit_target = next(iter(exits))
    if taken == exit_target and fallthrough in loop.body:
        return True
    if fallthrough == exit_target and taken in loop.body:
        return False
    return None


def _guard_fact_8616(
    current: CExpression, typed_conditions: tuple[ConditionIR, ...],
    condition_key: Callable[[object], tuple[int, int] | None],
) -> ConditionIR | None:
    """Require an effect-free single predicate with one exact typed owner."""
    if requires_composite_condition_ownership_8616(current):
        return None
    if classify_condition_call_effects_8616(current).has_semantic_call:
        return None
    key = condition_key(current)
    facts = tuple(fact for fact in typed_conditions if (fact.src_insn, fact.block_addr) == key)
    return facts[0] if len(facts) == 1 else None


def _replace_guard_8616(
    guard: CIfBreak | CIfElse, current: CExpression, fact: ConditionIR, polarity: bool,
    lower: Callable[[ConditionIR], CExpression | None],
    invert: Callable[[CExpression], CExpression],
    record_precision: Callable[[CExpression, CExpression], bool],
) -> bool:
    """Publish one CFG-proven replacement without altering the break body."""
    replacement = lower(fact)
    if replacement is None:
        raise PipelineHardError(f"classified loop-exit condition jcc={fact.src_insn:#x} could not be lowered")
    if not polarity:
        replacement = invert(replacement)
    replacement.tags = {
        **replacement.tags,
        "ins_addr": fact.src_insn,
        "vex_block_addr": fact.block_addr,
        "inertia_structuring_condition_cfg_materialized_8616": True,
    }
    already_owned = current.tags.get("inertia_structuring_condition_cfg_materialized_8616") is True
    if already_owned and _same_c_expression_8616(current, replacement):
        return False
    record_precision(current, replacement)
    if isinstance(guard, CIfBreak):
        guard.condition = replacement
    else:
        guard.condition_and_nodes = [(replacement, guard.condition_and_nodes[0][1])]
    return True


def materialize_existing_loop_exit_conditions_8616(
    root: object,
    typed_conditions: tuple[ConditionIR, ...],
    topology: LoopBreakTopology8616 | None,
    *,
    condition_key: Callable[[object], tuple[int, int] | None],
    lower: Callable[[ConditionIR], CExpression | None],
    invert: Callable[[CExpression], CExpression],
    record_precision: Callable[[CExpression, CExpression], bool],
) -> ExistingLoopExitStats8616:
    """Materialize existing break guards without changing their bodies or CFG."""
    if topology is None:
        return ExistingLoopExitStats8616()
    raw = normalized = materialized = changed = 0
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, (CWhileLoop, CForLoop, CDoWhileLoop)):
            continue
        owner = _loop_owner_8616(node, topology)
        if owner is None:
            continue
        for guard, current in _local_guards_8616(node.body):
            raw += 1
            fact = _guard_fact_8616(current, typed_conditions, condition_key)
            if fact is None:
                continue
            normalized += 1
            polarity = _exit_polarity_8616(fact, owner, topology)
            if polarity is None:
                continue
            materialized += 1
            changed += _replace_guard_8616(guard, current, fact, polarity, lower, invert, record_precision)
    return ExistingLoopExitStats8616(raw, normalized, materialized, materialized, raw - materialized, changed)
