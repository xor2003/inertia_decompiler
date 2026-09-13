"""Bind complete short-circuit pretest exits to their typed CFG conditions.

Layer: Structuring.
Responsibility: replace only a proven leading break predicate, preserving the
loop body and iterator and refusing statement-bearing or ambiguous guards.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence. Do not perform alias-state ownership, widening,
type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CDirtyExpression,
    CExpression,
    CIfBreak,
    CIfElse,
    CMultiStatementExpression,
    CStatements,
    CWhileLoop,
)

from ..c_ast_utils import _iter_c_nodes_deep_8616, _same_c_expression_8616
from ..condition_call_effects import classify_condition_call_effects_8616
from ..ir.condition_ir import ConditionIR
from ..ir.ssa_function import SSAFunctionArtifact
from .condition_exit_normalization import transparent_condition_exit_8616
from .loop_condition_ownership import _condition_tag_pairs_8616
from .pretest_condition_surface import pretest_condition_surface_8616

_MIN_COMPOSITE_FACTS = 2
_BINARY_OUTCOMES = 2


class _TaggedNode8616(Protocol):
    """Third-party C-AST identity tags consumed at this boundary."""

    tags: dict[str, object]


@dataclass(frozen=True, slots=True)
class CompositePretestPlan8616:
    """Exact branch set and two outcomes owned by a leading break guard."""

    guard: CIfBreak | CIfElse
    root_condition: ConditionIR
    conditions: tuple[ConditionIR, ...]
    body_target: int
    exit_target: int


@dataclass(frozen=True, slots=True)
class CompositePretestStats8616:
    """Closed evidence accounting for composite pretest condition replacement."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    changed_count: int = 0

    @property
    def changed(self) -> bool:
        """Return whether a guard was materialized."""
        return self.changed_count > 0


def _statements_8616(node: object) -> Iterator[object]:
    """Flatten statement-list wrappers without crossing executable nodes."""
    if isinstance(node, CStatements):
        for statement in node.statements:
            yield from _statements_8616(statement)
    else:
        yield node


def _tags_8616(node: object) -> dict[str, object]:
    """Read optional tags from third-party structured statements."""
    try:
        return cast(_TaggedNode8616, node).tags or {}
    except AttributeError:
        return {}


def _effect_free_guard_8616(expression: CExpression) -> bool:
    """Refuse calls, dirty operations and every executable embedded statement."""
    if classify_condition_call_effects_8616(expression).has_semantic_call:
        return False
    for node in _iter_c_nodes_deep_8616(expression):
        if isinstance(node, (CAssignment, CDirtyExpression)):
            return False
        if isinstance(node, CMultiStatementExpression) and any(_statements_8616(node.stmts)):
            return False
    return True


def _guard_facts_8616(
    guard: CIfBreak | CIfElse,
    typed_conditions: tuple[ConditionIR, ...],
) -> tuple[ConditionIR, ...]:
    """Require a unique typed fact for each branch identity in the guard."""
    keys = _condition_tag_pairs_8616(guard)
    matched: dict[tuple[int, int], ConditionIR] = {}
    for condition in typed_conditions:
        key = (condition.src_insn, condition.block_addr)
        if key not in keys:
            continue
        if key in matched:
            return ()
        matched[key] = condition
    return tuple(matched[key] for key in sorted(matched))


def _outcomes_8616(
    facts: tuple[ConditionIR, ...],
    body_target: int,
    successors: Mapping[int, tuple[int, ...]],
    artifact: SSAFunctionArtifact | None,
) -> set[int]:
    """Collect exact outcomes without bypassing any SSA effects."""
    blocks = frozenset(cast(int, fact.block_addr) for fact in facts)
    if body_target in blocks:
        return set()
    outcomes: set[int] = set()
    for fact in facts:
        targets = (fact.taken_target, fact.fallthrough_target)
        if any(not isinstance(target, int) for target in targets):
            return set()
        if set(targets) != set(successors.get(cast(int, fact.block_addr), ())):
            return set()
        for target in targets:
            normalized = transparent_condition_exit_8616(
                artifact, cast(int, target), successors, stop_at=None,
                retained_targets=blocks | {body_target},
            )
            if normalized not in blocks:
                outcomes.add(normalized)
    return outcomes


def classify_composite_pretest_condition_8616(
    loop: CWhileLoop,
    typed_conditions: tuple[ConditionIR, ...],
    successors: Mapping[int, tuple[int, ...]],
    artifact: SSAFunctionArtifact | None,
) -> CompositePretestPlan8616 | None:
    """Prove one complete, effect-free break guard with exact CFG outcomes."""
    if not isinstance(loop.condition, CConstant) or loop.condition.value != 1:
        return None
    surface = pretest_condition_surface_8616(loop)
    guard = surface.leading_break_guard
    if guard is None or not _effect_free_guard_8616(surface.conditions[-1]):
        return None
    statements = tuple(_statements_8616(loop.body))
    if len(statements) < _BINARY_OUTCOMES or statements[0] is not guard:
        return None
    body_target = _tags_8616(statements[1]).get("vex_block_addr")
    if not isinstance(body_target, int):
        return None
    facts = _guard_facts_8616(guard, typed_conditions)
    if len(facts) < _MIN_COMPOSITE_FACTS:
        return None
    guard_tags = _tags_8616(guard)
    owners = {guard_tags.get("vex_block_addr"), guard_tags.get("ins_addr")}
    roots = tuple(fact for fact in facts if fact.block_addr in owners)
    if len(roots) != 1:
        return None
    outcomes = _outcomes_8616(facts, body_target, successors, artifact)
    if len(outcomes) != _BINARY_OUTCOMES or body_target not in outcomes:
        return None
    return CompositePretestPlan8616(
        guard, roots[0], facts, body_target, next(iter(outcomes - {body_target})),
    )


def materialize_composite_pretest_conditions_8616(
    root: object,
    typed_conditions: tuple[ConditionIR, ...],
    successors: Mapping[int, tuple[int, ...]],
    artifact: SSAFunctionArtifact | None,
    lower_chain: Callable[[CompositePretestPlan8616], CExpression | None],
    record_precision: Callable[[CExpression, CExpression], bool],
) -> CompositePretestStats8616:
    """Materialize complete exit predicates without moving any loop statements."""
    raw_count = classified_count = materialized_count = changed_count = 0
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CWhileLoop):
            continue
        surface = pretest_condition_surface_8616(node)
        guard = surface.leading_break_guard
        if guard is None or len(_guard_facts_8616(guard, typed_conditions)) < _MIN_COMPOSITE_FACTS:
            continue
        raw_count += 1
        plan = classify_composite_pretest_condition_8616(node, typed_conditions, successors, artifact)
        if plan is None:
            continue
        classified_count += 1
        replacement = lower_chain(plan)
        if replacement is None:
            continue
        materialized_count += 1
        current = guard.condition if isinstance(guard, CIfBreak) else guard.condition_and_nodes[0][0]
        if _same_c_expression_8616(current, replacement) and _tags_8616(current).get(
            "inertia_structuring_condition_cfg_materialized_8616"
        ) is True:
            continue
        tags = _tags_8616(replacement).copy()
        tags.update({
            "ins_addr": plan.root_condition.src_insn,
            "vex_block_addr": plan.root_condition.block_addr,
            "inertia_structuring_condition_cfg_materialized_8616": True,
        })
        cast(_TaggedNode8616, replacement).tags = tags
        record_precision(current, replacement)
        if isinstance(guard, CIfBreak):
            guard.condition = replacement
        else:
            guard.condition_and_nodes = [(replacement, guard.condition_and_nodes[0][1])]
        changed_count += 1
    return CompositePretestStats8616(
        raw_count, classified_count, classified_count, materialized_count,
        raw_count - materialized_count, changed_count,
    )
