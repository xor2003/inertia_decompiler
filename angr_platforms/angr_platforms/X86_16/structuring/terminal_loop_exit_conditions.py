"""Consume complete wide decision graphs at existing terminal loop breaks.

Layer: Structuring.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence. Do not perform alias-state ownership, widening,
type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting
work here.
Responsibility: bind an effect-free terminal guard to its proven natural-loop
exit without moving preceding calls or changing the break body. Wide storage
and call capture remain in Types/Lowering; this owner proves only CFG polarity
and exact branch coverage. Never infer destinations from break-source tags.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CExpression,
    CIfBreak,
    CIfElse,
    CWhileLoop,
)

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..ir.condition_ir import ConditionIR
from ..ir.ssa_function import SSAFunctionArtifact
from ..pipeline.errors import PipelineHardError
from .composite_pretest_conditions import _effect_free_guard_8616, _guard_facts_8616, _statements_8616
from .condition_chain_provenance import bind_condition_chain_provenance_8616
from .existing_loop_exit_conditions import ExistingLoopExitStats8616, _loop_owner_8616, _sole_break_8616
from .loop_break_topology import LoopBreakTopology8616
from .natural_loop_topology import _header_dominated_nodes_8616
from .wide_call_condition_plan import WideCallConditionPlan8616, plan_wide_call_condition_8616

TERMINAL_WIDE_DECISION_TAG_8616: str = "inertia_terminal_wide_decision_8616"


@dataclass(frozen=True, slots=True)
class TerminalWideDecision8616:
    """Immutable complete decision and natural-loop owner for final validation."""

    comparison: WideCallConditionPlan8616
    loop_header: int


@dataclass(frozen=True, slots=True)
class TerminalLoopExitPlan8616:
    """Complete typed decision and the exact terminal guard it may replace."""

    guard: CIfBreak | CIfElse
    current: CExpression
    comparison: WideCallConditionPlan8616
    loop_header: int


def _terminal_guard_8616(loop: CWhileLoop) -> tuple[CIfBreak | CIfElse, CExpression] | None:
    """Require a direct final break guard, never a nested conditional exit."""
    statements = tuple(_statements_8616(loop.body))
    if not statements:
        return None
    guard = statements[-1]
    if isinstance(guard, CIfBreak):
        return guard, guard.condition
    if isinstance(guard, CIfElse) and guard.else_node is None and len(guard.condition_and_nodes) == 1:
        condition, body = guard.condition_and_nodes[0]
        if _sole_break_8616(body):
            return guard, condition
    return None


def classify_terminal_loop_exit_8616(
    loop: CWhileLoop,
    typed_conditions: tuple[ConditionIR, ...],
    topology: LoopBreakTopology8616,
    successors: dict[int, tuple[int, ...]],
    artifact: SSAFunctionArtifact | None,
) -> TerminalLoopExitPlan8616 | None:
    """Require all loop branches and a unique exhaustive wide exit decision."""
    if not isinstance(loop.condition, CConstant) or loop.condition.value != 1:
        return None
    owner = _loop_owner_8616(loop, topology)
    surface = _terminal_guard_8616(loop)
    if owner is None or surface is None:
        return None
    guard, current = surface
    if not _effect_free_guard_8616(current):
        return None
    facts = _guard_facts_8616(guard, typed_conditions)
    loop_facts = tuple(fact for fact in typed_conditions if fact.block_addr in owner.body)
    # A complete loop decision cannot silently omit an inner or untagged branch.
    if not facts or len(facts) != len(loop_facts) or any(fact not in loop_facts for fact in facts):
        return None
    blocks = {cast(int, fact.block_addr): fact for fact in facts}
    destinations = {target for _, target in owner.exit_edges}
    if len(blocks) != len(facts) or len(destinations) != 1:
        return None
    if any(source not in blocks for source, _ in owner.exit_edges):
        return None
    destination = next(iter(destinations))
    plans = tuple(
        plan for fact in facts
        if (plan := plan_wide_call_condition_8616(
            fact, blocks, successors, destination, owner.header, artifact=artifact,
        )) is not None
        and len(plan.conditions) == len(facts)
        and all(condition in facts for condition in plan.conditions)
    )
    if len(plans) != 1:
        return None
    # Every iteration must enter the whole decision, never a lower-word suffix.
    root_block = cast(int, plans[0].conditions[0].block_addr)
    dominated = _header_dominated_nodes_8616(owner.header, root_block, lambda block: successors.get(block, ()))
    if not {*blocks, owner.latch}.issubset(dominated):
        return None
    return TerminalLoopExitPlan8616(guard, current, plans[0], owner.header)


def materialize_terminal_loop_exit_conditions_8616(
    root: object,
    typed_conditions: tuple[ConditionIR, ...],
    topology: LoopBreakTopology8616 | None,
    successors: dict[int, tuple[int, ...]],
    artifact: SSAFunctionArtifact | None,
    lower: Callable[[WideCallConditionPlan8616], CExpression | None],
    record_precision: Callable[[CExpression, CExpression], bool],
) -> ExistingLoopExitStats8616:
    """Replace only a fully proven terminal predicate, preserving every statement."""
    if topology is None:
        return ExistingLoopExitStats8616()
    raw = classified = materialized = 0
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CWhileLoop) or _terminal_guard_8616(node) is None:
            continue
        raw += 1
        plan = classify_terminal_loop_exit_8616(node, typed_conditions, topology, successors, artifact)
        if plan is None:
            continue
        classified += 1
        replacement = lower(plan.comparison)
        fact = plan.comparison.conditions[0]
        if replacement is None:
            raise PipelineHardError(
                f"terminal-loop-exit jcc={fact.src_insn:#x}: complete decision could not be lowered"
            )
        provenance = bind_condition_chain_provenance_8616(replacement, plan.comparison.conditions)
        if provenance is None:
            raise PipelineHardError(f"terminal-loop-exit jcc={fact.src_insn:#x}: incomplete branch provenance")
        replacement.tags.update({
            TERMINAL_WIDE_DECISION_TAG_8616: TerminalWideDecision8616(plan.comparison, plan.loop_header),
            "ins_addr": fact.src_insn,
            "vex_block_addr": fact.block_addr,
            "inertia_structuring_condition_cfg_materialized_8616": True,
        })
        record_precision(plan.current, replacement)
        if isinstance(plan.guard, CIfBreak):
            plan.guard.condition = replacement
        else:
            plan.guard.condition_and_nodes = [(replacement, plan.guard.condition_and_nodes[0][1])]
        materialized += 1
    return ExistingLoopExitStats8616(raw, classified, classified, materialized, raw - materialized, materialized)
