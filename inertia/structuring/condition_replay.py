"""Retain typed condition orientation across codegen AST regeneration.

Layer: Structuring.
Responsibility: preserve the exact CFG leaf targets used to materialize a
typed condition chain so a later structured-AST rewrite can replay the same
proven orientation after source tags are lost.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.

The facts contain only typed branch identity and CFG addresses. This module
does not inspect C text, infer body meaning, or recover condition semantics.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from inertia.ir.condition_ir import ConditionIR
from inertia.lowering.structured_tags import copy_structured_tags_8616


@dataclass(frozen=True, slots=True)
class StructuringConditionReplayFact8616:
    """Record one proven root condition and its structured leaf targets."""

    root_src_insn: int
    root_block_addr: int
    true_target: int
    false_target: int


class _ConditionReplayCodegen8616(Protocol):
    """Owned metadata slot retained on the active codegen surface."""

    _inertia_structuring_condition_replay_facts_8616: tuple[StructuringConditionReplayFact8616, ...]


class _ConditionReplayExpression8616(Protocol):
    """Third-party structured expression tag surface."""

    tags: object


def bind_condition_replay_identity_8616(
    expression: object,
    condition: ConditionIR,
) -> bool:
    """Restamp one structured condition with its authoritative typed identity."""
    if not isinstance(condition.src_insn, int) or not isinstance(condition.block_addr, int):
        return False
    surface = cast(_ConditionReplayExpression8616, expression)
    try:
        tags = copy_structured_tags_8616(surface.tags) or {}
    except AttributeError:
        return False
    expected = {
        "ins_addr": condition.src_insn,
        "vex_block_addr": condition.block_addr,
    }
    if isinstance(condition.producer_insn, int):
        expected["condition_producer_insn"] = condition.producer_insn
    changed = any(tags.get(key) != value for key, value in expected.items())
    tags.update(expected)
    surface.tags = tags
    return changed


def condition_replay_facts_8616(codegen: object) -> tuple[StructuringConditionReplayFact8616, ...]:
    """Read typed replay facts from the dynamic angr codegen boundary."""
    surface = cast(_ConditionReplayCodegen8616, codegen)
    try:
        return surface._inertia_structuring_condition_replay_facts_8616
    except AttributeError:
        return ()


def record_condition_replay_fact_8616(
    codegen: object,
    condition: ConditionIR,
    true_target: int,
    false_target: int,
) -> None:
    """Store one exact replay fact when the root has complete provenance."""
    if not isinstance(condition.src_insn, int) or not isinstance(condition.block_addr, int):
        return
    fact = StructuringConditionReplayFact8616(
        root_src_insn=condition.src_insn,
        root_block_addr=condition.block_addr,
        true_target=true_target,
        false_target=false_target,
    )
    existing = condition_replay_facts_8616(codegen)
    if fact in existing:
        return
    cast(_ConditionReplayCodegen8616, codegen)._inertia_structuring_condition_replay_facts_8616 = (*existing, fact)


def select_condition_replay_fact_8616(
    condition: ConditionIR,
    facts: tuple[StructuringConditionReplayFact8616, ...],
) -> StructuringConditionReplayFact8616 | None:
    """Return the sole replay fact matching one exact typed root condition."""
    matches = tuple(
        fact
        for fact in facts
        if fact.root_src_insn == condition.src_insn and fact.root_block_addr == condition.block_addr
    )
    return matches[0] if len(matches) == 1 else None
