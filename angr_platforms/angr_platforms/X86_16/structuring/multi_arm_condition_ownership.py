"""Select typed conditions for multi-arm structured CFG nodes.

Layer: Structuring.
Responsibility: Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Recovers condition ownership lost while angr folds a decision
ladder into one ``CIfElse`` node. Selection uses only exact ConditionIR targets
and CFG successors; it does not infer operands or inspect rendered C.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

import itertools
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CBreak, CContinue, CExpression, CIfElse, CLabel, CStatements

from ..ir.condition_ir import ConditionIR
from ..ir.ssa_function import SSAFunctionArtifact
from ..structured_tags import copy_structured_tags_8616
from .condition_exit_normalization import exact_condition_exit_polarity_8616

_BINARY_ARITY = 2


class MultiArmConditionOwnershipStatus8616(Enum):
    """Typed outcomes for one multi-arm ownership selection."""

    SELECTED = "selected"
    TOO_FEW_ARMS = "too_few_arms"
    MISSING_BODY_TARGET = "missing_body_target"
    DUPLICATE_BODY_TARGET = "duplicate_body_target"
    MISSING_UNIQUE_FACT = "missing_unique_fact"
    ROOT_MISMATCH = "root_mismatch"
    DUPLICATE_FACT = "duplicate_fact"
    CFG_EDGE_MISMATCH = "cfg_edge_mismatch"
    DISCONNECTED_FALLTHROUGH = "disconnected_fallthrough"


@dataclass(frozen=True, slots=True)
class MultiArmConditionOwnershipResult8616:
    """Return selected arm facts or one structured refusal."""

    status: MultiArmConditionOwnershipStatus8616
    facts: tuple[ConditionIR, ...] = ()
    detail: str | None = None
    taken_polarities: tuple[bool, ...] = ()

    @property
    def selected(self) -> bool:
        """Return whether every arm has exact CFG-owned condition evidence."""
        return self.status is MultiArmConditionOwnershipStatus8616.SELECTED


@dataclass(frozen=True, slots=True)
class MultiArmConditionMaterializationResult8616[BodyT]:
    """Return replacement predicates with unchanged, precisely typed arm bodies."""

    condition_and_nodes: tuple[tuple[CExpression, BodyT], ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


def _refuse_8616(
    status: MultiArmConditionOwnershipStatus8616,
    detail: str | None = None,
) -> MultiArmConditionOwnershipResult8616:
    """Build one typed ownership refusal."""
    return MultiArmConditionOwnershipResult8616(status=status, detail=detail)


def select_multi_arm_condition_owners_8616(
    arm_body_targets: tuple[int | None, ...],
    conditions: tuple[ConditionIR, ...],
    *,
    root: ConditionIR,
    successors: Mapping[int, tuple[int, ...]],
) -> MultiArmConditionOwnershipResult8616:
    """Select one exact taken-edge condition for every structured arm."""
    if len(arm_body_targets) < _BINARY_ARITY:
        return _refuse_8616(MultiArmConditionOwnershipStatus8616.TOO_FEW_ARMS)
    if any(target is None for target in arm_body_targets):
        return _refuse_8616(
            MultiArmConditionOwnershipStatus8616.MISSING_BODY_TARGET
        )
    targets = tuple(int(target) for target in arm_body_targets if target is not None)
    if len(set(targets)) != len(targets):
        return _refuse_8616(
            MultiArmConditionOwnershipStatus8616.DUPLICATE_BODY_TARGET
        )

    selected: list[ConditionIR] = []
    for target in targets:
        candidates = tuple(
            condition
            for condition in conditions
            if condition.taken_target == target
            and isinstance(condition.block_addr, int)
            and isinstance(condition.fallthrough_target, int)
        )
        if len(candidates) != 1:
            return _refuse_8616(
                MultiArmConditionOwnershipStatus8616.MISSING_UNIQUE_FACT,
                detail=f"target={target:#x}:count={len(candidates)}",
            )
        selected.append(candidates[0])

    if selected[0] != root:
        return _refuse_8616(MultiArmConditionOwnershipStatus8616.ROOT_MISMATCH)
    if len({(fact.block_addr, fact.src_insn) for fact in selected}) != len(
        selected
    ):
        return _refuse_8616(MultiArmConditionOwnershipStatus8616.DUPLICATE_FACT)

    refused = _cfg_edges_proven_8616(selected, successors)
    if refused is not None:
        return refused
    refused = _fallthrough_connected_8616(selected)
    if refused is not None:
        return refused
    return MultiArmConditionOwnershipResult8616(
        status=MultiArmConditionOwnershipStatus8616.SELECTED,
        facts=tuple(selected),
    )


def _cfg_edges_proven_8616(
    selected: list[ConditionIR],
    successors: Mapping[int, tuple[int, ...]],
) -> MultiArmConditionOwnershipResult8616 | None:
    """Refuse when any selected fact's edges are absent from the CFG."""
    for fact in selected:
        block_addr = fact.block_addr
        if not isinstance(block_addr, int):
            return _refuse_8616(
                MultiArmConditionOwnershipStatus8616.CFG_EDGE_MISMATCH
            )
        block_successors = successors.get(block_addr, ())
        if (
            fact.taken_target not in block_successors
            or fact.fallthrough_target not in block_successors
        ):
            return _refuse_8616(
                MultiArmConditionOwnershipStatus8616.CFG_EDGE_MISMATCH,
                detail=f"block={block_addr:#x}",
            )
    return None


def _fallthrough_connected_8616(
    selected: list[ConditionIR],
) -> MultiArmConditionOwnershipResult8616 | None:
    """Refuse when consecutive selected facts are not fallthrough-linked."""
    for current, following in itertools.pairwise(selected):
        if current.fallthrough_target != following.block_addr:
            return _refuse_8616(
                MultiArmConditionOwnershipStatus8616.DISCONNECTED_FALLTHROUGH,
                detail=(
                    f"from={current.fallthrough_target!r}:"
                    f"to={following.block_addr!r}"
                ),
            )
    return None


def materialize_multi_arm_condition_owners_8616[BodyT](
    condition_and_nodes: tuple[tuple[CExpression, BodyT], ...],
    ownership: MultiArmConditionOwnershipResult8616,
    materialize: Callable[[ConditionIR], CExpression | None],
    *,
    invert: Callable[[CExpression], CExpression] | None = None,
) -> MultiArmConditionMaterializationResult8616[BodyT]:
    """Materialize selected facts while preserving third-party AST tags."""
    raw_count = len(condition_and_nodes)
    polarity_count_valid = not ownership.taken_polarities or len(ownership.taken_polarities) == raw_count
    if not ownership.selected or len(ownership.facts) != raw_count or not polarity_count_valid:
        return MultiArmConditionMaterializationResult8616(
            condition_and_nodes=(),
            raw_fact_count=raw_count,
            normalized_fact_count=0,
            classified_fact_count=0,
            materialized_count=0,
            failure_count=1,
        )
    replacements: list[tuple[CExpression, BodyT]] = []
    for index, ((condition, body), fact) in enumerate(zip(condition_and_nodes, ownership.facts, strict=True)):
        taken = ownership.taken_polarities[index] if ownership.taken_polarities else True
        replacement = materialize(fact)
        if replacement is None or (not taken and invert is None):
            return MultiArmConditionMaterializationResult8616(
                condition_and_nodes=(),
                raw_fact_count=raw_count,
                normalized_fact_count=raw_count,
                classified_fact_count=raw_count,
                materialized_count=0,
                failure_count=1,
            )
        if not taken:
            assert invert is not None
            replacement = invert(replacement)
        tags = copy_structured_tags_8616(condition.tags) or {}
        if isinstance(fact.src_insn, int):
            tags["ins_addr"] = fact.src_insn
        if isinstance(fact.block_addr, int):
            tags["vex_block_addr"] = fact.block_addr
        if isinstance(fact.producer_insn, int):
            tags["condition_producer_insn"] = fact.producer_insn
        tags["inertia_structuring_condition_cfg_materialized_8616"] = True
        tags["inertia_structuring_multi_arm_owner_materialized_8616"] = True
        replacement.tags = tags
        replacements.append((replacement, body))
    return MultiArmConditionMaterializationResult8616(
        condition_and_nodes=tuple(replacements),
        raw_fact_count=raw_count,
        normalized_fact_count=raw_count,
        classified_fact_count=raw_count,
        materialized_count=raw_count,
        failure_count=0,
    )


def select_exact_multi_arm_condition_owners_8616(
    arm_body_targets: tuple[int | None, ...],
    facts: tuple[ConditionIR, ...],
    *,
    else_target: int | None,
    successors: Mapping[int, tuple[int, ...]],
    artifact: SSAFunctionArtifact | None = None,
) -> MultiArmConditionOwnershipResult8616:
    """Prove a decision ladder through exact edges or effect-free SSA connectors.

    Physical ConditionIR edges remain authoritative and unchanged for replay.
    Normalization stops at every body and condition owner, never bypassing them.
    """
    if len(facts) < _BINARY_ARITY or len(arm_body_targets) != len(facts):
        return _refuse_8616(MultiArmConditionOwnershipStatus8616.TOO_FEW_ARMS)
    if else_target is None or any(target is None for target in arm_body_targets):
        return _refuse_8616(MultiArmConditionOwnershipStatus8616.MISSING_BODY_TARGET)
    identities = {(fact.block_addr, fact.src_insn) for fact in facts}
    if len(identities) != len(facts):
        return _refuse_8616(MultiArmConditionOwnershipStatus8616.DUPLICATE_FACT)
    polarities: list[bool] = []
    retained_targets = frozenset(
        target for target in (*arm_body_targets, else_target, *(fact.block_addr for fact in facts))
        if target is not None
    )
    for index, (target, fact) in enumerate(zip(arm_body_targets, facts, strict=True)):
        continuation = facts[index + 1].block_addr if index + 1 < len(facts) else else_target
        if fact.block_addr is None or fact.src_insn is None or continuation is None:
            return _refuse_8616(MultiArmConditionOwnershipStatus8616.MISSING_UNIQUE_FACT)
        expected_edges = {fact.taken_target, fact.fallthrough_target}
        if None in expected_edges or len(expected_edges) != _BINARY_ARITY or set(successors.get(fact.block_addr, ())) != expected_edges:
            return _refuse_8616(MultiArmConditionOwnershipStatus8616.CFG_EDGE_MISMATCH)
        polarity = exact_condition_exit_polarity_8616(
            artifact, fact, target, continuation, successors, retained_targets=retained_targets,
        )
        if polarity is None:
            return _refuse_8616(MultiArmConditionOwnershipStatus8616.DISCONNECTED_FALLTHROUGH)
        polarities.append(polarity)
    return MultiArmConditionOwnershipResult8616(
        MultiArmConditionOwnershipStatus8616.SELECTED, facts,
        taken_polarities=tuple(polarities),
    )


class _StatementTags8616(Protocol):
    """Dynamic angr statement tag boundary, separate from operand provenance."""

    tags: object


class _LabelCodegen8616(Protocol):
    """angr's authoritative label-address identity map."""

    map_addr_to_label: Mapping[tuple[int, int | None], CLabel]


def _label_entry_8616(label: CLabel) -> int | None:
    """Resolve one registered label by object identity, never its printed name."""
    try:
        labels = cast(_LabelCodegen8616, label.codegen).map_addr_to_label
    except AttributeError:
        return None
    addresses = [address for (address, _index), candidate in labels.items() if candidate is label]
    if len(addresses) != 1 or label.tags.get("ins_addr") != addresses[0]:
        return None
    return addresses[0]


def first_statement_block_8616(body: object) -> int | None:
    """Read a statement entry, registered label or already-bound guard owner.

    A nested condition supplies its root identity only after CFG ownership was
    materialized. Never use a descendant operand or an unbound condition tag.
    """
    while isinstance(body, CStatements) and body.statements:
        body = body.statements[0]
    if isinstance(body, (CStatements, CBreak, CContinue)):
        return None
    if isinstance(body, CLabel):
        return _label_entry_8616(body)
    if isinstance(body, CIfElse) and body.condition_and_nodes:
        condition, _arm = body.condition_and_nodes[0]
        owned = condition.tags.get("inertia_structuring_condition_cfg_materialized_8616") is True
        same_owner = condition.tags.get("ins_addr") == body.tags.get("ins_addr")
        if owned and same_owner:
            block = condition.tags.get("vex_block_addr")
            if isinstance(block, int) and not isinstance(block, bool):
                return block
    try:
        tags = copy_structured_tags_8616(cast(_StatementTags8616, body).tags) or {}
    except AttributeError:
        return None
    block = tags.get("vex_block_addr")
    return block if isinstance(block, int) and not isinstance(block, bool) else None
