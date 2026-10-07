"""Materialize atomic multi-arm wide return chains from typed CFG evidence.

Layer: Structuring.
Responsibility: replace structured multi-arm register-return scaffolding only
after every arm predicate and return leaf is proved from typed CFG semantics.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.

This boundary prevents a later single-branch recovery pass from retaining only
one arm of an if/else-if return chain. Recovery is atomic: an unknown predicate,
leaf, or observable body effect refuses the complete candidate without mutation.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum
from typing import cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CExpression,
    CIfElse,
    CReturn,
    CStatement,
    CStatements,
    CVariable,
)
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from inertia.ir.condition_ir import ConditionIR

log: logging.Logger = logging.getLogger(__name__)

type MultiArmConditionMaterializer8616 = Callable[
    [ConditionIR, int, int], CExpression | None
]
type MultiArmReturnRecoverer8616 = Callable[[int], CExpression | None]
type MultiArmBodyTargetResolver8616 = Callable[[object], int | None]


class MultiArmReturnChainStatus8616(Enum):
    """Typed outcome of one atomic multi-arm return-chain attempt."""

    MATERIALIZED = "materialized"
    REFUSED = "refused"


@dataclass(frozen=True, slots=True)
class MultiArmReturnCandidate8616:
    """One ordered structured arm and its exact CFG ownership evidence."""

    fact: ConditionIR
    structured_condition: CExpression
    body: object
    true_target: int
    false_target: int


@dataclass(frozen=True, slots=True)
class MultiArmReturnChainStats8616:
    """Closed evidence accounting for one atomic multi-arm recovery."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class MultiArmReturnChainResult8616:
    """Atomic replacement nodes and evidence status for one return chain."""

    status: MultiArmReturnChainStatus8616
    condition_and_nodes: tuple[tuple[CExpression, CStatement | None], ...] = ()
    else_node: CStatement | None = None
    return_expressions: tuple[CExpression, ...] = ()
    stats: MultiArmReturnChainStats8616 = MultiArmReturnChainStats8616()


def _refused_result_8616(raw_count: int) -> MultiArmReturnChainResult8616:
    """Build one typed atomic refusal with closed evidence accounting."""
    return MultiArmReturnChainResult8616(
        MultiArmReturnChainStatus8616.REFUSED,
        stats=MultiArmReturnChainStats8616(
            raw_fact_count=raw_count,
            failure_count=1 if raw_count else 0,
        ),
    )


def _debug_return_setup_8616(event: str, **fields: object) -> None:
    """Log one structured return-setup decision when diagnostics are enabled."""
    if os.environ.get("INERTIA_DEBUG_CONDITION_MATERIALIZATION") != "1":
        return
    details = " ".join(f"{key}={value!r}" for key, value in sorted(fields.items()))
    log.warning("[multi-arm-return-chain] event=%s %s", event, details)


def is_wide_register_return_setup_body_8616(body: object) -> bool:
    """Prove that a body contains only adjacent stack words copied to registers."""
    if not isinstance(body, CStatements):
        _debug_return_setup_8616("body-type-refused", body_type=type(body).__name__)
        return False
    statements = tuple(cast(Iterable[object], body.statements or ()))
    if len(statements) != 2:
        _debug_return_setup_8616(
            "statement-count-refused",
            statement_count=len(statements),
            statement_types=tuple(type(statement).__name__ for statement in statements),
        )
        return False
    assignments: list[CAssignment] = []
    for statement in statements:
        if not isinstance(statement, CAssignment):
            _debug_return_setup_8616(
                "statement-type-refused", statement_type=type(statement).__name__
            )
            return False
        assignments.append(statement)
    register_offsets: set[int] = set()
    stack_slices: list[SimStackVariable] = []
    for assignment in assignments:
        if not isinstance(assignment.lhs, CVariable) or not isinstance(
            assignment.rhs, CVariable
        ):
            _debug_return_setup_8616(
                "assignment-expression-refused",
                lhs_type=type(assignment.lhs).__name__,
                rhs_type=type(assignment.rhs).__name__,
            )
            return False
        lhs = assignment.lhs.variable
        rhs = assignment.rhs.variable
        if (
            not isinstance(lhs, SimRegisterVariable)
            or lhs.size != 2
            or not isinstance(rhs, SimStackVariable)
            or rhs.size not in {2, 4}
            or not isinstance(rhs.offset, int)
        ):
            _debug_return_setup_8616(
                "assignment-variable-refused",
                lhs_shape=(lhs.reg, lhs.size)
                if isinstance(lhs, SimRegisterVariable)
                else None,
                lhs_type=type(lhs).__name__,
                rhs_shape=(rhs.base, rhs.offset, rhs.size)
                if isinstance(rhs, SimStackVariable)
                else None,
                rhs_type=type(rhs).__name__,
            )
            return False
        register_offsets.add(lhs.reg)
        stack_slices.append(rhs)
    ordered = sorted(stack_slices, key=lambda variable: variable.offset)
    stack_pair_is_safe = (
        ordered[0].base == ordered[1].base
        and max(variable.offset + variable.size for variable in ordered)
        - min(variable.offset for variable in ordered)
        == 4
    )
    safe = len(register_offsets) == 2 and stack_pair_is_safe
    if not safe:
        _debug_return_setup_8616(
            "pair-shape-refused",
            register_offsets=tuple(sorted(register_offsets)),
            stack_slices=tuple(
                (variable.base, variable.offset, variable.size)
                for variable in ordered
            ),
        )
    return safe


def _is_materialized_return_body_8616(body: object) -> bool:
    """Return whether one structured body contains exactly one return."""
    if not isinstance(body, CStatements):
        return False
    statements = tuple(cast(Iterable[object], body.statements or ()))
    return len(statements) == 1 and isinstance(statements[0], CReturn)


def is_materialized_multi_arm_return_chain_8616(
    structured_arms: tuple[tuple[CExpression, object], ...],
    else_body: object,
) -> bool:
    """Return whether every arm is an already-proved return-chain replacement."""
    return (
        len(structured_arms) >= 2
        and all(
            condition.tags.get(
                "inertia_structuring_multi_arm_return_chain_materialized_8616"
            )
            is True
            and _is_materialized_return_body_8616(body)
            for condition, body in structured_arms
        )
        and _is_materialized_return_body_8616(else_body)
    )


def multi_arm_wide_return_obligation_count_8616(root: object) -> int:
    """Count arms in a structured wide-return chain that must not be discarded."""
    pending = [root]
    while pending:
        current = pending.pop()
        if isinstance(current, CIfElse):
            arms = tuple(current.condition_and_nodes or ())
            bodies = tuple(body for _condition, body in arms)
            if (
                len(arms) >= 2
                and current.else_node is not None
                and all(
                    is_wide_register_return_setup_body_8616(body)
                    or _is_materialized_return_body_8616(body)
                    for body in (*bodies, current.else_node)
                )
            ):
                return len(arms)
            pending.extend(body for _condition, body in arms if body is not None)
            if current.else_node is not None:
                pending.append(current.else_node)
        elif isinstance(current, CStatements):
            pending.extend(cast(Iterable[object], current.statements or ()))
    return 0


def _return_body_8616(
    codegen: object,
    original_body: object,
    expression: CExpression,
    target_addr: int,
) -> CStatements:
    """Build one return body while preserving the original CFG tags."""
    body_tags = dict(original_body.tags) if isinstance(original_body, CStatements) else {}
    body_tags.setdefault("ins_addr", target_addr)
    body_tags.setdefault("vex_block_addr", target_addr)
    statement = CReturn(expression, codegen=codegen, tags=dict(body_tags))
    return CStatements([statement], codegen=codegen, tags=body_tags)


def recover_multi_arm_wide_return_chain_8616(
    codegen: object,
    candidates: tuple[MultiArmReturnCandidate8616, ...],
    else_body: object,
    else_target: int,
    materialize_condition: MultiArmConditionMaterializer8616,
    recover_return: MultiArmReturnRecoverer8616,
) -> MultiArmReturnChainResult8616:
    """Build an all-or-nothing multi-arm return replacement from typed evidence."""
    raw_count = len(candidates)
    refused = _refused_result_8616(raw_count)
    if raw_count < 2 or not isinstance(else_target, int):
        return refused
    if not is_wide_register_return_setup_body_8616(else_body):
        return refused
    if any(
        not is_wide_register_return_setup_body_8616(candidate.body)
        for candidate in candidates
    ):
        return refused

    conditions: list[CExpression] = []
    returns: list[CExpression] = []
    for candidate in candidates:
        condition = materialize_condition(
            candidate.fact,
            candidate.true_target,
            candidate.false_target,
        )
        returned = recover_return(candidate.true_target)
        if condition is None or returned is None:
            return refused
        tags = dict(candidate.structured_condition.tags)
        if isinstance(candidate.fact.src_insn, int):
            tags["ins_addr"] = candidate.fact.src_insn
        if isinstance(candidate.fact.block_addr, int):
            tags["vex_block_addr"] = candidate.fact.block_addr
        if isinstance(candidate.fact.producer_insn, int):
            tags["condition_producer_insn"] = candidate.fact.producer_insn
        tags["inertia_structuring_condition_cfg_materialized_8616"] = True
        tags["inertia_structuring_multi_arm_return_chain_materialized_8616"] = True
        condition.tags = tags
        conditions.append(condition)
        returns.append(returned)
    else_return = recover_return(else_target)
    if else_return is None:
        return refused

    replacement_arms = tuple(
        (
            condition,
            _return_body_8616(
                codegen, candidate.body, returned, candidate.true_target
            ),
        )
        for candidate, condition, returned in zip(
            candidates, conditions, returns, strict=True
        )
    )
    return MultiArmReturnChainResult8616(
        MultiArmReturnChainStatus8616.MATERIALIZED,
        condition_and_nodes=replacement_arms,
        else_node=_return_body_8616(codegen, else_body, else_return, else_target),
        return_expressions=(*returns, else_return),
        stats=MultiArmReturnChainStats8616(
            raw_fact_count=raw_count,
            normalized_fact_count=raw_count,
            classified_fact_count=raw_count,
            materialized_count=raw_count,
        ),
    )


def recover_structured_multi_arm_wide_return_chain_8616(
    codegen: object,
    structured_arms: tuple[tuple[CExpression, object], ...],
    facts: tuple[ConditionIR, ...],
    else_body: object,
    resolve_body_target: MultiArmBodyTargetResolver8616,
    materialize_condition: MultiArmConditionMaterializer8616,
    recover_return: MultiArmReturnRecoverer8616,
) -> MultiArmReturnChainResult8616:
    """Resolve ordered CFG targets and recover one complete structured return chain."""
    raw_count = len(structured_arms)
    if raw_count < 2 or len(facts) != raw_count:
        return _refused_result_8616(raw_count)
    true_targets = tuple(resolve_body_target(body) for _condition, body in structured_arms)
    else_target = resolve_body_target(else_body)
    if else_target is None or any(target is None for target in true_targets):
        return _refused_result_8616(raw_count)
    proven_true_targets = cast(tuple[int, ...], true_targets)
    false_targets = tuple(
        facts[index + 1].block_addr if index + 1 < raw_count else else_target
        for index in range(raw_count)
    )
    if any(not isinstance(target, int) for target in false_targets):
        return _refused_result_8616(raw_count)
    candidates = tuple(
        MultiArmReturnCandidate8616(
            fact,
            condition,
            body,
            true_target,
            cast(int, false_target),
        )
        for (condition, body), fact, true_target, false_target in zip(
            structured_arms,
            facts,
            proven_true_targets,
            false_targets,
            strict=True,
        )
    )
    return recover_multi_arm_wide_return_chain_8616(
        codegen,
        candidates,
        else_body,
        else_target,
        materialize_condition,
        recover_return,
    )
