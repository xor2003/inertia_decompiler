# cython: language_level=3, infer_types=True
"""Prove multi-arm ownership of shared-epilogue scalar return ladders.

Layer: Structuring.
Responsibility: Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.

Cloned return statements inside a shared epilogue carry the same
``vex_block_addr``, so statement tags cannot distinguish ladder arms and
exact-edge selection must refuse. Ownership is instead proven from CFG path
evidence plus native classified return effects: every arm body must be a sole
scalar return, one resolved edge of each earlier fact must reach the next
condition, and the opposite edge must be a complete native return leaf whose
recovered signed-word expression matches that body's return value. The final
fact must prove both leaves against the last body and the else body. Ambiguous
values, unproved leaves, side-effectful bodies, and mismatched edges refuse
with a typed status.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Callable, Mapping

from angr.analyses.decompiler.structured_codegen.c import CConstant, CExpression, CVariable

from inertia.ir.condition_ir import ConditionIR
from inertia.ir.ssa_function import SSAFunctionArtifact
from inertia.lowering.c_ast_utils import _same_c_expression_8616

from .branch_return_expressions import sole_return_expression_8616
from .condition_comparison_polarity import _operand_storage_matches_8616, _operand_value_width_8616
from .condition_exit_normalization import transparent_condition_exit_8616
from .condition_storage_identity import _strip_casts_8616
from .multi_arm_condition_ownership import (
    MultiArmConditionOwnershipResult8616,
    MultiArmConditionOwnershipStatus8616,
)
from .scalar_return_evidence import _is_signed_word_expression_8616
import operator

_BINARY_EDGES = 2


@cython.ccall
def _refuse_scalar_8616(
    status: MultiArmConditionOwnershipStatus8616,
    detail: object = None,
) -> MultiArmConditionOwnershipResult8616:
    """Build one typed scalar return-arm ownership refusal."""
    return MultiArmConditionOwnershipResult8616(status=status, detail=detail)


@cython.ccall
def _same_proven_scalar_return_8616(body: CExpression, leaf: CExpression) -> cython.bint:
    """Match complete word literals or proven full-width variable projections."""
    if _operand_value_width_8616(body) != 16 or _operand_value_width_8616(leaf) != 16:
        return False
    if isinstance(body, CConstant) and isinstance(leaf, CConstant):
        if not isinstance(body.value, int) or not isinstance(leaf.value, int):
            return False
        if not (-32768 <= body.value <= 65535 and -32768 <= leaf.value <= 65535):
            return False
        return operator.eq(body.value & 0xffff, leaf.value & 0xffff)
    if not _operand_storage_matches_8616(body, leaf, same_expression=_same_c_expression_8616):
        return False
    return isinstance(_strip_casts_8616(body), CVariable) and isinstance(_strip_casts_8616(leaf), CVariable)


@cython.ccall
def _recovered_scalar_return_leaf_8616(
    leaf_addr: cython.longlong,
    retained_blocks: object,
    recover_return: Callable[[int], CExpression | None],
) -> CExpression | None:
    """Recover one proven signed-word return expression for a CFG leaf."""
    if leaf_addr in retained_blocks:
        return None
    value = recover_return(leaf_addr)
    if not _is_signed_word_expression_8616(value):
        return None
    return value


@cython.ccall
def _scalar_fact_targets_8616(
    fact: ConditionIR,
    successors: Mapping[cython.longlong, tuple[cython.longlong, ...]],
) -> object:
    """Validate complete integer coordinates against the exact CFG edge pair."""
    block_addr = fact.block_addr
    if (
        not isinstance(block_addr, int)
        or isinstance(block_addr, bool)
        or not isinstance(fact.src_insn, int)
        or isinstance(fact.src_insn, bool)
    ):
        return _refuse_scalar_8616(
            MultiArmConditionOwnershipStatus8616.MISSING_UNIQUE_FACT
        )
    taken, fallthrough = fact.taken_target, fact.fallthrough_target
    if not isinstance(taken, int) or isinstance(taken, bool) or not isinstance(fallthrough, int) or isinstance(fallthrough, bool):
        return _refuse_scalar_8616(MultiArmConditionOwnershipStatus8616.CFG_EDGE_MISMATCH)
    edges = {taken, fallthrough}
    if (
        operator.ne(len(edges), _BINARY_EDGES)
        or operator.ne(set(successors.get(block_addr, ())), edges)
    ):
        return _refuse_scalar_8616(
            MultiArmConditionOwnershipStatus8616.CFG_EDGE_MISMATCH,
            detail=f"block={block_addr:#x}",
        )
    return taken, fallthrough


@cython.ccall
def _select_scalar_fact_polarity_8616(
    index: cython.longlong,
    facts: object,
    arm_values: object,
    else_value: CExpression,
    successors: Mapping[cython.longlong, tuple[cython.longlong, ...]],
    artifact: SSAFunctionArtifact | None,
    retained_blocks: object,
    recover_return: Callable[[int], CExpression | None],
) -> bool | MultiArmConditionOwnershipResult8616:
    """Prove one arm's native leaf and continuation, or return a typed refusal."""
    fallthrough_value: object
    leaf_value: object
    taken_value: object
    fact = facts[index]
    last_index = len(facts) - 1
    targets = _scalar_fact_targets_8616(fact, successors)
    if isinstance(targets, MultiArmConditionOwnershipResult8616):
        return targets
    taken, fallthrough = targets
    block_addr = fact.block_addr
    resolved_taken = transparent_condition_exit_8616(
        artifact,
        taken,
        successors,
        stop_at=None,
        retained_targets=retained_blocks,
    )
    resolved_fallthrough = transparent_condition_exit_8616(
        artifact,
        fallthrough,
        successors,
        stop_at=None,
        retained_targets=retained_blocks,
    )
    if index < last_index:
        continuation = facts[index + 1].block_addr
        if not isinstance(continuation, int) or isinstance(continuation, bool):
            return _refuse_scalar_8616(
                MultiArmConditionOwnershipStatus8616.MISSING_UNIQUE_FACT
            )
        continuation_on_taken = resolved_taken == continuation
        if continuation_on_taken == (resolved_fallthrough == continuation):
            return _refuse_scalar_8616(
                MultiArmConditionOwnershipStatus8616.DISCONNECTED_FALLTHROUGH,
                detail=f"block={block_addr:#x}",
            )
        leaf_addr = (
            resolved_fallthrough if continuation_on_taken else resolved_taken
        )
        leaf_value = _recovered_scalar_return_leaf_8616(
            leaf_addr, retained_blocks, recover_return
        )
        if leaf_value is None:
            return _refuse_scalar_8616(
                MultiArmConditionOwnershipStatus8616.RETURN_LEAF_UNPROVED,
                detail=f"leaf={leaf_addr:#x}",
            )
        if not _same_proven_scalar_return_8616(arm_values[index], leaf_value):
            return _refuse_scalar_8616(
                MultiArmConditionOwnershipStatus8616.RETURN_VALUE_MISMATCH,
                detail=f"arm={index}",
            )
        return not continuation_on_taken
    taken_value = _recovered_scalar_return_leaf_8616(
        resolved_taken, retained_blocks, recover_return
    )
    fallthrough_value = _recovered_scalar_return_leaf_8616(
        resolved_fallthrough, retained_blocks, recover_return
    )
    if taken_value is None or fallthrough_value is None:
        return _refuse_scalar_8616(
            MultiArmConditionOwnershipStatus8616.RETURN_LEAF_UNPROVED,
            detail=f"block={block_addr:#x}",
        )
    body_value = arm_values[index]
    direct = _same_proven_scalar_return_8616(
        body_value, taken_value
    ) and _same_proven_scalar_return_8616(else_value, fallthrough_value)
    inverse = _same_proven_scalar_return_8616(
        body_value, fallthrough_value
    ) and _same_proven_scalar_return_8616(else_value, taken_value)
    if direct == inverse:
        status = (
            MultiArmConditionOwnershipStatus8616.AMBIGUOUS_RETURN
            if direct
            else MultiArmConditionOwnershipStatus8616.RETURN_VALUE_MISMATCH
        )
        return _refuse_scalar_8616(status, detail=f"block={block_addr:#x}")
    return direct


def select_scalar_return_arm_owners_8616(
    arm_bodies: object,
    else_body: object,
    facts: object,
    *,
    successors: Mapping[cython.longlong, tuple[cython.longlong, ...]],
    artifact: SSAFunctionArtifact | None = None,
    recover_return: Callable[[int], CExpression | None],
) -> MultiArmConditionOwnershipResult8616:
    """Select ladder facts when shared epilogues erase distinct body targets.

    For each arm before the last, exactly one transparently resolved edge must
    reach the next condition block while the other resolves to a complete
    native return leaf matching that arm's sole-return value. The final fact
    must orient both leaves against the last arm body and the else body; equal
    leaf values that cannot prove orientation refuse. Selected polarity is
    ``True`` when the structured true-arm sits on the fact's taken edge.
    """
    body: object
    index: object
    if len(facts) < _BINARY_EDGES or operator.ne(len(arm_bodies), len(facts)):
        return _refuse_scalar_8616(
            MultiArmConditionOwnershipStatus8616.TOO_FEW_ARMS
        )
    if else_body is None:
        return _refuse_scalar_8616(
            MultiArmConditionOwnershipStatus8616.MISSING_BODY_TARGET
        )
    identities = {(fact.block_addr, fact.src_insn) for fact in iter(facts)}
    if operator.ne(len(identities), len(facts)):
        return _refuse_scalar_8616(
            MultiArmConditionOwnershipStatus8616.DUPLICATE_FACT
        )
    arm_values: list[CExpression] = []
    for index, body in enumerate(arm_bodies):
        value = sole_return_expression_8616(body)
        if not isinstance(value, CExpression):
            return _refuse_scalar_8616(
                MultiArmConditionOwnershipStatus8616.RETURN_BODY_UNPROVED,
                detail=f"arm={index}",
            )
        arm_values.append(value)
    else_value = sole_return_expression_8616(else_body)
    if not isinstance(else_value, CExpression):
        return _refuse_scalar_8616(
            MultiArmConditionOwnershipStatus8616.RETURN_BODY_UNPROVED,
            detail="else",
        )

    retained_blocks = frozenset(
        fact.block_addr
        for fact in iter(facts)
        if isinstance(fact.block_addr, int) and not isinstance(fact.block_addr, bool)
    )
    polarities: list[cython.bint] = []
    for index in range(len(facts)):
        selected = _select_scalar_fact_polarity_8616(
            index, facts, arm_values, else_value, successors,
            artifact, retained_blocks, recover_return,
        )
        if not isinstance(selected, bool):
            return selected
        polarities.append(selected)
    return MultiArmConditionOwnershipResult8616(
        status=MultiArmConditionOwnershipStatus8616.SELECTED,
        facts=facts,
        taken_polarities=tuple(polarities),
    )
