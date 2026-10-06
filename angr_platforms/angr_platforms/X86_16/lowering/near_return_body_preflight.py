"""Preflight a retained scalar return before near-pointer type publication.

Layer: Types/Lowering.
Responsibility: close the structured body census and ensure pointer promotion
cannot reinterpret any base-argument use outside the proven return expression.
This mutation-free plan grants neither native-pointer nor segment authority.
Unknown node kinds, cycles and unsupported body shapes refuse and retain code.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from angr.analyses.decompiler.structured_codegen import c as structured_c

from .gp_word_assignment import CGPWordAssignment8616
from .near_return_c_ast_congruence import NearReturnOperandRole8616
from .near_return_expression import NearReturnPointerExpressionResult8616
from .near_return_selector import _volatile_type_8616
from .semantic_cast import CSemanticCast8616

_BODY_NODE_BUDGET_8616 = 512


class NearReturnBodyFailure8616(StrEnum):
    """Why a scalar body cannot participate in atomic pointer publication."""

    CANDIDATE_UNPROVEN = "candidate_unproven"
    BODY_CENSUS_UNPROVEN = "body_census_unproven"
    RETURN_UNBOUND = "return_unbound"
    BASE_USE_OUTSIDE_RETURN = "base_use_outside_return"
    VOLATILE_OPERAND = "volatile_operand"


@dataclass(frozen=True, slots=True)
class NearReturnBodyPreflight8616:
    """Retained body/replacement binding, not permission to mutate a signature."""

    body: object
    candidate: NearReturnPointerExpressionResult8616
    return_node: structured_c.CReturn | None
    failure: NearReturnBodyFailure8616 | None
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def complete(self) -> bool:
        """Rewalk current body and candidate so stale plans cannot be consumed."""
        counts = (self.raw_fact_count, self.normalized_fact_count,
                  self.classified_fact_count, self.materialized_count, self.failure_count)
        if self.failure is not None or counts != (1, 1, 1, 1, 0):
            return False
        if any(type(count) is not int for count in counts):
            return False
        node, failure = _body_preflight_8616(self.body, self.candidate)
        return failure is None and node is not None and node is self.return_node


def _body_children_8616(node: object) -> tuple[object, ...] | None:
    """Enumerate only known third-party C-node semantic fields, fail closed.

    Exact class matching prevents a plugin subclass's extra semantic fields
    from being silently omitted. Metadata, variable records and codegen links
    are not AST children and do not authorize storage identity.
    """
    node_type = type(node)
    if node_type is structured_c.CConstant:
        # Reference substitutions may render expressions, not literal leaves.
        constant = cast(structured_c.CConstant, node)
        return None if constant.reference_values else ()
    if node_type is structured_c.CVariable:
        return ()
    if node_type is structured_c.CStatements:
        return tuple(cast(structured_c.CStatements, node).statements)
    # These owned projections retain exactly the canonical lhs/rhs or expr;
    # their renderers add no separately mutable expression tree. Keep exact
    # class matching so plugins with additional semantic fields still refuse.
    if node_type in (structured_c.CAssignment, CGPWordAssignment8616):
        assignment = cast(structured_c.CAssignment, node)
        return assignment.lhs, assignment.rhs
    if node_type is structured_c.CReturn:
        returned = cast(structured_c.CReturn, node).retval
        return (returned,) if returned is not None else ()
    if node_type is structured_c.CBinaryOp:
        binary = cast(structured_c.CBinaryOp, node)
        return binary.lhs, binary.rhs
    if node_type in (structured_c.CTypeCast, CSemanticCast8616):
        return (cast(structured_c.CTypeCast, node).expr,)
    if node_type is structured_c.CUnaryOp:
        return (cast(structured_c.CUnaryOp, node).operand,)
    if node_type is structured_c.CFunctionCall:
        call = cast(structured_c.CFunctionCall, node)
        target = call.callee_target
        targets = (target,) if isinstance(target, structured_c.CExpression) else ()
        return targets + tuple(call.args)
    return None


def _closed_body_walk_8616(root: object) -> tuple[object, ...] | None:
    """Count semantic edges without deduplicating repeated variable occurrences."""
    pending: list[tuple[object, frozenset[int]]] = [(root, frozenset())]
    nodes: list[object] = []
    while pending:
        node, ancestors = pending.pop()
        if id(node) in ancestors or len(nodes) >= _BODY_NODE_BUDGET_8616:
            return None
        children = _body_children_8616(node)
        if children is None:
            return None
        nodes.append(node)
        lineage = ancestors | {id(node)}
        pending.extend((child, lineage) for child in children)
    return tuple(nodes)


def _base_variable_matches_8616(node: object, candidate: NearReturnPointerExpressionResult8616) -> bool:
    """Recognize exact canonical or registered alias identities, never offsets."""
    if not isinstance(node, structured_c.CVariable):
        return False
    # Role order is not authoritative; the congruence owns each role explicitly.
    base = next(operand for operand in candidate.bound_operands if operand.role is NearReturnOperandRole8616.OFFSET_BASE)
    aliases = (base.projection.variable, *base.projection.equivalent_variables)
    return node is base.cvar or any(node.variable is alias for alias in aliases)


def _body_preflight_8616(
    body: object, candidate: NearReturnPointerExpressionResult8616,
) -> tuple[structured_c.CReturn | None, NearReturnBodyFailure8616 | None]:
    """Bind the sole proven return and reject every unrelated base occurrence."""
    if not candidate.complete or candidate.congruence is None:
        return None, NearReturnBodyFailure8616.CANDIDATE_UNPROVEN
    if any(_volatile_type_8616(operand.cvar.variable_type) for operand in candidate.bound_operands):
        return None, NearReturnBodyFailure8616.VOLATILE_OPERAND
    nodes = _closed_body_walk_8616(body)
    if nodes is None:
        return None, NearReturnBodyFailure8616.BODY_CENSUS_UNPROVEN
    returns = tuple(node for node in nodes if isinstance(node, structured_c.CReturn))
    if len(returns) != 1 or returns[0].retval is not candidate.congruence.expression:
        return None, NearReturnBodyFailure8616.RETURN_UNBOUND
    returned_nodes = _closed_body_walk_8616(returns[0].retval)
    if returned_nodes is None:
        return None, NearReturnBodyFailure8616.BODY_CENSUS_UNPROVEN
    body_uses = sum(_base_variable_matches_8616(node, candidate) for node in nodes)
    return_uses = sum(_base_variable_matches_8616(node, candidate) for node in returned_nodes)
    if not return_uses or body_uses != return_uses:
        return None, NearReturnBodyFailure8616.BASE_USE_OUTSIDE_RETURN
    return returns[0], None


def preflight_near_return_body_8616(
    body: object, candidate: NearReturnPointerExpressionResult8616,
) -> NearReturnBodyPreflight8616:
    """Prepare a replayable, nonpublishing body replacement binding or refuse."""
    node, failure = _body_preflight_8616(body, candidate)
    accepted = int(failure is None)
    return NearReturnBodyPreflight8616(body, candidate, node, failure, 1, 1, accepted, accepted, 1 - accepted)
