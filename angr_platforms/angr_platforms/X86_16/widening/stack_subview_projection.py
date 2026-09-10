"""Materialize Widening-proven structured-C stack object views.

Layer: Widening.
Responsibility: project accepted stack-object byte views into structured C
only after the current Widening artifact proves one unique containing owner.
Consumes Alias-proven storage identity through the typed Widening artifact.
Do not join values from rendered text, cosmetic shape, postprocess, or
CLI/reporting evidence.

This pass consumes structured C AST shape as a materialization target, not as
semantic evidence. It refuses missing, stale, incomplete, ambiguous,
cross-region, wrong-offset, wrong-scale, or unsafe write projections. Do not
move this work to postprocess or infer it from rendered C or assembly text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c

from ..c_ast_utils import _clone_c_ast_tree_8616, _replace_c_children_8616
from ..pipeline.errors import PipelineHardError
from .stack_subview_expression import (
    StackSubviewRhsEffectKind8616,
    classify_subview_rhs_8616,
    make_scalar_subview_read_expr_8616,
    make_scalar_subview_write_assignment_8616,
    scalar_subview_proof_8616,
)
from .stack_subview_proof import (
    StackObjectViewProof8616,
    StackObjectViewResolutionKind8616,
    current_stack_object_widening_8616,
    resolve_stack_object_view_8616,
    resolve_widened_stack_object_read_8616,
    stack_variable_range_8616,
)


@dataclass(slots=True)
class StackSubviewProjectionStats8616:
    """Closed evidence counters for contained stack-subview materialization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class _StackSubviewCandidate8616:
    """One syntax-normalized stack subview recomposition candidate."""

    container: structured_c.CVariable
    subview: structured_c.CVariable
    projection_bits: int | None


def _dynamic_attr_8616(obj: object, name: str, default: object = None) -> Any:  # noqa: ANN401
    """Read optional third-party codegen state at the dynamic AST boundary."""
    return getattr(obj, name, default)


def _unwrap_casts_8616(node: object) -> object:
    """Remove syntax-only C casts while matching a structured expression."""
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    return node


def _constant_int_8616(node: object) -> int | None:
    """Return an integer C constant value without parsing rendered text."""
    node = _unwrap_casts_8616(node)
    if isinstance(node, structured_c.CConstant) and isinstance(node.value, int):
        return node.value
    return None


def _projection_candidate_8616(node: object) -> tuple[structured_c.CVariable, int | None] | None:
    """Match a byte projection multiplied or shifted into a wider value."""
    node = _unwrap_casts_8616(node)
    if not isinstance(node, structured_c.CBinaryOp):
        return None
    if node.op == "Shl":
        subview = _unwrap_casts_8616(node.lhs)
        shift = _constant_int_8616(node.rhs)
        if isinstance(subview, structured_c.CVariable) and shift is not None:
            return subview, shift
        return None
    if node.op != "Mul":
        return None
    for subview_node, scale_node in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        subview = _unwrap_casts_8616(subview_node)
        scale = _constant_int_8616(scale_node)
        if not isinstance(subview, structured_c.CVariable) or scale is None:
            continue
        projection_bits = scale.bit_length() - 1 if scale > 0 and scale & (scale - 1) == 0 else None
        return subview, projection_bits
    return None


def _stack_subview_candidate_8616(node: object) -> _StackSubviewCandidate8616 | None:
    """Match an OR recomposition with one direct container and one projected view."""
    node = _unwrap_casts_8616(node)
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "Or":
        return None
    for container_node, projection_node in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        container = _unwrap_casts_8616(container_node)
        projection = _projection_candidate_8616(projection_node)
        if isinstance(container, structured_c.CVariable) and projection is not None:
            subview, projection_bits = projection
            return _StackSubviewCandidate8616(container, subview, projection_bits)
    return None


def _word_byte_proof_8616(proof: StackObjectViewProof8616 | None) -> StackObjectViewProof8616 | None:
    """Accept the currently supported exact byte view of a word owner."""
    if proof is None or proof.owner_size != 2 or proof.view_size != 1:
        return None
    return proof if proof.relative_offset in {0, 1} else None


def _increment_codegen_counter_8616(codegen: object, name: str, amount: int) -> None:
    """Accumulate evidence on the dynamic third-party codegen boundary."""
    current = _dynamic_attr_8616(codegen, name, 0)
    current_value = current if isinstance(current, int) else 0
    setattr(cast(Any, codegen), name, current_value + amount)


def materialize_contained_stack_subviews_8616(codegen: object) -> bool:
    """Project proven word-owned byte views from the current Widening decision."""
    cfunc = _dynamic_attr_8616(codegen, "cfunc", None)
    root = _dynamic_attr_8616(cfunc, "statements", None)
    if root is None:
        return False
    artifact = current_stack_object_widening_8616(codegen)

    stats = StackSubviewProjectionStats8616()

    def transform(node: object) -> object:
        """Materialize one proven recomposition, direct read, or direct write."""
        if isinstance(node, structured_c.CAssignment) and isinstance(
            node.lhs, structured_c.CVariable
        ):
            resolution = resolve_stack_object_view_8616(
                codegen,
                cfunc,
                artifact,
                node.lhs,
            )
            if resolution.kind is not StackObjectViewResolutionKind8616.NOT_CANDIDATE:
                stats.raw_fact_count += 1
                proof = scalar_subview_proof_8616(resolution.proof)
                rhs_effect = classify_subview_rhs_8616(node.rhs)
                if (
                    resolution.kind is not StackObjectViewResolutionKind8616.ACCEPTED
                    or proof is None
                    or not isinstance(node.rhs, structured_c.CExpression)
                    or rhs_effect.kind is StackSubviewRhsEffectKind8616.UNSUPPORTED
                    or (
                        rhs_effect.kind
                        is StackSubviewRhsEffectKind8616.OWNER_PRESERVING_CALLS
                        and not proof.source.calls_preserve_owner(rhs_effect.callsite_addrs)
                    )
                ):
                    stats.failure_count += 1
                    return node
                stats.normalized_fact_count += 1
                stats.classified_fact_count += 1
                stats.materialized_count += 1
                return make_scalar_subview_write_assignment_8616(codegen, node, proof)

        candidate = _stack_subview_candidate_8616(node)
        if candidate is not None:
            stats.raw_fact_count += 1
            resolution = resolve_stack_object_view_8616(
                codegen,
                cfunc,
                artifact,
                candidate.subview,
            )
            proof = _word_byte_proof_8616(resolution.proof)
            container_range = (
                stack_variable_range_8616(candidate.container.variable, artifact.function_addr, codegen=codegen)
                if artifact is not None
                else None
            )
            owner_range = (
                (proof.source.address.offset, proof.source.address.size) if proof is not None else None
            )
            if (
                candidate.projection_bits != 8
                or resolution.kind is not StackObjectViewResolutionKind8616.ACCEPTED
                or proof is None
                or proof.relative_offset != 1
                or owner_range is None
                or container_range not in {(owner_range[0], 1), owner_range}
            ):
                stats.failure_count += 1
            else:
                stats.normalized_fact_count += 1
                stats.classified_fact_count += 1
                stats.materialized_count += 1
                return _clone_c_ast_tree_8616(proof.owner)

        if isinstance(node, structured_c.CVariable):
            resolution = resolve_stack_object_view_8616(codegen, cfunc, artifact, node)
            if resolution.kind is StackObjectViewResolutionKind8616.NOT_CANDIDATE:
                resolution = resolve_widened_stack_object_read_8616(
                    codegen,
                    cfunc,
                    artifact,
                    node,
                )
            if resolution.kind is StackObjectViewResolutionKind8616.NOT_CANDIDATE:
                return node
            stats.raw_fact_count += 1
            proof = scalar_subview_proof_8616(resolution.proof)
            if resolution.kind is not StackObjectViewResolutionKind8616.ACCEPTED or proof is None:
                stats.failure_count += 1
                return node
            stats.normalized_fact_count += 1
            stats.classified_fact_count += 1
            stats.materialized_count += 1
            return make_scalar_subview_read_expr_8616(codegen, proof)
        return node

    def should_process_child(parent: object, attr: str) -> bool:
        """Keep assignment lvalues and address operands outside value projection."""
        if isinstance(parent, structured_c.CAssignment) and attr == "lhs":
            return False
        return not (
            isinstance(parent, structured_c.CUnaryOp)
            and parent.op in {"Reference", "AddressOf"}
            and attr == "operand"
        )

    changed = _replace_c_children_8616(root, transform, should_process_child=should_process_child)
    _increment_codegen_counter_8616(
        codegen,
        "_inertia_stack_subview_raw_fact_count",
        stats.raw_fact_count,
    )
    _increment_codegen_counter_8616(
        codegen,
        "_inertia_stack_subview_normalized_fact_count",
        stats.normalized_fact_count,
    )
    _increment_codegen_counter_8616(
        codegen,
        "_inertia_stack_subview_classified_fact_count",
        stats.classified_fact_count,
    )
    _increment_codegen_counter_8616(
        codegen,
        "_inertia_stack_subview_materialized_count",
        stats.materialized_count,
    )
    _increment_codegen_counter_8616(
        codegen,
        "_inertia_stack_subview_failure_count",
        stats.failure_count,
    )
    cast(Any, codegen)._inertia_stack_subview_last_stats_8616 = stats
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError(
            "classified contained stack subview was not materialized",
            layer="widening",
        )
    return bool(changed and stats.materialized_count > 0)


__all__ = [
    "StackSubviewProjectionStats8616",
    "materialize_contained_stack_subviews_8616",
]
