"""Flatten additive validation expressions without losing typed value views.

Layer: Validation.
Responsibility: expose additive terms under an explicit semantic-cast policy.
This module does not infer types or mutate the structured C AST.

Package ownership contract (canonical inertia/validation package):
Owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CTypeCast

from inertia.lowering.semantic_cast import CSemanticCast8616


def _strip_additive_casts_8616(
    node: object,
    *,
    preserve_semantic_casts: bool,
) -> object:
    """Strip cast wrappers according to the requested validation policy."""
    while isinstance(node, CTypeCast) and not (
        preserve_semantic_casts and isinstance(node, CSemanticCast8616)
    ):
        node = node.expr
    return node


def flatten_additive_terms_8616(
    node: object,
    sign: int = 1,
    *,
    preserve_semantic_casts: bool = False,
) -> tuple[tuple[int, object], ...]:
    """Flatten additive terms while retaining typed value views when requested."""
    node = _strip_additive_casts_8616(
        node,
        preserve_semantic_casts=preserve_semantic_casts,
    )
    if isinstance(node, CBinaryOp) and node.op == "Add":
        return flatten_additive_terms_8616(
            node.lhs,
            sign,
            preserve_semantic_casts=preserve_semantic_casts,
        ) + flatten_additive_terms_8616(
            node.rhs,
            sign,
            preserve_semantic_casts=preserve_semantic_casts,
        )
    if isinstance(node, CBinaryOp) and node.op == "Sub":
        return flatten_additive_terms_8616(
            node.lhs,
            sign,
            preserve_semantic_casts=preserve_semantic_casts,
        ) + flatten_additive_terms_8616(
            node.rhs,
            -sign,
            preserve_semantic_casts=preserve_semantic_casts,
        )
    return ((sign, node),)
