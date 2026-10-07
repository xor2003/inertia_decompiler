"""Canonicalize exact structured predicate identities for Validation.

Layer: Validation.
Responsibility: normalize and invert exact structured predicate tokens for
path-sensitive validation.
Forbidden: semantic recovery, source/COD/assembly/rendered-C inspection, or
C-AST mutation.

Package ownership contract (canonical inertia/validation package):
Owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations

from typing import cast

from inertia.ir.condition_ir import inverted_comparison_op_8616

__all__ = ["PredicateToken8616", "invert_predicate_token_8616"]

type PredicateToken8616 = tuple[object, ...]


def invert_predicate_token_8616(token: PredicateToken8616) -> PredicateToken8616:
    """Return the canonical logical complement of one exact predicate token."""
    if len(token) == 4 and token[0] == "binary" and isinstance(token[1], str):
        inverted_op = inverted_comparison_op_8616(token[1])
        if inverted_op is not None:
            return ("binary", inverted_op, token[2], token[3])
    if len(token) == 2 and token[0] == "logical-not" and isinstance(token[1], tuple):
        return cast(PredicateToken8616, token[1])
    return ("logical-not", token)
