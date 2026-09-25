"""Expression-facing alias queries over typed alias storage facts.

Layer: Semantics.
Responsibility: owns instruction effects, flags, branch meaning, and expression interpretation.
This module interprets expression storage domains without owning alias state.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from typing import Any

from ..alias.alias_model_impl import (
    AliasStorageFacts,
    _alias_identity_for_variable,
    _storage_domain_for_variable,
    _StorageDomainSignature,
    _StorageView,
)
from .expression_analysis import _mk_fp_components, _unwrap_c_casts


def _dynamic_attr_8616(obj: object, name: str, default: object = None) -> Any:  # noqa: ANN401
    """Dynamic C-AST boundary: read optional third-party codegen attributes."""
    return getattr(obj, name, default)


def _binary_op_domain_8616(expr: object) -> _StorageDomainSignature:
    """Join the operand domains of one binary expression."""
    from angr.analyses.decompiler.structured_codegen import c as structured_c

    assert isinstance(expr, structured_c.CBinaryOp)
    domains: set[_StorageDomainSignature] = set()
    domain_list: list[_StorageDomainSignature] = []
    for child in (expr.lhs, expr.rhs):
        domain = _storage_domain_for_expr(child)
        if domain.is_const():
            continue
        if domain.is_unknown():
            return _StorageDomainSignature("unknown")
        domains.add(domain)
        domain_list.append(domain)
    if not domains:
        return _StorageDomainSignature("const")
    if len(domains) == 1:
        return next(iter(domains))
    if len(domain_list) == 2:
        joined = domain_list[0].join(domain_list[1])
        if joined is not None:
            return joined
    return _StorageDomainSignature("mixed")


def _storage_domain_for_expr(expr: object) -> _StorageDomainSignature:
    """Return the alias storage domain represented by a structured C expression."""
    expr = _unwrap_c_casts(expr)
    from angr.analyses.decompiler.structured_codegen import c as structured_c

    if isinstance(expr, structured_c.CVariable):
        variable = _dynamic_attr_8616(expr, "variable", None)
        if variable is None:
            return _StorageDomainSignature("unknown")
        return _storage_domain_for_variable(variable)
    if isinstance(expr, structured_c.CConstant):
        return _StorageDomainSignature("const")
    mk_fp_components = _mk_fp_components(expr)
    if mk_fp_components is not None:
        return _StorageDomainSignature("far_pointer", 32, _StorageView(0, 32))
    if isinstance(expr, structured_c.CUnaryOp):
        return _storage_domain_for_expr(expr.operand)
    if isinstance(expr, structured_c.CBinaryOp):
        return _binary_op_domain_8616(expr)
    return _StorageDomainSignature("unknown")


def describe_alias_storage(expr: object) -> AliasStorageFacts:
    """Describe the alias storage facts proven for a structured C expression."""
    domain = _storage_domain_for_expr(expr)
    identity = None
    expr = _unwrap_c_casts(expr)
    from angr.analyses.decompiler.structured_codegen import c as structured_c

    if isinstance(expr, structured_c.CVariable):
        variable = _dynamic_attr_8616(expr, "variable", None)
        if variable is not None:
            identity = _alias_identity_for_variable(variable)
    else:
        mk_fp_components = _mk_fp_components(expr)
        if mk_fp_components is not None:
            identity = ("far_pointer", mk_fp_components)
    return AliasStorageFacts(domain, identity)


def same_alias_storage_domain(lhs: object, rhs: object) -> bool:
    """Return whether two expressions have the same alias storage domain."""
    return describe_alias_storage(lhs).same_domain(describe_alias_storage(rhs))


def compatible_alias_storage_views(lhs: object, rhs: object) -> bool:
    """Return whether two expression storage views are adjacent or compatible."""
    return describe_alias_storage(lhs).compatible_view(describe_alias_storage(rhs))


def needs_alias_synthesis(expr: object) -> bool:
    """Return whether the expression needs explicit synthesized alias storage."""
    return describe_alias_storage(expr).needs_synthesis()


def can_join_alias_storage(lhs: object, rhs: object) -> bool:
    """Return whether two expression storage facts can be joined safely."""
    return describe_alias_storage(lhs).can_join(describe_alias_storage(rhs))


def contains_alias_storage(container: object, subview: object) -> bool:
    """Return whether one expression's proven storage contains another view."""
    return describe_alias_storage(container).contains(describe_alias_storage(subview))


__all__ = [
    "_storage_domain_for_expr",
    "can_join_alias_storage",
    "compatible_alias_storage_views",
    "contains_alias_storage",
    "describe_alias_storage",
    "needs_alias_synthesis",
    "same_alias_storage_domain",
]
