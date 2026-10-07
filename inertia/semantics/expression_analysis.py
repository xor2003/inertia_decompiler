"""Expression-shape interpretation used by semantic query layers.

Layer: Semantics.
Responsibility: owns instruction effects, flags, branch meaning, and expression interpretation.
This module unwraps semantic expression shapes without owning storage identity.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimTemporaryVariable


class VirtualValueIdentityKind8616(Enum):
    """Structured metadata fields that can identify one virtual SSA value."""

    VARIABLE_ID = "varid"
    AIL_EXPRESSION_INDEX = "idx"
    CODEGEN_EXPRESSION_INDEX = "expr_idx"
    OBJECT_ID = "oident"
    TEMPORARY_ID = "tmp_id"


@dataclass(frozen=True, slots=True)
class VirtualValueIdentity8616:
    """Typed identity for an unresolved virtual value at the C-AST boundary."""

    kind: VirtualValueIdentityKind8616
    value: int | str


def _dynamic_attr_8616(obj: object, name: str, default: object = None) -> Any:  # noqa: ANN401
    """Dynamic C-AST boundary: read optional third-party codegen attributes."""
    return getattr(obj, name, default)


def _unwrap_c_casts(expr: object) -> object:
    """Return the innermost expression after removing C type casts."""
    while isinstance(expr, structured_c.CTypeCast):
        expr = expr.expr
    return expr


def _constant_int_value(expr: object) -> int | None:
    """Return an integer C constant value after removing semantic casts."""
    expr = _unwrap_c_casts(expr)
    if isinstance(expr, structured_c.CConstant) and isinstance(expr.value, int):
        return expr.value
    return None


def _mk_fp_components(expr: object) -> tuple[int, int] | None:
    """Return constant MK_FP segment/offset components when fully proven."""
    expr = _unwrap_c_casts(expr)
    if not isinstance(expr, structured_c.CFunctionCall) or _dynamic_attr_8616(expr, "callee_target", None) != "MK_FP":
        return None
    args = list(_dynamic_attr_8616(expr, "args", ()) or ())
    if len(args) != 2:
        return None
    seg = _constant_int_value(args[0])
    off = _constant_int_value(args[1])
    if seg is None or off is None:
        return None
    return seg, off


def describe_virtual_value_identity_8616(expr: object) -> VirtualValueIdentity8616 | None:
    """Return the strongest structured identity for an angr virtual value.

    Names and rendered text are intentionally excluded: only explicit AIL or
    codegen identity fields may prove that two virtual-value occurrences are
    the same SSA carrier.
    """
    expr = _unwrap_c_casts(expr)
    if isinstance(expr, structured_c.CVariable) and isinstance(
        expr.variable, SimTemporaryVariable
    ):
        return VirtualValueIdentity8616(
            kind=VirtualValueIdentityKind8616.TEMPORARY_ID,
            value=expr.variable.tmp_id,
        )
    if not isinstance(expr, structured_c.CDirtyExpression):
        return None
    dirty = expr.dirty
    candidates = (
        (VirtualValueIdentityKind8616.VARIABLE_ID, _dynamic_attr_8616(dirty, "varid")),
        (VirtualValueIdentityKind8616.AIL_EXPRESSION_INDEX, _dynamic_attr_8616(dirty, "idx")),
        (VirtualValueIdentityKind8616.CODEGEN_EXPRESSION_INDEX, expr.idx),
        (VirtualValueIdentityKind8616.OBJECT_ID, _dynamic_attr_8616(dirty, "oident")),
    )
    for kind, value in candidates:
        if isinstance(value, (int, str)):
            return VirtualValueIdentity8616(kind=kind, value=value)
    return None


__all__ = [
    "VirtualValueIdentity8616",
    "VirtualValueIdentityKind8616",
    "_constant_int_value",
    "_mk_fp_components",
    "_unwrap_c_casts",
    "describe_virtual_value_identity_8616",
]
