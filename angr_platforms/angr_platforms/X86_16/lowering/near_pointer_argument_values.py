"""Materialize values after a call argument is proven to be a near pointer.

Layer: Types/Lowering.
Responsibility: project a proven near-pointer value into C without confusing
the DOS C null representation with an address in the live data segment.
The caller owns pointer classification and source-value provenance. This module
must not infer pointer classes from scalar values, names, source text, or output.
"""

from __future__ import annotations

from typing import Any, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeInt, SimTypeNum, SimTypePointer

from ..c_ast_utils import _clone_c_ast_tree_8616


def materialize_near_pointer_argument_value_8616(
    expression: object,
    segment: object,
    *,
    codegen: object,
    c_target: str,
) -> tuple[object, bool]:
    """Lower an already-classified near pointer; return whether wrapping occurred."""
    is_null_pointer_constant = (
        isinstance(expression, structured_c.CConstant)
        and type(expression.value) is int
        and expression.value == 0
        and isinstance(expression.type, (SimTypeChar, SimTypeInt, SimTypeNum, SimTypePointer))
        and not expression.reference_values
    )
    if is_null_pointer_constant:
        # DOS C represents a near null pointer as zero, not the host address DS:0.
        return expression, False
    helper = "SEG_PTR" if c_target == "portable-flat" else "MK_FP"
    # angr's constructor is a dynamic third-party codegen boundary.
    return structured_c.CFunctionCall(
        helper, None, [segment, _clone_c_ast_tree_8616(expression)],
        codegen=cast(Any, codegen),
    ), True
