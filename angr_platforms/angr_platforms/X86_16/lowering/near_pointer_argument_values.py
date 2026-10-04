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
from .near_pointer_value_runtime import NearPointerArgumentHelper8616


def is_near_pointer_argument_helper_call_8616(expression: object) -> bool:
    """Return True only for this module's retained single-evaluation wrapper.

    Representation identity, not a name match: the exact foreign AST class
    (subclasses cannot impersonate the wrapper), no bound callee function,
    the owned helper target spelling, exactly two arguments, and the enum
    member tag installed by the constructor below. A machine call that merely
    shares the target name, arity, or a string-forged tag is not owned
    representation and must still be treated as a real call.
    """
    helper_identity = NearPointerArgumentHelper8616.SINGLE_EVALUATION
    if type(expression) is not structured_c.CFunctionCall:
        # The exact foreign AST class check justifies narrowing; subclasses
        # cannot impersonate our retained single-evaluation wrapper.
        return False
    call_expression = cast(structured_c.CFunctionCall, expression)
    return (
        call_expression.callee_func is None
        and call_expression.callee_target == helper_identity.value
        and len(call_expression.args) == 2
        and call_expression.tags.get("inertia_near_pointer_argument_helper") is helper_identity
    )


def materialize_near_pointer_argument_value_8616(
    expression: object,
    segment: object,
    *,
    codegen: object,
    c_target: str,
) -> tuple[object, bool]:
    """Lower an already-classified near pointer; return whether wrapping occurred."""
    if is_near_pointer_argument_helper_call_8616(expression):
        # A name alone never suppresses conversion of a machine call's
        # scalar result; only our retained representation avoids wrapping.
        return expression, False
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
    # Both targets consume the same single-evaluation ABI. The header owns
    # native DOS versus guest-memory representation; DS:0 is not near null.
    del c_target
    helper_identity = NearPointerArgumentHelper8616.SINGLE_EVALUATION
    # angr's constructor is a dynamic third-party codegen boundary.
    return structured_c.CFunctionCall(
        helper_identity.value, None, [segment, _clone_c_ast_tree_8616(expression)],
        codegen=cast(Any, codegen),
        tags={"inertia_near_pointer_argument_helper": helper_identity},
    ), True
