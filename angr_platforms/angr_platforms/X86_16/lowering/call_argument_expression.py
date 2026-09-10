"""Materialize typed C expressions from proven call-argument operations.

Layer: Types/Lowering.
Responsibility: consume structured call-argument source operations and build
their typed C-AST expression without recovering new semantics. Preserve array
decay and decoded string-object addresses instead of converting them to segment
offsets again. A pointer type alone does not prove an offset was materialized.
Consumes Recovery, Alias, and Widening facts through typed source tokens.
Forbidden: source/COD/rendered-C inference, call discovery, or cleanup pruning.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Callable

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimType, SimTypeChar, SimTypeFixedSizeArray, SimTypePointer

from ..callsite_summary import CallsitePushExprOp8616

type CallArgumentSource8616 = tuple[object, ...]
type CallArgumentOperation8616 = tuple[str, object]
type CallArgumentSourceResolver8616 = Callable[
    [CallArgumentSource8616],
    structured_c.CExpression | None,
]
type CallArgumentTypeBinder8616 = Callable[
    [structured_c.CExpression],
    structured_c.CExpression,
]

CALL_ARGUMENT_SOURCE_OPERATION_NAMES_8616: frozenset[str] = frozenset(
    {
        CallsitePushExprOp8616.ADC_SOURCE.value,
        CallsitePushExprOp8616.ADD_SOURCE.value,
        CallsitePushExprOp8616.SBB_SOURCE.value,
        CallsitePushExprOp8616.SUB_SOURCE.value,
    }
)
CALL_ARGUMENT_INTEGER_OPERATION_NAMES_8616: frozenset[str] = frozenset(
    {
        CallsitePushExprOp8616.ADC.value,
        CallsitePushExprOp8616.ADD.value,
        CallsitePushExprOp8616.SBB.value,
        CallsitePushExprOp8616.SUB.value,
        CallsitePushExprOp8616.AND.value,
        CallsitePushExprOp8616.OR.value,
        CallsitePushExprOp8616.XOR.value,
        CallsitePushExprOp8616.SHL.value,
        CallsitePushExprOp8616.SHR.value,
        CallsitePushExprOp8616.SAR.value,
        CallsitePushExprOp8616.NEG.value,
        CallsitePushExprOp8616.MUL.value,
        CallsitePushExprOp8616.SIGN_EXT_HI.value,
    }
)

__all__ = (
    "CALL_ARGUMENT_INTEGER_OPERATION_NAMES_8616",
    "CALL_ARGUMENT_SOURCE_OPERATION_NAMES_8616",
    "CallArgumentOperation8616",
    "CallArgumentSource8616",
    "call_argument_has_materialized_object_address_8616",
    "materialize_call_argument_operations_8616",
)


def call_argument_has_materialized_object_address_8616(expression: object) -> bool:
    """Recognize concrete C object addresses, not guessed near-pointer values.

    Fixed arrays decay to addresses in argument position. A decoded character
    string bound to the constant's actual pointer type also denotes a C object.
    Numeric constants, pointer-typed scalar carriers, and integer conversions
    are not evidence of either form and remain subject to address lowering.
    """
    if isinstance(expression, structured_c.CVariable):
        return isinstance(expression.variable_type, SimTypeFixedSizeArray)
    if not isinstance(expression, structured_c.CConstant):
        return False
    type_ = expression.type
    references = expression.reference_values
    return bool(
        isinstance(type_, SimTypePointer)
        and isinstance(type_.pts_to, SimTypeChar)
        and isinstance(references, dict)
        and isinstance(references.get(type_), (str, bytes))
    )


def _constant_8616(
    value: int,
    word_type: SimType,
    codegen: object,
) -> structured_c.CConstant:
    """Build one word-sized constant for a materialized operation."""
    return structured_c.CConstant(value, word_type, codegen=codegen)


def _materialize_sign_extension_high_8616(
    expression: structured_c.CExpression,
    *,
    width_bits: int,
    bind_type: CallArgumentTypeBinder8616,
    word_type: SimType,
    codegen: object,
) -> structured_c.CExpression:
    """Build the exact all-zero/all-one high word of a signed value."""
    typed_expression = bind_type(expression)
    sign_bit = structured_c.CBinaryOp(
        "And",
        structured_c.CBinaryOp(
            "Shr",
            typed_expression,
            _constant_8616(max(width_bits, 1) - 1, word_type, codegen),
            codegen=codegen,
        ),
        _constant_8616(1, word_type, codegen),
        codegen=codegen,
    )
    return structured_c.CBinaryOp(
        "Sub",
        _constant_8616(0, word_type, codegen),
        sign_bit,
        codegen=codegen,
    )


def _unsigned_shift_lhs_8616(
    expression: structured_c.CExpression,
    *,
    word_type: SimType,
    codegen: object,
) -> structured_c.CExpression:
    """Cast address-like carriers before an unsigned logical shift."""
    node = expression
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    if isinstance(node, structured_c.CUnaryOp) and node.op in {"Reference", "AddressOf"}:
        return structured_c.CTypeCast(None, word_type, expression, codegen=codegen)
    return expression


def materialize_call_argument_operations_8616(
    base_expression: structured_c.CExpression,
    operations: tuple[object, ...],
    *,
    resolve_source: CallArgumentSourceResolver8616,
    bind_type: CallArgumentTypeBinder8616,
    word_type: SimType,
    signed_word_type: SimType,
    codegen: object,
) -> structured_c.CExpression | None:
    """Apply one proven operation sequence to a materialized base expression.

    Unknown, malformed, or unsupported operations refuse materialization. An
    arithmetic right shift explicitly casts its input to a signed word; unary
    negation remains an exact ``0 - value`` operation in the generated C AST.
    """
    expression = base_expression
    scalar_ops = {
        CallsitePushExprOp8616.ADD.value: "Add",
        CallsitePushExprOp8616.SUB.value: "Sub",
        CallsitePushExprOp8616.AND.value: "And",
        CallsitePushExprOp8616.OR.value: "Or",
        CallsitePushExprOp8616.XOR.value: "Xor",
        CallsitePushExprOp8616.SHL.value: "Shl",
        CallsitePushExprOp8616.SHR.value: "Shr",
        CallsitePushExprOp8616.SAR.value: "Shr",
        CallsitePushExprOp8616.MUL.value: "Mul",
    }
    for operation in operations:
        if not isinstance(operation, tuple) or len(operation) != 2:
            return None
        op_name, op_value = operation
        if not isinstance(op_name, str):
            return None
        if op_name in CALL_ARGUMENT_SOURCE_OPERATION_NAMES_8616:
            if not isinstance(op_value, tuple):
                return None
            rhs = resolve_source(op_value)
            if rhs is None:
                return None
            c_op = (
                "Add"
                if op_name
                in {
                    CallsitePushExprOp8616.ADD_SOURCE.value,
                    CallsitePushExprOp8616.ADC_SOURCE.value,
                }
                else "Sub"
            )
            expression = structured_c.CBinaryOp(
                c_op,
                bind_type(expression),
                bind_type(rhs),
                codegen=codegen,
            )
            continue
        if not isinstance(op_value, int):
            return None
        if op_name == CallsitePushExprOp8616.SIGN_EXT_HI.value:
            expression = _materialize_sign_extension_high_8616(
                expression,
                width_bits=op_value,
                bind_type=bind_type,
                word_type=word_type,
                codegen=codegen,
            )
            continue
        if op_name == CallsitePushExprOp8616.NEG.value:
            expression = structured_c.CBinaryOp(
                "Sub",
                _constant_8616(0, word_type, codegen),
                bind_type(expression),
                codegen=codegen,
            )
            continue
        scalar_c_op = scalar_ops.get(op_name)
        if scalar_c_op is None:
            return None
        lhs = expression
        if op_name == CallsitePushExprOp8616.SAR.value:
            lhs = structured_c.CTypeCast(None, signed_word_type, bind_type(lhs), codegen=codegen)
        elif op_name == CallsitePushExprOp8616.SHR.value:
            lhs = _unsigned_shift_lhs_8616(lhs, word_type=word_type, codegen=codegen)
        expression = structured_c.CBinaryOp(
            scalar_c_op,
            bind_type(lhs),
            _constant_8616(op_value, word_type, codegen),
            codegen=codegen,
        )
    return expression
