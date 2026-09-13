"""Evaluate integer constants while their native bit-width proof is available.

Layer: Types/Lowering, native codegen compatibility boundary.
Responsibility: preserve AIL modular arithmetic and dispatch explicit operation
types before native simplification removes casts. No store-width recovery,
rendered-text matching, signedness inference or instruction interpretation.
Consumes alias, widening, and typed facts at the native codegen boundary.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import operator
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol, cast

from angr.ailment.expression import BinaryOp, Const
from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CExpression,
    CStructuredCodeGenerator,
    CTypeCast,
    MakeTypecastsImplicit,
)
from angr.sim_type import SimType, SimTypeChar, SimTypeInt, SimTypeNum

from .native_integer_operations import lower_native_integer_operation_8616

_INTEGER_TYPES = (SimTypeChar, SimTypeInt, SimTypeNum)
_INTEGER_OPERATIONS: dict[str, Callable[[int, int], int]] = {
    "Add": operator.add, "Sub": operator.sub, "Mul": operator.mul,
    "And": operator.and_, "Or": operator.or_, "Xor": operator.xor,
}


def native_integer_constant_value_8616(expression: BinaryOp) -> int | None:
    """Evaluate same-width literal AIL arithmetic with its exact modular width."""
    operation = _INTEGER_OPERATIONS.get(expression.op)
    bits = expression.bits
    non_scalar = expression.floating_point or expression.vector_count is not None or expression.vector_size is not None
    if operation is None or non_scalar or not isinstance(bits, int) or bits <= 0:
        return None
    left, right = expression.operands
    if not isinstance(left, Const) or not isinstance(right, Const):
        return None
    if not isinstance(left.value, int) or not isinstance(right.value, int):
        return None
    if left.bits != bits or right.bits != bits:
        return None
    modulus = 1 << bits
    value = operation(left.value, right.value) & (modulus - 1)
    if expression.signed and value >= modulus // 2:
        value -= modulus
    return value


@dataclass(slots=True)
class NativeIntegerConstantReport8616:
    """Census of candidate expressions and exactly evaluated integer values."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


class _CodegenReportBoundary8616(Protocol):
    """Owned evaluation report attached to the third-party code generator."""

    _inertia_integer_constant_report_8616: NativeIntegerConstantReport8616


def _report_8616(codegen: object) -> NativeIntegerConstantReport8616:
    """Return the owned aggregate census at the native codegen boundary."""
    boundary = cast(_CodegenReportBoundary8616, codegen)
    try:
        return boundary._inertia_integer_constant_report_8616
    except AttributeError:
        report = NativeIntegerConstantReport8616()
        boundary._inertia_integer_constant_report_8616 = report
        return report


def fold_unsigned_narrowing_constant_8616(destination: SimType, expression: CTypeCast) -> CConstant | None:
    """Evaluate an integer literal only under an exact unsigned narrowing proof."""
    source = expression.src_type
    converted = expression.dst_type
    literal = expression.expr
    if not isinstance(literal, CConstant) or not isinstance(literal.value, int):
        return None
    if not all(isinstance(type_, _INTEGER_TYPES) for type_ in (source, converted, destination)):
        return None
    converted_integer = cast(SimTypeChar | SimTypeInt | SimTypeNum, converted)
    destination_integer = cast(SimTypeChar | SimTypeInt | SimTypeNum, destination)
    if converted_integer.signed is not False or destination_integer.signed is not False:
        return None
    try:
        source_bits, converted_bits, destination_bits = source.size, converted.size, destination.size
    except ValueError:
        return None
    if not isinstance(source_bits, int) or not isinstance(converted_bits, int):
        return None
    if not 0 < converted_bits < source_bits or destination_bits != converted_bits:
        return None
    value = literal.value & ((1 << converted_bits) - 1)
    return CConstant(value, converted, codegen=expression.codegen, tags=expression.tags)


def apply_native_unsigned_constant_casts_8616() -> None:
    """Preserve exact constant values at native implicit-cast simplification."""
    original = cast(Callable[[SimType, CExpression], CExpression], MakeTypecastsImplicit.collapse)
    if original.__name__ == "_collapse_unsigned_constants_8616":
        return

    def _collapse_unsigned_constants_8616(
        _cls: type[MakeTypecastsImplicit], destination: SimType, expression: CExpression,
    ) -> CExpression:
        """Keep native simplification unless an elided literal conversion is proven."""
        result = original(destination, expression)
        if type(expression) is not CTypeCast or result is not expression.expr:
            return result
        if expression.codegen.project.arch.name != "86_16":
            return result
        report = _report_8616(expression.codegen)
        report.raw_fact_count += 1
        replacement = fold_unsigned_narrowing_constant_8616(destination, expression)
        if replacement is None:
            return result
        report.normalized_fact_count += 1
        report.classified_fact_count += 1
        report.materialized_count += 1
        return replacement

    # Installing a classmethod is a dynamic third-party descriptor boundary.
    cast(Any, MakeTypecastsImplicit).collapse = classmethod(_collapse_unsigned_constants_8616)


def apply_native_integer_constant_values_8616() -> None:
    """Evaluate proven literal operations before lowering loses AIL bit widths."""
    apply_native_unsigned_constant_casts_8616()
    original = CStructuredCodeGenerator._handle_Expr_BinaryOp
    if original.__name__ == "_handle_integer_constant_8616":
        return

    def _handle_integer_constant_8616(
        self: CStructuredCodeGenerator, expression: BinaryOp, **kwargs: object,
    ) -> CExpression:
        """Preserve explicit scalar AIL types while leaving variable-backed nodes intact."""
        if self.project.arch.name == "86_16" and self._variable_map.variable(expression) is None:
            report = _report_8616(self)
            report.raw_fact_count += 1
            value = native_integer_constant_value_8616(expression)
            if value is not None:
                report.normalized_fact_count += 1
                report.classified_fact_count += 1
                type_ = self.default_simtype_from_bits(expression.bits, expression.signed)
                result = CConstant(value, type_, codegen=self, tags=expression.tags)
                report.materialized_count += 1
                return result
        native = cast(CExpression, original(self, expression, **kwargs))
        if self.project.arch.name == "86_16" and self._variable_map.variable(expression) is None:
            replacement = lower_native_integer_operation_8616(expression, native)
            if replacement is not None:
                report.normalized_fact_count += 1
                report.classified_fact_count += 1
                report.materialized_count += 1
                return replacement
        return native

    cast(Any, CStructuredCodeGenerator)._handle_Expr_BinaryOp = _handle_integer_constant_8616
