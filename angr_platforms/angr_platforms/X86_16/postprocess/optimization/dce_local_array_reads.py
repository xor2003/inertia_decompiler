"""Classify reads from already-materialized local C array objects.

Layer: Rewrite/Postprocess cleanup.
Responsibility: consume Alias-owned stack identity and Types-owned array
declarations to recognize effect-free local reads. Never infer an array from
a pointer, invent storage, recover an address, or authorize deletion alone.
The caller must separately prove that the value is dead. Calls and unknown
address expressions refuse; this grants no permission to delete memory writes.

Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control
flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimType, SimTypeArray, SimTypePointer, SimTypeReg
from angr.sim_variable import SimRegisterVariable, SimStackVariable, SimTemporaryVariable

from ...lowering.gp_register_state import runtime_gp_name_for_variable_8616
from .dce_purity import PURE_LOCAL_BINARY_OPS_8616, PURE_LOCAL_UNARY_OPS_8616


class _AddressKind8616(Enum):
    """Distinguish a known local array address from a scalar offset."""

    UNKNOWN = "unknown"
    OFFSET = "offset"
    ARRAY = "array"


def _scalar_type_8616(type_: SimType | None) -> bool:
    """Reject pointers masquerading as scalar offset carriers."""
    return isinstance(type_, SimTypeReg) and not isinstance(type_, SimTypePointer)


def _variable_kind_8616(node: CVariable) -> _AddressKind8616:
    """Consume an existing stack array or scalar/register-state value."""
    variable = node.variable
    if isinstance(variable, SimStackVariable) and isinstance(node.type, SimTypeArray):
        return _AddressKind8616.ARRAY
    scalar_storage = isinstance(variable, (SimStackVariable, SimRegisterVariable, SimTemporaryVariable))
    runtime_register = runtime_gp_name_for_variable_8616(variable) is not None
    if (scalar_storage or runtime_register) and _scalar_type_8616(node.type):
        return _AddressKind8616.OFFSET
    return _AddressKind8616.UNKNOWN


def _cast_kind_8616(kind: _AddressKind8616, target: SimType) -> _AddressKind8616:
    """Allow pointer views of an array, never scalar-to-pointer recovery."""
    if kind is _AddressKind8616.ARRAY and isinstance(target, SimTypePointer):
        return kind
    if kind is _AddressKind8616.OFFSET and _scalar_type_8616(target):
        return kind
    return _AddressKind8616.UNKNOWN


def _binary_kind_8616(
    op: str, left: _AddressKind8616, right: _AddressKind8616,
) -> _AddressKind8616:
    """Keep exactly one array anchor under pointer addition/subtraction."""
    if op in PURE_LOCAL_BINARY_OPS_8616 and left is right is _AddressKind8616.OFFSET:
        return _AddressKind8616.OFFSET
    array_plus_offset = left is _AddressKind8616.ARRAY and right is _AddressKind8616.OFFSET
    offset_plus_array = left is _AddressKind8616.OFFSET and right is _AddressKind8616.ARRAY
    if (op == "Add" and (array_plus_offset or offset_plus_array)) or (op == "Sub" and array_plus_offset):
        return _AddressKind8616.ARRAY
    return _AddressKind8616.UNKNOWN


@dataclass(slots=True)
class _AddressClassifier8616:
    """Bound recursive classification and reject malformed cyclic ASTs."""

    active: set[int] = field(default_factory=set)

    def classify(self, node: object) -> _AddressKind8616:
        """Visit an existing expression without retaining or mutating it."""
        marker = id(node)
        if marker in self.active:
            return _AddressKind8616.UNKNOWN
        self.active.add(marker)
        try:
            return self._classify(node)
        finally:
            self.active.remove(marker)

    def _classify(self, node: object) -> _AddressKind8616:
        if isinstance(node, CConstant) and isinstance(node.value, int):
            return _AddressKind8616.OFFSET
        if isinstance(node, CVariable):
            return _variable_kind_8616(node)
        if isinstance(node, CTypeCast):
            return _cast_kind_8616(self.classify(node.expr), node.dst_type)
        if isinstance(node, CBinaryOp):
            return _binary_kind_8616(node.op, self.classify(node.lhs), self.classify(node.rhs))
        if isinstance(node, CUnaryOp):
            return self._unary_kind(node)
        return _AddressKind8616.UNKNOWN

    def _unary_kind(self, node: CUnaryOp) -> _AddressKind8616:
        operand = self.classify(node.operand)
        if node.op in {"Reference", "AddressOf"} and operand is _AddressKind8616.ARRAY:
            return operand
        if node.op in PURE_LOCAL_UNARY_OPS_8616 and operand is _AddressKind8616.OFFSET:
            return operand
        return _AddressKind8616.UNKNOWN


def is_pure_local_array_read_8616(node: object) -> bool:
    """Recognize an unused-value candidate, not a liveness/deletion proof."""
    if not isinstance(node, CUnaryOp) or node.op != "Dereference":
        return False
    return _AddressClassifier8616().classify(node.operand) is _AddressKind8616.ARRAY
