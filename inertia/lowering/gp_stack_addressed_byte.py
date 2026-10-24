"""Expose an addressed byte view for Alias-proven GP restoration consumers.

Layer: Types/Lowering.
Responsibility: recognize an exact SS-based byte read of a referenced stack
object. Coordinate and native save/restore ownership remain with the caller;
this syntax projection alone grants no storage or value proof.
Consumes alias, widening, and typed facts
Do not recover semantics from COD, source, assembly, or rendered C text
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import (
    SimTypeChar,
    SimTypeInt,
    SimTypeLong,
    SimTypeLongLong,
    SimTypeNum,
    SimTypePointer,
    SimTypeShort,
)
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from .c_ast_utils import _iter_c_nodes_deep_8616
from .segment_register_state import runtime_segment_name_for_variable_8616
from .stack_c_ast_matching import _flatten_add_sub_terms_8616


class _Architecture(Protocol):
    """Third-party register layout needed to authenticate a physical SS view."""

    register_names: dict[int, str]


class _Project(Protocol):
    """Third-party project boundary carrying the architectural register layout."""

    arch: _Architecture


@dataclass(frozen=True, slots=True)
class AddressedStackByte8616:
    """One stack reference and constant displacement, without coordinate proof."""

    local: c.CVariable
    displacement: int


def _ss_base(node: object, project: _Project) -> bool:
    """Require exactly one positively scaled physical or owned runtime SS."""
    if not isinstance(node, c.CBinaryOp) or node.op not in {"Shl", "Mul"}:
        return False
    scale = node.rhs
    if not isinstance(scale, c.CConstant) or scale.value != (4 if node.op == "Shl" else 16):
        return False
    register = _segment_carrier(node.lhs)
    if not isinstance(register, c.CVariable):
        return False
    kind = register.type
    if not isinstance(kind, (SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeNum)):
        return False
    if kind.size != 16 or kind.signed:
        return False
    variable = register.variable
    if runtime_segment_name_for_variable_8616(variable) == "ss":
        return True
    return (isinstance(variable, SimRegisterVariable) and variable.size == 2
            and project.arch.register_names.get(variable.reg) == "ss")


def _segment_carrier(node: object) -> object | None:
    """Strip only integer casts that preserve every unsigned selector value."""
    while isinstance(node, c.CTypeCast):
        kind = node.dst_type
        if not isinstance(kind, (SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeNum)):
            return None
        if kind.size < 16 or (kind.size == 16 and kind.signed):
            return None
        node = node.expr
    return node


def _address_casts_preserve_ss(node: object, project: _Project) -> bool:
    """Reject casts that lose a selector, stack reference or physical address.

    Flattening removes casts, so authenticate every removed cast first. Physical
    addresses and stack-reference carriers require at least 32 bits; only the
    unscaled unsigned selector permits a 16-bit carrier. Casted constants and
    other carriers remain unsupported rather than acquiring guessed values.
    """
    for child in _iter_c_nodes_deep_8616(node):
        if not isinstance(child, c.CTypeCast):
            continue
        terms = tuple(_iter_c_nodes_deep_8616(child.expr))
        address_carrier = any(
            _ss_base(term, project)
            or (isinstance(term, c.CUnaryOp) and term.op == "Reference")
            for term in terms
        )
        if address_carrier:
            kind = child.dst_type
            if not isinstance(kind, (SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeNum, SimTypePointer)) or kind.size < 32:
                return False
            if isinstance(kind, SimTypePointer) and not isinstance(kind.pts_to, SimTypeChar):
                # A wider pointee changes the unit of subsequent + / -.
                return False
        else:
            carrier = _segment_carrier(child)
            if not isinstance(carrier, c.CVariable):
                return False
            kind = carrier.type
            if not isinstance(kind, (SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeNum)):
                return False
            if kind.size != 16 or kind.signed:
                return False
    return True


def addressed_stack_byte_8616(node: object, project: object) -> AddressedStackByte8616 | None:
    """Recognize one byte read with one SS base, one stack reference and constants.

    Foreign segments, multiple segment terms, negated references, other values
    and wider loads refuse. Consumers must bind the resulting referenced object
    through their authoritative coordinate registry and Alias fact.
    """
    if not isinstance(node, c.CUnaryOp) or node.op != "Dereference" or not isinstance(node.type, SimTypeChar):
        return None
    if not _address_casts_preserve_ss(node.operand, cast(_Project, project)):
        return None
    reference: c.CVariable | None = None
    displacement = 0
    segments = 0
    for term, sign in _flatten_add_sub_terms_8616(node.operand):
        if isinstance(term, c.CConstant) and type(term.value) is int:
            displacement += sign * term.value
        elif _ss_base(term, cast(_Project, project)):
            if sign != 1 or segments:
                return None
            segments += 1
        elif isinstance(term, c.CUnaryOp) and term.op == "Reference" and sign == 1:
            local = term.operand
            if reference is not None or not isinstance(local, c.CVariable) or not isinstance(local.variable, SimStackVariable):
                return None
            # Reference arithmetic is in pointed-to elements, not bytes.
            # Only a one-byte object grants the byte displacement used here.
            if not isinstance(local.type, SimTypeChar) or local.variable.size != 1:
                return None
            reference = local
        else:
            return None
    return AddressedStackByte8616(reference, displacement) if segments == 1 and reference is not None else None
