# cython: language_level=3, infer_types=True
"""Render fallback names using the proven machine-BP argument coordinates.

Layer: Types/Lowering.
Responsibility: consume published stack coordinates when selecting argument or
local identifiers. Never infer storage identity from names or entry-SP offsets.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Sequence
from typing import Final, Protocol, cast

from angr.sim_variable import SimStackVariable

from .stack_variable_coordinates import machine_bp_offset_for_stack_variable_8616

_BP_OFFSET_MODULUS: Final[cython.longlong] = 1 << 16
_BP_OFFSET_SIGN_BIT: Final[cython.longlong] = _BP_OFFSET_MODULUS >> 1
_BP_OFFSET_UNSIGNED_MAX: Final[cython.longlong] = _BP_OFFSET_MODULUS - 1


class _CodegenBoundary(Protocol):
    """Third-party codegen may expose its current argument declarations."""

    cfunc: _FunctionBoundary


class _FunctionBoundary(Protocol):
    """Argument list supplied by native structured codegen."""

    arg_list: Sequence[_ArgumentBoundary] | None


class _ArgumentBoundary(Protocol):
    """Native argument declaration with its underlying variable."""

    variable: object


@cython.ccall
def machine_bp_stack_object_name_8616(offset: cython.longlong, *, codegen: object | None = None) -> str:
    """Name a machine-BP slot without comparing it with raw entry-SP offsets."""
    argument: object
    is_unsigned_negative_offset = _BP_OFFSET_SIGN_BIT <= offset <= _BP_OFFSET_UNSIGNED_MAX
    offset = offset - _BP_OFFSET_MODULUS if is_unsigned_negative_offset else offset
    try:
        arguments = cast(_CodegenBoundary, codegen).cfunc.arg_list or ()
    except AttributeError:
        # Partial native codegen surfaces may have no function or declarations.
        arguments = ()
    for argument in arguments:
        variable = argument.variable
        if isinstance(variable, SimStackVariable):
            bp_offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
            if bp_offset == offset:
                return f"arg_{offset:x}"
    return f"local_{abs(offset):x}"
