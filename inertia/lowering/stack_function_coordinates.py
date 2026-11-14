# cython: language_level=3, infer_types=True
"""Project angr function-stack coordinates onto the 16-bit machine ABI.

Layer: Types/Lowering.
Responsibility: derive one typed entry-SP-to-machine-BP coordinate projection
from the final C function argument interface. Consumers may use that proven
delta for both arguments and locals, but must refuse inconsistent interfaces.
Consumes alias, widening, and typed facts. Do not recover semantics from COD,
source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_variable import SimStackVariable
import dataclasses
import operator


class _SizedTypeBoundary8616(Protocol):
    """Third-party angr type width used by the 16-bit ABI projection."""

    size: cython.longlong


class _FunctionTypeBoundary8616(Protocol):
    """Third-party angr function type fields consumed by this projection."""

    args: Sequence[object] | None


class _CFunctionBoundary8616(Protocol):
    """Third-party structured-C function fields consumed by this projection."""

    arg_list: Sequence[object] | None
    functy: _FunctionTypeBoundary8616 | None


class _CodegenBoundary8616(Protocol):
    """Third-party codegen field carrying the current C function."""

    cfunc: _CFunctionBoundary8616 | None


@dataclasses.dataclass(frozen=True, )
class FunctionStackArgumentCoordinate8616:
    """One final C argument in entry-SP and machine-BP coordinates."""

    argument_index: cython.longlong
    entry_sp_offset: cython.longlong
    machine_bp_offset: cython.longlong
    size: cython.longlong


@dataclasses.dataclass(frozen=True, )
class FunctionStackCoordinateProjection8616:
    """A coherent function-wide stack coordinate translation."""

    entry_sp_to_bp_delta: cython.longlong
    arguments: object

    def machine_bp_offset(self, entry_sp_offset: cython.longlong) -> cython.longlong:
        """Translate one entry-SP offset through the proven function delta."""
        return entry_sp_offset + self.entry_sp_to_bp_delta

    def argument_machine_bp_offset(
        self,
        entry_sp_offset: cython.longlong,
        size: object,
    ) -> int | None:
        """Return one unique argument offset matching an exact C stack slot."""
        matches = tuple(
            argument.machine_bp_offset
            for argument in iter(self.arguments)
            if operator.eq(argument.entry_sp_offset, entry_sp_offset)
            and (size is None or operator.eq(argument.size, size))
        )
        return matches[0] if len(matches) == 1 else None


@cython.ccall
def _x86_16_abi_type_size_bytes(type_: object, *, default: cython.longlong = 2) -> cython.longlong:
    """Return one typed 16-bit ABI value width in bytes."""
    fixed_size: object
    type_name = type(type_).__name__
    fixed_sizes = {
        "SimTypeChar": 1,
        "SimTypeNum": 1,
        "SimTypeShort": 2,
        "SimTypeInt": 2,
        "SimTypeBool": 2,
        "SimTypeLong": 4,
        "SimTypeLongLong": 8,
        "SimTypePointer": 2,
    }
    fixed_size = fixed_sizes.get(type_name)
    if fixed_size is not None:
        return fixed_size
    try:
        bits = cast(_SizedTypeBoundary8616, type_).size
    except (AttributeError, TypeError, ValueError):
        return default
    return max(1, (bits + 7) // 8) if isinstance(bits, int) and bits > 0 else default


@cython.ccall
def c_function_stack_coordinate_projection_8616(
    cfunc: object,
) -> FunctionStackCoordinateProjection8616 | None:
    """Derive one coherent near-function projection from final argument storage."""
    function_type: object
    argument: object
    argument_type: object
    index: object
    typed_cfunc = cast(_CFunctionBoundary8616, cfunc)
    try:
        arguments = tuple(typed_cfunc.arg_list or ())
    except AttributeError:
        return None
    try:
        function_type = typed_cfunc.functy
        argument_types = tuple(function_type.args or ()) if function_type is not None else ()
    except AttributeError:
        argument_types = ()
    if not arguments:
        return None
    typed_layout = operator.eq(len(arguments), len(argument_types))

    machine_bp_offset = 4
    coordinates: list[FunctionStackArgumentCoordinate8616] = []
    deltas: set[cython.longlong] = set()
    for index, (argument, argument_type) in enumerate(
        zip(
            arguments,
            argument_types if typed_layout else (None,) * len(arguments),
            strict=True,
        )
    ):
        if not isinstance(argument, CVariable):
            return None
        variable = argument.variable
        if (
            not isinstance(variable, SimStackVariable)
            or variable.base != "bp"
            or not isinstance(variable.offset, int)
            or not isinstance(variable.size, int)
            or variable.size <= 0
        ):
            return None
        coordinates.append(
            FunctionStackArgumentCoordinate8616(
                argument_index=index,
                entry_sp_offset=variable.offset,
                machine_bp_offset=machine_bp_offset,
                size=variable.size,
            )
        )
        deltas.add(machine_bp_offset - variable.offset)
        slot_size = (
            _x86_16_abi_type_size_bytes(argument_type)
            if typed_layout
            else variable.size
        )
        machine_bp_offset += max(2, slot_size)
    # A 16-bit near entry-SP interface starts at +2; establishing BP pushes the
    # saved BP and makes the same first argument BP+4. Zero, negative, or mixed
    # deltas mean the C interface is already projected or incomplete.
    if deltas != {2}:
        return None
    return FunctionStackCoordinateProjection8616(
        entry_sp_to_bp_delta=2,
        arguments=tuple(coordinates),
    )


@cython.ccall
def c_function_argument_machine_bp_offset_8616(
    cfunc: object,
    entry_sp_offset: cython.longlong,
    size: int | None,
) -> int | None:
    """Map one exact current C argument slot to its machine-BP ABI offset."""
    projection: object
    projection = c_function_stack_coordinate_projection_8616(cfunc)
    if projection is None:
        return None
    return projection.argument_machine_bp_offset(entry_sp_offset, size)


@cython.ccall
def projected_c_function_machine_bp_offset_8616(
    codegen: object,
    variable: SimStackVariable,
) -> int | None:
    """Translate one C stack variable when the full typed interface proves it."""
    cfunc: object
    projection: object
    typed_codegen = cast(_CodegenBoundary8616, codegen)
    try:
        cfunc = typed_codegen.cfunc
    except AttributeError:
        return None
    if cfunc is None or not isinstance(variable.offset, int):
        return None
    projection = c_function_stack_coordinate_projection_8616(cfunc)
    if projection is not None:
        return projection.machine_bp_offset(variable.offset)
    return _registered_cvar_offset_8616(codegen, cfunc, variable)


@cython.ccall
def _registered_cvar_offset_8616(
    codegen: object,
    cfunc: _CFunctionBoundary8616,
    variable: SimStackVariable,
) -> int | None:
    """Distinguish rebound formal arguments from untouched entry-SP locals."""
    bound: object
    argument: object
    # Final argument lowering may replace the C argument with its machine-BP
    # view while untouched local clones retain entry-SP offsets. The owned
    # registry preserves both coordinates and the exact C argument binding.
    from .stack_variable_coordinates import stack_variable_coordinate_registry_8616

    try:
        arguments = tuple(cfunc.arg_list or ())
    except AttributeError:
        return None
    registry = stack_variable_coordinate_registry_8616(codegen)
    bound_projections = []
    for argument in arguments:
        if not isinstance(argument, CVariable):
            continue
        argument_variable = argument.variable
        if (
            not isinstance(argument_variable, SimStackVariable)
            or not isinstance(argument_variable.offset, int)
            or not isinstance(argument_variable.size, int)
        ):
            continue
        bound = registry.for_variable(argument_variable)
        if bound is None:
            bound = registry.for_bp_range(
                argument_variable.offset,
                argument_variable.size,
            )
        if bound is None:
            bound = registry.for_entry_sp_range(
                argument_variable.offset,
                argument_variable.size,
            )
        if bound is not None:
            if variable is argument_variable or variable is argument.unified_variable:
                return bound.bp_offset
            bound_projections.append(bound)
    deltas = {
        item.bp_offset - item.entry_sp_offset for item in iter(bound_projections)
    }
    return variable.offset + 2 if deltas == {2} else None


@cython.ccall
def final_c_function_machine_bp_offset_8616(
    codegen: object,
    variable: SimStackVariable,
) -> int | None:
    """Resolve a final C variable without publishing mutable C evidence as Alias truth."""
    owned: object
    from .stack_variable_coordinates import (
        machine_bp_offset_for_stack_variable_8616,
        stack_variable_coordinate_registry_8616,
    )

    # A selected argument may already use machine-BP coordinates while its
    # untouched siblings still use entry-SP. Exact ownership outranks a delta.
    registry = stack_variable_coordinate_registry_8616(codegen)
    owned = registry.for_variable(variable)
    if owned is not None:
        return owned.bp_offset
    bound_views = {
        item.bp_offset for item in iter(registry.projections)
        if isinstance(item.cvar, CVariable)
        and item.cvar.unified_variable is variable
        and isinstance(item.cvar.variable, SimStackVariable)
        and (variable.base, variable.offset, variable.size, variable.region)
        == (item.cvar.variable.base, item.cvar.variable.offset, item.cvar.variable.size, item.cvar.variable.region)
    }
    if bound_views:
        return next(iter(bound_views)) if len(bound_views) == 1 else None
    projected = projected_c_function_machine_bp_offset_8616(codegen, variable)
    if isinstance(projected, int):
        return projected
    # Imported here to keep the authoritative Alias/frame owner independent of
    # this late C-interface projection.
    fallback = machine_bp_offset_for_stack_variable_8616(codegen, variable)
    return fallback if isinstance(fallback, int) else None


__all__ = [
    "FunctionStackArgumentCoordinate8616",
    "FunctionStackCoordinateProjection8616",
    "c_function_argument_machine_bp_offset_8616",
    "c_function_stack_coordinate_projection_8616",
    "final_c_function_machine_bp_offset_8616",
    "projected_c_function_machine_bp_offset_8616",
]
