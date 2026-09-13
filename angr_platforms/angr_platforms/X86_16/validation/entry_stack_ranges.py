"""Collect proven entry-defined stack argument ranges for tail validation.

Layer: Validation.
Responsibility: project explicit structured-C stack arguments into the shared
machine-BP coordinate domain and expose only exact initialized byte ranges.
Consumes the Types/Lowering stack-coordinate owner; it does not infer argument
semantics from names, rendered C, assembly text, or positive offsets alone.
Owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_type import SimType, SimTypeFunction
from angr.sim_variable import SimStackVariable

from ..lowering.stack_function_coordinates import (
    c_function_stack_coordinate_projection_8616,
)
from ..lowering.stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
)
from ..validation_dataflow import DefUseEntryStackRange8616

_BITS_PER_BYTE_8616 = 8
_FIRST_ARGUMENT_BP_OFFSET_8616 = 4

__all__ = [
    "EntryStackRangeCollection8616",
    "EntryStackRangeCollectionStats8616",
    "entry_stack_ranges_from_codegen_8616",
]


@dataclass(frozen=True, slots=True)
class EntryStackRangeCollectionStats8616:
    """Closed-loop counters for structured entry-stack argument evidence."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every stack argument reached one explicit verdict."""
        return (
            self.raw_fact_count == self.materialized_count + self.failure_count
            and self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
        )


@dataclass(frozen=True, slots=True)
class EntryStackRangeCollection8616:
    """Exact machine-BP entry ranges plus their collection accounting."""

    ranges: tuple[DefUseEntryStackRange8616, ...] = ()
    stats: EntryStackRangeCollectionStats8616 = (
        EntryStackRangeCollectionStats8616()
    )


class _CFunctionBoundary8616(Protocol):
    """Third-party structured function fields needed by this collector."""

    arg_list: Iterable[object] | None
    functy: object


class _CodegenBoundary8616(Protocol):
    """Third-party codegen field exposing the structured function contract."""

    cfunc: _CFunctionBoundary8616


def _stack_argument_variable_8616(argument: object) -> SimStackVariable | None:
    """Return the exact angr stack variable carried by one C argument."""
    if not isinstance(argument, CVariable):
        return None
    variable = argument.unified_variable
    if not isinstance(variable, SimStackVariable):
        variable = argument.variable
    return variable if isinstance(variable, SimStackVariable) else None


def _declared_argument_type_8616(prototype: object, index: int, argument: CVariable) -> SimType | None:
    """Read the rendered signature type, falling back only for a partial C AST."""
    if isinstance(prototype, SimTypeFunction):
        arguments = prototype.args or ()
        return arguments[index] if index < len(arguments) else None
    return argument.variable_type if prototype is None else None


def _argument_value_width_8616(argument_type: SimType | None, slot_width: object) -> int | None:
    """Limit initialized bytes to the C value, never padding or a unified owner."""
    if not isinstance(slot_width, int) or slot_width <= 0:
        return None
    if argument_type is None:
        return None
    try:
        bits = argument_type.size
    except (AttributeError, TypeError, ValueError):
        return None
    if not isinstance(bits, int) or bits <= 0 or bits % _BITS_PER_BYTE_8616:
        return None
    return min(slot_width, bits // _BITS_PER_BYTE_8616)


def entry_stack_ranges_from_codegen_8616(
    codegen: object,
) -> EntryStackRangeCollection8616:
    """Collect explicit C stack arguments in the machine-BP domain.

    Register arguments are outside this collector. A stack argument whose
    coordinate or width cannot be proven is counted as a failure and omitted,
    so downstream def-use validation refuses any read from that range.
    """
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        arguments = boundary.cfunc.arg_list
    except AttributeError:
        arguments = None
    if arguments is None:
        return EntryStackRangeCollection8616()
    try:
        argument_nodes = tuple(arguments)
    except TypeError:
        return EntryStackRangeCollection8616()
    function_projection = c_function_stack_coordinate_projection_8616(
        boundary.cfunc
    )
    try:
        prototype = boundary.cfunc.functy
    except AttributeError:
        prototype = None

    raw_fact_count = 0
    materialized_count = 0
    failure_count = 0
    ranges: list[DefUseEntryStackRange8616] = []
    for index, argument in enumerate(argument_nodes):
        variable = _stack_argument_variable_8616(argument)
        if variable is None:
            continue
        raw_fact_count += 1
        slot_width = variable.size
        argument_type = _declared_argument_type_8616(prototype, index, cast(CVariable, argument))
        width = _argument_value_width_8616(argument_type, slot_width)
        projected_argument = (
            function_projection.arguments[index]
            if function_projection is not None
            and index < len(function_projection.arguments)
            else None
        )
        bp_offset = (
            projected_argument.machine_bp_offset
            if projected_argument is not None
            and projected_argument.entry_sp_offset == variable.offset
            and projected_argument.size == slot_width
            else machine_bp_offset_for_stack_variable_8616(codegen, variable)
        )
        if (
            variable.base != "bp"
            or not isinstance(width, int)
            or width <= 0
            or not isinstance(bp_offset, int)
            or bp_offset < _FIRST_ARGUMENT_BP_OFFSET_8616
        ):
            failure_count += 1
            continue
        ranges.append(
            DefUseEntryStackRange8616(base_offset=bp_offset, width=width)
        )
        materialized_count += 1

    return EntryStackRangeCollection8616(
        ranges=tuple(sorted(set(ranges))),
        stats=EntryStackRangeCollectionStats8616(
            raw_fact_count=raw_fact_count,
            normalized_fact_count=materialized_count,
            classified_fact_count=materialized_count,
            materialized_count=materialized_count,
            failure_count=failure_count,
        ),
    )
