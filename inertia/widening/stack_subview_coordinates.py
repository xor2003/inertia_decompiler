"""Read published coordinates for structured stack-view materialization.

Layer: Widening.
Consumes alias-proven storage identity.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
Responsibility: preserve the existing coordinate binding of a C variable when
selecting an Alias-proven object view. This is a read-only structural interface
to the published registry, not a dependency on Lowering's implementation.
Bindings locate syntax; Alias and Widening still prove storage ownership.
Do not infer coordinates from generated names or overwrite published bindings.
"""

from __future__ import annotations

from typing import Protocol, cast

from angr.sim_variable import SimStackVariable


class _CoordinateBinding8616(Protocol):
    """Read-only coordinate field of an existing immutable binding."""

    @property
    def bp_offset(self) -> int:
        """Return the bound machine-BP displacement."""
        ...


class _CoordinateRegistry8616(Protocol):
    """Identity-based lookup surface of the published coordinate registry."""

    def for_variable(self, variable: SimStackVariable) -> _CoordinateBinding8616 | None:
        """Find the binding for an exact variable identity."""
        ...

    def for_equivalent_entry_sp_variable(self, variable: SimStackVariable) -> _CoordinateBinding8616 | None:
        """Find a clone only when its durable identifier and range agree."""
        ...


class _CodegenCoordinates8616(Protocol):
    """Third-party codegen extension carrying the published registry."""

    _inertia_stack_variable_coordinate_registry_8616: _CoordinateRegistry8616


def published_stack_variable_range_8616(
    codegen: object,
    variable: object,
    function_addr: int,
) -> tuple[int, int] | None:
    """Return an explicit binding without deriving a new coordinate domain."""
    raw_range = stack_variable_range_8616(variable, function_addr)
    if raw_range is None or not isinstance(variable, SimStackVariable):
        return None
    try:
        registry = cast(_CodegenCoordinates8616, codegen)._inertia_stack_variable_coordinate_registry_8616
    except AttributeError:
        return None
    binding = registry.for_variable(variable)
    if binding is None:
        binding = registry.for_equivalent_entry_sp_variable(variable)
    return (binding.bp_offset, raw_range[1]) if binding is not None else None


def stack_variable_range_8616(
    variable: object,
    function_addr: int,
    *,
    codegen: object | None = None,
) -> tuple[int, int] | None:
    """Read a bound machine range, retaining legacy syntax only when unbound."""
    if not isinstance(variable, SimStackVariable):
        return None
    if variable.base != "bp" or variable.region != function_addr:
        return None
    if not isinstance(variable.offset, int) or not isinstance(variable.size, int) or variable.size <= 0:
        return None
    if codegen is not None:
        bound = published_stack_variable_range_8616(codegen, variable, function_addr)
        if bound is not None:
            return bound
    return variable.offset, variable.size
