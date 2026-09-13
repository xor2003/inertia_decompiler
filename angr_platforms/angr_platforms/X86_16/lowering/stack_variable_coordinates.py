"""Keep machine-BP and angr entry-SP stack coordinates coherent.

Layer: Types/Lowering.
Responsibility: record the exact coordinate projection used when Alias-proven
SS:BP storage is materialized as angr ``SimStackVariable`` objects. Consumers
must ask this owner for machine-BP offsets instead of interpreting angr's
entry-SP ``variable.offset`` as a BP displacement.
Dynamic boundary: the registry is attached to third-party angr codegen objects.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_variable import SimStackVariable

from ..alias.stack_coordinate_projection import (
    StackCoordinateProjectionStatus8616,
    project_stack_offset_to_machine_bp_8616,
)
from ..alias.stack_memory_ssa_contracts import StackMemorySSAAliasArtifact8616
from ..analysis.stack_frame_ir import FrameAccessArtifact
from .stack_function_coordinates import projected_c_function_machine_bp_offset_8616
from .stack_storage_evidence import (
    alias_excludes_stack_range_8616,
    typed_frame_excludes_stack_range_8616,
)


class StackCoordinateProducer8616(StrEnum):
    """Identify the Lowering producer allowed to refresh a coordinate entry."""

    STACK_STORAGE = "stack_storage"
    CALL_OUTPUT_OBJECT = "call_output_object"


@dataclass(frozen=True, slots=True)
class StackVariableCoordinateProjection8616:
    """One machine-BP storage slot and its typed semantic value projection."""

    variable: SimStackVariable
    cvar: object
    bp_offset: int
    entry_sp_offset: int
    size: int
    display_name: str = ""
    equivalent_variables: tuple[SimStackVariable, ...] = ()
    producer: StackCoordinateProducer8616 = StackCoordinateProducer8616.STACK_STORAGE

    @property
    def value_size(self) -> int:
        """Return the current typed value width inside this storage slot."""
        return _semantic_value_size_8616(self.cvar, self.size)


@dataclass(frozen=True, slots=True)
class StackVariableCoordinateRegistry8616:
    """Immutable coordinate projections owned by one codegen surface."""

    projections: tuple[StackVariableCoordinateProjection8616, ...] = ()

    def for_variable(
        self,
        variable: SimStackVariable,
    ) -> StackVariableCoordinateProjection8616 | None:
        """Return the projection for the exact angr variable object."""
        return next(
            (
                projection
                for projection in self.projections
                if projection.variable is variable
                or any(alias is variable for alias in projection.equivalent_variables)
            ),
            None,
        )

    def for_bp_range(
        self,
        bp_offset: int,
        size: int,
    ) -> StackVariableCoordinateProjection8616 | None:
        """Return the unique projection for one exact machine-BP byte range."""
        matches = tuple(
            projection
            for projection in self.projections
            if projection.bp_offset == bp_offset and projection.size == size
        )
        return matches[0] if len(matches) == 1 else None

    def containing_bp_range(
        self,
        bp_offset: int,
        size: int,
    ) -> StackVariableCoordinateProjection8616 | None:
        """Return the unique projected owner containing one machine-BP range."""
        matches = tuple(
            projection
            for projection in self.projections
            if projection.bp_offset <= bp_offset
            and projection.bp_offset + projection.size >= bp_offset + size
        )
        return matches[0] if len(matches) == 1 else None

    def for_bp_value_range(
        self,
        bp_offset: int,
        size: int,
    ) -> StackVariableCoordinateProjection8616 | None:
        """Return the unique exact storage or typed low-value projection."""
        exact = self.for_bp_range(bp_offset, size)
        if exact is not None:
            return exact
        owner = self.containing_bp_range(bp_offset, size)
        if (
            owner is None
            or owner.bp_offset != bp_offset
            or owner.value_size != size
        ):
            return None
        return owner

    def for_entry_sp_range(
        self,
        entry_sp_offset: int,
        size: int,
    ) -> StackVariableCoordinateProjection8616 | None:
        """Return the unique projection surviving an AST variable clone."""
        matches = tuple(
            projection
            for projection in self.projections
            if projection.entry_sp_offset == entry_sp_offset and projection.size == size
        )
        return matches[0] if len(matches) == 1 else None

    def for_equivalent_entry_sp_variable(
        self,
        variable: SimStackVariable,
    ) -> StackVariableCoordinateProjection8616 | None:
        """Return a clone projection only when angr identity also agrees.

        A raw machine-BP variable can have the same numeric offset as another
        variable's projected entry-SP coordinate. Range equality alone cannot
        distinguish those domains, so an absent or different identifier must
        refuse clone recovery.
        """
        if not isinstance(variable.offset, int) or not isinstance(variable.size, int):
            return None
        ident = variable.ident
        if not isinstance(ident, str) or not ident:
            return None
        matches = tuple(
            projection
            for projection in self.projections
            if projection.entry_sp_offset == variable.offset
            and projection.size == variable.size
            and any(
                candidate.ident == ident
                for candidate in (projection.variable, *projection.equivalent_variables)
            )
        )
        return matches[0] if len(matches) == 1 else None

    def for_named_entry_sp_variable(
        self,
        variable: SimStackVariable,
    ) -> StackVariableCoordinateProjection8616 | None:
        """Return the unique durable-name projection for an AST snapshot clone."""
        if (
            not isinstance(variable.offset, int)
            or not isinstance(variable.size, int)
            or not isinstance(variable.name, str)
            or not variable.name
        ):
            return None
        matches = tuple(
            projection
            for projection in self.projections
            if projection.entry_sp_offset == variable.offset
            and projection.size == variable.size
            and projection.display_name == variable.name
        )
        return matches[0] if len(matches) == 1 else None

    def containing_entry_sp_range(
        self,
        entry_sp_offset: int,
        size: int,
    ) -> StackVariableCoordinateProjection8616 | None:
        """Return the unique projected owner containing one entry-SP range."""
        matches = tuple(
            projection
            for projection in self.projections
            if projection.entry_sp_offset <= entry_sp_offset
            and projection.entry_sp_offset + projection.size
            >= entry_sp_offset + size
        )
        return matches[0] if len(matches) == 1 else None


class _CodegenBoundary8616(Protocol):
    """Dynamic angr codegen extension carrying the owned registry."""

    _inertia_stack_variable_coordinate_registry_8616: StackVariableCoordinateRegistry8616
    _inertia_stack_memory_ssa_alias_artifact: StackMemorySSAAliasArtifact8616
    _inertia_vex_ir_frame: FrameAccessArtifact


class _CVariableBoundary8616(Protocol):
    """Third-party C variable field needed to publish a selected projection."""

    variable: object


class _TypedCVariableBoundary8616(Protocol):
    """Third-party C variable type field used to retain a typed value view."""

    variable_type: object


class _SizedTypeBoundary8616(Protocol):
    """Third-party angr type width used at the C-variable boundary."""

    size: int


def _semantic_value_size_8616(cvar: object, storage_size: int) -> int:
    """Return a proven semantic value width bounded by its ABI storage slot."""
    try:
        variable_type = cast(_TypedCVariableBoundary8616, cvar).variable_type
        bits = cast(_SizedTypeBoundary8616, variable_type).size
    except (AttributeError, TypeError, ValueError):
        return storage_size
    if not isinstance(bits, int) or bits <= 0:
        return storage_size
    value_size = max(1, (bits + 7) // 8)
    return value_size if value_size <= storage_size else storage_size


def stack_variable_coordinate_registry_8616(
    codegen: object,
) -> StackVariableCoordinateRegistry8616:
    """Return the typed registry attached to an angr codegen boundary."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        registry = boundary._inertia_stack_variable_coordinate_registry_8616
    except AttributeError:
        return StackVariableCoordinateRegistry8616()
    return registry if isinstance(registry, StackVariableCoordinateRegistry8616) else StackVariableCoordinateRegistry8616()


def reset_stack_variable_coordinate_registry_8616(codegen: object) -> None:
    """Reset projections before replaying exact stack materialization."""
    boundary = cast(_CodegenBoundary8616, codegen)
    boundary._inertia_stack_variable_coordinate_registry_8616 = (
        StackVariableCoordinateRegistry8616()
    )


def record_stack_variable_coordinate_projection_8616(
    codegen: object,
    *,
    variable: SimStackVariable,
    cvar: object,
    bp_offset: int,
    entry_sp_offset: int,
    size: int,
    display_name: str | None = None,
    producer: StackCoordinateProducer8616 = StackCoordinateProducer8616.STACK_STORAGE,
) -> StackVariableCoordinateProjection8616:
    """Record one exact projection, replacing prior data for that variable."""
    if size <= 0:
        raise ValueError("stack coordinate projection size must be positive")
    projection = StackVariableCoordinateProjection8616(
        variable=variable,
        cvar=cvar,
        bp_offset=bp_offset,
        entry_sp_offset=entry_sp_offset,
        size=size,
        producer=producer,
        display_name=(
            display_name
            if isinstance(display_name, str) and display_name
            else variable.name or ""
        ),
    )
    registry = stack_variable_coordinate_registry_8616(codegen)
    retained = tuple(
        item
        for item in registry.projections
        if item.variable is not variable
        and not (item.bp_offset == bp_offset and item.size == size)
    )
    boundary = cast(_CodegenBoundary8616, codegen)
    boundary._inertia_stack_variable_coordinate_registry_8616 = (
        StackVariableCoordinateRegistry8616((*retained, projection))
    )
    return projection


def record_stack_variable_coordinate_alias_8616(
    codegen: object,
    *,
    bp_offset: int,
    size: int,
    variable: SimStackVariable,
) -> StackVariableCoordinateProjection8616 | None:
    """Attach one Lowering-reconciled angr view to a canonical projection."""
    registry = stack_variable_coordinate_registry_8616(codegen)
    projection = registry.for_bp_range(bp_offset, size)
    if projection is None:
        return None
    if projection.variable is variable or any(
        alias is variable for alias in projection.equivalent_variables
    ):
        return projection
    rebound = StackVariableCoordinateProjection8616(
        variable=projection.variable,
        cvar=projection.cvar,
        bp_offset=projection.bp_offset,
        entry_sp_offset=projection.entry_sp_offset,
        size=projection.size,
        display_name=projection.display_name,
        equivalent_variables=(*projection.equivalent_variables, variable),
        producer=projection.producer,
    )
    boundary = cast(_CodegenBoundary8616, codegen)
    boundary._inertia_stack_variable_coordinate_registry_8616 = (
        StackVariableCoordinateRegistry8616(
            tuple(rebound if item is projection else item for item in registry.projections)
        )
    )
    return rebound


def bind_stack_variable_coordinate_cvar_8616(
    codegen: object,
    *,
    bp_offset: int,
    size: int,
    cvar: object,
    display_name: str | None = None,
    producer: StackCoordinateProducer8616 | None = None,
) -> StackVariableCoordinateProjection8616 | None:
    """Bind an existing projection to its canonical C interface variable.

    The projection variable retains angr's entry-SP coordinate. The C variable
    may instead be the canonical machine-BP function argument selected from the
    same Alias identity; consumers must resolve through this registry.
    """
    registry = stack_variable_coordinate_registry_8616(codegen)
    projection = registry.for_bp_range(bp_offset, size)
    if projection is None:
        return None
    rebound = StackVariableCoordinateProjection8616(
        variable=projection.variable,
        cvar=cvar,
        bp_offset=projection.bp_offset,
        entry_sp_offset=projection.entry_sp_offset,
        size=projection.size,
        display_name=display_name or projection.display_name,
        equivalent_variables=projection.equivalent_variables,
        producer=producer if producer is not None else projection.producer,
    )
    boundary = cast(_CodegenBoundary8616, codegen)
    boundary._inertia_stack_variable_coordinate_registry_8616 = (
        StackVariableCoordinateRegistry8616(
            tuple(rebound if item is projection else item for item in registry.projections)
        )
    )
    return rebound


def publish_selected_stack_cvar_projection_8616(
    codegen: object,
    cvar: object,
    *,
    bp_offset: int,
    size: int,
    entry_sp_offset: int | None = None,
) -> StackVariableCoordinateProjection8616 | None:
    """Publish one selected C variable with an optional proven entry-SP coordinate."""
    try:
        variable = cast(_CVariableBoundary8616, cvar).variable
    except AttributeError:
        return None
    if (
        not isinstance(variable, SimStackVariable)
        or variable.base != "bp"
        or not isinstance(variable.offset, int)
        or not isinstance(variable.size, int)
        or variable.size != size
    ):
        return None
    projection = stack_variable_coordinate_registry_8616(codegen).for_bp_range(
        bp_offset,
        size,
    )
    if (
        projection is not None
        and isinstance(entry_sp_offset, int)
        and projection.entry_sp_offset != entry_sp_offset
    ):
        return record_stack_variable_coordinate_projection_8616(
            codegen,
            variable=variable,
            cvar=cvar,
            bp_offset=bp_offset,
            entry_sp_offset=entry_sp_offset,
            size=size,
            display_name=variable.name,
        )
    if projection is not None:
        record_stack_variable_coordinate_alias_8616(
            codegen,
            bp_offset=bp_offset,
            size=size,
            variable=variable,
        )
        return bind_stack_variable_coordinate_cvar_8616(
            codegen,
            bp_offset=bp_offset,
            size=size,
            cvar=cvar,
            display_name=variable.name,
        )
    return record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=variable,
        cvar=cvar,
        bp_offset=bp_offset,
        entry_sp_offset=(
            entry_sp_offset if isinstance(entry_sp_offset, int) else variable.offset
        ),
        size=size,
        display_name=variable.name,
    )


def refresh_stack_variable_coordinate_cvar_8616(codegen: object, cvar: CVariable) -> None:
    """Grow accepted storage and replay names; value narrowing cannot shrink ABI slots."""
    variable = cvar.variable
    if not isinstance(variable, SimStackVariable) or variable.size <= 0:
        return
    registry = stack_variable_coordinate_registry_8616(codegen)
    projection = registry.for_variable(variable)
    if projection is None:
        return
    refreshed = replace(
        projection, cvar=cvar, size=max(projection.size, variable.size),
        display_name=variable.name or projection.display_name,
    )
    cast(_CodegenBoundary8616, codegen)._inertia_stack_variable_coordinate_registry_8616 = (
        StackVariableCoordinateRegistry8616(tuple(
            refreshed if item is projection else item for item in registry.projections
        ))
    )


def machine_bp_offset_for_stack_variable_8616(
    codegen: object,
    variable: SimStackVariable,
) -> int | None:
    """Return machine-BP offset, refusing unresolved coordinate collisions."""
    registry = stack_variable_coordinate_registry_8616(codegen)
    projection = registry.for_variable(variable)
    if projection is not None:
        return projection.bp_offset
    if isinstance(variable.offset, int) and isinstance(variable.size, int):
        projection = registry.for_equivalent_entry_sp_variable(variable)
        if projection is not None:
            return projection.bp_offset
        named_projection = registry.for_named_entry_sp_variable(variable)
        raw_projection = registry.for_bp_range(variable.offset, variable.size)
        if (
            named_projection is not None
            and (
                raw_projection is None
                or raw_projection is named_projection
                or raw_projection.display_name != variable.name
            )
        ):
            return named_projection.bp_offset
        projection = registry.for_entry_sp_range(variable.offset, variable.size)
        if (
            projection is not None
            and registry.for_bp_range(variable.offset, variable.size) is None
            and (
                alias_excludes_stack_range_8616(
                    codegen,
                    variable.offset,
                    variable.size,
                )
                or typed_frame_excludes_stack_range_8616(
                    codegen,
                    variable.offset,
                    variable.size,
                )
            )
        ):
            return projection.bp_offset
        if projection is not None:
            return (
                variable.offset
                if raw_projection is None or raw_projection is projection
                else None
            )
        projection = registry.containing_entry_sp_range(variable.offset, variable.size)
        if projection is not None:
            return projection.bp_offset + variable.offset - projection.entry_sp_offset
        boundary = cast(_CodegenBoundary8616, codegen)
        try:
            source_alias = boundary._inertia_stack_memory_ssa_alias_artifact
        except AttributeError:
            source_alias = None
        try:
            frame = boundary._inertia_vex_ir_frame
        except AttributeError:
            frame = None
        if isinstance(source_alias, StackMemorySSAAliasArtifact8616):
            coordinate = project_stack_offset_to_machine_bp_8616(
                source_alias,
                frame,
                variable.offset,
                variable.size,
            )
            if coordinate.materialized and isinstance(coordinate.bp_offset, int):
                return coordinate.bp_offset
            if coordinate.status is StackCoordinateProjectionStatus8616.AMBIGUOUS:
                return None
        if variable.offset < 0:
            c_function_offset = projected_c_function_machine_bp_offset_8616(
                codegen,
                variable,
            )
            if isinstance(c_function_offset, int):
                return c_function_offset
    return variable.offset if isinstance(variable.offset, int) else None


def stack_cvar_for_machine_bp_range_8616(
    codegen: object,
    bp_offset: int,
    size: int,
) -> object | None:
    """Return the canonical CVariable for one exact projected BP range."""
    projection = stack_variable_coordinate_registry_8616(codegen).for_bp_range(
        bp_offset,
        size,
    )
    return projection.cvar if projection is not None else None


def stack_cvar_for_machine_bp_value_range_8616(
    codegen: object,
    bp_offset: int,
    size: int,
) -> object | None:
    """Return the C value for an exact slot or its proven low-byte view."""
    projection = stack_variable_coordinate_registry_8616(codegen).for_bp_value_range(
        bp_offset,
        size,
    )
    return projection.cvar if projection is not None else None


__all__ = [
    "StackCoordinateProducer8616",
    "StackVariableCoordinateProjection8616",
    "StackVariableCoordinateRegistry8616",
    "bind_stack_variable_coordinate_cvar_8616",
    "machine_bp_offset_for_stack_variable_8616",
    "publish_selected_stack_cvar_projection_8616",
    "record_stack_variable_coordinate_alias_8616",
    "record_stack_variable_coordinate_projection_8616",
    "reset_stack_variable_coordinate_registry_8616",
    "stack_cvar_for_machine_bp_range_8616",
    "stack_cvar_for_machine_bp_value_range_8616",
    "stack_variable_coordinate_registry_8616",
]
