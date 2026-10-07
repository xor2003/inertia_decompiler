"""Close typed condition refreshes before returning to Structuring scheduling.

Layer: Structuring.
Responsibility: refresh condition ASTs from typed facts, close any recreated
segmented-memory expressions through Types/Lowering, and report typed replay
requirements to the Structuring stage.
Forbidden: discover conditions, infer alias/type facts, parse rendered C, or
silently classify an incomplete refresh as closed.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
Dynamic boundary: project and codegen are third-party angr plugin objects.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from inertia.lowering.condition_transfer import transfer_typed_conditions_to_codegen_8616
from inertia.lowering.segment_global_materialization import (
    cod_metadata_for_codegen_8616,
    run_segment_global_materialization_8616,
)

from .condition_materialization import (
    materialize_structuring_conditions_8616,
    structuring_condition_surface_token_8616,
)

__all__ = [
    "ConditionRefreshClosure8616",
    "StructuringConditionRefreshResult8616",
    "refresh_structuring_condition_semantics_8616",
]


class ConditionRefreshClosure8616(Enum):
    """State whether a condition refresh needs another general Lowering pass."""

    STABLE = "stable"
    CLOSED = "closed"
    REQUIRES_BROAD_REPLAY = "requires_broad_replay"


@dataclass(frozen=True, slots=True)
class StructuringConditionRefreshResult8616:
    """Typed scheduling result for one condition refresh request."""

    closure: ConditionRefreshClosure8616
    condition_changed: bool = False
    segment_global_changed: bool = False
    transferred_count: int = 0

    @property
    def changed(self) -> bool:
        """Return whether the request changed state or remained unclosed."""
        return (
            self.condition_changed
            or self.segment_global_changed
            or self.closure is ConditionRefreshClosure8616.REQUIRES_BROAD_REPLAY
        )

    @property
    def requires_broad_lowering_replay(self) -> bool:
        """Return whether conservative full Lowering replay is required."""
        return self.closure is ConditionRefreshClosure8616.REQUIRES_BROAD_REPLAY

    @classmethod
    def stable(cls) -> StructuringConditionRefreshResult8616:
        """Return a result for an unchanged, already-closed condition surface."""
        return cls(ConditionRefreshClosure8616.STABLE)

    @classmethod
    def unclosed(cls) -> StructuringConditionRefreshResult8616:
        """Return a conservative result when refresh completion is unknown."""
        return cls(ConditionRefreshClosure8616.REQUIRES_BROAD_REPLAY)


class _ConditionRefreshFunction8616(Protocol):
    """Third-party C-function fields consumed by condition refresh."""

    addr: int
    statements: object


class _ConditionRefreshCodegen8616(Protocol):
    """Third-party codegen metadata consumed and published by condition refresh."""

    cfunc: _ConditionRefreshFunction8616
    _inertia_typed_conditions_transferred: bool
    _inertia_structuring_conditions_materialized_after_transfer_8616: bool
    _inertia_structuring_conditions_materialized_root_8616: object
    _inertia_structuring_conditions_materialized_surface_8616: object
    _inertia_codegen_decl_refresh_required_8616: bool


class _SyntheticGlobalsBoundary8616(Protocol):
    """Optional synthetic-global metadata on a third-party pipeline object."""

    _inertia_synthetic_globals: object


def _synthetic_globals_8616(project: object, codegen: object) -> dict[object, object] | None:
    """Return dynamic synthetic-global metadata from its supported boundaries."""
    for owner in (codegen, project):
        try:
            value = cast(_SyntheticGlobalsBoundary8616, owner)._inertia_synthetic_globals
        except AttributeError:
            continue
        if isinstance(value, dict):
            return value
    return None


def refresh_structuring_condition_semantics_8616(
    project: object,
    codegen: object,
) -> StructuringConditionRefreshResult8616:
    """Refresh and fully lower typed condition expressions.

    Condition materialization constructs SS operands from typed stack evidence.
    The explicit segment/global replay closes every recreated DS/ES expression.
    Therefore a successful request is closed and does not require the unrelated
    callsite, direct-stack, or whole-AST Lowering replay.
    """
    surface = cast(_ConditionRefreshCodegen8616, codegen)
    try:
        function = surface.cfunc
        func_addr = function.addr
        current_root = function.statements
    except AttributeError:
        return StructuringConditionRefreshResult8616.stable()
    if not isinstance(func_addr, int):
        return StructuringConditionRefreshResult8616.stable()
    current_surface = structuring_condition_surface_token_8616(codegen)
    try:
        already_materialized = surface._inertia_structuring_conditions_materialized_after_transfer_8616
        materialized_root = surface._inertia_structuring_conditions_materialized_root_8616
        materialized_surface = surface._inertia_structuring_conditions_materialized_surface_8616
    except AttributeError:
        already_materialized = False
        materialized_root = None
        materialized_surface = None
    if already_materialized and materialized_root is current_root and materialized_surface == current_surface:
        return StructuringConditionRefreshResult8616.stable()

    transferred_count = 0
    try:
        conditions_transferred = surface._inertia_typed_conditions_transferred
    except AttributeError:
        conditions_transferred = False
    if not conditions_transferred:
        transferred_count = int(
            transfer_typed_conditions_to_codegen_8616(project, func_addr, codegen) or 0
        )
        surface._inertia_typed_conditions_transferred = True
    condition_result = materialize_structuring_conditions_8616(project, codegen)
    segment_result = run_segment_global_materialization_8616(
        project,
        codegen,
        _synthetic_globals_8616(project, codegen),
        cod_metadata=cod_metadata_for_codegen_8616(project, codegen),
    )
    if condition_result.changed or segment_result.changed:
        surface._inertia_codegen_decl_refresh_required_8616 = True
    surface._inertia_structuring_conditions_materialized_after_transfer_8616 = True
    surface._inertia_structuring_conditions_materialized_root_8616 = current_root
    surface._inertia_structuring_conditions_materialized_surface_8616 = (
        structuring_condition_surface_token_8616(codegen)
    )
    return StructuringConditionRefreshResult8616(
        ConditionRefreshClosure8616.CLOSED,
        condition_changed=condition_result.changed,
        segment_global_changed=segment_result.changed,
        transferred_count=transferred_count,
    )
