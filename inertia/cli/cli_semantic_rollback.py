"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
This module restores a bounded core-validated C AST when late CLI mutation fails validation.
This module coordinates validation and rollback; it does not recover or rewrite semantics.
"""

from __future__ import annotations

import copy
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol, cast


class FinalSemanticReport8616(Protocol):
    """Final semantic report surface required by rollback orchestration."""

    def semantic_failures(self) -> Mapping[str, object]:
        """Return semantic failure families for the current C AST."""
        ...


@dataclass(frozen=True)
class TrustedCoreSnapshot8616:
    """Bounded C AST and tail-validation state accepted by the core pipeline."""

    cfunc: object
    tail_validation_snapshot: dict[str, Any]


def snapshot_trusted_cfunc_8616(
    cfunc: object,
    *,
    preserve_objects: tuple[object, ...] = (),
) -> object | None:
    """Copy a bounded C AST without detaching angr's live type store.

    ``VariableManagerInternal.__getstate__`` clears ``types._kb`` on the live
    manager while preparing a copy. Restore that third-party boundary and bind
    the copied manager before any later lowering pass consumes either object.
    """
    dynamic_cfunc = cast(Any, cfunc)
    variable_manager: Any | None = None
    manager: Any | None = None
    type_store: Any | None = None
    type_store_kb: Any | None = None
    try:
        boundary_manager = cast(Any, dynamic_cfunc.variable_manager)
        boundary_type_store = cast(Any, boundary_manager.types)
        variable_manager = boundary_manager
        manager = boundary_manager.manager
        type_store = boundary_type_store
        type_store_kb = boundary_type_store._kb
    except AttributeError:
        # Synthetic fixtures may not expose angr's variable-manager boundary.
        pass

    try:
        snapshot = copy.deepcopy(
            cfunc,
            {id(value): value for value in preserve_objects},
        )
    except Exception:
        return None
    finally:
        if type_store is not None:
            type_store._kb = type_store_kb

    if variable_manager is not None:
        try:
            snapshot_manager = cast(Any, snapshot).variable_manager
            if manager is not None:
                snapshot_manager.set_manager(manager)
            else:
                snapshot_manager.types._kb = type_store_kb
        except AttributeError:
            return None
    return snapshot


def rollback_final_semantic_drift_8616(
    project: object,
    codegen: object,
    trusted: TrustedCoreSnapshot8616 | None,
    *,
    refresh_validation: Callable[[object, object], FinalSemanticReport8616],
    restore_cfunc: Callable[[object], bool],
    replay_projections: Callable[[object], bool] | None = None,
    function_addr: int,
) -> bool:
    """Restore and revalidate a trusted AST after an absolute final guard failure."""
    report = refresh_validation(project, codegen)
    if not report.semantic_failures() or trusted is None:
        return False
    dynamic_codegen = cast(Any, codegen)
    dynamic_project = cast(Any, project)
    try:
        current_cfunc = dynamic_codegen.cfunc
    except AttributeError:
        return False
    try:
        current_codegen_tail_snapshot = copy.deepcopy(
            dynamic_codegen._inertia_tail_validation_snapshot
        )
    except AttributeError:
        current_codegen_tail_snapshot = None
    try:
        current_project_tail_snapshot = copy.deepcopy(
            dynamic_project._inertia_last_tail_validation_snapshot
        )
    except AttributeError:
        current_project_tail_snapshot = None
    if not restore_cfunc(trusted.cfunc):
        return False
    if replay_projections is not None:
        replay_projections(codegen)

    restored_tail_snapshot = copy.deepcopy(trusted.tail_validation_snapshot)
    dynamic_codegen._inertia_tail_validation_snapshot = restored_tail_snapshot
    dynamic_project._inertia_last_tail_validation_snapshot = dict(restored_tail_snapshot)
    if refresh_validation(project, codegen).semantic_failures():
        if not restore_cfunc(current_cfunc):
            raise RuntimeError(
                "failed to restore the current C AST after rejecting an invalid rollback snapshot"
            )
        if replay_projections is not None:
            replay_projections(codegen)
        dynamic_codegen._inertia_tail_validation_snapshot = current_codegen_tail_snapshot
        dynamic_project._inertia_last_tail_validation_snapshot = current_project_tail_snapshot
        return False

    logging.getLogger(__name__).warning(
        "Rolled back CLI AST mutations after final semantic drift at function=%#x",
        function_addr,
    )
    dynamic_codegen._inertia_codegen_decl_refresh_required_8616 = True
    dynamic_codegen._inertia_force_codegen_regeneration_8616 = True
    return True


__all__ = [
    "FinalSemanticReport8616",
    "TrustedCoreSnapshot8616",
    "rollback_final_semantic_drift_8616",
    "snapshot_trusted_cfunc_8616",
]
