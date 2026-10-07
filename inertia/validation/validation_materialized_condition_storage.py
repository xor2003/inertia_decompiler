"""Validate storage identity for conditions materialized by Structuring.

Layer: Tail Validation.
Responsibility: capture the typed stack-storage surface of CFG-owned conditions
before and after Rewrite so a late pass cannot silently redirect a condition.

This module compares condition origin keys and ``SimStackVariable`` coordinates.
Names and rendered C are intentionally excluded: they are presentation details,
not evidence of storage identity. It does not recover or repair conditions.

Package ownership contract (canonical inertia/validation package):
Layer: Validation.
Owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CDoWhileLoop,
    CForLoop,
    CIfBreak,
    CIfElse,
    CVariable,
    CWhileLoop,
)
from angr.sim_variable import SimStackVariable

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.structuring.condition_materialization import condition_key_from_tags_8616


class _CodegenBoundary8616(Protocol):
    """Describe the third-party angr codegen field used by this validator."""

    cfunc: object


class _CFunctionBoundary8616(Protocol):
    """Describe variant root fields exposed by angr structured C functions."""

    body: object
    statements: object
    stmt: object


class _ValidationFailureBoundary8616(Protocol):
    """Describe validation-failure metadata attached to angr codegen."""

    _inertia_postprocess_validation_failed: bool
    _inertia_postprocess_validation_failure_pass: str
    _inertia_postprocess_validation_failure_error: str


@dataclass(frozen=True, order=True)
class ConditionStackStorageView8616:
    """Identify one stack variable without relying on its display name."""

    base: str
    offset: int
    size: int


@dataclass(frozen=True, order=True)
class MaterializedConditionStorageEntry8616:
    """Bind one Structuring condition origin to its stack-storage views."""

    key: tuple[int, int]
    stack_views: tuple[ConditionStackStorageView8616, ...]


@dataclass(frozen=True)
class MaterializedConditionStorageSurface8616:
    """Hold the deterministic storage surface for all owned conditions."""

    entries: tuple[MaterializedConditionStorageEntry8616, ...]

    @property
    def has_materialized_conditions(self) -> bool:
        """Return whether at least one keyed Structuring condition was found."""
        return bool(self.entries)


class MaterializedConditionStorageIntegrityStatus8616(Enum):
    """Classify whether Rewrite preserved an observed condition surface."""

    UNOBSERVED = "unobserved"
    STABLE = "stable"
    DRIFTED = "drifted"


@dataclass(frozen=True)
class MaterializedConditionStorageIntegrityResult8616:
    """Describe a before/after condition-storage integrity comparison."""

    status: MaterializedConditionStorageIntegrityStatus8616
    before: MaterializedConditionStorageSurface8616
    after: MaterializedConditionStorageSurface8616

    @property
    def drifted(self) -> bool:
        """Return whether Rewrite changed a previously observed surface."""
        return self.status is MaterializedConditionStorageIntegrityStatus8616.DRIFTED


def _codegen_root_8616(codegen: object) -> object | None:
    """Return the structured C root through the dynamic angr boundary."""
    try:
        cfunc = cast(_CodegenBoundary8616, codegen).cfunc
    except AttributeError:
        return None
    boundary = cast(_CFunctionBoundary8616, cfunc)
    for field_name in ("body", "statements", "stmt"):
        # Dynamic third-party boundary: angr variants expose different root fields.
        root = getattr(boundary, field_name, None)
        if root is not None:
            return cast(object, root)
    return cfunc


def _condition_expressions_8616(node: object) -> tuple[object, ...]:
    """Return condition expressions owned directly by one structured node."""
    if isinstance(node, CIfElse):
        # Dynamic third-party boundary: angr stores if/elif pairs in this field.
        pairs = tuple(getattr(node, "condition_and_nodes", ()) or ())
        return tuple(condition for condition, _body in pairs)
    if isinstance(node, (CIfBreak, CForLoop, CWhileLoop, CDoWhileLoop)):
        return (node.condition,) if node.condition is not None else ()
    return ()


def _is_cfg_materialized_condition_8616(condition: object) -> bool:
    """Return whether Structuring marked this condition as CFG-materialized."""
    for node in _iter_c_nodes_deep_8616(condition):
        # Dynamic third-party boundary: structured C tags are optional mappings.
        tags = getattr(node, "tags", None)
        if isinstance(tags, dict) and tags.get("inertia_structuring_condition_cfg_materialized_8616") is True:
            return True
    return False


def _stack_views_8616(condition: object) -> tuple[ConditionStackStorageView8616, ...]:
    """Collect deterministic stack coordinates used by one C condition."""
    views: set[ConditionStackStorageView8616] = set()
    for node in _iter_c_nodes_deep_8616(condition):
        if not isinstance(node, CVariable) or not isinstance(node.variable, SimStackVariable):
            continue
        variable = node.variable
        if not isinstance(variable.base, str) or not isinstance(variable.offset, int) or not isinstance(variable.size, int):
            continue
        views.add(
            ConditionStackStorageView8616(
                base=variable.base,
                offset=variable.offset,
                size=variable.size,
            )
        )
    return tuple(sorted(views))


def capture_materialized_condition_storage_surface_8616(
    codegen: object,
) -> MaterializedConditionStorageSurface8616:
    """Capture keyed stack storage for every CFG-materialized condition."""
    root = _codegen_root_8616(codegen)
    if root is None:
        return MaterializedConditionStorageSurface8616(entries=())
    entries: list[MaterializedConditionStorageEntry8616] = []
    for node in _iter_c_nodes_deep_8616(root):
        for condition in _condition_expressions_8616(node):
            if not _is_cfg_materialized_condition_8616(condition):
                continue
            key = condition_key_from_tags_8616(condition)
            if key is None:
                continue
            entries.append(
                MaterializedConditionStorageEntry8616(
                    key=key,
                    stack_views=_stack_views_8616(condition),
                )
            )
    return MaterializedConditionStorageSurface8616(entries=tuple(sorted(entries)))


def compare_materialized_condition_storage_surfaces_8616(
    before: MaterializedConditionStorageSurface8616,
    after: MaterializedConditionStorageSurface8616,
) -> MaterializedConditionStorageIntegrityResult8616:
    """Classify storage drift without treating names as semantic evidence."""
    if not before.has_materialized_conditions:
        status = MaterializedConditionStorageIntegrityStatus8616.UNOBSERVED
    elif before == after:
        status = MaterializedConditionStorageIntegrityStatus8616.STABLE
    else:
        status = MaterializedConditionStorageIntegrityStatus8616.DRIFTED
    return MaterializedConditionStorageIntegrityResult8616(
        status=status,
        before=before,
        after=after,
    )


def record_materialized_condition_storage_failure_8616(
    codegen: object,
    result: MaterializedConditionStorageIntegrityResult8616,
) -> bool:
    """Record a hard postprocess failure when a protected surface drifted."""
    if not result.drifted:
        return False
    boundary = cast(_ValidationFailureBoundary8616, codegen)
    boundary._inertia_postprocess_validation_failed = True
    boundary._inertia_postprocess_validation_failure_pass = "materialized_condition_storage_integrity"
    boundary._inertia_postprocess_validation_failure_error = (
        "Rewrite changed CFG-materialized condition stack storage: "
        f"before={result.before!r} after={result.after!r}"
    )
    return True
