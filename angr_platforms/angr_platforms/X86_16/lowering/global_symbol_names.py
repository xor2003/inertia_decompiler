"""Synchronize names for exact segmented-global storage identities.

Layer: Types/Lowering.
Responsibility: apply one proven symbol identity to every structured-C view of
the same DS offset and width and remove stale local-declaration cache entries
after global lowering materializes that identity.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

This module does not infer storage, types, aliases, or values. It consumes exact
storage facts to synchronize names and declaration caches, and it never
inspects rendered C, assembly text, or source text.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_variable import SimMemoryVariable, SimStackVariable, SimVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..pipeline.errors import PipelineHardError

__all__ = [
    "DSGlobalLocalDeclarationStats8616",
    "DSGlobalSymbolNameFact8616",
    "reconcile_ds_global_local_declarations_8616",
    "synchronize_ds_global_symbol_names_8616",
]


@dataclass(frozen=True, slots=True)
class DSGlobalSymbolNameFact8616:
    """One exact DS storage identity with a proven C symbol name."""

    offset: int
    width: int
    name: str

    def __post_init__(self) -> None:
        """Reject malformed owned name facts before AST mutation."""
        if not 0 <= self.offset <= 0xFFFF:
            raise ValueError("DS global symbol offset must fit 16 bits")
        if self.width <= 0:
            raise ValueError("DS global symbol width must be positive")
        if not self.name:
            raise ValueError("DS global symbol name must be nonempty")


@dataclass(frozen=True, slots=True)
class DSGlobalLocalDeclarationStats8616:
    """Closed counters for exact global/local declaration reconciliation."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


class _CFunctionBoundary8616(Protocol):
    """Third-party structured function fields used by name synchronization."""

    statements: object
    unified_local_vars: object
    variables_in_use: object


class _CodegenBoundary8616(Protocol):
    """Third-party codegen field used by name synchronization."""

    cfunc: _CFunctionBoundary8616 | None
    _inertia_ds_global_local_declaration_stats_8616: DSGlobalLocalDeclarationStats8616


def _names_by_storage_8616(
    facts: Iterable[DSGlobalSymbolNameFact8616],
) -> tuple[dict[tuple[int, int], str], int]:
    """Normalize exact DS facts and reject conflicting names."""
    fact_tuple = tuple(facts)
    names_by_storage: dict[tuple[int, int], str] = {}
    for fact in fact_tuple:
        if not isinstance(fact, DSGlobalSymbolNameFact8616):
            raise TypeError("facts must contain DSGlobalSymbolNameFact8616")
        key = (fact.offset, fact.width)
        previous = names_by_storage.setdefault(key, fact.name)
        if previous != fact.name:
            raise ValueError(
                "conflicting names for exact DS global storage identity "
                f"0x{fact.offset:04x}:{fact.width}"
            )
    return names_by_storage, len(fact_tuple)


def _nonstack_memory_storage_key_8616(variable: object) -> tuple[int, int] | None:
    """Return one concrete non-stack memory identity from angr metadata."""
    if not isinstance(variable, SimMemoryVariable) or isinstance(variable, SimStackVariable):
        return None
    if not isinstance(variable.addr, int) or not isinstance(variable.size, int):
        return None
    return variable.addr & 0xFFFF, variable.size


def _rename_memory_variable_8616(
    variable: object,
    names_by_storage: Mapping[tuple[int, int], str],
) -> bool:
    """Rename one exact third-party memory-variable view when proven."""
    if not isinstance(variable, SimMemoryVariable):
        return False
    if not isinstance(variable.addr, int) or not isinstance(variable.size, int):
        return False
    preferred_name = names_by_storage.get(
        (variable.addr & 0xFFFF, variable.size)
    )
    if preferred_name is None or variable.name == preferred_name:
        return False
    variable.name = preferred_name
    return True


def _rename_variable_pair_8616(
    variable: object,
    unified: object,
    names_by_storage: Mapping[tuple[int, int], str],
) -> bool:
    """Rename one variable and its unified view to the proven DS name."""
    changed = _rename_memory_variable_8616(variable, names_by_storage)
    if isinstance(unified, SimVariable) and _rename_memory_variable_8616(
        unified, names_by_storage
    ):
        changed = True
    return changed


def synchronize_ds_global_symbol_names_8616(
    codegen: object,
    facts: Iterable[DSGlobalSymbolNameFact8616],
) -> bool:
    """Give all exact C-variable views of each proven DS object one name."""
    names_by_storage, _raw_fact_count = _names_by_storage_8616(facts)
    if not names_by_storage:
        return False

    carrier = cast(_CodegenBoundary8616, codegen)
    try:
        cfunc = carrier.cfunc
    except AttributeError:
        return False
    if cfunc is None:
        return False

    changed = False
    for node in _iter_c_nodes_deep_8616(cfunc.statements):
        if not isinstance(node, CVariable):
            continue
        if _rename_variable_pair_8616(node.variable, node.unified_variable, names_by_storage):
            changed = True

    if _rename_variables_in_use_8616(cfunc.variables_in_use, names_by_storage):
        changed = True
    return changed


def _rename_variables_in_use_8616(
    variables_in_use: object,
    names_by_storage: Mapping[tuple[int, int], str],
) -> bool:
    """Rename every in-use variable and C-view to the proven DS name."""
    if not isinstance(variables_in_use, Mapping):
        return False
    changed = False
    for variable, cvariable in variables_in_use.items():
        if _rename_memory_variable_8616(variable, names_by_storage):
            changed = True
        if _rename_variable_view_8616(cvariable, names_by_storage):
            changed = True
    return changed


def _rename_variable_view_8616(
    cvariable: object,
    names_by_storage: Mapping[tuple[int, int], str],
) -> bool:
    """Rename one C-variable view and its unified payload to the DS name."""
    if not isinstance(cvariable, CVariable):
        return False
    return _rename_variable_pair_8616(
        cvariable.variable, cvariable.unified_variable, names_by_storage
    )


def _drop_stale_unified_locals_8616(
    unified_local_vars: object,
    names_by_storage: Mapping[tuple[int, int], str],
) -> tuple[int, int]:
    """Drop unified-local entries whose storage key is a proven DS global."""
    if not isinstance(unified_local_vars, Mapping):
        return 0, 0
    stale_local_variables = tuple(
        variable
        for variable in unified_local_vars
        if _nonstack_memory_storage_key_8616(variable) in names_by_storage
    )
    materialized_count = 0
    if isinstance(unified_local_vars, dict):
        for variable in stale_local_variables:
            del unified_local_vars[variable]
            materialized_count += 1
    return len(stale_local_variables), materialized_count


def _drop_stale_variables_in_use_8616(
    variables_in_use: object,
    referenced_variable_ids: set[int],
    names_by_storage: Mapping[tuple[int, int], str],
) -> tuple[int, int]:
    """Drop in-use carriers that only shadow a proven DS global view."""
    if not isinstance(variables_in_use, Mapping):
        return 0, 0
    stale_carriers = tuple(
        variable
        for variable, cvariable in variables_in_use.items()
        if id(variable) not in referenced_variable_ids
        and _nonstack_memory_storage_key_8616(variable) is None
        and isinstance(cvariable, CVariable)
        and (
            _nonstack_memory_storage_key_8616(cvariable.variable) in names_by_storage
            or _nonstack_memory_storage_key_8616(cvariable.unified_variable) in names_by_storage
        )
    )
    materialized_count = 0
    if isinstance(variables_in_use, dict):
        for variable in stale_carriers:
            del variables_in_use[variable]
            materialized_count += 1
    return len(stale_carriers), materialized_count


def reconcile_ds_global_local_declarations_8616(
    codegen: object,
    facts: Iterable[DSGlobalSymbolNameFact8616],
) -> bool:
    """Remove local declaration metadata for exact proven DS globals.

    angr may unify a transient register carrier with a non-stack memory
    variable after ``CFunction.refresh()`` has cached local declarations. The
    body is already lowered to the global, but the stale cache then shadows its
    external declaration. This reconciliation consumes the same exact
    offset/width facts as global materialization and never classifies by name.
    """
    names_by_storage, raw_fact_count = _names_by_storage_8616(facts)
    carrier = cast(_CodegenBoundary8616, codegen)
    try:
        cfunc = carrier.cfunc
    except AttributeError:
        cfunc = None
    if cfunc is None or not names_by_storage:
        carrier._inertia_ds_global_local_declaration_stats_8616 = (
            DSGlobalLocalDeclarationStats8616(
                raw_fact_count=raw_fact_count,
                normalized_fact_count=len(names_by_storage),
            )
        )
        return False

    referenced_variable_ids = {
        id(node.variable)
        for node in _iter_c_nodes_deep_8616(cfunc.statements)
        if isinstance(node, CVariable)
    }

    try:
        unified_local_vars = cfunc.unified_local_vars
    except AttributeError:
        # Dynamic boundary: synthetic/older angr CFunction surfaces may not
        # cache unified local declarations.
        unified_local_vars = {}
    classified_count, materialized_count = _drop_stale_unified_locals_8616(
        unified_local_vars, names_by_storage
    )

    try:
        variables_in_use = cfunc.variables_in_use
    except AttributeError:
        # Dynamic boundary: a declaration-only fixture may omit variable-use
        # indexing entirely.
        variables_in_use = {}
    carrier_classified, carrier_removed = _drop_stale_variables_in_use_8616(
        variables_in_use, referenced_variable_ids, names_by_storage
    )
    classified_count += carrier_classified
    materialized_count += carrier_removed

    failure_count = classified_count - materialized_count
    carrier._inertia_ds_global_local_declaration_stats_8616 = (
        DSGlobalLocalDeclarationStats8616(
            raw_fact_count=raw_fact_count,
            normalized_fact_count=len(names_by_storage),
            classified_fact_count=classified_count,
            materialized_count=materialized_count,
            failure_count=failure_count,
        )
    )
    if classified_count > 0 and materialized_count == 0:
        raise PipelineHardError(
            "classified stale DS-global local declarations were not reconciled"
        )
    return materialized_count > 0
