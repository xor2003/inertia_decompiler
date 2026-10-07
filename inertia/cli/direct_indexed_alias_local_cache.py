"""Connect direct local Alias input construction to persisted raw IR/SSA.

Layer: CLI/fallback/reporting orchestration.
Responsibility: hydrate exact function IR/SSA before the owning Alias builder
runs, then persist any newly built pair without classifying semantic facts.
"""

from __future__ import annotations

from inertia.alias.indexed_address_program import (
    IndexedAliasFunctionRefusal8616,
    IndexedAliasProgramEvidence8616,
    IndexedAliasProgramFailureKind8616,
    assemble_indexed_alias_program_evidence_8616,
    build_indexed_alias_program_evidence_8616,
)
from inertia.ir.direct_evidence_deadline import (
    direct_evidence_deadline_expired_8616,
    direct_evidence_deadline_scope_8616,
)

from . import indexed_alias_program_parallel as _alias_program_parallel
from .function_ir_ssa_cache import (
    hydrate_function_ir_ssa_catalog_8616,
    store_function_ir_ssa_catalog_8616,
)


def _deadline_refusal_program_8616(
    function: object,
) -> IndexedAliasProgramEvidence8616:
    """Return closed Alias accounting with an explicit deadline refusal."""
    selection = _alias_program_parallel.indexed_alias_function_selection_8616(
        function
    )
    refusal = IndexedAliasFunctionRefusal8616(
        selection.function_addr,
        IndexedAliasProgramFailureKind8616.IR_BUILD_FAILED,
        "direct-evidence deadline expired before local Alias evidence completed",
    )
    return assemble_indexed_alias_program_evidence_8616(
        (refusal,),
        (selection.function_addr,),
    )


def build_cached_direct_indexed_alias_local_evidence_8616(
    project: object,
    function: object,
    *,
    deadline: float | None = None,
) -> IndexedAliasProgramEvidence8616:
    """Build local Alias evidence under an optional absolute request deadline."""
    with direct_evidence_deadline_scope_8616(project, deadline):
        if direct_evidence_deadline_expired_8616(project):
            return _deadline_refusal_program_8616(function)
        functions = (function,)
        hydrated = hydrate_function_ir_ssa_catalog_8616(project, functions)
        if not hydrated.stats.closed:
            raise RuntimeError("direct function IR/SSA cache hydration accounting is not closed")
        if direct_evidence_deadline_expired_8616(project):
            return _deadline_refusal_program_8616(function)
        selection = _alias_program_parallel.indexed_alias_function_selection_8616(
            function
        )
        local_program = build_indexed_alias_program_evidence_8616(
            project,
            (selection,),
        )
        if direct_evidence_deadline_expired_8616(project):
            return _deadline_refusal_program_8616(function)
        stored = store_function_ir_ssa_catalog_8616(
            project,
            functions,
            already_hydrated=hydrated,
        )
        if not stored.stats.closed:
            raise RuntimeError("direct function IR/SSA cache store accounting is not closed")
        return local_program


__all__ = ["build_cached_direct_indexed_alias_local_evidence_8616"]

