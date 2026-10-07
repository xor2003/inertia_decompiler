"""Layer: Widening compatibility.

Responsibility: preserve flat widening_model callers while delegating proof to widening.stack_widening.
Forbidden: alias ownership, text-backed storage joins, or rewrite-stage widening repairs.

Package ownership contract (canonical inertia/widening package):
Consumes alias-proven storage identity.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations

from inertia.alias.state import AliasState
from inertia.widening.stack_widening import (
    WIDENING_PIPELINE,
    RegisterWideningCandidate,
    StorageJoinAnalysis,
    WideningCandidate,
    WideningPipelineSpec,
    WideningProof,
    _StorageDomainSignature,
    can_join_adjacent_register_slices,
    collect_widening_candidates,
    describe_widening_candidates,
    describe_x86_16_widening_pipeline,
)
from inertia.widening.stack_widening import (
    _register_version_for_expr as _canonical_register_version_for_expr,
)
from inertia.widening.stack_widening import (
    prove_adjacent_storage_slices as _prove_adjacent_storage_slices,
)

_register_version_for_expr = _canonical_register_version_for_expr


def prove_adjacent_storage_slices(
    low_expr: object,
    high_expr: object,
    *,
    alias_state: AliasState | None = None,
) -> WideningProof:
    """Prove adjacent storage slices through the canonical widening layer."""
    return _prove_adjacent_storage_slices(
        low_expr,
        high_expr,
        alias_state=alias_state,
        register_version_for_expr=_register_version_for_expr,
    )


def analyze_adjacent_storage_slices(
    low_expr: object,
    high_expr: object,
    *,
    alias_state: AliasState | None = None,
) -> StorageJoinAnalysis:
    """Return compatibility analysis for adjacent storage slices."""
    return StorageJoinAnalysis(
        prove_adjacent_storage_slices(low_expr, high_expr, alias_state=alias_state)
    )


def can_join_adjacent_storage_slices(
    low_expr: object,
    high_expr: object,
    *,
    alias_state: AliasState | None = None,
) -> bool:
    """Return whether adjacent storage slices are proven safe to join."""

    def _impl() -> bool:
        proof = prove_adjacent_storage_slices(low_expr, high_expr, alias_state=alias_state)
        if not proof.ok:
            return False
        try:
            low_candidate = RegisterWideningCandidate.from_expr(low_expr)
            high_candidate = RegisterWideningCandidate.from_expr(high_expr)
        except ValueError:
            low_candidate = None
            high_candidate = None
        if low_candidate is not None and high_candidate is not None:
            if alias_state is None:
                return low_candidate.is_joinable_with(high_candidate)
            return can_join_adjacent_register_slices(
                low_expr,
                high_expr,
                alias_state=alias_state,
                proof=proof,
            )
        try:
            low_generic = WideningCandidate.from_expr(low_expr)
            high_generic = WideningCandidate.from_expr(high_expr)
        except ValueError:
            return False
        if low_generic.domain.is_unknown() or high_generic.domain.is_unknown():
            return False
        if low_generic.domain.is_mixed() or high_generic.domain.is_mixed():
            return False
        return low_generic.is_joinable_with(high_generic)

    return _impl()


def merge_storage_slice_domains(
    low_expr: object,
    high_expr: object,
    *,
    alias_state: AliasState | None = None,
) -> _StorageDomainSignature:
    """Return the merged storage domain for proven adjacent slices."""
    proof = prove_adjacent_storage_slices(low_expr, high_expr, alias_state=alias_state)
    if not proof.ok or proof.merged_domain is None:
        return _StorageDomainSignature("mixed")
    return proof.merged_domain


__all__ = (
    "WIDENING_PIPELINE",
    "RegisterWideningCandidate",
    "StorageJoinAnalysis",
    "WideningCandidate",
    "WideningPipelineSpec",
    "WideningProof",
    "_register_version_for_expr",
    "analyze_adjacent_storage_slices",
    "can_join_adjacent_storage_slices",
    "collect_widening_candidates",
    "describe_widening_candidates",
    "describe_x86_16_widening_pipeline",
    "merge_storage_slice_domains",
    "prove_adjacent_storage_slices",
)
