"""Collect bounded indexed-address ranges from explicit typed witnesses.

Layer: IR.
Responsibility: validate a narrow typed SSA/CFG candidate boundary for
zero-based, unit-step, strict unsigned constant-bound natural loops and close
every candidate as one fact or refusal. No source text or implicit loop shape
is inspected, and missing evidence always refuses while preserving code.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from .indexed_address_range_contracts import (
    IndexedInductionSourceIdentity8616,
    IndexedLoopRangeCandidate8616,
    IndexedLoopRangeEvidence8616,
    IndexedLoopRangeFact8616,
    IndexedLoopRangeFailureKind8616,
    IndexedLoopRangeRefusal8616,
    IndexedLoopRangeStats8616,
    canonical_induction_source_identity_8616,
)


def _candidate_key_8616(candidate: IndexedLoopRangeCandidate8616) -> tuple[object, ...]:
    """Return the exact machine identity of one candidate access."""
    source = candidate.source
    return (
        source.function_addr,
        source.block_addr,
        source.instr_index,
        source.instr_addr,
        source.kind,
    )


def _failure_8616(
    candidate: IndexedLoopRangeCandidate8616,
    failure: IndexedLoopRangeFailureKind8616,
    detail: str,
) -> IndexedLoopRangeRefusal8616:
    """Create one typed refusal retaining the complete candidate input."""
    return IndexedLoopRangeRefusal8616(candidate, failure, detail)


def _validate_source_identity_8616(
    function_addr: int,
    candidate: IndexedLoopRangeCandidate8616,
) -> IndexedLoopRangeRefusal8616 | None:
    """Check the candidate source belongs to the function and is complete."""
    source = candidate.source
    if source.function_addr != function_addr:
        return _failure_8616(
            candidate,
            IndexedLoopRangeFailureKind8616.FUNCTION_MISMATCH,
            "candidate access belongs to a different function",
        )
    if not source.complete:
        return _failure_8616(
            candidate,
            IndexedLoopRangeFailureKind8616.SOURCE_FACT_INCOMPLETE,
            "indexed-address source fact is incomplete",
        )
    if candidate.generation_failure is not None:
        return _failure_8616(
            candidate,
            candidate.generation_failure,
            candidate.generation_detail or "typed candidate generation refused",
        )
    return None


def _proven_induction_identity_8616(
    candidate: IndexedLoopRangeCandidate8616,
) -> IndexedInductionSourceIdentity8616 | IndexedLoopRangeRefusal8616:
    """Return the proven canonical induction identity or a typed refusal."""
    canonical = canonical_induction_source_identity_8616(
        candidate.source.index_source
    )
    if canonical is None or candidate.induction_source is None:
        return _failure_8616(
            candidate,
            IndexedLoopRangeFailureKind8616.INDUCTION_IDENTITY_UNPROVEN,
            "canonical induction storage identity is absent",
        )
    if candidate.induction_source != canonical:
        return _failure_8616(
            candidate,
            IndexedLoopRangeFailureKind8616.INDUCTION_IDENTITY_MISMATCH,
            "candidate induction identity differs from the indexed access source",
        )
    return canonical


def _validate_induction_update_8616(
    candidate: IndexedLoopRangeCandidate8616,
) -> IndexedLoopRangeRefusal8616 | None:
    """Check the zero initializer and unit step with their write evidence."""
    if (
        candidate.init is None
        or isinstance(candidate.init, bool)
        or candidate.init_site is None
    ):
        return _failure_8616(
            candidate,
            IndexedLoopRangeFailureKind8616.INIT_UNPROVEN,
            "zero initializer or its exact site is absent",
        )
    if candidate.init != 0:
        return _failure_8616(
            candidate,
            IndexedLoopRangeFailureKind8616.INIT_NOT_ZERO,
            "loop initializer is not zero",
        )
    if candidate.init_write is None or not candidate.init_write.complete:
        return _failure_8616(
            candidate,
            IndexedLoopRangeFailureKind8616.INIT_UNPROVEN,
            "logical zero-write evidence is absent or incomplete",
        )
    if (
        candidate.step is None
        or isinstance(candidate.step, bool)
        or candidate.step_site is None
    ):
        return _failure_8616(
            candidate,
            IndexedLoopRangeFailureKind8616.STEP_UNPROVEN,
            "unit induction update or its exact site is absent",
        )
    if candidate.step != 1:
        return _failure_8616(
            candidate,
            IndexedLoopRangeFailureKind8616.STEP_NOT_UNIT,
            "loop induction update is not one",
        )
    if candidate.step_write is None or not candidate.step_write.complete:
        return _failure_8616(
            candidate,
            IndexedLoopRangeFailureKind8616.STEP_UNPROVEN,
            "logical old-word-plus-one evidence is absent or incomplete",
        )
    return None


def _validate_candidate_bound_8616(
    candidate: IndexedLoopRangeCandidate8616,
) -> IndexedLoopRangeRefusal8616 | None:
    """Check the constant upper bound lies in the induction value domain."""
    if not candidate.upper_bound_is_constant:
        return _failure_8616(
            candidate,
            IndexedLoopRangeFailureKind8616.DYNAMIC_BOUND,
            "loop upper bound is not a typed constant",
        )
    if candidate.upper_bound is None or isinstance(candidate.upper_bound, bool):
        return _failure_8616(
            candidate,
            IndexedLoopRangeFailureKind8616.BOUND_UNPROVEN,
            "constant loop upper bound is absent",
        )
    max_value = (1 << (candidate.source.index_value.size * 8)) - 1
    if not 0 < candidate.upper_bound <= max_value:
        return _failure_8616(
            candidate,
            IndexedLoopRangeFailureKind8616.BOUND_OUT_OF_RANGE,
            "constant upper bound is outside the induction value domain",
        )
    return None


def _validate_guard_loop_and_access_8616(
    candidate: IndexedLoopRangeCandidate8616,
) -> IndexedLoopRangeRefusal8616 | None:
    """Check the strict guard, natural loop, backedge, and access site."""
    guard = candidate.guard
    if guard is None or not guard.complete or candidate.guard_site is None:
        return _failure_8616(
            candidate,
            IndexedLoopRangeFailureKind8616.GUARD_UNPROVEN,
            "typed loop guard or its exact site is absent",
        )
    if not guard.proves_strict_unsigned_continue:
        return _failure_8616(
            candidate,
            IndexedLoopRangeFailureKind8616.GUARD_NOT_STRICT_UNSIGNED,
            "continued edge is not a strict unsigned upper-bound guard",
        )
    loop = candidate.natural_loop
    if loop is None or not loop.blocks or not loop.single_entry:
        return _failure_8616(
            candidate,
            IndexedLoopRangeFailureKind8616.NATURAL_LOOP_UNPROVEN,
            "single-entry natural-loop block witness is absent",
        )
    if (
        not loop.backedge_proven
        or loop.backedge_source_addr != loop.latch_block_addr
        or loop.backedge_target_addr != loop.header_block_addr
    ):
        return _failure_8616(
            candidate,
            IndexedLoopRangeFailureKind8616.BACKEDGE_UNPROVEN,
            "exact latch-to-header backedge is not proven",
        )
    if not guard.guard_dominates_access or not guard.guard_dominates_latch:
        return _failure_8616(
            candidate,
            IndexedLoopRangeFailureKind8616.DOMINANCE_UNPROVEN,
            "guard dominance over the access and latch is not proven",
        )
    return _validate_loop_access_site_8616(candidate)


def _validate_loop_access_site_8616(
    candidate: IndexedLoopRangeCandidate8616,
) -> IndexedLoopRangeRefusal8616 | None:
    """Check the access site matches the retained indexed fact inside the loop."""
    loop = candidate.natural_loop
    access_site = candidate.access_site
    if access_site is None:
        return _failure_8616(
            candidate,
            IndexedLoopRangeFailureKind8616.ACCESS_SITE_UNPROVEN,
            "exact indexed access site is absent",
        )
    source = candidate.source
    if (
        access_site.block_addr,
        access_site.instr_index,
        access_site.instr_addr,
    ) != (source.block_addr, source.instr_index, source.instr_addr):
        return _failure_8616(
            candidate,
            IndexedLoopRangeFailureKind8616.ACCESS_SITE_MISMATCH,
            "access witness does not identify the retained indexed fact",
        )
    if loop is None or access_site.block_addr not in loop.blocks:
        return _failure_8616(
            candidate,
            IndexedLoopRangeFailureKind8616.ACCESS_OUTSIDE_LOOP,
            "indexed access is outside the proven natural loop",
        )
    return None


def _validate_candidate_8616(
    function_addr: int,
    candidate: IndexedLoopRangeCandidate8616,
) -> IndexedLoopRangeFact8616 | IndexedLoopRangeRefusal8616:
    """Validate one explicit witness without deriving any missing proof."""
    source = candidate.source
    refusal = _validate_source_identity_8616(function_addr, candidate)
    if refusal is not None:
        return refusal
    canonical = _proven_induction_identity_8616(candidate)
    if isinstance(canonical, IndexedLoopRangeRefusal8616):
        return canonical
    refusal = _validate_induction_update_8616(candidate)
    if refusal is not None:
        return refusal
    refusal = _validate_candidate_bound_8616(candidate)
    if refusal is not None:
        return refusal
    refusal = _validate_guard_loop_and_access_8616(candidate)
    if refusal is not None:
        return refusal
    init = candidate.init
    init_site = candidate.init_site
    init_write = candidate.init_write
    step = candidate.step
    step_site = candidate.step_site
    step_write = candidate.step_write
    upper_bound = candidate.upper_bound
    guard_site = candidate.guard_site
    guard = candidate.guard
    access_site = candidate.access_site
    loop = candidate.natural_loop
    assert init is not None and init_site is not None and init_write is not None
    assert step is not None and step_site is not None and step_write is not None
    assert upper_bound is not None and guard_site is not None and guard is not None
    assert access_site is not None and loop is not None
    fact = IndexedLoopRangeFact8616(
        source,
        canonical,
        init,
        step,
        upper_bound,
        init_site,
        step_site,
        guard_site,
        access_site,
        loop,
        guard,
        init_write,
        step_write,
    )
    if not fact.complete:
        return _failure_8616(
            candidate,
            IndexedLoopRangeFailureKind8616.PROOF_SITE_CONFLICT,
            "typed proof sites, loop topology, and guard witness conflict",
        )
    return fact


def collect_indexed_loop_range_evidence_8616(
    function_addr: int,
    candidates: Iterable[IndexedLoopRangeCandidate8616],
) -> IndexedLoopRangeEvidence8616:
    """Close explicit typed candidates without consulting rendered or backend text."""
    ordered = tuple(
        sorted(
            candidates,
            key=lambda candidate: (
                candidate.source.block_addr,
                candidate.source.instr_index,
                candidate.source.instr_addr,
                candidate.source.kind.value,
            ),
        )
    )
    duplicate_keys = {
        key
        for key, count in Counter(_candidate_key_8616(item) for item in ordered).items()
        if count > 1
    }
    facts: list[IndexedLoopRangeFact8616] = []
    refusals: list[IndexedLoopRangeRefusal8616] = []
    for candidate in ordered:
        if _candidate_key_8616(candidate) in duplicate_keys:
            refusals.append(
                _failure_8616(
                    candidate,
                    IndexedLoopRangeFailureKind8616.DUPLICATE_ACCESS,
                    "multiple loop-range candidates own the same indexed access",
                )
            )
            continue
        outcome = _validate_candidate_8616(function_addr, candidate)
        if isinstance(outcome, IndexedLoopRangeRefusal8616):
            refusals.append(outcome)
        else:
            facts.append(outcome)
    raw_count = len(ordered)
    result = IndexedLoopRangeEvidence8616(
        function_addr,
        tuple(facts),
        tuple(refusals),
        IndexedLoopRangeStats8616(
            raw_fact_count=raw_count,
            normalized_fact_count=raw_count,
            classified_fact_count=raw_count,
            materialized_count=len(facts),
            failure_count=len(refusals),
        ),
    )
    if not result.closed:
        raise ValueError("indexed loop-range IR accounting did not close")
    return result


__all__ = ["collect_indexed_loop_range_evidence_8616"]
