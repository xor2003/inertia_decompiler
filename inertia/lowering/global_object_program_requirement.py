# cython: language_level=3, infer_types=True
"""Decide whether one direct run needs project-wide global object evidence.

Layer: Types/Lowering.
Responsibility: join local Alias access roles with binary-proven outgoing
pointer call sources and publish a typed requirement for the complete Alias and
Widening program catalog. CLI may sequence this decision but must not recreate
its semantic classification.
Consumes alias, widening, and typed facts. Does not mutate codegen.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum

from inertia.alias.indexed_address_access_contracts import IndexedAliasAccessRole8616
from inertia.alias.indexed_address_program import IndexedAliasProgramEvidence8616
from inertia.lowering.analysis_helpers import CallTargetKind8616, collect_neighbor_call_targets
from inertia.semantics.callsite_summary import (
    CallsiteSummary8616,
    build_callsite_summary_inventory_8616,
)

from .callee_global_object_evidence import (
    CalleePointerSourceKind8616,
    classify_callee_pointer_source_8616,
    logical_pointer_argument_sources_8616,
)
from .callee_pointer_evidence import (
    recover_callee_pointer_argument_evidence_at_address_8616,
)
import dataclasses
import operator
import builtins


class GlobalObjectProgramRequirementVerdict8616(StrEnum):
    """Typed outcome of the whole-program object-context decision."""

    NOT_REQUIRED = "not_required"
    REQUIRED = "required"
    UNKNOWN_REFUSE = "unknown_refuse"


class GlobalObjectProgramRequirementReason8616(StrEnum):
    """Proven reason a direct function needs project-wide object evidence."""

    LOCAL_GLOBAL_INDEXED_ACCESS = "local_global_indexed_access"
    LOCAL_POINTER_ARGUMENT = "local_pointer_argument"
    CALLEE_GLOBAL_POINTER_SOURCE = "callee_global_pointer_source"


@dataclasses.dataclass(frozen=True, )
class GlobalObjectProgramRequirementEvidence8616:
    """Closed evidence loop for one whole-program object-context decision."""

    verdict: GlobalObjectProgramRequirementVerdict8616
    reasons: object
    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong
    local_fact_count: cython.longlong
    global_pointer_source_count: cython.longlong
    stack_pointer_source_count: cython.longlong
    pointer_target_addrs: object
    callsite_addrs: object

    @property
    def closed(self) -> cython.bint:
        """Return whether every input fact became a decision or refusal."""
        counts = (
            self.raw_fact_count,
            self.normalized_fact_count,
            self.classified_fact_count,
            self.materialized_count,
            self.failure_count,
        )
        return bool(
            all(count >= 0 for count in iter(counts))
            and operator.eq(self.raw_fact_count, self.classified_fact_count + self.failure_count)
            and self.raw_fact_count >= self.normalized_fact_count
            >= self.classified_fact_count
            == self.materialized_count
            and operator.eq(self.local_fact_count + self.global_pointer_source_count
            + self.stack_pointer_source_count, self.classified_fact_count)
            and operator.eq((self.verdict is GlobalObjectProgramRequirementVerdict8616.REQUIRED), bool(self.reasons))
        )

    @property
    def requires_program(self) -> cython.bint:
        """Return whether proven facts require the complete program catalog."""
        return self.verdict is GlobalObjectProgramRequirementVerdict8616.REQUIRED


GLOBAL_OBJECT_PROGRAM_CALL_TARGET_KINDS_8616: frozenset[CallTargetKind8616] = frozenset(
    {
        CallTargetKind8616.CFG_RESOLVED_CALL,
        CallTargetKind8616.DIRECT_NEAR_CALL,
        CallTargetKind8616.DIRECT_FAR_CALL,
        CallTargetKind8616.STORED_NEAR_CALL,
    }
)


@cython.dataclasses.dataclass()
class _RequirementCensus8616:
    """Mutable census state for one catalog-requirement decision."""

    reasons: object = field(default_factory=set)
    local_fact_count: cython.longlong = 0
    global_source_count: cython.longlong = 0
    stack_source_count: cython.longlong = 0
    raw_count: cython.longlong = 0
    normalized_count: cython.longlong = 0
    classified_count: cython.longlong = 0
    pointer_targets: object = field(default_factory=set)
    relevant_callsites: object = field(default_factory=set)

    @cython.ccall
    def scan_local_program(
        self,
        local_program: IndexedAliasProgramEvidence8616,
    ) -> None:
        """Count local facts that alone require the catalog."""
        reason: object
        fact: object
        function_evidence: object
        for function_evidence in local_program.functions:
            # Access classification already projects upstream address refusals
            # exactly once. Retain that census here without double-counting
            # the same failure in address, copy, or range projections.
            self.raw_count += len(function_evidence.accesses.refusals)
            for fact in function_evidence.accesses.facts:
                reason = None
                if fact.role is IndexedAliasAccessRole8616.GLOBAL_INDEXED:
                    reason = GlobalObjectProgramRequirementReason8616.LOCAL_GLOBAL_INDEXED_ACCESS
                elif fact.is_pointer_argument:
                    reason = GlobalObjectProgramRequirementReason8616.LOCAL_POINTER_ARGUMENT
                if reason is None:
                    continue
                self.reasons.add(reason)
                self.local_fact_count += 1
                self.raw_count += 1
                self.normalized_count += 1
                self.classified_count += 1
        # An unavailable selected function is retained failure evidence: it
        # enters the raw census but can never be normalized or classified, so
        # it must surface through failure_count instead of reading as "no
        # facts, nothing required".
        self.raw_count += len(local_program.refusals)

    @cython.ccall
    def scan_callsites(
        self,
        summaries: Sequence[CallsiteSummary8616],
        pointer_argument_indices_by_target: Mapping[cython.longlong, tuple[cython.longlong, ...]],
    ) -> None:
        """Classify outgoing pointer-argument sources by provenance."""
        pointer_indices: object
        projected: object
        source: object
        _argument_index: object
        summary: object
        for summary in summaries:
            target_addr = summary.target_addr
            if not isinstance(target_addr, int):
                continue
            pointer_indices = pointer_argument_indices_by_target.get(target_addr, ())
            if not pointer_indices:
                continue
            self.pointer_targets.add(target_addr)
            self.relevant_callsites.add(summary.callsite_addr)
            self.raw_count += len(pointer_indices)
            projected = logical_pointer_argument_sources_8616(
                summary,
                pointer_indices,
            )
            if projected is None:
                continue
            for _argument_index, source in projected:
                if source is not None:
                    self.normalized_count += 1
                source_kind = classify_callee_pointer_source_8616(source)
                if source_kind is CalleePointerSourceKind8616.UNKNOWN:
                    continue
                self.classified_count += 1
                if source_kind is CalleePointerSourceKind8616.GLOBAL_OBJECT:
                    self.global_source_count += 1
                    self.reasons.add(
                        GlobalObjectProgramRequirementReason8616.CALLEE_GLOBAL_POINTER_SOURCE
                    )
                else:
                    self.stack_source_count += 1


def recover_global_object_program_requirement_8616(
    local_program: IndexedAliasProgramEvidence8616,
    summaries: Sequence[CallsiteSummary8616],
    pointer_argument_indices_by_target: Mapping[cython.longlong, tuple[cython.longlong, ...]],
) -> GlobalObjectProgramRequirementEvidence8616:
    """Join local and outgoing-call facts into one typed catalog decision."""
    if not local_program.closed:
        raise ValueError("local indexed Alias program must be closed")
    census = _RequirementCensus8616()
    census.scan_local_program(local_program)
    census.scan_callsites(summaries, pointer_argument_indices_by_target)
    reasons = census.reasons
    local_fact_count = census.local_fact_count
    global_source_count = census.global_source_count
    stack_source_count = census.stack_source_count
    raw_count = census.raw_count
    normalized_count = census.normalized_count
    classified_count = census.classified_count
    pointer_targets = census.pointer_targets
    relevant_callsites = census.relevant_callsites

    failure_count = raw_count - classified_count
    if reasons:
        verdict = GlobalObjectProgramRequirementVerdict8616.REQUIRED
    elif failure_count:
        verdict = GlobalObjectProgramRequirementVerdict8616.UNKNOWN_REFUSE
    else:
        verdict = GlobalObjectProgramRequirementVerdict8616.NOT_REQUIRED
    evidence = GlobalObjectProgramRequirementEvidence8616(
        verdict=verdict,
        reasons=tuple(sorted(reasons, key=lambda reason: reason.value)),
        raw_fact_count=raw_count,
        normalized_fact_count=normalized_count,
        classified_fact_count=classified_count,
        materialized_count=classified_count,
        failure_count=failure_count,
        local_fact_count=local_fact_count,
        global_pointer_source_count=global_source_count,
        stack_pointer_source_count=stack_source_count,
        pointer_target_addrs=tuple(sorted(pointer_targets)),
        callsite_addrs=tuple(sorted(relevant_callsites)),
    )
    if not evidence.closed:
        raise ValueError("global object program requirement accounting did not close")
    return evidence


def collect_global_object_program_requirement_8616(
    evidence_project: object,
    function: object,
    local_program: IndexedAliasProgramEvidence8616,
) -> GlobalObjectProgramRequirementEvidence8616:
    """Collect exact callsite and callee facts before deciding catalog need."""
    target_addr: object
    call_targets = tuple(
        target
        for target in builtins.iter(collect_neighbor_call_targets(function))
        if target.kind in GLOBAL_OBJECT_PROGRAM_CALL_TARGET_KINDS_8616
    )
    summaries = tuple(
        build_callsite_summary_inventory_8616(
            function,
            (target.callsite_addr for target in iter(call_targets)),
        ).values()
    )
    pointer_indices_by_target: dict[cython.longlong, tuple[cython.longlong, ...]] = {}
    for target_addr in sorted(
        {
            summary.target_addr
            for summary in iter(summaries)
            if isinstance(summary.target_addr, int)
        }
    ):
        evidence = recover_callee_pointer_argument_evidence_at_address_8616(
            evidence_project,
            target_addr,
        )
        if evidence.closes_classification:
            pointer_indices_by_target[target_addr] = evidence.pointer_argument_indices
    return recover_global_object_program_requirement_8616(
        local_program,
        summaries,
        pointer_indices_by_target,
    )


__all__ = [
    "GLOBAL_OBJECT_PROGRAM_CALL_TARGET_KINDS_8616",
    "GlobalObjectProgramRequirementEvidence8616",
    "GlobalObjectProgramRequirementReason8616",
    "GlobalObjectProgramRequirementVerdict8616",
    "collect_global_object_program_requirement_8616",
    "recover_global_object_program_requirement_8616",
]
