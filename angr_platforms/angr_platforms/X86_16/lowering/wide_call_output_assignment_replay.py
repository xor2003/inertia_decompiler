"""Reconcile regenerated carriers for proven wide call-output assignments.

Layer: Types/Lowering.
Responsibility: enforce one structured evaluation for one immutable wide
call-output fact after angr regenerates C-AST carrier statements.
Consumes alias, widening, and typed facts through exact Lowering facts and
instruction-tagged AST ownership only.
Do not recover semantics from COD, source, assembly, or rendered C text.
Do not infer semantics from symbols, source names, or untagged shape.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CFunctionCall,
    CStatements,
)

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..callsite_summary import CallsiteSummary8616
from ..ir import IRCallOutputProvenance8616, IRCallOutputShape8616
from ..semantics.carry_borrow_contracts import CarryBorrowKind8616
from .wide_call_output_assignment_ast import (
    WideCallOutputCallSite8616,
    _call_target_variants_8616,
    c_node_instruction_addrs_8616,
    callsite_tagged_calls_in_node_8616,
    callsite_tagged_statement_owners_8616,
)
from .wide_call_output_assignment_contracts import (
    WideCallOutputAssignmentArtifact8616,
    WideCallOutputAssignmentFact8616,
    WideCallOutputAssignmentVerdict8616,
)

_EVIDENCE_TAG_8616 = "inertia_x86_16_wide_call_output_assignment"
_LOGGER = logging.getLogger(__name__)


class WideCallOutputReplayStatus8616(StrEnum):
    """Typed status for an already-materialized fact's regenerated surface."""

    ABSENT = "absent"
    STABLE = "stable"
    PRUNED = "pruned"
    REFUSED = "refused"


class WideCallOutputReplayFailure8616(StrEnum):
    """Stable reason an already-materialized replay surface was refused."""

    CANONICAL_ASSIGNMENT_AMBIGUOUS = "canonical_assignment_ambiguous"
    CANONICAL_CALL_AMBIGUOUS = "canonical_call_ambiguous"
    DUPLICATE_EFFECT_AMBIGUOUS = "duplicate_effect_ambiguous"
    DUPLICATE_PROVENANCE_MIXED = "duplicate_provenance_mixed"
    SUMMARY_MISSING = "summary_missing"
    TARGET_CONFLICT = "target_conflict"
    UNOWNED_CALL_OCCURRENCE = "unowned_call_occurrence"


class WideCallOutputAuthoritativeOwnershipStatus8616(StrEnum):
    """Whether the dedicated wide-call pass owns one legacy stack projection."""

    NOT_PUBLISHED = "not_published"
    FACT_ABSENT = "fact_absent"
    MATERIALIZED = "materialized"
    REFUSED = "refused"
    AMBIGUOUS = "ambiguous"
    INVALID_ARTIFACT = "invalid_artifact"


@dataclass(frozen=True, slots=True)
class WideCallOutputReplayResult8616:
    """Result of checking one canonical assignment and any raw duplicates."""

    status: WideCallOutputReplayStatus8616
    duplicate_count: int = 0
    failure: WideCallOutputReplayFailure8616 | None = None

    @property
    def changed(self) -> bool:
        """Return whether exact regenerated duplicate statements were removed."""
        return self.status is WideCallOutputReplayStatus8616.PRUNED


@dataclass(frozen=True, slots=True)
class WideCallOutputAuthoritativeOwnership8616:
    """Typed ownership result for a duplicate direct-stack projection."""

    status: WideCallOutputAuthoritativeOwnershipStatus8616
    fact: WideCallOutputAssignmentFact8616

    @property
    def blocks_legacy_materialization(self) -> bool:
        """Return whether the dedicated owner published a conclusive outcome."""
        return self.status not in {
            WideCallOutputAuthoritativeOwnershipStatus8616.NOT_PUBLISHED,
            WideCallOutputAuthoritativeOwnershipStatus8616.FACT_ABSENT,
        }

    @property
    def materialized(self) -> bool:
        """Return whether the dedicated owner already emitted the assignment."""
        return self.status is WideCallOutputAuthoritativeOwnershipStatus8616.MATERIALIZED


class _ProjectCodegenBoundary8616(Protocol):
    """Owned callsite inventory used to prove regenerated call identity."""

    project: object
    _inertia_callsite_summary_inventory_8616: dict[int, CallsiteSummary8616]


class _WideCallOutputArtifactBoundary8616(Protocol):
    """Dynamic codegen field published by dedicated wide-call Lowering."""

    _inertia_wide_call_output_assignment_artifact_8616: WideCallOutputAssignmentArtifact8616


def classify_authoritative_wide_call_output_projection_8616(
    codegen: object,
    *,
    callsite_addr: int,
    target_addr: int,
    kind: CarryBorrowKind8616,
    source_offset: int,
    destination_offset: int,
    low_arithmetic_addr: int,
    high_arithmetic_addr: int,
    low_store_addr: int,
    high_store_addr: int,
) -> WideCallOutputAuthoritativeOwnership8616:
    """Match one legacy stack projection to its exact dedicated-owner fact."""
    expected = WideCallOutputAssignmentFact8616(
        call_output=IRCallOutputProvenance8616(
            callsite_addr=callsite_addr,
            target_addr=target_addr,
            shape=IRCallOutputShape8616.DX_AX,
        ),
        kind=kind,
        source_offset=source_offset,
        destination_offset=destination_offset,
        carrier_ins_addrs=tuple(
            sorted(
                {
                    callsite_addr,
                    low_arithmetic_addr,
                    high_arithmetic_addr,
                    low_store_addr,
                    high_store_addr,
                }
            )
        ),
        store_ins_addrs=(low_store_addr, high_store_addr),
    )
    boundary = cast(_WideCallOutputArtifactBoundary8616, codegen)
    try:
        artifact = boundary._inertia_wide_call_output_assignment_artifact_8616
    except AttributeError:
        return WideCallOutputAuthoritativeOwnership8616(
            WideCallOutputAuthoritativeOwnershipStatus8616.NOT_PUBLISHED,
            expected,
        )
    if not isinstance(artifact, WideCallOutputAssignmentArtifact8616):
        return WideCallOutputAuthoritativeOwnership8616(
            WideCallOutputAuthoritativeOwnershipStatus8616.INVALID_ARTIFACT,
            expected,
        )
    # Legacy stack facts can retain a slice target while the dedicated owner
    # publishes the original target. Every other instruction/storage fact must
    # still agree; return the authoritative fact without rewriting its identity.
    project = cast(_ProjectCodegenBoundary8616, codegen).project
    targets = _call_target_variants_8616(target_addr, project)
    matches = tuple(
        resolution for resolution in artifact.resolutions
        if resolution.fact is not None
        and resolution.fact.call_output.target_addr in targets
        and replace(resolution.fact, call_output=replace(
            resolution.fact.call_output, target_addr=expected.call_output.target_addr,
        )) == expected
    )
    if not matches:
        status = WideCallOutputAuthoritativeOwnershipStatus8616.FACT_ABSENT
    elif len(matches) != 1:
        status = WideCallOutputAuthoritativeOwnershipStatus8616.AMBIGUOUS
    elif matches[0].verdict is WideCallOutputAssignmentVerdict8616.MATERIALIZED:
        status = WideCallOutputAuthoritativeOwnershipStatus8616.MATERIALIZED
    else:
        status = WideCallOutputAuthoritativeOwnershipStatus8616.REFUSED
    matched_fact = (matches[0].fact or expected) if len(matches) == 1 else expected
    return WideCallOutputAuthoritativeOwnership8616(status, matched_fact)


def _refused_replay_8616(
    failure: WideCallOutputReplayFailure8616,
    duplicate_count: int = 0,
) -> WideCallOutputReplayResult8616:
    """Build one typed refusal and optionally emit focused diagnostics."""
    if os.environ.get("INERTIA_DEBUG_WIDE_CALL_OUTPUT_REPLAY") == "1":
        _LOGGER.warning(
            "wide call-output replay refused reason=%s duplicates=%d",
            failure.value,
            duplicate_count,
        )
    return WideCallOutputReplayResult8616(
        WideCallOutputReplayStatus8616.REFUSED,
        duplicate_count,
        failure,
    )


def _canonical_assignments_8616(
    root: object,
    fact: WideCallOutputAssignmentFact8616,
) -> tuple[CAssignment, ...]:
    """Return assignments carrying the exact immutable Lowering fact."""
    return tuple(
        node
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CAssignment)
        and isinstance(node.tags, dict)
        and node.tags.get(_EVIDENCE_TAG_8616) == fact
    )


def _delete_statement_owners_8616(
    owners: tuple[WideCallOutputCallSite8616, ...],
) -> None:
    """Delete exact duplicate statement slots in descending group order."""
    grouped: dict[int, tuple[CStatements, list[int]]] = {}
    for owner in owners:
        entry = grouped.setdefault(id(owner.statements), (owner.statements, []))
        entry[1].append(owner.index)
    for group, indices in grouped.values():
        for index in sorted(set(indices), reverse=True):
            del group.statements[index]


def _duplicate_summary_failure_8616(
    boundary: _ProjectCodegenBoundary8616,
    fact: WideCallOutputAssignmentFact8616,
    duplicate_count: int,
) -> WideCallOutputReplayFailure8616 | None:
    """Require exact published call identity before deleting duplicate effects."""
    if not duplicate_count:
        return None
    try:
        summary = boundary._inertia_callsite_summary_inventory_8616[fact.call_output.callsite_addr]
    except (AttributeError, KeyError):
        return WideCallOutputReplayFailure8616.SUMMARY_MISSING
    if summary.target_addr != fact.call_output.target_addr:
        return WideCallOutputReplayFailure8616.TARGET_CONFLICT
    return None


def reconcile_materialized_wide_call_output_assignment_8616(
    codegen: object,
    root: object,
    fact: WideCallOutputAssignmentFact8616,
) -> WideCallOutputReplayResult8616:
    """Prune only fully fact-owned duplicates of one canonical assignment."""
    canonical = _canonical_assignments_8616(root, fact)
    if not canonical:
        return WideCallOutputReplayResult8616(WideCallOutputReplayStatus8616.ABSENT)
    if len(canonical) != 1:
        return _refused_replay_8616(
            WideCallOutputReplayFailure8616.CANONICAL_ASSIGNMENT_AMBIGUOUS
        )
    boundary = cast(_ProjectCodegenBoundary8616, codegen)
    owners = callsite_tagged_statement_owners_8616(
        root,
        fact.call_output.callsite_addr,
    )
    canonical_calls = tuple(
        node
        for node in _iter_c_nodes_deep_8616(canonical[0])
        if isinstance(node, CFunctionCall)
    )
    if len(canonical_calls) != 1:
        return _refused_replay_8616(
            WideCallOutputReplayFailure8616.CANONICAL_CALL_AMBIGUOUS
        )
    canonical_call = canonical_calls[0]
    duplicates = tuple(owner for owner in owners if owner.call is not canonical_call)
    owned_call_ids = {id(owner.call) for owner in owners}
    all_tagged_call_ids = {
        id(call)
        for call in callsite_tagged_calls_in_node_8616(
            root,
            fact.call_output.callsite_addr,
        )
    }
    canonical_call_id = id(canonical_call)
    if all_tagged_call_ids - {canonical_call_id} != owned_call_ids - {
        canonical_call_id
    }:
        return _refused_replay_8616(
            WideCallOutputReplayFailure8616.UNOWNED_CALL_OCCURRENCE,
            len(duplicates),
        )
    failure = _duplicate_summary_failure_8616(boundary, fact, len(duplicates))
    if failure is not None:
        return _refused_replay_8616(failure, len(duplicates))
    required = frozenset(fact.carrier_ins_addrs)
    for owner in duplicates:
        statement_calls = tuple(
            node
            for node in _iter_c_nodes_deep_8616(owner.statement)
            if isinstance(node, CFunctionCall)
        )
        addresses = c_node_instruction_addrs_8616(owner.statement)
        if len(statement_calls) != 1:
            return _refused_replay_8616(
                WideCallOutputReplayFailure8616.DUPLICATE_EFFECT_AMBIGUOUS,
                len(duplicates),
            )
        if not addresses or not addresses <= required:
            return _refused_replay_8616(
                WideCallOutputReplayFailure8616.DUPLICATE_PROVENANCE_MIXED,
                len(duplicates),
            )
    if not duplicates:
        return WideCallOutputReplayResult8616(WideCallOutputReplayStatus8616.STABLE)
    _delete_statement_owners_8616(duplicates)
    return WideCallOutputReplayResult8616(
        WideCallOutputReplayStatus8616.PRUNED,
        len(duplicates),
    )


__all__ = (
    "WideCallOutputAuthoritativeOwnership8616",
    "WideCallOutputAuthoritativeOwnershipStatus8616",
    "WideCallOutputReplayFailure8616",
    "WideCallOutputReplayResult8616",
    "WideCallOutputReplayStatus8616",
    "classify_authoritative_wide_call_output_projection_8616",
    "reconcile_materialized_wide_call_output_assignment_8616",
)
