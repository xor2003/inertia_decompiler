"""Retain callsite-bound segment equality for contextual callee analysis.

Layer: IR.
Responsibility: bind an existing direct-call DS==SS proof to registered caller
and callee coverage. Recheck the retained evidence before supplying an entry
relation; never publish a program-wide invariant or guess callee preservation.
Owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.frontend.x86_16.frontend_direct_callsite_index import DecodedDirectCallsiteIndex8616

from .core import IRFunctionArtifact, IRValue, MemSpace, SegmentOrigin
from .direct_call_segment_entry import (
    DirectCallSegmentEntryCandidate8616,
    DirectCallSegmentEntryProof8616,
    DirectCallSegmentEntryRefusal8616,
    _call_target_evidence_8616,
    _decoded_entry_8616,
    _unique_call_8616,
    prove_x86_16_direct_call_segment_entry_8616,
)
from .ir_boundary_cfg import IRBoundaryCoverageResult8616
from .real16_invocation_domain import Real16InvocationDomain8616
from .segment_call_preservation import SegmentCallPreservationResult8616
from .segment_state_transfer import SegmentRestoreSource


class DirectCallSegmentContextFailure8616(StrEnum):
    """Why a contextual entry relation cannot be consumed."""

    COVERAGE_INCOMPLETE = "coverage_incomplete"
    PROJECT_MISMATCH = "project_mismatch"
    ENTRY_UNPROVEN = "entry_unproven"
    PARENT_UNBOUND = "parent_unbound"
    CALL_UNBOUND = "call_unbound"
    EQUALITY_LOST = "equality_lost"


@dataclass(frozen=True, slots=True)
class DirectCallSegmentContext8616:
    """One exact caller-to-callee entry relation, not a universal callee fact."""

    caller: IRBoundaryCoverageResult8616
    callee: IRBoundaryCoverageResult8616
    index: DecodedDirectCallsiteIndex8616
    restore_sources: tuple[SegmentRestoreSource, ...]
    proof: DirectCallSegmentEntryProof8616
    failure: DirectCallSegmentContextFailure8616 | None
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    invocation: Real16InvocationDomain8616 | None = None

    @property
    def candidate(self) -> DirectCallSegmentEntryCandidate8616:
        """Expose the exact call identity shared by local and inherited contexts."""
        return self.proof.candidate

    @property
    def complete(self) -> bool:
        """Re-evaluate the exact project-owned call and Alias lineage."""
        counts = (self.raw_fact_count, self.normalized_fact_count,
                  self.classified_fact_count, self.materialized_count, self.failure_count)
        if self.failure is not None or counts != (1, 1, 1, 1, 0):
            return False
        if any(type(count) is not int for count in counts):
            return False
        failure, proof = _context_evidence_8616(
            self.caller, self.callee, self.index, self.restore_sources, self.proof.candidate,
            invocation=self.invocation,
        )
        return failure is None and proof == self.proof


def _context_evidence_8616(
    caller: IRBoundaryCoverageResult8616, callee: IRBoundaryCoverageResult8616,
    index: DecodedDirectCallsiteIndex8616, sources: tuple[SegmentRestoreSource, ...],
    candidate: DirectCallSegmentEntryCandidate8616,
    *,
    invocation: Real16InvocationDomain8616 | None = None,
) -> tuple[DirectCallSegmentContextFailure8616 | None, DirectCallSegmentEntryProof8616]:
    """Consume complete registered boundaries before reproducing the call proof."""
    proof = prove_x86_16_direct_call_segment_entry_8616(
        candidate, caller_boundary=caller.boundary, callee_boundary=callee.boundary,
        artifact=caller.artifact, callsite_index=index, restore_sources=sources,
        invocation=invocation,
    )
    if not caller.complete or not callee.complete:
        return DirectCallSegmentContextFailure8616.COVERAGE_INCOMPLETE, proof
    if caller.boundary.project is not callee.boundary.project:
        return DirectCallSegmentContextFailure8616.PROJECT_MISMATCH, proof
    if not proof.complete:
        return DirectCallSegmentContextFailure8616.ENTRY_UNPROVEN, proof
    return None, proof


def bind_direct_call_segment_context_8616(
    caller: IRBoundaryCoverageResult8616, callee: IRBoundaryCoverageResult8616,
    index: DecodedDirectCallsiteIndex8616, sources: tuple[SegmentRestoreSource, ...],
    callsite_addr: int,
    *,
    invocation: Real16InvocationDomain8616 | None = None,
) -> DirectCallSegmentContext8616:
    """Bind one contextual DS==SS entry theorem without mutating project state.

    ``invocation`` is an optional source-bound ``Real16InvocationDomain8616``
    premise scoped to this exact callsite on this exact caller artifact; it is
    retained and replayed with the context only when the target proof
    consumes it, never widened to a callee fact.
    """
    candidate = DirectCallSegmentEntryCandidate8616(
        caller.artifact.function_addr, callsite_addr, callee.artifact.function_addr,
    )
    failure, proof = _context_evidence_8616(
        caller, callee, index, sources, candidate, invocation=invocation
    )
    accepted = int(failure is None)
    return DirectCallSegmentContext8616(
        caller, callee, index, sources, proof, failure, 1, 1, accepted, accepted,
        1 - accepted, proof.invocation,
    )


@dataclass(frozen=True, slots=True)
class PropagatedSegmentContext8616:
    """Retain a replayable contextual relation at one nested direct near CALL.

    The parent is an exact invocation context, not a universal function summary.
    Replaying raw caller effects must still prove DS==SS immediately before
    this call. No supplied segment-state map is trusted as proof.
    """

    parent: SegmentEntryContext8616
    caller: IRBoundaryCoverageResult8616
    callee: IRBoundaryCoverageResult8616
    index: DecodedDirectCallsiteIndex8616
    candidate: DirectCallSegmentEntryCandidate8616
    call_preservations: tuple[SegmentCallPreservationResult8616, ...]
    failure: DirectCallSegmentContextFailure8616 | None
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def complete(self) -> bool:
        """Recheck the parent, registered bodies, call identity and raw effects."""
        counts = (self.raw_fact_count, self.normalized_fact_count,
                  self.classified_fact_count, self.materialized_count, self.failure_count)
        if self.failure is not None or counts != (1, 1, 1, 1, 0):
            return False
        if any(type(count) is not int for count in counts):
            return False
        return _propagated_context_failure_8616(
            self.parent, self.caller, self.callee, self.index,
            self.candidate, self.call_preservations,
        ) is None


type SegmentEntryContext8616 = DirectCallSegmentContext8616 | PropagatedSegmentContext8616


def _call_has_same_instruction_segment_write_8616(
    artifact: IRFunctionArtifact, callsite_addr: int,
) -> bool:
    """Refuse segment writes hidden after the machine-instruction entry state.

    The solver's address-keyed entry map precedes the first IR effect sharing
    that address. It cannot certify equality at a later CALL operation if an
    intervening same-address effect assigns DS or SS.
    """
    return any(
        instruction.addr == callsite_addr
        and isinstance(instruction.dst, IRValue)
        and instruction.dst.space is MemSpace.REG
        and instruction.dst.name in {"ds", "ss"}
        for block in artifact.blocks for instruction in block.instrs
    )


def _propagated_context_failure_8616(
    parent: SegmentEntryContext8616,
    caller: IRBoundaryCoverageResult8616,
    callee: IRBoundaryCoverageResult8616,
    index: DecodedDirectCallsiteIndex8616,
    candidate: DirectCallSegmentEntryCandidate8616,
    call_preservations: tuple[SegmentCallPreservationResult8616, ...],
) -> DirectCallSegmentContextFailure8616 | None:
    """Replay existing segment transfer after independently binding the CALL.

    No new Alias restore sources are accepted here: this bounded theorem uses
    only inherited equality, explicit raw effects and bound call preservation.
    A local save/restore may still be proved by the existing local binder.
    """
    # Runtime import avoids the state solver's type-only context dependency.
    from .segment_state import build_x86_16_segment_state_artifact

    if not caller.complete or not callee.complete:
        return DirectCallSegmentContextFailure8616.COVERAGE_INCOMPLETE
    if caller.boundary.project is not callee.boundary.project:
        return DirectCallSegmentContextFailure8616.PROJECT_MISMATCH
    if not parent.complete or parent.callee is not caller:
        return DirectCallSegmentContextFailure8616.PARENT_UNBOUND
    if candidate.caller_start != caller.artifact.function_addr or candidate.callee_addr != callee.artifact.function_addr:
        return DirectCallSegmentContextFailure8616.CALL_UNBOUND
    call = _unique_call_8616(candidate, caller.artifact)
    decoded = _decoded_entry_8616(candidate, caller.boundary, index)
    if isinstance(call, DirectCallSegmentEntryRefusal8616) or isinstance(decoded, DirectCallSegmentEntryRefusal8616):
        return DirectCallSegmentContextFailure8616.CALL_UNBOUND
    call_block, call_index = call
    target_refusal, _ = _call_target_evidence_8616(
        candidate, call_block.instrs[call_index],
        project=caller.boundary.project, call_block=call_block, decoded_entry=decoded,
    )
    if target_refusal is not None:
        return DirectCallSegmentContextFailure8616.CALL_UNBOUND
    if _call_has_same_instruction_segment_write_8616(caller.artifact, candidate.callsite_addr):
        return DirectCallSegmentContextFailure8616.EQUALITY_LOST
    state = build_x86_16_segment_state_artifact(
        caller.artifact, entry_context=parent, call_preservations=call_preservations,
    )
    ds = state.state_before_instruction(candidate.callsite_addr, "ds")
    ss = state.state_before_instruction(candidate.callsite_addr, "ss")
    if ds is None or ss is None:
        return DirectCallSegmentContextFailure8616.EQUALITY_LOST
    proven = ds.origin is SegmentOrigin.PROVEN and ss.origin is SegmentOrigin.PROVEN
    if not proven or ds.source is None or ds.source != ss.source:
        return DirectCallSegmentContextFailure8616.EQUALITY_LOST
    return None


def bind_propagated_segment_context_8616(
    parent: SegmentEntryContext8616,
    callee: IRBoundaryCoverageResult8616,
    index: DecodedDirectCallsiteIndex8616,
    callsite_addr: int,
    *,
    call_preservations: tuple[SegmentCallPreservationResult8616, ...] = (),
) -> PropagatedSegmentContext8616:
    """Carry one contextual DS==SS theorem across a proved nested near call."""
    caller = parent.callee
    candidate = DirectCallSegmentEntryCandidate8616(
        caller.artifact.function_addr, callsite_addr, callee.artifact.function_addr,
    )
    failure = _propagated_context_failure_8616(
        parent, caller, callee, index, candidate, call_preservations,
    )
    accepted = int(failure is None)
    return PropagatedSegmentContext8616(
        parent, caller, callee, index, candidate, call_preservations,
        failure, 1, 1, accepted, accepted, 1 - accepted,
    )
