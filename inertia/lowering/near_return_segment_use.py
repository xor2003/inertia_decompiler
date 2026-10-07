"""Bind one returned near offset to the callee-entry data segment.

Layer: Types/Lowering.
Responsibility: join exact caller pointer-use evidence with registered raw IR
segment-preservation and transfer proofs. Establish only that the caller's
dereference selector uses the DS value present at the near CALL and preserved by its
callee. No source-pointer representation, pointee, C AST or prototype is
published. DS==SS is neither assumed nor required for this result-use theorem.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.ir.core import MemSpace, SegmentOrigin
from inertia.ir.direct_call_segment_context import SegmentEntryContext8616
from inertia.ir.segment_call_preservation import SegmentCallPreservationResult8616
from inertia.ir.segment_state import build_x86_16_segment_state_artifact

from .interprocedural_storage_return_type_contracts import ReturnPointerUseEvidence8616


class NearReturnSegmentUseFailure8616(StrEnum):
    """Why caller use cannot establish an entry-DS near-return interpretation."""

    POINTER_USE_UNPROVEN = "pointer_use_unproven"
    CALL_UNBOUND = "call_unbound"
    CALL_PRESERVATION_UNPROVEN = "call_preservation_unproven"
    DATA_SEGMENT_NOT_PRESERVED = "data_segment_not_preserved"
    DATA_SEGMENT_LIFETIME_UNPROVEN = "data_segment_lifetime_unproven"
    CALLER_CONTEXT_UNBOUND = "caller_context_unbound"


@dataclass(frozen=True, slots=True)
class NearReturnSegmentUse8616:
    """One replayable DS result-use binding, never pointer representation proof."""

    pointer_use: ReturnPointerUseEvidence8616
    call_preservation: SegmentCallPreservationResult8616
    caller_preservations: tuple[SegmentCallPreservationResult8616, ...]
    failure: NearReturnSegmentUseFailure8616 | None
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    caller_entry_context: SegmentEntryContext8616 | None = None

    @property
    def complete(self) -> bool:
        """Replay raw segment transfer and exact call binding before consumption."""
        counts = (self.raw_fact_count, self.normalized_fact_count,
                  self.classified_fact_count, self.materialized_count, self.failure_count)
        if self.failure is not None or counts != (1, 1, 1, 1, 0):
            return False
        if any(type(count) is not int for count in counts):
            return False
        return _segment_use_failure_8616(
            self.pointer_use, self.call_preservation, self.caller_preservations, self.caller_entry_context,
        ) is None


def _call_binding_failure_8616(
    use: ReturnPointerUseEvidence8616,
    preservation: SegmentCallPreservationResult8616,
    proofs: tuple[SegmentCallPreservationResult8616, ...],
) -> NearReturnSegmentUseFailure8616 | None:
    """Bind complete preservation and pointer-use coordinates to the same caller."""
    if not use.complete or use.address.space not in {MemSpace.DS, MemSpace.SS, MemSpace.ES}:
        return NearReturnSegmentUseFailure8616.POINTER_USE_UNPROVEN
    if not preservation.complete:
        return NearReturnSegmentUseFailure8616.CALL_PRESERVATION_UNPROVEN
    caller = preservation.caller
    if use.caller_addr != caller.artifact.function_addr or use.callsite_addr != preservation.callsite_addr:
        return NearReturnSegmentUseFailure8616.CALL_UNBOUND
    sites = caller.boundary.reachable_instruction_addrs
    if use.witness_instruction_addr not in sites or use.dereference_instruction_addr not in sites:
        return NearReturnSegmentUseFailure8616.CALL_UNBOUND
    matches = tuple(proof for proof in proofs if proof.callsite_addr == preservation.callsite_addr)
    if len(matches) != 1 or matches[0] is not preservation:
        return NearReturnSegmentUseFailure8616.CALL_PRESERVATION_UNPROVEN
    if "ds" not in preservation.preserved_registers:
        return NearReturnSegmentUseFailure8616.DATA_SEGMENT_NOT_PRESERVED
    return None


def _segment_use_failure_8616(
    use: ReturnPointerUseEvidence8616,
    preservation: SegmentCallPreservationResult8616,
    proofs: tuple[SegmentCallPreservationResult8616, ...],
    entry_context: SegmentEntryContext8616 | None = None,
) -> NearReturnSegmentUseFailure8616 | None:
    """Compare entry DS with the actual dereference selector's must-state.

    Ordinary architectural live-ins suffice for a preserved DS use. SS/ES uses
    require actual equality from local transfer or a retained contextual entry;
    a selector spelling is not permission to assume a small-model invariant.
    Input source-selector/native-pointer encoding is a separate obligation.
    """
    failure = _call_binding_failure_8616(use, preservation, proofs)
    if failure is not None:
        return failure
    if entry_context is not None and (
        not entry_context.complete or entry_context.callee.artifact is not preservation.caller.artifact
    ):
        return NearReturnSegmentUseFailure8616.CALLER_CONTEXT_UNBOUND
    state = build_x86_16_segment_state_artifact(
        preservation.caller.artifact, call_preservations=proofs, entry_context=entry_context,
    )
    entry = state.state_before_instruction(use.callsite_addr, "ds")
    consumed = state.state_before_instruction(use.dereference_instruction_addr, use.address.space.value)
    if entry is None or consumed is None:
        return NearReturnSegmentUseFailure8616.DATA_SEGMENT_LIFETIME_UNPROVEN
    proven = entry.origin is SegmentOrigin.PROVEN and consumed.origin is SegmentOrigin.PROVEN
    if not proven or entry.source is None or entry.source != consumed.source:
        return NearReturnSegmentUseFailure8616.DATA_SEGMENT_LIFETIME_UNPROVEN
    return None


def bind_near_return_data_segment_use_8616(
    pointer_use: ReturnPointerUseEvidence8616,
    call_preservation: SegmentCallPreservationResult8616,
    caller_preservations: tuple[SegmentCallPreservationResult8616, ...],
    *,
    caller_entry_context: SegmentEntryContext8616 | None = None,
) -> NearReturnSegmentUse8616:
    """Bind the caller's selector to callee-entry DS, or retain refusal."""
    failure = _segment_use_failure_8616(pointer_use, call_preservation, caller_preservations, caller_entry_context)
    accepted = int(failure is None)
    return NearReturnSegmentUse8616(
        pointer_use, call_preservation, caller_preservations, failure,
        1, 1, accepted, accepted, 1 - accepted, caller_entry_context,
    )
