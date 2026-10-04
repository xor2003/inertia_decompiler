"""Bind a pushed stack address to the actual near callee's data segment.

Layer: Types/Lowering.
Responsibility: join SSA-proven SS:BP address-of arguments with exact call and
segment receipts. This establishes offset transport and selector equality only;
it does not grant a native C-pointer representation, pointee type or publication.
Consumes binary IR/SSA and typed call evidence, never source or rendered text.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum

from ..callsite_summary import CallsitePushSourceKind8616, CallsiteSummary8616
from ..ir import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from ..ir.function_ssa_registry import FunctionSSAArtifactStage8616, registered_function_ssa_artifact_8616
from ..ir.segment_state import build_x86_16_segment_state_artifact
from ..ir.ssa_function import SSAFunctionArtifact
from ..semantics.call_target_evidence_8616 import resolve_call_target_evidence_8616
from .interprocedural_storage_contracts import StorageReachingDefinition8616
from .interprocedural_storage_reaching_contracts import CallArgumentDefinitionVerdict8616
from .interprocedural_storage_reaching_defs import (
    physical_call_argument_8616,
    resolve_call_argument_reaching_definition_8616,
)
from .near_return_segment_use import NearReturnSegmentUse8616


class NearPointerStackInputFailure8616(StrEnum):
    """Why one pushed stack-address input lacks near-data selector proof."""

    RETURN_USE_UNBOUND = "return_use_unbound"
    CALLER_SSA_UNBOUND = "caller_ssa_unbound"
    CALLSITE_UNBOUND = "callsite_unbound"
    ADDRESS_SOURCE_UNPROVEN = "address_source_unproven"
    SOURCE_DEFINITION_UNPROVEN = "source_definition_unproven"
    SELECTOR_EQUALITY_UNPROVEN = "selector_equality_unproven"


@dataclass(frozen=True, slots=True)
class NearPointerStackInputSegment8616:
    """Replayable near-call stack-address transport, not native-pointer proof."""

    project: object
    caller_ssa: SSAFunctionArtifact
    summary: CallsiteSummary8616
    logical_index: int
    return_use: NearReturnSegmentUse8616
    address: IRAddress | None
    failure: NearPointerStackInputFailure8616 | None
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def complete(self) -> bool:
        """Replay SSA address provenance and raw selector equality before use."""
        counts = (self.raw_fact_count, self.normalized_fact_count,
                  self.classified_fact_count, self.materialized_count, self.failure_count)
        if self.failure is not None or counts != (1, 1, 1, 1, 0):
            return False
        if any(type(count) is not int for count in counts):
            return False
        address, failure = _stack_input_segment_proof_8616(
            self.project, self.caller_ssa, self.summary, self.logical_index, self.return_use,
        )
        return failure is None and address is not None and address == self.address


def _bp_address_offset_8616(source: tuple[object, ...]) -> int | None:
    """Normalize only the legacy typed summary tuple at its boundary."""
    if len(source) != 2 or type(source[1]) is not int:
        return None
    kind = source[0]
    if kind not in (CallsitePushSourceKind8616.BP_ADDRESS, CallsitePushSourceKind8616.BP_ADDRESS.value):
        return None
    return source[1]


def _stack_input_segment_proof_8616(
    project: object,
    caller_ssa: SSAFunctionArtifact,
    summary: CallsiteSummary8616,
    logical_index: int,
    return_use: NearReturnSegmentUse8616,
) -> tuple[IRAddress | None, NearPointerStackInputFailure8616 | None]:
    """Reprove one exact stack-address push and its selector at the near call."""
    if not return_use.complete:
        return None, NearPointerStackInputFailure8616.RETURN_USE_UNBOUND
    preservation = return_use.call_preservation
    caller = preservation.caller.artifact
    registered = registered_function_ssa_artifact_8616(project, caller.function_addr)
    if registered.artifact is not caller_ssa or registered.stage is not FunctionSSAArtifactStage8616.SEMANTIC:
        return None, NearPointerStackInputFailure8616.CALLER_SSA_UNBOUND
    if summary.callsite_addr != preservation.callsite_addr or type(logical_index) is not int:
        return None, NearPointerStackInputFailure8616.CALLSITE_UNBOUND
    physical, failure = physical_call_argument_8616(summary, logical_index)
    if failure is not None or physical is None or physical.width != 2 or len(physical.pieces) != 1:
        return None, NearPointerStackInputFailure8616.ADDRESS_SOURCE_UNPROVEN
    piece = physical.pieces[0]
    offset = _bp_address_offset_8616(piece.source)
    if offset is None or piece.width != 2:
        return None, NearPointerStackInputFailure8616.ADDRESS_SOURCE_UNPROVEN
    # Semantic SSA target binding consumes the retained projection and decoded
    # caller census. A project alone cannot establish that source identity.
    evidence = resolve_call_target_evidence_8616(project, caller.function_addr)
    resolution = resolve_call_argument_reaching_definition_8616(
        caller_ssa, summary, logical_index, project=project,
        expected_target_addr=preservation.callee.coverage.artifact.function_addr,
        callsite_index=evidence.callsite_index,
        projection=evidence.projection,
    )
    if (not evidence.complete or resolution.verdict is not CallArgumentDefinitionVerdict8616.PROVEN
            or resolution.failure is not None or not resolution.stats.complete):
        return None, NearPointerStackInputFailure8616.SOURCE_DEFINITION_UNPROVEN
    address = _logical_stack_address_8616(resolution.definitions, offset)
    if address is None:
        return None, NearPointerStackInputFailure8616.SOURCE_DEFINITION_UNPROVEN
    if piece.push_addr not in preservation.caller.boundary.reachable_instruction_addrs:
        return None, NearPointerStackInputFailure8616.CALLSITE_UNBOUND
    if not _stack_selector_matches_entry_ds_8616(return_use, piece.push_addr):
        return None, NearPointerStackInputFailure8616.SELECTOR_EQUALITY_UNPROVEN
    return address, None


def _logical_stack_address_8616(definitions: tuple[StorageReachingDefinition8616, ...], offset: int) -> IRAddress | None:
    """Join exact source-byte slices of the pushed word, not a pointee extent."""
    addresses: list[IRAddress] = []
    for definition in definitions:
        storage = definition.source_storage
        if not definition.is_complete or storage is None or storage.address is None:
            return None
        address = storage.address
        exact = address.status is AddressStatus.STABLE and address.segment_origin is SegmentOrigin.PROVEN
        if not exact or address.space is not MemSpace.SS or address.base != ("bp",):
            return None
        if address.size != storage.width or address.size not in {1, 2}:
            return None
        addresses.append(address)
    if not addresses:
        return None
    ordered = sorted(addresses, key=lambda address: address.offset)
    cursor = offset
    for address in ordered:
        if address.offset != cursor:
            return None
        cursor += address.size
    if cursor != offset + 2:
        return None
    return replace(ordered[0], size=2)


def _stack_selector_matches_entry_ds_8616(return_use: NearReturnSegmentUse8616, push_addr: int) -> bool:
    """Require must-equality between the pushed address selector and entry DS."""
    caller = return_use.call_preservation.caller.artifact
    state = build_x86_16_segment_state_artifact(caller,
        call_preservations=return_use.caller_preservations, entry_context=return_use.caller_entry_context)
    source = state.state_before_instruction(push_addr, "ss")
    destination = state.state_before_instruction(return_use.call_preservation.callsite_addr, "ds")
    if source is None or destination is None:
        return False
    proven = source.origin is SegmentOrigin.PROVEN and destination.origin is SegmentOrigin.PROVEN
    return proven and source.source is not None and source.source == destination.source


def bind_near_pointer_stack_input_segment_8616(
    project: object,
    caller_ssa: SSAFunctionArtifact,
    summary: CallsiteSummary8616,
    logical_index: int,
    return_use: NearReturnSegmentUse8616,
) -> NearPointerStackInputSegment8616:
    """Bind one SSA-proven stack-address input or preserve a typed refusal."""
    address, failure = _stack_input_segment_proof_8616(project, caller_ssa, summary, logical_index, return_use)
    accepted = int(failure is None)
    return NearPointerStackInputSegment8616(project, caller_ssa, summary, logical_index,
        return_use, address, failure, 1, 1, accepted, accepted, 1 - accepted)
