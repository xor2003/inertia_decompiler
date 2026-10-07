"""Collect closed leaf-call proofs and refresh their IR state projection.

Layer: function summaries.
Responsibility: consume decoded frontend calls and registered local contracts,
request typed IR preservation proofs, and refresh state/contract projections.
Never recover aliases, pointer types, or semantics from source or rendered C.

Package ownership contract (canonical inertia/semantics package):
Layer: Semantics.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from inertia.frontend.x86_16.frontend_caller_return_use_program import (
    CallerReturnUseProgramEvidence8616,
    current_caller_return_use_program_evidence_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import mapped_entry_function_boundary_8616
from inertia.ir.core import IRFunctionArtifact
from inertia.ir.function_ir_registry import (
    FunctionIRArtifactFailure8616,
    publish_function_ir_artifact_8616,
    registered_function_ir_artifact_8616,
)
from inertia.ir.function_ssa_registry import FunctionSSAArtifactVerdict8616, function_ssa_artifact_at_address_8616
from inertia.ir.segment_call_preservation import SegmentCallPreservationResult8616, prove_segment_call_preservation_8616
from inertia.ir.segment_contract import SegmentFunctionContract, apply_x86_16_segment_function_contract
from inertia.ir.segment_state import (
    SegmentStateArtifact,
    apply_x86_16_segment_state_artifact,
    build_x86_16_segment_state_artifact,
)
from inertia.ir.vex_import import build_x86_16_ir_function_artifact


@dataclass(frozen=True, slots=True)
class SegmentCallPreservationRequest8616:
    """One already-proven near-call target supplied by the frontend summary."""

    callsite_addr: int
    target_addr: int

    def __post_init__(self) -> None:
        """Reject malformed coordinates rather than normalize guessed targets."""
        if any(type(value) is not int or value < 0 for value in (self.callsite_addr, self.target_addr)):
            raise ValueError("preservation request requires nonnegative integer coordinates")


class SegmentCallCollectionFailure8616(StrEnum):
    """Typed refusal reasons for individual proof requests."""

    CALLER_COVERAGE_MISSING = "caller_coverage_missing"
    DUPLICATE_CALLSITE = "duplicate_callsite"
    CALLEE_MISSING = "callee_missing"
    CALLEE_INCOMPLETE = "callee_incomplete"
    DECODED_CALLS_MISSING = "decoded_calls_missing"
    IR_PROOF_REFUSED = "ir_proof_refused"


@dataclass(frozen=True, slots=True)
class SegmentCallCollectionRefusal8616:
    """Keep a refused request and any exact upstream proof failure."""

    request: SegmentCallPreservationRequest8616
    failure: SegmentCallCollectionFailure8616
    proof: SegmentCallPreservationResult8616 | None = None


@dataclass(frozen=True, slots=True)
class SegmentCallPreservationCollection8616:
    """Request-scoped accepted proofs, refusals and closed evidence counts."""

    proofs: tuple[SegmentCallPreservationResult8616, ...]
    refusals: tuple[SegmentCallCollectionRefusal8616, ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def complete(self) -> bool:
        """Require every request accounted for and every retained proof still valid."""
        counts = (self.raw_fact_count, self.normalized_fact_count,
                  self.classified_fact_count, self.materialized_count, self.failure_count)
        if any(type(count) is not int for count in counts):
            return False
        return bool(
            self.raw_fact_count == self.normalized_fact_count == len(self.proofs) + len(self.refusals)
            and self.classified_fact_count == self.materialized_count == len(self.proofs)
            and self.failure_count == len(self.refusals)
            and all(proof.complete for proof in self.proofs)
        )


def collect_segment_call_preservations_8616(
    project: object,
    caller: SegmentFunctionContract,
    contracts: Mapping[int, SegmentFunctionContract],
    requests: tuple[SegmentCallPreservationRequest8616, ...],
    program: CallerReturnUseProgramEvidence8616 | None,
) -> SegmentCallPreservationCollection8616:
    """Collect per-request proofs without counting unrequested calls as covered."""
    proofs: list[SegmentCallPreservationResult8616] = []
    refusals: list[SegmentCallCollectionRefusal8616] = []
    site_counts = Counter(request.callsite_addr for request in requests)
    for request in sorted(requests, key=lambda item: (item.callsite_addr, item.target_addr)):
        refusal = _request_refusal_8616(project, caller, contracts, request, program, site_counts)
        if refusal is not None:
            refusals.append(refusal)
            continue
        assert caller.effect_closure is not None and program is not None
        callee = contracts[request.target_addr]
        assert callee.effect_closure is not None
        proof = prove_segment_call_preservation_8616(
            caller.effect_closure.coverage, callee.effect_closure, program.callsites, request.callsite_addr,
        )
        if proof.complete:
            proofs.append(proof)
        else:
            refusals.append(SegmentCallCollectionRefusal8616(request, SegmentCallCollectionFailure8616.IR_PROOF_REFUSED, proof))
    return SegmentCallPreservationCollection8616(
        tuple(proofs), tuple(refusals), len(requests), len(requests), len(proofs), len(proofs), len(refusals),
    )


def _request_refusal_8616(
    project: object,
    caller: SegmentFunctionContract,
    contracts: Mapping[int, SegmentFunctionContract],
    request: SegmentCallPreservationRequest8616,
    program: CallerReturnUseProgramEvidence8616 | None,
    site_counts: Counter[int],
) -> SegmentCallCollectionRefusal8616 | None:
    """Refuse missing ownership/evidence before requesting the exact IR proof."""
    closure = caller.effect_closure
    reason: SegmentCallCollectionFailure8616 | None = None
    if closure is None or not closure.coverage.complete or closure.coverage.boundary.project is not project:
        reason = SegmentCallCollectionFailure8616.CALLER_COVERAGE_MISSING
    elif site_counts[request.callsite_addr] != 1:
        reason = SegmentCallCollectionFailure8616.DUPLICATE_CALLSITE
    elif request.target_addr not in contracts:
        reason = SegmentCallCollectionFailure8616.CALLEE_MISSING
    elif not contracts[request.target_addr].effects_complete:
        reason = SegmentCallCollectionFailure8616.CALLEE_INCOMPLETE
    else:
        boundary = closure.coverage.boundary
        ranges = ((boundary.addr, boundary.addr + boundary.size),)
        if program is None or not program.range_census_complete or not program.matches(project, ranges):
            reason = SegmentCallCollectionFailure8616.DECODED_CALLS_MISSING
    return None if reason is None else SegmentCallCollectionRefusal8616(request, reason)


class _PreservationCodegenBoundary8616(Protocol):
    """Owned metadata carried through the dynamic codegen boundary."""

    _inertia_segment_function_contract: SegmentFunctionContract
    _inertia_segment_call_preservations_8616: tuple[SegmentCallPreservationResult8616, ...]
    _inertia_segment_call_preservation_collection_8616: SegmentCallPreservationCollection8616


@dataclass
class _LocalContractSurface8616:
    """Minimal typed codegen projection for registered binary-derived callee IR."""

    _inertia_vex_ir_artifact: IRFunctionArtifact
    _inertia_segment_state_artifact: SegmentStateArtifact
    _inertia_segment_function_contract: SegmentFunctionContract


def resolve_callee_segment_contract_8616(project: object, address: int) -> SegmentFunctionContract | None:
    """Resolve exact callee IR through its existing owner, then derive effects.

    Only this callee is requested: no recursive segment-summary expansion occurs.
    Registry resolution is not closure proof; the normal contract owner still
    requires the exact frontend instruction/edge census before authorization.
    Missing catalogs may use closed mapped-entry reachability. Existing raw
    artifacts are never rebuilt, so repeated callers retain identical evidence.
    """
    resolution = registered_function_ir_artifact_8616(project, address)
    artifact = resolution.artifact
    if artifact is None:
        if resolution.failure is not FunctionIRArtifactFailure8616.NOT_REGISTERED:
            return None
        boundary = mapped_entry_function_boundary_8616(project, address)
        if boundary is not None:
            raw = build_x86_16_ir_function_artifact(project, boundary)
            artifact = publish_function_ir_artifact_8616(project, raw).artifact
        else:
            ssa_resolution = function_ssa_artifact_at_address_8616(project, address)
            if ssa_resolution.verdict is not FunctionSSAArtifactVerdict8616.PROVEN:
                return None
            artifact = registered_function_ir_artifact_8616(project, address).artifact
        if artifact is None:
            return None
    surface = _LocalContractSurface8616(
        artifact, build_x86_16_segment_state_artifact(artifact), SegmentFunctionContract(function_addr=address),
    )
    apply_x86_16_segment_function_contract(project, surface)
    contract = surface._inertia_segment_function_contract
    return contract if contract.effects_complete else None


def refresh_segment_call_preservation_state_8616(
    project: object,
    codegen: object,
    caller: SegmentFunctionContract,
    contracts: Mapping[int, SegmentFunctionContract],
    requests: tuple[SegmentCallPreservationRequest8616, ...],
) -> SegmentFunctionContract:
    """Decode through the existing request owner and refresh accepted IR effects."""
    # Defer the large callsite-summary module until the stage runs; its public
    # scope owns decoder configuration and restores the outer request context.
    from .callsite_summary import caller_return_use_program_scope_8616

    resolved_contracts = dict(contracts)
    for address in sorted({request.target_addr for request in requests}):
        if address not in resolved_contracts:
            contract = resolve_callee_segment_contract_8616(project, address)
            if contract is not None:
                resolved_contracts[address] = contract
    program = None
    closure = caller.effect_closure
    candidates = any(request.target_addr in resolved_contracts and resolved_contracts[request.target_addr].effects_complete
                     for request in requests)
    if closure is not None and closure.coverage.complete and candidates:
        boundary = closure.coverage.boundary
        ranges = ((boundary.addr, boundary.addr + boundary.size),)
        with caller_return_use_program_scope_8616(project, ranges):
            program = current_caller_return_use_program_evidence_8616(project, ranges)
    collection = collect_segment_call_preservations_8616(project, caller, resolved_contracts, requests, program)
    surface = cast(_PreservationCodegenBoundary8616, codegen)
    try:
        previous = surface._inertia_segment_call_preservations_8616
    except AttributeError:
        previous = ()
    surface._inertia_segment_call_preservation_collection_8616 = collection
    surface._inertia_segment_call_preservations_8616 = collection.proofs
    if collection.proofs or previous:
        apply_x86_16_segment_state_artifact(project, codegen)
        apply_x86_16_segment_function_contract(project, codegen)
        return surface._inertia_segment_function_contract
    return caller
