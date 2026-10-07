"""Bind Alias-proved incoming BP preservation to one real near CALL.

Layer: Semantics.
Responsibility: verify the exact loaded call transfer, resolve its binary-framed
leaf body through existing Frontend/IR owners, and retain the Alias proof for
caller-effect consumers. Never infer a compiler ABI or pointer representation.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from inertia.alias.bp_preservation import BPPreservationResult8616, prove_bp_preservation_8616
from inertia.frontend.x86_16.frontend_boundary_transport import (
    capture_function_boundary_8616,
    restore_function_boundary_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
    mapped_entry_function_boundary_8616,
)
from inertia.ir.function_ir_registry import (
    FunctionIRArtifactFailure8616,
    publish_function_ir_artifact_8616,
    registered_function_ir_artifact_8616,
)
from inertia.ir.function_ssa_registry import function_boundary_at_address_8616
from inertia.ir.ir_boundary_cfg import prove_ir_boundary_coverage_8616
from inertia.ir.vex_import import build_x86_16_ir_function_artifact
from inertia.semantics.callsite_summary import CallsiteMachineFrameKind8616

from .direct_ret_call_effect import direct_near_call_target_is_bound_8616


class BPCallPreservationFailure8616(StrEnum):
    """Why one near call cannot consume a leaf BP preservation proof."""

    CALL_TARGET_UNPROVEN = "call_target_unproven"
    BOUNDARY_MISSING = "boundary_missing"
    IR_UNAVAILABLE = "ir_unavailable"
    BODY_REFUSED = "body_refused"


@dataclass(frozen=True, slots=True)
class BPCallPreservationResult8616:
    """One exact call and its retained body proof, or typed non-result."""

    project: object = field(compare=False, repr=False)
    callsite_addr: int | None
    return_addr: int | None
    target_addr: int | None
    frame_kind: CallsiteMachineFrameKind8616 | None
    body: BPPreservationResult8616 | None
    failure: BPCallPreservationFailure8616 | None
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def complete(self) -> bool:
        """Recheck exact call bytes, project/body identity and closed counts."""
        counts = (self.raw_fact_count, self.normalized_fact_count,
                  self.classified_fact_count, self.materialized_count, self.failure_count)
        if self.failure is not None or counts != (1, 1, 1, 1, 0) or any(type(count) is not int for count in counts):
            return False
        if self.body is None or not self.body.complete:
            return False
        coverage = self.body.coverage
        return bool(coverage.boundary.project is self.project and coverage.artifact.function_addr == self.target_addr
                    and direct_near_call_target_is_bound_8616(
                        self.project, self.callsite_addr, self.return_addr, self.target_addr, self.frame_kind,
                    ))


def _exact_boundary_8616(project: object, target: int) -> ExactFunctionRangeBoundary8616 | None:
    """Consume exact bounds or reconstruct witnessed blocks, never summed size."""
    function = function_boundary_at_address_8616(project, target)
    if isinstance(function, ExactFunctionRangeBoundary8616):
        return function
    if function is None:
        return mapped_entry_function_boundary_8616(project, target)
    witness = capture_function_boundary_8616(project, function)
    return None if witness is None else restore_function_boundary_8616(project, witness)


def _body_proof_8616(
    project: object, target: int,
) -> tuple[BPPreservationResult8616 | None, BPCallPreservationFailure8616 | None]:
    """Request one raw leaf only; no recursive Semantics/SSA expansion occurs."""
    boundary = _exact_boundary_8616(project, target)
    if boundary is None:
        return None, BPCallPreservationFailure8616.BOUNDARY_MISSING
    resolution = registered_function_ir_artifact_8616(project, target)
    artifact = resolution.artifact
    if artifact is None:
        if resolution.failure is not FunctionIRArtifactFailure8616.NOT_REGISTERED:
            return None, BPCallPreservationFailure8616.IR_UNAVAILABLE
        artifact = build_x86_16_ir_function_artifact(project, boundary)
        publication = publish_function_ir_artifact_8616(project, artifact)
        if publication.artifact is None:
            return None, BPCallPreservationFailure8616.IR_UNAVAILABLE
    body = prove_bp_preservation_8616(prove_ir_boundary_coverage_8616(project, boundary, artifact))
    return body, None if body.complete else BPCallPreservationFailure8616.BODY_REFUSED


def prove_direct_bp_call_preservation_8616(
    project: object, callsite_addr: int | None, return_addr: int | None,
    target_addr: int | None, frame_kind: CallsiteMachineFrameKind8616 | None,
) -> BPCallPreservationResult8616:
    """Produce a proof-bound caller BP effect without compiler convention guesses."""
    body = None
    failure: BPCallPreservationFailure8616 | None = BPCallPreservationFailure8616.CALL_TARGET_UNPROVEN
    if direct_near_call_target_is_bound_8616(project, callsite_addr, return_addr, target_addr, frame_kind):
        assert target_addr is not None
        body, failure = _body_proof_8616(project, target_addr)
    accepted = int(failure is None)
    return BPCallPreservationResult8616(
        project, callsite_addr, return_addr, target_addr, frame_kind, body, failure,
        1, 1, accepted, accepted, 1 - accepted,
    )
