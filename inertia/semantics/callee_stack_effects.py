"""Bind a real word CALL to its callee's retained returning SP proof.

Layer: Semantics.
Responsibility: authenticate the physical transfer and consume Alias-owned
callee SP dataflow over registered, fully covered raw IR. No convention,
prototype, source listing, or return-immediate shortcut supplies the effect.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from inertia.alias.callee_stack_pointer import (
    CalleeStackPointerResult8616,
    prove_callee_stack_pointer_8616,
)
from inertia.frontend.x86_16.synthetic_call_stub_evidence import is_synthetic_call_stub_8616
from inertia.ir.function_ir_registry import (
    FunctionIRArtifactFailure8616,
    publish_function_ir_artifact_8616,
    registered_function_ir_artifact_8616,
)
from inertia.ir.ir_boundary_cfg import prove_ir_boundary_coverage_8616
from inertia.ir.vex_import import build_x86_16_ir_function_artifact

from .bp_call_preservation import _exact_boundary_8616
from .callsite_summary import CallsiteMachineFrameKind8616
from .direct_ret_call_effect import direct_call_target_is_bound_8616


class CalleeStackCallFailure8616(StrEnum):
    """Typed reason a call cannot consume a complete callee SP proof."""

    CALL_TARGET_UNPROVEN = "call_target_unproven"
    SYNTHETIC_BODY = "synthetic_body"
    BOUNDARY_MISSING = "boundary_missing"
    IR_UNAVAILABLE = "ir_unavailable"
    BODY_REFUSED = "body_refused"


@dataclass(frozen=True, slots=True)
class CalleeStackCallResult8616:
    """Physical call identity and a retained whole-body Alias result."""

    project: object = field(compare=False, repr=False)
    callsite_addr: int | None
    return_addr: int | None
    target_addr: int | None
    frame_kind: CallsiteMachineFrameKind8616 | None
    body: CalleeStackPointerResult8616 | None
    failure: CalleeStackCallFailure8616 | None
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    def _retained_call_is_accepted(self) -> bool:
        """Require published call evidence rather than a retained refusal detail."""
        counts = (self.raw_fact_count, self.normalized_fact_count,
                  self.classified_fact_count, self.materialized_count, self.failure_count)
        return bool(
            self.failure is None and counts == (1, 1, 1, 1, 0)
            and all(type(count) is int for count in counts)
        )

    def _call_identity_is_current(self) -> bool:
        """Check the retained result and physical call before consuming Alias."""
        if not self._retained_call_is_accepted() or self.body is None:
            return False
        if self.target_addr is None or is_synthetic_call_stub_8616(self.project, self.target_addr):
            return False
        coverage = self.body.coverage
        return bool(
            coverage.boundary.project is self.project
            and coverage.artifact.function_addr == self.target_addr
            and direct_call_target_is_bound_8616(
                self.project, self.callsite_addr, self.return_addr, self.target_addr, self.frame_kind,
            )
        )

    @property
    def complete(self) -> bool:
        """Recheck source, registry identity, call bytes and Alias evidence."""
        return bool(
            self._call_identity_is_current()
            and self.body is not None
            and self.body.complete
        )

    @property
    def observed_return_sp_delta(self) -> int | None:
        """Expose accepted retained Alias data, without granting current authority."""
        if not self._retained_call_is_accepted() or self.body is None:
            return None
        return self.body.observed_return_sp_delta

    @property
    def return_sp_delta(self) -> int | None:
        """Project the displacement after one current call and body observation.

        Alias owns the source-bound transfer check in its projection accessor.
        Calling this result's complete property first would repeat that exact
        whole-body proof. Each new projection still checks both boundaries.
        """
        if not self._call_identity_is_current() or self.body is None:
            return None
        return self.body.return_sp_delta


def _body_stack_proof_8616(
    project: object, target: int,
) -> tuple[CalleeStackPointerResult8616 | None, CalleeStackCallFailure8616 | None]:
    """Consume or import one raw bounded body without recursive decompilation."""
    boundary = _exact_boundary_8616(project, target)
    if boundary is None:
        return None, CalleeStackCallFailure8616.BOUNDARY_MISSING
    resolution = registered_function_ir_artifact_8616(project, target)
    artifact = resolution.artifact
    if artifact is None:
        if resolution.failure is not FunctionIRArtifactFailure8616.NOT_REGISTERED:
            return None, CalleeStackCallFailure8616.IR_UNAVAILABLE
        artifact = build_x86_16_ir_function_artifact(project, boundary)
        publication = publish_function_ir_artifact_8616(project, artifact)
        if publication.artifact is None:
            return None, CalleeStackCallFailure8616.IR_UNAVAILABLE
    body = prove_callee_stack_pointer_8616(prove_ir_boundary_coverage_8616(project, boundary, artifact))
    return body, None if body.complete else CalleeStackCallFailure8616.BODY_REFUSED


def prove_direct_callee_stack_effect_8616(
    project: object, callsite_addr: int | None, return_addr: int | None,
    target_addr: int | None, frame_kind: CallsiteMachineFrameKind8616 | None,
) -> CalleeStackCallResult8616:
    """Publish a source-bound returning effect or a typed non-result."""
    body = None
    failure: CalleeStackCallFailure8616 | None = CalleeStackCallFailure8616.CALL_TARGET_UNPROVEN
    if target_addr is not None and is_synthetic_call_stub_8616(project, target_addr):
        failure = CalleeStackCallFailure8616.SYNTHETIC_BODY
    elif direct_call_target_is_bound_8616(
        project, callsite_addr, return_addr, target_addr, frame_kind,
    ):
        assert target_addr is not None
        body, failure = _body_stack_proof_8616(project, target_addr)
    accepted = int(failure is None)
    return CalleeStackCallResult8616(
        project, callsite_addr, return_addr, target_addr, frame_kind, body, failure,
        1, 1, accepted, accepted, 1 - accepted,
    )
