"""Retain CALL-target binder evidence for project-scoped consumers.

Layer: Semantics (staged candidate under
``.cache/comparator-implementation/call-target-retention/``; intended
production home ``semantics/call_target_evidence_8616.py``).
Responsibility: publish and resolve the exact retained evidence the shared
``bind_ssa_call_target_8616`` obligation needs — the
``CallSemanticProjection8616`` identity retained at Semantics publication,
the once-built decoded direct-callsite index retained by Frontend for one
proven caller census, and the registered source-IR/SSA identities consumed
by the input/output storage gates.

Resolution is read-only over the project registries: it never rebuilds VEX
or SSA artifacts per call and never invents a semantic projection. A
raw-stage caller resolves to the decoded index plus the retained raw IR
identity only; the decoded index is built at most once per proven caller
census and reused while that census identity holds. Missing, stale, or
conflicting projection, SSA, raw-IR, or caller-boundary evidence is a typed
refusal, never a guess.

This module does not classify targets or discharge native binding proofs;
those remain with ``direct_near_call_target_binding`` and the shared binder.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol, cast

from ..frontend_direct_callsite_index import (
    DecodedDirectCallsiteIndex8616,
    DirectCallTargetResolver8616,
    RetainedDecodedCallsiteIndex8616,
    decoded_callsite_index_for_boundary_8616,
    registered_decoded_callsite_index_8616,
)
from ..frontend_function_boundary import ExactFunctionRangeBoundary8616
from ..ir.core import IRFunctionArtifact
from ..ir.function_ir_registry import (
    FunctionIRArtifactFailure8616,
    FunctionIRArtifactVerdict8616,
    registered_function_ir_artifact_8616,
)
from ..ir.function_ssa_registry import (
    FunctionSSAArtifactFailure8616,
    FunctionSSAArtifactResolution8616,
    FunctionSSAArtifactStage8616,
    FunctionSSAArtifactVerdict8616,
    function_boundary_at_address_8616,
    registered_function_ssa_artifact_8616,
)
from ..ir.ssa_function import SSAFunctionArtifact

if TYPE_CHECKING:
    from .call_stack_effect_pipeline import CallSemanticProjection8616

__all__ = [
    "CallTargetEvidenceFailure8616",
    "CallTargetEvidencePublication8616",
    "CallTargetEvidenceResolution8616",
    "CallTargetEvidenceStats8616",
    "CallTargetEvidenceVerdict8616",
    "publish_call_semantic_projection_8616",
    "resolve_call_target_evidence_8616",
]


class CallTargetEvidenceVerdict8616(StrEnum):
    """Typed outcome of one retained call-target evidence operation."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"
    CONFLICT = "conflict"


class CallTargetEvidenceFailure8616(StrEnum):
    """Earliest retained-evidence obligation that could not be discharged."""

    CALLER_IDENTITY_INVALID = "caller_identity_invalid"
    CALLER_SSA_CONFLICT = "caller_ssa_conflict"
    SEMANTIC_PROJECTION_NOT_RETAINED = "semantic_projection_not_retained"
    SEMANTIC_PROJECTION_STALE = "semantic_projection_stale"
    SEMANTIC_PROJECTION_SSA_MISMATCH = "semantic_projection_ssa_mismatch"
    SEMANTIC_PROJECTION_INCOMPLETE = "semantic_projection_incomplete"
    SOURCE_IR_NOT_REGISTERED = "source_ir_not_registered"
    SOURCE_IR_CONFLICT = "source_ir_conflict"
    RAW_IR_NOT_REGISTERED = "raw_ir_not_registered"
    RAW_IR_CONFLICT = "raw_ir_conflict"
    CALLER_BOUNDARY_MISSING = "caller_boundary_missing"
    CALLER_BOUNDARY_CONFLICT = "caller_boundary_conflict"
    DECODED_RESOLVER_MISSING = "decoded_resolver_missing"
    DECODED_INDEX_REFUSED = "decoded_index_refused"
    EVIDENCE_CONFLICT = "evidence_conflict"


@dataclass(frozen=True, slots=True)
class CallTargetEvidenceStats8616:
    """Closed five-stage accounting for one evidence publish/resolve."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def closed(self) -> bool:
        """Return whether every consulted obligation became an admit or refusal."""
        counts = (
            self.raw_fact_count,
            self.normalized_fact_count,
            self.classified_fact_count,
            self.materialized_count,
            self.failure_count,
        )
        return bool(
            min(counts) >= 0
            and self.raw_fact_count == self.normalized_fact_count
            and self.normalized_fact_count
            == self.materialized_count + self.failure_count
            and self.classified_fact_count == self.materialized_count
        )


@dataclass(frozen=True, slots=True)
class CallTargetEvidencePublication8616:
    """Result of retaining one exact semantic projection on the project."""

    caller_addr: int
    verdict: CallTargetEvidenceVerdict8616
    failure: CallTargetEvidenceFailure8616 | None
    projection: CallSemanticProjection8616 | None
    stats: CallTargetEvidenceStats8616

    @property
    def complete(self) -> bool:
        """Return whether the projection is retained and closed."""
        return (
            self.verdict is CallTargetEvidenceVerdict8616.PROVEN
            and self.failure is None
            and self.projection is not None
            and self.projection.complete
            and self.projection.source_ir.function_addr == self.caller_addr
            and self.stats.closed
            and self.stats.raw_fact_count > 0
            and self.stats.failure_count == 0
        )


@dataclass(frozen=True, slots=True)
class CallTargetEvidenceResolution8616:
    """One caller's retained binder evidence, or a typed refusal.

    ``projection`` is the exact retained ``CallSemanticProjection8616`` only
    on the semantic route; it stays ``None`` for raw-stage callers so the
    binder's raw route runs without an invented projection. ``callsite_index``
    is the once-built decoded index for this caller's proven census.
    """

    caller_addr: int
    verdict: CallTargetEvidenceVerdict8616
    failure: CallTargetEvidenceFailure8616 | None
    stats: CallTargetEvidenceStats8616
    ssa_artifact: SSAFunctionArtifact | None = None
    ssa_stage: FunctionSSAArtifactStage8616 | None = None
    source_ir: IRFunctionArtifact | None = None
    projection: CallSemanticProjection8616 | None = None
    callsite_index: DecodedDirectCallsiteIndex8616 | None = None
    boundary: ExactFunctionRangeBoundary8616 | None = None

    @property
    def complete(self) -> bool:
        """Return whether closed binder evidence is available for transport."""
        available = (
            self.verdict is CallTargetEvidenceVerdict8616.PROVEN
            and self.failure is None
            and self.callsite_index is not None
            and self.callsite_index.stats.closed
            and self.source_ir is not None
            and self.source_ir.function_addr == self.caller_addr
            and self.boundary is not None
            and self.boundary.addr == self.caller_addr
            and self.stats.closed
            and self.stats.raw_fact_count > 0
            and self.stats.failure_count == 0
        )
        if not available:
            return False
        if self.ssa_stage is FunctionSSAArtifactStage8616.SEMANTIC:
            return (
                self.projection is not None
                and self.projection.complete
                and self.projection.source_ir is self.source_ir
                and self.projection.function_ssa is self.ssa_artifact
            )
        return self.projection is None

    def to_dict(self) -> dict[str, object]:
        """Return the typed verdict/failure/identity projection for reports."""
        return {
            "caller_addr": self.caller_addr,
            "verdict": self.verdict.value,
            "failure": None if self.failure is None else self.failure.value,
            "ssa_stage": None if self.ssa_stage is None else self.ssa_stage.value,
            "has_ssa_artifact": self.ssa_artifact is not None,
            "has_source_ir": self.source_ir is not None,
            "has_projection": self.projection is not None,
            "has_callsite_index": self.callsite_index is not None,
            "has_boundary": self.boundary is not None,
            "stats": {
                "raw_fact_count": self.stats.raw_fact_count,
                "normalized_fact_count": self.stats.normalized_fact_count,
                "classified_fact_count": self.stats.classified_fact_count,
                "materialized_count": self.stats.materialized_count,
                "failure_count": self.stats.failure_count,
                "closed": self.stats.closed,
            },
        }


class _CallTargetProjectionSurface8616(Protocol):
    """Project-owned semantic-projection retention extension."""

    _inertia_call_target_projections_8616: dict[int, CallSemanticProjection8616]


def _projection_class_8616() -> type:
    """Return the owned projection contract without an import cycle.

    ``call_stack_effect_pipeline`` publishes through this module, so the
    projection type resolves lazily at first use instead of at import.
    """
    from .call_stack_effect_pipeline import CallSemanticProjection8616

    return CallSemanticProjection8616


def _existing_projections_8616(
    project: object,
) -> dict[int, CallSemanticProjection8616] | None:
    """Return the retained projection map without creating it."""
    surface = cast(_CallTargetProjectionSurface8616, project)
    try:
        registry = surface._inertia_call_target_projections_8616
    except AttributeError:
        return None
    if not isinstance(registry, dict):
        raise TypeError("call-target projection registry must be a dict")
    return registry


def _retained_projection_8616(
    project: object, caller_addr: int
) -> CallSemanticProjection8616 | None:
    """Return one retained projection without mutating the project."""
    registry = _existing_projections_8616(project)
    retained = None if registry is None else registry.get(caller_addr)
    if retained is None:
        return None
    if type(retained) is not _projection_class_8616():
        raise TypeError("retained call-target projection has a foreign type")
    return retained


def publish_call_semantic_projection_8616(
    project: object,
    projection: CallSemanticProjection8616,
) -> CallTargetEvidencePublication8616:
    """Retain one complete semantic projection for later consumer resolution.

    The projection's ``source_ir`` address is the retention key. A repeated
    publication of the same or equal projection is idempotent; a different
    projection for the same caller is a conflict, never a silent overwrite.
    """
    if type(projection) is not _projection_class_8616():
        raise TypeError("call-target evidence requires CallSemanticProjection8616")
    caller_addr = projection.source_ir.function_addr
    stats_fail = CallTargetEvidenceStats8616(1, 1, 0, 0, 1)
    stats_pass = CallTargetEvidenceStats8616(1, 1, 1, 1, 0)
    if (
        type(caller_addr) is not int
        or caller_addr < 0
        or projection.function_ssa.function_addr != caller_addr
        or projection.effects.function.function_addr != caller_addr
        or projection.outputs.function.function_addr != caller_addr
    ):
        return CallTargetEvidencePublication8616(
            0 if type(caller_addr) is not int else caller_addr,
            CallTargetEvidenceVerdict8616.CONFLICT,
            CallTargetEvidenceFailure8616.EVIDENCE_CONFLICT,
            None,
            stats_fail,
        )
    if not projection.complete:
        return CallTargetEvidencePublication8616(
            caller_addr,
            CallTargetEvidenceVerdict8616.UNKNOWN_REFUSE,
            CallTargetEvidenceFailure8616.SEMANTIC_PROJECTION_INCOMPLETE,
            None,
            stats_fail,
        )
    surface = cast(_CallTargetProjectionSurface8616, project)
    registry = _existing_projections_8616(project)
    if registry is None:
        registry = {}
        surface._inertia_call_target_projections_8616 = registry
    existing = registry.get(caller_addr)
    if existing is None:
        registry[caller_addr] = projection
        retained = projection
    elif existing is projection or existing == projection:
        retained = existing
    else:
        return CallTargetEvidencePublication8616(
            caller_addr,
            CallTargetEvidenceVerdict8616.CONFLICT,
            CallTargetEvidenceFailure8616.EVIDENCE_CONFLICT,
            None,
            stats_fail,
        )
    return CallTargetEvidencePublication8616(
        caller_addr,
        CallTargetEvidenceVerdict8616.PROVEN,
        None,
        retained,
        stats_pass,
    )


def _resolution_8616(
    caller_addr: int,
    verdict: CallTargetEvidenceVerdict8616,
    failure: CallTargetEvidenceFailure8616 | None,
    consulted: int,
    admitted: int,
    *,
    ssa_artifact: SSAFunctionArtifact | None = None,
    ssa_stage: FunctionSSAArtifactStage8616 | None = None,
    source_ir: IRFunctionArtifact | None = None,
    projection: CallSemanticProjection8616 | None = None,
    callsite_index: DecodedDirectCallsiteIndex8616 | None = None,
    boundary: ExactFunctionRangeBoundary8616 | None = None,
) -> CallTargetEvidenceResolution8616:
    """Build one closed verdict over the obligations consulted so far."""
    failures = 0 if failure is None else 1
    stats = CallTargetEvidenceStats8616(
        consulted, consulted, admitted, admitted, failures
    )
    return CallTargetEvidenceResolution8616(
        caller_addr,
        verdict,
        failure,
        stats,
        ssa_artifact=ssa_artifact,
        ssa_stage=ssa_stage,
        source_ir=source_ir,
        projection=projection,
        callsite_index=callsite_index,
        boundary=boundary,
    )


def _registered_raw_identity_8616(
    project: object,
    caller_addr: int,
    consulted: int,
    *,
    not_registered: CallTargetEvidenceFailure8616,
    conflict: CallTargetEvidenceFailure8616,
) -> IRFunctionArtifact | CallTargetEvidenceResolution8616:
    """Return the registered raw artifact or the matching typed refusal."""
    raw = registered_function_ir_artifact_8616(project, caller_addr)
    if (
        raw.verdict is FunctionIRArtifactVerdict8616.PROVEN
        and raw.artifact is not None
    ):
        return raw.artifact
    is_conflict = raw.failure is FunctionIRArtifactFailure8616.ARTIFACT_CONFLICT
    return _resolution_8616(
        caller_addr,
        (
            CallTargetEvidenceVerdict8616.CONFLICT
            if is_conflict
            else CallTargetEvidenceVerdict8616.UNKNOWN_REFUSE
        ),
        conflict if is_conflict else not_registered,
        consulted,
        consulted - 1,
    )


def _caller_boundary_8616(
    project: object, caller_addr: int
) -> ExactFunctionRangeBoundary8616 | None:
    """Return an independently registered exact census boundary, if any."""
    boundary = function_boundary_at_address_8616(project, caller_addr)
    if isinstance(boundary, ExactFunctionRangeBoundary8616):
        return boundary
    return None


def _decoded_index_8616(
    project: object,
    caller_addr: int,
    consulted: int,
    *,
    boundary: ExactFunctionRangeBoundary8616 | None,
    direct_target_resolver: DirectCallTargetResolver8616 | None,
) -> RetainedDecodedCallsiteIndex8616 | CallTargetEvidenceResolution8616:
    """Return the retained once-built index, decoding at most once."""
    record = registered_decoded_callsite_index_8616(project, caller_addr)
    if record is not None:
        if record.boundary.project is not project or record.boundary.addr != caller_addr:
            return _resolution_8616(
                caller_addr,
                CallTargetEvidenceVerdict8616.CONFLICT,
                CallTargetEvidenceFailure8616.CALLER_BOUNDARY_CONFLICT,
                consulted,
                consulted - 1,
            )
        if boundary is not None and boundary != record.boundary:
            return _resolution_8616(
                caller_addr,
                CallTargetEvidenceVerdict8616.CONFLICT,
                CallTargetEvidenceFailure8616.CALLER_BOUNDARY_CONFLICT,
                consulted,
                consulted - 1,
            )
        return record
    if boundary is None:
        boundary = _caller_boundary_8616(project, caller_addr)
    if boundary is None:
        return _resolution_8616(
            caller_addr,
            CallTargetEvidenceVerdict8616.UNKNOWN_REFUSE,
            CallTargetEvidenceFailure8616.CALLER_BOUNDARY_MISSING,
            consulted,
            consulted - 1,
        )
    if boundary.addr != caller_addr or boundary.project is not project:
        return _resolution_8616(
            caller_addr,
            CallTargetEvidenceVerdict8616.CONFLICT,
            CallTargetEvidenceFailure8616.CALLER_BOUNDARY_CONFLICT,
            consulted,
            consulted - 1,
        )
    if direct_target_resolver is None:
        return _resolution_8616(
            caller_addr,
            CallTargetEvidenceVerdict8616.UNKNOWN_REFUSE,
            CallTargetEvidenceFailure8616.DECODED_RESOLVER_MISSING,
            consulted,
            consulted - 1,
        )
    try:
        return decoded_callsite_index_for_boundary_8616(
            project,
            boundary,
            direct_target_resolver=direct_target_resolver,
        )
    except ValueError:
        return _resolution_8616(
            caller_addr,
            CallTargetEvidenceVerdict8616.CONFLICT,
            CallTargetEvidenceFailure8616.DECODED_INDEX_REFUSED,
            consulted,
            consulted - 1,
        )


def _semantic_source_identity_8616(
    project: object,
    caller_addr: int,
    ssa: FunctionSSAArtifactResolution8616,
    retained: CallSemanticProjection8616,
    admitted: int,
) -> tuple[IRFunctionArtifact, int] | CallTargetEvidenceResolution8616:
    """Verify the retained projection against registered SSA/raw identities.

    The projection must name the exact registered semantic SSA object, be
    internally complete, and reference the registered raw artifact for this
    caller. Each violated obligation becomes the earliest typed refusal.
    """
    if retained.function_ssa is not ssa.artifact:
        return _resolution_8616(
            caller_addr,
            CallTargetEvidenceVerdict8616.CONFLICT,
            CallTargetEvidenceFailure8616.SEMANTIC_PROJECTION_SSA_MISMATCH,
            admitted + 1,
            admitted,
        )
    if not retained.complete:
        return _resolution_8616(
            caller_addr,
            CallTargetEvidenceVerdict8616.UNKNOWN_REFUSE,
            CallTargetEvidenceFailure8616.SEMANTIC_PROJECTION_INCOMPLETE,
            admitted + 1,
            admitted,
        )
    admitted += 1
    source = _registered_raw_identity_8616(
        project,
        caller_addr,
        admitted + 1,
        not_registered=CallTargetEvidenceFailure8616.SOURCE_IR_NOT_REGISTERED,
        conflict=CallTargetEvidenceFailure8616.SOURCE_IR_CONFLICT,
    )
    if isinstance(source, CallTargetEvidenceResolution8616):
        return source
    if source is not retained.source_ir and source != retained.source_ir:
        return _resolution_8616(
            caller_addr,
            CallTargetEvidenceVerdict8616.CONFLICT,
            CallTargetEvidenceFailure8616.SOURCE_IR_CONFLICT,
            admitted + 1,
            admitted,
        )
    return source, admitted + 1


def resolve_call_target_evidence_8616(
    project: object,
    caller_addr: int,
    *,
    boundary: ExactFunctionRangeBoundary8616 | None = None,
    direct_target_resolver: DirectCallTargetResolver8616 | None = None,
) -> CallTargetEvidenceResolution8616:
    """Resolve the retained binder evidence for one exact caller.

    Consulted obligations, in order: the SSA registry stage, the retained
    semantic projection (semantic route only), the registered raw IR
    identity, and the once-built decoded callsite index. ``boundary``
    supplies the proven caller census when no index is retained yet; an
    absent or conflicting census refuses instead of fabricating coverage.
    """
    if project is None or type(caller_addr) is not int or caller_addr < 0:
        return _resolution_8616(
            caller_addr if type(caller_addr) is int else 0,
            CallTargetEvidenceVerdict8616.UNKNOWN_REFUSE,
            CallTargetEvidenceFailure8616.CALLER_IDENTITY_INVALID,
            1,
            0,
        )
    ssa = registered_function_ssa_artifact_8616(project, caller_addr)
    if ssa.failure is FunctionSSAArtifactFailure8616.ARTIFACT_CONFLICT:
        return _resolution_8616(
            caller_addr,
            CallTargetEvidenceVerdict8616.CONFLICT,
            CallTargetEvidenceFailure8616.CALLER_SSA_CONFLICT,
            1,
            0,
        )
    admitted = 1
    semantic = (
        ssa.verdict is FunctionSSAArtifactVerdict8616.PROVEN
        and ssa.stage is FunctionSSAArtifactStage8616.SEMANTIC
    )
    retained = _retained_projection_8616(project, caller_addr)
    projection: CallSemanticProjection8616 | None = None
    source_ir: IRFunctionArtifact | None = None
    if semantic:
        if retained is None:
            return _resolution_8616(
                caller_addr,
                CallTargetEvidenceVerdict8616.UNKNOWN_REFUSE,
                CallTargetEvidenceFailure8616.SEMANTIC_PROJECTION_NOT_RETAINED,
                admitted + 1,
                admitted,
            )
        verified = _semantic_source_identity_8616(
            project, caller_addr, ssa, retained, admitted
        )
        if isinstance(verified, CallTargetEvidenceResolution8616):
            return verified
        projection = retained
        source_ir, admitted = verified
    else:
        if retained is not None:
            return _resolution_8616(
                caller_addr,
                CallTargetEvidenceVerdict8616.CONFLICT,
                CallTargetEvidenceFailure8616.SEMANTIC_PROJECTION_STALE,
                admitted + 1,
                admitted,
            )
        source = _registered_raw_identity_8616(
            project,
            caller_addr,
            admitted + 1,
            not_registered=CallTargetEvidenceFailure8616.RAW_IR_NOT_REGISTERED,
            conflict=CallTargetEvidenceFailure8616.RAW_IR_CONFLICT,
        )
        if isinstance(source, CallTargetEvidenceResolution8616):
            return source
        source_ir = source
        admitted += 1
    index = _decoded_index_8616(
        project,
        caller_addr,
        admitted + 1,
        boundary=boundary,
        direct_target_resolver=direct_target_resolver,
    )
    if isinstance(index, CallTargetEvidenceResolution8616):
        return index
    admitted += 1
    return _resolution_8616(
        caller_addr,
        CallTargetEvidenceVerdict8616.PROVEN,
        None,
        admitted,
        admitted,
        ssa_artifact=ssa.artifact,
        ssa_stage=ssa.stage,
        source_ir=source_ir,
        projection=projection,
        callsite_index=index.index,
        boundary=index.boundary,
    )
