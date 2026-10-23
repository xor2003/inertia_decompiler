"""Produce private conditional IR from one indexed native near-CALL entry.

Layer: IR.
Responsibility: compose existing native entry, target, preservation and scoped
view proofs into a typed pipeline input. The installed source supplies lookup
facts only; no boot reachability, universal registry publication, whole-function
validation or callee termination is inferred.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
    DirectCallTargetResolver8616,
    decoded_callsite_index_for_boundary_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
from inertia.frontend.x86_16.frontend_near_return_continuation import prove_near_call_frame_premise_8616
from inertia.frontend.x86_16.near_call_entry_context import (
    NativeNearCallEntry8616,
    bind_native_near_call_entry_8616,
)
from inertia.semantics.direct_near_call_target_binding import DirectNearCallCoordinates8616

from .direct_evidence_deadline import direct_evidence_deadline_expired_8616
from .entry_domain_call_preservation import (
    Real16InvocationSource8616,
    _decoded_entry_for_callsite_8616,
    _decoded_instruction_map_8616,
    _invocation_source_fields_valid_8616,
    _premise_target_resolver_8616,
)
from .native_import_surface_cache import native_import_request_8616
from .near_call_census import _CensusCall8616, prove_near_call_preservation_census_8616
from .near_call_jump_scope import NearCallJumpScope8616
from .near_call_preservation import (
    ConditionalNearCallPreservation8616,
    ConditionalNearCallPreservationFailure8616,
    ConditionalNearCallPreservationStats8616,
    _resolution_scope_8616,
)
from .scoped_function_ir_view import ScopedFunctionIRView8616
from .segment_call_preservation import segment_call_dependency_traversal_scope_8616
from .vex_import import (
    RawIRFunctionImportBundle8616,
    prove_scoped_x86_16_ir_function_view_8616,
    raw_x86_16_function_bundle_8616,
    raw_x86_16_import_bundle_for_artifact_8616,
)


class NearCallEntryPipelineStatus8616(StrEnum):
    """Conditional pipeline availability, never universal function acceptance."""

    CONDITIONAL = "conditional"
    REFUSED = "refused"


class NearCallEntryPipelineFailure8616(StrEnum):
    """Typed earliest non-result from the bounded native composition."""

    SOURCE_MISSING = "source_missing"
    BOUNDARY_FOREIGN = "boundary_foreign"
    ENTRY_MISSING = "entry_missing"
    ENTRY_AMBIGUOUS = "entry_ambiguous"
    ENTRY_UNPROVED = "entry_unproved"
    RAW_SOURCE_CHANGED = "raw_source_changed"
    CALL_CENSUS_UNPROVED = "call_census_unproved"
    CALL_PRESERVATION_UNPROVED = "call_preservation_unproved"
    VIEW_UNPROVED = "view_unproved"
    SOURCE_CHANGED = "source_changed"
    BUDGET_EXPIRED = "budget_expired"


class _SourceHolder8616(Protocol):
    """Existing optional installed-source slot on third-party angr projects."""

    _inertia_real16_invocation_source_8616: Real16InvocationSource8616 | None


def _installed_source_8616(project: object) -> Real16InvocationSource8616 | None:
    """Read installed authority without triggering boot/deferred intake."""
    try:
        source = cast(_SourceHolder8616, project)._inertia_real16_invocation_source_8616
    except AttributeError:
        return None
    if source is not None and type(source) is not Real16InvocationSource8616:
        raise TypeError("installed invocation source must be typed")
    if source is not None and not _invocation_source_fields_valid_8616(source):
        raise TypeError("installed invocation source fields are malformed")
    return source


def _incoming_rows_8616(
    source: Real16InvocationSource8616, target: int,
) -> tuple[DecodedDirectCallsite8616, ...]:
    """Select exact encoded near destinations without trusting lookup aliases."""
    return tuple(
        row for row in source.callsite_index.for_target(target)
        if (coordinates := row.encoded_near_coordinates()) is not None
        and coordinates[1] == target
    )


@dataclass(frozen=True, slots=True)
class NativeNearCallPipeline8616:
    """Private raw input and conditional view for one exact native incoming edge."""

    source: Real16InvocationSource8616
    bundle: RawIRFunctionImportBundle8616
    scope: NearCallJumpScope8616
    view: ScopedFunctionIRView8616
    incoming: DecodedDirectCallsite8616

    @property
    def premise(self) -> NearCallEntryPipelineStatus8616:
        """Expose the typed conditional discriminator for pipeline diagnostics."""
        return NearCallEntryPipelineStatus8616.CONDITIONAL

    def authenticates(self, project: object) -> bool:
        """Reconsume installed lookup membership and native conditional view."""
        if not self._source_current(project):
            return False
        if (self.view.source_artifact is not self.bundle.artifact
                or self.scope.artifact is not self.bundle.artifact
                or self.view.near_call_scope is not self.scope
                or not self.view.complete_for(self.scope)):
            return False
        return self._source_current(project)

    def _source_current(self, project: object) -> bool:
        """Check used source identities and ambiguity without native callbacks."""
        installed = _installed_source_8616(project)
        if (installed is None or installed is not self.source
                or self.scope.project is not project
                or installed.callsite_index is not self.scope.context.callsite_index):
            return False
        rows = _incoming_rows_8616(self.source, self.bundle.artifact.function_addr)
        return len(rows) == 1 and rows[0] is self.incoming


@dataclass(frozen=True, slots=True)
class NearCallEntryPipelineResult8616:
    """Closed typed result of attempting one private conditional input."""

    status: NearCallEntryPipelineStatus8616
    failure: NearCallEntryPipelineFailure8616 | None
    entry: NativeNearCallPipeline8616 | None
    stats: ConditionalNearCallPreservationStats8616

    def to_dict(self) -> dict[str, object]:
        """Report preparation only; no emitted-C or boot-proof claim."""
        return {
            "status": self.status.value,
            "failure": None if self.failure is None else self.failure.value,
            "conditional_only": True,
            "function_addr": None if self.entry is None else self.entry.bundle.artifact.function_addr,
            "stats": self.stats.to_dict(),
        }


def _refused_8616(failure: NearCallEntryPipelineFailure8616) -> NearCallEntryPipelineResult8616:
    """Close one failed preparation without publishing partial authority."""
    return NearCallEntryPipelineResult8616(
        NearCallEntryPipelineStatus8616.REFUSED, failure, None,
        ConditionalNearCallPreservationStats8616(1, 1, 1, 0, 1),
    )


def _call_steps_8616(
    project: object, boundary: ExactFunctionRangeBoundary8616,
    bundle: RawIRFunctionImportBundle8616, context: NativeNearCallEntry8616,
    resolver: DirectCallTargetResolver8616,
) -> tuple[ConditionalNearCallPreservation8616, ...] | NearCallEntryPipelineFailure8616:
    """Prove all raw CALLs using exact native indexed word-E8 coordinates."""
    indexed = decoded_callsite_index_for_boundary_8616(
        project, boundary, direct_target_resolver=resolver,
    )
    decoded = _decoded_instruction_map_8616(boundary)
    census: list[_CensusCall8616] = []
    with _resolution_scope_8616(project, resolver, None) as resolution:
        for block in bundle.artifact.blocks:
            for instruction in block.instrs:
                if instruction.op != "CALL":
                    continue
                if direct_evidence_deadline_expired_8616(project):
                    return NearCallEntryPipelineFailure8616.BUDGET_EXPIRED
                if type(instruction.addr) is not int:
                    return NearCallEntryPipelineFailure8616.CALL_CENSUS_UNPROVED
                row = _decoded_entry_for_callsite_8616(
                    indexed.index, boundary, decoded, instruction.addr, resolver,
                )
                coordinates = None if row is None else row.bound_near_coordinates(boundary)
                if coordinates is None:
                    return NearCallEntryPipelineFailure8616.CALL_CENSUS_UNPROVED
                census.append(_CensusCall8616(
                    block, instruction,
                    DirectNearCallCoordinates8616(instruction.addr, *coordinates),
                ))
        proved = prove_near_call_preservation_census_8616(
            project, tuple(census), artifact=bundle.artifact, context=context,
            direct_target_resolver=resolver, resolution=resolution,
        )
        if isinstance(proved, ConditionalNearCallPreservationFailure8616):
            return NearCallEntryPipelineFailure8616.CALL_PRESERVATION_UNPROVED
        return proved


def _bind_context_8616(
    project: object, boundary: ExactFunctionRangeBoundary8616,
    source: Real16InvocationSource8616,
) -> tuple[DecodedDirectCallsite8616, NativeNearCallEntry8616] | NearCallEntryPipelineFailure8616:
    """Bind precisely one indexed incoming native word CALL."""
    rows = _incoming_rows_8616(source, boundary.addr)
    if not rows:
        return NearCallEntryPipelineFailure8616.ENTRY_MISSING
    if len(rows) != 1:
        return NearCallEntryPipelineFailure8616.ENTRY_AMBIGUOUS
    premise = prove_near_call_frame_premise_8616(rows[0], source.callsite_index, boundary.addr)
    if premise is None:
        return NearCallEntryPipelineFailure8616.ENTRY_UNPROVED
    context = bind_native_near_call_entry_8616(
        project, boundary, premise, callsite_index=source.callsite_index,
    )
    if not isinstance(context, NativeNearCallEntry8616):
        return NearCallEntryPipelineFailure8616.ENTRY_UNPROVED
    return rows[0], context


def _prepare_8616(
    project: object, boundary: ExactFunctionRangeBoundary8616,
    bundle: RawIRFunctionImportBundle8616 | None,
) -> NearCallEntryPipelineResult8616:
    """Compose exact native owners within the caller's existing request budget."""
    source = _installed_source_8616(project)
    if source is None:
        return _refused_8616(NearCallEntryPipelineFailure8616.SOURCE_MISSING)
    if boundary.project is not project:
        return _refused_8616(NearCallEntryPipelineFailure8616.BOUNDARY_FOREIGN)
    if direct_evidence_deadline_expired_8616(project):
        return _refused_8616(NearCallEntryPipelineFailure8616.BUDGET_EXPIRED)
    bound = _bind_context_8616(project, boundary, source)
    if isinstance(bound, NearCallEntryPipelineFailure8616):
        return _refused_8616(bound)
    incoming, context = bound
    current = (raw_x86_16_function_bundle_8616(project, boundary) if bundle is None
               else raw_x86_16_import_bundle_for_artifact_8616(project, boundary, bundle.artifact))
    if current is None:
        return _refused_8616(NearCallEntryPipelineFailure8616.RAW_SOURCE_CHANGED)
    resolver = cast(DirectCallTargetResolver8616, _premise_target_resolver_8616(project))
    steps = _call_steps_8616(project, boundary, current, context, resolver)
    if isinstance(steps, NearCallEntryPipelineFailure8616):
        return _refused_8616(steps)
    scope = NearCallJumpScope8616(project, current.artifact, context, resolver, steps)
    view = prove_scoped_x86_16_ir_function_view_8616(project, current, boundary, near_call_scope=scope)
    if view.failure is not None:
        return _refused_8616(NearCallEntryPipelineFailure8616.VIEW_UNPROVED)
    entry = NativeNearCallPipeline8616(source, current, scope, view, incoming)
    if not entry._source_current(project):
        return _refused_8616(NearCallEntryPipelineFailure8616.SOURCE_CHANGED)
    if direct_evidence_deadline_expired_8616(project):
        return _refused_8616(NearCallEntryPipelineFailure8616.BUDGET_EXPIRED)
    return NearCallEntryPipelineResult8616(
        NearCallEntryPipelineStatus8616.CONDITIONAL, None, entry,
        ConditionalNearCallPreservationStats8616(1, 1, 1, 1, 0),
    )


def prepare_near_call_entry_pipeline_8616(
    project: object, boundary: ExactFunctionRangeBoundary8616, *,
    bundle: RawIRFunctionImportBundle8616 | None = None,
) -> NearCallEntryPipelineResult8616:
    """Prepare one private input from installed native inventory, without boot intake.

    A unique incoming near CALL is required; multiple contexts remain ambiguous.
    Every outgoing CALL must close through the existing conditional target and
    universal-callee preservation owners. The supplied raw artifact identity is
    retained after native rebind. No result is registered or attached to codegen.
    """
    if not isinstance(boundary, ExactFunctionRangeBoundary8616):
        raise TypeError("near-call pipeline requires an exact native boundary")
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
        return _prepare_8616(project, boundary, bundle)
