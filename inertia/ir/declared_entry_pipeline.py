"""Layer: IR.
Responsibility: consume explicit entry premises at initial pipeline attachment.

The project intake remains the only declaration registry. Codegen retains the
identical raw surface and consumed scope; conditional bodies are never published.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Protocol, cast

from inertia.frontend.x86_16.declared_function_entry import DeclaredFunctionEntryAdmission8616
from inertia.frontend.x86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
    exact_function_range_boundary_8616,
)
from inertia.pipeline.errors import PipelineHardError

from .declared_selector_call_preservation import collect_declared_selector_call_preservations_8616
from .declared_selector_invariant import (
    DeclaredSegmentInvariant,
    InvariantStatus,
    prove_declared_selector_invariant_8616,
)
from .entry_domain_call_preservation import (
    Real16InvocationSource8616,
    _function_entry_for_head_8616,
)
from .native_import_surface_cache import native_import_request_8616
from .near_call_entry_pipeline import NativeNearCallPipeline8616
from .real16_invocation_domain import (
    DeclaredFunctionEntryLink8616,
    Real16InvocationDomain8616,
    prove_fresh_real16_declared_function_entry_domain_8616,
    real16_native_census_import_8616,
)
from .scoped_function_ir_view import ScopedFunctionIRView8616
from .segment_call_preservation import (
    declared_entry_dependency_traversal_scope_8616,
    segment_call_dependency_traversal_scope_8616,
)
from .segment_state import apply_x86_16_segment_state_artifact

if TYPE_CHECKING:
    from .entry_domain_call_preservation import EntryDomainCallPreservation8616
    from .vex_import import RawIRFunctionImportBundle8616


class DeclaredEntryPremise8616(Enum):
    """Premise status of a consumed declared entry input.

    ``PROVEN_CONDITIONAL`` marks the proven scoped record;
    ``UNKNOWN_REFUSE`` marks a valid declaration whose entry-domain proof
    could not produce a scope — the authenticated raw graph is retained and
    consumed through the ordinary unscoped branches, with no premise
    authority inferred or published.
    """

    PROVEN_CONDITIONAL = "proven_conditional"
    UNKNOWN_REFUSE = "unknown_refuse"


@dataclass(frozen=True, slots=True)
class DeclaredEntryPipeline8616:
    """One codegen's source-bound, explicitly conditional initial IR input."""

    source: Real16InvocationSource8616
    admission: DeclaredFunctionEntryAdmission8616
    bundle: RawIRFunctionImportBundle8616
    scope: Real16InvocationDomain8616
    view: ScopedFunctionIRView8616
    selector_scope: DeclaredSegmentInvariant | None = None
    premise: DeclaredEntryPremise8616 = field(
        default=DeclaredEntryPremise8616.PROVEN_CONDITIONAL, init=False
    )


@dataclass(frozen=True, slots=True)
class UnprovedDeclaredEntry8616:
    """Authenticated raw declared input whose entry premise is unproved.

    ``bundle`` anchors the identical authenticated raw artifact — every
    original block, instruction, CALL identity, and typed refusal — and
    ``view`` is the scoped-view proof's own typed refusal record, kept as
    visible non-proof diagnostic. Nothing here mints a scope, publishes the
    artifact, or claims completeness: consumers dispatch to the existing
    ordinary unscoped branches.
    """

    source: Real16InvocationSource8616
    admission: DeclaredFunctionEntryAdmission8616
    bundle: RawIRFunctionImportBundle8616
    view: ScopedFunctionIRView8616
    selector_scope: DeclaredSegmentInvariant | None = None
    premise: DeclaredEntryPremise8616 = field(
        default=DeclaredEntryPremise8616.UNKNOWN_REFUSE, init=False
    )


# Union of the canonical retained inputs: proven conditional record or the
# typed non-proof record carrying the identical authenticated raw surface.
type DeclaredEntryInput8616 = DeclaredEntryPipeline8616 | UnprovedDeclaredEntry8616 | NativeNearCallPipeline8616


class _CodegenEntryBoundary8616(Protocol):
    """Typed optional slot on the third-party codegen object."""

    _inertia_declared_entry_pipeline_8616: DeclaredEntryInput8616


class _ProjectSourceBoundary8616(Protocol):
    """Already installed invocation authority on the third-party project."""

    _inertia_real16_invocation_source_8616: Real16InvocationSource8616 | None


class _DeferredDeclarationBoundary8616(Protocol):
    """Optional explicit-entry intake fields at the third-party adapter boundary."""

    function_entries: tuple[DeclaredFunctionEntryAdmission8616, ...]

    def validate_installed_source_8616(
        self, project: object, source: Real16InvocationSource8616,
    ) -> bool:
        """Reauthenticate the installed source against the current request."""
        ...

    def install(self, project: object) -> None:
        """Install declaration-first authority without a startup inventory."""
        ...


def _declared_source_8616(project: object, function_addr: int) -> Real16InvocationSource8616 | None:
    """Peek installed/declaration-only authority without triggering boot intake."""
    try:
        source = cast(_ProjectSourceBoundary8616, project)._inertia_real16_invocation_source_8616
    except AttributeError:
        source = None
    if source is not None:
        if type(source) is not Real16InvocationSource8616:
            raise TypeError("installed invocation source must be typed")
        # Dynamic third-party project boundary: the CLI adapter supplies this request.
        request = getattr(project, "_inertia_mz_static_invocation_request_8616", None)
        if (request is not None and source.function_entries
                and not cast(_DeferredDeclarationBoundary8616, request).validate_installed_source_8616(project, source)):
            raise PipelineHardError("installed declared entry authority changed", layer="ir", function_addr=function_addr)
        return source
    # Dynamic boundary: the third-party project may lack a deferred CLI adapter.
    request = getattr(project, "_inertia_mz_static_invocation_request_8616", None)
    # Dynamic boundary: historical third-party adapters may lack declarations.
    entries = getattr(request, "function_entries", ())
    if type(entries) is not tuple or any(type(entry) is not DeclaredFunctionEntryAdmission8616 for entry in entries):
        raise TypeError("deferred function entries must be typed immutable admissions")
    if not any((entry.spec.entry_segment << 4) + entry.spec.entry_offset == function_addr for entry in entries):
        return None
    cast(_DeferredDeclarationBoundary8616, request).install(project)
    try:
        source = cast(_ProjectSourceBoundary8616, project)._inertia_real16_invocation_source_8616
    except AttributeError:
        source = None
    if type(source) is not Real16InvocationSource8616:
        raise PipelineHardError("declared entry intake did not install authority", layer="ir", function_addr=function_addr)
    return source


def _retained_input_8616(codegen: object) -> DeclaredEntryInput8616 | None:
    """Read a consumed pipeline input without manufacturing a project premise."""
    try:
        retained = cast(_CodegenEntryBoundary8616, codegen)._inertia_declared_entry_pipeline_8616
    except AttributeError:
        return None
    if type(retained) not in (DeclaredEntryPipeline8616, UnprovedDeclaredEntry8616, NativeNearCallPipeline8616):
        raise TypeError("declared entry pipeline input must be typed")
    return retained


def _retained_native_entry_for_8616(
    project: object, codegen: object, function_addr: int,
) -> NativeNearCallPipeline8616 | None:
    """Validate a retained native entry's source membership without proof.

    The deferred-declaration source is revalidated — including the
    request's ``validate_installed_source_8616`` check — the requested
    head must equal the retained raw bundle's root, the retained entry's
    own source-only currency predicate ``_source_current`` must hold
    (membership evidence, never the ``authenticates`` replay), and the
    retained scope/view/bundle identity chain must be exact. ``None``
    means no retained native entry applies — the ordinary full prepare
    route owns every other case; stale or foreign identities are a hard
    error, never a silent fallback. This selector grants no proof
    authority: the canonical full consume stays with the call-Semantics
    consumer.
    """
    retained = _retained_input_8616(codegen)
    if not isinstance(retained, NativeNearCallPipeline8616):
        return None
    source = _declared_source_8616(project, function_addr)
    if not _retained_native_entry_current_8616(
        project, source, function_addr, retained,
    ):
        raise PipelineHardError("consumed native entry changed", layer="ir",
                                function_addr=function_addr)
    return retained


def _retained_native_entry_current_8616(
    project: object, source: Real16InvocationSource8616 | None, function_addr: int,
    retained: NativeNearCallPipeline8616,
) -> bool:
    """Cheap source/identity membership for a retained native entry."""
    return (
        source is not None
        and retained.source is source
        and retained.bundle.artifact.function_addr == function_addr
        and retained.scope.project is project
        and retained.view.source_artifact is retained.bundle.artifact
        and retained.scope.artifact is retained.bundle.artifact
        and retained.view.near_call_scope is retained.scope
        and retained._source_current(project)
    )


def prepare_declared_entry_pipeline_8616(
    project: object, codegen: object, function_addr: int,
) -> DeclaredEntryInput8616 | None:
    """Resolve an explicit entry before universal IR import or publication."""
    source = _declared_source_8616(project, function_addr)
    admission = None if source is None else _function_entry_for_head_8616(source, function_addr)
    retained = _retained_input_8616(codegen)
    if isinstance(retained, NativeNearCallPipeline8616):
        if (retained.bundle.artifact.function_addr != function_addr
                or not retained.authenticates(project)):
            raise PipelineHardError("consumed native entry changed", layer="ir", function_addr=function_addr)
        return retained
    if retained is not None:
        if retained.source is not source or retained.admission is not admission:
            raise PipelineHardError("consumed function entry declaration changed", layer="ir", function_addr=function_addr)
        return retained
    if admission is None or source is None:
        return _prepare_pending_native_entry_8616(project, source, function_addr)
    with native_import_request_8616(), declared_entry_dependency_traversal_scope_8616():
        return _prepare_native_entry_8616(project, source, admission)


def _prepare_pending_native_entry_8616(
    project: object, source: Real16InvocationSource8616 | None, function_addr: int,
) -> NativeNearCallPipeline8616 | None:
    """Use indexed native entry only for unresolved selector-dependent control.

    Already ordinary bodies keep their universal route. Deferred native intake
    is demanded only after a recovered body exposes pending selector control;
    this collects lookup facts, never a startup reachability theorem.
    """
    from .entry_domain_call_preservation import _exact_boundary_for_8616, _invocation_premise_source_8616
    from .function_ssa_registry import function_boundary_at_address_8616
    from .near_call_entry_pipeline import prepare_near_call_entry_pipeline_8616
    from .vex_import import raw_x86_16_function_bundle_8616
    from .vex_terminal_jump import TerminalJumpRefusalReason8616

    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
        if source is None:
            recovered = function_boundary_at_address_8616(project, function_addr)
            if recovered is None:
                return None
            pending = raw_x86_16_function_bundle_8616(project, recovered)
            if not any(evidence.failure is TerminalJumpRefusalReason8616.SELECTOR_WINDOW_UNPROVED
                       for evidence in pending.terminal_evidence.values()):
                return None
            source = _invocation_premise_source_8616(project)
        if source is None or not source.callsite_index.for_target(function_addr):
            return None
        boundary = _exact_boundary_for_8616(project, function_addr)
        if boundary is None:
            return None
        bundle = raw_x86_16_function_bundle_8616(project, boundary)
        if not any(evidence.failure is TerminalJumpRefusalReason8616.SELECTOR_WINDOW_UNPROVED
                   for evidence in bundle.terminal_evidence.values()):
            return None
        if _universal_pending_control_complete_8616(project, bundle):
            return None
        result = prepare_near_call_entry_pipeline_8616(project, boundary, bundle=bundle)
        if result.entry is None:
            raise PipelineHardError("native entry scoped CFG is unproved", layer="ir",
                                    function_addr=function_addr, details=result.to_dict())
        return result.entry



def _universal_pending_control_complete_8616(
    project: object, bundle: RawIRFunctionImportBundle8616,
) -> bool:
    """Keep native root-fetch discharge ahead of conditional caller selection.

    Raw selector-dependent terminals are candidates, not evidence that a caller
    premise is necessary. The canonical universal owner checks native encoding,
    reachable control and unchanged entry CS before admitting every candidate.
    No conditional scope, incoming caller or callee effect is supplied here.
    """
    from .entry_jump_domain import (
        EntryJumpDomainApplicationStatus8616,
        apply_entry_jump_domain_8616,
        collect_pending_terminal_jumps_8616,
        prove_entry_jump_domains_8616,
    )

    pending = collect_pending_terminal_jumps_8616(bundle.terminal_evidence)
    proof = prove_entry_jump_domains_8616(
        bundle.artifact, bundle.terminal_evidence, project=project)
    if not pending or proof.stats.failure_count or len(proof.admitted) != len(pending):
        return False
    application = apply_entry_jump_domain_8616(bundle.artifact, proof)
    return (application.status is EntryJumpDomainApplicationStatus8616.APPLIED
            and not application.refusals and len(application.applied) == len(pending))


def _prepare_native_entry_8616(
    project: object, source: Real16InvocationSource8616, admission: DeclaredFunctionEntryAdmission8616,
) -> DeclaredEntryInput8616:
    """Prove the declared head and scoped raw CFG without traversing startup."""
    from .vex_import import (
        prove_scoped_x86_16_ir_function_view_8616,
        raw_x86_16_import_bundle_for_artifact_8616,
    )

    spec = admission.spec
    if (spec.entry_segment << 4) + spec.entry_offset != spec.range_start:
        raise PipelineHardError("initial pipeline requires a declared function-head entry", layer="ir",
                                function_addr=(spec.entry_segment << 4) + spec.entry_offset)
    boundary = exact_function_range_boundary_8616(project, spec.range_start, spec.range_end)
    artifact = None if boundary is None else real16_native_census_import_8616(project, boundary)
    if boundary is None or artifact is None:
        raise PipelineHardError("declared entry native surface is incomplete", layer="ir", function_addr=spec.range_start)
    link = DeclaredFunctionEntryLink8616(admission, artifact, boundary)
    selector_scope = None
    records: tuple[EntryDomainCallPreservation8616, ...] = ()
    needs_call_targets = any(
        instruction.op == "CALL" for block in artifact.blocks for instruction in block.instrs
    )
    if needs_call_targets or artifact.refusals or any(block.refusals for block in artifact.blocks):
        # A raw CALL can retain a symbolic CS-relative target without an IR
        # refusal. Request its existing bounded selector authority explicitly;
        # instruction presence alone never admits a target or callee effect.
        selector_scope = prove_declared_selector_invariant_8616(project, source, link)
        records = (collect_declared_selector_call_preservations_8616(project, selector_scope)
                   if selector_scope.status is InvariantStatus.PROVEN_CONDITIONAL else ())
    scope = prove_fresh_real16_declared_function_entry_domain_8616(
        project, link, spec.range_start,
        boot=source.boot, boot_recompute=source.boot_recompute, declared_services=source.declared_services,
        entry_call_preservations=records,
    )
    bundle = raw_x86_16_import_bundle_for_artifact_8616(project, boundary, artifact)
    if bundle is None:
        raise PipelineHardError("declared entry native surface changed", layer="ir", function_addr=spec.range_start)
    if scope is None:
        # A valid declaration whose optional premise proof produced no scope
        # keeps its authenticated raw graph under a typed non-proof record;
        # the scoped view with no consuming entry carries its own refusal.
        # A forged declaration or changed native surface also ends here —
        # reauthenticate the declaration before granting the unproved leg.
        if not _declared_entry_surface_current_8616(project, source, link, boundary):
            raise PipelineHardError("declared entry premise is unproved", layer="ir",
                                    function_addr=spec.range_start, details={"failure": None})
        view = prove_scoped_x86_16_ir_function_view_8616(project, bundle, boundary, invocation_scope=None)
        return UnprovedDeclaredEntry8616(source, admission, bundle, view, selector_scope)
    view = prove_scoped_x86_16_ir_function_view_8616(
        project, bundle, boundary, invocation_scope=scope,
        call_preservations=(records if selector_scope is not None
                            and selector_scope.status is InvariantStatus.PROVEN_CONDITIONAL else None),
    )
    if view.failure is not None:
        raise PipelineHardError("declared entry scoped CFG is unproved", layer="ir", function_addr=spec.range_start,
                                details={"failure": view.failure, "detail": view.detail})
    return DeclaredEntryPipeline8616(source, admission, bundle, scope, view, selector_scope)


def _declared_entry_surface_current_8616(
    project: object, source: Real16InvocationSource8616,
    link: DeclaredFunctionEntryLink8616, boundary: ExactFunctionRangeBoundary8616,
) -> bool:
    """Reauthenticate a declaration against current boot and mapped bytes.

    Mirrors the entry-domain proof's own admission currency gates using the
    same canonical APIs: the retained boot recomputes the declared module and
    environment digest, the admission revalidates against them, and the
    project must still map the declared module bytes over the exact declared
    boundary. Any forged spec or changed native image returns ``False`` so
    the caller keeps its hard error instead of minting an unproved record.
    """
    from inertia.frontend.x86_16.declared_function_entry import (
        DeclaredFunctionEntryAdmission8616 as _Admission8616,
    )
    from inertia.frontend.x86_16.declared_function_entry import (
        revalidate_declared_function_entry_8616,
    )

    from .real16_declared_interrupt8616 import declared_environment_digest_8616
    from .real16_invocation_domain import (
        _BootSurface8616,
        _loaded_bytes_8616,
        _recompute_boot_8616,
    )

    if type(link.admission) is not _Admission8616:
        return False
    if _recompute_boot_8616(source.boot, source.boot_recompute) is not None:
        return False
    boot = cast(_BootSurface8616, source.boot)
    chunks = boot.image.chunks
    if len(chunks) != 1 or chunks[0][0] != boot.image.load_segment << 4:
        return False
    base, module = chunks[0]
    environment_digest = declared_environment_digest_8616(boot.environment)
    spec = link.admission.spec
    return bool(
        environment_digest is not None
        and revalidate_declared_function_entry_8616(
            link.admission, source=boot.source, loaded_module=module,
            environment_sha256=environment_digest,
        )
        and _loaded_bytes_8616(project, base, len(module)) == module
        and spec.load_segment == boot.image.load_segment
        and spec.range_start == boundary.addr
        and spec.range_end == boundary.addr + boundary.size
    )


def retain_declared_entry_pipeline_8616(codegen: object, entry: DeclaredEntryInput8616) -> None:
    """Retain a typed input for this consumer, without granting proof authority.

    Clinic may hand the identical input to a fresh codegen before raw IR
    attachment. Preparation authenticates it before semantic consumption;
    retaining the pointer neither installs IR nor authenticates native bytes.
    """
    cast(_CodegenEntryBoundary8616, codegen)._inertia_declared_entry_pipeline_8616 = entry


def apply_pipeline_segment_state_8616(project: object, codegen: object) -> bool:
    """Consume prepared initial entry evidence; preserve normal unscoped refreshes."""
    entry = _retained_input_8616(codegen)
    if entry is None:
        return bool(apply_x86_16_segment_state_artifact(project, codegen))
    if type(entry) is NativeNearCallPipeline8616:
        native_entry = entry
        try:
            return bool(apply_x86_16_segment_state_artifact(
                project, codegen, near_call_scope=native_entry.scope, scoped_view=native_entry.view,
            ))
        except ValueError as error:
            raise PipelineHardError("native entry segment-state binding refused", layer="ir",
                                    function_addr=entry.bundle.artifact.function_addr) from error
    if type(entry) is not DeclaredEntryPipeline8616:
        # An unproved declared entry carries no premise authority: consume
        # the identical raw artifact through the ordinary unscoped refresh,
        # keeping the same accounted failure route as the proven binding.
        try:
            return bool(apply_x86_16_segment_state_artifact(project, codegen))
        except ValueError as error:
            raise PipelineHardError("declared entry segment-state binding refused", layer="ir",
                                    function_addr=entry.bundle.artifact.function_addr) from error
    try:
        return bool(apply_x86_16_segment_state_artifact(
            project, codegen, invocation_scope=entry.scope, scoped_view=entry.view,
        ))
    except ValueError as error:
        # The owned attachment API uses ValueError for stale/foreign binding;
        # preserve its cause through the pipeline's accounted failure route.
        raise PipelineHardError("declared entry segment-state binding refused", layer="ir",
                                function_addr=entry.bundle.artifact.function_addr) from error
