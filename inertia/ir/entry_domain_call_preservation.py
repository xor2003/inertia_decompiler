"""Importer-time direct-CALL CS-preservation evidence for the entry-domain proof.

Layer: IR.
Responsibility: bind one reachable CALL inside a not-yet-registered in-flight
caller artifact to exact source-bound evidence so the entry-jump-domain proof
may retain ``cs`` identity across the call boundary. The caller side binds by
exact artifact, block, and instruction object identity plus the caller's exact
frontend boundary — an in-flight artifact cannot produce
``IRBoundaryCoverageResult8616`` for itself because the registry publication
finishes only after this proof runs. Every other obligation reuses the
existing owners unchanged: the decoded direct-callsite index, the
Semantics-owned symbolic operand binding (or an exact full-width CONST
operand), the registered callee artifact's boundary coverage, and the callee
segment-effect closure whose retained state census admits a non-leaf callee
only when every nested callsite carries one bound complete
``SegmentCallPreservationResult8616``. Calls lacking the whole chain keep the
default CALL_ON_PATH refusal; nothing here guesses targets, repairs operands,
or infers return behavior.

A universal request (``invocation_scope=None``) keeps the registry/publishing
callee route unchanged. A scoped request first authenticates its consuming
entry and the exact surface that entry owns: a coverage-bound entry binds the
identical registered artifact, while a chain-bound entry owns an in-flight raw
surface resolved only through the frozen scoped owners — raw bundle import,
scoped view, scoped coverage — and never through the publishing importer. The
identical entry is carried into every nested CALL proof as a per-callsite
premise re-derived by the source-bound premise owner, and conditional results
stay in the scope-keyed pool, never the universal caches.
Owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import StrEnum
from functools import partial
from typing import TYPE_CHECKING, Protocol, cast

from capstone import CS_ERR_DETAIL, CsError

from inertia.frontend.x86_16.frontend_boundary_transport import (
    capture_function_boundary_8616,
    restore_function_boundary_8616,
)
from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
    DecodedDirectCallsiteIndex8616,
    DecodedDirectCallsiteIndexStats8616,
    DecodedFarCallTarget8616,
    DirectCallTargetResolver8616,
    decoded_callsite_index_for_boundary_8616,
    registered_decoded_callsite_index_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
    mapped_entry_function_boundary_8616,
)
from inertia.frontend.x86_16.frontend_local_call_evidence import local_call_frame_evidence_8616
from inertia.frontend.x86_16.frontend_near_return_continuation import (
    NearCallFramePremise8616,
    prove_near_call_frame_premise_8616,
)

from .core import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace, SegmentOrigin
from .direct_evidence_deadline import (
    active_direct_evidence_deadline_8616 as _owner_active_direct_evidence_deadline_8616,
)
from .direct_evidence_deadline import (
    deadline_reached_8616,
    direct_evidence_deadline_scope_8616,
)
from .direct_evidence_deadline import (
    direct_evidence_deadline_expired_8616 as _owner_direct_evidence_deadline_expired_8616,
)
from .function_ir_registry import (
    FunctionIRArtifactFailure8616,
    FunctionIRArtifactVerdict8616,
    publish_function_ir_artifact_8616,
    registered_function_ir_artifact_8616,
)
from .ir_boundary_cfg import (
    IRBoundaryCoverageResult8616,
    prove_ir_boundary_coverage_8616,
    prove_scoped_ir_boundary_coverage_8616,
)
from .near_return_continuation_view import (
    NEAR_RETURN_CONTINUATION_PENDING_KIND_8616,
    prove_scoped_near_return_continuation_view_8616,
)
from .real16_declared_interrupt8616 import DeclaredInterruptService8616
from .segment_call_preservation import (
    SegmentCallPreservationFailure8616,
    SegmentCallPreservationResult8616,
    prove_segment_call_preservation_8616,
    segment_call_dependency_traversal_scope_8616,
)
from .segment_effect_closure import (
    SegmentEffectClosureResult8616,
    prove_segment_effect_closure_8616,
)
from .segment_state import build_x86_16_segment_state_artifact
from .segment_state_transfer import SEGMENT_REGISTERS

if TYPE_CHECKING:
    from inertia.semantics.direct_near_call_target_binding import (
        DirectNearCallTargetBinding8616,
    )

    from .near_return_continuation_view import ScopedNearReturnContinuationView8616
    from .real16_invocation_domain import Real16InvocationDomain8616
    from .scoped_function_ir_view import ScopedFunctionIRView8616

__all__ = [
    "EntryDomainCallPreservation8616",
    "EntryDomainCallPreservationFailure8616",
    "Real16InvocationSource8616",
    "collect_entry_domain_call_preservations_8616",
    "direct_evidence_deadline_expired_8616",
    "direct_evidence_deadline_scope_8616",
    "entry_domain_caller_boundary_8616",
    "entry_domain_invocation_premise_8616",
    "install_real16_invocation_source_8616",
    "prove_entry_domain_call_preservation_8616",
]

_CS_REGISTER_8616 = "cs"

# Deterministic recursion bounds for nested-callee closure resolution. The
# census traversal the proofs themselves consume is owned and bounded by
# ``segment_call_preservation``; these bounds only govern how many distinct
# callee closures this owner resolves while assembling one caller's evidence.
_ENTRY_DOMAIN_CALLEE_MAX_DEPTH_8616 = 16
_ENTRY_DOMAIN_CALLEE_MAX_RESOLUTIONS_8616 = 64

# Upper bound on the padding prefix between an encoded call target and the
# resolver's canonical callee identity. The window is re-verified byte by
# byte on every consumption, never inherited as a claim.
_CALL_PADDING_WINDOW_MAX_8616 = 0x100

# Deterministic recursion bounds for caller-domain premise resolution. One
# premise chain may recurse through boot, chained, and enclosed-entry
# parents; ``_ENTRY_PREMISE_MAX_DEPTH_8616`` bounds the chain length (same
# magnitude as the domain's replay bound) and
# ``_ENTRY_PREMISE_MAX_RESOLUTIONS_8616`` bounds the aggregate registered
# functions examined across one request tree.
_ENTRY_PREMISE_MAX_DEPTH_8616 = 16
_ENTRY_PREMISE_MAX_RESOLUTIONS_8616 = 64


class EntryDomainCallPreservationFailure8616(StrEnum):
    """Typed reasons an in-flight caller CALL cannot carry CS preservation."""

    CALLER_BINDING_MISMATCH = "entry_domain_call_caller_binding_mismatch"
    CALLSITE_UNPROVEN = "entry_domain_call_callsite_unproven"
    TARGET_MISMATCH = "entry_domain_call_target_mismatch"
    CALLEE_UNRESOLVED = "entry_domain_call_callee_unresolved"
    CALLEE_INCOMPLETE = "entry_domain_call_callee_incomplete"
    DEPENDENCY_UNPROVEN = "entry_domain_call_dependency_unproven"
    BUDGET_EXHAUSTED = "entry_domain_call_budget_exhausted"
    CS_NOT_PRESERVED = "entry_domain_call_cs_not_preserved"
    ACCOUNTING_INCOMPLETE = "entry_domain_call_accounting_incomplete"


class _DecodedCallsiteInstruction8616(Protocol):
    """Third-party decoded instruction surface consumed for callsite lookup."""

    address: object


class _CalleeImportSurface8616(Protocol):
    """Project-owned in-flight marker for importer-time callee imports.

    An on-demand callee import re-enters ``build_x86_16_ir_function_artifact``
    while the caller artifact is still in flight; the marker set records which
    callee addresses are mid-import so a cyclic call chain refuses instead of
    recursing, and the depth counter bounds acyclic import nesting.
    """

    _inertia_entry_domain_callee_imports_8616: set[int]
    _inertia_entry_domain_callee_import_depth_8616: int


class _LoaderMemory8616(Protocol):
    """Third-party loader byte surface for the proven NOP-prefix window."""

    def load(self, addr: int, size: int) -> bytes:
        """Read mapped bytes at one linear coordinate."""
        ...


class _LoaderSurface8616(Protocol):
    """Third-party loader surface exposing the mapped byte view."""

    memory: _LoaderMemory8616


class _MappedProject8616(Protocol):
    """Project boundary consumed only for mapped byte verification."""

    loader: _LoaderSurface8616


class _DecodedBlock8616(Protocol):
    """Third-party block projection consumed only at the frontend boundary."""

    addr: int
    capstone: object


class _CapstoneDisassembly8616(Protocol):
    """Third-party decoded instruction sequence for one decoded block."""

    insns: tuple[object, ...]


@dataclass(slots=True)
class _CalleeResolution8616:
    """Bounded resolution session shared across one request's import tree.

    One root collection mints exactly one session; nested importer
    invocations join it through the project-owned slot instead of minting a
    fresh budget, so ``remaining`` bounds the aggregate resolutions spent
    across the whole call tree — siblings, failed imports, and nested
    collections included. A direct-address caller may attach its existing
    absolute deadline; nested imports inherit the same timestamp.
    """

    resolver: DirectCallTargetResolver8616
    in_flight: frozenset[int] = frozenset()
    remaining: int = _ENTRY_DOMAIN_CALLEE_MAX_RESOLUTIONS_8616
    deadline: float | None = None
    # Retained per-callee callsite proofs keyed by the resolved callee head.
    # Each entry is populated only after that callee's whole closure proved
    # complete, so a reused record is closed acyclic dependency evidence —
    # never a partial or still-in-flight claim. Reuse binds the identical
    # artifact object the registry-first resolution returns, so unregistered
    # in-flight artifacts can never collide across separate imports.
    retained: dict[
        int,
        tuple[IRFunctionArtifact, tuple[SegmentCallPreservationResult8616, ...]],
    ] = field(default_factory=dict)
    # Retained complete callee closures keyed by callee head. A closure is
    # callsite-independent complete evidence (coverage + state + census);
    # retaining it collapses the repeated transitive resolution of a shared
    # callee across every callsite in the session. Populated only after
    # ``closure.complete``, so in-flight and cyclic entries never appear.
    retained_closures: dict[int, SegmentEffectClosureResult8616] = field(
        default_factory=dict
    )
    scoped_closures: dict[tuple[int, int], SegmentEffectClosureResult8616] = field(default_factory=dict)


class _CalleeResolutionSurface8616(Protocol):
    """Project-owned slot carrying the active request resolution session."""

    _inertia_entry_domain_call_resolution_8616: object


@dataclass(slots=True)
class _PremiseResolution8616:
    """Bounded resolution session shared across one premise request tree.

    One root collection or standalone premise request mints one session; nested premise
    resolutions reached through record collection re-entries join it
    through the project-owned slot instead of minting a fresh budget, so
    ``remaining`` bounds the aggregate registered-head resolutions spent
    across the whole recursion — enclosing-surface retries included.
    ``in_flight`` records the head identities currently being resolved so
    a cyclic caller graph refuses instead of recursing without bound. A
    direct request's absolute deadline is inherited by this same session.
    """

    in_flight: frozenset[int] = frozenset()
    remaining: int = _ENTRY_PREMISE_MAX_RESOLUTIONS_8616
    deadline: float | None = None


class _PremiseResolutionSurface8616(Protocol):
    """Project-owned slot carrying the active premise resolution session."""

    _inertia_entry_domain_premise_resolution_8616: object


@dataclass(frozen=True, slots=True)
class EntryDomainCallPreservation8616:
    """Bound CS-preservation evidence for one in-flight caller callsite.

    The retained chain is the whole certificate: consumption revalidates it
    end to end instead of trusting this record's verdict. ``artifact``,
    ``block``, and ``instruction`` are exact object identities into the
    caller surface the entry-domain proof consumes; ``entry`` is the decoded
    native callsite index entry; ``binding`` is the Semantics-owned symbolic
    operand binding when the operand is not an exact full-width constant;
    ``callee`` is the callee's complete segment-effect closure over the
    registered artifact and closed boundary coverage.
    """

    artifact: IRFunctionArtifact
    boundary: ExactFunctionRangeBoundary8616
    block: IRBlock
    instruction: IRInstr
    index: DecodedDirectCallsiteIndex8616
    entry: DecodedDirectCallsite8616 | None
    callee: SegmentEffectClosureResult8616 | None
    binding: DirectNearCallTargetBinding8616 | None
    callsite_addr: int
    target_addr: int | None
    failure: EntryDomainCallPreservationFailure8616 | None
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    invocation_scope: Real16InvocationDomain8616 | None = None

    @property
    def required_scope(self) -> Real16InvocationDomain8616 | None:
        """Return the entry scope a consumer must authenticate, or ``None``.

        Conditional evidence names exactly one required entry provenance:
        the explicitly retained ``invocation_scope`` wins; otherwise the
        caller-domain premise the Semantics binding consumed to discharge
        this callsite's target. A ``None`` result is universal evidence.
        """
        required = self.invocation_scope
        if required is None and self.binding is not None and self.binding.invocation is not None:
            required = self.binding.invocation.premise
        return required

    @property
    def complete(self) -> bool:
        """Revalidate the retained evidence chain under one bounded traversal."""
        return self.complete_for(None)

    def complete_for(self, invocation_scope: Real16InvocationDomain8616 | None) -> bool:
        """Consume conditional preservation only under its authenticated entry."""
        from .real16_invocation_domain import same_real16_entry_scope_8616

        with segment_call_dependency_traversal_scope_8616():
            required = self.required_scope
            if required is not None and not same_real16_entry_scope_8616(invocation_scope, required):
                return False
            return _preservation_failure_8616(self) is None

    @property
    def preserved_registers(self) -> tuple[str, ...]:
        """Project segment identities shared by callee entry and all RET exits."""
        return self.preserved_registers_for(None)

    def preserved_registers_for(
        self, invocation_scope: Real16InvocationDomain8616 | None,
    ) -> tuple[str, ...]:
        """Project retained effects under the separately authenticated domain."""
        if not self.complete_for(invocation_scope):
            return ()
        return _callee_preserved_registers_8616(self.callee)

    def to_dict(self) -> dict[str, object]:
        """Serialize the callsite evidence record for diagnostics."""
        return {
            "callsite_addr": self.callsite_addr,
            "target_addr": self.target_addr,
            "block_addr": self.block.addr,
            "failure": None if self.failure is None else self.failure.value,
            "preserved_registers": list(self.preserved_registers),
            "complete": self.complete,
        }


def _encoded_near_target_8616(
    entry: DecodedDirectCallsite8616,
) -> tuple[int, int] | None:
    """Recover the encoded continuation and raw target from retained bytes.

    The index entry's ``target_addr`` is the canonical caller-entry identity;
    the machine encoding is the proof source. Only the unprefixed word-E8
    ``E8 rel16`` form is decoded — the same form the Semantics binding owner
    requires — so prefixed or foreign encodings yield ``None`` and the
    callsite stays refused rather than guessing a coordinate.
    """
    return entry.encoded_near_coordinates()


def _mapped_bytes_8616(project: object, addr: int, size: int) -> bytes | None:
    """Load exactly ``size`` mapped bytes or ``None`` for an unmapped span."""
    try:
        memory = cast(_MappedProject8616, project).loader.memory
        raw = memory.load(addr, size)
    except (AttributeError, KeyError, TypeError):
        return None
    data = bytes(raw)
    return data if len(data) == size else None


def _callsite_window_8616(
    project: object, entry: DecodedDirectCallsite8616,
) -> tuple[int, int, tuple[int, ...]] | None:
    """Recompute the proven callee coordinates for one decoded callsite.

    Returns ``(next_addr, raw_target, candidates)``: the encoded continuation
    and full-width raw target recovered from the entry's retained native
    bytes, plus the ordered callee addresses that may carry the proven
    artifact. The canonical resolver target is tried first — it matches the
    identity the contract stage binds — and is admitted only when the
    executed prefix between raw and canonical is a proven single-byte-NOP
    window, the same standard ``CallerEntryIdentity8616`` enforces; padding
    bytes that trap or write state are not evidence. The raw encoding target
    always remains a candidate because its artifact decodes the exact bytes
    the call lands on, prefix included.
    """
    encoded = _encoded_near_target_8616(entry)
    canonical = entry.target_addr
    if encoded is None or type(canonical) is not int or canonical < 0:
        return None
    next_addr, raw_target = encoded
    if raw_target == canonical:
        return next_addr, raw_target, (raw_target,)
    window = canonical - raw_target
    if not 0 < window <= _CALL_PADDING_WINDOW_MAX_8616:
        return next_addr, raw_target, (raw_target,)
    prefix = _mapped_bytes_8616(project, raw_target, window)
    if prefix is not None and all(byte == 0x90 for byte in prefix):
        return next_addr, raw_target, (canonical, raw_target)
    return next_addr, raw_target, (raw_target,)


def _callee_imports_in_flight_8616(project: object) -> set[int]:
    """Return the project-owned set of in-flight on-demand callee imports."""
    surface = cast(_CalleeImportSurface8616, project)
    try:
        imports = surface._inertia_entry_domain_callee_imports_8616
    except AttributeError:
        imports = set()
        surface._inertia_entry_domain_callee_imports_8616 = imports
    if not isinstance(imports, set):
        raise TypeError("entry-domain callee import marker must be a set")
    return imports


def _callee_import_depth_8616(project: object) -> int:
    """Return the project-owned depth of nested on-demand callee imports."""
    surface = cast(_CalleeImportSurface8616, project)
    try:
        depth = surface._inertia_entry_domain_callee_import_depth_8616
    except AttributeError:
        depth = 0
        surface._inertia_entry_domain_callee_import_depth_8616 = depth
    if type(depth) is not int:
        raise TypeError("entry-domain callee import depth must be an int")
    return depth


def _active_resolution_8616(project: object) -> _CalleeResolution8616 | None:
    """Return the in-flight request resolution session, if one is running."""
    surface = cast(_CalleeResolutionSurface8616, project)
    try:
        resolution = surface._inertia_entry_domain_call_resolution_8616
    except AttributeError:
        return None
    if resolution is not None and type(resolution) is not _CalleeResolution8616:
        raise TypeError("entry-domain call resolution must be a typed session")
    return resolution


def _active_premise_resolution_8616(
    project: object,
) -> _PremiseResolution8616 | None:
    """Return the in-flight premise resolution session, if one is running."""
    surface = cast(_PremiseResolutionSurface8616, project)
    try:
        resolution = surface._inertia_entry_domain_premise_resolution_8616
    except AttributeError:
        return None
    if resolution is not None and type(resolution) is not _PremiseResolution8616:
        raise TypeError("entry-domain premise resolution must be a typed session")
    return resolution


def _active_direct_evidence_deadline_8616(project: object) -> float | None:
    """Return the owner-computed deadline after validating active IR sessions."""
    _active_resolution_8616(project)
    _active_premise_resolution_8616(project)
    return _owner_active_direct_evidence_deadline_8616(project)


def direct_evidence_deadline_expired_8616(project: object) -> bool:
    """Return whether the shared direct-evidence deadline has elapsed."""
    _active_direct_evidence_deadline_8616(project)
    return _owner_direct_evidence_deadline_expired_8616(project)


def _resolution_deadline_expired_8616(
    project: object,
    deadline: float | None,
) -> bool:
    """Honor both a standalone session deadline and the shared project minimum."""
    return deadline_reached_8616(deadline) or direct_evidence_deadline_expired_8616(
        project
    )


@dataclass(frozen=True, slots=True)
class Real16InvocationSource8616:
    """Retained source authority for caller-domain premise construction.

    Installed on the project under
    ``_inertia_real16_invocation_source_8616`` by the caller that owns
    authentic MZ evidence (tests or the invocation-source owner). Fields:

    - ``boot`` — the retained source-bound boot object consumed by
      ``prove_real16_invocation_domain_8616``;
    - ``boot_recompute`` — the recompute authority that must reproduce an
      equal boot object before any derived number is believed;
    - ``callsite_index`` — the project-wide decoded direct-call index the
      parent-edge search consumes;
    - ``pending_targets`` — discovered call-target heads whose mapped
      boundary could not close when the index was built: typed
      obligations the consumer must keep unresolved, not silently treat
      as a closed corpus. Empty for a fully closed inventory.
    - ``declared_services`` — the explicitly declared interrupt-service
      relations bound to the declared environment this source's boot
      carries; empty for the static-header boot, which can never mint
      service authority. Every premise derived under this source
      propagates the identical tuple to its own census — conditional
      declared evidence, never a universal DOS model.
    """

    boot: object
    boot_recompute: Callable[[object], object] | None
    callsite_index: DecodedDirectCallsiteIndex8616
    pending_targets: tuple[int, ...] = ()
    declared_services: tuple[DeclaredInterruptService8616, ...] = ()


class _Real16InvocationSourceHolder8616(Protocol):
    """Project slot carrying the optional invocation-source surface."""

    _inertia_real16_invocation_source_8616: Real16InvocationSource8616 | None


class _PendingStaticIntake8616(Protocol):
    """Deferred intake record installed on the project by the CLI layer.

    Cross-layer contract: ``inertia_decompiler`` owns the concrete record
    (it holds the retained MZ bytes); this reader consumes only the typed
    ``install(project)`` seam, which authenticates the retained bytes
    against the current mapped image and either installs the source or
    returns a typed refusal receipt.
    """

    def install(self, project: object) -> object:
        """Attempt the deferred intake; install the source or refuse."""
        ...


def install_real16_invocation_source_8616(
    project: object,
    source: Real16InvocationSource8616 | None,
) -> None:
    """Install or clear the project's invocation-source surface.

    Only the exact typed record is accepted; ``None`` clears the slot so
    a failed collection never leaks a stale authority into later imports.
    """
    if source is not None and type(source) is not Real16InvocationSource8616:
        raise TypeError("invocation source must be a typed retained record")
    if source is not None and (
        type(source.callsite_index) is not DecodedDirectCallsiteIndex8616
        or source.boot is None
        or type(source.declared_services) is not tuple
        or not all(
            type(service) is DeclaredInterruptService8616
            for service in source.declared_services
        )
    ):
        raise TypeError("invocation source requires a bound index and boot")
    cast(_Real16InvocationSourceHolder8616, project)._inertia_real16_invocation_source_8616 = (
        source
    )


def _real16_invocation_source_8616(
    project: object,
) -> Real16InvocationSource8616 | None:
    """Return the project's retained invocation source, or ``None``.

    When the slot is empty, a deferred static-intake request the project
    loader retained (``_inertia_mz_static_invocation_request_8616``, the
    cross-layer CLI contract) is given exactly one demand attempt against
    the current mapped image before ``None`` is reported. The request slot
    is a dynamic boundary on the third-party angr project — an attribute
    populated by another layer — so it is probed with ``getattr`` and
    validated before use; a malformed record is a caller contract error
    and raises, never silently substitutes.
    """
    surface = cast(_Real16InvocationSourceHolder8616, project)
    try:
        source = surface._inertia_real16_invocation_source_8616
    except AttributeError:
        source = None
    if source is None:
        # Dynamic boundary: the deferred intake record is authored by the
        # CLI layer and lives on the project as a plain attribute, so the
        # slot probe cannot use a typed accessor — validate before use.
        pending = getattr(
            project, "_inertia_mz_static_invocation_request_8616", None
        )
        if pending is not None:
            # The project slot is dynamic; the retained request has an owned
            # protocol. Malformed requests fail loudly at this method call.
            cast(_PendingStaticIntake8616, pending).install(project)
            try:
                source = surface._inertia_real16_invocation_source_8616
            except AttributeError:
                return None
    if source is not None and type(source) is not Real16InvocationSource8616:
        raise TypeError("invocation source must be a typed retained record")
    return source


def _scoped_invocation_source_8616(
    project: object,
) -> Real16InvocationSource8616 | None:
    """Demand dependency-local invocation authority from retained intake.

    Consulted only when the project-wide source is absent — the bounded
    caller inventory refused before producing one — so the demanding
    premise can still be attempted against the retained closed-caller
    census bound to the identical authenticated MZ bytes. The minted
    record is returned to this consumer only: the project-wide slot
    stays empty, the refused inventory's typed ledger stays refused, and
    the record's ``pending_targets`` obligations remain visible. A
    request record without the seam offers no scoped authority and the
    demand refuses; a non-callable seam or a mistyped return is a caller
    contract error and raises, never silently substitutes.
    """
    # Dynamic boundary: third-party angr projects may lack the CLI adapter slot.
    pending = getattr(
        project, "_inertia_mz_static_invocation_request_8616", None
    )
    if pending is None:
        return None
    # Dynamic plugin boundary: a project-attached adapter may lack this optional seam.
    seam = getattr(pending, "scoped_invocation_source_8616", None)
    if seam is None:
        return None
    if not callable(seam):
        raise TypeError("scoped invocation source seam must be callable")
    source = seam(project)
    if source is None:
        return None
    if (
        type(source) is not Real16InvocationSource8616
        or type(source.callsite_index) is not DecodedDirectCallsiteIndex8616
        or source.boot is None
        or type(source.declared_services) is not tuple
        or not all(
            type(service) is DeclaredInterruptService8616
            for service in source.declared_services
        )
    ):
        raise TypeError("scoped invocation source must be a typed retained record")
    return source


def _invocation_premise_source_8616(
    project: object,
) -> Real16InvocationSource8616 | None:
    """Return the source authority a caller-domain premise may consume.

    The installed project-wide source always wins; only its absence —
    the bounded inventory's budget refusal — lets the retained deferred
    intake record offer dependency-local authority over exactly the
    authenticated closed-caller census. ``None`` means no source
    authority exists under either contract and the premise demand must
    keep its default refusal.
    """
    source = _real16_invocation_source_8616(project)
    if source is not None:
        return source
    return _scoped_invocation_source_8616(project)


def _premise_target_resolver_8616(project: object) -> object:
    """Return the shared decoded direct-target resolver for one project.

    Deferred import: the analysis owner sits outside this module's
    dependency fan-in, so it is resolved only when a premise actually
    needs to collect an enclosing or registered surface's call records.
    """
    from inertia.lowering.analysis_helpers import (
        resolve_direct_call_target_from_instruction_8616,
    )

    return partial(resolve_direct_call_target_from_instruction_8616, project)


def _surface_call_preservations_8616(
    project: object,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
) -> tuple[EntryDomainCallPreservation8616, ...]:
    """Collect in-flight callsite records bound to one census surface.

    The census consumes only records carrying the identical artifact,
    block, and instruction objects it simulates, so each distinct census
    surface — a registered head's own artifact or an imported enclosing
    artifact — must be collected on its own. Collection is bounded by the
    shared callee-resolution session and refuses empty on any defect.
    """
    if not any(
        instruction.op == "CALL"
        for block in artifact.blocks
        for instruction in block.instrs
    ):
        return ()
    return collect_entry_domain_call_preservations_8616(
        project,
        artifact,
        boundary,
        direct_target_resolver=cast(
            DirectCallTargetResolver8616, _premise_target_resolver_8616(project)
        ),
    )


def _enclosing_surface_8616(
    project: object, head_addr: int,
) -> tuple[
    ExactFunctionRangeBoundary8616,
    IRFunctionArtifact,
    tuple[EntryDomainCallPreservation8616, ...],
] | None:
    """Resolve the exact enclosing surface rooted at a decoded edge target.

    ``head_addr`` is the row's raw decoded ``target_addr`` — the address
    the machine encoding actually lands on. The boundary must root
    exactly there and the artifact must come through the guarded native
    census import so its blocks are the identical objects the census
    re-derivation binds; anything weaker is ``None``, never a guess.
    """
    from .real16_invocation_domain import real16_native_census_import_8616

    boundary = _exact_boundary_for_8616(project, head_addr)
    if boundary is None or boundary.addr != head_addr:
        return None
    artifact = real16_native_census_import_8616(project, boundary)
    if (
        type(artifact) is not IRFunctionArtifact
        or artifact.function_addr != head_addr
    ):
        return None
    return (
        boundary,
        artifact,
        _surface_call_preservations_8616(project, artifact, boundary),
    )


def _edge_invocation_premise_8616(
    project: object,
    source: Real16InvocationSource8616,
    row: DecodedDirectCallsite8616,
    callsite_addr: int,
    callee_artifact: IRFunctionArtifact,
    callee_boundary: ExactFunctionRangeBoundary8616,
    callee_coverage: IRBoundaryCoverageResult8616 | None,
    callee_records: tuple[EntryDomainCallPreservation8616, ...],
    resolution: _PremiseResolution8616,
) -> Real16InvocationDomain8616 | None:
    """Prove one transported premise for a decoded edge into a callee head.

    The row's raw decoded target selects the transport shape: an exact
    head hit is a ``CALL_CHAINED`` edge over the callee surface; any
    other raw target the index normalized to this head is an
    ``ENCLOSED_ENTRY`` edge whose census runs over the enclosing surface
    rooted at the raw target. The parent premise is resolved recursively
    through the same session; ``None`` is returned whenever any leg
    cannot be proved — never a partial premise.
    """
    encoded = row.encoded_near_coordinates()
    if encoded is None or row.caller_start == callee_artifact.function_addr:
        return None
    raw_target = encoded[1]
    parent = _registered_invocation_premise_8616(
        project, row.caller_start, row.callsite_addr, source, resolution
    )
    if (
        parent is None
        or parent.failure is not None
        or parent.coverage is None
        or not parent.callsite_call_state
    ):
        return None
    from .real16_invocation_domain import (
        Real16CallChainLink8616,
        Real16EnclosedEntryLink8616,
        prove_real16_chained_invocation_domain_8616,
        prove_real16_enclosed_invocation_domain_8616,
    )

    callsite_artifact = parent.coverage.artifact
    callsite_boundary = parent.coverage.boundary
    if raw_target == callee_artifact.function_addr:
        link: Real16CallChainLink8616 | Real16EnclosedEntryLink8616
        link = Real16CallChainLink8616(
            parent=parent,
            callsite_index=source.callsite_index,
            callsite=row,
            callsite_artifact=callsite_artifact,
            callsite_boundary=callsite_boundary,
            call_state=parent.callsite_call_state,
            callee_artifact=callee_artifact,
            callee_boundary=callee_boundary,
        )
        premise = prove_real16_chained_invocation_domain_8616(
            project,
            callee_coverage,
            callsite_addr,
            boot=source.boot,
            boot_recompute=source.boot_recompute,
            chain=link,
            entry_call_preservations=callee_records,
            declared_services=source.declared_services,
        )
    else:
        enclosing = _enclosing_surface_8616(project, raw_target)
        if enclosing is None:
            return None
        enclosing_boundary, enclosing_artifact, enclosing_records = enclosing
        link = Real16EnclosedEntryLink8616(
            parent=parent,
            callsite_index=source.callsite_index,
            callsite=row,
            callsite_artifact=callsite_artifact,
            callsite_boundary=callsite_boundary,
            call_state=parent.callsite_call_state,
            enclosing_artifact=enclosing_artifact,
            enclosing_boundary=enclosing_boundary,
            callee_artifact=callee_artifact,
            callee_boundary=callee_boundary,
        )
        premise = prove_real16_enclosed_invocation_domain_8616(
            project,
            callee_coverage,
            callsite_addr,
            boot=source.boot,
            boot_recompute=source.boot_recompute,
            chain=link,
            entry_call_preservations=enclosing_records,
            declared_services=source.declared_services,
        )
    if premise.failure is None and premise.complete:
        return premise
    return None


def _caller_premise_surface_8616(
    project: object, head_addr: int,
) -> tuple[IRFunctionArtifact, ExactFunctionRangeBoundary8616, IRBoundaryCoverageResult8616] | None:
    """Resolve one native caller surface without publishing conditional evidence.

    The caller's premise session must guard this demand before import. Only a
    missing registration permits ordinary native intake; conflicting registry
    entries never trigger a replacement. Refusal-free native intake establishes
    registry ownership; byte-bound coverage must then close before premise use.
    """
    registered = registered_function_ir_artifact_8616(project, head_addr)
    if registered.verdict is FunctionIRArtifactVerdict8616.PROVEN and registered.artifact is not None:
        artifact = registered.artifact
    elif registered.failure is FunctionIRArtifactFailure8616.NOT_REGISTERED:
        artifact = None
    else:
        return None
    boundary = _exact_boundary_for_8616(project, head_addr)
    if (
        boundary is None or boundary.addr != head_addr
        or boundary.project is not project
    ):
        return None
    imported = artifact is None
    if imported:
        from .vex_import import build_x86_16_ir_function_artifact

        artifact = build_x86_16_ir_function_artifact(project, boundary)
    if artifact is None:
        return None
    if imported and (
        type(artifact) is not IRFunctionArtifact
        or artifact.function_addr != head_addr
        or artifact.refusals
        or any(block.refusals for block in artifact.blocks)
    ):
        return None
    if imported:
        publication = publish_function_ir_artifact_8616(project, artifact)
        if publication.verdict is not FunctionIRArtifactVerdict8616.PROVEN or publication.artifact is not artifact:
            return None
    coverage = prove_ir_boundary_coverage_8616(project, boundary, artifact)
    if not coverage.complete:
        return None
    return artifact, boundary, coverage


def _retry_registered_parent_edges_8616(
    project: object,
    rows: tuple[DecodedDirectCallsite8616, ...],
    callsite_addr: int,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    coverage: IRBoundaryCoverageResult8616,
    records: tuple[EntryDomainCallPreservation8616, ...],
    source: Real16InvocationSource8616,
    resolution: _PremiseResolution8616,
) -> Real16InvocationDomain8616 | None:
    """Try authenticated parent edges until one closes before expiry."""
    for row in rows:
        if _resolution_deadline_expired_8616(project, resolution.deadline):
            return None
        premise = _edge_invocation_premise_8616(
            project,
            source,
            row,
            callsite_addr,
            artifact,
            boundary,
            coverage,
            records,
            resolution,
        )
        if _resolution_deadline_expired_8616(project, resolution.deadline):
            return None
        if premise is not None:
            return premise
    return None


def _retry_registered_invocation_premise_8616(
    project: object,
    head_addr: int,
    callsite_addr: int,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    coverage: IRBoundaryCoverageResult8616,
    source: Real16InvocationSource8616,
    resolution: _PremiseResolution8616,
    *,
    retry_boot: bool,
) -> Real16InvocationDomain8616 | None:
    """Retry one refused caller premise only through available evidence."""
    rows = source.callsite_index.for_target(head_addr)
    if not rows and not retry_boot:
        return None
    if _resolution_deadline_expired_8616(project, resolution.deadline):
        return None
    records = _surface_call_preservations_8616(project, artifact, boundary)
    if _resolution_deadline_expired_8616(project, resolution.deadline):
        return None
    if retry_boot:
        retried = _boot_retry_invocation_premise_8616(
            project, coverage, callsite_addr, source, records
        )
        if _resolution_deadline_expired_8616(project, resolution.deadline):
            return None
        if retried is not None:
            return retried
    return _retry_registered_parent_edges_8616(
        project,
        rows,
        callsite_addr,
        artifact,
        boundary,
        coverage,
        records,
        source,
        resolution,
    )


def _registered_invocation_premise_8616(
    project: object,
    head_addr: int,
    callsite_addr: int,
    source: Real16InvocationSource8616,
    resolution: _PremiseResolution8616,
) -> Real16InvocationDomain8616 | None:
    """Resolve a premise for one registered or source-bound native caller.

    Missing callers are imported only inside the existing bounded in-flight
    guard; refused or conditional bodies never enter the universal registry.
    A registered caller can be reached three ways, all proven: the
    source-authenticated MZ entry equals the head (``BOOT_ENTRY_PATH``),
    a decoded row lands on the head itself (``CALL_CHAINED``), or a
    decoded row lands on an enclosing entry whose boundary provably
    contains the head (``ENCLOSED_ENTRY``). Parents are resolved through
    the same bounded session so cyclic or over-deep caller graphs refuse
    deterministically instead of recursing without bound.
    """
    if head_addr in resolution.in_flight:
        return None
    if (
        len(resolution.in_flight) >= _ENTRY_PREMISE_MAX_DEPTH_8616
        or resolution.remaining <= 0
        or _resolution_deadline_expired_8616(project, resolution.deadline)
    ):
        return None
    resolution.remaining -= 1
    prior_in_flight = resolution.in_flight
    resolution.in_flight = prior_in_flight | {head_addr}
    try:
        if _resolution_deadline_expired_8616(project, resolution.deadline):
            return None
        surface = _caller_premise_surface_8616(project, head_addr)
        if surface is None or _resolution_deadline_expired_8616(project, resolution.deadline):
            return None
        artifact, boundary, coverage = surface
        from .real16_invocation_domain import (
            Real16InvocationFailure8616,
            prove_real16_invocation_domain_8616,
        )

        premise = prove_real16_invocation_domain_8616(
            project,
            coverage,
            callsite_addr,
            boot=source.boot,
            boot_recompute=source.boot_recompute,
            declared_services=source.declared_services,
        )
        if _resolution_deadline_expired_8616(project, resolution.deadline):
            return None
        if premise.failure is None and premise.complete:
            return premise
        return _retry_registered_invocation_premise_8616(
            project,
            head_addr,
            callsite_addr,
            artifact,
            boundary,
            coverage,
            source,
            resolution,
            retry_boot=(
                premise.failure
                is Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN
            ),
        )
    finally:
        resolution.in_flight = prior_in_flight


def _boot_retry_invocation_premise_8616(
    project: object,
    coverage: IRBoundaryCoverageResult8616,
    callsite_addr: int,
    source: Real16InvocationSource8616,
    records: tuple[EntryDomainCallPreservation8616, ...],
) -> Real16InvocationDomain8616 | None:
    """Retry a boot-rooted proof with its surface's collected records.

    Invoked only after the unchanged boot proof refused at an interior
    call boundary: the censused entry prefix itself contains interior
    near calls whose bound evidence is the only sound way across. The
    retried proof consumes the in-flight records through the same exact
    artifact/block/instruction identity match as chained derivations —
    no authority is derived from the failed attempt or from any
    in-flight proof of the same obligation.
    """
    if not records:
        return None
    from .real16_invocation_domain import (
        prove_real16_invocation_domain_8616,
    )

    retried = prove_real16_invocation_domain_8616(
        project,
        coverage,
        callsite_addr,
        boot=source.boot,
        boot_recompute=source.boot_recompute,
        entry_call_preservations=records,
        declared_services=source.declared_services,
    )
    if retried.failure is None and retried.complete:
        return retried
    return None


def _caller_invocation_premise_8616(
    project: object,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    callsite_addr: int,
    entry_call_preservations: tuple[EntryDomainCallPreservation8616, ...],
) -> Real16InvocationDomain8616 | None:
    """Build a transported caller-domain premise for one exact callsite.

    For every decoded near-call edge into ``artifact``'s head retained in
    the project's source-authenticated index, the parent caller's own
    premise is resolved recursively — boot, chained, or enclosed — so its
    census proves the path to the edge callsite and captures the call-row
    state. A row landing on the head transports into the callee surface
    (``CALL_CHAINED``); a row landing on an enclosing entry transports
    into the enclosing surface that provably contains the whole callee
    (``ENCLOSED_ENTRY``). ``None`` is returned whenever any leg cannot be
    proved — never a partial premise.
    """
    source = _invocation_premise_source_8616(project)
    if source is None:
        return None
    surface = cast(_PremiseResolutionSurface8616, project)
    resolution = _active_premise_resolution_8616(project)
    root = resolution is None
    if resolution is None:
        resolution = _PremiseResolution8616(
            deadline=_active_direct_evidence_deadline_8616(project),
        )
        surface._inertia_entry_domain_premise_resolution_8616 = resolution
    prior_in_flight = resolution.in_flight
    resolution.in_flight = prior_in_flight | {artifact.function_addr}
    try:
        for row in source.callsite_index.for_target(artifact.function_addr):
            if _resolution_deadline_expired_8616(project, resolution.deadline):
                return None
            premise = _edge_invocation_premise_8616(
                project,
                source,
                row,
                callsite_addr,
                artifact,
                boundary,
                None,
                entry_call_preservations,
                resolution,
            )
            if _resolution_deadline_expired_8616(project, resolution.deadline):
                return None
            if premise is not None:
                return premise
        return None
    finally:
        resolution.in_flight = prior_in_flight
        if root:
            surface._inertia_entry_domain_premise_resolution_8616 = None


def entry_domain_invocation_premise_8616(
    project: object,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    callsite_addr: int,
    entry_call_preservations: tuple[EntryDomainCallPreservation8616, ...] = (),
) -> Real16InvocationDomain8616 | None:
    """Resolve a complete caller-domain premise for one exact row.

    Shared premise entry point for every entry-domain consumer: the direct
    near-call target binding retries with it on a bare selector-window
    refusal, and the terminal-jump proof consults it as its
    ``invocation_resolver`` when the joint fetch-window theorem cannot
    keep a decoded target invariant. The premise must be complete and
    bound to ``callsite_addr`` inside the identical ``artifact`` surface;
    anything weaker returns ``None`` so the caller's default refusal
    stands.
    """
    if (
        type(artifact) is not IRFunctionArtifact
        or type(boundary) is not ExactFunctionRangeBoundary8616
        or type(callsite_addr) is not int
    ):
        return None
    return _caller_invocation_premise_8616(
        project, artifact, boundary, callsite_addr, entry_call_preservations
    )


def _callee_preserved_registers_8616(
    callee: SegmentEffectClosureResult8616 | None,
) -> tuple[str, ...]:
    """Project only identities proven at callee entry and every return exit."""
    if callee is None:
        return ()
    state = callee.state
    entry = state.entry_states.get(callee.coverage.artifact.function_addr, {})
    return tuple(
        register
        for register in SEGMENT_REGISTERS
        if register in entry
        and entry[register].origin is SegmentOrigin.PROVEN
        and entry[register].source is not None
        and all(
            register in state.exit_states.get(block_addr, {})
            and state.exit_states[block_addr][register].origin is SegmentOrigin.PROVEN
            and state.exit_states[block_addr][register].source == entry[register].source
            for block_addr in callee.return_block_addrs
        )
    )


def _caller_surface_failure_8616(
    result: EntryDomainCallPreservation8616,
) -> EntryDomainCallPreservationFailure8616 | None:
    """Rebind the caller side by exact object identity and coordinates.

    The in-flight caller cannot be registry-authenticated, so the proof must
    point back into the identical artifact surface: the retained block object
    must be a member of the retained artifact, the retained instruction must
    be a member of that block's stream, and the typed CALL coordinate must
    agree with the recorded callsite and the caller boundary root.
    """
    if type(result.artifact) is not IRFunctionArtifact:
        return EntryDomainCallPreservationFailure8616.CALLER_BINDING_MISMATCH
    if type(result.boundary) is not ExactFunctionRangeBoundary8616:
        return EntryDomainCallPreservationFailure8616.CALLER_BINDING_MISMATCH
    if result.boundary.addr != result.artifact.function_addr:
        return EntryDomainCallPreservationFailure8616.CALLER_BINDING_MISMATCH
    if not any(block is result.block for block in result.artifact.blocks):
        return EntryDomainCallPreservationFailure8616.CALLER_BINDING_MISMATCH
    if not any(instr is result.instruction for instr in result.block.instrs):
        return EntryDomainCallPreservationFailure8616.CALLER_BINDING_MISMATCH
    instruction = result.instruction
    if (
        instruction.op != "CALL"
        or type(result.callsite_addr) is not int
        or instruction.addr != result.callsite_addr
    ):
        return EntryDomainCallPreservationFailure8616.CALLER_BINDING_MISMATCH
    return None


def _callsite_entry_failure_8616(
    result: EntryDomainCallPreservation8616,
) -> EntryDomainCallPreservationFailure8616 | None:
    """Rebind the decoded native callsite entry to this exact callsite."""
    entry = result.entry
    index = result.index
    if type(index) is not DecodedDirectCallsiteIndex8616 or not index.stats.closed:
        return EntryDomainCallPreservationFailure8616.CALLSITE_UNPROVEN
    if type(entry) is not DecodedDirectCallsite8616:
        return EntryDomainCallPreservationFailure8616.CALLSITE_UNPROVEN
    if (
        entry.callsite_addr != result.callsite_addr
        or entry.caller_start != result.boundary.addr
        or entry.is_far
        or type(entry.target_addr) is not int
        or entry not in index.for_target(entry.target_addr)
    ):
        return EntryDomainCallPreservationFailure8616.CALLSITE_UNPROVEN
    return None


def _callee_dependency_failure_8616(
    callee: SegmentEffectClosureResult8616,
) -> EntryDomainCallPreservationFailure8616 | None:
    """Require the callee's own call census to carry bound complete proofs.

    The closure admits supplied nested proofs only when each is a complete
    ``SegmentCallPreservationResult8616`` bound to the identical callee
    artifact; this census additionally requires one such proof for every
    callsite the callee itself records, so an uncensused nested call is
    refused instead of inherited silently.
    """
    census = frozenset(callee.callsite_addrs)
    if not census:
        return None
    artifact = callee.coverage.artifact
    by_site: dict[int, list[SegmentCallPreservationResult8616]] = {}
    for proof in callee.state.call_preservations:
        if not (
            type(proof) is SegmentCallPreservationResult8616
            and type(proof.caller) is IRBoundaryCoverageResult8616
            and proof.caller.artifact is artifact
            and type(proof.callsite_addr) is int
            and proof.callsite_addr in census
        ):
            return EntryDomainCallPreservationFailure8616.DEPENDENCY_UNPROVEN
        by_site.setdefault(proof.callsite_addr, []).append(proof)
    for site in census:
        bound = by_site.get(site)
        if bound is None or len(bound) != 1:
            return EntryDomainCallPreservationFailure8616.DEPENDENCY_UNPROVEN
        if not bound[0].complete_for(callee.state.invocation_scope):
            return EntryDomainCallPreservationFailure8616.DEPENDENCY_UNPROVEN
    return None


def _operand_target_failure_8616(
    result: EntryDomainCallPreservation8616,
) -> EntryDomainCallPreservationFailure8616 | None:
    """Rebind the call operand to the proven full-width callee address.

    A CONST operand binds only by exact full-width equality with the bound
    callee artifact. A symbolic operand must still carry a complete
    Semantics-owned binding against the *encoded* target recovered from the
    retained decoded instruction bytes — never the canonicalized index
    target — and the bound callee address must be a member of the proven
    candidate window for this callsite.
    """
    instruction = result.instruction
    target = instruction.args[0] if instruction.args else None
    entry = result.entry
    if (
        not isinstance(target, IRValue)
        or type(entry) is not DecodedDirectCallsite8616
        or result.target_addr is None
    ):
        return EntryDomainCallPreservationFailure8616.TARGET_MISMATCH
    window = _callsite_window_8616(result.boundary.project, entry)
    if window is None or result.target_addr not in window[2]:
        return EntryDomainCallPreservationFailure8616.TARGET_MISMATCH
    if target.space is MemSpace.CONST:
        if type(target.const) is not int or target.const != result.target_addr:
            return EntryDomainCallPreservationFailure8616.TARGET_MISMATCH
        return None
    binding = result.binding
    # Defer the Semantics binding owner until validation time for the same
    # package initialization-order reason as the production path.
    from inertia.semantics.direct_near_call_target_binding import (
        DirectNearCallTargetBinding8616,
    )

    if (
        not isinstance(binding, DirectNearCallTargetBinding8616)
        or not binding.complete
        or binding.callsite_addr != result.callsite_addr
        or binding.target_addr != window[1]
    ):
        return EntryDomainCallPreservationFailure8616.TARGET_MISMATCH
    return None


def _preservation_failure_8616(
    result: EntryDomainCallPreservation8616,
) -> EntryDomainCallPreservationFailure8616 | None:
    """Revalidate one bound callsite proof from its retained evidence."""
    counts = (
        result.raw_fact_count,
        result.normalized_fact_count,
        result.classified_fact_count,
        result.materialized_count,
        result.failure_count,
    )
    if result.failure is not None:
        if type(result.failure) is not EntryDomainCallPreservationFailure8616:
            return EntryDomainCallPreservationFailure8616.ACCOUNTING_INCOMPLETE
        return result.failure
    if counts != (1, 1, 1, 1, 0) or any(type(count) is not int for count in counts):
        return EntryDomainCallPreservationFailure8616.ACCOUNTING_INCOMPLETE
    failure = _caller_surface_failure_8616(result)
    if failure is not None:
        return failure
    failure = _callsite_entry_failure_8616(result)
    if failure is not None:
        return failure
    return _callee_chain_failure_8616(result)


def _callee_complete_in_scope_8616(
    result: EntryDomainCallPreservation8616, callee: SegmentEffectClosureResult8616,
) -> bool:
    """Authenticate registered transport before consuming conditional callee effects."""
    from .real16_invocation_domain import real16_scope_crosses_call_8616

    callee_scope = callee.state.invocation_scope
    if callee_scope is None:
        return callee.complete
    caller_scope = result.invocation_scope
    if caller_scope is None or caller_scope.coverage is None:
        return False
    if caller_scope.coverage.artifact is not result.artifact:
        return False
    return real16_scope_crosses_call_8616(
        caller_scope, callee_scope, caller_scope.coverage, result.callsite_addr,
    ) and callee.complete_for(callee_scope)


def _callee_chain_failure_8616(
    result: EntryDomainCallPreservation8616,
) -> EntryDomainCallPreservationFailure8616 | None:
    """Revalidate the callee side: artifact, window, closure, operand, CS."""
    entry = cast(DecodedDirectCallsite8616, result.entry)
    callee = result.callee
    if type(callee) is not SegmentEffectClosureResult8616:
        return EntryDomainCallPreservationFailure8616.CALLEE_UNRESOLVED
    if callee.coverage.boundary.project is not result.boundary.project:
        return EntryDomainCallPreservationFailure8616.CALLEE_UNRESOLVED
    window = _callsite_window_8616(result.boundary.project, entry)
    if (
        window is None
        or type(callee.coverage.artifact) is not IRFunctionArtifact
        or callee.coverage.artifact.function_addr not in window[2]
        or result.target_addr != callee.coverage.artifact.function_addr
    ):
        return EntryDomainCallPreservationFailure8616.TARGET_MISMATCH
    if not _callee_complete_in_scope_8616(result, callee):
        return EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE
    dependency_failure = _callee_dependency_failure_8616(callee)
    if dependency_failure is not None:
        return dependency_failure
    operand_failure = _operand_target_failure_8616(result)
    if operand_failure is not None:
        return operand_failure
    if _CS_REGISTER_8616 not in _callee_preserved_registers_8616(callee):
        return EntryDomainCallPreservationFailure8616.CS_NOT_PRESERVED
    return None


def _refused_result_8616(
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    block: IRBlock,
    instruction: IRInstr,
    index: DecodedDirectCallsiteIndex8616 | None,
    entry: DecodedDirectCallsite8616 | None,
    callee: SegmentEffectClosureResult8616 | None,
    callsite_addr: int | None,
    target_addr: int | None,
    failure: EntryDomainCallPreservationFailure8616,
) -> EntryDomainCallPreservation8616:
    """Build one refused callsite record retaining the evidence gathered."""
    if index is None:
        index = DecodedDirectCallsiteIndex8616(
            {}, DecodedDirectCallsiteIndexStats8616(0, 0, 0, 0, 0), (),
        )
    return EntryDomainCallPreservation8616(
        artifact=artifact,
        boundary=boundary,
        block=block,
        instruction=instruction,
        index=index,
        entry=entry,
        callee=callee,
        binding=None,
        callsite_addr=callsite_addr if callsite_addr is not None else -1,
        target_addr=target_addr,
        failure=failure,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=0,
        materialized_count=0,
        failure_count=1,
    )


def _decoded_instruction_map_8616(
    boundary: ExactFunctionRangeBoundary8616,
) -> dict[int, object]:
    """Map each decoded native instruction of the boundary by its address."""
    decoded: dict[int, object] = {}
    for block in boundary.blocks:
        insns = cast(_CapstoneDisassembly8616, cast(_DecodedBlock8616, block).capstone).insns
        for instruction in insns:
            address = cast(_DecodedCallsiteInstruction8616, instruction).address
            if type(address) is int:
                decoded[address] = instruction
    return decoded


def _decoded_entry_for_callsite_8616(
    index: DecodedDirectCallsiteIndex8616,
    boundary: ExactFunctionRangeBoundary8616,
    decoded_by_addr: dict[int, object],
    callsite_addr: int,
    resolver: DirectCallTargetResolver8616,
) -> DecodedDirectCallsite8616 | None:
    """Return the unique indexed near-call entry for one exact callsite."""
    instruction = decoded_by_addr.get(callsite_addr)
    if instruction is None:
        return None
    resolved = resolver(instruction)
    target_addr = (
        resolved.target_addr if isinstance(resolved, DecodedFarCallTarget8616) else resolved
    )
    if type(target_addr) is not int:
        return None
    entries = tuple(
        entry
        for entry in index.for_target(target_addr)
        if entry.callsite_addr == callsite_addr
        and entry.caller_start == boundary.addr
        and not entry.is_far
    )
    return entries[0] if len(entries) == 1 else None


def _exact_boundary_for_8616(
    project: object,
    function_addr: int,
) -> ExactFunctionRangeBoundary8616 | None:
    """Resolve the exact frontend boundary for one mapped function entry."""
    # The registry imports the VEX importer, which imports this owner.
    # Boundary lookup is needed only when resolving a live call, after
    # those module contracts have finished initialization.
    from .function_ssa_registry import function_boundary_at_address_8616

    # Reuse the census already retained for this project/head. Rediscovering
    # the same reachable body inside different decode bounds creates a second
    # boundary authority that the callsite registry correctly rejects.
    boundary: ExactFunctionRangeBoundary8616 | None
    retained = registered_decoded_callsite_index_8616(project, function_addr)
    if retained is not None:
        boundary = retained.boundary
        if boundary.project is not project or boundary.addr != function_addr:
            return None
        return boundary
    candidate = function_boundary_at_address_8616(project, function_addr)
    boundary = candidate if isinstance(candidate, ExactFunctionRangeBoundary8616) else None
    if boundary is None and candidate is not None:
        witness = capture_function_boundary_8616(project, candidate)
        if witness is not None:
            boundary = restore_function_boundary_8616(project, witness)
    if boundary is None:
        boundary = mapped_entry_function_boundary_8616(project, function_addr)
    if (
        boundary is None
        or boundary.project is not project
        or boundary.addr != function_addr
    ):
        return None
    return boundary


def _retained_nested_proof_8616(
    project: object,
    coverage: IRBoundaryCoverageResult8616,
    boundary: ExactFunctionRangeBoundary8616,
    index: DecodedDirectCallsiteIndex8616,
    callsite_addr: int,
    window: tuple[int, int, tuple[int, ...]],
    resolution: _CalleeResolution8616,
    invocation_scope: Real16InvocationDomain8616 | None = None,
) -> SegmentCallPreservationResult8616 | None:
    """Reuse a complete retained callsite proof for this exact surface.

    A retained proof is admitted only when it binds every identity the
    fresh recursion would establish: the identical current artifact object,
    the equal boundary census on the identical project, the identical
    retained decoded index object, the same decoded callsite address, a
    resolved callee head inside the current callsite window, and a still
    complete segment-preservation revalidation — the typed
    ``SegmentCallPreservationResult8616`` is itself the modeled-segment
    contract, whose ``complete`` re-runs bounded dependency revalidation
    under the ambient traversal. Entries are retained only from closures
    that proved complete, so retained evidence is acyclic by construction;
    a stale, foreign, mismatched, or incomplete record falls through to the
    ordinary recursion, which refuses honestly instead of borrowing the
    retained claim. Lookups are linear in the callee's own callsite count
    and spend no ``remaining`` budget: reuse performs no resolution.
    """
    artifact = coverage.artifact
    entry = resolution.retained.get(artifact.function_addr)
    if entry is None:
        return None
    retained_artifact, proofs = entry
    if retained_artifact is not artifact:
        return None
    for proof in proofs:
        if not _retained_proof_bound_8616(
            project, artifact, boundary, index, callsite_addr, window, proof
        ):
            continue
        if proof.complete:
            return proof
    return None


def _retained_proof_bound_8616(
    project: object,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    index: DecodedDirectCallsiteIndex8616,
    callsite_addr: int,
    window: tuple[int, int, tuple[int, ...]],
    proof: object,
) -> bool:
    """Bind one retained callsite proof to this exact current surface."""
    if (
        type(proof) is not SegmentCallPreservationResult8616
        or proof.callsite_addr != callsite_addr
        or type(proof.caller) is not IRBoundaryCoverageResult8616
    ):
        return False
    caller = proof.caller
    if (
        caller.artifact is not artifact
        or caller.boundary != boundary
        or caller.boundary.project is not project
        or proof.index is not index
    ):
        return False
    return _retained_callee_bound_8616(proof.callee, window)


def _retained_callee_bound_8616(
    callee: object,
    window: tuple[int, int, tuple[int, ...]],
) -> bool:
    """Bind the retained proof's resolved callee inside the callsite window."""
    if (
        type(callee) is not SegmentEffectClosureResult8616
        or type(callee.coverage) is not IRBoundaryCoverageResult8616
        or type(callee.coverage.artifact) is not IRFunctionArtifact
        or type(callee.coverage.artifact.function_addr) is not int
    ):
        return False
    return callee.coverage.artifact.function_addr in window[2]


def _retained_closure_bound_8616(
    project: object,
    callee_addr: int,
    closure: object,
    invocation_scope: Real16InvocationDomain8616 | None = None,
    scope_surface: tuple[
        IRFunctionArtifact, ExactFunctionRangeBoundary8616,
    ] | None = None,
) -> bool:
    """Bind a retained closure to this exact callee head on this project.

    Reuse requires the typed closure contract, a caller coverage carrying
    the exact artifact head and boundary census for ``callee_addr`` on the
    identical project, and a still-complete revalidation — the verdict
    re-runs the bounded dependency traversal rather than trusting a
    stored bit. A scoped hit additionally binds every identity the fresh
    resolution would establish, so the key alone is never evidence: the
    identical scope-authenticated raw ``artifact`` object, the identical
    ``boundary`` for a chain-bound entry, the identical consuming entry
    retained on the state, and the scoped view whose own retained scope
    and source surface are those same objects. A coverage-bound entry
    instead requires universal coverage evidence over the identical
    registered artifact. Same callee address under another entry, or a
    stale source, view, or dependency, is never a hit.
    """
    if not (
        type(closure) is SegmentEffectClosureResult8616
        and type(closure.coverage) is IRBoundaryCoverageResult8616
        and type(closure.coverage.artifact) is IRFunctionArtifact
        and closure.coverage.artifact.function_addr == callee_addr
        and type(closure.coverage.boundary) is ExactFunctionRangeBoundary8616
        and closure.coverage.boundary.addr == callee_addr
        and closure.coverage.boundary.project is project
    ):
        return False
    if invocation_scope is None:
        return closure.complete
    if scope_surface is None:
        return False
    view = closure.coverage.scoped_view
    if invocation_scope.coverage is not None:
        bound = (
            view is None
            and closure.coverage.artifact is scope_surface[0]
        )
    else:
        bound = (
            view is not None
            and view.invocation_scope is invocation_scope
            and view.source_artifact is scope_surface[0]
            and view.boundary is scope_surface[1]
            and closure.coverage.artifact is scope_surface[0]
            and closure.coverage.boundary is scope_surface[1]
        )
    return (
        bound
        and closure.state.invocation_scope is invocation_scope
        and closure.complete_for(invocation_scope)
    )


def _nested_invocation_premise_8616(
    project: object,
    coverage: IRBoundaryCoverageResult8616,
    boundary: ExactFunctionRangeBoundary8616,
    callsite_addr: int,
) -> Real16InvocationDomain8616 | None:
    """Resolve the caller-head premise for one nested callsite surface.

    The caller of a nested callsite is the registered callee whose closure
    is being assembled, so its domain premise resolves through the shared
    registered-head owner — boot, chained, or enclosed parents — under the
    project-scoped premise session. The returned premise must bind the
    identical artifact object, the identical project, and this exact
    callsite, and must replay complete under the current source authority;
    anything weaker is ``None`` so the callsite keeps its default refusal
    rather than borrowing a premise bound to another surface. No premise
    is derived for an unregistered or identity-divergent head.
    """
    source = _invocation_premise_source_8616(project)
    if source is None:
        return None
    artifact = coverage.artifact
    if (
        type(artifact) is not IRFunctionArtifact
        or type(boundary) is not ExactFunctionRangeBoundary8616
        or boundary.project is not project
        or boundary.addr != artifact.function_addr
        or type(callsite_addr) is not int
    ):
        return None
    registered = registered_function_ir_artifact_8616(
        project, artifact.function_addr
    )
    if (
        registered.verdict is not FunctionIRArtifactVerdict8616.PROVEN
        or registered.artifact is not artifact
        or artifact is None
    ):
        return None
    surface = cast(_PremiseResolutionSurface8616, project)
    resolution = _active_premise_resolution_8616(project)
    root = resolution is None
    if resolution is None:
        resolution = _PremiseResolution8616(
            deadline=_active_direct_evidence_deadline_8616(project),
        )
        surface._inertia_entry_domain_premise_resolution_8616 = resolution
    try:
        premise = _registered_invocation_premise_8616(
            project, artifact.function_addr, callsite_addr, source, resolution,
        )
    finally:
        if root:
            surface._inertia_entry_domain_premise_resolution_8616 = None
    if (
        premise is None
        or premise.failure is not None
        or premise.callsite_addr != callsite_addr
        or premise.coverage is None
    ):
        return None
    if (
        premise.coverage.artifact is not artifact
        or premise.coverage.boundary.project is not project
        or premise.coverage.boundary.addr != boundary.addr
        or not premise.complete
    ):
        return None
    return premise


def _scoped_nested_premise_8616(
    project: object,
    coverage: IRBoundaryCoverageResult8616,
    boundary: ExactFunctionRangeBoundary8616,
    callsite_addr: int,
    scope: Real16InvocationDomain8616,
) -> Real16InvocationDomain8616 | None:
    """Derive a per-callsite premise sharing the scoped consuming entry.

    The in-flight caller surface is premise-derivable only through the
    source-bound owner: the same decoded index rows, parent census, and
    retained chain links that authenticate the supplied entry, re-derived
    against this exact callsite coordinate. Reusing the offered scope
    wholesale is refused — its callsite names a different coordinate —
    and patching its callsite field would forge provenance rather than
    re-derive it. A premise bound to another coordinate or to another
    entry provenance is ``None``; ``same_real16_entry_scope_8616``
    decides, never address equality.

    The surface's own in-flight callsite records accompany the premise
    exactly as they did when the consuming entry was first derived:
    interior calls on the censused path require bound evidence, and the
    collection joins the active session so a cyclic path back into this
    head refuses rather than deriving authority from the proof being
    built.
    """
    artifact = coverage.artifact
    records = _surface_call_preservations_8616(project, artifact, boundary)
    premise = entry_domain_invocation_premise_8616(
        project, artifact, boundary, callsite_addr,
        entry_call_preservations=records,
    )
    if (
        premise is None
        or premise.failure is not None
        or premise.callsite_addr != callsite_addr
        or not premise.complete
    ):
        return None
    from .real16_invocation_domain import same_real16_entry_scope_8616

    return premise if same_real16_entry_scope_8616(premise, scope) else None


def _nested_callsite_proof_8616(
    project: object,
    coverage: IRBoundaryCoverageResult8616,
    boundary: ExactFunctionRangeBoundary8616,
    index: DecodedDirectCallsiteIndex8616,
    decoded_by_addr: dict[int, object],
    callsite_addr: int,
    resolution: _CalleeResolution8616,
    invocation_scope: Real16InvocationDomain8616 | None = None,
) -> SegmentCallPreservationResult8616 | None:
    """Prove one nested callsite against its recursively resolved callee.

    A nested callsite whose encoded target escapes the unconditional
    all-fetch-selector window reports ``TARGET_MISMATCH`` on the first
    proof attempt; only then is a genuinely derived caller-head premise
    resolved and re-offered, so the common in-window path spends no
    premise-resolution budget. The premise is consumed by the
    Semantics-owned binding inside the re-proved result and retained on
    the returned record — a premise that cannot discharge the exact
    site/target leaves the original typed refusal standing.

    Under a scoped caller surface the proof cannot even authenticate its
    coverage without an offered entry, so the per-callsite premise is
    derived upfront through the source-bound owner and must share the
    supplied consuming entry; a scope with no derivable premise for this
    coordinate keeps the nested call refused.
    """
    if _resolution_deadline_expired_8616(project, resolution.deadline):
        return None
    entry = _decoded_entry_for_callsite_8616(
        index, boundary, decoded_by_addr, callsite_addr, resolution.resolver,
    )
    if entry is None:
        return None
    window = _callsite_window_8616(project, entry)
    if window is None:
        return None
    retained = _retained_nested_proof_8616(
        project, coverage, boundary, index, callsite_addr, window, resolution,
    )
    if retained is not None:
        return retained
    nested = _resolve_nested_closure_8616(
        project, window, resolution, callsite=entry
    )
    if nested is None or _resolution_deadline_expired_8616(project, resolution.deadline):
        return None
    return _complete_nested_callsite_proof_8616(
        project,
        coverage,
        boundary,
        index,
        callsite_addr,
        nested,
        resolution,
        invocation_scope,
    )


def _complete_nested_callsite_proof_8616(
    project: object,
    coverage: IRBoundaryCoverageResult8616,
    boundary: ExactFunctionRangeBoundary8616,
    index: DecodedDirectCallsiteIndex8616,
    callsite_addr: int,
    nested: SegmentEffectClosureResult8616,
    resolution: _CalleeResolution8616,
    invocation_scope: Real16InvocationDomain8616 | None,
) -> SegmentCallPreservationResult8616 | None:
    """Finish a nested proof under the exact invocation and deadline scopes."""
    invocation: Real16InvocationDomain8616 | None = None
    if coverage.scoped_view is not None:
        if invocation_scope is None:
            return None
        invocation = _scoped_nested_premise_8616(
            project, coverage, boundary, callsite_addr, invocation_scope,
        )
        if invocation is None or _resolution_deadline_expired_8616(project, resolution.deadline):
            return None
    proof = prove_segment_call_preservation_8616(
        coverage, nested, index, callsite_addr, invocation=invocation,
    )
    if _resolution_deadline_expired_8616(project, resolution.deadline):
        return None
    if (
        invocation is None
        and proof.failure is SegmentCallPreservationFailure8616.TARGET_MISMATCH
    ):
        retried = _retried_nested_proof_8616(
            project, coverage, boundary, index, callsite_addr, nested,
            invocation_scope,
        )
        if retried is not None:
            return retried
    return proof if proof.complete_for(invocation_scope) else None


def _resolve_nested_closure_8616(
    project: object,
    window: tuple[int, int, tuple[int, ...]],
    resolution: _CalleeResolution8616,
    callsite: DecodedDirectCallsite8616 | None = None,
) -> SegmentEffectClosureResult8616 | None:
    """Resolve the first available closure; the caller verifies completeness.

    ``callsite`` is the independently authenticated decoded row for the
    exact edge being resolved; it is transported into each candidate so
    the premise-bound import names the actual transporting edge.
    """
    nested: SegmentEffectClosureResult8616 | None = None
    for candidate_addr in window[2]:
        nested = _callee_closure_8616(
            project, candidate_addr, resolution, callsite=callsite
        )[0]
        if nested is not None:
            break
    return nested


def _retried_nested_proof_8616(
    project: object,
    coverage: IRBoundaryCoverageResult8616,
    boundary: ExactFunctionRangeBoundary8616,
    index: DecodedDirectCallsiteIndex8616,
    callsite_addr: int,
    nested: SegmentEffectClosureResult8616,
    invocation_scope: Real16InvocationDomain8616 | None,
) -> SegmentCallPreservationResult8616 | None:
    """Re-prove a TARGET_MISMATCH universal nested call under a derived premise."""
    premise = _nested_invocation_premise_8616(
        project, coverage, boundary, callsite_addr,
    )
    if premise is None:
        return None
    retried = prove_segment_call_preservation_8616(
        coverage, nested, index, callsite_addr, invocation=premise,
    )
    return retried if retried.complete_for(invocation_scope) else None


def _callee_artifact_and_boundary_8616(
    project: object,
    callee_addr: int,
    callsite: DecodedDirectCallsite8616 | None = None,
) -> tuple[IRFunctionArtifact, ExactFunctionRangeBoundary8616] | None:
    """Resolve one callee artifact and its exact boundary, importing on demand.

    Registry publication is consulted first so identical artifacts are never
    rebuilt. A missing registration falls back to the established
    mapped-entry owner — the encoded CALL target is itself the proven entry —
    exactly like ``resolve_callee_segment_contract_8616``. The import is
    guarded by a project-scoped in-flight marker and depth counter so cyclic
    or deeply nested call chains refuse instead of recursing without bound.
    The fallback may derive a source-bound entry-frame premise for the
    callee head — the decoded near-CALL row retained in the project's
    source-authenticated index that matches ``callsite``, the edge
    actually being resolved — so the mapped-entry proof can bind a proven
    near-return continuation. An artifact derived under that premise
    stays conditional: it keeps its pending markers, is consumed only
    under the authenticated chain-bound entry for that exact edge, and is
    never published, so no unrelated entry can inherit it.
    """
    resolution = registered_function_ir_artifact_8616(project, callee_addr)
    if resolution.verdict is FunctionIRArtifactVerdict8616.PROVEN:
        if resolution.artifact is None:
            return None
        boundary = _exact_boundary_for_8616(project, callee_addr)
        if boundary is None:
            return None
        return resolution.artifact, boundary
    if resolution.failure is not FunctionIRArtifactFailure8616.NOT_REGISTERED:
        return None
    surface = cast(_CalleeImportSurface8616, project)
    imports = _callee_imports_in_flight_8616(project)
    depth = _callee_import_depth_8616(project)
    if callee_addr in imports or depth >= _ENTRY_DOMAIN_CALLEE_MAX_DEPTH_8616:
        return None
    return _import_unregistered_callee_8616(
        project, callee_addr, surface, imports, depth, callsite
    )


def _near_return_pending_8616(
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
) -> bool:
    """Recognize the premise-derived conditional callee surface.

    The boundary must retain the source-bound frame premise and at least
    one proven continuation block, and the raw artifact must carry the
    typed pending marker on a block — the surface audit in the scoped
    view owner re-checks every marker's placement. Anything less is not
    conditional continuation evidence and routes as an ordinary body.
    """
    continuations = boundary.near_return_continuations
    return (
        continuations is not None
        and type(continuations.premise) is NearCallFramePremise8616
        and bool(continuations.proven_block_addrs)
        and any(
            refusal.kind == NEAR_RETURN_CONTINUATION_PENDING_KIND_8616
            for block in artifact.blocks
            for refusal in block.refusals
        )
    )


class _TransportedInsnWrapper8616(Protocol):
    """Wrapper surface exposing the raw decoded instruction object."""

    insn: object


class _TransportedInsn8616(Protocol):
    """Decoded instruction fields the edge-transport relation consumes."""

    address: int
    size: int
    bytes: bytes


def _decoded_instruction_evidence_8616(
    instruction: object,
) -> tuple[int, int, bytes] | None:
    """Return ``(address, size, bytes)`` for one decoded instruction.

    The retained row's instruction may be the immutable
    ``DirectCapstoneInstruction8616`` view or a raw decoder object; the
    wrapper is unwrapped exactly like the premise owner's width check.
    ``None`` whenever the row's instruction carries no decoded
    address/extent/byte evidence — malformed or detail-less instructions
    can never authenticate a transported edge.
    """
    wrapper = cast(_TransportedInsnWrapper8616, instruction)
    try:
        try:
            insn = cast(_TransportedInsn8616, wrapper.insn)
        except AttributeError:
            insn = cast(_TransportedInsn8616, instruction)
        address = insn.address
        size = insn.size
        payload = bytes(insn.bytes)
    except (AttributeError, TypeError):
        return None
    except CsError as error:
        # Detail-disabled Capstone objects signal missing evidence this
        # way, including during wrapper inspection. Other decoder errors
        # stay loud.
        if error.errno != CS_ERR_DETAIL:
            raise
        return None
    if (
        type(address) is not int
        or type(size) is not int
        or size <= 0
        or len(payload) != size
    ):
        return None
    return address, size, payload


def _transported_edge_bound_8616(
    project: object,
    retained: DecodedDirectCallsite8616,
    transported: DecodedDirectCallsite8616,
) -> bool:
    """Authenticate the transported row's instruction against the source row.

    Distinct row objects are legitimate — the caller's boundary index and
    the project source index retain separate instances — so object
    identity cannot be the relation. But coordinate agreement alone is
    not evidence: the instruction the transported row actually decoded
    must agree with the retained source row on address, extent, and exact
    native bytes, and the retained row's bytes must equal the bytes
    mapped at that coordinate under the same project. A ``66 E8`` dword
    push, a near ``E9`` jump, a fabricated extent, or an undecoded
    instruction borrows another instruction's coordinates and refuses.
    """
    if not (
        isinstance(retained.instructions, tuple)
        and isinstance(transported.instructions, tuple)
        and type(retained.instruction_index) is int
        and type(transported.instruction_index) is int
        and 0 <= retained.instruction_index < len(retained.instructions)
        and 0 <= transported.instruction_index < len(transported.instructions)
    ):
        return False
    retained_evidence = _decoded_instruction_evidence_8616(
        retained.instructions[retained.instruction_index]
    )
    transported_evidence = _decoded_instruction_evidence_8616(
        transported.instructions[transported.instruction_index]
    )
    if retained_evidence is None or transported_evidence is None:
        return False
    if retained_evidence != transported_evidence:
        return False
    address, size, payload = retained_evidence
    native = _mapped_bytes_8616(project, address, size)
    return native is not None and native == payload


def _near_return_frame_premise_8616(
    project: object,
    callee_addr: int,
    callsite: DecodedDirectCallsite8616 | None = None,
) -> NearCallFramePremise8616 | None:
    """Bind the entry-frame premise to the resolved edge's decoded row.

    Only the project source-authenticated callsite index can bind a
    premise: its rows are the identical objects every chained entry
    retains, so the premise's callsite stays authenticatable by object
    identity. ``callsite`` is the independently authenticated decoded row
    for the exact edge being resolved — supplied by the callsite-driven
    resolution path — and the source-authenticated row must agree with it
    on callsite address, caller head, and decoded target so the premise
    names the actual transporting edge, never an address look-alike. A
    context-free request (``callsite=None``) keeps the stricter
    head-unique contract: only a head with exactly one decoded near-CALL
    row is unambiguous. An absent, ambiguous, foreign, far, or
    coordinate-mismatched edge leaves the boundary premise-less, the
    continuation unproven, and the import refused — a premise naming an
    edge other than the actual transporting one is worse than none.

    When the project-wide source is absent — the bounded caller inventory
    refused before producing one — the intake-retained local frame
    evidence is consulted instead. It covers only caller surfaces the
    refused traversal actually closed, so its rows prove the conditional
    near-CALL frame ("if this exact near-CALL executes, the callee entry
    top slot holds its return word") and nothing more: it is never a
    boot-to-caller reachability or complete-chain authority. Rows whose
    recorded caller head lies outside the proved closed census are
    filtered out rather than trusted.
    """
    source = _real16_invocation_source_8616(project)
    index: DecodedDirectCallsiteIndex8616 | None
    census_heads: frozenset[int] | None = None
    if source is None:
        local = local_call_frame_evidence_8616(project)
        if local is None:
            return None
        index = local.callsite_index
        census_heads = frozenset(local.boundary_heads)
    else:
        index = source.callsite_index
    if type(index) is not DecodedDirectCallsiteIndex8616:
        return None
    rows = index.for_target(callee_addr)
    if census_heads is not None:
        rows = tuple(
            row for row in rows if row.caller_start in census_heads
        )
    if callsite is not None:
        if (
            type(callsite) is not DecodedDirectCallsite8616
            or callsite.is_far
            or type(callsite.callsite_addr) is not int
            or type(callsite.caller_start) is not int
            or callsite.target_addr != callee_addr
        ):
            return None
        rows = tuple(
            row
            for row in rows
            if not row.is_far
            and row.callsite_addr == callsite.callsite_addr
            and row.caller_start == callsite.caller_start
            and row.target_addr == callsite.target_addr
        )
        if len(rows) != 1:
            return None
        if not _transported_edge_bound_8616(project, rows[0], callsite):
            return None
        return prove_near_call_frame_premise_8616(rows[0], index, callee_addr)
    if len(rows) != 1:
        return None
    return prove_near_call_frame_premise_8616(rows[0], index, callee_addr)


def _import_unregistered_callee_8616(
    project: object,
    callee_addr: int,
    surface: _CalleeImportSurface8616,
    imports: set[int],
    depth: int,
    callsite: DecodedDirectCallsite8616 | None = None,
) -> tuple[IRFunctionArtifact, ExactFunctionRangeBoundary8616] | None:
    """Import one unregistered callee under the source-bound premise.

    This resolution is reachable only through an encoded near-CALL
    callsite window, so the callee's entry top slot is that call's
    return word — but the premise is derived only from the project's
    source-authenticated callsite index, never asserted from the
    resolution path itself. When the resolution is callsite-driven,
    ``callsite`` carries the independently authenticated decoded row for
    the exact edge being resolved so a callee shared by several callers
    binds the row that actually transported this resolution. A missing
    or ambiguous edge leaves the boundary premise-less, the continuation
    unproven, and the import refused; every other unresolved path —
    backward error tails included — still refuses. A premise-derived
    artifact carries its pending markers verbatim: it is valid only
    inside the authenticated invocation context for that exact edge, so
    it is returned conditional and never published into the universal
    registry.
    """
    boundary = mapped_entry_function_boundary_8616(
        project,
        callee_addr,
        premise=_near_return_frame_premise_8616(project, callee_addr, callsite),
    )
    if boundary is None or boundary.addr != callee_addr:
        return None
    # Defer the importer until resolution time: vex_import binds this module
    # through the entry-domain proof before its own body finishes loading.
    from .vex_import import build_x86_16_ir_function_artifact

    imports.add(callee_addr)
    surface._inertia_entry_domain_callee_import_depth_8616 = depth + 1
    try:
        raw = build_x86_16_ir_function_artifact(project, boundary)
    finally:
        imports.discard(callee_addr)
        surface._inertia_entry_domain_callee_import_depth_8616 = depth
    if _near_return_pending_8616(raw, boundary):
        if type(raw) is not IRFunctionArtifact:
            return None
        return raw, boundary
    if raw.refusals:
        return None
    artifact = publish_function_ir_artifact_8616(project, raw).artifact
    if (
        artifact is None
        or type(artifact) is not IRFunctionArtifact
        or artifact.refusals
    ):
        return None
    return artifact, boundary


def _callee_resolution_guard_failure_8616(
    project: object,
    resolution: _CalleeResolution8616,
    callee_addr: int,
) -> EntryDomainCallPreservationFailure8616 | None:
    """Preserve cycle-first and depth short-circuit guards before retained reuse."""
    if callee_addr in resolution.in_flight:
        return EntryDomainCallPreservationFailure8616.DEPENDENCY_UNPROVEN
    if _resolution_deadline_expired_8616(project, resolution.deadline):
        return EntryDomainCallPreservationFailure8616.BUDGET_EXHAUSTED
    if (
        len(resolution.in_flight) >= _ENTRY_DOMAIN_CALLEE_MAX_DEPTH_8616
        or _callee_import_depth_8616(project) >= _ENTRY_DOMAIN_CALLEE_MAX_DEPTH_8616
    ):
        return EntryDomainCallPreservationFailure8616.BUDGET_EXHAUSTED
    return None


def _closure_scope_bound_8616(
    project: object, callee_addr: int, scope: Real16InvocationDomain8616 | None,
) -> tuple[IRFunctionArtifact, ExactFunctionRangeBoundary8616] | None:
    """Authenticate a scoped request and return the exact surface it owns.

    ``None`` means either a universal request (``scope is None``) or a
    refused scope — callers branch on ``invocation_scope is None`` first,
    so a scoped request returning ``None`` here is a typed refusal, never
    a fallthrough to the publishing resolver. The whole scope replays
    once through ``same_real16_entry_scope_8616`` before any retained
    field is trusted: only an independently authenticated entry may name
    a callee surface, so a forged link, stale chain, selector
    coincidence, or address equality without native replay cannot
    substitute. The anchor rule mirrors the scoped-view owner: a
    coverage-bound entry consumes its registered ``coverage`` pair,
    while an in-flight chained or enclosed entry consumes the retained
    link's callee pair — never a re-derived look-alike and never the
    enclosing census surface.
    """
    if scope is None:
        return None
    from .real16_invocation_domain import (
        Real16CallChainLink8616,
        Real16EnclosedEntryLink8616,
        Real16InvocationDomain8616,
        same_real16_entry_scope_8616,
    )

    if (
        type(scope) is not Real16InvocationDomain8616
        or scope.project is not project
    ):
        return None
    if not same_real16_entry_scope_8616(scope, scope):
        return None
    coverage = scope.coverage
    artifact: object
    boundary: object
    if coverage is not None:
        if type(coverage) is not IRBoundaryCoverageResult8616:
            return None
        artifact = coverage.artifact
        boundary = coverage.boundary
    else:
        chain = scope.chain
        if not isinstance(
            chain, (Real16CallChainLink8616, Real16EnclosedEntryLink8616)
        ):
            return None
        artifact = chain.callee_artifact
        boundary = chain.callee_boundary
    if (
        type(artifact) is not IRFunctionArtifact
        or type(boundary) is not ExactFunctionRangeBoundary8616
    ):
        return None
    proven_artifact: IRFunctionArtifact = artifact
    proven_boundary: ExactFunctionRangeBoundary8616 = boundary
    if (
        proven_artifact.function_addr != callee_addr
        or proven_boundary.addr != callee_addr
        or proven_boundary.project is not project
    ):
        return None
    return proven_artifact, proven_boundary


def _retain_callee_closure_8616(
    resolution: _CalleeResolution8616,
    callee_addr: int,
    artifact: IRFunctionArtifact,
    proofs: tuple[SegmentCallPreservationResult8616, ...],
    closure: SegmentEffectClosureResult8616,
    scope: Real16InvocationDomain8616 | None,
) -> None:
    """Keep conditional closures and dependencies out of universal reuse pools."""
    if not closure.complete_for(scope):
        return
    if scope is not None:
        resolution.scoped_closures[(callee_addr, id(scope))] = closure
        return
    if proofs:
        resolution.retained[callee_addr] = (artifact, proofs)
    resolution.retained_closures[callee_addr] = closure


def _scoped_callee_coverage_8616(
    project: object,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    scope: Real16InvocationDomain8616,
) -> IRBoundaryCoverageResult8616 | None:
    """Build scoped boundary coverage over the authenticated raw surface.

    The scope-authenticated ``artifact`` is re-bound through the frozen
    importer's raw-bundle owner — a fresh native re-derivation that
    authenticates the held object and never substitutes a new identity —
    then the scoped view is constructed under the independently supplied
    consuming entry, never inferred from the proof's own recorded scope.
    Nothing here registers, publishes, or rebuilds the pending body; any
    leg that cannot reauthenticate returns ``None`` so the caller keeps
    its typed refusal instead of importing a look-alike.
    """
    from .scoped_control_obligations import (
        mixed_pending_obligations_8616,
    )
    from .vex_import import (
        prove_scoped_control_obligations_view_8616,
        prove_scoped_x86_16_ir_function_view_8616,
        raw_x86_16_import_bundle_for_artifact_8616,
    )

    view: ScopedNearReturnContinuationView8616 | ScopedFunctionIRView8616
    if _near_return_pending_8616(artifact, boundary):
        if mixed_pending_obligations_8616(artifact):
            # A premise-derived body carrying selector-window
            # obligations besides the continuation marker needs the
            # composed conditional view: the native bundle authenticates
            # the held artifact, the continuation evidence discharges
            # first, and the retained entry-jump owner proves the
            # selector obligations over the continuation-effective
            # surface under the same consuming entry.
            bundle = raw_x86_16_import_bundle_for_artifact_8616(
                project, boundary, artifact
            )
            if bundle is None or bundle.artifact is not artifact:
                return None
            view = prove_scoped_control_obligations_view_8616(
                project, bundle, boundary, invocation_scope=scope,
            )
        else:
            # A continuation-only premise-derived body discharges through
            # its own scoped view owner: the view authenticates the
            # source-bound frame premise against the consuming entry's
            # retained chain link — no import re-derivation or retained
            # application is involved.
            view = prove_scoped_near_return_continuation_view_8616(
                artifact, boundary, invocation_scope=scope,
            )
    else:
        bundle = raw_x86_16_import_bundle_for_artifact_8616(project, boundary, artifact)
        if bundle is None or bundle.artifact is not artifact:
            return None
        view = prove_scoped_x86_16_ir_function_view_8616(
            project, bundle, boundary, invocation_scope=scope,
        )
    coverage = prove_scoped_ir_boundary_coverage_8616(
        project, boundary, artifact, view,
    )
    return coverage if coverage.complete_for(scope) else None


def _callee_effect_closure_8616(
    project: object,
    callee_addr: int,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    coverage: IRBoundaryCoverageResult8616,
    resolution: _CalleeResolution8616,
    invocation_scope: Real16InvocationDomain8616 | None,
) -> tuple[
    SegmentEffectClosureResult8616 | None,
    tuple[SegmentCallPreservationResult8616, ...],
]:

    """Assemble nested callsite proofs, state, and the effect closure.

    Shared tail of the universal and scoped resolution routes: the
    coverage verdict gates nested proofing under ``complete_for(scope)``
    so a conditional surface is proofed only under its authenticated
    consuming entry, the common scope flows unchanged into every nested
    CALL proof, and the retained view rides the state as conditional
    evidence — never a published artifact.
    """
    if _resolution_deadline_expired_8616(project, resolution.deadline):
        return None, ()
    nested_sites = sorted({
        instruction.addr
        for block in artifact.blocks
        for instruction in block.instrs
        if instruction.op == "CALL" and type(instruction.addr) is int
    })
    nested_proofs: list[SegmentCallPreservationResult8616] = []
    if nested_sites and coverage.complete_for(invocation_scope):
        index = decoded_callsite_index_for_boundary_8616(
            project, boundary, direct_target_resolver=resolution.resolver,
        ).index
        decoded_by_addr = _decoded_instruction_map_8616(boundary)
        if _resolution_deadline_expired_8616(project, resolution.deadline):
            return None, ()
        prior_in_flight = resolution.in_flight
        resolution.in_flight = prior_in_flight | {callee_addr}
        try:
            for site in nested_sites:
                if _resolution_deadline_expired_8616(project, resolution.deadline):
                    return None, tuple(nested_proofs)
                proof = _nested_callsite_proof_8616(
                    project, coverage, boundary, index, decoded_by_addr, site, resolution, invocation_scope,
                )
                if _resolution_deadline_expired_8616(project, resolution.deadline):
                    return None, tuple(nested_proofs)
                if proof is not None:
                    nested_proofs.append(proof)
        finally:
            resolution.in_flight = prior_in_flight
    if _resolution_deadline_expired_8616(project, resolution.deadline):
        return None, tuple(nested_proofs)
    state = build_x86_16_segment_state_artifact(
        artifact,
        call_preservations=tuple(nested_proofs),
        invocation_scope=invocation_scope,
        scoped_view=coverage.scoped_view,
    )
    return prove_segment_effect_closure_8616(coverage, state), tuple(nested_proofs)


def _callee_closure_8616(
    project: object,
    callee_addr: int,
    resolution: _CalleeResolution8616,
    invocation_scope: Real16InvocationDomain8616 | None = None,
    callsite: DecodedDirectCallsite8616 | None = None,
) -> tuple[
    SegmentEffectClosureResult8616 | None,
    EntryDomainCallPreservationFailure8616 | None,
]:
    """Resolve a callee's complete segment-effect closure or its refusal.

    Only the exact artifact and its proven frontend boundary supply the
    coverage certificate; a missing artifact or foreign project reports
    ``CALLEE_UNRESOLVED``, a cyclic revisit reports ``DEPENDENCY_UNPROVEN``,
    and a depth or aggregate-budget overflow reports ``BUDGET_EXHAUSTED`` so
    the callsite stays refused rather than guessed. A non-leaf callee is
    admitted only when every nested callsite produced a complete bound
    ``SegmentCallPreservationResult8616``; the state's supplied-proof surface
    records exactly those proofs for later census revalidation.

    A universal request keeps the established registry/publishing route
    unchanged; ``callsite`` is the independently authenticated decoded
    row for the exact edge being resolved when the request is
    callsite-driven, transported only into the premise-bound import. A
    scoped request must first authenticate the consuming entry and the
    exact surface it owns: a coverage-bound entry keeps the registry
    route and binds the identical registered artifact, while a
    chain-bound entry owns an in-flight raw surface that is resolved only
    through the frozen scoped owners — raw bundle, scoped view, scoped
    coverage — and never through the publishing importer. Conditional
    results live only in the scope-keyed pool.
    """
    guard_failure = _callee_resolution_guard_failure_8616(project, resolution, callee_addr)
    if guard_failure is not None:
        return None, guard_failure
    surface = _closure_scope_bound_8616(project, callee_addr, invocation_scope)
    if invocation_scope is not None and surface is None:
        return None, EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE
    retained = (resolution.retained_closures.get(callee_addr) if invocation_scope is None
                else resolution.scoped_closures.get((callee_addr, id(invocation_scope))))
    if retained is not None and _retained_closure_bound_8616(
        project, callee_addr, retained, invocation_scope, surface
    ):
        # The identical registered callee's complete closure already
        # resolved once in this session: reuse performs no resolution, so
        # it neither spends ``remaining`` nor weakens the cap.
        return retained, None
    if resolution.remaining <= 0:
        return None, EntryDomainCallPreservationFailure8616.BUDGET_EXHAUSTED
    resolution.remaining -= 1
    prior_in_flight = resolution.in_flight
    if invocation_scope is not None and invocation_scope.coverage is None:
        # A scoped body remains under construction through state/closure
        # validation, not just through discovery of its effective CFG.
        resolution.in_flight = prior_in_flight | {callee_addr}
    try:
        route, route_failure = _callee_route_8616(
            project, callee_addr, surface, invocation_scope, resolution,
            callsite,
        )
        if route is None:
            return None, route_failure
        if _resolution_deadline_expired_8616(project, resolution.deadline):
            return None, EntryDomainCallPreservationFailure8616.BUDGET_EXHAUSTED
        artifact, boundary, coverage = route
        closure, nested_proofs = _callee_effect_closure_8616(
            project, callee_addr, artifact, boundary, coverage, resolution, invocation_scope,
        )
        if _resolution_deadline_expired_8616(project, resolution.deadline):
            return None, EntryDomainCallPreservationFailure8616.BUDGET_EXHAUSTED
        if closure is None:
            return None, EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE
    finally:
        resolution.in_flight = prior_in_flight
    _retain_callee_closure_8616(
        resolution, callee_addr, artifact, nested_proofs, closure, invocation_scope,
    )
    return closure, None


def _callee_route_8616(
    project: object,
    callee_addr: int,
    surface: tuple[IRFunctionArtifact, ExactFunctionRangeBoundary8616] | None,
    invocation_scope: Real16InvocationDomain8616 | None,
    resolution: _CalleeResolution8616,
    callsite: DecodedDirectCallsite8616 | None = None,
) -> tuple[
    tuple[
        IRFunctionArtifact,
        ExactFunctionRangeBoundary8616,
        IRBoundaryCoverageResult8616,
    ]
    | None,
    EntryDomainCallPreservationFailure8616 | None,
]:
    """Resolve the callee's artifact, boundary and coverage for the route.

    A universal request keeps the established registry/publishing route
    unchanged; when it is callsite-driven, ``callsite`` carries the
    independently authenticated decoded row for the exact edge being
    resolved into the premise-bound import. A coverage-bound entry stays
    on that route but binds the identical registered artifact its
    coverage censused. A chain-bound entry owns an in-flight pending
    body: the head is held in-flight for the whole scoped resolution so
    a bootstrap cycle through the view's own record collection refuses
    instead of deriving authority from the closure being built, and
    coverage comes only from the frozen scoped owners — never the
    publishing importer.
    """
    if surface is None:
        resolved = _callee_artifact_and_boundary_8616(
            project, callee_addr, callsite
        )
        if resolved is None:
            return None, EntryDomainCallPreservationFailure8616.CALLEE_UNRESOLVED
        artifact, boundary = resolved
        if _near_return_pending_8616(artifact, boundary):
            # A premise-derived body is conditional evidence: only a
            # chain-bound entry authenticating the exact decoded edge may
            # close it. The universal coverage route must never see it —
            # refused coverage cannot launder pending markers.
            return None, EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE
        return (
            artifact,
            boundary,
            prove_ir_boundary_coverage_8616(project, boundary, artifact),
        ), None
    if invocation_scope is None:
        # A non-``None`` surface is minted only for a scoped request; keep
        # the refusal closed rather than resolving without its entry.
        return None, EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE
    if invocation_scope.coverage is not None:
        resolved = _callee_artifact_and_boundary_8616(
            project, callee_addr, callsite
        )
        if resolved is None:
            return None, EntryDomainCallPreservationFailure8616.CALLEE_UNRESOLVED
        artifact, boundary = resolved
        if artifact is not surface[0] or _near_return_pending_8616(
            artifact, boundary
        ):
            return None, EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE
        return (
            artifact,
            boundary,
            prove_ir_boundary_coverage_8616(project, boundary, artifact),
        ), None
    artifact, boundary = surface
    prior_in_flight = resolution.in_flight
    resolution.in_flight = prior_in_flight | {callee_addr}
    try:
        coverage = _scoped_callee_coverage_8616(
            project, artifact, boundary, invocation_scope,
        )
        if coverage is None:
            return None, EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE
        return (artifact, boundary, coverage), None
    finally:
        resolution.in_flight = prior_in_flight


def _bind_direct_call_target_8616(
    project: object,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    block: IRBlock,
    instruction: IRInstr,
    callsite_addr: int | None,
    window: tuple[int, int, tuple[int, ...]] | None,
    entry_call_preservations: tuple[EntryDomainCallPreservation8616, ...],
) -> tuple[DirectNearCallTargetBinding8616 | None, bool]:
    """Bind one symbolic CALL target, reporting cooperative expiry separately."""
    if window is None or callsite_addr is None:
        return None, False
    operand = instruction.args[0] if instruction.args else None
    if not isinstance(operand, IRValue) or operand.space is MemSpace.CONST:
        return None, False
    from inertia.semantics.direct_near_call_target_binding import (
        DirectNearCallCoordinates8616,
        DirectNearCallTargetBindingFailure8616,
        prove_direct_near_call_target_binding_at_coordinates_8616,
    )

    coordinates = DirectNearCallCoordinates8616(
        callsite_addr, window[0], window[1],
    )
    binding = prove_direct_near_call_target_binding_at_coordinates_8616(
        project,
        block=block,
        instruction=instruction,
        coordinates=coordinates,
    )
    if direct_evidence_deadline_expired_8616(project):
        return None, True
    if binding.failure is not DirectNearCallTargetBindingFailure8616.SELECTOR_WINDOW_UNPROVED:
        return binding, False
    premise = _caller_invocation_premise_8616(
        project,
        artifact,
        boundary,
        callsite_addr,
        entry_call_preservations,
    )
    if direct_evidence_deadline_expired_8616(project):
        return None, True
    if premise is None:
        return binding, False
    binding = prove_direct_near_call_target_binding_at_coordinates_8616(
        project,
        block=block,
        instruction=instruction,
        coordinates=coordinates,
        invocation=premise,
    )
    return (
        (None, True)
        if direct_evidence_deadline_expired_8616(project)
        else (binding, False)
    )


def _resolve_callsite_evidence_8616(
    project: object,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    block: IRBlock,
    instruction: IRInstr,
    *,
    index: DecodedDirectCallsiteIndex8616,
    decoded_by_addr: dict[int, object],
    resolution: _CalleeResolution8616,
    entry_call_preservations: tuple[EntryDomainCallPreservation8616, ...],
) -> tuple[
    DecodedDirectCallsite8616 | None,
    SegmentEffectClosureResult8616 | None,
    int | None,
    EntryDomainCallPreservationFailure8616 | None,
    DirectNearCallTargetBinding8616 | None,
] | None:
    """Resolve callsite, callee closure, and binding before the request deadline."""
    callsite_addr = instruction.addr if type(instruction.addr) is int else None
    entry = (
        None
        if callsite_addr is None
        else _decoded_entry_for_callsite_8616(
            index, boundary, decoded_by_addr, callsite_addr, resolution.resolver,
        )
    )
    window = None if entry is None else _callsite_window_8616(project, entry)
    callee: SegmentEffectClosureResult8616 | None = None
    callee_addr: int | None = None
    callee_refusal: EntryDomainCallPreservationFailure8616 | None = None
    if window is not None:
        for candidate_addr in window[2]:
            closure, refusal = _callee_closure_8616(
                project, candidate_addr, resolution, callsite=entry,
            )
            if closure is not None:
                callee = closure
                callee_addr = candidate_addr
                callee_refusal = None
                break
            callee_refusal = refusal
    if direct_evidence_deadline_expired_8616(project):
        return None
    binding, expired = _bind_direct_call_target_8616(
        project,
        artifact,
        boundary,
        block,
        instruction,
        callsite_addr,
        window,
        entry_call_preservations,
    )
    if expired:
        return None
    return entry, callee, callee_addr, callee_refusal, binding


def prove_entry_domain_call_preservation_8616(
    project: object,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    block: IRBlock,
    instruction: IRInstr,
    *,
    index: DecodedDirectCallsiteIndex8616,
    decoded_by_addr: dict[int, object],
    resolution: _CalleeResolution8616,
    entry_call_preservations: tuple[EntryDomainCallPreservation8616, ...] = (),
) -> EntryDomainCallPreservation8616:
    """Produce one bound callsite CS-preservation proof or typed refusal.

    The candidate is assembled from retained evidence first; the shared
    revalidation routine then decides the verdict, so a refused record and an
    admitted one differ only in what the identical checks could prove.

    ``entry_call_preservations`` is the in-flight record pool already
    collected for this caller in the same import session; it feeds the
    chained caller-domain premise consulted only when the Semantics
    binding's all-fetch-windows selector bound cannot discharge the call.
    """
    callsite_addr = instruction.addr if type(instruction.addr) is int else None
    if direct_evidence_deadline_expired_8616(project):
        return _refused_result_8616(
            artifact,
            boundary,
            block,
            instruction,
            index,
            None,
            None,
            callsite_addr,
            None,
            EntryDomainCallPreservationFailure8616.BUDGET_EXHAUSTED,
        )
    resolved = _resolve_callsite_evidence_8616(
        project,
        artifact,
        boundary,
        block,
        instruction,
        index=index,
        decoded_by_addr=decoded_by_addr,
        resolution=resolution,
        entry_call_preservations=entry_call_preservations,
    )
    if resolved is None:
        return _budget_exhausted_call_records_8616(
            artifact, boundary, ((block, instruction),), index,
        )[0]
    entry, callee, callee_addr, callee_refusal, binding = resolved
    candidate = EntryDomainCallPreservation8616(
        artifact=artifact,
        boundary=boundary,
        block=block,
        instruction=instruction,
        index=index,
        entry=entry,
        callee=callee,
        binding=binding,
        callsite_addr=callsite_addr if callsite_addr is not None else -1,
        target_addr=(
            entry.target_addr if callee_addr is None else callee_addr
        ) if entry is not None else None,
        failure=None,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
    )
    with segment_call_dependency_traversal_scope_8616():
        failure = _preservation_failure_8616(candidate)
    if (
        failure is EntryDomainCallPreservationFailure8616.CALLEE_UNRESOLVED
        and callee_refusal is not None
    ):
        failure = callee_refusal
    if failure is None:
        return candidate
    return EntryDomainCallPreservation8616(
        artifact=artifact,
        boundary=boundary,
        block=block,
        instruction=instruction,
        index=index,
        entry=entry,
        callee=callee,
        binding=binding,
        callsite_addr=candidate.callsite_addr,
        target_addr=candidate.target_addr,
        failure=failure,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=0,
        materialized_count=0,
        failure_count=1,
    )


def entry_domain_caller_boundary_8616(
    project: object,
    function: object,
    function_addr: int,
) -> ExactFunctionRangeBoundary8616 | None:
    """Resolve the caller's exact frontend boundary for the domain proof.

    An owned ``ExactFunctionRangeBoundary8616`` import surface supplies its own
    census directly; any other recovered function resolves through the shared
    boundary owners. A boundary whose root or project disagrees with the
    in-flight artifact is refused rather than repaired.
    """
    if isinstance(function, ExactFunctionRangeBoundary8616):
        boundary: ExactFunctionRangeBoundary8616 | None = function
    else:
        boundary = _exact_boundary_for_8616(project, function_addr)
    if (
        boundary is None
        or boundary.project is not project
        or boundary.addr != function_addr
    ):
        return None
    return boundary


def _selector_window_binding_failure_8616() -> object:
    """Return the Semantics-owned selector-window refusal enum member.

    Imported lazily for the same package initialization-order reason as
    the binding owner itself.
    """
    from inertia.semantics.direct_near_call_target_binding import (
        DirectNearCallTargetBindingFailure8616,
    )

    return DirectNearCallTargetBindingFailure8616.SELECTOR_WINDOW_UNPROVED


def _budget_exhausted_call_records_8616(
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    calls: tuple[tuple[IRBlock, IRInstr], ...],
    index: DecodedDirectCallsiteIndex8616 | None = None,
) -> tuple[EntryDomainCallPreservation8616, ...]:
    """Account every pending call as a typed refusal after request expiry."""
    return tuple(
        _refused_result_8616(
            artifact,
            boundary,
            block,
            instruction,
            index,
            None,
            None,
            instruction.addr if type(instruction.addr) is int else None,
            None,
            EntryDomainCallPreservationFailure8616.BUDGET_EXHAUSTED,
        )
        for block, instruction in calls
    )


@contextmanager
def _collection_premise_resolution_8616(project: object) -> Iterator[None]:
    """Share premise accounting across both CALL passes and nested collections.

    This scope owns only the work budget and in-flight recursion state. It
    neither retains proof verdicts nor widens the independent replay scope.
    An enclosing premise request keeps ownership of its existing session.
    """
    if _active_premise_resolution_8616(project) is not None:
        yield
        return
    surface = cast(_PremiseResolutionSurface8616, project)
    surface._inertia_entry_domain_premise_resolution_8616 = _PremiseResolution8616(
        deadline=_active_direct_evidence_deadline_8616(project),
    )
    try:
        yield
    finally:
        surface._inertia_entry_domain_premise_resolution_8616 = None


def collect_entry_domain_call_preservations_8616(
    project: object,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    *,
    direct_target_resolver: DirectCallTargetResolver8616,
) -> tuple[EntryDomainCallPreservation8616, ...]:
    """Bind every reachable CALL in the in-flight artifact to callee evidence.

    Returns one typed record per CALL instruction in the artifact; callers
    that cannot produce a complete chain keep their default refusal. The
    callsite index is the retained project-boundary inventory, decoded at
    most once per boundary census.
    """
    calls = tuple(
        (block, instruction)
        for block in artifact.blocks
        for instruction in block.instrs
        if instruction.op == "CALL"
    )
    if not calls:
        return ()
    if (
        boundary.project is not project
        or boundary.addr != artifact.function_addr
    ):
        return tuple(
            _refused_result_8616(
                artifact, boundary, block, instruction, None, None, None,
                instruction.addr if type(instruction.addr) is int else None,
                None,
                EntryDomainCallPreservationFailure8616.CALLER_BINDING_MISMATCH,
            )
            for block, instruction in calls
        )
    if direct_evidence_deadline_expired_8616(project):
        return _budget_exhausted_call_records_8616(
            artifact, boundary, calls,
        )
    index = decoded_callsite_index_for_boundary_8616(
        project, boundary, direct_target_resolver=direct_target_resolver,
    ).index
    decoded_by_addr = _decoded_instruction_map_8616(boundary)
    if direct_evidence_deadline_expired_8616(project):
        return _budget_exhausted_call_records_8616(
            artifact, boundary, calls, index,
        )
    # One request-scoped session bounds aggregate callee work. An on-demand
    # callee import re-enters this collector through the importer; it joins
    # the active session instead of minting a fresh budget, so nested
    # collections cannot reset the resolution count. The session is restored
    # in finally even when collection raises.
    surface = cast(_CalleeResolutionSurface8616, project)
    resolution = _active_resolution_8616(project)
    root = resolution is None
    if resolution is None:
        resolution = _CalleeResolution8616(
            resolver=direct_target_resolver,
            deadline=_active_direct_evidence_deadline_8616(project),
        )
        surface._inertia_entry_domain_call_resolution_8616 = resolution
    prior_in_flight = resolution.in_flight
    resolution.in_flight = resolution.in_flight | {artifact.function_addr}
    try:
        with _collection_premise_resolution_8616(project):
            records = tuple(
                prove_entry_domain_call_preservation_8616(
                    project, artifact, boundary, block, instruction,
                    index=index, decoded_by_addr=decoded_by_addr,
                    resolution=resolution,
                )
                for block, instruction in calls
            )
            # Second pass: only a selector-window refusal may be discharged
            # by a chained caller-domain premise, and the premise census needs
            # the caller's complete in-flight record pool — including records
            # for callsites ordered after this one — so it runs once all
            # first-pass records exist. A refused retry keeps the original
            # typed record rather than doubling the ledger.
            if (
                not direct_evidence_deadline_expired_8616(project)
                and any(
                    record.binding is not None
                    and record.binding.failure
                    is _selector_window_binding_failure_8616()
                    for record in records
                )
                and _invocation_premise_source_8616(project) is not None
            ):
                records = tuple(
                    prove_entry_domain_call_preservation_8616(
                        project, artifact, boundary, record.block,
                        record.instruction,
                        index=index, decoded_by_addr=decoded_by_addr,
                        resolution=resolution,
                        entry_call_preservations=records,
                    )
                    if (
                        record.binding is not None
                        and record.binding.failure
                        is _selector_window_binding_failure_8616()
                    )
                    else record
                    for record in records
                )
            return records
    finally:
        resolution.in_flight = prior_in_flight
        if root:
            surface._inertia_entry_domain_call_resolution_8616 = None
