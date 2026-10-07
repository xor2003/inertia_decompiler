"""Install a source-authenticated invocation surface from MZ bytes alone.

Layer: CLI/fallback/reporting.
Responsibility: bind the static decompiler's loaded project to the MZ byte
stream it was built from, project a typed static-header input from those
bytes plus the loader's declared load paragraph, verify the module is the
mapped binary exactly, build the bounded callsite inventory rooted at the
header entry, and install the typed invocation source. By default a
``MzStaticBoot8616`` carries only header-authenticated CS:IP/SS:SP; other
registers stay unknown and dependent effects refuse downstream. Explicit
caller-declared boot and service evidence may instead bind a conditional
source after the same source/entry checks and declaration authentication.
It does not invoke runtimes, overwrite memory, fabricate register values,
or claim universal guarantees — it only makes a typed installation
decision per load.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from functools import partial
from typing import Protocol, cast

from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsiteIndex8616,
    DirectCallTargetResolver8616,
)
from inertia.frontend.x86_16.frontend_invocation_inventory import (
    InvocationInventory8616,
    InvocationInventoryBudget8616,
    build_invocation_inventory_8616,
)
from inertia.frontend.x86_16.frontend_local_call_evidence import (
    LocalCallFrameEvidence8616,
    collect_local_call_frame_evidence_8616,
    install_local_call_frame_evidence_8616,
    local_call_frame_evidence_8616,
    local_call_frame_evidence_epoch_matches_8616,
)
from inertia.frontend.x86_16.mz_invocation_source import (
    MzInvocationSource8616,
    mz_invocation_source_8616,
)
from inertia.frontend.x86_16.mz_static_boot import (
    MzStaticBoot8616,
    mz_static_boot_8616,
    recompute_mz_static_boot_8616,
)
from inertia.ir.entry_domain_call_preservation import (
    Real16InvocationSource8616,
    install_real16_invocation_source_8616,
)
from inertia.ir.real16_declared_interrupt8616 import (
    DeclaredInterruptService8616,
    declared_environment_digest_8616,
)
from inertia.lowering.analysis_helpers import (
    resolve_direct_call_target_from_instruction_8616,
)

__all__ = [
    "MzStaticIntakeInstall8616",
    "MzStaticIntakeRequest8616",
    "MzStaticIntakeStatus8616",
    "install_mz_static_invocation_source_8616",
]


class MzStaticIntakeStatus8616(StrEnum):
    """Typed admission verdicts for one static-MZ intake attempt."""

    INSTALLED = "installed"
    #: A nested demand must not restart the inventory currently being built.
    IN_PROGRESS_REFUSED = "in_progress_refused"
    #: ``source`` was not a nonempty ``bytes`` stream — the intake owns no
    #: recovery path for a missing or mistyped program image.
    SOURCE_REFUSED = "source_refused"
    #: The project did not expose the DOS MZ loader surface (a numeric
    #: ``mz_load_segment``); blobs, foreign backends and hand-built
    #: projects cannot authenticate a load paragraph.
    LOADER_SURFACE_REFUSED = "loader_surface_refused"
    #: The shared MZ projection refused or was incomplete — the source
    #: bytes are not a relocatable MZ the loader surface corroborates.
    PROJECTION_REFUSED = "projection_refused"
    #: The loader's recorded entry does not equal the header-derived entry
    #: linear; the project was not loaded the way the header describes.
    ENTRY_MISMATCH_REFUSED = "entry_mismatch_refused"
    #: The relocated module differs from the mapped bytes at the declared
    #: load paragraph; the project's memory no longer carries that image.
    IMAGE_MISMATCH_REFUSED = "image_mismatch_refused"
    #: The bounded callsite inventory could not produce any caller
    #: evidence — traversal refused or a budget exhausted — so no source
    #: is installed. A ``PARTIAL_CALLER_EVIDENCE`` inventory is not a
    #: refusal: its index over closed caller surfaces is real evidence,
    #: and its ``pending_targets`` obligations ride on the installed
    #: source where consumers must keep them visible.
    INVENTORY_REFUSED = "inventory_refused"
    #: Caller-declared environment evidence failed authentication: the
    #: declared boot does not retain the identical source bytes, its entry
    #: diverges from the authenticated header entry, the caller's
    #: recompute authority does not reproduce it, or a service relation's
    #: digest does not match the declared environment it claims.
    DECLARED_REFUSED = "declared_refused"


@dataclass(frozen=True, slots=True)
class MzStaticIntakeInstall8616:
    """Typed receipt of one static-MZ intake decision.

    ``status`` is the verdict; ``inventory`` is the bounded inventory when
    built; ``entry_linear`` and ``boot_sha256`` bind the admitted header
    facts; ``refusal_addr`` names the mapped address whose bytes failed
    authentication when the status is ``IMAGE_MISMATCH_REFUSED``;
    ``pending_targets`` carries the inventory's unresolved discovered
    call-target obligations when the corpus closed only partially.
    ``local_evidence`` is the separate typed local authority retained when
    the inventory refused but its ledger recorded closed caller surfaces —
    conditional frame evidence only, never a ``Real16InvocationSource8616``.
    """

    status: MzStaticIntakeStatus8616
    inventory: InvocationInventory8616 | None
    entry_linear: int
    boot_sha256: str
    refusal_addr: int | None
    pending_targets: tuple[int, ...] = ()
    local_evidence: LocalCallFrameEvidence8616 | None = None

    @property
    def installed(self) -> bool:
        """Return whether this receipt installed a source."""
        return self.status is MzStaticIntakeStatus8616.INSTALLED


class _MzLoaderMemory8616(Protocol):
    """Third-party loader memory used for mapped-byte authentication."""

    def load(self, addr: int, size: int) -> object:
        """Return the mapped bytes for one linear range."""
        ...


class _MzLoaderObject8616(Protocol):
    """The DOS MZ backend surface the intake authenticates."""

    mz_load_segment: int


class _MzMappedObject8616(Protocol):
    """Third-party loaded-object bounds, inclusive at the upper endpoint."""

    min_addr: int
    max_addr: int


class _MzLoaderSurface8616(Protocol):
    """Third-party loader boundary consumed by intake authentication."""

    memory: _MzLoaderMemory8616
    main_object: object

    def find_object_containing(self, address: int) -> object | None:
        """Return the loaded object owning this address."""
        ...


class _MzProjectSurface8616(Protocol):
    """Minimal project surface required for intake authentication."""

    loader: _MzLoaderSurface8616
    entry: int


class _MzIntakeReceiptMarker8616(Protocol):
    """Project slot carrying the most recent deferred-intake receipt."""

    _inertia_mz_static_invocation_install_8616: MzStaticIntakeInstall8616


def _mz_loader_object_8616(project: object) -> _MzLoaderObject8616 | None:
    """Return the main object when it carries the DOS MZ loader surface.

    ``mz_load_segment`` exists only on the DOS MZ backend — a third-party
    dynamic boundary, so presence plus type is the gate.
    """
    try:
        main_object = cast(_MzProjectSurface8616, project).loader.main_object
    except AttributeError:
        return None
    load_segment = getattr(main_object, "mz_load_segment", None)
    if not isinstance(load_segment, int) or not 0 <= load_segment <= 0xFFFF:
        return None
    return cast(_MzLoaderObject8616, main_object)


def _refusal_8616(
    project: object,
    status: MzStaticIntakeStatus8616,
    *,
    refusal_addr: int | None = None,
    inventory: InvocationInventory8616 | None = None,
    local_evidence: LocalCallFrameEvidence8616 | None = None,
) -> MzStaticIntakeInstall8616:
    """Clear installed evidence, retain any local census, report the refusal.

    The project-wide invocation-source slot is always cleared; the separate
    local frame-evidence slot receives exactly ``local_evidence`` — a
    cleared slot on every refusal that produced no closed-caller census.
    """
    install_real16_invocation_source_8616(project, None)
    install_local_call_frame_evidence_8616(project, local_evidence)
    return MzStaticIntakeInstall8616(
        status=status,
        inventory=inventory,
        entry_linear=0,
        boot_sha256="",
        refusal_addr=refusal_addr,
        pending_targets=() if inventory is None else inventory.pending_targets,
        local_evidence=local_evidence,
    )


def _request_freshness_key_8616(
    project: object,
) -> tuple[int, int, str] | None:
    """Fingerprint the mapped evidence a deferred attempt authenticates.

    The key binds the loader's recorded entry, the declared load
    paragraph, and a digest of the whole mapped image. Any mutation of
    mapped bytes — or a different loader surface — yields a different
    key, so a memoized refusal can never masquerade as fresh evidence.
    ``None`` means the loader surface is absent; nothing is memoized.
    """
    main_object = _mz_loader_object_8616(project)
    if main_object is None:
        return None
    surface = cast(_MzProjectSurface8616, project)
    try:
        entry = surface.entry
        mapped = cast(
            _MzMappedObject8616 | None,
            surface.loader.find_object_containing(entry),
        )
        if mapped is None:
            return None
        lower, upper = mapped.min_addr, mapped.max_addr
        if (
            type(lower) is not int
            or type(upper) is not int
            or not lower <= upper
        ):
            return None
        image = surface.loader.memory.load(lower, upper - lower + 1)
    except (AttributeError, TypeError):
        return None
    if not isinstance(image, (bytes, bytearray)):
        return None
    digest = hashlib.sha256(bytes(image)).hexdigest()
    return (entry, main_object.mz_load_segment, digest)


@dataclass(slots=True)
class MzStaticIntakeRequest8616:
    """Deferred intake evidence retained on a project at build time.

    The loader verified that the project was built from ``source`` bytes;
    running the full bounded inventory eagerly would charge every MZ
    load for work most consumers never need, so the project carries this
    record instead and the first invocation-source demand calls
    ``install(project)`` — the consumer seam in the IR layer reads the
    project slot under ``_inertia_mz_static_invocation_request_8616``.

    Authentication refusals bind retained-source identity as well as entry,
    load paragraph and mapped-image identity. Inventory refusals are not
    cached: boundary closure can also depend on retained project proof
    evidence. A successful install lands in the invocation-source slot.
    Nested demands while installation is active return a typed non-result;
    the in-progress guard always clears, including on unexpected exceptions.
    """

    source: bytes
    #: Optional caller-declared environment authority: a ``ProgramBoot``
    #: over the identical ``source`` bytes plus the declared interrupt
    #: service relations minted under it. When supplied, the scoped source
    #: mint binds the declared boot so chained invocation legs propagate
    #: the explicit declaration; when absent the minted source keeps the
    #: static ``MzStaticBoot8616`` and admits no environment. Declared
    #: evidence is authenticated against this request's retained bytes —
    #: a boot over different bytes, a divergent entry, a recompute that
    #: does not reproduce the boot, or a relation digest that does not
    #: match the declared environment all refuse.
    declared_boot: object | None = None
    declared_boot_recompute: Callable[[object], object] | None = None
    declared_services: tuple[DeclaredInterruptService8616, ...] = ()
    # Dependency-local scoped authority memoized per retained evidence
    # record. The memo key is the identical ``LocalCallFrameEvidence8616``
    # object the minted source was authenticated under, so a replaced or
    # revoked evidence record re-derives instead of serving stale
    # authority, and premises derived under one minted record share the
    # identical boot object the scope-identity contract requires.
    _scoped_source: Real16InvocationSource8616 | None = field(
        default=None, init=False
    )
    _scoped_source_evidence: LocalCallFrameEvidence8616 | None = field(
        default=None, init=False
    )
    _refused_key: tuple[str, tuple[int, int, str]] | None = field(default=None, init=False)
    _refused_receipt: MzStaticIntakeInstall8616 | None = field(
        default=None, init=False
    )
    _installing: bool = field(default=False, init=False)

    def install(self, project: object) -> MzStaticIntakeInstall8616:
        """Attempt the deferred intake against the current mapped image.

        Returns the typed receipt; an authentication refusal for identical
        evidence may be memoized, changed evidence re-authenticates, and success installs
        the invocation source for subsequent slot reads. The latest
        receipt is stamped on the project under
        ``_inertia_mz_static_invocation_install_8616`` for diagnostics.
        """
        if self._installing:
            return MzStaticIntakeInstall8616(
                status=MzStaticIntakeStatus8616.IN_PROGRESS_REFUSED,
                inventory=None, entry_linear=0, boot_sha256="", refusal_addr=None,
            )
        self._installing = True
        try:
            return self._install_current(project)
        finally:
            self._installing = False

    def _install_current(self, project: object) -> MzStaticIntakeInstall8616:
        """Authenticate current evidence without reusing inventory refusals."""
        image_key = _request_freshness_key_8616(project)
        key = (
            (hashlib.sha256(self.source).hexdigest(), image_key)
            if image_key is not None and type(self.source) is bytes
            else None
        )
        if (
            key is not None
            and self._refused_receipt is not None
            and key == self._refused_key
        ):
            return self._refused_receipt
        receipt = install_mz_static_invocation_source_8616(
            project,
            self.source,
            declared_boot=self.declared_boot,
            declared_boot_recompute=self.declared_boot_recompute,
            declared_services=self.declared_services,
        )
        cast(
            _MzIntakeReceiptMarker8616, project
        )._inertia_mz_static_invocation_install_8616 = receipt
        # Boundary closure also depends on retained project proof evidence.
        # Image identity alone cannot establish freshness for that refusal.
        cacheable = receipt.status in {
            MzStaticIntakeStatus8616.SOURCE_REFUSED,
            MzStaticIntakeStatus8616.LOADER_SURFACE_REFUSED,
            MzStaticIntakeStatus8616.PROJECTION_REFUSED,
            MzStaticIntakeStatus8616.ENTRY_MISMATCH_REFUSED,
            MzStaticIntakeStatus8616.IMAGE_MISMATCH_REFUSED,
        }
        if key is not None and cacheable:
            self._refused_key = key
            self._refused_receipt = receipt
        else:
            self._refused_key = None
            self._refused_receipt = None
        return receipt

    def scoped_invocation_source_8616(
        self,
        project: object,
    ) -> Real16InvocationSource8616 | None:
        """Mint dependency-local invocation authority over closed evidence.

        When the project-wide source could not install — the bounded
        inventory refused — the retained local frame-evidence record still
        binds the authenticated MZ bytes, loader paragraph, entry linear,
        and a closed decoded callsite index over exactly the re-closed
        caller surfaces. This demand rebuilds the boot under that
        authenticated context and returns the record to the caller only:
        it is never installed into ``_inertia_real16_invocation_source_8616``,
        never marks the refused inventory ready, and keeps every
        ``pending_targets`` obligation visible on the record itself.

        ``None`` means no authentic closed evidence exists: a missing,
        revoked, or foreign-sourced evidence record, a retained source
        whose digest no longer matches, or a boot whose header entry
        diverges all refuse identically. The memoized record is keyed to
        the identical evidence object so every premise derived under it
        shares one boot identity — the object-identity contract the
        chained-scope consumer requires — while a replaced evidence
        record mints a fresh authority instead of reviving the old.
        """
        # Local frame evidence can survive removal of that request, but
        # invocation authority must remain bound to this exact receiver —
        # a removed, replaced, or detached receiver may never borrow the
        # retained slot's authentication, even on a memo hit.
        # Dynamic boundary: third-party angr projects may lack this optional slot.
        retained = getattr(
            project, "_inertia_mz_static_invocation_request_8616", None
        )
        if retained is not self:
            self._scoped_source = None
            self._scoped_source_evidence = None
            return None
        local = local_call_frame_evidence_8616(project)
        if local is None:
            self._scoped_source = None
            self._scoped_source_evidence = None
            return None
        if self._scoped_source_evidence is local:
            scoped = self._scoped_source
            if scoped is not None and self._scoped_declaration_current_8616(
                scoped, local
            ):
                return scoped
            # The retained evidence epoch survives but the declaration it
            # was minted under was revoked or replaced: drop the memo so a
            # stale declaration can never outlive its revocation, then mint
            # a fresh epoch under the current fields — or refuse when the
            # current declaration fails authentication.
            self._scoped_source = None
            self._scoped_source_evidence = None
        scoped = self._mint_scoped_source_8616(local)
        self._scoped_source = scoped
        self._scoped_source_evidence = local if scoped is not None else None
        return scoped

    def _scoped_declaration_current_8616(
        self,
        scoped: Real16InvocationSource8616,
        local: LocalCallFrameEvidence8616,
    ) -> bool:
        """Re-admit the memoized record's declaration under current fields.

        ``declared_boot``, ``declared_boot_recompute`` and
        ``declared_services`` are caller-mutable, so a memo hit must
        re-run the same admission the fresh mint performs before serving
        the retained record: the current fields authenticate through the
        shared binding contract, and the rebound boot and relation tuple
        must equal the minted record's — byte-for-byte the same declared
        semantics, never an identity shortcut over mutable content. A
        revocation or malformed replacement fails the bind and revokes
        the memo; a *valid* replacement binds a different declaration and
        is reminted by the caller as a new epoch rather than served
        stale.
        """
        binding = self._declared_scope_binding_8616(local)
        if binding is None:
            return False
        boot, recompute, services = binding
        return bool(
            boot == scoped.boot
            and recompute is scoped.boot_recompute
            and services == scoped.declared_services
        )

    def _mint_scoped_source_8616(
        self,
        local: LocalCallFrameEvidence8616,
    ) -> Real16InvocationSource8616 | None:
        """Authenticate retained bytes and bind one scoped source record.

        The evidence accessor already re-authenticated the mapped image,
        loader context, and the project's retained request; this mint
        additionally requires this request's own bytes to be the exact
        authenticated source so a swapped record cannot borrow the
        evidence's provenance. The boot is rebuilt from those bytes under
        the evidence's authenticated load paragraph and must land on the
        identical header-derived entry; the callsite index is the
        evidence's own closed census — rows from callers the refused
        traversal never closed simply do not exist here, so every parent
        edge a consumer resolves through it is independently
        authenticated. ``pending_targets`` is carried verbatim so the
        unresolved discovered frontier stays visible on the record.

        When the request carries caller-declared environment evidence the
        minted source binds it instead of the static boot: the declared
        boot must retain the identical source bytes, land on the identical
        entry, reproduce under the caller's recompute authority, and every
        declared service relation must bind the digest of that boot's own
        declared environment — re-derived here, never trusted from the
        relation. Absent declaration this mints the unchanged static boot.
        """
        if type(self.source) is not bytes or not self.source:
            return None
        if hashlib.sha256(self.source).hexdigest() != local.source_sha256:
            return None
        if (
            type(local.callsite_index) is not DecodedDirectCallsiteIndex8616
            or type(local.pending_targets) is not tuple
            or not all(type(head) is int for head in local.pending_targets)
        ):
            return None
        declared = self._declared_scope_binding_8616(local)
        if type(declared) is not tuple:
            return None
        boot, boot_recompute, services = declared
        return Real16InvocationSource8616(
            boot=boot,
            boot_recompute=boot_recompute,
            callsite_index=local.callsite_index,
            pending_targets=local.pending_targets,
            declared_services=services,
        )

    def _declared_scope_binding_8616(
        self,
        local: LocalCallFrameEvidence8616,
    ) -> tuple[MzStaticBoot8616 | _DeclaredBootSurface8616, Callable[[object], object] | None, tuple[DeclaredInterruptService8616, ...]] | None:
        """Bind the declared or static boot authority for one scoped mint.

        Delegates to the shared binding contract over this request's
        declared fields and the evidence's authenticated loader context;
        ``None`` refuses identically to the installed path.
        """
        return _declared_boot_binding_8616(
            self.source,
            local.load_segment,
            local.entry_linear,
            self.declared_boot,
            self.declared_boot_recompute,
            self.declared_services,
        )


def _declared_boot_binding_8616(
    source_bytes: bytes,
    load_segment: int,
    entry_linear: int,
    declared_boot: object | None,
    declared_boot_recompute: Callable[[object], object] | None,
    declared_services: tuple[DeclaredInterruptService8616, ...],
) -> tuple[MzStaticBoot8616 | _DeclaredBootSurface8616, Callable[[object], object] | None, tuple[DeclaredInterruptService8616, ...]] | None:
    """Bind the declared or static boot authority for one source mint.

    Returns ``(boot, boot_recompute, declared_services)``; ``None``
    refuses. Without declared fields the static ``MzStaticBoot8616``
    over the authenticated bytes is returned with empty services —
    identical to the undeclared contract. With a declared boot, the
    retained bytes, the entry linear, the caller's recompute authority
    and every relation's environment digest must all authenticate
    against this intake's own evidence — the digest is re-derived here,
    never trusted from the relation.
    """
    if declared_boot is None:
        if declared_services or declared_boot_recompute is not None:
            return None
        boot = mz_static_boot_8616(source_bytes, load_segment)
        if boot.entry.linear() != entry_linear:
            return None
        return (boot, recompute_mz_static_boot_8616, ())
    try:
        declared_surface = cast(_DeclaredBootSurface8616, declared_boot)
        declared_source = declared_surface.source
        entry = declared_surface.entry.linear()
        environment = declared_surface.environment
    except (AttributeError, TypeError):
        return None
    if (
        type(declared_source) is not bytes
        or declared_source != source_bytes
        or type(entry) is not int
        or entry != entry_linear
        or environment is None
    ):
        return None
    if (
        not callable(declared_boot_recompute)
        or declared_boot_recompute(declared_boot) != declared_boot
    ):
        return None
    digest = declared_environment_digest_8616(environment)
    if type(digest) is not str:
        return None
    if type(declared_services) is not tuple or not all(
        type(service) is DeclaredInterruptService8616
        and service.environment_sha256 == digest
        for service in declared_services
    ):
        return None
    return (declared_boot, declared_boot_recompute, declared_services)


def _authenticated_mz_surface_or_refusal_8616(
    project: object, source: bytes
) -> MzStaticIntakeInstall8616 | tuple[int, MzInvocationSource8616]:
    """Authenticate retained MZ bytes against the loader's live surface.

    Reparses the bytes under the loader's recorded paragraph, requires
    the loader entry to equal the header-derived entry, and requires the
    whole relocated module to equal the project's mapped bytes. Returns
    either a typed refusal receipt or ``(load_segment, projection)``.
    """
    main_object = _mz_loader_object_8616(project)
    if main_object is None:
        return MzStaticIntakeInstall8616(
            status=MzStaticIntakeStatus8616.LOADER_SURFACE_REFUSED,
            inventory=None,
            entry_linear=0,
            boot_sha256="",
            refusal_addr=None,
        )
    load_segment = main_object.mz_load_segment
    try:
        projection = mz_invocation_source_8616(source, load_segment)
    except (TypeError, ValueError):
        return MzStaticIntakeInstall8616(
            status=MzStaticIntakeStatus8616.PROJECTION_REFUSED,
            inventory=None,
            entry_linear=0,
            boot_sha256="",
            refusal_addr=None,
        )
    if not projection.complete:
        return MzStaticIntakeInstall8616(
            status=MzStaticIntakeStatus8616.PROJECTION_REFUSED,
            inventory=None,
            entry_linear=0,
            boot_sha256="",
            refusal_addr=None,
        )
    surface = cast(_MzProjectSurface8616, project)
    try:
        entry = surface.entry
    except AttributeError:
        entry = None
    if not isinstance(entry, int) or entry != projection.entry_linear:
        return _refusal_8616(
            project,
            MzStaticIntakeStatus8616.ENTRY_MISMATCH_REFUSED,
        )
    module_base = load_segment * 16
    try:
        mapped = surface.loader.memory.load(module_base, len(projection.module))
    except (AttributeError, TypeError):
        return _refusal_8616(
            project,
            MzStaticIntakeStatus8616.LOADER_SURFACE_REFUSED,
        )
    if mapped != projection.module:
        return _refusal_8616(
            project,
            MzStaticIntakeStatus8616.IMAGE_MISMATCH_REFUSED,
            refusal_addr=module_base,
        )
    return (load_segment, projection)


def _declared_binding_or_refusal_8616(
    project: object,
    source_bytes: bytes,
    load_segment: int,
    entry_linear: int,
    declared_boot: object | None,
    declared_boot_recompute: Callable[[object], object] | None,
    declared_services: tuple[DeclaredInterruptService8616, ...],
) -> tuple[MzStaticBoot8616 | _DeclaredBootSurface8616, Callable[[object], object] | None, tuple[DeclaredInterruptService8616, ...]] | MzStaticIntakeInstall8616:
    """Bind declared evidence for the installed path or refuse the intake.

    Same admission contract as the scoped mint — a ``None`` bind becomes
    a typed ``DECLARED_REFUSED`` receipt with cleared evidence, so the
    installed path can never install a partially authenticated
    declaration.
    """
    binding = _declared_boot_binding_8616(
        source_bytes,
        load_segment,
        entry_linear,
        declared_boot,
        declared_boot_recompute,
        declared_services,
    )
    if binding is None:
        return _refusal_8616(
            project,
            MzStaticIntakeStatus8616.DECLARED_REFUSED,
        )
    return binding


class _DeclaredBootEntrySurface8616(Protocol):
    """The linear-projection seam a declared boot entry must expose."""

    def linear(self) -> int:
        """Return the entry's linear address."""
        ...


class _DeclaredBootSurface8616(Protocol):
    """Fields the declared boot authority must expose for scope minting.

    The canonical ``ProgramBoot`` satisfies this shape; the intake reads
    only — ownership of the declared environment stays with the dosunit
    contract that minted it.
    """

    source: bytes
    entry: _DeclaredBootEntrySurface8616
    environment: object
    boot_sha256: str


def install_mz_static_invocation_source_8616(
    project: object,
    source: bytes,
    *,
    extra_entries: Iterable[int] = (),
    budget: InvocationInventoryBudget8616 | None = None,
    direct_target_resolver: DirectCallTargetResolver8616 | None = None,
    declared_boot: object | None = None,
    declared_boot_recompute: Callable[[object], object] | None = None,
    declared_services: tuple[DeclaredInterruptService8616, ...] = (),
) -> MzStaticIntakeInstall8616:
    """Install the static-header invocation source when bytes authenticate.

    Authentication happens before anything is admitted: the project's DOS
    MZ loader surface supplies the declared load paragraph, the retained
    MZ bytes are reparsed and relocated under that paragraph, the loader's
    recorded entry must equal the header-derived entry, and the whole
    relocated module must equal the project's mapped bytes. The bounded
    inventory then decodes closed boundaries reachable by direct near
    calls from the header entry; a corpus that closes only partially
    still supplies caller-edge evidence with its unresolved discovered
    targets carried as ``pending_targets`` obligations. Any refusal
    clears the project's
    invocation-source slot; success installs a ``Real16InvocationSource8616``
    whose boot is a ``MzStaticBoot8616`` unless caller-declared
    environment evidence was supplied — then the bound declared boot and
    its authenticated service relations install instead, so declared
    conditional services propagate through chained proof on the
    installed path exactly as on the scoped path. A declaration that
    fails authentication refuses ``DECLARED_REFUSED`` before the
    inventory runs.
    ``loader`` and ``entry`` are the third-party angr surface consumed
    through a typed Protocol — a dynamic boundary only in the remaining
    ``mz_load_segment`` presence check on the backend object.

    The retained local evidence is captured through its authenticated
    accessor before the unconditional clear so a refused corpus whose
    fresh recollection is the identical census epoch keeps its retained
    object installed: the scoped-authority memo's object-identity epoch
    then survives repeated demands and derived scopes keep their
    boot/index/row identity. Freshness is not skipped — the inventory
    still runs in full, and a census that retained proof evidence
    changed installs a new epoch exactly as before.
    """
    prior_local_evidence = local_call_frame_evidence_8616(project)
    install_real16_invocation_source_8616(project, None)
    install_local_call_frame_evidence_8616(project, None)
    if type(source) is not bytes or not source:
        return MzStaticIntakeInstall8616(
            status=MzStaticIntakeStatus8616.SOURCE_REFUSED,
            inventory=None,
            entry_linear=0,
            boot_sha256="",
            refusal_addr=None,
        )
    authenticated = _authenticated_mz_surface_or_refusal_8616(
        project, source
    )
    if isinstance(authenticated, MzStaticIntakeInstall8616):
        return authenticated
    load_segment, projection = authenticated
    bound = _declared_binding_or_refusal_8616(
        project,
        source,
        load_segment,
        projection.entry_linear,
        declared_boot,
        declared_boot_recompute,
        declared_services,
    )
    if isinstance(bound, MzStaticIntakeInstall8616):
        return bound
    boot, boot_recompute, services = bound
    resolver: DirectCallTargetResolver8616 = (
        partial(resolve_direct_call_target_from_instruction_8616, project)
        if direct_target_resolver is None
        else direct_target_resolver
    )
    inventory = build_invocation_inventory_8616(
        project,
        projection.entry_linear,
        extra_entries=extra_entries,
        budget=budget,
        direct_target_resolver=resolver,
    )
    # A completed traversal carries caller-edge evidence even when it is
    # only PARTIAL_CALLER_EVIDENCE: the index covers the closed caller
    # surfaces and the discovered targets that could not close stay visible
    # as typed obligations on the source — never silently treated as a
    # closed corpus. Index presence alone does not establish reconciled evidence.
    if not inventory.caller_evidence_ready or inventory.callsite_index is None:
        # A refused corpus can still carry closed caller surfaces: retain
        # them as separate typed local frame evidence bound to this
        # authenticated image — never as the project-wide source, never a
        # claim that the corpus or a boot-to-caller chain closed.
        local = collect_local_call_frame_evidence_8616(
            project,
            projection=projection,
            inventory=inventory,
            budget=budget,
            direct_target_resolver=resolver,
        )
        if (
            prior_local_evidence is not None
            and local is not None
            and local_call_frame_evidence_epoch_matches_8616(
                prior_local_evidence, local
            )
        ):
            # The inventory ran in full — freshness is not skipped — and
            # its recollection is the identical census epoch, so the
            # retained object stays installed. A changed census installs
            # the new record and a new epoch instead.
            local = prior_local_evidence
        return _refusal_8616(
            project,
            MzStaticIntakeStatus8616.INVENTORY_REFUSED,
            refusal_addr=inventory.refusal_addr,
            inventory=inventory,
            local_evidence=local,
        )
    install_real16_invocation_source_8616(
        project,
        Real16InvocationSource8616(
            boot=boot,
            boot_recompute=boot_recompute,
            callsite_index=inventory.callsite_index,
            pending_targets=inventory.pending_targets,
            declared_services=services,
        ),
    )
    return MzStaticIntakeInstall8616(
        status=MzStaticIntakeStatus8616.INSTALLED,
        inventory=inventory,
        entry_linear=projection.entry_linear,
        boot_sha256=boot.boot_sha256,
        refusal_addr=None,
        pending_targets=inventory.pending_targets,
    )
