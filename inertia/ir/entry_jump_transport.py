"""Bound entry-domain proof product for the AIL conversion boundary.

Layer: IR / control-domain evidence.

Responsibility: run one bounded native entry-domain proof over the same
recovered function surface a frontend consumer converted, reusing the owned
raw-import and ``entry_jump_domain`` proof/apply machinery unchanged. The
product carries the exact raw import bundle — the pre-discharge surface
identity and the terminal evidence the proof consumed — plus the native
``EntryJumpDomainProof8616`` and its ``EntryJumpDomainApplication8616``.
It never parses serialized summaries, fabricates per-block terminal
evidence or an address-name admission map, registers or publishes the
pending or discharged artifact, mutates execution VEX, or touches AIL.

This early pass uses only the function-entry fetch domain. It never resolves
callers or recursively discharges callees: unknown calls and transfers that
need invocation premises retain the existing proof owner's honest refusal. A deadline expiry or an in-flight
native census re-derivation returns a typed refusal product rather than a
partial proof. This is a narrow transport seam, not a second proof engine.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from .core import IRFunctionArtifact, IRRefusal
from .direct_evidence_deadline import direct_evidence_deadline_expired_8616
from .entry_jump_domain import (
    AdmittedTerminalJump8616,
    EntryJumpDomainApplication8616,
    EntryJumpDomainApplicationStatus8616,
    EntryJumpDomainProof8616,
    PendingTerminalJump8616,
    apply_entry_jump_domain_8616,
    collect_pending_terminal_jumps_8616,
    prove_entry_jump_domains_8616,
)
from .vex_import import (
    RawIRFunctionImportBundle8616,
    native_census_import_active_8616,
    raw_x86_16_function_bundle_8616,
)

__all__ = [
    "EntryJumpTransportProof8616",
    "EntryJumpTransportRefusal8616",
    "prove_entry_jump_transport_8616",
]


class EntryJumpTransportRefusal8616(StrEnum):
    """Typed reason the transport-stage proof product could not run."""

    CENSUS_IMPORT_ACTIVE = "entry_jump_transport_census_import_active"
    DIRECT_EVIDENCE_DEADLINE_EXPIRED = (
        "entry_jump_transport_direct_evidence_deadline_expired"
    )


@dataclass(frozen=True, slots=True)
class EntryJumpTransportProof8616:
    """Bound entry-domain proof product for one converted function surface.

    ``project`` and ``function`` retain the exact recovered identity the
    proof consumed — an admission is evidence for this pair only, never for
    a same-address look-alike. ``bundle`` retains the raw import: the
    pre-discharge blocks and the terminal evidence objects the proof
    authenticated, so a consumer binds each admission to the identical
    decoded carrier rather than a re-derived one. ``proof`` and
    ``application`` are the native owner products; ``application`` stays
    ``None`` when the proof could not be revalidated against the identical
    surface. ``refusal`` is the typed transport-stage non-result when the
    proof could not run at all. Nothing here is registered, published, or
    attached.
    """

    project: object = field(compare=False)
    function: object = field(compare=False)
    bundle: RawIRFunctionImportBundle8616 = field(compare=False)
    proof: EntryJumpDomainProof8616 | None
    application: EntryJumpDomainApplication8616 | None
    refusal: IRRefusal | None

    def pending_terminal_jumps(self) -> Mapping[int, PendingTerminalJump8616]:
        """Project the consumed terminal evidence into domain candidates."""
        return collect_pending_terminal_jumps_8616(
            self.bundle.terminal_evidence
        )

    def admitted_terminal_jumps(self) -> tuple[AdmittedTerminalJump8616, ...]:
        """Return the revalidated admissions, or empty when none stand."""
        application = self.application
        if (
            self.refusal is not None
            or application is None
            or application.status
            is not EntryJumpDomainApplicationStatus8616.APPLIED
        ):
            return ()
        return application.applied

    def to_dict(self) -> dict[str, object]:
        """Serialize the product for diagnostics; it is not fresh proof."""
        return {
            "function_addr": self.bundle.artifact.function_addr,
            "refusal": None if self.refusal is None else self.refusal.to_dict(),
            "proof": None if self.proof is None else self.proof.to_dict(),
            "application": (
                None
                if self.application is None
                else self.application.to_dict()
            ),
        }


def prove_entry_jump_transport_8616(
    project: object, function: object,
) -> EntryJumpTransportProof8616:
    """Prove pending terminal jumps for one converted function surface.

    Mirrors the universal importer's discharge segment over a fresh raw
    bundle: an identical domain artifact over the imported blocks and the
    existing proof and application owners, without caller or callee
    resolution. The pending surface is never registered,
    published, or attached. A native census re-derivation context or an
    expired direct-evidence deadline returns a typed refusal product; a
    surface with no pending candidates takes the constant-cost fast path
    with no census and no solver run.
    """
    bundle = raw_x86_16_function_bundle_8616(project, function)

    def _refused(
        reason: EntryJumpTransportRefusal8616,
        detail: str,
        *,
        proof: EntryJumpDomainProof8616 | None = None,
        application: EntryJumpDomainApplication8616 | None = None,
    ) -> EntryJumpTransportProof8616:
        """Close a typed refusal product over the imported bundle."""
        return EntryJumpTransportProof8616(
            project=project,
            function=function,
            bundle=bundle,
            proof=proof,
            application=application,
            refusal=IRRefusal(reason.value, detail, None),
        )

    if native_census_import_active_8616(project):
        return _refused(
            EntryJumpTransportRefusal8616.CENSUS_IMPORT_ACTIVE,
            "a native census re-derivation is in flight; the entry-domain "
            "discharge belongs to the consumed artifact, not this context",
        )
    if direct_evidence_deadline_expired_8616(project):
        return _refused(
            EntryJumpTransportRefusal8616.DIRECT_EVIDENCE_DEADLINE_EXPIRED,
            "direct-evidence deadline elapsed before the entry-domain "
            "proof could start",
        )
    if not collect_pending_terminal_jumps_8616(bundle.terminal_evidence):
        return EntryJumpTransportProof8616(
            project=project,
            function=function,
            bundle=bundle,
            proof=None,
            application=None,
            refusal=None,
        )
    function_addr = bundle.artifact.function_addr
    domain_artifact = IRFunctionArtifact(
        function_addr=function_addr,
        blocks=bundle.artifact.blocks,
        source_revision=bundle.artifact.source_revision,
    )
    proof = prove_entry_jump_domains_8616(
        domain_artifact,
        bundle.terminal_evidence,
        project=project,
    )
    if direct_evidence_deadline_expired_8616(project):
        return _refused(
            EntryJumpTransportRefusal8616.DIRECT_EVIDENCE_DEADLINE_EXPIRED,
            "direct-evidence deadline elapsed before application could "
            "revalidate the proof",
            proof=proof,
        )
    application = apply_entry_jump_domain_8616(domain_artifact, proof)
    return EntryJumpTransportProof8616(
        project=project,
        function=function,
        bundle=bundle,
        proof=proof,
        application=application,
        refusal=None,
    )
