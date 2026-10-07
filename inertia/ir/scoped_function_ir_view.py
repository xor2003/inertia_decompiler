"""Scoped function-IR CFG view bound to one authenticated consuming entry.

Layer: IR / control-domain transport.
Responsibility: retain one explicitly delimited transformation of a raw
in-flight function artifact — the entry-domain terminal-jump proof applied
under an independently supplied authenticated consuming scope — without
publishing the conditional body to the universal artifact registry. The
view revalidates the whole retained chain on every consumption: the
offered consuming entry must authenticate against the view's retained
scope through the shared entry-provenance owner, the retained scope must
still own the identical raw source artifact and boundary, the retained
application and accounting are rebound to the proof by identity and
recomputation — never by dataclass equality, which ignores provenance
fields — application admission is rerun end to end under the offered
scope, and the resulting block/instruction/refusal/edge census must
reconcile exactly with the proved delta including compare-excluded IR
metadata. Only admitted terminal JMP edges and their associated
selector-window refusal are ever discharged; a residual pending-window
refusal stays visible on the effective surface, exposes no outgoing-edge
claim to CFG consumers, and every unrelated refusal refuses. The
original source blocks and instruction objects remain the
effect-transfer and call-proof binding surface — admitted
blocks are reconstructed by the application owner, so consumers must
take instruction identity from ``source_block``/``source_artifact``, not
from the effective projection. There is no context-free ``complete`` and
no conversion to a universally publishable artifact.
Owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import StrEnum
from types import MappingProxyType

from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616

from .core import IRBlock, IRFunctionArtifact, IRRefusal, IRValue, MemSpace
from .entry_jump_domain import (
    AdmittedTerminalJump8616,
    EntryJumpDomainApplication8616,
    EntryJumpDomainApplicationStatus8616,
    EntryJumpDomainProof8616,
    _canonical_source_8616,
    apply_entry_jump_domain_8616,
)
from .ir_boundary_cfg import IRBoundaryCoverageResult8616
from .real16_invocation_domain import (
    Real16CallChainLink8616,
    Real16EnclosedEntryLink8616,
    Real16InvocationDomain8616,
    same_real16_entry_scope_8616,
)
from .segment_call_preservation import (
    segment_call_dependency_traversal_scope_8616,
)
from .vex_terminal_jump import TerminalJumpRefusalReason8616

__all__ = [
    "ScopedFunctionCFGProjection8616",
    "ScopedFunctionIRView8616",
    "ScopedFunctionIRViewFailure8616",
    "prove_scoped_function_ir_view_8616",
]

# The only refusal kind a scoped surface may still carry: a pending
# terminal jump that kept its default per-instruction window gate. The
# proof contract retains such candidates explicitly; their refusal is
# honest evidence of an edge that was never discharged, never a defect
# the consuming entry could waive.
_PENDING_JUMP_REFUSAL_KIND_8616 = (
    TerminalJumpRefusalReason8616.SELECTOR_WINDOW_UNPROVED.value
)


class ScopedFunctionIRViewFailure8616(StrEnum):
    """Typed reason a scoped function-IR view cannot certify its surface."""

    SCOPE_ABSENT = "scope_absent"
    SCOPE_UNBOUND = "scope_unbound"
    APPLICATION_REFUSED = "application_refused"
    APPLICATION_EMPTY = "application_empty"
    TRANSFORM_MISMATCH = "transform_mismatch"
    RESIDUAL_REFUSAL = "residual_refusal"


def _scope_surface_bound_8616(
    scope: Real16InvocationDomain8616 | None,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
) -> bool:
    """Prove the retained entry owns the identical raw source surface.

    The anchor rule mirrors the domain's own discharge owner: a
    coverage-bound entry consumes its registered ``artifact``/``boundary``
    pair, while an in-flight chained or enclosed entry consumes the
    retained link's callee pair — never a re-derived look-alike and never
    the enclosing census surface. Selector or address coincidence is not
    evidence; the surface must be the identical objects the entry's census
    was proved over, rooted at the consumed function head under the same
    project authority.
    """
    if scope is None or type(scope) is not Real16InvocationDomain8616:
        return False
    if scope.project is not boundary.project:
        return False
    if boundary.addr != artifact.function_addr:
        return False
    coverage = scope.coverage
    if coverage is not None:
        return (
            isinstance(coverage, IRBoundaryCoverageResult8616)
            and coverage.artifact is artifact
            and coverage.boundary is boundary
        )
    chain = scope.chain
    if isinstance(chain, (Real16CallChainLink8616, Real16EnclosedEntryLink8616)):
        return (
            chain.callee_artifact is artifact
            and chain.callee_boundary is boundary
        )
    return False


def _admitted_block_failure_8616(
    source_block: IRBlock,
    effective_block: IRBlock,
    jump: AdmittedTerminalJump8616,
) -> str | None:
    """Reconcile one admitted block against the exact proved delta.

    Only the proved rewrite is tolerated: the retained terminal JMP gains
    the proven loader-linear constant operand, the matching
    selector-window refusal is removed, and the proven target joins the
    successor set. Every other instruction must compare field-equal to
    its source twin — the application owner rebuilds admitted blocks, so
    identity lives on the source surface — and every non-discharged
    refusal and non-admitted edge must survive untouched.
    """
    if len(effective_block.instrs) != len(source_block.instrs):
        return "admitted block instruction census changed"
    rewritten = 0
    proven_args = (IRValue(MemSpace.CONST, const=jump.target, size=4),)
    for source_instr, effective_instr in zip(
        source_block.instrs, effective_block.instrs, strict=True
    ):
        if source_instr.op == "JMP" and source_instr.addr == jump.head:
            if effective_instr != replace(source_instr, args=proven_args):
                return (
                    "admitted transfer instruction diverges from the "
                    "proved operand rewrite"
                )
            rewritten += 1
        elif effective_instr != source_instr:
            return (
                "a non-transfer instruction changed inside an "
                "admitted block"
            )
    if rewritten != 1:
        return "admitted transfer instruction is missing or ambiguous"
    expected_refusals = tuple(
        refusal
        for refusal in source_block.refusals
        if not (
            refusal.kind == _PENDING_JUMP_REFUSAL_KIND_8616
            and refusal.block_addr == source_block.addr
        )
    )
    if effective_block.refusals != expected_refusals:
        return (
            "admitted block refusal census diverges from the proved "
            "discharge"
        )
    if effective_block.successor_addrs != tuple(
        sorted({*source_block.successor_addrs, jump.target})
    ):
        return "admitted block edge census diverges from the proved target"
    return None


def _transform_delta_failure_8616(
    source_blocks: tuple[IRBlock, ...],
    effective_blocks: tuple[IRBlock, ...],
    applied: tuple[AdmittedTerminalJump8616, ...],
) -> str | None:
    """Reconcile the effective census against the exact proved delta.

    Only an admitted block may differ from its source twin, and only by
    ``_admitted_block_failure_8616``'s proved rewrite. Every other block
    must be the identical source object — a rebuilt look-alike would
    break the instruction-identity contract effect and call-proof binding
    rely on. A missing or ambiguous transfer instruction, a dropped or
    extra refusal, or a reordered/foreign block is a typed mismatch,
    never a tolerated repair.
    """
    if len(effective_blocks) != len(source_blocks):
        return "effective block census differs from the proved source census"
    admitted_by_block: dict[int, AdmittedTerminalJump8616] = {}
    for jump in applied:
        if jump.block_addr in admitted_by_block:
            return "two admitted edges claim the same terminal block"
        admitted_by_block[jump.block_addr] = jump
    for source_block, effective_block in zip(
        source_blocks, effective_blocks, strict=True
    ):
        if effective_block.addr != source_block.addr:
            return (
                "effective block membership or order diverges from the "
                "proved source census"
            )
        admitted = admitted_by_block.get(source_block.addr)
        if admitted is None:
            if effective_block is not source_block:
                return (
                    "an unadmitted block was rebuilt; original instruction "
                    "identity is not preserved"
                )
            continue
        failure = _admitted_block_failure_8616(
            source_block, effective_block, admitted
        )
        if failure is not None:
            return failure
    return None


def _residual_refusal_failure_8616(blocks: tuple[IRBlock, ...]) -> str | None:
    """Refuse any effective refusal that is not a retained window pending.

    A pending selector-window refusal names an edge the proof never
    discharged; it stays visible so closure and coverage consumers see an
    honest hole. Every other refusal kind is an unrelated raw defect the
    consuming entry cannot waive — the view refuses rather than carry it
    under an authenticated surface.
    """
    for block in blocks:
        for refusal in block.refusals:
            if refusal.kind != _PENDING_JUMP_REFUSAL_KIND_8616:
                return (
                    f"block 0x{block.addr:x} retains unrelated refusal "
                    f"{refusal.kind!r}; an authenticated entry never "
                    "waives raw refusals"
                )
    return None


def _application_authentic_8616(
    application: EntryJumpDomainApplication8616,
    proof: EntryJumpDomainProof8616,
) -> bool:
    """Bind one application record to the exact retained proof objects.

    The application owner retains the proof's own ``admitted`` objects and
    the proof's recorded consuming entry on its result, and every nested
    provenance field on those records — ``invocation``,
    ``invocation_scope``, and each retained ``call_dependencies`` entry —
    is excluded from dataclass equality. Ordinary equality is therefore
    not evidence: an application only authenticates when its status is
    ``APPLIED`` with an empty refusal surface, its admissions are the same
    ordered objects the proof retains (so a rebuilt or stripped look-alike
    fails on identity, not on a field-by-field comparison that ignores the
    excluded fields), and its recorded consuming entry is the identical
    ``proof.invocation_scope`` object.
    """
    if application.status is not EntryJumpDomainApplicationStatus8616.APPLIED:
        return False
    if application.refusals != ():
        return False
    if len(application.applied) != len(proof.admitted):
        return False
    if any(
        applied is not recorded
        for applied, recorded in zip(
            application.applied, proof.admitted, strict=True
        )
    ):
        return False
    return application.invocation_scope is proof.invocation_scope


def _expected_view_counts_8616(
    proof: EntryJumpDomainProof8616, *, authenticated: bool
) -> tuple[int, int, int, int, int]:
    """Recompute the view's transport-admission ledger from the proof.

    These five counters account only for the scoped transport obligation —
    one proved candidate batch — never closed CFG coverage. An
    authenticated view materializes every admitted edge and keeps the
    proof's retained refusals as honest ``failure_count`` evidence; a
    refused or stale view materializes nothing and adds its own typed
    failure.
    """
    classified = len(proof.admitted) + len(proof.refusals)
    return (
        len(proof.source_binding.pending),
        classified,
        classified,
        len(proof.admitted) if authenticated else 0,
        len(proof.refusals) if authenticated else len(proof.refusals) + 1,
    )


@dataclass(frozen=True, slots=True)
class ScopedFunctionCFGProjection8616:
    """One bounded authenticated CFG consumption of the scoped view.

    ``source_artifact`` retains the identical raw input object for
    identity binding; ``scope`` is the explicit condition — the consuming
    entry the view authenticated for this single operation. ``applied``
    is the admitted-edge receipt. ``successors`` and ``predecessors`` are
    effective edge maps computed once from the freshly validated
    application: a consumer uses them only within this bounded operation,
    and a later independent consumer must revalidate through
    ``cfg_projection_for`` — this object is not a persistent cache.

    A block retaining a residual pending-window refusal is listed in
    ``pending`` with its refusals and exposes **no** entry in
    ``successors``: an unproved outgoing edge is an open hole, never a
    return exit. ``predecessors`` still records that block's raw census
    in-edges — the recorded edge into a pending block is honest evidence
    even while its own outgoing claim is withheld. Every lookup returns
    ``None`` for an address outside the authenticated census, so a
    foreign address can never masquerade as a proved exit block.
    """

    function_addr: int
    source_artifact: IRFunctionArtifact
    scope: Real16InvocationDomain8616
    applied: tuple[AdmittedTerminalJump8616, ...]
    blocks: tuple[IRBlock, ...]
    successors: Mapping[int, tuple[int, ...]]
    predecessors: Mapping[int, tuple[int, ...]]
    pending: Mapping[int, tuple[IRRefusal, ...]]

    def block_for(self, block_addr: int) -> IRBlock | None:
        """Return the effective block, or ``None`` outside the census."""
        for block in self.blocks:
            if block.addr == block_addr:
                return block
        return None

    def successors_for(self, block_addr: int) -> tuple[int, ...] | None:
        """Return authenticated successors, or ``None``.

        ``None`` means the address is outside the authenticated census or
        the block retains a residual pending-window refusal — in both
        cases there is no authenticated outgoing claim. An empty tuple is
        a proved exit within this view.
        """
        return self.successors.get(block_addr)

    def predecessors_for(self, block_addr: int) -> tuple[int, ...] | None:
        """Return recorded census in-edges, or ``None`` outside census."""
        return self.predecessors.get(block_addr)

    def pending_for(self, block_addr: int) -> tuple[IRRefusal, ...] | None:
        """Return residual refusals for one census block, or ``None``.

        ``None`` means the address is outside the authenticated census; an
        empty tuple means the block discharged every candidate; a
        non-empty tuple is the retained pending-window hole.
        """
        return self.pending.get(block_addr)


@dataclass(frozen=True, slots=True)
class ScopedFunctionIRView8616:
    """Scoped CFG view over one raw in-flight function artifact.

    ``source_artifact`` is the identical pending raw body the retained
    ``proof`` consumed; ``boundary`` is the exact frontend boundary the
    consuming entry authenticated; ``invocation_scope`` is the
    independently supplied consuming entry — never copied from the
    proof's own recorded scope — and ``application`` is the proof's
    materialization recomputed under that entry. ``failure`` records the
    typed non-result when construction cannot authenticate the chain;
    such a view is evidence of "no scoped transformation", and every
    projection refuses.

    Consumption goes through ``complete_for(offered_scope)`` only: the
    offered entry must authenticate against the retained scope via the
    shared entry-provenance owner, the retained scope must still own the
    identical raw surface, the retained application and counters are
    rebound to the proof by identity and recomputation — never by
    ordinary dataclass equality, which ignores provenance fields —
    application admission is rerun end to end under the offered scope,
    and the complete resulting block/instruction/refusal/edge census is
    reconciled against the proved delta before any effective
    successor/predecessor projection is exposed. Every projection
    consumes the fresh replay returned by ``_validated_application_for``,
    never the retained record; ``cfg_projection_for`` validates once and
    returns bounded edge maps for a single consumer operation. Nothing
    here registers or republishes the conditional body.
    """

    source_artifact: IRFunctionArtifact
    boundary: ExactFunctionRangeBoundary8616
    proof: EntryJumpDomainProof8616
    application: EntryJumpDomainApplication8616 | None
    failure: ScopedFunctionIRViewFailure8616 | None
    detail: str
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    invocation_scope: Real16InvocationDomain8616 | None = field(
        default=None, compare=False, repr=False
    )

    @property
    def complete(self) -> bool:
        """A scoped view never completes context-free; see ``complete_for``."""
        return self.complete_for(None)

    def _consumption_bound_8616(
        self, consuming_scope: Real16InvocationDomain8616 | None
    ) -> bool:
        """Rebind the offered entry and retained records to the proof.

        The offered entry must be a typed invocation domain that
        authenticates against the view's retained scope through
        ``same_real16_entry_scope_8616``, and the retained scope must
        still own the identical raw ``source_artifact``/``boundary``. The
        retained application must still be the exact result the proof
        produced: ``_application_authentic_8616`` binds its status,
        refusal surface, ordered admissions, and recorded consuming entry
        to the proof by identity — the fields dataclass equality is
        instructed to ignore are authenticated, never assumed — the five
        retained counters must recompute from the proof's own candidate
        ledger, and the retained block census must still reconcile with
        the proved delta by object identity and ordinary field equality.
        """
        if self.failure is not None:
            return False
        if (
            type(consuming_scope) is not Real16InvocationDomain8616
            or self.invocation_scope is None
            or self.application is None
        ):
            return False
        retained = self.application
        if not _scope_surface_bound_8616(
            self.invocation_scope, self.source_artifact, self.boundary
        ):
            return False
        if not same_real16_entry_scope_8616(
            consuming_scope, self.invocation_scope
        ):
            return False
        if not _application_authentic_8616(retained, self.proof):
            return False
        counts = (
            self.raw_fact_count,
            self.normalized_fact_count,
            self.classified_fact_count,
            self.materialized_count,
            self.failure_count,
        )
        if any(type(count) is not int for count in counts) or counts != (
            _expected_view_counts_8616(self.proof, authenticated=True)
        ):
            return False
        return (
            _transform_delta_failure_8616(
                self.source_artifact.blocks,
                retained.blocks,
                retained.applied,
            )
            is None
        )

    def _replay_authentic_8616(
        self, consuming_scope: Real16InvocationDomain8616 | None
    ) -> EntryJumpDomainApplication8616 | None:
        """Replay admission under the offered entry and authenticate it.

        The fresh application is rebound to the proof by the same
        identity rules as the retained record, its block census must
        reconcile with the proved delta, its canonical source form —
        which serializes every IR field including compare-excluded
        provenance — must equal the retained census, and no unrelated
        refusal may survive on the effective surface.
        """
        retained = self.application
        fresh = apply_entry_jump_domain_8616(
            self.source_artifact,
            self.proof,
            invocation_scope=consuming_scope,
        )
        if not _application_authentic_8616(fresh, self.proof):
            return None
        if (
            _transform_delta_failure_8616(
                self.source_artifact.blocks, fresh.blocks, fresh.applied
            )
            is not None
        ):
            return None
        if (
            retained is None
            or _canonical_source_8616(
                self.source_artifact.function_addr, retained.blocks
            )
            != _canonical_source_8616(
                self.source_artifact.function_addr, fresh.blocks
            )
        ):
            return None
        if _residual_refusal_failure_8616(fresh.blocks) is not None:
            return None
        return fresh

    def _validated_application_for(
        self, consuming_scope: Real16InvocationDomain8616 | None
    ) -> EntryJumpDomainApplication8616 | None:
        """Revalidate the retained chain and return fresh evidence or ``None``.

        The whole retained chain is rebound and replayed inside the
        shared bounded traversal: only the fresh application is returned,
        so consumers never read retained state that was not just
        revalidated.
        """
        with segment_call_dependency_traversal_scope_8616():
            if not self._consumption_bound_8616(consuming_scope):
                return None
            return self._replay_authentic_8616(consuming_scope)

    def complete_for(
        self, consuming_scope: Real16InvocationDomain8616 | None
    ) -> bool:
        """Revalidate the retained chain under the offered consuming entry.

        This verdict certifies the scoped transport admission only: the
        proved candidate batch applied under an authenticated entry. A
        partially discharged proof still completes here while carrying
        retained pending-window refusals — ``complete_for`` is never
        closed CFG coverage, and every residual refusal stays visible on
        the effective surface for coverage and closure consumers.
        """
        return self._validated_application_for(consuming_scope) is not None

    def applied_jumps_for(
        self, consuming_scope: Real16InvocationDomain8616 | None
    ) -> tuple[AdmittedTerminalJump8616, ...] | None:
        """Return the admitted terminal edges under an authenticated entry."""
        application = self._validated_application_for(consuming_scope)
        return None if application is None else application.applied

    def effective_blocks_for(
        self, consuming_scope: Real16InvocationDomain8616 | None
    ) -> tuple[IRBlock, ...] | None:
        """Return the effective block surface under an authenticated entry.

        Admitted blocks are reconstructed by the application owner, so
        their instruction objects are not the original identity: effect
        transfer and call-proof binding must consume ``source_block`` /
        ``source_artifact`` instead. Residual pending-window refusals
        remain visible on this surface.
        """
        application = self._validated_application_for(consuming_scope)
        return None if application is None else application.blocks

    def effective_successors_for(
        self,
        consuming_scope: Real16InvocationDomain8616 | None,
        block_addr: int,
    ) -> tuple[int, ...] | None:
        """Return the scoped CFG successors of one block, or ``None``.

        ``None`` means there is no authenticated outgoing claim: the view
        refused under the offered entry, the address is outside the
        authenticated census, or the block retains a residual
        pending-window refusal — an unproved edge is an open hole, never
        a return exit. An empty tuple is a proved exit within this view.
        A consumer walking many blocks should validate once through
        ``cfg_projection_for`` instead of revalidating per block here.
        """
        application = self._validated_application_for(consuming_scope)
        if application is None:
            return None
        for block in application.blocks:
            if block.addr == block_addr:
                return None if block.refusals else block.successor_addrs
        return None

    def effective_predecessors_for(
        self,
        consuming_scope: Real16InvocationDomain8616 | None,
        block_addr: int,
    ) -> tuple[int, ...] | None:
        """Return the scoped CFG predecessors of one block, or ``None``.

        ``None`` means the view refused or the address is outside the
        authenticated census; recorded census in-edges are returned
        otherwise, including edges recorded from a block whose own
        outgoing claim remains pending.
        """
        application = self._validated_application_for(consuming_scope)
        if application is None:
            return None
        census = {block.addr for block in application.blocks}
        if block_addr not in census:
            return None
        return tuple(
            sorted(
                block.addr
                for block in application.blocks
                if block_addr in block.successor_addrs
            )
        )

    def cfg_projection_for(
        self, consuming_scope: Real16InvocationDomain8616 | None
    ) -> ScopedFunctionCFGProjection8616 | None:
        """Validate once; return bounded CFG maps for one consumer operation.

        A single ``_validated_application_for`` replay authenticates the
        whole retained chain; the returned
        ``ScopedFunctionCFGProjection8616`` carries the source identity,
        the authenticated consuming entry as its explicit condition, the
        admitted-edge receipt, and predecessor/successor/pending maps for
        that single bounded consumption — it is not a persistent
        unconditional cache, and later independent consumers revalidate
        here rather than trusting a prior projection.
        """
        application = self._validated_application_for(consuming_scope)
        if application is None or consuming_scope is None:
            return None
        successors: dict[int, tuple[int, ...]] = {}
        predecessor_lists: dict[int, list[int]] = {
            block.addr: [] for block in application.blocks
        }
        pending: dict[int, tuple[IRRefusal, ...]] = {}
        for block in application.blocks:
            pending[block.addr] = block.refusals
            if not block.refusals:
                successors[block.addr] = block.successor_addrs
            for target in block.successor_addrs:
                if target in predecessor_lists:
                    predecessor_lists[target].append(block.addr)
        return ScopedFunctionCFGProjection8616(
            function_addr=self.source_artifact.function_addr,
            source_artifact=self.source_artifact,
            scope=consuming_scope,
            applied=application.applied,
            blocks=application.blocks,
            successors=MappingProxyType(successors),
            predecessors=MappingProxyType(
                {
                    addr: tuple(sorted(preds))
                    for addr, preds in predecessor_lists.items()
                }
            ),
            pending=MappingProxyType(pending),
        )

    def source_block(self, block_addr: int) -> IRBlock | None:
        """Return the original source block object for identity binding.

        Register-effect transfer and call-proof binding must consume the
        original instruction objects — the effective projection rebuilds
        admitted blocks, so only the source surface preserves the
        identities retained evidence records point at.
        """
        for block in self.source_artifact.blocks:
            if block.addr == block_addr:
                return block
        return None

    def to_dict(self) -> dict[str, object]:
        """Serialize the scoped view receipt for diagnostics and workers.

        Stale evidence is never serialized as accepted: the retained chain
        is revalidated under the view's own consuming entry, and admitted
        edges, the application status, and the ledger are emitted only
        from a freshly authenticated replay. ``authenticated`` records
        that verdict explicitly — a refused view and a view whose retained
        state no longer revalidates both serialize ``applied`` as empty —
        ``residual_pending_count`` counts the pending-window holes the
        effective surface still carries, so a partially discharged view is
        distinguishable from closed coverage, and the five counters are
        recomputed from the retained proof rather than trusted.
        """
        application = self._validated_application_for(self.invocation_scope)
        authenticated = application is not None
        counts = _expected_view_counts_8616(
            self.proof, authenticated=authenticated
        )
        return {
            "function_addr": self.source_artifact.function_addr,
            "boundary_addr": self.boundary.addr,
            "failure": None if self.failure is None else self.failure.value,
            "detail": self.detail,
            "authenticated": authenticated,
            "application_status": (
                None
                if application is None
                else application.status.value
            ),
            "applied": (
                []
                if application is None
                else [jump.to_dict() for jump in application.applied]
            ),
            "residual_pending_count": (
                0
                if application is None
                else sum(
                    len(block.refusals) for block in application.blocks
                )
            ),
            "invocation_scope": (
                None
                if self.invocation_scope is None
                else self.invocation_scope.to_dict()
            ),
            "raw_fact_count": counts[0],
            "normalized_fact_count": counts[1],
            "classified_fact_count": counts[2],
            "materialized_count": counts[3],
            "failure_count": counts[4],
        }


def _view_evaluation_8616(
    source_artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    proof: EntryJumpDomainProof8616,
    invocation_scope: Real16InvocationDomain8616,
) -> tuple[
    ScopedFunctionIRViewFailure8616 | None,
    str,
    EntryJumpDomainApplication8616 | None,
]:
    """Evaluate the scoped-view chain once for one supplied entry.

    The supplied entry must authenticate itself, own the identical raw
    surface through the domain's consumption anchor, and replay the
    proof's application admission end to end; the resulting
    block/instruction/refusal/edge census is then reconciled against the
    proved delta. Each typed refusal names the first stage that could
    not close — a later stage is never consulted to launder an earlier
    failure.
    """
    if not same_real16_entry_scope_8616(invocation_scope, invocation_scope):
        return (
            ScopedFunctionIRViewFailure8616.SCOPE_UNBOUND,
            "the supplied consuming entry cannot authenticate itself",
            None,
        )
    if not _scope_surface_bound_8616(
        invocation_scope, source_artifact, boundary
    ):
        return (
            ScopedFunctionIRViewFailure8616.SCOPE_UNBOUND,
            "the supplied consuming entry does not own the identical raw "
            "source artifact and boundary",
            None,
        )
    application = apply_entry_jump_domain_8616(
        source_artifact, proof, invocation_scope=invocation_scope
    )
    if application.status is EntryJumpDomainApplicationStatus8616.STALE_INPUT:
        detail = (
            application.refusals[0].detail
            if application.refusals
            else "proof application refused its input surface"
        )
        return (
            ScopedFunctionIRViewFailure8616.APPLICATION_REFUSED,
            detail,
            application,
        )
    if application.status is not EntryJumpDomainApplicationStatus8616.APPLIED:
        return (
            ScopedFunctionIRViewFailure8616.APPLICATION_EMPTY,
            "the retained proof admitted no edge for the scope to carry",
            application,
        )
    delta = _transform_delta_failure_8616(
        source_artifact.blocks, application.blocks, application.applied
    )
    if delta is not None:
        return (
            ScopedFunctionIRViewFailure8616.TRANSFORM_MISMATCH,
            delta,
            application,
        )
    residual = _residual_refusal_failure_8616(application.blocks)
    if residual is not None:
        return (
            ScopedFunctionIRViewFailure8616.RESIDUAL_REFUSAL,
            residual,
            application,
        )
    return None, "", application


def prove_scoped_function_ir_view_8616(
    source_artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    proof: EntryJumpDomainProof8616,
    *,
    invocation_scope: Real16InvocationDomain8616 | None,
) -> ScopedFunctionIRView8616:
    """Construct the scoped CFG view for one authenticated consuming entry.

    ``invocation_scope`` is the independently supplied consuming entry —
    it is never read from ``proof.invocation_scope``, so a proof cannot
    self-certify its own consuming authorization. The supplied entry must
    authenticate itself, own the identical raw ``source_artifact``/
    ``boundary`` through the domain's consumption anchor, and replay the
    proof's application admission end to end before the view retains the
    result. Every refusal is a typed non-result view: no pending body is
    registered, published, or presented as universally complete.
    """
    if type(source_artifact) is not IRFunctionArtifact:
        raise TypeError("scoped view requires a typed IRFunctionArtifact source")
    if not isinstance(boundary, ExactFunctionRangeBoundary8616):
        raise TypeError("scoped view requires the exact frontend boundary")
    if type(proof) is not EntryJumpDomainProof8616:
        raise TypeError("scoped view requires the retained entry-domain proof")
    if invocation_scope is not None and (
        type(invocation_scope) is not Real16InvocationDomain8616
    ):
        raise TypeError(
            "consuming entry must be a typed invocation domain or absent"
        )

    def refuse(
        failure: ScopedFunctionIRViewFailure8616,
        detail: str,
        application: EntryJumpDomainApplication8616 | None = None,
    ) -> ScopedFunctionIRView8616:
        counts = _expected_view_counts_8616(proof, authenticated=False)
        return ScopedFunctionIRView8616(
            source_artifact=source_artifact,
            boundary=boundary,
            proof=proof,
            application=application,
            failure=failure,
            detail=detail,
            raw_fact_count=counts[0],
            normalized_fact_count=counts[1],
            classified_fact_count=counts[2],
            materialized_count=counts[3],
            failure_count=counts[4],
            invocation_scope=invocation_scope,
        )

    if invocation_scope is None:
        return refuse(
            ScopedFunctionIRViewFailure8616.SCOPE_ABSENT,
            "no independently supplied consuming entry was offered",
        )
    failure, detail, application = _view_evaluation_8616(
        source_artifact, boundary, proof, invocation_scope
    )
    if failure is not None:
        return refuse(failure, detail, application)
    assert application is not None
    counts = _expected_view_counts_8616(proof, authenticated=True)
    return ScopedFunctionIRView8616(
        source_artifact=source_artifact,
        boundary=boundary,
        proof=proof,
        application=application,
        failure=None,
        detail="",
        raw_fact_count=counts[0],
        normalized_fact_count=counts[1],
        classified_fact_count=counts[2],
        materialized_count=counts[3],
        failure_count=counts[4],
        invocation_scope=invocation_scope,
    )
