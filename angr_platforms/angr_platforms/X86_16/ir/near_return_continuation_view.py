"""Scoped near-return continuation view over one raw pending artifact.

Layer: IR / control-domain transport.
Responsibility: retain the conditional return evidence a premise-derived
callee import carries — raw ``JMP`` source facts plus the typed
``near_return_continuation_pending`` refusals — and expose the effective
``RET`` surface only to the one consuming entry that authenticates the
source-bound ``NearCallFramePremise8616``. The view never registers,
publishes, or rewrites the retained artifact: the raw body keeps its
pending markers, so the universal registry, universal coverage, and every
context-free consumer keep refusing it. Consumption goes through
``cfg_projection_for(scope)``/``complete_for(scope)`` only: the offered
entry must be a typed invocation domain that self-authenticates through
the shared entry-provenance owner, crosses the identical decoded
near-CALL row and index the premise retains, and owns the identical raw
artifact/boundary pair through its retained chain link. A foreign,
stale, unbound, or absent premise — or a scope that cannot rebind that
exact edge — refuses with a typed non-result. When the premise-derived
body also carries selector-window obligations, the view additionally
retains the joint discharge evidence composed by the
scoped-control-obligations owner and replays both conditional
obligations under the same consuming entry; no marker class ever waives
the other.
Owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING

from ..frontend_function_boundary import ExactFunctionRangeBoundary8616
from ..frontend_near_return_continuation import (
    NearCallFramePremise8616,
    near_call_frame_premise_stale_8616,
)
from .core import IRBlock, IRFunctionArtifact, IRInstr, IRRefusal

if TYPE_CHECKING:
    from .entry_jump_domain import (
        EntryJumpDomainApplication8616,
        EntryJumpDomainProof8616,
    )
    from .real16_invocation_domain import Real16InvocationDomain8616
    from .scoped_function_ir_view import ScopedFunctionCFGProjection8616

__all__ = [
    "NEAR_RETURN_CONTINUATION_PENDING_KIND_8616",
    "ScopedNearReturnContinuationView8616",
    "ScopedNearReturnContinuationViewFailure8616",
    "prove_scoped_near_return_continuation_view_8616",
]

# The continuation pending marker: the near-return continuation the
# Frontend census proved but no consuming entry has yet authenticated.
# The marker withholds the conditional body from every universal route —
# registry publication, universal coverage, cached closure — until this
# view discharges it under the bound frame. A premise-derived artifact
# may additionally carry selector-window pending markers; those belong
# to the joint obligation surface the scoped-control-obligations owner
# composes under the same consuming entry, never to this marker's own
# discharge.
NEAR_RETURN_CONTINUATION_PENDING_KIND_8616: str = "near_return_continuation_pending"


class ScopedNearReturnContinuationViewFailure8616(StrEnum):
    """Typed reason a scoped continuation view cannot certify its surface."""

    SCOPE_ABSENT = "scope_absent"
    SCOPE_UNBOUND = "scope_unbound"
    PREMISE_ABSENT = "premise_absent"
    PREMISE_STALE = "premise_stale"
    SURFACE_MISMATCH = "surface_mismatch"
    RESIDUAL_REFUSAL = "residual_refusal"
    APPLICATION_REFUSED = "application_refused"
    APPLICATION_EMPTY = "application_empty"
    TRANSFORM_MISMATCH = "transform_mismatch"


def _pending_surface_failure_8616(
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
) -> tuple[
    ScopedNearReturnContinuationViewFailure8616 | None,
    str,
    NearCallFramePremise8616 | None,
    frozenset[int],
]:
    """Audit the pending surface the conditional view may discharge.

    Every refusal on the retained artifact — block-level or
    function-level — must be the continuation pending marker itself, and
    every marker must sit on a block the retained
    ``NearReturnContinuationArtifact8616`` proved. A proven block must
    still carry the raw ``JMP`` terminal and at least one marker; any
    other refusal is an unrelated raw defect no consuming entry may
    waive.
    """
    if (
        type(artifact) is not IRFunctionArtifact
        or not isinstance(boundary, ExactFunctionRangeBoundary8616)
        or boundary.addr != artifact.function_addr
    ):
        return (
            ScopedNearReturnContinuationViewFailure8616.SURFACE_MISMATCH,
            "artifact and boundary do not describe one identical surface",
            None,
            frozenset(),
        )
    continuations = boundary.near_return_continuations
    premise = None if continuations is None else continuations.premise
    if type(premise) is not NearCallFramePremise8616:
        return (
            ScopedNearReturnContinuationViewFailure8616.PREMISE_ABSENT,
            "boundary carries no source-bound near-call frame premise",
            None,
            frozenset(),
        )
    proven = frozenset() if continuations is None else (
        continuations.proven_block_addrs
    )
    if not proven or premise.callee_addr != artifact.function_addr:
        return (
            ScopedNearReturnContinuationViewFailure8616.SURFACE_MISMATCH,
            "premise binds a foreign callee head or proves nothing",
            premise,
            frozenset(),
        )
    if near_call_frame_premise_stale_8616(premise):
        return (
            ScopedNearReturnContinuationViewFailure8616.PREMISE_STALE,
            "retained index no longer authenticates the premise row",
            premise,
            frozenset(),
        )
    blocks_by_addr = {block.addr: block for block in artifact.blocks}
    if any(addr not in blocks_by_addr for addr in proven):
        return (
            ScopedNearReturnContinuationViewFailure8616.SURFACE_MISMATCH,
            "proven continuation block is absent from the raw census",
            premise,
            frozenset(),
        )
    block_failure = _pending_block_failure_8616(artifact, proven)
    if block_failure is not None:
        return block_failure[0], block_failure[1], premise, frozenset()
    for refusal in artifact.refusals:
        if (
            refusal.kind != NEAR_RETURN_CONTINUATION_PENDING_KIND_8616
            or refusal.block_addr not in proven
        ):
            return (
                ScopedNearReturnContinuationViewFailure8616.RESIDUAL_REFUSAL,
                "artifact retains a refusal outside the proven "
                "continuation census",
                premise,
                frozenset(),
            )
    return None, "", premise, frozenset(proven)


def _pending_block_failure_8616(
    artifact: IRFunctionArtifact,
    proven: frozenset[int],
) -> tuple[ScopedNearReturnContinuationViewFailure8616, str] | None:
    """Audit every block-level marker against the proven census.

    A proven block must keep its raw ``JMP`` terminal and at least one
    pending marker; a block-level refusal anywhere else — or any kind
    other than the pending marker itself — is a raw defect no consuming
    entry may waive.
    """
    for block in artifact.blocks:
        if block.addr in proven:
            terminal = block.instrs[-1] if block.instrs else None
            if terminal is None or terminal.op != "JMP":
                return (
                    ScopedNearReturnContinuationViewFailure8616.SURFACE_MISMATCH,
                    "proven block lost its retained raw JMP terminal",
                )
            if not any(
                refusal.kind == NEAR_RETURN_CONTINUATION_PENDING_KIND_8616
                for refusal in block.refusals
            ):
                return (
                    ScopedNearReturnContinuationViewFailure8616.SURFACE_MISMATCH,
                    "proven block carries no continuation pending marker",
                )
        for refusal in block.refusals:
            if (
                refusal.kind != NEAR_RETURN_CONTINUATION_PENDING_KIND_8616
                or block.addr not in proven
            ):
                return (
                    ScopedNearReturnContinuationViewFailure8616.RESIDUAL_REFUSAL,
                    f"block 0x{block.addr:x} retains unrelated refusal "
                    f"{refusal.kind!r}; an authenticated entry never "
                    "waives raw refusals",
                )
    return None


def _scope_binds_premise_8616(
    scope: Real16InvocationDomain8616 | None,
    premise: NearCallFramePremise8616,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
) -> bool:
    """Prove one consuming entry owns the premise's exact decoded edge.

    Only a chain-bound in-flight entry may consume conditional evidence:
    its retained link must carry the identical decoded row and index the
    premise binds and own the identical raw artifact/boundary pair —
    then the whole entry self-authenticates through the shared
    entry-provenance owner, which replays parent provenance. A
    coverage-bound entry names a registered surface and can never own a
    pending body; an enclosed entry crosses an enclosing surface, not
    this exact edge.
    """
    from .real16_invocation_domain import (
        Real16CallChainLink8616,
        Real16InvocationDomain8616,
        same_real16_entry_scope_8616,
    )

    if (
        type(scope) is not Real16InvocationDomain8616
        or scope.project is not boundary.project
        or scope.coverage is not None
    ):
        return False
    link = scope.chain
    if type(link) is not Real16CallChainLink8616:
        return False
    if (
        link.callsite is not premise.callsite
        or link.callsite_index is not premise.callsite_index
        or link.callee_artifact is not artifact
        or link.callee_boundary is not boundary
    ):
        return False
    return same_real16_entry_scope_8616(scope, scope)


@dataclass(frozen=True, slots=True)
class ScopedNearReturnContinuationView8616:
    """Scoped conditional view over one premise-derived raw artifact.

    ``source_artifact`` is the identical pending raw body — raw ``JMP``
    facts plus continuation pending markers — never a transformed or
    publishable artifact. ``premise`` and ``invocation_scope`` are
    identity-bound provenance excluded from equality and the repr.
    ``failure`` records the typed non-result when construction cannot
    authenticate the chain; every projection then refuses. There is no
    context-free ``complete``: only ``complete_for``/
    ``cfg_projection_for`` under an offered entry that re-authenticates
    the retained premise and scope end to end exposes the effective
    ``RET`` surface.

    When the raw surface also carries selector-window obligations,
    ``selector_proof``/``selector_application`` retain the composed
    discharge the scoped-control-obligations owner produced over the
    continuation-effective surface under the same consuming entry; the
    projection then replays both conditional discharges in order and
    keeps un-discharged selector markers visible as pending holes.
    """

    source_artifact: IRFunctionArtifact
    boundary: ExactFunctionRangeBoundary8616
    failure: ScopedNearReturnContinuationViewFailure8616 | None
    detail: str
    proven_block_addrs: frozenset[int]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    premise: NearCallFramePremise8616 | None = field(
        default=None, compare=False, repr=False
    )
    invocation_scope: Real16InvocationDomain8616 | None = field(
        default=None, compare=False, repr=False
    )
    selector_proof: EntryJumpDomainProof8616 | None = field(
        default=None, compare=False, repr=False
    )
    selector_application: EntryJumpDomainApplication8616 | None = field(
        default=None, compare=False, repr=False
    )

    @property
    def complete(self) -> bool:
        """A scoped view never completes context-free; see ``complete_for``."""
        return self.complete_for(None)

    def source_block(self, block_addr: int) -> IRBlock | None:
        """Return the identical raw block for identity binding."""
        for block in self.source_artifact.blocks:
            if block.addr == block_addr:
                return block
        return None

    def complete_for(
        self, consuming_scope: Real16InvocationDomain8616 | None
    ) -> bool:
        """Return whether the offered entry authenticates this view."""
        return self.cfg_projection_for(consuming_scope) is not None

    def cfg_projection_for(
        self, consuming_scope: Real16InvocationDomain8616 | None
    ) -> ScopedFunctionCFGProjection8616 | None:
        """Replay the whole chain and return the bounded effective CFG.

        The offered entry must authenticate against the retained scope
        through the shared entry-provenance owner and rebind the
        premise's exact decoded edge to the identical raw surface; only
        then does the projection expose it. Proven blocks are rebuilt
        with their ``JMP`` discharged to ``RET`` and their pending
        markers removed — a single-consumer operation, never a stored
        rewrite — while every other block stays the identical source
        object. A block with a residual refusal is listed in ``pending``
        and publishes no outgoing-edge claim. Consumption is also
        evidence-closed: the retained counters must form an exact
        integer ledger ``(N, N, N, N, 0)`` over a nonempty proven
        census — a forged or partially consumed ledger can never
        authorize a projection.

        A view retaining joint selector evidence replays the composed
        chain instead: the retained counters must recompute the joint
        per-marker obligation ledger, and the scoped-control-obligations
        owner re-derives the continuation-effective surface and replays
        the selector proof's application admission under the same
        offered entry before any effective edges are exposed.
        """
        from .real16_invocation_domain import (
            Real16InvocationDomain8616,
            same_real16_entry_scope_8616,
        )

        if (
            self.failure is not None
            or self.premise is None
            or self.invocation_scope is None
        ):
            return None
        if (
            type(consuming_scope) is not Real16InvocationDomain8616
            or consuming_scope.project is not self.boundary.project
        ):
            return None
        if not same_real16_entry_scope_8616(
            consuming_scope, self.invocation_scope
        ):
            return None
        if not _scope_binds_premise_8616(
            consuming_scope,
            self.premise,
            self.source_artifact,
            self.boundary,
        ):
            return None
        counts = (
            self.raw_fact_count,
            self.normalized_fact_count,
            self.classified_fact_count,
            self.materialized_count,
            self.failure_count,
        )
        if self.selector_proof is not None:
            from .scoped_control_obligations import (
                scoped_obligations_expected_counts_8616,
                scoped_obligations_projection_8616,
            )

            if any(type(count) is not int for count in counts) or counts != (
                scoped_obligations_expected_counts_8616(
                    self, authenticated=True
                )
            ):
                return None
            return scoped_obligations_projection_8616(self, consuming_scope)
        expected = len(self.proven_block_addrs)
        if (
            expected == 0
            or any(type(count) is not int for count in counts)
            or counts != (expected, expected, expected, expected, 0)
        ):
            return None
        return self._effective_projection_8616(consuming_scope)

    def _effective_projection_8616(
        self, consuming_scope: Real16InvocationDomain8616,
    ) -> ScopedFunctionCFGProjection8616 | None:
        """Build the bounded effective CFG for one authenticated entry."""
        from .scoped_function_ir_view import ScopedFunctionCFGProjection8616

        census = {block.addr for block in self.source_artifact.blocks}
        successors: dict[int, tuple[int, ...]] = {}
        predecessors: dict[int, list[int]] = {addr: [] for addr in census}
        pending: dict[int, tuple[IRRefusal, ...]] = {}
        effective: list[IRBlock] = []
        for block in self.source_artifact.blocks:
            residual = tuple(
                refusal
                for refusal in block.refusals
                if not (
                    block.addr in self.proven_block_addrs
                    and refusal.kind
                    == NEAR_RETURN_CONTINUATION_PENDING_KIND_8616
                )
            )
            if block.addr in self.proven_block_addrs:
                terminal = block.instrs[-1] if block.instrs else None
                if terminal is None or terminal.op != "JMP" or residual:
                    return None
                effective.append(
                    IRBlock(
                        addr=block.addr,
                        instrs=(
                            *block.instrs[:-1],
                            IRInstr(
                                op="RET",
                                dst=None,
                                args=(),
                                addr=terminal.addr,
                                origin=terminal.origin,
                            ),
                        ),
                        refusals=(),
                        successor_addrs=block.successor_addrs,
                    )
                )
            else:
                effective.append(block)
            if residual:
                pending[block.addr] = residual
                continue
            pending[block.addr] = ()
            successors[block.addr] = block.successor_addrs
        for block in self.source_artifact.blocks:
            for target in block.successor_addrs:
                if target in predecessors:
                    predecessors[target].append(block.addr)
        return ScopedFunctionCFGProjection8616(
            function_addr=self.source_artifact.function_addr,
            source_artifact=self.source_artifact,
            scope=consuming_scope,
            applied=(),
            blocks=tuple(effective),
            successors=MappingProxyType(successors),
            predecessors=MappingProxyType(
                {
                    addr: tuple(sorted(sources))
                    for addr, sources in predecessors.items()
                }
            ),
            pending=MappingProxyType(pending),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize this view's verdict and retained coordinates."""
        return {
            "verdict": "proven" if self.failure is None else "unknown_refuse",
            "failure": None if self.failure is None else self.failure.value,
            "detail": self.detail,
            "function_addr": self.source_artifact.function_addr,
            "proven_block_addrs": sorted(self.proven_block_addrs),
            "premise": (
                None if self.premise is None else self.premise.to_dict()
            ),
            "selector_proof": (
                None
                if self.selector_proof is None
                else self.selector_proof.to_dict()
            ),
            "selector_application_status": (
                None
                if self.selector_application is None
                else self.selector_application.status.value
            ),
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
        }


def prove_scoped_near_return_continuation_view_8616(
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    *,
    invocation_scope: Real16InvocationDomain8616 | None,
) -> ScopedNearReturnContinuationView8616:
    """Construct the scoped continuation view for one consuming entry.

    ``invocation_scope`` is independently supplied — never read back from
    the premise or inferred from the surface — and must be the typed
    chain-bound entry that crosses the premise's identical decoded
    near-CALL edge and owns this exact raw artifact/boundary pair. A
    missing, foreign, stale, or unauthenticated chain records a typed
    non-result; nothing here registers, publishes, or rebuilds the
    pending body.
    """
    failure, detail, premise, proven = _pending_surface_failure_8616(
        artifact, boundary
    )
    if failure is None:
        from .real16_invocation_domain import Real16InvocationDomain8616

        if type(invocation_scope) is not Real16InvocationDomain8616:
            failure = ScopedNearReturnContinuationViewFailure8616.SCOPE_ABSENT
            detail = "no typed consuming entry was supplied"
        elif premise is not None and not _scope_binds_premise_8616(
            invocation_scope, premise, artifact, boundary
        ):
            failure = ScopedNearReturnContinuationViewFailure8616.SCOPE_UNBOUND
            detail = (
                "consuming entry does not cross the premise's exact "
                "decoded near-call edge"
            )
    classified = len(proven)
    return ScopedNearReturnContinuationView8616(
        source_artifact=artifact,
        boundary=boundary,
        failure=failure,
        detail=detail,
        proven_block_addrs=proven,
        raw_fact_count=classified,
        normalized_fact_count=classified,
        classified_fact_count=classified,
        materialized_count=classified if failure is None else 0,
        failure_count=0 if failure is None else 1,
        premise=premise,
        invocation_scope=(
            invocation_scope if failure is None else None
        ),
    )
