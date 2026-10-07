"""Source-bound composition of premise-derived conditional obligations.

Layer: IR / control-domain transport.
Responsibility: compose the two existing conditional-discharge owners for one
premise-derived raw artifact that carries both marker classes — the
source-bound ``NearCallFramePremise8616`` continuation evidence and the
entry-domain terminal-jump selector-window proof. The continuation
discharge is applied first, producing the *continuation-effective surface*
(S1): every proven block rebuilt ``JMP``→``RET`` with its pending markers
removed and every other block kept as the identical raw object. The retained
``prove_entry_jump_domains_8616``/``apply_entry_jump_domain_8616`` pair then
runs over S1 exactly as it would over a raw artifact, so every selector
obligation is still proven against the same native bytes, the same boundary,
and the same independently supplied invocation entry. The composed product
is a ``ScopedNearReturnContinuationView8616`` — the scoped view owner for
premise-derived bodies — retaining the selector proof/application as joint
evidence; it is never registered, published, or exposed context-free.

Consumption replays the whole chain per operation: S1 is re-derived
deterministically from the retained raw artifact and proven census, its
canonical digest is rebound to the proof's recorded source binding, the
retained application is re-authenticated by object identity, and a fresh
application under the offered entry is reconciled field-by-field against
the proved delta. Missing, changed, foreign, or stale evidence of either
class — and every unrelated raw refusal — yields a typed non-result; a
near-return proof never waives selector markers and a selector proof never
waives the continuation marker.
Owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import TYPE_CHECKING

from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
from inertia.frontend.x86_16.frontend_near_return_continuation import (
    NearCallFramePremise8616,
    near_call_frame_premise_stale_8616,
)

from .core import IRBlock, IRFunctionArtifact, IRInstr, IRRefusal
from .entry_jump_domain import (
    EntryJumpDomainApplication8616,
    EntryJumpDomainApplicationStatus8616,
    EntryJumpDomainProof8616,
    _canonical_source_8616,
    _source_digest_8616,
    apply_entry_jump_domain_8616,
    prove_entry_jump_domains_8616,
)
from .near_return_continuation_view import (
    NEAR_RETURN_CONTINUATION_PENDING_KIND_8616,
    ScopedNearReturnContinuationView8616,
    ScopedNearReturnContinuationViewFailure8616,
    _scope_binds_premise_8616,
)
from .scoped_function_ir_view import (
    ScopedFunctionCFGProjection8616,
    _application_authentic_8616,
    _residual_refusal_failure_8616,
    _transform_delta_failure_8616,
)
from .segment_call_preservation import (
    segment_call_dependency_traversal_scope_8616,
)
from .vex_terminal_jump import (
    TerminalJumpEvidence8616,
    TerminalJumpRefusalReason8616,
)

if TYPE_CHECKING:
    from .entry_domain_call_preservation import EntryDomainCallPreservation8616
    from .real16_invocation_domain import Real16InvocationDomain8616

__all__ = [
    "mixed_pending_obligations_8616",
    "prove_scoped_control_obligations_8616",
    "scoped_obligations_expected_counts_8616",
    "scoped_obligations_projection_8616",
]

_SELECTOR_WINDOW_PENDING_KIND_8616 = (
    TerminalJumpRefusalReason8616.SELECTOR_WINDOW_UNPROVED.value
)


def mixed_pending_obligations_8616(artifact: object) -> bool:
    """Return whether one raw surface carries non-continuation refusals.

    A premise-derived artifact whose every refusal is the continuation
    pending marker belongs to the single-class continuation view owner;
    anything else — a selector-window obligation or an unrelated raw
    defect — must route through the composed obligation audit so each
    marker class is accounted for explicitly.
    """
    if type(artifact) is not IRFunctionArtifact:
        return False
    return any(
        refusal.kind != NEAR_RETURN_CONTINUATION_PENDING_KIND_8616
        for block in artifact.blocks
        for refusal in block.refusals
    ) or any(
        refusal.kind != NEAR_RETURN_CONTINUATION_PENDING_KIND_8616
        for refusal in artifact.refusals
    )


def _continuation_marker_blocks_8616(
    artifact: IRFunctionArtifact,
) -> frozenset[int]:
    """Enumerate every block carrying a continuation pending marker."""
    return frozenset(
        block.addr
        for block in artifact.blocks
        if any(
            refusal.kind == NEAR_RETURN_CONTINUATION_PENDING_KIND_8616
            for refusal in block.refusals
        )
    )


def _continuation_marker_count_8616(artifact: IRFunctionArtifact) -> int:
    """Count every distinct continuation obligation exactly.

    A function-level marker that merely mirrors a block-level marker on
    the same block is the same obligation projected at function level;
    an un-backed function-level marker is an additional obligation no
    block census covers — it must still be accounted, never hidden.
    """
    block_marked = _continuation_marker_blocks_8616(artifact)
    return sum(
        1
        for block in artifact.blocks
        for refusal in block.refusals
        if refusal.kind == NEAR_RETURN_CONTINUATION_PENDING_KIND_8616
    ) + sum(
        1
        for refusal in artifact.refusals
        if refusal.kind == NEAR_RETURN_CONTINUATION_PENDING_KIND_8616
        and refusal.block_addr not in block_marked
    )


def _selector_marker_count_8616(artifact: IRFunctionArtifact) -> int:
    """Count every distinct selector-window obligation exactly.

    Mirrors ``_continuation_marker_count_8616``: function-level markers
    backed by a block marker are the same obligation; un-backed ones are
    additional obligations the selector proof can never discharge.
    """
    block_marked = _selector_marker_blocks_8616(artifact)
    return sum(
        1
        for block in artifact.blocks
        for refusal in block.refusals
        if refusal.kind == _SELECTOR_WINDOW_PENDING_KIND_8616
    ) + sum(
        1
        for refusal in artifact.refusals
        if refusal.kind == _SELECTOR_WINDOW_PENDING_KIND_8616
        and refusal.block_addr not in block_marked
    )


def _selector_marker_blocks_8616(artifact: IRFunctionArtifact) -> frozenset[int]:
    """Enumerate every block carrying a selector-window pending marker."""
    return frozenset(
        block.addr
        for block in artifact.blocks
        if any(
            refusal.kind == _SELECTOR_WINDOW_PENDING_KIND_8616
            for refusal in block.refusals
        )
    )


def _obligation_surface_failure_8616(
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
) -> tuple[
    ScopedNearReturnContinuationViewFailure8616 | None,
    str,
    NearCallFramePremise8616 | None,
    frozenset[int],
]:
    """Audit the pending surface the composed view may discharge.

    Extends the continuation owner's surface audit to the two-class
    obligation surface: every proven continuation block must keep its raw
    ``JMP`` terminal and at least one pending marker, every block-level
    refusal must be either a continuation marker on a proven block or a
    selector-window pending marker, and every function-level refusal must
    belong to the same two classes. Any other refusal is an unrelated
    raw defect no consuming entry may waive.
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
    if premise is None or type(premise) is not NearCallFramePremise8616:
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
    for block in artifact.blocks:
        block_failure = _obligation_block_failure_8616(block, proven)
        if block_failure is not None:
            return block_failure[0], block_failure[1], premise, frozenset()
    level_failure = _obligation_level_failure_8616(artifact, proven)
    if level_failure is not None:
        return level_failure[0], level_failure[1], premise, frozenset()
    return None, "", premise, frozenset(proven)


def _obligation_block_failure_8616(
    block: IRBlock,
    proven: frozenset[int],
) -> tuple[ScopedNearReturnContinuationViewFailure8616, str] | None:
    """Audit one block's markers against the joint obligation census.

    A proven block must keep its raw ``JMP`` terminal and at least one
    continuation pending marker. Every block-level refusal must be either
    a continuation marker on a proven block or a selector-window pending
    marker; anything else is an unrelated raw defect no consuming entry
    may waive.
    """
    if block.addr in proven:
        terminal = block.instrs[-1] if block.instrs else None
        if terminal is None or terminal.op != "JMP":
            return (
                ScopedNearReturnContinuationViewFailure8616
                .SURFACE_MISMATCH,
                "proven block lost its retained raw JMP terminal",
            )
        if not any(
            refusal.kind == NEAR_RETURN_CONTINUATION_PENDING_KIND_8616
            for refusal in block.refusals
        ):
            return (
                ScopedNearReturnContinuationViewFailure8616
                .SURFACE_MISMATCH,
                "proven block carries no continuation pending marker",
            )
    for refusal in block.refusals:
        continuation = (
            refusal.kind == NEAR_RETURN_CONTINUATION_PENDING_KIND_8616
            and block.addr in proven
        )
        selector = refusal.kind == _SELECTOR_WINDOW_PENDING_KIND_8616
        if not continuation and not selector:
            return (
                ScopedNearReturnContinuationViewFailure8616
                .RESIDUAL_REFUSAL,
                f"block 0x{block.addr:x} retains unrelated refusal "
                f"{refusal.kind!r}; an authenticated entry never "
                "waives raw refusals",
            )
    return None


def _obligation_level_failure_8616(
    artifact: IRFunctionArtifact,
    proven: frozenset[int],
) -> tuple[ScopedNearReturnContinuationViewFailure8616, str] | None:
    """Audit every function-level marker against the joint census.

    A function-level conditional marker only authenticates as the
    function-level projection of a marker on the identical block: a
    continuation marker must name a proven block, and a selector marker
    must name a block carrying the block-level obligation. An orphan
    marker anywhere else is a raw defect, never evidence the joint
    census can fold into a block admission.
    """
    selector_blocks = _selector_marker_blocks_8616(artifact)
    for refusal in artifact.refusals:
        continuation = (
            refusal.kind == NEAR_RETURN_CONTINUATION_PENDING_KIND_8616
            and refusal.block_addr in proven
        )
        selector = (
            refusal.kind == _SELECTOR_WINDOW_PENDING_KIND_8616
            and refusal.block_addr in selector_blocks
        )
        if not continuation and not selector:
            return (
                ScopedNearReturnContinuationViewFailure8616.RESIDUAL_REFUSAL,
                "artifact retains a refusal outside the conditional "
                "obligation census",
            )
    return None


def _continuation_effective_blocks_8616(
    blocks: tuple[IRBlock, ...],
    proven: frozenset[int],
) -> tuple[IRBlock, ...] | None:
    """Derive the continuation-effective surface (S1) deterministically.

    Every proven continuation block is rebuilt with its terminal ``JMP``
    discharged to ``RET`` and its pending markers removed — the only
    rewrite the source-bound premise authorizes — while every other block
    stays the identical raw object so selector evidence, instruction
    identity, and any retained selector markers rebind to the same source.
    ``None`` means a proven block lost its raw terminal or carries a
    refusal the continuation class cannot own; the composition refuses
    rather than fabricate a surface.
    """
    effective: list[IRBlock] = []
    for block in blocks:
        if block.addr not in proven:
            effective.append(block)
            continue
        terminal = block.instrs[-1] if block.instrs else None
        if terminal is None or terminal.op != "JMP" or any(
            refusal.kind != NEAR_RETURN_CONTINUATION_PENDING_KIND_8616
            for refusal in block.refusals
        ):
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
    return tuple(effective)


def _discharged_selector_markers_8616(
    artifact: IRFunctionArtifact,
    proof: EntryJumpDomainProof8616 | None,
) -> int:
    """Count selector markers the retained proof's admissions discharge."""
    if proof is None:
        return 0
    admitted = {jump.block_addr for jump in proof.admitted}
    return sum(
        1
        for block in artifact.blocks
        if block.addr in admitted
        for refusal in block.refusals
        if refusal.kind == _SELECTOR_WINDOW_PENDING_KIND_8616
    )


def _obligation_counts_8616(
    artifact: IRFunctionArtifact,
    proof: EntryJumpDomainProof8616 | None,
    *,
    authenticated: bool,
) -> tuple[int, int, int, int, int]:
    """Recompute the joint obligation ledger over one raw surface."""
    continuations = _continuation_marker_count_8616(artifact)
    selectors = _selector_marker_count_8616(artifact)
    discharged = _discharged_selector_markers_8616(artifact, proof)
    obligations = continuations + selectors
    refused = selectors - discharged
    return (
        obligations,
        obligations,
        obligations,
        (continuations + discharged) if authenticated else 0,
        refused if authenticated else refused + 1,
    )


def scoped_obligations_expected_counts_8616(
    view: ScopedNearReturnContinuationView8616,
    *,
    authenticated: bool,
) -> tuple[int, int, int, int, int]:
    """Recompute the joint obligation ledger from retained evidence.

    The ledger counts every conditional marker on the retained raw
    surface: each continuation pending marker and each selector-window
    pending marker is one obligation. An authenticated view materializes
    the continuation census plus every marker on an admitted transfer
    block and keeps the un-discharged selector markers as honest failure
    evidence; a refused view materializes nothing and adds its own typed
    failure to the retained un-discharged marker count.
    """
    return _obligation_counts_8616(
        view.source_artifact, view.selector_proof, authenticated=authenticated
    )


def _joint_admission_failure_8616(
    invocation_scope: Real16InvocationDomain8616 | None,
    premise: NearCallFramePremise8616,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    s1_artifact: IRFunctionArtifact,
    s1_blocks: tuple[IRBlock, ...],
    proof: EntryJumpDomainProof8616,
) -> tuple[
    ScopedNearReturnContinuationViewFailure8616 | None,
    str,
    EntryJumpDomainApplication8616 | None,
]:
    """Authenticate the supplied entry and replay the selector discharge.

    The independently supplied entry must be a typed invocation domain
    that crosses the premise's exact decoded near-call edge and owns the
    identical raw artifact/boundary pair; only then is the retained
    selector proof applied over the continuation-effective surface under
    that same entry. A stale input, an empty admission, a transform
    delta, or an unrelated residual refusal each yields its typed
    non-result with the application record retained where produced.
    """
    from .real16_invocation_domain import Real16InvocationDomain8616

    if type(invocation_scope) is not Real16InvocationDomain8616:
        return (
            ScopedNearReturnContinuationViewFailure8616.SCOPE_ABSENT,
            "no typed consuming entry was supplied",
            None,
        )
    if not _scope_binds_premise_8616(
        invocation_scope, premise, artifact, boundary
    ):
        return (
            ScopedNearReturnContinuationViewFailure8616.SCOPE_UNBOUND,
            "consuming entry does not cross the premise's exact "
            "decoded near-call edge",
            None,
        )
    application = apply_entry_jump_domain_8616(
        s1_artifact, proof, invocation_scope=invocation_scope
    )
    if application.status is EntryJumpDomainApplicationStatus8616.STALE_INPUT:
        return (
            ScopedNearReturnContinuationViewFailure8616.APPLICATION_REFUSED,
            (
                application.refusals[0].detail
                if application.refusals
                else "proof application refused its input surface"
            ),
            application,
        )
    if application.status is not EntryJumpDomainApplicationStatus8616.APPLIED:
        return (
            ScopedNearReturnContinuationViewFailure8616.APPLICATION_EMPTY,
            "the retained selector proof admitted no edge for the "
            "scope to carry",
            application,
        )
    delta = _transform_delta_failure_8616(
        s1_blocks, application.blocks, application.applied
    )
    if delta is not None:
        return (
            ScopedNearReturnContinuationViewFailure8616.TRANSFORM_MISMATCH,
            delta,
            application,
        )
    residual = _residual_refusal_failure_8616(application.blocks)
    if residual is not None:
        return (
            ScopedNearReturnContinuationViewFailure8616.RESIDUAL_REFUSAL,
            residual,
            application,
        )
    return None, "", application


def prove_scoped_control_obligations_8616(
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    terminal_evidence: Mapping[int, TerminalJumpEvidence8616],
    *,
    project: object | None = None,
    call_preservations: tuple[EntryDomainCallPreservation8616, ...] = (),
    invocation_resolver: (
        Callable[[int], Real16InvocationDomain8616 | None] | None
    ) = None,
    invocation_scope: Real16InvocationDomain8616 | None = None,
) -> ScopedNearReturnContinuationView8616:
    """Compose both conditional discharges for one consuming entry.

    The continuation evidence comes first: the retained premise and
    proven census authorize the deterministic S1 surface. The retained
    entry-domain proof then classifies the selector obligations over S1
    under the same project source authority — never a foreign or
    re-derived surface — and the independently supplied
    ``invocation_scope`` (never inferred from the premise or the proof)
    must cross the premise's exact decoded near-CALL edge and own the
    identical raw artifact/boundary pair before the proof application is
    replayed under it. The returned view retains the raw artifact
    untouched: the conditional body stays unpublished, and every
    projection is a per-consumption replay.
    """

    def refuse(
        failure: ScopedNearReturnContinuationViewFailure8616,
        detail: str,
        premise: NearCallFramePremise8616 | None,
        proven: frozenset[int],
        proof: EntryJumpDomainProof8616 | None,
        application: EntryJumpDomainApplication8616 | None = None,
    ) -> ScopedNearReturnContinuationView8616:
        counts = _obligation_counts_8616(
            artifact, proof, authenticated=False
        )
        return ScopedNearReturnContinuationView8616(
            source_artifact=artifact,
            boundary=boundary,
            failure=failure,
            detail=detail,
            proven_block_addrs=proven,
            raw_fact_count=counts[0],
            normalized_fact_count=counts[1],
            classified_fact_count=counts[2],
            materialized_count=counts[3],
            failure_count=counts[4],
            premise=premise,
            selector_proof=proof,
            selector_application=application,
        )

    failure, detail, premise, proven = _obligation_surface_failure_8616(
        artifact, boundary
    )
    if failure is not None:
        return refuse(failure, detail, premise, proven, None)
    assert premise is not None
    s1_blocks = _continuation_effective_blocks_8616(artifact.blocks, proven)
    if s1_blocks is None:
        return refuse(
            ScopedNearReturnContinuationViewFailure8616.SURFACE_MISMATCH,
            "proven continuation block lost its retained raw JMP terminal",
            premise,
            proven,
            None,
        )
    s1_artifact = IRFunctionArtifact(
        function_addr=artifact.function_addr,
        blocks=s1_blocks,
    )
    proof = prove_entry_jump_domains_8616(
        s1_artifact,
        terminal_evidence,
        project=project,
        call_preservations=call_preservations,
        invocation_resolver=invocation_resolver,
    )
    # Every selector marker is one obligation; the proof must have
    # classified exactly the marker census — a marker with no recorded
    # candidate or a candidate with no marker means the bound evidence
    # does not describe this surface.
    if _selector_marker_blocks_8616(artifact) != frozenset(
        candidate.block_addr
        for candidate in proof.source_binding.pending
    ):
        return refuse(
            ScopedNearReturnContinuationViewFailure8616.RESIDUAL_REFUSAL,
            "selector marker census diverges from the proof's "
            "classified candidate census",
            premise,
            proven,
            proof,
        )
    admission = _joint_admission_failure_8616(
        invocation_scope,
        premise,
        artifact,
        boundary,
        s1_artifact,
        s1_blocks,
        proof,
    )
    if admission[0] is not None:
        return refuse(
            admission[0], admission[1], premise, proven, proof, admission[2]
        )
    application = admission[2]
    assert application is not None
    counts = _obligation_counts_8616(artifact, proof, authenticated=True)
    return ScopedNearReturnContinuationView8616(
        source_artifact=artifact,
        boundary=boundary,
        failure=None,
        detail="",
        proven_block_addrs=proven,
        raw_fact_count=counts[0],
        normalized_fact_count=counts[1],
        classified_fact_count=counts[2],
        materialized_count=counts[3],
        failure_count=counts[4],
        premise=premise,
        invocation_scope=invocation_scope,
        selector_proof=proof,
        selector_application=application,
    )


def _joint_replay_8616(
    view: ScopedNearReturnContinuationView8616,
    consuming_scope: Real16InvocationDomain8616,
) -> EntryJumpDomainApplication8616 | None:
    """Re-derive S1 and replay the retained selector chain end to end.

    The continuation-effective surface is rebuilt deterministically from
    the retained raw artifact and proven census, the proof's recorded
    source binding is rebound to that exact surface — root, block
    census, and canonical digest — and the retained application is
    re-authenticated by object identity before a fresh application runs
    under the offered entry. The fresh replay must be authentic to the
    same proof, reconcile field-by-field against the proved delta, and
    carry no unrelated residual refusal; only then is its effective
    surface returned.
    """
    proof = view.selector_proof
    retained = view.selector_application
    if proof is None or retained is None:
        return None
    # The retained ledger only summarizes the surface at construction; a
    # reconciled counter tuple must never authorize an obligation that
    # was added afterwards, so the live raw surface is re-audited end to
    # end — premise row, per-block markers, and every function-level
    # projection — before S1 is derived.
    audit = _obligation_surface_failure_8616(
        view.source_artifact, view.boundary
    )
    if (
        audit[0] is not None
        or audit[2] is None
        or audit[2] is not view.premise
        or audit[3] != view.proven_block_addrs
    ):
        return None
    s1_blocks = _continuation_effective_blocks_8616(
        view.source_artifact.blocks, view.proven_block_addrs
    )
    if s1_blocks is None:
        return None
    function_addr = view.source_artifact.function_addr
    s1_artifact = IRFunctionArtifact(
        function_addr=function_addr,
        blocks=s1_blocks,
    )
    binding = proof.source_binding
    if (
        proof.function_addr != function_addr
        or binding.function_addr != function_addr
        or binding.block_count != len(s1_blocks)
        or binding.digest != _source_digest_8616(function_addr, s1_blocks)
    ):
        return None
    if not _application_authentic_8616(retained, proof):
        return None
    fresh = apply_entry_jump_domain_8616(
        s1_artifact, proof, invocation_scope=consuming_scope
    )
    if not _application_authentic_8616(fresh, proof):
        return None
    if (
        _transform_delta_failure_8616(
            s1_blocks, fresh.blocks, fresh.applied
        )
        is not None
    ):
        return None
    if _canonical_source_8616(
        function_addr, retained.blocks
    ) != _canonical_source_8616(function_addr, fresh.blocks):
        return None
    if _residual_refusal_failure_8616(fresh.blocks) is not None:
        return None
    return fresh


def scoped_obligations_projection_8616(
    view: ScopedNearReturnContinuationView8616,
    consuming_scope: Real16InvocationDomain8616,
) -> ScopedFunctionCFGProjection8616 | None:
    """Replay the joint chain and expose the bounded effective CFG.

    Re-derives S1 from the retained raw artifact and proven census,
    rebinds the proof's recorded source binding to that exact surface —
    canonical digest, block census, and root — re-authenticates the
    retained application by object identity, then replays application
    admission end to end under the offered entry inside the shared
    bounded traversal. Only the fresh replay builds the projection;
    residual selector markers stay visible as pending holes.
    """
    function_addr = view.source_artifact.function_addr
    with segment_call_dependency_traversal_scope_8616():
        fresh = _joint_replay_8616(view, consuming_scope)
        if fresh is None:
            return None
        census = {block.addr for block in fresh.blocks}
        successors: dict[int, tuple[int, ...]] = {}
        predecessor_lists: dict[int, list[int]] = {
            addr: [] for addr in census
        }
        pending: dict[int, tuple[IRRefusal, ...]] = {}
        for block in fresh.blocks:
            pending[block.addr] = block.refusals
            if not block.refusals:
                successors[block.addr] = block.successor_addrs
            for target in block.successor_addrs:
                if target in predecessor_lists:
                    predecessor_lists[target].append(block.addr)
        return ScopedFunctionCFGProjection8616(
            function_addr=function_addr,
            source_artifact=view.source_artifact,
            scope=consuming_scope,
            applied=fresh.applied,
            blocks=fresh.blocks,
            successors=MappingProxyType(successors),
            predecessors=MappingProxyType(
                {
                    addr: tuple(sorted(sources))
                    for addr, sources in predecessor_lists.items()
                }
            ),
            pending=MappingProxyType(pending),
        )
