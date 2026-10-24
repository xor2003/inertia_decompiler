"""Batched fresh outgoing-CALL preservation census under one caller.

Layer: IR.
Responsibility: replace the per-CALL
``prove_near_call_preservation_from_coordinates_8616`` loop with one owned
census that authenticates the caller root and entry context once, stages
every outgoing CALL through the canonical staged gates, and promotes only
after the whole-census final native/graph/dependency seals and the
callback-free canonical final derivation. Phase order mirrors the reviewed
consumer census ``authenticate_near_call_jump_scope_8616``: original caller,
dependency and native snapshots precede callbacks; staged steps never
publish authority; fresh final observations precede owned-fact
reconciliation; promotion happens last. No persistent cache, no new
registry, no budget change.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from typing import cast

from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DirectCallTargetResolver8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
)
from inertia.frontend.x86_16.near_call_entry_context import (
    NativeNearCallEntry8616,
    _live_call_encoding_8616,
    consume_native_near_call_entry_8616,
)
from inertia.ir.core import IRBlock, IRInstr
from inertia.ir.direct_evidence_deadline import (
    direct_evidence_deadline_expired_8616,
)
from inertia.ir.entry_domain_call_preservation import _CalleeResolution8616
from inertia.ir.function_artifact import IRFunctionArtifact
from inertia.ir.near_call_jump_scope import _callee_dependency_fields_8616, _shared_caller_graph_8616
from inertia.ir.near_call_preservation import (
    ConditionalNearCallPreservation8616,
    ConditionalNearCallPreservationFailure8616,
    _bound_callee_evidence_8616,
    _callee_chain_failure_8616,
    _callsite_evidence_8616,
    _capture_caller_facts_8616,
    _conditional_preservation_record_8616,
    _DetachedCallerFacts8616,
    _resolution_scope_8616,
    _scoped_evidence_seal_8616,
    _SharedCallerGraph8616,
    _stale_caller_facts_8616,
    _surface_failure_8616,
)
from inertia.ir.raw_boot_native_surface_cache import _native_surface_key_8616
from inertia.ir.segment_effect_closure import SegmentEffectClosureResult8616
from inertia.ir.vex_import import build_x86_16_ir_function_artifact
from inertia.semantics.conditional_near_call_target import (
    ConditionalCallsiteSelectorObligation8616,
    ConditionalNearCallTargetTheorem8616,
    _derive_final_scoped_theorem_8616,
    _rebind_raw_root_8616,
    _ScopedFreshTheorem8616,
    _ScopedTargetStage8616,
    _staged_fresh_theorem_8616,
)
from inertia.semantics.direct_near_call_target_binding import (
    DirectNearCallCoordinates8616,
)


@dataclass(frozen=True, slots=True)
class _CensusCall8616:
    """One decoded outgoing-CALL surface for the batched census.

    The pipeline owns the exact coordinate decode; this record transports
    the typed census position so the producer can bind identical
    block/instruction surfaces without re-decoding.
    """

    block: IRBlock = field(compare=False)
    instruction: IRInstr = field(compare=False)
    coordinates: DirectNearCallCoordinates8616


@dataclass(frozen=True, slots=True)
class _StagedCensusCall8616:
    """Staged census evidence for one CALL; not admission authority.

    The retained theorem, caller snapshot, bound universal callee,
    candidate window, dependency pin and callee native key are sealed
    against the census's original pre-callback facts at the final
    whole-census seal before any conditional step is promoted.
    """

    theorem: ConditionalNearCallTargetTheorem8616 = field(compare=False)
    snapshot: _DetachedCallerFacts8616
    callee: SegmentEffectClosureResult8616 = field(compare=False)
    callee_addr: int
    candidates: tuple[int, ...]
    dependency_pin: str
    callee_native_key: tuple[object, ...]
    callee_native_authorities: tuple[object, ...] = field(
        compare=False, repr=False,
    )

    def __bool__(self) -> bool:
        """Reject staged evidence used as an admitted proof."""
        raise TypeError(
            "staged census call requires the final whole-census seal"
        )


def _staged_dependency_pin_8616(
    theorem: ConditionalNearCallTargetTheorem8616,
    obligation: ConditionalCallsiteSelectorObligation8616 | None,
    callee: SegmentEffectClosureResult8616,
    callee_addr: int | None,
) -> str:
    """Freeze one staged step's dependent projections for final reconcile.

    Same pinned surfaces as the consumer's ``_dependency_facts_8616``:
    record projections, retained identities and the callee's canonical
    source graph, state and closed evidence counts, so a callback that
    mutates step or callee facts after staging is refused at the final
    whole-census seal.
    """
    return json.dumps({
        "identities": (id(theorem), id(callee), id(obligation)),
        "scalars": (
            theorem.callsite_addr, theorem.next_addr, theorem.target_addr,
            callee_addr,
        ),
        "theorem": theorem.to_dict(),
        **_callee_dependency_fields_8616(callee),
    }, sort_keys=True)


def _census_entry_valid_8616(call: object) -> bool:
    """Require one typed census entry bound to its exact CALL surface."""
    if (
        type(call) is not _CensusCall8616
        or type(call.block) is not IRBlock
        or type(call.instruction) is not IRInstr
        or type(call.coordinates) is not DirectNearCallCoordinates8616
    ):
        return False
    return bool(
        call.instruction.op == "CALL"
        and call.instruction.addr == call.coordinates.callsite_addr
    )


def _artifact_call_identities_8616(
    artifact: IRFunctionArtifact,
) -> tuple[tuple[IRBlock, IRInstr], ...]:
    """Enumerate the artifact's CALL surfaces in canonical order."""
    return tuple(
        (block, instruction)
        for block in artifact.blocks
        for instruction in block.instrs
        if instruction.op == "CALL"
    )


def _final_census_reconcile_8616(
    census: tuple[_CensusCall8616, ...],
    artifact: IRFunctionArtifact,
    staged: tuple[_StagedCensusCall8616, ...],
) -> bool:
    """Reconcile census and staged steps against the artifact CALLs.

    Callbacks may mutate census entries mid-flight, so the final seal
    re-verifies the exact artifact census by block/instruction identity
    and that every staged theorem was built from the surviving entry —
    same block and instruction objects, same exact coordinates. Pure
    owned reads only; no native callback and no graph traversal.
    """
    expected = _artifact_call_identities_8616(artifact)
    if len(census) != len(expected) or len(staged) != len(census):
        return False
    for call, (block, instruction), step in zip(
        census, expected, staged, strict=True,
    ):
        if not _census_entry_valid_8616(call):
            return False
        if call.block is not block or call.instruction is not instruction:
            return False
        if (
            step.theorem.block is not call.block
            or step.theorem.instruction is not call.instruction
            or step.theorem.callsite_addr != call.coordinates.callsite_addr
            or step.theorem.next_addr != call.coordinates.next_addr
            or step.theorem.target_addr != call.coordinates.target_addr
        ):
            return False
    return True


def _stage_census_call_8616(
    project: object,
    artifact: IRFunctionArtifact,
    context: NativeNearCallEntry8616,
    boundary: ExactFunctionRangeBoundary8616,
    call: _CensusCall8616,
    shared: _SharedCallerGraph8616,
    resolver: DirectCallTargetResolver8616,
    session: _CalleeResolution8616,
) -> _StagedCensusCall8616 | ConditionalNearCallPreservationFailure8616:
    """Stage one fresh CALL against the census's shared caller evidence.

    Identical standalone check order minus the per-call root replay the
    census ran once: staged canonical theorem gates, the shared surface and
    caller-bound gate, the caller snapshot against the census's one
    pre-callback graph, the decoded callsite row and canonical candidate
    window, the bounded universal callee resolution and chain check, the
    callee live-source pin, then the canonical scoped evidence seal. The
    staged record owes the final whole-census seal; it is never a proof.
    """
    failure = ConditionalNearCallPreservationFailure8616
    if direct_evidence_deadline_expired_8616(project):
        return failure.REQUEST_EXPIRED
    staged: _ScopedFreshTheorem8616 = _staged_fresh_theorem_8616(
        project, artifact=artifact, context=context,
        block=call.block, instruction=call.instruction,
        coordinates=call.coordinates,
    )
    if (
        staged.status is not _ScopedTargetStage8616.STAGED
        or staged.theorem is None
    ):
        return failure.THEOREM_NOT_AUTHENTICATED
    theorem = staged.theorem
    surface_failure = _surface_failure_8616(
        project, theorem, artifact, context, call.block, call.instruction,
    )
    if surface_failure is not None:
        return surface_failure
    snapshot = _capture_caller_facts_8616(theorem, shared_graph=shared)
    if snapshot is None:
        return failure.SEAL_SOURCE_CHANGED
    census_failure, entry, candidates = _callsite_evidence_8616(
        project, boundary, theorem, resolver,
    )
    if census_failure is not None:
        return census_failure
    if entry is None:
        return failure.CALLSITE_UNPROVEN
    bound_failure, callee, callee_addr, _owner_failure = (
        _bound_callee_evidence_8616(
            project, artifact.function_addr, entry, candidates, resolver,
            session,
        )
    )
    if bound_failure is not None or callee is None or callee_addr is None:
        return (
            bound_failure
            if bound_failure is not None
            else failure.CALLEE_UNRESOLVED
        )
    callee_native = _native_surface_key_8616(
        project, callee.coverage.boundary, build_x86_16_ir_function_artifact,
    )
    if callee_native is None:
        return failure.SEAL_SOURCE_CHANGED
    seal_failure, _seal_owner = _scoped_evidence_seal_8616(
        project, theorem, snapshot, callee, callee_addr, candidates,
    )
    if seal_failure is not None:
        return seal_failure
    return _StagedCensusCall8616(
        theorem=theorem,
        snapshot=snapshot,
        callee=callee,
        callee_addr=callee_addr,
        candidates=candidates,
        dependency_pin=_staged_dependency_pin_8616(
            theorem, theorem.obligation, callee, callee_addr,
        ),
        callee_native_key=callee_native[0],
        callee_native_authorities=callee_native[1],
    )


def _final_native_seal_8616(
    project: object,
    context: NativeNearCallEntry8616,
    boundary: ExactFunctionRangeBoundary8616,
    staged: tuple[_StagedCensusCall8616, ...],
    incoming: bytes,
    caller_key: tuple[object, ...],
) -> ConditionalNearCallPreservationFailure8616 | None:
    """Replay the entry once, then compare every pinned live-source fact.

    The last entry consumption is the final native callback of the census;
    fresh reads of the incoming CALL encoding and the canonical native keys
    for the caller root and every bound callee must equal the facts pinned
    before and during staging. Any drift refuses as changed source.
    """
    failure = ConditionalNearCallPreservationFailure8616
    if not consume_native_near_call_entry_8616(
        project, context, callsite_index=context.callsite_index,
    ):
        return failure.THEOREM_NOT_AUTHENTICATED
    if direct_evidence_deadline_expired_8616(project):
        return failure.REQUEST_EXPIRED
    if _live_call_encoding_8616(project, context.premise) != incoming:
        return failure.SEAL_SOURCE_CHANGED
    caller_after = _native_surface_key_8616(
        project, boundary, build_x86_16_ir_function_artifact,
    )
    if direct_evidence_deadline_expired_8616(project):
        return failure.REQUEST_EXPIRED
    if caller_after is None or caller_after[0] != caller_key:
        return failure.SEAL_SOURCE_CHANGED
    for step in staged:
        callee_after = _native_surface_key_8616(
            project, step.callee.coverage.boundary,
            build_x86_16_ir_function_artifact,
        )
        if direct_evidence_deadline_expired_8616(project):
            return failure.REQUEST_EXPIRED
        if callee_after is None or callee_after[0] != step.callee_native_key:
            return failure.SEAL_SOURCE_CHANGED
    return None


def _final_owned_seal_8616(
    project: object,
    artifact: IRFunctionArtifact,
    staged: tuple[_StagedCensusCall8616, ...],
) -> ConditionalNearCallPreservationFailure8616 | None:
    """Seal owned caller and dependency facts after the last callback.

    One fresh whole-graph recapture — never a retained pre-callback graph —
    reconciles every step's detached snapshot; each step's dependency pin
    then re-compares its staged theorem/callee projections.
    """
    failure = ConditionalNearCallPreservationFailure8616
    shared_after = _shared_caller_graph_8616(artifact)
    if shared_after is None:
        return failure.SEAL_SOURCE_CHANGED
    for step in staged:
        if _stale_caller_facts_8616(
            project, step.theorem, step.snapshot, shared_fresh=shared_after,
        ):
            return failure.SEAL_SOURCE_CHANGED
        if step.dependency_pin != _staged_dependency_pin_8616(
            step.theorem, step.theorem.obligation, step.callee,
            step.callee_addr,
        ):
            return failure.SEAL_SOURCE_CHANGED
    return None


def _final_census_seal_8616(
    project: object,
    artifact: IRFunctionArtifact,
    context: NativeNearCallEntry8616,
    boundary: ExactFunctionRangeBoundary8616,
    census: tuple[_CensusCall8616, ...],
    staged: tuple[_StagedCensusCall8616, ...],
    incoming: bytes,
    caller_key: tuple[object, ...],
) -> ConditionalNearCallPreservationFailure8616 | None:
    """Run the whole-census final seals before any step promotes.

    The census and every staged step finally reconcile against the exact
    artifact CALL identities — a callback that rewrote, duplicated or
    dropped an entry mid-flight refuses here. Every callback-capable
    callee check completes before final reconciliation: each bound closure's canonical chain
    revalidates universal completeness, the nested dependency census and
    entry/return CS identity, bounded by the request deadline. The last
    entry replay is the final native callback, followed only by
    callback-free observations and comparisons — fresh live-source reads
    for the incoming CALL, caller root and every callee against the
    pinned keys, one fresh whole-graph recapture reconciling every
    detached snapshot, and the dependency pins. The canonical final
    derivation re-derives each theorem from the rooted IR last, so no
    callback — including a callee check — can mutate native bytes,
    caller or dependency facts and escape detection.
    """
    failure = ConditionalNearCallPreservationFailure8616
    for step in staged:
        chain_failure, _owner = _callee_chain_failure_8616(
            project, step.callee, step.callee_addr, step.candidates,
        )
        if chain_failure is not None:
            return chain_failure
        if direct_evidence_deadline_expired_8616(project):
            return failure.REQUEST_EXPIRED
    native = _final_native_seal_8616(
        project, context, boundary, staged, incoming, caller_key,
    )
    if native is not None:
        return native
    owned = _final_owned_seal_8616(project, artifact, staged)
    if owned is not None:
        return owned
    if not _final_census_reconcile_8616(census, artifact, staged):
        return failure.CALLER_MISMATCH
    for step in staged:
        if not _derive_final_scoped_theorem_8616(
            project, step.theorem, artifact=artifact, context=context,
        ):
            return failure.THEOREM_NOT_AUTHENTICATED
    if direct_evidence_deadline_expired_8616(project):
        return failure.REQUEST_EXPIRED
    return None


def _census_caller_bound_8616(
    project: object,
    census: tuple[_CensusCall8616, ...],
    artifact: object,
    context: object,
) -> ExactFunctionRangeBoundary8616 | ConditionalNearCallPreservationFailure8616:
    """Bind the typed caller boundary or refuse the whole census.

    Every census entry must be a typed call surface; artifact and context
    must be typed, project-bound and coordinate-consistent; and no two
    entries may stage the identical instruction. The census is then
    reconciled exhaustively against the artifact: it must name every CALL
    instruction in ``artifact.blocks`` exactly once, in artifact order, by
    block/instruction identity — a subset, superset, reordered or
    non-artifact census refuses the whole batch before any native
    callback runs.
    """
    failure = ConditionalNearCallPreservationFailure8616
    if not isinstance(artifact, IRFunctionArtifact) or not isinstance(context, NativeNearCallEntry8616):
        return failure.CALLER_MISMATCH
    if (
        type(artifact) is not IRFunctionArtifact
        or type(context) is not NativeNearCallEntry8616
    ):
        return failure.CALLER_MISMATCH
    bound_artifact = artifact
    bound_context = context
    boundary = bound_context.boundary
    if (
        type(boundary) is not ExactFunctionRangeBoundary8616
        or bound_context.project is not project
        or boundary.project is not project
        or boundary.addr != bound_artifact.function_addr
        or bound_artifact.function_addr != bound_context.target_addr
    ):
        return failure.CALLER_MISMATCH
    if not all(_census_entry_valid_8616(call) for call in census):
        return failure.CALLER_MISMATCH
    expected = _artifact_call_identities_8616(bound_artifact)
    if len(census) != len(expected) or any(
        call.block is not block or call.instruction is not instruction
        for call, (block, instruction) in zip(census, expected, strict=True)
    ):
        return failure.CALLER_MISMATCH
    return boundary


def _entry_context_equal_8616(
    current: NativeNearCallEntry8616, initial: NativeNearCallEntry8616,
) -> bool:
    """Compare entry values and excluded identities against the pre-callback copy.

    The dataclass equality owns the scalar/byte projection. Identity checks
    cover its compare=False authorities without traversing another caller graph.
    """
    return current == initial and all((
        current.project is initial.project,
        current.boundary is initial.boundary,
        current.premise is initial.premise,
        current.callsite_index is initial.callsite_index,
        current.callee_witness is initial.callee_witness,
    ))


def _census_entry_auth_8616(
    project: object,
    artifact: IRFunctionArtifact,
    context: NativeNearCallEntry8616,
    boundary: ExactFunctionRangeBoundary8616,
) -> (
    tuple[bytes, tuple[object, ...], _SharedCallerGraph8616]
    | ConditionalNearCallPreservationFailure8616
):
    """Pin census facts, then authenticate root and context exactly once.

    The shared caller graph and the live native facts (incoming CALL
    encoding, canonical caller key) are pinned before the first callback;
    the one raw-root rebind and one entry-context consumption then run the
    identical owner callbacks the standalone factory repeats per CALL.
    Returns ``(incoming, caller_key, shared)`` for the staged pass and the
    final whole-census seal.
    """
    failure = ConditionalNearCallPreservationFailure8616
    shared = _shared_caller_graph_8616(artifact)
    if shared is None:
        return failure.SEAL_SOURCE_CHANGED
    incoming = _live_call_encoding_8616(project, context.premise)
    caller_native = _native_surface_key_8616(
        project, boundary, build_x86_16_ir_function_artifact,
    )
    if incoming is None or caller_native is None:
        return failure.SEAL_SOURCE_CHANGED
    if not _rebind_raw_root_8616(project, context, artifact):
        return failure.THEOREM_NOT_AUTHENTICATED
    if direct_evidence_deadline_expired_8616(project):
        return failure.REQUEST_EXPIRED
    if not consume_native_near_call_entry_8616(
        project, context, callsite_index=context.callsite_index,
    ):
        return failure.THEOREM_NOT_AUTHENTICATED
    if direct_evidence_deadline_expired_8616(project):
        return failure.REQUEST_EXPIRED
    return incoming, caller_native[0], shared


def _stage_complete_census_8616(
    project: object,
    artifact: IRFunctionArtifact,
    context: NativeNearCallEntry8616,
    boundary: ExactFunctionRangeBoundary8616,
    census: tuple[_CensusCall8616, ...],
    shared: _SharedCallerGraph8616,
    resolver: DirectCallTargetResolver8616,
    resolution: _CalleeResolution8616 | None,
) -> (
    tuple[_StagedCensusCall8616, ...]
    | ConditionalNearCallPreservationFailure8616
):
    """Stage every CALL under the caller's owned resolution session."""
    staged: list[_StagedCensusCall8616] = []
    with _resolution_scope_8616(project, resolver, resolution) as session:
        for call in census:
            step = _stage_census_call_8616(
                project, artifact, context, boundary, call,
                shared, resolver, session,
            )
            if isinstance(step, ConditionalNearCallPreservationFailure8616):
                return step
            staged.append(step)
    return tuple(staged)


def _promote_census_steps_8616(
    staged: tuple[_StagedCensusCall8616, ...],
) -> tuple[ConditionalNearCallPreservation8616, ...]:
    """Materialize sealed staged evidence into the canonical step records.

    Identical record construction to the standalone factory's materialized
    tail: CONDITIONAL verdict, closed one-materialized stats, the retained
    theorem, bound callee and identical selector obligation, and the
    reconciled coordinate scalars.
    """
    return tuple(
        _conditional_preservation_record_8616(step.theorem, step.callee, step.callee_addr)
        for step in staged
    )

def prove_near_call_preservation_census_8616(
    project: object,
    census: tuple[_CensusCall8616, ...],
    *,
    artifact: object,
    context: object,
    direct_target_resolver: DirectCallTargetResolver8616,
    resolution: _CalleeResolution8616 | None = None,
) -> (
    tuple[ConditionalNearCallPreservation8616, ...]
    | ConditionalNearCallPreservationFailure8616
):
    """Produce every conditional preservation step in one owned census.

    The census must name every CALL instruction in ``artifact.blocks``
    exactly once, in order, by identity — a subset, superset, reordered
    or foreign census refuses before any callback. The caller root
    rebinds once and the entry context authenticates once before the
    staged pass; each CALL then runs the canonical staged gates, caller
    snapshot, callsite census, universal callee resolution and scoped
    evidence seal against the census's single pre-callback graph. Only
    after every callback-capable callee check, the final entry replay,
    whole-census native and fresh-graph/dependency observations and the
    callback-free final derivation does each step promote into the
    identical record the standalone factory emits. Typed refusal returns
    the preservation failure evidence; no partial census is ever
    published.
    """
    failure = ConditionalNearCallPreservationFailure8616
    if resolution is not None and type(resolution) is not _CalleeResolution8616:
        raise TypeError(
            "resolution must be a typed callee resolution session"
        )
    if direct_evidence_deadline_expired_8616(project):
        return failure.REQUEST_EXPIRED
    bound = _census_caller_bound_8616(project, census, artifact, context)
    if isinstance(bound, ConditionalNearCallPreservationFailure8616):
        return bound
    if not census:
        return ()
    bound_artifact = cast(IRFunctionArtifact, artifact)
    bound_context = cast(NativeNearCallEntry8616, context)
    initial_context = replace(bound_context)
    authenticated = _census_entry_auth_8616(
        project, bound_artifact, bound_context, bound,
    )
    if isinstance(authenticated, ConditionalNearCallPreservationFailure8616):
        return authenticated
    incoming, caller_key, shared = authenticated
    staged = _stage_complete_census_8616(
        project, bound_artifact, bound_context, bound, census, shared,
        direct_target_resolver, resolution,
    )
    if isinstance(staged, ConditionalNearCallPreservationFailure8616):
        return staged
    seal_failure = _final_census_seal_8616(
        project, bound_artifact, bound_context, bound, census, staged,
        incoming, caller_key,
    )
    if not _entry_context_equal_8616(bound_context, initial_context):
        return failure.SEAL_SOURCE_CHANGED
    if seal_failure is not None:
        return seal_failure
    return _promote_census_steps_8616(staged)
