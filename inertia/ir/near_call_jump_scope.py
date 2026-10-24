"""Conditional CALL census for an explicitly scoped entry-jump proof.

Layer: IR.
Responsibility: authenticate native near-call entry and every conditional
callee-preservation dependency without publishing universal preservation.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from inertia.frontend.x86_16.frontend_direct_callsite_index import DirectCallTargetResolver8616
from inertia.frontend.x86_16.near_call_entry_context import (
    NativeNearCallEntry8616,
    _live_call_encoding_8616,
    consume_native_near_call_entry_8616,
)
from inertia.semantics.conditional_near_call_target import (
    _derive_final_scoped_theorem_8616,
    _rebind_raw_root_8616,
)

from .core import IRFunctionArtifact
from .direct_evidence_deadline import direct_evidence_deadline_expired_8616
from .near_call_preservation import (
    ConditionalNearCallPreservation8616,
    _capture_caller_facts_8616,
    _consume_scoped_census_step_8616,
    _DetachedCallerFacts8616,
    _ScopedCensusStepStatus8616,
    _SharedCallerGraph8616,
    _stale_caller_facts_8616,
)
from .raw_boot_native_surface_cache import _native_surface_key_8616
from .segment_effect_closure import SegmentEffectClosureResult8616
from .source_graph_binding import (
    SourceGraphSerializationError8616,
    canonical_source_graph_8616,
    capture_immutable_source_graph_facts_8616,
)


@dataclass(frozen=True, slots=True)
class NearCallJumpScope8616:
    """Explicit conditional entry and complete caller CALL census.

    Neither construction nor serialization authenticates this record. The
    jump proof establishes entry CS identity inductively; the retained
    context remains a premise of every resulting admission and application.
    """

    project: object
    artifact: IRFunctionArtifact
    context: NativeNearCallEntry8616
    direct_target_resolver: DirectCallTargetResolver8616
    preservations: tuple[ConditionalNearCallPreservation8616, ...]

    def to_dict(self) -> dict[str, object]:
        """Serialize conditional premises without claiming universal proof."""
        return {
            "conditional_only": True,
            "context": self.context.to_dict(),
            "preservations": [record.to_dict() for record in self.preservations],
        }


def _shared_caller_graph_8616(
    artifact: IRFunctionArtifact,
) -> _SharedCallerGraph8616 | None:
    """Detach the caller's immutable source graph once for the whole census.

    A typed serialization refusal is already evidence drift and cannot
    authorize a partial census.
    """
    try:
        return _SharedCallerGraph8616(
            artifact=artifact,
            graph=capture_immutable_source_graph_facts_8616(
                artifact.function_addr, artifact.blocks, artifact.refusals,
            ),
        )
    except SourceGraphSerializationError8616:
        return None


def authenticate_near_call_jump_scope_8616(
    scope: NearCallJumpScope8616,
    *, project: object, artifact: IRFunctionArtifact,
) -> bool:
    """Authenticate one raw caller and the complete conditional CALL census.

    Original caller, dependency and native snapshots precede callbacks.
    One canonical root rebind authenticates the caller; each step retains
    operand, native origin, callee and deadline gates. Final native/context
    observations precede fresh comparisons against the original snapshots.
    Only then does callback-free canonical derivation reconcile every CALL
    theorem. Staged results never authorize a proof or a reusable bypass.
    """
    if type(scope) is not NearCallJumpScope8616:
        return False
    context = scope.context
    if (
        scope.project is not project or scope.artifact is not artifact
        or type(context) is not NativeNearCallEntry8616
        or artifact.function_addr != context.target_addr
        or not scope.preservations
    ):
        return False
    preservations = scope.preservations
    snapshots = _capture_census_8616(scope)
    if snapshots is None:
        return False
    records_before = _dependency_facts_8616(scope)
    native_before = _native_census_facts_8616(scope)
    if native_before is None:
        return False
    if not _rebind_raw_root_8616(project, context, artifact):
        return False
    if direct_evidence_deadline_expired_8616(project):
        return False

    if not consume_native_near_call_entry_8616(
        project, context, callsite_index=context.callsite_index,
    ):
        return False
    if not _stage_complete_target_census_8616(
        scope, project, artifact, context, snapshots, preservations,
    ):
        return False
    return _final_target_census_seal_8616(
        scope, project, artifact, context, preservations, snapshots,
        records_before, native_before,
    )


def _stage_complete_target_census_8616(
    scope: NearCallJumpScope8616,
    project: object,
    artifact: IRFunctionArtifact,
    context: NativeNearCallEntry8616,
    snapshots: tuple[_DetachedCallerFacts8616, ...],
    preservations: tuple[ConditionalNearCallPreservation8616, ...],
) -> bool:
    """Stage each source CALL exactly once; final admission remains separate."""
    consumed: set[int] = set()
    for block in artifact.blocks:
        for instruction in block.instrs:
            if instruction.op != "CALL":
                continue
            if not _staged_census_consume_8616(
                scope, project, artifact, context, block, instruction,
                snapshots, consumed, preservations,
            ):
                return False
    return len(consumed) == len(preservations)


def _final_target_census_seal_8616(
    scope: NearCallJumpScope8616,
    project: object,
    artifact: IRFunctionArtifact,
    context: NativeNearCallEntry8616,
    preservations: tuple[ConditionalNearCallPreservation8616, ...],
    snapshots: tuple[_DetachedCallerFacts8616, ...],
    records_before: str,
    native_before: _NativeCensusFacts8616,
) -> bool:
    """Observe native state, seal original facts, then derive without callbacks."""
    if not consume_native_near_call_entry_8616(
        project, context, callsite_index=context.callsite_index,
    ):
        return False
    native_after = _native_census_facts_8616(scope)
    if not (
        scope.project is project and scope.artifact is artifact
        and scope.context is context
        and scope.preservations is preservations
        and _caller_census_unchanged_8616(scope, snapshots, records_before)
        and native_before == native_after
    ):
        return False
    for step in preservations:
        if not _derive_final_scoped_theorem_8616(
            project, step.theorem, artifact=artifact, context=context,
        ):
            return False
    return not direct_evidence_deadline_expired_8616(project)


def _staged_census_consume_8616(
    scope: NearCallJumpScope8616,
    project: object,
    artifact: IRFunctionArtifact,
    context: NativeNearCallEntry8616,
    block: object,
    instruction: object,
    snapshots: tuple[_DetachedCallerFacts8616, ...],
    consumed: set[int],
    preservations: tuple[ConditionalNearCallPreservation8616, ...],
) -> bool:
    """Match and stage the unique census step for one CALL instruction.

    The step bound to this identical block/instruction must be unique,
    unconsumed and rooted at this identical context and artifact; its
    staged operation receives the original pre-callback snapshot captured
    at its own census position. ``True`` reports only staged completion —
    the caller's final whole-census seal still owes admission.
    """
    matches = tuple(
        index for index, step in enumerate(preservations)
        if step.theorem is not None
        and step.theorem.block is block
        and step.theorem.instruction is instruction
    )
    if len(matches) != 1:
        return False
    step = preservations[matches[0]]
    theorem = step.theorem
    if (
        id(step) in consumed or theorem is None
        or theorem.context is not context or theorem.artifact is not artifact
    ):
        return False
    staged = _consume_scoped_census_step_8616(
        project, step, artifact=artifact, context=context,
        block=block, instruction=instruction,
        direct_target_resolver=scope.direct_target_resolver,
        snapshot=snapshots[matches[0]],
    )
    if staged.status is not _ScopedCensusStepStatus8616.STAGED:
        return False
    consumed.add(id(step))
    return True


def _capture_census_8616(
    scope: NearCallJumpScope8616,
) -> tuple[_DetachedCallerFacts8616, ...] | None:
    """Capture all theorem projections against one detached caller graph.

    The single pre-callback capture supplies every staged step's
    snapshot; any theorem missing a complete projection refuses the whole
    census before any native callback runs.
    """
    shared = _shared_caller_graph_8616(scope.artifact)
    if shared is None:
        return None
    snapshots: list[_DetachedCallerFacts8616] = []
    for step in scope.preservations:
        if step.theorem is None:
            return None
        snapshot = _capture_caller_facts_8616(step.theorem, shared_graph=shared)
        if snapshot is None:
            return None
        snapshots.append(snapshot)
    return tuple(snapshots)


def _caller_census_unchanged_8616(
    scope: NearCallJumpScope8616,
    snapshots: tuple[_DetachedCallerFacts8616, ...],
    records_before: str,
) -> bool:
    """Seal every record against one graph captured after the final callback."""
    # State serialization can replay retained entry/view proofs. Finish those
    # callbacks before capturing the caller surface they may have changed.
    if records_before != _dependency_facts_8616(scope):
        return False
    shared_after = _shared_caller_graph_8616(scope.artifact)
    if shared_after is None:
        return False
    return bool(
        all(
            step.theorem is not None
            and not _stale_caller_facts_8616(
                scope.project, step.theorem, snapshot, shared_fresh=shared_after,
            )
            for step, snapshot in zip(scope.preservations, snapshots, strict=True)
        )
    )


@dataclass(frozen=True, slots=True)
class _NativeCensusFacts8616:
    """Detached native evidence with authorities pinned until final reconciliation."""

    incoming: bytes
    keys: tuple[tuple[object, ...], ...]
    pinned: tuple[object, ...] = field(compare=False, repr=False)


def _native_census_facts_8616(
    scope: NearCallJumpScope8616,
) -> _NativeCensusFacts8616 | None:
    """Read canonical caller/callee byte keys without importing or proving again.

    These reads bracket all proof callbacks, including the final entry replay.
    A boundary unsupported by the native-key owner refuses; it cannot borrow
    the previously authenticated IR as evidence of unchanged live bytes.
    """
    from .vex_import import build_x86_16_ir_function_artifact

    incoming = _live_call_encoding_8616(scope.project, scope.context.premise)
    if incoming is None:
        return None
    boundaries = [scope.context.boundary]
    for step in scope.preservations:
        if step.callee is None:
            return None
        boundaries.append(step.callee.coverage.boundary)
    keys: list[tuple[object, ...]] = []
    pinned: list[object] = []
    for boundary in boundaries:
        native = _native_surface_key_8616(
            scope.project, boundary, build_x86_16_ir_function_artifact,
        )
        if native is None:
            return None
        key, authorities = native
        keys.append(key)
        pinned.extend(authorities)
    return _NativeCensusFacts8616(incoming, tuple(keys), tuple(pinned))


def _dependency_facts_8616(scope: NearCallJumpScope8616) -> str:
    """Serialize dependencies, including live entry/view proof callbacks."""
    return json.dumps([
        {
            "step": step.to_dict(),
            "identities": (id(step), id(step.theorem), id(step.callee), id(step.obligation)),
            **_callee_dependency_fields_8616(step.callee),
        }
        for step in scope.preservations
    ], sort_keys=True)


def _callee_dependency_fields_8616(
    callee: SegmentEffectClosureResult8616 | None,
) -> dict[str, object]:
    """Serialize the shared callee source, state and closure mutation seal.

    Fresh production and retained consumption freeze the same projections;
    neither may omit a field observed by the other owner.
    """
    return {
        "callee_source": None if callee is None else canonical_source_graph_8616(
            callee.coverage.artifact.function_addr,
            callee.coverage.artifact.blocks,
        ),
        "callee_state": None if callee is None else callee.state.to_dict(),
        "callee_closure": None if callee is None else (
            id(callee.coverage), id(callee.state),
            callee.failure, callee.callsite_addrs,
            callee.return_block_addrs, callee.raw_fact_count,
            callee.normalized_fact_count, callee.classified_fact_count,
            callee.materialized_count, callee.failure_count,
        ),
    }
