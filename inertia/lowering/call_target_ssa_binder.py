"""Bind one symbolic SSA CALL to its native-proven full-width target.

Layer: Types/Lowering (staged candidate under
``.cache/comparator-implementation/call-target-consolidation/``; intended
production home ``lowering/call_target_ssa_binder.py``).
Responsibility: the shared typed CALL-target proof consumed by both the
input ``reaching_defs`` gate and the output ``return_defs`` gate —
dispatching between the raw and Semantics-enriched producer routes, then
discharging the native proof through the Semantics-owned
``prove_direct_near_call_target_binding_from_decoded_8616`` against
once-built decoded direct-callsite entries restricted to the exact
caller/callsite inside the admitted target relation.

* Raw route — the artifact is raw-stage SSA (unregistered or registered at
  ``IR`` stage): the SSA candidate binds positionally to the
  project-registered raw ``IRFunctionArtifact`` producer, modulo SSA
  version, and its operand producer closure must equal the owned
  ``build_x86_16_block_local_ssa`` projection of that raw block.
* Semantic route — the artifact is the retained ``SEMANTIC`` SSA: the
  supplied ``CallSemanticProjection8616`` must retain this exact SSA object
  with closed accounting and a registry-registered ``source_ir``; the bound
  block must satisfy the retained chain links (``outputs.function`` prefix
  accounted to ``CallOutputFact8616`` records, suffix object-identical to
  ``effects.function``, effects the typed overlay of ``source_ir``), and the
  operand producer closure must equal the owned block-local projection of
  the *enriched* block — the projection ``build_x86_16_function_ssa``
  actually consumed, where raw index ``i`` maps to SSA index ``i + prefix``.

No constant is fabricated, no operand rewritten, no annotation erased to
compare, no VEX/IR rebuilt per call, and every missing or conflicting link
is a typed refusal.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
    DecodedDirectCallsiteIndex8616,
)
from inertia.ir.function_ssa_registry import (
    FunctionSSAArtifactFailure8616,
    FunctionSSAArtifactStage8616,
    FunctionSSAArtifactVerdict8616,
    registered_function_ssa_artifact_8616,
)
from inertia.ir.ssa_function import SSAFunctionArtifact
from inertia.semantics.call_stack_effect_pipeline import (
    CallSemanticProjection8616,
)
from inertia.semantics.call_target_identity import (
    normalize_x86_16_call_target_addr_8616,
    x86_16_call_targets_equivalent_8616,
)
from inertia.semantics.direct_near_call_target_binding import (
    DirectNearCallTargetBinding8616,
    prove_direct_near_call_target_binding_from_decoded_8616,
)

from .call_target_bind_common import _unique_ssa_call_8616
from .call_target_raw_route import _raw_route_producer_8616
from .call_target_semantic_route import _semantic_route_producer_8616
from .call_target_ssa_contracts import (
    CallTargetBindResult8616,
    CallTargetBindStage8616,
    CallTargetBindStats8616,
    CallTargetBindVerdict8616,
    _BoundProducer8616,
    _refuse_8616,
)

__all__ = [
    "CallTargetBindResult8616",
    "CallTargetBindStage8616",
    "CallTargetBindStats8616",
    "CallTargetBindVerdict8616",
    "bind_ssa_call_target_8616",
]


def _decoded_entry_candidates_8616(
    callsite_index: DecodedDirectCallsiteIndex8616,
    project: object,
    caller_addr: int,
    callsite_addr: int,
    accepted_target_addrs: tuple[int, ...],
) -> tuple[DecodedDirectCallsite8616, ...]:
    """Collect unique admitted near entries for the exact caller callsite."""
    accepted = {
        address
        for address in accepted_target_addrs
        if type(address) is int and address >= 0
    }
    # The admitted relation may use image-relative coordinates while the
    # decoded census retains native linear targets. Canonicalization expands
    # lookup only; native proof and final full-width admission still decide.
    normalized = {
        target
        for address in accepted
        if (target := normalize_x86_16_call_target_addr_8616(project, address)) is not None
    }
    seen: set[tuple[int, int, int, int]] = set()
    entries: list[DecodedDirectCallsite8616] = []
    for accepted_addr in sorted(accepted | normalized):
        for entry in callsite_index.for_target(accepted_addr):
            if (
                entry.caller_start != caller_addr
                or entry.callsite_addr != callsite_addr
                or entry.is_far
            ):
                continue
            key = (
                entry.caller_start,
                entry.callsite_addr,
                entry.target_addr,
                entry.instruction_index,
            )
            if key in seen:
                continue
            seen.add(key)
            entries.append(entry)
    return tuple(sorted(entries, key=lambda item: item.instruction_index))


def _target_admitted_8616(
    project: object,
    target_addr: int,
    accepted_target_addrs: tuple[int, ...],
) -> bool:
    """Require the proven target inside the admitted exact/alias relation."""
    accepted = frozenset(
        address
        for address in accepted_target_addrs
        if type(address) is int and not isinstance(address, bool)
    )
    if not accepted:
        return False
    return target_addr in accepted or any(
        x86_16_call_targets_equivalent_8616(project, target_addr, address)
        for address in accepted
    )


def bind_ssa_call_target_8616(
    artifact: SSAFunctionArtifact,
    caller_addr: int,
    callsite_addr: int,
    accepted_target_addrs: tuple[int, ...],
    *,
    project: object | None,
    callsite_index: DecodedDirectCallsiteIndex8616 | None,
    projection: CallSemanticProjection8616 | None = None,
) -> CallTargetBindResult8616:
    """Prove the full-width target of one symbolic SSA CALL, or refuse.

    Route selection is evidence-driven: a supplied ``projection`` selects
    the semantic route; otherwise the artifact must be raw-stage SSA. A
    registered ``SEMANTIC`` artifact without its retained projection refuses
    ``SEMANTIC_PROJECTION_MISSING`` rather than silently mis-binding
    prefix-shifted positions; a registered artifact object different from
    the supplied one refuses ``SSA_ARTIFACT_STALE``.
    """
    if type(callsite_addr) is not int or callsite_addr < 0:
        return _refuse_8616(
            0,
            CallTargetBindVerdict8616.UNKNOWN_REFUSE,
            CallTargetBindStage8616.SSA_CALL_NOT_FOUND,
        )
    candidate = _unique_ssa_call_8616(artifact, caller_addr, callsite_addr)
    if isinstance(candidate, CallTargetBindResult8616):
        return candidate
    ssa_block_addr, ssa_instr_index, ssa_instr = candidate
    if project is None:
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.UNKNOWN_REFUSE,
            CallTargetBindStage8616.PROJECT_MISSING,
            normalized=True,
        )
    registered_ssa = registered_function_ssa_artifact_8616(project, caller_addr)
    if (
        registered_ssa.failure
        is FunctionSSAArtifactFailure8616.ARTIFACT_CONFLICT
        or (
            registered_ssa.verdict is FunctionSSAArtifactVerdict8616.PROVEN
            and registered_ssa.artifact is not artifact
        )
    ):
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.CONFLICT,
            CallTargetBindStage8616.SSA_ARTIFACT_STALE,
            normalized=True,
        )
    if projection is not None:
        producer = _semantic_route_producer_8616(
            project,
            projection,
            artifact,
            caller_addr,
            callsite_addr,
            ssa_block_addr,
            ssa_instr_index,
            ssa_instr,
        )
    elif (
        registered_ssa.verdict is FunctionSSAArtifactVerdict8616.PROVEN
        and registered_ssa.stage is FunctionSSAArtifactStage8616.SEMANTIC
    ):
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.UNKNOWN_REFUSE,
            CallTargetBindStage8616.SEMANTIC_PROJECTION_MISSING,
            normalized=True,
        )
    else:
        producer = _raw_route_producer_8616(
            project,
            artifact,
            caller_addr,
            callsite_addr,
            ssa_block_addr,
            ssa_instr_index,
            ssa_instr,
        )
    if isinstance(producer, CallTargetBindResult8616):
        return producer
    return _prove_admitted_8616(
        project,
        producer,
        callsite_index,
        caller_addr,
        callsite_addr,
        accepted_target_addrs,
        ssa_block_addr,
        ssa_instr_index,
    )



def _prove_admitted_8616(
    project: object,
    producer: _BoundProducer8616,
    callsite_index: DecodedDirectCallsiteIndex8616 | None,
    caller_addr: int,
    callsite_addr: int,
    accepted_target_addrs: tuple[int, ...],
    ssa_block_addr: int,
    ssa_instr_index: int,
) -> CallTargetBindResult8616:
    """Discharge the Semantics binding against admitted decoded evidence.

    The decoded index must contribute entries for the exact caller/callsite
    inside the admitted relation; every candidate is proved independently
    and ambiguous proven targets refuse. When the retained effect fact
    already carried a complete materialization-time binding, it must agree
    with the decoded-route target — it corroborates, never substitutes.
    """
    if not isinstance(callsite_index, DecodedDirectCallsiteIndex8616) or not (
        callsite_index.stats.closed
    ):
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.UNKNOWN_REFUSE,
            CallTargetBindStage8616.DECODED_INDEX_MISSING,
            normalized=True,
        )
    entries = _decoded_entry_candidates_8616(
        callsite_index, project, caller_addr, callsite_addr, accepted_target_addrs
    )
    if not entries:
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.UNKNOWN_REFUSE,
            CallTargetBindStage8616.DECODED_ENTRY_MISSING,
            normalized=True,
        )
    if len({entry.target_addr for entry in entries}) != 1:
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.CONFLICT,
            CallTargetBindStage8616.DECODED_TARGET_AMBIGUOUS,
            normalized=True,
            classified=True,
        )
    proven: list[DirectNearCallTargetBinding8616] = []
    last_binding: DirectNearCallTargetBinding8616 | None = None
    for entry in entries:
        proof = prove_direct_near_call_target_binding_from_decoded_8616(
            project,
            block=producer.raw_block,
            instruction=producer.raw_instr,
            decoded=entry,
        )
        last_binding = proof
        if proof.complete and proof.callsite_addr == callsite_addr:
            proven.append(proof)
    proven_targets = {binding.target_addr for binding in proven}
    if len(proven_targets) > 1:
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.CONFLICT,
            CallTargetBindStage8616.DECODED_TARGET_AMBIGUOUS,
            normalized=True,
            classified=True,
            binding=proven[0],
        )
    if not proven:
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.UNKNOWN_REFUSE,
            CallTargetBindStage8616.NATIVE_BINDING_REFUSED,
            normalized=True,
            classified=True,
            binding=last_binding,
        )
    return _admit_proven_8616(
        project,
        producer,
        proven[0],
        callsite_addr,
        accepted_target_addrs,
        ssa_block_addr,
        ssa_instr_index,
    )


def _admit_proven_8616(
    project: object,
    producer: _BoundProducer8616,
    binding: DirectNearCallTargetBinding8616,
    callsite_addr: int,
    accepted_target_addrs: tuple[int, ...],
    ssa_block_addr: int,
    ssa_instr_index: int,
) -> CallTargetBindResult8616:
    """Admit one decoded-proof target, corroborated by retained evidence.

    The projection's retained ``target_binding`` must agree whenever it
    carried a complete proof — it corroborates but never substitutes for
    the decoded route — and the proven coordinate must sit inside the
    admitted exact/alias target relation.
    """
    target_addr = binding.target_addr
    if type(target_addr) is not int or target_addr < 0:
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.UNKNOWN_REFUSE,
            CallTargetBindStage8616.NATIVE_BINDING_REFUSED,
            normalized=True,
            classified=True,
            binding=binding,
        )
    retained = None if producer.fact is None else producer.fact.target_binding
    if (
        retained is not None
        and retained.complete
        and retained.target_addr != target_addr
    ):
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.CONFLICT,
            CallTargetBindStage8616.RETAINED_BINDING_CONFLICT,
            normalized=True,
            classified=True,
            binding=binding,
        )
    if not _target_admitted_8616(project, target_addr, accepted_target_addrs):
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.CONFLICT,
            CallTargetBindStage8616.TARGET_NOT_ADMITTED,
            normalized=True,
            classified=True,
            binding=binding,
        )
    return CallTargetBindResult8616(
        callsite_addr=callsite_addr,
        verdict=CallTargetBindVerdict8616.PROVEN,
        stage=CallTargetBindStage8616.PROVEN,
        stats=CallTargetBindStats8616(1, 1, 1, 1, 0),
        target_addr=target_addr,
        block_addr=ssa_block_addr,
        instr_index=ssa_instr_index,
        binding=binding,
        retained_binding=retained,
    )
