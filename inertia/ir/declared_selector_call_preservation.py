"""Layer: IR.
Responsibility: collect conditional CALL records from a declared selector proof.

Universal callee closures produce selector-bound records. Invocation-bound
records retained by the selector proof preserve their original exact scope;
the batch reauthenticates them without publishing universal summaries.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, replace
from typing import Protocol, cast

from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
    DecodedDirectCallsiteIndex8616,
    DirectCallTargetResolver8616,
    decoded_callsite_index_for_boundary_8616,
)
from inertia.semantics.direct_near_call_target_binding import (
    DirectNearCallCoordinates8616,
    DirectNearCallTargetBindingPending8616,
    DirectNearCallTargetBindingVerdict8616,
    _seal_declared_selector_binding_8616,
    prepare_declared_near_call_target_binding_pending_8616,
)

from .core import IRBlock, IRInstr, IRValue, MemSpace
from .declared_selector_invariant import (
    DeclaredSegmentInvariant,
    DeclaredSelectorCallsite8616,
    InvariantStatus,
    Obligation,
    ObligationKind,
    _selector_cs_judgement_8616,
    consume_declared_selector_callsite_batch_8616,
    consume_declared_selector_cs_preservation_batch_8616,
    selector_callsite_8616,
)
from .declared_selector_scoped_callee import scoped_selector_record_facts_8616
from .direct_evidence_deadline import (
    deadline_reached_8616,
    direct_evidence_deadline_expired_8616,
)
from .entry_domain_call_preservation import (
    EntryDomainCallPreservation8616,
    EntryDomainCallPreservationFailure8616,
    _budget_exhausted_call_records_8616,
    _callee_dependency_failure_8616,
    _callee_preserved_registers_8616,
    _caller_premise_surface_8616,
    _caller_surface_failure_8616,
    _CallerInstructionPosition8616,
    _callsite_entry_failure_8616,
    _callsite_window_8616,
    _capture_caller_instruction_position_8616,
    _premise_target_resolver_8616,
    _refused_result_8616,
)
from .ir_boundary_cfg import IRBoundaryCoverageResult8616, prove_ir_boundary_coverage_8616
from .segment_call_preservation import segment_call_dependency_traversal_scope_8616
from .segment_effect_closure import SegmentEffectClosureResult8616, prove_segment_effect_closure_8616
from .segment_state import build_x86_16_segment_state_artifact
from .source_graph_binding import SourceGraphSerializationError8616, canonical_source_graph_8616


def _charge_collection_8616(project: object, units: int) -> bool:
    """Charge the existing shared ledger without increasing its limits."""
    with segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.census_work_units += units
        return (traversal.census_work_units <= traversal.census_work_limit
                and not deadline_reached_8616(traversal.census_deadline)
                and not direct_evidence_deadline_expired_8616(project))


def collect_declared_selector_call_preservations_8616(
    project: object, scope: DeclaredSegmentInvariant,
) -> tuple[EntryDomainCallPreservation8616, ...]:
    """Account every root CALL under its exact declared selector certificate."""
    link = scope.root_link
    if link is None:
        return ()
    artifact, boundary = link.artifact, link.boundary
    positions = tuple(
        _CallerInstructionPosition8616(
            artifact, block, instruction, artifact.blocks, block.instrs,
            block_index, instruction_index)
        for block_index, block in enumerate(artifact.blocks)
        for instruction_index, instruction in enumerate(block.instrs)
        if instruction.op == 'CALL')
    calls = tuple((position.block, position.instruction) for position in positions)
    if scope.project is not project or scope.status is not InvariantStatus.PROVEN_CONDITIONAL:
        return tuple(_refused_result_8616(
            artifact, boundary, block, instruction, None, None, None,
            instruction.addr, None,
            EntryDomainCallPreservationFailure8616.CALLER_BINDING_MISMATCH,
        ) for block, instruction in calls)
    with segment_call_dependency_traversal_scope_8616():
        if not _charge_collection_8616(project, len(calls)):
            return _budget_exhausted_call_records_8616(artifact, boundary, calls)
        index = decoded_callsite_index_for_boundary_8616(
            project, boundary, direct_target_resolver=cast(
                DirectCallTargetResolver8616, _premise_target_resolver_8616(project)),
        ).index
        index_facts = (_index_facts_8616(index)
                       if index._entries_by_normalized_target or index._entries_by_exact_far_target
                       else None)
        if index_facts is not None and not _charge_collection_8616(project, cast(int, index_facts[-1])):
            return _budget_exhausted_call_records_8616(artifact, boundary, calls, index)
        callees: dict[tuple[int, int, int, int], _PreparedCall8616] = {}
        prepared = tuple(_collect_call_8616(
            project, scope, index, position.block, position.instruction,
            index_facts=index_facts, callees=callees, position=position)
                         for position in positions)
        candidates = tuple(item for item in prepared if isinstance(item, _PreparedCall8616))
        if not candidates:
            return cast(tuple[EntryDomainCallPreservation8616, ...], prepared)
        assert index_facts is not None
        budget_refused: set[int] = set()
        admitted = _admit_prepared_calls_8616(project, candidates, budget_refused=budget_refused)
        index_current = index_facts == _index_facts_8616(index)
        index_current = _charge_collection_8616(project, cast(int, index_facts[-1])) and index_current
        callee_verdicts = _seal_shared_callees_8616(project, candidates, admitted)
        return tuple(_seal_call_8616(
            project, item, admitted[id(item)], index_admitted=index_current,
            budget_exhausted=id(item) in budget_refused,
            callee_admitted=(True if item.cs_only else callee_verdicts.get(id(item.record.callee), False)))
                     if isinstance(item, _PreparedCall8616) else item for item in prepared)


def _admit_prepared_calls_8616(
    project: object, candidates: tuple[_PreparedCall8616, ...],
    *, budget_refused: set[int],
) -> dict[int, bool]:
    """Batch each explicit authority without reconstructing CS-only closures."""
    admitted: dict[int, bool] = {}
    for cs_only in (False, True):
        group = tuple(item for item in candidates if item.cs_only is cs_only)
        if not group:
            continue
        projections = tuple(item.projection for item in group)
        obligations: list[Obligation] = []
        verdicts = (consume_declared_selector_cs_preservation_batch_8616(project, projections, obligations=obligations)
                    if cs_only else consume_declared_selector_callsite_batch_8616(project, projections, obligations=obligations))
        if any(item.kind in (ObligationKind.BUDGET_EXCEEDED, ObligationKind.DEADLINE_EXCEEDED)
               for item in obligations):
            budget_refused.update(id(item) for item, verdict in zip(group, verdicts, strict=True) if not verdict)
        admitted.update((id(item), verdict) for item, verdict in zip(group, verdicts, strict=True))
    return admitted


def _collect_call_8616(
    project: object, scope: DeclaredSegmentInvariant,
    index: DecodedDirectCallsiteIndex8616, block: IRBlock, instruction: IRInstr,
    *, index_facts: tuple[object, ...] | None = None,
    callees: dict[tuple[int, int, int, int], _PreparedCall8616] | None = None,
    position: _CallerInstructionPosition8616 | None = None,
) -> EntryDomainCallPreservation8616 | _PreparedCall8616:
    """Bind native geometry, symbolic operands and universal callee effects."""
    link = scope.root_link
    assert link is not None
    artifact, boundary = link.artifact, link.boundary
    if not _charge_collection_8616(project, 1):
        return _budget_exhausted_call_records_8616(
            artifact, boundary, ((block, instruction),), index)[0]
    geometry = tuple(row for row in scope.geometry_rows
                     if row.addr == instruction.addr and row.target is not None
                     and row.fallthrough is not None)
    if len(geometry) != 1:
        return _refused_result_8616(
            artifact, boundary, block, instruction, index, None, None,
            instruction.addr, None, EntryDomainCallPreservationFailure8616.TARGET_MISMATCH)
    row = geometry[0]
    assert row.target is not None and row.fallthrough is not None
    entries = tuple(entry for entry in index.for_target(row.target)
                    if entry.callsite_addr == instruction.addr
                    and entry.caller_start == artifact.function_addr)
    entry = entries[0] if len(entries) == 1 else None
    projection = selector_callsite_8616(scope, block, instruction, row.target, row.fallthrough)
    if entry is None or projection is None:
        return _refused_result_8616(
            artifact, boundary, block, instruction, index, entry, None,
            instruction.addr, row.target, EntryDomainCallPreservationFailure8616.CALLSITE_UNPROVEN)
    scoped = tuple(record for record in scope.scoped_call_preservations
                   if record.callsite_addr == instruction.addr
                   and record.artifact is artifact)
    if scoped:
        return _prepare_scoped_record_8616(project, projection, scoped, position)
    if _selector_cs_judgement_8616(projection):
        return _bound_record_8616(
            project, scope, index, entry, projection, None,
            index_facts=index_facts, position=position)
    return _callee_record_8616(
        project, scope, index, entry, projection, index_facts=index_facts, callees=callees,
        position=position)


def _prepare_scoped_record_8616(
    project: object, projection: DeclaredSelectorCallsite8616,
    records: tuple[EntryDomainCallPreservation8616, ...],
    position: _CallerInstructionPosition8616 | None,
) -> EntryDomainCallPreservation8616 | _PreparedCall8616:
    """Retain an exact invocation record for the selector batch's final proof.

    The invariant consumer authenticates the retained scoped pool after all
    preparation callbacks. Its pure certificate seal and this record snapshot
    must both agree before the original conditional record is returned.
    """
    record = records[0]
    if len(records) != 1 or not _scoped_record_matches_8616(record, projection):
        return _refuse_prepared_8616(record)
    assert record.callee is not None
    position = (_capture_caller_instruction_position_8616(
        record.artifact, record.block, record.instruction) if position is None else position)
    if position is None:
        return _refuse_prepared_8616(record)
    scoped_facts = scoped_selector_record_facts_8616(record)
    callee_facts = _callee_facts_8616(record.callee)
    index_facts = _index_facts_8616(record.index)
    units = (_metadata_work_units_8616(scoped_facts)
             + cast(int, callee_facts[-1]) + cast(int, index_facts[-1]) + 1)
    if not _charge_collection_8616(project, units):
        return _budget_exhausted_call_records_8616(
            record.artifact, record.boundary,
            ((record.block, record.instruction),), record.index)[0]
    return _PreparedCall8616(record, projection, None, callee_facts,
                             index_facts, units, position, scoped_facts)


def _scoped_record_matches_8616(
    record: EntryDomainCallPreservation8616, projection: DeclaredSelectorCallsite8616,
) -> bool:
    """Bind the original scoped record to this exact caller instruction."""
    link = projection.scope.root_link
    if link is None or record.required_scope is None or record.selector_projection is not None:
        return False
    identities = (record.artifact is link.artifact and record.boundary is link.boundary
                  and record.block is projection.block and record.instruction is projection.instruction)
    coordinates = (record.callsite_addr == projection.callsite_addr
                   and record.target_addr == projection.target_addr)
    return identities and coordinates and record.callee is not None and record.failure is None


def _callee_record_8616(
    project: object, scope: DeclaredSegmentInvariant, index: DecodedDirectCallsiteIndex8616,
    entry: DecodedDirectCallsite8616, projection: DeclaredSelectorCallsite8616,
    *, index_facts: tuple[object, ...] | None = None,
    callees: dict[tuple[int, int, int, int], _PreparedCall8616] | None = None,
    position: _CallerInstructionPosition8616 | None = None,
) -> EntryDomainCallPreservation8616 | _PreparedCall8616:
    """Retain a refused record whenever the full universal callee chain is absent."""
    link = scope.root_link
    assert link is not None
    artifact, boundary = link.artifact, link.boundary
    block, instruction = projection.block, projection.instruction
    # This table lives only inside one collection. Resolve each target once:
    # native intake may return fresh wrapper identities on a repeated lookup.
    # Every call still binds separately, and the post-callback selector/native
    # and shared-callee seals must authenticate all retained evidence.
    key = (id(project), id(scope), id(scope.source), projection.target_addr)
    retained = None if callees is None else callees.get(key)
    if retained is not None:
        callee = retained.record.callee
        assert callee is not None
        return _bound_record_8616(
            project, scope, index, entry, projection, callee,
            index_facts=index_facts, callee_facts=retained.callee_facts, position=position)
    surface = _caller_premise_surface_8616(project, projection.target_addr)
    if not _charge_collection_8616(project, 0):
        return _budget_exhausted_call_records_8616(
            artifact, boundary, ((block, instruction),), index)[0]
    if surface is None:
        return _refused_result_8616(
            artifact, boundary, block, instruction, index, entry, None,
            instruction.addr, projection.target_addr, EntryDomainCallPreservationFailure8616.CALLEE_UNRESOLVED)
    callee_artifact, callee_boundary, coverage = surface
    if not _charge_collection_8616(
        project, len(callee_artifact.blocks) + sum(len(block.instrs) for block in callee_artifact.blocks),
    ):
        return _budget_exhausted_call_records_8616(artifact, boundary, ((block, instruction),), index)[0]
    if type(coverage) is not IRBoundaryCoverageResult8616:
        coverage = prove_ir_boundary_coverage_8616(project, callee_boundary, callee_artifact)
    if not _charge_collection_8616(project, 0):
        return _budget_exhausted_call_records_8616(
            artifact, boundary, ((block, instruction),), index)[0]
    callee = prove_segment_effect_closure_8616(
        coverage, build_x86_16_segment_state_artifact(callee_artifact))
    universal_callee = _fresh_universal_closure_8616(callee)
    if not _charge_collection_8616(project, 1):
        return _budget_exhausted_call_records_8616(
            artifact, boundary, ((block, instruction),), index)[0]
    if not universal_callee:
        return _refused_result_8616(
            artifact, boundary, block, instruction, index, entry, callee,
            instruction.addr, projection.target_addr,
            EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE)
    result = _bound_record_8616(
        project, scope, index, entry, projection, callee, index_facts=index_facts, position=position)
    if isinstance(result, _PreparedCall8616) and callees is not None:
        callees[key] = result
    return result


def _fresh_universal_closure_8616(callee: SegmentEffectClosureResult8616) -> bool:
    """Consume the just-returned canonical factory result only until the pure seal."""
    if type(callee) is not SegmentEffectClosureResult8616:
        return False
    counts = (callee.raw_fact_count, callee.normalized_fact_count,
              callee.classified_fact_count, callee.materialized_count, callee.failure_count)
    return (callee.failure is None and callee.state.invocation_scope is None
            and counts == (1, 1, 1, 1, 0) and all(type(item) is int for item in counts))


@dataclass(frozen=True, slots=True)
class _PreparedCall8616:
    """Nonpublishing obligations retained until the shared selector batch seals."""

    record: EntryDomainCallPreservation8616
    projection: DeclaredSelectorCallsite8616
    pending: DirectNearCallTargetBindingPending8616 | None
    callee_facts: tuple[object, ...]
    index_facts: tuple[object, ...]
    work_units: int
    position: _CallerInstructionPosition8616
    scoped_facts: object | None = None
    cs_only: bool = False


class _NativeInstructionMetadata8616(Protocol):
    """Read-only third-party decoded instruction metadata at the native boundary."""

    address: int
    size: int
    bytes: bytes | bytearray


def _native_entry_facts_8616(entry: DecodedDirectCallsite8616) -> tuple[object, ...]:
    """Read the retained decoded CALL metadata without loading or lifting again."""
    position = entry.instruction_index
    if type(position) is not int or not 0 <= position < len(entry.instructions):
        return ()
    native = cast(_NativeInstructionMetadata8616, entry.instructions[position])
    return (id(native), type(native.address), native.address, type(native.size),
            native.size, bytes(native.bytes))


def _index_facts_8616(index: DecodedDirectCallsiteIndex8616) -> tuple[object, ...]:
    """Detach owned index maps and relevant native CALL coordinates and bytes."""
    def rows(mapping: dict[int, tuple[DecodedDirectCallsite8616, ...]]) -> tuple[object, ...]:
        """Keep map membership and each exact decoded entry's owned fields."""
        return tuple((key, tuple((
            id(entry), entry.caller_start, id(entry.instructions),
            entry.instruction_index, entry.callsite_addr, entry.target_addr,
            id(entry.entry_identity), entry.is_far, _native_entry_facts_8616(entry),
        ) for entry in entries)) for key, entries in mapping.items())

    near, far = rows(index._entries_by_normalized_target), rows(index._entries_by_exact_far_target)
    units = (sum(len(entries) for entries in index._entries_by_normalized_target.values())
             + sum(len(entries) for entries in index._entries_by_exact_far_target.values())
             + len(index.entry_identities) + len(index.caller_censuses) + 1)
    return (deepcopy(index.stats), near, far,
            tuple(id(item) for item in index.entry_identities),
            tuple(id(item) for item in index.caller_censuses), units)


def _metadata_work_units_8616(value: object) -> int:
    """Count detached mutable metadata entries, including nested summary containers."""
    if isinstance(value, dict):
        return sum(1 + _metadata_work_units_8616(item) for item in value.values())
    if isinstance(value, (tuple, list)):
        return sum(1 + _metadata_work_units_8616(item) for item in value)
    return 0


def _coverage_facts_8616(coverage: IRBoundaryCoverageResult8616) -> tuple[object, ...]:
    """Detach coverage accounting and every owned boundary coordinate."""
    boundary = coverage.boundary
    return (id(coverage), id(coverage.artifact), id(boundary), coverage.failure,
            coverage.raw_fact_count, coverage.normalized_fact_count,
            coverage.classified_fact_count, coverage.materialized_count, coverage.failure_count,
            id(coverage.scoped_view), id(boundary.project), boundary.addr, boundary.size,
            boundary.block_addrs_set, boundary.reachable_instruction_addrs,
            boundary.successor_edges, boundary.decode_lower_bound,
            tuple(id(item) for item in boundary.blocks), deepcopy(boundary.info),
            id(boundary.near_return_continuations))


def _callee_facts_8616(
    callee: SegmentEffectClosureResult8616, visited: set[int] | None = None,
) -> tuple[object, ...]:
    """Detach mutable universal state and nested closures without invoking evidence."""
    if visited is None:
        visited = set()
    if id(callee) in visited:
        return (id(callee), 0)
    visited.add(id(callee))
    coverage, state = callee.coverage, callee.state
    artifact = coverage.artifact
    dependencies = tuple((
        id(proof), _coverage_facts_8616(proof.caller), _index_facts_8616(proof.index), proof.callsite_addr,
        proof.failure, proof.raw_fact_count, proof.normalized_fact_count,
        proof.classified_fact_count, proof.materialized_count, proof.failure_count,
        id(proof.invocation), id(proof.invocation_scope),
        _callee_facts_8616(proof.callee, visited),
    ) for proof in state.call_preservations)
    state_maps = (state.entry_states, state.exit_states, state.instruction_entry_states,
                  state.instruction_exit_states, state.summary)
    units = (len(artifact.blocks) + sum(len(block.instrs) for block in artifact.blocks)
             + _metadata_work_units_8616(state_maps)
             + _metadata_work_units_8616(coverage.boundary.info)
             + sum(cast(int, item[-1][-1]) + cast(int, item[2][-1]) + 1 for item in dependencies))
    return (
        id(callee), _coverage_facts_8616(coverage), id(artifact), id(state),
        callee.failure, callee.callsite_addrs,
        callee.return_block_addrs, callee.raw_fact_count, callee.normalized_fact_count,
        callee.classified_fact_count, callee.materialized_count, callee.failure_count,
        id(state.source_artifact), id(state.entry_context), id(state.invocation_scope),
        id(state.scoped_view), dependencies, tuple(id(item) for item in state.declared_call_consumptions),
        deepcopy(state_maps),
        canonical_source_graph_8616(artifact.function_addr, artifact.blocks), artifact.refusals, units,
    )


def _bound_record_8616(
    project: object, scope: DeclaredSegmentInvariant, index: DecodedDirectCallsiteIndex8616,
    entry: DecodedDirectCallsite8616, projection: DeclaredSelectorCallsite8616,
    callee: SegmentEffectClosureResult8616 | None,
    *, index_facts: tuple[object, ...] | None = None,
    callee_facts: tuple[object, ...] | None = None,
    position: _CallerInstructionPosition8616 | None = None,
) -> EntryDomainCallPreservation8616 | _PreparedCall8616:
    """Prepare every callback obligation before the one shared selector admission."""
    link = scope.root_link
    assert link is not None
    artifact, boundary = link.artifact, link.boundary
    block, instruction = projection.block, projection.instruction
    result = EntryDomainCallPreservation8616(
        artifact, boundary, block, instruction, index, entry, callee, None,
        projection.callsite_addr, projection.target_addr, None, 1, 1, 1, 1, 0,
        selector_binding=projection,
    )
    callee_units = 0
    if callee_facts is None:
        callee_facts = () if callee is None else _callee_facts_8616(callee)
        callee_units = 0 if callee is None else cast(int, callee_facts[-1])
    index_units = 0
    if index_facts is None:
        index_facts = _index_facts_8616(index)
        index_units = cast(int, index_facts[-1])
    # Collection already visited the exact slots while enumerating CALLs.
    # Retain the operand-encoding charge, but avoid a second membership scan.
    membership_units = len(block.instrs) if position is None else 0
    units = callee_units + index_units + len(block.instrs) + membership_units + 1
    if not _charge_collection_8616(project, units):
        return _budget_exhausted_call_records_8616(artifact, boundary, ((block, instruction),), index)[0]
    position = (_capture_caller_instruction_position_8616(artifact, block, instruction)
                if position is None else position)
    failure = (_caller_surface_failure_8616(result, position=position) or _callsite_entry_failure_8616(result)
               or (None if callee is None else _callee_dependency_failure_8616(callee)))
    window = _callsite_window_8616(project, entry)
    operand = instruction.args[0] if instruction.args else None
    callee_bound = (_selector_cs_judgement_8616(projection) if callee is None else (
        callee.coverage.artifact.function_addr == projection.target_addr
        and callee.coverage.boundary.project is project
        and "cs" in _callee_preserved_registers_8616(callee)))
    if (failure is not None or window is None or projection.target_addr not in window[2]
            or not callee_bound):
        return _refuse_prepared_8616(result)
    assert position is not None
    if not isinstance(operand, IRValue):
        return _refuse_prepared_8616(result)
    pending = None
    if operand.space is MemSpace.CONST:
        if type(operand.const) is not int or operand.const != projection.target_addr:
            return _refuse_prepared_8616(result)
    else:
        offered = prepare_declared_near_call_target_binding_pending_8616(
            project, block=block, instruction=instruction,
            coordinates=DirectNearCallCoordinates8616(
                projection.callsite_addr, window[0], window[1]),
            selector_binding=projection,
        )
        if not isinstance(offered, DirectNearCallTargetBindingPending8616):
            return _refuse_prepared_8616(result)
        pending = offered
    if not _charge_collection_8616(project, 0):
        return _budget_exhausted_call_records_8616(artifact, boundary, ((block, instruction),), index)[0]
    # Pending operands still encode the entire current block. Both membership
    # seals now check retained slots directly; constants need no graph pass.
    final_units = (len(block.instrs) if pending is not None else 0) + 1
    return _PreparedCall8616(result, projection, pending, callee_facts, index_facts, final_units, position,
                             cs_only=callee is None)


def _refuse_prepared_8616(result: EntryDomainCallPreservation8616) -> EntryDomainCallPreservation8616:
    """Keep failed preparation in the complete per-CALL accounting census."""
    return _refused_result_8616(
        result.artifact, result.boundary, result.block, result.instruction,
        result.index, result.entry, result.callee, result.callsite_addr, result.target_addr,
        EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE,
    )


def _callee_facts_match_8616(prepared: _PreparedCall8616) -> bool:
    """Turn malformed owned source serialization into its precise typed non-proof."""
    callee = prepared.record.callee
    if callee is None:
        return False
    try:
        if prepared.scoped_facts is not None:
            return prepared.scoped_facts == cast(object, scoped_selector_record_facts_8616(prepared.record))
        if not _fresh_universal_closure_8616(callee):
            return False
        return prepared.callee_facts == _callee_facts_8616(callee)
    except SourceGraphSerializationError8616:
        return False


def _seal_shared_callees_8616(
    project: object, prepared: tuple[_PreparedCall8616, ...], admitted: dict[int, bool],
) -> dict[int, bool]:
    """Reconcile every distinct retained callee once after the last callback."""
    results: dict[int, bool] = {}
    for item in prepared:
        if item.cs_only:
            continue
        key = id(item.record.callee)
        if key in results or not admitted[id(item)]:
            continue
        if not _charge_collection_8616(project, cast(int, item.callee_facts[-1])):
            break
        results[key] = _callee_facts_match_8616(item)
    return results


def _seal_call_8616(
    project: object, prepared: _PreparedCall8616, admitted: bool,
    *, index_admitted: bool | None = None, callee_admitted: bool | None = None,
    budget_exhausted: bool = False,
) -> EntryDomainCallPreservation8616:
    """Materialize through pure metadata/operand seals after all callbacks finish."""
    result = prepared.record
    units = prepared.work_units if admitted else 0
    if admitted and callee_admitted is None and not prepared.cs_only:
        units += cast(int, prepared.callee_facts[-1])
    if not _charge_collection_8616(project, units) or budget_exhausted:
        return _budget_exhausted_call_records_8616(
            result.artifact, result.boundary, ((result.block, result.instruction),), result.index)[0]
    if not admitted:
        return _refuse_prepared_8616(result)
    if index_admitted is None:
        index_admitted = prepared.index_facts == _index_facts_8616(result.index)
    if callee_admitted is None:
        callee_admitted = prepared.cs_only or _callee_facts_match_8616(prepared)
    if (not index_admitted or not callee_admitted
            or _caller_surface_failure_8616(result, position=prepared.position) is not None
            or _callsite_entry_failure_8616(result) is not None):
        return _refuse_prepared_8616(result)
    return _seal_operand_8616(prepared)


def _seal_operand_8616(prepared: _PreparedCall8616) -> EntryDomainCallPreservation8616:
    """Finish a bound operand without replaying a just-consumed scoped proof."""
    result = prepared.record
    if prepared.scoped_facts is not None:
        if (not _scoped_record_matches_8616(result, prepared.projection)
                or not _callee_facts_match_8616(prepared)):
            return _refuse_prepared_8616(result)
        return result
    pending = prepared.pending
    if pending is not None:
        binding = _seal_declared_selector_binding_8616(pending, admitted=True)
        if binding.verdict is not DirectNearCallTargetBindingVerdict8616.PROVEN:
            return _refuse_prepared_8616(result)
        return replace(result, binding=binding)
    operand = result.instruction.args[0] if result.instruction.args else None
    if (not isinstance(operand, IRValue) or operand.space is not MemSpace.CONST
            or type(operand.const) is not int or operand.const != result.target_addr):
        return _refuse_prepared_8616(result)
    return result
