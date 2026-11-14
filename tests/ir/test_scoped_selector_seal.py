"""Post-authentication mutation controls for scoped selector sealing."""
from copy import copy
from dataclasses import replace

import pytest

from inertia.ir import declared_selector_invariant as selector
from inertia.ir import declared_selector_scoped_callee as snapshots
from tests.ir.test_forward_declared_call_scope import _collect, _forward_world
from tests.ir.test_scoped_selector_callee import _prove


@pytest.mark.parametrize("mutation", ["none", "edge", "entry_binding", "prior_proof", "record_entry", "selector_binding"])
def test_post_native_callback_mutation_refuses(monkeypatch, mutation):
    captured = []
    active = []
    changed = []
    original_scoped = selector._seal_scoped_receipt_8616
    original_seal = selector._seal_positive_receipt
    original_native = selector._prepare_scoped_native_rebind_8616

    def scoped(*args, **kwargs):
        captured.append(args[-1])
        return original_scoped(*args, **kwargs)

    def seal(*args, **kwargs):
        active.append(True)
        try:
            return original_seal(*args, **kwargs)
        finally:
            active.pop()

    def native(*args, **kwargs):
        value = original_native(*args, **kwargs)
        if active and captured and not changed:
            records = captured[-1].records
            assert len(records) == 2
            record = records[0]
            chain = record.callee.state.invocation_scope.chain
            if mutation == "edge":
                object.__setattr__(chain, "edge", object())
            elif mutation == "entry_binding":
                binding = chain.entry_binding
                object.__setattr__(binding, "target_addr", binding.target_addr ^ 1)
            elif mutation == "prior_proof":
                prior = records[1].required_scope.entry_call_preservations[0]
                object.__setattr__(prior, "classified_fact_count", prior.classified_fact_count + 1)
            elif mutation == "record_entry":
                object.__setattr__(record, "entry", None)
            elif mutation == "selector_binding":
                object.__setattr__(record, "selector_binding", object())
            changed.append(True)
        return value

    monkeypatch.setattr(selector, "_seal_scoped_receipt_8616", scoped)
    monkeypatch.setattr(selector, "_seal_positive_receipt", seal)
    monkeypatch.setattr(selector, "_prepare_scoped_native_rebind_8616", native)
    result = _prove(_forward_world())
    assert changed, result.obligations
    expected = selector.InvariantStatus.PROVEN_CONDITIONAL if mutation == "none" else selector.InvariantStatus.REFUSED
    assert result.status is expected, result.obligations


def test_shared_graph_expansion_is_linear_and_cross_root_mutation_is_visible():
    records = _collect(_forward_world())
    assert all(row.failure is None for row in records)
    one = snapshots.scoped_selector_records_facts_8616(records)
    repeated = snapshots.scoped_selector_records_facts_8616(records * 32)
    assert snapshots.scoped_selector_facts_work_8616(repeated) == snapshots.scoped_selector_facts_work_8616(one) + 62
    assert records[1].required_scope.entry_call_preservations[0] is records[0]
    object.__setattr__(records[0], "materialized_count", 0)
    assert repeated != snapshots.scoped_selector_records_facts_8616(records * 32)


def test_equal_nonidentical_entry_snapshot_tracks_mutable_fields():
    record = _collect(_forward_world())[0]
    copied = replace(record.entry)
    assert copied is not record.entry and copied == record.entry
    object.__setattr__(record, "entry", copied)
    assert record.complete_for(record.required_scope)
    before = snapshots.scoped_selector_record_facts_8616(record)
    object.__setattr__(copied, "target_addr", copied.target_addr ^ 1)
    assert before != snapshots.scoped_selector_record_facts_8616(record)


def test_shared_callsite_index_snapshot_cost_and_mutation() -> None:
    """Shared native index evidence costs less than distinct indexes and stays fresh."""
    records = _collect(_forward_world())
    assert len(records) == 2
    assert all(record.failure is None for record in records)
    assert records[0].index is records[1].index
    shared = snapshots.scoped_selector_records_facts_8616(records)
    distinct = (records[0], replace(records[1], index=copy(records[1].index)))
    separate = snapshots.scoped_selector_records_facts_8616(distinct)
    assert snapshots.scoped_selector_facts_work_8616(shared) < snapshots.scoped_selector_facts_work_8616(separate)
    records[0].index._entries_by_normalized_target.clear()
    assert shared != snapshots.scoped_selector_records_facts_8616(records)
    assert not snapshots.scoped_selector_records_current_8616(records)


@pytest.mark.parametrize("mutation", [None, "record_entry", "native_index"])
def test_two_scoped_calls_fit_shared_snapshot_budget(
    monkeypatch: pytest.MonkeyPatch, mutation: str | None,
) -> None:
    """Fresh native authentication of two scoped CALLs fits a bounded work request."""
    from inertia.ir.native_import_surface_cache import native_import_request_8616
    from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616

    world = _forward_world(guarded=False)
    scope = _prove(world)
    assert scope.status is selector.InvariantStatus.PROVEN_CONDITIONAL, scope.obligations
    projections = []
    for record in scope.scoped_call_preservations:
        assert record.entry is not None
        coordinates = record.entry.bound_near_coordinates(record.boundary)
        assert coordinates is not None
        projection = selector.selector_callsite_8616(
            scope, record.block, record.instruction, record.target_addr, coordinates[0],
        )
        assert projection is not None
        projections.append(projection)
    assert len(projections) == 2
    changed = []
    if mutation is not None:
        native = selector._prepare_selector_batch_surfaces_8616

        def mutate_after_native(*args, **kwargs):
            result = native(*args, **kwargs)
            if not changed:
                record = scope.scoped_call_preservations[0]
                if mutation == "record_entry":
                    assert record.entry is not None
                    object.__setattr__(record.entry, "target_addr", record.entry.target_addr ^ 1)
                else:
                    record.index._entries_by_normalized_target.clear()
                changed.append(True)
            return result

        monkeypatch.setattr(selector, "_prepare_selector_batch_surfaces_8616", mutate_after_native)
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616(
        census_work_limit=6500,
    ) as traversal:
        verdicts = selector.consume_declared_selector_callsite_batch_8616(world[0], tuple(projections))
    if mutation is not None:
        assert changed
        assert verdicts == (False, False)
    else:
        assert verdicts == (True, True)
    assert traversal.census_work_units <= 6500


@pytest.mark.parametrize("mutation", [None, "record_entry", "native_index"])
def test_mixed_call_collection_fits_one_native_seal_budget(
    monkeypatch: pytest.MonkeyPatch, mutation: str | None,
) -> None:
    """Mixed full-callee and CS-only evidence retains its identities within one budget."""
    from inertia.ir.declared_selector_call_preservation import collect_declared_selector_call_preservations_8616
    from inertia.ir.native_import_surface_cache import native_import_request_8616
    from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616

    world = _forward_world(guarded=False, caller_bytes=bytes.fromhex("b83412e80a00e80700e82400c3"))
    scope = _prove(world)
    assert scope.status is selector.InvariantStatus.PROVEN_CONDITIONAL, scope.obligations
    originals = scope.scoped_call_preservations
    assert len(originals) == 2
    changed = []
    if mutation is not None:
        native = selector._prepare_selector_batch_surfaces_8616

        def mutate_after_native(*args, **kwargs):
            result = native(*args, **kwargs)
            if not changed:
                if mutation == "record_entry":
                    assert originals[0].entry is not None
                    object.__setattr__(originals[0].entry, "target_addr", originals[0].entry.target_addr ^ 1)
                else:
                    originals[0].index._entries_by_normalized_target.clear()
                changed.append(True)
            return result

        monkeypatch.setattr(selector, "_prepare_selector_batch_surfaces_8616", mutate_after_native)
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616(
        census_work_limit=10000,
    ) as traversal:
        records = collect_declared_selector_call_preservations_8616(world[0], scope)
    assert len(records) == 3
    if mutation is not None:
        assert changed
        assert all(record.failure is not None for record in records)
    else:
        assert all(record.failure is None for record in records)
        assert records[0] is originals[0] and records[1] is originals[1]
        assert records[2].selector_projection is not None
    assert traversal.census_work_units <= 10000
