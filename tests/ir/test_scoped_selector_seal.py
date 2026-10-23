"""Post-authentication mutation controls for scoped selector sealing."""
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
