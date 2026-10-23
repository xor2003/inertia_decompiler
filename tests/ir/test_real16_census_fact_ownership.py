"""Closed stage receipts preserve separate ledgers and reject later edits."""

import pytest

from inertia.ir import real16_census_fact_ownership as owner

pytestmark = pytest.mark.decompiler


def completed_sets():
    sets = owner.new_census_fact_sets_8616()
    for row in ((1, 2), (3, 4)):
        for stage in sets:
            stage.add(row)
    return sets


def test_closed_receipt_keeps_four_distinct_equal_sets():
    sets = completed_sets()
    receipt = owner.census_fact_ownership_8616(sets)
    assert receipt is not None
    assert len({id(stage) for stage in sets}) == 4
    assert all(stage == {(1, 2), (3, 4)} for stage in sets)
    assert owner.census_fact_ownership_current_8616(receipt, sets)


def test_nested_rows_and_complete_duplicate_sequences_are_supported():
    sets = owner.new_census_fact_sets_8616()
    sets[0].add((1, 2))
    for stage in sets:
        stage.add((3, 4))
    assert owner.census_fact_ownership_8616(sets) is None
    for stage in sets[1:]:
        stage.add((1, 2))
    assert owner.census_fact_ownership_8616(sets) is not None
    for stage in sets:
        stage.add((1, 2))
    assert owner.census_fact_ownership_8616(sets) is not None


def test_partial_census_retains_unequal_public_stage_counts():
    sets = owner.new_census_fact_sets_8616()
    sets[0].add((1, 2))
    sets[1].add((1, 2))
    assert tuple(map(len, sets)) == (1, 1, 0, 0)
    assert owner.census_fact_ownership_8616(sets) is None


def test_out_of_order_additions_decline_even_when_sets_end_equal():
    sets = owner.new_census_fact_sets_8616()
    for index in (1, 0, 2, 3):
        sets[index].add((1, 2))
    assert sets[0] == sets[1] == sets[2] == sets[3]
    assert owner.census_fact_ownership_8616(sets) is None


@pytest.mark.parametrize("method", [
    "discard", "remove", "clear", "pop", "update", "difference_update",
    "intersection_update", "symmetric_difference_update", "__ior__",
    "__iand__", "__isub__", "__ixor__",
])
def test_each_supported_mutator_invalidates_receipt(method):
    sets = completed_sets()
    receipt = owner.census_fact_ownership_8616(sets)
    stage = sets[0]
    args = () if method in ("clear", "pop") else (
        (1, 2) if method in ("discard", "remove") else {(1, 2)},
    )
    getattr(stage, method)(*args)
    assert not owner.census_fact_ownership_current_8616(receipt, sets)


def test_same_cardinality_replacement_is_not_hidden_by_counts():
    sets = completed_sets()
    receipt = owner.census_fact_ownership_8616(sets)
    for stage in sets:
        stage.remove((1, 2))
        stage.add((5, 6))
    assert tuple(map(len, sets)) == (2, 2, 2, 2)
    assert not owner.census_fact_ownership_current_8616(receipt, sets)


def test_completed_later_row_requires_a_new_receipt():
    sets = completed_sets()
    receipt = owner.census_fact_ownership_8616(sets)
    for stage in sets:
        stage.add((5, 6))
    assert not owner.census_fact_ownership_current_8616(receipt, sets)
    assert owner.census_fact_ownership_8616(sets) is not None


def test_plain_replaced_and_mixed_owner_sets_decline():
    sets = completed_sets()
    receipt = owner.census_fact_ownership_8616(sets)
    assert owner.census_fact_ownership_8616(tuple(set(stage) for stage in sets)) is None
    other = completed_sets()
    assert owner.census_fact_ownership_8616((sets[0], *other[1:])) is None
    assert not owner.census_fact_ownership_current_8616(receipt, other)


def test_reinitialization_fails_loudly_and_revokes_old_receipt():
    sets = completed_sets()
    receipt = owner.census_fact_ownership_8616(sets)
    stage = sets[0]
    with pytest.raises(RuntimeError, match="reinitialized"):
        stage.__init__(stage.owner, stage.stage)
    assert not owner.census_fact_ownership_current_8616(receipt, sets)


def test_replaced_transition_producer_declines(monkeypatch):
    sets = completed_sets()
    receipt = owner.census_fact_ownership_8616(sets)
    monkeypatch.setattr(owner._FactOwner8616, "advance", lambda *args: None)
    assert not owner.census_fact_ownership_current_8616(receipt, sets)


@pytest.mark.parametrize("method", ["__ior__", "__iand__", "__isub__", "__ixor__"])
def test_unsupported_operator_operand_retains_builtin_notimplemented(method):
    stage = completed_sets()[0]
    assert getattr(stage, method)([(5, 6)]) is NotImplemented
    assert stage == {(1, 2), (3, 4)}
