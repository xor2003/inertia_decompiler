"""Bind split accepted input storage to binary-proven callee word reads."""

import importlib
from dataclasses import replace

import pytest
from angr_platforms.X86_16.ir import MemSpace
from angr_platforms.X86_16.lowering.interprocedural_storage_contracts import (
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageSlotContract8616,
    StorageTrialRole8616,
    StorageTrialSignedness8616,
    StorageTrialValueClass8616,
)
from angr_platforms.X86_16.lowering.modular_argument_type_facts import ModularArgumentTypeFacts8616
from test_x86_16_modular_input_type_join import _BASE_STORAGE, _CALLEE_ADDR, _census_project


def _slot():
    pieces = tuple(StorageIdentity8616(StorageIdentityKind8616.STACK, 1,
                   replace(_BASE_STORAGE, offset=4 + index, size=1)) for index in range(2))
    return StorageSlotContract8616(StorageTrialRole8616.INPUT, 0, pieces,
                                  StorageTrialSignedness8616.SIGN_INSENSITIVE,
                                  StorageTrialValueClass8616.VALUE)


def _bind(slot, *, registered=True):
    owner = importlib.import_module("angr_platforms.X86_16.lowering.storage_word_input_binding")
    facts = ModularArgumentTypeFacts8616(_census_project(register_ssa=registered), _CALLEE_ADDR)
    return owner.bind_storage_word_input_8616(slot, facts)


def test_split_input_uses_callee_proven_word_without_relabeling_pieces():
    slot = _slot()
    result = _bind(slot)
    assert result.complete
    assert result.proof.proven_storage.size == 2
    assert result.proof.proven_storage is not slot.pieces[0].address
    assert slot.pieces[0].address == replace(_BASE_STORAGE, size=1)
    assert result.raw_fact_count == result.normalized_fact_count == result.classified_fact_count == result.materialized_count == 1
    assert result.failure_count == 0


@pytest.mark.parametrize("corruption", ["gap", "reverse", "overlap", "segment", "output", "width", "foreign_width"])
def test_bad_piece_envelopes_refuse(corruption):
    slot = _slot()
    first, second = slot.pieces
    if corruption == "gap":
        slot = replace(slot, pieces=(first, replace(second, address=replace(second.address, offset=6))))
    elif corruption == "reverse":
        slot = replace(slot, pieces=(second, first))
    elif corruption == "overlap":
        slot = replace(slot, pieces=(first, first))
    elif corruption == "segment":
        slot = replace(slot, pieces=(first, replace(second, address=replace(second.address, space=MemSpace.DS))))
    elif corruption == "output":
        slot = replace(slot, role=StorageTrialRole8616.RETURN)
    elif corruption == "width":
        slot = replace(slot, pieces=(first,))
    else:
        slot = replace(slot, pieces=(replace(first, width=True), second))
    result = _bind(slot)
    assert not result.complete
    assert result.materialized_count == 0 and result.failure_count == 1


def test_missing_semantic_ssa_refuses_without_asserted_segment_proof():
    assert not _bind(_slot(), registered=False).complete


def test_receipt_replays_the_slot_envelope():
    result = _bind(_slot())
    assert result.complete
    assert not replace(result, slot=replace(result.slot, pieces=result.slot.pieces[:1])).complete
    assert not replace(result, raw_fact_count=True).complete
