"""Refusal and entry-preservation controls for register cutpoint proposals."""

import pytest

import tools.dosunit.compare.straightline_ssa as S
from tools.dosunit.compare.real16_call_contracts import materialize_function
from tools.dosunit.contracts.register_state_relations import (
    RegisterBinding,
    RegisterPermutation,
    RegisterRelationReason,
    RegisterRelationRefusal,
    propose_entry_permutation,
)


def _state(token=1):
    return {"ax": {"op": "input", "name": "ax", "width": 16},
            "cx": {"op": "input", "name": "cx", "width": 16},
            "paired_control": {"op": "const", "width": 32, "value": hex(token)}}


def _swap():
    return RegisterPermutation((RegisterBinding("ax", "cx", 16), RegisterBinding("cx", "ax", 16)))


def test_interior_relation_cannot_be_assumed_at_entry_backedge():
    relation = _swap()
    for token, expected in ((0, "failed"), (1, "passed")):
        oracle = _state(token)
        candidate = relation.candidate_inputs(oracle)
        normalized = relation.continuing_outputs(candidate, control_field="paired_control", reenters_entry=True)
        result = S._compare_functions(materialize_function("o", oracle),
                                      materialize_function("c", normalized), timeout_ms=3000)
        assert result["status"] == expected


def test_non_bijective_register_map_refuses():
    with pytest.raises(RegisterRelationRefusal) as failure:
        RegisterPermutation((RegisterBinding("ax", "cx", 16),))
    assert failure.value.reason is RegisterRelationReason.BIJECTION


def test_register_width_disagreement_refuses():
    with pytest.raises(RegisterRelationRefusal) as failure:
        RegisterPermutation((RegisterBinding("ax", "cx", 16), RegisterBinding("cx", "ax", 32)))
    assert failure.value.reason is RegisterRelationReason.WIDTH


def test_missing_state_is_not_invented():
    with pytest.raises(RegisterRelationRefusal) as failure:
        _swap().candidate_inputs({"ax": _state()["ax"]})
    assert failure.value.reason is RegisterRelationReason.MISSING


def test_unique_binary_entry_effects_only_propose_a_relation():
    original = _state()
    proposal = propose_entry_permutation(original, _swap().candidate_inputs(original), {"ax":16,"cx":16})
    assert proposal.relation == _swap()
    assert proposal.reason is RegisterRelationReason.BINARY_EFFECTS


def test_ambiguous_equal_effects_do_not_choose_a_map():
    term = {"op":"const","width":16,"value":"0x1"}
    original = {"ax":term,"cx":term,"dx":{"op":"const","width":16,"value":"0x2"}}
    candidate = {**original,"dx":term}
    proposal = propose_entry_permutation(original,candidate,{"ax":16,"cx":16,"dx":16})
    assert proposal.relation is None
    assert proposal.reason is RegisterRelationReason.AMBIGUOUS
