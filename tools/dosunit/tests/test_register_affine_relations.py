"""Prove modular inversion and fail-closed register relation synthesis."""
import pytest

import tools.dosunit.compare.straightline_ssa as S
from tools.dosunit.compare.real16_call_contracts import materialize_function
from tools.dosunit.contracts.register_affine_relations import (
    AffineRegisterBinding,
    RegisterAffineRelation,
    propose_entry_relation,
)
from tools.dosunit.contracts.register_state_relations import RegisterRelationReason, RegisterRelationRefusal


def state(width,token=1):
    return {'x':{'op':'input','width':width,'name':'x'},
            'paired_control':{'op':'const','width':32,'value':hex(token)}}

@pytest.mark.parametrize('width',[8,16,32])
@pytest.mark.parametrize('scale,offset',[(1,7),(3,9),(-1,-7)])
def test_exact_modular_inverse(width,scale,offset):
    original=state(width)
    mask=(1<<width)-1
    relation=RegisterAffineRelation((AffineRegisterBinding('x','x',width,scale&mask,offset&mask),))
    candidate=relation.candidate_inputs(original)
    result=relation.continuing_outputs(candidate,control_field='paired_control')
    compared=S._compare_functions(materialize_function('o',original),materialize_function('c',result),timeout_ms=3000)
    assert compared['status']=='passed',compared

@pytest.mark.parametrize('scale',[0,2,4])
def test_even_multiplier_is_not_bijective(scale):
    with pytest.raises(RegisterRelationRefusal) as failure:
        RegisterAffineRelation((AffineRegisterBinding('x','x',16,scale,7),))
    assert failure.value.reason is RegisterRelationReason.NONINVERTIBLE

@pytest.mark.parametrize('token,status',[(0,'failed'),(1,'passed')])
def test_entry_backedge_must_restore_identity(token,status):
    original=state(16,token)
    relation=RegisterAffineRelation((AffineRegisterBinding('x','x',16,1,7),))
    candidate=relation.candidate_inputs(original)
    outputs=relation.continuing_outputs(candidate,control_field='paired_control',reenters_entry=True)
    compared=S._compare_functions(materialize_function('o',original),materialize_function('c',outputs),timeout_ms=3000)
    assert compared['status']==status,compared


def test_low_bit_projection_proposes_modular_translation():
    original=state(16)
    rebuilt={**original,'x':{'op':'trunc','width':16,'args':[
        {'op':'add','width':32,'args':[{'op':'zext','width':32,'args':[original['x']]},
                                    {'op':'const','width':32,'value':'0x10007'}]}]}}
    proposal=propose_entry_relation(original,rebuilt,{'x':16})
    assert isinstance(proposal.relation,RegisterAffineRelation)
    assert proposal.relation.bindings==(AffineRegisterBinding('x','x',16,1,7),)
    assert proposal.reason is RegisterRelationReason.AFFINE_EFFECTS


def test_synthesis_refuses_noninvertible_candidate_scale():
    original=state(16)
    rebuilt={**original,'x':{'op':'mul','width':16,'args':[original['x'],{'op':'const','width':16,'value':'0x2'}]}}
    proposal=propose_entry_relation(original,rebuilt,{'x':16})
    assert proposal.relation is None
    assert proposal.reason is RegisterRelationReason.NONINVERTIBLE


@pytest.mark.parametrize('width', [8, 16])
@pytest.mark.parametrize('high_first', [True, False])
def test_high_half_merge_proposes_and_proves_low_modular_recurrence(width, high_first):
    original = state(width)
    low = {'op': 'zext', 'width': 2 * width, 'args': [original['x']]}
    high = {'op': 'shl', 'width': 2 * width, 'args': [
        {'op': 'zext', 'width': 2 * width, 'args': [
            {'op': 'input', 'width': width, 'name': 'high'}]},
        {'op': 'const', 'width': 8, 'value': hex(width)}]}
    merged = {'op': 'or', 'width': 2 * width, 'args': [high, low] if high_first else [low, high]}
    effect = {'op': 'trunc', 'width': width, 'args': [
        {'op': 'add', 'width': 2 * width, 'args': [
            {'op': 'mul', 'width': 2 * width, 'args': [merged,
                {'op': 'const', 'width': 2 * width, 'value': '0x3'}]},
            {'op': 'const', 'width': 2 * width, 'value': '0x7'}]}]}
    rebuilt = {**original, 'x': effect}
    proposal = propose_entry_relation(original, rebuilt, {'x': width})
    assert isinstance(proposal.relation, RegisterAffineRelation), proposal
    assert proposal.relation.bindings == (AffineRegisterBinding('x', 'x', width, 3, 7),)
    normalized = proposal.relation.continuing_outputs(rebuilt, control_field='paired_control')
    proof = S._compare_functions(materialize_function('oracle', original),
                                 materialize_function('candidate', normalized), timeout_ms=3000)
    assert proof['status'] == 'passed', proof


@pytest.mark.parametrize('other', [
    {'op': 'const', 'width': 16, 'value': '0x7'},
    {'op': 'shl', 'width': 16, 'args': [
        {'op': 'input', 'width': 16, 'name': 'high'},
        {'op': 'const', 'width': 8, 'value': '0x4'}]},
])
def test_overlapping_or_bits_cannot_propose_linear_addition(other):
    original = state(16)
    rebuilt = {**original, 'x': {'op': 'or', 'width': 16, 'args': [original['x'], other]}}
    proposal = propose_entry_relation(original, rebuilt, {'x': 16})
    assert proposal.relation is None
    assert proposal.reason is RegisterRelationReason.NO_MATCH
