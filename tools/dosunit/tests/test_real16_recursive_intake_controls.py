"""Synthetic consumer regressions; not native-image or public proof acceptance."""

import time

import pytest

import tools.dosunit.compare.real16_call_graph_admission as admission
from tools.dosunit.compare.real16_call_contracts import FunctionCtx, initial_state
from tools.dosunit.recursive_proofs import real16_joint_construction as construction
from tools.dosunit.recursive_proofs.recursive_call_components import FunctionId
from tools.dosunit.recursive_proofs.recursive_joint_admission import JointRefusal


def test_missing_admitted_call_site_is_typed_refusal(monkeypatch):
    """An unvisited declared CALL has no site; construction must refuse explicitly."""
    block = {'source': {'jumpkind': 'Ijk_Call'}}
    ctx = FunctionCtx('recursive', 'recursive', 0x1200, {9: block}, 12, 'a' * 64)
    monkeypatch.setattr(construction, '_effect', lambda *args: initial_state())
    with pytest.raises(JointRefusal):
        construction._pair_step(FunctionId('recursive'), ctx, ctx, 9,
                                [{}, {}], time.monotonic() + 1)


def constant(value):
    return {'op': 'const', 'width': 32, 'value': hex(value)}


def test_default_deadline_does_not_refuse_valid_nonliteral_call():
    """Real target/frame check over synthetic SSA; no native source claim."""
    block = {'source': {
        'jumpkind': 'Ijk_Call',
        'instructions': [{'bytes': 'e80d00', 'address': {'linear': '0x1200'}}],
        'transfer': {'kind': 'direct_call', 'target': {'linear': '0x1210'},
                     'fallthrough': {'linear': '0x1203'}},
    }}
    caller = FunctionCtx('caller', 'caller', 0x1200, {0: block, 3: {}}, 4, 'a' * 64)
    callee = FunctionCtx('callee', 'callee', 0x1210, {0: {}}, 1, 'b' * 64)
    state = initial_state()
    symbolic = {'op': 'input', 'name': 'eax', 'width': 32}
    zero = {'op': 'sub', 'width': 32, 'args': [symbolic, symbolic]}
    state['control_ip'] = {'op': 'add', 'width': 32,
                           'args': [constant(0x1210), zero]}
    results = []
    for deadline_ms in (1000, -1):
        acc = admission._Acc()
        budget = admission._Budget.start(admission.AdmissionLimits(deadline_ms=deadline_ms))
        admission._admit_site(acc, budget, caller, 0, block, state,
                              {callee.entry_linear: callee}, [])
        results.append(acc)
    assert not results[0].refusals, results[0].refusals
    assert not results[1].refusals, results[1].refusals
    assert results[1].sites[0].status is admission.SiteStatus.RESOLVED
