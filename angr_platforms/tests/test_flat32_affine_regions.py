"""Real-i386 affine register controls use the EBX base addressing encoding."""
import pytest
from test_flat32_comparator_lane import _compare_loops, _driver_lane

from tools.dosunit.proof_contracts import ProofStatus, proof_status_from_legacy

ORIGINAL='e3058d5b01e2fbc3'
CANDIDATE='8d5b07e3058d5b01e2fb8d5bf9c3'
@pytest.mark.parametrize('name',['msc8','bc5'])
@pytest.mark.parametrize('code,proved',[
    (ORIGINAL,True),(CANDIDATE,True),
    ('8d5b07e3058d5b01e2fb8d5bf8c3',False),
    ('8d5b07e3058d5b02e2fb8d5bf9c3',False),
    ('8d5b07e3058d5b01e1fb8d5bf9c3',False),
    ('8d5b07e3058d5b01e2fb8d5bf9c20400',False),
])
def test_affine_loop(name,code,proved):
    with _driver_lane(name) as lane:
        result=_compare_loops(lane,ORIGINAL,code,timeout_ms=20000,
                              outputs=tuple(reg for reg,width in lane.adapter.REG32.values()))
        assert (proof_status_from_legacy(result['status']) is ProofStatus.PROVED) is proved,result
        if code==CANDIDATE:
            assert result['register_relation'][0]['offset']==7
            assert result['register_relation'][0]['multiplier']==1
            assert len(result['relation_attempts'])==2
            assert result['counters']['failure_count']==0


@pytest.mark.parametrize('name', ['msc8', 'bc5'])
@pytest.mark.parametrize('candidate,proved', [
    ('538d5c5b07e3058d5b03e2fb5bc3', True),
    ('538d5c5b07e3058d5b03e2fb5ac3', False),
    ('538d5c5b07e3058d5b03e1fb5bc3', False),
])
def test_scaled_recurrence(name, candidate, proved):
    original = '53e3058d5b01e2fb5bc3'
    with _driver_lane(name) as lane:
        result = _compare_loops(lane, original, candidate, timeout_ms=30000,
                                outputs=tuple(reg for reg, width in lane.adapter.REG32.values()))
        assert (proof_status_from_legacy(result['status']) is ProofStatus.PROVED) is proved, result
        if proved:
            assert result['register_relation'][0]['multiplier'] == 3
            assert result['register_relation'][0]['offset'] == 7
            assert result['counters']['failure_count'] == 0

