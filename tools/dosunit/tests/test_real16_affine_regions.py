"""Actual binary modular additive region proofs and mutation controls."""
import pytest
from tools.dosunit.tests.test_real16_binary_compare import _compare, _exe, _verdict
from tools.dosunit.tests.test_real16_region_proof import _document

from tools.dosunit.contracts.proof_contracts import ProofStatus
from tools.dosunit.compare.real16_region_proof import compare_real16_regions
from tools.dosunit.contracts.register_affine_relations import RegisterAffineRelation

ORIGINAL='e3058d5f01e2fbc3'
CANDIDATE='8d5f07e3058d5f01e2fb8d5ff9c3'
@pytest.mark.parametrize('code,proved',[
    (ORIGINAL,True),(CANDIDATE,True),
    ('8d5f07e3058d5f01e2fb8d5ff8c3',False),
    ('8d5f07e3058d5f02e2fb8d5ff9c3',False),
    ('8d5f07e3058d5f01e1fb8d5ff9c3',False),
    ('8d5f07e3058d5f01e2fb8d5ff9c20200',False),
])
def test_affine_loop(tmp_path,code,proved):
    docs=[_document(tmp_path,bytes.fromhex(code),tag) for code,tag in [(ORIGINAL,'original'),(code,'candidate')]]
    proof=compare_real16_regions(*docs,'demo.exe:loop',timeout_ms=20000)
    assert (proof.status is ProofStatus.PROVED) is proved,proof
    if code==CANDIDATE:
        assert isinstance(proof.relation,RegisterAffineRelation)
        assert proof.relation.bindings[0].offset==7
        assert len(proof.attempts)==2
        assert proof.attempts[0].status is ProofStatus.UNKNOWN
        assert proof.counters.failure_count==0


@pytest.mark.parametrize('candidate,proved', [
    ('53678d5c5b07e3058d5f03e2fb5bc3', True),
    ('53678d5c5b07e3058d5f03e2fb5ac3', False),
    ('53678d5c5b07e3058d5f03e1fb5bc3', False),
])
def test_scaled_recurrence_with_address_override(tmp_path, candidate, proved):
    # BX is saved identically, related by 3*x+7 inside the loop, then restored.
    # The address override forms EBX from independently live high/low halves.
    original = '53e3058d5f01e2fb5bc3'
    docs = [_document(tmp_path, bytes.fromhex(code), tag)
            for code, tag in [(original, 'original'), (candidate, 'candidate')]]
    proof = compare_real16_regions(*docs, 'demo.exe:loop', timeout_ms=30000)
    assert (proof.status is ProofStatus.PROVED) is proved, proof
    if proved:
        assert isinstance(proof.relation, RegisterAffineRelation)
        assert proof.relation.bindings[0].multiplier == 3
        assert proof.relation.bindings[0].offset == 7
        assert proof.counters.failure_count == 0


@pytest.mark.parametrize('original,candidate,proved', [
    (ORIGINAL, CANDIDATE, True),
    ('53e3058d5f01e2fb5bc3', '53678d5c5b07e3058d5f03e2fb5bc3', True),
    ('53e3058d5f01e2fb5bc3', '53678d5c5b07e3058d5f03e2fb5ac3', False),
])
def test_public_affine_binary_pair(tmp_path, original, candidate, proved):
    left, left_catalog = _exe(tmp_path, 'public-original', original, len(bytes.fromhex(original)))
    right, right_catalog = _exe(tmp_path, 'public-candidate', candidate, len(bytes.fromhex(candidate)))
    report = _compare(left, right, left_catalog, right_catalog)
    # Keep the missing obligation visible instead of truncating the entire
    # binary/SSA report in pytest's assertion output.
    assert (ProofStatus(_verdict(report)['status']) is ProofStatus.PROVED) is proved, _verdict(report)
