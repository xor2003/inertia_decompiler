"""Unpatched flat32 consumers retain progress and full shared-guard effects."""
import pytest
from tools.dosunit.tests.test_flat32_comparator_lane import _compare_loops, _driver_lane

from tools.dosunit.contracts.proof_contracts import ProofStatus, proof_status_from_legacy
from tools.dosunit.compare.region_pairing import RegionFormation

ORIGINAL = 'e3088d5b018d49ffebf6c3'

@pytest.mark.parametrize('name', ['msc8', 'bc5'])
@pytest.mark.parametrize('candidate,proved', [
    ('eb068d5b018d49ffe302ebf6c3', True),
    ('eb068d5b028d49ffe302ebf6c3', False),
    ('eb068d5b018d4901e302ebf6c3', False),
    ('eb068d5b018d49ff8d5201e302ebf3c3', False),
    ('eb068d5b018d49ff8903e302ebf4c3', False),
])
def test_rotated_unpatched_consumer(name, candidate, proved):
    with _driver_lane(name) as lane:
        result = _compare_loops(lane, ORIGINAL, candidate, timeout_ms=30000,
                                outputs=tuple(reg for reg, width in lane.adapter.REG32.values()))
        assert (proof_status_from_legacy(result['status']) is ProofStatus.PROVED) is proved, result
        assert result['graph_evidence']['formation'] == RegionFormation.COVER
        assert result['graph_evidence']['oracle_occurrences'] > result['graph_evidence']['oracle_blocks']
