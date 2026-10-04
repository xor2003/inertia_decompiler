"""Unpatched real16 region consumer records finite-cover rotation evidence."""
import pytest
from test_real16_region_proof import _document

from tools.dosunit.proof_contracts import ProofStatus
from tools.dosunit.real16_region_proof import compare_real16_regions
from tools.dosunit.region_pairing import RegionFormation


@pytest.mark.parametrize('candidate,proved', [
    ('eb078d5f01678d49ffe302ebf5c3', True),
    ('eb078d5f02678d49ffe302ebf5c3', False),
    ('eb078d5f01678d4901e302ebf5c3', False),
    ('eb078d5f01678d49ff678d5201e302ebf1c3', False),
])
def test_rotated_unpatched_consumer(tmp_path, candidate, proved):
    original = 'e3098d5f01678d49ffebf5c3'
    docs = [_document(tmp_path, bytes.fromhex(code), tag)
            for code, tag in [(original, 'original'), (candidate, 'candidate')]]
    result = compare_real16_regions(*docs, 'demo.exe:loop', timeout_ms=30000)
    assert (result.status is ProofStatus.PROVED) is proved, result
    assert result.graph_evidence is not None, result
    assert result.graph_evidence.formation is RegionFormation.COVER
    assert result.graph_evidence.rejected_partition is not None
    assert result.graph_evidence.oracle_occurrences > result.graph_evidence.oracle_blocks
