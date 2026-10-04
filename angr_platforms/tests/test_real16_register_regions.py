"""Actual-MZ relational induction and mutation controls in the shared tree."""
import pytest
from test_real16_region_proof import _document

from tools.dosunit.proof_contracts import ProofStatus
from tools.dosunit.real16_region_proof import RegionObligation, compare_real16_regions

ORIGINAL = '85c074034875fdc3'
CANDIDATE = '9185c974034975fd91c3'

@pytest.mark.parametrize('code,proved', [
    (ORIGINAL, True), (CANDIDATE, True),
    ('9185c974034975fdc3', False),
    ('9185c974034175fd91c3', False),
    ('9185c975034975fd91c3', False),
    ('9185c974034975fd91c20200', False),
])
def test_register_loop(tmp_path, code, proved):
    docs=(_document(tmp_path,bytes.fromhex(ORIGINAL),'original'),
          _document(tmp_path,bytes.fromhex(code),'candidate'))
    result=compare_real16_regions(*docs,'demo.exe:loop',timeout_ms=20000)
    assert (result.status is ProofStatus.PROVED) is proved, result
    if code == CANDIDATE:
        assert not result.relation.is_identity
        assert len(result.attempts) == 2
        assert result.attempts[0].status is ProofStatus.UNKNOWN
        assert result.counters.failure_count == 0
        # This register permutation needs no memory invariant. Require every
        # state-relation obligation and preserve the exact absence of optional
        # invariant obligations rather than conflating them with all enum values.
        assert {item for row in result.transitions for item in row.obligations} == {
            RegionObligation.INITIATION, RegionObligation.PRESERVATION, RegionObligation.EXIT,
        }
