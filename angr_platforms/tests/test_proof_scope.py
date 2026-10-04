"""Proof scope controls prevent unreachable cutpoint SAT promotion."""
import pytest

from tools.dosunit.proof_contracts import ProofStatus
from tools.dosunit.proof_scope import ProofScope, admit_scope_status


@pytest.mark.parametrize('status', list(ProofStatus))
def test_complete_scope_preserves_status(status):
    assert admit_scope_status(status, ProofScope.COMPLETE_FUNCTION) is status

@pytest.mark.parametrize('status', list(ProofStatus))
def test_cutpoint_scope_only_refuses_counterexample(status):
    expected=ProofStatus.UNKNOWN if status is ProofStatus.COUNTEREXAMPLE else status
    assert admit_scope_status(status, ProofScope.CUTPOINT_SIMULATION) is expected
