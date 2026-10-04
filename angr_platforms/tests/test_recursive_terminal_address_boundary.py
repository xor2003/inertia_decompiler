"""Actual MZ recursion must reject terminal coordinates outside physical scope."""
from pathlib import Path

import pytest
from recursive_proof_fixtures.terminal_boundary_inputs import (
    make_terminal_inside_inputs,
    make_terminal_wrap_inputs,
)

from tools.dosunit.proof_contracts import ProofStatus
from tools.dosunit.recursive_proofs.real16_image_bound_domain import prove_image_bound_real16_domain
from tools.dosunit.recursive_proofs.real16_image_bound_joint_proof import check_image_bound_real16_joint
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointModelRequirement


@pytest.mark.parametrize("wrap", [False, True])
def test_terminal_address_scope_from_actual_recursive_mz(tmp_path: Path, wrap: bool) -> None:
    """Nearby positive and wrapped terminal share genuine recursive code bytes."""
    inputs = (make_terminal_wrap_inputs if wrap else make_terminal_inside_inputs)(tmp_path)
    receipt = prove_image_bound_real16_domain(*inputs)
    assert receipt.status is ProofStatus.PROVED
    proof = check_image_bound_real16_joint(receipt, *inputs)
    assert proof.address_model is not None
    assert proof.address_model.terminal_addresses == ((0x100000,) * 2 if wrap else (0xFFFFF,) * 2), (
        proof.reason, proof.detail, proof.address_model)
    assert proof.address_model.complete is (not wrap)
    assert proof.status is (ProofStatus.UNKNOWN if wrap else ProofStatus.CONDITIONAL)
    assert not proof.binary_equivalence_proved
    assert (JointModelRequirement.FAULT_DOMAIN in proof.remaining) is wrap
    if not wrap:
        assert proof.outcomes is not None and proof.outcomes.synchronous_closed
    assert JointModelRequirement.ENVIRONMENT in proof.remaining
    assert (JointModelRequirement.ADDRESS_MODEL in proof.remaining) is wrap
