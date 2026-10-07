"""Binary loop roles must come from guard and write evidence, not term order."""

from dataclasses import replace

import pytest
from inertia.ir.affine_indexed_address import prove_affine_indexed_address_8616
from inertia.ir.affine_induction_role import (
    AffineInductionRoleFailure8616,
    prove_affine_induction_role_8616,
)
from inertia.ir.indexed_address_access_normalization import normalize_indexed_address_accesses_8616
from inertia.ir.ssa_function import build_x86_16_function_ssa
from tests.fixtures.x86_16_logical_memory_fixtures import lift_ir_artifact_with_blocks


def _loop(*, guard_offset: str = "fe", increment_offset: str = "fe",
          initializer: str = "00", base_offset: str = "04", branch: str = "73"):
    binary = bytes.fromhex(
        f"55 89 e5 83 ec 02 c7 46 fe {initializer} 00 "
        f"83 7e {guard_offset} 04 {branch} 0f "
        f"8b 76 fe d1 e6 8b 5e {base_offset} 8b 00 "
        f"ff 46 {increment_offset} eb eb 89 ec 5d c3")
    artifact = build_x86_16_function_ssa(lift_ir_artifact_with_blocks(
        binary, (0x1000, 0x100b, 0x1011, 0x1020),
        ((0x1000, 0x100b), (0x100b, 0x1011), (0x100b, 0x1020), (0x1011, 0x100b))))
    access, = normalize_indexed_address_accesses_8616(artifact).accesses
    return prove_affine_indexed_address_8616(artifact, access)


@pytest.mark.parametrize("branch", ("73", "7d"))
def test_guard_and_latch_select_induction_without_guessing_residual_pointer(branch) -> None:
    address = _loop(branch=branch)
    role = prove_affine_induction_role_8616(address)
    assert role.complete
    assert role.induction is not None
    assert (role.induction.source.offset, role.induction.coefficient) == (-2, 2)
    assert tuple(term.source.offset for term in role.residual_terms) == (4,)
    assert role.stats.materialized_count == 1 and role.stats.failure_count == 0
    assert not replace(role, witness=None).complete
    assert role.witness is not None
    assert not replace(role, witness=replace(role.witness, term_index=0)).complete
    assert not replace(role, stats=replace(role.stats, materialized_count=0)).complete
    assert not replace(role, stats=replace(role.stats, materialized_count=True)).complete
    condition = role.witness.guard.condition
    changed = replace(condition, lhs=replace(condition.lhs, source_tmp=9999))
    assert not replace(role, witness=replace(role.witness, guard=replace(role.witness.guard, condition=changed))).complete


@pytest.mark.parametrize("changes", (
    {"guard_offset": "fc"}, {"increment_offset": "fc"},
    {"initializer": "01"}, {"branch": "74"}, {"base_offset": "fe"},
))
def test_unrelated_guard_or_step_cannot_assign_induction_role(changes) -> None:
    role = prove_affine_induction_role_8616(_loop(**changes))
    assert not role.complete and role.failure is not None
    assert role.induction is None and not role.residual_terms
    assert role.stats.failure_count == 1
    if "base_offset" in changes:
        assert role.failure is AffineInductionRoleFailure8616.ROLE_CONFLICT


def test_unproved_address_cannot_publish_a_role() -> None:
    address = _loop()
    role = prove_affine_induction_role_8616(replace(address, components=()))
    assert role.failure is AffineInductionRoleFailure8616.ADDRESS_UNPROVEN
    assert role.witness is None and role.induction is None


def test_missing_condition_evidence_cannot_select_from_increment_alone() -> None:
    address = _loop()
    address = replace(address, artifact=replace(address.artifact, condition_evidence=None))
    assert address.complete
    role = prove_affine_induction_role_8616(address)
    assert role.failure is AffineInductionRoleFailure8616.ROLE_UNPROVEN
    assert role.witness is None and role.induction is None
