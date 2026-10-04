"""Binary-only far callback code-target proof and explicit refusal controls."""

from __future__ import annotations

from dataclasses import replace

import pytest
from angr_platforms.X86_16.lowering.binary_far_callback_targets import (
    BinaryFarCallbackTargetStatus8616,
    prove_binary_far_callback_target_8616,
)
from angr_platforms.X86_16.lowering.function_pointer_parameter_evidence import (
    FunctionPointerParameterFact8616,
)
from angr_platforms.X86_16.mz_image import UnpackedMZImage

from inertia_decompiler.project_loading import _build_project


@pytest.fixture(scope="module")
def synthetic_mz(tmp_path_factory: pytest.TempPathFactory) -> object:
    """Load two far entries plus near, open, and data controls from one MZ."""
    image = bytearray(0x100)
    image[0:0x0A] = bytes.fromhex("55 8b ec b8 00 00 eb 00 5d cb")
    image[0x1A:0x24] = bytes.fromhex("55 8b ec b8 1a 00 eb 00 5d cb")
    image[0x30:0x35] = bytes.fromhex("55 8b ec 5d c3")
    image[0x40:0x45] = bytes.fromhex("55 8b ec eb 7f")
    image[0x60:0x66] = bytes.fromhex("55 8b ec 74 01 c3")
    path = tmp_path_factory.mktemp("far_callback_target") / "PROOF.EXE"
    path.write_bytes(
        UnpackedMZImage(
            image=bytes(image),
            relocations=(),
            entry_cs=0,
            entry_ip=0,
            stack_ss=0,
            stack_sp=0xFFFE,
        ).to_mz_bytes()
    )
    return _build_project(path, force_blob=False, base_addr=0x1000, entry_point=0)


@pytest.fixture(scope="module")
def far_parameter_fact() -> FunctionPointerParameterFact8616:
    """Supply the callee-owned far-function-pointer ABI, not a guessed C type."""
    return FunctionPointerParameterFact8616(
        stack_offset=6,
        argument_widths=(2,),
        return_width=2,
        callsite_addresses=(0x100A4, 0x100B0),
        pointer_width=4,
    )


@pytest.mark.parametrize("offset", [0, 0x1A])
def test_two_far_targets_prove_exact_binary_identity(
    synthetic_mz: object,
    far_parameter_fact: FunctionPointerParameterFact8616,
    offset: int,
) -> None:
    """Two distinct in-image branches must resolve to their own far symbols."""
    result = prove_binary_far_callback_target_8616(
        synthetic_mz, segment=0x1000, offset=offset, parameter_fact=far_parameter_fact
    )

    assert result.status is BinaryFarCallbackTargetStatus8616.PROVEN
    assert result.proof is not None
    assert result.proof.addr == 0x10000 + offset
    assert result.proof.name == f"sub_{0x10000 + offset:x}"
    assert result.proof.segment == 0x1000
    assert result.proof.offset == offset
    assert result.proof.far_return_addrs == (0x10009 + offset,)
    assert result.proof.decoded_insn_addrs == tuple(
        0x10000 + offset + local_offset for local_offset in (0, 1, 3, 6, 8, 9)
    )
    assert result.complete
    assert (
        result.raw_fact_count,
        result.normalized_fact_count,
        result.classified_fact_count,
        result.materialized_count,
        result.failure_count,
    ) == (1, 1, 1, 1, 0)


def test_synthetic_far_target_proves_and_refuses_near_return(
    synthetic_mz: object, far_parameter_fact: FunctionPointerParameterFact8616
) -> None:
    """A decoded far return is required; ordinary RET cannot close this ABI."""
    valid = prove_binary_far_callback_target_8616(
        synthetic_mz, segment=0x1000, offset=0, parameter_fact=far_parameter_fact
    )
    near = prove_binary_far_callback_target_8616(
        synthetic_mz, segment=0x1000, offset=0x30, parameter_fact=far_parameter_fact
    )

    assert valid.status is BinaryFarCallbackTargetStatus8616.PROVEN
    assert near.status is BinaryFarCallbackTargetStatus8616.NON_FAR_RETURN
    assert near.proof is None
    assert near.complete
    assert near.failure_count == 1


@pytest.mark.parametrize(
    ("segment", "offset", "status"),
    [
        (0x0FFF, 0x10, BinaryFarCallbackTargetStatus8616.INVALID_FAR_ADDRESS),
        (0x1000, 0x10000, BinaryFarCallbackTargetStatus8616.INVALID_FAR_ADDRESS),
        (0x1000, 0x80, BinaryFarCallbackTargetStatus8616.NO_CODE_ENTRY),
        (0x1000, 0x40, BinaryFarCallbackTargetStatus8616.OPEN_DECODE),
        (0x1000, 0x60, BinaryFarCallbackTargetStatus8616.NON_FAR_RETURN),
    ],
)
def test_far_target_refusal_controls(
    synthetic_mz: object,
    far_parameter_fact: FunctionPointerParameterFact8616,
    segment: int,
    offset: int,
    status: BinaryFarCallbackTargetStatus8616,
) -> None:
    """Address aliases, data, open branches, and mixed exits never become code."""
    result = prove_binary_far_callback_target_8616(
        synthetic_mz, segment=segment, offset=offset, parameter_fact=far_parameter_fact
    )

    assert result.status is status
    assert result.proof is None
    assert result.complete
    assert result.raw_fact_count == result.failure_count == 1
    assert result.materialized_count == 0


def test_near_parameter_fact_cannot_type_far_target(
    synthetic_mz: object, far_parameter_fact: FunctionPointerParameterFact8616
) -> None:
    """The same bytes cannot prove a far callback under a near callee ABI."""
    result = prove_binary_far_callback_target_8616(
        synthetic_mz,
        segment=0x1000,
        offset=0,
        parameter_fact=replace(far_parameter_fact, pointer_width=2),
    )

    assert result.status is BinaryFarCallbackTargetStatus8616.INVALID_POINTER_ABI
    assert result.proof is None
    assert result.complete
    assert result.failure_count == 1


def test_complete_rejects_corrupted_counts_and_published_proof(
    synthetic_mz: object, far_parameter_fact: FunctionPointerParameterFact8616
) -> None:
    """A green verdict cannot survive contradictory census or target evidence."""
    valid = prove_binary_far_callback_target_8616(
        synthetic_mz, segment=0x1000, offset=0, parameter_fact=far_parameter_fact
    )
    assert valid.complete
    assert valid.proof is not None
    assert valid.addr is not None
    proof = valid.proof

    corruptions = (
        replace(valid, classified_fact_count=0, materialized_count=0, failure_count=1),
        replace(valid, addr=valid.addr + 1),
        replace(valid, proof=replace(proof, addr=proof.addr + 1)),
        replace(valid, proof=replace(proof, segment=proof.segment + 1)),
        replace(valid, proof=replace(proof, name="sub_ffff")),
        replace(valid, proof=replace(proof, far_return_addrs=())),
        replace(valid, proof=replace(proof, decoded_insn_addrs=(proof.addr,))),
        replace(valid, proof=replace(proof, parameter_fact=replace(far_parameter_fact, pointer_width=2))),
    )
    assert all(not result.complete for result in corruptions)

    refused = prove_binary_far_callback_target_8616(
        synthetic_mz, segment=0x1000, offset=0x30, parameter_fact=far_parameter_fact
    )
    assert refused.complete
    assert not replace(refused, failure_count=0).complete
    assert not replace(refused, addr=proof.addr).complete
