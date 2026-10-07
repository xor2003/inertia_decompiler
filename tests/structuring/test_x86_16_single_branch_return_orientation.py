from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import IRValue, MemSpace

from inertia.structuring.single_branch_return_orientation import (
    SingleBranchReturnOrientation8616,
    classify_cfg_arm_orientation_8616,
    classify_cfg_binary_arm_orientation_8616,
    classify_direct_or_one_hop_target_orientation_8616,
    classify_single_branch_return_orientation_8616,
)


def _condition() -> ConditionIR:
    return ConditionIR(
        op="ne",
        lhs=IRValue(MemSpace.REG, "ax", size=2),
        rhs=IRValue(MemSpace.CONST, const=0, size=2),
        width_bits=16,
        src_insn=0x1002,
        block_addr=0x1000,
        taken_target=0x1010,
        fallthrough_target=0x1004,
    )


def test_return_orientation_accepts_one_taken_owned_match() -> None:
    evidence = classify_single_branch_return_orientation_8616(
        _condition(),
        "value",
        {0x1004: "limit", 0x1010: "value", 0x1020: "value"},
        {},
        lambda lhs, rhs: lhs == rhs,
        lambda _condition, target, _successors: True if target == 0x1010 else None,
    )

    assert evidence.orientation is SingleBranchReturnOrientation8616.TAKEN
    assert evidence.matching_targets == (0x1010, 0x1020)
    assert evidence.taken_owned_targets == (0x1010,)
    assert evidence.ambiguous_targets == (0x1020,)


def test_return_orientation_accepts_one_fallthrough_owned_match() -> None:
    evidence = classify_single_branch_return_orientation_8616(
        _condition(),
        "value",
        {0x1004: "value", 0x1010: "limit"},
        {},
        lambda lhs, rhs: lhs == rhs,
        lambda _condition, target, _successors: False if target == 0x1004 else None,
    )

    assert evidence.orientation is SingleBranchReturnOrientation8616.FALLTHROUGH
    assert evidence.orientation.as_taken_polarity() is False


def test_return_orientation_refuses_conflicting_edge_ownership() -> None:
    evidence = classify_single_branch_return_orientation_8616(
        _condition(),
        "value",
        {0x1004: "value", 0x1010: "value"},
        {},
        lambda lhs, rhs: lhs == rhs,
        lambda _condition, target, _successors: target == 0x1010,
    )

    assert evidence.orientation is SingleBranchReturnOrientation8616.UNKNOWN_REFUSE
    assert evidence.orientation.as_taken_polarity() is None


def test_direct_orientation_selects_unique_one_hop_exit_edge() -> None:
    orientation = classify_direct_or_one_hop_target_orientation_8616(
        _condition(),
        0x1030,
        {
            0x1004: (0x1030,),
            0x1010: (0x1020,),
            0x1020: (0x1030,),
        },
    )

    assert orientation is False


def test_direct_orientation_refuses_shared_immediate_target() -> None:
    orientation = classify_direct_or_one_hop_target_orientation_8616(
        _condition(),
        0x1030,
        {0x1004: (0x1030,), 0x1010: (0x1030,)},
    )

    assert orientation is None


def test_arm_orientation_prefers_exclusive_body_over_shared_suffix() -> None:
    evidence = classify_cfg_arm_orientation_8616(
        _condition(),
        (0x1020, 0x1030),
        {
            0x1004: (0x1030,),
            0x1010: (0x1020,),
            0x1020: (0x1030,),
        },
    )

    assert evidence.orientation is SingleBranchReturnOrientation8616.TAKEN
    assert evidence.exclusive_taken_targets == (0x1020,)
    assert evidence.shared_targets == (0x1030,)


def test_arm_orientation_uses_immediate_edge_for_shared_exit_only() -> None:
    evidence = classify_cfg_arm_orientation_8616(
        _condition(),
        (0x1030,),
        {
            0x1004: (0x1030,),
            0x1010: (0x1020,),
            0x1020: (0x1030,),
        },
    )

    assert evidence.orientation is SingleBranchReturnOrientation8616.FALLTHROUGH
    assert evidence.direct_shared_orientations == (False,)


def test_arm_orientation_refuses_conflicting_exclusive_blocks() -> None:
    evidence = classify_cfg_arm_orientation_8616(
        _condition(),
        (0x1020, 0x1040),
        {0x1004: (0x1040,), 0x1010: (0x1020,)},
    )

    assert evidence.orientation is SingleBranchReturnOrientation8616.UNKNOWN_REFUSE


def test_arm_orientation_refuses_unreachable_tagged_block() -> None:
    evidence = classify_cfg_arm_orientation_8616(
        _condition(),
        (0x1020, 0x9999),
        {0x1004: (0x1030,), 0x1010: (0x1020,)},
    )

    assert evidence.orientation is SingleBranchReturnOrientation8616.UNKNOWN_REFUSE
    assert evidence.exclusive_taken_targets == (0x1020,)
    assert evidence.unreachable_targets == (0x9999,)


def test_binary_arm_orientation_infers_empty_true_arm_from_proven_false_arm() -> None:
    evidence = classify_cfg_binary_arm_orientation_8616(
        _condition(),
        (),
        (0x1030,),
        {
            0x1004: (0x1030,),
            0x1010: (0x1020,),
            0x1020: (0x1040,),
        },
    )

    assert evidence.true_polarity is True
    assert evidence.false_polarity is False
    assert evidence.inferred_empty_arm_count == 1
    assert evidence.is_complementary


def test_binary_arm_orientation_refuses_nonempty_unknown_complement() -> None:
    evidence = classify_cfg_binary_arm_orientation_8616(
        _condition(),
        (0x9999,),
        (0x1030,),
        {0x1004: (0x1030,), 0x1010: (0x1020,)},
    )

    assert evidence.true_polarity is None
    assert evidence.false_polarity is False
    assert evidence.inferred_empty_arm_count == 0
    assert not evidence.is_complementary
