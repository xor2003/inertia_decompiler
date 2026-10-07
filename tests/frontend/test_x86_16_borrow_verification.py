"""Tests for exhaustive borrowed real-mode case classification.

Layer: Frontend tests.
Responsibility: prove defined, pyvex-proven, and undefined cases are disjoint.
"""

from __future__ import annotations

from inertia.frontend.x86_16.borrow_verification import BorrowCaseDisposition, classify_borrow_case
from inertia.frontend.x86_16.verification_80286 import REAL_MODE_FLAGS_MASK, _case_flags_mask


def _case(
    code: bytes,
    *,
    ecx: int = 0,
    exception: int | None = None,
    name: str = "instruction",
) -> dict[str, object]:
    case: dict[str, object] = {"bytes": [*code, 0xF4], "initial": {"regs": {"ecx": ecx}}, "name": name}
    if exception is not None:
        case["exception"] = {"number": exception}
    return case


def test_80286_symbolically_compared_opcode_is_pyvex_proven() -> None:
    classification = classify_borrow_case("80286", "AA", _case(b"\xaa"))
    assert classification.disposition is BorrowCaseDisposition.PYVEX_PROVEN


def test_80286_unproved_opcode_requires_hardware() -> None:
    classification = classify_borrow_case("80286", "00", _case(b"\x00\x00"))
    assert classification.disposition is BorrowCaseDisposition.HARDWARE_REQUIRED


def test_80386_defined_double_shift_requires_hardware() -> None:
    classification = classify_borrow_case("80386", "660FA4", _case(b"\x66\x0f\xa4\xc0\x20"))
    assert classification.disposition is BorrowCaseDisposition.HARDWARE_REQUIRED


def test_80386_undefined_double_shift_is_excluded() -> None:
    classification = classify_borrow_case("80386", "0FA4", _case(b"\x0f\xa4\xc0\x1f"))
    assert classification.disposition is BorrowCaseDisposition.UNDEFINED_EXCLUDED


def test_80386_cl_double_shift_uses_masked_count() -> None:
    classification = classify_borrow_case("80386", "0FA5", _case(b"\x0f\xa5\xc0", ecx=0x31))
    assert classification.disposition is BorrowCaseDisposition.UNDEFINED_EXCLUDED


def test_salc_remains_in_practical_hardware_verification_scope() -> None:
    classification = classify_borrow_case("80286", "D6", _case(b"\xd6"))
    assert classification.disposition is BorrowCaseDisposition.HARDWARE_REQUIRED


def test_x87_is_explicitly_outside_current_scope() -> None:
    classification = classify_borrow_case("80386", "D8.0", _case(b"\xd8\xc0"))
    assert classification.disposition is BorrowCaseDisposition.OUT_OF_SCOPE_EXCLUDED


def test_divide_error_remains_in_practical_hardware_verification_scope() -> None:
    classification = classify_borrow_case("80386", "F7.6", _case(b"\xf7\xf0", exception=0))
    assert classification.disposition is BorrowCaseDisposition.HARDWARE_REQUIRED


def test_non_divide_fault_is_outside_practical_scope() -> None:
    classification = classify_borrow_case("80386", "62", _case(b"\x62\x00", exception=5))
    assert classification.disposition is BorrowCaseDisposition.OUT_OF_SCOPE_EXCLUDED


def test_known_386e_sib_trace_is_an_oracle_defect() -> None:
    classification = classify_borrow_case("80386", "6783.3", _case(b"\x67\x83\x5c\x24\x4d\x2a"))
    assert classification.disposition is BorrowCaseDisposition.ORACLE_DEFECT_EXCLUDED


def test_386e_div_suppressed_scaled_sib_index_is_an_oracle_defect() -> None:
    classification = classify_borrow_case("80386", "67F7.6", _case(b"\x67\xf7\x34\xa2"))
    assert classification.disposition is BorrowCaseDisposition.ORACLE_DEFECT_EXCLUDED


def test_386e_div_real_sib_index_remains_hardware_required() -> None:
    classification = classify_borrow_case("80386", "67F7.6", _case(b"\x67\xf7\x34\x82"))
    assert classification.disposition is BorrowCaseDisposition.HARDWARE_REQUIRED


def test_invalid_lock_form_is_outside_practical_scope() -> None:
    classification = classify_borrow_case("80286", "5C", _case(b"\xf0\x5c", name="lock pop sp"))
    assert classification.disposition is BorrowCaseDisposition.OUT_OF_SCOPE_EXCLUDED


def test_valid_lock_memory_rmw_remains_in_scope() -> None:
    classification = classify_borrow_case(
        "80286",
        "01",
        _case(b"\xf0\x01\x00", name="lock add [ds:bx+si],ax"),
    )
    assert classification.disposition is BorrowCaseDisposition.HARDWARE_REQUIRED


def test_duplicate_segment_override_group_is_undefined() -> None:
    classification = classify_borrow_case("80286", "A1", _case(b"\x3e\x26\xa1\x00\x10"))
    assert classification.disposition is BorrowCaseDisposition.UNDEFINED_EXCLUDED


def test_distinct_prefix_groups_remain_hardware_required() -> None:
    classification = classify_borrow_case("80386", "66A1", _case(b"\x26\x66\xa1\x00\x10"))
    assert classification.disposition is BorrowCaseDisposition.HARDWARE_REQUIRED


def test_nested_enter_with_self_overlapping_frame_chain_is_out_of_scope() -> None:
    case = _case(b"\xc8\x01\xe4\xd6")
    case["initial"]["regs"].update({"bp": 0xFFFF, "sp": 0xFFFF})

    classification = classify_borrow_case("80286", "C8", case)

    assert classification.disposition is BorrowCaseDisposition.OUT_OF_SCOPE_EXCLUDED
    assert "overlaps" in classification.reason


def test_nested_enter_with_distinct_frame_and_stack_remains_hardware_required() -> None:
    case = _case(b"\xc8\x10\x00\x02")
    case["initial"]["regs"].update({"bp": 0x1000, "sp": 0x2000})

    classification = classify_borrow_case("80286", "C8", case)

    assert classification.disposition is BorrowCaseDisposition.HARDWARE_REQUIRED


def test_far_pointer_crossing_segment_end_is_out_of_scope() -> None:
    case = _case(b"\xff\x19")
    case["initial"]["regs"].update({"bx": 0xFFFF, "di": 0xFFFF})

    classification = classify_borrow_case("80286", "FF.3", case)

    assert classification.disposition is BorrowCaseDisposition.OUT_OF_SCOPE_EXCLUDED
    assert "far-pointer" in classification.reason


def test_far_pointer_contained_in_segment_remains_hardware_required() -> None:
    case = _case(b"\xff\x19")
    case["initial"]["regs"].update({"bx": 0x1000, "di": 0x0020})

    classification = classify_borrow_case("80286", "FF.3", case)

    assert classification.disposition is BorrowCaseDisposition.HARDWARE_REQUIRED


def test_80286_sal_extension_masks_undefined_adjust_flag() -> None:
    case = {"bytes": [0xD1, 0xF0, 0xF4], "initial": {"regs": {"cx": 0}}}
    assert _case_flags_mask("D1.6", case) == REAL_MODE_FLAGS_MASK & ~0x0010


def test_80286_immediate_shift_masks_overflow_unless_count_is_one() -> None:
    case = {"bytes": [0xC1, 0xE0, 0x04, 0xF4], "initial": {"regs": {"cx": 0}}}
    assert _case_flags_mask("C1.4", case) == REAL_MODE_FLAGS_MASK & ~0x0810
def test_suppressed_sib_index_oracle_defect_includes_address32_xchg16() -> None:
    """386E must not treat SIB index field 100 as ESP in address-size-32 XCHG."""
    case = {"bytes": [0x67, 0x87, 0x6C, 0xA4, 0xFE]}

    classification = classify_borrow_case("80386", "6787", case)

    assert classification.disposition is BorrowCaseDisposition.ORACLE_DEFECT_EXCLUDED


def test_suppressed_sib_index_oracle_defect_includes_group2_rotates() -> None:
    """386E must not duplicate a Group-2 SIB base through suppressed index 100."""
    case = {"bytes": [0x67, 0xC0, 0x5C, 0x60, 0x84, 0xB7]}

    classification = classify_borrow_case("80386", "67C0.3", case)

    assert classification.disposition is BorrowCaseDisposition.ORACLE_DEFECT_EXCLUDED


def test_suppressed_sib_index_oracle_defect_includes_byte_idiv() -> None:
    """386E must not scale a suppressed SIB index for address-size-32 byte IDIV."""
    case = {"bytes": [0x67, 0xF6, 0x3C, 0xA2]}

    classification = classify_borrow_case("80386", "67F6.7", case)

    assert classification.disposition is BorrowCaseDisposition.ORACLE_DEFECT_EXCLUDED


def test_missing_idiv8_overflow_fault_is_an_oracle_defect() -> None:
    """A normal-result trace cannot witness an overflowing signed-byte divide."""
    case = {
        "bytes": [0xF6, 0xF9],
        "initial": {"regs": {"eax": 0x648C, "ecx": 0xB7}},
        "exception": None,
    }

    classification = classify_borrow_case("80386", "F6.7", case)

    assert classification.disposition is BorrowCaseDisposition.ORACLE_DEFECT_EXCLUDED


def test_suppressed_sib_index_oracle_defect_includes_two_byte_btc() -> None:
    """386E must not materialize SIB index 100 for two-byte BT-family opcodes."""
    case = {"bytes": [0x67, 0x66, 0x0F, 0xBB, 0x3C, 0xE6]}

    classification = classify_borrow_case("80386", "67660FBB", case)

    assert classification.disposition is BorrowCaseDisposition.ORACLE_DEFECT_EXCLUDED


def test_suppressed_sib_index_oracle_defect_includes_immediate_bt_family() -> None:
    """386E must not materialize SIB index 100 for immediate BT-family opcodes."""
    case = {"bytes": [0x67, 0x0F, 0xBA, 0x34, 0xE6, 0xFF]}

    classification = classify_borrow_case("80386", "670FBA.6", case)

    assert classification.disposition is BorrowCaseDisposition.ORACLE_DEFECT_EXCLUDED
