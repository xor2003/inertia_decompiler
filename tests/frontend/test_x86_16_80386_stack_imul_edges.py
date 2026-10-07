"""Verify 80386 IMUL and 32-bit stack edges against hardware records."""

from __future__ import annotations

import gzip
import runpy
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import pytest

from inertia.frontend.x86_16.verification_80386 import verify_straightline_case_80386

REPO_ROOT = Path(__file__).resolve().parents[2]
MOO_ROOT = REPO_ROOT / "borrow" / "80386" / "v1_ex_real_mode"
MOO_PARSER = REPO_ROOT / "borrow" / "80286" / "tools" / "moo2json.py"


def _first_hardware_case(opcode: str) -> dict[str, Any]:
    """Load the first authoritative real-mode hardware case for *opcode*."""
    parser_globals = runpy.run_path(str(MOO_PARSER))
    parse_moo_bytes = cast(
        Callable[[bytes], tuple[str, list[dict[str, Any]]]],
        parser_globals["parse_moo_bytes"],
    )
    with gzip.open(MOO_ROOT / f"{opcode}.MOO.gz", "rb") as moo_file:
        _, cases = parse_moo_bytes(moo_file.read())
    return cases[0]


def _first_hardware_case_named(opcode: str, name: str, *, index: int | None = None) -> dict[str, Any]:
    """Load the first authoritative hardware case with the requested disassembly."""
    parser_globals = runpy.run_path(str(MOO_PARSER))
    parse_moo_bytes = cast(
        Callable[[bytes], tuple[str, list[dict[str, Any]]]],
        parser_globals["parse_moo_bytes"],
    )
    root = MOO_ROOT if (MOO_ROOT / f"{opcode}.MOO.gz").exists() else REPO_ROOT / "borrow" / "80286" / "v1_real_mode"
    with gzip.open(root / f"{opcode}.MOO.gz", "rb") as moo_file:
        _, cases = parse_moo_bytes(moo_file.read())
    return next(case for case in cases if case["name"] == name and (index is None or case["idx"] == index))


@pytest.mark.parametrize("opcode", ("660FAF", "6660", "6661"))
def test_80386_imul_pushad_popad_match_hardware(opcode: str) -> None:
    """Match IMUL, PUSHAD, and POPAD register/memory effects to hardware."""
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


@pytest.mark.parametrize("opcode", ("0FB6", "670FB6"))
def test_80386_movzx_r16_rm8_matches_hardware(opcode: str) -> None:
    """Zero-extend an 8-bit source across the complete 16-bit destination."""
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


@pytest.mark.parametrize(
    "opcode",
    (
        "0FA3",
        "0FAB",
        "0FB3",
        "0FBA.5",
        "0FBA.6",
        "0FBA.7",
        "0FBC",
        "0FBD",
        "660FA3",
        "660FAB",
        "660FB3",
        "660FBA.5",
        "660FBA.7",
        "660FBC",
        "660FBD",
        "F7.4",
        "67F7.4",
    ),
)
def test_80386_defined_bit_and_multiply_flags_match_hardware(opcode: str) -> None:
    """Compare only architecturally defined flags while preserving all data effects."""
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


@pytest.mark.parametrize("opcode", ("6691", "6692", "6693", "6694", "6695", "6696", "6697"))
def test_80386_xchg_eax_embedded_register_matches_hardware(opcode: str) -> None:
    """Decode the exchanged 32-bit register from opcode bits 0 through 2."""
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


def test_80386_mov_r32_segment_zero_extends_hardware_selector() -> None:
    """Write a segment selector across the complete 32-bit register destination."""
    opcode = "668C"
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


@pytest.mark.parametrize("opcode", ("98", "6698"))
def test_80386_cbw_and_cwde_operand_size_matches_hardware(opcode: str) -> None:
    """Select CBW or CWDE from the actual operand-size override prefix."""
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


@pytest.mark.parametrize("opcode", ("668D", "678D"))
def test_80386_lea_cross_width_effective_offset_matches_hardware(opcode: str) -> None:
    """Convert the address-sized effective offset to the LEA destination width."""
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


@pytest.mark.parametrize(
    "opcode",
    ("6631", "6633", "6635", "6681.6", "6683.6", "676631", "676633", "676681.6", "676683.6"),
)
def test_80386_standalone_xor_materializes_architectural_flags(opcode: str) -> None:
    """Keep standalone XOR EFLAGS even when typed condition evidence is recorded."""
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


@pytest.mark.parametrize("opcode", ("6681.2", "6683.2", "676681.2", "676683.2"))
def test_80386_adc_uses_wide_carry_out(opcode: str) -> None:
    """Compute 32-bit ADC carry in a 64-bit intermediate."""
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


@pytest.mark.parametrize(
    "opcode",
    (
        "660FA5",
        "660FAC",
        "66C1.2",
        "66C1.3",
            "66C1.4",
            "66C1.6",
        "66D1.4",
        "66D1.6",
        "66D3.2",
        "66D3.3",
            "66D3.4",
            "66D3.6",
        "67660FA4",
        "67660FA5",
        "6766C1.2",
        "6766D1.4",
        "6766D1.6",
        "6766D3.4",
        "67C1.2",
        "C0.0",
        "C0.1",
        "67D0.4",
        "67D0.6",
        "67D1.4",
        "67D1.6",
        "67D2.3",
        "67D3.2",
        "67D3.4",
        "C0.4",
        "C1.2",
        "C1.3",
        "C1.4",
        "C1.6",
        "D0.4",
        "D0.6",
        "D1.4",
        "D1.6",
        "D2.0",
        "D2.1",
        "D2.3",
        "D2.4",
        "D2.6",
        "D3.2",
        "D3.3",
        "D3.4",
        "D3.6",
    ),
)
def test_80386_shift_rotate_defined_flags_match_hardware(opcode: str) -> None:
    """Compare count-dependent defined flags and all shift/rotate data effects."""
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


@pytest.mark.parametrize(("opcode", "name"), (("D1.4", "shl dx,1"), ("D1.6", "sal dx,1")))
def test_80286_register_shift_by_one_materializes_hardware_flags(opcode: str, name: str) -> None:
    """Do not use the flag-eliding simple lift when shift flags remain observable."""
    result = verify_straightline_case_80386(_first_hardware_case_named(opcode, name), opcode=opcode)
    assert result.passed, result


@pytest.mark.parametrize(("opcode", "name"), (("C0.0", "rol bl,B0h"), ("C0.1", "ror bl,B0h")))
def test_80386_byte_full_rotation_updates_hardware_carry(opcode: str, name: str) -> None:
    """Retain the nonzero masked count when deriving carry for a full byte rotation."""
    result = verify_straightline_case_80386(_first_hardware_case_named(opcode, name), opcode=opcode)
    assert result.passed, result


@pytest.mark.parametrize(
    ("opcode", "name"),
    (("C0.2", "rcl byte [ds:di],BCh"), ("C0.3", "rcr bh,73h")),
)
def test_80386_multibit_rotate_ignores_undefined_overflow(opcode: str, name: str) -> None:
    """Exclude OF for encoded multibit rotates even when their effective count is one."""
    result = verify_straightline_case_80386(_first_hardware_case_named(opcode, name), opcode=opcode)
    assert result.passed, result


@pytest.mark.parametrize(("opcode", "name"), (("C0.2", "rcl bh,C1h"), ("C0.3", "rcr bh,C1h")))
def test_80386_rotate_through_carry_masks_count_for_defined_overflow(opcode: str, name: str) -> None:
    """Update OF when the five-bit-masked rotate-through-carry count is one."""
    result = verify_straightline_case_80386(_first_hardware_case_named(opcode, name), opcode=opcode)
    assert result.passed, result


def test_80386_verifier_executes_instruction_above_first_memory_page() -> None:
    """Execute an instruction whose hardware EIP lies above the first 4 KiB page."""
    opcode = "C0.2"
    case = _first_hardware_case_named(opcode, "rcl byte [ss:bp-5Bh],48h")
    result = verify_straightline_case_80386(case, opcode=opcode)
    assert result.passed, result


def test_80386_verifier_executes_instruction_in_reserved_top_page() -> None:
    """Mirror execution out of angr's reserved top-address extern region."""
    opcode = "C0.2"
    case = deepcopy(_first_hardware_case_named(opcode, "rcl byte [ss:bp-5Bh],48h"))
    case["initial"]["regs"]["eip"] = 0xFE08
    case["final"]["regs"]["eip"] = 0xFE0D
    result = verify_straightline_case_80386(case, opcode=opcode)
    assert result.passed, result


def test_80386_real_mode_iret_forces_reserved_flags_bit_one() -> None:
    """Restore an interrupt frame while forcing architectural FLAGS bit one."""
    opcode = "CF"
    case = _first_hardware_case_named(opcode, "iret", index=1)
    result = verify_straightline_case_80386(case, opcode=opcode)
    assert result.passed, result


@pytest.mark.parametrize(
    ("index", "name"),
    (
        (1, "o32 enter 372h,34h"),
        (56, "o32 enter 9E75h,F0h"),
        (75, "o32 enter 3F5Ah,31h"),
    ),
)
def test_80386_real_mode_enter32_uses_16bit_stack_addresses(index: int, name: str) -> None:
    """Copy ENTER frames through SS:BP, including cross-page dword accesses."""
    opcode = "66C8"
    case = _first_hardware_case_named(opcode, name, index=index)
    result = verify_straightline_case_80386(case, opcode=opcode)
    assert result.passed, result


@pytest.mark.parametrize("opcode", ("0FA4", "0FAD", "660FA4", "660FAD"))
def test_80386_double_shift_defined_flags_match_hardware(opcode: str) -> None:
    """Derive SHLD/SHRD result flags from the combined destination and source value."""
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


@pytest.mark.parametrize("opcode", ("66C1.7", "66D3.7", "6766C1.7", "6766D3.7"))
def test_80386_sar32_data_and_defined_flags_match_hardware(opcode: str) -> None:
    """Use arithmetic right shift and materialize defined flags for 32-bit SAR."""
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


@pytest.mark.parametrize("opcode", ("676C", "676E", "67A4", "67AA"))
def test_80386_address32_string_indices_and_repeat_counter_match_hardware(opcode: str) -> None:
    """Select ESI, EDI, and ECX for address32 byte-string execution."""
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


@pytest.mark.parametrize("opcode", ("67E2", "7B"))
def test_80386_short_control_flow_size_and_parity_match_hardware(opcode: str) -> None:
    """Use full prefixed size for LOOP and a one-bit parity-clear JNP condition."""
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


@pytest.mark.parametrize("opcode", ("66F7.4", "66F7.5", "6766F7.4", "6766F7.5"))
def test_80386_one_operand_multiply_wide_result_matches_hardware(opcode: str) -> None:
    """Compute the complete 64-bit EDX:EAX result for one-operand MUL and IMUL."""
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


@pytest.mark.parametrize("opcode", ("670FBA.7", "67660FBA.7"))
def test_80386_disp32_only_sib_uses_ds_for_bit_operation(opcode: str) -> None:
    """Use DS for a disp32-only SIB base while applying the immediate bit index."""
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


def test_80386_address32_bit_string_sign_extends_register_index() -> None:
    """Sign-extend a negative 16-bit bit-string index into the 32-bit address."""
    opcode = "670FA3"
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


def test_80386_aad_compares_only_architecturally_defined_flags() -> None:
    """Compare AAD parity, sign, and zero flags while ignoring undefined flags."""
    opcode = "D5"
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


def test_80386_hlt_preserves_retired_hardware_eip() -> None:
    """Keep the first HLT's retired EIP instead of removing a sentinel byte."""
    opcode = "F4"
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


def test_80386_pushfd_clears_non_pushed_upper_flags() -> None:
    """Push a zero-extended FLAGS image rather than reserved upper EFLAGS bits."""
    opcode = "669C"
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


def test_80386_iretd_pops_dword_interrupt_frame() -> None:
    """Pop EIP, CS, and EFLAGS as a twelve-byte operand32 frame."""
    opcode = "66CF"
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


def test_80386_iret_jumps_to_restored_ip_offset() -> None:
    """Use the restored IP as the architectural target without linearizing CS:IP."""
    opcode = "CF"
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


def test_80386_bound_out_of_range_matches_hardware_fault() -> None:
    """Match the selected BOUND exit and hardware vector-5 exception frame."""
    opcode = "6662"
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


@pytest.mark.parametrize("opcode", ("CC", "CD"))
def test_80386_software_interrupt_matches_hardware_ivt_entry(opcode: str) -> None:
    """Match INT3/INT synthetic exits and hardware IVT return frames."""
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


@pytest.mark.parametrize("opcode", ("39", "6639"))
def test_80386_address16_segment_limit_matches_hardware_fault(opcode: str) -> None:
    """Match word and dword accesses crossing the address16 segment limit."""
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


@pytest.mark.parametrize("opcode", ("F6.7", "67F6.7", "F7.7", "66F7.7", "6766F7.7"))
def test_80386_signed_division_widths_match_hardware(opcode: str) -> None:
    """Compare signed quotient and remainder data while ignoring undefined flags."""
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


@pytest.mark.parametrize("opcode", ("F7.6", "67F7.6", "66F7.6", "6766F7.6"))
def test_80386_unsigned_division_overflow_matches_hardware_fault(opcode: str) -> None:
    """Prove quotient overflow and the corresponding hardware vector-0 entry."""
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


@pytest.mark.parametrize(
    ("opcode", "index", "name"),
    (
        ("F7.6", 1, "div di"),
        ("67F7.6", 1, "div di"),
        ("66F7.6", 6, "div esi"),
        ("6766F7.6", 10, "div edi"),
    ),
)
def test_80386_successful_register_division_uses_normal_execution(
    opcode: str, index: int, name: str
) -> None:
    """Do not classify successful register DIV cases as vector-0 faults."""
    case = _first_hardware_case_named(opcode, name, index=index)
    result = verify_straightline_case_80386(case, opcode=opcode)
    assert result.passed, result


@pytest.mark.parametrize(
    ("opcode", "name"),
    (
        ("F7.6", "div word [ds:bx+11Dh]"),
        ("66F7.6", "div dword [ds:bx+11Dh]"),
        ("67F7.6", "div word [ds:ecx-3323h]"),
    ),
)
def test_80386_memory_division_error_matches_hardware_frame(opcode: str, name: str) -> None:
    """Validate explicit vector-0 witnesses for memory-divisor overflow."""
    case = _first_hardware_case_named(opcode, name, index=118)
    result = verify_straightline_case_80386(case, opcode=opcode)
    assert result.passed, result


def test_80386_repe_cmps_stops_on_first_unequal_byte() -> None:
    """Stop REPE CMPS when ZF clears instead of exhausting ECX."""
    opcode = "A6"
    case = _first_hardware_case_named(opcode, "repe cmpsb", index=9)
    result = verify_straightline_case_80386(case, opcode=opcode)
    assert result.passed, result


def test_80386_repe_cmps_stops_before_unreached_segment_limit() -> None:
    """Do not infer a later segment fault after REPE has already terminated."""
    opcode = "A7"
    case = _first_hardware_case_named(opcode, "repe cmpsw", index=58)
    result = verify_straightline_case_80386(case, opcode=opcode)
    assert result.passed, result


def test_80386_operand32_segment_pops_match_hardware() -> None:
    """Verify four-byte stack consumption and 16-bit selector writes for POP Sreg."""
    for opcode in ("6607", "660FA1", "660FA9"):
        result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
        assert result.passed, result


def test_80386_prefixed_stack_and_short_control_flow_match_hardware() -> None:
    """Keep width-prefixed stack, frame, branch, and loop semantics on the typed path."""
    for opcode in ("666A", "667B", "66C8", "66C9", "66E2", "6766E2"):
        result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
        assert result.passed, result


def test_80386_address32_segment_limit_fault_matches_hardware() -> None:
    """Prove the overflowing offset and corresponding hardware vector-13 entry."""
    for opcode in ("6718", "671B", "67661B", "676681.3", "6781.3", "67668E"):
        result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
        assert result.passed, result


def test_80386_invalid_lock_encodings_match_hardware_faults() -> None:
    """Prove invalid LOCK encodings enter hardware interrupt vector 6."""
    opcodes = (
        "0F9D",
        "0FBA.4",
        "660FBA.4",
        "6668",
        "66D1.0",
        "670F9D",
        "670FBA.4",
        "67660FBA.4",
        "676683.7",
        "6766D1.2",
        "6783.7",
        "67C0.3",
        "67D1.2",
        "68",
        "A0",
        "D1.0",
    )
    for opcode in opcodes:
        result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
        assert result.passed, result


@pytest.mark.parametrize("opcode", ("8F", "668F", "678F", "67668F"))
def test_80386_reserved_pop_extensions_match_hardware_faults(opcode: str) -> None:
    """Prove reserved 8F ModR/M extensions enter hardware interrupt vector 6."""
    result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
    assert result.passed, result


def test_80386_operand32_relative_control_flow_matches_hardware() -> None:
    """Use architectural EIP, decoded size, and symbolic flag composition for rel32 branches."""
    opcodes = ("660F80", "660F81", "660F82", "660F83", "660F86", "660F88", "660F89", "660F8B", "66E9")
    for opcode in opcodes:
        result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
        assert result.passed, result


def test_80386_operand32_far_pointer_loads_match_hardware() -> None:
    """Resolve segment, base, index, and displacement before loading 16:32 pointers."""
    opcodes = (
        "660FB2",
        "660FB4",
        "660FB5",
        "66C4",
        "66C5",
        "67660FB2",
        "67660FB4",
        "67660FB5",
        "6766C4",
        "6766C5",
    )
    for opcode in opcodes:
        result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
        assert result.passed, result


def test_80386_operand32_near_and_far_returns_match_hardware() -> None:
    """Restore dword offsets, word selectors, wrapped SP, and explicit return edges."""
    for opcode in ("66C2", "66C3", "66CA", "66CB"):
        result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
        assert result.passed, result


def test_80386_near_and_far_calls_and_jumps_match_hardware() -> None:
    """Preserve offset EIP, segmented CS, return widths, and decoded return addresses."""
    for opcode in ("669A", "66E8", "66E9", "66EA", "9A", "EA", "FF.3", "FF.5"):
        result = verify_straightline_case_80386(_first_hardware_case(opcode), opcode=opcode)
        assert result.passed, result
