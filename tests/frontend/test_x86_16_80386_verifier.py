"""Hardware-state verification for 80386 real-mode instruction semantics."""

from pathlib import Path

import pytest

from inertia.frontend.x86_16.verification_80286 import load_moo_cases
from inertia.frontend.x86_16.verification_80386 import verify_straightline_case_80386


def _moo(opcode: str) -> Path:
    """Return one 80386 real-mode hardware corpus path."""
    return Path(f"borrow/80386/v1_ex_real_mode/{opcode}.MOO.gz")


def test_borrow_80386_parser_preserves_32_bit_hardware_state() -> None:
    """The hardware oracle must retain 80386 registers instead of decode-only bytes."""
    cpu_name, cases = load_moo_cases(_moo("66B8"))

    assert cpu_name == "386E"
    initial_regs = cases[0]["initial"]["regs"]
    final_regs = cases[0]["final"]["regs"]
    assert {"eax", "eip", "eflags", "fs", "gs", "cr0", "cr3"} <= initial_regs.keys()
    assert {"eax", "eip"} <= final_regs.keys()


@pytest.mark.parametrize(
    "opcode,case_index",
    (
        ("660FB6", 19),
        ("660FB6", 35),
        ("660FB6", 48),
        ("660FB6", 6),
        ("660FB7", 0),
        ("660FB7", 275),
        ("660FB7", 532),
        ("660FB7", 4),
        ("660FBE", 58),
        ("660FBE", 131),
        ("660FBE", 65),
        ("660FBE", 24),
        ("660FBF", 25),
        ("660FBF", 339),
        ("660FBF", 523),
        ("660FBF", 51),
    ),
)
def test_80386_movx_matches_hardware_edge_state(opcode: str, case_index: int) -> None:
    """MOVZX/MOVSX must replace all destination bits at signed and unsigned boundaries."""
    _cpu_name, cases = load_moo_cases(_moo(opcode))
    result = verify_straightline_case_80386(cases[case_index], opcode=opcode)

    assert result.passed, result.error or result.mismatches


@pytest.mark.parametrize("case_index", (28, 55, 177, 44))
def test_80386_cwde_matches_hardware_edge_state(case_index: int) -> None:
    """CWDE must replace EAX with the signed extension of AX at boundary values."""
    _cpu_name, cases = load_moo_cases(_moo("6698"))
    result = verify_straightline_case_80386(cases[case_index], opcode="6698")

    assert result.passed, result.error or result.mismatches


def test_80386_xchg_preserves_effective_address_when_index_register_changes() -> None:
    """XCHG must store through the pre-exchange address when ESI contributes SI."""
    _cpu_name, cases = load_moo_cases(_moo("6687"))
    result = verify_straightline_case_80386(cases[22], opcode="6687")

    assert result.passed, result.error or result.mismatches


def test_80386_locked_btc_compares_only_defined_flags() -> None:
    """LOCK must not hide BTC's architecturally undefined non-carry flags."""
    _cpu_name, cases = load_moo_cases(_moo("67660FBB"))
    result = verify_straightline_case_80386(cases[145], opcode="67660FBB")

    assert result.passed, result.error or result.mismatches


@pytest.mark.parametrize("opcode", tuple(f"0F{value:02X}" for value in range(0x90, 0xA0)))
def test_80386_setcc_matches_hardware_state(opcode: str) -> None:
    """Every SETcc predicate must write one complete byte to register or memory destinations."""
    _cpu_name, cases = load_moo_cases(_moo(opcode))
    case_index = 1 if opcode == "0F9D" else 0  # Case zero has an invalid LOCK prefix.
    result = verify_straightline_case_80386(cases[case_index], opcode=opcode)

    assert result.passed, result.error or result.mismatches
