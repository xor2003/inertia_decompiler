from __future__ import annotations

import inertia.frontend.x86_16.coverage_manifest as coverage_manifest

from inertia.frontend.x86_16.coverage_manifest import COMPARE_VERIFIED_MOO_OPCODES


def test_coverage_manifest_exports_only_compare_verified_opcodes() -> None:
    assert coverage_manifest.__all__ == ["COMPARE_VERIFIED_MOO_OPCODES"]


def test_compare_verified_moo_opcodes_are_immutable_opcode_tokens() -> None:
    assert isinstance(COMPARE_VERIFIED_MOO_OPCODES, frozenset)
    assert COMPARE_VERIFIED_MOO_OPCODES
    for opcode in COMPARE_VERIFIED_MOO_OPCODES:
        assert opcode == opcode.upper()
        assert opcode.strip() == opcode
        assert ".." not in opcode
        parts = opcode.split(".")
        assert 1 <= len(parts) <= 2
        assert all(part for part in parts)
        assert all(part.isalnum() for part in parts)


def test_compare_verified_moo_opcodes_stay_deterministic() -> None:
    assert tuple(sorted(COMPARE_VERIFIED_MOO_OPCODES)) == (
        "15",
        "1A",
        "27",
        "2F",
        "37",
        "3F",
        "83.3",
        "85",
        "91",
        "98",
        "99",
        "9E",
        "9F",
        "A4",
        "A6",
        "AA",
        "AB",
        "AC",
        "AD",
        "AE",
        "AF",
        "D0.1",
        "D0.7",
        "D1.3",
        "D3.0",
        "D3.1",
        "D3.2",
        "D3.3",
        "D3.4",
        "D3.5",
        "D4",
        "D5",
        "D7",
        "E2",
        "F5",
        "F7.2",
        "F7.3",
        "F7.5",
        "F8",
        "F9",
    )


def test_compare_verified_moo_opcodes_keep_string_instruction_family() -> None:
    assert {"A4", "A6", "AA", "AB", "AC", "AD", "AE", "AF"} <= COMPARE_VERIFIED_MOO_OPCODES
