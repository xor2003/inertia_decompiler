from __future__ import annotations

from inertia.structuring.compare32_recovery import (
    Instruction8616,
    Operand8616,
    _function_instructions_8616,
    recover_32bit_compare_c_from_instructions_8616,
)


def _reg(name: str) -> Operand8616:
    return Operand8616("reg", name, 2)


def _bp(disp: int) -> Operand8616:
    return Operand8616("bp_mem", disp, 2)


def _imm(value: int) -> Operand8616:
    return Operand8616("imm", value, 2)


def _insn(mnemonic: str, op0: Operand8616, op1: Operand8616 | None = None) -> Instruction8616:
    return Instruction8616(0, mnemonic, op0, op1 or Operand8616(None, None, None))


def test_recover_signed_32bit_constant_compare_from_high_low_word_evidence():
    insns = [
        _insn("mov", _reg("ax"), _bp(4)),
        _insn("mov", _reg("dx"), _bp(6)),
        _insn("cmp", _bp(10), _reg("dx")),
        _insn("jge", Operand8616(None, None)),
        _insn("cmp", _bp(8), _reg("ax")),
        _insn("ja", Operand8616(None, None)),
        _insn("mov", _reg("ax"), _imm(0xFFFF)),
        _insn("mov", _reg("ax"), _imm(1)),
        _insn("mov", _reg("ax"), _imm(0)),
        _insn("mov", _reg("ax"), _imm(2)),
    ]

    recovered = recover_32bit_compare_c_from_instructions_8616(insns, function_name="compare_signed")

    assert recovered is not None
    assert "int compare_signed(long a, long b)" in recovered
    assert "if (a < b)" in recovered
    assert "return -1;" in recovered


def test_recover_unsigned_32bit_constant_compare_from_unsigned_jcc_evidence():
    insns = [
        _insn("mov", _reg("ax"), _bp(8)),
        _insn("mov", _reg("dx"), _bp(10)),
        _insn("cmp", _bp(6), _reg("dx")),
        _insn("jbe", Operand8616(None, None)),
        _insn("cmp", _bp(4), _reg("ax")),
        _insn("jb", Operand8616(None, None)),
        _insn("mov", _reg("ax"), _imm(0xFFFF)),
        _insn("mov", _reg("ax"), _imm(1)),
        _insn("mov", _reg("ax"), _imm(0)),
        _insn("mov", _reg("ax"), _imm(2)),
    ]

    recovered = recover_32bit_compare_c_from_instructions_8616(insns, function_name="compare_unsigned")

    assert recovered is not None
    assert "int compare_unsigned(unsigned long a, unsigned long b)" in recovered


def test_recover_32bit_compare_refuses_without_low_word_compare_evidence():
    insns = [
        _insn("mov", _reg("ax"), _bp(4)),
        _insn("mov", _reg("dx"), _bp(6)),
        _insn("cmp", _bp(10), _reg("dx")),
        _insn("jge", Operand8616(None, None)),
        _insn("mov", _reg("ax"), _imm(0xFFFF)),
        _insn("mov", _reg("ax"), _imm(1)),
        _insn("mov", _reg("ax"), _imm(0)),
        _insn("mov", _reg("ax"), _imm(2)),
    ]

    assert recover_32bit_compare_c_from_instructions_8616(insns, function_name="bad") is None


def test_function_instructions_collects_compare_evidence_across_function_blocks():
    block_insns = {
        0x1000: [
            _insn("mov", _reg("ax"), _bp(4)),
            _insn("mov", _reg("dx"), _bp(6)),
            _insn("cmp", _bp(10), _reg("dx")),
            _insn("jle", Operand8616(None, None)),
        ],
        0x1010: [
            _insn("cmp", _bp(8), _reg("ax")),
            _insn("jbe", Operand8616(None, None)),
        ],
        0x1020: [
            _insn("mov", _reg("ax"), _bp(4)),
            _insn("mov", _reg("dx"), _bp(6)),
        ],
        0x1030: [
            _insn("mov", _reg("ax"), _bp(8)),
            _insn("mov", _reg("dx"), _bp(10)),
        ],
    }

    class _CapstoneInsn:
        def __init__(self, insn: Instruction8616) -> None:
            self.insn = insn

    class _Factory:
        def block(self, addr: int) -> object:
            return type(
                "Block",
                (),
                {"capstone": type("Capstone", (), {"insns": [_CapstoneInsn(insn) for insn in block_insns[addr]]})()},
            )()

    project = type("Project", (), {"factory": _Factory()})()
    function = type("Function", (), {"addr": 0x1000, "block_addrs_set": set(block_insns)})()

    recovered = recover_32bit_compare_c_from_instructions_8616(
        _function_instructions_8616(project, function),
        function_name="select_max",
    )

    assert recovered is not None
    assert "long select_max(long a, long b)" in recovered
