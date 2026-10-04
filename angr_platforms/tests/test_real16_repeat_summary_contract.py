"""Binary-backed REP summary admission and complete control-state regressions."""

from pathlib import Path

import pytest
from test_dosunit_tool import _edge_catalog, _mz_exe

from tools.dosunit import straightline_ssa as S
from tools.dosunit.real16_binary_compare import compare_binary16
from tools.dosunit.repeat_string_contracts import (
    RepeatArchitecture,
    StringFamily,
    decode_repeat_summary,
    is_repeat_string_instruction,
)


def _instruction(code: str, display: str = "rep stosw") -> dict:
    return {"bytes": code, "size": len(bytes.fromhex(code)), "mnemonic": display,
            "disassembly": display, "address": {"linear": "0x1200"}}


def test_instruction_bytes_own_repeat_semantics() -> None:
    spec = decode_repeat_summary([_instruction("f3a4", "rep stosw")])
    assert spec is not None
    assert spec.family is StringFamily.MOVE
    assert decode_repeat_summary([_instruction("90", "rep stosw")]) is None
    assert not is_repeat_string_instruction(_instruction("90", "rep stosw"))


@pytest.mark.parametrize("architecture,width", [
    (RepeatArchitecture.REAL16, 2), (RepeatArchitecture.FLAT32, 4),
])
def test_repeat_operand_defaults_are_architecture_bound(architecture: RepeatArchitecture, width: int) -> None:
    spec = decode_repeat_summary([_instruction("f3a5", "untrusted label")], architecture=architecture)
    assert spec is not None
    assert spec.family is StringFamily.MOVE
    assert spec.width == width
    assert spec.architecture is architecture
    assert decode_repeat_summary([_instruction("66f3a5")], architecture=architecture) is None
    assert decode_repeat_summary([_instruction("67f3a5")], architecture=architecture) is None


@pytest.mark.parametrize("code", ["66f3ab", "67f3a4", "64f3a4", "f3ac"])
def test_unmodeled_repeat_forms_keep_native_ir(code: str) -> None:
    instruction = _instruction(code)
    assert is_repeat_string_instruction(instruction)
    assert decode_repeat_summary([instruction]) is None
    assert S._lower_repeat_string_summary([instruction], output_regs=("cx", "di"),
                                         max_assignments_per_function=0) is None


def test_repeat_summary_cannot_discard_leading_instruction() -> None:
    instructions = [_instruction("b90200", "mov cx, 2"), _instruction("f3ab")]
    assert decode_repeat_summary(instructions) is None
    assert S._lower_repeat_string_summary(instructions, output_regs=("cx", "di"),
                                         max_assignments_per_function=0) is None


def test_repeat_summary_requires_decoded_bytes() -> None:
    instruction = _instruction("f3ab")
    del instruction["bytes"]
    assert decode_repeat_summary([instruction]) is None


def test_repeat_summary_retains_modeled_direction_dependency() -> None:
    summary = S._lower_repeat_string_summary([_instruction("f3ab")], output_regs=("cx", "di"),
                                            max_assignments_per_function=0)
    assert summary is not None
    assert {"name": "dflag", "width": 32} in summary["inputs"]


def test_repeat_summary_keeps_full_loaded_control_and_state(tmp_path: Path) -> None:
    image = bytearray(0x10400)
    image[0x10200:0x10203] = bytes.fromhex("f3abc3")
    exe = tmp_path / "high_repeat.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:fill", "fill", offset=0x200, size=3)
    entry = catalog["functions"][0]["entry"]
    entry["segment_para"] = "0x1000"
    entry["linear"] = "0x10200"
    doc = S.lower_straightline_ssa_document(exe_path=exe, functions_catalog=catalog,
                                          output_regs=S.INTERNAL_STATE_REGS, max_blocks_per_function=4)
    assert doc["refusals"] == []
    block = doc["functions"][0]
    assert block["summary"]["family"] == "stos"
    assert set(S.INTERNAL_STATE_REGS) <= set(block["outputs"])
    assert block["outputs"]["control_ip"] == {"op": "const", "width": 32, "value": "0x11202"}
    assert block["outputs"]["ip"] == {"op": "const", "width": 16, "value": "0x1202"}
    assert "memory" in block["outputs"]


def _guest_store_result(code: bytes) -> bytes:
    from unicorn import UC_ARCH_X86, UC_MODE_16, Uc
    from unicorn.x86_const import UC_X86_REG_AX, UC_X86_REG_CS, UC_X86_REG_CX, UC_X86_REG_DI, UC_X86_REG_ES

    guest = Uc(UC_ARCH_X86, UC_MODE_16)
    guest.mem_map(0, 0x100000)
    guest.reg_write(UC_X86_REG_CS, 0x100)
    guest.reg_write(UC_X86_REG_ES, 0x300)
    guest.reg_write(UC_X86_REG_DI, 0x20)
    guest.reg_write(UC_X86_REG_AX, 0x1234)
    guest.reg_write(UC_X86_REG_CX, 2)
    guest.mem_write(0x3020, bytes.fromhex("a5a5a5a5"))
    guest.mem_write(0x1200, code)
    guest.emu_start(0x1200, 0x1202, count=100)
    assert guest.reg_read(UC_X86_REG_CX) == 0
    return bytes(guest.mem_read(0x3020, 4))


@pytest.mark.parametrize("mutate_width", [False, True])
def test_public_repeat_proof_and_independent_width_mutation(tmp_path: Path, mutate_width: bool) -> None:
    oracle_code = bytes.fromhex("f3abc3")
    candidate_code = bytes.fromhex("f3aac3") if mutate_width else oracle_code
    paths = []
    for name, code in (("oracle", oracle_code), ("candidate", candidate_code)):
        image = bytearray(0x240)
        image[0x200:0x203] = code
        path = tmp_path / f"{name}.exe"
        path.write_bytes(_mz_exe(bytes(image)))
        paths.append(path)
    catalog = _edge_catalog("demo.exe:fill", "fill", offset=0x200, size=3)
    report = compare_binary16(*paths, catalog, catalog, selected=["fill"], solver_timeout_ms=2000,
                              max_function_ms=15000)
    assert report["proof"]["obligations"]["required"] == 1
    assert report["proof"]["obligations"]["attempted"] == 1
    assert _guest_store_result(oracle_code) == bytes.fromhex("34123412")
    if mutate_width:
        assert _guest_store_result(candidate_code) == bytes.fromhex("3434a5a5")
        assert report["status"] == "unknown"
        assert report["proof"]["obligations"]["discharged"] == 0
    else:
        assert _guest_store_result(candidate_code) == bytes.fromhex("34123412")
        assert report["status"] == "proved"
        assert report["proof"]["obligations"]["discharged"] == 1
