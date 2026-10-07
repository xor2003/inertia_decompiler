"""Focused real16 direct-call composition regressions on actual MZ bytes.

Each fixture lowers real machine code to fresh full-state SSA documents
(``output_regs`` covering ``INTERNAL_STATE_REGS``) and exercises
``compare_real16_with_calls`` only; no public wrappers are involved.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).resolve().parent))

import tools.dosunit.compare.straightline_ssa as S
from tools.dosunit.compare.real16_call_composition import (
    compare_real16_with_calls,
)
from tools.dosunit.tests.test_dosunit_tool import _edge_function, _mz_exe


def _lower(
    tmp_path: Path, image: bytes, functions: list[dict[str, object]], tag: str,
    *, relocs: tuple[tuple[int, int], ...] = (),
) -> dict:
    exe = tmp_path / f"{tag}.exe"
    exe.write_bytes(_mz_exe(image, relocs=relocs))
    catalog = {
        "schema": "dosunit.functions.v1",
        "id": "functions:test",
        "module": "demo.exe",
        "program_kind": "mz_exe",
        "functions": functions,
        "diagnostics": [],
    }
    return S.lower_straightline_ssa_document(
        exe_path=exe,
        functions_catalog=catalog,
        output_regs=tuple(S.INTERNAL_STATE_REGS),
        max_blocks_per_function=32,
        follow_call_fallthrough=True,
    )


# Caller @0x200: mov dx,imm16 ; call 0x0230 (rel 0x002a) ; ret
def _caller_bytes(dx_imm: int = 1, call_rel: int = 0x002A) -> bytes:
    body = bytes(
        [0xBA, dx_imm & 0xFF, (dx_imm >> 8) & 0xFF, 0xE8, call_rel & 0xFF, (call_rel >> 8) & 0xFF, 0xC3]
    )
    image = bytearray(0x300)
    image[0x200 : 0x200 + len(body)] = body
    image[0x230:0x233] = bytes.fromhex("89d0c3")  # callee: mov ax,dx; ret
    return bytes(image)


def _caller_catalog(size: int = 7) -> list[dict[str, object]]:
    return [
        _edge_function("demo.exe:caller", "caller", offset=0x200, size=size),
        _edge_function("demo.exe:callee", "callee", offset=0x230, size=3),
    ]


def test_identical_caller_callee_passes(tmp_path: Path) -> None:
    image = _caller_bytes()
    oracle = _lower(tmp_path, image, _caller_catalog(), "oracle")
    candidate = _lower(tmp_path, image, _caller_catalog(), "candidate")
    result = compare_real16_with_calls(oracle, candidate, "demo.exe:caller", timeout_ms=20000)
    assert result["status"] == "passed", result
    assert result["calls"]["inlined_calls"] >= 2  # oracle + candidate sides
    assert result["calls"]["return_targets_proved"] >= 2


def test_self_document_passes(tmp_path: Path) -> None:
    doc = _lower(tmp_path, _caller_bytes(), _caller_catalog(), "self")
    result = compare_real16_with_calls(doc, doc, "demo.exe:caller", timeout_ms=20000)
    assert result["status"] == "passed", result


def test_unreachable_invalid_catalog_body_does_not_refuse_caller(tmp_path: Path) -> None:
    image = bytearray(_caller_bytes())
    image[0x260:0x263] = bytes.fromhex("f7f3c3")  # div bx; ret
    catalog = [*_caller_catalog(),
        _edge_function("demo.exe:unused", "unused", offset=0x260, size=3),
    ]
    doc = _lower(tmp_path, bytes(image), catalog, "unused")
    result = compare_real16_with_calls(doc, doc, "demo.exe:caller", timeout_ms=20000)
    assert result["status"] == "passed", result
    assert {item["function"] for item in result["dependencies"][0]["callees"]} == {"demo.exe:callee"}


def test_reachable_invalid_callee_still_refuses(tmp_path: Path) -> None:
    image = bytearray(_caller_bytes())
    image[0x230:0x233] = bytes.fromhex("f7f3c3")  # div bx; ret
    doc = _lower(tmp_path, bytes(image), _caller_catalog(), "invalid_callee")
    result = compare_real16_with_calls(doc, doc, "demo.exe:caller", timeout_ms=20000)
    assert result["status"] == "refused", result
    assert result["reason"] == "unsupported_return_control", result


def test_saved_return_jump_callee_proves_actual_continuation(tmp_path: Path) -> None:
    image = bytearray(_caller_bytes())
    image[0x230:0x233] = bytes.fromhex("59ffe1")  # pop cx; jmp cx
    doc = _lower(tmp_path, bytes(image), _caller_catalog(), "jump_return")
    result = compare_real16_with_calls(doc, doc, "demo.exe:caller", timeout_ms=20000)
    assert result["status"] == "passed", result
    assert result["calls"]["return_targets_proved"] == 2


def test_unsaved_indirect_callee_exit_still_refuses(tmp_path: Path) -> None:
    image = bytearray(_caller_bytes())
    image[0x230:0x233] = bytes.fromhex("59ffe0")  # pop cx; jmp ax
    doc = _lower(tmp_path, bytes(image), _caller_catalog(), "wrong_jump_return")
    result = compare_real16_with_calls(doc, doc, "demo.exe:caller", timeout_ms=20000)
    assert result["status"] == "refused", result
    assert result["reason"] == "return_target_unproved", result


def test_root_indirect_exit_requires_its_own_return_evidence(tmp_path: Path) -> None:
    image = bytearray(_caller_bytes())
    image[0x230:0x233] = bytes.fromhex("59ffe1")
    doc = _lower(tmp_path, bytes(image), _caller_catalog(), "root_jump")
    result = compare_real16_with_calls(doc, doc, "demo.exe:callee", timeout_ms=20000)
    assert result["status"] == "refused", result
    assert result["reason"] == "unsupported_control_transfer", result


@pytest.mark.parametrize("corrupt_upper_target", [False, True])
def test_dword_saved_return_jump_keeps_upper_control_bits(tmp_path: Path, corrupt_upper_target: bool) -> None:
    image = bytearray(_caller_bytes())
    image[0x200:0x20A] = bytes.fromhex("ba010066e827000000c3")
    callee = bytes.fromhex("665966ffe1")
    if corrupt_upper_target:
        callee = bytes.fromhex("66596681c90000010066ffe1")  # set EIP bit16
    image[0x230:0x230 + len(callee)] = callee
    catalog = _caller_catalog(size=10)
    catalog[1] = _edge_function("demo.exe:callee", "callee", offset=0x230, size=len(callee))
    doc = _lower(tmp_path, bytes(image), catalog, "dword_jump_return")
    result = compare_real16_with_calls(doc, doc, "demo.exe:caller", timeout_ms=20000)
    if corrupt_upper_target:
        assert result["status"] == "refused", result
        assert result["reason"] == "return_target_unproved", result
    else:
        assert result["status"] == "passed", result
        assert result["calls"]["return_targets_proved"] == 2


@pytest.mark.parametrize("width", [16, 32])
@pytest.mark.parametrize("loader_domain", [False, True])
@pytest.mark.parametrize("operation", ["call", "jump"])
def test_indirect_near_control_coordinates_match_independent_guest(
    width: int, loader_domain: bool, operation: str,
) -> None:
    """Indirect near control consumes an offset and projects its execution domain."""
    from types import SimpleNamespace

    from inertia.frontend.x86_16.control_coordinates import ControlAddressDomain
    from inertia.frontend.x86_16.regs import reg16_t, sgreg_t
    from unicorn import UC_ARCH_X86, UC_MODE_16, Uc
    from unicorn.x86_const import UC_X86_REG_CS, UC_X86_REG_ECX, UC_X86_REG_EIP, UC_X86_REG_SP, UC_X86_REG_SS

    from inertia.frontend.x86_16.instr16 import Instr16
    from inertia.frontend.x86_16.instr32 import Instr32
    from tests.frontend.test_x86_16_stack_helpers import _StackEmu

    guest = Uc(UC_ARCH_X86, UC_MODE_16)
    guest.mem_map(0, 0x100000)
    guest.reg_write(UC_X86_REG_CS, 0x1234)
    guest.reg_write(UC_X86_REG_ECX, 0x0200)
    guest.reg_write(UC_X86_REG_SS, 0x2000)
    guest.reg_write(UC_X86_REG_SP, 0x1000)
    linear = (0x1234 << 4) + 0x0100
    code = bytes.fromhex("ffd1" if operation == "call" else "ffe1")
    if width == 32:
        code = b"\x66" + code
    guest.mem_write(linear, code)
    guest.emu_start(linear, 0x100000, count=1)
    expected_offset = guest.reg_read(UC_X86_REG_EIP)
    assert expected_offset == 0x0200

    emu = _StackEmu()
    emu.control_address_domain = (ControlAddressDomain.LOADER_LINEAR if loader_domain
                                  else ControlAddressDomain.ARCHITECTURAL_OFFSET)
    emu.lifter_instruction.addr = linear if loader_domain else 0x0100
    instruction = SimpleNamespace(get_rm16=lambda: 0x0200, get_rm32=lambda: 0x0200,
                                  instr=SimpleNamespace(size=len(code)),
                                  _active_stack_emulator=lambda: emu)
    if operation == "call" and width == 16:
        Instr16.call_rm16(instruction)
    elif operation == "call":
        Instr32.call_rm32(instruction)
    elif width == 16:
        Instr16.jmp_rm16(instruction)
    else:
        Instr32.jmp_rm32(instruction)
    assert emu.irsb.next == expected_offset + ((0x1234 << 4) if loader_domain else 0)
    assert emu.get_gpreg(reg16_t.SP) == guest.reg_read(UC_X86_REG_SP)
    if operation == "call":
        stack_offset = 0x1000 - width // 8
        saved = int.from_bytes(guest.mem_read((0x2000 << 4) + stack_offset, width // 8), "little")
        assert saved == 0x0100 + len(code)
        assert emu.memory[(sgreg_t.SS, stack_offset)] == saved


def test_dx_argument_mutation_fails(tmp_path: Path) -> None:
    oracle = _lower(tmp_path, _caller_bytes(dx_imm=1), _caller_catalog(), "oracle")
    candidate = _lower(tmp_path, _caller_bytes(dx_imm=2), _caller_catalog(), "candidate")
    result = compare_real16_with_calls(oracle, candidate, "demo.exe:caller", timeout_ms=20000)
    assert result["status"] == "failed", result
    kinds = {m.get("kind") for m in result.get("mismatches", [])}
    assert kinds and kinds != {"output_set_changed"}, result["mismatches"]


def test_callee_return_value_mutation_fails(tmp_path: Path) -> None:
    # oracle callee: mov ax,dx; ret  vs  candidate callee: mov ax,2; ret
    # (caller writes dx=1, so ax=2 is a genuine semantic difference)
    oracle = _lower(tmp_path, _caller_bytes(), _caller_catalog(), "oracle")
    cand = bytearray(_caller_bytes())
    cand[0x230:0x234] = bytes.fromhex("b80200c3")
    cand_image = bytes(cand)
    cand_catalog = _caller_catalog()
    cand_catalog[1] = _edge_function("demo.exe:callee", "callee", offset=0x230, size=4)
    candidate = _lower(tmp_path, cand_image, cand_catalog, "candidate")
    result = compare_real16_with_calls(oracle, candidate, "demo.exe:caller", timeout_ms=20000)
    assert result["status"] == "failed", result


def test_callee_store_mutation_fails(tmp_path: Path) -> None:
    # callee stores ax to ss:[bp-4] vs ss:[bp-6] — ss-relative scratch writes
    # stay provably disjoint from the ret-load slot at the callee entry sp.
    # oracle:  push bp; mov bp,sp; mov [bp-4],ax; pop bp; ret
    # cand:    push bp; mov bp,sp; mov [bp-6],ax; pop bp; ret
    oracle_image = bytearray(_caller_bytes())
    oracle_image[0x230:0x239] = bytes.fromhex("5589e58946fc5dc3")
    cand_image = bytearray(_caller_bytes())
    cand_image[0x230:0x239] = bytes.fromhex("5589e58946fa5dc3")
    catalog = _caller_catalog()
    catalog[1] = _edge_function("demo.exe:callee", "callee", offset=0x230, size=9)
    oracle = _lower(tmp_path, bytes(oracle_image), catalog, "oracle")
    candidate = _lower(tmp_path, bytes(cand_image), catalog, "candidate")
    result = compare_real16_with_calls(oracle, candidate, "demo.exe:caller", timeout_ms=20000)
    assert result["status"] == "failed", result


def test_callee_arbitrary_data_store_refuses(tmp_path: Path) -> None:
    # callee writes ds:[0x0500]: under symbolic ss/ds the ret-load slot cannot
    # be proven disjoint, so the return-target proof must refuse.
    oracle_image = bytearray(_caller_bytes())
    oracle_image[0x230:0x234] = bytes.fromhex("a30005c3")
    cand_image = bytearray(_caller_bytes())
    cand_image[0x230:0x234] = bytes.fromhex("a30205c3")
    catalog = _caller_catalog()
    catalog[1] = _edge_function("demo.exe:callee", "callee", offset=0x230, size=4)
    oracle = _lower(tmp_path, bytes(oracle_image), catalog, "oracle")
    candidate = _lower(tmp_path, bytes(cand_image), catalog, "candidate")
    result = compare_real16_with_calls(oracle, candidate, "demo.exe:caller", timeout_ms=20000)
    assert result["status"] == "refused"
    assert result["reason"] == "return_target_unproved", result


def test_callee_stack_cleanup_mutation_fails(tmp_path: Path) -> None:
    # oracle callee ret ; candidate callee ret 2 (sp differs)
    cand_image = bytearray(_caller_bytes())
    cand_image[0x230:0x235] = bytes.fromhex("89d0c20200")  # mov ax,dx; ret 2
    oracle = _lower(tmp_path, _caller_bytes(), _caller_catalog(), "oracle")
    cand_catalog = _caller_catalog()
    cand_catalog[1] = _edge_function("demo.exe:callee", "callee", offset=0x230, size=5)
    candidate = _lower(tmp_path, bytes(cand_image), cand_catalog, "candidate")
    result = compare_real16_with_calls(oracle, candidate, "demo.exe:caller", timeout_ms=20000)
    assert result["status"] == "failed", result


def test_nested_near_call_chain_passes(tmp_path: Path) -> None:
    # caller@0x200: mov dx,1; call 0x0230; ret
    # mid@0x230:    mov ax,dx; call 0x0260 (rel = 0x260-0x235 = 0x2b); ret
    # leaf@0x260:   inc ax; ret
    image = bytearray(0x300)
    image[0x200:0x207] = bytes.fromhex("ba0100e82a00c3")
    image[0x230:0x236] = bytes.fromhex("89d0e82b00c3")
    image[0x260:0x262] = bytes.fromhex("40c3")
    catalog = [
        _edge_function("demo.exe:caller", "caller", offset=0x200, size=7),
        _edge_function("demo.exe:mid", "mid", offset=0x230, size=6),
        _edge_function("demo.exe:leaf", "leaf", offset=0x260, size=2),
    ]
    oracle = _lower(tmp_path, bytes(image), catalog, "oracle")
    candidate = _lower(tmp_path, bytes(image), catalog, "candidate")
    result = compare_real16_with_calls(oracle, candidate, "demo.exe:caller", timeout_ms=30000)
    assert result["status"] == "passed", result
    assert result["calls"]["inlined_calls"] >= 4


def test_recursive_call_refuses(tmp_path: Path) -> None:
    # fn@0x200: call 0x200 (rel = 0x200-0x203 = 0xfffd); ret
    image = bytearray(0x300)
    image[0x200:0x204] = bytes.fromhex("e8fdff c3".replace(" ", ""))
    catalog = [_edge_function("demo.exe:fn", "fn", offset=0x200, size=4)]
    doc = _lower(tmp_path, bytes(image), catalog, "doc")
    result = compare_real16_with_calls(doc, doc, "demo.exe:fn", timeout_ms=10000)
    assert result["status"] == "refused"
    assert result["reason"] == "recursive_call_cycle"


def test_missing_callee_mapping_refuses(tmp_path: Path) -> None:
    # caller calls 0x0240 which is not a catalog entry.
    image = bytearray(_caller_bytes(call_rel=0x0037))  # 0x206+0x37 = 0x23d? fix below
    # recompute: call at 0x203, next 0x206; want target 0x240 -> rel 0x003a
    image[0x200:0x207] = bytes.fromhex("ba0100e83a00c3")
    catalog = [_edge_function("demo.exe:caller", "caller", offset=0x200, size=7)]
    doc = _lower(tmp_path, bytes(image), catalog, "doc")
    result = compare_real16_with_calls(doc, doc, "demo.exe:caller", timeout_ms=10000)
    assert result["status"] == "refused"
    assert result["reason"] == "call_target_unmapped"


def test_indirect_call_refuses(tmp_path: Path) -> None:
    # caller@0x200: mov ax,0x0230; call ax; ret
    image = bytearray(0x300)
    image[0x200:0x207] = bytes.fromhex("b83002ffd0c3")
    catalog = [
        _edge_function("demo.exe:caller", "caller", offset=0x200, size=7),
        _edge_function("demo.exe:callee", "callee", offset=0x230, size=3),
    ]
    doc = _lower(tmp_path, bytes(image), catalog, "doc")
    result = compare_real16_with_calls(doc, doc, "demo.exe:caller", timeout_ms=10000)
    assert result["status"] == "refused"
    assert result["reason"] in {
        "call_target_unresolved",
        "unsupported_call",
        "unsupported_control_transfer",
        "call_target_mismatch",
        "successor_outside_region",
        "full_state_outputs_missing",
    }


def test_far_call_refuses(tmp_path: Path) -> None:
    # lcall 0x0000:0x0230 (9a 30 02 00 00); ret
    image = bytearray(0x300)
    image[0x200:0x206] = bytes.fromhex("9a300200 00c3".replace(" ", ""))
    image[0x230:0x233] = bytes.fromhex("89d0c3")
    catalog = [
        _edge_function("demo.exe:caller", "caller", offset=0x200, size=6),
        _edge_function("demo.exe:callee", "callee", offset=0x230, size=3),
    ]
    doc = _lower(tmp_path, bytes(image), catalog, "doc")
    result = compare_real16_with_calls(doc, doc, "demo.exe:caller", timeout_ms=10000)
    assert result["status"] == "refused", result
