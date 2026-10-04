"""Real binary direct-call proofs through the public real16 entry point."""

from pathlib import Path
from typing import Any

import pytest
from test_dosunit_tool import _edge_function, _mz_exe
from test_real16_call_composition import _caller_bytes, _caller_catalog, _lower

from tools.dosunit.real16_binary_compare import compare_binary16


@pytest.mark.parametrize("candidate_argument,expected", [(1, "proved"), (2, "counterexample")])
def test_public_direct_calls_preserve_whole_caller_obligation(
    tmp_path: Path, candidate_argument: int, expected: str,
) -> None:
    """A complete caller proves and a changed register argument is rejected."""
    oracle, candidate = tmp_path / "oracle.exe", tmp_path / "candidate.exe"
    oracle.write_bytes(_mz_exe(_caller_bytes()))
    candidate.write_bytes(_mz_exe(_caller_bytes(dx_imm=candidate_argument)))
    catalog = {"schema": "dosunit.functions.v1", "id": "functions:test", "module": "demo.exe",
               "program_kind": "mz_exe", "functions": _caller_catalog(), "diagnostics": []}
    report = compare_binary16(oracle, candidate, catalog, catalog, selected=("caller",))
    assert report["status"] == expected, {"proof": report["proof"], "backend": report["backend"]}
    verdict = report["proof"]["verdicts"][0]
    assert verdict["method"] == "ssa_z3_complete_call_inlining"
    calls = report["backend"]["direct_calls"]["demo.exe:caller"]
    assert calls["calls"]["return_targets_proved"] == 2
    assert len(calls["dependencies"]) == 2
    for side in calls["dependencies"]:
        assert side["entry"]["body_size"] == 7
        assert side["callees"][0]["body_size"] == 3
        assert len(side["callees"][0]["body_sha256"]) == 64


def test_saved_call_return_ip_must_use_architectural_coordinates(tmp_path: Path) -> None:
    """Reject a pair equal only when CALL saves loaded linear coordinates."""
    unicorn = pytest.importorskip("unicorn")
    from unicorn import x86_const as registers

    paths: list[Path] = []
    actual_bx: list[int] = []
    for name, leaf in (("original", "5589e58b5e025dc3"), ("candidate", "5589e5bb03125dc3")):
        image = bytearray(0x300)
        image[0x200:0x204] = bytes.fromhex("e82d00c3")
        image[0x230:0x238] = bytes.fromhex(leaf)
        path = tmp_path / (name + ".exe")
        path.write_bytes(_mz_exe(bytes(image)))
        paths.append(path)
        guest = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_16)
        guest.mem_map(0, 0x200000)
        guest.mem_write(0x1000, bytes(image))
        guest.reg_write(registers.UC_X86_REG_CS, 0x100)
        guest.reg_write(registers.UC_X86_REG_SS, 0x300)
        guest.reg_write(registers.UC_X86_REG_SP, 0x1000)
        guest.reg_write(registers.UC_X86_REG_IP, 0x200)
        guest.emu_start(0x1200, 0x1203, count=20)
        actual_bx.append(guest.reg_read(registers.UC_X86_REG_BX))
    assert actual_bx == [0x203, 0x1203]
    catalog = {"schema": "dosunit.functions.v1", "id": "functions:test", "module": "demo.exe",
               "program_kind": "mz_exe", "diagnostics": [], "functions": [
                   _edge_function("demo.exe:caller", "caller", offset=0x200, size=4),
                   _edge_function("demo.exe:callee", "callee", offset=0x230, size=8),
               ]}
    report = compare_binary16(*paths, catalog, catalog, selected=("caller",))
    assert report["status"] != "proved", report["proof"]


@pytest.mark.parametrize("changed_value,expected", [(0x2222, "proved"), (0x2223, "counterexample")])
def test_public_shifted_branchy_callee_preserves_complete_caller(
    tmp_path: Path, changed_value: int, expected: str,
) -> None:
    """Relocation and branch inversion preserve calls only with equal effects."""
    oracle_image = bytearray(0x280)
    candidate_image = bytearray(0x280)
    oracle_image[0x200:0x204] = bytes.fromhex("e80d00c3")
    candidate_image[0x200:0x204] = bytes.fromhex("e82d00c3")
    oracle_body = bytes.fromhex("3d01007404bb2222c3bb1111c3")
    candidate_body = bytes.fromhex("3d01007504bb1111c3bb") + changed_value.to_bytes(2, "little") + b"\xc3"
    oracle_image[0x210:0x210 + len(oracle_body)] = oracle_body
    candidate_image[0x230:0x230 + len(candidate_body)] = candidate_body
    oracle = tmp_path / "oracle.exe"
    candidate = tmp_path / "candidate.exe"
    oracle.write_bytes(_mz_exe(bytes(oracle_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    catalogs = []
    for offset, body in ((0x210, oracle_body), (0x230, candidate_body)):
        catalogs.append({
            "schema": "dosunit.functions.v1", "module": "demo.exe",
            "program_kind": "mz_exe", "diagnostics": [], "functions": [
                _edge_function("demo.exe:caller", "caller", offset=0x200, size=4),
                _edge_function("demo.exe:callee", "callee", offset=offset, size=len(body)),
            ],
        })
    report = compare_binary16(oracle, candidate, *catalogs, selected=("caller",))
    assert report["status"] == expected, report["proof"]
    verdict = report["proof"]["verdicts"][0]
    assert verdict["method"] == "ssa_z3_complete_call_inlining"
    calls = report["backend"]["direct_calls"]["demo.exe:caller"]
    assert calls["calls"]["return_targets_proved"] == 2
    assert len(calls["dependencies"]) == 2


@pytest.mark.parametrize("ax,expected_bx", [(0, 0x2222), (1, 0x1111)])
def test_shifted_branchy_call_native_continuation(ax: int, expected_bx: int) -> None:
    """Both branch arms independently return to the same saved continuation."""
    unicorn = pytest.importorskip("unicorn")
    from unicorn import x86_const as registers

    observations = []
    for displacement, offset, body in (
        (0x0D, 0x210, "3d01007404bb2222c3bb1111c3"),
        (0x2D, 0x230, "3d01007504bb1111c3bb2222c3"),
    ):
        image = bytearray(0x280)
        image[0x200:0x204] = b"\xe8" + displacement.to_bytes(2, "little") + b"\xc3"
        code = bytes.fromhex(body)
        image[offset:offset + len(code)] = code
        guest = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_16)
        guest.mem_map(0, 0x200000)
        guest.mem_write(0x1000, bytes(image))
        for register, value in (
            (registers.UC_X86_REG_CS, 0x100),
            (registers.UC_X86_REG_SS, 0x300),
            (registers.UC_X86_REG_SP, 0x1000),
            (registers.UC_X86_REG_AX, ax),
        ):
            guest.reg_write(register, value)
        guest.emu_start(0x1200, 0x1203, count=20)
        observations.append((
            guest.reg_read(registers.UC_X86_REG_BX),
            guest.reg_read(registers.UC_X86_REG_IP),
            guest.reg_read(registers.UC_X86_REG_SP),
            int.from_bytes(guest.mem_read(0x3FFE, 2), "little"),
        ))
    assert observations == [(expected_bx, 0x203, 0x1000, 0x203)] * 2


def _compare_stack_write_call(
    tmp_path: Path, *, candidate_value: int, wide_address: bool = False,
    candidate_callee_name: str = "callee",
) -> dict[str, Any]:
    """Compare real CALLs with equal continuation and full stack-array effects."""
    from tools.dosunit.real16_call_composition import compare_real16_with_calls

    documents = []
    for side, value, wide in (("oracle", 0x1234, False),
                              ("candidate", candidate_value, wide_address)):
        # disp8 plus NOP and disp16 have the same effective BP-4 address and
        # length. Both CALLs save the same architectural continuation0x20c.
        store = bytes.fromhex("c786fcff" if wide else "c746fc") + value.to_bytes(2, "little")
        if not wide:
            store += b"\x90"
        caller = bytes.fromhex("5589e5") + store + bytes.fromhex("e824005dc3")
        assert len(caller) == 14
        image = bytearray(0x240)
        image[0x200:0x20e] = caller
        image[0x230] = 0xc3
        name = "callee" if side == "oracle" else candidate_callee_name
        catalog = [
            _edge_function("demo.exe:caller", "caller", offset=0x200, size=14),
            _edge_function(f"demo.exe:{name}", name, offset=0x230, size=1),
        ]
        documents.append(_lower(tmp_path, bytes(image), catalog, side))
    result = compare_real16_with_calls(*documents, "demo.exe:caller", timeout_ms=20000)
    assert result["calls"]["return_targets_proved"] == 2, result
    assert len(result["dependencies"]) == 2, result
    return result


@pytest.mark.parametrize("callee_name", ["rebuilt_helper", "_rebuilt_helper@0"])
def test_complete_binary_call_proof_survives_changed_callee_labels(
    tmp_path: Path, callee_name: str,
) -> None:
    """Names select provenance; full binary effects discharge the call proof."""
    result = _compare_stack_write_call(
        tmp_path, candidate_value=0x1234, wide_address=True,
        candidate_callee_name=callee_name,
    )
    assert result["status"] == "passed", result
    assert result["dependencies"][0]["callees"][0]["function"] == "demo.exe:callee"
    assert result["dependencies"][1]["callees"][0]["function"] == f"demo.exe:{callee_name}"


def test_actual_mz_stack_memory_self(tmp_path: Path) -> None:
    """Identical MZ bytes preserve the full stack memory effect across a call."""
    result = _compare_stack_write_call(tmp_path, candidate_value=0x1234)
    assert result["status"] == "passed", result
    assert (tmp_path / "oracle.exe").read_bytes() == (tmp_path / "candidate.exe").read_bytes()
