"""Relocated far-call composition controls using actual MZ bytes and SSA/Z3."""

from pathlib import Path

import pytest
from tools.dosunit.tests.test_dosunit_tool import _edge_function, _mz_exe
from tools.dosunit.tests.test_real16_call_composition import _lower

from tools.dosunit.compare.real16_binary_compare import compare_binary16
from tools.dosunit.compare.real16_call_composition import compare_real16_with_calls
from tools.dosunit.runtime.real16_mz_load import image_from_mz_bytes
from tools.dosunit.runtime.real16_replay import compare_executions, replay
from tools.dosunit.runtime.real16_replay_model import (
    CallerFrame,
    FrameKind,
    Real16Agreement,
    Real16Vector,
    SegOffset,
)

RELOCS = ((0x206, 0),)


def _fixture(callee: bytes = bytes.fromhex("89d0cb")) -> tuple[bytes, list[dict[str, object]]]:
    # Loaded caller CS differs from callee CS by 0x10 paragraphs. The relocation
    # entry adjusts the immediate selector, not the callee offset 0x0230.
    image = bytearray(0x400)
    image[0x200:0x209] = bytes.fromhex("ba01009a30021000c3")
    image[0x330:0x330 + len(callee)] = callee
    catalog = [
        _edge_function("demo.exe:caller", "caller", offset=0x200, size=9),
        _edge_function("demo.exe:callee", "callee", offset=0x330, size=len(callee)),
    ]
    return bytes(image), catalog


def _comparison(tmp_path: Path, callee: bytes) -> dict:
    image, catalog = _fixture()
    other, other_catalog = _fixture(callee)
    left = _lower(tmp_path, image, catalog, "oracle", relocs=RELOCS)
    right = _lower(tmp_path, other, other_catalog, "candidate", relocs=RELOCS)
    return compare_real16_with_calls(left, right, "demo.exe:caller", timeout_ms=20000)


def test_relocated_far16_call_restores_actual_caller_cs(tmp_path: Path) -> None:
    result = _comparison(tmp_path, bytes.fromhex("89d0cb"))
    assert result["status"] == "passed", result
    assert result["calls"]["return_targets_proved"] == 2
    assert result["calls"]["cs_preserved_proved"] == 2


@pytest.mark.parametrize(
    "callee, expected",
    [
        ("b80200cb", "failed"),  # return value
        ("89d0ca0200", "failed"),  # RETF cleanup
        ("89d0c3", "refused"),  # near RET cannot restore far frame
        ("5589e58946fc5d89d0cb", "failed"),  # observable stack store
    ],
)
def test_far16_call_mutations_cannot_pass(tmp_path: Path, callee: str, expected: str) -> None:
    result = _comparison(tmp_path, bytes.fromhex(callee))
    assert result["status"] == expected, result


def test_far16_frame_agrees_with_independent_guest() -> None:
    image, _ = _fixture()
    other, _ = _fixture(bytes.fromhex("b80200cb"))
    left = image_from_mz_bytes(_mz_exe(image, relocs=RELOCS))
    right = image_from_mz_bytes(_mz_exe(other, relocs=RELOCS))
    entry = SegOffset(left.load_segment, 0x200)
    vector = Real16Vector(
        registers=(("sp", 0x100), ("flags", 2)),
        segments=(("ss", 0x7000), ("ds", left.load_segment), ("es", left.load_segment)),
        frame=CallerFrame(FrameKind.NEAR16, SegOffset(left.load_segment, 0x8000)),
    )
    oracle = replay(left, entry, vector)
    candidate = replay(right, entry, vector)
    assert compare_executions(oracle, oracle).agreement is Real16Agreement.AGREED
    assert dict(oracle.registers)["ax"] == 1
    assert dict(oracle.registers)["cs"] == left.load_segment
    assert compare_executions(oracle, candidate).agreement is Real16Agreement.MISMATCHED


@pytest.mark.parametrize("callee,expected", [("89d0cb", "proved"), ("b80200cb", "counterexample")])
def test_public_far16_call_obligation(tmp_path: Path, callee: str, expected: str) -> None:
    image, functions = _fixture()
    other, other_functions = _fixture(bytes.fromhex(callee))
    oracle, candidate = tmp_path / "oracle.exe", tmp_path / "candidate.exe"
    oracle.write_bytes(_mz_exe(image, relocs=RELOCS))
    candidate.write_bytes(_mz_exe(other, relocs=RELOCS))
    catalog = {"schema": "dosunit.functions.v1", "id": "functions:test", "module": "demo.exe",
               "program_kind": "mz_exe", "functions": functions, "diagnostics": []}
    candidate_catalog = {**catalog, "functions": other_functions}
    report = compare_binary16(oracle, candidate, catalog, candidate_catalog, selected=("caller",))
    assert report["status"] == expected, {"proof": report["proof"], "backend": report["backend"]}
    assert report["proof"]["verdicts"][0]["method"] == "ssa_z3_complete_call_inlining"
