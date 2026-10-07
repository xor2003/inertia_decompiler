"""Actual relocated FAR16 call-in-loop controls and independent guest replay."""
from pathlib import Path

import pytest
from tools.dosunit.tests.test_dosunit_tool import _edge_function, _mz_exe
from tools.dosunit.tests.test_real16_call_composition import _lower

from tools.dosunit.contracts.proof_contracts import ProofStatus
from tools.dosunit.compare.real16_loop_calls import compare_real16_loop_calls
from tools.dosunit.runtime.real16_mz_load import image_from_mz_bytes
from tools.dosunit.runtime.real16_replay import compare_executions, replay
from tools.dosunit.runtime.real16_replay_model import (
    CallerFrame,
    FrameKind,
    Real16Agreement,
    Real16Vector,
    SegOffset,
)

# MOV CX,AX; CMP CX,0; JZ RET; CALL FAR +10:0230; DEC CX; JMP CMP; RET.
# The callee selector word at 0x20a is relocated by the actual MZ loader.
BODY = bytes.fromhex("89c1 83f900 7408 9a30021000 49 ebf3 c3")
RELOCS = ((0x20A, 0),)


def fixture(callee: bytes) -> tuple[bytes, list[dict[str, object]]]:
    """Retain distinct caller/callee CS coordinates through MZ relocation."""
    image = bytearray(0x400)
    image[0x200:0x200 + len(BODY)] = BODY
    image[0x330:0x330 + len(callee)] = callee
    catalog = [
        _edge_function("demo.exe:loop", "loop", offset=0x200, size=len(BODY)),
        _edge_function("demo.exe:callee", "callee", offset=0x330, size=len(callee)),
    ]
    return bytes(image), catalog


@pytest.mark.parametrize("callee,positive", [
    ("9043cb", True),
    ("4bcb", False),
    ("43ca0200", False),
    ("43c3", False),
], ids=["equivalent", "effect", "cleanup", "wrong_return_kind"])
def test_far_call_loop_induction(tmp_path: Path, callee: str, positive: bool) -> None:
    """Actual far-call frames must close or retain a sound refused obligation."""
    image, catalog = fixture(bytes.fromhex("43cb"))
    other, other_catalog = fixture(bytes.fromhex(callee))
    oracle = _lower(tmp_path, image, catalog, "oracle", relocs=RELOCS)
    candidate = _lower(tmp_path, other, other_catalog, "candidate", relocs=RELOCS)
    proof = compare_real16_loop_calls(oracle, candidate, "demo.exe:loop", timeout_ms=10000)
    if positive:
        assert proof.status is ProofStatus.PROVED, proof
        assert proof.counters.failure_count == 0
    else:
        assert proof.status in {ProofStatus.COUNTEREXAMPLE, ProofStatus.UNKNOWN}, proof
        assert proof.counters.failure_count > 0


@pytest.mark.parametrize("iterations", [0, 1, 100])
def test_far_call_loop_independent_execution(iterations: int) -> None:
    """Zero/one/many FAR16 frames restore caller CS/SP and expose effect changes."""
    images = [image_from_mz_bytes(_mz_exe(fixture(bytes.fromhex(code))[0], relocs=RELOCS))
              for code in ("43cb", "9043cb", "4bcb")]
    entry = SegOffset(images[0].load_segment, 0x200)
    vector = Real16Vector(
        registers=(("ax", iterations), ("bx", 7), ("sp", 0x100), ("flags", 2)),
        segments=(("ss", 0x7000), ("ds", entry.segment), ("es", entry.segment)),
        frame=CallerFrame(FrameKind.NEAR16, SegOffset(entry.segment, 0x8000)),
    )
    results = [replay(image, entry, vector, instruction_limit=10000) for image in images]
    registers = dict(results[0].registers)
    assert registers["bx"] == 7 + iterations
    assert registers["cs"] == entry.segment
    assert registers["sp"] == 0x102
    assert compare_executions(results[0], results[1]).agreement is Real16Agreement.AGREED
    expected = Real16Agreement.AGREED if iterations == 0 else Real16Agreement.MISMATCHED
    assert compare_executions(results[0], results[2]).agreement is expected
