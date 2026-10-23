"""Binary controls for live untouched lanes across partial register writes.

Layer: tests.
Responsibility: ensure VEX-to-SSA liveness retains definitions of the other
byte when AH/AL, BH/BL, CH/CL or DH/DL is written.
"""

from pathlib import Path
from typing import Any

import pytest

from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.tests.test_dosunit_tool import _edge_catalog, _mz_exe


def _lower(tmp_path: Path, tag: str, body: bytes, register: str) -> dict[str, Any]:
    """Lower a complete real MZ function with one observed word register."""
    image = bytearray(0x240)
    image[0x200:0x200 + len(body)] = body
    exe = tmp_path / f"{tag}.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    doc = S.lower_straightline_ssa_document(
        exe_path=exe,
        functions_catalog=_edge_catalog("demo:f", "f", offset=0x200, size=len(body)),
        output_regs=(register,),
    )
    assert doc["counters"]["functions_refused"] == 0, doc
    assert len(doc["functions"]) == 1, doc
    return doc["functions"][0]


@pytest.mark.parametrize(("register", "code"), [("ax", 0), ("cx", 1), ("dx", 2), ("bx", 3)])
@pytest.mark.parametrize("order", ["low_high", "high_low", "word_high", "word_low"])
def test_other_byte_definition_survives_partial_write(
    tmp_path: Path, register: str, code: int, order: str,
) -> None:
    """Byte writes must produce the same word as the equivalent immediate."""
    low = bytes((0xB0 + code, 0x12))
    high = bytes((0xB4 + code, 0x34))
    bodies = {
        "low_high": low + high,
        "high_low": high + low,
        "word_high": bytes((0xB8 + code, 0x12, 0xFF)) + high,
        "word_low": bytes((0xB8 + code, 0xFF, 0x34)) + low,
    }
    oracle = _lower(tmp_path, "oracle", bytes((0xB8 + code, 0x12, 0x34, 0xC3)), register)
    candidate = _lower(tmp_path, "candidate", bodies[order] + b"\xc3", register)
    result = S._compare_functions(oracle, candidate, timeout_ms=1000)
    assert result["status"] == "passed", result


@pytest.mark.parametrize("corrupt", [False, True])
def test_memory_byte_load_survives_high_byte_clear(tmp_path: Path, corrupt: bool) -> None:
    """A later AH clear cannot delete the live AL load or hide a changed load."""
    # mov ax,[si]; and ax,00ff; ret versus mov al,[si(+1)]; mov ah,0; ret.
    oracle = _lower(tmp_path, "oracle", bytes.fromhex("8b0425ff00c3"), "ax")
    load = bytes.fromhex("8a4401" if corrupt else "8a04")
    candidate = _lower(tmp_path, "candidate", load + bytes.fromhex("b400c3"), "ax")
    result = S._compare_functions(oracle, candidate, timeout_ms=1000)
    assert result["status"] == ("failed" if corrupt else "passed"), result
