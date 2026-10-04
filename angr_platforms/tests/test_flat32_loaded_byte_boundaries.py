"""Actual PE byte-boundary controls under both native comparator drivers."""
from __future__ import annotations

import importlib
import io
import struct
from pathlib import Path

import angr
import pytest
from test_flat32_comparator_lane import _driver_lane

from tools.dosunit import flat32_pe_loader
from tools.dosunit.flat32_pe_loader import InclusivePE


def pe32_bytes(code: bytes) -> bytes:
    """Construct a real i386 PE whose virtual section ends at the last code byte."""
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x102)
    struct.pack_into("<H", data, 0x98, 0x10B)
    for offset, value in ((4, 0x200), (16, 0x1000), (20, 0x1000), (28, 0x400000),
                          (32, 0x1000), (36, 0x200), (56, 0x2000), (60, 0x200),
                          (72, 0x100000), (76, 0x1000), (80, 0x100000), (84, 0x1000), (92, 16)):
        struct.pack_into("<I", data, 0x98 + offset, value)
    struct.pack_into("<H", data, 0x98 + 68, 3)
    struct.pack_into("<8sIIIIIIHHI", data, 0x178, b".text\0\0\0", len(code), 0x1000,
                     0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    data[0x200:0x200 + len(code)] = code
    return bytes(data)


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_final_virtual_byte_survives_loader_and_native_decode(driver: str, tmp_path: Path) -> None:
    """A RET at the inclusive section end must remain in loaded executable code."""
    code = bytes.fromhex("b807000000c3")
    path = tmp_path / "last-byte.exe"
    path.write_bytes(pe32_bytes(code))
    with _driver_lane(driver) as lane:
        project = lane.adapter.load32(path)
        assert project.loader.memory.load(0x401000, len(code)) == code
        block = project.factory.block(0x401000)
        assert block.size == len(code)
        assert block.vex.jumpkind == "Ijk_Ret"


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_virtual_zero_tail_includes_final_declared_byte(driver: str, tmp_path: Path) -> None:
    """Declared PE BSS remains initialized through the inclusive virtual end."""
    data = bytearray(pe32_bytes(b"\xc3"))
    struct.pack_into("<I", data, 0x180, 0x300)
    path = tmp_path / "zero-tail.exe"
    path.write_bytes(data)
    with _driver_lane(driver) as lane:
        project = lane.adapter.load32(path)
        assert project.loader.memory.load(0x401200, 0x100) == bytes(0x100)


def test_final_word_seed_precedes_pe_base_relocation() -> None:
    """A relocation touching the final virtual byte sees complete original data."""
    code = bytearray(0x200)
    code[0] = 0xC3
    struct.pack_into("<IIHH", code, 0x100, 0x1000, 12, 0x31FC, 0)
    struct.pack_into("<I", code, 0x1FC, 0x400080)
    data = bytearray(pe32_bytes(bytes(code)))
    struct.pack_into("<H", data, 0x98 + 70, 0x40)
    struct.pack_into("<II", data, 0x98 + 96 + 5 * 8, 0x1100, 12)
    project = angr.Project(io.BytesIO(data), auto_load_libs=False,
                           main_opts={"backend": InclusivePE, "max_mapped_bytes": 8192, "base_addr": 0x500000})
    assert project.loader.memory.load(0x5011FC, 4) == struct.pack("<I", 0x500080)


def test_oversized_virtual_span_refuses_before_constructing_mapped_image() -> None:
    """The loader allowance applies before allocating inter-section padding."""
    with pytest.raises(ValueError, match="mapped span exceeds"):
        angr.Project(io.BytesIO(pe32_bytes(b"\xc3")), auto_load_libs=False,
                     main_opts={"backend": InclusivePE, "max_mapped_bytes": 4096})


def test_fast_pe_certificate_identity_tracks_owned_loader_source(tmp_path: Path,
                                                               monkeypatch: pytest.MonkeyPatch) -> None:
    """BC5 cannot reuse a loader certificate after its owned byte model changes."""
    source = tmp_path / "loader-source.py"
    source.write_text("version one\n")
    monkeypatch.setattr(flat32_pe_loader, "__file__", str(source))
    with _driver_lane("bc5"):
        fast = importlib.import_module("flat32_fast_pe")
        before = fast._loader_stamp()
        source.write_text("version two\n")
        after = fast._loader_stamp()
    assert before != after
    assert before["pe_loader_source"] != after["pe_loader_source"]
