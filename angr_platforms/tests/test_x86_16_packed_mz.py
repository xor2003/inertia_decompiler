from __future__ import annotations

import io
import struct
from pathlib import Path

import pytest
from angr_platforms.X86_16.exepack import unpack_exepack
from angr_platforms.X86_16.load_dos_mz import DOSMZHeader
from angr_platforms.X86_16.mz_image import MZHeaderView
from angr_platforms.X86_16.packed_mz import PackerType, detect_packer_in_bytes, unpack_lzexe_091

import decompile
import inertia_decompiler.project_loading as project_loading

_PROGRAM = bytes.fromhex("b83412" "ba0100" "8eda" "c3")
_PROGRAM_RELOCATION_OFFSET = 4
_EXEPACK_FIXTURES = Path(__file__).parent / "fixtures" / "exepack"
_PACKED_EXEPACK_FIXTURE_NAMES = (
    "hello-masm4.00-exepack.exe",
    "hello-masm4.00-link.exe",
    "hello-masm5.00-exepack.exe",
    "hello-masm5.00-link.exe",
    "hello-masm5.10-exepack.exe",
    "hello-masm5.10-link.exe",
)


def _mz(
    image: bytes,
    *,
    header_paragraphs: int,
    cs: int = 0,
    ip: int = 0,
    relocation_offset: int | None = None,
) -> bytearray:
    header = bytearray(header_paragraphs * 16)
    total = len(header) + len(image)
    struct.pack_into(
        "<2s13H",
        header,
        0,
        b"MZ",
        total % 512,
        (total + 511) // 512,
        0,
        header_paragraphs,
        0,
        0xFFFF,
        0x10,
        0x100,
        0,
        ip,
        cs,
        len(header) if relocation_offset is None else relocation_offset,
        0,
    )
    return header + image


class _LZEXEStreamWriter:
    def __init__(self) -> None:
        self.output = bytearray(2)
        self.word_position = 0
        self.bit_index = 0

    def bit(self, value: int) -> None:
        if value:
            self.output[self.word_position + (self.bit_index // 8)] |= 1 << (self.bit_index % 8)
        self.bit_index += 1
        if self.bit_index == 16:
            self.word_position = len(self.output)
            self.output += b"\x00\x00"
            self.bit_index = 0

    def byte(self, value: int) -> None:
        self.output.append(value & 0xFF)

    def literal(self, value: int) -> None:
        self.bit(1)
        self.byte(value)

    def end(self) -> None:
        self.bit(0)
        self.bit(1)
        self.byte(0xFF)
        self.byte(0)
        self.byte(0)


def _synthetic_lzexe() -> bytes:
    writer = _LZEXEStreamWriter()
    for value in _PROGRAM:
        writer.literal(value)
    writer.end()
    stream = bytes(writer.output)
    packed_paragraphs = (len(stream) + 15) // 16
    stream = stream.ljust(packed_paragraphs * 16, b"\x00")
    info = struct.pack("<6H", 0, 0, 0x100, 0x10, packed_paragraphs, 1)
    decompressor = (info + b"\x06\x0e\x1f\x8b").ljust(0x158, b"\x90")
    relocation_table = bytes([_PROGRAM_RELOCATION_OFFSET, 0, 1, 0])
    image = stream + decompressor + relocation_table
    packed = _mz(image, header_paragraphs=2, cs=packed_paragraphs, ip=len(info))
    packed[0x1C:0x20] = b"LZ91"
    return bytes(packed)


def _synthetic_pklite() -> bytes:
    packed = _mz(b"\x90" * 32, header_paragraphs=4)
    packed[0x1E:0x24] = b"PKLITE"
    return bytes(packed)


def _synthetic_diet() -> bytes:
    packed = _mz(b"\x90" * 32, header_paragraphs=4)
    packed[0x1C:0x20] = b"diet"
    return bytes(packed)


def _mz_image_and_relocations(data: bytes) -> tuple[MZHeaderView, bytes, tuple[tuple[int, int], ...]]:
    header = MZHeaderView.parse(data)
    assert header is not None
    declared_size = header.declared_file_size
    assert declared_size is not None
    assert declared_size <= len(data)
    image = data[header.header_size:declared_size]
    relocations = tuple(
        (
            struct.unpack_from("<H", data, header.relocation_offset + index * 4 + 2)[0],
            struct.unpack_from("<H", data, header.relocation_offset + index * 4)[0],
        )
        for index in range(header.relocation_count)
    )
    return header, image, relocations


def test_detector_uses_real_mz_header_fields_and_bounded_signatures() -> None:
    lzexe = detect_packer_in_bytes(_synthetic_lzexe())
    pklite = detect_packer_in_bytes(_synthetic_pklite())

    assert lzexe is not None
    assert lzexe.packer_type is PackerType.LZEXE
    assert lzexe.label == "LZEXE 0.91"
    assert pklite is not None
    assert pklite.packer_type is PackerType.PKLITE
    assert pklite.offset == 0x1E
    assert detect_packer_in_bytes(bytes(_mz(_PROGRAM, header_paragraphs=2))) is None
    assert detect_packer_in_bytes(b"not an executable") is None


def test_detector_recognizes_diet_and_real_exepack_headers() -> None:
    diet = detect_packer_in_bytes(_synthetic_diet())
    exepack = detect_packer_in_bytes((_EXEPACK_FIXTURES / _PACKED_EXEPACK_FIXTURE_NAMES[0]).read_bytes())

    assert diet is not None
    assert diet.packer_type is PackerType.DIET
    assert diet.offset == 0x1C
    assert exepack is not None
    assert exepack.packer_type is PackerType.EXEPACK
    assert exepack.signature == "RB"


def test_lzexe_decoder_preserves_relocations_entry_and_stack() -> None:
    unpacked = unpack_lzexe_091(_synthetic_lzexe())

    assert unpacked.image[: len(_PROGRAM)] == _PROGRAM
    assert unpacked.relocations == ((0, _PROGRAM_RELOCATION_OFFSET),)
    assert (unpacked.entry_cs, unpacked.entry_ip) == (0, 0)
    assert (unpacked.stack_ss, unpacked.stack_sp) == (0x10, 0x100)

    header = DOSMZHeader.from_stream(io.BytesIO(unpacked.to_mz_bytes()))
    assert header.relocation_count == 1
    assert (header.initial_cs, header.initial_ip) == (0, 0)
    assert (header.initial_ss, header.initial_sp) == (0x10, 0x100)


def test_project_loads_decoded_lzexe_through_normal_mz_backend(tmp_path: Path) -> None:
    packed_path = tmp_path / "PACKED.EXE"
    packed_path.write_bytes(_synthetic_lzexe())
    project_loading._detect_packed_mz_executable_cached.cache_clear()

    project = project_loading._build_project(
        packed_path,
        force_blob=False,
        base_addr=0x1000,
        entry_point=0x1000,
    )

    assert project.entry == 0x10000
    assert project.loader.main_object.initial_register_values == {
        "cs": 0x1000,
        "ip": 0,
        "ss": 0x1010,
        "sp": 0x100,
    }
    relocated = int.from_bytes(project.loader.memory.load(0x10000 + _PROGRAM_RELOCATION_OFFSET, 2), "little")
    assert relocated == 0x1001
    assert project._inertia_packed_exe == "LZEXE 0.91"


@pytest.mark.parametrize("fixture_name", _PACKED_EXEPACK_FIXTURE_NAMES)
def test_exepack_decoder_matches_original_across_historical_stubs(fixture_name: str) -> None:
    expected_header, expected_image, expected_relocations = _mz_image_and_relocations(
        (_EXEPACK_FIXTURES / "hello.exe").read_bytes()
    )
    unpacked = unpack_exepack((_EXEPACK_FIXTURES / fixture_name).read_bytes())

    assert unpacked.image[: len(expected_image)] == expected_image
    assert len(unpacked.image) - len(expected_image) in range(16)
    assert not any(unpacked.image[len(expected_image) :])
    assert sorted(unpacked.relocations) == sorted(expected_relocations)
    assert (unpacked.entry_cs, unpacked.entry_ip) == (expected_header.entry_cs, expected_header.entry_ip)
    assert (unpacked.stack_ss, unpacked.stack_sp) == (expected_header.stack_ss, expected_header.stack_sp)
    assert unpacked.max_alloc == expected_header.max_alloc
    assert unpacked.overlay_number == expected_header.overlay_number


def test_project_loads_decoded_exepack_through_normal_mz_backend() -> None:
    packed_path = _EXEPACK_FIXTURES / _PACKED_EXEPACK_FIXTURE_NAMES[0]
    unpacked = unpack_exepack(packed_path.read_bytes())
    project_loading._detect_packed_mz_executable_cached.cache_clear()

    project = project_loading._build_project(
        packed_path,
        force_blob=False,
        base_addr=0x1000,
        entry_point=0x1000,
    )

    assert project.entry == 0x10000 + (unpacked.entry_cs << 4) + unpacked.entry_ip
    assert project.loader.main_object.initial_register_values == {
        "cs": 0x1000 + unpacked.entry_cs,
        "ip": unpacked.entry_ip,
        "ss": 0x1000 + unpacked.stack_ss,
        "sp": unpacked.stack_sp,
    }
    assert project._inertia_packed_exe == "EXEPACK"


@pytest.mark.parametrize(
    ("payload", "packer_name"),
    ((_synthetic_pklite(), "PKLITE"), (_synthetic_diet(), "DIET")),
)
def test_cli_refuses_recognized_packer_without_a_proven_decoder(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    payload: bytes,
    packer_name: str,
) -> None:
    packed_path = tmp_path / "PACKED.EXE"
    monkeypatch.setenv("INERTIA_DEARK_PATH", str(tmp_path / "missing-deark"))
    packed_path.write_bytes(payload)
    project_loading._detect_packed_mz_executable_cached.cache_clear()

    rc = decompile.main([str(packed_path), "--timeout", "2"])
    captured = capsys.readouterr()

    assert rc == 7
    assert f"refused {packer_name}-packed executable" in captured.err
    if packer_name == "PKLITE":
        assert "github.com/jsummers/deark" in captured.err
    else:
        assert "unpack the executable first" in captured.err
