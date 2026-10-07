"""Bound LINK /MAP parsing and PE32 image-binding controls.

Layer: tests.
Responsibility: prove the candidate-link-map owner accepts only a real,
bounded MSVC map whose header agrees with the supplied PE32 candidate, and
that every malformed or disagreeing input refuses with a typed reason.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from tools.dosunit.catalog.pe32_link_map import (
    LinkMapError,
    LinkMapRejection,
    load_candidate_link_map,
    parse_link_map,
    read_pe32_identity,
)

TIMESTAMP = 0x6AC4B06D
BASE = 0x400000


def _pe32(code: bytes, data: bytes = b"", *, imagebase: int = BASE, timestamp: int = TIMESTAMP,
          data_rva: int = 0x2000) -> bytes:
    """Construct a real i386 PE32 with .text and optional .data sections."""
    nsec = 2 if data else 1
    raw = bytearray(0x200 + 0x200 + (0x200 if data else 0))
    raw[:2] = b"MZ"
    struct.pack_into("<I", raw, 0x3C, 0x80)
    raw[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", raw, 0x84, 0x14C, nsec, timestamp, 0, 0, 0xE0, 0x102)
    struct.pack_into("<H", raw, 0x98, 0x10B)
    image_size = data_rva + 0x1000 if data else 0x2000
    for offset, value in ((4, 0x200), (16, 0x1000), (28, imagebase), (32, 0x1000),
                          (36, 0x200), (56, image_size), (60, 0x200), (72, 0x100000),
                          (76, 0x1000), (80, 0x100000), (84, 0x1000), (92, 16)):
        struct.pack_into("<I", raw, 0x98 + offset, value)
    struct.pack_into("<H", raw, 0x98 + 68, 3)
    struct.pack_into("<8sIIIIIIHHI", raw, 0x178, b".text\0\0\0", max(len(code), 1), 0x1000,
                     0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    if data:
        struct.pack_into("<8sIIIIIIHHI", raw, 0x1A0, b".data\0\0\0", max(len(data), 1), data_rva,
                         0x200, 0x400, 0, 0, 0, 0, 0xC0000040)
        raw[0x400:0x400 + len(data)] = data
    raw[0x200:0x200 + len(code)] = code
    return bytes(raw)


def _map_text(publics: str = "", *, timestamp: int = TIMESTAMP, base: int = BASE,
              segments: str | None = None) -> str:
    """Emit a syntactically real MSVC /MAP document for the fixture image."""
    if segments is None:
        segments = (
            " 0001:00000000 00000010H .text                   CODE\n"
            " 0002:00000000 00000010H .data                   DATA\n"
        )
    if not publics:
        publics = (
            " 0001:00000000       _f                       00401000   f.obj\n"
            " 0002:00000000       _dword_402000            00403000   data.obj\n"
        )
    return (
        " sample\n\n"
        f" Timestamp is {timestamp:08x} (Tue Oct 06 01:25:17 2026)\n\n"
        f" Preferred load address is {base:08x}\n\n"
        " Start         Length     Name                   Class\n"
        f"{segments}\n"
        "  Address         Publics by Value              Rva+Base   Lib:Object\n\n"
        f"{publics}\n"
        " entry point at        0001:00000000\n\n"
        " Static symbols\n\n"
        " 0001:00000001       _helper                  00401001 f helper.obj\n\n"
        "FIXUPS: 1234 f 46\n"
    )


def _map_file(tmp_path: Path, **kwargs: object) -> Path:
    """Materialize the fixture map on disk."""
    path = tmp_path / "candidate.map"
    path.write_text(_map_text(**kwargs))
    return path


def _exe(tmp_path: Path, **kwargs: object) -> Path:
    """Materialize the fixture PE32 image on disk."""
    path = tmp_path / "candidate.exe"
    path.write_bytes(_pe32(b"\xc3", b"\x00" * 16, **kwargs))
    return path


def test_parses_bound_publics_and_ignores_trailing_sections(tmp_path: Path) -> None:
    """A real-shaped map yields typed header, segments and publics only."""
    link_map = parse_link_map(_map_file(tmp_path))
    assert link_map.module == "sample"
    assert link_map.timestamp == TIMESTAMP
    assert link_map.preferred_base == BASE
    assert [record.name for record in link_map.segments] == [".text", ".data"]
    assert link_map.segments[0].is_code and not link_map.segments[1].is_code
    assert [record.name for record in link_map.publics] == ["_f", "_dword_402000"]
    assert link_map.publics[1].address == 0x403000
    assert link_map.publics[1].data_alias() == ("dword_402000", 0x402000)
    assert link_map.publics[0].data_alias() is None


def test_only_one_canonical_underscore_prefix_is_a_data_alias() -> None:
    """Zero or two leading underscores never produce a claimed alias."""
    from tools.dosunit.catalog.pe32_link_map import MapPublic

    public = MapPublic(segment=2, offset=0, name="_off_8AC68", address=0xA7C68, origin="o.obj")
    assert public.data_alias() == ("off_8AC68", 0x8AC68)
    assert MapPublic(2, 0, "__dword_8A5EC", 0xA75EC, "o.obj").data_alias() is None
    assert MapPublic(2, 0, "dword_8A5EC", 0xA75EC, "o.obj").data_alias() is None
    assert MapPublic(2, 0, "_dword_08A5EC", 0xA75EC, "o.obj").data_alias() == ("dword_8A5EC", 0x8A5EC)


@pytest.mark.parametrize("field", ["timestamp", "base"])
def test_duplicate_header_identity_fields_refuse(tmp_path: Path, field: str) -> None:
    """Conflicting header declarations cannot be resolved by taking the last."""
    text = _map_text()
    addition = (" Timestamp is 11111111 (conflicting)\n" if field == "timestamp"
                else " Preferred load address is 00300000\n")
    text = text.replace(" Start", addition + " Start", 1)
    path = tmp_path / "duplicate.map"
    path.write_text(text)
    with pytest.raises(LinkMapError):
        parse_link_map(path)


def test_public_alias_outside_segment_does_not_fall_back_to_first_record(tmp_path: Path) -> None:
    """An index match cannot authorize an offset outside every contribution."""
    link_map = parse_link_map(_map_file(tmp_path))
    assert link_map.segment(2, 0xFFFFFFFF) is None


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        (" sample\n\n Preferred load address is 00400000\n\n"
         " Start         Length     Name                   Class\n"
         " 0001:00000000 00000010H .text                   CODE\n",
         LinkMapRejection.MISSING_HEADER),
        (" sample\n\n Timestamp is 6ac4b06d (x)\n\n"
         " Start         Length     Name                   Class\n"
         " 0001:00000000 00000010H .text                   CODE\n",
         LinkMapRejection.MISSING_HEADER),
        ("", LinkMapRejection.MISSING_HEADER),
    ],
    ids=["no_timestamp", "no_base", "empty"],
)
def test_malformed_or_incomplete_header_refuses(tmp_path: Path, text: str, reason: object) -> None:
    """Missing header fields refuse; nothing is guessed."""
    path = tmp_path / "bad.map"
    path.write_text(text)
    with pytest.raises(LinkMapError) as error:
        parse_link_map(path)
    assert error.value.reason is reason


def test_unknown_header_line_and_bad_public_row_refuse(tmp_path: Path) -> None:
    """Unrecognized lines inside recognized sections refuse rather than continue."""
    bad_header = _map_text().replace(" Preferred load address", " Preferential address")
    path = tmp_path / "bad.map"
    path.write_text(bad_header)
    with pytest.raises(LinkMapError, match="malformed_line"):
        parse_link_map(path)
    bad_row = _map_text().replace(
        " 0002:00000000       _dword_402000            00403000   data.obj",
        " 0002:00000000       _dword_402000            not-an-rva data.obj",
    )
    path.write_text(bad_row)
    with pytest.raises(LinkMapError, match="malformed_line"):
        parse_link_map(path)


def test_public_in_undeclared_segment_refuses(tmp_path: Path) -> None:
    """A public naming a segment absent from the table is malformed evidence."""
    path = _map_file(
        tmp_path, publics=" 0009:00000000       _dword_402000            00403000   d.obj\n"
    )
    with pytest.raises(LinkMapError) as error:
        parse_link_map(path)
    assert error.value.reason is LinkMapRejection.UNDECLARED_SEGMENT


def test_read_pe32_identity_rejects_non_pe32(tmp_path: Path) -> None:
    """Only an i386 PE32 image supplies a timestamp/base binding."""
    path = tmp_path / "plain.bin"
    path.write_bytes(b"\xc3" * 64)
    with pytest.raises(LinkMapError) as error:
        read_pe32_identity(path)
    assert error.value.reason is LinkMapRejection.NOT_PE32
    exe = _exe(tmp_path)
    assert read_pe32_identity(exe).image_base == BASE
    assert read_pe32_identity(exe).timestamp == TIMESTAMP


def test_map_bound_to_wrong_image_refuses(tmp_path: Path) -> None:
    """A map produced for a different timestamp or image base cannot bind."""
    exe = _exe(tmp_path)
    map_path = _map_file(tmp_path, timestamp=TIMESTAMP + 1)
    with pytest.raises(LinkMapError, match="image_mismatch"):
        load_candidate_link_map(map_path, exe)
    map_path = _map_file(tmp_path, base=BASE + 0x1000)
    with pytest.raises(LinkMapError, match="image_mismatch"):
        load_candidate_link_map(map_path, exe)
    bound = load_candidate_link_map(_map_file(tmp_path), exe)
    assert bound.provenance()["sha256"] == bound.sha256
    assert bound.provenance()["preferred_base"] == f"{BASE:08x}"
