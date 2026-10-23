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


def test_static_symbols_are_explicit_separate_intake(tmp_path: Path) -> None:
    path = _map_file(tmp_path)
    default = parse_link_map(path)
    code = parse_link_map(path, include_statics=True)
    assert default.statics == ()
    assert default.publics == code.publics
    assert [symbol.name for symbol in code.statics] == ["_helper"]
    assert code.provenance()["static_count"] == 1


def test_malformed_static_table_rejects_code_intake_only(tmp_path: Path) -> None:
    path = _map_file(tmp_path)
    path.write_text(path.read_text().replace("0001:00000001       _helper", "broken       _helper"))
    assert parse_link_map(path).statics == ()
    with pytest.raises(LinkMapError):
        parse_link_map(path, include_statics=True)


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


def test_global_layout_report_retains_checked_scope_and_pending_obligations() -> None:
    from tools.comparator.global_layout_checks import check_global_layout

    result = check_global_layout({0x3000: 0x1000, 0x3010: 0x1010, 0x3014: 0x1014})
    assert result["status"] == "checked"
    assert result["order_preserved"] and result["spacing_preserved"]
    assert result["uniform_displacement"] == 0x2000
    assert result["checked_adjacent_pairs"] == 2
    assert not result["function_equivalence_proved"]
    assert result["pending_conditions"]
    assert check_global_layout({0x3014: 0x1014, 0x3010: 0x1010, 0x3000: 0x1000}) == result


@pytest.mark.parametrize(("pairs", "order", "spacing"), [
    ({0x3000: 0x1010, 0x3010: 0x1000}, False, False),
    ({0x3000: 0x1000, 0x3014: 0x1010}, True, False),
    ({0x3000: 0x1000, 0x3010: 0x1000}, False, False),
])
def test_global_layout_detects_shuffle_padding_and_collapsed_objects(
    pairs: dict[int, int], order: bool, spacing: bool,
) -> None:
    from tools.comparator.global_layout_checks import check_global_layout

    result = check_global_layout(pairs)
    assert result["status"] == "mismatch"
    assert result["order_preserved"] is order
    assert result["spacing_preserved"] is spacing
    assert result["adjacent_pairs"][0]["status"] == "mismatch"


@pytest.mark.parametrize("pairs", [{}, {0x3000: 0x1000}])
def test_global_layout_requires_two_distinct_positions(pairs: dict[int, int]) -> None:
    from tools.comparator.global_layout_checks import check_global_layout

    assert check_global_layout(pairs)["status"] == "incomplete"


@pytest.mark.parametrize("pairs", [{True: 1}, {1: False}, {-1: 1}, {1: 0x100000000}])
def test_global_layout_rejects_invalid_coordinates(pairs: dict[int, int]) -> None:
    from tools.comparator.global_layout_checks import check_global_layout

    with pytest.raises(ValueError, match="32-bit"):
        check_global_layout(pairs)


def test_named_data_symbol_maps_only_bound_data(tmp_path: Path) -> None:
    from tools.comparator.msc8_catalog import link_map_global_map, lst_data_symbols
    from tools.dosunit.architectures.flat32_loader import load_flat32_project

    original_path = tmp_path / "original.exe"
    original_path.write_bytes(_pe32(b"\xc3", b"\0" * 16))
    original = load_flat32_project(original_path)
    candidate = load_flat32_project(_exe(tmp_path, data_rva=0x3000))
    listing = tmp_path / "original.lst"
    listing.write_text(".data:00402000 saved_handle dd ?\n.text:00401000 ignored dd 0\n")
    symbols = lst_data_symbols(listing)
    assert symbols == {"saved_handle": 0x402000}
    link_map = parse_link_map(_map_file(tmp_path, publics=
        " 0002:00000000       _saved_handle            00403000   data.obj\n"))
    assert link_map_global_map(link_map, candidate, original, symbols) == {0x403000: 0x402000}
    assert link_map_global_map(link_map, candidate, original, {}) == {}


def test_named_data_repeated_label_cannot_select_last_address(tmp_path: Path) -> None:
    from tools.comparator.msc8_catalog import lst_data_symbols

    listing = tmp_path / "original.lst"
    listing.write_text(".data:00402000 saved_handle dd ?\n.data:00402004 saved_handle dd ?\n")
    with pytest.raises(ValueError, match="conflicting"):
        lst_data_symbols(listing)


def _anonymous_fixture(tmp_path: Path, listing_rows: str, publics: str,
                       segments: str | None = None):
    """Bind a fixture oracle/candidate pair, listing rows, and map publics."""
    from tools.comparator.msc8_catalog import lst_data_rows
    from tools.dosunit.architectures.flat32_loader import load_flat32_project

    (tmp_path / "original.exe").write_bytes(_pe32(b"\xc3", b"\0" * 16))
    original = load_flat32_project(tmp_path / "original.exe")
    candidate = load_flat32_project(_exe(tmp_path, data_rva=0x3000))
    listing = tmp_path / "original.lst"
    listing.write_text(listing_rows)
    link_map = parse_link_map(_map_file(tmp_path, publics=publics, segments=segments))
    return link_map, candidate, original, lst_data_rows(listing)


def test_lst_data_rows_indexes_named_and_anonymous_only(tmp_path: Path) -> None:
    from tools.comparator.msc8_catalog import lst_data_rows

    listing = tmp_path / "original.lst"
    listing.write_text(
        ".data:00402000 saved_handle dd ?\n"
        ".data:00402004                 db 0FFh\n"
        ".data:00402008 aString        db 'x',0\n"
        ".data:00402010                 dw 4 dup(?)\n"
        ".data:00402018 ; just a comment about dd\n"
        ".data:00402020                 align 10h\n"
        ".text:00401000                 dd 0\n"
        ".text:00401004                 db 90h\n"
        ".rdata:00403000                dq ?\n"
        ".bss:00404000                  db ?\n"
    )
    rows = lst_data_rows(listing)
    assert rows == {
        0x402000: "dd", 0x402004: "db", 0x402008: "db", 0x402010: "dw",
        0x403000: "dq", 0x404000: "db",
    }


def test_anonymous_data_row_maps_with_explicit_claim(tmp_path: Path) -> None:
    from tools.comparator.msc8_catalog import link_map_global_map

    link_map, candidate, original, rows = _anonymous_fixture(
        tmp_path,
        ".data:00402000 saved_handle dd ?\n.data:00402004                 db 0FFh\n",
        " 0002:00000000       _saved_handle            00403000   data.obj\n"
        " 0002:00000004       _unk_402004              00403004   data.obj\n",
    )
    assert link_map_global_map(link_map, candidate, original, {}, rows) == {
        0x403004: 0x402004
    }


def test_anonymous_claim_never_reaches_code_address(tmp_path: Path) -> None:
    from tools.comparator.msc8_catalog import link_map_global_map

    link_map, candidate, original, rows = _anonymous_fixture(
        tmp_path,
        ".data:00402004                 db 0FFh\n.text:00401000                 db 90h\n",
        " 0002:00000004       _unk_401000              00403004   data.obj\n",
    )
    assert link_map_global_map(link_map, candidate, original, {}, rows) == {}


def test_anonymous_claim_requires_declared_row(tmp_path: Path) -> None:
    from tools.comparator.msc8_catalog import link_map_global_map

    link_map, candidate, original, rows = _anonymous_fixture(
        tmp_path,
        ".data:00402000 buffer_402000 dd ?\n",
        " 0002:00000004       _unk_402002              00403004   data.obj\n",
    )
    assert link_map_global_map(link_map, candidate, original, {}, rows) == {}


def test_anonymous_claim_requires_mapped_oracle(tmp_path: Path) -> None:
    from tools.comparator.msc8_catalog import link_map_global_map

    link_map, candidate, original, rows = _anonymous_fixture(
        tmp_path,
        ".data:00402004                 db 0FFh\n",
        " 0002:00000004       _unk_405000              00403004   data.obj\n",
    )
    assert link_map_global_map(link_map, candidate, original, {}, rows) == {}


def test_anonymous_claim_refuses_code_segment_public(tmp_path: Path) -> None:
    from tools.comparator.msc8_catalog import link_map_global_map

    link_map, candidate, original, rows = _anonymous_fixture(
        tmp_path,
        ".data:00402004                 db 0FFh\n",
        " 0001:00000004       _unk_402004              00401004   code.obj\n",
    )
    with pytest.raises(ValueError, match="CODE segment"):
        link_map_global_map(link_map, candidate, original, {}, rows)


def test_anonymous_claim_refuses_unmapped_candidate(tmp_path: Path) -> None:
    from tools.comparator.msc8_catalog import link_map_global_map

    link_map, candidate, original, rows = _anonymous_fixture(
        tmp_path,
        ".data:00402004                 db 0FFh\n",
        " 0002:00000800       _unk_402004              00403800   data.obj\n",
        segments=(
            " 0001:00000000 00000010H .text                   CODE\n"
            " 0002:00000000 00001000H .data                   DATA\n"
        ),
    )
    with pytest.raises(ValueError, match="not mapped non-executable"):
        link_map_global_map(link_map, candidate, original, {}, rows)


def test_conflicting_anonymous_claims_refuse(tmp_path: Path) -> None:
    from tools.comparator.msc8_catalog import link_map_global_map

    link_map, candidate, original, rows = _anonymous_fixture(
        tmp_path,
        ".data:00402004                 db 0FFh\n",
        " 0002:00000004       _unk_402004              00403004   a.obj\n"
        " 0002:00000008       _unk_402004              00403008   b.obj\n",
    )
    with pytest.raises(ValueError, match="conflicting data aliases"):
        link_map_global_map(link_map, candidate, original, {}, rows)


def test_anonymous_claim_requires_declared_segment(tmp_path: Path) -> None:
    """A public pointing outside every declared segment is refused at parse."""
    path = _map_file(
        tmp_path, publics=" 0009:00000004       _unk_402004              00403004   data.obj\n"
    )
    with pytest.raises(LinkMapError):
        parse_link_map(path)


def test_contradictory_named_label_blocks_anonymous_fallback(tmp_path: Path) -> None:
    """A listing label binding a different VA is contradictory evidence; an
    anonymous row at the claimed VA must never override it."""
    from tools.comparator.msc8_catalog import link_map_global_map, lst_data_symbols

    link_map, candidate, original, rows = _anonymous_fixture(
        tmp_path,
        ".data:00402004                 db 0FFh\n"
        ".data:00402100 unk_402004    dd ?\n",
        " 0002:00000004       _unk_402004              00403004   data.obj\n",
    )
    symbols = lst_data_symbols(tmp_path / "original.lst")
    assert symbols.get("unk_402004") == 0x402100
    assert link_map_global_map(link_map, candidate, original, symbols, rows) == {}
