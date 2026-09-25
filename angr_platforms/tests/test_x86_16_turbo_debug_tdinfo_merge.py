from __future__ import annotations

import struct
from pathlib import Path

from angr_platforms.X86_16.turbo_debug_tdinfo import (
    TDInfoNameKind,
    TDInfoSymbolClass,
    _parse_tdinfo_coverage_map,
    _parse_tdinfo_coverage_offsets,
    parse_tdinfo_exe_bytes,
)

from dump_debug_info import dump_debug_info


def _build_minimal_tdinfo_image() -> bytes:
    data = bytearray(512)
    data[0:2] = b"MZ"
    struct.pack_into("<HH", data, 2, 512, 1)
    debug_offset = 512
    name_pool = b"func\x00MYTYPE\x00"
    data.extend(b"\x00" * 96)
    struct.pack_into(
        "<HBBIHHHHH",
        data,
        debug_offset,
        0x52FB,
        1,
        3,
        len(name_pool),
        2,
        0,
        0,
        2,
        0,
    )
    struct.pack_into("<H", data, debug_offset + 42, 0)
    sym_off = debug_offset + 44
    struct.pack_into("<HHHHB", data, sym_off, 1, 0, 0x10, 0x20, TDInfoSymbolClass.STATIC)
    struct.pack_into("<HHHHB", data, sym_off + 9, 2, 0, 0, 0, TDInfoSymbolClass.TYPEDEF)
    data[-len(name_pool) :] = name_pool
    return bytes(data)


def test_tdinfo_exposes_symbol_classes_and_type_names():
    parsed = parse_tdinfo_exe_bytes(_build_minimal_tdinfo_image())

    assert parsed is not None
    assert parsed.type_names == ("MYTYPE",)
    assert parsed.named_symbols[0].name == "func"
    assert TDInfoSymbolClass.STATIC in parsed.symbols_by_class
    assert TDInfoSymbolClass.TYPEDEF in parsed.symbols_by_class
    assert parsed.code_labels


def test_dump_debug_info_exposes_tdinfo_symbols_by_class(tmp_path: Path):
    binary = tmp_path / "tdinfo.exe"
    binary.write_bytes(_build_minimal_tdinfo_image())

    payload = dump_debug_info(binary, load_base_linear=0)

    assert payload["tdinfo"] is not None
    symbols_by_class = payload["tdinfo"]["symbols_by_class"]
    assert "STATIC(0)" in symbols_by_class
    assert symbols_by_class["STATIC(0)"][0]["index"] == 1
    assert symbols_by_class["TYPEDEF(6)"][0]["index"] == 2


def _build_tdinfo_image_with_symbol_classes() -> bytes:
    data = bytearray(512)
    data[0:2] = b"MZ"
    struct.pack_into("<HH", data, 2, 512, 1)
    debug_offset = 512
    name_pool = b"func\x00local_i\x00reg_ax\x00answer\x00C:\\DBGPROBE.C\x00"
    data.extend(b"\x00" * 160)
    struct.pack_into(
        "<HBBIHHHHH",
        data,
        debug_offset,
        0x52FB,
        1,
        3,
        len(name_pool),
        5,
        0,
        0,
        4,
        0,
    )
    struct.pack_into("<H", data, debug_offset + 42, 0)
    sym_off = debug_offset + 44
    struct.pack_into("<HHHHB", data, sym_off, 1, 0, 0x10, 0x20, TDInfoSymbolClass.STATIC)
    struct.pack_into("<HHHHB", data, sym_off + 9, 2, 0x11, 0xFFFE, 0, TDInfoSymbolClass.AUTO)
    struct.pack_into("<HHHHB", data, sym_off + 18, 3, 0x11, 0, 0, TDInfoSymbolClass.REGISTER)
    struct.pack_into("<HHHHB", data, sym_off + 27, 4, 0x11, 42, 0, TDInfoSymbolClass.CONSTANT)
    data[-len(name_pool) :] = name_pool
    return bytes(data)


def test_tdinfo_exposes_named_non_static_symbols_by_class():
    parsed = parse_tdinfo_exe_bytes(_build_tdinfo_image_with_symbol_classes())

    assert parsed is not None
    assert parsed.names_by_class[TDInfoSymbolClass.AUTO] == ("local_i",)
    assert parsed.names_by_class[TDInfoSymbolClass.REGISTER] == ("reg_ax",)
    assert parsed.names_by_class[TDInfoSymbolClass.CONSTANT] == ("answer",)
    assert parsed.source_files == ("C:\\DBGPROBE.C",)
    assert "local_i" in parsed.candidate_identifiers
    assert parsed.name_pool_entries[-1].kind is TDInfoNameKind.SOURCE_FILE
    assert parsed.public_symbols == ()
    assert parsed.local_identifiers == ("func", "local_i", "reg_ax", "answer")
    assert parsed.stack_variables[0].name == "local_i"
    assert parsed.stack_variables[0].record.offset == 0xFFFE
    assert parsed.stack_variables[0].record.signed_offset == -2
    assert parsed.register_symbols[0].name == "reg_ax"
    assert parsed.constant_symbols[0].record.offset == 42
    assert parsed.raw_table_spans[0].name == "header"
    assert parsed.raw_table_spans[1].name == "symbol_records"
    assert parsed.raw_table_spans[1].count == 4
    assert parsed.raw_table_spans[-1].name == "name_pool"


def _build_tdinfo_image_with_payload(payload: bytes, name_pool: bytes, *, symbols_count: int = 0) -> bytes:
    data = bytearray(512)
    data[0:2] = b"MZ"
    struct.pack_into("<HH", data, 2, 512, 1)
    debug_offset = 512
    data.extend(b"\x00" * (44 + symbols_count * 9 + len(payload) + len(name_pool)))
    struct.pack_into(
        "<HBBIHHHHH",
        data,
        debug_offset,
        0x52FB,
        16,
        3,
        len(name_pool),
        name_pool.count(b"\x00"),
        1,
        2,
        symbols_count,
        0,
    )
    struct.pack_into("<H", data, debug_offset + 42, 0)
    payload_offset = debug_offset + 44 + symbols_count * 9
    data[payload_offset : payload_offset + len(payload)] = payload
    data[-len(name_pool) :] = name_pool
    return bytes(data)


def test_tdinfo_decodes_payload_extra_symbols_and_type_members():
    names = b"left\x00right\x00result\x00local_pair\x00PAIR\x00pair_s\x00"
    extra_symbols = (
        struct.pack("<HHHHB", 3, 4, 0xFFFA, 0, TDInfoSymbolClass.AUTO)
        + struct.pack("<HHHHB", 4, 0x19, 0xFFFC, 0, TDInfoSymbolClass.AUTO)
        + struct.pack("<HHHHB", 5, 0x19, 0, 0, TDInfoSymbolClass.TYPEDEF)
        + struct.pack("<HHHHB", 6, 0x19, 0, 0, TDInfoSymbolClass.STRUCT_UNION_OR_ENUM)
    )
    descriptors = bytes.fromhex("15000002000019001e06000400000000")
    # Real TD32 member records are name-first 5-byte records
    # (name_idx u16, type_idx u16, attr u8); attr&0x80 ends the list and a
    # u32 object-size trailer follows.
    members = bytes([1, 0, 4, 0, 0, 2, 0, 4, 0, 0x80, 4, 0, 0, 0])
    parsed = parse_tdinfo_exe_bytes(_build_tdinfo_image_with_payload(extra_symbols + descriptors + members, names))

    assert parsed is not None
    assert [symbol.name for symbol in parsed.stack_variables] == ["result", "local_pair"]
    assert parsed.type_names == ("PAIR", "pair_s")
    assert [(descriptor.type_index, descriptor.kind.name, descriptor.name, descriptor.size) for descriptor in parsed.type_descriptors] == [
        (0x18, "NEAR_POINTER", "", 2),
        (0x19, "STRUCT", "pair_s", 4),
    ]
    assert ("PAIR", 0x19, TDInfoSymbolClass.TYPEDEF) in [
        (ref.name, ref.type_index, ref.symbol_class) for ref in parsed.type_references
    ]
    assert [(member.name, member.offset, member.type_index, member.owner_type_index) for member in parsed.type_members] == [
        ("left", 0, 4, 0x19),
        ("right", 2, 4, 0x19),
    ]
    assert parsed.enum_members == ()


def test_tdinfo_decodes_enum_member_payload_sequences():
    names = b"RED\x00GREEN\x00BLUE\x00COLOR\x00color_e\x00"
    extra_symbols = (
        struct.pack("<HHHHB", 4, 0x18, 0, 0, TDInfoSymbolClass.TYPEDEF)
        + struct.pack("<HHHHB", 5, 0x18, 0, 0, TDInfoSymbolClass.STRUCT_UNION_OR_ENUM)
    )
    descriptors = bytes.fromhex("22050002000000000080ff7f01000000")
    enum_members = bytes([1, 0, 1, 0, 0, 2, 0, 2, 0, 0, 3, 0, 4, 0, 0x80, 2, 0, 0, 0])
    parsed = parse_tdinfo_exe_bytes(_build_tdinfo_image_with_payload(extra_symbols + descriptors + enum_members, names))

    assert parsed is not None
    assert parsed.type_names == ("COLOR", "color_e")
    assert [(descriptor.type_index, descriptor.kind.name, descriptor.name, descriptor.size) for descriptor in parsed.type_descriptors] == [
        (0x18, "ENUM", "color_e", 2),
    ]
    assert [(member.name, member.value, member.owner_type_index) for member in parsed.enum_members] == [
        ("RED", 1, 0x18),
        ("GREEN", 2, 0x18),
        ("BLUE", 4, 0x18),
    ]
    assert parsed.type_members == ()


def _build_tdinfo_image_with_version(major: int, minor: int) -> bytes:
    """Build a minimal TDS image with specified version."""
    data = bytearray(512)
    data[0:2] = b"MZ"
    struct.pack_into("<HH", data, 2, 512, 1)
    debug_offset = 512
    name_pool = b"func\x00"
    data.extend(b"\x00" * 96)
    struct.pack_into(
        "<HBBIHHHHH",
        data,
        debug_offset,
        0x52FB,
        minor,
        major,
        len(name_pool),
        2,
        0,
        0,
        1,
        0,
    )
    struct.pack_into("<H", data, debug_offset + 42, 0)
    sym_off = debug_offset + 44
    struct.pack_into("<HHHHB", data, sym_off, 1, 0, 0x10, 0x20, TDInfoSymbolClass.STATIC)
    data[-len(name_pool) :] = name_pool
    return bytes(data)


def test_tdinfo_version_identification_tds_28():
    """Test TDS 2.8 version identification (TLink 2.0a/2.0b)."""
    parsed = parse_tdinfo_exe_bytes(_build_tdinfo_image_with_version(2, 8))
    assert parsed is not None
    assert parsed.tds_version_str == "2.8"
    assert "2.0" in parsed.tlink_version_str


def test_tdinfo_version_identification_tds_29():
    """Test TDS 2.9 version identification (TLink 3.0/3.01)."""
    parsed = parse_tdinfo_exe_bytes(_build_tdinfo_image_with_version(2, 9))
    assert parsed is not None
    assert parsed.tds_version_str == "2.9"
    assert "3.0" in parsed.tlink_version_str


def test_tdinfo_version_identification_tds_30():
    """Test TDS 3.0 version identification (TLink 4.0)."""
    parsed = parse_tdinfo_exe_bytes(_build_tdinfo_image_with_version(3, 0))
    assert parsed is not None
    assert parsed.tds_version_str == "3.0"
    assert "4.0" in parsed.tlink_version_str


def test_tdinfo_version_identification_tds_310():
    """Test TDS 3.10 version identification (TLink 5.0/5.1)."""
    parsed = parse_tdinfo_exe_bytes(_build_tdinfo_image_with_version(3, 10))
    assert parsed is not None
    assert parsed.tds_version_str == "3.10"
    assert "5.0" in parsed.tlink_version_str


def test_tdinfo_version_identification_tds_41():
    """Test TDS 4.1 version identification (TLink 6.00/7.0a)."""
    parsed = parse_tdinfo_exe_bytes(_build_tdinfo_image_with_version(4, 1))
    assert parsed is not None
    assert parsed.tds_version_str == "4.1"
    assert "6.00" in parsed.tlink_version_str


def test_tdinfo_version_identification_tds_43():
    """Test TDS 4.3 version identification (TLink 7.1.30.1/7.1.32.2)."""
    parsed = parse_tdinfo_exe_bytes(_build_tdinfo_image_with_version(4, 3))
    assert parsed is not None
    assert parsed.tds_version_str == "4.3"
    assert "7.1" in parsed.tlink_version_str


def test_tdinfo_version_identification_unknown_version():
    """Test unknown TDS version returns unknown tlink version."""
    parsed = parse_tdinfo_exe_bytes(_build_tdinfo_image_with_version(9, 99))
    assert parsed is not None
    assert parsed.tds_version_str == "9.99"
    assert parsed.tlink_version_str == "unknown"


def test_tdinfo_coverage_offsets_attribute_to_their_segment():
    """Coverage-map boundaries are 1-based start indexes into the offsets
    table (observed RIPTIDE.EXE values: map starts 1,1164,... and offsets
    3,6,28,... — the first offsets belong to segment 1)."""
    map_data = struct.pack("<3H", 1, 1164, 2415)
    coverage_map = _parse_tdinfo_coverage_map(map_data, 0, 3)
    assert [entry.offset_index for entry in coverage_map] == [1, 1164, 2415]

    # Ordinals 1..1163 -> segment 1, 1164..2414 -> segment 2, 2415+ -> 3.
    offsets_data = struct.pack("<4H", 3, 6, 28, 35)
    padded = offsets_data + b"\x00" * (2415 * 2 - len(offsets_data))
    offsets = _parse_tdinfo_coverage_offsets(padded, 0, 2415, coverage_map)
    assert offsets[0].segment_index == 1
    assert offsets[1162].segment_index == 1
    assert offsets[1163].segment_index == 2
    assert offsets[2414].segment_index == 3
