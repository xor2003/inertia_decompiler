from __future__ import annotations

import struct

from inertia.cli.codeview_nb00 import parse_codeview_nb00_bytes


def _pstr(text: str) -> bytes:
    raw = text.encode("ascii")
    return bytes([len(raw)]) + raw


def _build_nb00_image(subsections: list[tuple[int, int, bytes]]) -> bytes:
    data = bytearray(32)
    debug_base = len(data)
    data.extend(b"NB00" + b"\x00\x00\x00\x00")
    entries: list[tuple[int, int, int, int]] = []
    for subsection_type, module_index, blob in subsections:
        lfo = len(data) - debug_base
        data.extend(blob)
        entries.append((subsection_type, module_index, lfo, len(blob)))

    directory_lfo = len(data) - debug_base
    struct.pack_into("<I", data, debug_base + 4, directory_lfo)
    data.extend(struct.pack("<H", len(entries)))
    for entry in entries:
        data.extend(struct.pack("<HHLH", *entry))

    trailer_offset = len(data)
    data.extend(b"NB00" + struct.pack("<I", trailer_offset + 8 - debug_base))
    return bytes(data)


def test_parse_codeview_nb00_type_subsection():
    data = bytearray(64)
    debug_base = 16
    subdir_offset = 8
    data[debug_base : debug_base + 4] = b"NB00"
    struct.pack_into("<I", data, debug_base + 4, subdir_offset)
    subdir = debug_base + subdir_offset
    struct.pack_into("<H", data, subdir, 1)
    struct.pack_into("<HHLH", data, subdir + 2, 0x103, 1, 20, 8)
    type_blob = bytes([1]) + struct.pack("<H", 5) + bytes([0x8D, 3]) + b"foo"
    data[debug_base + 20 : debug_base + 20 + len(type_blob)] = type_blob
    data.extend(b"NB00" + struct.pack("<I", len(data) - debug_base))

    parsed = parse_codeview_nb00_bytes(bytes(data))

    assert parsed is not None
    assert len(parsed.type_definitions) == 1
    assert parsed.type_definitions[0].index == 0x200
    assert parsed.type_definitions[0].leaves[0].kind == "string"
    assert parsed.type_definitions[0].leaves[0].value == "foo"
    assert parsed.type_record_names == ("foo",)


def test_parse_codeview_nb00_decodes_msc51_name_and_offset_leaves():
    data = bytearray(192)
    debug_base = 16
    subdir_offset = 8
    data[debug_base : debug_base + 4] = b"NB00"
    struct.pack_into("<I", data, debug_base + 4, subdir_offset)
    subdir = debug_base + subdir_offset
    field_record = bytes([0x7F, 0x82, 4]) + b"left" + bytes([0x88, 0, 0x82, 5]) + b"right" + bytes([0x88, 2])
    type_blob = bytes([1]) + struct.pack("<H", len(field_record)) + field_record
    struct.pack_into("<H", data, subdir, 1)
    struct.pack_into("<HHLH", data, subdir + 2, 0x103, 1, 32, len(type_blob))
    data[debug_base + 32 : debug_base + 32 + len(type_blob)] = type_blob
    data.extend(b"NB00" + struct.pack("<I", len(data) - debug_base))

    parsed = parse_codeview_nb00_bytes(bytes(data))

    assert parsed is not None
    assert parsed.type_record_names == ("left", "right")
    assert [(member.name, member.offset, member.owner_type_index) for member in parsed.type_members] == [
        ("left", 0, 0x200),
        ("right", 2, 0x200),
    ]
    leaves = parsed.type_definitions[0].leaves
    assert [leaf.value for leaf in leaves if leaf.kind == "string"] == ["left", "right"]
    assert [leaf.value for leaf in leaves if leaf.kind == "uint8"] == [0, 2]


def test_parse_codeview_nb00_source_lines_and_symbol_identifiers():
    module_blob = struct.pack("<HHHHHBBB", 0, 0, 0x80, 0, 0, 1, 0, len("C:\\DBG.OBJ")) + b"C:\\DBG.OBJ"
    source_blob = _pstr("c:\\DBG.C") + struct.pack("<HHHHH", 2, 16, 0x10, 17, 0x20)
    symbol_blob = b"\x06helper\x01p\x05count\x01i\x05total\x04main\x06result"

    image = _build_nb00_image(
        [
            (0x0101, 1, module_blob),
            (0x0104, 1, symbol_blob),
            (0x0105, 1, source_blob),
        ]
    )

    parsed = parse_codeview_nb00_bytes(image, load_base_linear=0x1000)

    assert parsed is not None
    assert parsed.source_files == ("c:\\DBG.C",)
    assert parsed.line_map[0x1010] == (16, 0)
    assert parsed.line_map[0x1020] == (17, 0)
    assert parsed.debug_identifiers == ("helper", "p", "count", "i", "total", "main", "result")
