from __future__ import annotations

import struct

from inertia.cli.codeview_nb02_nb04 import CodeViewSymbolType, parse_codeview_nb0204_bytes


def _pstr(text: str) -> bytes:
    raw = text.encode("ascii")
    return bytes([len(raw)]) + raw


def _symbol_record(record_type: int, payload: bytes) -> bytes:
    record = struct.pack("<HH", len(payload) + 2, record_type) + payload
    return record + (b"\x00" * ((4 - len(record) % 4) % 4))


def _build_nb04_image(subsections: list[tuple[int, int, bytes]]) -> bytes:
    data = bytearray(32)
    debug_base = len(data)
    data.extend(b"NB04" + b"\x00\x00\x00\x00")
    entries: list[tuple[int, int, int, int]] = []
    for subsection_type, module_index, blob in subsections:
        while len(data) % 4:
            data.append(0)
        lfo = len(data) - debug_base
        data.extend(blob)
        entries.append((subsection_type, module_index, lfo, len(blob)))

    while len(data) % 4:
        data.append(0)
    directory_lfo = len(data) - debug_base
    struct.pack_into("<I", data, debug_base + 4, directory_lfo)
    data.extend(struct.pack("<HHIII", 16, 12, len(entries), 0, 0))
    for entry in entries:
        data.extend(struct.pack("<HHII", *entry))

    trailer_offset = len(data)
    data.extend(b"NB04" + struct.pack("<I", trailer_offset + 8 - debug_base))
    return bytes(data)


def _build_cv4_image(signature: bytes, subsections: list[tuple[int, int, bytes]]) -> bytes:
    data = bytearray(32)
    debug_base = len(data)
    data.extend(signature + b"\x00\x00\x00\x00")
    entries: list[tuple[int, int, int, int]] = []
    for subsection_type, module_index, blob in subsections:
        while len(data) % 4:
            data.append(0)
        lfo = len(data) - debug_base
        data.extend(blob)
        entries.append((subsection_type, module_index, lfo, len(blob)))

    while len(data) % 4:
        data.append(0)
    directory_lfo = len(data) - debug_base
    struct.pack_into("<I", data, debug_base + 4, directory_lfo)
    data.extend(struct.pack("<HHIII", 16, 12, len(entries), 0, 0))
    for entry in entries:
        data.extend(struct.pack("<HHII", *entry))

    trailer_offset = len(data)
    data.extend(signature + struct.pack("<I", trailer_offset + 8 - debug_base))
    return bytes(data)


def _build_nb02_legacy_image(subsections: list[tuple[int, int, bytes]]) -> bytes:
    data = bytearray(32)
    debug_base = len(data)
    data.extend(b"NB02" + b"\x00\x00\x00\x00")
    entries: list[tuple[int, int, int, int]] = []
    for subsection_type, module_index, blob in subsections:
        lfo = len(data) - debug_base
        data.extend(blob)
        entries.append((subsection_type, module_index, lfo, len(blob)))

    directory_lfo = len(data) - debug_base
    struct.pack_into("<I", data, debug_base + 4, directory_lfo)
    data.extend(struct.pack("<H", len(entries)))
    for entry in entries:
        data.extend(struct.pack("<HHIH", *entry))

    trailer_offset = len(data)
    data.extend(b"NB02" + struct.pack("<I", trailer_offset + 8 - debug_base))
    return bytes(data)


def _nb00_type_record(*names: str) -> bytes:
    record = b"".join(bytes([0x82, len(name)]) + name.encode("ascii") for name in names)
    return b"\x00" + struct.pack("<H", len(record)) + record


def _nb00_field_record(fields: list[tuple[str, int]]) -> bytes:
    record = b"\x7f"
    for name, offset in fields:
        record += bytes([0x82, len(name)]) + name.encode("ascii") + bytes([0x88, offset])
    return b"\x00" + struct.pack("<H", len(record)) + record


def _cv4_type_record(leaf: int, payload: bytes) -> bytes:
    return struct.pack("<HH", len(payload) + 2, leaf) + payload


def _cv4_member(name: str, offset: int, type_index: int = 0x72) -> bytes:
    raw = name.encode("ascii")
    member = struct.pack("<HHHHB", 0x0406, type_index, 3, offset, len(raw)) + raw
    return member + bytes([0xF1]) * ((4 - len(member) % 4) % 4)


def test_parse_nb04_directory_symbols_stack_scope_and_lines():
    proc_payload = (
        struct.pack("<IIIHHHHHHB", 0, 0, 0, 0x24, 1, 0x20, 0x30, 2, 0x1234, 0)
        + _pstr("_main")
    )
    stack_payload = struct.pack("<hH", -2, 0x0011) + _pstr("local_i")
    data_payload = struct.pack("<HHH", 0x80, 3, 0x0011) + _pstr("global_value")
    symbols = (
        _symbol_record(CodeViewSymbolType.S_GPROC16, proc_payload)
        + _symbol_record(CodeViewSymbolType.S_BPREL16, stack_payload)
        + _symbol_record(CodeViewSymbolType.S_GDATA16, data_payload)
        + _symbol_record(CodeViewSymbolType.S_END, b"")
    )

    src = bytearray()
    src.extend(struct.pack("<HH", 1, 1))
    src.extend(struct.pack("<I", 20))
    src.extend(struct.pack("<II", 0x30, 0x54))
    src.extend(struct.pack("<H", 2))
    src.extend(struct.pack("<H", 0))
    file_table_offset = len(src)
    src.extend(struct.pack("<HI", 1, 0))
    line_base_patch_offset = len(src)
    src.extend(struct.pack("<I", 0))
    src.extend(struct.pack("<II", 0x30, 0x54))
    src.extend(_pstr("tiny.c"))
    line_table_offset = len(src)
    struct.pack_into("<I", src, line_base_patch_offset, line_table_offset)
    src.extend(struct.pack("<HHIIHH", 2, 2, 0x30, 0x34, 7, 8))
    assert file_table_offset == 20

    image = _build_nb04_image(
        [
            (0x0124, 1, symbols),
            (0x0127, 1, bytes(src)),
        ]
    )

    parsed = parse_codeview_nb0204_bytes(image, load_base_linear=0x1000)

    assert parsed is not None
    assert parsed.code_labels[0x1000 + (2 << 4) + 0x30] == "_main"
    assert parsed.data_labels[0x1000 + (3 << 4) + 0x80] == "global_value"
    assert parsed.procedures[0].length == 0x24
    assert parsed.procedures[0].extra["debug_start"] == 1
    assert parsed.stack_variables["_main"][0].name == "local_i"
    assert parsed.stack_variables["_main"][0].offset == -2
    assert parsed.source_files == ("tiny.c",)
    assert parsed.line_map[0x1000 + (2 << 4) + 0x30] == (7, 0)
    assert parsed.line_map[0x1000 + (2 << 4) + 0x34] == (8, 0)


def test_parse_nb04_legacy_directory_and_publics():
    public_blob = struct.pack("<HHHB", 0x20, 2, 0, 5) + b"_tick"
    image = _build_nb04_image([])
    debug_base = 32
    data = bytearray(image[: debug_base + 8])
    public_lfo = len(data) - debug_base
    data.extend(public_blob)
    directory_lfo = len(data) - debug_base
    struct.pack_into("<I", data, debug_base + 4, directory_lfo)
    data.extend(struct.pack("<H", 1))
    data.extend(struct.pack("<HHIH", 0x0122, 1, public_lfo, len(public_blob)))
    trailer_offset = len(data)
    data.extend(b"NB04" + struct.pack("<I", trailer_offset + 8 - debug_base))

    parsed = parse_codeview_nb0204_bytes(bytes(data), load_base_linear=0x1000)

    assert parsed is not None
    assert parsed.code_labels[0x1000 + (2 << 4) + 0x20] == "tick"


def test_parse_nb02_legacy_msc6_subsections_types_lines_and_identifiers():
    module_blob = struct.pack("<HHHHHBBB", 0, 0, 0x80, 0, 0, 1, 0, len("MEDIUM.C")) + b"MEDIUM.C"
    public_blob = struct.pack("<HHHB", 0x10, 0, 0, len("_accumulate_pairs")) + b"_accumulate_pairs"
    type_blob = _nb00_type_record("Pair") + _nb00_field_record([("left", 0), ("right", 2)])
    source_blob = _pstr("c:\\MEDIUM.C") + b"\x00\x00" + struct.pack("<HHHHH", 2, 17, 0x10, 22, 0x32)
    symbol_blob = b"\x10accumulate_pairs\x05pairs\x05count\x05total"

    image = _build_nb02_legacy_image(
        [
            (0x0101, 1, module_blob),
            (0x0102, 1, public_blob),
            (0x0103, 1, type_blob),
            (0x0109, 1, source_blob),
            (0x0104, 1, symbol_blob),
        ]
    )

    parsed = parse_codeview_nb0204_bytes(image, load_base_linear=0x1000)

    assert parsed is not None
    assert parsed.version == "NB02"
    assert parsed.modules == ("MEDIUM.C",)
    assert parsed.code_labels[0x1010] == "accumulate_pairs"
    assert parsed.source_files == ("c:\\MEDIUM.C",)
    assert parsed.line_map[0x1010] == (17, 0)
    assert parsed.line_map[0x1032] == (22, 0)
    assert parsed.type_record_names == ("Pair", "left", "right")
    assert [(member.name, member.offset) for member in parsed.type_members] == [("left", 0), ("right", 2)]
    assert parsed.debug_identifiers == ("accumulate_pairs", "pairs", "count", "total")


def test_parse_nb09_cv4_symbols_source_lines_and_type_names():
    proc_payload = (
        struct.pack("<IIIHHHHHHB", 0, 0, 0, 0x24, 1, 0x20, 0x30, 1, 0x1234, 0)
        + _pstr("helper")
    )
    stack_payload = struct.pack("<hH", -2, 0x0011) + _pstr("local_i")
    symbols = (
        b"\x01\x00\x00\x00"
        + _symbol_record(CodeViewSymbolType.S_GPROC16, proc_payload)
        + _symbol_record(CodeViewSymbolType.S_BPREL16, stack_payload)
        + _symbol_record(CodeViewSymbolType.S_END, b"")
    )

    src = bytearray()
    src.extend(struct.pack("<HH", 1, 1))
    src.extend(struct.pack("<I", 20))
    src.extend(struct.pack("<II", 0x30, 0x54))
    src.extend(struct.pack("<H", 1))
    src.extend(struct.pack("<H", 0))
    file_base = len(src)
    assert file_base == 20
    src.extend(struct.pack("<HHI", 1, 0, 0))
    line_base_patch = len(src) - 4
    src.extend(struct.pack("<II", 0x30, 0x54))
    src.extend(_pstr("z:\\tmp\\dbg.c"))
    while len(src) % 4:
        src.append(0)
    line_base = len(src)
    struct.pack_into("<I", src, line_base_patch, line_base)
    src.extend(struct.pack("<HHIIHH", 1, 2, 0x30, 0x34, 12, 13))

    type_blob = (
        b"\x01\x00\x00\x00"
        + _cv4_type_record(0x0204, _cv4_member("left", 0) + _cv4_member("right", 2))
        + _cv4_type_record(0x0005, b"\x02\x00\x00\x10\x00\x00\x00\x00\x00\x00\x04\x00" + _pstr("pair_s"))
    )
    image = _build_cv4_image(
        b"NB09",
        [
            (0x0125, 1, symbols),
            (0x0127, 1, bytes(src)),
            (0x012B, 0xFFFF, type_blob),
        ],
    )

    parsed = parse_codeview_nb0204_bytes(image, load_base_linear=0x1000)

    assert parsed is not None
    assert parsed.version == "NB09"
    assert parsed.code_labels[0x1000 + (1 << 4) + 0x30] == "helper"
    assert parsed.stack_variables["helper"][0].name == "local_i"
    assert parsed.stack_variables["helper"][0].offset == -2
    assert parsed.source_files == ("z:\\tmp\\dbg.c",)
    assert parsed.line_map[0x1000 + (1 << 4) + 0x30] == (12, 0)
    assert parsed.line_map[0x1000 + (1 << 4) + 0x34] == (13, 0)
    assert parsed.type_record_names == ("left", "right", "pair_s")
    assert [(member.name, member.offset, member.owner_type_index) for member in parsed.type_members] == [
        ("left", 0, 0x1000),
        ("right", 2, 0x1000),
    ]


def test_parse_nb08_uses_cv4_directory_reader():
    symbols = _symbol_record(
        CodeViewSymbolType.S_PUB16,
        struct.pack("<HHH", 0x40, 1, 0x0011) + _pstr("_main"),
    )
    image = _build_cv4_image(b"NB08", [(0x0125, 1, b"\x01\x00\x00\x00" + symbols)])

    parsed = parse_codeview_nb0204_bytes(image, load_base_linear=0x1000)

    assert parsed is not None
    assert parsed.version == "NB08"
    assert parsed.code_labels[0x1000 + (1 << 4) + 0x40] == "main"
