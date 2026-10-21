from __future__ import annotations

import struct

from inertia.cli.gdb_symbol_export import (
    GdbSymbol,
    GdbSymbolKind,
    build_elf32_symtab,
    collect_exe_debug_symbols,
)
from tests.cli.test_x86_16_codeview_nb0204 import _build_cv4_image


def _cv_image_with_pub() -> bytes:
    from inertia.cli.codeview_nb02_nb04 import CodeViewSymbolType
    from tests.cli.test_x86_16_codeview_nb0204 import _pstr, _symbol_record

    pubs = _symbol_record(
        CodeViewSymbolType.S_PUB16,
        struct.pack("<HHH", 0x40, 1, 0x0011) + _pstr("_func_one"),
    )
    return _build_cv4_image(b"NB02", [(0x0124, 1, b"\x01\x00\x00\x00" + pubs)])


def test_collect_symbols_from_codeview_image() -> None:
    table = collect_exe_debug_symbols(_cv_image_with_pub(), load_base_linear=0)
    assert table.source == "CodeView NB02"
    assert len(table.symbols) == 1
    sym = table.symbols[0]
    assert sym.name == "func_one"
    assert sym.address == (1 << 4) + 0x40
    assert sym.kind is GdbSymbolKind.FUNC


def test_collect_symbols_empty_for_plain_mz() -> None:
    table = collect_exe_debug_symbols(b"MZ" + b"\x00" * 64)
    assert table.source == "none"
    assert table.symbols == ()


def test_elf32_symtab_roundtrips_through_readelf_layout() -> None:
    symbols = (
        GdbSymbol(0x1234, "alpha", GdbSymbolKind.FUNC),
        GdbSymbol(0x5678, "beta", GdbSymbolKind.OBJECT),
    )
    blob = build_elf32_symtab(symbols)

    assert blob[:4] == b"\x7fELF"
    assert struct.unpack_from("<H", blob, 16)[0] == 1  # ET_REL
    shoff = struct.unpack_from("<I", blob, 32)[0]
    assert shoff + 5 * 40 <= len(blob)

    # .text must be loadable (SHT_NOBITS + ALLOC) or gdb ignores the file
    text_type, text_flags = struct.unpack_from("<II", blob, shoff + 40 + 4)
    assert text_type == 8 and text_flags & 0x2

    sym_off = struct.unpack_from("<I", blob, shoff + 80 + 16)[0]
    sym_size = struct.unpack_from("<I", blob, shoff + 80 + 20)[0]
    assert sym_size == (1 + len(symbols)) * 16

    str_off = struct.unpack_from("<I", blob, shoff + 120 + 16)[0]
    entries = [struct.unpack_from("<IIIBBH", blob, sym_off + 16 * (i + 1)) for i in range(2)]
    names = [
        blob[str_off + e[0] : blob.index(b"\x00", str_off + e[0])].decode()
        for e in entries
    ]
    assert names == ["alpha", "beta"]
    assert [e[1] for e in entries] == [0x1234, 0x5678]
    assert entries[0][3] == (1 << 4) | 2  # GLOBAL FUNC
    assert entries[1][3] == (1 << 4) | 1  # GLOBAL OBJECT
    assert all(e[5] == 1 for e in entries)  # .text-relative


def test_dwarf_sections_and_line_program_decode() -> None:
    from inertia.cli.gdb_symbol_export import (
        build_dwarf_debug_abbrev,
        build_dwarf_debug_info,
        build_dwarf_debug_line,
    )

    rows = ((0x100, 7, 0), (0x104, 8, 0), (0x110, 3, -1))
    line = build_dwarf_debug_line(rows, ("a.c",))
    total = struct.unpack_from("<I", line, 0)[0]
    assert total + 4 == len(line)
    assert struct.unpack_from("<H", line, 4)[0] == 2  # DWARF v2

    info = build_dwarf_debug_info("x.exe", 0x100, 0x200)
    abbrev = build_dwarf_debug_abbrev()
    blob = build_elf32_symtab(
        (GdbSymbol(0x100, "f", GdbSymbolKind.FUNC),),
        debug_line=line,
        debug_info=info,
        debug_abbrev=abbrev,
    )
    # sections must all appear in .shstrtab
    assert b".debug_line\x00" in blob
    assert b".debug_info\x00" in blob
    assert b".debug_abbrev\x00" in blob
    shoff = struct.unpack_from("<I", blob, 32)[0]
    shnum = struct.unpack_from("<H", blob, 48)[0]
    assert shnum == 8
    assert shoff + shnum * 40 <= len(blob)
