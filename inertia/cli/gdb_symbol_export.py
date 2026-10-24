"""Export MZ-EXE embedded debug info (NBxx CodeView / TDINFO) as an ELF32 symbol file.

Layer: CLI/fallback/reporting. Responsibility: translate parsed debug metadata into a
gdb-loadable ``.symtab`` so remote real-mode debugging gets named functions and
data labels. Optional evidence only — never required for decompilation.

Usage::

    python3 -m inertia.cli.gdb_symbol_export F14R.EXE --base 0x1a10 -o f14r.elf
    (gdb) add-symbol-file f14r.elf 0

``--base`` is the linear address where the MZ image is loaded in the emulator
(``(load_segment << 4)``); pass ``--base 0`` to emit image-relative symbols and
let ``add-symbol-file`` relocate instead.
"""

from __future__ import annotations

import argparse
import os
import struct
from dataclasses import dataclass, field
from enum import Enum

from .codeview_nb02_nb04 import parse_codeview_nb0204_bytes
from .turbo_debug_tdinfo import parse_tdinfo_exe_bytes


class GdbSymbolKind(Enum):
    """ELF STT_* binding for exported addresses."""

    FUNC = "func"
    OBJECT = "object"


@dataclass(frozen=True)
class GdbSymbol:
    """One absolute-address symbol destined for the ELF ``.symtab``."""

    address: int
    name: str
    kind: GdbSymbolKind


@dataclass(frozen=True)
class GdbSymbolTable:
    """Collected symbols plus which debug payload produced them.

    ``line_rows`` are ``(address, source_line, file_index)`` where
    ``file_index`` is a 0-based index into ``source_files`` or ``-1`` when the
    owning file could not be decoded.
    """

    symbols: tuple[GdbSymbol, ...]
    source: str
    diagnostics: tuple[str, ...] = field(default_factory=tuple)
    line_rows: tuple[tuple[int, int, int], ...] = ()
    source_files: tuple[str, ...] = ()


def _sanitise_name(name: str) -> str:
    """Strip leading underscores/control chars so names read naturally in gdb."""
    return name.lstrip("_").strip("\x00").strip()


def _merge_labels(
    symbols: dict[int, GdbSymbol],
    code_labels: dict[int, str],
    data_labels: dict[int, str],
) -> None:
    """Merge parser label maps into the symbol table, first source winning."""
    for addr, name in code_labels.items():
        clean = _sanitise_name(name)
        if clean:
            symbols.setdefault(addr, GdbSymbol(addr, clean, GdbSymbolKind.FUNC))
    for addr, name in data_labels.items():
        clean = _sanitise_name(name)
        if clean:
            symbols.setdefault(addr, GdbSymbol(addr, clean, GdbSymbolKind.OBJECT))


def collect_exe_debug_symbols(data: bytes, load_base_linear: int = 0) -> GdbSymbolTable:
    """Parse CodeView NBxx then TDINFO payloads and merge their label maps.

    CodeView is preferred; TDINFO fills any gaps it leaves. Returns an empty
    table (source ``"none"``) when the image carries neither payload.
    """
    symbols: dict[int, GdbSymbol] = {}
    sources: list[str] = []
    diagnostics: list[str] = []

    line_rows: tuple[tuple[int, int, int], ...] = ()
    source_files: tuple[str, ...] = ()

    cv = parse_codeview_nb0204_bytes(data, load_base_linear=load_base_linear)
    if cv is not None:
        sources.append(f"CodeView {cv.version}")
        _merge_labels(symbols, cv.code_labels, cv.data_labels)
        line_rows = tuple(
            (addr, line, fidx)
            for addr, (line, fidx) in sorted(cv.line_map.items())
        )
        source_files = cv.source_files
        diagnostics.append(
            f"codeview: {len(cv.code_labels)} code, {len(cv.data_labels)} data, "
            f"{len(cv.line_map)} line entries, {len(cv.segments)} segments"
        )

    td = parse_tdinfo_exe_bytes(data, load_base_linear=load_base_linear)
    if td is not None:
        sources.append("TDINFO")
        _merge_labels(symbols, td.code_labels, td.data_labels)
        diagnostics.append(
            f"tdinfo: {len(td.code_labels)} code, {len(td.data_labels)} data"
        )

    ordered = tuple(sorted(symbols.values(), key=lambda s: (s.address, s.name)))
    return GdbSymbolTable(
        symbols=ordered,
        source="+".join(sources) if sources else "none",
        diagnostics=tuple(diagnostics),
        line_rows=line_rows,
        source_files=source_files,
    )


_ST_TYPE = {GdbSymbolKind.OBJECT: 1, GdbSymbolKind.FUNC: 2}
_TEXT_SHNDX = 1


def _uleb128(value: int) -> bytes:
    """Encode an unsigned LEB128 integer."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _sleb128(value: int) -> bytes:
    """Encode a signed LEB128 integer."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        done = (value == 0 and not byte & 0x40) or (value == -1 and byte & 0x40)
        out.append(byte if done else byte | 0x80)
        if done:
            return bytes(out)


def build_dwarf_debug_line(
    line_rows: tuple[tuple[int, int, int], ...],
    source_files: tuple[str, ...],
) -> bytes:
    """Emit one DWARF v2 ``.debug_line`` compilation unit.

    Rows are ``(address, line, file_index)`` sorted by address; ``file_index``
    is a 0-based index into ``source_files`` or ``-1`` for an undecoded file.
    Explicit opcodes (set_address/set_file/advance_line/copy) are used instead
    of special opcodes for simplicity and unbounded deltas.
    """
    file_names = ("<unknown>", *source_files)
    names = b"\x00"  # empty include_directories table
    for fname in file_names:
        names += (
            fname.encode("ascii", errors="replace")
            + b"\x00"
            + _uleb128(0)
            + _uleb128(0)
            + _uleb128(0)
        )
    names += b"\x00"  # file_names terminator

    program = bytearray()
    cur_file, cur_line = 1, 1
    for addr, line, fidx in line_rows:
        program += b"\x00" + _uleb128(5) + b"\x02" + struct.pack("<I", addr & 0xFFFFFFFF)
        fno = fidx + 2 if fidx >= 0 else 1
        if fno != cur_file:
            program += b"\x04" + _uleb128(fno)
            cur_file = fno
        delta = line - cur_line
        if delta:
            program += b"\x03" + _sleb128(delta)
            cur_line = line
        program += b"\x01"  # DW_LNS_copy
    if line_rows:
        program += (
            b"\x00" + _uleb128(5) + b"\x02"
            + struct.pack("<I", (line_rows[-1][0] + 1) & 0xFFFFFFFF)
        )
    program += b"\x00" + _uleb128(1) + b"\x01"  # DW_LNE_end_sequence

    header_body = (
        struct.pack("<BBbBB", 1, 1, -5, 14, 13)
        + bytes([0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1])
        + names
    )
    unit = struct.pack("<HI", 2, len(header_body)) + header_body + bytes(program)
    return struct.pack("<I", len(unit)) + unit


def build_dwarf_debug_abbrev() -> bytes:
    """One-abbreviation ``.debug_abbrev`` table for the skeleton CU DIE."""
    # abbrev 1: DW_TAG_compile_unit, no children
    attrs = (
        (0x03, 0x08),  # DW_AT_name,        DW_FORM_string
        (0x11, 0x01),  # DW_AT_low_pc,      DW_FORM_addr
        (0x12, 0x01),  # DW_AT_high_pc,     DW_FORM_addr
        (0x10, 0x06),  # DW_AT_stmt_list,   DW_FORM_data4
        (0x25, 0x08),  # DW_AT_producer,    DW_FORM_string
        (0x13, 0x05),  # DW_AT_language,    DW_FORM_data2
    )
    body = b""
    for attr, form in attrs:
        body += _uleb128(attr) + _uleb128(form)
    return _uleb128(1) + _uleb128(0x11) + b"\x00" + body + b"\x00\x00" + b"\x00"


def build_dwarf_debug_info(name: str, low_pc: int, high_pc: int) -> bytes:
    """Skeleton DWARF v2 ``.debug_info`` anchoring ``.debug_line`` for gdb.

    A single ``DW_TAG_compile_unit`` covering ``[low_pc, high_pc)`` with
    ``DW_AT_stmt_list = 0`` so gdb resolves ``info line`` against our emitted
    line program.
    """
    die = (
        _uleb128(1)
        + name.encode("ascii", errors="replace") + b"\x00"
        + struct.pack("<I", low_pc & 0xFFFFFFFF)
        + struct.pack("<I", high_pc & 0xFFFFFFFF)
        + struct.pack("<I", 0)  # stmt_list: start of .debug_line
        + b"inertia_decompiler NB/TD export\x00"
        + struct.pack("<H", 0x0001)  # DW_LANG_C89
    )
    body = die + b"\x00"  # root DIE + null DIE ending its children list
    unit = (
        struct.pack("<HIB", 2, 0, 4)  # version, abbrev_offset, addr_size
        + body
    )
    return struct.pack("<I", len(unit)) + unit


def build_elf32_symtab(
    symbols: tuple[GdbSymbol, ...],
    debug_line: bytes = b"",
    debug_info: bytes = b"",
    debug_abbrev: bytes = b"",
) -> bytes:
    """Serialise symbols into a minimal ELF32 relocatable object.

    Sections: null, ``.text`` (SHT_NOBITS, allocatable), ``.symtab``,
    ``.strtab``, optional ``.debug_line``/``.debug_info``/``.debug_abbrev``,
    ``.shstrtab``. Symbols are ``.text``-relative so
    ``add-symbol-file FILE <text_addr>`` relocates them when ``--base 0``
    was used, and keeps baked addresses when the text address is 0.
    DWARF payloads use the same address convention so relocation is
    consistent between ``info symbol`` and ``info line``.
    """
    strtab = b"\x00"
    name_offsets: list[int] = []
    for sym in symbols:
        name_offsets.append(len(strtab))
        strtab += sym.name.encode("ascii", errors="replace") + b"\x00"

    symtab = b"\x00" * 16  # mandatory null symbol
    for sym, name_off in zip(symbols, name_offsets, strict=True):
        st_info = (1 << 4) | _ST_TYPE[sym.kind]  # STB_GLOBAL | STT_*
        symtab += struct.pack(
            "<IIIBBH", name_off, sym.address & 0xFFFFFFFF, 0, st_info, 0,
            _TEXT_SHNDX
        )

    shstrtab = (
        b"\x00.text\x00.symtab\x00.strtab\x00.debug_line\x00"
        b".debug_info\x00.debug_abbrev\x00.shstrtab\x00"
    )
    name_text = shstrtab.index(b".text")
    name_symtab = shstrtab.index(b".symtab")
    name_strtab = shstrtab.index(b".strtab")
    name_debug_line = shstrtab.index(b".debug_line")
    name_debug_info = shstrtab.index(b".debug_info")
    name_debug_abbrev = shstrtab.index(b".debug_abbrev")
    name_shstrtab = shstrtab.index(b".shstrtab")

    ehdr_size = 52
    off_symtab = ehdr_size
    off_strtab = off_symtab + len(symtab)
    cursor = (off_strtab + len(strtab) + 3) & ~3

    def shdr(name: int, shtype: int, flags: int, offset: int, size: int,
             link: int = 0, info: int = 0, align: int = 4, entsize: int = 0) -> bytes:
        return struct.pack(
            "<IIIIIIIIII", name, shtype, flags, 0, offset, size, link, info,
            align, entsize
        )

    debug_blobs = [
        (name_debug_line, debug_line),
        (name_debug_info, debug_info),
        (name_debug_abbrev, debug_abbrev),
    ]
    blob_parts: list[tuple[int, bytes]] = []  # (offset, data) after strtab
    extra_shdrs: list[bytes] = []
    for sec_name, payload in debug_blobs:
        if not payload:
            continue
        blob_parts.append((cursor, payload))
        extra_shdrs.append(shdr(sec_name, 1, 0, cursor, len(payload), align=1))
        cursor += len(payload)
    off_shstrtab = cursor
    off_shoff = (off_shstrtab + len(shstrtab) + 3) & ~3

    text_size = (max((s.address for s in symbols), default=0) + 1) & 0xFFFFFFFF

    sections = [
        b"\x00" * 40,
        shdr(name_text, 8, 0x6, 0, text_size, align=16),  # NOBITS ALLOC|EXEC
        shdr(name_symtab, 2, 0, off_symtab, len(symtab),
             link=3, info=1, entsize=16),
        shdr(name_strtab, 3, 0, off_strtab, len(strtab), align=1),
        *extra_shdrs,
        shdr(name_shstrtab, 3, 0, off_shstrtab, len(shstrtab), align=1),
    ]
    section_headers = b"".join(sections)

    ehdr = struct.pack(
        "<16sHHIIIIIHHHHHH",
        b"\x7fELF\x01\x01\x01" + b"\x00" * 9,
        1,  # ET_REL
        3,  # EM_386
        1,  # EV_CURRENT
        0,  # e_entry
        0,  # e_phoff
        off_shoff,
        0,  # e_flags
        ehdr_size,
        0,
        0,
        40,  # e_shentsize
        len(sections),  # e_shnum
        len(sections) - 1,  # e_shstrndx
    )
    blob = ehdr + symtab + strtab
    for part_offset, payload in blob_parts:
        blob += b"\x00" * (part_offset - len(blob))
        blob += payload
    blob += shstrtab
    blob += b"\x00" * (off_shoff - len(blob))
    return blob + section_headers


def write_elf32_symtab(
    path: str,
    symbols: tuple[GdbSymbol, ...],
    debug_line: bytes = b"",
    debug_info: bytes = b"",
    debug_abbrev: bytes = b"",
) -> None:
    """Write ``build_elf32_symtab`` output to ``path``."""
    with open(path, "wb") as handle:
        handle.write(
            build_elf32_symtab(symbols, debug_line, debug_info, debug_abbrev)
        )


def main(argv: list[str] | None = None) -> int:
    """CLI entry: export an MZ-EXE's embedded debug info to an ELF symbol file."""
    parser = argparse.ArgumentParser(
        description="Export NBxx/TDINFO debug info from an MZ EXE as an ELF32 symtab."
    )
    parser.add_argument("exe", help="MZ executable containing NBxx or TDINFO")
    parser.add_argument(
        "--base",
        type=lambda s: int(s, 0),
        default=0,
        help="linear address where the image is loaded (default 0 = image-relative)",
    )
    parser.add_argument("-o", "--output", required=True, help="output ELF path")
    parser.add_argument(
        "--no-lines",
        action="store_true",
        help="omit the .debug_line section (line info needs a baked --base)",
    )
    args = parser.parse_args(argv)

    with open(args.exe, "rb") as handle:
        data = handle.read()
    table = collect_exe_debug_symbols(data, load_base_linear=args.base)
    for line in table.diagnostics:
        print(line)
    if not table.symbols:
        print(f"no debug info found in {args.exe}")
        return 1
    debug_line = b""
    debug_info = b""
    debug_abbrev = b""
    if not args.no_lines and table.line_rows:
        debug_line = build_dwarf_debug_line(table.line_rows, table.source_files)
        addrs = [s.address for s in table.symbols] + [r[0] for r in table.line_rows]
        debug_info = build_dwarf_debug_info(
            os.path.basename(args.exe), min(addrs), max(addrs) + 1
        )
        debug_abbrev = build_dwarf_debug_abbrev()
    write_elf32_symtab(args.output, table.symbols, debug_line, debug_info, debug_abbrev)
    print(f"wrote {len(table.symbols)} symbols ({table.source}) to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
