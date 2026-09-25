"""CodeView NB02/NB04/NB08/NB09 parser.

Layer: Optional evidence/reporting.
Responsibility: parse CodeView debug records into optional labels and diagnostics.
Forbidden: requiring debug symbols for arguments, types, control flow, or validation success.

Minimal implementation focused on 80/20 value:
- Function names (from SST_PUBLIC and S_GPROC16)
- Stack variables (from S_BPREL16)
- Local/global variables (from S_LDATA16)
- Line number mapping (from SST_SRCMODULE)

References:
- LLVM llvm/include/llvm/DebugInfo/CodeView/
- Wine dlls/dbghelp/
- Open Watcom debugger
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any

from . import codeview_nb00 as _nb00


class CodeViewSymbolType(IntEnum):
    """CodeView symbol record types used by optional debug metadata."""

    S_BPREL16 = 0x0100  # Stack-relative variable (BP-relative) 16-bit
    S_LDATA16 = 0x0101  # Local data
    S_GDATA16 = 0x0102  # Global data
    S_PUB16 = 0x0103  # Public symbol
    S_LPROC16 = 0x0104  # Local procedure (16-bit)
    S_GPROC16 = 0x0105  # Global procedure (16-bit)
    S_END = 0x0006  # End of procedure/scope
    S_RETURN = 0x4609  # Return symbol


_LEGACY_PROC16_TYPES = {0x0110, 0x0111}
_PROC16_TYPES = {CodeViewSymbolType.S_GPROC16, CodeViewSymbolType.S_LPROC16, *_LEGACY_PROC16_TYPES}
_DATA16_TYPES = {CodeViewSymbolType.S_GDATA16, CodeViewSymbolType.S_LDATA16}


class CodeViewSubsectionType(IntEnum):
    """CodeView subsection types found in NB02/NB04 directory entries."""

    SST_MODULE = 0x0120
    SST_TYPES = 0x0121
    SST_PUBLIC = 0x0122
    SST_PUBLIC_SYM = 0x0223
    SST_SYMBOLS = 0x0124
    SST_ALIGN_SYM = 0x0125
    SST_SRCMODULE = 0x0127
    SST_SRCMODULE_FILE = 0x0211
    SST_LIBRARIES = 0x0180
    SST_GLOBAL_SYM = 0x0220
    SST_GLOBAL_PUB = 0x0221
    SST_GLOBAL_TYPES = 0x0222


_PUBLIC_SUBSECTIONS = {
    CodeViewSubsectionType.SST_PUBLIC,
    CodeViewSubsectionType.SST_PUBLIC_SYM,
    CodeViewSubsectionType.SST_GLOBAL_PUB,
}
_SYMBOL_SUBSECTIONS = {
    CodeViewSubsectionType.SST_SYMBOLS,
    CodeViewSubsectionType.SST_ALIGN_SYM,
    CodeViewSubsectionType.SST_GLOBAL_SYM,
    0x0129,
}
_HASHED_PUBLIC_SUBSECTIONS = {0x012A}
_CV4_TYPE_SUBSECTIONS = {0x012B}
_CV4_FIRST_TYPE_INDEX = 0x1000
_CV4_LF_FIELDLIST = 0x0204
_CV4_LF_MEMBER = 0x0406


@dataclass(frozen=True)
class CodeViewSymbol:
    """Parsed CodeView symbol retained as optional label or debug evidence."""

    type_code: int
    name: str
    offset: int  # Offset within segment
    segment: int | None
    length: int | None = None  # For procedures
    data_type: int | None = None  # Type index
    extra: dict[str, Any] = field(default_factory=dict)

    def is_procedure(self) -> bool:
        """Return whether this symbol describes a 16-bit procedure."""
        return self.type_code in _PROC16_TYPES

    def is_stack_var(self) -> bool:
        """Return whether this symbol describes a BP-relative stack variable."""
        return self.type_code == CodeViewSymbolType.S_BPREL16

    def is_data_symbol(self) -> bool:
        """Return whether this symbol describes a local or global data object."""
        return self.type_code in {CodeViewSymbolType.S_GDATA16, CodeViewSymbolType.S_LDATA16}


@dataclass(frozen=True)
class CodeViewNB0204Info:
    """Parsed CodeView NB02/NB04/NB08/NB09 debug metadata."""

    version: str  # "NB02", "NB04", "NB05", "NB08", or "NB09"
    debug_base: int
    code_labels: dict[int, str] = field(default_factory=dict)  # address -> function name
    data_labels: dict[int, str] = field(default_factory=dict)  # address -> data name
    procedures: tuple[CodeViewSymbol, ...] = ()
    stack_variables: dict[str, list[CodeViewSymbol]] = field(default_factory=dict)  # func_name -> vars
    line_map: dict[int, tuple[int, int]] = field(default_factory=dict)  # code_addr -> (source_line, col)
    modules: tuple[str, ...] = ()
    source_files: tuple[str, ...] = ()
    type_record_names: tuple[str, ...] = ()
    type_members: tuple[_nb00.CodeViewNB00TypeMember, ...] = ()
    debug_identifiers: tuple[str, ...] = ()


def find_codeview_nb0204(data: bytes, *, signatures: list[bytes] | None = None) -> tuple[str, int] | None:
    """Find CodeView NB02/NB04 debug info trailer in binary.

    Args:
        data: Binary file contents
        signatures: List of signatures to search for (default: [b'NB02', b'NB04', b'NB05', b'NB08', b'NB09'])

    Returns:
        (signature, debug_base) or None if not found
    """
    if signatures is None:
        signatures = [b"NB09", b"NB08", b"NB04", b"NB02", b"NB05"]

    # Search from end backwards (trailer is typically at end of debug info)
    for trailer_offset in range(len(data) - 8, max(-1, len(data) - 512), -1):
        if trailer_offset + 8 > len(data):
            continue

        for sig in signatures:
            if data[trailer_offset : trailer_offset + 4] == sig:
                # Read offset to start of CV header
                try:
                    debug_offset = struct.unpack_from("<I", data, trailer_offset + 4)[0]
                    debug_base = trailer_offset + 8 - debug_offset

                    # Validate: check that debug_base points to a valid CV header
                    if 0 <= debug_base < len(data) and debug_base + 8 <= len(data):
                        root_sig = data[debug_base : debug_base + 4]
                        if root_sig == sig:
                            return sig.decode("ascii", errors="ignore"), debug_base
                except (struct.error, ValueError):
                    continue

    return None


def parse_codeview_nb0204(binary_path: Path, *, load_base_linear: int = 0) -> CodeViewNB0204Info | None:
    """Parse CodeView NB02/NB04 from binary file."""
    try:
        data = binary_path.read_bytes()
        return parse_codeview_nb0204_bytes(data, load_base_linear=load_base_linear)
    except (OSError, ValueError):
        return None


@dataclass(slots=True)
class _NB0204Collections8616:
    """Accumulating collections for NB02/NB04 subsection parsing."""

    code_labels: dict[int, str] = field(default_factory=dict)
    data_labels: dict[int, str] = field(default_factory=dict)
    procedures: list[CodeViewSymbol] = field(default_factory=list)
    stack_variables: dict[str, list[CodeViewSymbol]] = field(default_factory=dict)
    modules: list[str] = field(default_factory=list)
    source_files: list[str] = field(default_factory=list)
    line_map: dict[int, tuple[int, int]] = field(default_factory=dict)
    type_record_names: list[str] = field(default_factory=list)
    type_members: list[_nb00.CodeViewNB00TypeMember] = field(default_factory=list)
    debug_identifiers: list[str] = field(default_factory=list)
    legacy_modules: dict[int, _nb00.CodeViewNB00Module] = field(default_factory=dict)
    legacy_publics: list[_nb00.CodeViewNB00PublicSymbol] = field(default_factory=list)


def _parse_label_subsection_8616(
    sink: _NB0204Collections8616,
    subsection_type: int,
    blob: bytes,
    load_base_linear: int,
) -> bool:
    """Parse label/symbol producing subsections; return False if not handled."""
    if subsection_type in _PUBLIC_SUBSECTIONS:
        _parse_public_symbols(blob, sink.code_labels, sink.data_labels, load_base_linear)
        return True
    if subsection_type in _HASHED_PUBLIC_SUBSECTIONS:
        sink.debug_identifiers.extend(_parse_legacy_symbol_names(blob))
        return True
    if subsection_type in _SYMBOL_SUBSECTIONS:
        syms = _parse_symbol_records(blob)
        _materialize_symbol_records(
            syms, sink.code_labels, sink.data_labels, sink.procedures, sink.stack_variables, load_base_linear
        )
        sink.debug_identifiers.extend(_parse_legacy_symbol_names(blob))
        return True
    if subsection_type == CodeViewSubsectionType.SST_MODULE:
        # Extract module name
        sink.modules.extend(_parse_module_names(blob))
        return True
    if subsection_type == CodeViewSubsectionType.SST_SRCMODULE:
        parsed_source_files, parsed_line_map = _parse_source_module_lines(
            blob, load_base_linear=load_base_linear
        )
        sink.source_files.extend(parsed_source_files)
        sink.line_map.update(parsed_line_map)
        return True
    return False


def _parse_legacy_subsection_8616(
    sink: _NB0204Collections8616,
    entry: dict[str, Any],
    subsection_type: int,
    blob: bytes,
    load_base_linear: int,
) -> None:
    """Parse legacy NB00-format subsections into the sink."""
    if subsection_type == _nb00.CodeViewSubsectionType.MODULES:
        module = _nb00._parse_module_subsection(entry["module"], blob)
        sink.legacy_modules[module.module_index] = module
        if module.name:
            sink.modules.append(module.name)
    elif subsection_type == _nb00.CodeViewSubsectionType.PUBLICS:
        sink.legacy_publics.extend(_nb00._parse_publics_subsection(entry["module"], blob))
    elif subsection_type == _nb00.CodeViewSubsectionType.TYPE:
        definitions = _nb00._parse_type_subsection(blob)
        sink.type_record_names.extend(_nb00._collect_type_record_names(definitions))
        sink.type_members.extend(_nb00._collect_type_members(definitions))
    elif subsection_type in _CV4_TYPE_SUBSECTIONS:
        sink.type_record_names.extend(_parse_legacy_symbol_names(blob))
        sink.type_members.extend(_collect_cv4_type_members(blob))
    elif subsection_type in {_nb00.CodeViewSubsectionType.SRCLINES, _nb00.CodeViewSubsectionType.SRCLNSEG}:
        parsed_source_files, parsed_line_map = _parse_legacy_source_lines(
            blob,
            sink.legacy_modules.get(entry["module"]),
            load_base_linear=load_base_linear,
        )
        sink.source_files.extend(parsed_source_files)
        sink.line_map.update(parsed_line_map)
    elif subsection_type == _nb00.CodeViewSubsectionType.SYMBOLS:
        sink.debug_identifiers.extend(_parse_legacy_symbol_names(blob))


def _apply_legacy_publics_8616(sink: _NB0204Collections8616, load_base_linear: int) -> None:
    """Fold legacy public symbols into code/data label maps."""
    if not sink.legacy_publics:
        return
    module_ranges = tuple(
        (module.linear_range(load_base_linear=load_base_linear), module.module_index)
        for module in sink.legacy_modules.values()
    )
    for symbol in sink.legacy_publics:
        linear = symbol.linear_addr(load_base_linear=load_base_linear)
        name = symbol.name.lstrip("_")
        if _nb00._public_is_code_symbol(symbol, linear=linear, module_ranges=module_ranges):
            sink.code_labels.setdefault(linear, name)
        else:
            sink.data_labels.setdefault(linear, symbol.name)


def parse_codeview_nb0204_bytes(data: bytes, *, load_base_linear: int = 0) -> CodeViewNB0204Info | None:
    """Parse optional NB02/NB04 CodeView debug metadata from executable bytes."""
    located = find_codeview_nb0204(data)
    if located is None:
        return None

    version, debug_base = located

    try:
        # Read header at debug_base
        # struct CVHeader { char sig[4]; uint32_t subdir_offset; }
        if debug_base + 8 > len(data):
            return None

        _sig, subdir_offset = struct.unpack_from("<4sI", data, debug_base)
        debug_offset = debug_base + subdir_offset

        if not (0 <= debug_offset < len(data)):
            return None

        sink = _NB0204Collections8616()

        # Parse subsection directory
        directory_entries = _parse_subsection_directory(data, debug_base, debug_offset)

        for entry in directory_entries:
            offset = entry["offset"]
            size = entry["size"]

            if offset + size > len(data):
                continue

            blob = data[offset : offset + size]
            subsection_type = entry["type"]
            if not _parse_label_subsection_8616(sink, subsection_type, blob, load_base_linear):
                _parse_legacy_subsection_8616(sink, entry, subsection_type, blob, load_base_linear)

        _apply_legacy_publics_8616(sink, load_base_linear)

        return CodeViewNB0204Info(
            version=version,
            debug_base=debug_base,
            code_labels=sink.code_labels,
            data_labels=sink.data_labels,
            procedures=tuple(sink.procedures),
            stack_variables=sink.stack_variables,
            line_map=sink.line_map,
            modules=tuple(sink.modules),
            source_files=tuple(sink.source_files),
            type_record_names=tuple(dict.fromkeys(sink.type_record_names)),
            type_members=tuple(sink.type_members),
            debug_identifiers=tuple(dict.fromkeys(sink.debug_identifiers)),
        )

    except (struct.error, ValueError, IndexError):
        return None


def _parse_directory_entries_8616(
    data: bytes,
    debug_base: int,
    offset: int,
    count: int,
    entry_fmt: str,
    entry_stride: int,
) -> list[dict[str, Any]]:
    """Parse a fixed-stride run of subsection directory entries."""
    entries: list[dict[str, Any]] = []
    for _ in range(count):
        entry_type, entry_module, entry_offset, subsection_size = struct.unpack_from(
            entry_fmt, data, offset
        )
        abs_offset = debug_base + entry_offset
        if 0 <= abs_offset <= len(data) and subsection_size > 0:
            entries.append(
                {
                    "type": entry_type,
                    "module": entry_module,
                    "offset": abs_offset,
                    "size": subsection_size,
                }
            )
        offset += entry_stride
    return entries


def _parse_subsection_directory(
    data: bytes,
    debug_base: int,
    directory_offset: int,
) -> list[dict[str, Any]]:
    """Parse subsection directory entries."""
    entries: list[dict[str, Any]] = []

    try:
        if directory_offset + 16 <= len(data):
            header_size, entry_size, count, _next_dir, _flags = struct.unpack_from("<HHIII", data, directory_offset)
            if header_size >= 16 and entry_size >= 12 and 0 < count < 0x10000:
                offset = directory_offset + header_size
                if offset + count * entry_size <= len(data):
                    return _parse_directory_entries_8616(
                        data, debug_base, offset, count, "<HHII", entry_size
                    )

        if directory_offset + 2 > len(data):
            return entries
        count = struct.unpack_from("<H", data, directory_offset)[0]
        offset = directory_offset + 2
        if count and offset + count * 10 <= len(data):
            entries = _parse_directory_entries_8616(data, debug_base, offset, count, "<HHIH", 10)

    except (struct.error, ValueError):
        pass

    return entries


def _parse_public_symbols(
    blob: bytes,
    code_labels: dict[int, str],
    data_labels: dict[int, str],
    load_base_linear: int,
) -> None:
    """Parse SST_PUBLIC symbols."""
    offset = 0

    while offset + 6 < len(blob):
        try:
            # struct: offset (2), segment (2), type (2), name_len (1)
            sym_offset, segment, _sym_type, name_len = struct.unpack_from("<HHHB", blob, offset)
            offset += 7

            if name_len > 0 and offset + name_len <= len(blob):
                name = blob[offset : offset + name_len].decode("ascii", errors="ignore")
                offset += name_len

                if name:
                    linear_addr = load_base_linear + (segment << 4) + sym_offset
                    if _public_name_looks_like_data(name):
                        data_labels[linear_addr] = name
                    else:
                        code_labels[linear_addr] = name.lstrip("_")

        except (struct.error, ValueError):
            break


def _parse_symbol_records(blob: bytes) -> list[CodeViewSymbol]:
    symbols = _parse_symbol_records_from_offset(blob, 0)
    if not symbols and len(blob) > 4:
        symbols = _parse_symbol_records_from_offset(blob, 4)
    return symbols


def _parse_bprel_symbol_8616(
    record_type: int, blob: bytes, data_offset: int, record_end: int, current_procedure: str | None
) -> CodeViewSymbol | None:
    """Parse one S_BPREL16 BP-relative stack variable record."""
    if data_offset + 4 > record_end:
        return None
    bp_offset, data_type = struct.unpack_from("<hH", blob, data_offset)
    name = _read_pascal_string(blob, data_offset + 4, record_end)
    if not name:
        return None
    return CodeViewSymbol(
        type_code=record_type,
        name=name,
        offset=bp_offset,
        segment=None,
        data_type=data_type,
        extra={"bp_relative": True, "procedure": current_procedure},
    )


def _parse_data_symbol_8616(
    record_type: int, blob: bytes, data_offset: int, record_end: int
) -> CodeViewSymbol | None:
    """Parse one S_LDATA16/S_PUB16 segmented data symbol record."""
    if data_offset + 6 > record_end:
        return None
    symbol_offset, segment, data_type = struct.unpack_from("<HHH", blob, data_offset)
    name = _read_pascal_string(blob, data_offset + 6, record_end)
    if not name:
        return None
    return CodeViewSymbol(
        type_code=record_type,
        name=name,
        offset=symbol_offset,
        segment=segment,
        data_type=data_type,
    )


def _skip_record_padding_8616(blob: bytes, offset: int) -> int:
    """Skip 4-byte alignment padding after a record."""
    while offset < len(blob) and offset % 4:
        if blob[offset] != 0:
            break
        offset += 1
    return offset


def _parse_symbol_record_8616(
    record_type: int,
    blob: bytes,
    data_offset: int,
    record_end: int,
    current_procedure: str | None,
) -> tuple[CodeViewSymbol | None, str | None]:
    """Parse one symbol record; return it plus the updated procedure context."""
    if record_type in _PROC16_TYPES:
        symbol = _parse_proc16_symbol(record_type, blob, data_offset, record_end)
        if symbol is not None:
            return symbol, symbol.name or current_procedure
        return None, current_procedure
    if record_type == CodeViewSymbolType.S_END:
        return None, None
    if record_type == CodeViewSymbolType.S_BPREL16:
        return (
            _parse_bprel_symbol_8616(record_type, blob, data_offset, record_end, current_procedure),
            current_procedure,
        )
    if record_type in _DATA16_TYPES or record_type == CodeViewSymbolType.S_PUB16:
        return _parse_data_symbol_8616(record_type, blob, data_offset, record_end), current_procedure
    return None, current_procedure


def _parse_symbol_records_from_offset(blob: bytes, initial_offset: int) -> list[CodeViewSymbol]:
    """Parse symbol records from SST_SYMBOLS subsection."""
    symbols: list[CodeViewSymbol] = []
    offset = initial_offset
    current_procedure: str | None = None

    while offset < len(blob):
        try:
            # Each record: length (2), type (2), data...
            if offset + 4 > len(blob):
                break

            length = struct.unpack_from("<H", blob, offset)[0]
            offset += 2

            if length < 2 or offset + length > len(blob):
                break

            record_type = struct.unpack_from("<H", blob, offset)[0]
            offset += 2
            data_offset = offset
            record_end = data_offset + length - 2

            # Record-specific parsing
            symbol, current_procedure = _parse_symbol_record_8616(
                record_type, blob, data_offset, record_end, current_procedure
            )
            if symbol is not None:
                symbols.append(symbol)

            # Skip to next record
            offset = _skip_record_padding_8616(blob, record_end)

        except (struct.error, ValueError, IndexError):
            break

    return symbols


def _materialize_symbol_record_8616(
    sym: CodeViewSymbol,
    code_labels: dict[int, str],
    data_labels: dict[int, str],
    procedures: list[CodeViewSymbol],
    stack_variables: dict[str, list[CodeViewSymbol]],
    load_base_linear: int,
) -> None:
    """Route one parsed symbol into its label/procedure/stack bucket."""
    linear = _symbol_linear_addr(sym, load_base_linear=load_base_linear)
    if sym.is_procedure():
        procedures.append(sym)
        if sym.name and linear is not None:
            code_labels[linear] = sym.name
        return
    if sym.is_stack_var():
        procedure_name = sym.extra.get("procedure") if isinstance(sym.extra, dict) else None
        if not procedure_name:
            procedure_name = "<global>"
        stack_variables.setdefault(procedure_name, []).append(sym)
        return
    if sym.is_data_symbol():
        if sym.name and linear is not None:
            data_labels[linear] = sym.name
        return
    if sym.type_code != CodeViewSymbolType.S_PUB16 or not (sym.name and linear is not None):
        return
    if _public_name_looks_like_data(sym.name):
        data_labels.setdefault(linear, sym.name)
    else:
        code_labels.setdefault(linear, sym.name.lstrip("_"))


def _materialize_symbol_records(
    syms: list[CodeViewSymbol],
    code_labels: dict[int, str],
    data_labels: dict[int, str],
    procedures: list[CodeViewSymbol],
    stack_variables: dict[str, list[CodeViewSymbol]],
    load_base_linear: int,
) -> None:
    for sym in syms:
        _materialize_symbol_record_8616(
            sym, code_labels, data_labels, procedures, stack_variables, load_base_linear
        )


def _parse_proc16_symbol(record_type: int, blob: bytes, data_offset: int, record_end: int) -> CodeViewSymbol | None:
    if data_offset + 25 <= record_end:
        proc_length, debug_start, debug_end, proc_offset, segment, proctype = struct.unpack_from(
            "<HHHHHH", blob, data_offset + 12
        )
        flags = blob[data_offset + 24]
        name = _read_pascal_string(blob, data_offset + 25, record_end)
        if name:
            return CodeViewSymbol(
                type_code=record_type,
                name=name,
                offset=proc_offset,
                segment=segment,
                length=proc_length,
                data_type=proctype,
                extra={"debug_start": debug_start, "debug_end": debug_end, "flags": flags},
            )

    if data_offset + 16 <= record_end:
        proc_length, proc_offset, segment = struct.unpack_from("<HHH", blob, data_offset + 10)
        name = _read_pascal_string(blob, data_offset + 16, record_end)
        if name:
            return CodeViewSymbol(
                type_code=record_type,
                name=name,
                offset=proc_offset,
                segment=segment,
                length=proc_length,
            )
    return None


def _read_pascal_string(blob: bytes, offset: int, end: int) -> str:
    if offset >= end:
        return ""
    length = blob[offset]
    start = offset + 1
    stop = start + length
    if length == 0 or stop > end:
        return ""
    return blob[start:stop].decode("ascii", errors="ignore")


def _symbol_linear_addr(symbol: CodeViewSymbol, *, load_base_linear: int) -> int | None:
    if symbol.offset < 0:
        return None
    if symbol.segment is None:
        return load_base_linear + symbol.offset
    return load_base_linear + (symbol.segment << 4) + symbol.offset


def _public_name_looks_like_data(name: str) -> bool:
    lowered = name.lower().lstrip("_")
    return lowered.startswith(("dgroup@", "byte_", "word_", "dword_", "off_", "stru_", "seg_", "data_"))


def _collect_source_line_pairs_8616(
    blob: bytes,
    line_base: int,
    line_map: dict[int, tuple[int, int]],
    load_base_linear: int,
) -> None:
    """Collect offset/line pairs from one segment's line table."""
    if line_base + 4 > len(blob):
        return
    segment, pair_count = struct.unpack_from("<HH", blob, line_base)
    pair_offset = line_base + 4
    if pair_count > 0x10000 or pair_offset + pair_count * 6 > len(blob):
        return
    offsets = struct.unpack_from(f"<{pair_count}I", blob, pair_offset) if pair_count else ()
    pair_offset += pair_count * 4
    lines = struct.unpack_from(f"<{pair_count}H", blob, pair_offset) if pair_count else ()
    for code_offset, source_line in zip(offsets, lines, strict=False):
        linear = load_base_linear + (segment << 4) + code_offset
        line_map[linear] = (source_line, 0)


def _parse_source_file_record_8616(
    blob: bytes,
    file_base: int,
    source_files: list[str],
    line_map: dict[int, tuple[int, int]],
    load_base_linear: int,
) -> None:
    """Parse one source file record's name and per-segment line tables."""
    if file_base + 6 > len(blob):
        return
    file_segment_count = struct.unpack_from("<H", blob, file_base)[0]
    if file_segment_count > 512:
        return
    file_offset = _source_file_record_table_offset(blob, file_base, file_segment_count)
    if file_offset is None:
        return
    line_bases = struct.unpack_from(f"<{file_segment_count}I", blob, file_offset) if file_segment_count else ()
    file_offset += file_segment_count * 4
    file_offset += file_segment_count * 8
    if file_offset < len(blob):
        name_length = blob[file_offset]
        name_start = file_offset + 1
        name_end = name_start + name_length
        if name_length and name_end <= len(blob):
            source_files.append(blob[name_start:name_end].decode("ascii", errors="ignore"))

    for line_base in line_bases:
        _collect_source_line_pairs_8616(blob, line_base, line_map, load_base_linear)


def _parse_source_module_lines(
    blob: bytes,
    *,
    load_base_linear: int,
) -> tuple[list[str], dict[int, tuple[int, int]]]:
    source_files: list[str] = []
    line_map: dict[int, tuple[int, int]] = {}
    if len(blob) < 4:
        return source_files, line_map
    try:
        file_count, segment_count = struct.unpack_from("<HH", blob, 0)
        offset = 4
        if file_count > 512 or segment_count > 512:
            return source_files, line_map
        if offset + file_count * 4 + segment_count * 8 + segment_count * 2 > len(blob):
            return source_files, line_map
        file_bases = struct.unpack_from(f"<{file_count}I", blob, offset) if file_count else ()
        offset += file_count * 4
        offset += segment_count * 8
        offset += segment_count * 2
        if segment_count % 2:
            offset += 2

        for file_base in file_bases:
            _parse_source_file_record_8616(blob, file_base, source_files, line_map, load_base_linear)
    except (struct.error, ValueError):
        return source_files, line_map
    return source_files, line_map


def _source_file_record_table_offset(blob: bytes, file_base: int, file_segment_count: int) -> int | None:
    for file_offset in (file_base + 4, file_base + 6):
        if file_offset + file_segment_count * 4 + file_segment_count * 8 > len(blob):
            continue
        line_bases = struct.unpack_from(f"<{file_segment_count}I", blob, file_offset) if file_segment_count else ()
        if all(0 <= line_base < len(blob) for line_base in line_bases):
            return file_offset
    return None


def _parse_legacy_source_lines(
    blob: bytes,
    module: _nb00.CodeViewNB00Module | None,
    *,
    load_base_linear: int,
) -> tuple[list[str], dict[int, tuple[int, int]]]:
    """Parse old NB02/NB00 SRCLINES/SRCLNSEG line pairs.

    MS C 6 NB02 uses the NB00 directory ids with a compact source-line blob:
    a Pascal source filename, a small pad, then repeated uint16 line/offset
    pairs. These pairs are debug evidence only; they do not imply control-flow
    or type semantics.
    """
    source_files: list[str] = []
    line_map: dict[int, tuple[int, int]] = {}
    if not blob:
        return source_files, line_map

    search_start = 0
    if blob[0] and 1 + blob[0] <= len(blob):
        name_length = blob[0]
        name_start = 1
        name_end = name_start + name_length
        filename = blob[name_start:name_end].decode("ascii", errors="ignore")
        if filename:
            source_files.append(filename)
        search_start = name_end

    count_offset = _find_legacy_line_count_offset(blob, search_start)
    if count_offset is None:
        return source_files, line_map

    pair_count = struct.unpack_from("<H", blob, count_offset)[0]
    pair_offset = count_offset + 2
    segment_base = load_base_linear
    if module is not None:
        segment_base += module.cs_base << 4

    try:
        for _ in range(pair_count):
            source_line, code_offset = struct.unpack_from("<HH", blob, pair_offset)
            pair_offset += 4
            if source_line:
                line_map[segment_base + code_offset] = (source_line, 0)
    except (struct.error, ValueError):
        return source_files, line_map

    return source_files, line_map


def _find_legacy_line_count_offset(blob: bytes, search_start: int) -> int | None:
    for candidate in range(search_start, min(len(blob) - 1, search_start + 16)):
        pair_count = struct.unpack_from("<H", blob, candidate)[0]
        if pair_count == 0 or pair_count > 0x4000:
            continue
        if candidate + 2 + pair_count * 4 <= len(blob):
            return candidate
    return None


def _collect_cv4_type_members(blob: bytes) -> tuple[_nb00.CodeViewNB00TypeMember, ...]:
    records = _parse_cv4_type_records(blob)
    members: list[_nb00.CodeViewNB00TypeMember] = []
    seen: set[tuple[int, str, int]] = set()
    for type_index, leaf, payload in records:
        if leaf != _CV4_LF_FIELDLIST:
            continue
        for leaf_index, name, offset, _member_type_index in _parse_cv4_fieldlist_members(payload):
            key = (type_index, name, offset)
            if key in seen:
                continue
            seen.add(key)
            members.append(
                _nb00.CodeViewNB00TypeMember(
                    name=name,
                    offset=offset,
                    owner_type_index=type_index,
                    leaf_index=leaf_index,
                )
            )
    return tuple(members)


def _parse_cv4_type_records(blob: bytes) -> tuple[tuple[int, int, bytes], ...]:
    best: tuple[tuple[int, int, bytes], ...] = ()
    best_score = 0
    for start in range(min(len(blob), 0x40)):
        records = _parse_cv4_type_records_from_offset(blob, start)
        if not records:
            continue
        score = len(records) + 4 * sum(1 for _type_index, leaf, _payload in records if leaf == _CV4_LF_FIELDLIST)
        if score > best_score:
            best = records
            best_score = score
    return best


def _parse_cv4_type_records_from_offset(blob: bytes, start: int) -> tuple[tuple[int, int, bytes], ...]:
    records: list[tuple[int, int, bytes]] = []
    offset = start
    type_index = _CV4_FIRST_TYPE_INDEX
    while offset + 4 <= len(blob):
        record_length = struct.unpack_from("<H", blob, offset)[0]
        if record_length < 2 or offset + 2 + record_length > len(blob):
            break
        leaf = struct.unpack_from("<H", blob, offset + 2)[0]
        payload_start = offset + 4
        payload_end = offset + 2 + record_length
        records.append((type_index, leaf, blob[payload_start:payload_end]))
        offset = payload_end
        type_index += 1
    if not records:
        return ()
    trailing = blob[offset:]
    if any(byte != 0 for byte in trailing):
        return ()
    return tuple(records)


def _parse_cv4_fieldlist_members(payload: bytes) -> tuple[tuple[int, str, int, int], ...]:
    members: list[tuple[int, str, int, int]] = []
    offset = 0
    leaf_index = 0
    while offset + 2 <= len(payload):
        if payload[offset] >= 0xF0:
            offset += 1
            continue
        subleaf = struct.unpack_from("<H", payload, offset)[0]
        if subleaf != _CV4_LF_MEMBER:
            offset += 2
            leaf_index += 1
            continue
        if offset + 9 > len(payload):
            break
        member_type_index, _attributes, member_offset = struct.unpack_from("<HHH", payload, offset + 2)
        name = _read_pascal_string(payload, offset + 8, len(payload))
        if not name or not _is_debug_identifier_name(name):
            offset += 2
            leaf_index += 1
            continue
        members.append((leaf_index, name, member_offset, member_type_index))
        offset = offset + 9 + len(name)
        while offset < len(payload) and payload[offset] >= 0xF0:
            offset += 1
        leaf_index += 1
    return tuple(members)


def _parse_legacy_symbol_names(blob: bytes) -> tuple[str, ...]:
    names: list[str] = []
    for offset, name_length in enumerate(blob):
        if name_length == 0 or name_length > 80:
            continue
        name_start = offset + 1
        name_end = name_start + name_length
        if name_end > len(blob):
            continue
        try:
            name = blob[name_start:name_end].decode("ascii")
        except UnicodeDecodeError:
            continue
        if _is_debug_identifier_name(name):
            names.append(name)
    return tuple(dict.fromkeys(names))


def _is_debug_identifier_name(name: str) -> bool:
    if not name:
        return False
    allowed_extra = "_$?@"
    if not all(ch.isalnum() or ch in allowed_extra for ch in name):
        return False
    return any(ch.isalpha() or ch == "_" for ch in name)


def _parse_module_names(blob: bytes) -> list[str]:
    """Parse module names from SST_MODULE subsection."""
    names: list[str] = []

    try:
        # Module record format varies, but typically ends with null-terminated strings
        offset = 0
        while offset < len(blob):
            if blob[offset] == 0:
                break
            # Find null terminator
            null_pos = blob.find(b"\x00", offset)
            if null_pos == -1:
                null_pos = len(blob)

            name = blob[offset:null_pos].decode("ascii", errors="ignore")
            if name:
                names.append(name)

            offset = null_pos + 1

    except (ValueError, IndexError):
        pass

    return names
