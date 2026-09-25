"""Layer: Optional evidence/reporting.

Responsibility: parse Turbo Debugger TDINFO records into optional labels and diagnostics.
Forbidden: requiring debug symbols for arguments, types, control flow, or validation success.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field, replace
from enum import IntEnum
from pathlib import Path

_TDINFO_MAGIC = 0x52FB
_PAGE_SIZE = 512

# TLink/TDS Version Identification Table
# Maps TDS major.minor version to TLink version, commandline format, and associated products
#
# OLD Format (1.0-1.1 did not contain TDS info):
#   TDS 2.8  -> TLink 2.0a (31.10.1988) - Turbo Assembler 1.0, Turbo C 2.0, Turbo C 2.01
#   TDS 2.8  -> TLink 2.0b (2.5.1989)  - Turbo Assembler 1.01
#   TDS 2.9  -> TLink 3.0 (7.5.1990)   - Turbo Assembler 2.0
#   TDS 2.9  -> TLink 3.01 (29.10.1990) - Turbo Assembler 2.01
#
# NEW Format:
#   TDS 3.0  -> TLink 4.0 (23.4.1991)  - Borland C++ 2.0
#   TDS 3.10 -> TLink 5.0 (11.11.1991) - Borland C++ 3.0
#   TDS 3.10 -> TLink 5.1 (10.6.1992)  - Borland C++ 3.1
#   TDS 4.1  -> TLink 6.00 (2.12.1993) - Turbo Assembler 4.0, Borland C++ 4.0
#   TDS 4.1  -> TLink 7.0a (17.11.1994) - Borland C++ 4.5, 4.52
#   TDS 4.3  -> TLink 7.1.30.1 (21.2.1996) - Turbo Assembler 5.0
#   TDS 4.3  -> TLink 7.1.32.2 (6.5.1997)  - Borland C++ 5.0, 5.02

_TDS_VERSION_MAP = {
    # (tds_major, tds_minor): (tds_version_str, tlink_version_str, commandline_hint, products)
    (2, 8): (
        "2.8",
        "2.0a/2.0b",
        "Turbo Link  Version 2.0  Copyright (c) 1987, 1988 Borland International",
        "Turbo Assembler 1.0/1.01, Turbo C 2.0/2.01",
    ),
    (2, 9): (
        "2.9",
        "3.0/3.01",
        "Turbo Link  Version 3.0 Copyright (c) 1987, 1990 Borland International",
        "Turbo Assembler 2.0/2.01",
    ),
    (3, 0): ("3.0", "4.0", "Turbo Link  Version 4.0 Copyright (c) 1991 Borland International", "Borland C++ 2.0"),
    (3, 10): (
        "3.10",
        "5.0/5.1",
        "Turbo Link  Version 5.0 Copyright (c) 1991 Borland International",
        "Borland C++ 3.0/3.1",
    ),
    (4, 1): (
        "4.1",
        "6.00/7.0a",
        "Turbo Link  Version 6.00 Copyright (c) 1992, 1993 Borland International",
        "Turbo Assembler 4.0, Borland C++ 4.0/4.5/4.52",
    ),
    (4, 3): (
        "4.3",
        "7.1.30.1/7.1.32.2",
        "Turbo Link  Version 7.1 Copyright (c) 1987, 1996 Borland International",
        "Turbo Assembler 5.0, Borland C++ 5.0/5.02",
    ),
}

# TDS versions that have no TDS info (pre-2.0 format)
_OLD_FORMAT_NO_TDS = {(1, 0), (1, 1)}


class TDInfoSymbolClass(IntEnum):
    """Turbo Debugger symbol storage classes used as optional debug metadata."""

    STATIC = 0
    ABSOLUTE = 1
    AUTO = 2
    PASCAL_VAR = 3
    REGISTER = 4
    CONSTANT = 5
    TYPEDEF = 6
    STRUCT_UNION_OR_ENUM = 7


class TDInfoNameKind(IntEnum):
    """Classification for entries recovered from the TDINFO name pool."""

    UNKNOWN = 0
    SOURCE_FILE = 1
    PUBLIC_SYMBOL = 2
    IDENTIFIER = 3


class TDInfoTypeKind(IntEnum):
    """TDINFO type descriptor tags preserved for debug-schema reporting."""

    NEAR_POINTER = 0x15
    FAR_POINTER = 0x16
    SEGMENT = 0x17
    NEAR386_POINTER = 0x18
    FAR386_POINTER = 0x19
    C_ARRAY = 0x1A
    VL_ARRAY = 0x1B
    P_ARRAY = 0x1C
    ARRAY_DESCRIPTOR = 0x1D
    STRUCT = 0x1E
    UNION = 0x1F
    VL_STRUCT = 0x20
    VL_UNION = 0x21
    ENUM = 0x22
    FUNCTION = 0x23
    CLASS = 0x2E


@dataclass(frozen=True)
class TDInfoHeader:
    """Decoded TDINFO header counters and version fields."""

    major_version: int
    minor_version: int
    names_pool_size_in_bytes: int
    names_count: int
    types_count: int
    members_count: int
    symbols_count: int
    globals_count: int
    extension_size: int


@dataclass(frozen=True)
class TDInfoSymbolRecord:
    """Raw TDINFO symbol record with segmented address metadata."""

    index: int
    type_index: int
    offset: int
    segment: int
    symbol_class: TDInfoSymbolClass

    def linear_addr(self, *, load_base_linear: int) -> int:
        """Return a display-only linear address for optional symbol labels."""
        return load_base_linear + (self.segment << 4) + self.offset

    @property
    def signed_offset(self) -> int:
        """Interpret the 16-bit record offset as a signed stack displacement."""
        return self.offset - 0x10000 if self.offset & 0x8000 else self.offset


@dataclass(frozen=True)
class TDInfoNamedSymbol:
    """TDINFO symbol paired with its decoded name pool entry."""

    name: str
    record: TDInfoSymbolRecord


@dataclass(frozen=True)
class TDInfoTypeMember:
    """Member entry decoded from a TDINFO structure, union, or array payload."""

    name: str
    offset: int
    type_index: int
    attributes: int
    payload_offset: int
    owner_type_index: int | None = None


@dataclass(frozen=True)
class TDInfoEnumMember:
    """Enum value decoded from a TDINFO enum payload."""

    name: str
    value: int
    attributes: int
    payload_offset: int
    owner_type_index: int | None = None


@dataclass(frozen=True)
class TDInfoTypeDescriptor:
    """TDINFO type descriptor retained as optional debug type evidence."""

    type_index: int
    kind: TDInfoTypeKind
    name: str
    size: int
    payload_offset: int
    raw_bytes: bytes
    base_type_index: int | None = None
    target_type_index: int | None = None
    return_type_index: int | None = None
    call_kind: int | None = None
    attributes: int | None = None
    lower_bound: int | None = None
    upper_bound: int | None = None
    member_ref: int | None = None


@dataclass(frozen=True)
class TDInfoMemberList:
    """One decoded TD32 member-record list: an aggregate's field block.

    ``record_index`` is the TD32 member-table record ordinal of the list's
    first field record.  Borland type descriptors reference this ordinal
    through their trailing ``member_ref`` field (verified against TDUMP).
    """

    record_index: int
    payload_offset: int
    size: int
    owner_name: str
    owner_type_index: int | None
    bitfield: bool
    member_names: tuple[str, ...]
    method_names: tuple[str, ...]


@dataclass(frozen=True)
class TDInfoTypeReference:
    """Reference from a named TDINFO symbol to a type descriptor index."""

    name: str
    type_index: int
    symbol_class: TDInfoSymbolClass


@dataclass(frozen=True)
class TDInfoNamePoolEntry:
    """Classified TDINFO name-pool string."""

    index: int
    name: str
    kind: TDInfoNameKind


@dataclass(frozen=True)
class TDInfoRawTableSpan:
    """Byte span for a TDINFO table retained for diagnostics and schema dumps."""

    name: str
    offset: int
    size: int
    count: int | None = None
    record_size: int | None = None


@dataclass(frozen=True)
class TDInfoEXEInfo:
    """Parsed TDINFO payload exposed as optional labels and debug diagnostics."""

    header: TDInfoHeader
    debug_info_offset: int
    symbols: tuple[TDInfoSymbolRecord, ...]
    names: tuple[str, ...]
    name_pool_entries: tuple[TDInfoNamePoolEntry, ...] = ()
    source_files: tuple[str, ...] = ()
    candidate_identifiers: tuple[str, ...] = ()
    public_symbols: tuple[str, ...] = ()
    local_identifiers: tuple[str, ...] = ()
    named_symbols: tuple[TDInfoNamedSymbol, ...] = ()
    names_by_class: dict[TDInfoSymbolClass, tuple[str, ...]] = field(default_factory=dict)
    symbols_by_class: dict[TDInfoSymbolClass, tuple[TDInfoSymbolRecord, ...]] = field(default_factory=dict)
    stack_variables: tuple[TDInfoNamedSymbol, ...] = ()
    register_symbols: tuple[TDInfoNamedSymbol, ...] = ()
    constant_symbols: tuple[TDInfoNamedSymbol, ...] = ()
    type_names: tuple[str, ...] = ()
    type_descriptors: tuple[TDInfoTypeDescriptor, ...] = ()
    type_references: tuple[TDInfoTypeReference, ...] = ()
    type_members: tuple[TDInfoTypeMember, ...] = ()
    enum_members: tuple[TDInfoEnumMember, ...] = ()
    member_lists: tuple[TDInfoMemberList, ...] = ()
    raw_table_spans: tuple[TDInfoRawTableSpan, ...] = ()
    code_labels: dict[int, str] = field(default_factory=dict)
    data_labels: dict[int, str] = field(default_factory=dict)
    # TLink/TDS version identification
    tds_version_str: str = ""
    tlink_version_str: str = ""
    commandline_hint: str = ""
    products: str = ""


def parse_tdinfo_exe(path: Path, *, load_base_linear: int = 0) -> TDInfoEXEInfo | None:
    """Parse TDINFO debug metadata from an MZ executable when present."""
    return parse_tdinfo_exe_bytes(path.read_bytes(), load_base_linear=load_base_linear)


def _tdinfo_header_layout_8616(data: bytes) -> tuple | None:
    """Decode the TDINFO header layout, or None when absent/truncated."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None

    used_bytes_in_last_page, file_size_in_pages = struct.unpack_from("<HH", data, 2)
    if file_size_in_pages == 0:
        return None
    used_bytes = used_bytes_in_last_page or _PAGE_SIZE
    debug_info_offset = file_size_in_pages * _PAGE_SIZE - (_PAGE_SIZE - used_bytes)
    if debug_info_offset < 0 or debug_info_offset + 44 > len(data):
        return None

    magic_number = struct.unpack_from("<H", data, debug_info_offset)[0]
    if magic_number != _TDINFO_MAGIC:
        return None

    (
        _magic,
        minor_version,
        major_version,
        names_pool_size_in_bytes,
        names_count,
        types_count,
        members_count,
        symbols_count,
        globals_count,
    ) = struct.unpack_from("<HBBIHHHHH", data, debug_info_offset)
    extension_size = struct.unpack_from("<H", data, debug_info_offset + 42)[0]
    symbol_records_offset = debug_info_offset + 44 + extension_size
    if symbol_records_offset + symbols_count * 9 > len(data):
        return None
    names_pool_offset = len(data) - names_pool_size_in_bytes
    if names_pool_offset < symbol_records_offset or names_pool_offset < 0:
        return None
    header = TDInfoHeader(
        major_version=major_version,
        minor_version=minor_version,
        names_pool_size_in_bytes=names_pool_size_in_bytes,
        names_count=names_count,
        types_count=types_count,
        members_count=members_count,
        symbols_count=symbols_count,
        globals_count=globals_count,
        extension_size=extension_size,
    )
    return (
        header,
        debug_info_offset,
        symbol_records_offset,
        names_pool_offset,
    )


@dataclass
class _TdinfoSymbolCollection8616:
    """Mutable buckets for TDINFO symbol classification."""

    symbols: list[TDInfoSymbolRecord] = field(default_factory=list)
    symbols_by_class: dict[TDInfoSymbolClass, list[TDInfoSymbolRecord]] = field(
        default_factory=lambda: {klass: [] for klass in TDInfoSymbolClass}
    )
    named_symbols: list[TDInfoNamedSymbol] = field(default_factory=list)
    names_by_class: dict[TDInfoSymbolClass, list[str]] = field(
        default_factory=lambda: {klass: [] for klass in TDInfoSymbolClass}
    )
    code_labels: dict[int, str] = field(default_factory=dict)
    data_labels: dict[int, str] = field(default_factory=dict)
    type_names: list[str] = field(default_factory=list)
    stack_variables: list[TDInfoNamedSymbol] = field(default_factory=list)
    register_symbols: list[TDInfoNamedSymbol] = field(default_factory=list)
    constant_symbols: list[TDInfoNamedSymbol] = field(default_factory=list)
    type_references: list[TDInfoTypeReference] = field(default_factory=list)

    def add_symbol(self, symbol: TDInfoSymbolRecord, names: tuple[str, ...]) -> str | None:
        """Classify one symbol record into the typed buckets."""
        self.symbols.append(symbol)
        self.symbols_by_class.setdefault(symbol.symbol_class, []).append(symbol)
        name = _tdinfo_symbol_name(symbol, names)
        if name is None:
            return None
        named_symbol = TDInfoNamedSymbol(name=name, record=symbol)
        self.named_symbols.append(named_symbol)
        self.names_by_class.setdefault(symbol.symbol_class, []).append(name)
        if symbol.type_index:
            self.type_references.append(
                TDInfoTypeReference(name=name, type_index=symbol.type_index, symbol_class=symbol.symbol_class)
            )
        if symbol.symbol_class in {
            TDInfoSymbolClass.TYPEDEF,
            TDInfoSymbolClass.STRUCT_UNION_OR_ENUM,
        } and _tdinfo_type_name_looks_user_defined(name):
            self.type_names.append(name)
        elif symbol.symbol_class in {TDInfoSymbolClass.AUTO, TDInfoSymbolClass.PASCAL_VAR}:
            self.stack_variables.append(named_symbol)
        elif symbol.symbol_class is TDInfoSymbolClass.REGISTER:
            self.register_symbols.append(named_symbol)
        elif symbol.symbol_class is TDInfoSymbolClass.CONSTANT:
            self.constant_symbols.append(named_symbol)
        return name


def _collect_tdinfo_symbols_8616(
    data: bytes,
    *,
    symbol_records_offset: int,
    symbols_count: int,
    names: tuple[str, ...],
    load_base_linear: int,
    collection: _TdinfoSymbolCollection8616,
) -> None:
    """Fold fixed 9-byte symbol records into the collection."""
    for index in range(symbols_count):
        entry_offset = symbol_records_offset + index * 9
        name_index, type_index, offset, segment, bitfield = struct.unpack_from("<HHHHB", data, entry_offset)
        symbol_class = TDInfoSymbolClass(bitfield & 0x7)
        symbol = TDInfoSymbolRecord(
            index=name_index,
            type_index=type_index,
            offset=offset,
            segment=segment,
            symbol_class=symbol_class,
        )
        name = collection.add_symbol(symbol, names)
        if symbol.symbol_class is not TDInfoSymbolClass.STATIC:
            continue
        if name is None:
            continue
        linear = symbol.linear_addr(load_base_linear=load_base_linear)
        if _tdinfo_name_looks_like_code(name):
            collection.code_labels.setdefault(linear, name.lstrip("_"))
        else:
            collection.data_labels.setdefault(linear, name)


def _tdinfo_version_strings_8616(major_version: int, minor_version: int) -> tuple[str, str, str, str]:
    """Return (tds, tlink, commandline_hint, products) version strings."""
    normalized_minor_version = 10 if major_version == 3 and minor_version == 0x10 else minor_version
    tds_key = (major_version, normalized_minor_version)
    if tds_key in _OLD_FORMAT_NO_TDS:
        return "N/A (pre-2.0 format)", "1.0/1.1", "No TDS info in header", "Turbo C 1.0/1.5"
    if tds_key in _TDS_VERSION_MAP:
        return _TDS_VERSION_MAP[tds_key]
    return f"{major_version}.{normalized_minor_version}", "unknown", "", ""


def parse_tdinfo_exe_bytes(data: bytes, *, load_base_linear: int = 0) -> TDInfoEXEInfo | None:
    """Parse TDINFO debug metadata from executable bytes when present."""
    layout = _tdinfo_header_layout_8616(data)
    if layout is None:
        return None
    header, debug_info_offset, symbol_records_offset, names_pool_offset = layout
    symbols_count = header.symbols_count
    symbol_records_size = symbols_count * 9
    payload_offset = symbol_records_offset + symbol_records_size
    payload_blob = data[payload_offset:names_pool_offset]
    raw_table_spans = _tdinfo_raw_table_spans(
        debug_info_offset=debug_info_offset,
        symbol_records_offset=symbol_records_offset,
        symbol_records_size=symbol_records_size,
        symbols_count=symbols_count,
        names_pool_offset=names_pool_offset,
        names_pool_size=header.names_pool_size_in_bytes,
    )

    names = _parse_tdinfo_name_pool(data[names_pool_offset:], expected_count=header.names_count)
    name_pool_entries = _classify_tdinfo_name_pool(names)
    public_symbols = tuple(entry.name for entry in name_pool_entries if entry.kind is TDInfoNameKind.PUBLIC_SYMBOL)
    local_identifiers = tuple(entry.name for entry in name_pool_entries if entry.kind is TDInfoNameKind.IDENTIFIER)

    collection = _TdinfoSymbolCollection8616()
    _collect_tdinfo_symbols_8616(
        data,
        symbol_records_offset=symbol_records_offset,
        symbols_count=symbols_count,
        names=names,
        load_base_linear=load_base_linear,
        collection=collection,
    )

    extra_symbols, extra_symbol_bytes = _parse_tdinfo_extra_symbol_records(
        payload_blob,
        names,
        types_count=header.types_count,
    )
    if extra_symbols:
        for symbol in extra_symbols:
            collection.add_symbol(symbol, names)

    descriptor_payload = payload_blob[extra_symbol_bytes:]
    type_descriptors = _parse_tdinfo_type_descriptors(
        descriptor_payload,
        names,
        payload_base_offset=payload_offset + extra_symbol_bytes,
        type_references=tuple(collection.type_references),
    )
    type_members, enum_members, member_lists = _parse_tdinfo_members(
        descriptor_payload,
        names,
        payload_base_offset=payload_offset + extra_symbol_bytes,
        type_descriptors=type_descriptors,
        types_count=header.types_count,
    )

    # Lookup TLink/TDS version identification
    tds_version_str, tlink_version_str, commandline_hint, products = _tdinfo_version_strings_8616(
        header.major_version, header.minor_version,
    )

    return TDInfoEXEInfo(
        header=header,
        debug_info_offset=debug_info_offset,
        symbols=tuple(collection.symbols),
        names=names,
        name_pool_entries=name_pool_entries,
        source_files=tuple(entry.name for entry in name_pool_entries if entry.kind is TDInfoNameKind.SOURCE_FILE),
        candidate_identifiers=tuple(
            entry.name
            for entry in name_pool_entries
            if entry.kind in {TDInfoNameKind.IDENTIFIER, TDInfoNameKind.PUBLIC_SYMBOL}
        ),
        public_symbols=public_symbols,
        local_identifiers=local_identifiers,
        named_symbols=tuple(collection.named_symbols),
        names_by_class={klass: tuple(items) for klass, items in collection.names_by_class.items() if items},
        symbols_by_class={klass: tuple(items) for klass, items in collection.symbols_by_class.items() if items},
        stack_variables=tuple(collection.stack_variables),
        register_symbols=tuple(collection.register_symbols),
        constant_symbols=tuple(collection.constant_symbols),
        type_names=tuple(dict.fromkeys(collection.type_names)),
        type_descriptors=type_descriptors,
        type_references=tuple(dict.fromkeys(collection.type_references)),
        type_members=type_members,
        enum_members=enum_members,
        member_lists=member_lists,
        raw_table_spans=raw_table_spans,
        code_labels=collection.code_labels,
        data_labels=collection.data_labels,
        tds_version_str=tds_version_str,
        tlink_version_str=tlink_version_str,
        commandline_hint=commandline_hint,
        products=products,
    )


def _tdinfo_raw_table_spans(
    *,
    debug_info_offset: int,
    symbol_records_offset: int,
    symbol_records_size: int,
    symbols_count: int,
    names_pool_offset: int,
    names_pool_size: int,
) -> tuple[TDInfoRawTableSpan, ...]:
    spans = [
        TDInfoRawTableSpan(
            name="header",
            offset=debug_info_offset,
            size=symbol_records_offset - debug_info_offset,
        ),
        TDInfoRawTableSpan(
            name="symbol_records",
            offset=symbol_records_offset,
            size=symbol_records_size,
            count=symbols_count,
            record_size=9,
        ),
    ]
    unknown_offset = symbol_records_offset + symbol_records_size
    unknown_size = names_pool_offset - unknown_offset
    if unknown_size > 0:
        spans.append(
            TDInfoRawTableSpan(
                name="uninterpreted_payload",
                offset=unknown_offset,
                size=unknown_size,
            )
        )
    spans.append(
        TDInfoRawTableSpan(
            name="name_pool",
            offset=names_pool_offset,
            size=names_pool_size,
        )
    )
    return tuple(spans)


_TDINFO_TYPE_SIZES = {
    0x01: 0,
    0x02: 1,
    0x04: 2,
    0x06: 4,
    0x08: 1,
    0x0A: 2,
    0x0C: 4,
    0x0E: 4,
    0x0F: 8,
    0x10: 10,
    0x11: 6,
    0x12: 1,
    0x18: 2,
    0x19: 4,
}


_TDINFO_DESCRIPTOR_FIRST_INDEX = 0x18
_TDINFO_DESCRIPTOR_RECORD_SIZE = 8
_TDINFO_ENUM_DESCRIPTOR_RECORD_SIZE = 16


def _parse_tdinfo_type_descriptors(
    payload: bytes,
    names: tuple[str, ...],
    *,
    payload_base_offset: int,
    type_references: tuple[TDInfoTypeReference, ...] = (),
) -> tuple[tuple[TDInfoTypeDescriptor, ...], int]:
    best_start = 0
    best: tuple[TDInfoTypeDescriptor, ...] = ()
    for start in range(len(payload)):
        sequence = _parse_tdinfo_type_descriptor_sequence(
            payload,
            names,
            start=start,
            payload_base_offset=payload_base_offset,
        )
        if len(sequence) > len(best):
            best_start = start
            best = sequence
    if not best:
        return (), 0
    return _tdinfo_reconcile_descriptor_indexes(best, type_references), best_start + sum(
        len(descriptor.raw_bytes) for descriptor in best
    )


def _parse_tdinfo_type_descriptor_sequence(
    payload: bytes,
    names: tuple[str, ...],
    *,
    start: int,
    payload_base_offset: int,
) -> tuple[TDInfoTypeDescriptor, ...]:
    descriptors: list[TDInfoTypeDescriptor] = []
    offset = start
    type_index = _TDINFO_DESCRIPTOR_FIRST_INDEX
    while offset < len(payload):
        parsed = _parse_tdinfo_type_descriptor(
            payload,
            names,
            offset=offset,
            payload_base_offset=payload_base_offset,
            type_index=type_index,
        )
        if parsed is None:
            break
        descriptors.append(parsed)
        offset += len(parsed.raw_bytes)
        type_index += 1
    if len(descriptors) < 2 and not any(descriptor.name for descriptor in descriptors):
        return ()
    return tuple(descriptors)


def _tdinfo_descriptor_head_8616(
    payload: bytes,
    names: tuple[str, ...],
    offset: int,
) -> tuple[TDInfoTypeKind, bytes, str, int] | None:
    """Return (kind, raw, name, size) for one descriptor record, or None."""
    if offset + _TDINFO_DESCRIPTOR_RECORD_SIZE > len(payload):
        return None
    try:
        kind = TDInfoTypeKind(payload[offset])
    except ValueError:
        return None
    record_size = (
        _TDINFO_ENUM_DESCRIPTOR_RECORD_SIZE
        if kind is TDInfoTypeKind.ENUM
        else _TDINFO_DESCRIPTOR_RECORD_SIZE
    )
    if offset + record_size > len(payload):
        return None
    name_index = struct.unpack_from("<H", payload, offset + 1)[0]
    if name_index > len(names):
        return None
    name = names[name_index - 1] if name_index else ""
    if name and _classify_tdinfo_name(name) is TDInfoNameKind.SOURCE_FILE:
        return None
    size = struct.unpack_from("<H", payload, offset + 3)[0]
    if size > 0x1000:
        return None
    return kind, payload[offset : offset + record_size], name, size


def _tdinfo_descriptor_links_8616(
    kind: TDInfoTypeKind,
    raw: bytes,
) -> tuple[int | None, int | None, int | None, int | None, int | None, int | None]:
    """Return (base, target, return, call_kind, lower, upper) links for one kind."""
    aux_type = struct.unpack_from("<H", raw, 6)[0]
    if kind in {
        TDInfoTypeKind.C_ARRAY,
        TDInfoTypeKind.VL_ARRAY,
        TDInfoTypeKind.P_ARRAY,
        TDInfoTypeKind.ARRAY_DESCRIPTOR,
    }:
        return aux_type, None, None, None, None, None
    if kind in {
        TDInfoTypeKind.NEAR_POINTER,
        TDInfoTypeKind.FAR_POINTER,
        TDInfoTypeKind.NEAR386_POINTER,
        TDInfoTypeKind.FAR386_POINTER,
    }:
        return None, aux_type, None, None, None, None
    if kind is TDInfoTypeKind.FUNCTION:
        return None, None, aux_type, raw[7], None, None
    if kind is TDInfoTypeKind.ENUM:
        return (
            aux_type,
            None,
            None,
            None,
            _tdinfo_i16(struct.unpack_from("<H", raw, 8)[0]),
            _tdinfo_i16(struct.unpack_from("<H", raw, 10)[0]),
        )
    return None, None, None, None, None, None


def _parse_tdinfo_type_descriptor(
    payload: bytes,
    names: tuple[str, ...],
    *,
    offset: int,
    payload_base_offset: int,
    type_index: int,
) -> TDInfoTypeDescriptor | None:
    head = _tdinfo_descriptor_head_8616(payload, names, offset)
    if head is None:
        return None
    kind, raw, name, size = head
    attributes = raw[5]
    (
        base_type_index,
        target_type_index,
        return_type_index,
        call_kind,
        lower_bound,
        upper_bound,
    ) = _tdinfo_descriptor_links_8616(kind, raw)
    return TDInfoTypeDescriptor(
        type_index=type_index,
        kind=kind,
        name=name,
        size=size,
        payload_offset=payload_base_offset + offset,
        raw_bytes=bytes(raw),
        base_type_index=base_type_index,
        target_type_index=target_type_index,
        return_type_index=return_type_index,
        call_kind=call_kind,
        attributes=attributes,
        lower_bound=lower_bound,
        upper_bound=upper_bound,
    )


def _tdinfo_i16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def _tdinfo_reconcile_descriptor_indexes(
    descriptors: tuple[TDInfoTypeDescriptor, ...],
    type_references: tuple[TDInfoTypeReference, ...],
) -> tuple[TDInfoTypeDescriptor, ...]:
    index_by_name: dict[str, int] = {}
    for ref in type_references:
        if ref.symbol_class not in {TDInfoSymbolClass.TYPEDEF, TDInfoSymbolClass.STRUCT_UNION_OR_ENUM}:
            continue
        if ref.name.startswith("_"):
            continue
        index_by_name.setdefault(ref.name, ref.type_index)
    reconciled: list[TDInfoTypeDescriptor] = []
    next_index = _TDINFO_DESCRIPTOR_FIRST_INDEX
    used_indexes: set[int] = set()
    for descriptor in descriptors:
        named_index = index_by_name.get(descriptor.name)
        if named_index is not None:
            type_index = named_index
        else:
            while next_index in used_indexes:
                next_index += 1
            type_index = next_index
        used_indexes.add(type_index)
        next_index = max(next_index, type_index + 1)
        reconciled.append(replace(descriptor, type_index=type_index))
    return tuple(reconciled)


def _parse_tdinfo_extra_symbol_records(
    payload: bytes,
    names: tuple[str, ...],
) -> tuple[tuple[TDInfoSymbolRecord, ...], int]:
    symbols: list[TDInfoSymbolRecord] = []
    offset = 0
    while offset + 9 <= len(payload):
        name_index, type_index, symbol_offset, segment, bitfield = struct.unpack_from("<HHHHB", payload, offset)
        if not (1 <= name_index <= len(names)):
            break
        name = names[name_index - 1]
        if _classify_tdinfo_name(name) is TDInfoNameKind.SOURCE_FILE:
            break
        if type_index > 0x100:
            break
        try:
            symbol_class = TDInfoSymbolClass(bitfield & 0x7)
        except ValueError:
            break
        if symbol_class not in {
            TDInfoSymbolClass.AUTO,
            TDInfoSymbolClass.PASCAL_VAR,
            TDInfoSymbolClass.REGISTER,
            TDInfoSymbolClass.CONSTANT,
            TDInfoSymbolClass.TYPEDEF,
            TDInfoSymbolClass.STRUCT_UNION_OR_ENUM,
        }:
            break
        if not name or name == "?":
            break
        symbols.append(
            TDInfoSymbolRecord(
                index=name_index,
                type_index=type_index,
                offset=symbol_offset,
                segment=segment,
                symbol_class=symbol_class,
            )
        )
        offset += 9
    return tuple(symbols), offset


def _emit_tdinfo_enum_members_8616(
    sequence: object,
    enum_seen: set[tuple[str, int]],
    owner_type_index: int | None,
) -> list[TDInfoEnumMember]:
    """Materialize enum members for one sequence, deduplicated by enum_seen."""
    emitted: list[TDInfoEnumMember] = []
    for member in sequence:
        enum_key = (member.name, member.type_index)
        if enum_key in enum_seen:
            continue
        enum_seen.add(enum_key)
        emitted.append(
            TDInfoEnumMember(
                name=member.name,
                value=member.type_index,
                attributes=member.attributes,
                payload_offset=member.payload_offset,
                owner_type_index=owner_type_index,
            )
        )
    return emitted


def _emit_tdinfo_struct_members_8616(
    sequence: object,
    seen: set[tuple[str, int, int]],
    owner_type_index: int | None,
) -> list[TDInfoTypeMember]:
    """Materialize struct members for one sequence, deduplicated by seen."""
    emitted: list[TDInfoTypeMember] = []
    for member in sequence:
        key = (member.name, member.offset, member.type_index)
        if key in seen:
            continue
        seen.add(key)
        emitted.append(
            TDInfoTypeMember(
                name=member.name,
                offset=member.offset,
                type_index=member.type_index,
                attributes=member.attributes,
                payload_offset=member.payload_offset,
                owner_type_index=owner_type_index,
            )
        )
    return emitted


def _parse_tdinfo_members(
    payload: bytes,
    names: tuple[str, ...],
    *,
    payload_base_offset: int,
    type_descriptors: tuple[TDInfoTypeDescriptor, ...] = (),
) -> tuple[tuple[TDInfoTypeMember, ...], tuple[TDInfoEnumMember, ...]]:
    members: list[TDInfoTypeMember] = []
    enum_members: list[TDInfoEnumMember] = []
    occupied: set[int] = set()
    seen: set[tuple[str, int, int]] = set()
    enum_seen: set[tuple[str, int]] = set()
    struct_owner_indexes = [
        descriptor.type_index
        for descriptor in type_descriptors
        if descriptor.kind
        in {
            TDInfoTypeKind.STRUCT,
            TDInfoTypeKind.UNION,
            TDInfoTypeKind.VL_STRUCT,
            TDInfoTypeKind.VL_UNION,
        }
    ]
    enum_owner_indexes = [
        descriptor.type_index for descriptor in type_descriptors if descriptor.kind is TDInfoTypeKind.ENUM
    ]
    next_struct_owner = 0
    next_enum_owner = 0
    for start in range(max(0, len(payload) - 9)):
        if start in occupied:
            continue
        sequence = _parse_tdinfo_member_sequence(payload, names, start=start, payload_base_offset=payload_base_offset)
        if len(sequence) < 2:
            continue
        if not any(member.attributes & 0x80 for member in sequence) and not _tdinfo_sequence_followed_by_member_tail(
            payload,
            start + len(sequence) * 5,
        ):
            continue
        for index in range(start, start + len(sequence) * 5):
            occupied.add(index)
        if _tdinfo_member_sequence_is_enum(sequence):
            owner_type_index = (
                enum_owner_indexes[next_enum_owner] if next_enum_owner < len(enum_owner_indexes) else None
            )
            next_enum_owner += 1
            enum_members.extend(_emit_tdinfo_enum_members_8616(sequence, enum_seen, owner_type_index))
        else:
            owner_type_index = (
                struct_owner_indexes[next_struct_owner]
                if next_struct_owner < len(struct_owner_indexes)
                else None
            )
            next_struct_owner += 1
            members.extend(_emit_tdinfo_struct_members_8616(sequence, seen, owner_type_index))
    return tuple(members), tuple(enum_members)


def _parse_tdinfo_member_sequence(
    payload: bytes,
    names: tuple[str, ...],
    *,
    start: int,
    payload_base_offset: int,
) -> tuple[TDInfoTypeMember, ...]:
    members: list[TDInfoTypeMember] = []
    offset = start
    member_offset = 0
    while offset + 5 <= len(payload):
        attributes = payload[offset]
        if attributes & 0x40:
            break
        name_index, type_index = struct.unpack_from("<HH", payload, offset + 1)
        if not (1 <= name_index <= len(names)):
            break
        name = names[name_index - 1]
        if _classify_tdinfo_name(name) is not TDInfoNameKind.IDENTIFIER:
            break
        type_size = _TDINFO_TYPE_SIZES.get(type_index)
        next_is_tail = offset + 5 < len(payload) and payload[offset + 5] in {0x80, 0xC0}
        if type_size is None and not (attributes & 0x80) and not next_is_tail:
            break
        members.append(
            TDInfoTypeMember(
                name=name,
                offset=member_offset,
                type_index=type_index,
                attributes=attributes,
                payload_offset=payload_base_offset + offset,
            )
        )
        offset += 5
        member_offset += type_size or 0
        if attributes & 0x80 or (type_size is None and next_is_tail):
            break
    return tuple(members)


def _tdinfo_sequence_followed_by_member_tail(payload: bytes, offset: int) -> bool:
    return offset < len(payload) and payload[offset] in {0x80, 0xC0}


def _tdinfo_member_sequence_is_enum(sequence: tuple[TDInfoTypeMember, ...]) -> bool:
    # Struct fields use TD type indexes. A named field with type VOID is not
    # valid in normal C, while enum constants commonly have value 0 or 1.
    return any(member.type_index in {0, 1} for member in sequence)


def _parse_tdinfo_name_pool(data: bytes, *, expected_count: int) -> tuple[str, ...]:
    names: list[str] = []
    for raw_name in data.split(b"\x00"):
        if len(names) >= expected_count:
            break
        names.append(raw_name.decode("ascii", errors="ignore"))
    while len(names) < expected_count:
        names.append("")
    return tuple(names)


def _tdinfo_symbol_name(symbol: TDInfoSymbolRecord, names: tuple[str, ...]) -> str | None:
    if not (1 <= symbol.index <= len(names)):
        return None
    name = names[symbol.index - 1]
    if not name or name == "?":
        return None
    return name


def _classify_tdinfo_name_pool(names: tuple[str, ...]) -> tuple[TDInfoNamePoolEntry, ...]:
    return tuple(
        TDInfoNamePoolEntry(index=index, name=name, kind=_classify_tdinfo_name(name))
        for index, name in enumerate(names, start=1)
        if name and name != "?"
    )


def _classify_tdinfo_name(name: str) -> TDInfoNameKind:
    lowered = name.lower()
    basename = lowered.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    if "." in basename and basename.rsplit(".", 1)[-1] in {"c", "h", "asm", "pas", "cpp", "cxx"}:
        return TDInfoNameKind.SOURCE_FILE
    stripped = name.lstrip("_")
    if name.startswith("_") and stripped:
        return TDInfoNameKind.PUBLIC_SYMBOL
    if stripped.replace("@", "_").replace("$", "_").isidentifier():
        return TDInfoNameKind.IDENTIFIER
    return TDInfoNameKind.UNKNOWN


def _tdinfo_name_looks_like_code(name: str) -> bool:
    lowered = name.lower()
    return not lowered.startswith(("dgroup@", "byte_", "word_", "dword_", "off_", "stru_"))


def _tdinfo_type_name_looks_user_defined(name: str) -> bool:
    if not name or name.startswith("_"):
        return False
    return _classify_tdinfo_name(name) is TDInfoNameKind.IDENTIFIER
