# cython: language_level=3, infer_types=True
"""Layer: Optional evidence/reporting.

Responsibility: parse Turbo Debugger TDINFO records into optional labels and diagnostics.
Forbidden: requiring debug symbols for arguments, types, control flow, or validation success.

Package ownership contract (canonical inertia/cli package):
Layer: CLI/fallback/reporting.
Owns command entrypoints, fallback orchestration, diagnostics, and reporting of recovered evidence.
Do not perform frontend, IR, semantic, alias, widening, lowering, structuring, rewrite,
postprocess, or validation work here.
"""

from __future__ import annotations
import dataclasses
import typing
import cython

import struct
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from enum import IntEnum
from pathlib import Path
from typing import Any
import operator
import builtins

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
    MEMBER_FUNCTION = 0x2D
    CLASS = 0x2E
    # Pointer-to-member descriptor (``T K::*``); ``ref`` is the pointee
    # type descriptor.  Size is 4 for data-member pointers and 6 for
    # member-function pointers (offset + this-adjustor + vtab index).
    MEMBER_POINTER = 0x38
    # Synthetic kind for builtin-type records (kind byte holds the Borland
    # builtin type id — see builtin_type_id on the descriptor).
    BUILTIN = 0x100


@dataclasses.dataclass(frozen=True)
class TDInfoHeader:
    """Decoded TDINFO header counters and version fields."""

    major_version: cython.longlong
    minor_version: cython.longlong
    names_pool_size_in_bytes: cython.longlong
    names_count: cython.longlong
    types_count: cython.longlong
    members_count: cython.longlong
    symbols_count: cython.longlong
    globals_count: cython.longlong
    extension_size: cython.longlong
    # Extended TDS 3.x table counts (zero when the header predates them).
    source_modules_count: cython.longlong = 0
    local_symbols_count: cython.longlong = 0
    scopes_count: cython.longlong = 0
    line_entries_count: cython.longlong = 0
    include_files_count: cython.longlong = 0
    segments_count: cython.longlong = 0
    correlations_count: cython.longlong = 0
    class_entries_count: cython.longlong = 0
    parent_entries_count: cython.longlong = 0
    module_class_entries_count: cython.longlong = 0
    coverage_offsets_count: cython.longlong = 0


@dataclasses.dataclass(frozen=True)
class TDInfoModule:
    """One TD32 module-table entry: a compilation unit's table references."""

    index: cython.longlong
    name: object
    language_flags: cython.longlong
    symbols_index: cython.longlong
    symbols_count: cython.longlong
    sources_index: cython.longlong
    sources_count: cython.longlong
    correlation_index: cython.longlong
    correlation_count: cython.longlong


@dataclasses.dataclass(frozen=True)
class TDInfoSourceFile:
    """One TD32 source-file-table entry: a name plus DOS timestamp."""

    index: cython.longlong
    name: object
    size: cython.longlong
    timestamp: cython.longlong


@dataclasses.dataclass(frozen=True)
class TDInfoSegment:
    """One TD32 segment-table entry mapping a code segment to a module."""

    index: cython.longlong
    module_index: cython.longlong
    code_segment: cython.longlong
    code_offset: cython.longlong
    code_length: cython.longlong
    scope_index: cython.longlong
    scope_count: cython.longlong
    correlation_index: cython.longlong
    correlation_count: cython.longlong


@dataclasses.dataclass(frozen=True)
class TDInfoLineEntry:
    """One TD32 line-table entry: a source line's code offset."""

    index: cython.longlong
    line: cython.longlong
    offset: cython.longlong


@dataclasses.dataclass(frozen=True)
class TDInfoScope:
    """One TD32 scope-table entry: a lexical scope's autos and bounds."""

    index: cython.longlong
    autos_index: cython.longlong
    autos_count: cython.longlong
    parent_scope: cython.longlong
    function_symbol: cython.longlong
    scope_offset: cython.longlong
    scope_length: cython.longlong


@dataclasses.dataclass(frozen=True)
class TDInfoCorrelation:
    """One TD32 correlation-table entry mapping a source file's line run."""

    index: cython.longlong
    segment_index: cython.longlong
    file_index: cython.longlong
    line_index: cython.longlong
    line_count: cython.longlong


@dataclasses.dataclass(frozen=True)
class TDInfoClassEntry:
    """One TD32 class-table entry: a class's member list and parents.

    Verified against TDUMP on Borland C++ 2.0 TDS 3.0 output: 11-byte
    records ``u16 parent_table_index, u16 parent_count, u16
    member_ordinal, u16 name_index, u16 vptr_index, u8 info``.
    ``member_ordinal`` is the member-table record ordinal of the class's
    field list — the same ordinal space aggregate descriptors use for
    ``member_ref``.  ``parent_table_index`` is a 1-based index into the
    parent table, whose u16 entries are class-table indexes.
    """

    index: cython.longlong
    name: object
    name_index: cython.longlong
    parent_table_index: cython.longlong
    parent_count: cython.longlong
    member_ordinal: cython.longlong
    vptr_index: cython.longlong
    info: cython.longlong
    parent_class_indexes: tuple[cython.longlong, ...] = ()


@dataclasses.dataclass(frozen=True)
class TDInfoModuleClassEntry:
    """One TD32 module-class-table entry: a module's class-table run."""

    index: cython.longlong
    flags: cython.longlong
    reserved: cython.longlong
    class_index: cython.longlong
    class_count: cython.longlong


@dataclasses.dataclass(frozen=True)
class TDInfoTableLayout:
    """Computed file offsets for every fixed-size TD32 table.

    Real TDS 3.x payloads store the tables back-to-back in a fixed order,
    each with a record size verified against TDUMP on Borland C++ 2.0
    output.  ``members_end`` bounds the variable-size member stream.
    """

    module_table_offset: cython.longlong = 0
    source_file_table_offset: cython.longlong = 0
    line_table_offset: cython.longlong = 0
    scope_table_offset: cython.longlong = 0
    segment_table_offset: cython.longlong = 0
    correlation_table_offset: cython.longlong = 0
    type_table_offset: cython.longlong = 0
    member_table_offset: cython.longlong = 0
    member_table_end: cython.longlong = 0
    class_table_offset: cython.longlong = 0
    parent_table_offset: cython.longlong = 0
    module_class_table_offset: cython.longlong = 0
    coverage_map_table_offset: cython.longlong = 0
    coverage_offsets_table_offset: cython.longlong = 0
    module_flags_table_offset: cython.longlong = 0


@dataclasses.dataclass(frozen=True)
class TDInfoSymbolRecord:
    """Raw TDINFO symbol record with segmented address metadata."""

    index: cython.longlong
    type_index: cython.longlong
    offset: cython.longlong
    segment: cython.longlong
    symbol_class: TDInfoSymbolClass

    def linear_addr(self, *, load_base_linear: cython.longlong) -> cython.longlong:
        """Return a display-only linear address for optional symbol labels."""
        return load_base_linear + (self.segment << 4) + self.offset

    @property
    def signed_offset(self) -> cython.longlong:
        """Interpret the 16-bit record offset as a signed stack displacement."""
        return self.offset - 0x10000 if self.offset & 0x8000 else self.offset


@dataclasses.dataclass(frozen=True)
class TDInfoNamedSymbol:
    """TDINFO symbol paired with its decoded name pool entry."""

    name: object
    record: TDInfoSymbolRecord


@dataclasses.dataclass(frozen=True)
class TDInfoTypeMember:
    """Member entry decoded from a TDINFO structure, union, or array payload."""

    name: object
    offset: cython.longlong
    type_index: cython.longlong
    attributes: cython.longlong
    payload_offset: cython.longlong
    owner_type_index: int | None = None


@dataclasses.dataclass(frozen=True)
class TDInfoEnumMember:
    """Enum value decoded from a TDINFO enum payload."""

    name: object
    value: cython.longlong
    attributes: cython.longlong
    payload_offset: cython.longlong
    owner_type_index: int | None = None


@dataclasses.dataclass(frozen=True)
class TDInfoTypeDescriptor:
    """TDINFO type descriptor retained as optional debug type evidence."""

    type_index: cython.longlong
    kind: TDInfoTypeKind
    name: object
    size: cython.longlong
    payload_offset: cython.longlong
    raw_bytes: object
    base_type_index: int | None = None
    target_type_index: int | None = None
    return_type_index: int | None = None
    call_kind: int | None = None
    attributes: int | None = None
    lower_bound: int | None = None
    upper_bound: int | None = None
    member_ref: int | None = None
    builtin_type_id: int | None = None
    # Raw 8-byte extension slot that follows MEMBER_FUNCTION,
    # MEMBER_POINTER, VL_STRUCT, VL_UNION, and ranged-builtin descriptors
    # (unnumbered in the flat type table).  For MEMBER_FUNCTION it decodes
    # as ``owner_type u16, vtab_offset u16, member_name_index u16,
    # flags u16`` — vtab_offset is the byte offset into the owning class's
    # vtable (0 for non-virtual methods; verified against BC31 output),
    # and the name index points at the member's mangled ``@``-name pool
    # entry.  The flags high nibble varies per module for the same class
    # (0x1000/0x3000/0x9000) — an emission-state marker, not virtualness.
    # For MEMBER_POINTER the tail u16 is the flags field too (0x9000 seen
    # on member-function pointers).
    extension: bytes = b""


@dataclasses.dataclass(frozen=True)
class TDInfoMemberList:
    """One decoded TD32 member-record list: an aggregate's field block.

    ``record_index`` is the TD32 member-table record ordinal of the list's
    first field record.  Borland type descriptors reference this ordinal
    through their trailing ``member_ref`` field (verified against TDUMP).
    """

    record_index: cython.longlong
    payload_offset: cython.longlong
    size: cython.longlong
    owner_name: object
    owner_type_index: int | None
    bitfield: cython.bint
    member_names: object
    method_names: object
    members: tuple[TDInfoTypeMember, ...] = ()
    block_ordinal: int | None = None


@dataclasses.dataclass(frozen=True)
class TDInfoTypeReference:
    """Reference from a named TDINFO symbol to a type descriptor index."""

    name: object
    type_index: cython.longlong
    symbol_class: TDInfoSymbolClass


@dataclasses.dataclass(frozen=True)
class TDInfoNamePoolEntry:
    """Classified TDINFO name-pool string."""

    index: cython.longlong
    name: object
    kind: TDInfoNameKind


@dataclasses.dataclass(frozen=True)
class TDInfoRawTableSpan:
    """Byte span for a TDINFO table retained for diagnostics and schema dumps."""

    name: object
    offset: cython.longlong
    size: cython.longlong
    count: int | None = None
    record_size: int | None = None


@dataclasses.dataclass(frozen=True)
class TDInfoCoverageMapEntry:
    """Per-segment start index into the coverage-offsets table."""

    index: cython.longlong
    offset_index: cython.longlong


@dataclasses.dataclass(frozen=True)
class TDInfoCoverageOffset:
    """Coverage-table code offset: a statement boundary inside a segment."""

    index: cython.longlong
    segment_index: cython.longlong
    offset: cython.longlong


@dataclasses.dataclass(frozen=True)
class TDInfoModuleFlags:
    """TD32 module flags record (all zero in this corpus)."""

    index: cython.longlong
    flags: cython.longlong


@dataclasses.dataclass(frozen=True)
class TDInfoEXEInfo:
    """Parsed TDINFO payload exposed as optional labels and debug diagnostics."""

    header: TDInfoHeader
    debug_info_offset: cython.longlong
    symbols: object
    names: object
    name_pool_entries: tuple[TDInfoNamePoolEntry, ...] = ()
    source_files: tuple[str, ...] = ()
    candidate_identifiers: tuple[str, ...] = ()
    public_symbols: tuple[str, ...] = ()
    local_identifiers: tuple[str, ...] = ()
    named_symbols: tuple[TDInfoNamedSymbol, ...] = ()
    names_by_class: object = field(default_factory=dict)
    symbols_by_class: object = field(default_factory=dict)
    stack_variables: tuple[TDInfoNamedSymbol, ...] = ()
    register_symbols: tuple[TDInfoNamedSymbol, ...] = ()
    constant_symbols: tuple[TDInfoNamedSymbol, ...] = ()
    type_names: tuple[str, ...] = ()
    type_descriptors: tuple[TDInfoTypeDescriptor, ...] = ()
    type_references: tuple[TDInfoTypeReference, ...] = ()
    type_members: tuple[TDInfoTypeMember, ...] = ()
    enum_members: tuple[TDInfoEnumMember, ...] = ()
    member_lists: tuple[TDInfoMemberList, ...] = ()
    modules: tuple[TDInfoModule, ...] = ()
    source_file_entries: tuple[TDInfoSourceFile, ...] = ()
    segments: tuple[TDInfoSegment, ...] = ()
    class_entries: tuple[TDInfoClassEntry, ...] = ()
    parent_class_table: tuple[cython.longlong, ...] = ()
    module_class_entries: tuple[TDInfoModuleClassEntry, ...] = ()
    line_entries: tuple[TDInfoLineEntry, ...] = ()
    scopes: tuple[TDInfoScope, ...] = ()
    correlations: tuple[TDInfoCorrelation, ...] = ()
    coverage_map: tuple[TDInfoCoverageMapEntry, ...] = ()
    coverage_offsets: tuple[TDInfoCoverageOffset, ...] = ()
    module_flags: tuple[TDInfoModuleFlags, ...] = ()
    raw_table_spans: tuple[TDInfoRawTableSpan, ...] = ()
    code_labels: object = field(default_factory=dict)
    data_labels: object = field(default_factory=dict)
    # TLink/TDS version identification
    tds_version_str: str = ""
    tlink_version_str: str = ""
    commandline_hint: str = ""
    products: str = ""


@cython.ccall
def parse_tdinfo_exe(path: Path, *, load_base_linear: cython.longlong = 0) -> TDInfoEXEInfo | None:
    """Parse TDINFO debug metadata from an MZ executable when present."""
    return parse_tdinfo_exe_bytes(path.read_bytes(), load_base_linear=load_base_linear)


@cython.ccall
def _tdinfo_header_layout_8616(data: object) -> object:
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
    names_pool_offset = len(data) - names_pool_size_in_bytes

    # TDS 3.x headers carry an extended count block (+0x12..+0x3E) whose
    # tables let the whole payload be validated byte-for-byte.  Older or
    # synthetic headers only cover the base counts, so the layout is only
    # trusted when the chained table sizes land inside the payload.
    if debug_info_offset + 0x42 <= len(data):
        (
            source_modules_count,
            local_symbols_count,
            scopes_count,
            line_entries_count,
            include_files_count,
            segments_count,
            correlations_count,
        ) = struct.unpack_from("<7H", data, debug_info_offset + 0x12)
        (
            class_entries_count,
            parent_entries_count,
            _overload_entries_count,
            _scope_class_entries_count,
            _global_classes_count,
            module_class_entries_count,
            coverage_offsets_count,
        ) = struct.unpack_from("<7H", data, debug_info_offset + 0x30)
    else:
        (
            source_modules_count,
            local_symbols_count,
            scopes_count,
            line_entries_count,
            include_files_count,
            segments_count,
            correlations_count,
            class_entries_count,
            parent_entries_count,
            module_class_entries_count,
            coverage_offsets_count,
        ) = (0,) * 11

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
        source_modules_count=source_modules_count,
        local_symbols_count=local_symbols_count,
        scopes_count=scopes_count,
        line_entries_count=line_entries_count,
        include_files_count=include_files_count,
        segments_count=segments_count,
        correlations_count=correlations_count,
        class_entries_count=class_entries_count,
        parent_entries_count=parent_entries_count,
        module_class_entries_count=module_class_entries_count,
        coverage_offsets_count=coverage_offsets_count,
    )

    layout = TDInfoTableLayout()
    # Header is 0x50 bytes when the extended count block is present.
    header_size = 0x50 if source_modules_count or segments_count else 44
    symbol_records_offset = debug_info_offset + header_size + extension_size
    if symbol_records_offset + symbols_count * 9 > len(data):
        return None
    if names_pool_offset < symbol_records_offset or names_pool_offset < 0:
        return None

    if header_size == 0x50:
        cursor = symbol_records_offset + symbols_count * 9
        module_table_offset = cursor
        cursor += source_modules_count * 16
        source_file_table_offset = cursor
        cursor += include_files_count * 6
        line_table_offset = cursor
        cursor += line_entries_count * 4
        scope_table_offset = cursor
        cursor += scopes_count * 12
        segment_table_offset = cursor
        cursor += segments_count * 16
        correlation_table_offset = cursor
        cursor += correlations_count * 8
        type_table_offset = cursor
        cursor += types_count * 8
        member_table_offset = cursor
        # The class/parent/module-class/coverage tail tables follow the
        # member stream; their total size bounds the member table end.
        tail_size = (
            class_entries_count * 11
            + parent_entries_count * 2
            + module_class_entries_count * 8
            + segments_count * 2
            + coverage_offsets_count * 2
            + source_modules_count * 4
        )
        member_table_end = names_pool_offset - tail_size
        if member_table_offset <= member_table_end <= len(data):
            tail = member_table_end
            layout = TDInfoTableLayout(
                module_table_offset=module_table_offset,
                source_file_table_offset=source_file_table_offset,
                line_table_offset=line_table_offset,
                scope_table_offset=scope_table_offset,
                segment_table_offset=segment_table_offset,
                correlation_table_offset=correlation_table_offset,
                type_table_offset=type_table_offset,
                member_table_offset=member_table_offset,
                member_table_end=member_table_end,
            )
            layout = replace(
                layout,
                class_table_offset=tail,
                parent_table_offset=tail + class_entries_count * 11,
                module_class_table_offset=(
                    tail + class_entries_count * 11 + parent_entries_count * 2
                ),
                coverage_map_table_offset=(
                    tail
                    + class_entries_count * 11
                    + parent_entries_count * 2
                    + module_class_entries_count * 8
                ),
                coverage_offsets_table_offset=(
                    tail
                    + class_entries_count * 11
                    + parent_entries_count * 2
                    + module_class_entries_count * 8
                    + segments_count * 2
                ),
                module_flags_table_offset=(
                    tail
                    + class_entries_count * 11
                    + parent_entries_count * 2
                    + module_class_entries_count * 8
                    + segments_count * 2
                    + coverage_offsets_count * 2
                ),
            )
    return (
        header,
        debug_info_offset,
        symbol_records_offset,
        names_pool_offset,
        layout,
    )


@dataclasses.dataclass
class _TdinfoSymbolCollection8616:
    """Mutable buckets for TDINFO symbol classification."""

    symbols: object = field(default_factory=list)
    symbols_by_class: object = field(
        default_factory=lambda: {klass: [] for klass in iter(TDInfoSymbolClass)}
    )
    named_symbols: object = field(default_factory=list)
    names_by_class: object = field(
        default_factory=lambda: {klass: [] for klass in iter(TDInfoSymbolClass)}
    )
    code_labels: object = field(default_factory=dict)
    data_labels: object = field(default_factory=dict)
    type_names: object = field(default_factory=list)
    stack_variables: object = field(default_factory=list)
    register_symbols: object = field(default_factory=list)
    constant_symbols: object = field(default_factory=list)
    type_references: object = field(default_factory=list)

    def add_symbol(self, symbol: TDInfoSymbolRecord, names: object) -> object:
        """Classify one symbol record into the typed buckets."""
        name: object
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


@cython.ccall
def _collect_tdinfo_symbols_8616(
    data: object,
    *,
    symbol_records_offset: cython.longlong,
    symbols_count: cython.longlong,
    names: object,
    load_base_linear: cython.longlong,
    collection: _TdinfoSymbolCollection8616,
) -> None:
    """Fold fixed 9-byte symbol records into the collection."""
    name: object
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


@cython.ccall
def _tdinfo_version_strings_8616(major_version: cython.longlong, minor_version: cython.longlong) -> object:
    """Return (tds, tlink, commandline_hint, products) version strings."""
    normalized_minor_version = 10 if major_version == 3 and minor_version == 0x10 else minor_version
    tds_key = (major_version, normalized_minor_version)
    if tds_key in _OLD_FORMAT_NO_TDS:
        return "N/A (pre-2.0 format)", "1.0/1.1", "No TDS info in header", "Turbo C 1.0/1.5"
    if tds_key in _TDS_VERSION_MAP:
        return _TDS_VERSION_MAP[tds_key]
    return f"{major_version}.{normalized_minor_version}", "unknown", "", ""


def parse_tdinfo_exe_bytes(data: object, *, load_base_linear: cython.longlong = 0) -> TDInfoEXEInfo | None:
    """Parse TDINFO debug metadata from executable bytes when present."""
    layout_result: object
    symbol: object
    layout_result = _tdinfo_header_layout_8616(data)
    if layout_result is None:
        return None
    header, debug_info_offset, symbol_records_offset, names_pool_offset, table_layout = layout_result
    symbols_count = header.symbols_count
    symbol_records_size = symbols_count * 9
    payload_offset = symbol_records_offset + symbol_records_size
    payload_blob = data[payload_offset:names_pool_offset]

    names = _parse_tdinfo_name_pool(data[names_pool_offset:], expected_count=header.names_count)
    name_pool_entries = _classify_tdinfo_name_pool(names)
    public_symbols = tuple(entry.name for entry in iter(name_pool_entries) if entry.kind is TDInfoNameKind.PUBLIC_SYMBOL)
    local_identifiers = tuple(entry.name for entry in iter(name_pool_entries) if entry.kind is TDInfoNameKind.IDENTIFIER)

    collection = _TdinfoSymbolCollection8616()
    _collect_tdinfo_symbols_8616(
        data,
        symbol_records_offset=symbol_records_offset,
        symbols_count=symbols_count,
        names=names,
        load_base_linear=load_base_linear,
        collection=collection,
    )

    modules: tuple[TDInfoModule, ...] = ()
    source_file_entries: tuple[TDInfoSourceFile, ...] = ()
    segments: tuple[TDInfoSegment, ...] = ()
    class_entries: tuple[TDInfoClassEntry, ...] = ()
    parent_class_table: tuple[cython.longlong, ...] = ()
    module_class_entries: tuple[TDInfoModuleClassEntry, ...] = ()
    line_entries: tuple[TDInfoLineEntry, ...] = ()
    scopes: tuple[TDInfoScope, ...] = ()
    correlations: tuple[TDInfoCorrelation, ...] = ()
    coverage_map: tuple[TDInfoCoverageMapEntry, ...] = ()
    coverage_offsets: tuple[TDInfoCoverageOffset, ...] = ()
    module_flags: tuple[TDInfoModuleFlags, ...] = ()
    type_descriptors: object
    member_payload: object
    member_base_offset: cython.longlong

    if table_layout.type_table_offset:
        # Extended TDS 3.x layout: every table offset is computed from the
        # header counts, and the type table is a flat 1-based array.
        modules = _parse_tdinfo_module_table(
            data,
            table_layout.module_table_offset,
            header.source_modules_count,
            names,
        )
        source_file_entries = _parse_tdinfo_source_file_table(
            data,
            table_layout.source_file_table_offset,
            header.include_files_count,
            names,
        )
        segments = _parse_tdinfo_segment_table(
            data,
            table_layout.segment_table_offset,
            header.segments_count,
        )
        parent_class_table = _parse_tdinfo_parent_table(
            data,
            table_layout.parent_table_offset,
            header.parent_entries_count,
        )
        class_entries = _parse_tdinfo_class_table(
            data,
            table_layout.class_table_offset,
            header.class_entries_count,
            names,
            parent_class_table,
        )
        module_class_entries = _parse_tdinfo_module_class_table(
            data,
            table_layout.module_class_table_offset,
            header.module_class_entries_count,
        )
        line_entries = _parse_tdinfo_line_table(
            data,
            table_layout.line_table_offset,
            header.line_entries_count,
        )
        scopes = _parse_tdinfo_scope_table(
            data,
            table_layout.scope_table_offset,
            header.scopes_count,
        )
        correlations = _parse_tdinfo_correlation_table(
            data,
            table_layout.correlation_table_offset,
            header.correlations_count,
        )
        coverage_map = _parse_tdinfo_coverage_map(
            data,
            table_layout.coverage_map_table_offset,
            header.segments_count,
        )
        coverage_offsets = _parse_tdinfo_coverage_offsets(
            data,
            table_layout.coverage_offsets_table_offset,
            header.coverage_offsets_count,
            coverage_map,
        )
        module_flags = _parse_tdinfo_module_flags(
            data,
            table_layout.module_flags_table_offset,
            header.source_modules_count,
        )
        type_descriptors = _parse_tdinfo_flat_type_table(
            data,
            table_layout.type_table_offset,
            header.types_count,
            names,
            members_bound=header.members_count + 64,
        )
        member_payload = data[table_layout.member_table_offset : table_layout.member_table_end]
        member_base_offset = table_layout.member_table_offset
    else:
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
            members_count=header.members_count,
            types_count=header.types_count,
        )
        member_payload = descriptor_payload
        member_base_offset = payload_offset + extra_symbol_bytes

    raw_table_spans = _tdinfo_raw_table_spans(
        debug_info_offset=debug_info_offset,
        symbol_records_offset=symbol_records_offset,
        symbol_records_size=symbol_records_size,
        symbols_count=symbols_count,
        names_pool_offset=names_pool_offset,
        names_pool_size=header.names_pool_size_in_bytes,
        header=header,
        layout=table_layout,
    )
    type_members, enum_members, member_lists = _parse_tdinfo_members(
        member_payload,
        names,
        payload_base_offset=member_base_offset,
        type_descriptors=type_descriptors,
        types_count=header.types_count,
        class_entries=class_entries,
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
        source_files=tuple(entry.name for entry in iter(name_pool_entries) if entry.kind is TDInfoNameKind.SOURCE_FILE),
        candidate_identifiers=tuple(
            entry.name
            for entry in iter(name_pool_entries)
            if entry.kind in {TDInfoNameKind.IDENTIFIER, TDInfoNameKind.PUBLIC_SYMBOL}
        ),
        public_symbols=public_symbols,
        local_identifiers=local_identifiers,
        named_symbols=tuple(collection.named_symbols),
        names_by_class={klass: tuple(items) for klass, items in builtins.iter(collection.names_by_class.items()) if items},
        symbols_by_class={klass: tuple(items) for klass, items in builtins.iter(collection.symbols_by_class.items()) if items},
        stack_variables=tuple(collection.stack_variables),
        register_symbols=tuple(collection.register_symbols),
        constant_symbols=tuple(collection.constant_symbols),
        type_names=tuple(dict.fromkeys(collection.type_names)),
        type_descriptors=type_descriptors,
        type_references=tuple(dict.fromkeys(collection.type_references)),
        type_members=type_members,
        enum_members=enum_members,
        member_lists=member_lists,
        modules=modules,
        source_file_entries=source_file_entries,
        segments=segments,
        class_entries=class_entries,
        parent_class_table=parent_class_table,
        module_class_entries=module_class_entries,
        line_entries=line_entries,
        scopes=scopes,
        correlations=correlations,
        coverage_map=coverage_map,
        coverage_offsets=coverage_offsets,
        module_flags=module_flags,
        raw_table_spans=raw_table_spans,
        code_labels=collection.code_labels,
        data_labels=collection.data_labels,
        tds_version_str=tds_version_str,
        tlink_version_str=tlink_version_str,
        commandline_hint=commandline_hint,
        products=products,
    )


@cython.ccall
def _tdinfo_raw_table_spans(
    *,
    debug_info_offset: cython.longlong,
    symbol_records_offset: cython.longlong,
    symbol_records_size: cython.longlong,
    symbols_count: cython.longlong,
    names_pool_offset: cython.longlong,
    names_pool_size: cython.longlong,
    header: TDInfoHeader,
    layout: TDInfoTableLayout,
) -> tuple[TDInfoRawTableSpan, ...]:
    count: object
    name: object
    offset: object
    record_size: object
    size: object
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
    if layout.type_table_offset:
        # Extended layout: report each decoded table's byte span so no
        # TDINFO region silently disappears from the dump.
        named = (
            ("module_table", layout.module_table_offset, header.source_modules_count * 16, header.source_modules_count, 16),
            ("source_file_table", layout.source_file_table_offset, header.include_files_count * 6, header.include_files_count, 6),
            ("line_number_table", layout.line_table_offset, header.line_entries_count * 4, header.line_entries_count, 4),
            ("scope_table", layout.scope_table_offset, header.scopes_count * 12, header.scopes_count, 12),
            ("segment_table", layout.segment_table_offset, header.segments_count * 16, header.segments_count, 16),
            ("correlation_table", layout.correlation_table_offset, header.correlations_count * 8, header.correlations_count, 8),
            ("type_table", layout.type_table_offset, header.types_count * 8, header.types_count, 8),
            ("member_table", layout.member_table_offset, layout.member_table_end - layout.member_table_offset, header.members_count, None),
        )
        for name, offset, size, count, record_size in named:
            spans.append(
                TDInfoRawTableSpan(name=name, offset=offset, size=size, count=count, record_size=record_size)
            )
        tail_named = (
            ("class_table", layout.class_table_offset, header.class_entries_count * 11, header.class_entries_count, 11),
            ("parent_table", layout.parent_table_offset, header.parent_entries_count * 2, header.parent_entries_count, 2),
            ("module_class_table", layout.module_class_table_offset, header.module_class_entries_count * 8, header.module_class_entries_count, 8),
            ("coverage_map_table", layout.coverage_map_table_offset, header.segments_count * 2, header.segments_count, 2),
            ("coverage_offsets_table", layout.coverage_offsets_table_offset, header.coverage_offsets_count * 2, header.coverage_offsets_count, 2),
            ("module_flags_table", layout.module_flags_table_offset, header.source_modules_count * 4, header.source_modules_count, 4),
        )
        for name, offset, size, count, record_size in tail_named:
            if size > 0:
                spans.append(
                    TDInfoRawTableSpan(name=name, offset=offset, size=size, count=count, record_size=record_size)
                )
    else:
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


@cython.ccall
def _parse_tdinfo_module_table(
    data: object,
    offset: cython.longlong,
    count: cython.longlong,
    names: object,
) -> tuple[TDInfoModule, ...]:
    """Decode the TD32 module table: 16-byte records of table references."""
    modules: list[TDInfoModule] = []
    for index in range(count):
        entry_offset = offset + index * 16
        if entry_offset + 16 > len(data):
            break
        (
            name_index,
            language_flags,
            symbols_index,
            symbols_count,
            sources_index,
            sources_count,
            correlation_index,
            correlation_count,
        ) = struct.unpack_from("<8H", data, entry_offset)
        name = names[name_index - 1] if 0 < name_index <= len(names) else ""
        modules.append(
            TDInfoModule(
                index=index + 1,
                name=name,
                language_flags=language_flags,
                symbols_index=symbols_index,
                symbols_count=symbols_count,
                sources_index=sources_index,
                sources_count=sources_count,
                correlation_index=correlation_index,
                correlation_count=correlation_count,
            )
        )
    return tuple(modules)


@cython.ccall
def _parse_tdinfo_source_file_table(
    data: object,
    offset: cython.longlong,
    count: cython.longlong,
    names: object,
) -> tuple[TDInfoSourceFile, ...]:
    """Decode the TD32 source-file table: 6-byte name/size/timestamp records."""
    entries: list[TDInfoSourceFile] = []
    for index in range(count):
        entry_offset = offset + index * 6
        if entry_offset + 6 > len(data):
            break
        name_index, size, timestamp = struct.unpack_from("<HHH", data, entry_offset)
        name = names[name_index - 1] if 0 < name_index <= len(names) else ""
        entries.append(
            TDInfoSourceFile(
                index=index + 1,
                name=name,
                size=size,
                timestamp=timestamp,
            )
        )
    return tuple(entries)


@cython.ccall
def _parse_tdinfo_segment_table(
    data: object,
    offset: cython.longlong,
    count: cython.longlong,
) -> tuple[TDInfoSegment, ...]:
    """Decode the TD32 segment table: 16-byte module/scope mappings."""
    segments: list[TDInfoSegment] = []
    for index in range(count):
        entry_offset = offset + index * 16
        if entry_offset + 16 > len(data):
            break
        (
            module_index,
            code_segment,
            code_offset,
            code_length,
            scope_index,
            scope_count,
            correlation_index,
            correlation_count,
        ) = struct.unpack_from("<8H", data, entry_offset)
        segments.append(
            TDInfoSegment(
                index=index + 1,
                module_index=module_index,
                code_segment=code_segment,
                code_offset=code_offset,
                code_length=code_length,
                scope_index=scope_index,
                scope_count=scope_count,
                correlation_index=correlation_index,
                correlation_count=correlation_count,
            )
        )
    return tuple(segments)


@cython.ccall
def _parse_tdinfo_class_table(
    data: object,
    offset: cython.longlong,
    count: cython.longlong,
    names: object,
    parent_class_table: object,
) -> tuple[TDInfoClassEntry, ...]:
    """Decode the TD32 class table: 11-byte class records."""
    classes: list[TDInfoClassEntry] = []
    for index in range(count):
        entry_offset = offset + index * 11
        if entry_offset + 11 > len(data):
            break
        (
            parent_table_index,
            parent_count,
            member_ordinal,
            name_index,
            vptr_index,
            info,
        ) = struct.unpack_from("<HHHHHB", data, entry_offset)
        name = names[name_index - 1] if 1 <= name_index <= len(names) else ""
        # The parent-table index is 1-based (TDUMP prints it verbatim).
        parents: tuple[cython.longlong, ...] = ()
        if parent_count and parent_table_index >= 1:
            base = parent_table_index - 1
            parents = tuple(parent_class_table[base : base + parent_count])
        classes.append(
            TDInfoClassEntry(
                index=index + 1,
                name=name,
                name_index=name_index,
                parent_table_index=parent_table_index,
                parent_count=parent_count,
                member_ordinal=member_ordinal,
                vptr_index=vptr_index,
                info=info,
                parent_class_indexes=parents,
            )
        )
    return tuple(classes)


def _parse_tdinfo_parent_table(
    data: object,
    offset: cython.longlong,
    count: cython.longlong,
) -> tuple[cython.longlong, ...]:
    """Decode the TD32 parent table: u16 class-table indexes."""
    if offset < 0 or offset + count * 2 > len(data):
        return ()
    return tuple(
        struct.unpack_from("<H", data, offset + index * 2)[0]
        for index in range(count)
    )


@cython.ccall
def _parse_tdinfo_module_class_table(
    data: object,
    offset: cython.longlong,
    count: cython.longlong,
) -> tuple[TDInfoModuleClassEntry, ...]:
    """Decode the TD32 module-class table: 8-byte class-range records."""
    entries: list[TDInfoModuleClassEntry] = []
    for index in range(count):
        entry_offset = offset + index * 8
        if entry_offset + 8 > len(data):
            break
        flags, reserved, class_index, class_count = struct.unpack_from(
            "<4H", data, entry_offset
        )
        entries.append(
            TDInfoModuleClassEntry(
                index=index + 1,
                flags=flags,
                reserved=reserved,
                class_index=class_index,
                class_count=class_count,
            )
        )
    return tuple(entries)


def _parse_tdinfo_line_table(
    data: object,
    offset: cython.longlong,
    count: cython.longlong,
) -> tuple[TDInfoLineEntry, ...]:
    """Decode the TD32 line table: 4-byte (line, offset) records."""
    if offset < 0 or offset + count * 4 > len(data):
        return ()
    return tuple(
        TDInfoLineEntry(
            index=index + 1,
            line=line,
            offset=code_offset,
        )
        for index, (line, code_offset) in builtins.iter(enumerate(
            struct.iter_unpack("<HH", data[offset : offset + count * 4])
        ))
    )


@cython.ccall
def _parse_tdinfo_scope_table(
    data: object,
    offset: cython.longlong,
    count: cython.longlong,
) -> tuple[TDInfoScope, ...]:
    """Decode the TD32 scope table: 12-byte lexical scope records."""
    scopes: list[TDInfoScope] = []
    for index in range(count):
        entry_offset = offset + index * 12
        if entry_offset + 12 > len(data):
            break
        (
            autos_index,
            autos_count,
            parent_scope,
            function_symbol,
            scope_offset,
            scope_length,
        ) = struct.unpack_from("<6H", data, entry_offset)
        scopes.append(
            TDInfoScope(
                index=index + 1,
                autos_index=autos_index,
                autos_count=autos_count,
                parent_scope=parent_scope,
                function_symbol=function_symbol,
                scope_offset=scope_offset,
                scope_length=scope_length,
            )
        )
    return tuple(scopes)


def _parse_tdinfo_coverage_map(
    data: object,
    offset: cython.longlong,
    count: cython.longlong,
) -> tuple[TDInfoCoverageMapEntry, ...]:
    """Decode the coverage map: one u16 per segment = start index into the
    coverage-offsets table (statement-boundary code offsets)."""
    if offset < 0 or offset + count * 2 > len(data):
        return ()
    return tuple(
        TDInfoCoverageMapEntry(index=index + 1, offset_index=start)
        for index, (start,) in builtins.iter(enumerate(
            struct.iter_unpack("<H", data[offset : offset + count * 2])
        ))
    )


def _parse_tdinfo_coverage_offsets(
    data: object,
    offset: cython.longlong,
    count: cython.longlong,
    coverage_map: object,
) -> tuple[TDInfoCoverageOffset, ...]:
    """Decode coverage offsets, attributing each to its segment's range."""
    code_offset: object
    index: object
    if offset < 0 or offset + count * 2 > len(data):
        return ()
    bounds = sorted(entry.offset_index for entry in iter(coverage_map) if entry.offset_index)
    bounds.append(count + 1)
    offsets: list[TDInfoCoverageOffset] = []
    for index, (code_offset,) in enumerate(
        struct.iter_unpack("<H", data[offset : offset + count * 2])
    ):
        ordinal = index + 1
        segment_index = sum(1 for bound in iter(bounds[:-1]) if ordinal >= bound)
        offsets.append(
            TDInfoCoverageOffset(
                index=ordinal,
                segment_index=segment_index,
                offset=code_offset,
            )
        )
    return tuple(offsets)


def _parse_tdinfo_module_flags(
    data: object,
    offset: cython.longlong,
    count: cython.longlong,
) -> tuple[TDInfoModuleFlags, ...]:
    """Decode per-module flag dwords (unused/zero in this corpus)."""
    if offset < 0 or offset + count * 4 > len(data):
        return ()
    return tuple(
        TDInfoModuleFlags(index=index + 1, flags=flags)
        for index, (flags,) in builtins.iter(enumerate(
            struct.iter_unpack("<I", data[offset : offset + count * 4])
        ))
    )


@cython.ccall
def _parse_tdinfo_correlation_table(
    data: object,
    offset: cython.longlong,
    count: cython.longlong,
) -> tuple[TDInfoCorrelation, ...]:
    """Decode the TD32 correlation table: 8-byte file/line-run records."""
    correlations: list[TDInfoCorrelation] = []
    for index in range(count):
        entry_offset = offset + index * 8
        if entry_offset + 8 > len(data):
            break
        segment_index, file_index, line_index, line_count = struct.unpack_from(
            "<4H", data, entry_offset
        )
        correlations.append(
            TDInfoCorrelation(
                index=index + 1,
                segment_index=segment_index,
                file_index=file_index,
                line_index=line_index,
                line_count=line_count,
            )
        )
    return tuple(correlations)


@cython.ccall
def _parse_tdinfo_flat_type_table(
    data: object,
    offset: cython.longlong,
    count: cython.longlong,
    names: object,
    *,
    members_bound: cython.longlong = 0x10000,
) -> tuple[TDInfoTypeDescriptor, ...]:
    """Decode the flat TD32 type table: 8-byte records, 1-based index.

    Verified against TDUMP on Borland C++ 2.0 TDS 3.0 output: type index N
    lives at ``offset + (N - 1) * 8`` — member records reference these
    indexes directly, so no anchoring is required.
    """
    parsed: object
    descriptors: list[TDInfoTypeDescriptor] = []
    index = 0
    while index < count:
        entry_offset = offset + index * 8
        if entry_offset + _TDINFO_DESCRIPTOR_RECORD_SIZE > len(data):
            break
        parsed = _parse_tdinfo_type_descriptor(
            data,
            names,
            offset=entry_offset,
            payload_base_offset=0,
            type_index=index + 1,
            members_bound=members_bound,
            fixed_record_size=_TDINFO_DESCRIPTOR_RECORD_SIZE,
            allow_builtins=True,
        )
        if parsed is None:
            index += 1
            continue
        # Member-function, very-large, and integral-builtin descriptors
        # are followed by an 8-byte extension slot (TDUMP prints it as raw
        # trailing bytes and does not give it a type number).
        has_extension = parsed.kind in _TDINFO_EXTENDED_DESCRIPTOR_KINDS or (
            parsed.kind is TDInfoTypeKind.BUILTIN
            and parsed.builtin_type_id in _TDINFO_RANGED_BUILTIN_TYPE_IDS
        )
        if has_extension:
            parsed = replace(
                parsed, extension=data[entry_offset + 8 : entry_offset + 16]
            )
        descriptors.append(parsed)
        index += 2 if has_extension else 1
    return tuple(descriptors)


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

# Aggregate descriptor kinds whose trailing u16 is a member-table record
# ordinal (TD32 member_ref), verified against TDUMP "New record offset"
# markers on Borland C++ 2.0 TDS 3.0 output.
_TDINFO_AGGREGATE_DESCRIPTOR_KINDS = {
    TDInfoTypeKind.STRUCT,
    TDInfoTypeKind.UNION,
    TDInfoTypeKind.VL_STRUCT,
    TDInfoTypeKind.VL_UNION,
    TDInfoTypeKind.ENUM,
    TDInfoTypeKind.CLASS,
}

# Very-large aggregate descriptors end in a 2-byte field that is not a
# member-table record ordinal (e.g. PARMS frames carry values like 0xD600
# where the member table holds only ~2800 records).
_TDINFO_VL_DESCRIPTOR_KINDS = {
    TDInfoTypeKind.VL_STRUCT,
    TDInfoTypeKind.VL_UNION,
}

# Descriptor kinds followed by an unnumbered 8-byte extension slot in the
# type table (verified against TDUMP type-number gaps).
_TDINFO_EXTENDED_DESCRIPTOR_KINDS = {
    TDInfoTypeKind.MEMBER_FUNCTION,
    TDInfoTypeKind.MEMBER_POINTER,
    TDInfoTypeKind.VL_STRUCT,
    TDInfoTypeKind.VL_UNION,
}

# Builtin-type records start the type table: their kind byte is the Borland
# builtin type id (void, char, int, label, raw pword/tbyte, ...).  Integral
# builtins carry an 8-byte min/max range extension slot (TDUMP prints it as
# raw trailing bytes and skips it in the type numbering).
_TDINFO_BUILTIN_TYPE_IDS = {
    0x00, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0C,
    0x0D, 0x0E, 0x0F, 0x10, 0x24, 0x28, 0x2A, 0x2B,
}
_TDINFO_RANGED_BUILTIN_TYPE_IDS = {0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0C}

# Borland builtin type ids, verified against TDUMP's own "Types Table"
# rendering on both the real executable and a BC31-compiled test binary:
# TD32 folds plain ``char`` into the unsigned slot (id 8) and ``short`` /
# ``unsigned short`` into the int slots.  The pascal_* entries are Turbo
# Pascal builtins shared with Turbo Debugger — they appear as fixed
# preamble slots but are never referenced by C++ members in this corpus.
# ``label``/``pword`` (ids 0x24/0x2A) are protected-mode control-flow and
# far-pointer builtins emitted by BC2-era libraries.
TDINFO_BUILTIN_TYPE_NAMES: dict[cython.longlong, str] = {
    0x00: "void",
    0x04: "signed char",
    0x05: "int",
    0x06: "long",
    0x07: "long long",
    0x08: "unsigned char",
    0x09: "unsigned int",
    0x0A: "unsigned long",
    0x0C: "pascal_char",
    0x0D: "float",
    0x0E: "pascal_real48",
    0x0F: "double",
    0x10: "long double",
    0x24: "label",
    0x28: "pascal_bool",
    0x2A: "pword",
    0x2B: "tbyte",
}


@cython.ccall
def _parse_tdinfo_type_descriptors(
    payload: object,
    names: object,
    *,
    payload_base_offset: cython.longlong,
    type_references: object = (),
    members_count: cython.longlong = 0,
    types_count: cython.longlong = 0,
) -> object:
    """Scan `payload` for TD32 type descriptor records.

    Real TDS 3.x payloads keep descriptor records in per-module runs mixed
    with other tables, so every offset is probed instead of assuming one
    contiguous descriptor table.
    """
    parsed: object
    descriptors: list[TDInfoTypeDescriptor] = []
    offset = 0
    type_index = _TDINFO_DESCRIPTOR_FIRST_INDEX
    while offset + _TDINFO_DESCRIPTOR_RECORD_SIZE <= len(payload):
        parsed = _parse_tdinfo_type_descriptor(
            payload,
            names,
            offset=offset,
            payload_base_offset=payload_base_offset,
            type_index=type_index,
            members_bound=members_count + 64,
        )
        if parsed is None:
            offset += 1
            continue
        descriptors.append(parsed)
        offset += len(parsed.raw_bytes)
        if parsed.kind in _TDINFO_EXTENDED_DESCRIPTOR_KINDS:
            # These descriptor kinds carry an 8-byte extension slot.
            offset += _TDINFO_DESCRIPTOR_RECORD_SIZE
        type_index += 1
    return _tdinfo_reconcile_descriptor_indexes(
        tuple(descriptors),
        type_references,
        types_count=types_count,
    )


@cython.ccall
def _tdinfo_descriptor_kind_8616(
    payload: object,
    offset: cython.longlong,
    allow_builtins: cython.bint,
) -> TDInfoTypeKind | None:
    """Map a record's tag byte to a type kind, or None when unknown."""
    try:
        return TDInfoTypeKind(payload[offset])
    except ValueError:
        if allow_builtins and payload[offset] in _TDINFO_BUILTIN_TYPE_IDS:
            return TDInfoTypeKind.BUILTIN
        return None


@cython.ccall
def _tdinfo_descriptor_head_8616(
    payload: object,
    names: object,
    offset: cython.longlong,
    *,
    members_bound: cython.longlong = 0x10000,
    fixed_record_size: cython.longlong = 0,
    allow_builtins: cython.bint = False,
) -> object:
    """Return (kind, raw, name, size) for one descriptor record, or None."""
    kind: object
    if offset + _TDINFO_DESCRIPTOR_RECORD_SIZE > len(payload):
        return None
    kind = _tdinfo_descriptor_kind_8616(payload, offset, allow_builtins)
    if kind is None:
        return None
    record_size = fixed_record_size or (
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
    if kind in _TDINFO_AGGREGATE_DESCRIPTOR_KINDS:
        # Aggregate descriptors name a struct/class/union or are anonymous
        # nested aggregates; a mangled method name or an empty+sizeless
        # record is a false positive from scanning foreign bytes.  VL
        # (very-large) descriptors carry a different aux field than the
        # member-table ordinal — no bound applies to them.
        if name.startswith("@") or (not name and size == 0):
            return None
        if (
            kind not in _TDINFO_VL_DESCRIPTOR_KINDS
            and struct.unpack_from("<H", payload, offset + 6)[0] >= members_bound
        ):
            return None
    return kind, payload[offset : offset + record_size], name, size


@cython.ccall
def _tdinfo_descriptor_links_8616(
    kind: TDInfoTypeKind,
    raw: object,
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
        TDInfoTypeKind.MEMBER_POINTER,
    }:
        return None, aux_type, None, None, None, None
    if kind in {TDInfoTypeKind.FUNCTION, TDInfoTypeKind.MEMBER_FUNCTION}:
        return None, None, aux_type, raw[7], None, None
    if kind is TDInfoTypeKind.ENUM:
        lower = _tdinfo_i16(struct.unpack_from("<H", raw, 8)[0]) if len(raw) >= 12 else None
        upper = _tdinfo_i16(struct.unpack_from("<H", raw, 10)[0]) if len(raw) >= 12 else None
        return aux_type, None, None, None, lower, upper
    return None, None, None, None, None, None


@cython.ccall
def _parse_tdinfo_type_descriptor(
    payload: object,
    names: object,
    *,
    offset: cython.longlong,
    payload_base_offset: cython.longlong,
    type_index: cython.longlong,
    members_bound: cython.longlong = 0x10000,
    fixed_record_size: cython.longlong = 0,
    allow_builtins: cython.bint = False,
) -> TDInfoTypeDescriptor | None:
    head: object
    head = _tdinfo_descriptor_head_8616(
        payload,
        names,
        offset,
        members_bound=members_bound,
        fixed_record_size=fixed_record_size,
        allow_builtins=allow_builtins,
    )
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
    member_ref = None
    if kind in _TDINFO_AGGREGATE_DESCRIPTOR_KINDS and kind not in _TDINFO_VL_DESCRIPTOR_KINDS:
        member_ref = struct.unpack_from("<H", raw, 6)[0]
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
        member_ref=member_ref,
        builtin_type_id=raw[0] if kind is TDInfoTypeKind.BUILTIN else None,
    )


@cython.ccall
def _tdinfo_i16(value: cython.longlong) -> cython.longlong:
    return value - 0x10000 if value & 0x8000 else value


def _tdinfo_group_descriptor_runs(
    descriptors: object,
) -> object:
    """Group offset-sorted descriptors into contiguous 8-byte runs."""
    descriptor: object
    by_offset = sorted(descriptors, key=lambda descriptor: descriptor.payload_offset)
    runs: list[list[TDInfoTypeDescriptor]] = []
    for descriptor in by_offset:
        if runs and operator.eq(descriptor.payload_offset - runs[-1][-1].payload_offset, _TDINFO_DESCRIPTOR_RECORD_SIZE):
            runs[-1].append(descriptor)
        else:
            runs.append([descriptor])
    return runs


def _tdinfo_anchor_run_by_votes(
    run: object,
    index_by_name: object,
) -> int | None:
    """Vote a run's index base from named descriptors, or None if ambiguous.

    Each named descriptor may be any module's copy of that type, so every
    candidate global index contributes one base vote.  A base is trusted
    only when supported by anchors with a unique index or by at least two
    distinct names — otherwise ambiguous single-name copies would mislabel
    the whole run.
    """
    descriptor: object
    global_index: object
    position: object
    votes: Counter[cython.longlong] = Counter()
    names_at_base: dict[cython.longlong, set[str]] = {}
    for position, descriptor in enumerate(run):
        for global_index in index_by_name.get(descriptor.name, ()):
            base = global_index - position
            if base < 0:
                continue
            votes[base] += 1
            names_at_base.setdefault(base, set()).add(descriptor.name)
    if not votes:
        return None
    base, _ = max(votes.items(), key=lambda item: (len(names_at_base[item[0]]), item[1], -item[0]))
    supporting = names_at_base[base]
    if len(supporting) >= 2 or any(len(index_by_name[name]) == 1 for name in iter(supporting)):
        return base
    return None


def _tdinfo_anchor_run_by_continuation(
    run: object,
    position: cython.longlong,
    runs: object,
    index_by_name: object,
    assigned: object,
    index_bound: cython.longlong,
) -> int | None:
    """Pick the candidate base closest to the previous run's continuation.

    Gaps between runs hold records the scanner could not decode, so
    ``prev_base + prev_len + gap_records`` estimates the next base.
    """
    expected: object
    descriptor: object
    global_index: object
    pos: object
    candidates: set[cython.longlong] = set()
    for pos, descriptor in enumerate(run):
        for global_index in index_by_name.get(descriptor.name, ()):
            base = global_index - pos
            if base >= 0 and base + len(run) <= index_bound:
                candidates.add(base)
    if not candidates:
        return None
    expected = None
    if position > 0:
        prev = runs[position - 1]
        if id(prev[-1]) in assigned:
            gap = run[0].payload_offset - (prev[-1].payload_offset + _TDINFO_DESCRIPTOR_RECORD_SIZE)
            if gap >= 0:
                expected = assigned[id(prev[-1])] + 1 + gap // _TDINFO_DESCRIPTOR_RECORD_SIZE
    if expected is None:
        return min(candidates)
    return min(candidates, key=lambda candidate: (abs(candidate - expected), candidate))


@cython.ccall
def _tdinfo_type_index_by_name(
    type_references: object,
) -> object:
    """Map each named type to every global index its copies occupy."""
    ref: object
    index_by_name: dict[str, set[cython.longlong]] = {}
    for ref in type_references:
        if ref.symbol_class not in {TDInfoSymbolClass.TYPEDEF, TDInfoSymbolClass.STRUCT_UNION_OR_ENUM}:
            continue
        if ref.name.startswith("_"):
            continue
        index_by_name.setdefault(ref.name, set()).add(ref.type_index)
    return index_by_name


def _tdinfo_assign_run_bases(
    runs: object,
    index_by_name: object,
    types_count: cython.longlong,
) -> object:
    """Anchor each descriptor run to its global index base."""
    base: object
    descriptor: object
    pos: object
    position: object
    run: object
    assigned: dict[cython.longlong, cython.longlong] = {}
    for run in runs:
        base = _tdinfo_anchor_run_by_votes(run, index_by_name)
        if base is None:
            continue
        for position, descriptor in enumerate(run):
            assigned[id(descriptor)] = base + position

    index_bound = types_count + 64 if types_count else 0x10000
    for position, run in enumerate(runs):
        if any(id(descriptor) in assigned for descriptor in iter(run)):
            continue
        base = _tdinfo_anchor_run_by_continuation(
            run, position, runs, index_by_name, assigned, index_bound
        )
        if base is None:
            continue
        for pos, descriptor in enumerate(run):
            assigned[id(descriptor)] = base + pos
    return assigned


@cython.ccall
def _tdinfo_reconcile_descriptor_indexes(
    descriptors: object,
    type_references: object,
    *,
    types_count: cython.longlong = 0,
) -> tuple[TDInfoTypeDescriptor, ...]:
    """Assign original TD32 type indexes to scanned descriptors.

    Type references from the symbol stream carry the true index for named
    types.  Descriptors are stored in ascending index order inside each
    contiguous 8-byte run, so one anchored descriptor recovers the indexes
    of every record in that run — including anonymous pointers, arrays,
    and function types that member records reference.
    """
    candidate: object
    candidates: object
    type_index: object
    descriptor: object
    index_by_name = _tdinfo_type_index_by_name(type_references)
    runs = _tdinfo_group_descriptor_runs(descriptors)
    assigned = _tdinfo_assign_run_bases(runs, index_by_name, types_count)

    used_indexes: set[cython.longlong] = set(assigned.values())
    reconciled: list[TDInfoTypeDescriptor] = []
    # Unanchored descriptors (scan false positives or fragments without a
    # named anchor) are numbered in a disjoint space above the real type
    # table so member records never resolve to them by index.
    next_index = max(types_count, _TDINFO_DESCRIPTOR_FIRST_INDEX)
    for descriptor in descriptors:
        type_index = assigned.get(id(descriptor))
        candidates = index_by_name.get(descriptor.name, ())
        if type_index is None and len(candidates) == 1:
            candidate = next(iter(candidates))
            if candidate not in used_indexes:
                type_index = candidate
        if type_index is None:
            while next_index in used_indexes:
                next_index += 1
            type_index = next_index
        used_indexes.add(type_index)
        reconciled.append(replace(descriptor, type_index=type_index))
    return tuple(reconciled)


@cython.ccall
def _parse_tdinfo_extra_symbol_records(
    payload: object,
    names: object,
    *,
    types_count: cython.longlong = 0,
) -> tuple[tuple[TDInfoSymbolRecord, ...], cython.longlong]:
    symbols: list[TDInfoSymbolRecord] = []
    offset = 0
    type_bound = max(types_count, 0x100)
    while offset + 9 <= len(payload):
        name_index, type_index, symbol_offset, segment, bitfield = struct.unpack_from("<HHHHB", payload, offset)
        if not (1 <= name_index <= len(names)):
            break
        name = names[name_index - 1]
        if _classify_tdinfo_name(name) is TDInfoNameKind.SOURCE_FILE:
            break
        if type_index > type_bound:
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



# TD32 member-record stream layout (Borland C++ 2.0 / TDS 3.0, verified
# against TDUMP.EXE on a real trailer):
#
#   field record (5 bytes, name-first):
#       name_index u16, type_index u16, attributes u8
#       attr & 0x01 -> packed bitfield member
#       attr & 0x40 and not 0x80 -> followed by a 5-byte offset-extension
#           record: u32 absolute offset of the *next* member (TDUMP's
#           "New record offset") plus one flag byte
#       attr & 0x80 -> last member of the list; a u32 object-size trailer
#           follows the record
#   method record (5 bytes, attr-first):
#       attributes u8 in 0x48..0x4f (0x4a ctor, 0x49 dtor, 0x48 method),
#       name_index u16 ("@CLASS@METHOD$Q..."), type_index u16 — emitted
#       before the owning class's field list
#   var-decl record (4 bytes):
#       name_index u16, type_index u16 — inside method groups only
#       (function-pointer members); told apart from a field record by the
#       following byte being a method attr 0x48..0x4f
#   bookkeeping record (5 bytes): name_index in {0, 0xffff} or
#       type_index == 0 — bitfield packing records, no named member
#   separators: a lone 0x00 between blocks (skipped only when the next
#       position decodes as a record), and a lone 0x01 after a trailer
#       introducing the packed-bitfield member sub-list
#
# Every 5-byte record — field, method, extension, trailer, var-decl, or
# bookkeeping — counts as one member-table ordinal; separators and the
# bitfield marker do not.  Descriptor member_ref values point into that
# ordinal space.

_TDINFO_MEMBER_ATTR_BITFIELD = 0x01
_TDINFO_MEMBER_ATTR_OFFSET_EXT = 0x40
_TDINFO_MEMBER_ATTR_LIST_END = 0x80
_TDINFO_MEMBER_ATTR_RESERVED_MASK = 0x38
_TDINFO_METHOD_ATTR_LOW = 0x48
_TDINFO_METHOD_ATTR_HIGH = 0x4F
_TDINFO_TYPE_INDEX_FLOOR_BOUND = 0x200
_TDINFO_MAX_AGGREGATE_SIZE = 0x8000


class _TDInfoStreamRecordKind(IntEnum):
    """Role of one decoded record inside the TD32 member-record stream."""

    FIELD = 0
    METHOD = 1
    OFFSET_EXTENSION = 2
    LIST_TRAILER = 3
    VAR_DECL = 4
    BOOKKEEPING = 5
    BITFIELD_MARKER = 6


@dataclasses.dataclass(frozen=True)
class _TDInfoStreamRecord:
    """One decoded record of the TD32 member-record stream."""

    kind: _TDInfoStreamRecordKind
    ordinal: int | None
    payload_offset: cython.longlong
    name_index: cython.longlong = 0
    type_index: cython.longlong = 0
    attributes: cython.longlong = 0
    trailer_size: int | None = None
    next_offset: int | None = None


@cython.ccall
def _tdinfo_stream_name(names: object, name_index: cython.longlong) -> object:
    """Return the decoded name-pool entry, or "" for out-of-range indexes."""
    if not 1 <= name_index <= len(names):
        return ""
    return names[name_index - 1]


@cython.ccall
def _tdinfo_method_record_at(
    payload: object,
    names: object,
    type_bound: cython.longlong,
    offset: cython.longlong,
) -> object:
    """Decode an attr-first method record at `offset`, or None."""
    if not (_TDINFO_METHOD_ATTR_LOW <= payload[offset] <= _TDINFO_METHOD_ATTR_HIGH):
        return None
    name_index, type_index = struct.unpack_from("<HH", payload, offset + 1)
    name = _tdinfo_stream_name(names, name_index)
    if not name.startswith("@") or not (1 <= type_index <= type_bound):
        return None
    return name_index, type_index


@cython.ccall
def _tdinfo_field_record_at(
    payload: object,
    names: object,
    type_bound: cython.longlong,
    offset: cython.longlong,
) -> object:
    """Decode a name-first field record at `offset`, or None."""
    name_index, type_index = struct.unpack_from("<HH", payload, offset)
    attributes = payload[offset + 4]
    if attributes & _TDINFO_MEMBER_ATTR_RESERVED_MASK:
        return None
    if not (1 <= name_index <= len(names)) or not (1 <= type_index <= type_bound):
        return None
    name = names[name_index - 1]
    if not name or name.startswith("@") or _classify_tdinfo_name(name) is TDInfoNameKind.SOURCE_FILE:
        return None
    return name_index, type_index, attributes


@cython.ccall
def _tdinfo_bookkeeping_record_at(payload: object, offset: cython.longlong) -> cython.bint:
    """Return True when `offset` holds a bookkeeping pseudo-record.

    Bitfield groups keep 5-byte records whose name_index is 0/0xffff or
    whose type_index is 0; they occupy member-table ordinals but carry no
    named member.
    """
    name_index, type_index = struct.unpack_from("<HH", payload, offset)
    return name_index in {0, 0xFFFF} or type_index == 0


@cython.ccall
def _tdinfo_var_decl_record_at(
    payload: object,
    names: object,
    type_bound: cython.longlong,
    offset: cython.longlong,
) -> object:
    """Decode a 4-byte (name_index, type_index) var-decl record, or None.

    These sit inside method groups; the byte after the pair is always a
    method-attribute byte 0x48..0x4f.
    """
    name_index, type_index = struct.unpack_from("<HH", payload, offset)
    if not (1 <= name_index <= len(names)) or not (1 <= type_index <= type_bound):
        return None
    if not (_TDINFO_METHOD_ATTR_LOW <= payload[offset + 4] <= _TDINFO_METHOD_ATTR_HIGH):
        return None
    if _classify_tdinfo_name(names[name_index - 1]) is TDInfoNameKind.SOURCE_FILE:
        return None
    return name_index, type_index


@cython.ccall
def _tdinfo_stream_record_starts(
    payload: object,
    names: object,
    type_bound: cython.longlong,
    offset: cython.longlong,
) -> cython.bint:
    """Return True when any stream record can start at `offset`."""
    if offset + 5 > len(payload):
        return False
    return (
        _tdinfo_field_record_at(payload, names, type_bound, offset) is not None
        or _tdinfo_method_record_at(payload, names, type_bound, offset) is not None
        or _tdinfo_var_decl_record_at(payload, names, type_bound, offset) is not None
        or _tdinfo_bookkeeping_record_at(payload, offset)
    )


@cython.ccall
def _tdinfo_field_tail(
    payload: object,
    names: object,
    type_bound: cython.longlong,
    pos: cython.longlong,
    ordinal: cython.longlong,
    attributes: cython.longlong,
    payload_base_offset: cython.longlong,
    records: object,
) -> tuple[cython.longlong, cython.longlong, cython.bint, cython.bint]:
    """Consume the records that may follow a FIELD record.

    Returns (pos, ordinal, in_bitfield, stop).  Handles the 5-byte
    offset-extension record after ``attr&0x40``, the 4-byte size trailer
    after ``attr&0x80``, and the separator/bitfield-marker bytes that may
    start the next list.
    """
    in_bitfield = False
    if attributes & _TDINFO_MEMBER_ATTR_OFFSET_EXT and not attributes & _TDINFO_MEMBER_ATTR_LIST_END:
        if pos + 5 > len(payload):
            return pos, ordinal, in_bitfield, True
        records.append(
            _TDInfoStreamRecord(
                kind=_TDInfoStreamRecordKind.OFFSET_EXTENSION,
                ordinal=ordinal,
                payload_offset=payload_base_offset + pos,
                next_offset=struct.unpack_from("<I", payload, pos)[0],
            )
        )
        return pos + 5, ordinal + 1, in_bitfield, False
    if not attributes & _TDINFO_MEMBER_ATTR_LIST_END:
        return pos, ordinal, in_bitfield, False
    in_bitfield = False
    if pos + 4 > len(payload):
        return pos, ordinal, in_bitfield, True
    trailer_size = struct.unpack_from("<I", payload, pos)[0]
    if not (0 < trailer_size <= _TDINFO_MAX_AGGREGATE_SIZE):
        return pos, ordinal, in_bitfield, True
    records.append(
        _TDInfoStreamRecord(
            kind=_TDInfoStreamRecordKind.LIST_TRAILER,
            ordinal=ordinal,
            payload_offset=payload_base_offset + pos,
            trailer_size=trailer_size,
        )
    )
    pos += 4
    ordinal += 1
    if pos >= len(payload):
        return pos, ordinal, in_bitfield, False
    if payload[pos] == 0 and _tdinfo_stream_record_starts(payload, names, type_bound, pos + 1):
        return pos + 1, ordinal, in_bitfield, False
    if payload[pos] == 1 and _tdinfo_stream_record_starts(payload, names, type_bound, pos + 1):
        records.append(
            _TDInfoStreamRecord(
                kind=_TDInfoStreamRecordKind.BITFIELD_MARKER,
                ordinal=None,
                payload_offset=payload_base_offset + pos,
            )
        )
        return pos + 1, ordinal, True, False
    return pos, ordinal, in_bitfield, False


@cython.ccall
def _walk_tdinfo_member_stream(
    payload: object,
    names: object,
    *,
    type_bound: cython.longlong,
    start: cython.longlong,
    payload_base_offset: cython.longlong,
) -> tuple[tuple[_TDInfoStreamRecord, ...], cython.longlong]:
    """Walk one contiguous TD32 record stream from `start`.

    Returns (records, end_offset).  Each record carries its member-table
    ordinal — the index space aggregate descriptor ``member_ref`` values
    reference.  The walk stops at the first byte that decodes as nothing.
    """
    bitfield_state: object
    field: object
    method: object
    var_decl: object
    records: list[_TDInfoStreamRecord] = []
    pos = start
    ordinal = 0
    in_bitfield = False
    while pos + 5 <= len(payload):
        base_offset = payload_base_offset + pos
        method = None if in_bitfield else _tdinfo_method_record_at(payload, names, type_bound, pos)
        if method is not None:
            records.append(
                _TDInfoStreamRecord(
                    kind=_TDInfoStreamRecordKind.METHOD,
                    ordinal=ordinal,
                    payload_offset=base_offset,
                    name_index=method[0],
                    type_index=method[1],
                    attributes=payload[pos],
                )
            )
            ordinal += 1
            pos += 5
            continue
        field = _tdinfo_field_record_at(payload, names, type_bound, pos)
        if field is not None:
            name_index, type_index, attributes = field
            records.append(
                _TDInfoStreamRecord(
                    kind=_TDInfoStreamRecordKind.FIELD,
                    ordinal=ordinal,
                    payload_offset=base_offset,
                    name_index=name_index,
                    type_index=type_index,
                    attributes=attributes,
                )
            )
            ordinal += 1
            pos += 5
            pos, ordinal, bitfield_state, stop = _tdinfo_field_tail(
                payload, names, type_bound, pos, ordinal, attributes, payload_base_offset, records
            )
            if bitfield_state is not None:
                in_bitfield = bitfield_state
            if stop:
                break
            continue
        if _tdinfo_bookkeeping_record_at(payload, pos):
            records.append(
                _TDInfoStreamRecord(
                    kind=_TDInfoStreamRecordKind.BOOKKEEPING,
                    ordinal=ordinal,
                    payload_offset=base_offset,
                )
            )
            ordinal += 1
            pos += 5
            continue
        var_decl = None if in_bitfield else _tdinfo_var_decl_record_at(payload, names, type_bound, pos)
        if var_decl is not None:
            records.append(
                _TDInfoStreamRecord(
                    kind=_TDInfoStreamRecordKind.VAR_DECL,
                    ordinal=ordinal,
                    payload_offset=base_offset,
                    name_index=var_decl[0],
                    type_index=var_decl[1],
                    attributes=_TDINFO_METHOD_ATTR_LOW,
                )
            )
            ordinal += 1
            pos += 4
            continue
        if payload[pos] == 0 and _tdinfo_stream_record_starts(payload, names, type_bound, pos + 1):
            pos += 1
            continue
        break
    return tuple(records), pos


@cython.ccall
def _tdinfo_owner_name_from_methods(method_names: object) -> object:
    """Extract the owning class name from '@CLASS@METHOD$Q...' records."""
    method_name: object
    for method_name in method_names:
        if method_name.startswith("@") and "@" in method_name[1:]:
            return method_name[1 : method_name.index("@", 1)]
    return ""


def _tdinfo_close_member_list(
    records: object,
    index: cython.longlong,
    current: object,
    pending_methods: object,
    pending_block_ordinal: object,
    first_ordinal: cython.longlong,
    bitfield_next: cython.bint,
    previous_owner: object,
    size_candidates_of: Callable[[int, int], tuple[cython.longlong, ...]],
) -> TDInfoMemberList | None:
    """Emit a member list when a trailer follows the current fields."""
    if index >= len(records) or records[index].kind is not _TDInfoStreamRecordKind.LIST_TRAILER:
        return None
    trailer = records[index]
    # Method-derived owner is strongest; a bitfield sub-list inherits the
    # preceding list's owner.  Other lists leave owner_name empty so
    # descriptor member_ref matching wins.
    owner_name = _tdinfo_owner_name_from_methods(pending_methods)
    if not owner_name and bitfield_next:
        owner_name = previous_owner
    members = _tdinfo_materialize_members(
        current,
        size_candidates_of,
        trailer_size=None if bitfield_next else (trailer.trailer_size or 0),
    )
    return TDInfoMemberList(
        record_index=first_ordinal,
        payload_offset=current[0]["pos"] if current else trailer.payload_offset,
        size=trailer.trailer_size or 0,
        owner_name=owner_name,
        owner_type_index=None,
        bitfield=bitfield_next,
        member_names=tuple(member.name for member in iter(members)),
        method_names=tuple(pending_methods),
        members=members,
        block_ordinal=(
            pending_block_ordinal if pending_block_ordinal is not None else first_ordinal
        ),
    )


@cython.ccall
def _tdinfo_member_lists_from_stream(
    records: object,
    names: object,
    size_candidates_of: Callable[[int, int], tuple[cython.longlong, ...]],
) -> object:
    """Group walked stream records into member lists split by trailers.

    Member offsets are solved against the trailer's object size so the
    layout stays consistent even when some member type indexes do not
    resolve to a unique descriptor.
    """
    member_list: object
    pending_block_ordinal: object
    lists: list[TDInfoMemberList] = []
    current: list[dict[str, Any]] = []
    pending_methods: list[str] = []
    pending_block_ordinal = None
    pending_ext: int | None = None
    first_ordinal = 0
    bitfield_next = False
    previous_owner = ""
    index = 0
    while index < len(records):
        record = records[index]
        if record.kind is _TDInfoStreamRecordKind.BITFIELD_MARKER:
            bitfield_next = True
            index += 1
            continue
        if record.kind is _TDInfoStreamRecordKind.METHOD:
            if pending_block_ordinal is None:
                pending_block_ordinal = record.ordinal
            pending_methods.append(names[record.name_index - 1])
            index += 1
            continue
        if record.kind in (_TDInfoStreamRecordKind.FIELD, _TDInfoStreamRecordKind.VAR_DECL):
            if not current and record.ordinal is not None:
                first_ordinal = record.ordinal
            current.append(
                {
                    "name": names[record.name_index - 1],
                    "ti": record.type_index,
                    "attr": record.attributes,
                    "pos": record.payload_offset,
                    "ext": pending_ext,
                    "bitfield": bool(record.attributes & _TDINFO_MEMBER_ATTR_BITFIELD),
                    "var_decl": record.kind is _TDInfoStreamRecordKind.VAR_DECL,
                }
            )
            pending_ext = None
            index += 1
            if index < len(records) and records[index].kind is _TDInfoStreamRecordKind.OFFSET_EXTENSION:
                extension = records[index]
                if extension.next_offset is not None and extension.next_offset != 0xFFFFFFFF:
                    pending_ext = extension.next_offset
                index += 1
            member_list = _tdinfo_close_member_list(
                records,
                index,
                current,
                pending_methods,
                pending_block_ordinal,
                first_ordinal,
                bitfield_next,
                previous_owner,
                size_candidates_of,
            )
            if member_list is not None:
                lists.append(member_list)
                previous_owner = member_list.owner_name
                current = []
                pending_methods = []
                pending_block_ordinal = None
                pending_ext = None
                first_ordinal = 0
                bitfield_next = False
                index += 1
            continue
        index += 1
    return lists


@cython.ccall
def _tdinfo_materialize_members(
    entries: object,
    size_candidates_of: Callable[[int, int], tuple[cython.longlong, ...]],
    *,
    trailer_size: int | None,
) -> tuple[TDInfoTypeMember, ...]:
    """Emit members with offsets solved to satisfy the trailer size."""
    offsets: object
    entry: object
    offset: object
    offsets = _tdinfo_solve_member_offsets(entries, size_candidates_of, trailer_size)
    if offsets is None:
        # No satisfying layout — fall back to preferred candidate sizes.
        offsets = []
        offset = 0
        for entry in entries:
            cur = entry["ext"] if entry["ext"] is not None else offset
            offsets.append(cur)
            sizes = () if entry["bitfield"] else (size_candidates_of(entry["ti"], entry["pos"]) or ())
            offset = cur + (sizes[0] if sizes else (4 if entry["var_decl"] else 0))
    members = []
    for entry, offset in zip(entries, offsets, strict=True):
        members.append(
            TDInfoTypeMember(
                name=entry["name"],
                offset=offset,
                type_index=entry["ti"],
                attributes=entry["attr"],
                payload_offset=entry["pos"],
            )
        )
    return tuple(members)


@cython.ccall
def _tdinfo_offset_transitions(
    states: object,
    entry: object,
    size_candidates_of: Callable[[int, int], tuple[cython.longlong, ...]],
    trailer_size: object,
) -> object:
    """Advance every DP state across one member entry."""
    best: object
    off: object
    offs: object
    rank: object
    score: object
    size: object
    if entry["bitfield"]:
        sizes: tuple[cython.longlong, ...] = (0,)
    else:
        sizes = tuple(size_candidates_of(entry["ti"], entry["pos"])) or (
            (4,) if entry["var_decl"] else (0,)
        )
    new: dict[cython.longlong, tuple[cython.longlong, tuple[cython.longlong, ...]]] = {}
    for off, (score, offs) in states.items():
        cur = entry["ext"] if entry["ext"] is not None else off
        for rank, size in enumerate(sizes):
            nxt = cur + size
            if trailer_size is not None and nxt > trailer_size:
                continue
            nscore = score + (1 if rank == 0 else 0)
            best = new.get(nxt)
            if best is None or nscore > best[0]:
                new[nxt] = (nscore, (*offs, cur))
    return new


def _tdinfo_solve_member_offsets(
    entries: object,
    size_candidates_of: Callable[[int, int], tuple[cython.longlong, ...]],
    trailer_size: object,
) -> object:
    """Solve member offsets so member sizes sum to `trailer_size`.

    DP over members: each member's offset is the previous member's end, or
    an absolute offset-extension override.  States are pruned by the
    trailer bound and ranked by preferred-size hits.
    """
    entry: object
    # offset -> (score, offsets tuple)
    states: dict[cython.longlong, tuple[cython.longlong, tuple[cython.longlong, ...]]] = {0: (0, ())}
    for entry in entries:
        states = _tdinfo_offset_transitions(states, entry, size_candidates_of, trailer_size)
        if not states:
            return None
        if len(states) > 4096:
            keep = sorted(tuple(states.items()), key=lambda kv: -kv[1][0])[:1024]
            states = dict(keep)
    if trailer_size is not None:
        states = {off: v for off, v in builtins.iter(states.items()) if operator.eq(off, trailer_size)}
        if not states:
            return None
    _off, (_score, offs) = max(states.items(), key=lambda kv: kv[1][0])
    return list(offs)


def _tdinfo_calibrate_member_index_shift(
    lists: object,
    descriptors: object,
) -> cython.longlong:
    """Return the constant shift between list ordinals and descriptor refs.

    Member-table ordinals start at the first record of the stream; when a
    walk began mid-stream the shift is nonzero, so calibrate it against
    size-matched descriptor pairs.
    """
    descriptor: object
    ordinal: object
    size: object
    size_by_ordinal = {
        member_list.record_index: member_list.size
        for member_list in iter(lists)
        if member_list.member_names
    }
    candidates: Counter[cython.longlong] = Counter()
    for descriptor in descriptors:
        if descriptor.member_ref is None or not descriptor.size:
            continue
        for ordinal, size in size_by_ordinal.items():
            if operator.eq(size, descriptor.size):
                candidates[descriptor.member_ref - ordinal] += 1
    if not candidates:
        return 0
    # Pick the candidate that yields the most ref+size matches — a single
    # stray pair must not outvote the majority shift of a long stream.
    ref_size_pairs = {
        (descriptor.member_ref, descriptor.size)
        for descriptor in iter(descriptors)
        if descriptor.member_ref is not None and descriptor.size
    }
    def _match_count(shift: cython.longlong) -> cython.longlong:
        return sum(
            1
            for ordinal, size in builtins.iter(size_by_ordinal.items())
            if (ordinal + shift, size) in ref_size_pairs
        )

    return max(candidates, key=_match_count)


@cython.ccall
def _tdinfo_match_owner_descriptor(
    member_list: TDInfoMemberList,
    descriptors: object,
    shift: cython.longlong,
) -> TDInfoTypeDescriptor | None:
    """Find the aggregate descriptor whose member_ref/size match a list.

    Both fields must agree — a member-table ordinal hit without a matching
    object size is a false positive from scan-based descriptor decoding.
    """
    descriptor: object
    target = member_list.record_index + shift
    for descriptor in descriptors:
        if (
            operator.eq(descriptor.member_ref, target)
            and operator.eq(descriptor.size, member_list.size)
        ):
            return descriptor
    return None


def _tdinfo_collect_member_runs(
    payload: object,
    names: object,
    type_bound: cython.longlong,
    reserved: object,
    payload_base_offset: cython.longlong,
) -> object:
    """Walk the payload and collect runs containing complete member lists."""
    runs: list[tuple[_TDInfoStreamRecord, ...]] = []
    pos = 0
    while pos + 5 <= len(payload):
        if pos in reserved:
            pos += 1
            continue
        records, end = _walk_tdinfo_member_stream(
            payload,
            names,
            type_bound=type_bound,
            start=pos,
            payload_base_offset=payload_base_offset,
        )
        complete_lists = sum(
            1 for record in iter(records) if record.kind is _TDInfoStreamRecordKind.LIST_TRAILER
        )
        if complete_lists and len(records) >= 2:
            runs.append(records)
            pos = max(end, pos + 1)
        else:
            pos += 1
    return runs


def _tdinfo_member_size_resolver(
    type_descriptors: object,
) -> Callable[[int, int], tuple[cython.longlong, ...]]:
    """Build the member-size candidate lookup for the offset solver.

    Member type_index values are original TD32 type indexes, which the
    descriptor reconciliation recovers.  Per-module tables duplicate each
    index, so the copy nearest the member record is the owning module's.
    A function-typed member holds a far code pointer (4 bytes here).
    """
    descriptor: object
    descriptors_by_index: dict[cython.longlong, list[TDInfoTypeDescriptor]] = {}
    for descriptor in type_descriptors:
        descriptors_by_index.setdefault(descriptor.type_index, []).append(descriptor)

    def _member_size_candidates(type_index: cython.longlong, position: cython.longlong) -> tuple[cython.longlong, ...]:
        builtin: object
        candidates: object
        descriptor: object
        builtin = _TDINFO_TYPE_SIZES.get(type_index)
        if builtin is not None:
            return (builtin,)
        candidates = descriptors_by_index.get(type_index)
        if not candidates:
            return ()
        by_distance = sorted(candidates, key=lambda descriptor: abs(descriptor.payload_offset - position))
        sizes: list[cython.longlong] = []
        for descriptor in by_distance:
            size = (
                4
                if descriptor.kind in {TDInfoTypeKind.FUNCTION, TDInfoTypeKind.MEMBER_FUNCTION}
                else descriptor.size
            )
            if size and size not in sizes:
                sizes.append(size)
        return tuple(sizes)

    return _member_size_candidates


@cython.ccall
def _tdinfo_match_owner_class(
    member_list: TDInfoMemberList,
    class_entries: object,
) -> TDInfoClassEntry | None:
    """Match a member list to a class-table entry via member_ordinal.

    The class table references the ordinal of the class's method block
    (one-based), which precedes the data-member records — the ordinal the
    descriptor ``member_ref`` of plain structs points at directly.
    """
    block: object
    entry: object
    block = member_list.block_ordinal
    if block is None:
        return None
    for entry in class_entries:
        if operator.eq(entry.member_ordinal, block + 1):
            return entry
    return None


@cython.ccall
def _tdinfo_resolve_list_owners(
    runs: object,
    names: object,
    type_descriptors: object,
    size_candidates_of: Callable[[int, int], tuple[cython.longlong, ...]],
    class_entries: object = (),
) -> object:
    """Materialize member lists and resolve their owning aggregate."""
    descriptor: object
    matched: object
    matched_class: object
    member_list: object
    records: object
    descriptor_by_name = {d.name.lower(): d for d in iter(type_descriptors) if d.name}
    resolved_lists: list[TDInfoMemberList] = []
    for records in runs:
        run_lists = _tdinfo_member_lists_from_stream(records, names, size_candidates_of)
        shift = _tdinfo_calibrate_member_index_shift(run_lists, type_descriptors)
        for member_list in run_lists:
            owner_type_index = member_list.owner_type_index
            owner_name = member_list.owner_name
            # A descriptor member_ref/size match is stronger evidence than
            # a method-derived or inherited owner name; the class-table
            # member_ordinal link is equally authoritative for classes.
            matched = _tdinfo_match_owner_descriptor(member_list, type_descriptors, shift)
            matched_class = _tdinfo_match_owner_class(member_list, class_entries)
            if matched is not None:
                owner_type_index = matched.type_index
                owner_name = matched.name or owner_name
            elif matched_class is not None:
                owner_name = owner_name or matched_class.name
                descriptor = descriptor_by_name.get(owner_name.lower())
                if descriptor is not None:
                    owner_type_index = descriptor.type_index
            elif owner_name and owner_name.lower() in descriptor_by_name:
                owner_type_index = descriptor_by_name[owner_name.lower()].type_index
            resolved_lists.append(
                replace(member_list, owner_type_index=owner_type_index, owner_name=owner_name)
            )
    return resolved_lists


@cython.ccall
def _tdinfo_dedup_members(
    resolved_lists: object,
    enum_owner_indexes: object,
) -> tuple[tuple[TDInfoTypeMember, ...], tuple[TDInfoEnumMember, ...]]:
    """Flatten member lists into deduplicated member and enum sequences."""
    member: object
    member_list: object
    members: list[TDInfoTypeMember] = []
    enum_members: list[TDInfoEnumMember] = []
    seen: set[tuple[str, cython.longlong, cython.longlong, int | None]] = set()
    enum_seen: set[tuple[str, cython.longlong]] = set()
    for member_list in resolved_lists:
        owner_type_index = member_list.owner_type_index
        if owner_type_index in enum_owner_indexes:
            for member in member_list.members:
                enum_key = (member.name, member.type_index)
                if enum_key in enum_seen:
                    continue
                enum_seen.add(enum_key)
                enum_members.append(
                    TDInfoEnumMember(
                        name=member.name,
                        value=member.type_index,
                        attributes=member.attributes,
                        payload_offset=member.payload_offset,
                        owner_type_index=owner_type_index,
                    )
                )
            continue
        for member in member_list.members:
            key = (member.name, member.offset, member.type_index, owner_type_index)
            if key in seen:
                continue
            seen.add(key)
            members.append(replace(member, owner_type_index=owner_type_index))
    return tuple(members), tuple(enum_members)


@cython.ccall
def _parse_tdinfo_members(
    payload: object,
    names: object,
    *,
    payload_base_offset: cython.longlong,
    type_descriptors: object = (),
    types_count: cython.longlong = 0,
    class_entries: object = (),
) -> tuple[tuple[TDInfoTypeMember, ...], tuple[TDInfoEnumMember, ...], tuple[TDInfoMemberList, ...]]:
    """Decode the TD32 member-record stream into per-aggregate member lists.

    Real TDS 3.x payloads keep member records in one contiguous stream of
    5-byte records mixed with 4-byte var decls, offset extensions, size
    trailers, and bitfield bookkeeping.  Walk each contiguous run so list
    order and the member-table ordinals used by descriptor ``member_ref``
    are preserved.
    """
    type_bound = max(types_count, _TDINFO_TYPE_INDEX_FLOOR_BOUND)
    # Bytes already consumed by descriptor records cannot also start a
    # member-list run — the regions are disjoint in real TD32 payloads, and
    # descriptor bytes can themselves decode as phantom member records.
    reserved = {
        index
        for descriptor in iter(type_descriptors)
        for index in range(
            descriptor.payload_offset - payload_base_offset,
            descriptor.payload_offset - payload_base_offset + len(descriptor.raw_bytes),
        )
    }
    runs = _tdinfo_collect_member_runs(payload, names, type_bound, reserved, payload_base_offset)
    size_candidates_of = _tdinfo_member_size_resolver(type_descriptors)
    resolved_lists = _tdinfo_resolve_list_owners(
        runs, names, type_descriptors, size_candidates_of, class_entries
    )
    enum_owner_indexes = {
        descriptor.type_index for descriptor in iter(type_descriptors) if descriptor.kind is TDInfoTypeKind.ENUM
    }
    members, enum_members = _tdinfo_dedup_members(resolved_lists, enum_owner_indexes)
    return members, enum_members, tuple(resolved_lists)


@cython.ccall
def _parse_tdinfo_name_pool(data: object, *, expected_count: cython.longlong) -> tuple[str, ...]:
    raw_name: object
    names: list[str] = []
    for raw_name in data.split(b"\x00"):
        if len(names) >= expected_count:
            break
        names.append(raw_name.decode("ascii", errors="ignore"))
    while len(names) < expected_count:
        names.append("")
    return tuple(names)


@cython.ccall
def _tdinfo_symbol_name(symbol: TDInfoSymbolRecord, names: object) -> object:
    if not (1 <= symbol.index <= len(names)):
        return None
    name = names[symbol.index - 1]
    if not name or name == "?":
        return None
    return name


def _classify_tdinfo_name_pool(names: object) -> tuple[TDInfoNamePoolEntry, ...]:
    return tuple(
        TDInfoNamePoolEntry(index=index, name=name, kind=_classify_tdinfo_name(name))
        for index, name in builtins.iter(enumerate(names, start=1))
        if name and name != "?"
    )


@cython.ccall
def _classify_tdinfo_name(name: object) -> TDInfoNameKind:
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


@cython.ccall
def _tdinfo_name_looks_like_code(name: object) -> cython.bint:
    lowered = name.lower()
    return not lowered.startswith(("dgroup@", "byte_", "word_", "dword_", "off_", "stru_"))


@cython.ccall
def _tdinfo_type_name_looks_user_defined(name: object) -> cython.bint:
    if not name or name.startswith("_"):
        return False
    return _classify_tdinfo_name(name) is TDInfoNameKind.IDENTIFIER
