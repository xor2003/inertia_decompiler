"""Layer: Optional evidence/reporting.

Responsibility: parse CodeView NB00 debug records into optional labels and diagnostics.
Forbidden: requiring debug symbols for arguments, types, control flow, or validation success.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path


class CodeViewSubsectionType(IntEnum):
    """NB00 subsection tags used to route optional CodeView debug tables."""

    MODULES = 0x101
    PUBLICS = 0x102
    TYPE = 0x103
    SYMBOLS = 0x104
    SRCLINES = 0x105
    LIBRARIES = 0x106
    COMPACTED = 0x108
    SRCLNSEG = 0x109


@dataclass(frozen=True)
class CodeViewDirectoryEntry:
    """Directory entry pointing at one NB00 debug subsection payload."""

    subsection_type: int
    module_index: int
    data_offset: int
    data_size: int


@dataclass(frozen=True)
class CodeViewNB00Module:
    """NB00 module span used to classify optional labels and source lines."""

    module_index: int
    cs_base: int
    cs_offset: int
    cs_length: int
    overlay_number: int
    library_index: int
    segment_count: int
    name: str

    def linear_range(self, *, load_base_linear: int) -> tuple[int, int]:
        """Return the display-only linear range covered by this module."""
        start = load_base_linear + (self.cs_base << 4) + self.cs_offset
        return start, start + self.cs_length


@dataclass(frozen=True)
class CodeViewNB00PublicSymbol:
    """Public symbol recovered from NB00 debug data as optional label evidence."""

    module_index: int
    offset: int
    segment: int
    type_index: int
    name: str

    def linear_addr(self, *, load_base_linear: int) -> int:
        """Return a display-only linear address for this public symbol."""
        return load_base_linear + (self.segment << 4) + self.offset


@dataclass(frozen=True)
class CodeViewNB00Info:
    """Parsed NB00 debug metadata exposed as optional labels and diagnostics."""

    version: str
    debug_base: int
    subsection_directory_offset: int
    modules: tuple[CodeViewNB00Module, ...]
    publics: tuple[CodeViewNB00PublicSymbol, ...]
    type_definitions: tuple[CodeViewNB00TypeDefinition, ...] = ()
    type_record_names: tuple[str, ...] = ()
    type_members: tuple[CodeViewNB00TypeMember, ...] = ()
    source_files: tuple[str, ...] = ()
    line_map: dict[int, tuple[int, int]] = field(default_factory=dict)
    debug_identifiers: tuple[str, ...] = ()
    code_labels: dict[int, str] = field(default_factory=dict)
    data_labels: dict[int, str] = field(default_factory=dict)
    code_ranges: dict[int, tuple[int, int]] = field(default_factory=dict)


@dataclass(frozen=True)
class CodeViewNB00TypeLeaf:
    """Raw NB00 type-record leaf preserved for debug-schema reporting."""

    kind: str
    value: object


@dataclass(frozen=True)
class CodeViewNB00TypeMember:
    """Member name and offset decoded from an NB00 type record."""

    name: str
    offset: int
    owner_type_index: int
    leaf_index: int


@dataclass(frozen=True)
class CodeViewNB00TypeDefinition:
    """NB00 type record retained as optional debug type evidence."""

    index: int
    linkage: int
    leaves: tuple[CodeViewNB00TypeLeaf, ...]


def find_codeview_nb00(data: bytes) -> tuple[str, int, int] | None:
    """Locate an NB00 trailer and subsection directory in executable bytes."""
    for trailer_offset in range(len(data) - 8, max(-1, len(data) - 256), -1):
        signature, debug_offset = struct.unpack_from("<4sI", data, trailer_offset)
        if not signature.startswith(b"NB0"):
            continue
        debug_base = trailer_offset + 8 - debug_offset
        if debug_base < 0 or debug_base + 8 > len(data):
            continue
        root_sig, subdir_offset = struct.unpack_from("<4sI", data, debug_base)
        if root_sig != b"NB00":
            continue
        return signature.decode("ascii", errors="ignore"), debug_base, debug_base + subdir_offset
    return None


def parse_codeview_nb00(path: Path, *, load_base_linear: int = 0) -> CodeViewNB00Info | None:
    """Parse optional NB00 debug metadata from an executable path."""
    return parse_codeview_nb00_bytes(path.read_bytes(), load_base_linear=load_base_linear)


def parse_codeview_nb00_bytes(data: bytes, *, load_base_linear: int = 0) -> CodeViewNB00Info | None:
    """Parse optional NB00 debug metadata from executable bytes."""
    located = find_codeview_nb00(data)
    if located is None:
        return None
    version, debug_base, subsection_directory_offset = located
    directory_entries = _read_subsection_directory(data, subsection_directory_offset)

    modules: dict[int, CodeViewNB00Module] = {}
    publics: list[CodeViewNB00PublicSymbol] = []
    type_definitions: list[CodeViewNB00TypeDefinition] = []
    source_files: list[str] = []
    line_map: dict[int, tuple[int, int]] = {}
    debug_identifiers: list[str] = []
    for entry in directory_entries:
        blob = data[debug_base + entry.data_offset : debug_base + entry.data_offset + entry.data_size]
        if entry.subsection_type == CodeViewSubsectionType.MODULES:
            module = _parse_module_subsection(entry.module_index, blob)
            modules[module.module_index] = module
        elif entry.subsection_type == CodeViewSubsectionType.PUBLICS:
            publics.extend(_parse_publics_subsection(entry.module_index, blob))
        elif entry.subsection_type == CodeViewSubsectionType.TYPE:
            type_definitions.extend(_parse_type_subsection(blob))
        elif entry.subsection_type == CodeViewSubsectionType.SYMBOLS:
            debug_identifiers.extend(_parse_symbol_names_subsection(blob))
        elif entry.subsection_type in {CodeViewSubsectionType.SRCLINES, CodeViewSubsectionType.SRCLNSEG}:
            parsed_files, parsed_lines = _parse_source_lines_subsection(
                blob,
                modules.get(entry.module_index),
                load_base_linear=load_base_linear,
            )
            source_files.extend(parsed_files)
            line_map.update(parsed_lines)

    code_ranges = _synthesize_code_ranges(tuple(modules.values()), tuple(publics), load_base_linear=load_base_linear)
    code_labels: dict[int, str] = {}
    data_labels: dict[int, str] = {}
    module_ranges = tuple(
        (module.linear_range(load_base_linear=load_base_linear), module.module_index) for module in modules.values()
    )

    for symbol in publics:
        linear = symbol.linear_addr(load_base_linear=load_base_linear)
        name = symbol.name.lstrip("_")
        if _public_is_code_symbol(symbol, linear=linear, module_ranges=module_ranges):
            code_labels.setdefault(linear, name)
        else:
            data_labels.setdefault(linear, symbol.name)

    return CodeViewNB00Info(
        version=version,
        debug_base=debug_base,
        subsection_directory_offset=subsection_directory_offset,
        modules=tuple(sorted(modules.values(), key=lambda item: item.module_index)),
        publics=tuple(publics),
        type_definitions=tuple(type_definitions),
        type_record_names=_collect_type_record_names(tuple(type_definitions)),
        type_members=_collect_type_members(tuple(type_definitions)),
        source_files=tuple(dict.fromkeys(source_files)),
        line_map=line_map,
        debug_identifiers=tuple(dict.fromkeys(debug_identifiers)),
        code_labels=code_labels,
        data_labels=data_labels,
        code_ranges=code_ranges,
    )


def _read_subsection_directory(data: bytes, subsection_directory_offset: int) -> tuple[CodeViewDirectoryEntry, ...]:
    if subsection_directory_offset < 0 or subsection_directory_offset + 2 > len(data):
        raise ValueError("invalid CodeView subsection directory offset")
    count = struct.unpack_from("<H", data, subsection_directory_offset)[0]
    offset = subsection_directory_offset + 2
    entries: list[CodeViewDirectoryEntry] = []
    for _ in range(count):
        if offset + 10 > len(data):
            break
        subsection_type, module_index, data_offset, data_size = struct.unpack_from("<HHLH", data, offset)
        entries.append(
            CodeViewDirectoryEntry(
                subsection_type=subsection_type,
                module_index=module_index,
                data_offset=data_offset,
                data_size=data_size,
            )
        )
        offset += 10
    return tuple(entries)


def _parse_module_subsection(module_index: int, blob: bytes) -> CodeViewNB00Module:
    if len(blob) < 9:
        raise ValueError("short NB00 module subsection")
    cs_base, cs_offset, cs_length, overlay_number, library_index, segment_count, _, name_length = struct.unpack_from(
        "<HHHHHBBB", blob
    )
    name_bytes = blob[-name_length:] if name_length <= len(blob) else b""
    return CodeViewNB00Module(
        module_index=module_index,
        cs_base=cs_base,
        cs_offset=cs_offset,
        cs_length=cs_length,
        overlay_number=overlay_number,
        library_index=library_index,
        segment_count=segment_count,
        name=name_bytes.decode("ascii", errors="ignore"),
    )


def _parse_publics_subsection(module_index: int, blob: bytes) -> tuple[CodeViewNB00PublicSymbol, ...]:
    publics: list[CodeViewNB00PublicSymbol] = []
    offset = 0
    while offset + 7 <= len(blob):
        symbol_offset, segment, type_index, name_length = struct.unpack_from("<HHHB", blob, offset)
        offset += 7
        name_bytes = blob[offset : offset + name_length]
        offset += name_length
        publics.append(
            CodeViewNB00PublicSymbol(
                module_index=module_index,
                offset=symbol_offset,
                segment=segment,
                type_index=type_index,
                name=name_bytes.decode("ascii", errors="ignore"),
            )
        )
    return tuple(publics)


def _parse_type_subsection(blob: bytes) -> tuple[CodeViewNB00TypeDefinition, ...]:
    definitions: list[CodeViewNB00TypeDefinition] = []
    offset = 0
    type_index = 0x200
    while offset + 3 <= len(blob):
        linkage = blob[offset]
        record_length = struct.unpack_from("<H", blob, offset + 1)[0]
        offset += 3
        record = blob[offset : offset + record_length]
        if len(record) < record_length:
            break
        offset += record_length
        definitions.append(
            CodeViewNB00TypeDefinition(
                index=type_index,
                linkage=linkage,
                leaves=tuple(_parse_type_record(record)),
            )
        )
        type_index += 1
    return tuple(definitions)


def _parse_type_record(record: bytes) -> tuple[CodeViewNB00TypeLeaf, ...]:
    leaves: list[CodeViewNB00TypeLeaf] = []
    offset = 0
    while offset < len(record):
        leaf, consumed = _read_leaf(record, offset)
        if consumed <= 0:
            break
        leaves.append(leaf)
        offset += consumed
    return tuple(leaves)


def _fixed_width_leaf(
    record: bytes, offset: int, tag: int
) -> tuple[CodeViewNB00TypeLeaf, int] | None:
    """Decode one fixed-width integer leaf when the full extent fits."""
    if tag == 0x89 and offset + 3 <= len(record):
        return CodeViewNB00TypeLeaf("uint16", struct.unpack_from("<H", record, offset + 1)[0]), 3
    if tag == 0x8A and offset + 5 <= len(record):
        return CodeViewNB00TypeLeaf("uint32", struct.unpack_from("<I", record, offset + 1)[0]), 5
    if tag == 0x83 and offset + 3 <= len(record):
        return CodeViewNB00TypeLeaf("index", struct.unpack_from("<H", record, offset + 1)[0]), 3
    if tag == 0x88 and offset + 2 <= len(record):
        return CodeViewNB00TypeLeaf("uint8", record[offset + 1]), 2
    return None


def _length_prefixed_string_leaf(
    record: bytes, offset: int
) -> tuple[CodeViewNB00TypeLeaf, int] | None:
    """Decode one length-prefixed string leaf when the full extent fits."""
    strlen = record[offset + 1]
    end = offset + 2 + strlen
    if end > len(record):
        return None
    return CodeViewNB00TypeLeaf(
        "string", record[offset + 2 : end].decode("ascii", errors="ignore")
    ), 2 + strlen


def _read_leaf(record: bytes, offset: int) -> tuple[CodeViewNB00TypeLeaf, int]:
    """Decode one CodeView leaf record at ``offset``."""
    if offset >= len(record):
        return CodeViewNB00TypeLeaf("invalid", None), 0
    tag = record[offset]
    if tag <= 0x7F:
        return CodeViewNB00TypeLeaf("int8", tag), 1
    fixed = _fixed_width_leaf(record, offset, tag)
    if fixed is not None:
        return fixed
    if tag == 0x8D and offset + 2 <= len(record):
        string_leaf = _length_prefixed_string_leaf(record, offset)
        if string_leaf is not None:
            return string_leaf
    if tag == 0x82 and offset + 2 <= len(record):
        string_leaf = _length_prefixed_string_leaf(record, offset)
        if string_leaf is not None:
            return string_leaf
    if tag in {0x8B, 0x8C, 0x8E, 0x8F, 0x92, 0x94}:
        return CodeViewNB00TypeLeaf(f"leaf_{tag:02x}", None), 1
    return CodeViewNB00TypeLeaf(f"unknown_{tag:02x}", None), 1


def _collect_type_record_names(
    type_definitions: tuple[CodeViewNB00TypeDefinition, ...],
) -> tuple[str, ...]:
    names: list[str] = []
    for definition in type_definitions:
        for leaf in definition.leaves:
            if leaf.kind == "string" and isinstance(leaf.value, str) and leaf.value:
                names.append(leaf.value)
    return tuple(dict.fromkeys(names))


def _collect_type_members(
    type_definitions: tuple[CodeViewNB00TypeDefinition, ...],
) -> tuple[CodeViewNB00TypeMember, ...]:
    members: list[CodeViewNB00TypeMember] = []
    seen: set[tuple[int, str, int]] = set()
    for definition in type_definitions:
        leaves = definition.leaves
        for leaf_index, leaf in enumerate(leaves[:-1]):
            if leaf.kind != "string" or not isinstance(leaf.value, str) or not leaf.value:
                continue
            offset_leaf = leaves[leaf_index + 1]
            if offset_leaf.kind not in {"uint8", "uint16", "uint32"} or not isinstance(offset_leaf.value, int):
                continue
            offset = int(offset_leaf.value)
            key = (definition.index, leaf.value, offset)
            if key in seen:
                continue
            seen.add(key)
            members.append(
                CodeViewNB00TypeMember(
                    name=leaf.value,
                    offset=offset,
                    owner_type_index=definition.index,
                    leaf_index=leaf_index,
                )
            )
    return tuple(members)


def _parse_source_lines_subsection(
    blob: bytes,
    module: CodeViewNB00Module | None,
    *,
    load_base_linear: int,
) -> tuple[list[str], dict[int, tuple[int, int]]]:
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

    count_offset = _find_source_line_count_offset(blob, search_start)
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


def _find_source_line_count_offset(blob: bytes, search_start: int) -> int | None:
    for candidate in range(search_start, min(len(blob) - 1, search_start + 16)):
        pair_count = struct.unpack_from("<H", blob, candidate)[0]
        if pair_count == 0 or pair_count > 0x4000:
            continue
        if candidate + 2 + pair_count * 4 <= len(blob):
            return candidate
    return None


def _parse_symbol_names_subsection(blob: bytes) -> tuple[str, ...]:
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


def _public_is_code_symbol(
    symbol: CodeViewNB00PublicSymbol,
    *,
    linear: int,
    module_ranges: tuple[tuple[tuple[int, int], int], ...],
) -> bool:
    if symbol.segment == 0:
        return True
    return any(start <= linear < end for (start, end), _module_index in module_ranges)


def _synthesize_code_ranges(
    modules: tuple[CodeViewNB00Module, ...],
    publics: tuple[CodeViewNB00PublicSymbol, ...],
    *,
    load_base_linear: int,
) -> dict[int, tuple[int, int]]:
    def _impl() -> dict[int, tuple[int, int]]:
        module_ranges = {
            module.module_index: module.linear_range(load_base_linear=load_base_linear)
            for module in modules
            if module.cs_length > 0
        }
        by_module: dict[int, list[int]] = {}
        for symbol in publics:
            if symbol.segment != 0 and symbol.module_index not in module_ranges:
                continue
            linear = symbol.linear_addr(load_base_linear=load_base_linear)
            module_range = module_ranges.get(symbol.module_index)
            if module_range is None or not (module_range[0] <= linear < module_range[1]):
                continue
            by_module.setdefault(symbol.module_index, []).append(linear)

        ranges: dict[int, tuple[int, int]] = {}
        for module_index, starts in by_module.items():
            start_end = module_ranges[module_index][1]
            ordered = sorted(set(starts))
            for index, start in enumerate(ordered):
                end = ordered[index + 1] if index + 1 < len(ordered) else start_end
                if start < end:
                    ranges[start] = (start, end)
        return ranges

    return _impl()
