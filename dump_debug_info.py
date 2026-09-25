#!/usr/bin/env python3
"""Dump optional CodeView/Turbo Debug metadata for diagnostics.

Layer: Tooling/gates.
"""

from __future__ import annotations

import argparse
import json
import logging
import struct
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "angr_platforms"))
logging.getLogger("angr.state_plugins.unicorn_engine").disabled = True

from angr_platforms.X86_16.borland_mangling import (  # noqa: E402
    demangle_borland_name,
    render_borland_signature,
)
from angr_platforms.X86_16.codeview_nb00 import CodeViewNB00Info, parse_codeview_nb00  # noqa: E402
from angr_platforms.X86_16.codeview_nb02_nb04 import (  # noqa: E402
    CodeViewNB0204Info,
    CodeViewSymbol,
    parse_codeview_nb0204,
)
from angr_platforms.X86_16.turbo_debug_tdinfo import (  # noqa: E402
    TDINFO_BUILTIN_TYPE_NAMES,
    TDInfoEXEInfo,
    TDInfoSymbolClass,
    TDInfoTypeKind,
    parse_tdinfo_exe,
)


def _parse_int(value: str) -> int:
    return int(value, 0)


def _hex_keyed(mapping: dict[int, Any]) -> dict[str, Any]:
    return {f"0x{addr:x}": value for addr, value in sorted(mapping.items())}


def _symbol(symbol: CodeViewSymbol) -> dict[str, Any]:
    return {
        "type_code": f"0x{int(symbol.type_code):04x}",
        "name": symbol.name,
        "offset": symbol.offset,
        "segment": symbol.segment,
        "length": symbol.length,
        "data_type": symbol.data_type,
        "extra": symbol.extra,
    }


def _type_member(member: Any) -> dict[str, Any]:  # noqa: ANN401
    return {
        "name": member.name,
        "offset": member.offset,
        "owner_type_index": getattr(member, "owner_type_index", None),
        "leaf_index": getattr(member, "leaf_index", None),
        "type_index": getattr(member, "type_index", None),
        "source": getattr(member, "source", None),
    }


def _nb00(info: CodeViewNB00Info | None) -> dict[str, Any] | None:
    if info is None:
        return None
    return {
        "version": info.version,
        "debug_base": f"0x{info.debug_base:x}",
        "subsection_directory_offset": f"0x{info.subsection_directory_offset:x}",
        "modules": [
            {
                "module_index": module.module_index,
                "cs_base": module.cs_base,
                "cs_offset": module.cs_offset,
                "cs_length": module.cs_length,
                "overlay_number": module.overlay_number,
                "library_index": module.library_index,
                "segment_count": module.segment_count,
                "name": module.name,
            }
            for module in info.modules
        ],
        "publics": [
            {
                "module_index": public.module_index,
                "offset": public.offset,
                "segment": public.segment,
                "type_index": public.type_index,
                "name": public.name,
            }
            for public in info.publics
        ],
        "type_definitions": [
            {
                "index": definition.index,
                "linkage": definition.linkage,
                "leaves": [{"kind": leaf.kind, "value": leaf.value} for leaf in definition.leaves],
            }
            for definition in info.type_definitions
        ],
        "type_record_names": list(info.type_record_names),
        "type_members": [_type_member(member) for member in info.type_members],
        "source_files": list(info.source_files),
        "debug_identifiers": list(info.debug_identifiers),
        "line_map": _hex_keyed({addr: [line, col] for addr, (line, col) in info.line_map.items()}),
        "code_labels": _hex_keyed(info.code_labels),
        "data_labels": _hex_keyed(info.data_labels),
        "code_ranges": _hex_keyed({start: [span[0], span[1]] for start, span in info.code_ranges.items()}),
    }


def _nb0204(info: CodeViewNB0204Info | None) -> dict[str, Any] | None:
    if info is None:
        return None
    return {
        "version": info.version,
        "debug_base": f"0x{info.debug_base:x}",
        "modules": list(info.modules),
        "source_files": list(info.source_files),
        "type_record_names": list(info.type_record_names),
        "type_members": [_type_member(member) for member in info.type_members],
        "debug_identifiers": list(info.debug_identifiers),
        "code_labels": _hex_keyed(info.code_labels),
        "data_labels": _hex_keyed(info.data_labels),
        "procedures": [_symbol(symbol) for symbol in info.procedures],
        "stack_variables": {
            name: [_symbol(symbol) for symbol in symbols] for name, symbols in sorted(info.stack_variables.items())
        },
        "line_map": _hex_keyed({addr: [line, col] for addr, (line, col) in info.line_map.items()}),
    }


def _td_symbol_class(symbol_class: TDInfoSymbolClass) -> str:
    return f"{symbol_class.name}({int(symbol_class)})"


class _TDInfoTypeNamer:
    """Render flat-table type indexes as C-style names."""

    def __init__(self, info: TDInfoEXEInfo) -> None:
        self.by_index = {d.type_index: d for d in info.type_descriptors}
        # Descriptor member_ref is the member-table ordinal (1-based) of the
        # aggregate's member list — used to inline anonymous bitfield structs.
        self.list_by_ordinal = {
            member_list.record_index + 1: member_list
            for member_list in info.member_lists
        }

    def name_of(self, type_index: int, depth: int = 0) -> str:
        """Resolve one type index to a rendered C-style name."""
        if type_index == 0:
            return "void"
        descriptor = self.by_index.get(type_index)
        if descriptor is None or depth > 8:
            return f"type_0x{type_index:x}"
        kind = descriptor.kind
        if kind is TDInfoTypeKind.BUILTIN:
            builtin_id = descriptor.builtin_type_id or 0
            return TDINFO_BUILTIN_TYPE_NAMES.get(builtin_id, f"builtin_{builtin_id:02x}")
        if kind is TDInfoTypeKind.FAR_POINTER:
            return self._pointer_name(descriptor, depth)
        if kind is TDInfoTypeKind.NEAR_POINTER:
            return f"{self.name_of(descriptor.target_type_index or 0, depth + 1)} *"
        if kind is TDInfoTypeKind.SEGMENT:
            return f"{self.name_of(descriptor.target_type_index or 0, depth + 1)} _seg *"
        if kind is TDInfoTypeKind.MEMBER_POINTER:
            return f"member_ptr({self.name_of(descriptor.target_type_index or 0, depth + 1)})"
        if kind is TDInfoTypeKind.C_ARRAY:
            return self._array_name(descriptor, depth)
        return self._aggregate_name(descriptor, type_index)

    def _pointer_name(self, descriptor: Any, depth: int) -> str:  # noqa: ANN401
        target = descriptor.target_type_index or 0
        pointee = self.by_index.get(target)
        if pointee is not None and pointee.kind is TDInfoTypeKind.FUNCTION:
            ret = self.name_of(pointee.return_type_index or 0, depth + 1)
            return f"{ret}(far*)()"
        return f"{self.name_of(target, depth + 1)} far *"

    def _array_name(self, descriptor: Any, depth: int) -> str:  # noqa: ANN401
        base = self.name_of(descriptor.base_type_index or 0, depth + 1)
        bound = descriptor.upper_bound
        if bound is not None and bound < 0x8000:
            return f"{base}[{bound + 1}]"
        # TD32 array descriptors omit the bound; recover the element count
        # from aggregate size / element size (loop.cels is 16, not 10).
        element = self.by_index.get(descriptor.base_type_index or 0)
        if element is not None and element.size and descriptor.size % element.size == 0:
            return f"{base}[{descriptor.size // element.size}]"
        return f"{base}[]"

    def _aggregate_name(self, descriptor: Any, type_index: int) -> str:  # noqa: ANN401
        if descriptor.name:
            return descriptor.name
        if descriptor.kind in (TDInfoTypeKind.STRUCT, TDInfoTypeKind.UNION):
            bitfields = self.list_by_ordinal.get(descriptor.member_ref or 0)
            if bitfields is not None and bitfields.bitfield:
                fields = "; ".join(
                    f"unsigned {member.name}:1"
                    for member in bitfields.members
                    if member.name
                )
                return f"struct {{ {fields}; }}"
        return f"anon_0x{type_index:x}"


def _tdinfo_type_names(info: TDInfoEXEInfo) -> dict[int, str]:
    """Resolve each flat-table type index to a rendered C-style name."""
    namer = _TDInfoTypeNamer(info)
    return {ti: namer.name_of(ti) for ti in namer.by_index}


# Pointer-descriptor attribute bits verified against TDUMP's type listing
# on a BC31 binary: 0x01 renders as "huge" on far pointers, 0x04 as "_DS"
# on near pointers.  Other bits are kept raw in ``attributes``.
_TDINFO_POINTER_FLAG_NAMES = {0x01: "huge", 0x04: "_DS"}


def _tdinfo_pointer_flags(descriptor: Any) -> dict[str, Any]:  # noqa: ANN401
    """Decode known pointer-attribute bits (huge / _DS) into flag names."""
    if descriptor.kind not in (
        TDInfoTypeKind.NEAR_POINTER,
        TDInfoTypeKind.FAR_POINTER,
    ):
        return {}
    attributes = descriptor.attributes or 0
    flags = [name for bit, name in _TDINFO_POINTER_FLAG_NAMES.items() if attributes & bit]
    return {"pointer_flags": flags} if flags else {}


def _tdinfo_extension_fields(descriptor: Any, names: tuple[str, ...]) -> dict[str, Any]:  # noqa: ANN401
    """Decode a descriptor's 8-byte extension slot (member functions)."""
    if not descriptor.extension:
        return {}
    fields: dict[str, Any] = {"extension": descriptor.extension.hex()}
    if descriptor.kind is TDInfoTypeKind.MEMBER_FUNCTION and len(descriptor.extension) == 8:
        owner, vtab_offset, name_index, flags = struct.unpack("<HHHH", descriptor.extension)
        fields["owner_type_index"] = owner
        fields["vtab_offset"] = vtab_offset
        fields["member_name_index"] = name_index
        fields["member_flags"] = flags
        if 0 < name_index <= len(names):
            fields["member_name"] = names[name_index - 1]
    return fields


def _tdinfo_function_signatures(
    info: TDInfoEXEInfo, type_names: dict[int, str]
) -> list[dict[str, Any]]:
    """Join symbols with mangled names and FUNCTION/MEMBER_FUNCTION types.

    Return types come from the descriptor's ``return_type_index``; parameter
    lists come from the Borland-mangled symbol name.
    """
    descriptors = {d.type_index: d for d in info.type_descriptors}
    signatures: list[dict[str, Any]] = []
    for symbol in info.named_symbols:
        descriptor = descriptors.get(symbol.record.type_index)
        if descriptor is None or descriptor.kind not in (
            TDInfoTypeKind.FUNCTION,
            TDInfoTypeKind.MEMBER_FUNCTION,
        ):
            continue
        entry: dict[str, Any] = {
            "name": symbol.name,
            "segment": f"0x{symbol.record.segment:x}",
            "offset": f"0x{symbol.record.offset:x}",
            "type_index": symbol.record.type_index,
            "return_type": type_names.get(descriptor.return_type_index or 0, "void"),
        }
        if symbol.name.startswith("@"):
            sig = demangle_borland_name(symbol.name)
            entry["signature"] = render_borland_signature(sig)
            if sig.params:
                entry["signature"] = (
                    f"{entry['return_type']} " + entry["signature"]
                )
        signatures.append(entry)
    return signatures


def _tdinfo_struct_declarations(
    info: TDInfoEXEInfo, type_names: dict[int, str]
) -> dict[str, list[str]]:
    """Reconstruct C-style field declarations for resolved aggregates.

    Per-module member-list copies repeat the same owner; the first list wins
    and later copies are emitted only if they carry extra members.
    """
    declarations: dict[str, list[str]] = {}
    for member_list in info.member_lists:
        if not member_list.owner_name or not member_list.size:
            continue
        lines = [
            f"{type_names.get(member.type_index, '?')} {member.name}; /* +0x{member.offset:x} */"
            for member in member_list.members
        ]
        existing = declarations.get(member_list.owner_name)
        if existing is None or len(lines) > len(existing):
            declarations[member_list.owner_name] = lines
    return declarations


def _tdinfo(info: TDInfoEXEInfo | None) -> dict[str, Any] | None:
    if info is None:
        return None

    type_names = _tdinfo_type_names(info)

    def record(record_obj) -> dict[str, Any]:  # noqa: ANN001
        return {
            "index": record_obj.index,
            "type_index": record_obj.type_index,
            "offset": record_obj.offset,
            "signed_offset": record_obj.signed_offset,
            "segment": record_obj.segment,
            "symbol_class": _td_symbol_class(record_obj.symbol_class),
        }

    def named(named_obj) -> dict[str, Any]:  # noqa: ANN001
        return {"name": named_obj.name, "record": record(named_obj.record)}

    return {
        "debug_info_offset": f"0x{info.debug_info_offset:x}",
        "header": {
            "major_version": info.header.major_version,
            "minor_version": info.header.minor_version,
            "names_pool_size_in_bytes": info.header.names_pool_size_in_bytes,
            "names_count": info.header.names_count,
            "types_count": info.header.types_count,
            "members_count": info.header.members_count,
            "symbols_count": info.header.symbols_count,
            "globals_count": info.header.globals_count,
            "extension_size": info.header.extension_size,
            "source_modules_count": info.header.source_modules_count,
            "local_symbols_count": info.header.local_symbols_count,
            "scopes_count": info.header.scopes_count,
            "line_entries_count": info.header.line_entries_count,
            "include_files_count": info.header.include_files_count,
            "segments_count": info.header.segments_count,
            "correlations_count": info.header.correlations_count,
            "class_entries_count": info.header.class_entries_count,
            "parent_entries_count": info.header.parent_entries_count,
            "module_class_entries_count": info.header.module_class_entries_count,
            "coverage_offsets_count": info.header.coverage_offsets_count,
        },
        "modules": [
            {
                "index": module.index,
                "name": module.name,
                "language_flags": f"0x{module.language_flags:x}",
                "symbols_index": module.symbols_index,
                "symbols_count": module.symbols_count,
                "sources_index": module.sources_index,
                "sources_count": module.sources_count,
                "correlation_index": module.correlation_index,
                "correlation_count": module.correlation_count,
            }
            for module in info.modules
        ],
        "source_file_entries": [
            {
                "index": entry.index,
                "name": entry.name,
                "size": entry.size,
                "timestamp": f"0x{entry.timestamp:x}",
            }
            for entry in info.source_file_entries
        ],
        "segments": [
            {
                "index": segment.index,
                "module_index": segment.module_index,
                "code_segment": f"0x{segment.code_segment:x}",
                "code_offset": f"0x{segment.code_offset:x}",
                "code_length": f"0x{segment.code_length:x}",
                "scope_index": segment.scope_index,
                "scope_count": segment.scope_count,
                "correlation_index": segment.correlation_index,
                "correlation_count": segment.correlation_count,
            }
            for segment in info.segments
        ],
        "tds_version": info.tds_version_str,
        "tlink_version": info.tlink_version_str,
        "products": info.products,
        "commandline_hint": info.commandline_hint,
        "names": list(info.names),
        "demangled_names": {
            pool_name: render_borland_signature(demangle_borland_name(pool_name))
            for pool_name in sorted(info.names)
            if pool_name.startswith("@")
        },
        "name_pool_entries": [
            {"index": entry.index, "name": entry.name, "kind": entry.kind.name} for entry in info.name_pool_entries
        ],
        "source_files": list(info.source_files),
        "candidate_identifiers": list(info.candidate_identifiers),
        "public_symbols": list(info.public_symbols),
        "local_identifiers": list(info.local_identifiers),
        "type_names": list(info.type_names),
        "type_descriptors": [
            {
                "type_index": descriptor.type_index,
                "kind": descriptor.kind.name,
                "name": descriptor.name,
                "size": descriptor.size,
                "payload_offset": f"0x{descriptor.payload_offset:x}",
                "base_type_index": descriptor.base_type_index,
                "target_type_index": descriptor.target_type_index,
                "return_type_index": descriptor.return_type_index,
                "call_kind": descriptor.call_kind,
                "attributes": descriptor.attributes,
                **_tdinfo_pointer_flags(descriptor),
                "lower_bound": descriptor.lower_bound,
                "upper_bound": descriptor.upper_bound,
                "member_ref": descriptor.member_ref,
                "builtin_type_id": descriptor.builtin_type_id,
                **_tdinfo_extension_fields(descriptor, info.names),
                "raw_bytes": descriptor.raw_bytes.hex(),
            }
            for descriptor in info.type_descriptors
        ],
        "type_references": [
            {
                "name": ref.name,
                "type_index": ref.type_index,
                "symbol_class": _td_symbol_class(ref.symbol_class),
            }
            for ref in info.type_references
        ],
        "type_members": [
            {
                "name": member.name,
                "offset": member.offset,
                "owner_type_index": member.owner_type_index,
                "type_index": member.type_index,
                "attributes": member.attributes,
                "payload_offset": f"0x{member.payload_offset:x}",
            }
            for member in info.type_members
        ],
        "enum_members": [
            {
                "name": member.name,
                "value": member.value,
                "owner_type_index": member.owner_type_index,
                "attributes": member.attributes,
                "payload_offset": f"0x{member.payload_offset:x}",
            }
            for member in info.enum_members
        ],
        "member_lists": [
            {
                "record_index": member_list.record_index,
                "block_ordinal": member_list.block_ordinal,
                "payload_offset": f"0x{member_list.payload_offset:x}",
                "size": member_list.size,
                "owner_name": member_list.owner_name,
                "owner_type_index": member_list.owner_type_index,
                "bitfield": member_list.bitfield,
                "method_names": list(member_list.method_names),
                "method_signatures": [
                    render_borland_signature(demangle_borland_name(method_name))
                    for method_name in member_list.method_names
                ],
                "members": [
                    {
                        "name": member.name,
                        # Bitfield members carry a bit position (ordinal in
                        # declaration order) rather than a byte offset.
                        **(
                            {"bit_index": bit_index}
                            if member_list.bitfield
                            else {"offset": member.offset}
                        ),
                        "type_index": member.type_index,
                        "type_name": type_names.get(member.type_index, "?"),
                        "attributes": member.attributes,
                    }
                    for bit_index, member in enumerate(member_list.members)
                ],
            }
            for member_list in info.member_lists
        ],
        "coverage_map": [
            {"index": entry.index, "offset_index": entry.offset_index}
            for entry in info.coverage_map
        ],
        "coverage_offsets": [
            {
                "index": entry.index,
                "segment_index": entry.segment_index,
                "offset": f"0x{entry.offset:x}",
            }
            for entry in info.coverage_offsets
        ],
        "module_flags": [
            {"index": entry.index, "flags": f"0x{entry.flags:08x}"}
            for entry in info.module_flags
        ],
        "struct_declarations": _tdinfo_struct_declarations(info, type_names),
        "function_signatures": _tdinfo_function_signatures(info, type_names),
        "class_entries": [
            {
                "index": entry.index,
                "name": entry.name,
                "name_index": entry.name_index,
                "parent_table_index": entry.parent_table_index,
                "parent_count": entry.parent_count,
                "member_ordinal": entry.member_ordinal,
                "vptr_index": entry.vptr_index,
                "info": entry.info,
                "parent_class_indexes": list(entry.parent_class_indexes),
            }
            for entry in info.class_entries
        ],
        "parent_class_table": list(info.parent_class_table),
        "module_class_entries": [
            {
                "index": entry.index,
                "flags": entry.flags,
                "reserved": entry.reserved,
                "class_index": entry.class_index,
                "class_count": entry.class_count,
            }
            for entry in info.module_class_entries
        ],
        "line_entries": [
            {"index": entry.index, "line": entry.line, "offset": entry.offset}
            for entry in info.line_entries
        ],
        "scopes": [
            {
                "index": entry.index,
                "autos_index": entry.autos_index,
                "autos_count": entry.autos_count,
                "parent_scope": entry.parent_scope,
                "function_symbol": entry.function_symbol,
                "scope_offset": entry.scope_offset,
                "scope_length": entry.scope_length,
            }
            for entry in info.scopes
        ],
        "correlations": [
            {
                "index": entry.index,
                "segment_index": entry.segment_index,
                "file_index": entry.file_index,
                "line_index": entry.line_index,
                "line_count": entry.line_count,
            }
            for entry in info.correlations
        ],
        "raw_table_spans": [
            {
                "name": span.name,
                "offset": f"0x{span.offset:x}",
                "size": span.size,
                "count": span.count,
                "record_size": span.record_size,
            }
            for span in info.raw_table_spans
        ],
        "symbols": [record(symbol) for symbol in info.symbols],
        "named_symbols": [named(symbol) for symbol in info.named_symbols],
        "names_by_class": {_td_symbol_class(klass): list(names) for klass, names in info.names_by_class.items()},
        "symbols_by_class": {
            _td_symbol_class(klass): [record(symbol) for symbol in symbols]
            for klass, symbols in info.symbols_by_class.items()
        },
        "stack_variables": [named(symbol) for symbol in info.stack_variables],
        "register_symbols": [named(symbol) for symbol in info.register_symbols],
        "constant_symbols": [named(symbol) for symbol in info.constant_symbols],
        "code_labels": _hex_keyed(info.code_labels),
        "data_labels": _hex_keyed(info.data_labels),
    }


def dump_debug_info(path: Path, *, load_base_linear: int) -> dict[str, Any]:  # noqa: D103
    return {
        "binary": str(path),
        "load_base_linear": f"0x{load_base_linear:x}",
        "codeview_nb00": _nb00(parse_codeview_nb00(path, load_base_linear=load_base_linear)),
        "codeview_nb0204": _nb0204(parse_codeview_nb0204(path, load_base_linear=load_base_linear)),
        "tdinfo": _tdinfo(parse_tdinfo_exe(path, load_base_linear=load_base_linear)),
    }


def main(argv: list[str] | None = None) -> int:  # noqa: D103
    parser = argparse.ArgumentParser(description="Dump all supported DOS debug information from an executable.")
    parser.add_argument("binary", type=Path)
    parser.add_argument("--load-base-linear", type=_parse_int, default=0, help="linear load base, e.g. 0x10000")
    parser.add_argument("--compact", action="store_true", help="emit single-line JSON")
    args = parser.parse_args(argv)

    payload = dump_debug_info(args.binary, load_base_linear=args.load_base_linear)
    indent = None if args.compact else 2
    print(json.dumps(payload, indent=indent, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
