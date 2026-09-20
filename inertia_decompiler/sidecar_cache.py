"""Cache parsed sidecar metadata as optional evidence artifacts.

Layer: CLI/fallback/reporting.
Responsibility: persist optional sidecar metadata without turning debug evidence into required semantics.
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Protocol

from angr_platforms.X86_16.lst_extract import (
    DebugEnumMemberEvidence,
    DebugSymbolEvidence,
    DebugTypeDescriptorEvidence,
    DebugTypeMemberEvidence,
    DebugTypeReferenceEvidence,
    LSTMetadata,
)

from inertia_decompiler.cache import (
    _cache_file_fingerprint,
    _load_cache_json,
    _sidecar_metadata_cache_key,
    _store_cache_json,
)

_SOURCE_FORMAT_RENAMES = {
    "flair_pat": "startup_flair_pat",
}
_SOURCE_FORMAT_DROP_TOKENS = {
    "local_omf_pat",
    "local_pat",
    "peer_exe",
}
_SIDECAR_METADATA_PARSER_CACHE_VERSION = 13

type PayloadSequence = tuple[object, ...]
type PayloadPairs = tuple[tuple[object, object], ...]
type PayloadTriples = tuple[tuple[object, object, object], ...]


class _KnowledgeBaseLike(Protocol):
    """Project knowledge-base surface used to attach sidecar labels."""

    labels: dict[int, str]


class _ProjectLike(Protocol):
    """Third-party angr project attributes used by sidecar caching."""

    kb: _KnowledgeBaseLike
    _inertia_lst_metadata: LSTMetadata
    _inertia_debug_source_files: tuple[str, ...]
    _inertia_debug_type_names: tuple[str, ...]
    _inertia_debug_type_descriptors: tuple[DebugTypeDescriptorEvidence, ...]
    _inertia_debug_type_references: tuple[DebugTypeReferenceEvidence, ...]
    _inertia_debug_symbols: tuple[DebugSymbolEvidence, ...]
    _inertia_debug_type_members: tuple[DebugTypeMemberEvidence, ...]
    _inertia_debug_enum_members: tuple[DebugEnumMemberEvidence, ...]
    _inertia_debug_identifiers: tuple[str, ...]
    _inertia_debug_line_map: dict[int, tuple[int, int]]


def _visible_source_format(source_format: str | None) -> str:
    return _normalize_source_format(source_format)


def _normalize_source_format(source_format: str | None) -> str:
    raw = source_format or ""
    normalized_tokens: list[str] = []
    seen: set[str] = set()
    for part in raw.split("+"):
        token = part.strip()
        if not token:
            continue
        if token in _SOURCE_FORMAT_DROP_TOKENS:
            continue
        token = _SOURCE_FORMAT_RENAMES.get(token, token)
        if token in _SOURCE_FORMAT_DROP_TOKENS or token in seen:
            continue
        normalized_tokens.append(token)
        seen.add(token)
    return "+".join(normalized_tokens) if normalized_tokens else "sidecars"


_PROJECT_ATTR_KEYS = (
    "_inertia_flair_sig_titles",
    "_inertia_flair_startup_matches",
    "_inertia_signature_compiler_names",
)


@dataclass(frozen=True)
class CachedSidecarMetadata:
    """Cached sidecar metadata plus optional project-scoped signature attributes."""

    metadata: LSTMetadata
    project_attrs: dict[str, tuple[str, ...]]


def _maybe_rebase_stale_absolute_metadata(metadata: LSTMetadata, project: _ProjectLike) -> LSTMetadata:
    def _impl() -> LSTMetadata:
        # Dynamic angr boundary: loader/main_object are supplied by the third-party Project.
        main_object = getattr(getattr(project, "loader", None), "main_object", None)
        # Dynamic angr boundary: linked_base is optional on loader main objects.
        linked_base = getattr(main_object, "linked_base", 0) or 0
        if linked_base <= 0:
            return metadata
        if not metadata.absolute_addrs:
            return metadata
        if "cod_listing" not in (metadata.source_format or ""):
            return metadata
        code_keys = tuple(metadata.code_labels.keys())
        if not code_keys:
            return metadata
        if max(code_keys) >= linked_base:
            return metadata
        # Dynamic angr boundary: project entry can be absent in synthetic tests.
        if getattr(project, "entry", 0) < linked_base:
            return metadata
        shift = linked_base
        return LSTMetadata(
            data_labels={addr + shift: name for addr, name in metadata.data_labels.items()},
            code_labels={addr + shift: name for addr, name in metadata.code_labels.items()},
            code_ranges={
                addr + shift: (start + shift, end + shift) for addr, (start, end) in metadata.code_ranges.items()
            },
            function_entry_addrs=frozenset(addr + shift for addr in metadata.function_entry_addrs),
            signature_code_addrs=frozenset(addr + shift for addr in metadata.signature_code_addrs),
            absolute_addrs=True,
            source_format=metadata.source_format,
            struct_names=metadata.struct_names,
            debug_source_files=metadata.debug_source_files,
            debug_type_names=metadata.debug_type_names,
            debug_type_descriptors=metadata.debug_type_descriptors,
            debug_type_references=metadata.debug_type_references,
            debug_symbols=tuple(
                replace(symbol, linear_addr=symbol.linear_addr + shift)
                if symbol.linear_addr is not None
                else symbol
                for symbol in metadata.debug_symbols
            ),
            debug_type_members=metadata.debug_type_members,
            debug_enum_members=metadata.debug_enum_members,
            debug_identifiers=metadata.debug_identifiers,
            debug_line_map={addr + shift: line for addr, line in metadata.debug_line_map.items()},
            cod_path=metadata.cod_path,
            cod_proc_kinds={addr + shift: kind for addr, kind in metadata.cod_proc_kinds.items()},
        )

    return _impl()


def sidecar_metadata_cache_key(
    *,
    binary_path: Path | None,
    pat_backend: str | None,
    signature_catalog: Path | None,
) -> dict[str, object] | None:
    """Build the cache key for sidecar metadata inputs."""
    extra: dict[str, object] = {
        "pat_backend": pat_backend or "",
        "parser_version": _SIDECAR_METADATA_PARSER_CACHE_VERSION,
    }
    signature_fingerprint = _cache_file_fingerprint(signature_catalog)
    if signature_fingerprint is not None:
        extra["signature_catalog"] = signature_fingerprint
    return _sidecar_metadata_cache_key(binary_path=binary_path, kind="sidecar_metadata", extra=extra)


def load_cached_sidecar_metadata(
    *,
    binary_path: Path | None,
    pat_backend: str | None,
    signature_catalog: Path | None,
) -> tuple[CachedSidecarMetadata | None, dict[str, object] | None]:
    """Load cached sidecar metadata and its cache key when available."""
    cache_key = sidecar_metadata_cache_key(
        binary_path=binary_path,
        pat_backend=pat_backend,
        signature_catalog=signature_catalog,
    )
    if cache_key is None:
        return None, None
    cached = _load_cache_json("sidecar_metadata", cache_key)
    if not isinstance(cached, dict):
        return None, cache_key
    metadata_payload = cached.get("metadata")
    if not isinstance(metadata_payload, dict):
        return None, cache_key
    metadata = _deserialize_lst_metadata(metadata_payload)
    if metadata is None:
        return None, cache_key
    project_attrs = _deserialize_project_attrs(cached.get("project_attrs"))
    return CachedSidecarMetadata(metadata=metadata, project_attrs=project_attrs), cache_key


def store_cached_sidecar_metadata(
    *,
    cache_key: dict[str, object] | None,
    metadata: LSTMetadata,
    project: _ProjectLike,
) -> None:
    """Store parsed sidecar metadata in the optional evidence cache."""
    if cache_key is None:
        return
    payload = {
        "metadata": _serialize_lst_metadata(metadata),
        "project_attrs": _serialize_project_attrs(project),
    }
    _store_cache_json("sidecar_metadata", cache_key, payload)


def apply_cached_sidecar_metadata(project: _ProjectLike, cached: CachedSidecarMetadata) -> LSTMetadata:
    """Attach cached sidecar metadata to a project and return the effective metadata."""
    metadata = _maybe_rebase_stale_absolute_metadata(cached.metadata, project)
    project._inertia_lst_metadata = metadata
    _attach_debug_evidence_attrs(project, metadata)
    for addr, name in metadata.data_labels.items():
        project.kb.labels[addr] = name
    for addr, name in metadata.code_labels.items():
        project.kb.labels[addr] = name
    for key, values in cached.project_attrs.items():
        # Dynamic compatibility boundary: cached project attrs are keyed optional angr Project sidecars.
        setattr(project, key, values)
    return metadata


def _attach_debug_evidence_attrs(project: _ProjectLike, metadata: LSTMetadata) -> None:
    project._inertia_debug_source_files = metadata.debug_source_files
    project._inertia_debug_type_names = metadata.debug_type_names
    project._inertia_debug_type_descriptors = metadata.debug_type_descriptors
    project._inertia_debug_type_references = metadata.debug_type_references
    project._inertia_debug_symbols = metadata.debug_symbols
    project._inertia_debug_type_members = metadata.debug_type_members
    project._inertia_debug_enum_members = metadata.debug_enum_members
    project._inertia_debug_identifiers = metadata.debug_identifiers
    project._inertia_debug_line_map = metadata.debug_line_map


def emit_sidecar_metadata_debug(project: _ProjectLike, metadata: LSTMetadata) -> None:
    """Emit a compact debug summary for loaded sidecar metadata."""
    print(
        f"[dbg] loaded sidecar metadata: format={_visible_source_format(metadata.source_format)} "
        f"code_labels={len(metadata.code_labels)} data_labels={len(metadata.data_labels)} "
        f"structs={len(metadata.struct_names)} debug_files={len(metadata.debug_source_files)} "
        f"debug_types={len(metadata.debug_type_names)} debug_refs={len(metadata.debug_type_references)} "
        f"debug_descs={len(metadata.debug_type_descriptors)} "
        f"debug_symbols={len(metadata.debug_symbols)} "
        f"debug_members={len(metadata.debug_type_members)} debug_enums={len(metadata.debug_enum_members)} "
        f"debug_ids={len(metadata.debug_identifiers)} debug_lines={len(metadata.debug_line_map)}",
        file=sys.stderr,
        flush=True,
    )
    # Dynamic compatibility boundary: signature metadata is attached opportunistically to angr Project objects.
    compiler_names = getattr(project, "_inertia_signature_compiler_names", ())
    if compiler_names:
        filtered_compiler_names = []
        for name in compiler_names:
            normalized = str(name).strip()
            if not normalized or normalized.lower() in {"ida flair", "v"}:
                continue
            if normalized not in filtered_compiler_names:
                filtered_compiler_names.append(normalized)
        if filtered_compiler_names:
            print(
                f"[dbg] signature-matched compiler versions: {', '.join(filtered_compiler_names[:4])}",
                file=sys.stderr,
                flush=True,
            )
    # Dynamic compatibility boundary: flair metadata is attached opportunistically to angr Project objects.
    flair_titles = getattr(project, "_inertia_flair_sig_titles", ())
    if flair_titles:
        print(
            f"[dbg] flair signature catalogs: {', '.join(flair_titles[:3])}",
            file=sys.stderr,
            flush=True,
        )


def _serialize_lst_metadata(metadata: LSTMetadata) -> dict[str, object]:
    return {
        "data_labels": sorted(metadata.data_labels.items()),
        "code_labels": sorted(metadata.code_labels.items()),
        "code_ranges": sorted((addr, start, end) for addr, (start, end) in metadata.code_ranges.items()),
        "function_entry_addrs": sorted(metadata.function_entry_addrs),
        "signature_code_addrs": sorted(metadata.signature_code_addrs),
        "absolute_addrs": bool(metadata.absolute_addrs),
        "source_format": metadata.source_format,
        "struct_names": list(metadata.struct_names),
        "debug_source_files": list(metadata.debug_source_files),
        "debug_type_names": list(metadata.debug_type_names),
        "debug_type_descriptors": [
            {
                "type_index": descriptor.type_index,
                "kind": descriptor.kind,
                "name": descriptor.name,
                "size": descriptor.size,
                "base_type_index": descriptor.base_type_index,
                "target_type_index": descriptor.target_type_index,
                "return_type_index": descriptor.return_type_index,
                "call_kind": descriptor.call_kind,
                "attributes": descriptor.attributes,
                "lower_bound": descriptor.lower_bound,
                "upper_bound": descriptor.upper_bound,
                "source": descriptor.source,
            }
            for descriptor in metadata.debug_type_descriptors
        ],
        "debug_type_references": [
            {
                "name": ref.name,
                "type_index": ref.type_index,
                "symbol_class": ref.symbol_class,
                "source": ref.source,
            }
            for ref in metadata.debug_type_references
        ],
        "debug_symbols": [
            {
                "name": symbol.name,
                "symbol_class": symbol.symbol_class,
                "storage": symbol.storage,
                "offset": symbol.offset,
                "signed_offset": symbol.signed_offset,
                "segment": symbol.segment,
                "linear_addr": symbol.linear_addr,
                "length": symbol.length,
                "type_index": symbol.type_index,
                "owner_name": symbol.owner_name,
                "attributes": [[key, value] for key, value in symbol.attributes],
                "source": symbol.source,
            }
            for symbol in metadata.debug_symbols
        ],
        "debug_type_members": [
            {
                "name": member.name,
                "offset": member.offset,
                "owner_type_index": member.owner_type_index,
                "type_index": member.type_index,
                "leaf_index": member.leaf_index,
                "attributes": member.attributes,
                "source": member.source,
            }
            for member in metadata.debug_type_members
        ],
        "debug_enum_members": [
            {
                "name": member.name,
                "value": member.value,
                "owner_type_index": member.owner_type_index,
                "attributes": member.attributes,
                "source": member.source,
            }
            for member in metadata.debug_enum_members
        ],
        "debug_identifiers": list(metadata.debug_identifiers),
        "debug_line_map": sorted((addr, line, col) for addr, (line, col) in metadata.debug_line_map.items()),
        "cod_path": metadata.cod_path,
        "cod_proc_kinds": sorted(metadata.cod_proc_kinds.items()),
    }


def lst_metadata_content_digest_8616(metadata: LSTMetadata) -> str:
    """Return deterministic identity for all attached sidecar evidence fields."""
    encoded = json.dumps(
        _serialize_lst_metadata(metadata),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _payload_sequence(payload: dict[str, object], key: str) -> PayloadSequence:
    value = payload.get(key, ())
    if isinstance(value, (list, tuple)):
        return tuple(value)
    return ()


def _payload_pairs(payload: dict[str, object], key: str) -> PayloadPairs:
    pairs: list[tuple[object, object]] = []
    for item in _payload_sequence(payload, key):
        if isinstance(item, (list, tuple)) and len(item) == 2:
            pairs.append((item[0], item[1]))
    return tuple(pairs)


def _payload_triples(payload: dict[str, object], key: str) -> PayloadTriples:
    triples: list[tuple[object, object, object]] = []
    for item in _payload_sequence(payload, key):
        if isinstance(item, (list, tuple)) and len(item) == 3:
            triples.append((item[0], item[1], item[2]))
    return tuple(triples)


def _payload_ints(payload: dict[str, object], key: str) -> tuple[int, ...]:
    values: list[int] = []
    for item in _payload_sequence(payload, key):
        value = _optional_int(item)
        if value is not None:
            values.append(value)
    return tuple(values)


def _coerce_cache_int(value: object) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, (str, bytes, bytearray)):
        return int(value)
    return int(str(value))


def _deserialize_lst_metadata(payload: dict[str, object]) -> LSTMetadata | None:
    try:
        data_labels = {_coerce_cache_int(addr): str(name) for addr, name in _payload_pairs(payload, "data_labels")}
        code_labels = {_coerce_cache_int(addr): str(name) for addr, name in _payload_pairs(payload, "code_labels")}
        code_ranges = {
            _coerce_cache_int(addr): (_coerce_cache_int(start), _coerce_cache_int(end))
            for addr, start, end in _payload_triples(payload, "code_ranges")
        }
        signature_code_addrs = frozenset(_payload_ints(payload, "signature_code_addrs"))
        function_entry_addrs = frozenset(_payload_ints(payload, "function_entry_addrs"))
        cod_proc_kinds = {_coerce_cache_int(addr): str(kind) for addr, kind in _payload_pairs(payload, "cod_proc_kinds")}
        struct_names = tuple(str(name) for name in _payload_sequence(payload, "struct_names"))
        debug_source_files = tuple(str(name) for name in _payload_sequence(payload, "debug_source_files"))
        debug_type_names = tuple(str(name) for name in _payload_sequence(payload, "debug_type_names"))
        debug_type_descriptors = _deserialize_debug_type_descriptors(payload.get("debug_type_descriptors", ()))
        debug_type_references = _deserialize_debug_type_references(payload.get("debug_type_references", ()))
        debug_symbols = _deserialize_debug_symbols(payload.get("debug_symbols", ()))
        debug_type_members = _deserialize_debug_type_members(payload.get("debug_type_members", ()))
        debug_enum_members = _deserialize_debug_enum_members(payload.get("debug_enum_members", ()))
        debug_identifiers = tuple(str(name) for name in _payload_sequence(payload, "debug_identifiers"))
        debug_line_map = {
            _coerce_cache_int(addr): (_coerce_cache_int(line), _coerce_cache_int(col))
            for addr, line, col in _payload_triples(payload, "debug_line_map")
        }
        cod_path = payload.get("cod_path")
        if cod_path is not None:
            cod_path = str(cod_path)
        return LSTMetadata(
            data_labels=data_labels,
            code_labels=code_labels,
            code_ranges=code_ranges,
            function_entry_addrs=function_entry_addrs,
            signature_code_addrs=signature_code_addrs,
            absolute_addrs=bool(payload.get("absolute_addrs", False)),
            source_format=_normalize_source_format(str(payload.get("source_format", "sidecars"))),
            struct_names=struct_names,
            debug_source_files=debug_source_files,
            debug_type_names=debug_type_names,
            debug_type_descriptors=debug_type_descriptors,
            debug_type_references=debug_type_references,
            debug_symbols=debug_symbols,
            debug_type_members=debug_type_members,
            debug_enum_members=debug_enum_members,
            debug_identifiers=debug_identifiers,
            debug_line_map=debug_line_map,
            cod_path=cod_path,
            cod_proc_kinds=cod_proc_kinds,
        )
    except Exception:
        return None


def _deserialize_debug_type_members(payload: object) -> tuple[DebugTypeMemberEvidence, ...]:
    if not isinstance(payload, list):
        return ()
    members: list[DebugTypeMemberEvidence] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        if not name:
            continue
        offset = _optional_int(item.get("offset"))
        owner_type_index = _optional_int(item.get("owner_type_index"))
        type_index = _optional_int(item.get("type_index"))
        leaf_index = _optional_int(item.get("leaf_index"))
        attributes = _optional_int(item.get("attributes"))
        members.append(
            DebugTypeMemberEvidence(
                name=name,
                offset=offset,
                owner_type_index=owner_type_index,
                type_index=type_index,
                leaf_index=leaf_index,
                attributes=attributes,
                source=str(item.get("source", "")),
            )
        )
    return tuple(members)


def _deserialize_debug_type_descriptors(payload: object) -> tuple[DebugTypeDescriptorEvidence, ...]:
    if not isinstance(payload, list):
        return ()
    descriptors: list[DebugTypeDescriptorEvidence] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        type_index = _optional_int(item.get("type_index"))
        kind = str(item.get("kind", "")).strip()
        if type_index is None or not kind:
            continue
        descriptors.append(
            DebugTypeDescriptorEvidence(
                type_index=type_index,
                kind=kind,
                name=str(item.get("name", "")),
                size=_optional_int(item.get("size")),
                base_type_index=_optional_int(item.get("base_type_index")),
                target_type_index=_optional_int(item.get("target_type_index")),
                return_type_index=_optional_int(item.get("return_type_index")),
                call_kind=_optional_int(item.get("call_kind")),
                attributes=_optional_int(item.get("attributes")),
                lower_bound=_optional_int(item.get("lower_bound")),
                upper_bound=_optional_int(item.get("upper_bound")),
                source=str(item.get("source", "")),
            )
        )
    return tuple(descriptors)


def _deserialize_debug_symbols(payload: object) -> tuple[DebugSymbolEvidence, ...]:
    if not isinstance(payload, list):
        return ()
    symbols: list[DebugSymbolEvidence] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        if not name:
            continue
        symbols.append(
            DebugSymbolEvidence(
                name=name,
                symbol_class=str(item.get("symbol_class", "")),
                storage=str(item.get("storage", "")),
                offset=_optional_int(item.get("offset")),
                signed_offset=_optional_int(item.get("signed_offset")),
                segment=_optional_int(item.get("segment")),
                linear_addr=_optional_int(item.get("linear_addr")),
                length=_optional_int(item.get("length")),
                type_index=_optional_int(item.get("type_index")),
                owner_name=str(item.get("owner_name", "")),
                attributes=_deserialize_symbol_attributes(item.get("attributes")),
                source=str(item.get("source", "")),
            )
        )
    return tuple(symbols)


def _deserialize_symbol_attributes(payload: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(payload, list):
        return ()
    attrs: list[tuple[str, str]] = []
    for item in payload:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            continue
        attrs.append((str(item[0]), str(item[1])))
    return tuple(attrs)


def _deserialize_debug_type_references(payload: object) -> tuple[DebugTypeReferenceEvidence, ...]:
    if not isinstance(payload, list):
        return ()
    refs: list[DebugTypeReferenceEvidence] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        type_index = _optional_int(item.get("type_index"))
        if not name or type_index is None:
            continue
        refs.append(
            DebugTypeReferenceEvidence(
                name=name,
                type_index=type_index,
                symbol_class=str(item.get("symbol_class", "")),
                source=str(item.get("source", "")),
            )
        )
    return tuple(refs)


def _deserialize_debug_enum_members(payload: object) -> tuple[DebugEnumMemberEvidence, ...]:
    if not isinstance(payload, list):
        return ()
    members: list[DebugEnumMemberEvidence] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        value = _optional_int(item.get("value"))
        if not name or value is None:
            continue
        members.append(
            DebugEnumMemberEvidence(
                name=name,
                value=value,
                owner_type_index=_optional_int(item.get("owner_type_index")),
                attributes=_optional_int(item.get("attributes")),
                source=str(item.get("source", "")),
            )
        )
    return tuple(members)


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    if not isinstance(value, (int, str, bytes, bytearray)):
        return None
    return int(value)


def _serialize_project_attrs(project: _ProjectLike) -> dict[str, list[str]]:
    payload: dict[str, list[str]] = {}
    for key in _PROJECT_ATTR_KEYS:
        # Dynamic compatibility boundary: project signature attrs are optional third-party Project sidecars.
        values = getattr(project, key, ())
        if not isinstance(values, (tuple, list)) or not values:
            continue
        payload[key] = [str(value) for value in values]
    return payload


def _deserialize_project_attrs(payload: object) -> dict[str, tuple[str, ...]]:
    if not isinstance(payload, dict):
        return {}
    restored: dict[str, tuple[str, ...]] = {}
    for key in _PROJECT_ATTR_KEYS:
        values = payload.get(key)
        if isinstance(values, list) and values:
            restored[key] = tuple(str(value) for value in values)
    return restored
