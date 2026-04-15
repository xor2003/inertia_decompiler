from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from angr_platforms.X86_16.lst_extract import LSTMetadata

from inertia_decompiler.cache import (
    _cache_file_fingerprint,
    _load_cache_json,
    _sidecar_metadata_cache_key,
    _store_cache_json,
)


_PROJECT_ATTR_KEYS = (
    "_inertia_flair_local_pat_sources",
    "_inertia_flair_sig_titles",
    "_inertia_flair_startup_matches",
    "_inertia_peer_exe_paths",
    "_inertia_peer_exe_titles",
    "_inertia_signature_compiler_names",
)


@dataclass(frozen=True)
class CachedSidecarMetadata:
    metadata: LSTMetadata
    project_attrs: dict[str, tuple[str, ...]]


def sidecar_metadata_cache_key(
    *,
    binary_path: Path | None,
    pat_backend: str | None,
    signature_catalog: Path | None,
    allow_peer_exe: bool,
) -> dict[str, object] | None:
    extra: dict[str, object] = {
        "pat_backend": pat_backend or "",
        "allow_peer_exe": bool(allow_peer_exe),
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
    allow_peer_exe: bool,
) -> tuple[CachedSidecarMetadata | None, dict[str, object] | None]:
    cache_key = sidecar_metadata_cache_key(
        binary_path=binary_path,
        pat_backend=pat_backend,
        signature_catalog=signature_catalog,
        allow_peer_exe=allow_peer_exe,
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
    project,
) -> None:
    if cache_key is None:
        return
    payload = {
        "metadata": _serialize_lst_metadata(metadata),
        "project_attrs": _serialize_project_attrs(project),
    }
    _store_cache_json("sidecar_metadata", cache_key, payload)


def apply_cached_sidecar_metadata(project, cached: CachedSidecarMetadata) -> LSTMetadata:
    metadata = cached.metadata
    project._inertia_lst_metadata = metadata
    for addr, name in metadata.data_labels.items():
        project.kb.labels[addr] = name
    for addr, name in metadata.code_labels.items():
        project.kb.labels[addr] = name
    for key, values in cached.project_attrs.items():
        setattr(project, key, values)
    return metadata


def emit_sidecar_metadata_debug(project, metadata: LSTMetadata) -> None:
    print(
        f"[dbg] loaded sidecar metadata: format={metadata.source_format} "
        f"code_labels={len(metadata.code_labels)} data_labels={len(metadata.data_labels)} structs={len(metadata.struct_names)}"
    )
    compiler_names = getattr(project, "_inertia_signature_compiler_names", ())
    if compiler_names:
        print(f"[dbg] signature-matched compiler families: {', '.join(compiler_names[:4])}")
    flair_titles = getattr(project, "_inertia_flair_sig_titles", ())
    if flair_titles:
        print(f"[dbg] flair signature catalogs: {', '.join(flair_titles[:3])}")


def _serialize_lst_metadata(metadata: LSTMetadata) -> dict[str, object]:
    return {
        "data_labels": sorted(metadata.data_labels.items()),
        "code_labels": sorted(metadata.code_labels.items()),
        "code_ranges": sorted((addr, start, end) for addr, (start, end) in metadata.code_ranges.items()),
        "signature_code_addrs": sorted(metadata.signature_code_addrs),
        "absolute_addrs": bool(metadata.absolute_addrs),
        "source_format": metadata.source_format,
        "struct_names": list(metadata.struct_names),
        "cod_path": metadata.cod_path,
        "cod_proc_kinds": sorted(metadata.cod_proc_kinds.items()),
    }


def _deserialize_lst_metadata(payload: dict[str, object]) -> LSTMetadata | None:
    try:
        data_labels = {int(addr): str(name) for addr, name in payload.get("data_labels", ())}
        code_labels = {int(addr): str(name) for addr, name in payload.get("code_labels", ())}
        code_ranges = {
            int(addr): (int(start), int(end))
            for addr, start, end in payload.get("code_ranges", ())
        }
        signature_code_addrs = frozenset(int(addr) for addr in payload.get("signature_code_addrs", ()))
        cod_proc_kinds = {int(addr): str(kind) for addr, kind in payload.get("cod_proc_kinds", ())}
        struct_names = tuple(str(name) for name in payload.get("struct_names", ()))
        cod_path = payload.get("cod_path")
        if cod_path is not None:
            cod_path = str(cod_path)
        return LSTMetadata(
            data_labels=data_labels,
            code_labels=code_labels,
            code_ranges=code_ranges,
            signature_code_addrs=signature_code_addrs,
            absolute_addrs=bool(payload.get("absolute_addrs", False)),
            source_format=str(payload.get("source_format", "sidecars")),
            struct_names=struct_names,
            cod_path=cod_path,
            cod_proc_kinds=cod_proc_kinds,
        )
    except Exception:
        return None


def _serialize_project_attrs(project) -> dict[str, list[str]]:
    payload: dict[str, list[str]] = {}
    for key in _PROJECT_ATTR_KEYS:
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
