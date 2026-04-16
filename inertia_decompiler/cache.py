from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path


_ROOT = Path(__file__).resolve().parents[1]

DECOMPILATION_CACHE_SCHEMA = 2
DECOMPILATION_CACHE_DIR = _ROOT / ".inertia_decomp_cache"
RECOVERY_CACHE_SOURCE_FILES = (
    _ROOT / "decompile.py",
    _ROOT / "inertia_decompiler" / "cli.py",
    _ROOT / "inertia_decompiler" / "cache.py",
    _ROOT / "inertia_decompiler" / "decompilation_quality.py",
    _ROOT / "inertia_decompiler" / "disassembly_helpers.py",
    _ROOT / "inertia_decompiler" / "non_optimized_fallback.py",
    _ROOT / "inertia_decompiler" / "project_loading.py",
    _ROOT / "inertia_decompiler" / "source_sidecar.py",
    _ROOT / "inertia_decompiler" / "sidecar_policy.py",
    _ROOT / "inertia_decompiler" / "sidecar_parsers.py",
    _ROOT / "inertia_decompiler" / "sidecar_metadata.py",
    _ROOT / "inertia_decompiler" / "slice_recovery.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "analysis_helpers.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "load_dos_mz.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "load_dos_ne.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "lift_86_16.py",
)
SIDECAR_METADATA_CACHE_SOURCE_FILES = (
    _ROOT / "inertia_decompiler" / "cache.py",
    _ROOT / "inertia_decompiler" / "sidecar_parsers.py",
    _ROOT / "inertia_decompiler" / "sidecar_metadata.py",
    _ROOT / "omf_pat.py",
    _ROOT / "signature_catalog.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "cod_extract.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "codeview_nb00.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "codeview_nb02_nb04.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "flair_extract.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "load_dos_mz.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "load_dos_ne.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "lst_extract.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "turbo_debug_tdinfo.py",
)
DECOMPILATION_CACHE_SOURCE_FILES = (
    _ROOT / "decompile.py",
    _ROOT / "inertia_decompiler" / "cli.py",
    _ROOT / "inertia_decompiler" / "cache.py",
    _ROOT / "inertia_decompiler" / "decompilation_quality.py",
    _ROOT / "inertia_decompiler" / "disassembly_helpers.py",
    _ROOT / "inertia_decompiler" / "non_optimized_fallback.py",
    _ROOT / "inertia_decompiler" / "project_loading.py",
    _ROOT / "inertia_decompiler" / "source_sidecar.py",
    _ROOT / "inertia_decompiler" / "sidecar_policy.py",
    _ROOT / "inertia_decompiler" / "sidecar_parsers.py",
    _ROOT / "inertia_decompiler" / "sidecar_metadata.py",
    _ROOT / "inertia_decompiler" / "slice_recovery.py",
    _ROOT / "inertia_decompiler" / "tail_validation.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "analysis_helpers.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "decompiler_postprocess.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "decompiler_postprocess_simplify.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "decompiler_structuring_stage.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "lift_86_16.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "load_dos_mz.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "load_dos_ne.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "tail_validation.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "tail_validation_fingerprint.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "tail_validation_routing.py",
)


def _cache_file_fingerprint(path: Path | None) -> dict[str, object] | None:
    if path is None:
        return None
    try:
        resolved = path.resolve()
        stat = resolved.stat()
    except OSError:
        return None
    return {
        "path": str(resolved),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }


def _cache_sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@lru_cache(maxsize=8)
def _cache_source_digest(paths: tuple[Path, ...]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        try:
            resolved = path.resolve()
            data = resolved.read_bytes()
        except OSError:
            continue
        digest.update(str(resolved).encode("utf-8"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return digest.hexdigest()


def _cache_sidecar_fingerprints(binary_path: Path | None) -> dict[str, dict[str, object]]:
    if binary_path is None:
        return {}
    sidecars: dict[str, dict[str, object]] = {}
    for suffix in (".lst", ".map", ".cod"):
        fingerprint = _cache_file_fingerprint(binary_path.with_suffix(suffix))
        if fingerprint is not None:
            sidecars[suffix] = fingerprint
    return sidecars


def _cache_json_path(namespace: str, key: dict[str, object]) -> Path:
    encoded = json.dumps(key, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return DECOMPILATION_CACHE_DIR / namespace / f"{_cache_sha256_bytes(encoded)}.json"


def _load_cache_json(namespace: str, key: dict[str, object]) -> dict[str, object] | None:
    path = _cache_json_path(namespace, key)
    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _store_cache_json(namespace: str, key: dict[str, object], payload: dict[str, object]) -> dict[str, object] | None:
    path = _cache_json_path(namespace, key)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, sort_keys=True))
    except OSError:
        return None
    return None


def _function_decompilation_cache_key(
    *,
    binary_path: Path | None,
    function_addr: int,
    function_name: str | None,
    api_style: str,
    enable_structured_simplify: bool,
    enable_postprocess: bool,
) -> dict[str, object] | None:
    binary_fingerprint = _cache_file_fingerprint(binary_path)
    if binary_fingerprint is None:
        return None
    return {
        "schema": DECOMPILATION_CACHE_SCHEMA,
        "kind": "function_decompile",
        "binary": binary_fingerprint,
        "sidecars": _cache_sidecar_fingerprints(binary_path),
        "components": _cache_source_digest(DECOMPILATION_CACHE_SOURCE_FILES),
        "addr": function_addr,
        "function_name": function_name,
        "api_style": api_style,
        "structured_simplify": enable_structured_simplify,
        "postprocess": enable_postprocess,
    }


def _recovery_cache_key(
    *,
    binary_path: Path | None,
    kind: str,
    extra: dict[str, object] | None = None,
) -> dict[str, object] | None:
    binary_fingerprint = _cache_file_fingerprint(binary_path)
    if binary_fingerprint is None:
        return None
    payload = {
        "schema": DECOMPILATION_CACHE_SCHEMA,
        "kind": kind,
        "binary": binary_fingerprint,
        "sidecars": _cache_sidecar_fingerprints(binary_path),
        "components": _cache_source_digest(RECOVERY_CACHE_SOURCE_FILES),
    }
    if extra:
        payload.update(extra)
    return payload


def _sidecar_metadata_cache_key(
    *,
    binary_path: Path | None,
    kind: str,
    extra: dict[str, object] | None = None,
) -> dict[str, object] | None:
    binary_fingerprint = _cache_file_fingerprint(binary_path)
    if binary_fingerprint is None:
        return None
    payload = {
        "schema": DECOMPILATION_CACHE_SCHEMA,
        "kind": kind,
        "binary": binary_fingerprint,
        "sidecars": _cache_sidecar_fingerprints(binary_path),
        "components": _cache_source_digest(SIDECAR_METADATA_CACHE_SOURCE_FILES),
    }
    if extra:
        payload.update(extra)
    return payload
