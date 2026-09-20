"""Content-addressed cache keys for decompiler recovery artifacts.

Layer: CLI/fallback/reporting.
Responsibility: derive cache keys from binary, sidecar, and implementation fingerprints only.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path

from inertia_decompiler.cache_file_digest import (
    cache_content_fingerprint_8616,
    cache_file_digest_8616,
    cache_file_fingerprint_8616,
)
from inertia_decompiler.cache_io import load_cache_json_path, store_cache_json_path
from inertia_decompiler.cache_lock import cache_path_lock
from inertia_decompiler.cache_runtime_contract import cache_runtime_contract_8616
from inertia_decompiler.cache_source_manifest import (
    DIRECT_GLOBAL_OBJECT_CACHE_SOURCE_FILES,
    FUNCTION_DISCOVERY_CACHE_SOURCE_FILES,
    FUNCTION_IR_SSA_CACHE_SOURCE_FILES,
    INDEXED_ALIAS_PROGRAM_CACHE_SOURCE_FILES,
    PROGRAM_CALLSITE_CACHE_SOURCE_FILES,
    RecoveryCacheSourceScope8616,
)
from inertia_decompiler.external_unpacker_cache import deark_cache_identity

_ROOT = Path(__file__).resolve().parents[1]

DECOMPILATION_CACHE_SCHEMA: int = 9
DECOMPILATION_CACHE_DIR: Path = _ROOT / ".inertia_decomp_cache"
_CACHE_NON_SEMANTIC_ENVIRONMENT_NAMES: frozenset[str] = frozenset(
    {
        "INERTIA_ALLOW_PARALLEL_MSC6_WORKERS",
        "INERTIA_ARCHITECTURE_GUARD_VERIFIED_PARENT_PID",
        "INERTIA_ARCH_GUARD_VERIFIED_PARENT_PID",
        "INERTIA_CORE_CPROFILE_PATH",
        "INERTIA_DECOMPILE_VENV",
        "INERTIA_DISABLE_TIMING", "INERTIA_INDEXED_ALIAS_WORKERS",
        "INERTIA_SERIAL_CLEAN_WORKER_EVIDENCE",
        "INERTIA_SERIAL_CLEAN_WORKER_RESULT",
        "INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE",
        "INERTIA_DEBUG_TIMING",
    }
)
_CACHE_NON_SEMANTIC_ENVIRONMENT_PREFIXES: tuple[str, ...] = ("INERTIA_OTEL_",)
BASE_RECOVERY_CACHE_SOURCE_FILES: tuple[Path, ...] = (
    _ROOT / "decompile.py",
    _ROOT / "inertia_decompiler" / "cli.py",
    _ROOT / "inertia_decompiler" / "cli_core.py",
    _ROOT / "inertia_decompiler" / "cli_decompilation.py",
    _ROOT / "inertia_decompiler" / "cli_function_discovery.py",
    _ROOT / "inertia_decompiler" / "cache.py",
    _ROOT / "inertia_decompiler" / "decompilation_quality.py",
    _ROOT / "inertia_decompiler" / "disassembly_helpers.py",
    _ROOT / "inertia_decompiler" / "non_optimized_fallback.py",
    _ROOT / "inertia_decompiler" / "project_loading.py",
    _ROOT / "inertia_decompiler" / "source_sidecar.py",
    _ROOT / "inertia_decompiler" / "binary_signature_metadata.py",
    _ROOT / "inertia_decompiler" / "sidecar_policy.py",
    _ROOT / "inertia_decompiler" / "sidecar_parsers.py",
    _ROOT / "inertia_decompiler" / "sidecar_metadata.py",
    _ROOT / "inertia_decompiler" / "slice_recovery.py",
    _ROOT / "inertia_decompiler" / "rizin_discovery.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "analysis_helpers.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "load_dos_mz.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "load_dos_ne.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "lift_86_16.py",
)
SIDECAR_METADATA_CACHE_SOURCE_FILES: tuple[Path, ...] = (
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
BASE_DECOMPILATION_CACHE_SOURCE_FILES: tuple[Path, ...] = (
    _ROOT / "decompile.py",
    _ROOT / "inertia_decompiler" / "cli.py",
    _ROOT / "inertia_decompiler" / "cli_decompilation.py",
    _ROOT / "inertia_decompiler" / "cli_core.py",
    _ROOT / "inertia_decompiler" / "cli_c_ast_rewrites.py",
    _ROOT / "inertia_decompiler" / "cli_dead_local_prune.py",
    _ROOT / "inertia_decompiler" / "cli_c_text_postprocess.py",
    _ROOT / "inertia_decompiler" / "cache.py",
    _ROOT / "inertia_decompiler" / "decompilation_quality.py",
    _ROOT / "inertia_decompiler" / "disassembly_helpers.py",
    _ROOT / "inertia_decompiler" / "recompile_check.py",
    _ROOT / "inertia_decompiler" / "non_optimized_fallback.py",
    _ROOT / "inertia_decompiler" / "project_loading.py",
    _ROOT / "inertia_decompiler" / "source_sidecar.py",
    _ROOT / "inertia_decompiler" / "sidecar_policy.py",
    _ROOT / "inertia_decompiler" / "sidecar_parsers.py",
    _ROOT / "inertia_decompiler" / "sidecar_metadata.py",
    _ROOT / "inertia_decompiler" / "slice_recovery.py",
    _ROOT / "inertia_decompiler" / "tail_validation.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "analysis_helpers.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "postprocess" / "optimization" / "dead_setup.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "postprocess" / "optimization" / "const_prop.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "postprocess" / "optimization" / "dce.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "postprocess" / "optimization" / "pass_driver.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "condition_ir.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "decompiler_postprocess_flags.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "decompiler_postprocess.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "decompiler_postprocess_calls.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "decompiler_postprocess_jcc.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "decompiler_postprocess_stage.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "decompiler_postprocess_simplify.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "decompiler_postprocess_typed_conditions.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "decompiler_postprocess_utils.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "segmented_memory_reasoning.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "lowering" / "real_mode_linear.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "lowering" / "segmented_global_loads.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "callsite_stack_metadata.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "decompiler_structuring_stage.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "lift_86_16.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "load_dos_mz.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "load_dos_ne.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "tail_validation.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "tail_validation_condition_context.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "tail_validation_fingerprint.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "tail_validation_routing.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "type_array_matching.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "cod_comment_emitter.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "cod_extract.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "ir" / "core.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "pipeline" / "invariants.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "validation_summary.py",
    _ROOT / "inertia_decompiler" / "cli_access_object_hints.py",
    _ROOT / "inertia_decompiler" / "cli_access_profiles.py",
    _ROOT / "inertia_decompiler" / "cli_access_traits.py",
)


def _production_decompiler_source_files() -> tuple[Path, ...]:
    """Return every production Python module that can affect decompilation."""
    package_roots = (
        _ROOT / "inertia_decompiler",
        _ROOT / "angr_platforms" / "angr_platforms" / "X86_16",
    )
    discovered = {
        path for package_root in package_roots for path in package_root.rglob("*.py") if "__pycache__" not in path.parts
    }
    discovered.add(_ROOT / "decompile.py")
    return tuple(sorted(discovered))


_PRODUCTION_DECOMPILER_SOURCE_FILES: tuple[Path, ...] = _production_decompiler_source_files()
RECOVERY_CACHE_SOURCE_FILES: tuple[Path, ...] = tuple(
    sorted({*BASE_RECOVERY_CACHE_SOURCE_FILES, *_PRODUCTION_DECOMPILER_SOURCE_FILES})
)
DECOMPILATION_CACHE_SOURCE_FILES: tuple[Path, ...] = tuple(
    sorted({*BASE_DECOMPILATION_CACHE_SOURCE_FILES, *_PRODUCTION_DECOMPILER_SOURCE_FILES})
)


def _cache_sha256_file(path: Path) -> str:
    """Return an exact content digest with bounded process-local reuse."""
    return cache_file_digest_8616(path).sha256


def _cache_file_fingerprint(path: Path | None) -> dict[str, object] | None:
    """Preserve the cache module's path-qualified fingerprint contract."""
    return cache_file_fingerprint_8616(path)


def _cache_content_fingerprint(path: Path | None) -> dict[str, object] | None:
    """Preserve the cache module's path-independent fingerprint contract."""
    return cache_content_fingerprint_8616(path)


def is_non_semantic_cache_environment_name(name: str) -> bool:
    """Return whether an Inertia variable controls transport or diagnostics only."""
    return name in _CACHE_NON_SEMANTIC_ENVIRONMENT_NAMES or name.startswith(_CACHE_NON_SEMANTIC_ENVIRONMENT_PREFIXES)


def _cache_runtime_environment() -> dict[str, str]:
    """Capture runtime switches that can change recovery or emitted diagnostics."""
    environment = {
        name: value
        for name, value in sorted(os.environ.items())
        if name.startswith("INERTIA_") and not is_non_semantic_cache_environment_name(name)
    }
    decoder_digest = deark_cache_identity()
    if decoder_digest is not None:
        environment["INERTIA_DEARK_EXECUTABLE_SHA256"] = decoder_digest
    return environment


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


def _case_insensitive_sibling_path(binary_path: Path, suffix: str) -> Path | None:
    direct = binary_path.with_suffix(suffix)
    if direct.exists():
        return direct
    parent = binary_path.parent
    try:
        siblings = sorted(parent.iterdir(), key=lambda path: path.name.lower())
    except OSError:
        return None
    wanted_stem = binary_path.stem.lower()
    wanted_suffix = suffix.lower()
    for sibling in siblings:
        if sibling.stem.lower() == wanted_stem and sibling.suffix.lower() == wanted_suffix:
            return sibling
    return None


def _cache_sidecar_fingerprints(binary_path: Path | None) -> dict[str, dict[str, object]]:
    if binary_path is None:
        return {}
    sidecars: dict[str, dict[str, object]] = {}
    for suffix in (".lst", ".map", ".cod", ".idc", ".inc"):
        sidecar_path = _case_insensitive_sibling_path(binary_path, suffix)
        fingerprint = _cache_content_fingerprint(sidecar_path)
        if fingerprint is not None:
            sidecars[suffix] = fingerprint
    return sidecars


def _cache_json_path(namespace: str, key: dict[str, object]) -> Path:
    encoded = json.dumps(key, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return DECOMPILATION_CACHE_DIR / namespace / f"{_cache_sha256_bytes(encoded)}.json"


def _load_cache_json(namespace: str, key: dict[str, object]) -> dict[str, object] | None:
    """Load one cache record through the checked JSON I/O owner."""
    return load_cache_json_path(namespace, _cache_json_path(namespace, key), key_context=key)


@contextmanager
def _cache_key_lock(
    namespace: str,
    key: dict[str, object],
    *,
    timeout_seconds: float = 600.0,
) -> Iterator[None]:
    """Serialize producers for one cache key while allowing readers to retry."""
    lock_path = _cache_json_path(namespace, key).with_suffix(".lock")
    with cache_path_lock(lock_path, timeout_seconds=timeout_seconds):
        yield


def _store_cache_json(namespace: str, key: dict[str, object], payload: dict[str, object]) -> dict[str, object] | None:
    """Store one cache record with an atomic final-path replacement."""
    store_cache_json_path(namespace, _cache_json_path(namespace, key), payload, key_context=key)
    return None


def _function_decompilation_cache_key(
    *,
    binary_path: Path | None,
    function_addr: int,
    active_function_addr: int,
    recovery_addr: int | None,
    function_name: str | None,
    api_style: str,
    c_target: str,
    sidecar_metadata_digest: str | None,
    recovery_shape_digest: str,
    annotation_evidence_digest: str,
    project_evidence_digest: str,
    enable_structured_simplify: bool,
    enable_postprocess: bool,
) -> dict[str, object] | None:
    if not cache_runtime_contract_8616().allows_semantic_cache:
        return None
    binary_fingerprint = _cache_content_fingerprint(binary_path)
    if binary_fingerprint is None:
        return None
    sidecars = _cache_sidecar_fingerprints(binary_path)
    environment = _cache_runtime_environment()
    if not sidecars and sidecar_metadata_digest is None:
        environment.pop("INERTIA_IGNORE_LOCAL_SIDECAR_HINTS_8616", None)
    return {
        "schema": DECOMPILATION_CACHE_SCHEMA,
        "kind": "function_decompile",
        "binary": binary_fingerprint,
        "sidecars": sidecars,
        "environment": environment,
        "components": _cache_source_digest(DECOMPILATION_CACHE_SOURCE_FILES),
        "function_addr": function_addr,
        "active_function_addr": active_function_addr,
        "recovery_addr": recovery_addr,
        "function_name": function_name,
        "api_style": api_style,
        "c_target": c_target,
        "sidecar_metadata_digest": sidecar_metadata_digest,
        "recovery_shape_digest": recovery_shape_digest,
        "annotation_evidence_digest": annotation_evidence_digest,
        "project_evidence_digest": project_evidence_digest,
        "structured_simplify": enable_structured_simplify,
        "postprocess": enable_postprocess,
    }


def _recovery_cache_key(
    *,
    binary_path: Path | None,
    kind: str,
    extra: dict[str, object] | None = None,
    source_scope: RecoveryCacheSourceScope8616 = RecoveryCacheSourceScope8616.FULL_DECOMPILATION,
) -> dict[str, object] | None:
    """Build recovery identity, excluding sidecar policy when no sidecar exists."""
    if not cache_runtime_contract_8616().allows_semantic_cache:
        return None
    binary_fingerprint = _cache_content_fingerprint(binary_path)
    if binary_fingerprint is None:
        return None
    sidecars = _cache_sidecar_fingerprints(binary_path)
    environment = _cache_runtime_environment()
    normalized_extra = dict(extra or {})
    if not sidecars:
        environment.pop("INERTIA_IGNORE_LOCAL_SIDECAR_HINTS_8616", None)
        if "ignore_local_sidecar_hints" in normalized_extra:
            normalized_extra["ignore_local_sidecar_hints"] = False
    source_files = {
        RecoveryCacheSourceScope8616.DIRECT_GLOBAL_OBJECT: DIRECT_GLOBAL_OBJECT_CACHE_SOURCE_FILES,
        RecoveryCacheSourceScope8616.FUNCTION_IR_SSA: FUNCTION_IR_SSA_CACHE_SOURCE_FILES,
        RecoveryCacheSourceScope8616.FUNCTION_DISCOVERY: FUNCTION_DISCOVERY_CACHE_SOURCE_FILES,
        RecoveryCacheSourceScope8616.INDEXED_ALIAS_PROGRAM: INDEXED_ALIAS_PROGRAM_CACHE_SOURCE_FILES,
        RecoveryCacheSourceScope8616.PROGRAM_CALLSITE: PROGRAM_CALLSITE_CACHE_SOURCE_FILES,
    }.get(source_scope, RECOVERY_CACHE_SOURCE_FILES)
    payload = {
        "schema": DECOMPILATION_CACHE_SCHEMA,
        "kind": kind,
        "binary": binary_fingerprint,
        "sidecars": sidecars,
        "environment": environment,
        "components": _cache_source_digest(source_files),
    }
    payload.update(normalized_extra)
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
