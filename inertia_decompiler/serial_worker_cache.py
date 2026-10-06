"""Content-addressed cache for validated serial clean-worker results.

Layer: CLI/fallback/reporting.
Responsibility: reuse immutable validated worker output for an identical worker input contract.

This module does not infer decompiler semantics. A cache hit is accepted only
when the binary, production implementation, CLI policy, caller evidence, and
semantic environment match exactly and the stored C retains its validation and
compiler-acceptance hashes.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from angr_platforms.X86_16.pipeline.errors import PipelineHardError
from angr_platforms.X86_16.segment_program_layout_codec import segment_program_function_evidence_from_record_8616
from angr_platforms.X86_16.tail_validation import x86_16_tail_validation_snapshot_passed

from inertia_decompiler.cache import (
    DECOMPILATION_CACHE_DIR,
    _cache_file_fingerprint,
    _cache_key_lock,
    _load_cache_json,
    _recovery_cache_key,
    _store_cache_json,
    is_non_semantic_cache_environment_name,
)
from inertia_decompiler.cache_runtime_contract import live_decompilation_diagnostics_requested_8616
from inertia_decompiler.cli_arg_parser import CliArguments
from inertia_decompiler.direct_addr_failure_family import FailureFamilySnapshot

SERIAL_WORKER_CACHE_NAMESPACE_8616: str = "serial_clean_worker"
SERIAL_WORKER_CACHE_SCHEMA_8616: int = 2
SERIAL_WORKER_CACHE_MAX_ENTRIES_8616: int = 4096
SERIAL_WORKER_CACHE_ANALYSIS_TIMEOUT_FIELD_8616: str = "cache_analysis_timeout"


class SerialWorkerCacheVerdict8616(StrEnum):
    """Typed outcome of a serial clean-worker cache lookup."""

    HIT = "hit"
    MISS = "miss"
    REFUSED = "refused"
    DISABLED = "disabled"


class SerialWorkerCacheReason8616(StrEnum):
    """Structured reason for a serial clean-worker cache verdict."""

    DIAGNOSTICS = "diagnostics"
    LIVE_DECLARATION_AUTHORITY_REQUIRED = "live_declaration_authority_required"
    NO_KEY = "no_key"
    NOT_FOUND = "not_found"
    INSUFFICIENT_ANALYSIS_BUDGET = "insufficient_analysis_budget"
    ACCEPTANCE_PROOF = "acceptance_proof"
    VALIDATED = "validated"


@dataclass(frozen=True)
class SerialWorkerCacheInputs8616:
    """Complete deterministic input contract for one clean worker."""

    binary_path: Path
    requested_addr: int
    recovery_addr: int
    timeout: int
    window: int
    base_addr: int
    entry_point: int
    c_target: str
    api_style: str
    pat_backend: str
    blob: bool
    signature_catalog: Path | None
    evidence_sha256: str
    semantic_environment: tuple[tuple[str, str], ...]
    result_schema: int
    declared_call_effects: tuple[Path, ...] = ()


@dataclass(frozen=True)
class SerialWorkerCacheLookup8616:
    """Validated cache lookup result and its content-addressed key."""

    verdict: SerialWorkerCacheVerdict8616
    key: dict[str, object] | None
    record: dict[str, object] | None
    reason: SerialWorkerCacheReason8616
    requested_timeout: int


def semantic_worker_environment_8616(environment: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
    """Return stable environment values that can affect generated semantics."""
    return tuple(
        sorted(
            (name, value)
            for name, value in environment.items()
            if name.startswith("INERTIA_") and not is_non_semantic_cache_environment_name(name)
        )
    )


def evidence_file_digest_8616(path: Path) -> str:
    """Hash the exact typed-evidence payload handed to a clean worker."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def serial_worker_cache_inputs_8616(
    args: CliArguments,
    *,
    requested_addr: int,
    recovery_addr: int,
    timeout: int,
    evidence_path: Path,
    environment: Mapping[str, str],
    result_schema: int,
) -> SerialWorkerCacheInputs8616:
    """Build typed cache inputs from the clean worker's exact CLI contract."""
    return SerialWorkerCacheInputs8616(
        binary_path=args.binary,
        requested_addr=requested_addr,
        recovery_addr=recovery_addr,
        timeout=timeout,
        window=args.window,
        base_addr=args.base_addr,
        entry_point=args.entry_point,
        c_target=args.c_target,
        api_style=args.api_style,
        pat_backend=args.pat_backend,
        blob=args.blob,
        signature_catalog=args.signature_catalog,
        evidence_sha256=evidence_file_digest_8616(evidence_path),
        declared_call_effects=tuple(args.declared_call_effects),
        semantic_environment=semantic_worker_environment_8616(environment),
        result_schema=result_schema,
    )


def build_serial_worker_cache_key_8616(inputs: SerialWorkerCacheInputs8616) -> dict[str, object] | None:
    """Build the content key for an immutable clean-worker result."""
    signature_fingerprint = _cache_file_fingerprint(inputs.signature_catalog)
    cache_key = _recovery_cache_key(
        binary_path=inputs.binary_path,
        kind="serial_clean_worker_result",
        extra={
            "serial_worker_cache_schema": SERIAL_WORKER_CACHE_SCHEMA_8616,
            "result_schema": inputs.result_schema,
            "requested_addr": inputs.requested_addr,
            "recovery_addr": inputs.recovery_addr,
            "window": inputs.window,
            "base_addr": inputs.base_addr,
            "entry_point": inputs.entry_point,
            "c_target": inputs.c_target,
            "api_style": inputs.api_style,
            "pat_backend": inputs.pat_backend,
            "blob": inputs.blob,
            "signature_catalog": signature_fingerprint,
            "evidence_sha256": inputs.evidence_sha256,
            "declared_call_effects": [
                _cache_file_fingerprint(path) for path in inputs.declared_call_effects
            ],
            "semantic_environment": inputs.semantic_environment,
            "worker_policy": {
                "alternate_source_c": False,
                "ignore_local_sidecar_hints": True,
                "direct_addr_prefer_lst": False,
                "parallelism": 1,
            },
        },
    )
    if not isinstance(cache_key, dict):
        return None
    return {str(key): value for key, value in cache_key.items()}


def _validated_result_record_8616(
    record: Mapping[str, object],
    *,
    result_schema: int,
    expected_function_addrs: tuple[int, ...] = (),
) -> dict[str, object] | None:
    """Return a cacheable result record only when acceptance proof is closed."""
    if record.get("schema") != result_schema or record.get("status") != "ok":
        return None
    payload = record.get("payload")
    validated_hash = record.get("validated_payload_hash")
    gcc_hash = record.get("gcc_checked_payload_hash")
    tail_validation = record.get("tail_validation")
    if not isinstance(payload, str) or not payload.strip():
        return None
    payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    if validated_hash != payload_hash or gcc_hash != payload_hash:
        return None
    if not isinstance(tail_validation, Mapping) or not x86_16_tail_validation_snapshot_passed(tail_validation):
        return None
    if FailureFamilySnapshot.from_record(record.get("failure_family_snapshot")) is None:
        return None
    try:
        segment_evidence = segment_program_function_evidence_from_record_8616(
            record.get("segment_program_function_evidence")
        )
    except PipelineHardError, ValueError:
        return None
    # This cache owns no live project/source authority for conditional effects.
    if segment_evidence.declared_call_consumptions:
        return None
    if expected_function_addrs and segment_evidence.function_addr not in expected_function_addrs:
        return None
    return dict(record)


def load_serial_worker_cache_8616(
    inputs: SerialWorkerCacheInputs8616,
    *,
    enabled: bool,
) -> SerialWorkerCacheLookup8616:
    """Load one exact validated result or return an explicit miss/refusal."""
    if inputs.declared_call_effects:
        return SerialWorkerCacheLookup8616(
            SerialWorkerCacheVerdict8616.DISABLED, None, None,
            SerialWorkerCacheReason8616.LIVE_DECLARATION_AUTHORITY_REQUIRED,
            inputs.timeout,
        )
    if not enabled or live_decompilation_diagnostics_requested_8616():
        return SerialWorkerCacheLookup8616(
            SerialWorkerCacheVerdict8616.DISABLED,
            None,
            None,
            SerialWorkerCacheReason8616.DIAGNOSTICS,
            inputs.timeout,
        )
    key = build_serial_worker_cache_key_8616(inputs)
    if key is None:
        return SerialWorkerCacheLookup8616(
            SerialWorkerCacheVerdict8616.DISABLED,
            None,
            None,
            SerialWorkerCacheReason8616.NO_KEY,
            inputs.timeout,
        )
    cached = _load_cache_json(SERIAL_WORKER_CACHE_NAMESPACE_8616, key)
    if cached is None:
        return SerialWorkerCacheLookup8616(
            SerialWorkerCacheVerdict8616.MISS,
            key,
            None,
            SerialWorkerCacheReason8616.NOT_FOUND,
            inputs.timeout,
        )
    cached_timeout = cached.get(SERIAL_WORKER_CACHE_ANALYSIS_TIMEOUT_FIELD_8616)
    if not isinstance(cached_timeout, int) or isinstance(cached_timeout, bool) or cached_timeout < inputs.timeout:
        return SerialWorkerCacheLookup8616(
            SerialWorkerCacheVerdict8616.MISS,
            key,
            None,
            SerialWorkerCacheReason8616.INSUFFICIENT_ANALYSIS_BUDGET,
            inputs.timeout,
        )
    record = _validated_result_record_8616(
        cached,
        result_schema=inputs.result_schema,
        expected_function_addrs=(inputs.requested_addr, inputs.recovery_addr),
    )
    if record is None:
        return SerialWorkerCacheLookup8616(
            SerialWorkerCacheVerdict8616.REFUSED,
            key,
            None,
            SerialWorkerCacheReason8616.ACCEPTANCE_PROOF,
            inputs.timeout,
        )
    record.pop(SERIAL_WORKER_CACHE_ANALYSIS_TIMEOUT_FIELD_8616, None)
    return SerialWorkerCacheLookup8616(
        SerialWorkerCacheVerdict8616.HIT,
        key,
        record,
        SerialWorkerCacheReason8616.VALIDATED,
        inputs.timeout,
    )


def _prune_serial_worker_cache_8616(max_entries: int) -> None:
    """Bound the dedicated cache without touching other cache namespaces."""
    namespace_dir = DECOMPILATION_CACHE_DIR / SERIAL_WORKER_CACHE_NAMESPACE_8616
    try:
        entries = sorted(
            (path.stat().st_mtime_ns, path.name, path) for path in namespace_dir.glob("*.json") if path.is_file()
        )
    except OSError:
        return
    for _mtime_ns, _name, path in entries[: max(0, len(entries) - max_entries)]:
        try:
            path.unlink()
        except OSError:
            continue


def store_serial_worker_cache_8616(
    lookup: SerialWorkerCacheLookup8616,
    record: Mapping[str, object],
    *,
    result_schema: int,
    max_entries: int = SERIAL_WORKER_CACHE_MAX_ENTRIES_8616,
) -> bool:
    """Persist one immutable validated result and enforce the cache bound."""
    if lookup.key is None or lookup.verdict is SerialWorkerCacheVerdict8616.DISABLED:
        return False
    validated = _validated_result_record_8616(record, result_schema=result_schema)
    if validated is None:
        return False
    validated[SERIAL_WORKER_CACHE_ANALYSIS_TIMEOUT_FIELD_8616] = lookup.requested_timeout
    try:
        with _cache_key_lock(SERIAL_WORKER_CACHE_NAMESPACE_8616, lookup.key):
            existing = _load_cache_json(SERIAL_WORKER_CACHE_NAMESPACE_8616, lookup.key)
            existing_timeout = (
                existing.get(SERIAL_WORKER_CACHE_ANALYSIS_TIMEOUT_FIELD_8616) if existing is not None else None
            )
            existing_validated = (
                _validated_result_record_8616(existing, result_schema=result_schema) if existing is not None else None
            )
            if (
                isinstance(existing_timeout, int)
                and not isinstance(existing_timeout, bool)
                and existing_timeout >= lookup.requested_timeout
                and existing_validated is not None
            ):
                return True
            _store_cache_json(SERIAL_WORKER_CACHE_NAMESPACE_8616, lookup.key, validated)
            if _load_cache_json(SERIAL_WORKER_CACHE_NAMESPACE_8616, lookup.key) != validated:
                return False
    except OSError, TimeoutError:
        return False
    _prune_serial_worker_cache_8616(max_entries)
    return True
