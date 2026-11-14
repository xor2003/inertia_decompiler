# cython: language_level=3, infer_types=True
"""Validated cache for identical direct-address CLI requests.

Layer: CLI/fallback/reporting.
Responsibility: reuse accepted direct-address C without repeating recovery when
the complete deterministic request identity and acceptance proof still match.

This cache owns no decompiler semantics. It refuses records without passed tail
validation, matching validation/compiler hashes, clean generated C, and typed
failure-family provenance. Diagnostic modes bypass it because they require live
recovery artifacts.
"""

from __future__ import annotations
import typing
import cython

import copy
import os
from dataclasses import dataclass
from enum import StrEnum

from inertia.cli.accepted_payload_integrity import verify_accepted_payload_integrity_8616
from inertia.cli.cache import (
    _cache_key_lock,
    _load_cache_json,
    _store_cache_json,
)
from inertia.cli.decompilation_quality import assess_final_generated_c_text
from inertia.cli.direct_addr_failure_family import FailureFamilySnapshot
from inertia.cli.direct_request_identity import (
    DIRECT_REQUEST_CACHE_NAMESPACE_8616,
    DIRECT_REQUEST_CACHE_SCHEMA_8616,
    DirectRequestCacheInputs8616,
    build_direct_request_cache_key_8616,
)
import dataclasses
import operator

_EXPECTED_VALIDATION_STAGES_8616: tuple[str, ...] = ("structuring", "postprocess")


class DirectRequestCacheVerdict8616(StrEnum):
    """Typed outcome of one direct-request cache lookup."""

    HIT = "hit"
    MISS = "miss"
    REFUSED = "refused"
    DISABLED = "disabled"


class DirectRequestCacheReason8616(StrEnum):
    """Structured reason for one direct-request cache verdict."""

    VALIDATED = "validated"
    NOT_FOUND = "not_found"
    ACCEPTANCE_PROOF = "acceptance_proof"
    DIAGNOSTICS = "diagnostics"
    NO_KEY = "no_key"


@dataclasses.dataclass(frozen=True, )
class DirectRequestCacheArtifact8616:
    """Accepted generated-C result independent of live angr objects."""

    function_addr: cython.longlong
    function_name: object
    arch_name: object
    entry_point: cython.longlong
    runtime_header: object
    startup_diagnostic_lines: object
    payload: object
    tail_validation: object
    elapsed: float | None
    block_count: int | None
    byte_count: int | None
    validated_payload_hash: object
    gcc_checked_payload_hash: object
    failure_family_snapshot: FailureFamilySnapshot
    diagnostic_output: object
    segment_program_function_evidence_record: object


@dataclasses.dataclass(frozen=True, )
class DirectRequestCacheLookup8616:
    """Cache verdict, key, and accepted artifact for one request."""

    verdict: DirectRequestCacheVerdict8616
    reason: DirectRequestCacheReason8616
    key: object
    artifact: DirectRequestCacheArtifact8616 | None


@cython.ccall
def _tail_stage_diagnostic_status_8616(stage: object) -> object:
    status: object
    if not isinstance(stage, dict):
        return type(stage).__name__
    status = stage.get("status")
    if isinstance(status, str) and status:
        return status
    return "changed" if bool(stage.get("changed", False)) else "stable"


def render_direct_request_tail_snapshot_diagnostic_8616(
    snapshot: object,
) -> str:
    """Render the stable direct-cache diagnostic from typed validation state."""
    if snapshot is None:
        merged_stages: object = "NOT_DICT"
        merged_statuses: object = "N/A"
    else:
        merged_stages = [name for name in iter(_EXPECTED_VALIDATION_STAGES_8616) if name in snapshot]
        merged_stages.extend(
            sorted(name for name in iter(snapshot) if name not in _EXPECTED_VALIDATION_STAGES_8616)
        )
        merged_statuses = {
            name: _tail_stage_diagnostic_status_8616(snapshot[name])
            for name in iter(merged_stages)
        }
    return (
        "[dbg] direct_decompile_job snapshot: project_fb_stages=NOT_DICT "
        f"func_info_tv_stages=None merged_stages={merged_stages} "
        f"merged_statuses={merged_statuses}"
    )


@cython.ccall
def _optional_int(record: object, name: object) -> int | None:
    value: object
    value = record.get(name)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


@cython.ccall
def _optional_float(record: object, name: object) -> float | None:
    value: object
    value = record.get(name)
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


@cython.ccall
def _tail_validation_record_passed_8616(snapshot: object) -> cython.bint:
    """Mirror the authoritative X86 validator for lightweight cache refusal."""
    entry: object
    status: object
    stage: object
    if not isinstance(snapshot, dict):
        return False
    for stage in _EXPECTED_VALIDATION_STAGES_8616:
        entry = snapshot.get(stage)
        if not isinstance(entry, dict):
            return False
        status = entry.get("status")
        if isinstance(status, str) and status:
            if status != "stable":
                return False
            continue
        if bool(entry.get("changed", False)):
            return False
    return True


def _validated_scalar_fields_8616(
    record: object,
) -> object:
    """Validate the record's scalar/header fields and return them in order."""
    arch_name: object
    entry_point: object
    function_addr: object
    function_name: object
    gcc_hash: object
    payload: object
    raw_tail_validation: object
    runtime_header: object
    startup_diagnostic_lines: object
    validated_hash: object
    function_addr = record.get("function_addr")
    function_name = record.get("function_name")
    arch_name = record.get("arch_name")
    entry_point = record.get("entry_point")
    runtime_header = record.get("runtime_header")
    startup_diagnostic_lines = record.get("startup_diagnostic_lines")
    payload = record.get("payload")
    validated_hash = record.get("validated_payload_hash")
    gcc_hash = record.get("gcc_checked_payload_hash")
    raw_tail_validation = record.get("tail_validation")
    if not isinstance(function_addr, int) or isinstance(function_addr, bool) or function_addr < 0:
        return None
    if not isinstance(function_name, str) or not function_name.strip():
        return None
    if not isinstance(arch_name, str) or not arch_name.strip():
        return None
    if not isinstance(entry_point, int) or isinstance(entry_point, bool) or entry_point < 0:
        return None
    if not isinstance(runtime_header, str):
        return None
    if not isinstance(startup_diagnostic_lines, list) or not all(
        isinstance(line, str) and bool(line) for line in iter(startup_diagnostic_lines)
    ):
        return None
    if not isinstance(payload, str) or not payload.strip():
        return None
    if not isinstance(validated_hash, str) or not isinstance(gcc_hash, str):
        return None
    return (
        function_addr,
        function_name,
        arch_name,
        entry_point,
        runtime_header,
        startup_diagnostic_lines,
        payload,
        validated_hash,
        gcc_hash,
        raw_tail_validation,
    )


@cython.ccall
def _payload_proof_ok_8616(
    payload: object,
    validated_hash: object,
    gcc_hash: object,
    raw_tail_validation: object,
) -> cython.bint:
    """Return True when integrity, tail validation, and text review all pass."""
    integrity = verify_accepted_payload_integrity_8616(
        payload,
        validated_payload_hash=validated_hash,
        gcc_checked_payload_hash=gcc_hash,
    )
    if not integrity.passed:
        return False
    if not isinstance(raw_tail_validation, dict) or not _tail_validation_record_passed_8616(
        raw_tail_validation
    ):
        return False
    return not assess_final_generated_c_text(payload).reject_as_decompiled


@cython.ccall
def _artifact_from_record_8616(record: object) -> DirectRequestCacheArtifact8616 | None:
    """Decode only a record whose complete acceptance proof remains valid."""
    diagnostic_output: object
    failure_snapshot: object
    fields: object
    raw_segment_evidence: object
    if operator.ne(record.get("schema"), DIRECT_REQUEST_CACHE_SCHEMA_8616) or record.get("status") != "ok":
        return None
    fields = _validated_scalar_fields_8616(record)
    if fields is None:
        return None
    (
        function_addr,
        function_name,
        arch_name,
        entry_point,
        runtime_header,
        startup_diagnostic_lines,
        payload,
        validated_hash,
        gcc_hash,
        raw_tail_validation,
    ) = fields
    if not _payload_proof_ok_8616(payload, validated_hash, gcc_hash, raw_tail_validation):
        return None
    # The acceptance proof above already verified the tail-validation record is a
    # dict; narrow it locally for the immutable artifact contract.
    if not isinstance(raw_tail_validation, dict):
        return None
    failure_snapshot = FailureFamilySnapshot.from_record(record.get("failure_family_snapshot"))
    if failure_snapshot is None:
        return None
    diagnostic_output = record.get("diagnostic_output")
    if diagnostic_output is not None and not isinstance(diagnostic_output, str):
        return None
    if os.environ.get("INERTIA_ENABLE_TYPED_SWITCH_AST_ARTIFACTS") == "1" and not diagnostic_output:
        return None
    raw_segment_evidence = record.get("segment_program_function_evidence")
    if raw_segment_evidence is not None and not isinstance(raw_segment_evidence, dict):
        return None
    return DirectRequestCacheArtifact8616(
        function_addr=function_addr,
        function_name=function_name,
        arch_name=arch_name,
        entry_point=entry_point,
        runtime_header=runtime_header,
        startup_diagnostic_lines=tuple(startup_diagnostic_lines),
        payload=payload,
        tail_validation=copy.deepcopy(raw_tail_validation),
        elapsed=_optional_float(record, "elapsed"),
        block_count=_optional_int(record, "block_count"),
        byte_count=_optional_int(record, "byte_count"),
        validated_payload_hash=validated_hash,
        gcc_checked_payload_hash=gcc_hash,
        failure_family_snapshot=failure_snapshot,
        diagnostic_output=diagnostic_output or "",
        segment_program_function_evidence_record=copy.deepcopy(raw_segment_evidence),
    )


@cython.ccall
def load_direct_request_cache_8616(
    inputs: DirectRequestCacheInputs8616,
    *,
    enabled: cython.bint,
) -> DirectRequestCacheLookup8616:
    """Load one accepted artifact or return an explicit typed miss/refusal."""
    artifact: object
    key: object
    record: object
    key = build_direct_request_cache_key_8616(inputs)
    if key is None:
        return DirectRequestCacheLookup8616(
            DirectRequestCacheVerdict8616.DISABLED,
            DirectRequestCacheReason8616.NO_KEY,
            None,
            None,
        )
    if not enabled:
        return DirectRequestCacheLookup8616(
            DirectRequestCacheVerdict8616.DISABLED,
            DirectRequestCacheReason8616.DIAGNOSTICS,
            key,
            None,
        )
    record = _load_cache_json(DIRECT_REQUEST_CACHE_NAMESPACE_8616, key)
    if record is None:
        return DirectRequestCacheLookup8616(
            DirectRequestCacheVerdict8616.MISS,
            DirectRequestCacheReason8616.NOT_FOUND,
            key,
            None,
        )
    artifact = _artifact_from_record_8616(record)
    if artifact is None:
        return DirectRequestCacheLookup8616(
            DirectRequestCacheVerdict8616.REFUSED,
            DirectRequestCacheReason8616.ACCEPTANCE_PROOF,
            key,
            None,
        )
    return DirectRequestCacheLookup8616(
        DirectRequestCacheVerdict8616.HIT,
        DirectRequestCacheReason8616.VALIDATED,
        key,
        artifact,
    )


@cython.ccall
def store_direct_request_cache_8616(
    lookup: DirectRequestCacheLookup8616,
    artifact: DirectRequestCacheArtifact8616,
) -> cython.bint:
    """Persist one artifact only after revalidating its acceptance record."""
    if lookup.key is None or lookup.verdict is DirectRequestCacheVerdict8616.DISABLED:
        return False
    record: dict[str, object] = {
        "schema": DIRECT_REQUEST_CACHE_SCHEMA_8616,
        "status": "ok",
        "function_addr": artifact.function_addr,
        "function_name": artifact.function_name,
        "arch_name": artifact.arch_name,
        "entry_point": artifact.entry_point,
        "runtime_header": artifact.runtime_header,
        "startup_diagnostic_lines": list(artifact.startup_diagnostic_lines),
        "payload": artifact.payload,
        "tail_validation": artifact.tail_validation,
        "elapsed": artifact.elapsed,
        "block_count": artifact.block_count,
        "byte_count": artifact.byte_count,
        "validated_payload_hash": artifact.validated_payload_hash,
        "gcc_checked_payload_hash": artifact.gcc_checked_payload_hash,
        "failure_family_snapshot": artifact.failure_family_snapshot.to_record(),
        "diagnostic_output": artifact.diagnostic_output or None,
        "segment_program_function_evidence": (
            None
            if artifact.segment_program_function_evidence_record is None
            else artifact.segment_program_function_evidence_record
        ),
    }
    if _artifact_from_record_8616(record) is None:
        return False
    try:
        with _cache_key_lock(DIRECT_REQUEST_CACHE_NAMESPACE_8616, lookup.key):
            _store_cache_json(DIRECT_REQUEST_CACHE_NAMESPACE_8616, lookup.key, record)
            stored = _load_cache_json(DIRECT_REQUEST_CACHE_NAMESPACE_8616, lookup.key)
    except (OSError, TimeoutError):
        return False
    return bool(stored == record)
