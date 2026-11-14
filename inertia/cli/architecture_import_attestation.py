# cython: language_level=3, infer_types=True
"""Content-addressed runtime import-guard attestations.

Layer: CLI/fallback/reporting.
Responsibility: cache exact per-file import-ownership verdicts for startup guards.
"""

from __future__ import annotations
import typing
import cython

import hashlib
import json
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from tools.dev import check_decompiler_architecture as architecture_check
from tools.dev.check_decompiler_architecture import ArchitectureViolation
import dataclasses
import operator
import builtins

__all__ = [
    "RuntimeImportGuardEvaluation",
    "architecture_guard_cache_is_clean",
    "architecture_guard_checker_fingerprint",
    "architecture_startup_source_fingerprint",
    "evaluate_runtime_import_snapshot",
    "load_startup_architecture_verdict",
    "store_architecture_guard_cache",
    "store_startup_architecture_verdict",
]

ARCHITECTURE_GUARD_CACHE_SCHEMA: cython.longlong = 2
STARTUP_ARCHITECTURE_CACHE_SCHEMA: cython.longlong = 1


class _RuntimeImportGuardRule(Enum):
    """One authoritative import-ownership rule applied to a source file."""

    POSTPROCESS = "postprocess"
    SEMANTIC_LAYER = "semantic_layer"
    CLI = "cli"


@dataclasses.dataclass(frozen=True, )
class _RuntimeImportFileAttestation:
    """Content-addressed runtime import-guard verdict for one source file."""

    digest: object
    violations: object


@dataclasses.dataclass(frozen=True, )
class RuntimeImportGuardEvaluation:
    """Closed per-file runtime import-guard evaluation for one source snapshot."""

    files: object
    violations: object


@cython.ccall
def architecture_guard_cache_is_clean(cache_path: Path, fingerprint: object) -> cython.bint:
    """Return whether the persistent attestation matches current source bytes."""
    try:
        payload: object = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return (
        isinstance(payload, dict)
        and operator.eq(payload.get("schema"), ARCHITECTURE_GUARD_CACHE_SCHEMA)
        and operator.eq(payload.get("fingerprint"), fingerprint)
        and payload.get("clean") is True
    )


def _runtime_import_rule_paths(
    root: Path,
    cli_path: Path,
) -> dict[Path, tuple[_RuntimeImportGuardRule, ...]]:
    """Return every guarded file with its authoritative import rules."""
    path: object
    mutable: dict[Path, set[_RuntimeImportGuardRule]] = {}
    for path in architecture_check._postprocess_import_paths(root):
        mutable.setdefault(path, set()).add(_RuntimeImportGuardRule.POSTPROCESS)
    for path in architecture_check._semantic_layer_no_postprocess_import_paths(root):
        mutable.setdefault(path, set()).add(_RuntimeImportGuardRule.SEMANTIC_LAYER)
    mutable.setdefault(cli_path, set()).add(_RuntimeImportGuardRule.CLI)
    return {
        path: tuple(sorted(rules, key=lambda rule: rule.value))
        for path, rules in builtins.iter(sorted(tuple(mutable.items()), key=lambda item: str(item[0])))
    }


@cython.ccall
def _runtime_import_source_digest(path: Path) -> object:
    """Return a stable digest for one guarded source path."""
    try:
        data = path.read_bytes()
    except OSError:
        data = b"<missing>"
    return hashlib.sha256(data).hexdigest()


@cython.ccall
def architecture_guard_checker_fingerprint(runtime_guard_path: Path) -> object:
    """Hash rule and cache implementations that determine stored verdicts."""
    path: object
    digest = hashlib.sha256()
    for path in sorted(
        (
            Path(architecture_check.__file__).resolve(),
            runtime_guard_path.resolve(),
            Path(__file__).resolve(),
        )
    ):
        digest.update(str(path).encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


@cython.ccall
def architecture_startup_source_fingerprint(root: Path, repo_root: Path) -> object:
    """Hash every source that can change default startup-check conclusions."""
    path: object
    paths = {
        *architecture_check._owned_contract_source_paths(root),
        *(repo_root / "inertia" / "cli").rglob("*.py"),
        repo_root / "decompile.py",
        Path(architecture_check.__file__).resolve(),
    }
    digest = hashlib.sha256()
    for path in sorted(paths):
        try:
            data = path.read_bytes()
        except OSError:
            data = b"<missing>"
        digest.update(str(path.resolve()).encode("utf-8"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return digest.hexdigest()


@cython.ccall
def _decode_cached_violation(value: object) -> ArchitectureViolation | None:
    """Decode one structured violation from the untrusted JSON cache boundary."""
    detail: object
    path: object
    rule: object
    if not isinstance(value, dict):
        return None
    path = value.get("path")
    rule = value.get("rule")
    detail = value.get("detail")
    if not isinstance(path, str) or not isinstance(rule, str) or not isinstance(detail, str):
        return None
    return ArchitectureViolation(path=path, rule=rule, detail=detail)


def load_startup_architecture_verdict(
    cache_path: Path,
    fingerprint: object,
) -> object:
    """Load one exact startup verdict, returning ``None`` on stale evidence."""
    try:
        payload: object = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or operator.ne(payload.get("schema"), STARTUP_ARCHITECTURE_CACHE_SCHEMA):
        return None
    if operator.ne(payload.get("fingerprint"), fingerprint) or not isinstance(payload.get("violations"), list):
        return None
    violations = tuple(_decode_cached_violation(value) for value in iter(payload["violations"]))
    return None if any(value is None for value in iter(violations)) else tuple(
        value for value in iter(violations) if value is not None
    )


@cython.ccall
def store_startup_architecture_verdict(
    cache_path: Path,
    fingerprint: object,
    violations: object,
) -> None:
    """Atomically persist one complete content-addressed startup verdict."""
    temporary = cache_path.with_name(f".{cache_path.name}.{os.getpid()}.tmp")
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(
            json.dumps(
                {
                    "schema": STARTUP_ARCHITECTURE_CACHE_SCHEMA,
                    "fingerprint": fingerprint,
                    "violations": [
                        {"path": item.path, "rule": item.rule, "detail": item.detail}
                        for item in iter(violations)
                    ],
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        temporary.replace(cache_path)
    except OSError:
        temporary.unlink(missing_ok=True)


@cython.ccall
def _load_runtime_import_attestations(
    cache_path: Path,
    root: Path,
    cli_path: Path,
    checker_fingerprint: object,
) -> object:
    """Load compatible per-file verdicts from the persistent guard cache."""
    attestation: object
    files: object
    encoded: object
    path: object
    try:
        payload: object = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    if not _compatible_guard_payload(payload, root, cli_path, checker_fingerprint):
        return {}
    files = payload.get("files")
    if not isinstance(files, dict):
        return {}
    attestations: dict[str, _RuntimeImportFileAttestation] = {}
    for path, encoded in files.items():
        if not isinstance(path, str) or not isinstance(encoded, dict):
            continue
        attestation = _decode_cached_file_attestation(encoded)
        if attestation is not None:
            attestations[path] = attestation
    return attestations


@cython.ccall
def _compatible_guard_payload(
    payload: object,
    root: Path,
    cli_path: Path,
    checker_fingerprint: object,
) -> cython.bint:
    """Return True when the persisted guard cache matches this environment."""
    return (
        operator.eq(payload.get("schema"), ARCHITECTURE_GUARD_CACHE_SCHEMA)
        and operator.eq(payload.get("checker_fingerprint"), checker_fingerprint)
        and operator.eq(payload.get("root"), str(root.resolve()))
        and operator.eq(payload.get("cli"), str(cli_path.resolve()))
    )


@cython.ccall
def _decode_cached_file_attestation(encoded: object) -> _RuntimeImportFileAttestation | None:
    """Decode one cached per-file attestation, or None when malformed."""
    digest: object
    encoded_violations: object
    violation: object
    encoded_violation: object
    digest = encoded.get("digest")
    encoded_violations = encoded.get("violations")
    if not isinstance(digest, str) or not isinstance(encoded_violations, list):
        return None
    violations: list[ArchitectureViolation] = []
    for encoded_violation in encoded_violations:
        violation = _decode_cached_violation(encoded_violation)
        if violation is None:
            return None
        violations.append(violation)
    return _RuntimeImportFileAttestation(
        digest=digest,
        violations=tuple(violations),
    )


@cython.ccall
def _evaluate_runtime_import_path(
    root: Path,
    path: Path,
    rules: object,
) -> tuple[ArchitectureViolation, ...]:
    """Evaluate all authoritative import rules assigned to one source file."""
    rule: object
    violations: list[ArchitectureViolation] = []
    for rule in rules:
        if rule is _RuntimeImportGuardRule.POSTPROCESS:
            violations.extend(architecture_check._check_postprocess_file_imports(root, path))
        elif rule is _RuntimeImportGuardRule.SEMANTIC_LAYER:
            violations.extend(
                architecture_check._check_semantic_layer_file_does_not_import_postprocess(
                    root,
                    path,
                )
            )
        else:
            violations.extend(architecture_check._check_cli_imports(path))
    return tuple(violations)


@cython.ccall
def evaluate_runtime_import_snapshot(
    cache_path: Path,
    root: Path,
    cli_path: Path,
    checker_fingerprint: object,
) -> RuntimeImportGuardEvaluation:
    """Reuse exact file verdicts and evaluate only changed guarded sources."""
    attestation: object
    path: object
    rules: object
    cached = _load_runtime_import_attestations(
        cache_path,
        root,
        cli_path,
        checker_fingerprint,
    )
    files: list[tuple[str, _RuntimeImportFileAttestation]] = []
    violations: list[ArchitectureViolation] = []
    for path, rules in _runtime_import_rule_paths(root, cli_path).items():
        source_path = str(path.resolve())
        digest = _runtime_import_source_digest(path)
        attestation = cached.get(source_path)
        if attestation is None or operator.ne(attestation.digest, digest):
            attestation = _RuntimeImportFileAttestation(
                digest=digest,
                violations=_evaluate_runtime_import_path(root, path, rules),
            )
        files.append((source_path, attestation))
        violations.extend(attestation.violations)
    return RuntimeImportGuardEvaluation(
        files=tuple(files),
        violations=tuple(violations),
    )


@cython.ccall
def store_architecture_guard_cache(
    cache_path: Path,
    fingerprint: object,
    checker_fingerprint: object,
    root: Path,
    cli_path: Path,
    evaluation: RuntimeImportGuardEvaluation,
) -> None:
    """Atomically persist content-addressed per-file import verdicts."""
    temporary = cache_path.with_name(f".{cache_path.name}.{os.getpid()}.tmp")
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(
            json.dumps(
                {
                    "schema": ARCHITECTURE_GUARD_CACHE_SCHEMA,
                    "fingerprint": fingerprint,
                    "checker_fingerprint": checker_fingerprint,
                    "root": str(root.resolve()),
                    "cli": str(cli_path.resolve()),
                    "clean": not evaluation.violations,
                    "files": {
                        source_path: {
                            "digest": attestation.digest,
                            "violations": [
                                {
                                    "path": violation.path,
                                    "rule": violation.rule,
                                    "detail": violation.detail,
                                }
                                for violation in iter(attestation.violations)
                            ],
                        }
                        for source_path, attestation in iter(evaluation.files)
                    },
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        temporary.replace(cache_path)
    except OSError:
        temporary.unlink(missing_ok=True)
