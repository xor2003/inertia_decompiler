"""Content-addressed runtime import-guard attestations.

Layer: CLI/fallback/reporting.
Responsibility: cache exact per-file import-ownership verdicts for startup guards.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from scripts import check_decompiler_architecture as architecture_check
from scripts.check_decompiler_architecture import ArchitectureViolation

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

ARCHITECTURE_GUARD_CACHE_SCHEMA: int = 2
STARTUP_ARCHITECTURE_CACHE_SCHEMA: int = 1


class _RuntimeImportGuardRule(Enum):
    """One authoritative import-ownership rule applied to a source file."""

    POSTPROCESS = "postprocess"
    SEMANTIC_LAYER = "semantic_layer"
    CLI = "cli"


@dataclass(frozen=True, slots=True)
class _RuntimeImportFileAttestation:
    """Content-addressed runtime import-guard verdict for one source file."""

    digest: str
    violations: tuple[ArchitectureViolation, ...]


@dataclass(frozen=True, slots=True)
class RuntimeImportGuardEvaluation:
    """Closed per-file runtime import-guard evaluation for one source snapshot."""

    files: tuple[tuple[str, _RuntimeImportFileAttestation], ...]
    violations: tuple[ArchitectureViolation, ...]


def architecture_guard_cache_is_clean(cache_path: Path, fingerprint: str) -> bool:
    """Return whether the persistent attestation matches current source bytes."""
    try:
        payload: object = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return (
        isinstance(payload, dict)
        and payload.get("schema") == ARCHITECTURE_GUARD_CACHE_SCHEMA
        and payload.get("fingerprint") == fingerprint
        and payload.get("clean") is True
    )


def _runtime_import_rule_paths(
    root: Path,
    cli_path: Path,
) -> dict[Path, tuple[_RuntimeImportGuardRule, ...]]:
    """Return every guarded file with its authoritative import rules."""
    mutable: dict[Path, set[_RuntimeImportGuardRule]] = {}
    for path in architecture_check._postprocess_import_paths(root):
        mutable.setdefault(path, set()).add(_RuntimeImportGuardRule.POSTPROCESS)
    for path in architecture_check._semantic_layer_no_postprocess_import_paths(root):
        mutable.setdefault(path, set()).add(_RuntimeImportGuardRule.SEMANTIC_LAYER)
    mutable.setdefault(cli_path, set()).add(_RuntimeImportGuardRule.CLI)
    return {
        path: tuple(sorted(rules, key=lambda rule: rule.value))
        for path, rules in sorted(mutable.items(), key=lambda item: str(item[0]))
    }


def _runtime_import_source_digest(path: Path) -> str:
    """Return a stable digest for one guarded source path."""
    try:
        data = path.read_bytes()
    except OSError:
        data = b"<missing>"
    return hashlib.sha256(data).hexdigest()


def architecture_guard_checker_fingerprint(runtime_guard_path: Path) -> str:
    """Hash rule and cache implementations that determine stored verdicts."""
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


def architecture_startup_source_fingerprint(root: Path, repo_root: Path) -> str:
    """Hash every source that can change default startup-check conclusions."""
    paths = {
        *root.rglob("*.py"),
        *(repo_root / "inertia_decompiler").rglob("*.py"),
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


def _decode_cached_violation(value: object) -> ArchitectureViolation | None:
    """Decode one structured violation from the untrusted JSON cache boundary."""
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
    fingerprint: str,
) -> tuple[ArchitectureViolation, ...] | None:
    """Load one exact startup verdict, returning ``None`` on stale evidence."""
    try:
        payload: object = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or payload.get("schema") != STARTUP_ARCHITECTURE_CACHE_SCHEMA:
        return None
    if payload.get("fingerprint") != fingerprint or not isinstance(payload.get("violations"), list):
        return None
    violations = tuple(_decode_cached_violation(value) for value in payload["violations"])
    return None if any(value is None for value in violations) else tuple(
        value for value in violations if value is not None
    )


def store_startup_architecture_verdict(
    cache_path: Path,
    fingerprint: str,
    violations: tuple[ArchitectureViolation, ...],
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
                        for item in violations
                    ],
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        temporary.replace(cache_path)
    except OSError:
        temporary.unlink(missing_ok=True)


def _load_runtime_import_attestations(
    cache_path: Path,
    root: Path,
    cli_path: Path,
    checker_fingerprint: str,
) -> dict[str, _RuntimeImportFileAttestation]:
    """Load compatible per-file verdicts from the persistent guard cache."""
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


def _compatible_guard_payload(
    payload: dict[str, object],
    root: Path,
    cli_path: Path,
    checker_fingerprint: str,
) -> bool:
    """Return True when the persisted guard cache matches this environment."""
    return (
        payload.get("schema") == ARCHITECTURE_GUARD_CACHE_SCHEMA
        and payload.get("checker_fingerprint") == checker_fingerprint
        and payload.get("root") == str(root.resolve())
        and payload.get("cli") == str(cli_path.resolve())
    )


def _decode_cached_file_attestation(encoded: dict[object, object]) -> _RuntimeImportFileAttestation | None:
    """Decode one cached per-file attestation, or None when malformed."""
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


def _evaluate_runtime_import_path(
    root: Path,
    path: Path,
    rules: tuple[_RuntimeImportGuardRule, ...],
) -> tuple[ArchitectureViolation, ...]:
    """Evaluate all authoritative import rules assigned to one source file."""
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


def evaluate_runtime_import_snapshot(
    cache_path: Path,
    root: Path,
    cli_path: Path,
    checker_fingerprint: str,
) -> RuntimeImportGuardEvaluation:
    """Reuse exact file verdicts and evaluate only changed guarded sources."""
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
        if attestation is None or attestation.digest != digest:
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


def store_architecture_guard_cache(
    cache_path: Path,
    fingerprint: str,
    checker_fingerprint: str,
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
                                for violation in attestation.violations
                            ],
                        }
                        for source_path, attestation in evaluation.files
                    },
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        temporary.replace(cache_path)
    except OSError:
        temporary.unlink(missing_ok=True)
