"""Runtime startup guard for decompiler architecture constraints.

Layer: CLI/fallback/reporting.
Responsibility: owns startup enforcement of architecture guard checks.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterable
from pathlib import Path

from inertia.cli import architecture_import_attestation
from tools.dev import check_decompiler_architecture as architecture_check
from tools.dev.check_decompiler_architecture import ArchitectureViolation

__all__ = [
    "ARCHITECTURE_GUARD_VERIFIED_PARENT_PID_ENV",
    "DecompilerArchitectureGuardError",
    "assert_decompiler_architecture_clean",
    "cached_decompiler_architecture_import_violations",
    "cached_decompiler_startup_architecture_violations",
    "format_decompiler_architecture_guard_error",
]

ARCHITECTURE_GUARD_VERIFIED_PARENT_PID_ENV: str = "INERTIA_ARCH_GUARD_VERIFIED_PARENT_PID"
_ARCHITECTURE_GUARD_CACHE_PATH: Path = (
    architecture_check.REPO_ROOT
    / ".inertia_decomp_cache"
    / "architecture_import_guard.json"
)
_ARCHITECTURE_STARTUP_CACHE_PATH: Path = (
    architecture_check.REPO_ROOT
    / ".inertia_decomp_cache"
    / "architecture_startup_guard.json"
)
_ARCHITECTURE_GUARD_VERIFIED_PROCESS_PID: int | None = None


class DecompilerArchitectureGuardError(RuntimeError):
    """Raised when the runtime decompiler architecture guard fails."""


def format_decompiler_architecture_guard_error(violations: Iterable[ArchitectureViolation]) -> str:
    """Format a clear startup error for wrong-layer decompiler changes."""
    lines = [
        "Decompiler architecture guard failed.",
        "Wrong-layer imports, missing guard documentation, or unsafe agent project guide settings were detected before decompiler startup.",
        "Move the work to the owning layer, or update the architecture allowlist with a documented migration reason.",
        "Run: make architecture-check PYTHON=./.venv/bin/python",
        "",
        "Violations:",
    ]
    lines.extend(f"- {violation.format()}" for violation in violations)
    return "\n".join(lines)


def _runtime_import_violations(
    root: Path,
    cli_path: Path,
) -> tuple[ArchitectureViolation, ...]:
    """Run only import ownership checks required on every CLI startup."""
    return (
        *architecture_check._check_postprocess_imports(root),
        *architecture_check._check_semantic_layers_do_not_import_postprocess(root),
        *architecture_check._check_cli_imports(cli_path),
    )


_RUNTIME_IMPORT_VIOLATIONS_IMPL = _runtime_import_violations


def _architecture_guard_source_fingerprint(
    root: Path,
    cli_path: Path,
) -> str:
    """Hash every source that can change runtime import-guard conclusions."""
    paths = {
        *architecture_check._owned_contract_source_paths(root),
        cli_path,
        Path(architecture_check.__file__).resolve(),
        Path(architecture_import_attestation.__file__).resolve(),
        Path(__file__).resolve(),
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


def _architecture_guard_cache_is_clean(fingerprint: str) -> bool:
    """Return whether the persistent attestation matches current source bytes."""
    is_clean: bool = architecture_import_attestation.architecture_guard_cache_is_clean(
        _ARCHITECTURE_GUARD_CACHE_PATH,
        fingerprint,
    )
    return is_clean


def _architecture_guard_checker_fingerprint() -> str:
    """Hash rule and cache implementations that determine stored verdicts."""
    fingerprint: str = architecture_import_attestation.architecture_guard_checker_fingerprint(
        Path(__file__),
    )
    return fingerprint


def cached_decompiler_architecture_import_violations() -> tuple[ArchitectureViolation, ...]:
    """Return default-tree import violations using the persistent attestation."""
    global _ARCHITECTURE_GUARD_VERIFIED_PROCESS_PID
    root_path = architecture_check.X86_16_ROOT
    cli_path = architecture_check.CLI_DECOMPILATION
    process_pid = os.getpid()
    if process_pid == _ARCHITECTURE_GUARD_VERIFIED_PROCESS_PID:
        return ()
    fingerprint = _architecture_guard_source_fingerprint(root_path, cli_path)
    if _architecture_guard_cache_is_clean(fingerprint):
        _ARCHITECTURE_GUARD_VERIFIED_PROCESS_PID = process_pid
        return ()
    checker_fingerprint = _architecture_guard_checker_fingerprint()
    evaluation = architecture_import_attestation.evaluate_runtime_import_snapshot(
        _ARCHITECTURE_GUARD_CACHE_PATH,
        root_path,
        cli_path,
        checker_fingerprint,
    )
    final_fingerprint = _architecture_guard_source_fingerprint(root_path, cli_path)
    if final_fingerprint != fingerprint:
        raise DecompilerArchitectureGuardError(
            "Decompiler source changed while the runtime import guard was running; retry startup."
        )
    architecture_import_attestation.store_architecture_guard_cache(
        _ARCHITECTURE_GUARD_CACHE_PATH,
        fingerprint,
        checker_fingerprint,
        root_path,
        cli_path,
        evaluation,
    )
    if not evaluation.violations:
        _ARCHITECTURE_GUARD_VERIFIED_PROCESS_PID = process_pid
    violations: tuple[ArchitectureViolation, ...] = evaluation.violations
    return violations


def cached_decompiler_startup_architecture_violations() -> tuple[ArchitectureViolation, ...]:
    """Return the exact cached default-tree startup verdict or evaluate it."""
    fingerprint = architecture_import_attestation.architecture_startup_source_fingerprint(
        architecture_check.X86_16_ROOT,
        architecture_check.REPO_ROOT,
    )
    cached: tuple[ArchitectureViolation, ...] | None = (
        architecture_import_attestation.load_startup_architecture_verdict(
            _ARCHITECTURE_STARTUP_CACHE_PATH,
            fingerprint,
        )
    )
    if cached is not None:
        return cached
    import_violations = cached_decompiler_architecture_import_violations()
    violations: tuple[ArchitectureViolation, ...] = architecture_check.check_decompiler_startup_architecture(
        architecture_check.X86_16_ROOT,
        architecture_check.CLI_DECOMPILATION,
        architecture_check.REPO_ROOT,
        prechecked_import_violations=import_violations,
    )
    final_fingerprint = architecture_import_attestation.architecture_startup_source_fingerprint(
        architecture_check.X86_16_ROOT,
        architecture_check.REPO_ROOT,
    )
    if final_fingerprint != fingerprint:
        return (
            ArchitectureViolation(
                path="<startup-architecture-snapshot>",
                rule="startup-architecture-source-race",
                detail="decompiler source changed during startup architecture checking; retry the gate",
            ),
        )
    architecture_import_attestation.store_startup_architecture_verdict(
        _ARCHITECTURE_STARTUP_CACHE_PATH,
        fingerprint,
        violations,
    )
    return violations


def assert_decompiler_architecture_clean() -> None:
    """Stop decompiler startup if runtime import-layer guardrails are violated."""
    root = os.environ.get("INERTIA_ARCH_GUARD_X86_16_ROOT")
    cli = os.environ.get("INERTIA_ARCH_GUARD_CLI")
    repo_root = os.environ.get("INERTIA_ARCH_GUARD_REPO_ROOT")
    verified_parent_pid = os.environ.get(ARCHITECTURE_GUARD_VERIFIED_PARENT_PID_ENV)
    if not (root or cli or repo_root) and verified_parent_pid is not None:
        try:
            if int(verified_parent_pid) == os.getppid():
                return
        except ValueError:
            pass
    root_path = Path(root) if root else architecture_check.X86_16_ROOT
    cli_path = Path(cli) if cli else architecture_check.CLI_DECOMPILATION
    cache_allowed = (
        not (root or cli or repo_root)
        and _runtime_import_violations is _RUNTIME_IMPORT_VIOLATIONS_IMPL
    )
    violations = (
        cached_decompiler_architecture_import_violations()
        if cache_allowed
        else _runtime_import_violations(root_path, cli_path)
    )
    if violations:
        raise DecompilerArchitectureGuardError(format_decompiler_architecture_guard_error(violations))
