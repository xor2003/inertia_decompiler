#!/usr/bin/env python3
"""Entrypoint for the x86-16 decompiler CLI.

Layer: CLI/fallback/reporting.
Responsibility: enter the CLI only after the runtime architecture guard.
"""

from __future__ import annotations

import contextlib
import logging
import os
import sys
from pathlib import Path
from types import ModuleType

_ROOT = Path(__file__).resolve().parent
_PROJECT_VENV_PYTHONS = (_ROOT / ".venv" / "bin" / "python",)


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


_DECOMPILE_DISABLE_CLI_LAZY_IMPORTS: bool = _env_truthy("INERTIA_DISABLE_CLI_LAZY_IMPORTS")


def _ensure_project_venv() -> None:
    if os.environ.get("INERTIA_DECOMPILE_VENV") == "1":
        return
    for candidate in _PROJECT_VENV_PYTHONS:
        if not candidate.exists():
            continue
        try:
            if candidate.samefile(sys.executable):
                return
        except FileNotFoundError:
            continue
        env = os.environ.copy()
        env["INERTIA_DECOMPILE_VENV"] = "1"
        env["PYTHONHASHSEED"] = "0"
        env["VIRTUAL_ENV"] = str(candidate.parent.parent)
        current_path = env.get("PATH", "")
        env["PATH"] = f"{candidate.parent}:{current_path}" if current_path else str(candidate.parent)
        os.execvpe(str(candidate), [str(candidate), str(Path(__file__).resolve()), *sys.argv[1:]], env)


def _ensure_deterministic_hash_seed() -> None:
    """Restart the CLI before decompiler imports when Python hash order is unstable."""
    if os.environ.get("PYTHONHASHSEED") == "0":
        return
    env = os.environ.copy()
    env["PYTHONHASHSEED"] = "0"
    executable = sys.executable
    os.execvpe(executable, [executable, str(Path(__file__).resolve()), *sys.argv[1:]], env)


def _ensure_python_jit() -> None:
    """Restart before application imports with the CPython JIT enabled."""
    if os.environ.get("PYTHON_JIT") == "1":
        return
    env = os.environ.copy()
    env["PYTHON_JIT"] = "1"
    env["PYTHONHASHSEED"] = "0"
    executable = sys.executable
    os.execvpe(executable, [executable, str(Path(__file__).resolve()), *sys.argv[1:]], env)


def _install_early_log_levels() -> None:
    for logger_name, level in (
        ("angr.state_plugins.unicorn_engine", logging.CRITICAL),
        ("angr.analyses.calling_convention.calling_convention", logging.CRITICAL),
        ("angr.analyses.calling_convention.fact_collector.SimEngineFactCollectorVEX", logging.CRITICAL),
        ("angr.analyses.decompiler.structured_codegen.c", logging.CRITICAL),
        ("angr.analyses.decompiler.decompiler", logging.ERROR),
        ("angr.project", logging.ERROR),
        ("angr.analyses.cfg.cfg_fast", logging.ERROR),
        ("angr.analyses.cfg.cfg_base", logging.ERROR),
        ("angr.analyses.fcp.fcp.SimEngineFCPVEX", logging.CRITICAL),
    ):
        logging.getLogger(logger_name).setLevel(level)


def _enable_line_buffered_stdio() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            with contextlib.suppress(Exception):
                reconfigure(line_buffering=True)


def _install_msgspec_shim_if_missing() -> None:
    try:
        import msgspec  # noqa: F401
    except ModuleNotFoundError:
        try:  # noqa: SIM105
            # Explicit import keeps fallback deterministic for environments where
            # sitecustomize.py is not auto-discovered (e.g. PyPy packaging paths).
            import sitecustomize  # noqa: F401
        except Exception:
            pass


_install_msgspec_shim_if_missing()


def _configure_python_recursion_limit() -> None:
    raw = os.environ.get("INERTIA_PYTHON_RECURSION_LIMIT", "").strip()
    target = 12000
    if raw:
        try:
            target = max(2000, int(raw))
        except Exception:
            target = 12000
    current = sys.getrecursionlimit()
    if target > current:
        sys.setrecursionlimit(target)


# Only trampoline into the project venv when invoked as the entrypoint script.
# Tests import this module for helper access and must not exec-replace the process.
if __name__ == "__main__":
    _ensure_project_venv()
    _ensure_python_jit()
    _ensure_deterministic_hash_seed()
_install_early_log_levels()
_enable_line_buffered_stdio()
_configure_python_recursion_limit()

from inertia.cli.architecture_runtime_guard import (  # noqa: E402
    DecompilerArchitectureGuardError,
    assert_decompiler_architecture_clean,
)

try:
    assert_decompiler_architecture_clean()
except DecompilerArchitectureGuardError as ex:
    print(str(ex), file=sys.stderr)
    raise SystemExit(3) from ex

_CLI_MODULE: ModuleType | None = None


def _ensure_cli() -> ModuleType:
    global _CLI_MODULE
    if _CLI_MODULE is None:
        _CLI_MODULE = __import__("inertia.cli.cli", fromlist=["*"])
        if _DECOMPILE_DISABLE_CLI_LAZY_IMPORTS:
            # Dynamic boundary: third-party CLI plugin module can vary by package layout.
            for _name in vars(_CLI_MODULE):
                if _name.startswith("__"):
                    continue
                if _name not in globals():
                    globals()[_name] = _CLI_MODULE.__dict__[_name]
            # Dynamic boundary: third-party plugin exports may be runtime-computed.
            for _name in _CLI_MODULE.__dict__.get("__all__", ()):
                if _name.startswith("__"):
                    continue
                if _name not in globals():
                    globals()[_name] = _CLI_MODULE.__dict__[_name]
    return _CLI_MODULE


def __getattr__(name: str) -> object:
    try:
        _plugin = _ensure_cli()
        # Dynamic boundary: third-party plugin exports are runtime-resolved here.
        return getattr(_plugin, name)
    except AttributeError as ex:
        raise AttributeError(name) from ex


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(dir(_ensure_cli())))


class _EntrypointCompatModule(ModuleType):
    """Mirror legacy facade assignments into the owning CLI proxy modules."""

    def __setattr__(self, name: str, value: object) -> None:
        """Forward external monkeypatches while retaining the facade attribute."""
        ModuleType.__setattr__(self, name, value)
        if name.startswith("__"):
            return
        setattr(_ensure_cli(), name, value)


sys.modules[__name__].__class__ = _EntrypointCompatModule


def _run_entrypoint() -> int:
    """Use lightweight validated reuse before loading the full CLI stack."""
    from inertia.cli.direct_request_fast_path import try_direct_request_fast_path_8616

    fast_status = try_direct_request_fast_path_8616()
    if fast_status is not None:
        return fast_status
    cli_module = _ensure_cli()
    return int(cli_module.main())


if __name__ == "__main__":
    try:
        _entrypoint_status = _run_entrypoint()
    finally:
        if _CLI_MODULE is not None:
            from inertia.cli.telemetry import emit_compact_summary

            emit_compact_summary()
    raise SystemExit(_entrypoint_status)
