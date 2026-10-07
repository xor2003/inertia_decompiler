"""Tests for the decompiler's early CPython JIT restart.

Layer: CLI tests.
Responsibility: prove the wrapper enables JIT before importing the application.
"""

from __future__ import annotations

import os

import decompile


def test_decompile_reexec_enables_jit_and_deterministic_hashing(monkeypatch) -> None:
    """A non-JIT process restarts itself with both startup-only settings."""
    captured: dict[str, object] = {}

    def fake_execvpe(executable: str, argv: list[str], env: dict[str, str]) -> None:
        captured.update(executable=executable, argv=argv, env=env)

    monkeypatch.delenv("PYTHON_JIT", raising=False)
    monkeypatch.setattr(os, "execvpe", fake_execvpe)

    decompile._ensure_python_jit()

    env = captured["env"]
    assert isinstance(env, dict)
    assert env["PYTHON_JIT"] == "1"
    assert env["PYTHONHASHSEED"] == "0"


def test_decompile_does_not_reexec_when_jit_is_requested(monkeypatch) -> None:
    """The environment marker prevents a restart loop."""
    monkeypatch.setenv("PYTHON_JIT", "1")

    def unexpected_execvpe(*_args: object) -> None:
        raise AssertionError("unexpected JIT restart")

    monkeypatch.setattr(os, "execvpe", unexpected_execvpe)
    decompile._ensure_python_jit()
