"""Debugger launch coordinates and historical entry controls."""

from __future__ import annotations

import importlib
from pathlib import Path
from unittest.mock import Mock

from tools.debugger import cli


def test_root_import_is_qualified_launcher() -> None:
    assert importlib.import_module("debugger") is cli


def test_checkout_workspace_does_not_follow_tool_directory() -> None:
    assert Path(__file__).resolve().parents[3] == cli.WORKSPACE_PATH
    assert cli.PROJECT_VENV_PYTHON == cli.WORKSPACE_PATH / ".venv/bin/python"


def test_venv_reexecution_uses_package_command(monkeypatch, tmp_path) -> None:
    interpreter = tmp_path / "python"
    interpreter.touch()
    execute = Mock()
    monkeypatch.delenv("INERTIA_DEBUGGER_VENV", raising=False)
    monkeypatch.setattr(cli, "PROJECT_VENV_PYTHON", interpreter)
    monkeypatch.setattr(cli.sys, "argv", ["tools/debugger/cli/py.py", "--help"])
    monkeypatch.setattr(cli.os, "execvpe", execute)
    cli.ensure_project_venv()
    executable, arguments, environment = execute.call_args.args
    assert executable == str(interpreter)
    assert arguments == [str(interpreter), "-m", "tools.debugger.cli", "--help"]
    assert environment["INERTIA_DEBUGGER_VENV"] == "1"


def test_angr_server_keeps_runtime_owner_and_workspace(monkeypatch) -> None:
    process = Mock()
    spawn = Mock(return_value=process)
    monkeypatch.setattr(cli.subprocess, "Popen", spawn)
    server = cli.start_angr_gdb_server("GAME.EXE", 1234, "127.0.0.1")
    arguments = spawn.call_args.args[0]
    assert arguments[:3] == [cli.sys.executable, "-m", "inertia.cli.debug_dos"]
    assert spawn.call_args.kwargs["cwd"] == str(cli.WORKSPACE_PATH)
    assert server.process is process
    assert server.port == 1234
