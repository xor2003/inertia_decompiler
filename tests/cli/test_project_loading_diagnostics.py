"""Project-loading diagnostics must not corrupt generated C on stdout."""

import pytest

from inertia.cli.cli_output import _print_diagnostic_text, _timestamped_print
from inertia.cli.project_loading import _debug_print
from inertia.cli.work_items import _diagnostic_print


@pytest.mark.parametrize("under_pytest", [False, True])
@pytest.mark.parametrize("brief", [False, True])
@pytest.mark.parametrize("emit", [_debug_print, _diagnostic_print, _timestamped_print, _print_diagnostic_text])
def test_project_debug_output_always_uses_stderr(monkeypatch, capsys, under_pytest, brief, emit):
    if under_pytest:
        monkeypatch.setenv("PYTEST_CURRENT_TEST", "generated_c (call)")
    else:
        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.setenv("INERTIA_BRIEF", "1" if brief else "0")
    emit("[dbg] project diagnostic")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "project diagnostic" in captured.err


@pytest.mark.parametrize("brief", [False, True])
def test_timestamped_print_keeps_generated_c_on_stdout(monkeypatch, capsys, brief):
    monkeypatch.setenv("INERTIA_BRIEF", "1" if brief else "0")
    _timestamped_print("int f(void) { return 0; }")
    captured = capsys.readouterr()
    assert captured.out == "int f(void) { return 0; }\n"
    assert captured.err == ""
