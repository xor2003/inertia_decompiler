from __future__ import annotations

import pytest

from inertia.frontend.x86_16.exception import EXCEPTION, EXCEPTION_WITH, EXP_DE, EXP_GP


def test_exception_helper_returns_when_condition_is_false(capsys: pytest.CaptureFixture[str]) -> None:
    EXCEPTION(EXP_DE, False)

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_exception_helper_warns_and_raises_exception_number(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(Exception) as exc_info:
        EXCEPTION(EXP_GP, True)

    assert exc_info.value.args == (EXP_GP,)
    assert "WARN: Exception interrupt 13 (True)" in capsys.readouterr().out


def test_exception_with_runs_callback_before_raising(capsys: pytest.CaptureFixture[str]) -> None:
    calls: list[str] = []

    with pytest.raises(Exception) as exc_info:
        EXCEPTION_WITH(EXP_DE, "bad-divide", lambda: calls.append("callback"))

    assert calls == ["callback"]
    assert exc_info.value.args == (EXP_DE,)
    assert "WARN: Exception interrupt 0 (bad-divide)" in capsys.readouterr().out
