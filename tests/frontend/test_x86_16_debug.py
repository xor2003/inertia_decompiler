from __future__ import annotations

import pytest
import pyvex
import inertia.frontend.x86_16.debug as debug
from inertia.frontend.x86_16.arch_86_16 import Arch86_16


def test_msg_prints_formatted_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    debug.MSG("value=%s", 7)

    captured = capsys.readouterr()
    assert captured.out == "value=7\n"
    assert captured.err == ""


def test_warn_is_nonfatal_and_respects_default_debug_level(capsys: pytest.CaptureFixture[str]) -> None:
    debug.WARN("port %x", 0x3F8)

    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == ""


def test_info_respects_debug_level(capsys: pytest.CaptureFixture[str]) -> None:
    previous_level = debug.debug_level
    try:
        debug.set_debuglv(0)
        debug.INFO(1, "hidden")
        assert capsys.readouterr().out == ""

        debug.set_debuglv(1)
        debug.INFO(1, "visible %s", "line")
        assert "visible line" in capsys.readouterr().out
    finally:
        debug.debug_level = previous_level


def test_error_exits_with_visible_status_one(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        debug.ERROR("not implemented: 0x%02x /%d\n", 0xC1, 1)

    assert raised.value.code == 1
    captured = capsys.readouterr()
    assert "[ERROR]" in captured.err
    assert "not implemented: 0xc1 /1" in captured.err


def test_failed_assert_exits_with_status_one() -> None:
    debug.ASSERT(True)
    with pytest.raises(SystemExit) as raised:
        debug.ASSERT(False)
    assert raised.value.code == 1


def test_unsupported_instruction_exits_at_the_real_lifter_boundary(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Keep unsupported frontend encodings visible to the invoking process."""
    with pytest.raises(SystemExit) as raised:
        pyvex.lift(bytes.fromhex("660f00c0"), 0x1000, Arch86_16())

    assert raised.value.code == 1
    assert "not implemented: 0x0f00 /0" in capsys.readouterr().err
