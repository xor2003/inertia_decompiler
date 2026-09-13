from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.arch_86_16 import Arch86_16

from inertia_decompiler.cli_string_timeout_fallback import try_render_x86_16_string_timeout_fallback


class _Memory:
    def __init__(self, base: int, data: bytes):
        self._base = base
        self._data = data

    def load(self, start: int, size: int) -> bytes:
        begin = start - self._base
        return self._data[begin : begin + size]


def _linear_project(code: bytes, *, base: int = 0x1000):
    arch = Arch86_16()
    return SimpleNamespace(
        arch=arch,
        loader=SimpleNamespace(memory=_Memory(base, code)),
    )


def test_string_timeout_fallback_renders_generic_movs_intrinsic():
    project = _linear_project(b"\xfc\xf3\xa5")

    fallback = try_render_x86_16_string_timeout_fallback(project, start=0x1000, end=0x1003, name="memcpy_like")

    assert fallback is not None
    assert "memcpy_class" in fallback.c_text
    assert "__x86_16_movs(2);" in fallback.c_text


def test_string_timeout_fallback_renders_generic_strlen_copy_intrinsic():
    project = _linear_project(b"\x30\xc0\xf2\xae\xf3\xa4")

    fallback = try_render_x86_16_string_timeout_fallback(project, start=0x1000, end=0x1006, name="strcpy_like")

    assert fallback is not None
    assert fallback.family == "strlen_class,movs_class"
    assert "__x86_16_scas_zterm_len(1);" in fallback.c_text
    assert "__x86_16_movs(1);" in fallback.c_text


def test_string_timeout_fallback_refuses_unproven_mixed_overlap_body():
    project = _linear_project(b"\xfd\xf3\xa4\xfc\xa4\xf3\xa5")

    fallback = try_render_x86_16_string_timeout_fallback(project, start=0x1000, end=0x1007, name="memcpy_like")

    assert fallback is None


def test_string_timeout_fallback_refuses_unproven_scan_tail_body():
    project = _linear_project(b"\xf2\xae\xae")

    fallback = try_render_x86_16_string_timeout_fallback(project, start=0x1000, end=0x1003, name="scan_like")

    assert fallback is None


@pytest.mark.parametrize("extra", [b"\x40", b"\xa3\x00\x02", b"\xcd\x21", b"\x50"])
def test_string_timeout_fallback_refuses_unrepresented_effects(extra: bytes) -> None:
    """String evidence cannot replace arithmetic, stores, interrupts or stack effects."""
    code = b"\xfc\xbf\x00\x02\xb8\x34\x12\xb9\x03\x00\xf3\xab" + extra + b"\xc3"
    base = 0x1000
    fallback = try_render_x86_16_string_timeout_fallback(
        _linear_project(code), start=base, end=base + len(code), name="mixed_effects",
    )
    assert fallback is None
