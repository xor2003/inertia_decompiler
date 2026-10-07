"""Regressions for canonical MS C public-entry padding aliases."""

from types import SimpleNamespace

from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.lowering.analysis_helpers import (
    canonicalize_x86_16_padding_call_target_8616,
)


class _Memory:
    def __init__(self, base: int, data: bytes) -> None:
        self._base = base
        self._data = data

    def load(self, addr: int, size: int) -> bytes:
        start = addr - self._base
        return self._data[start : start + size]


def test_canonicalizes_long_msc_public_entry_padding() -> None:
    public_entry = 0x10794
    framed_entry = 0x107B8
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(
            memory=_Memory(
                public_entry,
                b"\x90" * (framed_entry - public_entry) + b"\x55\x8b\xec",
            )
        ),
    )

    assert (
        canonicalize_x86_16_padding_call_target_8616(project, public_entry)
        == framed_entry
    )
