from __future__ import annotations

import pytest

from inertia.frontend.x86_16.interrupt import IDTR, TR, Interrupt


class _InterruptProbe(Interrupt):
    def __init__(self) -> None:
        self.pushed: list[object] = []

    def push16(self, value: object) -> None:
        self.pushed.append(value)

    def get_flags(self) -> int:
        return 0x0202

    def get_ip(self) -> int:
        return 0x1234


def test_interrupt_descriptor_register_constants_are_stable() -> None:
    assert IDTR == 1
    assert TR == 3


def test_interrupt_dispatch_surface_is_explicitly_unimplemented() -> None:
    interrupt = _InterruptProbe()

    with pytest.raises(NotImplementedError):
        interrupt.set_pic(object(), True)
    with pytest.raises(NotImplementedError):
        interrupt.handle_interrupt()
    with pytest.raises(NotImplementedError):
        interrupt.chk_irq()


def test_save_regs_pushes_flags_cs_and_ip() -> None:
    interrupt = _InterruptProbe()

    interrupt.save_regs(False, 0xBEEF)

    assert interrupt.pushed == [0x0202, 0xBEEF, 0x1234]
