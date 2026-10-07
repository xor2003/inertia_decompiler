"""Frontend immediate-port zero-extension controls without native lifting."""
from __future__ import annotations

from collections.abc import Callable
from functools import partial
from types import SimpleNamespace

import pytest

from inertia.frontend.x86_16.instr16 import Instr16
from inertia.frontend.x86_16.instr32 import Instr32
from inertia.frontend.x86_16.instr_base import InstrBase

_IMMEDIATE_HANDLERS = (
    (InstrBase.in_al_imm8, "in", 8), (InstrBase.out_imm8_al, "out", 8),
    (Instr16.in_ax_imm8, "in", 16), (Instr16.out_imm8_ax, "out", 16),
    (Instr32.in_eax_imm8, "in", 32), (Instr32.out_imm8_eax, "out", 32),
)
_DX_HANDLERS = (
    (InstrBase.in_al_dx, "in", 8), (InstrBase.out_dx_al, "out", 8),
    (Instr16.in_ax_dx, "in", 16), (Instr16.out_dx_ax, "out", 16),
    (Instr32.in_eax_dx, "in", 32), (Instr32.out_dx_eax, "out", 32),
)


def _instruction(immediate: int) -> tuple[SimpleNamespace, list[tuple[str, int, int]]]:
    events = []

    def read(width: int, port: int) -> int:
        events.append(("in", width, port))
        return 0x5A

    def write(width: int, port: int, value: int) -> None:
        events.append(("out", width, port))

    emu = SimpleNamespace(
        in_io8=partial(read, 8), in_io16=partial(read, 16), in_io32=partial(read, 32),
        out_io8=partial(write, 8), out_io16=partial(write, 16), out_io32=partial(write, 32),
        get_gpreg=lambda _register: 0xFF80, set_gpreg=lambda _register, _value: None,
    )
    return SimpleNamespace(emu=emu, instr=SimpleNamespace(imm8=immediate)), events


@pytest.mark.parametrize("handler,direction,width", _IMMEDIATE_HANDLERS)
@pytest.mark.parametrize("decoded,port", [(0x7F, 0x7F), (-128, 0x80), (-1, 0xFF), (0x80, 0x80), (0xFF, 0xFF)])
def test_immediate_port_is_zero_extended(handler: Callable[[SimpleNamespace], None], direction: str, width: int, decoded: int, port: int) -> None:
    """Signed decoder storage cannot sign-extend an architectural imm8 port."""
    instruction, events = _instruction(decoded)
    handler(instruction)
    assert events == [(direction, width, port)]


@pytest.mark.parametrize("handler,direction,width", _DX_HANDLERS)
def test_dx_port_keeps_all_sixteen_bits(handler: Callable[[SimpleNamespace], None], direction: str, width: int) -> None:
    """The immediate-only repair must not truncate a genuine DX=0xff80 port."""
    instruction, events = _instruction(0)
    handler(instruction)
    assert events == [(direction, width, 0xFF80)]
