from __future__ import annotations

from types import SimpleNamespace

from inertia.frontend.x86_16.simprocs_io import X86DirtyIN, X86DirtyOUT


class _FakeSolver:
    def eval(self, value: object) -> int:
        return int(value)

    def BVV(self, value: int, bits: int) -> tuple[int, int]:
        return value, bits


def _procedure_with_fake_state(cls: type[object]) -> object:
    procedure = object.__new__(cls)
    procedure.state = SimpleNamespace(solver=_FakeSolver())
    return procedure


def test_x86_dirty_in_returns_width_specific_default_values() -> None:
    procedure = _procedure_with_fake_state(X86DirtyIN)

    assert X86DirtyIN.run(procedure, 8, port=0x3F8) == (0xFF, 8)
    assert X86DirtyIN.run(procedure, 16, port=0x3F8) == (0xFFFF, 16)
    assert X86DirtyIN.run(procedure, 32, port=0x3F8) == (0xFFFFFFFF, 32)


def test_x86_dirty_in_defaults_to_32_bits_for_unparseable_size() -> None:
    procedure = _procedure_with_fake_state(X86DirtyIN)

    assert X86DirtyIN.run(procedure, object()) == (0xFFFFFFFF, 32)


def test_x86_dirty_out_is_noop_without_port_device() -> None:
    procedure = _procedure_with_fake_state(X86DirtyOUT)

    assert X86DirtyOUT.run(procedure, 16, 0x3F8, 0xFF) is None
