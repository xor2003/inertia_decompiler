from __future__ import annotations

from dataclasses import dataclass

from angr_platforms.X86_16.control_coordinates import ControlAddressDomain
from angr_platforms.X86_16.emulator import Emulator
from angr_platforms.X86_16.processor import Processor


@dataclass(frozen=True)
class _Register:
    name: str
    vex_offset: int


@dataclass(frozen=True)
class _Arch:
    register_list: tuple[_Register, ...]
    control_address_domain: ControlAddressDomain = ControlAddressDomain.LOADER_LINEAR


class _MemoryEmulator(Emulator):
    def __init__(self) -> None:
        super().__init__(_Arch(register_list=(_Register("AX", 0), _Register("Ip", 16))))
        self.reads: list[tuple[object, object]] = []
        self.writes: list[tuple[object, object, object]] = []

    def read_mem16_seg(self, seg: object, addr: object) -> tuple[str, object, object]:
        self.reads.append((seg, addr))
        return ("read16", seg, addr)

    def write_mem16_seg(self, seg: object, addr: object, val: object) -> None:
        self.writes.append((seg, addr, val))


def test_emulator_builds_vex_offset_map_from_arch_contract() -> None:
    emulator = Emulator(_Arch(register_list=(_Register("AX", 0), _Register("Ip", 16))))

    assert emulator.vex_offsets == {"ax": 0, "ip": 16}
    assert emulator.irsb is None


def test_emulator_initializes_processor_once_through_runtime_mro(monkeypatch) -> None:
    calls: list[object] = []
    original = Processor.__init__

    def counted(processor: Processor) -> None:
        calls.append(processor)
        original(processor)

    monkeypatch.setattr(Processor, "__init__", counted)

    emulator = Emulator(_Arch(register_list=()))

    assert calls == [emulator]


def test_emulator_real_mode_ring_check_allows_instruction() -> None:
    emulator = Emulator(_Arch(register_list=()))

    assert emulator.chk_ring(3) is True


def test_emulator_data16_forwards_to_memory_hooks() -> None:
    emulator = _MemoryEmulator()

    assert emulator.get_data16("ds", 0x1234) == ("read16", "ds", 0x1234)
    emulator.put_data16("es", 0x2000, 0xBEEF)

    assert emulator.reads == [("ds", 0x1234)]
    assert emulator.writes == [("es", 0x2000, 0xBEEF)]
