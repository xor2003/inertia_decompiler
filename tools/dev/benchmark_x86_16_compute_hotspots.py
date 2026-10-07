#!/usr/bin/env python3
"""Micro-benchmarks for x86-16 lifting compute hotspots.

Layer: Tooling/gates.
Responsibility: benchmark x86-16 lifting hotspots without changing decompiler semantics.

Run:
  PYTHONPATH=. ./.venv/bin/python tools/dev/benchmark_x86_16_compute_hotspots.py
"""

from __future__ import annotations

import time

from inertia.frontend.x86_16.instr16 import Instr16
from inertia.frontend.x86_16.instr32 import Instr32
from inertia.frontend.x86_16.instr_base import InstrBase
from inertia.frontend.x86_16.instruction import CHK_MODRM, MAX_OPCODE, SIB, InstrData, ModRM


class _DummyEmu:
    """Minimal emulator placeholder for constructor benchmarks."""



class _TableHost:
    """Minimal opcode-table host used by registration benchmarks."""

    def __init__(self) -> None:
        self.instrfuncs = [None] * MAX_OPCODE
        self.chk = [0] * MAX_OPCODE

    def set_funcflag(self, opcode: int, func: object, flags: int) -> None:
        """Delegate opcode registration to the canonical instruction helper."""
        InstrBase.set_funcflag(self, opcode, func, flags)


def _dummy_handler() -> None:
    return None


def _bench_registration_attr_lookup(iterations: int) -> float:
    start = time.perf_counter()
    for _ in range(iterations):
        host = _TableHost()
        for opcode in range(0x40, 0x80):
            host.set_funcflag(opcode, _dummy_handler, CHK_MODRM)
    return time.perf_counter() - start


def _bench_registration_local_alias(iterations: int) -> float:
    start = time.perf_counter()
    for _ in range(iterations):
        host = _TableHost()
        sf = host.set_funcflag
        for opcode in range(0x40, 0x80):
            sf(opcode, _dummy_handler, CHK_MODRM)
    return time.perf_counter() - start


def _bench_instr16_ctor(iterations: int) -> float:
    emu = _DummyEmu()
    start = time.perf_counter()
    for _ in range(iterations):
        Instr16(emu, InstrData())
    return time.perf_counter() - start


def _bench_instr32_ctor(iterations: int) -> float:
    emu = _DummyEmu()
    start = time.perf_counter()
    for _ in range(iterations):
        Instr32(emu, InstrData())
    return time.perf_counter() - start


class _PlainModRM:
    """Plain class baseline for ModRM allocation benchmarks."""

    def __init__(self) -> None:
        self.rm = 0
        self.reg = 0
        self.mod = 0


class _PlainSIB:
    """Plain class baseline for SIB allocation benchmarks."""

    def __init__(self) -> None:
        self.base = 0
        self.index = 0
        self.scale = 0


class _PlainInstrData:
    """Plain class baseline for instruction-data allocation benchmarks."""

    def __init__(self) -> None:
        self.prefix = 0
        self.pre_segment = None
        self.pre_repeat = 0
        self.segment = 0
        self.opcode = 0
        self.modrm = _PlainModRM()
        self.sib = _PlainSIB()
        self.disp8 = 0
        self.disp16 = 0
        self.disp32 = 0
        self.imm8 = 0
        self.imm16 = 0
        self.imm32 = 0
        self.ptr16 = 0
        self.moffs = 0
        self.prefix_len = 0
        self.size = 0
        self.operand_bits = 0
        self.address_bits = 0
        self.displacement_bits = 0
        self.repeat_class = "none"
        self.control_flow_class = "none"
        self.width_case = ""


def _bench_instrdata_slots(iterations: int) -> float:
    start = time.perf_counter()
    for _ in range(iterations):
        InstrData()
    return time.perf_counter() - start


def _bench_instrdata_plain(iterations: int) -> float:
    start = time.perf_counter()
    for _ in range(iterations):
        _PlainInstrData()
    return time.perf_counter() - start


def main() -> None:
    """Run local hotspot benchmarks and print plain-text timing summaries."""
    reg_iters = 50000
    ctor_iters = 3000
    data_iters = 200000

    reg_attr = _bench_registration_attr_lookup(reg_iters)
    reg_alias = _bench_registration_local_alias(reg_iters)
    i16 = _bench_instr16_ctor(ctor_iters)
    i32 = _bench_instr32_ctor(ctor_iters)
    data_slots = _bench_instrdata_slots(data_iters)
    data_plain = _bench_instrdata_plain(data_iters)

    print(f"registration_iterations={reg_iters} opcodes_per_iter=64")
    print(f"registration_attr_lookup_s={reg_attr:.6f}")
    print(f"registration_local_alias_s={reg_alias:.6f}")
    print(f"registration_alias_speedup_x={reg_attr / reg_alias:.3f}")
    print(f"instr16_ctor_iterations={ctor_iters} total_s={i16:.6f} per_ctor_us={i16 * 1e6 / ctor_iters:.2f}")
    print(f"instr32_ctor_iterations={ctor_iters} total_s={i32:.6f} per_ctor_us={i32 * 1e6 / ctor_iters:.2f}")
    print(f"instrdata_iterations={data_iters}")
    print(f"instrdata_slots_s={data_slots:.6f}")
    print(f"instrdata_plain_s={data_plain:.6f}")
    print(f"instrdata_slots_speedup_x={data_plain / data_slots:.3f}")
    print(f"slot_check_modrm={not hasattr(ModRM(), '__dict__')}")
    print(f"slot_check_sib={not hasattr(SIB(), '__dict__')}")


if __name__ == "__main__":
    main()
