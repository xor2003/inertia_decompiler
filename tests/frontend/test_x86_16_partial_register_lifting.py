from __future__ import annotations

from types import SimpleNamespace

import pyvex
from angr import options as o
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir import MemSpace
from inertia.ir.vex_import import build_x86_16_ir_function_artifact
from pyvex.expr import Get
from pyvex.stmt import Put

import decompile


def test_mov_cl_immediate_lifts_as_byte_view_without_reading_cx() -> None:
    arch = Arch86_16()
    irsb = pyvex.lift(bytes.fromhex("b105"), 0x1000, arch)

    puts = [statement for statement in irsb.statements if isinstance(statement, Put)]
    full_cx_reads = [
        expr
        for expr in irsb.expressions
        if isinstance(expr, Get)
        and expr.offset == arch.registers["cx"][0]
        and expr.result_size(irsb.tyenv) == 16
    ]

    assert len(puts) == 1
    assert puts[0].offset == arch.registers["cl"][0]
    assert puts[0].data.result_size(irsb.tyenv) == 8
    assert full_cx_reads == []


def test_partial_cl_write_preserves_high_byte_for_later_full_cx_read() -> None:
    code = bytes.fromhex("b10589c8")  # mov cl, 5; mov ax, cx
    project = decompile._build_project_from_bytes(code, base_addr=0x1000, entry_point=0x1000)
    state = project.factory.blank_state(
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )
    state.regs.cx = 0xABCD

    simgr = project.factory.simgr(state)
    simgr.step(num_inst=2, insn_bytes=code)

    assert len(simgr.active) == 1
    successor = simgr.active[0]
    assert successor.solver.eval(successor.regs.cx) == 0xAB05
    assert successor.solver.eval(successor.regs.ax) == 0xAB05


def test_vex_import_preserves_byte_register_put_width() -> None:
    project = decompile._build_project_from_bytes(
        bytes.fromhex("a0341288c3c3"),
        base_addr=0x1000,
        entry_point=0x1000,
    )
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})

    artifact = build_x86_16_ir_function_artifact(project, function)
    byte_moves = tuple(
        instruction
        for instruction in artifact.blocks[0].instrs
        if instruction.op == "MOV"
        and instruction.dst is not None
        and instruction.dst.space is MemSpace.REG
        and instruction.dst.name in {"al", "bl"}
    )

    assert tuple((move.dst.name, move.dst.size, move.size) for move in byte_moves) == (
        ("al", 1, 1),
        ("bl", 1, 1),
    )


def test_vex_import_preserves_high_byte_register_identity() -> None:
    project = decompile._build_project_from_bytes(
        bytes.fromhex("b448c3"),
        base_addr=0x1000,
        entry_point=0x1000,
    )
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})

    artifact = build_x86_16_ir_function_artifact(project, function)
    ah_write = next(
        instruction
        for instruction in artifact.blocks[0].instrs
        if instruction.op == "MOV"
        and instruction.dst is not None
        and instruction.dst.space is MemSpace.REG
        and instruction.dst.name == "ah"
    )

    assert (ah_write.dst.size, ah_write.size) == (1, 1)
