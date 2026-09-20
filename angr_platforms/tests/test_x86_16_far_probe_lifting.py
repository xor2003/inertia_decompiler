"""Far stack-probe lifting must inline the helper body with faithful local effects."""

from __future__ import annotations

import io
from types import SimpleNamespace

import angr
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.compiler_helpers import (
    CompilerHelperEvidenceKind8616,
    hook_x86_16_known_compiler_helpers_8616,
)
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact

FUNCTION_ADDR = 0x1000
# The blob backend maps one 64K window, so the synthetic probe stays below
# 0x10000. The seg:off pair deliberately differs from the caller's segment so
# far-target linearization is proven, not assumed.
FAR_PROBE_SEG = 0x0700
FAR_PROBE_OFFSET = 0x0800
FAR_PROBE_LINEAR = (FAR_PROBE_SEG << 4) + FAR_PROBE_OFFSET
LCALL_ADDR = 0x1003
LCALL_RETURN_IP = LCALL_ADDR + 5

MSC_AFCHKSTK_BYTES = bytes.fromhex("59 5a 8b dc 2b d8 72 0b 3b 1e c6 00 72 05 8b e3 52 51 cb")


def _caller_code(ax: int) -> bytes:
    # mov ax, N ; lcall FAR_PROBE_SEG:FAR_PROBE_OFFSET ; ret
    lcall = bytes([0x9A, FAR_PROBE_OFFSET & 0xFF, FAR_PROBE_OFFSET >> 8, FAR_PROBE_SEG & 0xFF, FAR_PROBE_SEG >> 8])
    return bytes([0xB8, ax & 0xFF, 0x00]) + lcall + bytes([0xC3])


def _lift_with_far_probe(ax: int, *, hook_helpers: bool) -> object:
    caller = _caller_code(ax)
    blob = caller + b"\x90" * (FAR_PROBE_LINEAR - FUNCTION_ADDR - len(caller)) + MSC_AFCHKSTK_BYTES
    project = angr.Project(
        io.BytesIO(blob),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": FUNCTION_ADDR,
            "entry_point": FUNCTION_ADDR,
        },
        auto_load_libs=False,
    )
    if hook_helpers:
        hook_x86_16_known_compiler_helpers_8616(project)
    function = SimpleNamespace(
        addr=FUNCTION_ADDR,
        block_addrs_set={FUNCTION_ADDR},
        graph=SimpleNamespace(edges=()),
        info={},
    )
    return build_x86_16_ir_function_artifact(project, function)


def _instrs(artifact: object) -> list:
    return [ins for block in artifact.blocks for ins in block.instrs]


def _register_writes(artifact: object, register: str, *, at_addr: int | None = None) -> list:
    writes = [
        ins
        for ins in _instrs(artifact)
        if ins.op == "MOV" and ins.dst is not None and ins.dst.name == register
        and (at_addr is None or ins.addr == at_addr)
    ]
    return writes


def test_unregistered_far_probe_keeps_linearized_call_edge():
    artifact = _lift_with_far_probe(2, hook_helpers=False)

    calls = [ins for ins in _instrs(artifact) if ins.op == "CALL"]

    assert len(calls) == 1
    assert calls[0].args[0].const == FAR_PROBE_LINEAR


def test_scan_registers_far_probe_and_inline_removes_the_call_edge():
    artifact = _lift_with_far_probe(2, hook_helpers=True)

    ops = [ins.op for ins in _instrs(artifact)]

    assert "CALL" not in ops
    assert "STORE" not in ops


def test_far_probe_inline_models_helper_register_effects_with_allocation():
    artifact = _lift_with_far_probe(2, hook_helpers=True)

    # CX carries the popped far return IP; DX the popped CS read from the register.
    cx_writes = _register_writes(artifact, "cx", at_addr=LCALL_ADDR)
    assert cx_writes
    assert all(ins.args[0].const == LCALL_RETURN_IP for ins in cx_writes)
    dx_writes = _register_writes(artifact, "dx", at_addr=LCALL_ADDR)
    assert dx_writes
    assert all(ins.args[0].name == "cs" and ins.args[0].const is None for ins in dx_writes)
    # BX mirrors the helper's next-SP subtraction and SP is decremented by AX=2.
    assert _register_writes(artifact, "bx", at_addr=LCALL_ADDR)
    assert _register_writes(artifact, "sp", at_addr=LCALL_ADDR)
    subs = [ins for ins in _instrs(artifact) if ins.op == "Iop_Sub16" and ins.addr == LCALL_ADDR]
    assert subs
    assert any(ins.args[0].name == "sp" and ins.args[1].const == 2 for ins in subs)


def test_far_probe_inline_with_zero_allocation_keeps_sp_stable():
    # The STORE.EXE large-model bump_static shape: mov ax, 0 before the probe call.
    artifact = _lift_with_far_probe(0, hook_helpers=True)

    ops = [ins.op for ins in _instrs(artifact)]

    assert "CALL" not in ops
    assert "STORE" not in ops
    assert not _register_writes(artifact, "sp", at_addr=LCALL_ADDR)
    cx_writes = _register_writes(artifact, "cx", at_addr=LCALL_ADDR)
    assert cx_writes
    assert all(ins.args[0].const == LCALL_RETURN_IP for ins in cx_writes)


def test_scan_evidence_reports_far_probe_kind():
    blob = b"\x90" * 4 + MSC_AFCHKSTK_BYTES
    project = angr.Project(
        io.BytesIO(blob),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": FUNCTION_ADDR,
            "entry_point": FUNCTION_ADDR,
        },
        auto_load_libs=False,
    )

    evidence = hook_x86_16_known_compiler_helpers_8616(project)

    assert len(evidence) == 1
    assert evidence[0].kind is CompilerHelperEvidenceKind8616.STACK_PROBE_FAR
    assert evidence[0].addr == FUNCTION_ADDR + 4
