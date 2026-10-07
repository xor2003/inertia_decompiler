"""Far stack-probe registration must not rewrite the native call site.

The binary scanner may record and hook a proven ``aFCHKSTK`` target, but
registry membership is analysis metadata for Semantics and runtime owners,
not permission for the lifter to erase the architectural ``lcall``. The
native CALL keeps its pushed CS:IP frame and its Call edge into the
helper's own bytes; helper scratch effects (CX/DX/BX writes, SP
allocation) belong to the helper block, never to the call instruction.
Concrete returning-path observations are compared by executing unhooked
native bytes against Unicorn to the same post-return boundary. These vectors
do not establish all-input equivalence or complete flag/memory behavior.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, replace
from types import SimpleNamespace

import angr
import pytest
from inertia.frontend.x86_16.public_api import VEX_BACKEND
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.vex_import import build_x86_16_ir_function_artifact
from inertia.frontend.x86_16.lifter_backend import LifterBackend
from unicorn import UC_ARCH_X86, UC_MODE_16, Uc
from unicorn.x86_const import (
    UC_X86_REG_BX,
    UC_X86_REG_CS,
    UC_X86_REG_CX,
    UC_X86_REG_DS,
    UC_X86_REG_DX,
    UC_X86_REG_IP,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)

from inertia.semantics.compiler_helpers import (
    CompilerHelperEvidenceKind8616,
    hook_x86_16_known_compiler_helpers_8616,
    is_x86_16_registered_stack_probe_target_8616,
)

FUNCTION_ADDR = 0x1000
# The blob backend maps one 64K window, so the synthetic probe stays below
# 0x10000. The seg:off pair deliberately differs from the caller's segment so
# far-target linearization is proven, not assumed.
FAR_PROBE_SEG = 0x0700
FAR_PROBE_OFFSET = 0x0800
FAR_PROBE_LINEAR = (FAR_PROBE_SEG << 4) + FAR_PROBE_OFFSET
LCALL_ADDR = 0x1003
LCALL_RETURN_LINEAR = LCALL_ADDR + 5
# Caller block plus the helper's guarded normal-return path fit well under
# this bound even if the lifter splits every machine instruction into its
# own block.
NATIVE_STEP_BOUND = 16

MSC_AFCHKSTK_BYTES = bytes.fromhex("59 5a 8b dc 2b d8 72 0b 3b 1e c6 00 72 05 8b e3 52 51 cb")
POINT_AFCHKSTK_BYTES = bytes.fromhex("59 5a 8b dc 2b d8 72 0b 3b 1e be 00 72 05 8b e3 52 51 cb")


@pytest.fixture(autouse=True)
def _require_compiled_lifter() -> None:
    """These regressions must exercise the mandatory compiled native lifter."""
    assert VEX_BACKEND is LifterBackend.CYTHON


def _caller_code(ax: int) -> bytes:
    # mov ax, N ; lcall FAR_PROBE_SEG:FAR_PROBE_OFFSET ; ret
    lcall = bytes([0x9A, FAR_PROBE_OFFSET & 0xFF, FAR_PROBE_OFFSET >> 8, FAR_PROBE_SEG & 0xFF, FAR_PROBE_SEG >> 8])
    return bytes([0xB8, ax & 0xFF, 0x00]) + lcall + bytes([0xC3])


def _probe_project(ax: int, *, hook_helpers: bool) -> angr.Project:
    """Load the same exact caller/helper bytes for IR and concrete execution."""
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
    return project


def _function_artifact(project: angr.Project) -> object:
    """Build the caller artifact without inventing an entry CS value."""
    function = SimpleNamespace(
        addr=FUNCTION_ADDR,
        block_addrs_set={FUNCTION_ADDR},
        graph=SimpleNamespace(edges=()),
        info={},
    )
    return build_x86_16_ir_function_artifact(project, function)


def _lift_with_far_probe(ax: int, *, hook_helpers: bool) -> object:
    """Lift the caller block with optional helper scanning enabled."""
    return _function_artifact(_probe_project(ax, hook_helpers=hook_helpers))


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


def _assert_native_far_call_site(artifact: object) -> None:
    """Require the architectural lcall frame and target, with no inlined scratch.

    A registered helper target must still lift as one CALL to the proven
    linear address, with the four-byte CS:IP return frame pushed at the call
    instruction. Helper scratch effects (CX/DX/BX writes) belong to the
    helper's own bytes and must never appear in the caller's artifact.
    """
    callsite = [ins for ins in _instrs(artifact) if ins.addr == LCALL_ADDR]
    calls = [ins for ins in callsite if ins.op == "CALL"]
    assert len(calls) == 1
    assert calls[0].args[0].const == FAR_PROBE_LINEAR
    # The lcall pushes CS then return IP; VEX word stores are bytewise, so
    # the far frame contributes exactly four stored bytes at the call mark.
    stores = [ins for ins in callsite if ins.op == "STORE"]
    assert stores
    assert sum(ins.size for ins in stores) == 4
    assert _register_writes(artifact, "sp", at_addr=LCALL_ADDR)
    for scratch in ("cx", "dx", "bx"):
        assert not _register_writes(artifact, scratch)


def _callsite_signature(artifact: object) -> tuple[tuple[str, int], ...]:
    """Op/size sequence lifted at the lcall mark for invariance checks."""
    return tuple(
        (ins.op, ins.size) for ins in _instrs(artifact) if ins.addr == LCALL_ADDR
    )


def test_unregistered_far_probe_keeps_linearized_call_edge() -> None:
    artifact = _lift_with_far_probe(2, hook_helpers=False)

    calls = [ins for ins in _instrs(artifact) if ins.op == "CALL"]

    assert len(calls) == 1
    assert calls[0].args[0].const == FAR_PROBE_LINEAR


def test_scan_registers_far_probe_without_rewriting_native_call() -> None:
    """Registry membership is evidence, not permission to erase the lcall."""
    project = _probe_project(2, hook_helpers=True)

    # Recognition stays available for proof consumers; it must not change
    # native lifting of the caller.
    assert is_x86_16_registered_stack_probe_target_8616(project.arch, FAR_PROBE_LINEAR)
    assert project.is_hooked(FAR_PROBE_LINEAR)
    _assert_native_far_call_site(_function_artifact(project))


def test_registered_far_probe_call_site_keeps_frame_effects() -> None:
    """With AX=2 the call site is the plain native lcall with no inlining."""
    _assert_native_far_call_site(_lift_with_far_probe(2, hook_helpers=True))


def test_registered_far_probe_call_site_is_allocation_independent() -> None:
    """AX is a runtime helper input; AX=0 must lift an identical call site."""
    zero = _lift_with_far_probe(0, hook_helpers=True)

    _assert_native_far_call_site(zero)
    assert _callsite_signature(zero) == _callsite_signature(_lift_with_far_probe(2, hook_helpers=True))


@dataclass(frozen=True)
class _ProbeObservation:
    """Returning-path scratch/control subset, not flag or frame closure."""

    cx: int
    dx: int
    bx: int
    sp: int
    cs: int
    control: int


def _original_probe_observation(ax: int, caller_cs: int) -> _ProbeObservation:
    """Execute the original unhooked bytes with both guards on the return path."""
    guest = Uc(UC_ARCH_X86, UC_MODE_16)
    guest.mem_map(0, 0x100000)
    guest.mem_write(FUNCTION_ADDR, _caller_code(ax))
    guest.mem_write(FAR_PROBE_LINEAR, MSC_AFCHKSTK_BYTES)
    guest.reg_write(UC_X86_REG_CS, caller_cs)
    guest.reg_write(UC_X86_REG_SS, 0x2000)
    guest.reg_write(UC_X86_REG_DS, 0x3000)
    guest.reg_write(UC_X86_REG_SP, 0x8000)
    guest.mem_write(0x300C6, b"\x00\x00")
    guest.emu_start(FUNCTION_ADDR, LCALL_RETURN_LINEAR, count=16)
    restored_cs = guest.reg_read(UC_X86_REG_CS)
    return _ProbeObservation(
        cx=guest.reg_read(UC_X86_REG_CX), dx=guest.reg_read(UC_X86_REG_DX),
        bx=guest.reg_read(UC_X86_REG_BX), sp=guest.reg_read(UC_X86_REG_SP),
        cs=restored_cs, control=(restored_cs << 4) + guest.reg_read(UC_X86_REG_IP),
    )


def _native_probe_observation(ax: int, caller_cs: int) -> _ProbeObservation:
    """Execute the real helper bytes to the same post-return boundary.

    The scan still registers and hooks the helper, but the comparison must
    be satisfied by lifted machine code only: the SimProcedure is removed
    after registration, then bounded stepping runs the caller's CALL and
    the helper's own guarded normal-return path until the linear PC
    reaches the Unicorn guest's stop address.
    """
    project = _probe_project(ax, hook_helpers=True)
    assert is_x86_16_registered_stack_probe_target_8616(project.arch, FAR_PROBE_LINEAR)
    assert project.is_hooked(FAR_PROBE_LINEAR)
    project.unhook(FAR_PROBE_LINEAR)
    assert not project.is_hooked(FAR_PROBE_LINEAR)
    state = project.factory.blank_state(addr=FUNCTION_ADDR)
    state.regs.cs, state.regs.ss, state.regs.ds = caller_cs, 0x2000, 0x3000
    state.regs.sp = 0x8000
    # A zero stack-limit word selects the helper's normal return path
    # explicitly; the failure tail is outside this fixture's scope.
    state.memory.store(0x300C6, 0, size=2, endness="Iend_LE")
    visited: list[int] = []
    for _ in range(NATIVE_STEP_BOUND):
        (state,) = project.factory.successors(state, opt_level=0).flat_successors
        visited.append(state.solver.eval(state.regs.eip))
        if visited[-1] == LCALL_RETURN_LINEAR:
            break
    # The CALL must transfer into the helper's native bytes, and bounded
    # stepping must land on the identical post-return boundary.
    assert FAR_PROBE_LINEAR in visited
    assert visited[-1] == LCALL_RETURN_LINEAR
    return _ProbeObservation(
        cx=state.solver.eval(state.regs.cx), dx=state.solver.eval(state.regs.dx),
        bx=state.solver.eval(state.regs.bx), sp=state.solver.eval(state.regs.sp),
        cs=state.solver.eval(state.regs.cs), control=state.solver.eval(state.regs.eip),
    )


def _assert_probe_observation(actual: _ProbeObservation, expected: _ProbeObservation) -> None:
    """Compare every promised scratch/control field, with no normalization away."""
    assert actual == expected


@pytest.mark.parametrize("ax", [0, 2])
@pytest.mark.parametrize("caller_cs", [0, 0x80])
def test_far_probe_returning_registers_match_independent_guest(ax: int, caller_cs: int) -> None:
    """A nonzero caller CS distinguishes saved IP from the loaded return PC."""
    expected = _original_probe_observation(ax, caller_cs)
    assert expected.cx == LCALL_RETURN_LINEAR - (caller_cs << 4)
    assert expected.control == LCALL_RETURN_LINEAR
    assert expected.sp == expected.bx == 0x8000 - ax
    assert expected.dx == expected.cs == caller_cs
    _assert_probe_observation(_native_probe_observation(ax, caller_cs), expected)


def test_far_probe_oracle_rejects_lost_segment_and_saved_loader_pc() -> None:
    """Corrupted coordinates or allocation cannot pass the original-byte oracle."""
    expected = _original_probe_observation(2, 0x80)
    actual = _native_probe_observation(2, 0x80)
    _assert_probe_observation(actual, expected)
    mutants = (
        replace(actual, cx=LCALL_RETURN_LINEAR),
        replace(actual, control=expected.cx),
        replace(actual, sp=actual.sp + 2),
    )
    for mutant in mutants:
        with pytest.raises(AssertionError):
            _assert_probe_observation(mutant, expected)


def test_scan_evidence_reports_far_probe_kind() -> None:
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


def test_point_linked_far_probe_variant_is_binary_recognized() -> None:
    """The linked POINT helper differs only in its stack-limit displacement."""
    blob = b"\x90" * 4 + POINT_AFCHKSTK_BYTES
    project = angr.Project(
        io.BytesIO(blob),
        main_opts={
            "backend": "blob", "arch": Arch86_16(),
            "base_addr": FUNCTION_ADDR, "entry_point": FUNCTION_ADDR,
        },
        auto_load_libs=False,
    )

    evidence = hook_x86_16_known_compiler_helpers_8616(project)

    assert len(evidence) == 1
    assert evidence[0].kind is CompilerHelperEvidenceKind8616.STACK_PROBE_FAR


def test_far_probe_diverted_overflow_branch_is_not_inlined() -> None:
    """A branch into the returning path cannot inherit helper effects."""
    for branch_index in (7, 13):
        mutated = bytearray(MSC_AFCHKSTK_BYTES)
        mutated[branch_index] = 0
        blob = b"\x90" * 4 + mutated
        project = angr.Project(
            io.BytesIO(blob),
            main_opts={
                "backend": "blob", "arch": Arch86_16(),
                "base_addr": FUNCTION_ADDR, "entry_point": FUNCTION_ADDR,
            },
            auto_load_libs=False,
        )

        assert hook_x86_16_known_compiler_helpers_8616(project) == ()
