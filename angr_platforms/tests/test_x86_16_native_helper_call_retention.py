"""Registered compiler-helper targets must not erase native call effects.

A decoded call target's membership in the binary-proven helper registry is
analysis metadata for Semantics and runtime owners, not permission for the
lifter to erase the architectural CALL. A near call must keep its
return-address push and its CS-relative modulo control edge; a far call
must keep its pushed CS:IP return frame, segment transfer, and Call edge.
Helper scratch effects (CX/DX/BX writes, SP allocation) may be applied only
by Semantics proofs that consume binary evidence with their own premises.
"""

from __future__ import annotations

import io
from types import SimpleNamespace

import angr
import pytest
from angr_platforms.X86_16 import VEX_BACKEND
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.compiler_helpers import hook_x86_16_known_compiler_helpers_8616
from angr_platforms.X86_16.ir import IRInstr, IRValue, MemSpace
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact
from angr_platforms.X86_16.lifter_backend import LifterBackend
from angr_platforms.X86_16.semantics.call_stack_allocation import (
    binary_stack_allocation_target_8616,
    collect_call_stack_allocation_proofs_8616,
)
from pyvex.expr import Const

_FUNCTION = 0x1000
_NEAR_TARGET = 0x1010
_FAR_SEG = 0x0700
_FAR_OFFSET = 0x0800
_FAR_LINEAR = (_FAR_SEG << 4) + _FAR_OFFSET
_ALIAS_ENTRY = 0x20400
_ALIAS_TARGET = 0x21222
_ALIAS_HELPER = 0x11222

MSC_ANCHKSTK_BYTES = bytes.fromhex("59 8b dc 2b d8 72 0a 3b 1e b6 00 72 04 8b e3 ff e1")
MSC_AFCHKSTK_BYTES = bytes.fromhex("59 5a 8b dc 2b d8 72 0b 3b 1e c6 00 72 05 8b e3 52 51 cb")


@pytest.fixture(autouse=True)
def _require_compiled_lifter() -> None:
    """These regressions must exercise the mandatory compiled native lifter."""
    assert VEX_BACKEND is LifterBackend.CYTHON


def _near_caller(allocation: int, *, entry: int = _FUNCTION, target: int = _NEAR_TARGET) -> tuple[bytes, int]:
    """Encode ``mov ax, N`` then ``call target``; return bytes and call addr."""
    call_addr = entry + 3
    displacement = target - (call_addr + 3)
    assert 0 <= displacement <= 0x7FFF
    return (
        bytes((0xB8, allocation & 0xFF, allocation >> 8, 0xE8, displacement & 0xFF, displacement >> 8)),
        call_addr,
    )


def _far_caller() -> bytes:
    """Encode ``lcall _FAR_SEG:_FAR_OFFSET`` followed by ``ret``."""
    return bytes((
        0x9A, _FAR_OFFSET & 0xFF, _FAR_OFFSET >> 8, _FAR_SEG & 0xFF, _FAR_SEG >> 8, 0xC3,
    ))


def _blob(placements: tuple[tuple[int, bytes], ...], base: int = _FUNCTION) -> bytes:
    """Place code fragments at their linear addresses in one NOP-padded blob."""
    image = bytearray()
    for linear, code in sorted(placements):
        gap = linear - base - len(image)
        assert gap >= 0
        image += b"\x90" * gap + code
    return bytes(image)


def _project(code: bytes) -> angr.Project:
    """Load caller/helper bytes as one flat blob without a declared boot CS."""
    arch = Arch86_16()
    # CLE bounds the flat image by arch.bits; real-mode linear addresses
    # exceed 64 KiB even though the native registers/instructions are 16-bit.
    arch.bits = 32
    return angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": arch,
            "base_addr": _FUNCTION,
            "entry_point": _FUNCTION,
        },
        auto_load_libs=False,
    )


def _near_block(
    allocation: int,
    *,
    entry: int = _FUNCTION,
    target: int = _NEAR_TARGET,
    helper_linear: int | None = _NEAR_TARGET,
) -> tuple[object, angr.Project, int]:
    """Lift the near caller block after optional production helper scanning."""
    caller, call_addr = _near_caller(allocation, entry=entry, target=target)
    placements = [(entry, caller)]
    if helper_linear is not None:
        placements.append((helper_linear, MSC_ANCHKSTK_BYTES))
    project = _project(_blob(tuple(placements)))
    if helper_linear is not None:
        hook_x86_16_known_compiler_helpers_8616(project)
    return project.factory.block(entry, opt_level=0), project, call_addr


def _far_block() -> tuple[object, angr.Project]:
    """Lift the far caller block after production helper scanning."""
    project = _project(_blob(((_FUNCTION, _far_caller()), (_FAR_LINEAR, MSC_AFCHKSTK_BYTES))))
    hook_x86_16_known_compiler_helpers_8616(project)
    return project.factory.block(_FUNCTION, opt_level=0), project


def _puts_stores_at(block: object, addr: int) -> tuple[tuple[int, ...], int]:
    """Collect register Put offsets and stored byte widths at one mark."""
    current: int | None = None
    puts: list[int] = []
    stores = 0
    for statement in block.vex.statements:
        if statement.tag == "Ist_IMark":
            current = statement.addr
        elif current == addr and statement.tag == "Ist_Put":
            puts.append(statement.offset)
        elif current == addr and statement.tag == "Ist_Store":
            stores += statement.data.result_size(block.vex.tyenv) // 8
    return tuple(puts), stores


def _ir_artifact(project: object, entry: int = _FUNCTION) -> object:
    """Build the universal IR artifact for one single-entry-block function."""
    function = SimpleNamespace(
        addr=entry,
        block_addrs_set={entry},
        graph=SimpleNamespace(edges=()),
        info={},
    )
    return build_x86_16_ir_function_artifact(project, function)


def _instrs(artifact: object) -> list:
    return [ins for block in artifact.blocks for ins in block.instrs]


def _assert_near_call_effects(block: object, arch: object, call_addr: int) -> None:
    """Require the architectural near-call frame and symbolic Call edge."""
    puts, stores = _puts_stores_at(block, call_addr)
    assert block.vex.jumpkind == "Ijk_Call"
    assert stores == 2
    assert puts == (arch.registers["sp"][0],)
    assert not isinstance(block.vex.next, Const)


@pytest.mark.parametrize("allocation", [0, 4])
def test_registered_near_helper_call_keeps_call_frame_and_edge(allocation: int) -> None:
    """A binary-registered near target retains push, store, and Call exit."""
    block, project, call_addr = _near_block(allocation)

    _assert_near_call_effects(block, project.arch, call_addr)


def test_registered_near_helper_call_survives_into_universal_ir() -> None:
    """The callsite remains a CALL operand for Semantics proof owners."""
    _block, project, call_addr = _near_block(4)

    calls = [ins for ins in _instrs(_ir_artifact(project)) if ins.op == "CALL"]

    assert len(calls) == 1
    assert calls[0].addr == call_addr


def test_registered_far_helper_call_keeps_frame_and_call_edge() -> None:
    """A binary-registered far target keeps CS:IP pushes and CS transfer."""
    block, project = _far_block()
    arch = project.arch
    puts, stores = _puts_stores_at(block, _FUNCTION)

    assert block.vex.jumpkind == "Ijk_Call"
    assert stores == 4
    assert arch.registers["sp"][0] in puts
    assert arch.registers["cs"][0] in puts
    for scratch in ("cx", "dx", "bx"):
        assert arch.registers[scratch][0] not in puts
    assert isinstance(block.vex.next, Const)
    assert block.vex.next.con.value == _FAR_LINEAR


def test_registered_far_helper_call_survives_into_universal_ir() -> None:
    """The far callsite remains a CALL with its proven linear target."""
    _block, project = _far_block()

    calls = [ins for ins in _instrs(_ir_artifact(project)) if ins.op == "CALL"]

    assert len(calls) == 1
    assert calls[0].addr == _FUNCTION
    assert calls[0].args[0].const == _FAR_LINEAR


def test_low_word_registry_alias_does_not_substitute_near_call() -> None:
    """A helper at 0x11222 registers low word 0x1222; a call decoded to
    0x21222 matches only through the ``target & 0xFFFF`` alias and must not
    be rewritten. Under a different CS the real linear target is elsewhere."""
    caller, call_addr = _near_caller(4, entry=_ALIAS_ENTRY, target=_ALIAS_TARGET)
    project = _project(_blob(((_ALIAS_HELPER, MSC_ANCHKSTK_BYTES), (_ALIAS_ENTRY, caller))))
    evidence = hook_x86_16_known_compiler_helpers_8616(project)
    assert tuple(item.addr for item in evidence) == (_ALIAS_HELPER,)

    block = project.factory.block(_ALIAS_ENTRY, opt_level=0)

    _assert_near_call_effects(block, project.arch, call_addr)


def test_low_word_alias_yields_no_allocation_target_or_proof() -> None:
    """The aliased decoded constant cannot bind helper allocation evidence."""
    caller, call_addr = _near_caller(4, entry=_ALIAS_ENTRY, target=_ALIAS_TARGET)
    project = _project(_blob(((_ALIAS_HELPER, MSC_ANCHKSTK_BYTES), (_ALIAS_ENTRY, caller))))
    hook_x86_16_known_compiler_helpers_8616(project)
    artifact = _ir_artifact(project, entry=_ALIAS_ENTRY)

    bound = IRInstr(
        "CALL", None, (IRValue(MemSpace.CONST, const=_ALIAS_TARGET, size=4),),
        addr=call_addr,
    )
    assert binary_stack_allocation_target_8616(project, bound) is None
    assert collect_call_stack_allocation_proofs_8616(project, artifact) == {}


def test_unregistered_near_call_keeps_identical_call_effects() -> None:
    """Ordinary unregistered near calls are unchanged by helper machinery."""
    block, project, call_addr = _near_block(4, helper_linear=None)

    _assert_near_call_effects(block, project.arch, call_addr)
