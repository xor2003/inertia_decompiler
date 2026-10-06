"""Native target-only controls for explicitly declared synthetic near calls."""

from __future__ import annotations

import io
from dataclasses import replace
from typing import Protocol

import angr
import pytest
from angr_platforms.X86_16 import lift_86_16
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import CallsiteMachineFrameKind8616
from angr_platforms.X86_16.cod_analysis_image import build_cod_analysis_image_8616
from angr_platforms.X86_16.ir.core import IRBlock, IRInstr
from angr_platforms.X86_16.ir.vex_import import _block_to_ir
from angr_platforms.X86_16.semantics.direct_near_call_target_binding import (
    DirectNearCallCoordinates8616,
    DirectNearCallTargetBinding8616,
)
from angr_platforms.X86_16.semantics.direct_near_call_target_binding import (
    prove_declared_direct_near_call_target_binding_at_coordinates_8616 as declared,
)
from angr_platforms.X86_16.semantics.direct_near_call_target_binding import (
    prove_direct_near_call_target_binding_at_coordinates_8616 as ordinary,
)
from angr_platforms.X86_16.semantics.direct_ret_call_effect import prove_direct_near_ret_only_effect_8616
from angr_platforms.X86_16.synthetic_call_stub_evidence import record_synthetic_call_stubs_8616


class BindingProof(Protocol):
    """Shared signature of both target-only binding entrypoints."""

    def __call__(
        self,
        project: object,
        *,
        block: IRBlock,
        instruction: IRInstr,
        coordinates: DirectNearCallCoordinates8616,
    ) -> DirectNearCallTargetBinding8616:
        """Bind current native control identity under the chosen target policy."""
        ...


NativeCall = tuple[angr.Project, IRBlock, IRInstr, DirectNearCallCoordinates8616]


def world(register: bool = True) -> NativeCall:
    """Mint a frontend synthetic call and import it with the required Cython lifter."""
    assert lift_86_16.__file__.endswith(".so")
    image = build_cod_analysis_image_8616(
        [
            {"offset": 0, "bytes": bytes.fromhex("e80000"), "text": "call arbitrary_external"},
            {"offset": 3, "bytes": b"\xc3", "text": "ret"},
        ]
    )
    project = angr.Project(
        io.BytesIO(image.code),
        main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000, "entry_point": 0x1000},
        auto_load_libs=False,
        simos="DOS",
    )
    targets = frozenset(0x1000 + offset for offset in image.call_target_offsets)
    if register:
        record_synthetic_call_stubs_8616(project, targets)
    block, _, _ = _block_to_ir(project.factory.block(0x1000, opt_level=0))
    call = next(i for i in block.instrs if i.op == "CALL")
    coordinates = DirectNearCallCoordinates8616(0x1000, 0x1003, next(iter(targets)))
    return project, block, call, coordinates


def prove(fn: BindingProof, parts: NativeCall) -> DirectNearCallTargetBinding8616:
    """Apply one binding policy to the same exact native fixture surface."""
    p, b, i, c = parts
    return fn(p, block=b, instruction=i, coordinates=c)


def test_native_declared_binding_keeps_real_body_default() -> None:
    """Explicit stub binding leaves every ordinary real-body gate unchanged."""
    parts = world()
    assert prove(declared, parts).complete
    assert not prove(ordinary, parts).complete


@pytest.mark.parametrize("corruption", ("target", "origin", "operand", "bytes", "foreign", "registry", "real_body"))
def test_declared_binding_rechecks_every_authority(corruption: str) -> None:
    """Corrupt one independent authority and require fresh binding refusal."""
    p, b, i, c = world(register=corruption != "real_body")
    if corruption == "target":
        c = replace(c, target_addr=c.target_addr + 1)
    elif corruption == "origin":
        old = i
        i = replace(i, origin=None)
        b = replace(b, instrs=tuple(i if item is old else item for item in b.instrs))
    elif corruption == "operand":
        old = i
        assert i.args[0].source_tmp is not None
        i = replace(i, args=(replace(i.args[0], source_tmp=i.args[0].source_tmp + 1),))
        b = replace(b, instrs=tuple(i if item is old else item for item in b.instrs))
    elif corruption == "bytes":
        assert prove(declared, (p, b, i, c)).complete
        p.loader.memory.store(0x1000, bytes.fromhex("e80000"))
    elif corruption == "foreign":
        i = replace(i)
    elif corruption == "registry":
        record_synthetic_call_stubs_8616(p, frozenset({-1}))
    assert not prove(declared, (p, b, i, c)).complete
    if corruption == "real_body":
        assert prove(ordinary, (p, b, i, c)).complete


def test_stub_binding_never_grants_ret_body_effects() -> None:
    """Neither RET bytes nor later stub-body changes turn identity into effects."""
    parts = world()
    project, _block, _instruction, coordinates = parts
    for opcode in (b"\xc3", b"\x90"):
        project.loader.memory.store(coordinates.target_addr, opcode)
        assert prove(declared, parts).complete
        effect = prove_direct_near_ret_only_effect_8616(
            project,
            coordinates.callsite_addr,
            coordinates.next_addr,
            coordinates.target_addr,
            CallsiteMachineFrameKind8616.NEAR,
        )
        assert not effect.complete
