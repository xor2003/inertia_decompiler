"""Typed fixtures for X86-16 logical-memory resolver regressions."""

from __future__ import annotations

import io
from types import SimpleNamespace

import angr
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.logical_memory_capture import (
    IRLogicalMemoryCaptureRecord8616,
)
from inertia.ir.logical_memory_contracts import (
    IRLogicalMemoryArtifact8616,
    IRLogicalMemoryFailureKind8616,
    IRMemoryAccessKind8616,
)
from inertia.ir.logical_memory_resolution import (
    resolve_logical_memory_accesses_8616,
)
from inertia.ir.vex_import import build_x86_16_ir_function_artifact

FUNCTION_ADDR = 0x1000
BLOCK_ADDR = 0x1000


def logical_address(space: MemSpace, offset: int, size: int) -> IRAddress:
    """Build one stable segmented address for resolver fixtures."""
    return IRAddress(
        space=space,
        offset=offset,
        size=size,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )


def memory_instruction(
    kind: IRMemoryAccessKind8616,
    *,
    insn_addr: int = BLOCK_ADDR,
    space: MemSpace = MemSpace.DS,
    offset: int = 0x2000,
    size: int = 2,
    ordinal: int = 0,
) -> IRInstr:
    """Build one typed raw LOAD or STORE at an exact machine instruction."""
    address = logical_address(space, offset, size)
    if kind is IRMemoryAccessKind8616.READ:
        return IRInstr(
            "LOAD",
            IRValue(MemSpace.TMP, name=f"load_{insn_addr:x}_{ordinal}", size=size),
            (address,),
            size=size,
            addr=insn_addr,
        )
    assert kind is IRMemoryAccessKind8616.WRITE
    return IRInstr(
        "STORE",
        None,
        (address, IRValue(MemSpace.REG, name="ax", size=size)),
        size=size,
        addr=insn_addr,
    )


def logical_capture(
    kind: IRMemoryAccessKind8616,
    *,
    insn_addr: int = BLOCK_ADDR,
    space: MemSpace = MemSpace.DS,
    offset: int = 0x2000,
    size: int = 2,
    ordinal: int = 0,
) -> IRLogicalMemoryCaptureRecord8616:
    """Build one complete typed frontend capture for a machine operand."""
    return IRLogicalMemoryCaptureRecord8616(
        function_addr=FUNCTION_ADDR,
        block_addr=BLOCK_ADDR,
        insn_addr=insn_addr,
        access_ordinal=ordinal,
        kind=kind,
        address_bits=16,
        address=logical_address(space, offset, size),
    )


def resolve_logical_memory(
    instructions: tuple[IRInstr, ...],
    captures: tuple[IRLogicalMemoryCaptureRecord8616, ...],
) -> tuple[IRBlock, IRLogicalMemoryArtifact8616]:
    """Resolve one deterministic block while returning the unchanged raw IR."""
    block = IRBlock(BLOCK_ADDR, instructions)
    result = resolve_logical_memory_accesses_8616(
        FUNCTION_ADDR,
        (block,),
        captures,
    )
    return block, result


def lift_ir_artifact(code: bytes) -> IRFunctionArtifact:
    """Lift one real-mode blob through the public VEX artifact builder."""
    return lift_ir_artifact_with_blocks(code, (BLOCK_ADDR,), ())


def lift_ir_artifact_with_blocks(
    code: bytes,
    block_addrs: tuple[int, ...],
    edges: tuple[tuple[int, int], ...],
    *,
    prelift: bool = False,
) -> IRFunctionArtifact:
    """Lift a blob through an explicit possibly overlapping function graph."""
    project = angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": FUNCTION_ADDR,
            "entry_point": FUNCTION_ADDR,
        },
        auto_load_libs=False,
    )
    nodes = {address: SimpleNamespace(addr=address) for address in block_addrs}
    function = SimpleNamespace(
        addr=FUNCTION_ADDR,
        block_addrs_set=set(block_addrs),
        graph=SimpleNamespace(
            edges=tuple((nodes[source], nodes[target]) for source, target in edges)
        ),
        info={},
    )
    if prelift:
        for block_addr in block_addrs:
            _ = project.factory.block(block_addr, opt_level=0).vex
    return build_x86_16_ir_function_artifact(project, function)


def assert_closed_single_refusal(
    result: IRLogicalMemoryArtifact8616,
    expected: IRLogicalMemoryFailureKind8616,
) -> None:
    """Assert one captured candidate reached one typed refusal and closed counts."""
    assert result.closed
    assert result.accesses == ()
    assert len(result.refusals) == 1
    assert result.refusals[0].failure is expected
    assert result.stats.to_dict() == {
        "raw_fact_count": 1,
        "normalized_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 0,
        "failure_count": 1,
    }


__all__ = [
    "assert_closed_single_refusal",
    "lift_ir_artifact",
    "lift_ir_artifact_with_blocks",
    "logical_address",
    "logical_capture",
    "memory_instruction",
    "resolve_logical_memory",
]
