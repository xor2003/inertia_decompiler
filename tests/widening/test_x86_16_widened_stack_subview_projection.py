from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.ir.analysis.stack_frame_ir import (
    BPFrameCoordinateEvidence8616,
    FrameAccessArtifact,
    FrameCoordinateStats8616,
    FrameCoordinateStatus8616,
)
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.core import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.logical_memory_contracts import (
    IRLogicalMemoryAccess8616,
    IRLogicalMemoryAccessKey8616,
    IRLogicalMemoryArtifact8616,
    IRLogicalMemoryStats8616,
    IRMemoryAccessKind8616,
    IRMemoryExecutionSlice8616,
)
from inertia.ir.ssa_function import build_x86_16_function_ssa

from inertia.alias.stack_memory_ssa import (
    build_x86_16_stack_memory_ssa_alias_artifact,
)
from inertia.widening.stack_memory_objects import (
    build_x86_16_stack_memory_object_widening_artifact,
)
from inertia.widening.stack_subview_projection import (
    materialize_contained_stack_subviews_8616,
)

FUNCTION_ADDR = 0x4010


class _DummyCodegen:
    def __init__(self) -> None:
        self._idx = 0
        self.cfunc: SimpleNamespace | None = None
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_node_idx(self) -> int:
        self._idx += 1
        return self._idx

    def next_ident(self, name: str) -> str:
        return name


def _bp_slot(offset: int, size: int) -> IRAddress:
    return IRAddress(
        MemSpace.SS,
        base=("bp",),
        offset=offset,
        size=size,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.DEFAULTED,
    )


def _load(offset: int, size: int, register: str, insn_addr: int) -> IRInstr:
    address = _bp_slot(offset, size)
    return IRInstr(
        "LOAD",
        IRValue(MemSpace.REG, name=register, size=size),
        (address,),
        size=size,
        addr=insn_addr,
    )


def _attach_alias_and_widening(
    codegen: _DummyCodegen,
    instructions: tuple[IRInstr, ...],
) -> None:
    function_ssa = build_x86_16_function_ssa(
        IRFunctionArtifact(
            function_addr=FUNCTION_ADDR,
            blocks=(IRBlock(addr=FUNCTION_ADDR, instrs=instructions),),
        )
    )
    block = function_ssa.blocks[0]
    grouped: dict[int, list[tuple[int, IRAddress]]] = {}
    for index, instruction in enumerate(block.instrs):
        address = instruction.args[0]
        if isinstance(instruction.addr, int) and isinstance(address, IRAddress):
            grouped.setdefault(instruction.addr, []).append((index, address))
    logical_accesses = tuple(
        IRLogicalMemoryAccess8616(
            IRLogicalMemoryAccessKey8616(
                FUNCTION_ADDR,
                block.addr,
                insn_addr,
                0,
            ),
            IRMemoryAccessKind8616.READ,
            replace(items[0][1], size=sum(address.size for _, address in items)),
            16,
            tuple(
                IRMemoryExecutionSlice8616(
                    block.addr,
                    index,
                    insn_addr,
                    byte_offset,
                    address,
                )
                for byte_offset, (index, address) in enumerate(items)
            ),
        )
        for insn_addr, items in sorted(grouped.items())
    )
    function_ssa = replace(
        function_ssa,
        logical_memory=IRLogicalMemoryArtifact8616(
            FUNCTION_ADDR,
            logical_accesses,
            (),
            IRLogicalMemoryStats8616(
                len(logical_accesses),
                len(logical_accesses),
                len(logical_accesses),
                len(logical_accesses),
                0,
            ),
        ),
    )
    source = build_x86_16_stack_memory_ssa_alias_artifact(function_ssa)
    codegen._inertia_stack_memory_ssa_alias_artifact = source
    codegen._inertia_vex_ir_frame = FrameAccessArtifact(
        bp_coordinate=BPFrameCoordinateEvidence8616(
            status=FrameCoordinateStatus8616.PROVEN,
            bp_entry_sp_delta=-2,
            detail="fixture entry-SP projection",
            stats=FrameCoordinateStats8616(1, 1, 1, 1, 0),
        )
    )
    codegen._inertia_stack_memory_object_widening_artifact = (
        build_x86_16_stack_memory_object_widening_artifact(source)
    )


def _stack_var(offset: int, size: int, name: str, codegen: _DummyCodegen) -> CVariable:
    return CVariable(
        SimStackVariable(offset, size, base="bp", name=name, region=FUNCTION_ADDR),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def test_alias_byte_read_projects_from_wider_structured_carrier() -> None:
    codegen = _DummyCodegen()
    owner = _stack_var(2, 2, "arg_4", codegen)
    widened_byte = _stack_var(5, 2, "local_5", codegen)
    destination = CVariable(SimpleNamespace(name="inertia_ax"), codegen=codegen)
    rhs = CBinaryOp(
        "Shr",
        widened_byte,
        CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    assignment = CAssignment(destination, rhs, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=FUNCTION_ADDR,
        statements=CStatements([assignment], codegen=codegen),
        variables_in_use={owner.variable: owner, widened_byte.variable: widened_byte},
    )
    _attach_alias_and_widening(
        codegen,
        (
            _load(4, 1, "al", 0x4010),
            _load(5, 1, "ah", 0x4010),
            _load(5, 1, "al", 0x4012),
        ),
    )

    assert materialize_contained_stack_subviews_8616(codegen) is True
    assert isinstance(assignment.rhs, CBinaryOp) and assignment.rhs.op == "Shr"
    projected = assignment.rhs.lhs
    assert isinstance(projected, CBinaryOp) and projected.op == "And"
    assert isinstance(projected.lhs, CBinaryOp) and projected.lhs.op == "Shr"
    stats = codegen._inertia_stack_subview_last_stats_8616
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_wider_structured_carrier_refuses_competing_exact_read() -> None:
    codegen = _DummyCodegen()
    owner = _stack_var(2, 2, "arg_4", codegen)
    widened_byte = _stack_var(5, 2, "local_5", codegen)
    destination = CVariable(SimpleNamespace(name="inertia_ax"), codegen=codegen)
    assignment = CAssignment(destination, widened_byte, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=FUNCTION_ADDR,
        statements=CStatements([assignment], codegen=codegen),
        variables_in_use={owner.variable: owner, widened_byte.variable: widened_byte},
    )
    _attach_alias_and_widening(
        codegen,
        (
            _load(4, 1, "al", 0x4010),
            _load(5, 1, "ah", 0x4010),
            _load(5, 1, "al", 0x4012),
            _load(5, 1, "dl", 0x4014),
            _load(6, 1, "dh", 0x4014),
        ),
    )

    assert materialize_contained_stack_subviews_8616(codegen) is False
    assert assignment.rhs is widened_byte
    assert codegen._inertia_stack_subview_last_stats_8616.failure_count == 1
