from __future__ import annotations

from types import SimpleNamespace

from angr.sim_variable import SimStackVariable
from inertia.ir.analysis.stack_frame_ir import (
    BPFrameCoordinateEvidence8616,
    FrameAccessArtifact,
    FrameCoordinateStats8616,
    FrameCoordinateStatus8616,
)
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
from inertia.ir.ssa_function import build_x86_16_function_ssa
from inertia.lowering.stack_memory_ssa import (
    StackMemorySSALoweringRefusalKind8616,
    lower_x86_16_stack_memory_ssa_alias_artifact,
)
from inertia.lowering.stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    record_stack_variable_coordinate_projection_8616,
    stack_variable_coordinate_registry_8616,
)

from inertia.alias.stack_memory_ssa import (
    StackMemoryAliasRefusalKind8616,
    build_x86_16_stack_memory_ssa_alias_artifact,
)
from inertia.alias.stack_memory_ssa_contracts import (
    StackMemorySSAAliasArtifact8616,
)
from inertia.widening.stack_memory_objects import (
    build_x86_16_stack_memory_object_widening_artifact,
)


def _address(space: MemSpace, base: str, offset: int) -> IRAddress:
    return IRAddress(
        space,
        base=(base,),
        offset=offset,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )


class _Codegen:
    def __init__(self, source: StackMemorySSAAliasArtifact8616) -> None:
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cfunc = SimpleNamespace(
            addr=source.function_addr,
            variables_in_use={},
            unified_local_vars={},
            arg_list=(),
            sort_local_vars=lambda: None,
        )
        self._inertia_stack_memory_ssa_alias_artifact = source
        if source.accesses:
            self._inertia_stack_memory_object_widening_artifact = (
                build_x86_16_stack_memory_object_widening_artifact(source)
            )
        self._inertia_vex_ir_frame = FrameAccessArtifact(
            bp_coordinate=BPFrameCoordinateEvidence8616(
                status=FrameCoordinateStatus8616.PROVEN,
                bp_entry_sp_delta=-2,
                detail="safety fixture",
                stats=FrameCoordinateStats8616(1, 1, 1, 1, 0),
            )
        )
        self._index = 0

    def next_idx(self, _name: str) -> int:
        self._index += 1
        return self._index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def test_one_branch_sp_change_refuses_join_stack_materialization() -> None:
    sp_slot = _address(MemSpace.SS, "sp", 0)
    function_ssa = build_x86_16_function_ssa(
        IRFunctionArtifact(
            function_addr=0x1000,
            blocks=(
                IRBlock(addr=0x1000, successor_addrs=(0x1010, 0x1020)),
                IRBlock(
                    addr=0x1010,
                    successor_addrs=(0x1030,),
                    instrs=(
                        IRInstr(
                            "MOV",
                            IRValue(MemSpace.REG, name="sp", size=2),
                            (IRValue(MemSpace.REG, name="sp", offset=-2, size=2),),
                            size=2,
                        ),
                    ),
                ),
                IRBlock(addr=0x1020, successor_addrs=(0x1030,)),
                IRBlock(
                    addr=0x1030,
                    instrs=(
                        IRInstr(
                            "LOAD",
                            IRValue(MemSpace.REG, name="ax", size=2),
                            (sp_slot,),
                            size=2,
                        ),
                    ),
                ),
            ),
        )
    )

    source = build_x86_16_stack_memory_ssa_alias_artifact(function_ssa)
    codegen = _Codegen(source)
    existing_variable = SimStackVariable(-2, 1, base="bp", name="existing")
    existing_cvar = SimpleNamespace(variable=existing_variable)
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=existing_variable,
        cvar=existing_cvar,
        bp_offset=-2,
        entry_sp_offset=-2,
        size=1,
    )
    lowered = lower_x86_16_stack_memory_ssa_alias_artifact(codegen)

    assert function_ssa.predecessor_map[0x1030] == (0x1010, 0x1020)
    assert function_ssa.memory_bindings == ()
    assert [refusal.kind for refusal in function_ssa.memory_refusals] == [
        "unproven_stack_range"
    ]
    assert source.facts == source.accesses == ()
    assert (
        source.refusals[0].kind
        is StackMemoryAliasRefusalKind8616.UPSTREAM_MEMORY_REFUSAL
    )
    assert lowered is not None and lowered.complete is True
    assert lowered.candidates == ()
    assert (
        lowered.refusals[0].kind
        is StackMemorySSALoweringRefusalKind8616.SOURCE_ALIAS_REFUSAL
    )
    assert codegen.cfunc.variables_in_use == {}
    projection = stack_variable_coordinate_registry_8616(codegen).for_variable(
        existing_variable
    )
    assert projection is not None and projection.cvar is existing_cvar


def test_equal_offset_ds_and_ss_accesses_materialize_only_ss_owner() -> None:
    ss_slot = _address(MemSpace.SS, "bp", -2)
    ds_word = _address(MemSpace.DS, "bp", -2)
    function_ssa = build_x86_16_function_ssa(
        IRFunctionArtifact(
            function_addr=0x1000,
            blocks=(
                IRBlock(
                    addr=0x1000,
                    instrs=(
                        IRInstr(
                            "STORE",
                            None,
                            (ss_slot, IRValue(MemSpace.CONST, const=1, size=2)),
                            size=2,
                        ),
                        IRInstr(
                            "STORE",
                            None,
                            (ds_word, IRValue(MemSpace.CONST, const=2, size=2)),
                            size=2,
                        ),
                        IRInstr(
                            "LOAD",
                            IRValue(MemSpace.REG, name="ax", size=2),
                            (ss_slot,),
                            size=2,
                        ),
                        IRInstr(
                            "LOAD",
                            IRValue(MemSpace.REG, name="bx", size=2),
                            (ds_word,),
                            size=2,
                        ),
                    ),
                ),
            ),
        )
    )

    source = build_x86_16_stack_memory_ssa_alias_artifact(function_ssa)
    codegen = _Codegen(source)
    lowered = lower_x86_16_stack_memory_ssa_alias_artifact(codegen)

    assert function_ssa.memory_refusals == ()
    assert [
        (item.block_addr, item.instr_index) for item in function_ssa.memory_accesses
    ] == [(0x1000, 0), (0x1000, 2)]
    ds_addresses = (
        function_ssa.blocks[0].instrs[1].args[0],
        function_ssa.blocks[0].instrs[3].args[0],
    )
    assert all(
        isinstance(address, IRAddress)
        and address.space is MemSpace.DS
        and address.version is None
        for address in ds_addresses
    )
    assert len(source.facts) == 2
    assert all(fact.address.space is MemSpace.SS for fact in source.facts)
    assert source.refusals == ()
    assert lowered is not None and lowered.complete is True
    assert len(lowered.candidates) == 1
    assert lowered.candidates[0].address.space is MemSpace.SS
    assert lowered.candidates[0].address.offset == -2
    stack_variables = [
        variable
        for variable in codegen.cfunc.variables_in_use
        if isinstance(variable, SimStackVariable)
    ]
    assert [(variable.base, variable.offset, variable.size) for variable in stack_variables] == [
        ("bp", -4, 2)
    ]
    assert machine_bp_offset_for_stack_variable_8616(codegen, stack_variables[0]) == -2
