from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimStackVariable
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
from inertia.lowering.instruction_bp_stack_access import (
    build_instruction_bp_stack_access_index_8616,
)
from inertia.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)
from inertia.lowering.stack_word_load_materialization import (
    materialize_stack_word_load_recompositions_8616,
)

from inertia.alias.stack_memory_ssa import (
    build_x86_16_stack_memory_ssa_alias_artifact,
)


class _Codegen:
    def __init__(self, source: object) -> None:
        self.project = SimpleNamespace(arch=Arch86_16())
        self._inertia_stack_memory_ssa_alias_artifact = source
        self.cstyle_null_cmp = False
        self._idx = 0

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _stack_address(offset: int, size: int) -> IRAddress:
    return IRAddress(
        MemSpace.SS,
        base=("bp",),
        offset=offset,
        size=size,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )


def _unknown_call_word_read_alias_artifact():
    low_address = _stack_address(4, 1)
    high_address = _stack_address(5, 1)
    word_address = _stack_address(4, 2)
    logical = IRLogicalMemoryArtifact8616(
        0x1000,
        (
            IRLogicalMemoryAccess8616(
                IRLogicalMemoryAccessKey8616(0x1000, 0x1000, 0x1000, 0),
                IRMemoryAccessKind8616.READ,
                word_address,
                16,
                (
                    IRMemoryExecutionSlice8616(
                        0x1000, 0, 0x1000, 0, low_address
                    ),
                    IRMemoryExecutionSlice8616(
                        0x1000, 1, 0x1000, 1, high_address
                    ),
                ),
            ),
        ),
        (),
        IRLogicalMemoryStats8616(1, 1, 1, 1, 0),
    )
    function = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1000,
                instrs=(
                    IRInstr(
                        "LOAD",
                        IRValue(MemSpace.TMP, name="low", size=1),
                        (low_address,),
                        size=1,
                        addr=0x1000,
                    ),
                    IRInstr(
                        "LOAD",
                        IRValue(MemSpace.TMP, name="high", size=1),
                        (high_address,),
                        size=1,
                        addr=0x1000,
                    ),
                    IRInstr(
                        "CALL",
                        None,
                        (IRValue(MemSpace.CONST, const=0x2000, size=2),),
                        addr=0x1003,
                    ),
                ),
            ),
        ),
        logical_memory=logical,
    )
    return build_x86_16_stack_memory_ssa_alias_artifact(
        build_x86_16_function_ssa(function)
    )


def test_pre_call_logical_word_keeps_alias_identity_when_composed_value_ssa_refuses() -> None:
    alias = _unknown_call_word_read_alias_artifact()

    assert tuple(
        (fact.kind.value, fact.address.offset, fact.address.size)
        for fact in alias.facts
    ) == (("load", 4, 1), ("load", 5, 1))
    assert alias.accesses == ()
    assert len(alias.logical_accesses) == 1
    assert alias.logical_accesses[0].storage.domain.stack_slot.width == 2
    assert alias.logical_stats.failure_count == 0
    assert alias.logical_storage_complete is True
    assert alias.logical_storage_stats.materialized_count == 1
    assert tuple(
        (identity.source.key.insn_addr, identity.address.offset, identity.address.size)
        for identity in alias.logical_storage_identities
    ) == ((0x1000, 4, 2),)

    index = build_instruction_bp_stack_access_index_8616(alias)
    assert tuple(index.by_instruction_addr) == (0x1000,)
    assert tuple(
        (access.displacement, access.size, access.evidence.value)
        for access in index.by_instruction_addr[0x1000]
    ) == (
        (4, 1, "execution_slice"),
        (4, 2, "logical_access"),
        (5, 1, "execution_slice"),
    )


def test_alias_identity_collapses_adjacent_byte_variables_to_word_owner() -> None:
    alias = _unknown_call_word_read_alias_artifact()
    codegen = _Codegen(alias)
    low_variable = SimStackVariable(4, 2, base="bp", name="x")
    high_variable = SimStackVariable(5, 1, base="bp", name="local_5")
    low = structured_c.CVariable(
        low_variable,
        variable_type=SimTypeShort(False).with_arch(codegen.project.arch),
        codegen=codegen,
    )
    high = structured_c.CVariable(
        high_variable,
        variable_type=SimTypeChar(False).with_arch(codegen.project.arch),
        codegen=codegen,
    )
    root = structured_c.CBinaryOp(
        "Or",
        low,
        structured_c.CBinaryOp(
            "Shl",
            high,
            structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x1000},
    )

    result = materialize_stack_word_load_recompositions_8616(codegen, root)

    assert result.root is low
    assert result.artifact.complete is True
    assert result.artifact.stats.raw_fact_count == 1
    assert result.artifact.stats.materialized_count == 1
    assert result.artifact.refusals == ()


def test_logical_word_identity_collapses_same_canonical_argument_views() -> None:
    alias = _unknown_call_word_read_alias_artifact()
    codegen = _Codegen(alias)
    variable = SimStackVariable(2, 2, base="bp", name="arg_4")
    owner = structured_c.CVariable(
        variable,
        variable_type=SimTypeShort(False).with_arch(codegen.project.arch),
        codegen=codegen,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=variable,
        cvar=owner,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
    )
    root = structured_c.CBinaryOp(
        "Or",
        owner,
        structured_c.CBinaryOp(
            "Mul",
            owner,
            structured_c.CConstant(0x100, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    result = materialize_stack_word_load_recompositions_8616(codegen, root)

    assert result.root is owner
    assert result.artifact.complete is True
    assert result.artifact.stats.materialized_count == 1
    assert result.artifact.refusals == ()
