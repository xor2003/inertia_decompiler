from inertia.ir.core import (
    AddressStatus,
    IRAddress,
    IRBinaryValue,
    IRBlock,
    IRCallStackEffect8616,
    IRCondition,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.ssa import build_x86_16_block_local_ssa
from inertia.ir.ssa_function import build_x86_16_function_ssa


def test_block_local_ssa_versions_register_defs_monotonically():
    block = IRBlock(
        addr=0x1000,
        instrs=(
            IRInstr("MOV", IRValue(MemSpace.REG, name="ax", size=2), (IRValue(MemSpace.CONST, const=1),), size=2),
            IRInstr(
                "MOV", IRValue(MemSpace.REG, name="ax", size=2), (IRValue(MemSpace.REG, name="ax", size=2),), size=2
            ),
        ),
    )

    ssa = build_x86_16_block_local_ssa(block)

    assert [binding.version for binding in ssa.bindings] == [0, 1]
    assert ssa.instrs[1].args[0].version == 0
    assert ssa.instrs[1].dst.version == 1


def test_block_local_ssa_preserves_register_version_captured_by_vex_temporary() -> None:
    block = IRBlock(
        addr=0x1000,
        instrs=(
            IRInstr(
                "MOV",
                IRValue(MemSpace.TMP, name="t0", size=2, source_tmp=0),
                (IRValue(MemSpace.REG, name="ax", size=2),),
                size=2,
            ),
            IRInstr(
                "MOV",
                IRValue(MemSpace.REG, name="ax", size=2),
                (IRValue(MemSpace.CONST, const=1, size=2),),
                size=2,
            ),
            IRInstr(
                "MOV",
                IRValue(MemSpace.TMP, name="t1", size=2, source_tmp=1),
                (IRValue(MemSpace.REG, name="ax", size=2, source_tmp=0),),
                size=2,
            ),
        ),
    )

    ssa = build_x86_16_block_local_ssa(block)

    first_read = ssa.instrs[0].args[0]
    captured_read = ssa.instrs[2].args[0]
    assert isinstance(first_read, IRValue)
    assert isinstance(captured_read, IRValue)
    assert first_read.version == captured_read.version == 0
    assert ssa.instrs[1].dst is not None
    assert ssa.instrs[1].dst.version == 1


def test_block_local_ssa_preserves_nested_value_and_condition_provenance():
    indexed_value = IRValue(
        MemSpace.TMP,
        name="carry",
        size=1,
        expr=("carry_input",),
        index=IRBinaryValue(
            "add",
            IRValue(MemSpace.REG, name="si", size=2),
            IRValue(MemSpace.CONST, const=2, size=2),
            size=2,
        ),
        memory_access_size=1,
        memory_access_insn=0x1002,
        source_tmp=73,
    )
    condition = IRCondition(
        "ult",
        (
            IRBinaryValue(
                "add",
                IRValue(MemSpace.REG, name="ax", size=2),
                indexed_value,
                size=2,
            ),
            IRValue(MemSpace.CONST, const=0x100, size=2),
        ),
        expr=("carry_compare",),
        width_bits=16,
    )
    block = IRBlock(
        addr=0x1000,
        instrs=(
            IRInstr("MOV", IRValue(MemSpace.REG, name="si", size=2), (IRValue(MemSpace.CONST, const=1),)),
            IRInstr("MOV", IRValue(MemSpace.REG, name="ax", size=2), (IRValue(MemSpace.CONST, const=2),)),
            IRInstr("CJMP", None, (condition, IRValue(MemSpace.CONST, const=0x1010, size=2))),
        ),
    )

    ssa = build_x86_16_block_local_ssa(block)

    rewritten_condition = ssa.instrs[2].args[0]
    assert isinstance(rewritten_condition, IRCondition)
    assert rewritten_condition.width_bits == 16
    assert rewritten_condition.expr == ("carry_compare",)
    rewritten_sum = rewritten_condition.args[0]
    assert isinstance(rewritten_sum, IRBinaryValue)
    assert isinstance(rewritten_sum.lhs, IRValue)
    assert rewritten_sum.lhs.version == 0
    rewritten_carry = rewritten_sum.rhs
    assert isinstance(rewritten_carry, IRValue)
    assert rewritten_carry.source_tmp == 73
    assert rewritten_carry.memory_access_size == 1
    assert rewritten_carry.memory_access_insn == 0x1002
    assert rewritten_carry.expr == ("carry_input",)
    assert isinstance(rewritten_carry.index, IRBinaryValue)
    assert isinstance(rewritten_carry.index.lhs, IRValue)
    assert rewritten_carry.index.lhs.version == 0


def test_function_ssa_builds_phi_node_at_cfg_join():
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1000,
                successor_addrs=(0x1020, 0x1010),
                instrs=(
                    IRInstr(
                        "MOV", IRValue(MemSpace.REG, name="ax", size=2), (IRValue(MemSpace.CONST, const=1),), size=2
                    ),
                ),
            ),
            IRBlock(
                addr=0x1010,
                successor_addrs=(0x1020,),
                instrs=(
                    IRInstr(
                        "MOV", IRValue(MemSpace.REG, name="ax", size=2), (IRValue(MemSpace.CONST, const=2),), size=2
                    ),
                ),
            ),
            IRBlock(addr=0x1020, instrs=()),
        ),
    )

    function_ssa = build_x86_16_function_ssa(artifact)

    assert function_ssa.summary["phi_node_count"] == 1
    assert function_ssa.predecessor_map[0x1020] == (0x1000, 0x1010)
    phi = function_ssa.phi_nodes[0]
    assert phi.block_addr == 0x1020
    assert phi.target.name == "ax"
    assert [item.source_block_addr for item in phi.incoming] == [0x1000, 0x1010]


def _bp_slot(offset: int, size: int) -> IRAddress:
    return IRAddress(
        MemSpace.SS,
        base=("bp",),
        offset=offset,
        size=size,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.DEFAULTED,
    )


def test_function_memory_ssa_versions_exact_bp_range_across_branch_join():
    slot = _bp_slot(-2, 2)
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(addr=0x1000, successor_addrs=(0x1010, 0x1020)),
            IRBlock(
                addr=0x1010,
                successor_addrs=(0x1030,),
                instrs=(IRInstr("STORE", None, (slot, IRValue(MemSpace.CONST, const=1, size=2)), size=2),),
            ),
            IRBlock(
                addr=0x1020,
                successor_addrs=(0x1030,),
                instrs=(IRInstr("STORE", None, (slot, IRValue(MemSpace.CONST, const=2, size=2)), size=2),),
            ),
            IRBlock(
                addr=0x1030,
                instrs=(IRInstr("LOAD", IRValue(MemSpace.REG, name="ax", size=2), (slot,), size=2),),
            ),
        ),
    )

    function_ssa = build_x86_16_function_ssa(artifact)

    assert function_ssa.memory_stats.complete is True
    assert function_ssa.memory_stats.raw_fact_count == 3
    assert [binding.address.version for binding in function_ssa.memory_bindings] == [1, 2]
    assert len(function_ssa.memory_phi_nodes) == 1
    phi = function_ssa.memory_phi_nodes[0]
    assert phi.block_addr == 0x1030
    assert phi.target.version == 3
    assert [item.address.version for item in phi.incoming] == [1, 2]
    load_address = function_ssa.blocks[-1].instrs[0].args[0]
    assert isinstance(load_address, IRAddress)
    assert load_address.version == phi.target.version


def test_function_memory_ssa_refuses_unproven_sp_relative_range():
    unknown_sp = IRAddress(
        MemSpace.SS,
        base=("sp",),
        offset=2,
        size=2,
        status=AddressStatus.PROVISIONAL,
        segment_origin=SegmentOrigin.DEFAULTED,
    )
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1000,
                instrs=(IRInstr("LOAD", IRValue(MemSpace.REG, name="ax", size=2), (unknown_sp,), size=2),),
            ),
        ),
    )

    function_ssa = build_x86_16_function_ssa(artifact)

    assert function_ssa.memory_stats.complete is True
    assert function_ssa.memory_stats.failure_count == 1
    assert function_ssa.memory_refusals[0].kind == "unproven_stack_range"
    load_address = function_ssa.blocks[0].instrs[0].args[0]
    assert isinstance(load_address, IRAddress)
    assert load_address.version is None


def test_function_memory_ssa_refuses_unknown_call_stack_effect():
    slot = _bp_slot(-2, 2)
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1000,
                instrs=(
                    IRInstr("STORE", None, (slot, IRValue(MemSpace.CONST, const=1, size=2)), size=2),
                    IRInstr("CALL", None, (IRValue(MemSpace.CONST, const=0x2000, size=2),)),
                    IRInstr("LOAD", IRValue(MemSpace.REG, name="ax", size=2), (slot,), size=2),
                ),
            ),
        ),
    )

    function_ssa = build_x86_16_function_ssa(artifact)

    assert function_ssa.memory_stats.complete is True
    assert function_ssa.memory_stats.failure_count == 2
    assert function_ssa.memory_bindings == ()
    assert {refusal.kind for refusal in function_ssa.memory_refusals} == {"unknown_call_stack_effect"}


def test_function_memory_ssa_preserves_range_only_from_complete_call_effect():
    slot = _bp_slot(-2, 2)
    call_effect = IRCallStackEffect8616(
        net_stack_delta=0,
        preserved_ranges=(slot,),
        complete=True,
    )
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1000,
                instrs=(
                    IRInstr("STORE", None, (slot, IRValue(MemSpace.CONST, const=1, size=2)), size=2),
                    IRInstr(
                        "CALL",
                        None,
                        (IRValue(MemSpace.CONST, const=0x2000, size=2),),
                        call_stack_effect=call_effect,
                    ),
                    IRInstr("LOAD", IRValue(MemSpace.REG, name="ax", size=2), (slot,), size=2),
                ),
            ),
        ),
    )

    function_ssa = build_x86_16_function_ssa(artifact)

    assert function_ssa.memory_stats.complete is True
    assert function_ssa.memory_stats.failure_count == 0
    assert len(function_ssa.memory_bindings) == 1
    store_address = function_ssa.blocks[0].instrs[0].args[0]
    load_address = function_ssa.blocks[0].instrs[2].args[0]
    assert isinstance(store_address, IRAddress)
    assert isinstance(load_address, IRAddress)
    assert store_address.version == load_address.version == 1
