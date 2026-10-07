from __future__ import annotations

import io
from dataclasses import replace
from types import SimpleNamespace

import angr
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir import (
    AddressStatus,
    IndexedAddressAccessKind8616,
    IndexedAddressFailureKind8616,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRLogicalMemoryAccess8616,
    IRMemoryAccessKind8616,
    IRValue,
    MemSpace,
    SegmentOrigin,
    build_x86_16_function_ssa,
    collect_indexed_address_evidence_8616,
)
from inertia.ir.vex_condition_transport import (
    VexConditionTransportNormalizer8616,
    build_vex_condition_transport_layout_8616,
)
from inertia.ir.vex_import import build_x86_16_ir_function_artifact


def _lift(code: bytes) -> IRFunctionArtifact:
    project = angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    return build_x86_16_ir_function_artifact(project, function)


def _memory_instructions_at(artifact: IRFunctionArtifact, address: int) -> tuple[IRInstr, ...]:
    return tuple(
        instruction
        for instruction in artifact.blocks[0].instrs
        if instruction.addr == address and instruction.op in {"LOAD", "STORE"}
    )


def _memory_address(instruction: IRInstr) -> IRAddress:
    address = instruction.args[0]
    assert isinstance(address, IRAddress)
    return address


def _logical_accesses_at(
    artifact: IRFunctionArtifact,
    address: int,
) -> tuple[IRLogicalMemoryAccess8616, ...]:
    logical = artifact.logical_memory
    assert logical is not None and logical.closed
    return tuple(item for item in logical.accesses if item.key.insn_addr == address)


def test_push_indexed_word_is_one_typed_machine_load() -> None:
    artifact = _lift(bytes.fromhex("55 89 e5 83 ec 02 c7 46 fe 01 00 8b 5e fe ff b7 36 01 c9 c3"))
    evidence = collect_indexed_address_evidence_8616(build_x86_16_function_ssa(artifact))
    memory_ops = _memory_instructions_at(artifact, 0x100E)
    loads = tuple(item for item in memory_ops if item.op == "LOAD")
    stack_stores = tuple(item for item in memory_ops if item.op == "STORE")
    indexed_load, stack_store = _logical_accesses_at(artifact, 0x100E)

    assert len(loads) == len(stack_stores) == 2
    assert all(item.size == _memory_address(item).size == 1 for item in memory_ops)
    assert indexed_load.kind is IRMemoryAccessKind8616.READ
    assert indexed_load.address.space is MemSpace.DS and indexed_load.address.size == 2
    assert stack_store.kind is IRMemoryAccessKind8616.WRITE
    assert stack_store.address.space is MemSpace.SS and stack_store.address.size == 2
    assert evidence.closed
    assert evidence.refusals == ()
    assert evidence.stats.raw_fact_count == 2
    assert evidence.stats.normalized_fact_count == 1
    assert evidence.stats.coalesced_fact_count == 1
    (fact,) = evidence.facts
    assert fact.kind is IndexedAddressAccessKind8616.LOAD
    assert fact.address.space is MemSpace.DS
    assert fact.address.offset == 0x136
    assert fact.address.size == 2
    assert fact.index_source.space is MemSpace.SS
    assert fact.index_source.base == ("bp",)
    assert fact.index_source.offset == -2
    assert fact.index_source.size == 2
    # The PUSH captures BX before tracing its earlier word-load definition.
    assert fact.definition_path[0].instr_addr == 0x100E
    assert all(site.instr_addr == 0x100B for site in fact.definition_path[1:])
    assert tuple(site.op for site in fact.definition_path) == (
        "MOV",
        "MOV",
        "Iop_Or16",
        "MOV",
        "LOAD",
        "Iop_Shl16",
        "MOV",
        "LOAD",
    )


def test_byte_immediate_store_uses_vex_constant_width() -> None:
    artifact = _lift(bytes.fromhex("c6 87 f1 08 07 c3"))

    (store,) = _memory_instructions_at(artifact, 0x1000)

    assert store.op == "STORE"
    assert store.size == 1
    assert _memory_address(store).size == 1
    assert store.args[1].size == 1


def test_indexed_word_store_is_one_typed_machine_store() -> None:
    artifact = _lift(bytes.fromhex("55 89 e5 83 ec 02 c7 46 fe 01 00 8b 5e fe 89 87 4c 0b c9 c3"))
    evidence = collect_indexed_address_evidence_8616(build_x86_16_function_ssa(artifact))
    stores = _memory_instructions_at(artifact, 0x100E)
    (logical_store,) = _logical_accesses_at(artifact, 0x100E)

    assert len(stores) == 2
    assert all(item.op == "STORE" and item.size == _memory_address(item).size == 1 for item in stores)
    assert logical_store.kind is IRMemoryAccessKind8616.WRITE
    assert logical_store.address.space is MemSpace.DS
    assert logical_store.address.size == 2
    assert evidence.closed
    assert evidence.refusals == ()
    assert evidence.stats.raw_fact_count == 2
    assert evidence.stats.normalized_fact_count == 1
    assert evidence.stats.coalesced_fact_count == 1
    (fact,) = evidence.facts
    assert fact.kind is IndexedAddressAccessKind8616.STORE
    assert fact.address.space is MemSpace.DS
    assert fact.address.offset == 0xB4C
    assert fact.address.size == 2


def test_indexed_word_value_refuses_without_logical_memory_evidence() -> None:
    artifact = build_x86_16_function_ssa(
        _lift(bytes.fromhex("55 89 e5 83 ec 02 c7 46 fe 01 00 8b 5e fe ff b7 36 01 c9 c3"))
    )

    evidence = collect_indexed_address_evidence_8616(
        replace(artifact, logical_memory=None)
    )

    assert evidence.closed
    assert evidence.facts == ()
    assert len(evidence.refusals) == 1
    assert (
        evidence.refusals[0].failure
        is IndexedAddressFailureKind8616.INDEX_SOURCE_UNPROVEN
    )
    assert evidence.stats.raw_fact_count == 2
    assert evidence.stats.normalized_fact_count == 1
    assert evidence.stats.coalesced_fact_count == 1


def test_indexed_word_value_refuses_mismatched_logical_execution_slice() -> None:
    artifact = build_x86_16_function_ssa(
        _lift(bytes.fromhex("55 89 e5 83 ec 02 c7 46 fe 01 00 8b 5e fe ff b7 36 01 c9 c3"))
    )
    logical = artifact.logical_memory
    assert logical is not None and logical.closed
    source_read = next(
        access
        for access in logical.accesses
        if access.kind is IRMemoryAccessKind8616.READ
        and access.key.insn_addr == 0x100B
        and access.address.space is MemSpace.SS
        and access.address.size == 2
    )
    low_slice, high_slice = source_read.execution_slices
    mismatched_read = replace(
        source_read,
        execution_slices=(
            low_slice,
            replace(high_slice, instr_index=high_slice.instr_index + 1),
        ),
    )
    mismatched_logical = replace(
        logical,
        accesses=tuple(
            mismatched_read if access.key == source_read.key else access
            for access in logical.accesses
        ),
    )
    assert mismatched_read.complete and mismatched_logical.closed

    evidence = collect_indexed_address_evidence_8616(
        replace(artifact, logical_memory=mismatched_logical)
    )

    assert evidence.closed
    assert evidence.facts == ()
    assert len(evidence.refusals) == 1
    assert (
        evidence.refusals[0].failure
        is IndexedAddressFailureKind8616.INDEX_SOURCE_UNPROVEN
    )


def test_noncontiguous_same_instruction_micro_ops_refuse_normalization() -> None:
    index = IRValue(MemSpace.REG, name="bx", size=2)
    addresses = tuple(
        IRAddress(
            MemSpace.DS,
            base=("bx",),
            offset=offset,
            size=1,
            status=AddressStatus.STABLE,
            segment_origin=SegmentOrigin.PROVEN,
            base_values=(index,),
        )
        for offset in (0x200, 0x202)
    )
    artifact = build_x86_16_function_ssa(
        IRFunctionArtifact(
            0x1000,
            (
                IRBlock(
                    0x1000,
                    tuple(
                        IRInstr(
                            "LOAD",
                            IRValue(MemSpace.TMP, name=f"t{position}", size=1),
                            (address,),
                            size=1,
                            addr=0x1000,
                        )
                        for position, address in enumerate(addresses)
                    ),
                ),
            ),
        )
    )

    evidence = collect_indexed_address_evidence_8616(artifact)

    assert evidence.closed
    assert evidence.facts == ()
    assert evidence.stats.raw_fact_count == 2
    assert evidence.stats.normalized_fact_count == 1
    assert evidence.stats.coalesced_fact_count == 1
    assert evidence.refusals[0].failure is IndexedAddressFailureKind8616.ACCESS_MICRO_OP_CONFLICT


def test_ir_import_removes_exact_jcc_transport_load() -> None:
    artifact = _lift(bytes.fromhex("8b 5e fe d1 e3 38 87 4e 0b 7c 02 90 90 c3"))

    indexed_loads = tuple(
        instruction
        for instruction in artifact.blocks[0].instrs
        if instruction.op == "LOAD"
        and _memory_address(instruction).space is MemSpace.DS
        and _memory_address(instruction).base == ("bx",)
    )

    assert len(indexed_loads) == 1
    assert indexed_loads[0].addr == 0x1005
    assert indexed_loads[0].size == 1
    assert _memory_address(indexed_loads[0]).offset == 0xB4E
    assert _memory_instructions_at(artifact, 0x1009) == ()
    assert artifact.summary["condition_transport_raw_fact_count"] == 1
    assert artifact.summary["condition_transport_normalized_fact_count"] == 1
    assert artifact.summary["condition_transport_classified_fact_count"] == 1
    assert artifact.summary["condition_transport_materialized_count"] == 1
    assert artifact.summary["condition_transport_failure_count"] == 0


def test_jcc_transport_refuses_load_not_used_by_exit_guard() -> None:
    load_expr = SimpleNamespace(tag="Iex_Load", args=())
    statements = (
        SimpleNamespace(tag="Ist_IMark", addr=0x1005),
        SimpleNamespace(tag="Ist_WrTmp", tmp=1, data=load_expr),
        SimpleNamespace(tag="Ist_IMark", addr=0x1009),
        SimpleNamespace(tag="Ist_WrTmp", tmp=2, data=load_expr),
        SimpleNamespace(
            tag="Ist_Exit",
            guard=SimpleNamespace(tag="Iex_Const", args=()),
        ),
    )
    layout = build_vex_condition_transport_layout_8616(statements)
    normalizer = VexConditionTransportNormalizer8616(layout)
    address = IRAddress(MemSpace.DS, base=("bx",), offset=0x20, size=1)
    predecessor = IRInstr("LOAD", None, (address,), size=1, addr=0x1005)
    branch_load = IRInstr("LOAD", None, (address,), size=1, addr=0x1009)

    assert normalizer.observe_load(
        predecessor,
        IRValue(MemSpace.TMP, name="load_t1", size=1),
        1,
    ) is None
    assert normalizer.observe_load(
        branch_load,
        IRValue(MemSpace.TMP, name="load_t2", size=1),
        2,
    ) is None
    assert normalizer.stats().raw_fact_count == 0
