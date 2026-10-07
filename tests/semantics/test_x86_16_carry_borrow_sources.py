from __future__ import annotations

import io
from dataclasses import replace
from types import SimpleNamespace

import angr
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir import IRAddress, IRFunctionArtifact, IRInstr, MemSpace
from inertia.ir.logical_memory_contracts import (
    IRLogicalMemoryAccess8616,
    IRLogicalMemoryAccessKey8616,
    IRLogicalMemoryArtifact8616,
    IRLogicalMemoryFailureKind8616,
    IRLogicalMemoryRefusal8616,
    IRLogicalMemoryStats8616,
    IRMemoryAccessKind8616,
    IRMemoryExecutionSlice8616,
    empty_ir_logical_memory_artifact_8616,
    logical_memory_byte_offset_8616,
)
from inertia.ir.ssa_function import (
    SSAFunctionArtifact,
    build_x86_16_function_ssa,
)
from inertia.ir.vex_import import build_x86_16_ir_function_artifact
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401

from inertia.alias.carry_borrow_projection import (
    CarryBorrowAliasFailure8616,
    project_carry_borrow_aliases_8616,
)
from inertia.semantics.carry_borrow_contracts import (
    CarryBorrowEvidence8616,
    CarryBorrowOperandUse8616,
)
from inertia.semantics.carry_borrow_links import analyze_carry_borrow_links_8616
from inertia.semantics.carry_borrow_ssa import operand_use_8616
from inertia.widening.carry_borrow_values import widen_carry_borrow_values_8616


def _lift_ir(code: bytes) -> IRFunctionArtifact:
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


def _lift_ssa(code: bytes) -> SSAFunctionArtifact:
    return build_x86_16_function_ssa(_lift_ir(code))


def _ranges(addresses: tuple[IRAddress, ...]) -> tuple[tuple[int, int], ...]:
    return tuple((address.offset, address.size) for address in addresses)


def _logical_reads(
    artifact: SSAFunctionArtifact,
    offsets: tuple[int, ...],
) -> IRLogicalMemoryArtifact8616:
    block = artifact.blocks[0]
    loads = {
        address.offset: (index, instruction, address)
        for index, instruction in enumerate(block.instrs)
        if instruction.op == "LOAD"
        and instruction.args
        and isinstance((address := instruction.args[0]), IRAddress)
        and address.space is MemSpace.DS
    }
    accesses: list[IRLogicalMemoryAccess8616] = []
    for ordinal, offset in enumerate(offsets):
        low_index, low_instruction, low_address = loads[offset]
        high_index, high_instruction, high_address = loads[offset + 1]
        assert low_instruction.addr is not None
        assert high_instruction.addr == low_instruction.addr
        accesses.append(
            IRLogicalMemoryAccess8616(
                IRLogicalMemoryAccessKey8616(
                    artifact.function_addr,
                    block.addr,
                    low_instruction.addr,
                    ordinal,
                ),
                IRMemoryAccessKind8616.READ,
                replace(low_address, size=2),
                16,
                (
                    IRMemoryExecutionSlice8616(
                        block.addr,
                        low_index,
                        low_instruction.addr,
                        0,
                        low_address,
                    ),
                    IRMemoryExecutionSlice8616(
                        block.addr,
                        high_index,
                        high_instruction.addr,
                        1,
                        high_address,
                    ),
                ),
            )
        )
    count = len(accesses)
    return IRLogicalMemoryArtifact8616(
        artifact.function_addr,
        tuple(accesses),
        (),
        IRLogicalMemoryStats8616(count, count, count, count, 0),
    )


def _replace_link(
    evidence: CarryBorrowEvidence8616,
    **changes: object,
) -> CarryBorrowEvidence8616:
    resolution = evidence.resolutions[0]
    assert resolution.link is not None
    return replace(
        evidence,
        resolutions=(replace(resolution, link=replace(resolution.link, **changes)),),
    )


def _direct_word_use(use: CarryBorrowOperandUse8616) -> CarryBorrowOperandUse8616:
    assert use.definition is not None
    assert use.value.source_tmp is not None
    assert use.memory_word is not None
    logical_address = use.memory_word.logical_address
    load = replace(
        use.definition,
        instruction=IRInstr(
            "LOAD",
            use.value,
            (logical_address,),
            size=2,
            addr=use.definition.instruction.addr,
        ),
    )
    direct = operand_use_8616(use.value, {use.value.source_tmp: load}, None)
    assert direct is not None and direct.memory_word is not None
    return direct


def test_function_ssa_preserves_logical_memory_artifact() -> None:
    source = _lift_ir(bytes.fromhex("01 d8 11 ca c3"))
    logical_memory = empty_ir_logical_memory_artifact_8616(source.function_addr)

    artifact = build_x86_16_function_ssa(replace(source, logical_memory=logical_memory))

    assert artifact.logical_memory is logical_memory


def test_authoritative_logical_words_retain_exact_byte_load_sites() -> None:
    artifact = _lift_ssa(bytes.fromhex("03 06 00 20 13 16 02 20 c3"))
    logical_memory = _logical_reads(artifact, (0x2000, 0x2002))

    semantics = analyze_carry_borrow_links_8616(
        replace(artifact, logical_memory=logical_memory)
    )

    link = semantics.links[0]
    assert link.low_rhs.memory_word is not None
    assert link.high_rhs.memory_word is not None
    assert tuple(
        (item.address.offset, item.address.size)
        for item in link.low_rhs.memory_word.execution_loads
    ) == ((0x2000, 1), (0x2001, 1))
    assert tuple(
        (item.address.offset, item.address.size)
        for item in link.high_rhs.memory_word.execution_loads
    ) == ((0x2002, 1), (0x2003, 1))
    assert _ranges((link.low_rhs.memory_word.logical_address,)) == ((0x2000, 2),)
    assert _ranges((link.high_rhs.memory_word.logical_address,)) == ((0x2002, 2),)
    assert len(
        {
            (item.site.block_addr, item.site.instr_index)
            for item in link.low_rhs.memory_word.execution_loads
        }
    ) == 2


def test_direct_offset_word_wrap_is_retained_before_typed_alias_refusal() -> None:
    artifact = _lift_ssa(bytes.fromhex("03 06 ff ff 13 16 01 00 c3"))

    semantics = analyze_carry_borrow_links_8616(artifact)

    word = semantics.links[0].low_rhs.memory_word
    assert word is not None
    assert word.logical_address.offset == 0xFFFF
    assert word.logical_address.size == 2
    assert word.address_bits == 16
    execution_addresses = tuple(item.address for item in word.execution_loads)
    assert _ranges(execution_addresses) == ((-1, 1), (0, 1))
    assert tuple(
        logical_memory_byte_offset_8616(address, 0, word.address_bits)
        for address in execution_addresses
    ) == (
        0xFFFF,
        0x0000,
    )

    aliases = project_carry_borrow_aliases_8616(semantics)

    assert aliases.stats.raw_fact_count == aliases.stats.failure_count == 1
    assert (
        aliases.resolutions[0].failure
        is CarryBorrowAliasFailure8616.SOURCE_RANGE_WRAP_UNSUPPORTED
    )


def test_logical_word_mismatch_or_refusal_does_not_claim_raw_byte_shape() -> None:
    artifact = _lift_ssa(bytes.fromhex("03 06 00 20 13 16 02 20 c3"))
    logical_memory = _logical_reads(artifact, (0x2000, 0x2002))
    low_access, high_access = logical_memory.accesses
    low_execution, high_execution = low_access.execution_slices
    mismatched_low = replace(
        low_access,
        execution_slices=(
            low_execution,
            replace(high_execution, instr_index=high_execution.instr_index + 1),
        ),
    )
    mismatched = replace(
        logical_memory,
        accesses=(mismatched_low, high_access),
    )
    refused = IRLogicalMemoryArtifact8616(
        artifact.function_addr,
        (),
        (
            IRLogicalMemoryRefusal8616(
                artifact.function_addr,
                artifact.blocks[0].addr,
                low_access.key.insn_addr,
                low_access.key.access_ordinal,
                IRLogicalMemoryFailureKind8616.AMBIGUOUS_EXECUTION_SLICES,
                "test refusal",
            ),
        ),
        IRLogicalMemoryStats8616(1, 1, 1, 0, 1),
    )
    open_evidence = replace(logical_memory, stats=IRLogicalMemoryStats8616())

    for evidence in (None, open_evidence, mismatched, refused):
        semantics = analyze_carry_borrow_links_8616(
            replace(artifact, logical_memory=evidence)
        )
        memory_word = semantics.links[0].low_rhs.memory_word
        assert memory_word is None
        aliases = project_carry_borrow_aliases_8616(semantics)
        assert aliases.stats.raw_fact_count == aliases.stats.failure_count == 1
        assert aliases.resolutions[0].failure is CarryBorrowAliasFailure8616.SOURCE_DEFINITION_MISMATCH


def test_exact_logical_memory_words_reach_widening() -> None:
    artifact = _lift_ssa(bytes.fromhex("2b 06 a6 0b 1b 16 a8 0b c3"))

    semantics = analyze_carry_borrow_links_8616(artifact)
    assert semantics.complete
    assert semantics.stats.raw_fact_count == semantics.stats.materialized_count == 1
    link = semantics.links[0]
    assert link.low_rhs.memory_word is not None
    assert link.high_rhs.memory_word is not None
    assert tuple(
        (address.space, address.offset, address.size)
        for address in (link.low_rhs.memory_word.logical_address,)
    ) == ((MemSpace.DS, 0x0BA6, 2),)
    assert tuple(
        (address.space, address.offset, address.size)
        for address in (link.high_rhs.memory_word.logical_address,)
    ) == ((MemSpace.DS, 0x0BA8, 2),)

    aliases = project_carry_borrow_aliases_8616(semantics)
    widening = widen_carry_borrow_values_8616(aliases)

    assert aliases.complete and aliases.stats.materialized_count == 1
    assert widening.complete and widening.stats.materialized_count == 1
    value = widening.values[0]
    assert value.address_space is MemSpace.DS
    assert value.source_memory is not None
    assert _ranges(value.source_memory.addresses) == ((0x0BA6, 2), (0x0BA8, 2))


def test_direct_raw_word_loads_reach_alias_and_widening() -> None:
    semantics = analyze_carry_borrow_links_8616(
        _lift_ssa(bytes.fromhex("2b 06 a6 0b 1b 16 a8 0b c3"))
    )
    link = semantics.links[0]
    low_rhs = _direct_word_use(link.low_rhs)
    high_rhs = _direct_word_use(link.high_rhs)
    direct = _replace_link(semantics, low_rhs=low_rhs, high_rhs=high_rhs)

    for use in (low_rhs, high_rhs):
        assert use.memory_word is not None
        assert len(use.memory_word.execution_loads) == 1
        assert use.memory_word.execution_loads[0].site is use.definition
        assert use.memory_word.logical_address == use.memory_word.execution_loads[0].address

    aliases = project_carry_borrow_aliases_8616(direct)
    widening = widen_carry_borrow_values_8616(aliases)

    assert aliases.complete and aliases.stats.materialized_count == 1
    assert widening.complete and widening.stats.materialized_count == 1
    assert widening.values[0].source_memory is not None


def test_alias_reconciles_raw_loads_with_logical_word_range() -> None:
    semantics = analyze_carry_borrow_links_8616(
        _lift_ssa(bytes.fromhex("2b 06 a6 0b 1b 16 a8 0b c3"))
    )
    link = semantics.links[0]
    assert link.low_rhs.memory_word is not None
    word = link.low_rhs.memory_word
    logical_address = word.logical_address
    cases = (
        (replace(logical_address, space=MemSpace.ES), CarryBorrowAliasFailure8616.SEGMENT_MISMATCH),
        (replace(logical_address, offset=logical_address.offset + 1), CarryBorrowAliasFailure8616.SOURCE_RANGE_MISMATCH),
    )

    for changed_address, expected in cases:
        changed_use = replace(
            link.low_rhs,
            memory_word=replace(word, logical_address=changed_address),
        )
        aliases = project_carry_borrow_aliases_8616(
            _replace_link(semantics, low_rhs=changed_use)
        )
        assert aliases.stats.raw_fact_count == aliases.stats.failure_count == 1
        assert aliases.resolutions[0].failure is expected


def test_exact_low_high_constant_pair_reaches_widening() -> None:
    artifact = _lift_ssa(bytes.fromhex("2d 4b 00 83 da 00 c3"))

    semantics = analyze_carry_borrow_links_8616(artifact)
    aliases = project_carry_borrow_aliases_8616(semantics)
    widening = widen_carry_borrow_values_8616(aliases)

    assert semantics.complete and semantics.stats.materialized_count == 1
    assert aliases.complete and aliases.stats.materialized_count == 1
    assert widening.complete and widening.stats.materialized_count == 1
    value = widening.values[0]
    assert value.source_constant == 75
    assert value.low.rhs_constant is not None and value.low.rhs_constant.const == 75
    assert value.high.rhs_constant is not None and value.high.rhs_constant.const == 0


def test_mixed_constant_and_register_source_carriers_refuse() -> None:
    semantics = analyze_carry_borrow_links_8616(
        _lift_ssa(bytes.fromhex("2d 4b 00 19 ca c3"))
    )
    assert semantics.complete and semantics.stats.materialized_count == 1

    aliases = project_carry_borrow_aliases_8616(semantics)

    assert aliases.complete
    assert aliases.stats.raw_fact_count == aliases.stats.failure_count == 1
    assert (
        aliases.resolutions[0].failure
        is CarryBorrowAliasFailure8616.SOURCE_CARRIER_MISMATCH
    )
