"""Source-free positive and refusal tests for a modular stack-argument use proof."""

from __future__ import annotations

import io
from dataclasses import replace

import angr
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
    exact_function_range_boundary_8616,
)
from angr_platforms.X86_16.ir import (
    AddressStatus,
    IRAddress,
    IRCallStackEffect8616,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from angr_platforms.X86_16.ir.logical_memory_contracts import (
    IRLogicalMemoryFailureKind8616,
    IRLogicalMemoryRefusal8616,
)
from angr_platforms.X86_16.ir.ssa_function import (
    SSACallStackEffectSite8616,
    SSAFunctionArtifact,
)
from angr_platforms.X86_16.ir.stack_argument_modular_use import (
    ModularArgumentUseFailure8616,
    ModularArgumentUseVerdict8616,
    prove_stack_argument_modular_return_use_8616,
)
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401
from angr_platforms.X86_16.semantics.call_stack_effect_pipeline import (
    build_semantic_function_ssa_8616,
)

_MODULAR_RETURN_CODE = bytes.fromhex(
    "55 8b ec 57 56 8b 46 06 d1 e0 03 46 04 e9 00 00 "
    "5e 5f 8b e5 5d c3"
)
_INDEX_STORAGE = IRAddress(
    space=MemSpace.SS,
    base=("bp",),
    offset=6,
    size=2,
    status=AddressStatus.STABLE,
    segment_origin=SegmentOrigin.PROVEN,
)


def _semantic_ssa(code: bytes) -> tuple[ExactFunctionRangeBoundary8616, SSAFunctionArtifact]:
    project = angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
        simos="DOS",
    )
    boundary = exact_function_range_boundary_8616(project, 0x1000, 0x1016)
    assert boundary is not None
    _, outputs, ssa = build_semantic_function_ssa_8616(project, boundary)
    assert not outputs.function.refusals
    return boundary, ssa


def _replace_instruction(
    ssa: SSAFunctionArtifact,
    block_addr: int,
    instr_index: int,
    **changes: object,
) -> SSAFunctionArtifact:
    blocks = []
    for block in ssa.blocks:
        if block.addr != block_addr:
            blocks.append(block)
            continue
        instructions = list(block.instrs)
        instructions[instr_index] = replace(instructions[instr_index], **changes)
        blocks.append(replace(block, instrs=tuple(instructions)))
    return replace(ssa, blocks=tuple(blocks))


def test_word_index_shift_add_return_has_sign_insensitive_use() -> None:
    boundary, ssa = _semantic_ssa(_MODULAR_RETURN_CODE)

    result = prove_stack_argument_modular_return_use_8616(boundary, ssa, _INDEX_STORAGE)

    assert result.verdict is ModularArgumentUseVerdict8616.PROVEN
    assert result.failure is None
    assert result.stats.raw_fact_count == 1
    assert result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == 1
    assert result.stats.materialized_count == 1
    assert result.stats.failure_count == 0


def test_signed_shift_refuses_sign_insensitive_use() -> None:
    signed_shift = _MODULAR_RETURN_CODE.replace(bytes.fromhex("d1 e0"), bytes.fromhex("d1 f8"))
    boundary, ssa = _semantic_ssa(signed_shift)

    result = prove_stack_argument_modular_return_use_8616(boundary, ssa, _INDEX_STORAGE)

    assert result.verdict is ModularArgumentUseVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ModularArgumentUseFailure8616.SIGN_DEPENDENT_OPERATION
    assert result.stats.failure_count == 1


def test_missing_exact_cfg_edge_refuses_modular_use() -> None:
    boundary, ssa = _semantic_ssa(_MODULAR_RETURN_CODE)
    incomplete_boundary = replace(boundary, successor_edges=())

    result = prove_stack_argument_modular_return_use_8616(
        incomplete_boundary,
        ssa,
        _INDEX_STORAGE,
    )

    assert result.verdict is ModularArgumentUseVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ModularArgumentUseFailure8616.CFG_NOT_CLOSED


def test_unproven_prior_call_refuses_modular_use() -> None:
    boundary, ssa = _semantic_ssa(_MODULAR_RETURN_CODE)
    # Deliberately corrupt one typed instruction without supplying its effect.
    ssa = _replace_instruction(ssa, 0x1000, 0, op="CALL", dst=None, args=())

    result = prove_stack_argument_modular_return_use_8616(boundary, ssa, _INDEX_STORAGE)

    assert result.verdict is ModularArgumentUseVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ModularArgumentUseFailure8616.CALL_EFFECT_UNKNOWN


def test_unknown_ssa_source_refuses_modular_use() -> None:
    boundary, ssa = _semantic_ssa(_MODULAR_RETURN_CODE)
    access = next(
        item for item in ssa.logical_memory.accesses
        if item.address.base == ("bp",) and item.address.offset == 6
    )
    first_source = min(item.instr_index for item in access.execution_slices)
    block = next(item for item in ssa.blocks if item.addr == access.key.block_addr)
    consumer = block.instrs[first_source + 1]
    assert isinstance(consumer.args[0], IRValue)
    broken_source = replace(consumer.args[0], source_tmp=0xDEAD)
    ssa = _replace_instruction(
        ssa, block.addr, first_source + 1, args=(broken_source, *consumer.args[1:]),
    )

    result = prove_stack_argument_modular_return_use_8616(boundary, ssa, _INDEX_STORAGE)

    assert result.verdict is ModularArgumentUseVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ModularArgumentUseFailure8616.SSA_DEFINITION_UNKNOWN


def test_tainted_store_refuses_modular_use() -> None:
    boundary, ssa = _semantic_ssa(_MODULAR_RETURN_CODE)
    access = next(
        item for item in ssa.logical_memory.accesses
        if item.address.base == ("bp",) and item.address.offset == 6
    )
    first_source = min(item.instr_index for item in access.execution_slices)
    ssa = _replace_instruction(
        ssa, access.key.block_addr, first_source + 1, op="STORE", dst=None,
    )

    result = prove_stack_argument_modular_return_use_8616(boundary, ssa, _INDEX_STORAGE)

    assert result.verdict is ModularArgumentUseVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ModularArgumentUseFailure8616.UNSUPPORTED_USE


def test_escaped_prior_call_input_refuses_modular_use() -> None:
    boundary, ssa = _semantic_ssa(_MODULAR_RETURN_CODE)
    ssa = _replace_instruction(ssa, 0x1000, 0, op="CALL", dst=None, args=())
    effect = IRCallStackEffect8616(
        net_stack_delta=0,
        preserved_ranges=(_INDEX_STORAGE,),
        escaped_ranges=(_INDEX_STORAGE,),
        complete=True,
        bp_preserved=True,
    )
    ssa = replace(ssa, memory_call_effects=(SSACallStackEffectSite8616(0x1000, 0, 0x1000, effect),))

    result = prove_stack_argument_modular_return_use_8616(boundary, ssa, _INDEX_STORAGE)

    assert result.verdict is ModularArgumentUseVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ModularArgumentUseFailure8616.CALL_EFFECT_UNKNOWN


def test_unknown_prior_call_stack_delta_refuses_modular_use() -> None:
    boundary, ssa = _semantic_ssa(_MODULAR_RETURN_CODE)
    ssa = _replace_instruction(ssa, 0x1000, 0, op="CALL", dst=None, args=())
    effect = IRCallStackEffect8616(
        preserved_ranges=(_INDEX_STORAGE,),
        complete=True,
        bp_preserved=True,
    )
    ssa = replace(ssa, memory_call_effects=(SSACallStackEffectSite8616(0x1000, 0, 0x1000, effect),))

    result = prove_stack_argument_modular_return_use_8616(boundary, ssa, _INDEX_STORAGE)

    assert result.verdict is ModularArgumentUseVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ModularArgumentUseFailure8616.CALL_EFFECT_UNKNOWN


def test_reversed_logical_byte_offsets_refuse_modular_use() -> None:
    boundary, ssa = _semantic_ssa(_MODULAR_RETURN_CODE)
    assert ssa.logical_memory is not None
    access = next(item for item in ssa.logical_memory.accesses if item.address.offset == 6)
    swapped = replace(access, execution_slices=tuple(
        replace(item, source_byte_offset=1 - item.source_byte_offset)
        for item in access.execution_slices
    ))
    logical = replace(
        ssa.logical_memory,
        accesses=tuple(swapped if item == access else item for item in ssa.logical_memory.accesses),
    )
    ssa = replace(ssa, logical_memory=logical)

    result = prove_stack_argument_modular_return_use_8616(boundary, ssa, _INDEX_STORAGE)

    assert result.verdict is ModularArgumentUseVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ModularArgumentUseFailure8616.INPUT_ACCESS_UNKNOWN


def test_foreign_logical_read_block_refuses_without_exception() -> None:
    boundary, ssa = _semantic_ssa(_MODULAR_RETURN_CODE)
    assert ssa.logical_memory is not None
    access = next(item for item in ssa.logical_memory.accesses if item.address.offset == 6)
    foreign = replace(
        access,
        key=replace(access.key, block_addr=0xDEAD),
        execution_slices=tuple(
            replace(item, block_addr=0xDEAD) for item in access.execution_slices
        ),
    )
    assert foreign.complete
    logical = replace(
        ssa.logical_memory,
        accesses=tuple(foreign if item == access else item for item in ssa.logical_memory.accesses),
    )
    assert logical.closed
    ssa = replace(ssa, logical_memory=logical)

    result = prove_stack_argument_modular_return_use_8616(boundary, ssa, _INDEX_STORAGE)

    assert result.verdict is ModularArgumentUseVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ModularArgumentUseFailure8616.INPUT_ACCESS_UNKNOWN


def test_foreign_logical_artifact_function_refuses_modular_use() -> None:
    boundary, ssa = _semantic_ssa(_MODULAR_RETURN_CODE)
    assert ssa.logical_memory is not None
    ssa = replace(ssa, logical_memory=replace(ssa.logical_memory, function_addr=0xDEAD))

    result = prove_stack_argument_modular_return_use_8616(boundary, ssa, _INDEX_STORAGE)

    assert result.verdict is ModularArgumentUseVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ModularArgumentUseFailure8616.INPUT_ACCESS_UNKNOWN


def test_closed_artifact_with_refused_memory_operand_refuses_modular_use() -> None:
    boundary, ssa = _semantic_ssa(_MODULAR_RETURN_CODE)
    assert ssa.logical_memory is not None
    logical = ssa.logical_memory
    refusal = IRLogicalMemoryRefusal8616(
        function_addr=ssa.function_addr,
        block_addr=logical.accesses[0].key.block_addr,
        insn_addr=logical.accesses[0].key.insn_addr,
        access_ordinal=99,
        failure=IRLogicalMemoryFailureKind8616.AMBIGUOUS_EXECUTION_SLICES,
        detail="unknown overlapping operand",
    )
    stats = replace(
        logical.stats,
        raw_fact_count=logical.stats.raw_fact_count + 1,
        normalized_fact_count=logical.stats.normalized_fact_count + 1,
        classified_fact_count=logical.stats.classified_fact_count + 1,
        failure_count=logical.stats.failure_count + 1,
    )
    logical = replace(logical, refusals=(refusal,), stats=stats)
    assert logical.closed
    ssa = replace(ssa, logical_memory=logical)

    result = prove_stack_argument_modular_return_use_8616(boundary, ssa, _INDEX_STORAGE)

    assert result.verdict is ModularArgumentUseVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ModularArgumentUseFailure8616.INPUT_ACCESS_UNKNOWN
