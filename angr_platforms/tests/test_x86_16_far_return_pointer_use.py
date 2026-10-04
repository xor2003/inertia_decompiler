"""Source-free paired DX:AX far-return use and refusal regressions."""

from __future__ import annotations

import io
from dataclasses import replace

import angr
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.caller_return_use_contracts import (
    CallerReturnUseEvidence8616,
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
)
from angr_platforms.X86_16.callsite_summary import collect_caller_return_use_evidence_8616
from angr_platforms.X86_16.frontend_function_boundary import exact_function_range_boundary_8616
from angr_platforms.X86_16.ir import IRValue
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401
from angr_platforms.X86_16.lowering.far_return_pointer_census import (
    FarReturnPointerCensusFailure8616,
    join_far_return_pointer_census_8616,
)
from angr_platforms.X86_16.lowering.far_return_pointer_use import (
    FarReturnPointerUseFailure8616,
    prove_far_return_pointer_use_8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_contracts import (
    StorageIdentity8616,
    StorageIdentityKind8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_return_defs import (
    resolve_storage_call_output_definitions_8616,
)
from angr_platforms.X86_16.semantics.call_stack_effect_pipeline import (
    build_semantic_function_ssa_8616,
)

_CODE = bytes.fromhex("9a 13 00 00 01 8e c2 89 c3 26 83 3f 0e c3")


def _far_census_case(code: bytes):
    image = bytearray(0x20)
    image[:len(code)] = code
    image[0x13] = 0xCB
    project = angr.Project(
        io.BytesIO(image),
        main_opts={
            "backend": "blob", "arch": Arch86_16(),
            "base_addr": 0x1000, "entry_point": 0x1000,
        },
        auto_load_libs=False,
        simos="DOS",
    )
    return collect_caller_return_use_evidence_8616(
        project, 0x1013, ((0x1000, 0x1000 + len(code)), (0x1013, 0x1014)),
    )


def test_direct_far_call_census_reaches_ax_after_segment_copy() -> None:
    evidence = _far_census_case(bytes.fromhex("9a 13 00 00 01 8e c2 89 c3 26 83 3f 0e c3"))

    assert evidence.fact_census_complete
    assert evidence.raw_fact_count == evidence.materialized_count == 1
    assert evidence.verdict is CallerReturnUseVerdict8616.USED
    assert evidence.callsite_addrs == (0x1000,)
    assert evidence.facts[0].kind is CallsiteReturnUseKind8616.VALUE
    assert evidence.facts[0].witness_instruction_addr == 0x1007


def test_direct_far_call_census_keeps_distinct_segment_target() -> None:
    evidence = _far_census_case(bytes.fromhex("9a 13 00 00 02 8e c2 89 c3 26 83 3f 0e c3"))

    assert evidence.raw_fact_count == 0
    assert evidence.callsite_addrs == ()


def test_direct_far_call_ax_clobber_is_not_a_pointer_use() -> None:
    evidence = _far_census_case(bytes.fromhex("9a 13 00 00 01 8e c2 b8 00 00 c3"))

    assert evidence.raw_fact_count == 1
    assert evidence.facts[0].verdict is CallerReturnUseVerdict8616.UNUSED
    assert evidence.facts[0].kind is CallsiteReturnUseKind8616.CLOBBERED


def _case(code: bytes = _CODE, registers: tuple[str, str] = ("ax", "dx")):
    project = angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob", "arch": Arch86_16(),
            "base_addr": 0x1000, "entry_point": 0x1000,
        },
        auto_load_libs=False,
        simos="DOS",
    )
    boundary = exact_function_range_boundary_8616(project, 0x1000, 0x1000 + len(code))
    assert boundary is not None
    _, outputs, artifact = build_semantic_function_ssa_8616(project, boundary)
    assert not outputs.function.refusals
    storages = tuple(
        StorageIdentity8616(kind=StorageIdentityKind8616.REGISTER, width=2, register=name)
        for name in registers
    )
    definitions = resolve_storage_call_output_definitions_8616(
        artifact, 0x1000, 0x1000, 0x1013, (0x1013,), storages,
    )
    assert definitions.complete
    return artifact, definitions


def _replace_copy_source(artifact, destination_name: str, source_name: str):
    blocks = []
    for block in artifact.blocks:
        instructions = []
        for instruction in block.instrs:
            matching_destination = (
                instruction.op == "MOV"
                and instruction.dst is not None
                and instruction.dst.name == destination_name
            )
            matching_source = (
                len(instruction.args) == 1
                and isinstance(instruction.args[0], IRValue)
                and instruction.args[0].name in {"ax", "dx"}
            )
            if matching_destination and matching_source:
                source = instruction.args[0]
                instruction = replace(instruction, args=(replace(source, name=source_name),))
            instructions.append(instruction)
        blocks.append(replace(block, instrs=tuple(instructions)))
    return replace(artifact, blocks=tuple(blocks))


def test_exact_dx_ax_to_es_bx_word_read_proves_far_return_use() -> None:
    artifact, definitions = _case()

    result = prove_far_return_pointer_use_8616(artifact, 0x1000, definitions)

    assert result.complete
    assert result.evidence is not None
    assert result.evidence.dereference_instruction_addr == 0x1009
    assert result.evidence.access_width_bytes == 2
    assert result.stats.raw_fact_count == result.stats.materialized_count == 1


def test_wrong_segment_carrier_refuses() -> None:
    artifact, definitions = _case()
    changed = _replace_copy_source(artifact, "es", "ax")

    result = prove_far_return_pointer_use_8616(changed, 0x1000, definitions)

    assert result.failure is FarReturnPointerUseFailure8616.SEGMENT_COPY_MISSING


def test_wrong_offset_carrier_refuses() -> None:
    artifact, definitions = _case()
    changed = _replace_copy_source(artifact, "bx", "dx")

    result = prove_far_return_pointer_use_8616(changed, 0x1000, definitions)

    assert result.failure is FarReturnPointerUseFailure8616.OFFSET_COPY_MISSING


def test_clobbered_offset_before_dereference_refuses() -> None:
    code = bytes.fromhex("9a 13 00 00 01 8e c2 89 c3 89 cb 26 83 3f 0e c3")
    artifact, definitions = _case(code)

    result = prove_far_return_pointer_use_8616(artifact, 0x1000, definitions)

    assert result.failure is FarReturnPointerUseFailure8616.CARRIER_CLOBBERED


def test_partial_offset_write_after_copy_refuses() -> None:
    code = bytes.fromhex("9a 13 00 00 01 8e c2 89 c3 b3 00 26 83 3f 0e c3")
    artifact, definitions = _case(code)

    result = prove_far_return_pointer_use_8616(artifact, 0x1000, definitions)

    assert result.failure is FarReturnPointerUseFailure8616.CARRIER_CLOBBERED


def test_segment_overwrite_after_copy_refuses() -> None:
    code = bytes.fromhex("9a 13 00 00 01 8e c2 89 c3 8e c1 26 83 3f 0e c3")
    artifact, definitions = _case(code)

    result = prove_far_return_pointer_use_8616(artifact, 0x1000, definitions)

    assert result.failure is FarReturnPointerUseFailure8616.CARRIER_CLOBBERED


def test_no_dereference_does_not_prove_pointer_type() -> None:
    artifact, definitions = _case(bytes.fromhex("9a 13 00 00 01 8e c2 89 c3 c3"))

    result = prove_far_return_pointer_use_8616(artifact, 0x1000, definitions)

    assert result.failure is FarReturnPointerUseFailure8616.DEREFERENCE_NOT_FOUND


def test_incomplete_cfg_and_missing_logical_memory_refuse() -> None:
    artifact, definitions = _case()
    broken_cfg = replace(artifact, predecessor_map={0x1000: (), 0x1005: ()})
    broken_access = replace(artifact, logical_memory=None)

    assert prove_far_return_pointer_use_8616(
        broken_cfg, 0x1000, definitions,
    ).failure is FarReturnPointerUseFailure8616.CFG_INCOMPLETE
    assert prove_far_return_pointer_use_8616(
        broken_access, 0x1000, definitions,
    ).failure is FarReturnPointerUseFailure8616.LOGICAL_ACCESS_UNPROVEN


def test_wrong_physical_return_pair_refuses() -> None:
    artifact, definitions = _case(registers=("ax", "cx"))

    result = prove_far_return_pointer_use_8616(artifact, 0x1000, definitions)

    assert result.failure is FarReturnPointerUseFailure8616.OUTPUT_SHAPE_MISMATCH


def test_far_return_use_refuses_foreign_callee_provenance() -> None:
    artifact, definitions = _case()
    assert definitions.provenance is not None
    foreign = replace(
        definitions,
        provenance=replace(definitions.provenance, function_addr=0x2013),
    )
    assert foreign.complete

    result = prove_far_return_pointer_use_8616(artifact, 0x1000, foreign)

    assert result.failure is FarReturnPointerUseFailure8616.CALL_TARGET_MISMATCH
    assert not result.complete


def _paired_census():
    fact = _far_census_case(bytes.fromhex("9a 13 00 00 01 8e c2 89 c3 26 83 3f 0e c3")).facts[0]
    artifact, definitions = _case()
    first = prove_far_return_pointer_use_8616(artifact, 0x1000, definitions)
    assert first.complete and first.evidence is not None
    second_fact = replace(
        fact, caller_addr=0x2000, callsite_addr=0x2000, witness_instruction_addr=0x2007,
    )
    first_use = first.evidence
    second_use = replace(
        first_use,
        caller_addr=0x2000,
        callsite_addr=0x2000,
        segment_copy=replace(
            first_use.segment_copy,
            block_addr=first_use.segment_copy.block_addr + 0x1000,
            instr_addr=first_use.segment_copy.instr_addr + 0x1000,
        ),
        offset_copy=replace(
            first_use.offset_copy,
            block_addr=first_use.offset_copy.block_addr + 0x1000,
            instr_addr=first_use.offset_copy.instr_addr + 0x1000,
        ),
        dereference_instruction_addr=first_use.dereference_instruction_addr + 0x1000,
        access_key=replace(
            first_use.access_key,
            function_addr=first_use.access_key.function_addr + 0x1000,
            block_addr=first_use.access_key.block_addr + 0x1000,
            insn_addr=first_use.access_key.insn_addr + 0x1000,
        ),
    )
    second = replace(first, evidence=second_use)
    census = CallerReturnUseEvidence8616(
        target_addr=0x1013,
        verdict=CallerReturnUseVerdict8616.USED,
        raw_fact_count=2,
        normalized_fact_count=2,
        classified_fact_count=2,
        materialized_count=2,
        failure_count=0,
        used_callsite_count=2,
        unused_callsite_count=0,
        callsite_addrs=(0x1000, 0x2000),
        facts=(fact, second_fact),
    )
    assert census.fact_census_complete and second.complete
    return census, first, second


def test_far_return_census_requires_every_paired_caller_use() -> None:
    census, first, second = _paired_census()

    result = join_far_return_pointer_census_8616(census, (second, first))

    assert result.complete
    assert tuple(use.callsite_addr for use in result.uses) == (0x1000, 0x2000)
    assert result.stats.raw_fact_count == result.stats.materialized_count == 2


def test_far_return_census_refuses_missing_or_duplicate_callsite_proofs() -> None:
    census, first, second = _paired_census()

    missing = join_far_return_pointer_census_8616(census, (first,))
    duplicate = join_far_return_pointer_census_8616(census, (first, first, second))

    assert missing.failure is FarReturnPointerCensusFailure8616.PROOF_MISSING
    assert duplicate.failure is FarReturnPointerCensusFailure8616.PROOF_DUPLICATE
    assert not missing.complete and not duplicate.complete


def test_far_return_census_refuses_unrelated_ax_use_and_witness_mismatch() -> None:
    census, first, second = _paired_census()
    wrong_kind = replace(
        census,
        facts=(replace(census.facts[0], kind=CallsiteReturnUseKind8616.CONDITION), census.facts[1]),
    )
    wrong_witness = replace(
        census,
        facts=(replace(census.facts[0], witness_instruction_addr=0x1005), census.facts[1]),
    )

    assert join_far_return_pointer_census_8616(
        wrong_kind, (first, second),
    ).failure is FarReturnPointerCensusFailure8616.RETURN_USE_NOT_VALUE
    assert join_far_return_pointer_census_8616(
        wrong_witness, (first, second),
    ).failure is FarReturnPointerCensusFailure8616.WITNESS_MISMATCH


def test_far_return_census_refuses_open_caller_inventory() -> None:
    census, first, second = _paired_census()
    open_census = replace(census, failure_count=1)

    result = join_far_return_pointer_census_8616(open_census, (first, second))

    assert result.failure is FarReturnPointerCensusFailure8616.CENSUS_INCOMPLETE
    assert not result.complete


def test_far_return_census_refuses_duplicate_inventory_facts() -> None:
    census, first, _ = _paired_census()
    repeated = replace(
        census,
        facts=(census.facts[0], census.facts[0]),
        callsite_addrs=(0x1000, 0x1000),
    )
    assert repeated.fact_census_complete

    result = join_far_return_pointer_census_8616(repeated, (first,))

    assert result.failure is FarReturnPointerCensusFailure8616.CENSUS_INCOMPLETE
    assert not result.complete


def test_far_return_census_refuses_extra_or_unproven_paired_uses() -> None:
    census, first, second = _paired_census()
    assert second.evidence is not None
    extra = replace(second, evidence=replace(second.evidence, callsite_addr=0x2005))
    unproven = replace(second, stats=replace(second.stats, failure_count=1))
    assert extra.complete and not unproven.complete

    extra_result = join_far_return_pointer_census_8616(census, (first, second, extra))
    unproven_result = join_far_return_pointer_census_8616(census, (first, unproven))

    assert extra_result.failure is FarReturnPointerCensusFailure8616.PROOF_EXTRA
    assert unproven_result.failure is FarReturnPointerCensusFailure8616.PROOF_UNPROVEN
    assert not extra_result.complete and not unproven_result.complete


def test_far_return_census_complete_rechecks_source_verdict() -> None:
    census, first, second = _paired_census()
    result = join_far_return_pointer_census_8616(census, (first, second))
    assert result.complete

    contradicted = replace(result, census=replace(census, verdict=CallerReturnUseVerdict8616.UNKNOWN))

    assert not contradicted.complete


def test_far_return_census_refuses_foreign_target() -> None:
    census, first, second = _paired_census()
    foreign = replace(census, target_addr=0x2013)

    result = join_far_return_pointer_census_8616(foreign, (first, second))

    assert result.failure is FarReturnPointerCensusFailure8616.TARGET_MISMATCH
    assert not result.complete


def test_two_binary_far_calls_join_to_one_target_without_sidecars() -> None:
    call_and_use = bytes.fromhex("9a 30 00 00 01 8e c2 89 c3 26 83 3f 00")
    caller_code = call_and_use + call_and_use + bytes.fromhex("c3")
    image = bytearray(0x31)
    image[:len(caller_code)] = caller_code
    image[0x30] = 0xCB
    project = angr.Project(
        io.BytesIO(image),
        main_opts={
            "backend": "blob", "arch": Arch86_16(),
            "base_addr": 0x1000, "entry_point": 0x1000,
        },
        auto_load_libs=False,
        simos="DOS",
    )
    census = collect_caller_return_use_evidence_8616(
        project, 0x1030, ((0x1000, 0x1000 + len(caller_code)), (0x1030, 0x1031)),
    )
    assert census.fact_census_complete
    assert census.callsite_addrs == (0x1000, 0x100D)
    boundary = exact_function_range_boundary_8616(project, 0x1000, 0x1000 + len(caller_code))
    assert boundary is not None
    _, outputs, artifact = build_semantic_function_ssa_8616(project, boundary)
    assert not outputs.function.refusals
    storages = tuple(
        StorageIdentity8616(kind=StorageIdentityKind8616.REGISTER, width=2, register=name)
        for name in ("ax", "dx")
    )
    proofs = []
    for fact in census.facts:
        definitions = resolve_storage_call_output_definitions_8616(
            artifact, 0x1000, fact.callsite_addr, 0x1030, (0x1030,), storages, project=project,
        )
        assert definitions.complete
        proofs.append(prove_far_return_pointer_use_8616(artifact, fact.callsite_addr, definitions))

    result = join_far_return_pointer_census_8616(census, tuple(proofs))

    assert result.complete
    assert result.stats.raw_fact_count == result.stats.materialized_count == 2
    assert tuple(use.callee_addr for use in result.uses) == (0x1030, 0x1030)
