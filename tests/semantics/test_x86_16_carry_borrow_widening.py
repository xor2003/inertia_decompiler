from __future__ import annotations

import io
from dataclasses import replace
from types import SimpleNamespace

import angr
import pytest
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.structuring.decompiler_structuring_stage import DECOMPILER_STRUCTURING_PASSES
from inertia.ir import IRInstr, IRValue, MemSpace
from inertia.ir.ssa_function import SSAFunctionArtifact, build_x86_16_function_ssa
from inertia.ir.vex_import import build_x86_16_ir_function_artifact
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401

from inertia.alias.carry_borrow_contracts import CarryBorrowOperandRole8616
from inertia.alias.carry_borrow_projection import (
    CarryBorrowAliasFailure8616,
    project_carry_borrow_aliases_8616,
)
from inertia.semantics.carry_borrow_contracts import (
    CarryBorrowEvidence8616,
    CarryBorrowFailure8616,
    CarryBorrowKind8616,
)
from inertia.semantics.carry_borrow_links import analyze_carry_borrow_links_8616
from inertia.semantics.carry_borrow_ssa import single_source_8616
from inertia.widening.carry_borrow_pipeline import (
    CarryBorrowWideningPipeline8616,
    apply_carry_borrow_widening_pipeline_8616,
)
from inertia.widening.carry_borrow_values import (
    WideCarryBorrowFailure8616,
    WideValueSignedness8616,
    widen_carry_borrow_values_8616,
)


def _lift_ssa(code: bytes) -> SSAFunctionArtifact:
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
    return build_x86_16_function_ssa(build_x86_16_ir_function_artifact(project, function))


def _positive_evidence() -> CarryBorrowEvidence8616:
    return analyze_carry_borrow_links_8616(_lift_ssa(bytes.fromhex("01 d8 11 ca c3")))


def _replace_instruction(
    artifact: SSAFunctionArtifact,
    index: int,
    instruction: IRInstr,
) -> SSAFunctionArtifact:
    block = artifact.blocks[0]
    instructions = list(block.instrs)
    instructions[index] = instruction
    return replace(artifact, blocks=(replace(block, instrs=tuple(instructions)),))


def _replace_link(evidence: CarryBorrowEvidence8616, **changes: object) -> CarryBorrowEvidence8616:
    resolution = evidence.resolutions[0]
    assert resolution.link is not None
    updated = replace(resolution, link=replace(resolution.link, **changes))
    return replace(evidence, resolutions=(updated,))


@pytest.mark.parametrize(
    ("code", "kind"),
    (
        (bytes.fromhex("01 d8 11 ca c3"), CarryBorrowKind8616.ADD_WITH_CARRY),
        (bytes.fromhex("29 d8 19 ca c3"), CarryBorrowKind8616.SUB_WITH_BORROW),
    ),
)
def test_real_lifter_carry_borrow_links_widen_exact_register_pairs(
    code: bytes,
    kind: CarryBorrowKind8616,
) -> None:
    artifact = _lift_ssa(code)
    temporary_destinations = tuple(
        instruction.dst
        for block in artifact.blocks
        for instruction in block.instrs
        if instruction.dst is not None and instruction.dst.space is MemSpace.TMP
    )
    assert temporary_destinations
    assert all(value.source_tmp is not None for value in temporary_destinations)

    semantics = analyze_carry_borrow_links_8616(artifact)
    assert semantics.complete
    assert semantics.stats.raw_fact_count == semantics.stats.materialized_count == 1
    link = semantics.links[0]
    assert link.kind is kind
    assert link.flags_definition.instruction.dst is not None
    assert link.flags_definition.instruction.addr == 0x1000
    assert link.flags_read.instruction.addr == 0x1002
    assert single_source_8616(link.flags_read) == link.flags_definition.instruction.dst

    aliases = project_carry_borrow_aliases_8616(semantics)
    assert aliases.complete
    assert aliases.stats.raw_fact_count == aliases.stats.materialized_count == 1

    widening = widen_carry_borrow_values_8616(aliases)
    assert widening.complete
    assert widening.stats.raw_fact_count == widening.stats.materialized_count == 1
    value = widening.values[0]
    assert value.kind is kind
    assert value.size == 4
    assert value.signedness is WideValueSignedness8616.UNKNOWN
    assert value.address_space is None
    assert (value.low.result.name, value.high.result.name) == ("ax", "dx")
    assert (value.low.rhs.value.name, value.high.rhs.value.name) == ("bx", "cx")


def test_semantics_retains_exact_segmented_memory_word_loads() -> None:
    artifact = _lift_ssa(bytes.fromhex("03 06 00 20 13 16 02 20 c3"))

    evidence = analyze_carry_borrow_links_8616(artifact)

    assert evidence.complete
    assert evidence.stats.raw_fact_count == evidence.stats.materialized_count == 1
    link = evidence.links[0]
    assert link.low_rhs.memory_word is not None
    assert link.high_rhs.memory_word is not None
    low_word = link.low_rhs.memory_word
    high_word = link.high_rhs.memory_word
    assert tuple(
        (load.address.space, load.address.offset, load.address.size)
        for load in low_word.execution_loads
    ) == (
        (MemSpace.DS, 0x2000, 1),
        (MemSpace.DS, 0x2001, 1),
    )
    assert tuple(
        (load.address.space, load.address.offset, load.address.size)
        for load in high_word.execution_loads
    ) == (
        (MemSpace.DS, 0x2002, 1),
        (MemSpace.DS, 0x2003, 1),
    )
    assert (low_word.logical_address.space, low_word.logical_address.offset, low_word.size) == (
        MemSpace.DS,
        0x2000,
        2,
    )
    assert (high_word.logical_address.space, high_word.logical_address.offset, high_word.size) == (
        MemSpace.DS,
        0x2002,
        2,
    )

    aliases = project_carry_borrow_aliases_8616(evidence)
    assert aliases.complete
    assert aliases.stats.raw_fact_count == aliases.stats.materialized_count == 1
    fact = aliases.facts[0]
    assert fact.source_memory is not None
    assert fact.source_memory.space is MemSpace.DS
    assert tuple((address.offset, address.size) for address in fact.source_memory.addresses) == (
        (0x2000, 2),
        (0x2002, 2),
    )
    assert fact.source_memory.storage.identity == ("memory", ("ds", 0x2000, 4))

    widening = widen_carry_borrow_values_8616(aliases)
    assert widening.complete
    assert widening.stats.raw_fact_count == widening.stats.materialized_count == 1
    value = widening.values[0]
    assert value.address_space is MemSpace.DS
    assert value.source_memory == fact.source_memory
    assert value.low.rhs_memory == fact.low_rhs.memory
    assert value.high.rhs_memory == fact.high_rhs.memory


@pytest.mark.parametrize(
    ("code", "failure"),
    (
        (
            bytes.fromhex("03 06 00 20 26 13 16 02 20 c3"),
            CarryBorrowAliasFailure8616.SEGMENT_MISMATCH,
        ),
        (
            bytes.fromhex("03 06 00 20 13 16 04 20 c3"),
            CarryBorrowAliasFailure8616.SOURCE_RANGE_MISMATCH,
        ),
    ),
)
def test_alias_refuses_unproven_segmented_memory_pairs(
    code: bytes,
    failure: CarryBorrowAliasFailure8616,
) -> None:
    semantics = analyze_carry_borrow_links_8616(_lift_ssa(code))
    assert semantics.complete
    assert semantics.stats.materialized_count == 1

    aliases = project_carry_borrow_aliases_8616(semantics)

    assert aliases.complete
    assert aliases.stats.raw_fact_count == aliases.stats.failure_count == 1
    assert aliases.resolutions[0].failure is failure

    widening = widen_carry_borrow_values_8616(aliases)
    assert widening.complete
    assert widening.resolutions[0].failure is WideCarryBorrowFailure8616.ALIAS_REFUSED


def test_semantics_refuses_non_unit_carry_mask_with_closed_counters() -> None:
    artifact = _lift_ssa(bytes.fromhex("01 d8 11 ca c3"))
    evidence = analyze_carry_borrow_links_8616(artifact)
    link = evidence.links[0]
    mask_site = link.carry_mask
    mask_args = tuple(
        replace(arg, const=2) if isinstance(arg, IRValue) and arg.const == 1 else arg
        for arg in mask_site.instruction.args
    )
    changed = _replace_instruction(
        artifact,
        mask_site.instr_index,
        replace(mask_site.instruction, args=mask_args),
    )

    refused = analyze_carry_borrow_links_8616(changed)

    assert refused.complete
    assert refused.stats.raw_fact_count == refused.stats.failure_count == 1
    assert refused.stats.materialized_count == 0
    assert refused.resolutions[0].failure is CarryBorrowFailure8616.CARRY_MASK_MISMATCH


def test_alias_refuses_result_carrier_mismatch() -> None:
    evidence = _positive_evidence()
    link = evidence.links[0]
    low_write = link.low_result_write
    assert low_write.instruction.dst is not None
    changed_write = replace(
        low_write,
        instruction=replace(
            low_write.instruction,
            dst=replace(low_write.instruction.dst, name="bx"),
        ),
    )

    refused = project_carry_borrow_aliases_8616(
        _replace_link(evidence, low_result_write=changed_write),
    )

    assert refused.complete
    assert refused.resolutions[0].failure is CarryBorrowAliasFailure8616.RESULT_CARRIER_MISMATCH


def test_alias_refuses_segment_mismatch() -> None:
    evidence = _positive_evidence()
    link = evidence.links[0]
    low_write = link.low_result_write
    assert low_write.instruction.dst is not None
    changed_write = replace(
        low_write,
        instruction=replace(
            low_write.instruction,
            dst=replace(low_write.instruction.dst, space=MemSpace.DS),
        ),
    )

    refused = project_carry_borrow_aliases_8616(
        _replace_link(evidence, low_result_write=changed_write),
    )

    assert refused.complete
    assert refused.resolutions[0].failure is CarryBorrowAliasFailure8616.SEGMENT_MISMATCH


def test_alias_refuses_mismatched_source_definition() -> None:
    evidence = _positive_evidence()
    link = evidence.links[0]
    changed_use = replace(link.low_lhs, value=replace(link.low_lhs.value, source_tmp=999))

    refused = project_carry_borrow_aliases_8616(_replace_link(evidence, low_lhs=changed_use))

    assert refused.complete
    assert refused.stats.raw_fact_count == refused.stats.failure_count == 1
    assert refused.resolutions[0].failure is CarryBorrowAliasFailure8616.SOURCE_DEFINITION_MISMATCH
    assert refused.resolutions[0].failure_operand is CarryBorrowOperandRole8616.LOW_LHS

    widening = widen_carry_borrow_values_8616(refused)
    assert widening.complete
    assert widening.resolutions[0].failure is WideCarryBorrowFailure8616.ALIAS_REFUSED


def test_widening_refuses_incoherent_alias_projection() -> None:
    aliases = project_carry_borrow_aliases_8616(_positive_evidence())
    resolution = aliases.resolutions[0]
    assert resolution.fact is not None
    changed_fact = replace(
        resolution.fact,
        low_result_domain=resolution.fact.high_result_domain,
    )
    changed = replace(aliases, resolutions=(replace(resolution, fact=changed_fact),))

    refused = widen_carry_borrow_values_8616(changed)

    assert refused.complete
    assert refused.resolutions[0].failure is WideCarryBorrowFailure8616.ALIAS_EVIDENCE_MISMATCH


def test_runtime_pipeline_attaches_coherent_artifact_before_structuring() -> None:
    function_ssa = _lift_ssa(bytes.fromhex("01 d8 11 ca c3"))
    codegen = SimpleNamespace(_inertia_vex_ir_function_ssa=function_ssa)

    assert not apply_carry_borrow_widening_pipeline_8616(SimpleNamespace(), codegen)
    artifact = codegen._inertia_carry_borrow_widening_pipeline_8616
    assert isinstance(artifact, CarryBorrowWideningPipeline8616)
    assert artifact.complete
    assert artifact.source_ssa is function_ssa
    assert artifact.widening.stats.materialized_count == 1

    assert not apply_carry_borrow_widening_pipeline_8616(SimpleNamespace(), codegen)
    assert codegen._inertia_carry_borrow_widening_pipeline_8616 is artifact

    names = tuple(spec.name for spec in DECOMPILER_STRUCTURING_PASSES)
    assert names.index("_vex_ir_artifact_8616") < names.index("_stack_memory_ssa_alias_artifact_8616")
    assert names.index("_stack_memory_ssa_alias_artifact_8616") < names.index(
        "_carry_borrow_widening_artifact_8616"
    )
