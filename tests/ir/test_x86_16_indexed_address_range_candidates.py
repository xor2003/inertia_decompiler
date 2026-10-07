from __future__ import annotations

import io
from dataclasses import replace
from types import SimpleNamespace

import angr
import pytest
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.core import IRInstr, IRValue, MemSpace
from inertia.ir.indexed_address_evidence import (
    collect_indexed_address_evidence_8616,
)
from inertia.ir.indexed_address_range_candidates import (
    build_indexed_loop_range_candidates_8616,
    collect_indexed_loop_ranges_from_ssa_8616,
)
from inertia.ir.indexed_address_range_contracts import (
    IndexedLoopGuardPolarity8616,
    IndexedLoopGuardRelation8616,
)
from inertia.ir.indexed_address_range_evidence import (
    collect_indexed_loop_range_evidence_8616,
)
from inertia.ir.indexed_induction_write_census import (
    IndexedInductionEffectVerdict8616,
)
from inertia.ir.logical_memory_write_value import (
    LogicalWordWriteValueKind8616,
    trace_logical_word_write_values_8616,
)
from inertia.ir.ssa_function import build_x86_16_function_ssa
from inertia.ir.vex_import import build_x86_16_ir_function_artifact

ZERO_BASED_INDEXED_LOOP = bytes.fromhex(
    "55 89 e5 83 ec 02 "
    "c7 46 fe 00 00 "
    "83 7e fe 04 "
    "73 0c "
    "8b 5e fe "
    "8a 87 00 02 "
    "ff 46 fe "
    "eb ee "
    "89 ec 5d c3"
)


def test_real_ssa_loop_produces_exact_constant_range_witness() -> None:
    project = angr.Project(
        io.BytesIO(ZERO_BASED_INDEXED_LOOP),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )
    function = SimpleNamespace(
        addr=0x1000,
        block_addrs_set={0x1000, 0x100B, 0x1011, 0x101D},
        info={},
    )
    ssa = build_x86_16_function_ssa(
        build_x86_16_ir_function_artifact(project, function)
    )
    indexed = collect_indexed_address_evidence_8616(ssa)

    result = collect_indexed_loop_ranges_from_ssa_8616(ssa, indexed)

    assert result.closed
    assert result.refusals == ()
    assert result.stats.raw_fact_count == result.stats.materialized_count == 1
    fact = result.facts[0]
    assert fact.complete
    assert (fact.init, fact.step, fact.upper_bound) == (0, 1, 4)
    assert fact.init_write.kind is LogicalWordWriteValueKind8616.CONSTANT_ZERO
    assert (
        fact.step_write.kind
        is LogicalWordWriteValueKind8616.OLD_LOGICAL_WORD_PLUS_ONE
    )
    assert fact.guard.condition.op == "uge"
    assert fact.guard.relation is IndexedLoopGuardRelation8616.UNSIGNED_GE
    assert (
        fact.guard.polarity
        is IndexedLoopGuardPolarity8616.CONTINUE_WHEN_FALSE
    )
    assert fact.guard.proves_strict_unsigned_continue
    assert fact.natural_loop.entry_edges == ((0x1000, 0x100B),)
    assert fact.natural_loop.exit_edges == ((0x100B, 0x101D),)
    candidate = build_indexed_loop_range_candidates_8616(
        ssa, indexed, trace_logical_word_write_values_8616(ssa),
    )[0]
    census = candidate.induction_write_census
    assert census is not None and census.complete
    assert census.raw_fact_count == census.normalized_fact_count
    assert census.classified_fact_count == census.materialized_count == census.raw_fact_count
    assert census.failure_count == 0
    assert not replace(census, checked_blocks=()).complete
    expected_sites = {(lane.block_addr, lane.instr_index) for lane in census.expected_lanes}
    assert not replace(census, effects=tuple(
        effect for effect in census.effects
        if (effect.block_addr, effect.instr_index) not in expected_sites
    )).complete
    for corrupted in (
        replace(candidate, induction_write_census=None),
        replace(candidate, induction_write_census=replace(
            census, induction_source=replace(census.induction_source, offset=-4),
        )),
        replace(candidate, induction_write_census=replace(census, expected_lanes=())),
        replace(candidate, induction_write_census=replace(census, function_addr=0x2000)),
        replace(candidate, induction_write_census=replace(census, initializer_dominates_header=False)),
        replace(candidate, induction_write_census=replace(census, loop_blocks=())),
    ):
        refused = collect_indexed_loop_range_evidence_8616(ssa.function_addr, (corrupted,))
        assert refused.closed and not refused.facts
        assert refused.stats.failure_count == 1
    assert fact.induction_write_census == census
    assert not replace(fact, induction_write_census=None).complete
    assert not replace(fact, induction_write_census=replace(census, function_addr=0x2000)).complete


@pytest.mark.parametrize("bound", (1, 4, 127))
def test_real_signed_positive_bound_retains_signed_guard(bound: int) -> None:
    binary = bytearray(ZERO_BASED_INDEXED_LOOP)
    binary[14] = bound
    binary[15] = 0x7D  # JGE exits: continued edge is signed index < bound.
    project = angr.Project(io.BytesIO(binary), main_opts={
        "backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000,
        "entry_point": 0x1000,
    }, auto_load_libs=False)
    function = SimpleNamespace(addr=0x1000,
                               block_addrs_set={0x1000, 0x100B, 0x1011, 0x101D}, info={})
    ssa = build_x86_16_function_ssa(build_x86_16_ir_function_artifact(project, function))
    result = collect_indexed_loop_ranges_from_ssa_8616(ssa, collect_indexed_address_evidence_8616(ssa))
    assert result.closed and not result.refusals
    assert result.stats.materialized_count == 1
    fact = result.facts[0]
    assert fact.complete and fact.upper_bound == bound
    assert fact.guard.condition.op == "sge"
    assert fact.guard.relation.value == "signed_ge"
    assert not fact.guard.proves_strict_unsigned_continue
    assert not replace(fact, upper_bound=0x8000).complete
    assert not replace(fact, upper_bound=bound + 1).complete
    assert not replace(fact, guard=replace(
        fact.guard, relation=IndexedLoopGuardRelation8616.UNSIGNED_GE,
    )).complete
    assert not replace(fact, guard=replace(fact.guard, condition=replace(
        fact.guard.condition, lhs=replace(fact.guard.condition.lhs, offset=6),
    ))).complete
    assert not replace(fact, guard=replace(fact.guard, condition=replace(
        fact.guard.condition, op="uge",
    ))).complete
    assert not replace(fact, guard=replace(fact.guard, condition=replace(
        fact.guard.condition, width_bits=32,
    ))).complete
    assert not replace(fact, guard=replace(fact.guard, condition=replace(
        fact.guard.condition, rhs=IRValue(MemSpace.SS, name="bp", offset=8, size=2),
    ))).complete


@pytest.mark.parametrize("bound", (0, 0xFF))
def test_real_signed_nonpositive_bound_is_not_a_nonempty_range(bound: int) -> None:
    binary = bytearray(ZERO_BASED_INDEXED_LOOP)
    binary[14] = bound
    binary[15] = 0x7D
    project = angr.Project(io.BytesIO(binary), main_opts={
        "backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000,
        "entry_point": 0x1000,
    }, auto_load_libs=False)
    function = SimpleNamespace(addr=0x1000,
                               block_addrs_set={0x1000, 0x100B, 0x1011, 0x101D}, info={})
    ssa = build_x86_16_function_ssa(build_x86_16_ir_function_artifact(project, function))
    result = collect_indexed_loop_ranges_from_ssa_8616(ssa, collect_indexed_address_evidence_8616(ssa))
    assert result.closed and not result.facts
    assert result.stats.materialized_count == 0 and result.stats.failure_count == 1

@pytest.mark.parametrize("guard_opcode", (0x73, 0x7D))
@pytest.mark.parametrize("overwrite", (
    bytes.fromhex("c7 46 fe 07 00"),
    bytes.fromhex("c6 46 fe 07"),
    bytes.fromhex("31 46 fe"),
    bytes.fromhex("66 bd 00 10 00 00"),
))
def test_every_induction_write_is_accounted_before_range_publication(
    guard_opcode: int, overwrite: bytes,
) -> None:
    """Raw word/byte mutations and wide frame writes stay in the census."""
    binary = bytearray(ZERO_BASED_INDEXED_LOOP)
    binary[15] = guard_opcode
    binary[16] += len(overwrite)
    binary[17:17] = overwrite
    binary[28 + len(overwrite)] = (0xEE - len(overwrite)) & 0xFF
    project = angr.Project(io.BytesIO(binary), main_opts={
        "backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000,
        "entry_point": 0x1000,
    }, auto_load_libs=False)
    function = SimpleNamespace(addr=0x1000, block_addrs_set={
        0x1000, 0x100B, 0x1011, 0x101D + len(overwrite),
    }, info={})
    ssa = build_x86_16_function_ssa(build_x86_16_ir_function_artifact(project, function))
    result = collect_indexed_loop_ranges_from_ssa_8616(ssa, collect_indexed_address_evidence_8616(ssa))
    assert result.closed and not result.facts
    assert result.stats.materialized_count == 0 and result.stats.failure_count == 1
    census = result.refusals[0].candidate.induction_write_census
    assert census is not None and not census.complete
    assert census.failure_count > 0
    assert census.raw_fact_count == census.materialized_count + census.failure_count
    relabeled = replace(census, effects=tuple(
        replace(effect, verdict=IndexedInductionEffectVerdict8616.ACCOUNTED)
        for effect in census.effects
    ))
    assert relabeled.failure_count == 0
    assert not relabeled.complete
    omitted = replace(census, effects=tuple(
        effect for effect in census.effects
        if effect.verdict is IndexedInductionEffectVerdict8616.ACCOUNTED
    ))
    assert omitted.failure_count > 0
    assert not omitted.complete


@pytest.mark.parametrize("binary,body", (
    (bytes.fromhex(
        "55 89 e5 83 ec 02 c7 46 fe 00 00 8b 5e fe 8a 87 00 02 "
        "83 7e fe 04 7d 05 ff 46 fe eb ee 89 ec 5d c3",
    ), 0x1018),
    (bytes.fromhex(
        "55 89 e5 83 ec 02 c7 46 fe 00 00 83 7e fe 04 7d 0c "
        "ff 46 fe 8b 5e fe 8a 87 00 02 eb ee 89 ec 5d c3",
    ), 0x1011),
))
def test_block_dominance_cannot_replace_guard_and_increment_order(
    binary: bytes, body: int,
) -> None:
    """Header-before-guard and latch-after-increment reads can observe index N."""
    project = angr.Project(io.BytesIO(binary), main_opts={
        "backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000,
        "entry_point": 0x1000,
    }, auto_load_libs=False)
    function = SimpleNamespace(addr=0x1000, block_addrs_set={
        0x1000, 0x100B, body, 0x101D,
    }, info={})
    ssa = build_x86_16_function_ssa(build_x86_16_ir_function_artifact(project, function))
    result = collect_indexed_loop_ranges_from_ssa_8616(ssa, collect_indexed_address_evidence_8616(ssa))
    assert result.closed and not result.facts
    assert result.stats.materialized_count == 0 and result.stats.failure_count == 1


@pytest.mark.parametrize("operation", ("DIRTY", "INT", "UNCLASSIFIED_EFFECT"))
def test_opaque_effect_cannot_preserve_induction_by_omitting_store_opcode(operation: str) -> None:
    """An unknown operation may write memory even without an explicit STORE."""
    project = angr.Project(io.BytesIO(ZERO_BASED_INDEXED_LOOP), main_opts={
        "backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000,
        "entry_point": 0x1000,
    }, auto_load_libs=False)
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000, 0x100B, 0x1011, 0x101D}, info={})
    ssa = build_x86_16_function_ssa(build_x86_16_ir_function_artifact(project, function))
    original = collect_indexed_loop_ranges_from_ssa_8616(ssa, collect_indexed_address_evidence_8616(ssa))
    assert len(original.facts) == 1 and original.facts[0].complete
    body = next(block for block in ssa.blocks if block.addr == 0x1011)
    opaque = IRInstr(operation, None, (), addr=body.instrs[-1].addr)
    changed = replace(body, instrs=(*body.instrs, opaque))
    source = replace(ssa, blocks=tuple(changed if block is body else block for block in ssa.blocks))
    result = collect_indexed_loop_ranges_from_ssa_8616(source, collect_indexed_address_evidence_8616(source))
    assert result.closed and not result.facts
    assert result.stats.failure_count == 1
    census = result.refusals[0].candidate.induction_write_census
    assert census is not None and census.failure_count > 0 and not census.complete
    relabeled = replace(census, effects=tuple(
        replace(effect, verdict=IndexedInductionEffectVerdict8616.ACCOUNTED) for effect in census.effects
    ))
    assert not relabeled.complete
