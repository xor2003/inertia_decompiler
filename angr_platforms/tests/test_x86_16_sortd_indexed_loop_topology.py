from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from angr_platforms.X86_16.alias.indexed_address_program import (
    IndexedAliasFunctionSelection8616,
    build_indexed_alias_program_evidence_8616,
)
from angr_platforms.X86_16.codegen_metadata import GlobalDeclarationArrayExtent8616
from angr_platforms.X86_16.ir.core import IRValue, MemSpace
from angr_platforms.X86_16.ir.indexed_address_evidence import (
    collect_indexed_address_evidence_8616,
)
from angr_platforms.X86_16.ir.indexed_address_range_candidates import (
    build_indexed_loop_range_candidates_8616,
    collect_indexed_loop_ranges_from_ssa_8616,
)
from angr_platforms.X86_16.ir.indexed_address_range_contracts import (
    IndexedLoopRangeFailureKind8616,
)
from angr_platforms.X86_16.ir.logical_memory_write_value import (
    LogicalWordWriteValueKind8616,
    trace_logical_word_write_values_8616,
)
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact
from angr_platforms.X86_16.lowering.bounded_global_array_declarations import (
    materialize_project_bounded_global_arrays_8616,
)
from angr_platforms.X86_16.lowering.indexed_global_evidence import (
    IndexedSegmentedGlobalEvidence8616,
)
from angr_platforms.X86_16.widening.indexed_global_object_layout import (
    recover_global_object_layout_evidence_8616,
)
from angr_platforms.X86_16.widening.indexed_global_object_program_ranges import (
    recover_program_bounded_global_object_ranges_8616,
)

from inertia_decompiler.cli_function_discovery import _recover_fast_exe_catalog
from inertia_decompiler.project_loading import _build_project
from scripts.check_sortd_sidecar_free import mz_executable_image

REPO_ROOT = Path(__file__).resolve().parents[2]
SORTD_EXE = REPO_ROOT / "SORTD.EXE"
_INIT_BARS_ADDR = 0x10560
_INITIALIZATION_ADDR = 0x105F0
_UPDATE_ADDR = 0x105F8
_GUARD_ADDR = 0x105FB
_GUARD_TAKEN_ADDR = 0x10607
_GUARD_FALLTHROUGH_ADDR = 0x10604
_COMPUTED_COLOR_ADDR = 0x10654
_CONSTANT_COLOR_ADDR = 0x10647
_BACKEDGE_ADDR = 0x10666
_INDEXED_FACT_COUNT = 3


def test_sortd_initbars_overlap_prefix_reaches_canonical_guard(
    tmp_path: Path,
) -> None:
    """Keep the InitBars update edge separate from its overlapping guard."""
    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTD_EXE.read_bytes()))
    project = _build_project(
        isolated_binary,
        force_blob=False,
        base_addr=0x10000,
        entry_point=0x1000,
    )
    recovered = _recover_fast_exe_catalog(
        project,
        timeout=120,
        window=0x300,
        low_memory=False,
        limit=None,
    )
    function = next(
        candidate
        for _cfg, candidate in recovered
        if candidate.addr == _INIT_BARS_ADDR
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    ssa = build_x86_16_function_ssa(artifact)

    assert artifact.refusals == ()
    assert artifact.condition_evidence is not None
    assert artifact.condition_evidence.complete
    assert ssa.condition_evidence is artifact.condition_evidence
    assert artifact.condition_evidence.conditions_for_block(_UPDATE_ADDR) == ()
    guard_conditions = artifact.condition_evidence.conditions_for_block(_GUARD_ADDR)
    assert len(guard_conditions) == 1
    guard = guard_conditions[0]
    assert guard.op == "sgt"
    assert isinstance(guard.lhs, IRValue)
    assert isinstance(guard.rhs, IRValue)
    assert (guard.lhs.space, guard.lhs.offset, guard.lhs.size) == (
        MemSpace.DS,
        0x0BA2,
        2,
    )
    assert (guard.rhs.space, guard.rhs.offset, guard.rhs.size) == (
        MemSpace.SS,
        -2,
        2,
    )
    assert guard.taken_target == _GUARD_TAKEN_ADDR
    assert guard.fallthrough_target == _GUARD_FALLTHROUGH_ADDR
    # Coherent frontend graphs need no repair; require the resulting topology.
    blocks = {block.addr: block for block in artifact.blocks}
    assert blocks[_UPDATE_ADDR].successor_addrs == (_GUARD_ADDR,)
    assert set(blocks[_GUARD_ADDR].successor_addrs) == {_GUARD_FALLTHROUGH_ADDR, _GUARD_TAKEN_ADDR}
    summary = artifact.summary
    assert (
        summary["block_successor_rewrite_raw_fact_count"]
        == summary["block_successor_rewrite_normalized_fact_count"]
        == summary["block_successor_rewrite_classified_fact_count"]
        == summary["block_successor_rewrite_materialized_count"]
    )
    assert artifact.summary["block_successor_rewrite_failure_count"] == 0
    # Both color paths reach the distinct jump block, not the update directly.
    assert blocks[_COMPUTED_COLOR_ADDR].successor_addrs == (_BACKEDGE_ADDR,)
    assert blocks[_CONSTANT_COLOR_ADDR].successor_addrs == (_BACKEDGE_ADDR,)
    assert blocks[_BACKEDGE_ADDR].successor_addrs == (_UPDATE_ADDR,)
    assert ssa.predecessor_map[_BACKEDGE_ADDR] == (_CONSTANT_COLOR_ADDR, _COMPUTED_COLOR_ADDR)
    assert ssa.predecessor_map[_UPDATE_ADDR] == (_BACKEDGE_ADDR,)
    assert ssa.predecessor_map[_GUARD_ADDR] == (0x105E9, _UPDATE_ADDR)
    assert ssa.predecessor_map[_GUARD_FALLTHROUGH_ADDR] == (_GUARD_ADDR,)
    assert ssa.predecessor_map[_GUARD_TAKEN_ADDR] == (_GUARD_ADDR,)

    indexed = collect_indexed_address_evidence_8616(ssa)
    writes = trace_logical_word_write_values_8616(ssa)
    candidates = build_indexed_loop_range_candidates_8616(
        ssa,
        indexed,
        writes,
    )
    ranges = collect_indexed_loop_ranges_from_ssa_8616(ssa, indexed)

    assert len(candidates) == len(indexed.facts) == _INDEXED_FACT_COUNT
    assert all(candidate.upper_bound is None for candidate in candidates)
    assert all(not candidate.upper_bound_is_constant for candidate in candidates)
    assert all(candidate.guard is not None for candidate in candidates)
    assert all(candidate.guard.condition is guard for candidate in candidates)
    assert all(
        candidate.init_write is not None
        and candidate.init_write.kind
        is LogicalWordWriteValueKind8616.CONSTANT_ZERO
        and candidate.init_write.access.key.insn_addr == _INITIALIZATION_ADDR
        for candidate in candidates
    )
    assert all(
        candidate.step_write is not None
        and candidate.step_write.kind
        is LogicalWordWriteValueKind8616.OLD_LOGICAL_WORD_PLUS_ONE
        and candidate.step_write.access.key.insn_addr == _UPDATE_ADDR
        for candidate in candidates
    )
    assert ranges.closed
    assert ranges.facts == ()
    assert ranges.stats.raw_fact_count == ranges.stats.failure_count == _INDEXED_FACT_COUNT
    assert {
        refusal.failure for refusal in ranges.refusals
    } == {IndexedLoopRangeFailureKind8616.DYNAMIC_BOUND}

    program = build_indexed_alias_program_evidence_8616(
        project,
        (IndexedAliasFunctionSelection8616(_INIT_BARS_ADDR, function),),
    )
    layouts = recover_global_object_layout_evidence_8616(program)
    project_ranges = recover_program_bounded_global_object_ranges_8616(
        program,
        layouts,
    )
    assert project_ranges.closed
    assert project_ranges.ranges == ()
    assert project_ranges.refusals
    project._inertia_project_bounded_global_object_ranges_8616 = project_ranges
    codegen = SimpleNamespace(
        _inertia_global_declaration_specs_8616=(
            (
                "unsigned short",
                "g_0B4C",
                GlobalDeclarationArrayExtent8616.UNKNOWN,
            ),
        )
    )
    declaration_before = codegen._inertia_global_declaration_specs_8616

    assert not materialize_project_bounded_global_arrays_8616(
        project,
        codegen,
        (IndexedSegmentedGlobalEvidence8616(0x0B4C, "g_0B4C", 0, 2),),
    )
    lowering = codegen._inertia_bounded_global_array_lowering_evidence_8616
    assert lowering.closed
    assert lowering.facts == ()
    assert lowering.upstream_refusals == project_ranges.refusals
    assert codegen._inertia_global_declaration_specs_8616 == declaration_before
