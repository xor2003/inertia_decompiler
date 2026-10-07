from __future__ import annotations

from inertia.ir.ssa import SSABlock
from inertia.ir.ssa_cfg import (
    SSACFGFailureKind8616,
    build_ssa_cfg_snapshot_8616,
    classify_ssa_natural_loop_8616,
    compute_ssa_dominators_8616,
)
from inertia.ir.ssa_function import SSAFunctionArtifact


def _artifact(
    predecessor_map: dict[int, tuple[int, ...]],
    *,
    block_addrs: tuple[int, ...] | None = None,
) -> SSAFunctionArtifact:
    addresses = block_addrs or tuple(predecessor_map)
    return SSAFunctionArtifact(
        function_addr=0x100,
        blocks=tuple(SSABlock(address, (), ()) for address in addresses),
        predecessor_map=predecessor_map,
    )


def test_simple_loop_has_exact_dominators_and_natural_topology() -> None:
    artifact = _artifact(
        {
            0x100: (),
            0x110: (0x100, 0x130),
            0x120: (0x110,),
            0x130: (0x120,),
            0x140: (0x110,),
        }
    )

    snapshot = build_ssa_cfg_snapshot_8616(artifact)
    dominators = compute_ssa_dominators_8616(snapshot)
    loop = classify_ssa_natural_loop_8616(snapshot, dominators, 0x110, 0x130)

    assert snapshot.complete
    assert snapshot.edges == (
        (0x100, 0x110),
        (0x110, 0x120),
        (0x110, 0x140),
        (0x120, 0x130),
        (0x130, 0x110),
    )
    assert dominators.dominators(0x130) == (0x100, 0x110, 0x120, 0x130)
    assert loop.complete
    assert loop.blocks == (0x110, 0x120, 0x130)
    assert loop.entry_edges == ((0x100, 0x110),)
    assert loop.backedges == ((0x130, 0x110),)
    assert loop.exit_edges == ((0x110, 0x140),)
    assert loop.stats.raw_fact_count == loop.stats.materialized_count == 1


def test_multiple_predecessors_intersect_dominator_sets() -> None:
    snapshot = build_ssa_cfg_snapshot_8616(
        _artifact(
            {
                0x100: (),
                0x110: (0x100,),
                0x120: (0x100,),
                0x130: (0x120, 0x110),
            },
            block_addrs=(0x130, 0x120, 0x110, 0x100),
        )
    )

    assert snapshot.predecessors(0x130) == (0x110, 0x120)
    dominators = compute_ssa_dominators_8616(snapshot)
    assert dominators.complete
    assert dominators.dominators(0x130) == (0x100, 0x130)
    assert dominators.dominates(0x110, 0x130) is False


def test_disjoint_second_latch_is_a_typed_loop_refusal() -> None:
    snapshot = build_ssa_cfg_snapshot_8616(
        _artifact(
            {
                0x100: (),
                0x110: (0x100, 0x130, 0x150),
                0x120: (0x110,),
                0x130: (0x120,),
                0x140: (0x110,),
                0x150: (0x140,),
                0x160: (0x110,),
            }
        )
    )
    loop = classify_ssa_natural_loop_8616(
        snapshot, compute_ssa_dominators_8616(snapshot), 0x110, 0x130
    )

    assert loop.failure is SSACFGFailureKind8616.NON_UNIQUE_LATCH
    assert loop.blocks == loop.backedges == ()
    assert loop.stats.raw_fact_count == loop.stats.failure_count == 1


def test_unreachable_and_incomplete_successor_evidence_refuse() -> None:
    unreachable = build_ssa_cfg_snapshot_8616(
        _artifact({0x100: (), 0x110: (0x100,), 0x120: ()})
    )
    incomplete = build_ssa_cfg_snapshot_8616(
        _artifact(
            {0x100: (), 0x110: (0x100,)},
            block_addrs=(0x100, 0x110, 0x120),
        )
    )
    unknown_successor = build_ssa_cfg_snapshot_8616(
        _artifact(
            {0x100: (), 0x110: (0x100,), 0x999: (0x110,)},
            block_addrs=(0x100, 0x110),
        )
    )

    assert unreachable.failure is SSACFGFailureKind8616.UNREACHABLE_BLOCK
    assert unreachable.refusal_nodes == (0x120,)
    assert incomplete.failure is SSACFGFailureKind8616.SUCCESSOR_EVIDENCE_INCOMPLETE
    assert incomplete.refusal_nodes == (0x120,)
    assert unknown_successor.failure is SSACFGFailureKind8616.UNKNOWN_SUCCESSOR
    assert unknown_successor.refusal_nodes == (0x999,)
    for refusal in (unreachable, incomplete, unknown_successor):
        assert refusal.block_addrs == refusal.edges == ()
        assert refusal.stats.raw_fact_count == refusal.stats.failure_count == 1


def test_unknown_edge_refusal_is_deterministic_and_blocks_later_proofs() -> None:
    first = _artifact(
        {0x100: (), 0x110: (0x999, 0x100)},
        block_addrs=(0x110, 0x100),
    )
    second = _artifact(
        {0x110: (0x100, 0x999), 0x100: ()},
        block_addrs=(0x100, 0x110),
    )

    first_snapshot = build_ssa_cfg_snapshot_8616(first)
    second_snapshot = build_ssa_cfg_snapshot_8616(second)
    assert first_snapshot == second_snapshot
    assert first_snapshot.failure is SSACFGFailureKind8616.UNKNOWN_PREDECESSOR
    assert first_snapshot.refusal_nodes == (0x999,)

    dominators = compute_ssa_dominators_8616(first_snapshot)
    loop = classify_ssa_natural_loop_8616(first_snapshot, dominators, 0x100, 0x110)
    assert dominators.failure is SSACFGFailureKind8616.SNAPSHOT_UNPROVEN
    assert dominators.dominator_sets == ()
    assert loop.failure is SSACFGFailureKind8616.SNAPSHOT_UNPROVEN
    assert loop.blocks == loop.entry_edges == loop.backedges == loop.exit_edges == ()


def test_external_body_entry_refuses_before_publishing_a_loop() -> None:
    snapshot = build_ssa_cfg_snapshot_8616(
        _artifact(
            {
                0x100: (),
                0x110: (0x100, 0x130),
                0x120: (0x110, 0x150),
                0x130: (0x120,),
                0x140: (0x110,),
                0x150: (0x100,),
            }
        )
    )
    loop = classify_ssa_natural_loop_8616(
        snapshot,
        compute_ssa_dominators_8616(snapshot),
        0x110,
        0x130,
    )

    assert loop.failure is SSACFGFailureKind8616.HEADER_DOMINANCE_UNPROVEN
    assert loop.blocks == ()
    assert loop.stats.raw_fact_count == loop.stats.failure_count == 1
