"""Finite paired CFG proposals retain entry, calls, closure and progress."""

import pytest

from tools.dosunit.paired_region_graph import (
    RegionExitKind,
    RegionGraphReason,
    RegionGraphRefusal,
    RegionNode,
    collapse_regions,
    pair_regions,
)


def _loop():
    return {0: RegionNode(0, (1, 3), RegionExitKind.BORING),
            1: RegionNode(1, (0, 3), RegionExitKind.BORING),
            3: RegionNode(3, (), RegionExitKind.RETURN)}


def test_finite_reblocking_keeps_entry_and_all_real_steps():
    original = collapse_regions(_loop(), 0)
    split = {10: RegionNode(10, (11, 13), RegionExitKind.BORING),
             11: RegionNode(11, (12,), RegionExitKind.BORING),
             12: RegionNode(12, (10, 13), RegionExitKind.BORING),
             13: RegionNode(13, (), RegionExitKind.RETURN)}
    candidate = collapse_regions(split, 10)
    pairs = pair_regions(original, candidate)
    assert len(pairs) == 3
    assert original.regions[original.owners[0]].members[0] == 0
    assert candidate.regions[candidate.owners[10]].members[0] == 10
    assert candidate.regions[candidate.owners[11]].members == (11, 12)
    assert set(candidate.owners) == set(split)


def test_call_is_a_boundary_even_with_one_continuation_predecessor():
    nodes = {0: RegionNode(0, (1,), RegionExitKind.CALL),
             1: RegionNode(1, (), RegionExitKind.RETURN)}
    partition = collapse_regions(nodes, 0)
    assert partition.owners[0] != partition.owners[1]
    assert partition.regions[partition.owners[0]].kind is RegionExitKind.CALL


@pytest.mark.parametrize("nodes,entry,reason", [
    ({}, 0, RegionGraphReason.EMPTY),
    ({0: RegionNode(0, (), RegionExitKind.RETURN)}, 1, RegionGraphReason.ENTRY),
    ({0: RegionNode(0, (1,), RegionExitKind.BORING)}, 0, RegionGraphReason.UNMAPPED),
    ({0: RegionNode(0, (0,), RegionExitKind.BORING)}, 0, RegionGraphReason.CHAIN_CYCLE),
    ({0: RegionNode(0, (), RegionExitKind.RETURN), 1: RegionNode(1, (2,), RegionExitKind.BORING),
      2: RegionNode(2, (1,), RegionExitKind.BORING)}, 0, RegionGraphReason.CHAIN_CYCLE),
])
def test_incomplete_or_nonprogressing_graphs_refuse(nodes, entry, reason):
    with pytest.raises(RegionGraphRefusal) as caught:
        collapse_regions(nodes, entry)
    assert caught.value.reason is reason


def test_unpaired_unreachable_region_does_not_disappear():
    original = collapse_regions(_loop(), 0)
    changed = _loop()
    changed[4] = RegionNode(4, (), RegionExitKind.RETURN)
    with pytest.raises(RegionGraphRefusal) as caught:
        pair_regions(original, collapse_regions(changed, 0))
    assert caught.value.reason is RegionGraphReason.CLOSURE


def test_one_cutpoint_cannot_pair_with_two_distinct_boundaries():
    original = {0: RegionNode(0, (1, 2), RegionExitKind.BORING),
                1: RegionNode(1, (3,), RegionExitKind.CALL),
                2: RegionNode(2, (3,), RegionExitKind.CALL),
                3: RegionNode(3, (), RegionExitKind.RETURN)}
    changed = {10: RegionNode(10, (11, 12), RegionExitKind.BORING),
               11: RegionNode(11, (13,), RegionExitKind.CALL),
               12: RegionNode(12, (14,), RegionExitKind.CALL),
               13: RegionNode(13, (), RegionExitKind.RETURN),
               14: RegionNode(14, (), RegionExitKind.RETURN)}
    with pytest.raises(RegionGraphRefusal) as caught:
        pair_regions(collapse_regions(original, 0), collapse_regions(changed, 10))
    assert caught.value.reason is RegionGraphReason.BIJECTION
