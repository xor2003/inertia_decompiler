"""Closed finite region covers retain rotated guard effects and progress."""
import pytest

from tools.dosunit.finite_region_cover import cover_regions, pair_covers
from tools.dosunit.paired_region_graph import RegionExitKind as K
from tools.dosunit.paired_region_graph import RegionGraphRefusal, RegionNode


def test_rotation_shared_guard_is_composed_on_entry_and_backedge() -> None:
    """Both entry and iteration transitions include the real shared guard."""
    original = {0: RegionNode(0, (2, 1), K.BORING), 1: RegionNode(1, (1, 2), K.BORING),
                2: RegionNode(2, (), K.RETURN)}
    rotated = {0: RegionNode(0, (3,), K.BORING), 1: RegionNode(1, (3,), K.BORING),
               2: RegionNode(2, (), K.RETURN), 3: RegionNode(3, (2, 1), K.BORING)}
    # Original body loop branch true->return matches the guard's true->return.
    original[1] = RegionNode(1, (2, 1), K.BORING)
    left, right = cover_regions(original, 0), cover_regions(rotated, 0)
    assert right.regions[0].members == (0, 3)
    assert right.regions[1].members == (1, 3)
    assert right.covered == frozenset(rotated)
    assert set(right.cutpoints) == {0, 1, 2}
    assert len(pair_covers(left, right)) == 3


@pytest.mark.parametrize('nodes', [
    {0: RegionNode(0, (0,), K.BORING)},
    {0: RegionNode(0, (1,), K.BORING), 1: RegionNode(1, (2,), K.BORING),
     2: RegionNode(2, (1,), K.BORING)},
    {0: RegionNode(0, (9,), K.BORING)},
    {0: RegionNode(0, (), K.RETURN), 1: RegionNode(1, (), K.RETURN)},
])
def test_missing_progress_edges_or_coverage_refuse(nodes: dict[int, RegionNode]) -> None:
    """Cycles, missing edges and uncovered blocks never produce a cover."""
    with pytest.raises(RegionGraphRefusal):
        cover_regions(nodes, 0)


def test_unconditional_entry_reentry_composes_the_original_header() -> None:
    """The function's initial header may also execute inside a later transition."""
    nodes = {0: RegionNode(0, (2, 1), K.BORING),
             1: RegionNode(1, (0,), K.BORING),
             2: RegionNode(2, (), K.RETURN)}
    cover = cover_regions(nodes, 0)
    assert cover.regions[0].members == (0,)
    assert cover.regions[1].members == (1, 0)
    assert cover.regions[1].exits == (2, 1)
    assert cover.covered == frozenset(nodes)


def test_conditional_entry_backedge_retains_the_entry_boundary() -> None:
    """Conditional entry backedges still require the consumer's identity relation."""
    nodes = {0: RegionNode(0, (2, 1), K.BORING),
             1: RegionNode(1, (0, 2), K.BORING),
             2: RegionNode(2, (), K.RETURN)}
    cover = cover_regions(nodes, 0)
    assert cover.regions[1].members == (1,)
    assert cover.regions[1].exits == (0, 2)


def test_conditional_side_entrance_keeps_the_guard_as_a_cutpoint() -> None:
    """A shared guard targeted by a branch cannot disappear into its predecessors."""
    nodes = {0: RegionNode(0, (1, 3), K.BORING),
             1: RegionNode(1, (3,), K.BORING),
             3: RegionNode(3, (4, 1), K.BORING),
             4: RegionNode(4, (), K.RETURN)}
    cover = cover_regions(nodes, 0)
    assert 3 in cover.cutpoints
    assert cover.regions[cover.cutpoints[1]].members == (1,)
    assert cover.regions[cover.cutpoints[3]].members == (3,)


def test_call_continuation_remains_a_separate_cutpoint() -> None:
    """A finite prefix may end at a call but cannot compose unchecked continuation."""
    nodes = {0: RegionNode(0, (1,), K.BORING),
             1: RegionNode(1, (2,), K.CALL),
             2: RegionNode(2, (), K.RETURN)}
    cover = cover_regions(nodes, 0)
    assert cover.regions[0].members == (0, 1)
    assert cover.regions[0].kind is K.CALL
    assert cover.regions[0].exits == (2,)
    assert cover.regions[cover.cutpoints[2]].members == (2,)
