"""Independent exhaustive tiny-graph oracle for untrusted branch proposals."""

from itertools import permutations, product

import tools.dosunit.compare.region_branch_pairing as owner
from tools.dosunit.compare.paired_region_graph import (
    CollapsedRegion,
    RegionExitKind,
    RegionGraphRefusal,
    pair_region_edges,
)

type Layout = tuple[CollapsedRegion, ...]


def _oracle(left: Layout, right: Layout) -> set[frozenset[tuple[int, int]]]:
    """Check all total maps with adjacency constraints, without a search frontier."""
    if len(left) != len(right):
        return set()
    reachable = {0}
    while True:
        expanded = reachable | {target for index in reachable for target in left[index].exits}
        if expanded == reachable:
            break
        reachable = expanded
    if reachable != set(range(len(left))):
        return set()
    accepted = set()
    for mapping in permutations(range(len(right))):
        if mapping[0] != 0:
            continue
        valid = True
        for index, original in enumerate(left):
            rebuilt = right[mapping[index]]
            expected = tuple(mapping[target] for target in original.exits)
            same_edges = (set(expected) == set(rebuilt.exits) if len(expected) == 2
                          else expected == rebuilt.exits)
            if original.kind is not rebuilt.kind or not same_edges:
                valid = False
                break
        if valid:
            accepted.add(frozenset(enumerate(mapping)))
    return accepted


def _layouts(size: int) -> list[Layout]:
    """Enumerate admitted single/dual edge and CALL/RETURN shapes deterministically."""
    choices = [(RegionExitKind.RETURN, ())]
    choices += [(kind, (target,)) for kind in (RegionExitKind.BORING, RegionExitKind.CALL)
                for target in range(size)]
    choices += [(RegionExitKind.BORING, (left, right))
                for left in range(size) for right in range(size) if left != right]
    return [tuple(CollapsedRegion((index,), exits, kind) for index, (kind, exits) in enumerate(spec))
            for spec in product(choices, repeat=size)]


def _check(left: Layout, right: Layout) -> None:
    """Require exact complete candidate sets and unchanged preferred legacy maps."""
    targets = dict(enumerate(range(len(left))))
    report = owner.propose_branch_bijections(left, right, targets, targets, 0, 0)
    assert report.status is owner.BranchSearchStatus.EXHAUSTED
    assert {frozenset(candidate) for candidate in report.candidates} == _oracle(left, right)
    try:
        ordered = pair_region_edges(left, right, targets, targets, 0, 0)
    except RegionGraphRefusal as error:
        assert report.ordered is None
        assert report.ordered_refusal is error.reason
    else:
        assert report.ordered == ordered
        assert report.candidates[0] == ordered


def test_exhaustive_two_region_pairs() -> None:
    """All 2401 two-region layout pairs agree with total-map enumeration."""
    layouts = _layouts(2)
    assert len(layouts) == 49
    for left, right in product(layouts, repeat=2):
        _check(left, right)


def test_deterministic_three_region_sample() -> None:
    """Independent larger samples include cyclic and disconnected graph shapes."""
    layouts = _layouts(3)
    for index in range(128):
        left = layouts[(index * 31) % len(layouts)]
        right = layouts[(index * 97 + 11) % len(layouts)]
        _check(left, right)
        _check(left, left)
