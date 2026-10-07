"""Controls for bounded branch-swap cutpoint-bijection proposals.

Layer: tests.
Responsibility: pin that ``propose_branch_bijections`` preserves the
deterministic ordered-zip proposal, enumerates complete closed bijections
when equivalent conditions exchange binary branch arms (``JE``/``JNE``),
refuses partial or non-bijective coverings, stays iterative on cycles, and
reports bounded search completeness honestly. Membership is cross-checked
against an independent brute-force permutation oracle. Every candidate is a
structural proposal only: no candidate proves machine behavior and there is
no PROVED status anywhere in the contract.
"""

from __future__ import annotations

from itertools import permutations

import pytest

import tools.dosunit.compare.region_branch_pairing as rbp
from tools.dosunit.compare.paired_region_graph import (
    CollapsedRegion,
    RegionExitKind,
    RegionGraphReason,
    RegionGraphRefusal,
    pair_region_edges,
)

_BORING = RegionExitKind.BORING
_CALL = RegionExitKind.CALL
_RETURN = RegionExitKind.RETURN


def _layout(spec: list[tuple[RegionExitKind, tuple[int, ...]]]) -> tuple[tuple[CollapsedRegion, ...], dict[int, int]]:
    """Build single-block regions whose exit addresses are region indices."""
    regions = tuple(CollapsedRegion(members=(index,), exits=exits, kind=kind)
                    for index, (kind, exits) in enumerate(spec))
    return regions, {index: index for index in range(len(regions))}


def _propose(oracle: list[tuple[RegionExitKind, tuple[int, ...]]],
             candidate: list[tuple[RegionExitKind, tuple[int, ...]]],
             *, max_states: int = 4096, max_candidates: int = 64,
             deadline_seconds: float | None = None) -> rbp.BranchPairingReport:
    """Run the proposal enumerator over two tiny region layouts."""
    oracle_regions, oracle_targets = _layout(oracle)
    candidate_regions, candidate_targets = _layout(candidate)
    return rbp.propose_branch_bijections(oracle_regions, candidate_regions, oracle_targets,
                                         candidate_targets, 0, 0, max_states=max_states,
                                         max_candidates=max_candidates, deadline_seconds=deadline_seconds)


def _assert_complete(report: rbp.BranchPairingReport, oracle_size: int, candidate_size: int) -> None:
    """Require every reported candidate to be a complete closed bijection."""
    for candidate in report.candidates:
        assert len(candidate) == oracle_size == candidate_size
        lefts, rights = zip(*candidate, strict=True)
        assert sorted(lefts) == list(range(oracle_size))
        assert sorted(rights) == list(range(candidate_size))


def _orders(arity: int) -> tuple[tuple[int, ...], ...]:
    """Independent copy of the permitted permutations used by the oracle."""
    return ((0, 1), (1, 0)) if arity == 2 else (tuple(range(arity)),)


def _brute_force(oracle: list[tuple[RegionExitKind, tuple[int, ...]]],
                 candidate: list[tuple[RegionExitKind, tuple[int, ...]]]) -> set[frozenset[tuple[int, int]]]:
    """Enumerate valid connected bijections without using the proposal search."""
    oracle_regions, oracle_targets = _layout(oracle)
    candidate_regions, candidate_targets = _layout(candidate)
    size = len(oracle_regions)
    if size != len(candidate_regions):
        return set()
    reachable = {oracle_targets[0]}
    frontier = [oracle_targets[0]]
    while frontier:
        index = frontier.pop()
        for target in (oracle_targets[address] for address in oracle_regions[index].exits):
            if target not in reachable:
                reachable.add(target)
                frontier.append(target)
    if reachable != set(range(size)):
        return set()
    valid: set[frozenset[tuple[int, int]]] = set()
    for perm in permutations(range(size)):
        mapping = dict(enumerate(perm))
        if mapping[oracle_targets[0]] != candidate_targets[0]:
            continue
        if all(_consistent(oracle_regions[index], candidate_regions[mapping[index]], mapping,
                           oracle_targets, candidate_targets) for index in range(size)):
            valid.add(frozenset(mapping.items()))
    return valid


def _consistent(original: CollapsedRegion, rebuilt: CollapsedRegion, mapping: dict[int, int],
                oracle_targets: dict[int, int], candidate_targets: dict[int, int]) -> bool:
    """Check kind/arity plus one permitted exit permutation against a map."""
    if original.kind is not rebuilt.kind or len(original.exits) != len(rebuilt.exits):
        return False
    return any(
        all(mapping[oracle_targets[address]] == candidate_targets[rebuilt.exits[index]]
            for address, index in zip(original.exits, order, strict=True))
        for order in _orders(len(original.exits))
    )


def test_ordered_zip_preserved_first() -> None:
    """A linear graph yields exactly the deterministic ordered proposal."""
    report = _propose([(_BORING, (1,)), (_RETURN, ())], [(_BORING, (1,)), (_RETURN, ())])
    expected = ((0, 0), (1, 1))
    assert report.status is rbp.BranchSearchStatus.EXHAUSTED
    assert report.limit is rbp.BranchSearchLimit.NONE
    assert report.ordered == expected
    assert report.candidates == (expected,)
    _assert_complete(report, 2, 2)


def test_reversed_diamond_bijection() -> None:
    """Swapped JE/JNE-style arms pair when the ordered zip refuses SHAPE."""
    oracle = [(_BORING, (1, 2)), (_CALL, (3,)), (_BORING, (3,)), (_RETURN, ())]
    candidate = [(_BORING, (1, 2)), (_BORING, (3,)), (_CALL, (3,)), (_RETURN, ())]
    oracle_regions, oracle_targets = _layout(oracle)
    candidate_regions, candidate_targets = _layout(candidate)
    with pytest.raises(RegionGraphRefusal) as refusal:
        pair_region_edges(oracle_regions, candidate_regions, oracle_targets, candidate_targets, 0, 0)
    assert refusal.value.reason is RegionGraphReason.SHAPE
    report = rbp.propose_branch_bijections(oracle_regions, candidate_regions, oracle_targets,
                                           candidate_targets, 0, 0)
    assert report.status is rbp.BranchSearchStatus.EXHAUSTED
    assert report.ordered is None
    assert [frozenset(candidate) for candidate in report.candidates] == [
        frozenset({(0, 0), (1, 2), (2, 1), (3, 3)})]
    assert report.counters.generated >= 2 and report.counters.dead_ends >= 1
    _assert_complete(report, 4, 4)


def test_reversed_loop_header() -> None:
    """A loop back edge under swapped exits still closes without hanging."""
    oracle = [(_BORING, (1, 2)), (_BORING, (0,)), (_RETURN, ())]
    candidate = [(_BORING, (2, 1)), (_BORING, (0,)), (_RETURN, ())]
    report = _propose(oracle, candidate)
    assert report.status is rbp.BranchSearchStatus.EXHAUSTED
    assert [frozenset(candidate) for candidate in report.candidates] == [
        frozenset({(0, 0), (1, 1), (2, 2)})]
    _assert_complete(report, 3, 3)


def test_symmetric_diamond_keeps_ordered_and_alternative() -> None:
    """Identical arms admit the ordered proposal and the swapped bijection."""
    diamond = [(_BORING, (1, 2)), (_BORING, (3,)), (_BORING, (3,)), (_RETURN, ())]
    report = _propose(diamond, diamond)
    assert report.ordered == report.candidates[0]
    assert report.status is rbp.BranchSearchStatus.EXHAUSTED
    assert {frozenset(candidate) for candidate in report.candidates} == {
        frozenset({(0, 0), (1, 1), (2, 2), (3, 3)}),
        frozenset({(0, 0), (1, 2), (2, 1), (3, 3)}),
    }
    _assert_complete(report, 4, 4)


def test_missing_region_not_bijective() -> None:
    """A collapsed join cannot cover two oracle exits; nothing is proposed."""
    oracle = [(_BORING, (1, 2)), (_BORING, (3,)), (_BORING, (4,)), (_RETURN, ()), (_RETURN, ())]
    candidate = [(_BORING, (1, 2)), (_BORING, (3,)), (_BORING, (3,)), (_RETURN, ())]
    report = _propose(oracle, candidate)
    assert report.status is rbp.BranchSearchStatus.EXHAUSTED
    assert report.candidates == () and report.counters.dead_ends >= 1


def test_partial_pairing_never_masquerades() -> None:
    """A consistent partial pairing over fewer regions is not a candidate."""
    report = _propose([(_BORING, (1,)), (_RETURN, ()), (_RETURN, ())],
                      [(_BORING, (1,)), (_RETURN, ())])
    assert report.status is rbp.BranchSearchStatus.EXHAUSTED
    assert report.candidates == () and report.ordered is None


def test_input_refusals_propagate() -> None:
    """Malformed inputs keep the typed refusals permutation cannot repair."""
    regions, targets = _layout([(_BORING, (1,)), (_RETURN, ())])
    with pytest.raises(RegionGraphRefusal) as entry:
        rbp.propose_branch_bijections(regions, regions, targets, targets, 99, 0)
    assert entry.value.reason is RegionGraphReason.ENTRY
    with pytest.raises(RegionGraphRefusal) as unmapped:
        rbp.propose_branch_bijections((CollapsedRegion(members=(0,), exits=(9,), kind=_BORING),),
                                      regions, {0: 0}, targets, 0, 0)
    assert unmapped.value.reason is RegionGraphReason.UNMAPPED
    with pytest.raises(RegionGraphRefusal) as empty:
        rbp.propose_branch_bijections((), regions, targets, targets, 0, 0)
    assert empty.value.reason is RegionGraphReason.EMPTY


def test_ternary_exits_keep_ordered_zip() -> None:
    """Wider cutpoint arity never permutes; a SHAPE failure stays fatal."""
    oracle = [(_BORING, (1, 2, 3)), (_CALL, (4,)), (_BORING, (4,)), (_BORING, (4,)), (_RETURN, ())]
    candidate = [(_BORING, (1, 2, 3)), (_BORING, (4,)), (_CALL, (4,)), (_BORING, (4,)), (_RETURN, ())]
    report = _propose(oracle, candidate)
    assert report.status is rbp.BranchSearchStatus.EXHAUSTED
    assert report.candidates == ()
    assert rbp._exit_orders(3) == ((0, 1, 2),)


def test_deterministic_reports() -> None:
    """Identical inputs produce identical reports including candidate order."""
    oracle = [(_BORING, (1, 2)), (_CALL, (3,)), (_BORING, (3,)), (_RETURN, ())]
    candidate = [(_BORING, (1, 2)), (_BORING, (3,)), (_CALL, (3,)), (_RETURN, ())]
    assert _propose(oracle, candidate) == _propose(oracle, candidate)
    diamond = [(_BORING, (1, 2)), (_BORING, (3,)), (_BORING, (3,)), (_RETURN, ())]
    assert _propose(diamond, diamond) == _propose(diamond, diamond)


def test_max_states_limit() -> None:
    """A zero state budget stops before any expansion and says LIMIT."""
    diamond = [(_BORING, (1, 2)), (_BORING, (3,)), (_BORING, (3,)), (_RETURN, ())]
    report = _propose(diamond, diamond, max_states=0)
    assert report.status is rbp.BranchSearchStatus.LIMIT
    assert report.limit is rbp.BranchSearchLimit.MAX_STATES
    assert report.candidates == () and report.ordered is None
    _assert_complete(report, 4, 4)


def test_max_candidates_limit() -> None:
    """The alternative cap keeps the ordered proposal and reports LIMIT."""
    diamond = [(_BORING, (1, 2)), (_BORING, (3,)), (_BORING, (3,)), (_RETURN, ())]
    report = _propose(diamond, diamond, max_candidates=1)
    assert report.status is rbp.BranchSearchStatus.LIMIT
    assert report.limit is rbp.BranchSearchLimit.MAX_CANDIDATES
    assert report.candidates == (report.ordered,)


def test_deadline_limit() -> None:
    """An immediate deadline reports DEADLINE rather than exhaustion."""
    oracle = [(_BORING, (1, 2)), (_CALL, (3,)), (_BORING, (3,)), (_RETURN, ())]
    candidate = [(_BORING, (1, 2)), (_BORING, (3,)), (_CALL, (3,)), (_RETURN, ())]
    report = _propose(oracle, candidate, deadline_seconds=0.0)
    assert report.status is rbp.BranchSearchStatus.LIMIT
    assert report.limit is rbp.BranchSearchLimit.DEADLINE
    assert report.candidates == ()


_BRUTE_CASES: list[tuple[list[tuple[RegionExitKind, tuple[int, ...]]],
                         list[tuple[RegionExitKind, tuple[int, ...]]]]] = [
    ([(_BORING, (1,)), (_RETURN, ())],
     [(_BORING, (1,)), (_RETURN, ())]),
    ([(_BORING, (1, 2)), (_BORING, (3,)), (_BORING, (3,)), (_RETURN, ())],
     [(_BORING, (1, 2)), (_BORING, (3,)), (_BORING, (3,)), (_RETURN, ())]),
    ([(_BORING, (1, 2)), (_CALL, (3,)), (_BORING, (3,)), (_RETURN, ())],
     [(_BORING, (1, 2)), (_BORING, (3,)), (_CALL, (3,)), (_RETURN, ())]),
    ([(_BORING, (1, 2)), (_BORING, (0,)), (_RETURN, ())],
     [(_BORING, (2, 1)), (_BORING, (0,)), (_RETURN, ())]),
    ([(_BORING, (1, 2)), (_BORING, (3,)), (_BORING, (4,)), (_RETURN, ()), (_RETURN, ())],
     [(_BORING, (1, 2)), (_BORING, (3,)), (_BORING, (3,)), (_RETURN, ())]),
    ([(_BORING, (1,)), (_RETURN, ()), (_RETURN, ())],
     [(_BORING, (1,)), (_RETURN, ())]),
]


def test_brute_force_membership() -> None:
    """Exhausted candidates equal the independent permutation oracle's set."""
    for oracle, candidate in _BRUTE_CASES:
        report = _propose(oracle, candidate)
        assert report.status is rbp.BranchSearchStatus.EXHAUSTED
        assert {frozenset(pairing) for pairing in report.candidates} == _brute_force(oracle, candidate)
        assert report.ordered is None or report.candidates[0] == report.ordered
        _assert_complete(report, len(oracle), len(candidate))


def test_parent_zero_candidate_budget_emits_nothing() -> None:
    """A total result cap cannot be bypassed by the preferred ordered map."""
    graph = [(_BORING, (1,)), (_RETURN, ())]
    report = _propose(graph, graph, max_candidates=0)
    assert report.candidates == ()
    assert report.ordered is None
    assert report.limit is rbp.BranchSearchLimit.MAX_CANDIDATES


def test_parent_expired_deadline_emits_no_ordered_proposal() -> None:
    """Ordered graph work is subject to the same deadline as alternatives."""
    graph = [(_BORING, (1,)), (_RETURN, ())]
    report = _propose(graph, graph, deadline_seconds=0)
    assert report.candidates == ()
    assert report.ordered is None
    assert report.counters.expanded == 0
    assert report.limit is rbp.BranchSearchLimit.DEADLINE
