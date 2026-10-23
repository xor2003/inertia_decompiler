"""Independent rejection contracts required before macro-step promotion."""

import time
from typing import cast

import pytest

import tools.dosunit.compare.macro_step_pairing as pairing
import tools.dosunit.ssa.region_path_terms as terms
from tools.dosunit.compare.macro_step_contracts import MacroStepLimits, MacroStepReason, MacroStepRefusal
from tools.dosunit.compare.paired_region_graph import RegionExitKind, RegionNode, collapse_regions


def test_return_frontiers_obey_path_limit() -> None:
    """Return paths consume the same path budget as continuing paths."""
    nodes = {
        0: RegionNode(0, (1, 2), RegionExitKind.BORING),
        1: RegionNode(1, (), RegionExitKind.RETURN),
        2: RegionNode(2, (), RegionExitKind.RETURN),
    }
    budget = pairing._SearchBudget(MacroStepLimits(max_paths_per_cut=1), time.monotonic() + 5)
    with pytest.raises(MacroStepRefusal) as refused:
        pairing._expand_frontier(collapse_regions(nodes, 0), frozenset({0}), budget)
    assert refused.value.reason is MacroStepReason.MACRO_PATH_LIMIT


@pytest.mark.parametrize("width", [None, 0, -1, True, "32"])
def test_missing_or_invalid_width_refuses(width: object) -> None:
    """A malformed scalar cannot acquire a guessed bitvector sort."""
    term: terms.Term = {"op": "input"}
    if width is not None:
        term["width"] = width
    with pytest.raises(MacroStepRefusal) as refused:
        terms.scalar_sentinel(term)
    assert refused.value.reason is MacroStepReason.MACRO_ADMISSION


def test_malformed_memory_cannot_disappear() -> None:
    """Invalid state must refuse rather than silently shrink observables."""
    with pytest.raises(MacroStepRefusal) as refused:
        # Deliberately corrupt a nominally typed boundary to test rejection.
        terms.masked_state(cast(dict[str, terms.Term], {"memory": None}), terms.guard_true())
    assert refused.value.reason is MacroStepReason.MACRO_ADMISSION


def test_multiple_cuts_never_pair_paths_from_different_inputs() -> None:
    """Equal exit kinds do not allow paths to borrow another cut's coverage."""
    nodes = {
        0: RegionNode(0, (1, 2), RegionExitKind.BORING),
        1: RegionNode(1, (1, 2), RegionExitKind.BORING),
        2: RegionNode(2, (), RegionExitKind.RETURN),
    }
    search = pairing.propose_macro_steps(
        nodes, nodes, 0, 0, cut_pairs=((0, 0), (1, 1)), deadline_seconds=5,
    )
    for proposal in search.proposals:
        for candidate in proposal.pairings:
            assert candidate.slow_concats
            assert all(paths[0].start_cut == candidate.fast_path.start_cut
                       for paths in candidate.slow_concats)


@pytest.mark.parametrize("cuts", [(), ((1, 1),), ((0, 0), (1, 0)), ((0, 0), (9, 9))])
def test_invalid_cut_correspondence_is_rejected(cuts: tuple[tuple[int, int], ...]) -> None:
    """Missing entry, duplicate endpoints and nonexistent cuts supply no proof."""
    nodes = {0: RegionNode(0, (1,), RegionExitKind.BORING),
             1: RegionNode(1, (), RegionExitKind.RETURN)}
    with pytest.raises(MacroStepRefusal) as refused:
        pairing.propose_macro_steps(nodes, nodes, 0, 0, cut_pairs=cuts, deadline_seconds=5)
    assert refused.value.reason is MacroStepReason.MACRO_ENDPOINT


@pytest.mark.parametrize("condition,changed,expected", [
    (4, False, "proved"), (4, True, "counterexample"), (2, False, "unknown"),
])
def test_macro_guard_uses_only_demanded_dec_flags(condition: int, changed: bool, expected: str) -> None:
    """DEC zero testing ignores preserved carry; carry testing must retain it."""
    from tools.dosunit.compare.flat32_macro_terms import prove_guard_equal32

    def const(value: int) -> dict:
        return {"op": "const", "width": 32, "value": hex(value)}

    value = {"op": "input", "name": "eax", "width": 32}
    carry = {"op": "summary_x86g_calculate_eflags_c", "width": 32,
             "args": [{"op": "input", "name": name, "width": 32}
                      for name in ("cc_op", "cc_dep1", "cc_dep2", "cc_ndep")]}
    condition_term = {"op": "summary_x86g_calculate_condition", "width": 32,
                      "args": [const(condition), const(21), value, const(0), carry]}
    guard = {"op": "trunc", "width": 1, "args": [condition_term]}
    expected_guard = {"op": "eq", "width": 1, "args": [value, const(1 if changed else 0)]}
    assert prove_guard_equal32(guard, expected_guard, time.monotonic() + 5).value == expected
