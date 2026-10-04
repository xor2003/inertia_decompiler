"""Bounded alternative cutpoint bijections for reversed branch successors.

Layer: dosunit relational control-flow proposal search.
Responsibility: enumerate complete closed region bijections that preserve
region kinds and boundary arity while allowing the two exits of a binary
branch region to pair in either order. This covers the ``JE``/``JNE``
formation where equivalent conditions exchange successor arms.

Every returned pairing is a structural proposal only. It never labels the
graph as proved: state materialization, actual guard agreement, transition
effects and internal progress stay with the existing complete proof
consumers, which must still check each proposed pair. There is no PROVED
status here and no name, address, source or rendered-C evidence.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import StrEnum

from tools.dosunit.paired_region_graph import (
    CollapsedRegion,
    RegionGraphReason,
    RegionGraphRefusal,
)


class BranchSearchStatus(StrEnum):
    """Whether the bounded enumeration covered the whole search space."""

    EXHAUSTED = "exhausted"
    LIMIT = "limit_reached"


class BranchSearchLimit(StrEnum):
    """Which bound ended the enumeration, if any did."""

    NONE = "none"
    MAX_STATES = "max_states"
    MAX_CANDIDATES = "max_candidates"
    DEADLINE = "deadline"


@dataclass(frozen=True, slots=True)
class BranchSearchCounters:
    """Work counters recording exactly what the enumeration did."""

    expanded: int
    generated: int
    dead_ends: int
    duplicates: int


@dataclass(frozen=True, slots=True)
class BranchPairingReport:
    """Complete cutpoint-bijection proposals plus typed search completeness.

    ``ordered`` retains the deterministic typed-IR-order zip proposal when it
    is a complete closed bijection; it is then also ``candidates[0]`` within the same total resource bounds.
    ``candidates`` contains only complete bijections covering every region of
    both layouts; a partial pairing is never reported. ``status`` is
    ``EXHAUSTED`` only when the bounded search visited the whole space, so an
    exhausted report with empty ``candidates`` means no such bijection exists
    within the permitted permutations, while ``LIMIT`` reports a possibly
    incomplete result set that must not be read as absence.
    """

    status: BranchSearchStatus
    limit: BranchSearchLimit
    ordered: tuple[tuple[int, int], ...] | None
    candidates: tuple[tuple[tuple[int, int], ...], ...]
    counters: BranchSearchCounters
    ordered_refusal: RegionGraphReason | None = None


@dataclass(frozen=True, slots=True)
class _SearchState:
    """One queued frontier under a fixed partial bijection."""

    forward: dict[int, int]
    backward: dict[int, int]
    pending: tuple[tuple[int, int], ...]
    pairs: tuple[tuple[int, int], ...]
    ordered: bool = True


def _expand(state: _SearchState, oracle_regions: tuple[CollapsedRegion, ...],
            candidate_regions: tuple[CollapsedRegion, ...],
            oracle_targets: dict[int, int],
            candidate_targets: dict[int, int]) -> tuple[list[_SearchState], bool, RegionGraphReason | None]:
    """Advance one frontier item under the bijection rules.

    Returns ``(children, complete, dead_end)``: ``complete`` means the drained
    frontier closed over every region of both layouts, ``dead_end`` means this
    branch violated bijection, kind/arity or closure and produced nothing.
    """
    if not state.pending:
        complete = len(state.pairs) == len(oracle_regions) == len(candidate_regions)
        return [], complete, None if complete else RegionGraphReason.CLOSURE
    (left, right), rest = state.pending[0], state.pending[1:]
    known = state.forward.get(left)
    if known is not None:
        if known == right:
            return [_SearchState(state.forward, state.backward, rest, state.pairs, state.ordered)], False, None
        return [], False, RegionGraphReason.BIJECTION
    if right in state.backward:
        return [], False, RegionGraphReason.BIJECTION
    original, rebuilt = oracle_regions[left], candidate_regions[right]
    if original.kind is not rebuilt.kind or len(original.exits) != len(rebuilt.exits):
        return [], False, RegionGraphReason.SHAPE
    forward, backward = {**state.forward, left: right}, {**state.backward, right: left}
    pairs = (*state.pairs, (left, right))
    children: list[_SearchState] = []
    for order in reversed(_exit_orders(len(original.exits))):
        pending = rest + tuple(
            (oracle_targets[exit_address], candidate_targets[rebuilt.exits[index]])
            for exit_address, index in zip(original.exits, order, strict=True)
        )
        children.append(_SearchState(forward, backward, pending, pairs, state.ordered and order == tuple(range(len(original.exits)))))
    return children, False, None


def _exit_orders(arity: int) -> tuple[tuple[int, ...], ...]:
    """Permitted successor permutations; only binary branches may exchange arms.

    Identity order always comes first so the deterministic typed-IR proposal
    stays the preferred alternative. Wider cutpoint arity keeps the strict
    ordered zip; permuting jump-table-like exits is out of scope.
    """
    if arity == 2:
        return ((0, 1), (1, 0))
    return (tuple(range(arity)),)


def _validate_inputs(
    oracle_regions: tuple[CollapsedRegion, ...], candidate_regions: tuple[CollapsedRegion, ...],
    oracle_targets: dict[int, int], candidate_targets: dict[int, int],
    oracle_entry: int, candidate_entry: int,
) -> None:
    """Reject malformed closed layouts before proposing any correspondence."""
    if oracle_entry not in oracle_targets or candidate_entry not in candidate_targets:
        raise RegionGraphRefusal(RegionGraphReason.ENTRY)
    if not oracle_regions or not candidate_regions:
        raise RegionGraphRefusal(RegionGraphReason.EMPTY)
    for regions, targets in ((oracle_regions, oracle_targets), (candidate_regions, candidate_targets)):
        if any(not region.members for region in regions):
            raise RegionGraphRefusal(RegionGraphReason.EMPTY)
        if any(target not in targets for region in regions for target in region.exits):
            raise RegionGraphRefusal(RegionGraphReason.UNMAPPED)
        if any(not 0 <= index < len(regions) for index in targets.values()):
            raise RegionGraphRefusal(RegionGraphReason.BIJECTION)

def propose_branch_bijections(
    oracle_regions: tuple[CollapsedRegion, ...],
    candidate_regions: tuple[CollapsedRegion, ...],
    oracle_targets: dict[int, int],
    candidate_targets: dict[int, int],
    oracle_entry: int,
    candidate_entry: int,
    *,
    max_states: int = 4096,
    max_candidates: int = 64,
    deadline_seconds: float | None = None,
) -> BranchPairingReport:
    """Enumerate complete closed region bijections under binary-arm swaps.

    The deterministic ordered-zip proposal is the first search branch,
    subject to the same total deadline and work/result caps as alternatives. The bounded depth-first enumeration then
    revisits the same forward/backward bijection rules while permitting each
    paired binary branch to pair its exits in either order. Search is always
    bounded by ``max_states`` and ``max_candidates`` and optionally by
    ``deadline_seconds``; it is iterative, so cyclic graphs cannot overflow
    Python recursion. Input refusals that permutation cannot repair
    (``EMPTY``/``ENTRY``/``UNMAPPED``) propagate unchanged.
    """
    if max_states < 0 or max_candidates < 0:
        raise ValueError("branch search bounds must be nonnegative")
    start = time.monotonic()
    _validate_inputs(oracle_regions, candidate_regions, oracle_targets, candidate_targets, oracle_entry, candidate_entry)

    ordered: tuple[tuple[int, int], ...] | None = None
    candidates: list[tuple[tuple[int, int], ...]] = []
    seen: set[frozenset[tuple[int, int]]] = set()
    status, limit = BranchSearchStatus.EXHAUSTED, BranchSearchLimit.NONE
    expanded = generated = dead_ends = duplicates = 0
    ordered_refusal: RegionGraphReason | None = None
    stack = [_SearchState({}, {}, ((oracle_targets[oracle_entry], candidate_targets[candidate_entry]),), ())]
    while stack:
        if deadline_seconds is not None and time.monotonic() - start >= deadline_seconds:
            status, limit = BranchSearchStatus.LIMIT, BranchSearchLimit.DEADLINE
            break
        if expanded >= max_states or len(candidates) >= max_candidates:
            status = BranchSearchStatus.LIMIT
            limit = BranchSearchLimit.MAX_STATES if expanded >= max_states else BranchSearchLimit.MAX_CANDIDATES
            break
        state = stack.pop()
        expanded += 1
        children, complete, dead_end = _expand(state, oracle_regions, candidate_regions,
                                               oracle_targets, candidate_targets)
        generated += len(children)
        stack.extend(children)
        if dead_end is not None:
            dead_ends += 1
            if state.ordered:
                ordered_refusal = dead_end
        elif complete:
            key = frozenset(state.pairs)
            if state.ordered:
                ordered = state.pairs
            if key in seen:
                duplicates += 1
            else:
                seen.add(key)
                candidates.append(state.pairs)
    return BranchPairingReport(status, limit, ordered, tuple(candidates),
                               BranchSearchCounters(expanded, generated, dead_ends, duplicates), ordered_refusal)
