"""Bounded finite frontier expansion and unequal-step pairing proposals.

Layer: dosunit relational control-flow proposal.
Responsibility: expand each side's collapsed region graph into finite frontier
paths between paired macro-cuts (this slice proposes the entry pair only),
enumerate 1..K concatenations per side, and emit endpoint-compatible pairing
candidates for the solver layer. Every path retains all feasible exits:
nothing is dropped, and every bound that stops expansion is a typed refusal
or a LIMIT status — never silent success and never proof.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from tools.dosunit.compare.macro_step_contracts import (
    FrontierPath,
    MacroDirection,
    MacroEndpointKind,
    MacroSearchStatus,
    MacroStepCounters,
    MacroStepLimits,
    MacroStepProposal,
    MacroStepReason,
    MacroStepRefusal,
    MacroStepSearch,
    PairingCandidate,
)
from tools.dosunit.compare.paired_region_graph import (
    RegionExitKind,
    RegionNode,
    RegionPartition,
    collapse_regions,
)


@dataclass
class _SearchBudget:
    """Shared bounded-search accounting across expansion and pairing."""

    limits: MacroStepLimits
    deadline: float
    states: int = 0
    dead_ends: int = 0

    def tick(self) -> None:
        """Charge one search state; refuse on exhaustion or deadline."""
        self.states += 1
        if self.states > self.limits.max_states:
            raise MacroStepRefusal(MacroStepReason.MACRO_STATE_LIMIT, {"states": self.states})
        if time.monotonic() >= self.deadline:
            raise MacroStepRefusal(MacroStepReason.MACRO_DEADLINE)


def _append_path(paths: list[FrontierPath], path: FrontierPath, budget: _SearchBudget) -> None:
    """Charge every emitted path against the path budget before appending."""
    if len(paths) >= budget.limits.max_paths_per_cut:
        raise MacroStepRefusal(MacroStepReason.MACRO_PATH_LIMIT, {"paths": len(paths) + 1})
    paths.append(path)


def _expand_frontier(
    partition: RegionPartition, cut_heads: frozenset[int], budget: _SearchBudget,
) -> tuple[FrontierPath, ...]:
    """All finite region paths from a cut to the next cut visit or a return.

    Bounded depth-first expansion over the real CFG successors: any reachable
    cycle that does not cross a macro-cut exceeds ``max_frontier_regions`` and
    refuses ``MACRO_DEPTH`` — constructively checking the progress
    precondition that every reachable cycle visits a macro-cut. CALL and
    other non-integer boundaries stay typed refusals in this slice.
    """
    heads = {region.members[0]: index for index, region in enumerate(partition.regions)}
    paths: list[FrontierPath] = []
    # Each stack item is the region index sequence walked so far.
    stack: list[tuple[int, ...]] = [
        (partition.owners[cut_head],) for cut_head in sorted(cut_heads)
    ]
    while stack:
        budget.tick()
        region_indices = stack.pop()
        region = partition.regions[region_indices[-1]]
        if region.kind is RegionExitKind.CALL:
            raise MacroStepRefusal(
                MacroStepReason.MACRO_UNSUPPORTED_BOUNDARY,
                {"head": region.members[0], "kind": region.kind.value},
            )
        if region.kind is RegionExitKind.RETURN:
            _append_path(paths, FrontierPath(
                tuple(partition.regions[index] for index in region_indices),
                partition.regions[region_indices[0]].members[0],
                region.members[0], MacroEndpointKind.RETURN,
            ), budget)
            continue
        for exit_address in region.exits:
            if exit_address in cut_heads:
                _append_path(paths, FrontierPath(
                    tuple(partition.regions[index] for index in region_indices),
                    partition.regions[region_indices[0]].members[0],
                    exit_address, MacroEndpointKind.CONTINUING,
                ), budget)
                continue
            if len(region_indices) >= budget.limits.max_frontier_regions:
                raise MacroStepRefusal(
                    MacroStepReason.MACRO_DEPTH,
                    {"regions": len(region_indices), "at": exit_address},
                )
            next_region = heads.get(exit_address)
            if next_region is None:
                raise MacroStepRefusal(
                    MacroStepReason.MACRO_ENDPOINT, {"head": exit_address},
                )
            stack.append((*region_indices, next_region))
    return tuple(paths)


def _enumerate_concats(
    paths: tuple[FrontierPath, ...], max_segments: int, budget: _SearchBudget,
) -> tuple[tuple[FrontierPath, ...], ...]:
    """All 1..K frontier-path sequences chained through macro-cuts.

    A non-final segment must end at a macro-cut (CONTINUING) whose head starts
    the next segment; the final segment may end at a cut or at a return. Each
    concatenation consumes positive binary progress per segment.
    """
    budget.tick()
    by_start: dict[int, list[FrontierPath]] = {}
    for path in paths:
        by_start.setdefault(path.start_cut, []).append(path)
    concats: list[tuple[FrontierPath, ...]] = [(path,) for path in paths]
    frontier: list[tuple[FrontierPath, ...]] = list(concats)
    for _length in range(2, max_segments + 1):
        extended: list[tuple[FrontierPath, ...]] = []
        for concat in frontier:
            budget.tick()
            last = concat[-1]
            if last.end_kind is not MacroEndpointKind.CONTINUING:
                continue
            for follow in by_start.get(last.end_head, ()):
                budget.tick()
                extended.append((*concat, follow))
        concats.extend(extended)
        frontier = extended
        if not frontier:
            break
    return tuple(concats)


def _endpoints_compatible(
    fast: FrontierPath, slow_last: FrontierPath,
    fast_head_to_slow_head: dict[int, int],
) -> bool:
    """Pair only explicitly paired continuing cuts or matched returns."""
    if fast.end_kind is not slow_last.end_kind:
        return False
    if fast.end_kind is MacroEndpointKind.RETURN:
        return True
    return fast_head_to_slow_head.get(fast.end_head) == slow_last.end_head


def _path_key(path: FrontierPath) -> tuple[int, ...]:
    """Deterministic structural order for paths and concatenations."""
    return tuple(member for region in path.regions for member in region.members)


def _directional_pairings(
    fast_paths: tuple[FrontierPath, ...],
    slow_concats: tuple[tuple[FrontierPath, ...], ...],
    fast_head_to_slow_head: dict[int, int],
    budget: _SearchBudget,
) -> tuple[PairingCandidate, ...]:
    """Endpoint-compatible slow concatenations per fast-side frontier path."""
    pairings: list[PairingCandidate] = []
    for path in fast_paths:
        budget.tick()
        candidates = tuple(sorted(
            (concat for concat in slow_concats
             if _endpoints_compatible(path, concat[-1], fast_head_to_slow_head)),
            key=lambda concat: (len(concat), tuple(_path_key(p) for p in concat)),
        ))
        pairings.append(PairingCandidate(path, candidates))
    return tuple(pairings)


def propose_macro_steps(
    oracle_nodes: dict[int, RegionNode], candidate_nodes: dict[int, RegionNode],
    oracle_entry: int, candidate_entry: int,
    *, limits: MacroStepLimits | None = None, deadline_seconds: float,
) -> MacroStepSearch:
    """Propose entry-cut macro-step pairings under one shared search budget.

    Both partitions collapse through the production finite-chain formation; a
    chain cycle or malformed graph keeps its original typed refusal. The
    proposals are structural only: guard equality, masked state, endpoint
    consistency, coverage and progress all remain solver obligations.
    """
    bound = limits or MacroStepLimits()
    budget = _SearchBudget(bound, time.monotonic() + max(deadline_seconds, 0.001))
    oracle = collapse_regions(oracle_nodes, oracle_entry)
    candidate = collapse_regions(candidate_nodes, candidate_entry)
    oracle_paths = _expand_frontier(oracle, frozenset({oracle_entry}), budget)
    candidate_paths = _expand_frontier(candidate, frozenset({candidate_entry}), budget)
    oracle_concats = _enumerate_concats(oracle_paths, bound.max_concat_segments, budget)
    candidate_concats = _enumerate_concats(candidate_paths, bound.max_concat_segments, budget)

    proposals: list[MacroStepProposal] = []
    pairing_candidates = 0
    ordered = (MacroDirection.ORACLE_SLOWER, MacroDirection.CANDIDATE_SLOWER)
    if len(oracle_paths) > len(candidate_paths):
        ordered = (MacroDirection.CANDIDATE_SLOWER, MacroDirection.ORACLE_SLOWER)
    for direction in ordered:
        fast_is_oracle = direction is MacroDirection.CANDIDATE_SLOWER
        fast_paths = oracle_paths if fast_is_oracle else candidate_paths
        slow_concats = candidate_concats if fast_is_oracle else oracle_concats
        pair_map = ({oracle_entry: candidate_entry} if fast_is_oracle
                    else {candidate_entry: oracle_entry})
        pairings = _directional_pairings(fast_paths, slow_concats, pair_map, budget)
        pairing_candidates += sum(len(candidate.slow_concats) for candidate in pairings)
        proposals.append(MacroStepProposal(
            direction, ((oracle_entry, candidate_entry),), pairings,
            oracle_paths, candidate_paths,
        ))
        if pairing_candidates > bound.max_transitions:
            raise MacroStepRefusal(
                MacroStepReason.MACRO_TRANSITION_LIMIT,
                {"pairing_candidates": pairing_candidates},
            )
    return MacroStepSearch(
        MacroSearchStatus.EXHAUSTED,
        tuple(proposals),
        MacroStepCounters(
            len(oracle_paths), len(candidate_paths),
            len(oracle_concats), len(candidate_concats),
            pairing_candidates, budget.dead_ends,
        ),
    )
