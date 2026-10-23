"""Typed partition and finite-cover proposals for complete region proofs.

Layer: dosunit relational control-flow proof.
Responsibility: preserve the disjoint-partition path, retain its typed rejection,
and propose a complete overlapping cover for rotated guards. All results remain
unproved until consumers establish complete state, control and progress.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import StrEnum

from tools.dosunit.compare.finite_region_cover import FiniteRegionCover, cover_regions, pair_covers
from tools.dosunit.compare.paired_region_graph import (
    CollapsedRegion,
    RegionExitKind,
    RegionGraphReason,
    RegionGraphRefusal,
    RegionNode,
    RegionPartition,
    collapse_regions,
    pair_regions,
)
from tools.dosunit.compare.region_branch_pairing import BranchPairingReport, propose_branch_bijections

type RegionLayout = RegionPartition | FiniteRegionCover


class RegionFormation(StrEnum):
    """The exact binary CFG formation whose transitions require proof."""

    PARTITION = 'disjoint_finite_partition'
    COVER = 'overlapping_finite_cover'
    TERMINAL_COVER = 'shared_terminal_suffix_cover'


class BranchOrientation(StrEnum):
    """Structural successor order proposed for complete solver discharge."""

    ORDERED = 'ordered_successors'
    PERMUTED = 'permuted_binary_successors'


@dataclass(frozen=True, slots=True)
class RegionPairingEvidence:
    """Complete coverage and rejected graph evidence for one untrusted proposal."""

    formation: RegionFormation
    oracle_blocks: int
    candidate_blocks: int
    oracle_occurrences: int
    candidate_occurrences: int
    paired_cutpoints: int
    rejected_partition: RegionGraphReason | None = None
    orientation: BranchOrientation = BranchOrientation.ORDERED
    terminal_merges: bool = False
    state_merges: bool = False


@dataclass(frozen=True, slots=True)
class PairedRegions:
    """Two complete finite layouts and an unproved closed cutpoint bijection."""

    oracle: RegionLayout
    candidate: RegionLayout
    pairs: tuple[tuple[int, int], ...]
    evidence: RegionPairingEvidence


@dataclass(frozen=True, slots=True)
class RegionCandidateEvidence:
    """Serializable untrusted mapping and its complete coverage accounting."""

    pairs: tuple[tuple[int, int], ...]
    coverage: RegionPairingEvidence


@dataclass(frozen=True, slots=True)
class RegionPairingDiagnostics:
    """Durable search evidence without retaining executable layout objects."""

    candidates: tuple[RegionCandidateEvidence, ...]
    searches: tuple[tuple[RegionFormation, BranchPairingReport], ...]
    refusals: tuple[tuple[RegionFormation, RegionGraphReason], ...]


@dataclass(frozen=True, slots=True)
class RegionPairingSearch:
    """Unproved complete graph candidates and their bounded search evidence."""

    candidates: tuple[PairedRegions, ...]
    searches: tuple[tuple[RegionFormation, BranchPairingReport], ...]
    refusals: tuple[tuple[RegionFormation, RegionGraphReason], ...] = ()

    def evidence(self) -> RegionPairingDiagnostics:
        """Project exact proposal accounting into public JSON-safe contracts."""
        return RegionPairingDiagnostics(
            tuple(RegionCandidateEvidence(candidate.pairs, candidate.evidence) for candidate in self.candidates),
            self.searches, self.refusals,
        )



def _repeated_kind(
    pairs: tuple[tuple[int, int], ...], left: tuple[CollapsedRegion, ...],
    right: tuple[CollapsedRegion, ...], kind: RegionExitKind,
) -> bool:
    """Report reused indices by boundary kind without inferring equality."""
    return any(len(indices := [pair[side] for pair in pairs if regions[pair[side]].kind is kind])
               > len(set(indices)) for side, regions in enumerate((left, right)))


def _proposals(
    left: RegionLayout, right: RegionLayout, formation: RegionFormation,
    oracle_blocks: int, candidate_blocks: int, rejected: RegionGraphReason | None,
    *, deadline_seconds: float, max_candidates: int, allow_terminal_merges: bool = False,
    allow_state_merges: bool = False,
) -> tuple[tuple[PairedRegions, ...], BranchPairingReport]:
    """Keep successor order as evidence, never as a state-equality verdict."""
    left_targets = left.owners if isinstance(left, RegionPartition) else left.cutpoints
    right_targets = right.owners if isinstance(right, RegionPartition) else right.cutpoints
    report = propose_branch_bijections(
        left.regions, right.regions, left_targets, right_targets, left.entry, right.entry,
        deadline_seconds=deadline_seconds, max_candidates=max_candidates,
        allow_terminal_merges=allow_terminal_merges, allow_state_merges=allow_state_merges,
    )
    proposals = tuple(PairedRegions(left, right, pairs, RegionPairingEvidence(
        formation, oracle_blocks, candidate_blocks,
        sum(len(region.members) for region in left.regions),
        sum(len(region.members) for region in right.regions), len(pairs), rejected,
        BranchOrientation.ORDERED if pairs == report.ordered else BranchOrientation.PERMUTED,
        _repeated_kind(pairs, left.regions, right.regions, RegionExitKind.RETURN),
        _repeated_kind(pairs, left.regions, right.regions, RegionExitKind.BORING),
    )) for pairs in report.candidates)
    return proposals, report


def propose_region_pairings(
    oracle: dict[int, RegionNode], candidate: dict[int, RegionNode],
    oracle_entry: int, candidate_entry: int, *, deadline_seconds: float,
    max_candidates: int = 64,
    allow_terminal_merges: bool = False,
    allow_state_merges: bool = False,
) -> RegionPairingSearch:
    """Propose partition and cover bijections under one total search deadline.

    A consumer may prove any complete candidate even when enumeration reached a
    limit. Neither exhausted enumeration nor a structural proposal proves a
    mismatch or equality. The original singular API retains its ordered path.
    """
    deadline = time.monotonic() + max(deadline_seconds, 0.0)
    left = collapse_regions(oracle, oracle_entry)
    right = collapse_regions(candidate, candidate_entry)
    partition, partition_report = _proposals(
        left, right, RegionFormation.PARTITION, len(oracle), len(candidate), None,
        deadline_seconds=deadline - time.monotonic(), max_candidates=max_candidates,
        allow_terminal_merges=allow_terminal_merges, allow_state_merges=allow_state_merges,
    )
    rejected = partition_report.ordered_refusal
    try:
        left_cover = cover_regions(oracle, oracle_entry)
        right_cover = cover_regions(candidate, candidate_entry)
    except RegionGraphRefusal as error:
        return RegionPairingSearch(partition, ((RegionFormation.PARTITION, partition_report),),
                                   ((RegionFormation.COVER, error.reason),))
    cover, cover_report = _proposals(
        left_cover, right_cover, RegionFormation.COVER, len(oracle), len(candidate), rejected,
        deadline_seconds=deadline - time.monotonic(), max_candidates=max_candidates - len(partition),
        allow_terminal_merges=allow_terminal_merges, allow_state_merges=allow_state_merges,
    )
    candidates = partition + cover
    reports = ((RegionFormation.PARTITION, partition_report), (RegionFormation.COVER, cover_report))
    if not allow_terminal_merges:
        return RegionPairingSearch(candidates, reports)
    try:
        terminal_left = cover_regions(oracle, oracle_entry, include_terminal_suffixes=True)
        terminal_right = cover_regions(candidate, candidate_entry, include_terminal_suffixes=True)
    except RegionGraphRefusal as error:
        return RegionPairingSearch(candidates, reports, ((RegionFormation.TERMINAL_COVER, error.reason),))
    if terminal_left == left_cover and terminal_right == right_cover:
        return RegionPairingSearch(candidates, reports)
    terminal, terminal_report = _proposals(
        terminal_left, terminal_right, RegionFormation.TERMINAL_COVER, len(oracle), len(candidate), rejected,
        deadline_seconds=deadline - time.monotonic(), max_candidates=max_candidates - len(candidates),
        allow_terminal_merges=allow_terminal_merges, allow_state_merges=allow_state_merges,
    )
    return RegionPairingSearch(candidates + terminal, (*reports, (RegionFormation.TERMINAL_COVER, terminal_report)))


def propose_paired_regions(
    oracle: dict[int, RegionNode], candidate: dict[int, RegionNode],
    oracle_entry: int, candidate_entry: int,
) -> PairedRegions:
    """Try the established partition before proposing shared finite suffixes."""
    rejected: RegionGraphReason | None = None
    try:
        left = collapse_regions(oracle, oracle_entry)
        right = collapse_regions(candidate, candidate_entry)
        pairs = pair_regions(left, right)
    except RegionGraphRefusal as error:
        if error.reason not in {RegionGraphReason.SHAPE, RegionGraphReason.BIJECTION}:
            raise
        rejected = error.reason
    else:
        return PairedRegions(left, right, pairs, RegionPairingEvidence(
            RegionFormation.PARTITION, len(oracle), len(candidate),
            sum(len(region.members) for region in left.regions),
            sum(len(region.members) for region in right.regions), len(pairs)))
    left_cover = cover_regions(oracle, oracle_entry)
    right_cover = cover_regions(candidate, candidate_entry)
    pairs = pair_covers(left_cover, right_cover)
    return PairedRegions(left_cover, right_cover, pairs, RegionPairingEvidence(
        RegionFormation.COVER, len(oracle), len(candidate),
        sum(len(region.members) for region in left_cover.regions),
        sum(len(region.members) for region in right_cover.regions), len(pairs), rejected))


def paired_control_tokens(
    pairs: list[tuple[int, int]],
    oracle: list[CollapsedRegion],
    candidate: list[CollapsedRegion],
    *, allow_state_merges: bool = False,
) -> list[int]:
    """Identify pairs connected by an explicitly admitted shared region.

    Every edge of such a component is a separate universal state obligation.
    State merges require the consumer to prove every transition and its class
    successor token; the entry pair remains exclusive. Positive finite progress
    in every region preserves divergence under this coinductive relation.
    Transitivity therefore justifies a common control token after every edge
    proves. Unrelated return components must retain distinct tokens, otherwise
    a wrong branch could select a different return computation undetected.
    """
    parents = list(range(len(pairs)))
    owners: dict[tuple[int, int], int] = {}
    for index, pair in enumerate(pairs):
        for side, region_index in enumerate(pair):
            key = (side, region_index)
            prior = owners.get(key)
            if prior is not None:
                region = (oracle, candidate)[side][region_index]
                shared_return = region.kind is RegionExitKind.RETURN and not region.exits
                shared_state = (allow_state_merges and region.kind is RegionExitKind.BORING
                                and prior != 0 and index != 0)
                if not (shared_return or shared_state):
                    raise RegionGraphRefusal(RegionGraphReason.BIJECTION)
                parents[_token_root(parents, index)] = _token_root(parents, prior)
            owners[key] = index
    roots = [_token_root(parents, index) for index in range(len(pairs))]
    identifiers = {root: index for index, root in enumerate(dict.fromkeys(roots))}
    return [identifiers[root] for root in roots]


def _token_root(parents: list[int], index: int) -> int:
    """Find the representative of a finite return-pair component."""
    while parents[index] != index:
        parents[index] = parents[parents[index]]
        index = parents[index]
    return index
