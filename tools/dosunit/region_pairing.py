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

from tools.dosunit.finite_region_cover import FiniteRegionCover, cover_regions, pair_covers
from tools.dosunit.paired_region_graph import (
    RegionGraphReason,
    RegionGraphRefusal,
    RegionNode,
    RegionPartition,
    collapse_regions,
    pair_regions,
)
from tools.dosunit.region_branch_pairing import BranchPairingReport, propose_branch_bijections

type RegionLayout = RegionPartition | FiniteRegionCover


class RegionFormation(StrEnum):
    """The exact binary CFG formation whose transitions require proof."""

    PARTITION = 'disjoint_finite_partition'
    COVER = 'overlapping_finite_cover'


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


def _proposals(
    left: RegionLayout, right: RegionLayout, formation: RegionFormation,
    oracle_blocks: int, candidate_blocks: int, rejected: RegionGraphReason | None,
    *, deadline_seconds: float, max_candidates: int,
) -> tuple[tuple[PairedRegions, ...], BranchPairingReport]:
    """Keep successor order as evidence, never as a state-equality verdict."""
    left_targets = left.owners if isinstance(left, RegionPartition) else left.cutpoints
    right_targets = right.owners if isinstance(right, RegionPartition) else right.cutpoints
    report = propose_branch_bijections(
        left.regions, right.regions, left_targets, right_targets, left.entry, right.entry,
        deadline_seconds=deadline_seconds, max_candidates=max_candidates,
    )
    proposals = tuple(PairedRegions(left, right, pairs, RegionPairingEvidence(
        formation, oracle_blocks, candidate_blocks,
        sum(len(region.members) for region in left.regions),
        sum(len(region.members) for region in right.regions), len(pairs), rejected,
        BranchOrientation.ORDERED if pairs == report.ordered else BranchOrientation.PERMUTED,
    )) for pairs in report.candidates)
    return proposals, report


def propose_region_pairings(
    oracle: dict[int, RegionNode], candidate: dict[int, RegionNode],
    oracle_entry: int, candidate_entry: int, *, deadline_seconds: float,
    max_candidates: int = 64,
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
    )
    return RegionPairingSearch(partition + cover, (
        (RegionFormation.PARTITION, partition_report), (RegionFormation.COVER, cover_report),
    ))


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
