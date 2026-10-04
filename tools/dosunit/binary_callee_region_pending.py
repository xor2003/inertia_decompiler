"""Pending repeat-summary classification and discharge for cyclic candidates.

Layer: tools/dosunit comparator callee evidence intake.
Responsibility: own the structural distinction between a closed region whose
only retained cycles are intra-block ``direct_default_next`` self-edges and a
region with any residual inter-block back-edge, then discharge each pending
self-edge through the existing byte-derived repeat-string summary contract.
Structural pending evidence is never an admission: only
``decode_repeat_summary`` on the exact recorded instruction bytes plus the
lowered part's own ``repeat_string`` transfer marker discharge it, and the
lowered residual graph must be acyclic before any publication.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import tools.dosunit.straightline_ssa as S
from tools.dosunit.binary_callee_region_contracts import (
    EdgeKind,
    RegionScanOutcome,
    ScannedBlock,
)
from tools.dosunit.real16_call_evidence import block_source
from tools.dosunit.repeat_string_contracts import RepeatArchitecture, decode_repeat_summary


class PendingCycleVerdict(StrEnum):
    """Structural cycle class of a fully closed scanned region."""

    ACYCLIC = "acyclic"
    PENDING_SUMMARY = "pending_summary"
    CYCLIC = "cyclic"


class PendingDischargeReason(StrEnum):
    """Typed obligation a pending self-edge or residual graph failed."""

    LEADER_UNMAPPED = "pending_leader_unmapped"
    UNSUPPORTED_MODE = "pending_edge_unsupported_mode"
    NOT_REPEAT = "pending_edge_not_repeat_string"
    SUMMARY_MISSING = "repeat_summary_missing_in_part"
    RESIDUAL_CYCLE = "residual_cycle"
    INCOMPLETE_GRAPH = "incomplete_lowered_graph"


@dataclass(frozen=True)
class PendingDischargeFailure:
    """An unmet summary obligation retained as typed internal evidence."""

    reason: PendingDischargeReason
    linear: int | None = None
    mode_bits: int | None = None

    def to_dict(self) -> dict[str, str | int]:
        """Serialize the failure at the report boundary."""
        result: dict[str, str | int] = {"reason": self.reason.value}
        if self.linear is not None:
            result["linear"] = self.linear
        if self.mode_bits is not None:
            result["mode_bits"] = self.mode_bits
        return result


@dataclass(frozen=True)
class PendingCycleReport:
    """Cycle verdict plus the isolated self-edge leaders awaiting discharge."""

    verdict: PendingCycleVerdict
    self_edge_leaders: tuple[int, ...] = ()


def _has_back_edge(entry: int, adjacency: Mapping[int, Iterable[int]]) -> bool:
    """Iterative DFS back-edge check over an explicit successor map."""
    color: dict[int, int] = {}
    stack: list[tuple[int, Any]] = [(entry, iter(sorted(adjacency.get(entry, ()))))]
    color[entry] = 1
    while stack:
        node, iterator = stack[-1]
        advanced = False
        for successor in iterator:
            state = color.get(successor, 0)
            if state == 1:
                return True
            if state == 0:
                color[successor] = 1
                stack.append((successor, iter(sorted(adjacency.get(successor, ())))))
                advanced = True
                break
        if not advanced:
            color[node] = 2
            stack.pop()
    return False


def classify_pending_cycle(blocks: Iterable[ScannedBlock], entry: int) -> PendingCycleReport:
    """Classify the closed retained edge graph without inspecting semantics.

    Only ``direct_default_next`` edges whose target is their own block start
    are isolated self-edges (the VEX repeat-prefix next-loop shape); every
    other edge stays in the residual graph. The region is ``PENDING_SUMMARY``
    only when stripping those self-edges leaves an acyclic graph.
    """
    adjacency: dict[int, list[int]] = {}
    leaders: set[int] = set()
    for block in blocks:
        residual: list[int] = []
        for edge in block.edges:
            if edge.target is None:
                continue
            if edge.kind is EdgeKind.DIRECT_DEFAULT_NEXT and edge.target == block.linear:
                leaders.add(block.linear)
            else:
                residual.append(edge.target)
        adjacency[block.linear] = residual
    if _has_back_edge(entry, adjacency):
        return PendingCycleReport(PendingCycleVerdict.CYCLIC)
    if leaders:
        return PendingCycleReport(PendingCycleVerdict.PENDING_SUMMARY, tuple(sorted(leaders)))
    return PendingCycleReport(PendingCycleVerdict.ACYCLIC)


def _repeat_architecture(mode_bits: int) -> RepeatArchitecture | None:
    """Map the scan's lifter mode onto the repeat contract's architectures."""
    if mode_bits == 16:
        return RepeatArchitecture.REAL16
    if mode_bits == 32:
        return RepeatArchitecture.FLAT32
    return None


def _part_linear(part: dict[str, Any]) -> int | None:
    """Read one lowered part's own block entry linear address."""
    entry = part.get("entry")
    if not isinstance(entry, dict):
        return None
    value = S._optional_int(entry.get("linear"))
    return value if type(value) is int else None


def _verify_repeat_edges(
    parts: Iterable[dict[str, Any]], scan: RegionScanOutcome
) -> PendingDischargeFailure | None:
    """Bind every pending edge to byte admission and its lowered summary."""
    by_linear = {linear: part for part in parts
                 if (linear := _part_linear(part)) is not None}
    blocks = {block.linear: block for block in scan.blocks}
    for edge in scan.pending_summary_edges:
        linear = edge.linear
        block = blocks.get(linear)
        if block is None:
            return PendingDischargeFailure(PendingDischargeReason.LEADER_UNMAPPED, linear)
        architecture = _repeat_architecture(edge.mode_bits)
        if architecture is None:
            return PendingDischargeFailure(PendingDischargeReason.UNSUPPORTED_MODE, linear, edge.mode_bits)
        instructions = [dict(record) for record in block.instructions]
        if decode_repeat_summary(instructions, architecture=architecture) is None:
            return PendingDischargeFailure(PendingDischargeReason.NOT_REPEAT, linear)
        part = by_linear.get(linear)
        transfer = block_source(part).get("transfer") if part is not None else None
        summary = transfer.get("summary") if isinstance(transfer, dict) else None
        if summary != "repeat_string":
            return PendingDischargeFailure(PendingDischargeReason.SUMMARY_MISSING, linear)
    return None


def _lowered_adjacency(parts: Iterable[dict[str, Any]]) -> dict[int, list[int]] | None:
    """Build a complete successor graph; malformed parts never disappear."""
    adjacency: dict[int, list[int]] = {}
    for part in parts:
        linear = _part_linear(part)
        function_entry = part.get("function_entry")
        base = (S._optional_int(function_entry.get("linear"))
                if isinstance(function_entry, dict) else None)
        if linear is None or base is None or linear in adjacency:
            return None
        adjacency[linear] = sorted(base + delta
                                   for delta in S._direct_successor_delta_set(part))
    return adjacency


def verify_pending_summary(
    parts: Iterable[dict[str, Any]], scan: RegionScanOutcome,
) -> PendingDischargeFailure | None:
    """Require byte-admitted summaries and a complete acyclic lowered graph.

    The caller must first validate source hashes, exact block correspondence
    and full-state grouping. Summary markers are consumed only under those
    prerequisites; they are not independent semantic proof certificates.
    """
    part_list = list(parts)
    failure = _verify_repeat_edges(part_list, scan)
    if failure is not None:
        return failure
    adjacency = _lowered_adjacency(part_list)
    if adjacency is None or scan.entry_loader_linear not in adjacency:
        return PendingDischargeFailure(PendingDischargeReason.INCOMPLETE_GRAPH)
    if any(target not in adjacency for targets in adjacency.values() for target in targets):
        return PendingDischargeFailure(PendingDischargeReason.INCOMPLETE_GRAPH)
    if _has_back_edge(scan.entry_loader_linear, adjacency):
        return PendingDischargeFailure(PendingDischargeReason.RESIDUAL_CYCLE)
    return None
