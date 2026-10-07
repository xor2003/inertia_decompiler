"""Interior-leader boundary normalization for the callee-region scanner.

Layer: tools/dosunit real-mode comparator intake (block-boundary policy).
Responsibility: classify a queued control target against already decoded block
spans — established leader, interior instruction head (split candidate),
interior byte (refusal), or fresh address bounded by the nearest forward
decoded leader — and verify that a bounded prefix re-decode reproduces the
retained instruction-head records exactly.  Only retained decoded instruction
heads may become internal leaders; mid-instruction targets stay refusals, and
all decode, byte and budget verification stays in the scanner owner.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import tools.dosunit.compare.straightline_ssa as S
from tools.dosunit.catalog.binary_callee_intake import _instruction_bytes
from tools.dosunit.catalog.binary_callee_region_contracts import (
    EdgeKind,
    RegionScanRefusal,
    RegionScanRefusalReason,
    ScannedBlock,
)


class LeaderVerdict(StrEnum):
    """How a queued target relates to already-decoded block spans."""

    FRESH = "fresh"
    DECODED = "decoded"
    SPLIT = "split"
    MID_BLOCK = "mid_block"


@dataclass(frozen=True)
class LeaderDecision:
    """Boundary verdict for one queued target.

    ``owner`` is the decoded block containing an interior target (SPLIT on a
    retained head, MID_BLOCK otherwise); ``forward_bound`` bounds a fresh lift
    at the nearest decoded block start so a new decode cannot span a validated
    leader.
    """

    verdict: LeaderVerdict
    owner: ScannedBlock | None = None
    forward_bound: int | None = None


def _record_linear(record: Mapping[str, Any]) -> int | None:
    """Typed accessor for one record's decoded linear address."""
    value = record.get("linear")
    return value if type(value) is int else None


def _is_head(block: ScannedBlock, at: int) -> bool:
    """Whether ``at`` is a retained decoded instruction head of ``block``."""
    return any(_record_linear(record) == at for record in block.instructions)


def classify_leader(blocks: Sequence[ScannedBlock], at: int) -> LeaderDecision:
    """Classify ``at`` against decoded spans; pure policy, no mutation.

    Spans never overlap, so at most one block may contain ``at`` strictly.
    A FRESH decision carries the nearest forward block start as ``forward_bound``.
    """
    owner: ScannedBlock | None = None
    bound: int | None = None
    for block in blocks:
        start = block.linear
        end = start + block.size
        if at == start:
            return LeaderDecision(LeaderVerdict.DECODED)
        if start < at < end:
            owner = block
        elif start > at and (bound is None or start < bound):
            bound = start
    if owner is None:
        return LeaderDecision(LeaderVerdict.FRESH, forward_bound=bound)
    if _is_head(owner, at):
        return LeaderDecision(LeaderVerdict.SPLIT, owner=owner)
    return LeaderDecision(LeaderVerdict.MID_BLOCK, owner=owner)


def prefix_records(block: ScannedBlock, leader: int) -> tuple[Mapping[str, Any], ...]:
    """Retained records of ``block`` strictly before ``leader``; empty if ``leader``
    is not a retained head."""
    records = tuple(block.instructions)
    prefix = tuple(record for record in records
                   if (linear := _record_linear(record)) is not None and linear < leader)
    if not prefix or len(prefix) == len(records):
        return ()
    if _record_linear(records[len(prefix)]) != leader:
        return ()
    return prefix


def prefix_body_verdict(
    block: ScannedBlock, leader: int, lifted: S.LiftedBlock, body: bytes,
) -> RegionScanRefusal | None:
    """Verify a bounded prefix re-decode reproduces the retained head records.

    The re-lift must cover exactly ``leader - block.linear`` bytes and repeat
    the retained instruction addresses, sizes and bytes — any disagreement is a
    decode-evidence gap, not a semantic judgment.
    """
    start = block.linear
    if len(body) != leader - start:
        return RegionScanRefusal(
            RegionScanRefusalReason.DECODE_GAP,
            detail={"boundary": "prefix_length", "at": f"0x{start:05x}",
                    "leader": f"0x{leader:05x}", "decoded": len(body),
                    "expected": leader - start})
    expected = prefix_records(block, leader)
    fresh = tuple(lifted.instructions or ())
    if not expected or len(fresh) != len(expected):
        return RegionScanRefusal(
            RegionScanRefusalReason.DECODE_GAP,
            detail={"boundary": "prefix_records", "at": f"0x{start:05x}",
                    "leader": f"0x{leader:05x}"})
    for index, (new, old) in enumerate(zip(fresh, expected, strict=True)):
        if (new.get("linear") != old.get("linear") or new.get("size") != old.get("size")
                or _instruction_bytes(new) != _instruction_bytes(old)):
            return RegionScanRefusal(
                RegionScanRefusalReason.DECODE_GAP,
                detail={"boundary": "prefix_record_mismatch", "at": f"0x{start:05x}",
                        "leader": f"0x{leader:05x}", "instruction": index})
    return None


def prefix_edge_verdict(
    block: ScannedBlock, owner: ScannedBlock, leader: int,
) -> RegionScanRefusal | None:
    """Require the rebuilt prefix's default successor to be exactly ``leader``
    and every prefix exit to be one the retained owner already proved.

    Comparing ``(target, jumpkind)`` — not guard text — keeps the check immune
    to temporary renumbering across re-lifts. This rejects new target/kind
    pairs and increased multiplicity; it is not a proof about exit guards
    or dropped exits. Semantic admission still belongs to lowering/proof.
    """
    if not any(edge.kind is EdgeKind.DIRECT_DEFAULT_NEXT and edge.target == leader
               for edge in block.edges):
        return RegionScanRefusal(
            RegionScanRefusalReason.DECODE_GAP,
            detail={"boundary": "prefix_next", "at": f"0x{block.linear:05x}",
                    "leader": f"0x{leader:05x}"})
    remaining = [(exit_.target, exit_.jumpkind) for exit_ in owner.exits]
    for exit_ in block.exits:
        key = (exit_.target, exit_.jumpkind)
        if key not in remaining:
            return RegionScanRefusal(
                RegionScanRefusalReason.DECODE_GAP,
                detail={"boundary": "prefix_exit", "at": f"0x{block.linear:05x}",
                        "leader": f"0x{leader:05x}",
                        "target": None if exit_.target is None else f"0x{exit_.target:05x}",
                        "jumpkind": exit_.jumpkind})
        remaining.remove(key)
    return None
