"""Typed source-bound candidate-region scan contracts.

Layer: tools/dosunit comparator intake contracts.
Responsibility: retain bounded CFG/source evidence and explicit refusal outcomes;
a completed candidate never establishes callee admission or equivalence.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

import tools.dosunit.straightline_ssa as S
from tools.dosunit.proof_contracts import FactCounters

type LiftCallback = Callable[[int, int], S.LiftedBlock]
type ReadBytesCallback = Callable[[int, int], bytes | None]

class EdgeKind(StrEnum):
    """Typed control edge derived only from binary IR."""

    CONDITIONAL_EXIT = "conditional_exit"
    DIRECT_DEFAULT_NEXT = "direct_default_next"
    INDIRECT_SUCCESSOR = "indirect_successor"


class BlockTerminal(StrEnum):
    """Whether a verified block is a closed near-RET sink or has open edges."""

    OPEN = "open"
    NEAR_RET = "near_ret"


class RegionScanRefusalReason(StrEnum):
    """Typed reason a region scan could not establish source control closure."""

    INVALID_BUDGET = "invalid_budget"
    INVALID_WINDOW = "invalid_window"
    ENTRY_OUTSIDE_WINDOW = "entry_outside_window"
    ENTRY_UNMAPPED = "entry_unmapped"
    LIFT_FAILED = "lift_failed"
    DECODE_GAP = "decode_gap"
    BYTES_MISMATCH = "bytes_mismatch"
    MID_BLOCK_TARGET = "mid_block_target"
    OVERLAPPING_BLOCKS = "overlapping_blocks"
    SCOPE_ESCAPE = "scope_escape"
    TRAP_EXIT = "trap_exit"
    NESTED_CALL = "nested_call"
    INTERRUPT = "interrupt"
    INDIRECT_CONTROL = "indirect_control"
    ENVIRONMENT_EFFECT = "environment_effect"
    TERMINAL_NOT_NEAR_RET = "terminal_not_near_ret"
    UNSUPPORTED_CONTROL = "unsupported_control"
    EXTERNAL_EDGE = "external_edge"
    CYCLE = "cycle"
    MISSING_TERMINAL = "missing_terminal"
    BUDGET_EXCEEDED = "budget_exceeded"


class RegionScanStatus(StrEnum):
    """Outcome of one scan; COMPLETED is a candidate, not an admission."""

    COMPLETED = "completed"
    COMPLETED_PENDING_SUMMARY = "completed_pending_summary"
    REFUSED = "refused"


@dataclass(frozen=True)
class ScanWindow:
    """Declared half-open loader-linear window; edges outside never expand."""

    start: int
    end: int

    def valid(self) -> bool:
        """Whether the window is a non-empty machine interval."""
        return type(self.start) is int and type(self.end) is int and 0 <= self.start < self.end

    def contains(self, linear: int) -> bool:
        """Whether a loader-linear address lies inside the window."""
        return self.start <= linear < self.end


@dataclass(frozen=True)
class RegionScanBudget:
    """Positive bounded limits; a scan bound is never the region size."""

    max_blocks: int
    max_instructions: int
    max_bytes: int
    max_span: int

    def valid(self) -> bool:
        """Whether every bound is a positive integer (bools refused)."""
        fields = (self.max_blocks, self.max_instructions, self.max_bytes, self.max_span)
        return all(type(value) is int and value > 0 for value in fields)


@dataclass(frozen=True)
class RegionEdge:
    """One typed control edge retained from decoded VEX IR."""

    kind: EdgeKind
    source: int
    target: int | None
    jumpkind: str
    external: bool = False
    detail: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ScannedExit:
    """Typed record of one ``Ist_Exit`` statement and its IRConst target."""

    jumpkind: str
    target: int | None
    guard_repr: str
    dst_repr: str


@dataclass(frozen=True)
class ScannedBlock:
    """One verified source-bound block; conditional control stays attached."""

    linear: int
    size: int
    bytes_hex: str
    jumpkind: str
    terminal: BlockTerminal
    instructions: tuple[Mapping[str, Any], ...]
    exits: tuple[ScannedExit, ...]
    next_repr: str
    edges: tuple[RegionEdge, ...]


@dataclass(frozen=True)
class PendingSummaryEdge:
    """One retained intra-block self-edge awaiting repeat-summary discharge.

    The scan records only that a ``direct_default_next`` edge loops to its own
    block start and that the residual graph is acyclic; whether the block is an
    admitted repeat-string instruction is the lowering owner's byte-derived
    obligation, not evidence this record asserts.
    """

    linear: int
    mode_bits: int


@dataclass(frozen=True)
class RegionScanRefusal:
    """Typed refusal naming the precise evidence boundary that failed."""

    reason: RegionScanRefusalReason
    detail: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the refusal to a JSON-stable document."""
        return {"reason": self.reason.value, "detail": dict(self.detail)}


@dataclass(frozen=True)
class RegionScanRequest:
    """Caller-supplied bounded scan request.

    ``entry_loader_linear`` must already be source-bound by the parent's CALL
    verification; ``lift_block``/``read_bytes`` are the bounded lift and live
    byte-read callbacks over the verified image.
    """

    entry_loader_linear: int
    window: ScanWindow
    budget: RegionScanBudget
    lift_block: LiftCallback
    read_bytes: ReadBytesCallback
    mode_bits: int = 16


@dataclass(frozen=True)
class RegionScanOutcome:
    """Candidate region evidence or an explicit refusal; never an admission."""

    status: RegionScanStatus
    entry_loader_linear: int
    window: ScanWindow
    blocks: tuple[ScannedBlock, ...]
    spans: tuple[tuple[int, int], ...]
    source_bytes: bytes
    source_sha256: str | None
    counters: FactCounters
    refusal: RegionScanRefusal | None = None
    pending_summary_edges: tuple[PendingSummaryEdge, ...] = ()

    def __post_init__(self) -> None:
        """Reject outcomes that mix statuses or drop classified evidence."""
        refused = self.status is RegionScanStatus.REFUSED
        if refused != (self.refusal is not None):
            raise ValueError("scan outcome must be exactly one of candidate or refusal")
        pending = self.status is RegionScanStatus.COMPLETED_PENDING_SUMMARY
        if pending != bool(self.pending_summary_edges):
            raise ValueError("pending-summary outcome must name its retained self-edges")
        if pending and any(
            edge.linear not in {block.linear for block in self.blocks}
            for edge in self.pending_summary_edges
        ):
            raise ValueError("pending summary edge lacks a decoded owner block")
        if not self.counters.closed():
            raise ValueError("classified scan evidence failed to materialize")

    @property
    def terminals(self) -> tuple[int, ...]:
        """Loader-linear addresses of verified terminal near-RET blocks."""
        return tuple(block.linear for block in self.blocks if block.terminal is BlockTerminal.NEAR_RET)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the outcome; refusal retains every decoded block/edge."""
        return {
            "status": self.status.value,
            "entry_loader_linear": f"0x{self.entry_loader_linear:05x}",
            "window": {"start": f"0x{self.window.start:05x}", "end": f"0x{self.window.end:05x}"},
            "spans": [[f"0x{s:05x}", f"0x{e:05x}"] for s, e in self.spans],
            "source_sha256": self.source_sha256,
            "terminals": [f"0x{t:05x}" for t in self.terminals],
            "pending_summary_edges": [
                {"linear": f"0x{e.linear:05x}", "mode_bits": e.mode_bits}
                for e in self.pending_summary_edges
            ],
            "blocks": [
                {
                    "linear": f"0x{b.linear:05x}",
                    "size": b.size,
                    "bytes": b.bytes_hex,
                    "jumpkind": b.jumpkind,
                    "terminal": b.terminal.value,
                    "exits": [
                        {"jumpkind": x.jumpkind, "target": None if x.target is None else f"0x{x.target:05x}",
                         "guard": x.guard_repr, "dst": x.dst_repr}
                        for x in b.exits
                    ],
                    "next": b.next_repr,
                    "edges": [
                        {"kind": e.kind.value, "source": f"0x{e.source:05x}",
                         "target": None if e.target is None else f"0x{e.target:05x}",
                         "jumpkind": e.jumpkind, "external": e.external, "detail": dict(e.detail)}
                        for e in b.edges
                    ],
                }
                for b in self.blocks
            ],
            "refusal": None if self.refusal is None else self.refusal.to_dict(),
            "counters": asdict(self.counters),
        }


