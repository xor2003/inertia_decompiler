"""Bounded source-byte/VEX CFG scan of uncatalogued multi-block callees.

Layer: tools/dosunit real-mode comparator intake (source-bound candidate scanner).
Responsibility: expand a caller-verified near-CALL target into a bounded
region of exactly decoded VEX blocks with typed control edges.  Successor
targets come only from typed ``Ist_Exit.dst`` IRConst payloads and
``irsb.next``, or the existing native terminal-jump theorem for symbolic
real16 successors, canonicalized through the straightline owner; rendered text,
symbols and names are never consulted.  Every instruction record's address,
size and raw bytes are re-verified against live source bytes, and every
control edge must stay inside the declared window. Acyclic candidates close
on near RETs; isolated self-edges remain explicit pending-summary obligations
and do not establish termination before lowering discharges them.
Reachable targets that land on a retained decoded instruction head are
normalized by bounded leader-split re-decode rather than refused; only true
mid-instruction targets and incompatible overlapping decodes refuse.  A
completed result is a *candidate* — boundary evidence for the parent's
lowering and composition owners — never an admitted function body and never
an equivalence, saved-return-frame, or CS-restoration proof.  The caller
CALL identity and image/domain checks are the parent's obligation; this
scanner does not verify the caller.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

import pyvex

import tools.dosunit.straightline_ssa as S
from tools.dosunit.binary_callee_control_target import proven_terminal_target
from tools.dosunit.binary_callee_intake import (
    _INTERRUPT_OPCODES,
    _NEAR_RET_OPCODES,
    _effective_opcode,
    _instruction_bytes,
)
from tools.dosunit.binary_callee_region_contracts import (
    BlockTerminal as BlockTerminal,
)
from tools.dosunit.binary_callee_region_contracts import (
    EdgeKind as EdgeKind,
)
from tools.dosunit.binary_callee_region_contracts import (
    LiftCallback as LiftCallback,
)
from tools.dosunit.binary_callee_region_contracts import (
    PendingSummaryEdge as PendingSummaryEdge,
)
from tools.dosunit.binary_callee_region_contracts import (
    ReadBytesCallback as ReadBytesCallback,
)
from tools.dosunit.binary_callee_region_contracts import (
    RegionEdge as RegionEdge,
)
from tools.dosunit.binary_callee_region_contracts import (
    RegionScanBudget as RegionScanBudget,
)
from tools.dosunit.binary_callee_region_contracts import (
    RegionScanOutcome as RegionScanOutcome,
)
from tools.dosunit.binary_callee_region_contracts import (
    RegionScanRefusal as RegionScanRefusal,
)
from tools.dosunit.binary_callee_region_contracts import (
    RegionScanRefusalReason as RegionScanRefusalReason,
)
from tools.dosunit.binary_callee_region_contracts import (
    RegionScanRequest as RegionScanRequest,
)
from tools.dosunit.binary_callee_region_contracts import (
    RegionScanStatus as RegionScanStatus,
)
from tools.dosunit.binary_callee_region_contracts import (
    ScannedBlock as ScannedBlock,
)
from tools.dosunit.binary_callee_region_contracts import (
    ScannedExit as ScannedExit,
)
from tools.dosunit.binary_callee_region_contracts import (
    ScanWindow as ScanWindow,
)
from tools.dosunit.binary_callee_region_pending import (
    PendingCycleVerdict,
    classify_pending_cycle,
)
from tools.dosunit.binary_callee_region_split import (
    LeaderVerdict,
    classify_leader,
    prefix_body_verdict,
    prefix_edge_verdict,
)
from tools.dosunit.binary_environment import decoded_port_effects, requires_environment_contract
from tools.dosunit.proof_contracts import FactCounters

_CALL_OPCODES = frozenset({0xE8, 0x9A})
_FAR_RETURN_OPCODES = frozenset({0xCA, 0xCB, 0xCF})
_FAR_JUMP_OPCODES = frozenset({0xEA})
_MODE_BITS = frozenset({16, 32, 64})


class _ScanRefusal(Exception):
    """Owned control-flow abort carrying a typed scan refusal."""

    def __init__(self, reason: RegionScanRefusalReason, **detail: Any) -> None:  # noqa: ANN401
        super().__init__(reason.value)
        self.refusal = RegionScanRefusal(reason=reason, detail=detail)

    @classmethod
    def from_refusal(cls, refusal: RegionScanRefusal) -> _ScanRefusal:
        """Re-raise a built refusal while keeping the abort uniform."""
        abort = cls(refusal.reason)
        abort.refusal = refusal
        return abort


@dataclass
class _ScanState:
    """Mutable deterministic worklist state for one region scan."""

    pending: list[int]
    queued: set[int]
    decoded: set[int] = field(default_factory=set)
    spans: list[tuple[int, int]] = field(default_factory=list)
    blocks: list[ScannedBlock] = field(default_factory=list)
    consumed_bytes: int = 0
    instructions_seen: int = 0
    edge_count: int = 0


def _decode_block_body(request: RegionScanRequest, at: int, lifted: S.LiftedBlock) -> bytes:
    """Verify contiguous instruction and IRSB coverage; return exact bytes."""
    if not isinstance(lifted, S.LiftedBlock):
        raise _ScanRefusal(RegionScanRefusalReason.LIFT_FAILED, at=f"0x{at:05x}",
                           lifted_type=type(lifted).__name__)
    irsb = lifted.irsb
    if not isinstance(irsb, pyvex.IRSB) or irsb.statements is None:
        raise _ScanRefusal(RegionScanRefusalReason.LIFT_FAILED, at=f"0x{at:05x}")
    if type(irsb.size) is not int or irsb.size <= 0 or irsb.addr != at:
        raise _ScanRefusal(RegionScanRefusalReason.LIFT_FAILED, at=f"0x{at:05x}",
                           irsb_size=irsb.size, irsb_addr=irsb.addr)
    records = list(lifted.instructions or [])
    if not records or records[0].get("linear") != at:
        raise _ScanRefusal(RegionScanRefusalReason.DECODE_GAP, at=f"0x{at:05x}",
                           first=None if not records else records[0].get("linear"))
    chunks: list[bytes] = []
    cursor = at
    for index, record in enumerate(records):
        linear = record.get("linear")
        size = record.get("size")
        data = _instruction_bytes(record)
        if type(linear) is not int or type(size) is not int or size <= 0 or data is None or len(data) != size:
            raise _ScanRefusal(RegionScanRefusalReason.DECODE_GAP, at=f"0x{at:05x}", instruction=index)
        if linear != cursor:
            raise _ScanRefusal(RegionScanRefusalReason.DECODE_GAP, at=f"0x{at:05x}", instruction=index,
                               expected=f"0x{cursor:05x}", actual=f"0x{linear:05x}")
        chunks.append(data)
        cursor += size
    body = b"".join(chunks)
    if len(body) != irsb.size:
        raise _ScanRefusal(RegionScanRefusalReason.DECODE_GAP, at=f"0x{at:05x}",
                           irsb_size=irsb.size, decoded=len(body))
    if at + len(body) > request.window.end:
        raise _ScanRefusal(RegionScanRefusalReason.SCOPE_ESCAPE, at=f"0x{at:05x}",
                           block_end=f"0x{at + len(body):05x}", window_end=f"0x{request.window.end:05x}")
    return body


def _opcode_verdict(opcode: int | None, jumpkind: str) -> RegionScanRefusal | None:
    """Classify the decoded terminal opcode before consulting the jumpkind."""
    if opcode in _INTERRUPT_OPCODES:
        return RegionScanRefusal(RegionScanRefusalReason.INTERRUPT, detail={"opcode": opcode})
    if opcode in _CALL_OPCODES or jumpkind == "Ijk_Call":
        return RegionScanRefusal(RegionScanRefusalReason.NESTED_CALL,
                                 detail={"opcode": opcode, "jumpkind": jumpkind})
    if opcode in _FAR_RETURN_OPCODES:
        return RegionScanRefusal(RegionScanRefusalReason.TERMINAL_NOT_NEAR_RET, detail={"opcode": opcode})
    if opcode in _FAR_JUMP_OPCODES:
        return RegionScanRefusal(RegionScanRefusalReason.UNSUPPORTED_CONTROL,
                                 detail={"opcode": opcode, "kind": "far_jump"})
    return None


def _classify_terminal(
    *,
    jumpkind: str,
    opcode: int | None,
    exits: tuple[ScannedExit, ...],
    next_const: int | None,
) -> tuple[BlockTerminal, RegionScanRefusal | None]:
    """Return the block terminal verdict; None means open direct control."""
    trap = any(exit_.jumpkind.startswith("Ijk_Sig") for exit_ in exits)
    indirect_exit = any(exit_.target is None for exit_ in exits)
    if trap:
        return BlockTerminal.OPEN, RegionScanRefusal(RegionScanRefusalReason.TRAP_EXIT,
                                                     detail={"jumpkinds": sorted({e.jumpkind for e in exits})})
    opcode_verdict = _opcode_verdict(opcode, jumpkind)
    if opcode_verdict is not None:
        return BlockTerminal.OPEN, opcode_verdict
    if jumpkind.startswith("Ijk_Sig"):
        return BlockTerminal.OPEN, RegionScanRefusal(RegionScanRefusalReason.TRAP_EXIT, detail={"jumpkind": jumpkind})
    if jumpkind == "Ijk_Ret":
        if exits:
            return BlockTerminal.OPEN, RegionScanRefusal(RegionScanRefusalReason.UNSUPPORTED_CONTROL,
                                                         detail={"jumpkind": jumpkind, "exits": len(exits)})
        if opcode in _NEAR_RET_OPCODES:
            return BlockTerminal.NEAR_RET, None
        return BlockTerminal.OPEN, RegionScanRefusal(RegionScanRefusalReason.TERMINAL_NOT_NEAR_RET,
                                                     detail={"opcode": opcode, "jumpkind": jumpkind})
    if opcode in _NEAR_RET_OPCODES:
        return BlockTerminal.OPEN, RegionScanRefusal(RegionScanRefusalReason.UNSUPPORTED_CONTROL,
                                                     detail={"opcode": opcode, "jumpkind": jumpkind})
    if jumpkind != "Ijk_Boring":
        return BlockTerminal.OPEN, RegionScanRefusal(RegionScanRefusalReason.UNSUPPORTED_CONTROL,
                                                     detail={"jumpkind": jumpkind})
    if indirect_exit or next_const is None:
        return BlockTerminal.OPEN, RegionScanRefusal(RegionScanRefusalReason.INDIRECT_CONTROL,
                                                     detail={"jumpkind": jumpkind})
    return BlockTerminal.OPEN, None


def _check_environment(request: RegionScanRequest, lifted: S.LiftedBlock) -> RegionScanRefusal | None:
    """Refuse dirty helpers and decoded port events; missing decode is a gap."""
    if requires_environment_contract(lifted.irsb):
        return RegionScanRefusal(RegionScanRefusalReason.ENVIRONMENT_EFFECT, detail={"boundary": "dirty_helper"})
    for index, record in enumerate(lifted.instructions):
        data = _instruction_bytes(record)
        linear = record.get("linear")
        if not isinstance(linear, int):
            return RegionScanRefusal(RegionScanRefusalReason.DECODE_GAP,
                                     detail={"instruction": index, "boundary": "port_address"})
        effects = decoded_port_effects(data or b"", linear, mode_bits=request.mode_bits)
        if effects is None:
            return RegionScanRefusal(RegionScanRefusalReason.DECODE_GAP,
                                     detail={"instruction": index, "boundary": "port_decode"})
        if effects:
            return RegionScanRefusal(RegionScanRefusalReason.ENVIRONMENT_EFFECT,
                                     detail={"instruction": index,
                                             "effects": sorted(effect.value for effect in effects)})
    return None


def _canonical_target(request: RegionScanRequest, target: int, reference: int) -> int:
    """Resolve real16 near coordinates while preserving flat absolute targets."""
    if request.mode_bits == 16:
        resolved = S._canonical_near_linear_target(target, reference_linear=reference)
        if not isinstance(resolved, int):
            raise TypeError("near-coordinate owner returned a non-integer target")
        return resolved
    return target


def _build_block(
    request: RegionScanRequest, at: int, lifted: S.LiftedBlock, body: bytes,
) -> tuple[ScannedBlock, RegionScanRefusal | None]:
    """Attach typed exits/edges and the terminal verdict to a verified block."""
    irsb = lifted.irsb
    records = list(lifted.instructions)
    reference = records[-1].get("linear")
    if not isinstance(reference, int):
        raise _ScanRefusal(RegionScanRefusalReason.DECODE_GAP, at=at)
    exits: list[ScannedExit] = []
    edges: list[RegionEdge] = []
    for statement in irsb.statements:
        if not isinstance(statement, pyvex.stmt.Exit):
            continue
        jumpkind = str(statement.jumpkind)
        raw = statement.dst.value
        target = (
            _canonical_target(request, raw, reference) if type(raw) is int else None
        )
        exits.append(ScannedExit(jumpkind=jumpkind, target=target,
                                 guard_repr=str(statement.guard), dst_repr=str(statement.dst)))
        edges.append(RegionEdge(EdgeKind.CONDITIONAL_EXIT, source=at, target=target, jumpkind=jumpkind,
                                external=target is not None and not request.window.contains(target),
                                detail={"guard": str(statement.guard), "dst": str(statement.dst)}))
    next_const = S._const_expr_value(irsb.next)
    jumpkind = str(irsb.jumpkind)
    native_target = None
    if next_const is None and request.mode_bits == 16 and jumpkind == "Ijk_Boring":
        native_target = proven_terminal_target(
            irsb, body, head=reference, size=records[-1]["size"],
        )
        next_const = native_target
    if jumpkind == "Ijk_Boring":
        if next_const is None:
            edges.append(RegionEdge(EdgeKind.INDIRECT_SUCCESSOR, source=at, target=None,
                                    jumpkind=jumpkind, detail={"next": str(irsb.next)}))
        else:
            target = (native_target if native_target is not None
                      else _canonical_target(request, next_const, reference))
            edges.append(RegionEdge(EdgeKind.DIRECT_DEFAULT_NEXT, source=at, target=target,
                                    jumpkind=jumpkind,
                                    external=not request.window.contains(target),
                                    detail={"next": str(irsb.next)}))
    opcode = _effective_opcode(_instruction_bytes(records[-1]) or b"")
    terminal, verdict = _classify_terminal(
        jumpkind=jumpkind, opcode=opcode, exits=tuple(exits), next_const=next_const)
    if verdict is None:
        verdict = _check_environment(request, lifted)
    block = ScannedBlock(
        linear=at, size=len(body), bytes_hex=body.hex(), jumpkind=jumpkind, terminal=terminal,
        instructions=tuple(dict(record) for record in records), exits=tuple(exits),
        next_repr=str(irsb.next), edges=tuple(edges))
    return block, verdict


def _enqueue_internal(request: RegionScanRequest, state: _ScanState, block: ScannedBlock) -> None:
    """Queue window-internal edge targets; external edges refuse, never drop.

    Interior targets are queued normally: ``_walk_region`` classifies them at
    dequeue time and normalizes retained instruction heads by leader split.
    """
    for edge in block.edges:
        target = edge.target
        if target is None:
            continue
        if edge.external or not request.window.contains(target):
            raise _ScanRefusal(RegionScanRefusalReason.EXTERNAL_EDGE, source=f"0x{edge.source:05x}",
                               target=f"0x{target:05x}", kind=edge.kind.value)
        if target in state.decoded or target in state.queued:
            continue
        state.pending.append(target)
        state.queued.add(target)


def _budgeted_lift(
    request: RegionScanRequest, state: _ScanState, at: int, bound: int | None = None,
) -> S.LiftedBlock:
    """Lift one block inside the remaining block/byte budgets.

    ``bound`` is an exclusive absolute loader-linear end — a validated block
    leader such as an interior split point or the nearest forward decoded
    block start — so a (re-)decode can never span a proven boundary.
    """
    if len(state.blocks) >= request.budget.max_blocks:
        raise _ScanRefusal(RegionScanRefusalReason.BUDGET_EXCEEDED,
                           counter="blocks", limit=request.budget.max_blocks)
    lift_size = min(request.window.end - at, request.budget.max_bytes - state.consumed_bytes)
    if bound is not None:
        lift_size = min(lift_size, bound - at)
    if lift_size <= 0:
        raise _ScanRefusal(RegionScanRefusalReason.BUDGET_EXCEEDED,
                           counter="bytes", limit=request.budget.max_bytes)
    try:
        return request.lift_block(at, lift_size)
    except TimeoutError as error:
        raise _ScanRefusal(RegionScanRefusalReason.BUDGET_EXCEEDED,
                           counter="lift_ms", error=str(error)) from error


def _check_block_budgets(request: RegionScanRequest, state: _ScanState, at: int, body: bytes, insns: int) -> None:
    """Enforce byte, instruction and extent budgets on a decoded block."""
    if state.consumed_bytes + len(body) > request.budget.max_bytes:
        raise _ScanRefusal(RegionScanRefusalReason.BUDGET_EXCEEDED,
                           counter="bytes", limit=request.budget.max_bytes, at=f"0x{at:05x}")
    if state.instructions_seen + insns > request.budget.max_instructions:
        raise _ScanRefusal(RegionScanRefusalReason.BUDGET_EXCEEDED,
                           counter="instructions", limit=request.budget.max_instructions)
    extent = max(at + len(body), max((end for _, end in state.spans), default=at)) - min(
        at, min((start for start, _ in state.spans), default=at))
    if extent > request.budget.max_span:
        raise _ScanRefusal(RegionScanRefusalReason.BUDGET_EXCEEDED,
                           counter="span", limit=request.budget.max_span, extent=extent)


def _check_overlap(state: _ScanState, at: int, size: int) -> None:
    """Refuse a lifted block whose span intersects a decoded block."""
    for start, end in state.spans:
        if start < at + size and at < end:
            raise _ScanRefusal(RegionScanRefusalReason.OVERLAPPING_BLOCKS, at=f"0x{at:05x}",
                               existing=(f"0x{start:05x}", f"0x{end:05x}"), size=size)


def _verify_live_bytes(request: RegionScanRequest, at: int, body: bytes) -> None:
    """Re-read the decoded span through the live byte callback."""
    live = request.read_bytes(at, len(body))
    if live is None or live != body:
        raise _ScanRefusal(RegionScanRefusalReason.BYTES_MISMATCH, at=f"0x{at:05x}",
                           decoded=body.hex(), loaded=None if live is None else live.hex())


def _split_decoded_block(request: RegionScanRequest, state: _ScanState,
                         owner: ScannedBlock, leader: int) -> None:
    """Replace ``owner`` by its verified bounded prefix ending at ``leader``.

    The prefix is re-lifted through the normal bounded callback (never sliced
    from the retained VEX stream), must reproduce the retained instruction-head
    records exactly, consumes the cumulative byte/instruction budgets and
    retains the existing block-count cap, and is re-verified against live source bytes.  The
    retained block is only replaced after the prefix proves a default edge to
    ``leader``; ``leader`` itself is re-queued for a normal bounded decode.
    """
    start = owner.linear
    prefix_size = leader - start
    if prefix_size > request.budget.max_bytes - state.consumed_bytes:
        raise _ScanRefusal(RegionScanRefusalReason.BUDGET_EXCEEDED,
                           counter="bytes", limit=request.budget.max_bytes,
                           at=f"0x{start:05x}")
    lifted = _budgeted_lift(request, state, start, bound=leader)
    body = _decode_block_body(request, start, lifted)
    verdict = prefix_body_verdict(owner, leader, lifted, body)
    if verdict is not None:
        raise _ScanRefusal.from_refusal(verdict)
    _check_block_budgets(request, state, start, body, len(lifted.instructions))
    _verify_live_bytes(request, start, body)
    block, build_verdict = _build_block(request, start, lifted, body)
    if build_verdict is not None:
        raise _ScanRefusal.from_refusal(build_verdict)
    edge_verdict = prefix_edge_verdict(block, owner, leader)
    if edge_verdict is not None:
        raise _ScanRefusal.from_refusal(edge_verdict)
    old_span = (start, start + owner.size)
    state.spans[state.spans.index(old_span)] = (start, leader)
    state.blocks[state.blocks.index(owner)] = block
    state.consumed_bytes += len(body)
    state.instructions_seen += len(lifted.instructions)
    state.edge_count += len(block.edges)
    _enqueue_internal(request, state, block)


def _walk_region(request: RegionScanRequest, state: _ScanState) -> None:
    """Bounded deterministic worklist over internal direct successors."""
    while state.pending:
        at = state.pending.pop(0)
        state.queued.discard(at)
        decision = classify_leader(state.blocks, at)
        if decision.verdict is LeaderVerdict.DECODED:
            continue
        owner = decision.owner
        if decision.verdict is LeaderVerdict.MID_BLOCK:
            if owner is None:
                raise TypeError("mid-block decision missing owner block")
            raise _ScanRefusal(RegionScanRefusalReason.MID_BLOCK_TARGET, target=f"0x{at:05x}",
                               span=(f"0x{owner.linear:05x}", f"0x{owner.linear + owner.size:05x}"))
        if decision.verdict is LeaderVerdict.SPLIT:
            if owner is None:
                raise TypeError("split decision missing owner block")
            _split_decoded_block(request, state, owner, at)
            continue
        lifted = _budgeted_lift(request, state, at, bound=decision.forward_bound)
        body = _decode_block_body(request, at, lifted)
        _check_block_budgets(request, state, at, body, len(lifted.instructions))
        _check_overlap(state, at, len(body))
        _verify_live_bytes(request, at, body)
        block, verdict = _build_block(request, at, lifted, body)
        state.blocks.append(block)
        state.spans.append((at, at + len(body)))
        state.decoded.add(at)
        state.consumed_bytes += len(body)
        state.instructions_seen += len(lifted.instructions)
        state.edge_count += len(block.edges)
        if verdict is not None:
            raise _ScanRefusal.from_refusal(verdict)
        _enqueue_internal(request, state, block)


def _validate_request(request: RegionScanRequest) -> None:
    """Fail closed on malformed bounds, window or an unmapped entry."""
    if not request.window.valid():
        raise _ScanRefusal(RegionScanRefusalReason.INVALID_WINDOW,
                           start=request.window.start, end=request.window.end)
    if not request.budget.valid():
        raise _ScanRefusal(RegionScanRefusalReason.INVALID_BUDGET,
                           budget={
                               "max_blocks": request.budget.max_blocks,
                               "max_instructions": request.budget.max_instructions,
                               "max_bytes": request.budget.max_bytes,
                               "max_span": request.budget.max_span,
                           })
    if request.mode_bits not in _MODE_BITS or type(request.entry_loader_linear) is not int:
        raise _ScanRefusal(RegionScanRefusalReason.INVALID_BUDGET,
                           mode_bits=request.mode_bits, entry=request.entry_loader_linear)
    if not request.window.contains(request.entry_loader_linear):
        raise _ScanRefusal(RegionScanRefusalReason.ENTRY_OUTSIDE_WINDOW,
                           entry=f"0x{request.entry_loader_linear:05x}")
    if not request.read_bytes(request.entry_loader_linear, 1):
        raise _ScanRefusal(RegionScanRefusalReason.ENTRY_UNMAPPED,
                           entry=f"0x{request.entry_loader_linear:05x}")


def _outcome(request: RegionScanRequest, state: _ScanState, refusal: RegionScanRefusal | None,
             pending_edges: tuple[PendingSummaryEdge, ...] = ()) -> RegionScanOutcome:
    """Assemble the typed outcome; refusals keep every decoded block and edge."""
    ordered = sorted(state.blocks, key=lambda block: block.linear)
    source = b"".join(bytes.fromhex(block.bytes_hex) for block in ordered)
    counters = FactCounters(
        raw_fact_count=state.instructions_seen,
        normalized_fact_count=len(state.blocks),
        classified_fact_count=state.edge_count,
        materialized_count=len(state.blocks),
        failure_count=0 if refusal is None else 1,
    )
    status = RegionScanStatus.REFUSED if refusal is not None else (
        RegionScanStatus.COMPLETED_PENDING_SUMMARY if pending_edges
        else RegionScanStatus.COMPLETED)
    return RegionScanOutcome(
        status=status,
        entry_loader_linear=request.entry_loader_linear,
        window=request.window,
        blocks=tuple(ordered),
        spans=tuple(sorted(state.spans)),
        source_bytes=source,
        source_sha256=hashlib.sha256(source).hexdigest() if source else None,
        counters=counters,
        refusal=refusal,
        pending_summary_edges=pending_edges,
    )


def scan_candidate_region(request: RegionScanRequest) -> RegionScanOutcome:
    """Scan a bounded multi-block callee candidate from source bytes.

    An acyclic completed candidate has every path closed on a near RET inside
    the window and no refused edge, block or byte check.
    Isolated intra-block self-edges that leave an acyclic residual graph are
    retained as pending-summary evidence in a distinct
    ``COMPLETED_PENDING_SUMMARY`` outcome — never relabeled as acyclic and
    never an admission: the lowering owner must discharge each retained edge
    through the source-bound repeat-summary contract.  The candidate is exact
    boundary evidence for parent lowering — not an admitted function body and
    not an equivalence or saved-return proof.
    """
    state = _ScanState(pending=[request.entry_loader_linear],
                       queued={request.entry_loader_linear})
    refusal: RegionScanRefusal | None = None
    pending_edges: tuple[PendingSummaryEdge, ...] = ()
    try:
        _validate_request(request)
        _walk_region(request, state)
        report = classify_pending_cycle(state.blocks, request.entry_loader_linear)
        if report.verdict is PendingCycleVerdict.CYCLIC:
            raise _ScanRefusal(RegionScanRefusalReason.CYCLE, entry=f"0x{request.entry_loader_linear:05x}")
        if not any(block.terminal is BlockTerminal.NEAR_RET for block in state.blocks):
            raise _ScanRefusal(RegionScanRefusalReason.MISSING_TERMINAL,
                               entry=f"0x{request.entry_loader_linear:05x}")
        if report.verdict is PendingCycleVerdict.PENDING_SUMMARY:
            pending_edges = tuple(
                PendingSummaryEdge(linear=leader, mode_bits=request.mode_bits)
                for leader in report.self_edge_leaders
            )
    except _ScanRefusal as abort:
        refusal = abort.refusal
    return _outcome(request, state, refusal, pending_edges)
