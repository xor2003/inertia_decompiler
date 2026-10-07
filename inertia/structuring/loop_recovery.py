"""Recover natural loop metadata from CFG and structured IR evidence.

Layer: Structuring.
Responsibility: owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.

Output: metadata-only dataclasses (RecoveredLoop, etc.).
Do NOT emit C `for` loops here — lowering belongs in a later pass.

Forbidden: text matching, asm/C regex, sample-specific address hacks.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

from .natural_loop_topology import (
    LoopTopologyStats8616,
    LoopTopologyVerdict8616,
    NaturalLoopTopology8616,
    classify_natural_loop_topology_8616,
)

__all__ = [
    "BlockSemantics",
    "CFGView",
    "InductionUpdate",
    "LoopBackEdge",
    "LoopGuard",
    "LoopTopologyStats8616",
    "LoopTopologyVerdict8616",
    "NaturalLoop",
    "NaturalLoopTopology8616",
    "RecoveredLoop",
    "build_natural_loop",
    "classify_natural_loop_topology_8616",
    "compute_dominators",
    "find_back_edges",
    "find_loop_guard",
    "find_loop_induction",
    "match_induction_update",
    "match_loop_guard",
    "recover_loops",
    "recover_natural_loops",
]


@dataclass(frozen=True, slots=True)
class LoopBackEdge:
    """CFG edge from a latch block back to a loop header."""

    header: int
    latch: int


@dataclass(frozen=True, slots=True)
class NaturalLoop:
    """Natural loop membership recovered from a back edge."""

    header: int
    latch: int
    blocks: frozenset[int]


@dataclass(frozen=True, slots=True)
class InductionUpdate:
    """Recovered induction-variable update evidence."""

    variable: object
    initial: object | None
    step: int
    update_block: int
    confidence: float


@dataclass(frozen=True, slots=True)
class LoopGuard:
    """Recovered loop guard evidence tied to an induction variable."""

    variable: object
    bound: object
    op: str
    signed: bool
    guard_block: int
    confidence: float


@dataclass(frozen=True, slots=True)
class RecoveredLoop:
    """Recovered loop with optional induction and guard evidence."""

    loop: NaturalLoop
    induction: InductionUpdate | None
    guard: LoopGuard | None
    confidence: float


class CFGView(Protocol):
    """Minimal CFG interface used by loop recovery."""

    def successors(self, block: int) -> Iterable[int]:
        """Return successor block ids."""
        ...

    def predecessors(self, block: int) -> Iterable[int]:
        """Return predecessor block ids."""
        ...


class BlockSemantics(Protocol):
    """Minimal block semantics interface used by loop recovery."""

    def statements(self, block: int) -> Iterable[object]:
        """Return semantic statements for a block."""
        ...

    def terminator_condition(self, block: int) -> object | None:
        """Return the block terminator condition when one exists."""
        ...


def compute_dominators(cfg: CFGView, entry: int, blocks: Iterable[int]) -> dict[int, set[int]]:
    """Compute dominator sets for the selected CFG blocks."""
    block_set = set(blocks)
    dom = {b: set(block_set) for b in block_set}
    dom[entry] = {entry}

    changed = True
    while changed:
        changed = False
        for b in sorted(block_set):
            if b == entry:
                continue
            preds = [p for p in cfg.predecessors(b) if p in block_set]
            new_dom = {b} if not preds else set.intersection(*(dom[p] for p in preds)) | {b}
            if new_dom != dom[b]:
                dom[b] = new_dom
                changed = True

    return dom


def find_back_edges(cfg: CFGView, entry: int, blocks: Iterable[int]) -> list[LoopBackEdge]:
    """Find CFG edges whose destination dominates their source."""
    block_list = list(blocks)
    dom = compute_dominators(cfg, entry, block_list)
    edges = [
        LoopBackEdge(header=dst, latch=src)
        for src in block_list
        for dst in cfg.successors(src)
        if dst in dom.get(src, set())
    ]

    return sorted(edges, key=lambda e: (e.header, e.latch))


def build_natural_loop(cfg: CFGView, edge: LoopBackEdge) -> NaturalLoop:
    """Build the natural loop induced by a back edge."""
    members = {edge.header, edge.latch}
    worklist = [edge.latch]

    while worklist:
        b = worklist.pop()
        for pred in cfg.predecessors(b):
            if pred not in members:
                members.add(pred)
                worklist.append(pred)

    return NaturalLoop(
        header=edge.header,
        latch=edge.latch,
        blocks=frozenset(members),
    )


def recover_natural_loops(cfg: CFGView, entry: int, blocks: Iterable[int]) -> list[NaturalLoop]:
    """Recover natural loops from CFG topology only."""
    return [build_natural_loop(cfg, edge) for edge in find_back_edges(cfg, entry, blocks)]


# ── Induction variable detection ──


def _same_var(a: object, b: object) -> bool:
    return repr(a) == repr(b)


def match_induction_update(stmt: object) -> InductionUpdate | None:
    """Match one structured statement as an induction update."""

    def _impl() -> InductionUpdate | None:
        """Match ``i = i + c`` or ``i = i - c``.

        Operates on dynamic angr/compatibility boundary node objects, not rendered text.
        """
        target = getattr(stmt, "target", None) or getattr(stmt, "lhs", None)
        value = getattr(stmt, "value", None) or getattr(stmt, "rhs", None)
        if target is None or value is None:
            return None

        op = getattr(value, "op", None)
        left = getattr(value, "left", None) or getattr(value, "lhs", None)
        right = getattr(value, "right", None) or getattr(value, "rhs", None)

        if op not in ("Add", "Sub"):
            return None
        if not _same_var(target, left):
            return None
        constant = getattr(right, "value", None)
        if not isinstance(constant, int):
            return None

        c = constant
        step = c if op == "Add" else -c

        return InductionUpdate(variable=target, initial=None, step=step, update_block=-1, confidence=0.75)

    return _impl()


def find_loop_induction(loop: NaturalLoop, semantics: BlockSemantics) -> InductionUpdate | None:
    """Find a unique induction update inside a recovered loop."""
    candidates: list[InductionUpdate] = []

    for block in sorted(loop.blocks):
        for stmt in semantics.statements(block):
            match = match_induction_update(stmt)
            if match is not None:
                candidates.append(
                    InductionUpdate(
                        variable=match.variable,
                        initial=match.initial,
                        step=match.step,
                        update_block=block,
                        confidence=match.confidence,
                    )
                )

    return candidates[0] if len(candidates) == 1 else None


# ── Loop guard detection ──


def match_loop_guard(cond: object, induction: InductionUpdate | None, guard_block: int) -> LoopGuard | None:
    """Match a typed condition as a loop guard for an induction update."""

    def _impl() -> LoopGuard | None:
        """Match ``i < N``, ``i <= N``, ``i != N``, ``i > N``, or ``i >= N``.

        Operates on dynamic angr/compatibility boundary condition objects, not text.
        """
        if cond is None or induction is None:
            return None

        op = getattr(cond, "op", None)
        left = getattr(cond, "left", None) or getattr(cond, "lhs", None)
        right = getattr(cond, "right", None) or getattr(cond, "rhs", None)

        if op is None or left is None or right is None:
            return None

        op_str = str(op)
        known = {"LT", "LE", "GT", "GE", "NE", "EQ"}
        if op_str not in known and op_str.lstrip("SU") not in known:
            return None

        if not _same_var(left, induction.variable):
            return None

        signed = op_str.startswith("S")
        normalized_op = op_str
        if normalized_op.startswith(("S", "U")):
            normalized_op = normalized_op[1:]

        return LoopGuard(
            variable=left,
            bound=right,
            op=normalized_op,
            signed=signed,
            guard_block=guard_block,
            confidence=0.75,
        )

    return _impl()


def find_loop_guard(
    loop: NaturalLoop,
    semantics: BlockSemantics,
    induction: InductionUpdate | None,
) -> LoopGuard | None:
    """Find the loop guard attached to a loop header or latch."""
    for block in (loop.header, loop.latch):
        cond = semantics.terminator_condition(block)
        guard = match_loop_guard(cond, induction, block)
        if guard is not None:
            return guard
    return None


# ── Final recovery API ──


def recover_loops(
    cfg: CFGView,
    semantics: BlockSemantics,
    *,
    entry: int,
    blocks: Iterable[int],
) -> list[RecoveredLoop]:
    """Recover natural loops with optional induction and guard evidence."""
    recovered: list[RecoveredLoop] = []

    for loop in recover_natural_loops(cfg, entry, blocks):
        induction = find_loop_induction(loop, semantics)
        guard = find_loop_guard(loop, semantics, induction)

        confidence = 0.4
        if induction is not None:
            confidence += 0.25
        if guard is not None:
            confidence += 0.25

        recovered.append(
            RecoveredLoop(
                loop=loop,
                induction=induction,
                guard=guard,
                confidence=min(confidence, 0.95),
            )
        )

    return sorted(recovered, key=lambda x: (x.loop.header, x.loop.latch))
