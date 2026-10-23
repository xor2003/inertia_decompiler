"""Bounded flag-helper evidence over serialized SSA expression DAGs.

Layer: dosunit SSA.
Responsibility: distinguish reachable abstract helpers from incomplete scans;
neither a traversal limit nor malformed references establish helper evidence.
"""
from __future__ import annotations

from collections.abc import Callable
from collections.abc import Set as AbstractSet
from enum import IntEnum, StrEnum
from typing import Any, Final

DEFAULT_FLAG_SCAN_STEP_BUDGET: Final[int] = 1024


class FlagScanOutcome(StrEnum):
    """Evidence found, complete helper-free coverage, or unproved coverage."""

    UNINTERPRETED_HELPER = "uninterpreted_helper"
    CLEAN = "clean"
    INCOMPLETE = "incomplete"


class _WorkKind(IntEnum):
    """Explicit DFS entry and exit events, including shared reference targets."""

    CLOSE = 0
    EXPAND = 1


def _target(
    term: object, assignments: dict[str, dict[str, Any]], *, resolve: bool,
) -> dict[str, Any] | None:
    """Resolve a reference on visitation, preserving sibling-cycle detection."""
    if not isinstance(term, dict):
        return None
    ref = term.get("ref")
    if ref is None or not resolve:
        return term
    return assignments.get(ref) if isinstance(ref, str) else None


def scan_flag_evidence(
    root: object,
    assignments: dict[str, dict[str, Any]],
    *,
    summary_ops: AbstractSet[str],
    summary_is_uninterpreted: Callable[[dict[str, Any], dict[str, dict[str, Any]]], bool],
    step_budget: int = DEFAULT_FLAG_SCAN_STEP_BUDGET,
) -> FlagScanOutcome:
    """Visit each shared compound term once within an explicit expansion budget.

    References resolve only when popped, so siblings are not prematurely
    considered complete. Active targets catch cycles; dangling references and
    budget exhaustion remain incomplete. Leaf checks do not expand the graph.
    The SSA operator arity bounds leaf work per admitted compound node.
    """
    work: list[tuple[_WorkKind, object]] = [(_WorkKind.EXPAND, root)]
    active: set[int] = set()
    done: set[int] = set()
    steps = 0
    complete = True
    while work:
        kind, raw = work.pop()
        term = _target(raw, assignments, resolve=kind is _WorkKind.EXPAND)
        if term is None:
            complete = False
            continue
        marker = id(term)
        if kind is _WorkKind.CLOSE:
            active.remove(marker)
            done.add(marker)
            continue
        if marker in active:
            complete = False
            continue
        if marker in done:
            continue
        if term.get("op") in summary_ops and summary_is_uninterpreted(term, assignments):
            return FlagScanOutcome.UNINTERPRETED_HELPER
        args = ({"ref": term["ref"]},) if "ref" in term else term.get("args", ())
        if not isinstance(args, (list, tuple)):
            complete = False
            continue
        if not args:
            done.add(marker)
            continue
        if steps >= step_budget:
            return FlagScanOutcome.INCOMPLETE
        steps += 1
        active.add(marker)
        work.append((_WorkKind.CLOSE, term))
        work.extend((_WorkKind.EXPAND, child) for child in args)
    return FlagScanOutcome.CLEAN if complete else FlagScanOutcome.INCOMPLETE
