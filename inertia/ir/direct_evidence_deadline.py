"""Shared cooperative deadline for direct Alias and IR evidence work.

Layer: IR.
Responsibility: own one absolute direct-evidence deadline across local Alias
hydration and nested call-preservation sessions, without owning their budgets.

Package ownership contract (canonical inertia/ir package):
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Protocol, cast

__all__ = [
    "active_direct_evidence_deadline_8616",
    "deadline_reached_8616",
    "direct_evidence_deadline_expired_8616",
    "direct_evidence_deadline_scope_8616",
]


class _DeadlineSessionSurface8616(Protocol):
    """Minimal active resolution session view needed for deadline inheritance."""

    deadline: float | None


class _ProjectDeadlineSurface8616(Protocol):
    """Project-owned deadline and active-session slots."""

    _inertia_direct_evidence_deadline_8616: float | None
    _inertia_entry_domain_call_resolution_8616: object
    _inertia_entry_domain_premise_resolution_8616: object


def deadline_reached_8616(deadline: float | None) -> bool:
    """Return whether one absolute monotonic deadline has elapsed."""
    return deadline is not None and time.monotonic() >= deadline


def _project_deadline_8616(project: object) -> float | None:
    """Read and validate the optional project-scoped absolute deadline."""
    surface = cast(_ProjectDeadlineSurface8616, project)
    try:
        deadline = surface._inertia_direct_evidence_deadline_8616
    except AttributeError:
        return None
    if deadline is not None and type(deadline) is not float:
        raise TypeError("direct-evidence deadline must be a float or None")
    return deadline


def _session_deadline_8616(session: object | None) -> float | None:
    """Read a bounded session deadline without importing its proof owner."""
    if session is None:
        return None
    try:
        deadline = cast(_DeadlineSessionSurface8616, session).deadline
    except AttributeError as ex:
        raise TypeError("active evidence session must expose a typed deadline") from ex
    if deadline is not None and type(deadline) is not float:
        raise TypeError("active evidence session deadline must be a float or None")
    return deadline


def _active_session_deadlines_8616(project: object) -> tuple[float | None, float | None]:
    """Return active callee and premise deadlines from their project slots."""
    surface = cast(_ProjectDeadlineSurface8616, project)
    try:
        callee = surface._inertia_entry_domain_call_resolution_8616
    except AttributeError:
        callee = None
    try:
        premise = surface._inertia_entry_domain_premise_resolution_8616
    except AttributeError:
        premise = None
    return _session_deadline_8616(callee), _session_deadline_8616(premise)


def active_direct_evidence_deadline_8616(project: object) -> float | None:
    """Return the earliest project-slot or active-session deadline."""
    candidates = (
        _project_deadline_8616(project),
        *_active_session_deadlines_8616(project),
    )
    active = tuple(deadline for deadline in candidates if deadline is not None)
    return min(active) if active else None


def direct_evidence_deadline_expired_8616(project: object) -> bool:
    """Return whether the earliest active direct-evidence deadline elapsed."""
    return deadline_reached_8616(active_direct_evidence_deadline_8616(project))


@contextmanager
def direct_evidence_deadline_scope_8616(
    project: object,
    deadline: float | None,
) -> Iterator[None]:
    """Install the earliest request/session deadline and restore the old slot."""
    if deadline is not None and type(deadline) is not float:
        raise TypeError("direct-evidence deadline must be a float or None")
    previous = _project_deadline_8616(project)
    inherited = active_direct_evidence_deadline_8616(project)
    candidates = tuple(
        active
        for active in (deadline, inherited)
        if active is not None
    )
    if not candidates:
        yield
        return
    surface = cast(_ProjectDeadlineSurface8616, project)
    surface._inertia_direct_evidence_deadline_8616 = min(candidates)
    try:
        yield
    finally:
        surface._inertia_direct_evidence_deadline_8616 = previous
