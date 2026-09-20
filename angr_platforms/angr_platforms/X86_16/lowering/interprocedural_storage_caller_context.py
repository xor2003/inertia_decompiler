"""Resolve exact caller execution context from the direct-call census.

Layer: Types/Lowering.
Responsibility: join one callsite identity to the census-owned evidence project
and exact caller function boundary used by all interprocedural SSA consumers.
This module does not rebuild boundaries, infer types, or mutate codegen.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from ..caller_return_use_contracts import CallerReturnUseFact8616
from .callee_callsite_census import collect_callee_callsite_census_8616

__all__ = [
    "CallerSSAContext8616",
    "CallerSSAContextVerdict8616",
    "caller_ssa_context_for_callsite_8616",
    "caller_ssa_context_for_return_use_8616",
]


class CallerSSAContextVerdict8616(StrEnum):
    """Typed outcome of joining return-use and direct-call identities."""

    PROVEN = "proven"
    UNAVAILABLE = "unavailable"
    CONFLICT = "conflict"


@dataclass(frozen=True, slots=True)
class CallerSSAContext8616:
    """One exact caller project and function boundary, or a typed refusal."""

    verdict: CallerSSAContextVerdict8616
    caller_addr: int
    callsite_addr: int
    evidence_project: object | None = field(default=None, compare=False, repr=False)
    caller_function: object | None = field(default=None, compare=False, repr=False)

    @property
    def complete(self) -> bool:
        """Return whether both execution owner and exact boundary are retained."""
        return (
            self.verdict is CallerSSAContextVerdict8616.PROVEN
            and self.evidence_project is not None
            and self.caller_function is not None
        )


def caller_ssa_context_for_return_use_8616(
    project: object,
    callee_addr: int,
    fact: CallerReturnUseFact8616,
) -> CallerSSAContext8616:
    """Join one return-use fact to its unique normalized direct-call fact."""
    return caller_ssa_context_for_callsite_8616(
        project, callee_addr, fact.caller_addr, fact.callsite_addr
    )


def caller_ssa_context_for_callsite_8616(
    project: object,
    callee_addr: int,
    caller_addr: int,
    callsite_addr: int,
) -> CallerSSAContext8616:
    """Select the exact caller owner shared by return and memory-effect consumers."""
    census = collect_callee_callsite_census_8616(project, callee_addr)
    matches = tuple(
        caller
        for caller in census.facts
        if caller.caller_addr == caller_addr
        and caller.callsite_addr == callsite_addr
        and caller.summary is not None
    )
    if len(matches) == 1:
        match = matches[0]
        return CallerSSAContext8616(
            CallerSSAContextVerdict8616.PROVEN,
            caller_addr,
            callsite_addr,
            evidence_project=match.evidence_project,
            caller_function=match.caller_function,
        )
    return CallerSSAContext8616(
        CallerSSAContextVerdict8616.CONFLICT
        if len(matches) > 1
        else CallerSSAContextVerdict8616.UNAVAILABLE,
        caller_addr,
        callsite_addr,
    )
