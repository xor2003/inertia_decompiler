"""Typed comparison of independent real16 execution observations.

Layer: dosunit concrete execution comparison.
Responsibility: compare declared registers, defined flags, memory and outcomes
without promoting execution agreement or incomplete coverage to semantic proof.
"""

from __future__ import annotations

from tools.dosunit.real16_replay_model import (
    COMPLETE_OUTCOMES,
    DEFAULT_OBSERVABLES,
    FLAG_OBSERVABLES,
    GENERAL_REGS,
    HIGH_REGS,
    PRESERVED_OBSERVABLES,
    SEGMENT_REGS,
    Real16Agreement,
    Real16Comparison,
    Real16ReplayResult,
    Real16ReplayStatus,
    effective_flags_mask,
)


def _observed_register(name: str, value: int, flags_mask: int) -> int:
    """Apply the declared flag mask to flag observables; others compare raw.

    Defined flag bits inside the mask are always compared; bits outside the
    mask are architecturally undefined for the vector and excluded. This is
    the only place a flag difference may be invisible, and it is explicit in
    the typed contract rather than silently dropped.
    """
    if name == "eflags":
        return value & flags_mask
    if name == "flags":
        return value & (flags_mask & 0xFFFF)
    return value


def _declared_state_equal(
    oracle: Real16ReplayResult, candidate: Real16ReplayResult,
    observables: tuple[str, ...], flags_mask: int,
) -> bool:
    """Compare registers under the mask plus declared observations/writes."""
    left, right = dict(oracle.registers), dict(candidate.registers)
    registers_equal = all(
        _observed_register(name, left[name], flags_mask)
        == _observed_register(name, right[name], flags_mask)
        for name in observables
    )
    return (
        registers_equal
        and oracle.observations == candidate.observations
        and oracle.writes == candidate.writes
    )


def compare_executions(
    oracle: Real16ReplayResult, candidate: Real16ReplayResult, *,
    observables: tuple[str, ...] = DEFAULT_OBSERVABLES,
) -> Real16Comparison:
    """Compare two replay results under the declared observation contract.

    Only ``RETURNED`` executions may reach ``AGREED``; equal CPU-fault
    outcomes stay ``INCOMPLETE`` because identical non-return evidence does
    not bound post-outcome behaviour (supported scope). Distinct complete
    outcomes — different statuses, or the same CPU-fault class with different
    detail, events or declared state — are ``MISMATCHED`` as known-unequal
    evidence. Control coverage gaps, budget, unsupported and unavailable statuses are never complete
    outcomes and stay ``INCOMPLETE`` regardless of the other side.
    """
    observables = tuple(dict.fromkeys(observables))
    if not observables or not set(observables) >= PRESERVED_OBSERVABLES:
        raise ValueError("observables must retain the caller-owned preserved set")
    known = set(GENERAL_REGS) | set(HIGH_REGS) | set(SEGMENT_REGS) | FLAG_OBSERVABLES | {"ip"}
    if not set(observables) <= known:
        raise ValueError("observables must name supported registers")
    mask = effective_flags_mask(oracle.flags_mask) | effective_flags_mask(candidate.flags_mask)
    if oracle.status not in COMPLETE_OUTCOMES or candidate.status not in COMPLETE_OUTCOMES:
        return Real16Comparison(
            Real16Agreement.INCOMPLETE, observables, mask,
            "at least one side has no complete outcome",
        )
    if oracle.status is not candidate.status:
        return Real16Comparison(
            Real16Agreement.MISMATCHED, observables, mask,
            "distinct complete outcomes",
        )
    if oracle.status is Real16ReplayStatus.RETURNED:
        if _declared_state_equal(oracle, candidate, observables, mask):
            return Real16Comparison(Real16Agreement.AGREED, observables, mask)
        return Real16Comparison(
            Real16Agreement.MISMATCHED, observables, mask,
            "declared observations diverge",
        )
    # FAULTED: the exact CPU outcome is status + detail + typed events +
    # declared state. Identical CPU-fault outcomes are recorded but never promoted to
    # agreement; any divergence is known-unequal evidence.
    if (
        oracle.detail == candidate.detail
        and oracle.events == candidate.events
        and _declared_state_equal(oracle, candidate, observables, mask)
    ):
        return Real16Comparison(
            Real16Agreement.INCOMPLETE, observables, mask,
            "equal non-return outcome; agreement unsupported",
        )
    return Real16Comparison(
        Real16Agreement.MISMATCHED, observables, mask,
        "distinct fault/control outcome",
    )


def compare_replays(
    oracle: Real16ReplayResult, candidate: Real16ReplayResult, *,
    observables: tuple[str, ...] = DEFAULT_OBSERVABLES,
) -> Real16Agreement:
    """Return the agreement verdict of the typed differential comparison.

    Agreement never promotes a proof: it covers exactly the declared
    observables, observations, writes and masked flags — not timing or
    instruction counts.
    """
    return compare_executions(oracle, candidate, observables=observables).agreement
