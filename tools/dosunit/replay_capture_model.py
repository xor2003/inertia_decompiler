"""Shared typed contracts for guarded runtime capture at a declared boundary.

Layer: dosunit concrete execution contracts.
Responsibility: own the boundary-capture outcome taxonomy and the owned
mutable capture run state shared by the real16 and flat32 guarded capture
APIs. A capture is concrete execution evidence about one actually executed
prefix; it is never replay agreement, a proof verdict, or a claim about
callable entry domains, complete callee targets, or caller continuation
derived from a single trace.

"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

DEFAULT_TRACE_LIMIT: int = 4096
"""Default fetch-trace bound for capture runs; replay does not trace."""


class CaptureStatus(StrEnum):
    """Typed outcome of a guarded boundary capture; never a proof verdict.

    ``CAPTURED`` means the fetch stream reached the declared boundary after
    an admitted executed prefix and the returned snapshot is real guest
    state. Every other member is a typed non-result; the concrete
    ``execution_status``/``detail``/``events`` fields on the capture record
    carry the exact replay typing of the refusal instead of a guessed state.
    """

    CAPTURED = "captured"
    """Fetch reached the boundary; the register/observation snapshot is real."""
    EXECUTION_REFUSED = "execution_refused"
    """The executed prefix produced a typed replay outcome: an unadmitted
    instruction class (machine input, device I/O, privileged, unmodeled
    register file, undecodable), a fault, an unmapped/denied access, a write
    into declared instruction bytes, or a fetch outside declared code."""
    RETURNED_BEFORE_BOUNDARY = "returned_before_boundary"
    """Fetch reached the caller-frame return trap before the boundary."""
    BUDGET_EXHAUSTED = "budget_exhausted"
    """The instruction budget was consumed without reaching the boundary."""
    TRACE_OVERFLOW = "trace_overflow"
    """The fetch-trace bound was consumed before reaching the boundary."""
    BOUNDARY_INVALID = "boundary_invalid"
    """The declared boundary is outside executable scope or aliases the
    caller-frame return trap; no execution occurred."""
    UNAVAILABLE = "unavailable"
    """The concrete backend was unavailable; no execution occurred."""


class CaptureObservationStatus(StrEnum):
    """Whether one requested capture observation produced host bytes."""

    CAPTURED = "captured"
    """The range was read from the guest at the boundary."""
    UNMAPPED = "unmapped"
    """The range had no declared/guest mapping; no bytes were read."""


@dataclass(slots=True)
class _CaptureState:
    """Owned mutable boundary state for one isolated guest execution.

    ``boundary`` is the resolved physical fetch address that stops the run;
    ``trace`` records the fetched addresses of the executed prefix plus the
    boundary fetch (the return-trap fetch is checked before recording) and
    is bounded by ``trace_limit``. ``reached`` and ``overflow`` are the two
    capture-local stop reasons; every other stop keeps the underlying
    replay outcome typed on the run state.
    """

    boundary: int
    trace_limit: int
    trace: list[int] = field(default_factory=list)
    reached: bool = False
    overflow: bool = False


def resolve_capture_status(
    capture: _CaptureState, execution: StrEnum, *, returned: StrEnum, budget: StrEnum
) -> CaptureStatus:
    """Map one run's capture-local and replay outcomes to the capture taxonomy.

    ``execution`` is the executor's own outcome enum after the shared loop
    stopped; ``returned`` and ``budget`` name that executor's return-trap and
    budget outcomes. Capture-local stops (boundary reached, trace overflow)
    outrank the run-state default, which still holds its initial value in
    those cases. Anything else is a real replay outcome surfaced as
    ``EXECUTION_REFUSED``; the exact executor status stays on the record.
    """
    if capture.overflow:
        return CaptureStatus.TRACE_OVERFLOW
    if capture.reached:
        return CaptureStatus.CAPTURED
    if execution == returned:
        return CaptureStatus.RETURNED_BEFORE_BOUNDARY
    if execution == budget:
        return CaptureStatus.BUDGET_EXHAUSTED
    return CaptureStatus.EXECUTION_REFUSED
