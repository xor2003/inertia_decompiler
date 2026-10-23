"""Layer: IR.
Responsibility: select equivalent temporary caller intervals at a protection query.
"""
from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from .real16_persistent_bytes8616 import PersistentBytes8616, canonical_known_root_8616


@dataclass(frozen=True, slots=True)
class ScratchCallerRange8616:
    """Already-authenticated complete caller range, never fresh proof authority."""

    start: int
    end: int


class ScratchProtectionBudget8616(Protocol):
    """Existing scratch work/deadline owner; no independent budget or cache."""

    work_units: int
    deadline: float


class CallerIntervalSelectionStatus8616(Enum):
    """Separate exact selection, unknown metadata fallback and resource refusal."""

    ORIGINAL = "original"
    SELECTED = "selected"
    REFUSED = "refused"


@dataclass(frozen=True, slots=True)
class CallerIntervalSelection8616:
    """One temporary union input, with no lifetime beyond the current query.

    ``envelope`` is the half-open ``(low, high)`` bound over exactly the
    returned ``intervals``, accumulated during the already-charged selection
    walk. It is conservative evidence only: a byte range disjoint from it
    cannot overlap any selected interval, while an intersecting range still
    requires the ordinary exact union check. ``None`` whenever selection did
    not run to a complete exact result.
    """

    status: CallerIntervalSelectionStatus8616
    intervals: set[tuple[int, int]] | None = None
    envelope: tuple[int, int] | None = None


def select_caller_intervals_8616[Budget: ScratchProtectionBudget8616](
    budget: Budget, spans: set[tuple[int, int]], caller_range: ScratchCallerRange8616,
    charge: Callable[[Budget], bool],
) -> CallerIntervalSelection8616:
    """Use the existing charged input walk to omit exact contained intervals.

    The complete range must itself be offered. Unknown metadata requires the
    original charged union walk; resource refusal never authorizes fallback.
    """
    budget.work_units += 1
    if time.monotonic() > budget.deadline or charge(budget):
        return CallerIntervalSelection8616(CallerIntervalSelectionStatus8616.REFUSED)
    if not _exact_range_8616(caller_range, spans):
        return CallerIntervalSelection8616(CallerIntervalSelectionStatus8616.ORIGINAL)
    start, end = caller_range.start, caller_range.end
    intervals: set[tuple[int, int]] = set()
    complete_present = False
    envelope_low: int | None = None
    envelope_high = 0
    for span in spans:
        budget.work_units += 1
        if time.monotonic() > budget.deadline or charge(budget):
            return CallerIntervalSelection8616(CallerIntervalSelectionStatus8616.REFUSED)
        if not _exact_span_8616(span):
            return CallerIntervalSelection8616(CallerIntervalSelectionStatus8616.ORIGINAL)
        base, size = span
        complete = base == start and size == end - start
        complete_present = complete_present or complete
        if complete or not start <= base <= base + size <= end:
            intervals.add((base, base + size))
            envelope_low = base if envelope_low is None else min(envelope_low, base)
            envelope_high = max(envelope_high, base + size)
    if not complete_present:
        return CallerIntervalSelection8616(CallerIntervalSelectionStatus8616.ORIGINAL)
    return CallerIntervalSelection8616(
        CallerIntervalSelectionStatus8616.SELECTED, intervals,
        None if envelope_low is None else (envelope_low, envelope_high),
    )


def _exact_span_8616(span: tuple[int, int]) -> bool:
    """Read coordinates only from an exact owned tuple with positive size."""
    if type(span) is not tuple or len(span) != 2:
        return False
    return (type(span[0]) is int and type(span[1]) is int
            and span[0] >= 0 and span[1] > 0)


def _exact_range_8616(caller_range: ScratchCallerRange8616, spans: set[tuple[int, int]]) -> bool:
    """Only exact coordinates and an owned set authorize interval selection."""
    if type(caller_range) is not ScratchCallerRange8616 or type(spans) is not set:
        return False
    return (type(caller_range.start) is int and type(caller_range.end) is int
            and 0 <= caller_range.start < caller_range.end)


def _written_key_envelope_8616[Budget: ScratchProtectionBudget8616](
    budget: Budget, keys: Iterable[int], initial: tuple[int, int] | None,
    charge: Callable[[Budget], bool],
) -> tuple[int, int] | None:
    """Extend bounds by charged exact-key inspection; unknown input yields no bound."""
    low, high = (None, 0) if initial is None else initial
    for address in keys:
        budget.work_units += 1
        if time.monotonic() > budget.deadline or charge(budget):
            return None
        if type(address) is not int:
            return None
        low = address if low is None else min(low, address)
        high = max(high, address + 1)
    return None if low is None else (low, high)


def written_address_envelope_8616[Budget: ScratchProtectionBudget8616](
    budget: Budget, known: Mapping[int, int], unknown: set[int], manifest_size: int,
    charge: Callable[[Budget], bool],
) -> tuple[int, int] | None:
    """Bound current writes without scanning a large canonical known-byte map.

    Small ordinary ledgers use a charged scan. Large canonical facades use
    their maintained root-bound envelope and scan only unknown bytes. Foreign
    iterators never authorize exclusion. None means no usable bound; the
    caller must check its original resource owner before taking a fallback.
    """
    if type(unknown) is not set or type(known) not in (dict, PersistentBytes8616):
        return None
    if type(known) is PersistentBytes8616 and not canonical_known_root_8616(known):
        return None
    count = len(known) + len(unknown)
    if count == 0:
        return None
    if count * 2 < manifest_size:
        return _written_key_envelope_8616(
            budget, (address for written in (known, unknown) for address in written), None, charge,
        )
    if not isinstance(known, PersistentBytes8616) or (len(unknown) + 1) * 2 >= manifest_size:
        return None
    budget.work_units += 1
    if time.monotonic() > budget.deadline or charge(budget):
        return None
    envelope = known.address_envelope_8616()
    if envelope is None:
        return None
    return _written_key_envelope_8616(budget, unknown, envelope, charge)
