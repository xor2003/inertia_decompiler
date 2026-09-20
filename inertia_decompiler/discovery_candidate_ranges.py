"""Bound selected entries independently of library-body inclusion policy.

Layer: CLI/fallback/reporting.
Responsibility: retain known signature entry boundaries when constructing
candidate recovery windows. These windows are not proof of function semantics.
"""

from __future__ import annotations

from bisect import bisect_right
from collections.abc import Iterable


def pre_entry_candidate_ranges(
    selected: Iterable[int], signature_entries: Iterable[int], *, end: int,
) -> dict[int, tuple[int, int]]:
    """Stop each selected candidate at the next known entry or image limit."""
    starts = sorted(set(selected))
    if any(start >= end for start in starts):
        raise ValueError("Selected pre-entry candidate must precede its end bound")
    boundaries = sorted({*starts, *(addr for addr in signature_entries if addr < end), end})
    return {start: (start, boundaries[bisect_right(boundaries, start)]) for start in starts}
