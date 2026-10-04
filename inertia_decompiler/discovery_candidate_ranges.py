"""Bound selected entries independently of library-body inclusion policy.

Layer: CLI/fallback/reporting.
Responsibility: retain signature entry hints for candidate recovery windows,
but let closed Frontend binary bodies override interior hints in caller scans.
Candidate windows alone are not proof of function semantics.
"""

from __future__ import annotations

from bisect import bisect_right
from collections.abc import Iterable

from angr_platforms.X86_16.frontend_function_boundary import (
    exact_function_range_boundary_8616,
)


def pre_entry_candidate_ranges(
    selected: Iterable[int], signature_entries: Iterable[int], *, end: int,
) -> dict[int, tuple[int, int]]:
    """Stop each selected candidate at the next known entry or image limit."""
    starts = sorted(set(selected))
    if any(start >= end for start in starts):
        raise ValueError("Selected pre-entry candidate must precede its end bound")
    boundaries = sorted({*starts, *(addr for addr in signature_entries if addr < end), end})
    return {start: (start, boundaries[bisect_right(boundaries, start)]) for start in starts}


def pre_entry_caller_ranges_8616(
    project: object,
    selected: Iterable[int],
    signature_entries: Iterable[int],
    *,
    end: int,
) -> dict[int, tuple[int, int]]:
    """Keep caller bodies that independently prove a signature hint is interior.

    The next selected entry and startup/image end supply the bounded binary
    window. Only a closed Frontend reachability census can identify a signature
    delimiter as interior. Remove those delimiters individually, keeping the
    next unreachable or unproven neighboring entry. Unavailable/open binary
    proof keeps the original limit. Library recovery windows remain unchanged.
    """
    starts = tuple(selected)
    hint_entries = tuple(signature_entries)
    ranges = pre_entry_candidate_ranges(starts, hint_entries, end=end)
    binary_windows = pre_entry_candidate_ranges(starts, (), end=end)
    for start, (_start, hinted_end) in ranges.items():
        binary_end = binary_windows[start][1]
        if hinted_end == binary_end:
            continue
        boundary = exact_function_range_boundary_8616(project, start, binary_end)
        if (
            boundary is not None
            and boundary.project is project
            and boundary.addr == start
            and boundary.size == binary_end - start
            and hinted_end in boundary.reachable_instruction_addrs
        ):
            remaining_hints = (
                addr for addr in hint_entries
                if addr not in boundary.reachable_instruction_addrs
            )
            ranges[start] = pre_entry_candidate_ranges(
                (start,), remaining_hints, end=binary_end,
            )[start]
    return ranges
