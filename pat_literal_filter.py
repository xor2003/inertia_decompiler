"""Necessary-byte filtering for optional PAT evidence.

Layer: Optional evidence/reporting.
Responsibility: derive a required literal from typed PAT bytes, never classify
a match. The existing backend remains the authority for surviving candidates.
"""

from __future__ import annotations


def required_pat_literal(
    pattern: tuple[int | None, ...],
    module_length: int,
    tail: tuple[int | None, ...],
) -> bytes:
    """Return the first longest fixed run in the bytes the matcher checks.

    Mirror the existing matcher's prefix/tail concatenation exactly, without
    strengthening its evidence using unchecked bytes, CRCs, or symbol names.
    An empty result imposes no filter, including for all-wildcard patterns.
    """
    checked = pattern[:min(module_length, 32)]
    if module_length > 32:
        checked += tail
    longest = b""
    current = bytearray()
    for value in (*checked, None):
        if value is None:
            if len(current) > len(longest):
                longest = bytes(current)
            current.clear()
        else:
            current.append(value)
    return longest
