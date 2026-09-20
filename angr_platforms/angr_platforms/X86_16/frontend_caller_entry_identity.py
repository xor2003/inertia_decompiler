"""Prove caller entry equivalence without changing binary decoding bounds.

Layer: Frontend.
Responsibility: give an independently supplied caller range one stable entry
identity across instruction inventories. Only a contiguous prefix of single
byte x86 NOPs may be skipped. Zero bytes, traps, instruction prefixes and
prologue-shaped bytes are never evidence of equivalent execution. This is
not function discovery, and does not widen the supplied range.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CallerEntryIdentity8616:
    """Keep decoding bounds and the exact witness for a NOP-equivalent entry."""

    decode_start: int
    decode_end: int
    entry_addr: int
    nop_prefix: bytes

    def __post_init__(self) -> None:
        """Reject forged, out-of-range and wrapping entry-equivalence proofs."""
        valid_bounds = 0 <= self.decode_start <= self.entry_addr < self.decode_end
        exact_prefix = (
            len(self.nop_prefix) == self.entry_addr - self.decode_start
            and all(byte == 0x90 for byte in self.nop_prefix)
        )
        same_segment_window = self.decode_start >> 16 == self.entry_addr >> 16
        if not valid_bounds or not exact_prefix or not same_segment_window:
            raise ValueError(f"invalid caller entry identity: {self!r}")


def prove_caller_entry_identity_8616(
    start: int, end: int, data: bytes,
) -> CallerEntryIdentity8616 | None:
    """Normalize a complete binary range, retaining unknown entries unchanged.

    A non-NOP endpoint is required: an all-NOP range cannot establish a body.
    Skipping a prefix never removes a call, register effect, flag effect or
    memory effect. Decode still starts at the original address.
    """
    if start < 0 or end <= start or len(data) != end - start:
        return None
    prefix_size = 0
    for byte in data:
        if byte != 0x90:
            break
        prefix_size += 1
    reaches_body = prefix_size < len(data)
    same_segment_window = start >> 16 == (start + prefix_size) >> 16
    if not reaches_body or not same_segment_window:
        prefix_size = 0
    return CallerEntryIdentity8616(start, end, start + prefix_size, data[:prefix_size])


def caller_target_identity_8616(
    target: int, identities: Iterable[CallerEntryIdentity8616],
) -> int:
    """Resolve proven aliases under the existing near-call target convention.

    Conflicting normalized windows must fail explicitly, not choose whichever
    caller range happened to be visited first. Segment-aware target resolution
    outside this near-call inventory retains its existing owner.
    """
    normalized = target & 0xffff
    candidates = {
        identity.entry_addr & 0xffff for identity in identities
        if identity.decode_start & 0xffff <= normalized <= identity.entry_addr & 0xffff
    }
    if len(candidates) > 1:
        raise ValueError(f"conflicting caller entry aliases for {target:#x}: {sorted(candidates)!r}")
    return next(iter(candidates), normalized)
