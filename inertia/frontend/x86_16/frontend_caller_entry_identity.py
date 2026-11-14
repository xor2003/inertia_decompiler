# cython: language_level=3, infer_types=True
"""Prove caller entry equivalence without changing binary decoding bounds.

Layer: Frontend.
Responsibility: give an independently supplied caller range one stable entry
identity across instruction inventories. Only a contiguous prefix of single
byte x86 NOPs may be skipped. Zero bytes, traps, instruction prefixes and
prologue-shaped bytes are never evidence of equivalent execution. This is
not function discovery, and does not widen the supplied range.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Iterable
from dataclasses import dataclass
import dataclasses
import operator


@dataclasses.dataclass(frozen=True, )
class CallerEntryIdentity8616:
    """Keep decoding bounds and the exact witness for a NOP-equivalent entry."""

    decode_start: cython.longlong
    decode_end: cython.longlong
    entry_addr: cython.longlong
    nop_prefix: object

    def __post_init__(self) -> None:
        """Reject forged, out-of-range and wrapping entry-equivalence proofs."""
        valid_bounds = 0 <= self.decode_start <= self.entry_addr < self.decode_end
        exact_prefix = (
            operator.eq(len(self.nop_prefix), self.entry_addr - self.decode_start)
            and all(byte == 0x90 for byte in iter(self.nop_prefix))
        )
        same_segment_window = operator.eq(self.decode_start >> 16, self.entry_addr >> 16)
        if not valid_bounds or not exact_prefix or not same_segment_window:
            raise ValueError(f"invalid caller entry identity: {self!r}")


@cython.ccall
def prove_caller_entry_identity_8616(
    start: cython.longlong, end: cython.longlong, data: object,
) -> CallerEntryIdentity8616 | None:
    """Normalize a complete binary range, retaining unknown entries unchanged.

    A non-NOP endpoint is required: an all-NOP range cannot establish a body.
    Skipping a prefix never removes a call, register effect, flag effect or
    memory effect. Decode still starts at the original address.
    """
    byte: object
    if start < 0 or end <= start or operator.ne(len(data), end - start):
        return None
    prefix_size = 0
    for byte in data:
        if byte != 0x90:
            break
        prefix_size += 1
    reaches_body = prefix_size < len(data)
    same_segment_window = operator.eq(start >> 16, (start + prefix_size) >> 16)
    if not reaches_body or not same_segment_window:
        prefix_size = 0
    return CallerEntryIdentity8616(start, end, start + prefix_size, data[:prefix_size])


@cython.ccall
def caller_target_identity_8616(
    target: cython.longlong, identities: Iterable[CallerEntryIdentity8616],
) -> cython.longlong:
    """Resolve proven aliases under the existing near-call target convention.

    Conflicting normalized windows must fail explicitly, not choose whichever
    caller range happened to be visited first. Segment-aware target resolution
    outside this near-call inventory retains its existing owner.
    """
    normalized = target & 0xffff
    candidates = {
        identity.entry_addr & 0xffff for identity in iter(identities)
        if identity.decode_start & 0xffff <= normalized <= identity.entry_addr & 0xffff
    }
    if len(candidates) > 1:
        raise ValueError(f"conflicting caller entry aliases for {target:#x}: {sorted(candidates)!r}")
    return next(iter(candidates), normalized)
