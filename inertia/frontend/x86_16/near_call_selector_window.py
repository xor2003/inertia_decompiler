"""Conditional CS selector interval for one source-bound near-CALL premise.

Layer: frontend x86_16.
Responsibility: derive the closed inclusive selector interval under which
one premise-bound ``E8`` near CALL still fetches entirely inside the CS
window below 1 MiB and decodes to the same raw linear destination, then
retain that interval beside the exact premise identity that earned it.

This is geometry data only. It establishes neither CS preservation inside
the callee, nor boot/reachability authority, nor a selector receipt from
decoded numbers alone: the bound row and index are re-proven by the
canonical premise owner before any bound is computed, and every selector
admitted here still owes its own CS-preservation proof before any
consumer may use the interval.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import ClassVar

from .frontend_near_return_continuation import (
    EntryTopSlotKind8616,
    NearCallFramePremise8616,
    prove_near_call_frame_premise_8616,
)

__all__ = [
    "NearCallSelectorWindow8616",
    "NearCallSelectorWindowFailure8616",
    "NearCallSelectorWindowRefusal8616",
    "project_near_call_selector_window_8616",
]

_SELECTOR_SHIFT_8616 = 4
_WORD_SPAN_8616 = 0x10000
_PHYSICAL_LIMIT_8616 = 0x100000
_SELECTOR_BASE_MAX_8616 = 0xFFFF0


class NearCallSelectorWindowFailure8616(StrEnum):
    """Typed reasons a premise cannot yield a selector window."""

    PREMISE_ABSENT = "near_call_selector_premise_absent"
    PREMISE_REPROOF_FAILED = "near_call_selector_premise_reproof_failed"
    PREMISE_COORDINATE_FORGERY = "near_call_selector_premise_coordinate_forgery"
    UNSUPPORTED_NEAR_FORM = "near_call_selector_unsupported_near_form"
    FETCH_EXTENT_INVALID = "near_call_selector_fetch_extent_invalid"
    FETCH_A20_AMBIGUOUS = "near_call_selector_fetch_a20_ambiguous"
    TARGET_A20_AMBIGUOUS = "near_call_selector_target_a20_ambiguous"
    SELECTOR_WINDOW_EMPTY = "near_call_selector_window_empty"
    TARGET_NOT_WINDOW_INVARIANT = "near_call_selector_target_not_window_invariant"


@dataclass(frozen=True, slots=True)
class NearCallSelectorWindow8616:
    """Proven closed selector interval for one exact near-CALL premise.

    Every selector in ``[selector_low, selector_high]`` fetches the bound
    instruction entirely inside its CS window below 1 MiB and decodes the
    same ``target_addr`` (the raw ``next_addr + displacement`` linear
    destination). ``premise`` is the retained source-bound identity a
    consumer re-binds by identity, never a copied coordinate claim.
    ``callee_addr`` records the premise's bound (possibly normalized)
    callee coordinate separately from the raw decoded destination.
    """

    cs_preservation_required: ClassVar[bool] = True

    premise: NearCallFramePremise8616 = field(compare=False, repr=False)
    selector_low: int = 0
    selector_high: int = 0
    callsite_addr: int = 0
    next_addr: int = 0
    target_addr: int = 0
    callee_addr: int = 0

    def admits_linear_destination(self, destination: int) -> bool:
        """Return whether ``destination`` lies inside every retained CS window.

        Pure interval arithmetic: the destination must satisfy
        ``(selector_high << 4) <= destination <= (selector_low << 4) +
        0xFFFF`` so that ``destination - (s << 4)`` is a valid 16-bit IP
        offset for every admitted selector ``s``. This says nothing about
        whether CS is actually preserved at the later point; a consumer
        must prove that separately before using this answer.
        """
        return bool(
            type(destination) is int
            and (self.selector_high << _SELECTOR_SHIFT_8616) <= destination
            and destination
            <= (self.selector_low << _SELECTOR_SHIFT_8616) + _WORD_SPAN_8616 - 1
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize this projection's proven bounds for diagnostics."""
        return {
            "selector_low": self.selector_low,
            "selector_high": self.selector_high,
            "callsite_addr": self.callsite_addr,
            "next_addr": self.next_addr,
            "target_addr": self.target_addr,
            "callee_addr": self.callee_addr,
            "cs_preservation_required": self.cs_preservation_required,
        }


@dataclass(frozen=True, slots=True)
class NearCallSelectorWindowRefusal8616:
    """Honest non-result for a premise that cannot yield a window."""

    failure: NearCallSelectorWindowFailure8616
    callsite_addr: int | None = None
    target_addr: int | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize this refusal for diagnostics."""
        return {
            "failure": self.failure.value,
            "callsite_addr": self.callsite_addr,
            "target_addr": self.target_addr,
        }


def _refusal_8616(
    failure: NearCallSelectorWindowFailure8616,
    premise: NearCallFramePremise8616 | None = None,
) -> NearCallSelectorWindowRefusal8616:
    """Retain one typed refusal with best-effort diagnostic coordinates."""
    return NearCallSelectorWindowRefusal8616(
        failure=failure,
        callsite_addr=None if premise is None else premise.callsite_addr,
        target_addr=None if premise is None else premise.callee_addr,
    )


def project_near_call_selector_window_8616(
    premise: object,
) -> NearCallSelectorWindow8616 | NearCallSelectorWindowRefusal8616:
    """Derive the conditional CS selector interval for one bound near CALL.

    The canonical premise owner re-proves ``premise`` against its own
    retained row and index; a foreign, rebuilt, stale, open-census, or
    word-width-changed row refuses before any bound is computed, and a
    forged dataclass coordinate disagrees with the re-derived premise and
    refuses separately. Only the exact unprefixed ``E8`` word form is
    admitted; far, ``66 E8``, prefixed, or malformed extents refuse
    honestly. The admitted selectors are exactly those whose CS window
    contains every instruction byte below 1 MiB; the raw decoded
    destination must then be identical under every admitted selector,
    otherwise the whole projection refuses.
    """
    if (
        type(premise) is not NearCallFramePremise8616
        or premise.kind
        is not EntryTopSlotKind8616.NEAR_CALL_CONTINUATION
    ):
        return _refusal_8616(NearCallSelectorWindowFailure8616.PREMISE_ABSENT)
    bound = premise
    callsite = bound.callsite
    reproven = prove_near_call_frame_premise_8616(
        callsite, bound.callsite_index, bound.callee_addr
    )
    if reproven is None:
        return _refusal_8616(
            NearCallSelectorWindowFailure8616.PREMISE_REPROOF_FAILED, bound
        )
    forged_coordinates = (
        reproven.callsite is not callsite
        or reproven.callsite_index is not bound.callsite_index
        or (
            reproven.callsite_addr,
            reproven.caller_start,
            reproven.callee_addr,
            reproven.return_addr,
        )
        != (
            bound.callsite_addr,
            bound.caller_start,
            bound.callee_addr,
            bound.return_addr,
        )
    )
    if forged_coordinates:
        return _refusal_8616(
            NearCallSelectorWindowFailure8616.PREMISE_COORDINATE_FORGERY,
            bound,
        )
    coordinates = callsite.encoded_near_coordinates()
    if coordinates is None:
        return _refusal_8616(
            NearCallSelectorWindowFailure8616.UNSUPPORTED_NEAR_FORM, bound
        )
    next_addr, target_addr = coordinates
    callsite_addr = bound.callsite_addr
    if (
        type(callsite_addr) is not int
        or callsite_addr < 0
        or next_addr <= callsite_addr
    ):
        return _refusal_8616(
            NearCallSelectorWindowFailure8616.FETCH_EXTENT_INVALID, bound
        )
    if next_addr > _PHYSICAL_LIMIT_8616:
        return _refusal_8616(
            NearCallSelectorWindowFailure8616.FETCH_A20_AMBIGUOUS, bound
        )
    if type(target_addr) is not int or not 0 <= target_addr < _PHYSICAL_LIMIT_8616:
        return _refusal_8616(
            NearCallSelectorWindowFailure8616.TARGET_A20_AMBIGUOUS, bound
        )
    # A selector s legally fetches all bytes iff
    # (s << 4) <= callsite_addr and next_addr <= (s << 4) + 0x10000, with
    # the A20 limit already excluded above. The decoded destination is
    # (s << 4) + ((target_addr - (s << 4)) & 0xFFFF); it equals the bound
    # target_addr exactly while 0 <= target_addr - (s << 4) <= 0xFFFF.
    selector_low = (max(0, next_addr - _WORD_SPAN_8616) + 0xF) >> _SELECTOR_SHIFT_8616
    selector_high = (
        min(callsite_addr, _SELECTOR_BASE_MAX_8616) >> _SELECTOR_SHIFT_8616
    )
    if selector_low > selector_high:
        return _refusal_8616(
            NearCallSelectorWindowFailure8616.SELECTOR_WINDOW_EMPTY, bound
        )
    if not (
        (selector_high << _SELECTOR_SHIFT_8616) <= target_addr
        <= (selector_low << _SELECTOR_SHIFT_8616) + _WORD_SPAN_8616 - 1
    ):
        return _refusal_8616(
            NearCallSelectorWindowFailure8616.TARGET_NOT_WINDOW_INVARIANT,
            bound,
        )
    return NearCallSelectorWindow8616(
        premise=bound,
        selector_low=selector_low,
        selector_high=selector_high,
        callsite_addr=callsite_addr,
        next_addr=next_addr,
        target_addr=target_addr,
        callee_addr=bound.callee_addr,
    )
