"""Typed per-call machine-SP coordinate decomposition.

Layer: IR.
Responsibility: own the immutable per-call stack coordinate contract carrying
independently evidenced callee-purged bytes, separately decoded caller
post-call cleanup, machine return-frame width, the net caller-visible SP delta
across the call boundary, and the argument-stack top anchor.
``IRCallStackEffect8616`` remains the owner of ``net_stack_delta``; a proven
coordinate derives and validates that projection instead of competing with it.
``None`` is absent evidence, never a proven zero, and every unproven field
keeps a typed refusal naming the missing proof. The closed evidence census
reconciles all seven coordinate slots; ``complete`` requires every slot proven.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from .core import MemSpace

if TYPE_CHECKING:
    from inertia.semantics.call_stack_coordinate_source import CallStackCoordinateSource8616
    from inertia.semantics.callee_stack_effects import CalleeStackCallResult8616

__all__ = [
    "CALL_STACK_COORDINATE_SLOTS_8616",
    "CallArgumentAnchorKind8616",
    "CallStackCoordinateRefusal8616",
    "IRCallArgumentTop8616",
    "IRCallStackCoordinateObservation8616",
    "IRCallStackCoordinates8616",
]

#: Coordinate slots each proof evaluates: return frame width, callee purge,
#: caller cleanup, linked-return extra, net boundary delta, argument top, body SP transfer.
CALL_STACK_COORDINATE_SLOTS_8616: int = 7


@dataclass(frozen=True, slots=True)
class IRCallStackCoordinateObservation8616:
    """One immediate source observation shared by coordinate projections.

    This value is not retained proof authority. New consumers must observe
    again so changed caller, callee, coverage or producer evidence invalidates.
    """

    coordinates: IRCallStackCoordinates8616 = field(compare=False, repr=False)
    callee_return_sp_delta: int | None
    proven_net_sp_delta: int | None
    sp_delta_proven: bool
    closed: bool
    complete: bool

    def to_dict(self) -> dict[str, object]:
        """Serialize the immediate immutable coordinate view without rechecking."""
        return self.coordinates._observation_payload(
            self.callee_return_sp_delta, self.sp_delta_proven,
        )


class CallArgumentAnchorKind8616(StrEnum):
    """Machine SP coordinate the argument-region top is anchored to."""

    CALLER_SP_BEFORE_CALL = "caller_sp_before_call"
    CALLEE_ENTRY_SP = "callee_entry_sp"


class CallStackCoordinateRefusal8616(StrEnum):
    """Typed reason one coordinate slot has no evidence."""

    CALL_IDENTITY_UNPROVEN = "call_identity_unproven"
    CALL_OPERAND_WIDTH_UNPROVEN = "call_operand_width_unproven"
    CALL_HEAD_DECODE_REFUSED = "call_head_decode_refused"
    CALL_HEAD_NOT_FOUND = "call_head_not_found"
    CALL_TARGET_CONFLICT = "call_target_conflict"
    RETURN_ADDRESS_MISMATCH = "return_address_mismatch"
    CALL_FRAME_KIND_UNKNOWN = "call_frame_kind_unknown"
    CALL_TARGET_UNRESOLVED = "call_target_unresolved"
    CALLEE_TERMINAL_EVIDENCE_UNAVAILABLE = "callee_terminal_evidence_unavailable"
    CALLEE_TERMINAL_EVIDENCE_INCOMPLETE = "callee_terminal_evidence_incomplete"
    CALLEE_STACK_EFFECT_UNPROVEN = "callee_stack_effect_unproven"
    CALLEE_RETURN_OPERAND_WIDTH_UNPROVEN = "callee_return_operand_width_unproven"
    RETURN_FRAME_KIND_UNSUPPORTED = "return_frame_kind_unsupported"
    RETURN_FRAME_KIND_CONFLICT = "return_frame_kind_conflict"
    CALLER_CLEANUP_UNPROVEN = "caller_cleanup_unproven"
    CALLER_CLEANUP_EVIDENCE_CONFLICT = "caller_cleanup_evidence_conflict"
    ARGUMENT_COUNT_UNKNOWN = "argument_count_unknown"
    ARGUMENT_ZERO_ARITY_UNPROVEN = "argument_zero_arity_unproven"
    ARGUMENT_SETUP_INCOMPLETE = "argument_setup_incomplete"
    ARGUMENT_REGION_AMBIGUOUS = "argument_region_ambiguous"
    ARGUMENT_OPERAND_WIDTH_UNPROVEN = "argument_operand_width_unproven"
    ARGUMENT_WINDOW_DECODE_REFUSED = "argument_window_decode_refused"


@dataclass(frozen=True, slots=True)
class IRCallArgumentTop8616:
    """Proven top of the contiguous argument region for one exact CALL.

    ``anchor`` names the machine SP the coordinate is relative to. The actual
    argument top — the lowest proven argument byte — sits
    ``top_offset_bytes`` above that anchor; the region extends
    ``extent_bytes`` upward from there. Unproven pushes outside the region
    are not claimed as arguments.
    """

    space: MemSpace
    anchor: CallArgumentAnchorKind8616
    top_offset_bytes: int
    extent_bytes: int
    push_instruction_addrs: tuple[int, ...]

    @property
    def valid(self) -> bool:
        """Require a word-sized, segmented region with ordered source heads."""
        addresses = self.push_instruction_addrs
        return bool(
            self.space is MemSpace.SS
            and isinstance(self.anchor, CallArgumentAnchorKind8616)
            and type(self.top_offset_bytes) is int
            and 0 <= self.top_offset_bytes <= 0xFFFF
            and type(self.extent_bytes) is int
            and 0 <= self.extent_bytes <= 0xFFFF
            and self.extent_bytes % 2 == 0
            and all(type(address) is int and address >= 0 for address in addresses)
            and tuple(sorted(set(addresses))) == addresses
            and 2 * len(addresses) <= self.extent_bytes <= 4 * len(addresses)
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize this argument-top coordinate for diagnostics."""
        return {
            "kind": "call_argument_top",
            "space": self.space.value,
            "anchor": self.anchor.value,
            "top_offset_bytes": self.top_offset_bytes,
            "extent_bytes": self.extent_bytes,
            "push_instruction_addrs": list(self.push_instruction_addrs),
        }


@dataclass(frozen=True, slots=True)
class IRCallStackCoordinates8616:
    """Independently evidenced SP decomposition for one exact CALL boundary.

    ``callee_purged_bytes`` is the callee terminal RET imm16 census result;
    ``caller_cleanup_bytes`` is a separately decoded caller post-call reclaim
    instruction bound to the return edge (never counted in ``net_sp_delta``);
    ``return_frame_bytes`` is the width the CALL itself pushes;
    ``additional_return_bytes`` is the proven linked return-segment extra;
    ``net_sp_delta`` is the signed 16-bit caller-visible SP change across the
    boundary excluding separately decoded caller cleanup instructions.
    Identity fields bind the contract to the pre-insertion machine call and
    its admitted target, never to a rendered output position. The census
    counters close over the seven coordinate slots; ``complete`` requires all
    of them proven.
    """

    callsite_addr: int
    target_addr: int | None = None
    return_addr: int | None = None
    return_frame_bytes: int | None = None
    callee_purged_bytes: int | None = None
    caller_cleanup_bytes: int | None = None
    caller_cleanup_instruction_addr: int | None = None
    additional_return_bytes: int | None = None
    net_sp_delta: int | None = None
    argument_top: IRCallArgumentTop8616 | None = None
    callee_sp_proof: CalleeStackCallResult8616 | None = None
    source: CallStackCoordinateSource8616 | None = field(default=None, compare=False, repr=False)
    refusals: tuple[CallStackCoordinateRefusal8616, ...] = field(default=(), compare=True)
    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    def _slot_values(self) -> tuple[object, ...]:
        """Return the coordinate slots in census order, including body transfer."""
        return (
            self.return_frame_bytes,
            self.callee_purged_bytes,
            self.caller_cleanup_bytes,
            self.additional_return_bytes,
            self.net_sp_delta,
            self.argument_top,
            (None if self.callee_sp_proof is None
             else self.callee_sp_proof.observed_return_sp_delta),
        )

    def _layout_valid(self) -> bool:
        """Reject contradictory types, machine widths and segmented layout."""
        addresses = (self.callsite_addr, self.target_addr, self.return_addr,
                     self.caller_cleanup_instruction_addr)
        if any(value is not None and (type(value) is not int or value < 0) for value in addresses):
            return False
        if self.return_frame_bytes is not None and (
            type(self.return_frame_bytes) is not int or self.return_frame_bytes not in {2, 4}
        ):
            return False
        counts = (self.callee_purged_bytes, self.caller_cleanup_bytes)
        if any(value is not None and (type(value) is not int or not 0 <= value <= 0xFFFF) for value in counts):
            return False
        if self.additional_return_bytes is not None and (
            type(self.additional_return_bytes) is not int or self.additional_return_bytes not in {0, 2}
        ):
            return False
        if self.net_sp_delta is not None and (
            type(self.net_sp_delta) is not int or not -0x8000 <= self.net_sp_delta < 0x8000
        ):
            return False
        if (self.caller_cleanup_bytes is None) != (self.caller_cleanup_instruction_addr is None):
            return False
        return self.argument_top is None or self.argument_top.valid

    @property
    def callee_return_sp_delta(self) -> int | None:
        """Return the proven callee-entry-to-after-RET displacement."""
        return self.callee_sp_proof.return_sp_delta if self.callee_sp_proof is not None else None

    @property
    def has_proven_sp_delta(self) -> bool:
        """Authorize only the source-bound, consistent partial SP projection."""
        return self.observe().sp_delta_proven

    @property
    def closed(self) -> bool:
        """Return whether every evaluated slot has a durable typed outcome."""
        counts = (self.raw_fact_count, self.normalized_fact_count,
                  self.classified_fact_count, self.materialized_count, self.failure_count)
        if not self._layout_valid() or any(type(count) is not int or count < 0 for count in counts):
            return False
        known = sum(slot is not None for slot in self._slot_values())
        return bool(
            self.raw_fact_count == self.normalized_fact_count == CALL_STACK_COORDINATE_SLOTS_8616
            and self.classified_fact_count == self.materialized_count == known
            and self.failure_count == self.raw_fact_count - known
            and self.source is not None
            and self.source.matches(self)
        )

    @property
    def complete(self) -> bool:
        """Return whether all seven coordinate slots carry proven evidence."""
        return self.observe().complete

    def observe(self) -> IRCallStackCoordinateObservation8616:
        """Share one fresh source/body check across this observation's fields.

        Retained values establish only the census. Closure still reproduces
        their source, and the independent call/body proof remains mandatory.
        Do not retain this observation across mutations or later admissions.
        """
        closed = self.closed
        proof = self.callee_sp_proof
        # Source.matches reproduces every scalar field using return_sp_delta's
        # current call/body proof. A matching non-None net displacement therefore
        # already checked that same body during this immediate observation.
        # Partial decompositions still need an independent body observation.
        source_body_checked = closed and self.net_sp_delta is not None
        valid_body = proof is not None and (source_body_checked or proof.complete)
        delta = None if not valid_body or proof is None else proof.observed_return_sp_delta
        proven = False
        if (
            closed and proof is not None and proof.frame_kind is not None
            and delta is not None and self.return_frame_bytes is not None
        ):
            expected = ((delta - self.return_frame_bytes + 0x8000) & 0xFFFF) - 0x8000
            proven = bool(
                proof.callsite_addr == self.callsite_addr
                and proof.return_addr == self.return_addr
                and proof.target_addr == self.target_addr
                and proof.frame_kind.return_frame_width == self.return_frame_bytes
                and self.net_sp_delta == expected
            )
        complete = bool(
            proven and self.raw_fact_count == CALL_STACK_COORDINATE_SLOTS_8616
            and self.materialized_count == self.raw_fact_count
            and not self.refusals
            and all(slot is not None for slot in self._slot_values())
        )
        return IRCallStackCoordinateObservation8616(
            self, delta, self.net_sp_delta if proven else None, proven, closed, complete,
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize this coordinate decomposition for diagnostics."""
        return self.observe().to_dict()

    def _observation_payload(self, delta: int | None, proven: bool) -> dict[str, object]:
        """Project already-observed flags without starting a new proof walk."""
        return {
            "kind": "call_stack_coordinates",
            "callsite_addr": self.callsite_addr,
            "target_addr": self.target_addr,
            "return_addr": self.return_addr,
            "return_frame_bytes": self.return_frame_bytes,
            "callee_purged_bytes": self.callee_purged_bytes,
            "caller_cleanup_bytes": self.caller_cleanup_bytes,
            "caller_cleanup_instruction_addr": self.caller_cleanup_instruction_addr,
            "additional_return_bytes": self.additional_return_bytes,
            "net_sp_delta": self.net_sp_delta,
            "callee_return_sp_delta": delta,
            "sp_delta_proven": proven,
            "source_present": self.source is not None,
            "callee_proof_present": self.callee_sp_proof is not None,
            "argument_top": (
                None if self.argument_top is None else self.argument_top.to_dict()
            ),
            "refusals": [refusal.value for refusal in self.refusals],
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
        }
