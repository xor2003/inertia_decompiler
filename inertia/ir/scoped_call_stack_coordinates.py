"""Scoped sibling carrier for per-call SP coordinates under dual entry scopes.

Layer: IR.
Responsibility: retain the universal physical coordinate record and the
Semantics scoped call effect as one source-bound carrier. Projection of the
caller-visible SP displacement requires BOTH the offered caller scope and the
offered callee scope to re-authenticate against retained provenance, plus the
physical source CALL identity and return-frame width — then derives
``signed16(body_delta - return_frame_bytes)``. This carrier never publishes a
context-free scalar: ``net_sp_delta``/``current_net_stack_delta``/
``has_proven_sp_delta`` consumers keep their universal meaning, and a
missing, foreign or stale scope yields ``None``, never a numeric fallback.
Owns typed Value/Address/Condition and coordinate records. Do not perform
alias-state ownership, semantics decoding, lowering, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from inertia.semantics.scoped_callee_stack_effects import (
    ScopedCalleeStackCallResult8616,
)

from .call_stack_coordinates import IRCallStackCoordinates8616

__all__ = [
    "IRScopedCallStackCoordinates8616",
    "ScopedCallStackCoordinateFailure8616",
    "prove_scoped_ir_call_stack_coordinates_8616",
]

_WORD_BITS_8616 = 0x10000
_WORD_SIGN_8616 = 0x8000


class ScopedCallStackCoordinateFailure8616(StrEnum):
    """Typed reason a scoped coordinate carrier cannot publish."""

    COORDINATES_MISSING = "coordinates_missing"
    EFFECT_REFUSED = "effect_refused"
    COORDINATE_CONFLICT = "coordinate_conflict"
    SOURCE_UNPROVEN = "source_unproven"
    FRAME_UNPROVEN = "frame_unproven"


def _signed_word_delta_8616(value: int) -> int:
    """Express one modular word displacement in signed affine coordinates."""
    return ((value + _WORD_SIGN_8616) % _WORD_BITS_8616) - _WORD_SIGN_8616


@dataclass(frozen=True, slots=True)
class IRScopedCallStackCoordinates8616:
    """Physical coordinates plus the dual-scope call-effect binding.

    ``coordinates`` is the same universal record every consumer already
    reads; it keeps ``net_sp_delta=None`` whenever only the scoped effect
    proved the delta, so no universal field silently turns conditional.
    ``effect`` retains live project/domain objects — it is provenance, and
    is excluded from equality and the repr. The five counters close the
    evidence ledger exactly like the universal record.
    """

    coordinates: IRCallStackCoordinates8616 | None = None
    effect: ScopedCalleeStackCallResult8616 | None = field(
        default=None, compare=False, repr=False,
    )
    failure: ScopedCallStackCoordinateFailure8616 | None = None
    detail: str = ""
    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 1

    def _retained_carrier_is_accepted(self) -> bool:
        """Require an accepted publication, independent of source currency."""
        counts = (
            self.raw_fact_count, self.normalized_fact_count,
            self.classified_fact_count, self.materialized_count,
            self.failure_count,
        )
        return bool(
            self.failure is None and counts == (1, 1, 1, 1, 0)
            and all(type(count) is int for count in counts)
        )

    @property
    def complete(self) -> bool:
        """Scoped evidence is never context-free; see ``net_sp_delta_for``."""
        return self.net_sp_delta_for(None, None) is not None

    def complete_for(
        self,
        offered_caller_scope: object,
        offered_callee_scope: object,
    ) -> bool:
        """Re-authenticate both scopes and the physical coordinate contract.

        The offered scopes must satisfy the retained effect's dual-context
        check; the physical record must still carry a bound source, return
        frame and matching coordinates, and the effect's projection must be
        current on the same source surface.
        """
        if not self._retained_carrier_is_accepted():
            return False
        if self.coordinates is None or self.effect is None:
            return False
        if _conflict_8616(self.coordinates, self.effect) is not None:
            return False
        return self.effect.complete_for(offered_caller_scope, offered_callee_scope)

    def net_sp_delta_for(
        self,
        offered_caller_scope: object,
        offered_callee_scope: object,
    ) -> int | None:
        """Return signed16(body delta - return frame) under both scopes."""
        if not self.complete_for(offered_caller_scope, offered_callee_scope):
            return None
        assert self.effect is not None and self.coordinates is not None
        delta = self.effect.return_sp_delta_for(
            offered_caller_scope, offered_callee_scope,
        )
        frame = self.coordinates.return_frame_bytes
        if delta is None or frame is None:
            return None
        return _signed_word_delta_8616(delta - frame)

    def has_proven_sp_delta_for(
        self,
        offered_caller_scope: object,
        offered_callee_scope: object,
    ) -> bool:
        """Report whether the scoped net displacement currently projects."""
        return self.net_sp_delta_for(offered_caller_scope, offered_callee_scope) is not None

    @property
    def observed_return_sp_delta(self) -> int | None:
        """Expose the retained body diagnostic without granting authority."""
        if not self._retained_carrier_is_accepted() or self.effect is None:
            return None
        return self.effect.observed_return_sp_delta

    def to_dict(self) -> dict[str, object]:
        """Serialize carrier shape for diagnostics; never authorization."""
        return {
            "kind": "scoped_call_stack_coordinates",
            "failure": None if self.failure is None else self.failure.value,
            "detail": self.detail,
            "observed_return_sp_delta": self.observed_return_sp_delta,
            "coordinates": (
                None if self.coordinates is None else self.coordinates.to_dict()
            ),
            "counts": [
                self.raw_fact_count, self.normalized_fact_count,
                self.classified_fact_count, self.materialized_count,
                self.failure_count,
            ],
        }


def _conflict_8616(
    coordinates: IRCallStackCoordinates8616,
    effect: ScopedCalleeStackCallResult8616,
) -> ScopedCallStackCoordinateFailure8616 | None:
    """Reproduce the physical source and bind both retained records to its CALL.

    A stored source reference and matching scalar fields do not establish
    freshness: the universal record must close its own evidence census and
    replay its source before the scoped result can derive a displacement.
    """
    if coordinates.source is None:
        return ScopedCallStackCoordinateFailure8616.SOURCE_UNPROVEN
    if coordinates.return_frame_bytes is None:
        return ScopedCallStackCoordinateFailure8616.FRAME_UNPROVEN
    conflict = (
        coordinates.callsite_addr != effect.callsite_addr
        or coordinates.return_addr != effect.return_addr
        or coordinates.target_addr != effect.target_addr
        or coordinates.source.project is not effect.project
        or effect.frame_kind is None
        or coordinates.return_frame_bytes != effect.frame_kind.return_frame_width
    )
    if conflict:
        return ScopedCallStackCoordinateFailure8616.COORDINATE_CONFLICT
    if not coordinates.closed:
        return ScopedCallStackCoordinateFailure8616.SOURCE_UNPROVEN
    return None


def prove_scoped_ir_call_stack_coordinates_8616(
    coordinates: IRCallStackCoordinates8616 | None,
    effect: ScopedCalleeStackCallResult8616 | None,
) -> IRScopedCallStackCoordinates8616:
    """Bind a physical coordinate record to one dual-scope call effect.

    The coordinate record must retain its physical source and return-frame
    proof even when ``net_sp_delta`` stayed unproven; the effect must be an
    accepted scoped adapter result. Any coordinate/effect disagreement —
    callsite, return, target, frame width or project identity — refuses as
    ``COORDINATE_CONFLICT`` rather than merging two different calls.
    """
    if type(coordinates) is not IRCallStackCoordinates8616:
        return IRScopedCallStackCoordinates8616(
            coordinates if type(coordinates) is IRCallStackCoordinates8616 else None,
            None, ScopedCallStackCoordinateFailure8616.COORDINATES_MISSING, "",
            1, 1, 0, 0, 1,
        )
    if type(effect) is not ScopedCalleeStackCallResult8616 or effect.failure is not None:
        detail = "" if effect is None else (
            "" if effect.failure is None else effect.failure.value
        )
        return IRScopedCallStackCoordinates8616(
            coordinates, None,
            ScopedCallStackCoordinateFailure8616.EFFECT_REFUSED, detail,
            1, 1, 0, 0, 1,
        )
    failure = _conflict_8616(coordinates, effect)
    if failure is not None:
        return IRScopedCallStackCoordinates8616(
            coordinates, effect, failure, "",
            1, 1, 0, 0, 1,
        )
    return IRScopedCallStackCoordinates8616(
        coordinates, effect, None, "",
        1, 1, 1, 1, 0,
    )
