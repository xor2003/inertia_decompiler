"""Publish typed call-input outcomes for pipeline orchestration.

Layer: Pipeline contracts.
Responsibility: share immutable lowering outcomes and observe their optional
codegen publication. No call semantics, C-AST transforms or proof recovery live
in this module.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Protocol, cast


class _CallInputPublication8616(Protocol):
    """Describe the optional raw extension slot on third-party codegen objects."""

    _inertia_call_stack_input_lowering_8616: object


class CallStackInputFailure8616(StrEnum):
    """Typed reasons a complete source-to-C call context cannot be published."""

    SOURCE_UNAVAILABLE = "source_unavailable"
    CALL_IDENTITY = "call_identity"
    POSITION_UNPROVEN = "position_unproven"
    TYPE_UNPROVEN = "type_unproven"
    RESULT_USE_UNPROVEN = "result_use_unproven"
    ARGUMENT_EFFECT = "argument_effect"
    UNOWNED_SP_USE = "unowned_sp_use"
    ENTRY_CAPTURE = "entry_capture"
    INVALID_BINDING = "invalid_binding"



class CallStackInputStatus8616(StrEnum):
    """Whether actual generated call contexts changed, remained valid or refused."""

    MATERIALIZED = "materialized"
    STABLE = "stable"
    REFUSED = "refused"



@dataclass(frozen=True, slots=True)
class CallStackInputStats8616:
    """Closed source-call census; unsupported functions keep their original tree."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    changed_count: int = 0
    refusal_count: int = 0



@dataclass(frozen=True, slots=True)
class CallStackInputResult8616:
    """Inspectable outcome without embedding mutable native objects."""

    status: CallStackInputStatus8616
    stats: CallStackInputStats8616
    failure: CallStackInputFailure8616 | None = None

    @property
    def changed(self) -> bool:
        """Return whether input contexts or their entry capture changed."""
        return self.stats.changed_count > 0

    def to_dict(self) -> dict[str, object]:
        """Export typed state and all evidence counters."""
        return {"status": self.status.value, "stats": asdict(self.stats),
                "failure": self.failure.value if self.failure is not None else None}



def call_stack_input_lowering_result_8616(codegen: object) -> CallStackInputResult8616 | None:
    """Read Types' optional publication without authorizing any semantic effect.

    Unsupported codegen backends may omit this extension. A malformed value
    remains an error rather than silently becoming an absent observation.
    """
    try:
        result = cast(_CallInputPublication8616, codegen)._inertia_call_stack_input_lowering_8616
    except AttributeError:
        return None
    if result is None or isinstance(result, CallStackInputResult8616):
        return result
    raise TypeError("Call-input lowering publication has an invalid type")
