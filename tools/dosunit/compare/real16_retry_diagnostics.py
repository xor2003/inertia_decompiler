"""Additive retry-stage admission diagnostics for the real16 retry chain.

Layer: dosunit binary proof orchestration.
Responsibility: record the shared-deadline admission decision at each
deadline-gated retry stage (closed call-loop induction, paired-region
induction, macro-step induction) as typed backend metadata so the
wall-clock retry boundary is directly observable in retained evidence.
Diagnostics are additive only: they never alter scheduling, admission
gates, deadline arithmetic, timeout arguments, or verdict rows. Every
``remaining_ms`` is the stage owner's own already-computed shared-deadline
remainder; this module performs no clock reads.
"""

from __future__ import annotations

from collections.abc import MutableMapping
from dataclasses import asdict, dataclass
from typing import Any, Final

RETRY_BUDGET_KEY: Final[str] = "retry_budget"


@dataclass(frozen=True, slots=True)
class RetryStageDecision:
    """Observed admission decision at one deadline-gated retry stage.

    ``required`` is the conjunction of the stage's non-budget gates (call
    presence, prior UNKNOWN status, resolved candidate) exactly as the stage
    owner computed them. ``budget_open`` is the shared-deadline gate alone.
    ``attempted`` is their conjunction and is true exactly when the stage
    body ran. ``required=False`` records a non-budget skip — a closed
    status or unresolved-candidate gate — and is never a budget
    exhaustion; ``required=True and not budget_open`` records a genuine
    deadline-exhausted skip. ``remaining_ms`` is the owner's observed
    remainder and may be non-positive.
    """

    attempted: bool
    required: bool
    budget_open: bool
    remaining_ms: int

    @classmethod
    def decide(cls, *, required: bool, remaining_ms: int) -> RetryStageDecision:
        """Fold the owner's gate inputs into one immutable admission record."""
        budget_open = remaining_ms > 0
        return cls(
            attempted=required and budget_open,
            required=required,
            budget_open=budget_open,
            remaining_ms=remaining_ms,
        )

    def to_document(self) -> dict[str, Any]:
        """Serialize as additive JSON-compatible backend metadata."""
        return asdict(self)


def record_stage_decision(
    backend: MutableMapping[str, Any], stage: str, decision: RetryStageDecision,
) -> None:
    """Merge one stage decision under ``backend["retry_budget"][stage]``.

    The nested map is always replaced with a fresh dict so callers merging a
    prior stage's backend dict never mutate the earlier evidence object.
    """
    budget = dict(backend.get(RETRY_BUDGET_KEY) or {})
    budget[stage] = decision.to_document()
    backend[RETRY_BUDGET_KEY] = budget
