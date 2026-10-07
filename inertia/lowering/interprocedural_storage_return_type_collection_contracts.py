"""Contracts for complete caller-observed return-type collection.

Layer: Types/Lowering.
Responsibility: retain one function-wide join of exact caller return uses and
stable reasons why a return type cannot be published.
Consumes alias, widening, and typed facts. This module does not inspect IR,
mutate prototypes, or recover semantics from text.

Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .interprocedural_storage_contracts import (
    StorageTrialSignedness8616,
    StorageTrialStats8616,
    StorageTrialValueClass8616,
)
from .interprocedural_storage_return_type_contracts import ReturnStorageTypeResult8616

__all__ = [
    "FunctionReturnStorageTypeFailure8616",
    "FunctionReturnStorageTypeResult8616",
    "FunctionReturnStorageTypeVerdict8616",
]


class FunctionReturnStorageTypeVerdict8616(StrEnum):
    """Outcome of joining every exact caller observation for one return."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"
    CONFLICT = "conflict"


class FunctionReturnStorageTypeFailure8616(StrEnum):
    """Stable reason a complete caller census cannot publish a return type."""

    EVIDENCE_UNAVAILABLE = "evidence_unavailable"
    CENSUS_INCOMPLETE = "census_incomplete"
    CALLER_CONTEXT_UNAVAILABLE = "caller_context_unavailable"
    CALLSITE_CLASSIFICATION_REFUSED = "callsite_classification_refused"
    SIGNEDNESS_CONFLICT = "signedness_conflict"
    SIGNEDNESS_UNINFORMATIVE = "signedness_uninformative"
    VALUE_CLASS_CONFLICT = "value_class_conflict"


@dataclass(frozen=True, slots=True)
class FunctionReturnStorageTypeResult8616:
    """Function-wide return type proof and its exact per-call classifications."""

    function_addr: int
    verdict: FunctionReturnStorageTypeVerdict8616
    signedness: StorageTrialSignedness8616 | None
    value_class: StorageTrialValueClass8616 | None
    classifications: tuple[ReturnStorageTypeResult8616, ...]
    neutral_fact_count: int
    failure: FunctionReturnStorageTypeFailure8616 | None
    stats: StorageTrialStats8616

    @property
    def complete(self) -> bool:
        """Return whether every caller fact supports one informative type."""
        return (
            self.verdict is FunctionReturnStorageTypeVerdict8616.PROVEN
            and self.signedness
            in {StorageTrialSignedness8616.SIGNED, StorageTrialSignedness8616.UNSIGNED}
            and self.value_class is StorageTrialValueClass8616.VALUE
            and self.failure is None
            and self.stats.complete
            and len(self.classifications) + self.neutral_fact_count == self.stats.raw_fact_count
        )
