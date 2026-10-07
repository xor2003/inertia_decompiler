"""Typed outcomes for production interprocedural storage-trial collection.

Layer: Types/Lowering.
Responsibility: retain exact collection refusals and closed callsite evidence
counters before SCC-wide function-contract resolution.
Consumes alias, widening, and typed facts. This module does not mutate codegen.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.ir.function_ssa_registry import FunctionSSAArtifactFailure8616

from .interprocedural_storage_contracts import (
    FunctionStorageTrials8616,
    StorageTrialStats8616,
)
from .interprocedural_storage_reaching_contracts import (
    CallArgumentDefinitionFailure8616,
)

__all__ = [
    "FunctionInputStorageTrialCollection8616",
    "StorageTrialCollectionFailure8616",
    "StorageTrialCollectionFailureKind8616",
    "StorageTrialCollectionVerdict8616",
]


class StorageTrialCollectionVerdict8616(StrEnum):
    """Typed outcome of collecting one function's input trials."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"
    CONFLICT = "conflict"


class StorageTrialCollectionFailureKind8616(StrEnum):
    """Stable reasons why production input trials remain incomplete."""

    INCOMPLETE_CALLER_CENSUS = "incomplete_caller_census"
    CALLSITE_IDENTITY_CONFLICT = "callsite_identity_conflict"
    CALLER_ADDRESS_UNKNOWN = "caller_address_unknown"
    CALLER_SSA_UNAVAILABLE = "caller_ssa_unavailable"
    ARGUMENT_STORAGE_UNKNOWN = "argument_storage_unknown"
    REACHING_DEFINITION_REFUSED = "reaching_definition_refused"
    REACHING_DEFINITION_CONFLICT = "reaching_definition_conflict"
    STORAGE_PIECE_CONFLICT = "storage_piece_conflict"
    STACK_DELTA_UNKNOWN = "stack_delta_unknown"
    SIGNEDNESS_UNKNOWN = "signedness_unknown"
    SIGNEDNESS_CONFLICT = "signedness_conflict"
    VALUE_CLASS_UNKNOWN = "value_class_unknown"
    VALUE_CLASS_CONFLICT = "value_class_conflict"


@dataclass(frozen=True, slots=True)
class StorageTrialCollectionFailure8616:
    """One exact callsite or argument refusal retained for diagnostics."""

    kind: StorageTrialCollectionFailureKind8616
    callee_addr: int
    caller_addr: int | None
    callsite_addr: int | None
    logical_index: int | None = None
    ssa_failure: FunctionSSAArtifactFailure8616 | None = None
    reaching_failure: CallArgumentDefinitionFailure8616 | None = None


@dataclass(frozen=True, slots=True)
class FunctionInputStorageTrialCollection8616:
    """Complete input trials or typed refusals for one callee census."""

    verdict: StorageTrialCollectionVerdict8616
    trials: FunctionStorageTrials8616
    failures: tuple[StorageTrialCollectionFailure8616, ...]
    stats: StorageTrialStats8616

    @property
    def complete(self) -> bool:
        """Return whether every caller became one proof-bearing callsite."""
        return (
            self.verdict is StorageTrialCollectionVerdict8616.PROVEN
            and not self.failures
            and self.trials.caller_census_complete
            and self.stats.complete
        )
