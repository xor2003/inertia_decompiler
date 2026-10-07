"""Typed outcomes for deterministic return storage-trial collection.

Layer: Types/Lowering.
Responsibility: retain exact return/live-out collection refusals and merged
callsite trials before SCC-wide function-contract resolution.
Consumes Semantics-owned terminal storage, caller-use metadata, function SSA,
Alias identities, and typed conditions. This module owns contracts only and
does not inspect IR, mutate codegen, or publish function interfaces.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.ir.function_ssa_registry import FunctionSSAArtifactFailure8616

from .interprocedural_storage_collection_contracts import (
    StorageTrialCollectionVerdict8616,
)
from .interprocedural_storage_contracts import (
    FunctionStorageTrials8616,
    StorageTrialStats8616,
)
from .interprocedural_storage_live_out_contracts import MemoryLiveOutFailure8616
from .interprocedural_storage_return_defs import (
    CallOutputDefinitionFailure8616,
)
from .interprocedural_storage_return_passthrough_contracts import (
    ReturnPassThroughTrialFailure8616,
)
from .interprocedural_storage_return_type_contracts import (
    ReturnStorageTypeFailure8616,
)

__all__ = [
    "FunctionReturnStorageTrialCollection8616",
    "ReturnStorageTrialCollectionFailure8616",
    "ReturnStorageTrialCollectionFailureKind8616",
]


class ReturnStorageTrialCollectionFailureKind8616(StrEnum):
    """Stable reasons why return/live-out trials remain incomplete."""

    INPUT_COLLECTION_INCOMPLETE = "input_collection_incomplete"
    FUNCTION_IDENTITY_CONFLICT = "function_identity_conflict"
    INCOMPLETE_RETURN_CENSUS = "incomplete_return_census"
    RETURN_TARGET_CONFLICT = "return_target_conflict"
    CALLSITE_SET_CONFLICT = "callsite_set_conflict"
    CALLER_IDENTITY_CONFLICT = "caller_identity_conflict"
    TERMINAL_STORAGE_UNKNOWN = "terminal_storage_unknown"
    CALLER_SSA_UNAVAILABLE = "caller_ssa_unavailable"
    CALL_OUTPUT_DEFINITION_REFUSED = "call_output_definition_refused"
    CALL_OUTPUT_DEFINITION_CONFLICT = "call_output_definition_conflict"
    RETURN_TYPE_REFUSED = "return_type_refused"
    RETURN_TYPE_CONFLICT = "return_type_conflict"
    RETURN_USE_UNSUPPORTED = "return_use_unsupported"
    WITNESS_NOT_FOUND = "witness_not_found"
    WITNESS_CONFLICT = "witness_conflict"
    RETURN_PASSTHROUGH_REFUSED = "return_passthrough_refused"
    MEMORY_LIVE_OUT_REFUSED = "memory_live_out_refused"
    MEMORY_LIVE_OUT_CONFLICT = "memory_live_out_conflict"


@dataclass(frozen=True, slots=True)
class ReturnStorageTrialCollectionFailure8616:
    """One exact return callsite refusal with retained upstream evidence."""

    kind: ReturnStorageTrialCollectionFailureKind8616
    callee_addr: int
    caller_addr: int | None = None
    callsite_addr: int | None = None
    ssa_failure: FunctionSSAArtifactFailure8616 | None = None
    definition_failure: CallOutputDefinitionFailure8616 | None = None
    type_failure: ReturnStorageTypeFailure8616 | None = None
    passthrough_failure: ReturnPassThroughTrialFailure8616 | None = None
    live_out_failure: MemoryLiveOutFailure8616 | None = None


@dataclass(frozen=True, slots=True)
class FunctionReturnStorageTrialCollection8616:
    """Merged input and return trials or typed refusals for one callee."""

    verdict: StorageTrialCollectionVerdict8616
    trials: FunctionStorageTrials8616
    failures: tuple[ReturnStorageTrialCollectionFailure8616, ...]
    stats: StorageTrialStats8616

    @property
    def complete(self) -> bool:
        """Return whether every retained callsite has a closed return outcome."""
        return (
            self.verdict is StorageTrialCollectionVerdict8616.PROVEN
            and not self.failures
            and self.trials.caller_census_complete
            and self.stats.complete
        )
