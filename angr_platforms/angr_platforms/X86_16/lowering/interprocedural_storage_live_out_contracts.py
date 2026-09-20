"""Typed contracts for direct segmented-memory live-out collection.

Layer: Types/Lowering.
Responsibility: retain exact caller-use outcomes, refusals, and closed counters
when Semantics-proven DS/ES outputs cross a call boundary. This module owns no
CFG traversal, Alias inference, C type projection, prototype mutation, or codegen.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..alias.terminal_memory_outputs import (
    TerminalMemoryAliasFact8616,
    TerminalMemoryAliasFailure8616,
)
from ..ir.condition_ir import ConditionIR
from ..ir.function_ssa_registry import FunctionSSAArtifactFailure8616
from ..semantics.terminal_memory_output_contracts import (
    MemoryOutputKey8616,
    TerminalMemoryOutputDisposition8616,
    TerminalMemoryOutputFact8616,
    TerminalMemoryOutputFailure8616,
)
from ..widening.terminal_memory_output_views import (
    TerminalMemoryOutputViewFact8616,
    TerminalMemoryOutputViewFailure8616,
)
from .interprocedural_storage_contracts import (
    StorageIdentity8616,
    StorageTrial8616,
    StorageTrialSignedness8616,
    StorageTrialStats8616,
    StorageUseEvidence8616,
)
from .interprocedural_storage_return_defs import CallOutputDefinitionFailure8616
from .pointer_parameter_caller_target_contracts import (
    PointerParameterCallerTarget8616,
    PointerParameterCallerTargetFailure8616,
)


class MemoryLiveOutCollectionVerdict8616(StrEnum):
    """Outcome of collecting one function's bounded direct-memory live-outs."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"
    CONFLICT = "conflict"


class MemoryLiveOutUseDisposition8616(StrEnum):
    """Reachability outcome for one exact caller storage-use candidate."""

    NOT_REACHED = "not_reached"
    USED = "used"


class MemoryLiveOutFailureKind8616(StrEnum):
    """Stable reasons one bounded memory live-out candidate cannot close."""

    CALLEE_SSA_UNAVAILABLE = "callee_ssa_unavailable"
    TERMINAL_EVIDENCE_REFUSED = "terminal_evidence_refused"
    ALIAS_EVIDENCE_REFUSED = "alias_evidence_refused"
    WIDENING_EVIDENCE_REFUSED = "widening_evidence_refused"
    CALLER_SSA_UNAVAILABLE = "caller_ssa_unavailable"
    CALLER_CONTEXT_CONFLICT = "caller_context_conflict"
    CALL_OUTPUT_DEFINITION_REFUSED = "call_output_definition_refused"
    CALL_OUTPUT_DEFINITION_CONFLICT = "call_output_definition_conflict"
    CFG_INCOMPLETE = "cfg_incomplete"
    CFG_CYCLE = "cfg_cycle"
    INTERVENING_ALIAS = "intervening_alias"
    INTERVENING_CALL = "intervening_call"
    INTERVENING_WRITE = "intervening_write"
    CONDITION_NOT_FOUND = "condition_not_found"
    CONDITION_CONFLICT = "condition_conflict"
    CONDITION_UNSUPPORTED = "condition_unsupported"
    SIGNEDNESS_CONFLICT = "signedness_conflict"
    POINTER_TARGET_REFUSED = "pointer_target_refused"
    POINTER_TARGET_CONFLICT = "pointer_target_conflict"


@dataclass(frozen=True, slots=True)
class MemoryLiveOutUseFact8616:
    """One exact storage candidate and its bounded caller-use outcome."""

    storage: StorageIdentity8616
    output_view: TerminalMemoryOutputViewFact8616
    disposition: MemoryLiveOutUseDisposition8616
    use: StorageUseEvidence8616 | None = None
    signedness: StorageTrialSignedness8616 | None = None
    condition: ConditionIR | None = None

    @property
    def alias_output(self) -> TerminalMemoryAliasFact8616:
        """Return the Alias owner retained inside the Widening view."""
        return self.output_view.alias_output

    @property
    def terminal_output(self) -> TerminalMemoryOutputFact8616:
        """Return the Semantics output retained inside the Alias proof."""
        return self.alias_output.terminal_output

    @property
    def complete(self) -> bool:
        """Return whether this fact retains every field required by its verdict."""
        output_matches = bool(
            self.output_view.complete
            and self.storage.address == self.output_view.address
        )
        if self.disposition is MemoryLiveOutUseDisposition8616.NOT_REACHED:
            return self.storage.is_exact and output_matches and all(
                item is None for item in (self.use, self.signedness, self.condition)
            )
        return bool(
            self.storage.is_exact
            and output_matches
            and self.use is not None
            and self.use.is_complete
            and self.signedness is not None
            and self.condition is not None
        )


@dataclass(frozen=True, slots=True)
class MemoryLiveOutCandidateResult8616:
    """Inactive candidate, closed use fact/trial, or one typed refusal."""

    activated: bool
    fact: MemoryLiveOutUseFact8616 | None = None
    trial: StorageTrial8616 | None = None
    failure: MemoryLiveOutFailureKind8616 | None = None
    definition_failure: CallOutputDefinitionFailure8616 | None = None

    @property
    def complete(self) -> bool:
        """Return whether this activated candidate has one durable outcome."""
        if not self.activated:
            return (self.fact, self.trial, self.failure, self.definition_failure) == (None,) * 4
        if self.failure is not None:
            return self.fact is None and self.trial is None
        if self.fact is None or not self.fact.complete or self.definition_failure is not None:
            return False
        needs_trial = bool(
            self.fact.disposition is MemoryLiveOutUseDisposition8616.USED
            and self.fact.terminal_output.disposition
            is TerminalMemoryOutputDisposition8616.MUST_WRITE
        )
        return self.trial.is_complete if needs_trial and self.trial is not None else (
            self.trial is None and not needs_trial
        )


@dataclass(frozen=True, slots=True)
class CallsiteMemoryLiveOutEvidence8616:
    """Closed direct-memory facts and materialized trials for one callsite."""

    caller_addr: int
    callee_addr: int
    callsite_addr: int
    facts: tuple[MemoryLiveOutUseFact8616, ...] = ()
    trials: tuple[StorageTrial8616, ...] = ()
    pointer_effects: tuple[PointerParameterCallerTarget8616, ...] = ()


@dataclass(frozen=True, slots=True)
class MemoryLiveOutFailure8616:
    """One exact refusal retaining all available upstream typed evidence."""

    kind: MemoryLiveOutFailureKind8616
    callee_addr: int
    caller_addr: int | None = None
    callsite_addr: int | None = None
    storage_key: MemoryOutputKey8616 | None = None
    ssa_failure: FunctionSSAArtifactFailure8616 | None = None
    terminal_failure: TerminalMemoryOutputFailure8616 | None = None
    alias_failure: TerminalMemoryAliasFailure8616 | None = None
    view_failure: TerminalMemoryOutputViewFailure8616 | None = None
    definition_failure: CallOutputDefinitionFailure8616 | None = None
    pointer_failure: PointerParameterCallerTargetFailure8616 | None = None


@dataclass(frozen=True, slots=True)
class FunctionMemoryLiveOutCollection8616:
    """Function-wide direct-memory live-outs or atomic typed refusals."""

    verdict: MemoryLiveOutCollectionVerdict8616
    callsites: tuple[CallsiteMemoryLiveOutEvidence8616, ...]
    failures: tuple[MemoryLiveOutFailure8616, ...]
    stats: StorageTrialStats8616

    @property
    def complete(self) -> bool:
        """Return whether every activated candidate has one retained outcome."""
        return (
            self.verdict is MemoryLiveOutCollectionVerdict8616.PROVEN
            and not self.failures
            and self.stats.complete
            and all(fact.complete for site in self.callsites for fact in site.facts)
            and all(trial.is_complete for site in self.callsites for trial in site.trials)
            and all(
                effect.complete for site in self.callsites for effect in site.pointer_effects
            )
        )


def refused_memory_live_out_collection_8616(
    failure: MemoryLiveOutFailure8616,
    raw: int,
    normalized: int,
) -> FunctionMemoryLiveOutCollection8616:
    """Build one atomic typed refusal without publishing partial live-out trials."""
    conflict = failure.kind in {
        MemoryLiveOutFailureKind8616.CALLER_CONTEXT_CONFLICT,
        MemoryLiveOutFailureKind8616.CALL_OUTPUT_DEFINITION_CONFLICT,
        MemoryLiveOutFailureKind8616.CONDITION_CONFLICT,
        MemoryLiveOutFailureKind8616.SIGNEDNESS_CONFLICT,
        MemoryLiveOutFailureKind8616.POINTER_TARGET_CONFLICT,
    }
    verdict = (
        MemoryLiveOutCollectionVerdict8616.CONFLICT
        if conflict
        else MemoryLiveOutCollectionVerdict8616.UNKNOWN_REFUSE
    )
    return FunctionMemoryLiveOutCollection8616(
        verdict,
        (),
        (failure,),
        StorageTrialStats8616(
            raw_fact_count=raw,
            normalized_fact_count=normalized,
            failure_count=max(1, raw - normalized),
        ),
    )


__all__ = [
    "CallsiteMemoryLiveOutEvidence8616",
    "FunctionMemoryLiveOutCollection8616",
    "MemoryLiveOutCandidateResult8616",
    "MemoryLiveOutCollectionVerdict8616",
    "MemoryLiveOutFailure8616",
    "MemoryLiveOutFailureKind8616",
    "MemoryLiveOutUseDisposition8616",
    "MemoryLiveOutUseFact8616",
    "refused_memory_live_out_collection_8616",
]
