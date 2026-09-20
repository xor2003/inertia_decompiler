"""Join and resolve one function's interprocedural storage trials.

Layer: Types/Lowering.
Responsibility: validate one complete caller census, derive exact direct input
and output slots, and finalize a function contract only after the SCC owner has
resolved every deferred recursive return pass-through. This module does not
infer signatures, mutate codegen, or synthesize missing SSA uses.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from ..pipeline.errors import PipelineHardError
from .interprocedural_memory_output_object_contracts import (
    MemoryOutputObjectJoinEvidence8616,
)
from .interprocedural_memory_output_objects import (
    join_memory_output_object_contracts_8616,
)
from .interprocedural_storage_contracts import (
    CallsiteStorageBinding8616,
    CallsiteStorageTrials8616,
    FunctionStorageContract8616,
    FunctionStorageResolution8616,
    FunctionStorageTrials8616,
    StorageSlotContract8616,
    StorageTrial8616,
    StorageTrialFailureKind8616,
    StorageTrialRole8616,
    StorageTrialStats8616,
    StorageTrialVerdict8616,
)
from .interprocedural_storage_return_discard import discarded_return_census_proves_empty_8616
from .interprocedural_storage_return_passthrough_contracts import ReturnPassThroughTrial8616
from .interprocedural_storage_slot_join import (
    join_storage_slot_contracts_8616,
    ordered_storage_trials_8616,
)

__all__ = [
    "FunctionStorageTrialJoin8616", "join_function_storage_trials_8616",
    "resolve_joined_function_storage_trials_8616",
]


@dataclass(frozen=True, slots=True)
class FunctionStorageTrialJoin8616:
    """Validated direct slots and deferred facts for one function census."""

    trials: FunctionStorageTrials8616
    all_trials: tuple[StorageTrial8616, ...]
    passthroughs: tuple[ReturnPassThroughTrial8616, ...]
    inputs: tuple[StorageSlotContract8616, ...] | None
    direct_outputs: tuple[StorageSlotContract8616, ...] | None
    memory_output_join: MemoryOutputObjectJoinEvidence8616
    stack_delta: int | None
    failures: tuple[StorageTrialFailureKind8616, ...]
    raw_count: int
    normalized_count: int

    @property
    def function_addr(self) -> int:
        """Return the exact function address owning this joined census."""
        return int(self.trials.function_addr)

    @property
    def direct_output_seed(self) -> tuple[StorageSlotContract8616, ...] | None:
        """Return a non-empty output seed only from an otherwise valid join."""
        if self.failures or not self.direct_outputs:
            return None
        return self.direct_outputs


def _trial_matches_callsite_8616(
    trial: StorageTrial8616,
    callsite: CallsiteStorageTrials8616,
) -> bool:
    """Return whether one complete trial belongs to its containing callsite."""
    return bool(
        trial.is_complete
        and trial.callee_addr == callsite.callee_addr
        and trial.caller_addr == callsite.caller_addr
        and trial.callsite_addr == callsite.callsite_addr
    )


def _ordered_failures_8616(
    failures: Iterable[StorageTrialFailureKind8616],
) -> tuple[StorageTrialFailureKind8616, ...]:
    """Return unique failure kinds in stable contract order."""
    return tuple(sorted(set(failures), key=lambda item: item.value))


def _return_evidence_failures_8616(
    callsites: tuple[CallsiteStorageTrials8616, ...],
) -> tuple[StorageTrialFailureKind8616, ...]:
    """Require exclusive and correctly bound observed/deferred/discarded facts."""
    failures: list[StorageTrialFailureKind8616] = []
    for site in callsites:
        deferred_valid = all(trial.belongs_to(site.callee_addr, site.caller_addr, site.callsite_addr)
                             for trial in site.return_passthroughs)
        discard_valid = site.discarded_return is None or site.discarded_return.belongs_to(
            site.callee_addr, site.caller_addr, site.callsite_addr,
        )
        if not deferred_valid or not discard_valid:
            failures.append(StorageTrialFailureKind8616.INCOMPLETE_TRIAL)
        return_modes = (bool(site.return_passthroughs), bool(site.returns), site.discarded_return is not None)
        if len(site.return_passthroughs) > 1 or sum(return_modes) > 1:
            failures.append(StorageTrialFailureKind8616.CALLSITE_SET_CONFLICT)
    return _ordered_failures_8616(failures)


def join_function_storage_trials_8616(
    trials: FunctionStorageTrials8616,
) -> FunctionStorageTrialJoin8616:
    """Validate one caller census and derive only directly proven slot shapes."""
    all_trials = tuple(
        trial
        for callsite in trials.callsites
        for trial in (*callsite.arguments, *callsite.returns, *callsite.live_outs)
    )
    passthroughs = tuple(
        trial for callsite in trials.callsites for trial in callsite.return_passthroughs
    )
    discarded = tuple(site.discarded_return for site in trials.callsites if site.discarded_return is not None)
    memory_effects = tuple(
        effect for callsite in trials.callsites for effect in callsite.memory_effects
    )
    pointer_effects = tuple(
        effect for callsite in trials.callsites for effect in callsite.pointer_effects
    )
    interface_trials = tuple(
        trial
        for callsite in trials.callsites
        for trial in (*callsite.arguments, *callsite.returns)
    )
    raw_count = (
        len(interface_trials)
        + len(passthroughs)
        + len(discarded)
        + len(memory_effects)
        + len(pointer_effects)
    )
    normalized_count = (
        sum(item.is_complete for item in interface_trials)
        + sum(item.is_complete for item in passthroughs)
        + sum(item.is_complete for item in discarded)
        + sum(item.complete for item in memory_effects)
        + sum(item.complete for item in pointer_effects)
    )
    failures: list[StorageTrialFailureKind8616] = []
    expected = tuple(sorted(set(trials.expected_callsite_addrs)))
    observed = tuple(sorted(callsite.callsite_addr for callsite in trials.callsites))
    if not trials.caller_census_complete:
        failures.append(StorageTrialFailureKind8616.INCOMPLETE_CALLER_CENSUS)
    if len(expected) != len(trials.expected_callsite_addrs) or observed != expected:
        failures.append(StorageTrialFailureKind8616.CALLSITE_SET_CONFLICT)
    if any(callsite.callee_addr != trials.function_addr for callsite in trials.callsites):
        failures.append(StorageTrialFailureKind8616.CALLSITE_SET_CONFLICT)
    if any(
        not _trial_matches_callsite_8616(trial, callsite)
        for callsite in trials.callsites
        for trial in (*callsite.arguments, *callsite.returns, *callsite.live_outs)
    ):
        failures.append(StorageTrialFailureKind8616.INCOMPLETE_TRIAL)
    failures.extend(_return_evidence_failures_8616(trials.callsites))
    stack_deltas = {callsite.stack_delta for callsite in trials.callsites}
    if not trials.callsites or None in stack_deltas or len(stack_deltas) != 1:
        failures.append(StorageTrialFailureKind8616.STACK_DELTA_CONFLICT)
    inputs, input_failure = join_storage_slot_contracts_8616(
        trials.callsites,
        StorageTrialRole8616.INPUT,
    )
    direct_outputs, output_failure = join_storage_slot_contracts_8616(
        trials.callsites,
        StorageTrialRole8616.RETURN,
    )
    memory_output_join = join_memory_output_object_contracts_8616(trials.callsites)
    failures.extend(item for item in (input_failure, output_failure) if item is not None)
    if memory_output_join.storage_failure is not None:
        failures.append(memory_output_join.storage_failure)
    stack_delta = next(iter(stack_deltas)) if len(stack_deltas) == 1 else None
    if not isinstance(stack_delta, int):
        stack_delta = None
    return FunctionStorageTrialJoin8616(
        trials=trials,
        all_trials=all_trials,
        passthroughs=passthroughs,
        inputs=inputs,
        direct_outputs=direct_outputs,
        memory_output_join=memory_output_join,
        stack_delta=stack_delta,
        failures=_ordered_failures_8616(failures),
        raw_count=raw_count,
        normalized_count=normalized_count,
    )


def _refused_resolution_8616(
    joined: FunctionStorageTrialJoin8616,
    failures: Iterable[StorageTrialFailureKind8616],
) -> FunctionStorageResolution8616:
    """Build one deterministic refusal without classifying guessed facts."""
    ordered_failures = _ordered_failures_8616(failures)
    conflict_kinds = {
        StorageTrialFailureKind8616.ARGUMENT_ORDER_CONFLICT,
        StorageTrialFailureKind8616.CALLSITE_SET_CONFLICT,
        StorageTrialFailureKind8616.SIGNEDNESS_CONFLICT,
        StorageTrialFailureKind8616.SPLIT_PROVENANCE_CONFLICT,
        StorageTrialFailureKind8616.STACK_DELTA_CONFLICT,
        StorageTrialFailureKind8616.STORAGE_CONFLICT,
        StorageTrialFailureKind8616.VALUE_CLASS_CONFLICT,
    }
    verdict = (
        StorageTrialVerdict8616.CONFLICT
        if any(item in conflict_kinds for item in ordered_failures)
        else StorageTrialVerdict8616.UNKNOWN_REFUSE
    )
    return FunctionStorageResolution8616(
        function_addr=joined.function_addr,
        verdict=verdict,
        contract=None,
        failures=ordered_failures,
        stats=StorageTrialStats8616(
            raw_fact_count=joined.raw_count,
            normalized_fact_count=joined.normalized_count,
            failure_count=max(
                1,
                joined.raw_count - joined.normalized_count,
                len(ordered_failures),
            ),
        ),
    )


def resolve_joined_function_storage_trials_8616(
    joined: FunctionStorageTrialJoin8616,
    passthrough_outputs: tuple[StorageSlotContract8616, ...] | None,
    *,
    recursive_callers: frozenset[int] = frozenset(),
) -> FunctionStorageResolution8616:
    """Finalize one join after the SCC fixed point resolves pass-throughs."""
    failures = list(joined.failures)
    outputs = joined.direct_outputs
    if joined.passthroughs and not failures:
        unproven_empty = passthrough_outputs == () and not discarded_return_census_proves_empty_8616(
            joined.trials, recursive_callers,
        )
        if passthrough_outputs is None or unproven_empty:
            failures.append(StorageTrialFailureKind8616.PASSTHROUGH_OUTPUT_UNRESOLVED)
        elif outputs and outputs != passthrough_outputs:
            failures.append(StorageTrialFailureKind8616.STORAGE_CONFLICT)
        else:
            outputs = passthrough_outputs
    if (
        failures
        or joined.inputs is None
        or outputs is None
        or not joined.memory_output_join.complete
        or joined.stack_delta is None
    ):
        return _refused_resolution_8616(joined, failures)
    bindings = tuple(
        CallsiteStorageBinding8616(
            caller_addr=callsite.caller_addr,
            callsite_addr=callsite.callsite_addr,
            arguments=ordered_storage_trials_8616(callsite, StorageTrialRole8616.INPUT),
            returns=ordered_storage_trials_8616(callsite, StorageTrialRole8616.RETURN),
            stack_delta=joined.stack_delta,
            live_outs=ordered_storage_trials_8616(callsite, StorageTrialRole8616.LIVE_OUT),
            memory_effects=callsite.memory_effects,
            pointer_effects=callsite.pointer_effects,
            return_passthroughs=callsite.return_passthroughs,
            discarded_return=callsite.discarded_return,
        )
        for callsite in sorted(joined.trials.callsites, key=lambda item: item.callsite_addr)
    )
    contract = FunctionStorageContract8616(
        function_addr=joined.function_addr,
        inputs=joined.inputs,
        outputs=outputs,
        stack_delta=joined.stack_delta,
        callsites=bindings,
        memory_outputs=joined.memory_output_join.objects,
        pointer_memory_outputs=joined.memory_output_join.pointer_objects,
    )
    stats = StorageTrialStats8616(
        raw_fact_count=joined.raw_count,
        normalized_fact_count=joined.raw_count,
        classified_fact_count=joined.raw_count,
        materialized_count=joined.raw_count,
    )
    if not stats.complete:
        raise PipelineHardError(
            "accepted storage trials did not close their evidence counters",
            layer="types/lowering",
            function_addr=joined.function_addr,
        )
    return FunctionStorageResolution8616(
        function_addr=joined.function_addr,
        verdict=StorageTrialVerdict8616.ACCEPTED,
        contract=contract,
        failures=(),
        stats=stats,
    )
