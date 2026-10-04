"""Collect proof-bearing input storage trials from the production pipeline.

Layer: Types/Lowering.
Responsibility: join the closed caller census, exact callee stack identities,
caller SSA reaching definitions, typed signedness, and pointer/value evidence
into deterministic input trials for the SCC solver.
Consumes alias, widening, and typed facts. This module does not mutate codegen
or infer return storage.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from ..analysis_helpers import resolve_direct_call_target_from_instruction_8616
from ..frontend_function_boundary import ExactFunctionRangeBoundary8616
from ..ir import IRAddress
from ..ir.function_ssa_registry import FunctionSSAArtifactVerdict8616
from ..ir.ssa_function import SSAFunctionArtifact
from ..semantics.call_stack_effect_pipeline import (
    semantic_function_ssa_artifact_at_address_8616,
)
from ..semantics.call_target_evidence_8616 import (
    resolve_call_target_evidence_8616,
)
from .callee_argument_width_evidence import (
    collect_callee_argument_width_evidence_8616,
)
from .callee_callsite_census import CalleeCallsiteFact8616
from .callee_pointer_evidence import (
    CalleePointerArgumentEvidence8616,
    callee_pointer_argument_evidence_at_address_8616,
)
from .condition_argument_type_facts import (
    ConditionArgumentFactsResult8616,
    collect_condition_argument_type_facts_8616,
)
from .input_offset_value import collect_input_offset_value_8616
from .interprocedural_storage_collection_contracts import (
    FunctionInputStorageTrialCollection8616,
    StorageTrialCollectionFailure8616,
    StorageTrialCollectionFailureKind8616,
    StorageTrialCollectionVerdict8616,
)
from .interprocedural_storage_contracts import (
    CallsiteStorageTrials8616,
    FunctionStorageTrials8616,
    StorageTrial8616,
    StorageTrialRole8616,
    StorageTrialSignedness8616,
    StorageTrialStats8616,
    StorageTrialValueClass8616,
)
from .interprocedural_storage_input_preflight import (
    classify_callsite_inputs_before_ssa_8616,
)
from .interprocedural_storage_logical_input_contracts import LogicalInputRootBinding8616
from .interprocedural_storage_reaching_contracts import (
    CallArgumentDefinitionResolution8616,
    CallArgumentDefinitionVerdict8616,
)
from .interprocedural_storage_reaching_defs import (
    resolve_call_argument_reaching_definition_8616,
)
from .interprocedural_storage_trial_types import (
    callee_storage_pieces_8616,
)
from .modular_argument_type_facts import ModularArgumentTypeFacts8616

__all__ = [
    "collect_function_input_storage_trials_8616",
]


_CONFLICT_FAILURES = frozenset(
    {
        StorageTrialCollectionFailureKind8616.CALLSITE_IDENTITY_CONFLICT,
        StorageTrialCollectionFailureKind8616.REACHING_DEFINITION_CONFLICT,
        StorageTrialCollectionFailureKind8616.STORAGE_PIECE_CONFLICT,
        StorageTrialCollectionFailureKind8616.SIGNEDNESS_CONFLICT,
        StorageTrialCollectionFailureKind8616.VALUE_CLASS_CONFLICT,
    }
)


def _failure_8616(
    kind: StorageTrialCollectionFailureKind8616,
    callee_addr: int,
    fact: CalleeCallsiteFact8616 | None = None,
    *,
    logical_index: int | None = None,
) -> StorageTrialCollectionFailure8616:
    """Build one location-bearing collection refusal."""
    return StorageTrialCollectionFailure8616(
        kind=kind,
        callee_addr=callee_addr,
        caller_addr=None if fact is None else fact.caller_addr,
        callsite_addr=None if fact is None else fact.callsite_addr,
        logical_index=logical_index,
    )


def _input_trials_8616(
    callee_addr: int, caller_addr: int, callsite_addr: int, logical_index: int,
    storage: IRAddress, reaching: CallArgumentDefinitionResolution8616,
    signedness: StorageTrialSignedness8616, value_class: StorageTrialValueClass8616,
    *, caller_ssa: SSAFunctionArtifact | None = None,
) -> tuple[StorageTrial8616, ...] | None:
    """Bind one complete input's exact pieces, retaining only producer-owned roots."""
    use = reaching.use
    storage_pieces = callee_storage_pieces_8616(storage, reaching.definitions)
    if use is None or storage_pieces is None:
        return None
    trials: list[StorageTrial8616] = []
    argument_offset = 0
    piece_count = len(storage_pieces)
    for piece_index, (piece, definition) in enumerate(
        zip(storage_pieces, reaching.definitions, strict=True)
    ):
        logical = definition.logical_push
        source_slice = None if logical is None else logical.definition_slice(definition)
        binding = None
        if logical is not None and source_slice is not None:
            binding = LogicalInputRootBinding8616(
                callee_addr=callee_addr, caller_addr=caller_addr,
                callsite_addr=callsite_addr, logical_index=logical_index,
                piece_index=piece_index, piece_count=piece_count,
                push_addr=definition.instr_addr, source_offset=source_slice.source_offset,
                argument_offset=argument_offset, byte_width=piece.width,
                argument_storage=storage, logical_push=logical, call_use=use,
            )
        trial = StorageTrial8616(
            callee_addr=callee_addr, caller_addr=caller_addr, callsite_addr=callsite_addr,
            role=StorageTrialRole8616.INPUT, logical_index=logical_index,
            piece_index=piece_index, piece_count=piece_count,
            storage=piece, reaching_definition=definition, use=use,
            signedness=signedness, value_class=value_class, logical_root=binding,
            input_offset_value=(
                collect_input_offset_value_8616(binding, artifact=caller_ssa, definition=definition, use=use)
                if caller_ssa is not None and storage.size == 2 else None
            ),
        )
        if logical is not None and (binding is None or not trial.logical_root_is_bound):
            return None
        trials.append(trial)
        argument_offset += piece.width
    return tuple(trials)


def _callsite_trials_8616(
    callee_addr: int,
    fact: CalleeCallsiteFact8616,
    argument_storage: tuple[IRAddress, ...],
    signedness_facts: ConditionArgumentFactsResult8616,
    pointer_evidence: CalleePointerArgumentEvidence8616 | None,
    modular_facts: ModularArgumentTypeFacts8616,
) -> tuple[CallsiteStorageTrials8616 | None, tuple[StorageTrialCollectionFailure8616, ...], bool]:
    """Materialize every logical input at one exact caller or refuse the callsite."""
    caller_addr = fact.caller_addr
    summary = fact.summary
    if not isinstance(caller_addr, int):
        return None, (_failure_8616(StorageTrialCollectionFailureKind8616.CALLER_ADDRESS_UNKNOWN, callee_addr, fact),), False
    logical_argument_count = (
        None
        if summary is None
        else len(summary.logical_arg_widths)
        if summary.logical_arg_widths
        else summary.arg_count
    )
    if summary is None or len(argument_storage) != logical_argument_count:
        return None, (_failure_8616(StorageTrialCollectionFailureKind8616.ARGUMENT_STORAGE_UNKNOWN, callee_addr, fact),), False
    if not isinstance(summary.stack_cleanup, int) or summary.stack_cleanup < 0:
        return None, (_failure_8616(StorageTrialCollectionFailureKind8616.STACK_DELTA_UNKNOWN, callee_addr, fact),), False
    preflight = classify_callsite_inputs_before_ssa_8616(
        callee_addr,
        fact,
        summary,
        argument_storage,
        signedness_facts,
        pointer_evidence,
        modular_facts,
    )
    if not preflight.complete:
        return None, preflight.failures, True
    ssa_resolution = semantic_function_ssa_artifact_at_address_8616(
        fact.evidence_project,
        caller_addr,
        function=fact.caller_function,
    )
    function_ssa = ssa_resolution.artifact
    if ssa_resolution.verdict is not FunctionSSAArtifactVerdict8616.PROVEN or function_ssa is None:
        failure = StorageTrialCollectionFailure8616(
            kind=StorageTrialCollectionFailureKind8616.CALLER_SSA_UNAVAILABLE,
            callee_addr=callee_addr,
            caller_addr=caller_addr,
            callsite_addr=fact.callsite_addr,
            ssa_failure=ssa_resolution.failure,
        )
        return None, (failure,), False
    evidence = resolve_call_target_evidence_8616(
        fact.evidence_project,
        caller_addr,
        boundary=(
            fact.caller_function
            if isinstance(fact.caller_function, ExactFunctionRangeBoundary8616)
            else None
        ),
        direct_target_resolver=lambda instruction: (
            resolve_direct_call_target_from_instruction_8616(
                fact.evidence_project, instruction
            )
        ),
    )
    callsite_index = evidence.callsite_index if evidence.complete else None
    projection = evidence.projection if evidence.complete else None
    trials: list[StorageTrial8616] = []
    failures: list[StorageTrialCollectionFailure8616] = []
    for classified_input in preflight.inputs:
        logical_index = classified_input.logical_index
        storage = classified_input.storage
        reaching = resolve_call_argument_reaching_definition_8616(
            function_ssa,
            summary,
            logical_index,
            project=fact.evidence_project,
            expected_target_addr=fact.evidence_target_addr,
            callsite_index=callsite_index,
            projection=projection,
        )
        if reaching.verdict is not CallArgumentDefinitionVerdict8616.PROVEN or reaching.use is None:
            kind = (
                StorageTrialCollectionFailureKind8616.REACHING_DEFINITION_CONFLICT
                if reaching.verdict is CallArgumentDefinitionVerdict8616.CONFLICT
                else StorageTrialCollectionFailureKind8616.REACHING_DEFINITION_REFUSED
            )
            failures.append(
                StorageTrialCollectionFailure8616(
                    kind=kind,
                    callee_addr=callee_addr,
                    caller_addr=caller_addr,
                    callsite_addr=fact.callsite_addr,
                    logical_index=logical_index,
                    reaching_failure=reaching.failure,
                )
            )
            continue
        input_trials = _input_trials_8616(
            callee_addr, caller_addr, fact.callsite_addr, logical_index,
            storage, reaching,
            classified_input.signedness, classified_input.value_class,
            caller_ssa=function_ssa,
        )
        if input_trials is None:
            failures.append(_failure_8616(
                StorageTrialCollectionFailureKind8616.STORAGE_PIECE_CONFLICT,
                callee_addr, fact, logical_index=logical_index,
            ))
            continue
        trials.extend(input_trials)
    if failures:
        return None, tuple(failures), True
    return (
        CallsiteStorageTrials8616(
            caller_addr=caller_addr,
            callee_addr=callee_addr,
            callsite_addr=fact.callsite_addr,
            arguments=tuple(trials),
            stack_delta=summary.stack_cleanup,
        ),
        (),
        True,
    )


def collect_function_input_storage_trials_8616(
    project: object,
    codegen: object,
    function_addr: int,
) -> FunctionInputStorageTrialCollection8616:
    """Collect all input trials only when the caller and type censuses close."""
    width_evidence = collect_callee_argument_width_evidence_8616(project, function_addr)
    count_evidence = width_evidence.count_evidence
    facts = () if count_evidence is None else count_evidence.callsite_facts
    failures: list[StorageTrialCollectionFailure8616] = []
    if not width_evidence.closes_census or count_evidence is None:
        failures.append(
            _failure_8616(
                StorageTrialCollectionFailureKind8616.INCOMPLETE_CALLER_CENSUS,
                function_addr,
            )
        )
    callsite_addrs = tuple(fact.callsite_addr for fact in facts)
    if len(set(callsite_addrs)) != len(callsite_addrs):
        failures.append(
            _failure_8616(
                StorageTrialCollectionFailureKind8616.CALLSITE_IDENTITY_CONFLICT,
                function_addr,
            )
        )
    signedness_facts = collect_condition_argument_type_facts_8616(codegen)
    pointer_evidence = callee_pointer_argument_evidence_at_address_8616(
        project,
        function_addr,
    )
    modular_facts = ModularArgumentTypeFacts8616(project, function_addr)
    callsites: list[CallsiteStorageTrials8616] = []
    normalized_count = 0
    if not failures:
        for fact in sorted(facts, key=lambda item: (item.callsite_addr, item.caller_addr or -1)):
            callsite, callsite_failures, normalized = _callsite_trials_8616(
                function_addr,
                fact,
                width_evidence.argument_storage,
                signedness_facts,
                pointer_evidence,
                modular_facts,
            )
            normalized_count += int(normalized)
            failures.extend(callsite_failures)
            if callsite is not None:
                callsites.append(callsite)
    raw_count = width_evidence.raw_fact_count
    materialized_count = len(callsites)
    stats = StorageTrialStats8616(
        raw_fact_count=raw_count,
        normalized_fact_count=normalized_count,
        classified_fact_count=materialized_count,
        materialized_count=materialized_count,
        failure_count=max(0, raw_count - materialized_count),
    )
    caller_census_complete = not failures and stats.complete
    trials = FunctionStorageTrials8616(
        function_addr=function_addr,
        caller_census_complete=caller_census_complete,
        expected_callsite_addrs=tuple(sorted(callsite_addrs)),
        callsites=tuple(callsites),
    )
    verdict = (
        StorageTrialCollectionVerdict8616.PROVEN
        if caller_census_complete
        else (
            StorageTrialCollectionVerdict8616.CONFLICT
            if any(failure.kind in _CONFLICT_FAILURES for failure in failures)
            else StorageTrialCollectionVerdict8616.UNKNOWN_REFUSE
        )
    )
    return FunctionInputStorageTrialCollection8616(
        verdict=verdict,
        trials=trials,
        failures=tuple(failures),
        stats=stats,
    )
