"""Collect deterministic return/live-out storage trials from typed evidence.

Layer: Types/Lowering.
Responsibility: join Semantics-owned terminal return storage, the closed binary
caller-use census, exact caller SSA, and typed scalar/pointer use proofs into
solver-ready return trials while preserving existing input callsite evidence.
Canonicalizes multiple SSA operations for one physical split-return comparison
to one exact instruction-level use, while refusing distinct instruction sites.
Consumes alias, widening, and typed facts. This module does not infer ABI
returns, mutate codegen, publish contracts, or repair emitted calls.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Protocol, cast

from ..alias.domains import AX, DX, DomainKey, register_domain_for_name
from ..caller_return_use_contracts import (
    CallerReturnUseEvidence8616,
    CallerReturnUseFact8616,
    CallerReturnUseVerdict8616,
)
from ..ir.condition_ir import ConditionIR
from ..ir.function_ssa_registry import (
    FunctionSSAArtifactFailure8616,
)
from ..ir.ssa_function import SSAFunctionArtifact
from ..semantics.call_stack_effect_pipeline import (
    semantic_function_ssa_artifact_at_address_8616,
)
from ..semantics.terminal_return_storage import (
    terminal_return_storage_8616,
)
from .condition_transfer import collect_typed_condition_artifacts_8616
from .interprocedural_storage_caller_context import (
    CallerSSAContext8616,
    CallerSSAContextVerdict8616,
    caller_ssa_context_for_return_use_8616,
)
from .interprocedural_storage_collection_contracts import (
    FunctionInputStorageTrialCollection8616,
    StorageTrialCollectionVerdict8616,
)
from .interprocedural_storage_contracts import (
    CallsiteStorageTrials8616,
    FunctionStorageTrials8616,
    StorageIdentity8616,
    StorageTrial8616,
    StorageTrialRole8616,
    StorageTrialStats8616,
    StorageTrialValueClass8616,
    StorageUseEvidence8616,
)
from .interprocedural_storage_live_out import (
    attach_callsite_memory_live_out_evidence_8616,
    collect_function_memory_live_out_trials_8616,
)
from .interprocedural_storage_live_out_contracts import (
    CallsiteMemoryLiveOutEvidence8616,
    MemoryLiveOutCollectionVerdict8616,
    MemoryLiveOutFailure8616,
)
from .interprocedural_storage_return_collection_contracts import (
    FunctionReturnStorageTrialCollection8616,
    ReturnStorageTrialCollectionFailure8616,
    ReturnStorageTrialCollectionFailureKind8616,
)
from .interprocedural_storage_return_defs import (
    CallOutputDefinitionFailure8616,
    resolve_call_output_definitions_8616,
)
from .interprocedural_storage_return_discard import DiscardedReturnTrial8616
from .interprocedural_storage_return_passthrough import (
    materialize_return_passthrough_trial_8616,
)
from .interprocedural_storage_return_passthrough_contracts import (
    ReturnPassThroughTrialFailure8616,
)
from .interprocedural_storage_return_split_condition_graph import (
    select_split_return_condition_8616,
    split_return_register_matches_8616,
)
from .interprocedural_storage_return_trial_materialization import (
    materialize_callsite_return_trials_8616,
    return_output_storages_8616,
)
from .interprocedural_storage_return_type_contracts import (
    ReturnStorageTypeFailure8616,
)
from .pointer_parameter_caller_target_contracts import (
    PointerParameterCallerTargetEvidence8616,
)


class _FunctionSurface8616(Protocol):
    """Third-party function boundary required by terminal Semantics."""

    addr: int


_CONFLICT_FAILURES_8616 = frozenset(
    {
        ReturnStorageTrialCollectionFailureKind8616.FUNCTION_IDENTITY_CONFLICT,
        ReturnStorageTrialCollectionFailureKind8616.RETURN_TARGET_CONFLICT,
        ReturnStorageTrialCollectionFailureKind8616.CALLSITE_SET_CONFLICT,
        ReturnStorageTrialCollectionFailureKind8616.CALLER_IDENTITY_CONFLICT,
        ReturnStorageTrialCollectionFailureKind8616.CALL_OUTPUT_DEFINITION_CONFLICT,
        ReturnStorageTrialCollectionFailureKind8616.RETURN_TYPE_CONFLICT,
        ReturnStorageTrialCollectionFailureKind8616.WITNESS_CONFLICT,
        ReturnStorageTrialCollectionFailureKind8616.MEMORY_LIVE_OUT_CONFLICT,
    }
)


def _failure_8616(
    kind: ReturnStorageTrialCollectionFailureKind8616,
    callee_addr: int,
    fact: CallerReturnUseFact8616 | None = None,
    *,
    ssa_failure: FunctionSSAArtifactFailure8616 | None = None,
    definition_failure: CallOutputDefinitionFailure8616 | None = None,
    type_failure: ReturnStorageTypeFailure8616 | None = None,
    passthrough_failure: ReturnPassThroughTrialFailure8616 | None = None,
    live_out_failure: MemoryLiveOutFailure8616 | None = None,
) -> ReturnStorageTrialCollectionFailure8616:
    """Build one exact typed refusal without text-based classification."""
    return ReturnStorageTrialCollectionFailure8616(
        kind=kind,
        callee_addr=callee_addr,
        caller_addr=None if fact is None else fact.caller_addr,
        callsite_addr=None if fact is None else fact.callsite_addr,
        ssa_failure=ssa_failure,
        definition_failure=definition_failure,
        type_failure=type_failure,
        passthrough_failure=passthrough_failure,
        live_out_failure=live_out_failure,
    )


def _return_census_complete_8616(evidence: CallerReturnUseEvidence8616) -> bool:
    """Validate fact verdicts and counters beyond structural retention."""
    included = tuple(fact for fact in evidence.facts if not fact.excluded_recursive_passthrough)
    used = sum(fact.verdict is CallerReturnUseVerdict8616.USED for fact in included)
    unused = sum(fact.verdict is CallerReturnUseVerdict8616.UNUSED for fact in included)
    discard_facts_complete = all(
        DiscardedReturnTrial8616(evidence.target_addr, fact).is_complete
        for fact in included if fact.verdict is CallerReturnUseVerdict8616.UNUSED
    )
    expected_verdict = CallerReturnUseVerdict8616.UNKNOWN
    if used:
        expected_verdict = CallerReturnUseVerdict8616.USED
    elif included:
        expected_verdict = CallerReturnUseVerdict8616.UNUSED
    return (
        evidence.fact_census_complete
        and discard_facts_complete
        and bool(evidence.facts)
        and evidence.failure_count == 0
        and evidence.excluded_callsite_count == len(evidence.facts) - len(included)
        and evidence.used_callsite_count == used
        and evidence.unused_callsite_count == unused
        and used + unused == len(included)
        and evidence.verdict is expected_verdict
    )


def _canonical_instruction_use_8616(
    artifact: SSAFunctionArtifact,
    condition: ConditionIR,
    storage: StorageIdentity8616,
    callsite_addr: int,
) -> StorageUseEvidence8616 | None:
    """Collapse matching SSA operations only when they share one instruction site."""
    producer = condition.producer_insn
    if not isinstance(producer, int) or isinstance(producer, bool):
        return None
    indices_by_site: dict[tuple[int, int], list[int]] = {}
    for block in artifact.blocks:
        for instr_index, instruction in enumerate(block.instrs):
            if instruction.addr != producer or not any(
                split_return_register_matches_8616(argument, storage)
                for argument in instruction.args
            ):
                continue
            indices_by_site.setdefault((block.addr, instruction.addr), []).append(
                instr_index
            )
    if len(indices_by_site) != 1:
        return None
    (block_addr, instr_addr), instr_indices = next(iter(indices_by_site.items()))
    return StorageUseEvidence8616(
        block_addr=block_addr,
        instr_index=min(instr_indices),
        instr_addr=instr_addr,
        callsite_addr=callsite_addr,
    )


def _materialize_canonical_split_return_trials_8616(
    project: object,
    callee_addr: int,
    fact: CallerReturnUseFact8616,
    output_storages: tuple[StorageIdentity8616, ...],
    accepted_target_addrs: tuple[int, ...],
    conditions_by_caller: dict[int, tuple[ConditionIR, ...]],
    caller_context: CallerSSAContext8616 | None,
) -> tuple[StorageTrial8616, ...] | None:
    """Retry a typed split-witness conflict at exact instruction granularity."""
    if len(output_storages) != 2:
        return None
    storages_by_domain: dict[DomainKey, StorageIdentity8616] = {}
    for storage in output_storages:
        domain = register_domain_for_name(storage.register)
        if domain is None or domain in storages_by_domain:
            return None
        storages_by_domain[domain] = storage
    if set(storages_by_domain) != {AX, DX}:
        return None

    caller_project = project if caller_context is None else caller_context.evidence_project
    caller_function = None if caller_context is None else caller_context.caller_function
    if caller_project is None:
        return None
    ssa = semantic_function_ssa_artifact_at_address_8616(
        caller_project, fact.caller_addr, function=caller_function
    )
    artifact = ssa.artifact
    if artifact is None:
        return None
    definitions = resolve_call_output_definitions_8616(
        artifact,
        fact,
        callee_addr,
        accepted_target_addrs,
        output_storages,
        project=caller_project,
    )
    if not definitions.complete or len(definitions.definitions) != len(output_storages):
        return None
    definition_keys = tuple(
        None if definition.source_storage is None else definition.source_storage.key
        for definition in definitions.definitions
    )
    if definition_keys != tuple(storage.key for storage in output_storages):
        return None

    conditions = conditions_by_caller.get(fact.caller_addr)
    if conditions is None:
        collected, _edge_evidence = collect_typed_condition_artifacts_8616(
            caller_project,
            fact.caller_addr,
        )
        conditions = tuple(collected)
        conditions_by_caller[fact.caller_addr] = conditions
    witness_addr = fact.witness_instruction_addr
    if not isinstance(witness_addr, int) or isinstance(witness_addr, bool):
        return None
    candidate, selection_failure = select_split_return_condition_8616(
        artifact,
        witness_addr,
        conditions,
        storages_by_domain[DX],
        storages_by_domain[AX],
    )
    if candidate is None or selection_failure is not None:
        return None

    uses_by_domain: dict[DomainKey, StorageUseEvidence8616] = {}
    for domain, storage in storages_by_domain.items():
        condition = (
            candidate.high_condition if domain == DX else candidate.low_condition
        )
        use = _canonical_instruction_use_8616(
            artifact,
            condition,
            storage,
            fact.callsite_addr,
        )
        if use is None:
            return None
        uses_by_domain[domain] = use
    provenance = definitions.provenance
    if provenance is None:
        return None
    piece_count = len(output_storages)
    trials: list[StorageTrial8616] = []
    for piece_index, (storage, definition) in enumerate(
        zip(output_storages, definitions.definitions, strict=True)
    ):
        domain = register_domain_for_name(storage.register)
        use = None if domain is None else uses_by_domain.get(domain)
        if use is None:
            return None
        trials.append(
            StorageTrial8616(
                callee_addr=callee_addr,
                caller_addr=fact.caller_addr,
                callsite_addr=fact.callsite_addr,
                role=StorageTrialRole8616.RETURN,
                logical_index=0,
                piece_index=piece_index,
                piece_count=piece_count,
                storage=storage,
                reaching_definition=definition,
                use=use,
                signedness=candidate.signedness,
                value_class=StorageTrialValueClass8616.VALUE,
                provenance=provenance,
            )
        )
    return tuple(trials)


def collect_function_return_storage_trials_8616(
    project: object,
    function: object,
    inputs: FunctionInputStorageTrialCollection8616,
    evidence: CallerReturnUseEvidence8616,
    *,
    accepted_target_addrs: tuple[int, ...] = (),
    pointer_targets: PointerParameterCallerTargetEvidence8616 | None = None,
) -> FunctionReturnStorageTrialCollection8616:
    """Merge exact return/live-out trials into one complete input census."""
    callee_addr = inputs.trials.function_addr
    failures: list[ReturnStorageTrialCollectionFailure8616] = []
    if not inputs.complete:
        failures.append(
            _failure_8616(
                ReturnStorageTrialCollectionFailureKind8616.INPUT_COLLECTION_INCOMPLETE,
                callee_addr,
            )
        )
    function_surface = cast(_FunctionSurface8616, function)
    try:
        function_addr = function_surface.addr
    except AttributeError:
        function_addr = -1
    if function_addr != callee_addr:
        failures.append(
            _failure_8616(
                ReturnStorageTrialCollectionFailureKind8616.FUNCTION_IDENTITY_CONFLICT,
                callee_addr,
            )
        )
    targets = tuple(
        dict.fromkeys(
            address
            for address in (callee_addr, *accepted_target_addrs)
            if isinstance(address, int) and not isinstance(address, bool)
        )
    )
    if evidence.target_addr not in targets:
        failures.append(
            _failure_8616(
                ReturnStorageTrialCollectionFailureKind8616.RETURN_TARGET_CONFLICT,
                callee_addr,
            )
        )
    if not _return_census_complete_8616(evidence):
        failures.append(
            _failure_8616(
                ReturnStorageTrialCollectionFailureKind8616.INCOMPLETE_RETURN_CENSUS,
                callee_addr,
            )
        )
    fact_addrs = tuple(fact.callsite_addr for fact in evidence.facts)
    if (
        len(set(fact_addrs)) != len(fact_addrs)
        or tuple(sorted(fact_addrs)) != inputs.trials.expected_callsite_addrs
    ):
        failures.append(
            _failure_8616(
                ReturnStorageTrialCollectionFailureKind8616.CALLSITE_SET_CONFLICT,
                callee_addr,
            )
        )

    input_by_callsite = {callsite.callsite_addr: callsite for callsite in inputs.trials.callsites}
    if len(input_by_callsite) != len(inputs.trials.callsites):
        failures.append(
            _failure_8616(
                ReturnStorageTrialCollectionFailureKind8616.CALLSITE_SET_CONFLICT,
                callee_addr,
            )
        )
    memory_live_out_evidence: tuple[CallsiteMemoryLiveOutEvidence8616, ...] = ()
    live_out_stats = StorageTrialStats8616()
    if not failures:
        live_outs = collect_function_memory_live_out_trials_8616(
            project,
            callee_addr,
            inputs.trials.callsites,
            targets,
            pointer_targets=pointer_targets,
        )
        live_out_stats = live_outs.stats
        if not live_outs.complete:
            if not live_outs.failures:
                raise RuntimeError("incomplete memory live-out collection lost its typed refusal")
            kind = (
                ReturnStorageTrialCollectionFailureKind8616.MEMORY_LIVE_OUT_CONFLICT
                if live_outs.verdict is MemoryLiveOutCollectionVerdict8616.CONFLICT
                else ReturnStorageTrialCollectionFailureKind8616.MEMORY_LIVE_OUT_REFUSED
            )
            failures.append(
                _failure_8616(kind, callee_addr, live_out_failure=live_outs.failures[0])
            )
        else:
            memory_live_out_evidence = live_outs.callsites
    used_facts = tuple(
        fact
        for fact in evidence.facts
        if fact.verdict is CallerReturnUseVerdict8616.USED
        and not fact.excluded_recursive_passthrough
    )
    output_storages: tuple[StorageIdentity8616, ...] = ()
    if used_facts and not failures:
        terminal_storage = terminal_return_storage_8616(project, function)
        if terminal_storage is None:
            failures.append(
                _failure_8616(
                    ReturnStorageTrialCollectionFailureKind8616.TERMINAL_STORAGE_UNKNOWN,
                    callee_addr,
                )
            )
        else:
            output_storages = return_output_storages_8616(terminal_storage)

    merged: list[CallsiteStorageTrials8616] = []
    normalized_count = evidence.normalized_fact_count + live_out_stats.normalized_fact_count
    if failures:
        normalized_count = 0
    materialized_count = live_out_stats.materialized_count
    conditions_by_caller: dict[int, tuple[ConditionIR, ...]] = {}
    if not failures:
        for fact in sorted(evidence.facts, key=lambda item: (item.callsite_addr, item.caller_addr)):
            callsite = input_by_callsite.get(fact.callsite_addr)
            if callsite is None:
                failures.append(
                    _failure_8616(
                        ReturnStorageTrialCollectionFailureKind8616.CALLSITE_SET_CONFLICT,
                        callee_addr,
                        fact,
                    )
                )
                continue
            if callsite.caller_addr != fact.caller_addr:
                failures.append(
                    _failure_8616(
                        ReturnStorageTrialCollectionFailureKind8616.CALLER_IDENTITY_CONFLICT,
                        callee_addr,
                        fact,
                    )
                )
                continue
            callsite = attach_callsite_memory_live_out_evidence_8616(
                callsite, memory_live_out_evidence
            )
            caller_context = caller_ssa_context_for_return_use_8616(
                project, callee_addr, fact
            )
            if caller_context.verdict is CallerSSAContextVerdict8616.CONFLICT:
                failures.append(
                    _failure_8616(
                        ReturnStorageTrialCollectionFailureKind8616.CALLER_IDENTITY_CONFLICT,
                        callee_addr,
                        fact,
                    )
                )
                continue
            exact_context = caller_context if caller_context.complete else None
            if fact.excluded_recursive_passthrough:
                passthrough = materialize_return_passthrough_trial_8616(
                    project,
                    callee_addr,
                    fact,
                    targets,
                    exact_context,
                )
                if not passthrough.complete or passthrough.trial is None:
                    failures.append(
                        _failure_8616(
                            ReturnStorageTrialCollectionFailureKind8616.RETURN_PASSTHROUGH_REFUSED,
                            callee_addr,
                            fact,
                            passthrough_failure=passthrough.failure,
                        )
                    )
                    continue
                merged.append(
                    replace(
                        callsite,
                        return_passthroughs=(passthrough.trial,),
                    )
                )
                materialized_count += 1
                continue
            if fact.verdict is CallerReturnUseVerdict8616.UNUSED:
                merged.append(replace(callsite, discarded_return=DiscardedReturnTrial8616(callee_addr, fact)))
                materialized_count += 1
                continue
            return_trials, failure = materialize_callsite_return_trials_8616(
                project,
                callee_addr,
                fact,
                output_storages,
                targets,
                conditions_by_caller,
                exact_context,
            )
            if (
                failure is not None
                and failure.kind
                is ReturnStorageTrialCollectionFailureKind8616.RETURN_TYPE_CONFLICT
                and failure.type_failure
                is ReturnStorageTypeFailure8616.SPLIT_WITNESS_CONFLICT
            ):
                return_trials = _materialize_canonical_split_return_trials_8616(
                    project,
                    callee_addr,
                    fact,
                    output_storages,
                    targets,
                    conditions_by_caller,
                    exact_context,
                )
                if return_trials is not None:
                    failure = None
            if failure is not None or return_trials is None:
                if failure is not None:
                    failures.append(failure)
                continue
            merged.append(replace(callsite, returns=return_trials))
            materialized_count += 1

    raw_count = evidence.raw_fact_count + live_out_stats.raw_fact_count
    stats = StorageTrialStats8616(
        raw_fact_count=raw_count,
        normalized_fact_count=normalized_count,
        classified_fact_count=materialized_count,
        materialized_count=materialized_count,
        failure_count=max(len(failures), raw_count - materialized_count),
    )
    complete = not failures and stats.complete
    trials = FunctionStorageTrials8616(
        function_addr=callee_addr,
        caller_census_complete=complete,
        expected_callsite_addrs=inputs.trials.expected_callsite_addrs,
        callsites=tuple(merged),
    )
    verdict = (
        StorageTrialCollectionVerdict8616.PROVEN
        if complete
        else (
            StorageTrialCollectionVerdict8616.CONFLICT
            if inputs.verdict is StorageTrialCollectionVerdict8616.CONFLICT
            or any(failure.kind in _CONFLICT_FAILURES_8616 for failure in failures)
            else StorageTrialCollectionVerdict8616.UNKNOWN_REFUSE
        )
    )
    return FunctionReturnStorageTrialCollection8616(
        verdict=verdict,
        trials=trials,
        failures=tuple(failures),
        stats=stats,
    )
