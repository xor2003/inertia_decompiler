"""Prove and materialize one direct segmented-memory live-out use.

Layer: Types/Lowering.
Responsibility: bind one Widening-proven output view to CALL_OUTPUT, prove an
unclobbered caller CFG path, classify ConditionIR, and build one provisional
LIVE_OUT trial.
Function censuses stay outside. Only ConditionIR-attributed access instructions
activate evidence; JCC replay loads and absent direct uses do not become facts.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import replace

from ..alias.terminal_memory_outputs import TerminalMemoryAliasEvidence8616
from ..ir import IRValue
from ..ir.condition_ir import ConditionIR
from ..ir.ssa_function import SSAFunctionArtifact
from ..semantics.terminal_memory_output_contracts import TerminalMemoryOutputDisposition8616
from ..widening.terminal_memory_output_views import (
    TerminalMemoryOutputViewFact8616,
    collect_terminal_memory_output_views_8616,
)
from .interprocedural_storage_contracts import (
    CallsiteStorageTrials8616,
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageTrial8616,
    StorageTrialRole8616,
    StorageTrialSignedness8616,
    StorageTrialStats8616,
    StorageTrialValueClass8616,
    StorageUseEvidence8616,
)
from .interprocedural_storage_live_out_contracts import (
    CallsiteMemoryLiveOutEvidence8616,
    FunctionMemoryLiveOutCollection8616,
    MemoryLiveOutCandidateResult8616,
    MemoryLiveOutCollectionVerdict8616,
    MemoryLiveOutFailure8616,
    MemoryLiveOutFailureKind8616,
    MemoryLiveOutUseDisposition8616,
    MemoryLiveOutUseFact8616,
    refused_memory_live_out_collection_8616,
)
from .interprocedural_storage_live_out_paths import (
    MemoryLiveOutPathVerdict8616,
    memory_live_out_path_failure_8616,
    prove_memory_live_out_path_8616,
)
from .interprocedural_storage_return_defs import (
    CallOutputDefinitionVerdict8616,
    resolve_storage_call_output_definitions_8616,
)


def collect_callsite_memory_live_out_8616(
    aliases: TerminalMemoryAliasEvidence8616,
    artifact: SSAFunctionArtifact,
    site: CallsiteStorageTrials8616,
    targets: tuple[int, ...],
    conditions: tuple[ConditionIR, ...],
) -> FunctionMemoryLiveOutCollection8616:
    """Collect all direct memory views for one exact caller, atomically refusing conflicts."""
    facts: list[MemoryLiveOutUseFact8616] = []
    trials: list[StorageTrial8616] = []
    raw = normalized = materialized = 0
    for alias_output in aliases.canonical_facts:
        output = alias_output.terminal_output
        views = collect_terminal_memory_output_views_8616(alias_output, artifact)
        if not views.complete:
            return refused_memory_live_out_collection_8616(
                MemoryLiveOutFailure8616(
                    MemoryLiveOutFailureKind8616.WIDENING_EVIDENCE_REFUSED,
                    site.callee_addr, site.caller_addr, site.callsite_addr, output.key,
                    view_failure=views.failure,
                ),
                raw + views.stats.raw_fact_count,
                normalized + views.stats.normalized_fact_count,
            )
        for output_view in views.facts:
            candidate = materialize_memory_live_out_candidate_8616(
                artifact, output_view, site.caller_addr, site.callee_addr,
                site.callsite_addr, targets, conditions,
            )
            if not candidate.activated:
                continue
            raw += 1
            normalized += 1
            if candidate.failure is not None:
                return refused_memory_live_out_collection_8616(
                    MemoryLiveOutFailure8616(
                        candidate.failure, site.callee_addr, site.caller_addr,
                        site.callsite_addr, output.key,
                        definition_failure=candidate.definition_failure,
                    ),
                    raw, normalized,
                )
            if not candidate.complete or candidate.fact is None:
                raise RuntimeError("complete memory live-out candidate lost its typed outcome")
            facts.append(candidate.fact)
            if candidate.trial is not None:
                trials.append(replace(candidate.trial, logical_index=len(trials)))
            materialized += 1
    return FunctionMemoryLiveOutCollection8616(
        MemoryLiveOutCollectionVerdict8616.PROVEN,
        (CallsiteMemoryLiveOutEvidence8616(
            site.caller_addr, site.callee_addr, site.callsite_addr,
            tuple(facts), tuple(trials),
        ),),
        (),
        StorageTrialStats8616(raw, normalized, materialized, materialized),
    )


def _value_matches_8616(value: object, storage: StorageIdentity8616, use: StorageUseEvidence8616) -> bool:
    """Match one canonical condition operand to one exact direct LOAD."""
    address = storage.address
    return bool(
        isinstance(value, IRValue)
        and address is not None
        and value.space is address.space
        and value.offset == address.offset
        and value.size == storage.width
        and value.memory_access_insn == use.instr_addr
    )


def _condition_for_use_8616(
    conditions: tuple[ConditionIR, ...], storage: StorageIdentity8616, use: StorageUseEvidence8616,
) -> tuple[ConditionIR | None, StorageTrialSignedness8616 | None, MemoryLiveOutFailureKind8616 | None]:
    """Select one canonical direct-memory condition and its exact sign class."""
    matching: list[ConditionIR] = []
    for condition in conditions:
        operands = (condition.lhs,) if condition.is_zero_test else (condition.lhs, condition.rhs)
        if condition.width_bits == storage.width * 8 and sum(
            _value_matches_8616(operand, storage, use) for operand in operands
        ) == 1 and condition not in matching:
            matching.append(condition)
    if not matching:
        return None, None, MemoryLiveOutFailureKind8616.CONDITION_NOT_FOUND
    if len(matching) != 1:
        return None, None, MemoryLiveOutFailureKind8616.CONDITION_CONFLICT
    condition = matching[0]
    signedness = (
        StorageTrialSignedness8616.SIGNED
        if condition.is_signed
        else StorageTrialSignedness8616.UNSIGNED
        if condition.is_unsigned
        else StorageTrialSignedness8616.SIGN_INSENSITIVE
        if condition.op in {"eq", "ne", "zero", "nonzero"}
        else None
    )
    if signedness is None:
        return None, None, MemoryLiveOutFailureKind8616.CONDITION_UNSUPPORTED
    return condition, signedness, None


type _ConditionCandidate8616 = tuple[
    StorageUseEvidence8616,
    ConditionIR | None,
    StorageTrialSignedness8616 | None,
    MemoryLiveOutFailureKind8616 | None,
]
type _ProvenCondition8616 = tuple[StorageUseEvidence8616, ConditionIR, StorageTrialSignedness8616]


def _select_clean_condition_8616(
    candidates: tuple[_ConditionCandidate8616, ...],
) -> _ProvenCondition8616 | MemoryLiveOutFailureKind8616:
    """Require all reachable uses to have compatible explicit condition types."""
    typed: list[_ProvenCondition8616] = []
    for use, condition, signedness, failure in candidates:
        if failure is not None or condition is None or signedness is None:
            return failure or MemoryLiveOutFailureKind8616.CONDITION_UNSUPPORTED
        typed.append((use, condition, signedness))
    if len({item[2] for item in typed}) != 1:
        return MemoryLiveOutFailureKind8616.SIGNEDNESS_CONFLICT
    return typed[0]


def _condition_candidates_8616(
    uses: tuple[StorageUseEvidence8616, ...],
    conditions: tuple[ConditionIR, ...],
    storage: StorageIdentity8616,
) -> tuple[_ConditionCandidate8616, ...]:
    """Activate only exact memory uses attributed to typed conditions."""
    candidates: list[_ConditionCandidate8616] = []
    for use in uses:
        condition, signedness, failure = _condition_for_use_8616(conditions, storage, use)
        if failure is not MemoryLiveOutFailureKind8616.CONDITION_NOT_FOUND:
            candidates.append((use, condition, signedness, failure))
    return tuple(candidates)


def materialize_memory_live_out_candidate_8616(
    artifact: SSAFunctionArtifact,
    output_view: TerminalMemoryOutputViewFact8616,
    caller_addr: int,
    callee_addr: int,
    callsite_addr: int,
    accepted_target_addrs: tuple[int, ...],
    conditions: tuple[ConditionIR, ...],
) -> MemoryLiveOutCandidateResult8616:
    """Materialize one activated direct-memory output candidate or refuse."""
    alias_output = output_view.alias_output
    output = alias_output.terminal_output
    if not output_view.complete:
        raise RuntimeError("Types/Lowering received an incomplete Widening output view")
    storage = StorageIdentity8616(
        StorageIdentityKind8616.MEMORY, output_view.width, output_view.address
    )
    uses = tuple(
        StorageUseEvidence8616(
            access.block_addr,
            access.instr_index,
            access.instr_addr,
            callsite_addr,
        )
        for access in output_view.accesses
    )
    condition_candidates = _condition_candidates_8616(uses, conditions, storage)
    if not condition_candidates:
        return MemoryLiveOutCandidateResult8616(False)
    if not storage.is_exact:
        raise RuntimeError("Widening published an inexact direct-memory view")
    definitions = resolve_storage_call_output_definitions_8616(
        artifact,
        caller_addr,
        callsite_addr,
        callee_addr,
        accepted_target_addrs,
        (storage,),
    )
    if not definitions.complete:
        conflict = definitions.verdict is CallOutputDefinitionVerdict8616.CONFLICT
        return MemoryLiveOutCandidateResult8616(
            True,
            failure=(
                MemoryLiveOutFailureKind8616.CALL_OUTPUT_DEFINITION_CONFLICT
                if conflict
                else MemoryLiveOutFailureKind8616.CALL_OUTPUT_DEFINITION_REFUSED
            ),
            definition_failure=definitions.failure,
        )
    paths = tuple(
        (
            candidate,
            prove_memory_live_out_path_8616(
                artifact,
                definitions,
                storage,
                candidate[0],
            ),
        )
        for candidate in condition_candidates
    )
    path_failure = memory_live_out_path_failure_8616(
        tuple(path for _candidate, path in paths)
    )
    if path_failure is not None:
        return MemoryLiveOutCandidateResult8616(True, failure=path_failure)
    clean_candidates = tuple(
        candidate
        for candidate, path in paths
        if path.verdict is MemoryLiveOutPathVerdict8616.CLEAN
    )
    if not clean_candidates:
        fact = MemoryLiveOutUseFact8616(
            storage,
            output_view,
            MemoryLiveOutUseDisposition8616.NOT_REACHED,
        )
        return MemoryLiveOutCandidateResult8616(True, fact=fact)
    selected = _select_clean_condition_8616(clean_candidates)
    if isinstance(selected, MemoryLiveOutFailureKind8616):
        return MemoryLiveOutCandidateResult8616(True, failure=selected)
    use, condition, signedness = selected
    fact = MemoryLiveOutUseFact8616(
        storage,
        output_view,
        MemoryLiveOutUseDisposition8616.USED,
        use,
        signedness,
        condition,
    )
    if output.disposition is TerminalMemoryOutputDisposition8616.CONDITIONAL:
        return MemoryLiveOutCandidateResult8616(True, fact=fact)
    provenance = definitions.provenance
    if provenance is None:
        raise RuntimeError("complete CALL_OUTPUT lost provenance")
    trial = StorageTrial8616(
        callee_addr=callee_addr,
        caller_addr=caller_addr,
        callsite_addr=callsite_addr,
        role=StorageTrialRole8616.LIVE_OUT,
        logical_index=0,
        piece_index=0,
        piece_count=1,
        storage=storage,
        reaching_definition=definitions.definitions[0],
        use=use,
        signedness=signedness,
        value_class=StorageTrialValueClass8616.VALUE,
        provenance=provenance,
    )
    return MemoryLiveOutCandidateResult8616(True, fact=fact, trial=trial)
