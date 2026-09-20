"""Collect function-wide direct segmented-memory live-out trials.

Layer: Types/Lowering.
Responsibility: join callee terminal-memory facts with every caller SSA census,
delegate candidate proof/materialization, and close function-wide evidence stats.
This module does not traverse CFGs, infer aliases, project C, or publish contracts.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import replace

from ..alias.terminal_memory_outputs import classify_terminal_memory_output_aliases_8616
from ..ir.condition_ir import ConditionIR
from ..semantics.call_stack_effect_pipeline import (
    semantic_function_ssa_artifact_at_address_8616,
)
from ..semantics.terminal_memory_outputs import collect_terminal_memory_output_evidence_8616
from .condition_transfer import collect_typed_condition_artifacts_8616
from .interprocedural_storage_caller_context import (
    CallerSSAContextVerdict8616,
    caller_ssa_context_for_callsite_8616,
)
from .interprocedural_storage_contracts import (
    CallsiteStorageTrials8616,
    StorageTrialStats8616,
)
from .interprocedural_storage_live_out_contracts import (
    CallsiteMemoryLiveOutEvidence8616,
    FunctionMemoryLiveOutCollection8616,
    MemoryLiveOutCollectionVerdict8616,
    MemoryLiveOutFailure8616,
    MemoryLiveOutFailureKind8616,
)
from .interprocedural_storage_live_out_contracts import (
    refused_memory_live_out_collection_8616 as _failed_8616,
)
from .interprocedural_storage_live_out_flow import collect_callsite_memory_live_out_8616
from .pointer_parameter_caller_target_contracts import (
    PointerParameterCallerTarget8616,
    PointerParameterCallerTargetEvidence8616,
)


def attach_callsite_memory_live_out_evidence_8616(
    callsite: CallsiteStorageTrials8616,
    evidence: tuple[CallsiteMemoryLiveOutEvidence8616, ...],
) -> CallsiteStorageTrials8616:
    """Attach the unique exact live-out projection to one callsite contract."""
    matches = tuple(item for item in evidence if item.callsite_addr == callsite.callsite_addr)
    if len(matches) != 1:
        raise RuntimeError("complete memory live-out collection lost exact callsite evidence")
    match = matches[0]
    if match.caller_addr != callsite.caller_addr or match.callee_addr != callsite.callee_addr:
        raise RuntimeError("memory live-out callsite identity changed during projection")
    return replace(
        callsite,
        live_outs=match.trials,
        memory_effects=match.facts,
        pointer_effects=match.pointer_effects,
    )


def _pointer_effects_by_callsite_8616(
    callee_addr: int,
    callsites: tuple[CallsiteStorageTrials8616, ...],
    evidence: PointerParameterCallerTargetEvidence8616 | None,
) -> tuple[
    dict[int, tuple[PointerParameterCallerTarget8616, ...]] | None,
    MemoryLiveOutFailure8616 | None,
]:
    """Validate and partition exact dynamic effects by known callsite."""
    expected = {item.callsite_addr: item for item in callsites}
    if len(expected) != len(callsites):
        return None, MemoryLiveOutFailure8616(
            MemoryLiveOutFailureKind8616.POINTER_TARGET_CONFLICT,
            callee_addr,
        )
    empty: dict[int, tuple[PointerParameterCallerTarget8616, ...]] = dict.fromkeys(expected, ())
    if evidence is None:
        return empty, None
    if not evidence.complete:
        return None, MemoryLiveOutFailure8616(
            MemoryLiveOutFailureKind8616.POINTER_TARGET_REFUSED,
            callee_addr,
            pointer_failure=evidence.failure,
        )
    if evidence.callee_addr != callee_addr:
        return None, MemoryLiveOutFailure8616(
            MemoryLiveOutFailureKind8616.POINTER_TARGET_CONFLICT,
            callee_addr,
        )
    grouped: dict[int, list[PointerParameterCallerTarget8616]] = {
        callsite_addr: [] for callsite_addr in expected
    }
    for effect in evidence.facts:
        callsite = expected.get(effect.callsite_addr)
        if (
            callsite is None
            or not effect.complete
            or effect.callee_addr != callee_addr
            or effect.caller_addr != callsite.caller_addr
        ):
            return None, MemoryLiveOutFailure8616(
                MemoryLiveOutFailureKind8616.POINTER_TARGET_CONFLICT,
                callee_addr,
                effect.caller_addr,
                effect.callsite_addr,
            )
        if any(item.logical_index == effect.logical_index for item in grouped[effect.callsite_addr]):
            return None, MemoryLiveOutFailure8616(
                MemoryLiveOutFailureKind8616.POINTER_TARGET_CONFLICT,
                callee_addr,
                effect.caller_addr,
                effect.callsite_addr,
            )
        grouped[effect.callsite_addr].append(effect)
    if evidence.facts and any(not grouped[callsite_addr] for callsite_addr in expected):
        return None, MemoryLiveOutFailure8616(
            MemoryLiveOutFailureKind8616.POINTER_TARGET_CONFLICT,
            callee_addr,
        )
    return {
        callsite_addr: tuple(sorted(items, key=lambda item: item.logical_index))
        for callsite_addr, items in grouped.items()
    }, None


def _pointer_only_collection_8616(
    callee_addr: int,
    callsites: tuple[CallsiteStorageTrials8616, ...],
    pointer_by_callsite: dict[int, tuple[PointerParameterCallerTarget8616, ...]],
    pointer_count: int,
) -> FunctionMemoryLiveOutCollection8616:
    """Retain closed pointer effects when the callee has no direct-memory output."""
    sites = tuple(
        CallsiteMemoryLiveOutEvidence8616(
            site.caller_addr, callee_addr, site.callsite_addr,
            pointer_effects=pointer_by_callsite[site.callsite_addr],
        )
        for site in callsites
    )
    return FunctionMemoryLiveOutCollection8616(
        MemoryLiveOutCollectionVerdict8616.PROVEN,
        sites, (),
        StorageTrialStats8616(pointer_count, pointer_count, pointer_count, pointer_count),
    )


def _caller_conditions_8616(
    project: object,
    caller_addr: int,
    cache: dict[tuple[int, int], tuple[ConditionIR, ...]],
) -> tuple[ConditionIR, ...]:
    """Keep equal-address conditions isolated by their authoritative project owner."""
    key = (id(project), caller_addr)
    conditions = cache.get(key)
    if conditions is None:
        collected, _edge_evidence = collect_typed_condition_artifacts_8616(project, caller_addr)
        conditions = tuple(collected)
        cache[key] = conditions
    return conditions


def collect_function_memory_live_out_trials_8616(
    project: object,
    callee_addr: int,
    callsites: tuple[CallsiteStorageTrials8616, ...],
    accepted_target_addrs: tuple[int, ...],
    *,
    pointer_targets: PointerParameterCallerTargetEvidence8616 | None = None,
) -> FunctionMemoryLiveOutCollection8616:
    """Collect exact direct and dynamic memory effects for one callee."""
    pointer_by_callsite, pointer_failure = _pointer_effects_by_callsite_8616(
        callee_addr,
        callsites,
        pointer_targets,
    )
    pointer_count = 0 if pointer_targets is None else len(pointer_targets.facts)
    if pointer_failure is not None or pointer_by_callsite is None:
        return _failed_8616(
            pointer_failure
            or MemoryLiveOutFailure8616(
                MemoryLiveOutFailureKind8616.POINTER_TARGET_REFUSED,
                callee_addr,
            ),
            max(1, pointer_count),
            0,
        )
    callee_ssa = semantic_function_ssa_artifact_at_address_8616(project, callee_addr)
    if callee_ssa.artifact is None:
        return _failed_8616(
            MemoryLiveOutFailure8616(
                MemoryLiveOutFailureKind8616.CALLEE_SSA_UNAVAILABLE,
                callee_addr,
                ssa_failure=callee_ssa.failure,
            ),
            max(1, pointer_count),
            pointer_count,
        )
    terminal = collect_terminal_memory_output_evidence_8616(project, callee_ssa.artifact)
    if not terminal.complete:
        return _failed_8616(
            MemoryLiveOutFailure8616(
                MemoryLiveOutFailureKind8616.TERMINAL_EVIDENCE_REFUSED,
                callee_addr,
                terminal_failure=terminal.failure,
            ),
            max(1, pointer_count + terminal.stats.raw_fact_count),
            pointer_count + terminal.stats.normalized_fact_count,
        )
    aliases = classify_terminal_memory_output_aliases_8616(terminal)
    if not aliases.complete:
        return _failed_8616(
            MemoryLiveOutFailure8616(
                MemoryLiveOutFailureKind8616.ALIAS_EVIDENCE_REFUSED,
                callee_addr,
                alias_failure=aliases.failure,
            ),
            max(1, pointer_count + aliases.stats.raw_fact_count),
            pointer_count + aliases.stats.normalized_fact_count,
        )
    if not aliases.facts:
        return _pointer_only_collection_8616(
            callee_addr, callsites, pointer_by_callsite, pointer_count
        )

    targets = tuple(dict.fromkeys((callee_addr, *accepted_target_addrs)))
    conditions_by_caller: dict[tuple[int, int], tuple[ConditionIR, ...]] = {}
    collected_sites: list[CallsiteMemoryLiveOutEvidence8616] = []
    raw = normalized = materialized = pointer_count
    for site in sorted(callsites, key=lambda item: (item.callsite_addr, item.caller_addr)):
        context = caller_ssa_context_for_callsite_8616(
            project, callee_addr, site.caller_addr, site.callsite_addr
        )
        if context.verdict is CallerSSAContextVerdict8616.CONFLICT:
            return _failed_8616(
                MemoryLiveOutFailure8616(
                    MemoryLiveOutFailureKind8616.CALLER_CONTEXT_CONFLICT,
                    callee_addr, site.caller_addr, site.callsite_addr,
                ),
                max(1, raw), normalized,
            )
        caller_project = context.evidence_project if context.complete else project
        caller_function = context.caller_function if context.complete else None
        caller_ssa = semantic_function_ssa_artifact_at_address_8616(
            caller_project,
            site.caller_addr,
            function=caller_function,
        )
        artifact = caller_ssa.artifact
        if artifact is None:
            return _failed_8616(
                MemoryLiveOutFailure8616(
                    MemoryLiveOutFailureKind8616.CALLER_SSA_UNAVAILABLE,
                    callee_addr,
                    site.caller_addr,
                    site.callsite_addr,
                    ssa_failure=caller_ssa.failure,
                ),
                max(1, raw),
                normalized,
            )
        conditions = _caller_conditions_8616(
            caller_project, site.caller_addr, conditions_by_caller
        )
        collected = collect_callsite_memory_live_out_8616(
            aliases, artifact, site, targets, conditions
        )
        raw += collected.stats.raw_fact_count
        normalized += collected.stats.normalized_fact_count
        if not collected.complete:
            return _failed_8616(collected.failures[0], max(1, raw), normalized)
        materialized += collected.stats.materialized_count
        collected_sites.append(
            replace(
                collected.callsites[0],
                pointer_effects=pointer_by_callsite[site.callsite_addr],
            )
        )
    stats = StorageTrialStats8616(raw, normalized, materialized, materialized)
    return FunctionMemoryLiveOutCollection8616(
        MemoryLiveOutCollectionVerdict8616.PROVEN,
        tuple(collected_sites),
        (),
        stats,
    )


__all__ = ["collect_function_memory_live_out_trials_8616"]
