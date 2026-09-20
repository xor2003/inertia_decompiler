"""Require positive discard evidence before resolving recursive void outputs."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.caller_return_use_contracts import (
    CallerReturnUseFact8616,
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_contracts import (
    CallsiteStorageTrials8616,
    StorageTrialStats8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_return_trial_collection import (
    collect_function_return_storage_trials_8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_solver import resolve_program_storage_trials_8616
from test_x86_16_interprocedural_storage_return_passthrough import (
    FUNCTION_ADDR,
    _evidence,
    _fact,
    _inputs,
    _project_and_function,
)


def _closed_discard_census():
    discarded = CallerReturnUseFact8616(
        caller_addr=0x2000, callsite_addr=0x2010,
        verdict=CallerReturnUseVerdict8616.UNUSED,
        kind=CallsiteReturnUseKind8616.CLOBBERED, witness_instruction_addr=0x2013,
    )
    inputs = _inputs()
    external = CallsiteStorageTrials8616(
        caller_addr=discarded.caller_addr, callee_addr=FUNCTION_ADDR,
        callsite_addr=discarded.callsite_addr, stack_delta=0,
    )
    inputs = replace(
        inputs, stats=StorageTrialStats8616(2, 2, 2, 2),
        trials=replace(inputs.trials,
                       expected_callsite_addrs=(*inputs.trials.expected_callsite_addrs, external.callsite_addr),
                       callsites=(*inputs.trials.callsites, external)),
    )
    evidence = _evidence(_fact())
    evidence = replace(
        evidence, verdict=CallerReturnUseVerdict8616.UNUSED,
        raw_fact_count=2, normalized_fact_count=2, classified_fact_count=1, materialized_count=1,
        unused_callsite_count=1, facts=(*evidence.facts, discarded),
        callsite_addrs=(*evidence.callsite_addrs, discarded.callsite_addr),
    )
    return inputs, evidence


def _collected():
    project, function = _project_and_function()
    inputs, evidence = _closed_discard_census()
    collection = collect_function_return_storage_trials_8616(project, function, inputs, evidence)
    assert collection.complete
    return collection


def test_independent_discard_proof_resolves_recursive_empty_output():
    collection = _collected()
    resolved = resolve_program_storage_trials_8616((collection.trials,))
    contract = resolved.contract_for(FUNCTION_ADDR)
    assert contract is not None
    assert contract.outputs == ()
    assert resolved.stats.raw_fact_count == resolved.stats.materialized_count == 2
    assert resolved.stats.complete
    assert contract.callsites[0].return_passthroughs
    assert contract.callsites[1].discarded_return == collection.trials.callsites[1].discarded_return
    assert contract.callsites[1].discarded_return.observation.verdict is CallerReturnUseVerdict8616.UNUSED


def test_contradictory_unused_observation_refuses_at_collection_boundary():
    project, function = _project_and_function()
    inputs, evidence = _closed_discard_census()
    recursive, unused = evidence.facts
    contradictory = replace(unused, kind=CallsiteReturnUseKind8616.VALUE)
    evidence = replace(evidence, facts=(recursive, contradictory))
    collection = collect_function_return_storage_trials_8616(project, function, inputs, evidence)
    assert not collection.complete
    assert collection.failures


@pytest.mark.parametrize("corruption", ["missing", "unknown", "witness", "caller", "callee", "value_use", "census", "extra_call", "internal_only"])
def test_incomplete_or_conflicting_discard_cannot_seed_empty_output(corruption):
    trials = _collected().trials
    recursive, external = trials.callsites
    proof = external.discarded_return
    assert proof is not None
    if corruption == "missing":
        external = replace(external, discarded_return=None)
    elif corruption == "unknown":
        external = replace(external, discarded_return=replace(
            proof, observation=replace(proof.observation, verdict=CallerReturnUseVerdict8616.UNKNOWN)))
    elif corruption == "witness":
        external = replace(external, discarded_return=replace(
            proof, observation=replace(proof.observation, witness_instruction_addr=None)))
    elif corruption == "caller":
        external = replace(external, caller_addr=0x3000)
    elif corruption == "callee":
        external = replace(external, discarded_return=replace(proof, callee_addr=0x3000))
    elif corruption == "value_use":
        external = replace(external, discarded_return=replace(
            proof, observation=replace(proof.observation, kind=CallsiteReturnUseKind8616.VALUE)))
    elif corruption == "census":
        trials = replace(trials, caller_census_complete=False)
    elif corruption == "internal_only":
        proof = replace(proof, observation=replace(proof.observation, caller_addr=FUNCTION_ADDR))
        external = replace(external, caller_addr=FUNCTION_ADDR, discarded_return=proof)
    else:
        trials = replace(trials, expected_callsite_addrs=(*trials.expected_callsite_addrs, 0x3010))
    trials = replace(trials, callsites=(recursive, external))
    resolved = resolve_program_storage_trials_8616((trials,))
    assert resolved.contract_for(FUNCTION_ADDR) is None
    assert resolved.resolutions[0].failures


def test_value_observing_caller_keeps_output_despite_another_discard():
    from test_x86_16_interprocedural_storage_return_passthrough import _direct_ax_return_trial

    trials = _collected().trials
    value = _direct_ax_return_trial(caller_addr=0x3000, callsite_addr=0x3010)
    observed = CallsiteStorageTrials8616(
        caller_addr=value.caller_addr, callee_addr=value.callee_addr,
        callsite_addr=value.callsite_addr, returns=(value,), stack_delta=0,
    )
    trials = replace(trials, callsites=(*trials.callsites, observed),
                     expected_callsite_addrs=(*trials.expected_callsite_addrs, observed.callsite_addr))
    resolved = resolve_program_storage_trials_8616((trials,))
    contract = resolved.contract_for(FUNCTION_ADDR)
    assert contract is not None
    assert len(contract.outputs) == 1
    assert contract.outputs[0].pieces[0].register == "ax"
    assert contract.callsites[1].discarded_return is not None


def test_discard_and_value_use_at_same_callsite_conflict():
    from angr_platforms.X86_16.lowering.interprocedural_storage_contracts import StorageTrialFailureKind8616
    from test_x86_16_interprocedural_storage_return_passthrough import _direct_ax_return_trial

    trials = _collected().trials
    recursive, external = trials.callsites
    trials = replace(trials, callsites=(recursive, replace(external, returns=(_direct_ax_return_trial(),))))
    resolution = resolve_program_storage_trials_8616((trials,)).resolutions[0]
    assert resolution.contract is None
    assert StorageTrialFailureKind8616.CALLSITE_SET_CONFLICT in resolution.failures


def test_worker_evidence_codec_reconstructs_same_discard_contract():
    import json

    from inertia_decompiler.discovery_cache_contract import (
        caller_return_use_evidence_from_record_8616,
        caller_return_use_evidence_record_8616,
    )

    inputs, evidence = _closed_discard_census()
    restored = caller_return_use_evidence_from_record_8616(
        json.loads(json.dumps(caller_return_use_evidence_record_8616(evidence))))
    project, function = _project_and_function()
    rebuilt = collect_function_return_storage_trials_8616(project, function, inputs, restored)
    original = _collected()
    assert rebuilt.trials == original.trials
    assert resolve_program_storage_trials_8616((rebuilt.trials,)) == resolve_program_storage_trials_8616((original.trials,))


@pytest.mark.parametrize("corruption", ["binding", "both", "witness"])
def test_atomic_publication_refuses_lost_or_corrupted_discard_proof(corruption):
    from angr_platforms.X86_16.lowering.interprocedural_storage_transaction import (
        apply_program_storage_resolution_8616,
        program_storage_resolution_8616,
    )
    from angr_platforms.X86_16.pipeline.errors import PipelineHardError

    resolved = resolve_program_storage_trials_8616((_collected().trials,))
    project = SimpleNamespace()
    assert apply_program_storage_resolution_8616(project, resolved)
    function = resolved.resolutions[0]
    contract = function.contract
    recursive, external = contract.callsites
    original_proof = external.discarded_return
    proof = None if corruption != "witness" else replace(
        original_proof, observation=replace(original_proof.observation, witness_instruction_addr=None))
    contract = replace(contract, callsites=(recursive, replace(external, discarded_return=proof)))
    corrupted = replace(resolved, resolutions=(replace(function, contract=contract),))
    if corruption == "both":
        trials = resolved.function_trials[0]
        recursive_trial, external_trial = trials.callsites
        corrupted = replace(corrupted, function_trials=(replace(
            trials, callsites=(recursive_trial, replace(external_trial, discarded_return=None))),))
    with pytest.raises(PipelineHardError, match="discarded-return"):
        apply_program_storage_resolution_8616(project, corrupted)
    assert program_storage_resolution_8616(project) is resolved
