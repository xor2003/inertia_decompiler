"""Production lifecycle tests for atomic interprocedural storage publication."""

from __future__ import annotations

from types import SimpleNamespace

import angr_platforms.X86_16.lowering.callsite_prototype_declarations as declaration_lowering
import angr_platforms.X86_16.lowering.helper_call_interfaces as helper_lowering
import angr_platforms.X86_16.lowering.interprocedural_storage_pipeline as storage_pipeline
import angr_platforms.X86_16.lowering.interprocedural_storage_prototype_application as prototype_application
import angr_platforms.X86_16.lowering.stack_prototype_materialization as stack_prototype_lowering
import pytest
from angr_platforms.X86_16.caller_return_use_contracts import (
    CallerReturnUseEvidence8616,
    CallerReturnUseFact8616,
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_collection_contracts import (
    FunctionInputStorageTrialCollection8616,
    StorageTrialCollectionVerdict8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_contracts import (
    CallsiteStorageTrials8616,
    FunctionStorageTrials8616,
    StorageTrialStats8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_pipeline import (
    FunctionStoragePublicationVerdict8616,
    collect_and_publish_function_storage_contract_8616,
    publish_and_reconcile_callsite_interfaces_8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_return_collection_contracts import (
    FunctionReturnStorageTrialCollection8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_transaction import (
    function_storage_resolution_8616,
    program_storage_resolution_8616,
)
from angr_platforms.X86_16.pipeline.errors import PipelineHardError


def _trials(
    function_addr: int,
    *,
    conflicting_stack_delta: bool = False,
) -> FunctionStorageTrials8616:
    """Build a closed zero-argument caller census for lifecycle tests."""
    callsites = [
        CallsiteStorageTrials8616(
            caller_addr=function_addr - 0x100,
            callee_addr=function_addr,
            callsite_addr=function_addr - 0xF0,
            stack_delta=0,
        )
    ]
    if conflicting_stack_delta:
        callsites.append(
            CallsiteStorageTrials8616(
                caller_addr=function_addr - 0x200,
                callee_addr=function_addr,
                callsite_addr=function_addr - 0x1F0,
                stack_delta=2,
            )
        )
    return FunctionStorageTrials8616(
        function_addr=function_addr,
        caller_census_complete=True,
        expected_callsite_addrs=tuple(
            sorted(callsite.callsite_addr for callsite in callsites)
        ),
        callsites=tuple(callsites),
    )


def _input_collection(
    function_addr: int,
    *,
    complete: bool = True,
    conflicting_stack_delta: bool = False,
) -> FunctionInputStorageTrialCollection8616:
    """Build a typed complete or refused input collection."""
    return FunctionInputStorageTrialCollection8616(
        verdict=(
            StorageTrialCollectionVerdict8616.PROVEN
            if complete
            else StorageTrialCollectionVerdict8616.UNKNOWN_REFUSE
        ),
        trials=(
            _trials(function_addr, conflicting_stack_delta=conflicting_stack_delta)
            if complete
            else FunctionStorageTrials8616(function_addr, False, (), ())
        ),
        failures=(),
        stats=(
            StorageTrialStats8616(1, 1, 1, 1)
            if complete
            else StorageTrialStats8616(failure_count=1)
        ),
    )


def _return_collection(
    inputs: FunctionInputStorageTrialCollection8616,
) -> FunctionReturnStorageTrialCollection8616:
    """Preserve one complete input census as a closed unused-return result."""
    return FunctionReturnStorageTrialCollection8616(
        verdict=StorageTrialCollectionVerdict8616.PROVEN,
        trials=inputs.trials,
        failures=(),
        stats=StorageTrialStats8616(1, 1, 1, 1),
    )


def _return_evidence(function_addr: int) -> CallerReturnUseEvidence8616:
    """Build one exact closed unused caller-return fact."""
    callsite_addr = function_addr - 0xF0
    fact = CallerReturnUseFact8616(
        caller_addr=function_addr - 0x100,
        callsite_addr=callsite_addr,
        verdict=CallerReturnUseVerdict8616.UNUSED,
        kind=CallsiteReturnUseKind8616.CLOBBERED,
        witness_instruction_addr=callsite_addr + 3,
    )
    return CallerReturnUseEvidence8616(
        target_addr=function_addr,
        verdict=CallerReturnUseVerdict8616.UNUSED,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        used_callsite_count=0,
        unused_callsite_count=1,
        callsite_addrs=(callsite_addr,),
        facts=(fact,),
    )


def _project(*function_addrs: int) -> SimpleNamespace:
    """Build one project carrying exact functions and caller-return evidence."""
    functions = {address: SimpleNamespace(addr=address) for address in function_addrs}
    return SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda *, addr, create=False: functions.get(addr),
            )
        ),
        _inertia_caller_return_use_evidence_by_addr_8616={
            address: _return_evidence(address) for address in function_addrs
        },
    )


def _install_collectors(monkeypatch, collections: dict[int, FunctionInputStorageTrialCollection8616]) -> None:
    """Install deterministic typed collection results at the lifecycle boundary."""
    caller_targets = object()

    def _returns(_project, _function, inputs, _evidence, **kwargs):
        assert kwargs["pointer_targets"] is caller_targets
        return _return_collection(inputs)

    monkeypatch.setattr(
        storage_pipeline,
        "publish_pointer_parameter_outputs_8616",
        lambda _project, _function_addr, *, function: object(),
    )
    monkeypatch.setattr(
        storage_pipeline,
        "publish_pointer_parameter_caller_targets_8616",
        lambda _project, _function_addr, *, function, outputs: caller_targets,
    )
    monkeypatch.setattr(
        storage_pipeline,
        "collect_function_input_storage_trials_8616",
        lambda _project, _codegen, function_addr: collections[function_addr],
    )
    monkeypatch.setattr(
        storage_pipeline,
        "collect_function_return_storage_trials_8616",
        _returns,
    )


def test_publication_merges_sorted_trials_and_is_replay_stable(monkeypatch) -> None:
    project = _project(0x2000, 0x3000)
    collections = {
        address: _input_collection(address) for address in (0x2000, 0x3000)
    }
    _install_collectors(monkeypatch, collections)

    first = collect_and_publish_function_storage_contract_8616(
        project,
        SimpleNamespace(cfunc=SimpleNamespace(addr=0x3000)),
    )
    second_codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x2000))
    second = collect_and_publish_function_storage_contract_8616(project, second_codegen)
    replay = collect_and_publish_function_storage_contract_8616(project, second_codegen)

    assert first.verdict is FunctionStoragePublicationVerdict8616.PUBLISHED_ACCEPTED
    assert second.verdict is FunctionStoragePublicationVerdict8616.PUBLISHED_ACCEPTED
    assert replay.verdict is FunctionStoragePublicationVerdict8616.UNCHANGED_ACCEPTED
    resolution = program_storage_resolution_8616(project)
    assert resolution is not None
    assert tuple(item.function_addr for item in resolution.function_trials) == (
        0x2000,
        0x3000,
    )
    assert tuple(item.function_addr for item in resolution.resolutions) == (
        0x2000,
        0x3000,
    )
    assert resolution.stats.complete


def test_incomplete_collection_does_not_replace_atomic_program_payload(monkeypatch) -> None:
    project = _project(0x2000, 0x3000)
    collections = {
        0x2000: _input_collection(0x2000),
        0x3000: _input_collection(0x3000, complete=False),
    }
    _install_collectors(monkeypatch, collections)
    collect_and_publish_function_storage_contract_8616(
        project,
        SimpleNamespace(cfunc=SimpleNamespace(addr=0x2000)),
    )
    before = program_storage_resolution_8616(project)

    refused = collect_and_publish_function_storage_contract_8616(
        project,
        SimpleNamespace(cfunc=SimpleNamespace(addr=0x3000)),
    )

    assert refused.verdict is FunctionStoragePublicationVerdict8616.INPUT_REFUSED
    assert refused.published is False
    assert program_storage_resolution_8616(project) is before
@pytest.mark.parametrize("failure", ("input", "return_evidence", "return_collection"))
@pytest.mark.parametrize("through_consumers", (False, True))
def test_refused_refresh_cannot_reuse_previously_accepted_contract(
    monkeypatch, failure, through_consumers,
) -> None:
    """An older complete census must not override the current refusal."""
    project = _project(0x2000)
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x2000))
    collections = {0x2000: _input_collection(0x2000)}
    _install_collectors(monkeypatch, collections)
    accepted = collect_and_publish_function_storage_contract_8616(project, codegen)
    assert accepted.verdict is FunctionStoragePublicationVerdict8616.PUBLISHED_ACCEPTED
    before = program_storage_resolution_8616(project)
    if failure == "input":
        collections[0x2000] = _input_collection(0x2000, complete=False)
    elif failure == "return_evidence":
        project._inertia_caller_return_use_evidence_by_addr_8616.clear()
    else:
        monkeypatch.setattr(
            storage_pipeline,
            "collect_function_return_storage_trials_8616",
            lambda *args, **kwargs: FunctionReturnStorageTrialCollection8616(
                verdict=StorageTrialCollectionVerdict8616.UNKNOWN_REFUSE,
                trials=collections[0x2000].trials,
                failures=(),
                stats=StorageTrialStats8616(failure_count=1),
            ),
        )

    monkeypatch.setattr(
        prototype_application,
        "apply_accepted_function_storage_prototype_8616",
        lambda *args: pytest.fail("stale contract reached a prototype consumer"),
    )
    refresh = (
        publish_and_reconcile_callsite_interfaces_8616
        if through_consumers
        else collect_and_publish_function_storage_contract_8616
    )
    with pytest.raises(PipelineHardError, match="previously accepted storage contract") as error:
        refresh(project, codegen)
    assert error.value.function_addr == 0x2000
    assert error.value.layer == "types/lowering"
    assert error.value.details.verdict is {
        "input": FunctionStoragePublicationVerdict8616.INPUT_REFUSED,
        "return_evidence": FunctionStoragePublicationVerdict8616.RETURN_EVIDENCE_UNAVAILABLE,
        "return_collection": FunctionStoragePublicationVerdict8616.RETURN_REFUSED,
    }[failure]
    assert program_storage_resolution_8616(project) is before


def test_complete_conflicting_trials_publish_typed_refusal(monkeypatch) -> None:
    project = _project(0x2000)
    collections = {
        0x2000: _input_collection(0x2000, conflicting_stack_delta=True),
    }
    _install_collectors(monkeypatch, collections)

    result = collect_and_publish_function_storage_contract_8616(
        project,
        SimpleNamespace(cfunc=SimpleNamespace(addr=0x2000)),
    )

    assert result.verdict is FunctionStoragePublicationVerdict8616.PUBLISHED_REFUSED
    assert result.published
    function_result = function_storage_resolution_8616(project, 0x2000)
    assert function_result is not None
    assert function_result.contract is None
    assert function_result.stats.failure_count > 0


def test_pointer_outputs_publish_before_input_collection_refusal(monkeypatch) -> None:
    events: list[str] = []
    project = _project(0x2000)
    monkeypatch.setattr(
        storage_pipeline,
        "publish_pointer_parameter_outputs_8616",
        lambda _project, _function_addr, *, function: events.append("pointer-output")
        or "outputs",
    )
    monkeypatch.setattr(
        storage_pipeline,
        "publish_pointer_parameter_caller_targets_8616",
        lambda _project, _function_addr, *, function, outputs: events.append(f"caller-target:{outputs}"),
    )
    monkeypatch.setattr(
        storage_pipeline,
        "collect_function_input_storage_trials_8616",
        lambda _project, _codegen, _function_addr: (
            events.append("input") or _input_collection(0x2000, complete=False)
        ),
    )

    result = collect_and_publish_function_storage_contract_8616(
        project,
        SimpleNamespace(cfunc=SimpleNamespace(addr=0x2000)),
    )

    assert result.verdict is FunctionStoragePublicationVerdict8616.INPUT_REFUSED
    assert events == ["pointer-output", "caller-target:outputs", "input"]


def test_lifecycle_applies_storage_prototype_before_legacy_consumers(monkeypatch) -> None:
    events: list[str] = []
    monkeypatch.setattr(
        storage_pipeline,
        "collect_and_publish_function_storage_contract_8616",
        lambda _project, _codegen: events.append("publish"),
    )
    monkeypatch.setattr(
        prototype_application,
        "apply_accepted_function_storage_prototype_8616",
        lambda _project, _codegen: (
            events.append("apply")
            or SimpleNamespace(changed=True, blocks_legacy_reconciliation=False)
        ),
    )
    monkeypatch.setattr(
        stack_prototype_lowering,
        "reconcile_exact_stack_argument_prototype_8616",
        lambda _project, _codegen: events.append("legacy") or False,
    )
    monkeypatch.setattr(
        helper_lowering,
        "materialize_known_helper_call_interfaces_8616",
        lambda _project, _codegen: events.append("helpers") or False,
    )
    monkeypatch.setattr(
        declaration_lowering,
        "materialize_callsite_prototype_declarations_8616",
        lambda _project, _codegen: events.append("declarations") or False,
    )

    changed = publish_and_reconcile_callsite_interfaces_8616(object(), object())

    assert changed is True
    assert events == ["publish", "apply", "legacy", "helpers", "declarations"]


def test_lifecycle_blocks_width_fallback_after_typed_application_refusal(monkeypatch) -> None:
    monkeypatch.setattr(
        storage_pipeline,
        "collect_and_publish_function_storage_contract_8616",
        lambda _project, _codegen: None,
    )
    monkeypatch.setattr(
        prototype_application,
        "apply_accepted_function_storage_prototype_8616",
        lambda _project, _codegen: SimpleNamespace(
            changed=False,
            blocks_legacy_reconciliation=True,
        ),
    )
    monkeypatch.setattr(
        stack_prototype_lowering,
        "reconcile_exact_stack_argument_prototype_8616",
        lambda _project, _codegen: pytest.fail("legacy reconciliation must be blocked"),
    )
    monkeypatch.setattr(
        helper_lowering,
        "materialize_known_helper_call_interfaces_8616",
        lambda _project, _codegen: False,
    )
    monkeypatch.setattr(
        declaration_lowering,
        "materialize_callsite_prototype_declarations_8616",
        lambda _project, _codegen: False,
    )

    assert publish_and_reconcile_callsite_interfaces_8616(object(), object()) is False
