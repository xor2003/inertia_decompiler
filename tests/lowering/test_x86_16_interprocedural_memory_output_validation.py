from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest
from inertia.ir import (
    AddressStatus,
    IRAddress,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.condition_ir import ConditionIR
from inertia.lowering.interprocedural_memory_output_validation import (
    MemoryOutputTransactionFailure8616,
    validate_memory_output_transaction_8616,
)
from inertia.lowering.interprocedural_storage_contracts import (
    CallsiteStorageTrials8616,
    FunctionStorageTrials8616,
    StorageDefinitionKind8616,
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageReachingDefinition8616,
    StorageTrial8616,
    StorageTrialRole8616,
    StorageTrialSignedness8616,
    StorageTrialValueClass8616,
    StorageUseEvidence8616,
    ValueProvenance8616,
)
from inertia.lowering.interprocedural_storage_live_out_contracts import (
    MemoryLiveOutUseDisposition8616,
    MemoryLiveOutUseFact8616,
)
from inertia.lowering.interprocedural_storage_solver import (
    resolve_program_storage_trials_8616,
)
from inertia.lowering.interprocedural_storage_transaction import (
    apply_program_storage_resolution_8616,
)
from inertia.pipeline.errors import PipelineHardError

from inertia.alias.alias_model_impl import (
    AliasStorageFacts,
    alias_facts_for_ir_address_8616,
)
from inertia.alias.storage_fact_join import (
    build_segmented_alias_range_8616,
)
from inertia.alias.terminal_memory_outputs import (
    classify_terminal_memory_output_aliases_8616,
)
from inertia.semantics.terminal_memory_output_contracts import (
    TerminalMemoryOutputDisposition8616,
    TerminalMemoryOutputEvidence8616,
    TerminalMemoryOutputFact8616,
    TerminalMemoryOutputStats8616,
    TerminalMemoryStoreSite8616,
)
from inertia.widening.terminal_memory_output_views import (
    TerminalMemoryOutputViewAccess8616,
    TerminalMemoryOutputViewFact8616,
    TerminalMemoryOutputViewKind8616,
)

CALLEE = 0x2000
CALLER = 0x3000
CALLSITE = 0x3010


def _address(offset: int, size: int) -> IRAddress:
    return IRAddress(
        MemSpace.DS,
        offset=offset,
        size=size,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )


def _accepted_resolution():
    owner_address = _address(0x1200, 2)
    terminal = TerminalMemoryOutputFact8616(
        owner_address,
        TerminalMemoryOutputDisposition8616.MUST_WRITE,
        (TerminalMemoryStoreSite8616(CALLEE, 0, CALLEE),),
        (CALLEE,),
        (CALLEE,),
    )
    terminal_evidence = TerminalMemoryOutputEvidence8616(
        CALLEE,
        (terminal,),
        None,
        TerminalMemoryOutputStats8616(1, 1, 1, 1),
    )
    alias_evidence = classify_terminal_memory_output_aliases_8616(terminal_evidence)
    assert alias_evidence.complete
    owner = alias_evidence.canonical_facts[0]
    storage = StorageIdentity8616(
        StorageIdentityKind8616.MEMORY,
        2,
        owner_address,
    )
    alias_storage = alias_facts_for_ir_address_8616(owner_address)
    assert isinstance(alias_storage, AliasStorageFacts)
    storage_range = build_segmented_alias_range_8616((owner_address,), (alias_storage,))
    assert storage_range is not None
    use = StorageUseEvidence8616(CALLER, 1, CALLSITE + 3, CALLSITE)
    view = TerminalMemoryOutputViewFact8616(
        owner,
        storage_range,
        TerminalMemoryOutputViewKind8616.WHOLE,
        0,
        (
            TerminalMemoryOutputViewAccess8616(
                CALLER,
                1,
                use.instr_addr,
                owner_address,
                2,
            ),
        ),
    )
    effect = MemoryLiveOutUseFact8616(
        storage,
        view,
        MemoryLiveOutUseDisposition8616.USED,
        use,
        StorageTrialSignedness8616.SIGN_INSENSITIVE,
        ConditionIR(
            "ne",
            IRValue(MemSpace.DS, offset=0x1200, size=2),
            IRValue(MemSpace.CONST, const=0, size=2),
            width_bits=16,
        ),
    )
    trial = StorageTrial8616(
        callee_addr=CALLEE,
        caller_addr=CALLER,
        callsite_addr=CALLSITE,
        role=StorageTrialRole8616.LIVE_OUT,
        logical_index=0,
        piece_index=0,
        piece_count=1,
        storage=storage,
        reaching_definition=StorageReachingDefinition8616(
            IRValue(MemSpace.DS, offset=0x1200, size=2),
            CALLER,
            0,
            CALLSITE,
            storage,
            StorageDefinitionKind8616.CALL_OUTPUT,
        ),
        use=use,
        signedness=StorageTrialSignedness8616.SIGN_INSENSITIVE,
        value_class=StorageTrialValueClass8616.VALUE,
        provenance=ValueProvenance8616(CALLEE, CALLSITE, 0x1200),
    )
    callsite = CallsiteStorageTrials8616(
        CALLER,
        CALLEE,
        CALLSITE,
        live_outs=(trial,),
        memory_effects=(effect,),
        stack_delta=0,
    )
    return resolve_program_storage_trials_8616(
        (FunctionStorageTrials8616(CALLEE, True, (CALLSITE,), (callsite,)),)
    )


def _replace_contract(resolution, contract):
    function_resolution = replace(resolution.resolutions[0], contract=contract)
    return replace(resolution, resolutions=(function_resolution,))


def test_complete_memory_object_transaction_is_publishable() -> None:
    resolution = _accepted_resolution()
    contract = resolution.contract_for(CALLEE)
    assert contract is not None

    evidence = validate_memory_output_transaction_8616(contract)

    assert evidence.complete
    assert evidence.stats.raw_fact_count == evidence.stats.materialized_count
    assert apply_program_storage_resolution_8616(SimpleNamespace(), resolution)


@pytest.mark.parametrize(
    ("mutation", "failure"),
    (
        (
            lambda contract: replace(contract, memory_outputs=()),
            MemoryOutputTransactionFailure8616.ORPHAN_EFFECT,
        ),
        (
            lambda contract: replace(
                contract,
                memory_outputs=(*contract.memory_outputs, contract.memory_outputs[0]),
            ),
            MemoryOutputTransactionFailure8616.DUPLICATE_OWNER,
        ),
        (
            lambda contract: replace(
                contract,
                memory_outputs=(
                    replace(
                        contract.memory_outputs[0],
                        views=(
                            replace(
                                contract.memory_outputs[0].views[0],
                                callsite_addr=CALLSITE + 2,
                            ),
                        ),
                    ),
                ),
            ),
            MemoryOutputTransactionFailure8616.CALLSITE_MISSING,
        ),
        (
            lambda contract: replace(
                contract,
                callsites=(replace(contract.callsites[0], memory_effects=()),),
            ),
            MemoryOutputTransactionFailure8616.EFFECT_MISSING,
        ),
    ),
)
def test_incoherent_memory_objects_refuse_before_project_publication(
    mutation,
    failure: MemoryOutputTransactionFailure8616,
) -> None:
    resolution = _accepted_resolution()
    contract = resolution.contract_for(CALLEE)
    assert contract is not None
    broken_contract = mutation(contract)
    broken = _replace_contract(resolution, broken_contract)

    evidence = validate_memory_output_transaction_8616(broken_contract)

    assert evidence.failure is failure
    assert evidence.stats.failure_count == 1
    project = SimpleNamespace()
    with pytest.raises(PipelineHardError, match=failure.value):
        apply_program_storage_resolution_8616(project, broken)
    assert not hasattr(project, "_inertia_interprocedural_storage_resolution_8616")
