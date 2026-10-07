from __future__ import annotations

from inertia.ir import (
    AddressStatus,
    IRAddress,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.condition_ir import ConditionIR
from inertia.lowering.interprocedural_memory_output_object_contracts import (
    MemoryOutputObjectFailure8616,
)
from inertia.lowering.interprocedural_memory_output_objects import (
    join_memory_output_object_contracts_8616,
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

from inertia.alias.alias_model_impl import (
    AliasStorageFacts,
    alias_facts_for_ir_address_8616,
)
from inertia.alias.storage_fact_join import (
    build_segmented_alias_range_8616,
)
from inertia.alias.terminal_memory_outputs import (
    TerminalMemoryAliasFact8616,
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


def _address(offset: int, size: int, space: MemSpace = MemSpace.DS) -> IRAddress:
    return IRAddress(
        space,
        offset=offset,
        size=size,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )


def _owner(
    space: MemSpace = MemSpace.DS,
    disposition: TerminalMemoryOutputDisposition8616 = (
        TerminalMemoryOutputDisposition8616.MUST_WRITE
    ),
) -> TerminalMemoryAliasFact8616:
    address = _address(0x1200, 2, space)
    terminal = TerminalMemoryOutputFact8616(
        address,
        disposition,
        (TerminalMemoryStoreSite8616(CALLEE, 0, CALLEE),),
        (CALLEE,),
        (CALLEE,) if disposition is TerminalMemoryOutputDisposition8616.MUST_WRITE else (),
    )
    evidence = TerminalMemoryOutputEvidence8616(
        CALLEE,
        (terminal,),
        None,
        TerminalMemoryOutputStats8616(1, 1, 1, 1),
    )
    aliases = classify_terminal_memory_output_aliases_8616(evidence)
    assert aliases.complete
    return aliases.canonical_facts[0]


def _effect_and_trial(
    owner: TerminalMemoryAliasFact8616,
    offset: int,
    size: int,
    logical_index: int,
    *,
    caller: int = CALLER,
    callsite: int = CALLSITE,
) -> tuple[MemoryLiveOutUseFact8616, StorageTrial8616]:
    address = _address(offset, size, owner.storage_range.space)
    storage = StorageIdentity8616(StorageIdentityKind8616.MEMORY, size, address)
    use = StorageUseEvidence8616(caller, logical_index + 1, callsite + 3, callsite)
    alias_storage = alias_facts_for_ir_address_8616(address)
    assert isinstance(alias_storage, AliasStorageFacts)
    storage_range = build_segmented_alias_range_8616((address,), (alias_storage,))
    assert storage_range is not None
    view = TerminalMemoryOutputViewFact8616(
        owner,
        storage_range,
        (
            TerminalMemoryOutputViewKind8616.WHOLE
            if address == owner.terminal_output.address
            else TerminalMemoryOutputViewKind8616.CONTAINED
        ),
        address.offset - owner.storage_range.offset,
        (
            TerminalMemoryOutputViewAccess8616(
                caller,
                logical_index + 1,
                use.instr_addr,
                address,
                size,
            ),
        ),
    )
    condition = ConditionIR(
        "ne",
        IRValue(address.space, offset=offset, size=size),
        IRValue(MemSpace.CONST, const=0, size=size),
        width_bits=size * 8,
    )
    fact = MemoryLiveOutUseFact8616(
        storage,
        view,
        MemoryLiveOutUseDisposition8616.USED,
        use,
        StorageTrialSignedness8616.SIGN_INSENSITIVE,
        condition,
    )
    trial = StorageTrial8616(
        callee_addr=CALLEE,
        caller_addr=caller,
        callsite_addr=callsite,
        role=StorageTrialRole8616.LIVE_OUT,
        logical_index=logical_index,
        piece_index=0,
        piece_count=1,
        storage=storage,
        reaching_definition=StorageReachingDefinition8616(
            IRValue(address.space, offset=offset, size=size),
            caller,
            0,
            callsite,
            storage,
            StorageDefinitionKind8616.CALL_OUTPUT,
        ),
        use=use,
        signedness=StorageTrialSignedness8616.SIGN_INSENSITIVE,
        value_class=StorageTrialValueClass8616.VALUE,
        provenance=ValueProvenance8616(CALLEE, callsite, offset),
    )
    assert fact.complete and trial.is_complete
    return fact, trial


def _callsite(
    *pairs: tuple[MemoryLiveOutUseFact8616, StorageTrial8616],
    caller: int = CALLER,
    callsite: int = CALLSITE,
) -> CallsiteStorageTrials8616:
    return CallsiteStorageTrials8616(
        caller,
        CALLEE,
        callsite,
        live_outs=tuple(trial for _effect, trial in pairs),
        memory_effects=tuple(effect for effect, _trial in pairs),
        stack_delta=0,
    )


def test_whole_and_byte_views_form_one_memory_output_object() -> None:
    owner = _owner()
    callsite = _callsite(
        _effect_and_trial(owner, 0x1200, 2, 0),
        _effect_and_trial(owner, 0x1201, 1, 1),
    )
    trials = FunctionStorageTrials8616(CALLEE, True, (CALLSITE,), (callsite,))

    contract = resolve_program_storage_trials_8616((trials,)).contract_for(CALLEE)

    assert contract is not None
    assert contract.outputs == ()
    assert len(contract.memory_outputs) == 1
    memory_object = contract.memory_outputs[0]
    assert memory_object.alias_output == owner
    assert tuple(view.effect.storage.address for view in memory_object.views) == (
        _address(0x1200, 2),
        _address(0x1201, 1),
    )
    assert tuple(trial.storage.address for trial in contract.callsites[0].live_outs) == (
        _address(0x1200, 2),
        _address(0x1201, 1),
    )


def test_disjoint_callers_share_one_owner_and_retain_both_views() -> None:
    owner = _owner()
    first = _callsite(_effect_and_trial(owner, 0x1200, 1, 0))
    second_caller = 0x4000
    second_callsite = 0x4010
    second = _callsite(
        _effect_and_trial(
            owner,
            0x1201,
            1,
            0,
            caller=second_caller,
            callsite=second_callsite,
        ),
        caller=second_caller,
        callsite=second_callsite,
    )
    trials = FunctionStorageTrials8616(
        CALLEE,
        True,
        (CALLSITE, second_callsite),
        (second, first),
    )

    contract = resolve_program_storage_trials_8616((trials,)).contract_for(CALLEE)

    assert contract is not None
    assert len(contract.memory_outputs) == 1
    assert tuple(
        view.effect.storage.address.offset for view in contract.memory_outputs[0].views
    ) == (0x1200, 0x1201)


def test_ds_and_es_owners_remain_separate_memory_objects() -> None:
    ds_owner = _owner(MemSpace.DS)
    es_owner = _owner(MemSpace.ES)
    callsite = _callsite(
        _effect_and_trial(es_owner, 0x1200, 2, 0),
        _effect_and_trial(ds_owner, 0x1200, 2, 1),
    )

    evidence = join_memory_output_object_contracts_8616((callsite,))

    assert evidence.complete
    assert evidence.stats.raw_fact_count == evidence.stats.materialized_count == 2
    assert tuple(item.alias_output.storage_range.space for item in evidence.objects) == (
        MemSpace.DS,
        MemSpace.ES,
    )


def test_conflicting_alias_owners_refuse_without_partial_objects() -> None:
    must_write = _owner(disposition=TerminalMemoryOutputDisposition8616.MUST_WRITE)
    conditional = _owner(disposition=TerminalMemoryOutputDisposition8616.CONDITIONAL)
    first = _callsite(_effect_and_trial(must_write, 0x1200, 2, 0))
    second_effect, _unused_trial = _effect_and_trial(
        conditional,
        0x1200,
        2,
        0,
        caller=0x4000,
        callsite=0x4010,
    )
    second = CallsiteStorageTrials8616(
        0x4000,
        CALLEE,
        0x4010,
        memory_effects=(second_effect,),
        stack_delta=0,
    )

    evidence = join_memory_output_object_contracts_8616((first, second))

    assert evidence.objects == ()
    assert evidence.failure is MemoryOutputObjectFailure8616.OWNER_CONFLICT
    assert evidence.stats.failure_count == 1


def test_missing_must_write_trial_refuses_without_partial_objects() -> None:
    effect, _unused_trial = _effect_and_trial(_owner(), 0x1200, 2, 0)
    callsite = CallsiteStorageTrials8616(
        CALLER,
        CALLEE,
        CALLSITE,
        memory_effects=(effect,),
        stack_delta=0,
    )

    evidence = join_memory_output_object_contracts_8616((callsite,))

    assert evidence.objects == ()
    assert evidence.failure is MemoryOutputObjectFailure8616.MISSING_TRIAL
    assert evidence.stats.raw_fact_count == evidence.stats.normalized_fact_count == 1


def test_duplicate_effect_refuses_without_consuming_one_copy() -> None:
    effect, trial = _effect_and_trial(_owner(), 0x1200, 2, 0)
    callsite = CallsiteStorageTrials8616(
        CALLER,
        CALLEE,
        CALLSITE,
        live_outs=(trial,),
        memory_effects=(effect, effect),
        stack_delta=0,
    )

    evidence = join_memory_output_object_contracts_8616((callsite,))

    assert evidence.objects == ()
    assert evidence.failure is MemoryOutputObjectFailure8616.DUPLICATE_EFFECT
    assert evidence.stats.failure_count == 1


def test_orphan_live_out_trial_counts_and_refuses() -> None:
    _unused_effect, trial = _effect_and_trial(_owner(), 0x1200, 2, 0)
    callsite = CallsiteStorageTrials8616(
        CALLER,
        CALLEE,
        CALLSITE,
        live_outs=(trial,),
        stack_delta=0,
    )

    evidence = join_memory_output_object_contracts_8616((callsite,))

    assert evidence.objects == ()
    assert evidence.failure is MemoryOutputObjectFailure8616.EXTRA_TRIAL
    assert evidence.stats.raw_fact_count == evidence.stats.failure_count == 1
