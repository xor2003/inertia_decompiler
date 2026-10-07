from types import SimpleNamespace

from inertia.ir import (
    AddressStatus,
    IRAddress,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.lowering.interprocedural_storage_contracts import (
    CallsiteStorageTrials8616,
    FunctionStorageTrials8616,
    StorageDefinitionKind8616,
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageReachingDefinition8616,
    StorageTrial8616,
    StorageTrialFailureKind8616,
    StorageTrialRole8616,
    StorageTrialSignedness8616,
    StorageTrialValueClass8616,
    StorageTrialVerdict8616,
    StorageUseEvidence8616,
    ValueProvenance8616,
)
from inertia.lowering.interprocedural_storage_solver import (
    resolve_program_storage_trials_8616,
)
from inertia.lowering.interprocedural_storage_transaction import (
    accepted_callsite_storage_binding_8616,
    accepted_function_storage_contract_8616,
    apply_program_storage_resolution_8616,
)


def _stack_identity(offset: int, width: int) -> StorageIdentity8616:
    return StorageIdentity8616(
        kind=StorageIdentityKind8616.STACK,
        width=width,
        address=IRAddress(
            space=MemSpace.SS,
            base=("bp",),
            offset=offset,
            size=width,
            status=AddressStatus.STABLE,
            segment_origin=SegmentOrigin.PROVEN,
        ),
    )


def _register_identity(name: str, width: int = 2) -> StorageIdentity8616:
    return StorageIdentity8616(
        kind=StorageIdentityKind8616.REGISTER, width=width, register=name
    )


def _trial(
    *,
    callee_addr: int,
    caller_addr: int,
    callsite_addr: int,
    role: StorageTrialRole8616,
    logical_index: int,
    storage: StorageIdentity8616,
    source_storage: StorageIdentity8616,
    value_class: StorageTrialValueClass8616 = StorageTrialValueClass8616.VALUE,
    signedness: StorageTrialSignedness8616 = StorageTrialSignedness8616.SIGNED,
    piece_index: int = 0,
    piece_count: int = 1,
    provenance: ValueProvenance8616 | None = None,
) -> StorageTrial8616:
    source_address = source_storage.address
    is_return = role is StorageTrialRole8616.RETURN
    value = IRValue(
        space=(source_address.space if source_address is not None else MemSpace.REG),
        name=source_storage.register,
        offset=0 if source_address is None else source_address.offset,
        size=source_storage.width,
        version=None if is_return else callsite_addr + logical_index + piece_index + 1,
    )
    if is_return and provenance is None:
        provenance = ValueProvenance8616(callee_addr, callsite_addr, callsite_addr)
    return StorageTrial8616(
        callee_addr=callee_addr,
        caller_addr=caller_addr,
        callsite_addr=callsite_addr,
        role=role,
        logical_index=logical_index,
        piece_index=piece_index,
        piece_count=piece_count,
        storage=storage,
        reaching_definition=StorageReachingDefinition8616(
            value=value,
            block_addr=caller_addr,
            instr_index=logical_index + piece_index,
            instr_addr=callsite_addr if is_return else callsite_addr - 2 - piece_index,
            source_storage=source_storage,
            definition_kind=StorageDefinitionKind8616.CALL_OUTPUT if is_return else StorageDefinitionKind8616.VALUE,
        ),
        use=StorageUseEvidence8616(
            block_addr=caller_addr,
            instr_index=logical_index + piece_index + 2,
            instr_addr=callsite_addr,
            callsite_addr=callsite_addr,
        ),
        signedness=signedness,
        value_class=value_class,
        provenance=provenance,
    )


def _recursive_quicksort_trials() -> FunctionStorageTrials8616:
    function_addr = 0x2000
    callsites: list[CallsiteStorageTrials8616] = []
    for callsite_addr, source_offsets in ((0x2010, (4, 6)), (0x2020, (6, 4))):
        arguments = tuple(
            _trial(
                callee_addr=function_addr,
                caller_addr=function_addr,
                callsite_addr=callsite_addr,
                role=StorageTrialRole8616.INPUT,
                logical_index=index,
                storage=_stack_identity(4 + index * 2, 2),
                source_storage=_stack_identity(source_offset, 2),
            )
            for index, source_offset in enumerate(source_offsets)
        )
        callsites.append(
            CallsiteStorageTrials8616(
                caller_addr=function_addr,
                callee_addr=function_addr,
                callsite_addr=callsite_addr,
                arguments=arguments,
                stack_delta=4,
            )
        )
    return FunctionStorageTrials8616(
        function_addr=function_addr,
        caller_census_complete=True,
        expected_callsite_addrs=(0x2010, 0x2020),
        callsites=tuple(callsites),
    )


def _single_argument_function(
    function_addr: int,
    caller_addr: int,
    callsite_addr: int,
) -> FunctionStorageTrials8616:
    argument = _trial(
        callee_addr=function_addr,
        caller_addr=caller_addr,
        callsite_addr=callsite_addr,
        role=StorageTrialRole8616.INPUT,
        logical_index=0,
        storage=_stack_identity(4, 2),
        source_storage=_register_identity("ax"),
    )
    return FunctionStorageTrials8616(
        function_addr=function_addr,
        caller_census_complete=True,
        expected_callsite_addrs=(callsite_addr,),
        callsites=(
            CallsiteStorageTrials8616(
                caller_addr=caller_addr,
                callee_addr=function_addr,
                callsite_addr=callsite_addr,
                arguments=(argument,),
                stack_delta=2,
            ),
        ),
    )


def test_quicksort_recursive_edges_converge_and_retain_opposite_source_order() -> None:
    resolution = resolve_program_storage_trials_8616((_recursive_quicksort_trials(),))

    assert resolution.sccs == ((0x2000,),)
    assert resolution.iterations_by_scc == (2,)
    assert resolution.stats.complete is True
    contract = resolution.contract_for(0x2000)
    assert contract is not None
    assert tuple(slot.width for slot in contract.inputs) == (2, 2)
    assert tuple(
        trial.reaching_definition.source_storage.address.offset
        for trial in contract.callsites[1].arguments
        if trial.reaching_definition.source_storage is not None
        and trial.reaching_definition.source_storage.address is not None
    ) == (6, 4)

    project = SimpleNamespace()
    assert apply_program_storage_resolution_8616(project, resolution) is True
    assert apply_program_storage_resolution_8616(project, resolution) is False
    assert accepted_function_storage_contract_8616(project, 0x2000) == contract
    assert accepted_callsite_storage_binding_8616(project, 0x2000, 0x2020) == contract.callsites[1]


def test_mutually_recursive_scc_is_independent_of_input_order() -> None:
    first = _single_argument_function(0x3000, 0x3100, 0x3110)
    second = _single_argument_function(0x3100, 0x3000, 0x3010)

    forward = resolve_program_storage_trials_8616((first, second))
    reverse = resolve_program_storage_trials_8616((second, first))

    assert forward == reverse
    assert forward.sccs == ((0x3000, 0x3100),)
    assert forward.iterations_by_scc == (2,)


def test_beep_incomplete_caller_census_refuses_without_guessed_contract() -> None:
    complete_callsite = _single_argument_function(0x4000, 0x4100, 0x4110).callsites[0]
    trials = FunctionStorageTrials8616(
        function_addr=0x4000,
        caller_census_complete=False,
        expected_callsite_addrs=(0x4110, 0x4120),
        callsites=(complete_callsite,),
    )

    resolution = resolve_program_storage_trials_8616((trials,))
    result = resolution.resolutions[0]

    assert result.contract is None
    assert result.verdict is StorageTrialVerdict8616.CONFLICT
    assert StorageTrialFailureKind8616.INCOMPLETE_CALLER_CENSUS in result.failures
    assert StorageTrialFailureKind8616.CALLSITE_SET_CONFLICT in result.failures
    project = SimpleNamespace()
    assert apply_program_storage_resolution_8616(project, resolution) is True
    assert accepted_function_storage_contract_8616(project, 0x4000) is None


def test_percolateup_pointer_to_value_disagreement_is_a_typed_conflict() -> None:
    function_addr = 0x5000
    callsites = tuple(
        CallsiteStorageTrials8616(
            caller_addr=0x5100 + index * 0x100,
            callee_addr=function_addr,
            callsite_addr=callsite_addr,
            arguments=(
                _trial(
                    callee_addr=function_addr,
                    caller_addr=0x5100 + index * 0x100,
                    callsite_addr=callsite_addr,
                    role=StorageTrialRole8616.INPUT,
                    logical_index=0,
                    storage=_stack_identity(4, 2),
                    source_storage=_register_identity("ax"),
                    value_class=value_class,
                ),
            ),
            stack_delta=2,
        )
        for index, (callsite_addr, value_class) in enumerate(
            (
                (0x5110, StorageTrialValueClass8616.POINTER),
                (0x5210, StorageTrialValueClass8616.VALUE),
            )
        )
    )
    trials = FunctionStorageTrials8616(
        function_addr=function_addr,
        caller_census_complete=True,
        expected_callsite_addrs=(0x5110, 0x5210),
        callsites=callsites,
    )

    result = resolve_program_storage_trials_8616((trials,)).resolutions[0]

    assert result.verdict is StorageTrialVerdict8616.CONFLICT
    assert result.contract is None
    assert result.failures == (StorageTrialFailureKind8616.VALUE_CLASS_CONFLICT,)


def test_split_return_requires_one_shared_provenance() -> None:
    function_addr = 0x6000
    callsite_addr = 0x6110
    returns = tuple(
        _trial(
            callee_addr=function_addr,
            caller_addr=0x6100,
            callsite_addr=callsite_addr,
            role=StorageTrialRole8616.RETURN,
            logical_index=0,
            piece_index=index,
            piece_count=2,
            storage=_register_identity(register),
            source_storage=_register_identity(register),
            provenance=ValueProvenance8616(function_addr, callsite_addr, callsite_addr + index),
        )
        for index, register in enumerate(("ax", "dx"))
    )
    trials = FunctionStorageTrials8616(
        function_addr=function_addr,
        caller_census_complete=True,
        expected_callsite_addrs=(callsite_addr,),
        callsites=(
            CallsiteStorageTrials8616(
                caller_addr=0x6100,
                callee_addr=function_addr,
                callsite_addr=callsite_addr,
                returns=returns,
                stack_delta=0,
            ),
        ),
    )

    result = resolve_program_storage_trials_8616((trials,)).resolutions[0]

    assert result.verdict is StorageTrialVerdict8616.CONFLICT
    assert result.failures == (StorageTrialFailureKind8616.SPLIT_PROVENANCE_CONFLICT,)


def test_split_return_with_shared_provenance_materializes_exact_pieces() -> None:
    function_addr = 0x7000
    callsite_addr = 0x7110
    provenance = ValueProvenance8616(function_addr, callsite_addr, callsite_addr)
    returns = tuple(
        _trial(
            callee_addr=function_addr,
            caller_addr=0x7100,
            callsite_addr=callsite_addr,
            role=StorageTrialRole8616.RETURN,
            logical_index=0,
            piece_index=index,
            piece_count=2,
            storage=_register_identity(register),
            source_storage=_register_identity(register),
            signedness=StorageTrialSignedness8616.SIGN_INSENSITIVE,
            provenance=provenance,
        )
        for index, register in enumerate(("ax", "dx"))
    )
    trials = FunctionStorageTrials8616(
        function_addr=function_addr,
        caller_census_complete=True,
        expected_callsite_addrs=(callsite_addr,),
        callsites=(
            CallsiteStorageTrials8616(
                caller_addr=0x7100,
                callee_addr=function_addr,
                callsite_addr=callsite_addr,
                returns=returns,
                stack_delta=0,
            ),
        ),
    )
    contract = resolve_program_storage_trials_8616((trials,)).contract_for(function_addr)
    assert contract is not None
    assert contract.outputs[0].width == 4
    assert contract.outputs[0].signedness is StorageTrialSignedness8616.SIGN_INSENSITIVE
    assert tuple(piece.register for piece in contract.outputs[0].pieces) == ("ax", "dx")


def test_sign_insensitive_byte_use_joins_unsigned_extension_evidence() -> None:
    function_addr = 0x7200
    return_storage = _register_identity("al", 1)
    callsites = tuple(
        CallsiteStorageTrials8616(
            caller_addr=caller_addr,
            callee_addr=function_addr,
            callsite_addr=callsite_addr,
            returns=(
                _trial(
                    callee_addr=function_addr,
                    caller_addr=caller_addr,
                    callsite_addr=callsite_addr,
                    role=StorageTrialRole8616.RETURN,
                    logical_index=0,
                    storage=return_storage,
                    source_storage=return_storage,
                    signedness=signedness,
                ),
            ),
            stack_delta=0,
        )
        for caller_addr, callsite_addr, signedness in (
            (0x7300, 0x7310, StorageTrialSignedness8616.UNSIGNED),
            (0x7400, 0x7410, StorageTrialSignedness8616.SIGN_INSENSITIVE),
        )
    )
    trials = FunctionStorageTrials8616(
        function_addr=function_addr,
        caller_census_complete=True,
        expected_callsite_addrs=(0x7310, 0x7410),
        callsites=callsites,
    )

    contract = resolve_program_storage_trials_8616((trials,)).contract_for(
        function_addr
    )

    assert contract is not None
    assert contract.outputs[0].signedness is StorageTrialSignedness8616.UNSIGNED
