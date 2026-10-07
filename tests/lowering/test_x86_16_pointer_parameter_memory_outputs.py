from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from typing import cast

from inertia.ir import MemSpace
from inertia.lowering.interprocedural_memory_output_object_contracts import (
    MemoryOutputObjectFailure8616,
)
from inertia.lowering.interprocedural_memory_output_objects import (
    join_memory_output_object_contracts_8616,
)
from inertia.lowering.interprocedural_memory_output_validation import (
    MemoryOutputTransactionFailure8616,
    validate_memory_output_transaction_8616,
)
from inertia.lowering.interprocedural_storage_contracts import (
    CallsiteStorageBinding8616,
    CallsiteStorageTrials8616,
    FunctionStorageContract8616,
)
from inertia.lowering.pointer_parameter_caller_target_contracts import (
    PointerParameterCallerTarget8616,
)
from inertia.lowering.pointer_parameter_memory_output_contracts import (
    PointerParameterMemoryOutputFailure8616,
)
from inertia.lowering.pointer_parameter_memory_outputs import (
    join_pointer_parameter_memory_outputs_8616,
)


def _effect(
    logical_index: int,
    *,
    caller_addr: int = 0x1100,
    callsite_addr: int = 0x1110,
) -> PointerParameterCallerTarget8616:
    """Build a minimal complete dynamic-effect double for join isolation."""
    source = SimpleNamespace(
        logical_index=logical_index,
        argument_storage=SimpleNamespace(offset=4 + logical_index * 2, size=2),
        output_view=SimpleNamespace(
            segment=MemSpace.DS,
            relative_offset=0,
            width=2,
        ),
        complete=True,
    )
    return cast(
        PointerParameterCallerTarget8616,
        SimpleNamespace(
            caller_addr=caller_addr,
            callee_addr=0x107B8,
            callsite_addr=callsite_addr,
            logical_index=logical_index,
            source=source,
            complete=True,
        ),
    )


def _trials(
    *effects: PointerParameterCallerTarget8616,
) -> CallsiteStorageTrials8616:
    """Retain dynamic effects in one otherwise empty callsite census row."""
    return CallsiteStorageTrials8616(
        caller_addr=0x1100,
        callee_addr=0x107B8,
        callsite_addr=0x1110,
        pointer_effects=effects,
        stack_delta=0,
    )


def test_dynamic_outputs_join_without_direct_storage_or_live_out_trials() -> None:
    effects = (_effect(0), _effect(1))
    joined = join_memory_output_object_contracts_8616((_trials(*effects),))

    assert joined.complete
    assert joined.objects == ()
    assert len(joined.pointer_objects) == 2
    assert sum(len(item.views) for item in joined.pointer_objects) == 2

    binding = CallsiteStorageBinding8616(
        caller_addr=0x1100,
        callsite_addr=0x1110,
        arguments=(),
        returns=(),
        stack_delta=0,
        pointer_effects=effects,
    )
    contract = FunctionStorageContract8616(
        function_addr=0x107B8,
        inputs=(),
        outputs=(),
        stack_delta=0,
        callsites=(binding,),
        pointer_memory_outputs=joined.pointer_objects,
    )
    validation = validate_memory_output_transaction_8616(contract)
    assert validation.complete
    assert validation.stats.raw_fact_count == 7

    orphan = validate_memory_output_transaction_8616(
        replace(contract, pointer_memory_outputs=())
    )
    assert orphan.failure is MemoryOutputTransactionFailure8616.ORPHAN_EFFECT

    missing = validate_memory_output_transaction_8616(
        replace(contract, callsites=(replace(binding, pointer_effects=()),))
    )
    assert missing.failure is MemoryOutputTransactionFailure8616.EFFECT_MISSING

    wrong_callee = validate_memory_output_transaction_8616(
        replace(contract, function_addr=0x207B8)
    )
    assert wrong_callee.failure is MemoryOutputTransactionFailure8616.CALLSITE_CONFLICT


def test_dynamic_output_join_refuses_duplicate_and_wrong_callsite_atomically() -> None:
    effect = _effect(0)
    duplicate = join_pointer_parameter_memory_outputs_8616(
        (_trials(effect, effect),)
    )
    assert not duplicate.complete
    assert duplicate.objects == ()
    assert duplicate.failure is PointerParameterMemoryOutputFailure8616.DUPLICATE_EFFECT

    conflict = join_pointer_parameter_memory_outputs_8616(
        (_trials(_effect(0, caller_addr=0x2200)),)
    )
    assert not conflict.complete
    assert conflict.objects == ()
    assert conflict.failure is PointerParameterMemoryOutputFailure8616.CALLSITE_CONFLICT

    aggregate = join_memory_output_object_contracts_8616((_trials(effect, effect),))
    assert not aggregate.complete
    assert aggregate.objects == ()
    assert aggregate.pointer_objects == ()
    assert aggregate.failure is MemoryOutputObjectFailure8616.POINTER_OUTPUT_REFUSED
