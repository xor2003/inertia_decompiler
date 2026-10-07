"""Sign-insensitive stack-argument type evidence from typed conditions."""

from __future__ import annotations

from types import SimpleNamespace

from inertia.semantics.callsite_summary import (
    CallsitePushSourceKind8616,
    CallsiteSummary8616,
)
from inertia.ir import (
    AddressStatus,
    IRAddress,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.condition_ir import ConditionIR
from inertia.lowering.condition_argument_type_facts import (
    StackArgumentSignedness8616,
    collect_condition_argument_type_facts_8616,
)
from inertia.lowering.interprocedural_storage_contracts import (
    StorageTrialSignedness8616,
    StorageTrialValueClass8616,
)
from inertia.lowering.interprocedural_storage_reaching_contracts import (
    PhysicalCallArgument8616,
    PhysicalCallArgumentPiece8616,
)
from inertia.lowering.interprocedural_storage_trial_types import (
    classify_input_argument_8616,
)


def _condition(op: str) -> ConditionIR:
    return ConditionIR(
        op,
        IRValue(MemSpace.SS, name="bp", offset=8, size=2),
        IRValue(MemSpace.CONST, const=0, size=2),
        width_bits=16,
    )


def test_equality_condition_proves_sign_insensitive_stack_argument() -> None:
    result = collect_condition_argument_type_facts_8616(
        SimpleNamespace(_inertia_typed_conditions=(_condition("ne"),))
    )

    assert result.failure_count == 0
    assert len(result.facts) == 1
    assert result.facts[0].signedness is StackArgumentSignedness8616.SIGN_INSENSITIVE


def test_ordering_fact_overrides_neutral_equality_without_conflict() -> None:
    result = collect_condition_argument_type_facts_8616(
        SimpleNamespace(
            _inertia_typed_conditions=(_condition("ne"), _condition("slt"))
        )
    )

    assert result.failure_count == 0
    assert result.facts[0].signedness is StackArgumentSignedness8616.SIGNED


def test_sign_insensitive_fact_materializes_value_class() -> None:
    facts = collect_condition_argument_type_facts_8616(
        SimpleNamespace(_inertia_typed_conditions=(_condition("ne"),))
    )
    summary = CallsiteSummary8616(
        callsite_addr=0x1010,
        target_addr=0x1100,
        return_addr=0x1013,
        kind="near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register=None,
        return_used=None,
    )
    physical = PhysicalCallArgument8616(
        width=2,
        pieces=(
            PhysicalCallArgumentPiece8616(
                width=2,
                source=(CallsitePushSourceKind8616.IMMEDIATE.value, 0),
                push_addr=0x100F,
            ),
        ),
    )
    storage = IRAddress(
        space=MemSpace.SS,
        base=("bp",),
        offset=8,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )

    result = classify_input_argument_8616(
        summary,
        physical,
        storage,
        0,
        1,
        facts,
        None,
    )

    assert result.failure is None
    assert result.signedness is StorageTrialSignedness8616.SIGN_INSENSITIVE
    assert result.value_class is StorageTrialValueClass8616.VALUE
