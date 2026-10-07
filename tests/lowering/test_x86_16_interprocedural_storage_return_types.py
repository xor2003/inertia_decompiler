"""Real typed-condition tests for interprocedural return classification."""

from __future__ import annotations

import io
from dataclasses import replace
from types import SimpleNamespace

import angr
import pytest
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.caller_return_use_contracts import (
    AxValueView8616,
    ByteReturnExtensionKind8616,
    CallerReturnUseFact8616,
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
)
from inertia.ir import IRValue, MemSpace
from inertia.ir.condition_ir import ConditionIR
from inertia.frontend.x86_16.lift_86_16 import Instruction_ANY, Lifter86_16  # noqa: F401
from inertia.lowering.condition_transfer import (
    collect_typed_condition_artifacts_8616,
)
from inertia.lowering.interprocedural_storage_contracts import (
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageTrialSignedness8616,
    StorageTrialValueClass8616,
)
from inertia.lowering.interprocedural_storage_return_types import (
    ReturnStorageTypeFailure8616,
    ReturnStorageTypeVerdict8616,
    classify_return_storage_type_8616,
)


def _conditions(code: bytes, block_addrs: set[int]) -> tuple[ConditionIR, ...]:
    project = angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )
    original_cache = Instruction_ANY._inertia_module_condition_cache
    Instruction_ANY._inertia_module_condition_cache = {}
    surface = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: SimpleNamespace(
                    block_addrs_set=block_addrs
                )
            )
        ),
        factory=project.factory,
    )
    try:
        conditions, _edge_evidence = collect_typed_condition_artifacts_8616(
            surface,
            0x1000,
        )
    finally:
        Instruction_ANY._inertia_module_condition_cache = original_cache
    return tuple(conditions)


def _fact(
    *,
    witness: int = 0x1003,
    kind: CallsiteReturnUseKind8616 = CallsiteReturnUseKind8616.CONDITION,
    extension: ByteReturnExtensionKind8616 | None = None,
) -> CallerReturnUseFact8616:
    return CallerReturnUseFact8616(
        caller_addr=0x1000,
        callsite_addr=0x1000,
        verdict=CallerReturnUseVerdict8616.USED,
        kind=kind,
        witness_instruction_addr=witness,
        byte_extension=extension,
        byte_extension_instruction_addr=(0x1002 if extension is not None else None),
        observed_value_view=(AxValueView8616.AX if extension is not None else None),
    )


def _register(name: str = "ax", width: int = 2) -> StorageIdentity8616:
    return StorageIdentity8616(
        kind=StorageIdentityKind8616.REGISTER,
        width=width,
        register=name,
    )


def _word_condition(jcc_opcode: int) -> tuple[ConditionIR, ...]:
    code = bytes.fromhex("e8060083f800") + bytes((jcc_opcode, 0x01, 0x90, 0xC3))
    return _conditions(code, {0x1000, 0x1003, 0x1008, 0x1009})


def test_signed_ordering_proves_scalar_return_type_from_real_ir() -> None:
    conditions = _word_condition(0x7C)  # jl

    result = classify_return_storage_type_8616(
        _fact(),
        (_register(),),
        conditions,
    )

    assert result.verdict is ReturnStorageTypeVerdict8616.PROVEN
    assert result.complete
    assert result.signedness is StorageTrialSignedness8616.SIGNED
    assert result.value_class is StorageTrialValueClass8616.VALUE
    assert result.condition is conditions[0]
    assert result.condition.producer_insn == 0x1003
    assert result.stats.complete


def test_signed_byte_condition_proves_exact_al_return_view() -> None:
    condition = ConditionIR(
        op="slt",
        lhs=IRValue(space=MemSpace.REG, name="al", offset=0, size=1),
        rhs=IRValue(space=MemSpace.CONST, const=0, size=1),
        width_bits=8,
        src_insn=0x1005,
        producer_insn=0x1003,
    )

    result = classify_return_storage_type_8616(
        _fact(),
        (_register("al", 1),),
        (condition,),
    )

    assert result.complete
    assert result.signedness is StorageTrialSignedness8616.SIGNED
    assert result.value_class is StorageTrialValueClass8616.VALUE


@pytest.mark.parametrize(
    ("extension", "signedness"),
    (
        (
            ByteReturnExtensionKind8616.ZERO_EXTEND_AL_TO_AX,
            StorageTrialSignedness8616.UNSIGNED,
        ),
        (
            ByteReturnExtensionKind8616.SIGN_EXTEND_AL_TO_AX,
            StorageTrialSignedness8616.SIGNED,
        ),
    ),
)
def test_byte_extension_proves_scalar_al_return_type(
    extension: ByteReturnExtensionKind8616,
    signedness: StorageTrialSignedness8616,
) -> None:
    result = classify_return_storage_type_8616(
        _fact(kind=CallsiteReturnUseKind8616.VALUE, extension=extension),
        (_register("al", 1),),
        (),
    )

    assert result.complete
    assert result.signedness is signedness
    assert result.value_class is StorageTrialValueClass8616.VALUE


def test_byte_equality_proves_sign_insensitive_scalar_value() -> None:
    condition = ConditionIR(
        op="ne",
        lhs=IRValue(space=MemSpace.REG, name="al", offset=0, size=1),
        rhs=IRValue(space=MemSpace.CONST, const=13, size=1),
        width_bits=8,
        producer_insn=0x1003,
    )

    result = classify_return_storage_type_8616(
        _fact(),
        (_register("al", 1),),
        (condition,),
    )

    assert result.complete
    assert result.signedness is StorageTrialSignedness8616.SIGN_INSENSITIVE
    assert result.value_class is StorageTrialValueClass8616.VALUE


def test_unsigned_ordering_retains_signedness_but_refuses_pointer_ambiguity() -> None:
    conditions = _word_condition(0x72)  # jb

    result = classify_return_storage_type_8616(
        _fact(),
        (_register(),),
        conditions,
    )

    assert result.verdict is ReturnStorageTypeVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ReturnStorageTypeFailure8616.VALUE_CLASS_UNKNOWN
    assert result.signedness is StorageTrialSignedness8616.UNSIGNED
    assert result.value_class is None
    assert result.condition is conditions[0]
    assert result.stats.failure_count == 1


def test_equality_condition_refuses_unknown_signedness() -> None:
    result = classify_return_storage_type_8616(
        _fact(),
        (_register(),),
        _word_condition(0x74),  # je
    )

    assert result.verdict is ReturnStorageTypeVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ReturnStorageTypeFailure8616.SIGNEDNESS_UNKNOWN
    assert result.signedness is None
    assert result.value_class is None


def test_wrong_witness_or_register_cannot_classify_return() -> None:
    conditions = _word_condition(0x7C)

    wrong_witness = classify_return_storage_type_8616(
        _fact(witness=0x1004),
        (_register(),),
        conditions,
    )
    wrong_register = classify_return_storage_type_8616(
        _fact(),
        (_register("dx"),),
        conditions,
    )

    assert wrong_witness.failure is ReturnStorageTypeFailure8616.CONDITION_NOT_FOUND
    assert wrong_register.failure is ReturnStorageTypeFailure8616.OUTPUT_CARRIER_UNSUPPORTED


def test_split_or_malformed_output_storage_is_a_typed_refusal() -> None:
    conditions = _word_condition(0x7C)

    split = classify_return_storage_type_8616(
        _fact(),
        (_register("ax"), _register("dx")),
        conditions,
    )
    malformed = classify_return_storage_type_8616(
        _fact(),
        (_register("ax", 1),),
        conditions,
    )

    assert split.failure is ReturnStorageTypeFailure8616.SPLIT_OUTPUT_UNSUPPORTED
    assert malformed.verdict is ReturnStorageTypeVerdict8616.CONFLICT
    assert malformed.failure is ReturnStorageTypeFailure8616.OUTPUT_STORAGE_CONFLICT


def test_conflicting_conditions_refuse_and_equivalent_cache_entries_deduplicate() -> None:
    condition = _word_condition(0x7C)[0]

    duplicate = classify_return_storage_type_8616(
        _fact(),
        (_register(),),
        (condition, condition),
    )
    conflict = classify_return_storage_type_8616(
        _fact(),
        (_register(),),
        (condition, replace(condition, op="ult")),
    )

    assert duplicate.complete
    assert conflict.verdict is ReturnStorageTypeVerdict8616.CONFLICT
    assert conflict.failure is ReturnStorageTypeFailure8616.CONDITION_CONFLICT


def test_non_condition_return_use_refuses_without_reinterpreting_value_flow() -> None:
    result = classify_return_storage_type_8616(
        _fact(kind=CallsiteReturnUseKind8616.VALUE),
        (_register(),),
        _word_condition(0x7C),
    )

    assert result.verdict is ReturnStorageTypeVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ReturnStorageTypeFailure8616.RETURN_USE_NOT_CONDITION
    assert result.condition is None


def test_unknown_and_unused_return_facts_refuse_before_type_proof() -> None:
    unknown_fact = replace(
        _fact(),
        verdict=CallerReturnUseVerdict8616.UNKNOWN,
        kind=None,
        witness_instruction_addr=None,
    )
    unused_fact = replace(
        _fact(),
        verdict=CallerReturnUseVerdict8616.UNUSED,
        kind=CallsiteReturnUseKind8616.CLOBBERED,
    )

    unknown = classify_return_storage_type_8616(
        unknown_fact,
        (_register(),),
        _word_condition(0x7C),
    )
    unused = classify_return_storage_type_8616(
        unused_fact,
        (_register(),),
        _word_condition(0x7C),
    )

    assert unknown.failure is ReturnStorageTypeFailure8616.RETURN_USE_UNKNOWN
    assert unknown.stats.normalized_fact_count == 0
    assert unused.failure is ReturnStorageTypeFailure8616.RETURN_NOT_OBSERVED
    assert unused.stats.normalized_fact_count == 1


def test_missing_output_and_contradictory_register_name_refuse() -> None:
    condition = _word_condition(0x7C)[0]
    assert isinstance(condition.lhs, IRValue)
    contradictory = replace(
        condition,
        lhs=replace(condition.lhs, name="bx"),
    )

    missing_output = classify_return_storage_type_8616(
        _fact(),
        (),
        (condition,),
    )
    contradictory_name = classify_return_storage_type_8616(
        _fact(),
        (_register(),),
        (contradictory,),
    )

    assert missing_output.failure is ReturnStorageTypeFailure8616.OUTPUT_STORAGE_UNKNOWN
    assert contradictory_name.failure is ReturnStorageTypeFailure8616.CONDITION_NOT_FOUND
