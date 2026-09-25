"""Classify interprocedural return storage from exact typed conditions.

Layer: Types/Lowering.
Responsibility: join one exact caller return-use witness, its physical output
storage, and canonical ConditionIR semantics into a return type-class proof.
Consumes alias, widening, and typed facts. This module does not inspect source,
assembly, rendered C, or Structuring artifacts, and it does not mutate codegen.
Ambiguous pointer/value uses and unsupported split carriers are typed refusals.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ..alias.domains import (
    AX,
    DomainKey,
    View,
    register_domain_for_name,
    register_offset_for_name,
    register_pair_name,
    register_view_for_name,
)
from ..caller_return_use_contracts import (
    AxValueView8616,
    ByteReturnExtensionKind8616,
    CallerReturnUseFact8616,
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
)
from ..ir import IRValue, MemSpace
from ..ir.condition_ir import ConditionIR
from .interprocedural_storage_contracts import (
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageTrialSignedness8616,
    StorageTrialStats8616,
    StorageTrialValueClass8616,
)
from .interprocedural_storage_return_type_contracts import (
    ReturnPointerAliasStep8616,
    ReturnPointerUseEvidence8616,
    ReturnStorageTypeFailure8616,
    ReturnStorageTypeResult8616,
    ReturnStorageTypeVerdict8616,
)

__all__ = [
    "ReturnPointerAliasStep8616",
    "ReturnPointerUseEvidence8616",
    "ReturnStorageTypeFailure8616",
    "ReturnStorageTypeResult8616",
    "ReturnStorageTypeVerdict8616",
    "classify_return_storage_type_8616",
]


@dataclass(frozen=True, slots=True)
class _RegisterRange8616:
    """Canonical byte range and alias identity for one register storage."""

    offset: int
    width: int
    domain: DomainKey
    view: View


def _refused_result_8616(
    failure: ReturnStorageTypeFailure8616,
    *,
    verdict: ReturnStorageTypeVerdict8616 = ReturnStorageTypeVerdict8616.UNKNOWN_REFUSE,
    normalized: bool = False,
    signedness: StorageTrialSignedness8616 | None = None,
    condition: ConditionIR | None = None,
) -> ReturnStorageTypeResult8616:
    """Build one atomic refusal without discarding partial typed evidence."""
    return ReturnStorageTypeResult8616(
        verdict=verdict,
        signedness=signedness,
        value_class=None,
        condition=condition,
        failure=failure,
        stats=StorageTrialStats8616(
            raw_fact_count=1,
            normalized_fact_count=int(normalized),
            failure_count=1,
        ),
    )


def _register_range_8616(storage: StorageIdentity8616) -> _RegisterRange8616 | None:
    """Resolve one exact register identity through the Alias-owned domain map."""
    if not storage.is_exact or storage.kind is not StorageIdentityKind8616.REGISTER:
        return None
    domain = register_domain_for_name(storage.register)
    view = register_view_for_name(storage.register)
    pair_name = register_pair_name(storage.register)
    base_offset = register_offset_for_name(pair_name)
    if domain is None or view is None or base_offset is None:
        return None
    if not _byte_aligned_view_8616(view, storage):
        return None
    return _RegisterRange8616(
        offset=base_offset + view.bit_offset // 8,
        width=storage.width,
        domain=domain,
        view=view,
    )


def _byte_aligned_view_8616(view: View, storage: StorageIdentity8616) -> bool:
    """Return whether one register view is a byte-aligned exact-width piece."""
    return bool(
        view.bit_offset % 8 == 0
        and view.bit_width % 8 == 0
        and storage.width == view.bit_width // 8
    )


def _is_exact_register_value_8616(
    value: object,
    register_range: _RegisterRange8616,
) -> bool:
    """Return whether a typed operand names exactly the output register view."""
    if (
        not isinstance(value, IRValue)
        or value.space is not MemSpace.REG
        or value.offset != register_range.offset
        or value.size != register_range.width
    ):
        return False
    if value.name is None:
        return True
    return bool(
        register_domain_for_name(value.name) == register_range.domain
        and register_view_for_name(value.name) == register_range.view
    )


def _condition_uses_output_8616(
    condition: ConditionIR,
    register_range: _RegisterRange8616,
) -> bool:
    """Return whether exactly one canonical condition operand is the output."""
    operands = (condition.lhs,) if condition.is_zero_test else (condition.lhs, condition.rhs)
    return sum(
        _is_exact_register_value_8616(operand, register_range)
        for operand in operands
    ) == 1


def _condition_matches_witness_8616(condition: ConditionIR, witness: int) -> bool:
    """Return whether a condition retains the exact observed use instruction."""
    return bool(
        condition.producer_insn == witness
        or condition.operand_bind_insn == witness
    )


def _unique_conditions_8616(conditions: Sequence[ConditionIR]) -> tuple[ConditionIR, ...]:
    """Deduplicate equivalent cached projections while preserving source order."""
    unique: list[ConditionIR] = []
    for condition in conditions:
        if condition not in unique:
            unique.append(condition)
    return tuple(unique)


def _proven_scalar_result_8616(
    signedness: StorageTrialSignedness8616,
    *,
    condition: ConditionIR | None = None,
    byte_extension_fact: CallerReturnUseFact8616 | None = None,
) -> ReturnStorageTypeResult8616:
    """Build one complete scalar return classification."""
    return ReturnStorageTypeResult8616(
        verdict=ReturnStorageTypeVerdict8616.PROVEN,
        signedness=signedness,
        value_class=StorageTrialValueClass8616.VALUE,
        condition=condition,
        byte_extension_fact=byte_extension_fact,
        failure=None,
        stats=StorageTrialStats8616(
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
        ),
    )


def _classify_byte_extension_8616(
    fact: CallerReturnUseFact8616,
    output_storages: tuple[StorageIdentity8616, ...],
) -> ReturnStorageTypeResult8616:
    """Classify an exact AL result promoted to AX before its scalar use."""
    if len(output_storages) != 1:
        return _refused_result_8616(
            ReturnStorageTypeFailure8616.SPLIT_OUTPUT_UNSUPPORTED,
            normalized=True,
        )
    register_range = _register_range_8616(output_storages[0])
    if (
        register_range is None
        or register_range.domain != AX
        or register_range.width != 1
        or register_range.view.bit_offset != 0
        or fact.observed_value_view is not AxValueView8616.AX
    ):
        return _refused_result_8616(
            ReturnStorageTypeFailure8616.OUTPUT_CARRIER_UNSUPPORTED,
            normalized=True,
        )
    extension = fact.byte_extension
    if extension is None:
        return _refused_result_8616(
            ReturnStorageTypeFailure8616.SIGNEDNESS_UNKNOWN,
            normalized=True,
        )
    signedness = {
        ByteReturnExtensionKind8616.SIGN_EXTEND_AL_TO_AX: StorageTrialSignedness8616.SIGNED,
        ByteReturnExtensionKind8616.ZERO_EXTEND_AL_TO_AX: StorageTrialSignedness8616.UNSIGNED,
    }.get(extension)
    if signedness is None:
        return _refused_result_8616(
            ReturnStorageTypeFailure8616.SIGNEDNESS_UNKNOWN,
            normalized=True,
        )
    return _proven_scalar_result_8616(
        signedness,
        byte_extension_fact=fact,
    )


def classify_return_storage_type_8616(
    fact: CallerReturnUseFact8616,
    output_storages: tuple[StorageIdentity8616, ...],
    conditions: Sequence[ConditionIR],
) -> ReturnStorageTypeResult8616:
    """Prove a return type only from an exact typed caller condition witness."""
    if not fact.classified:
        return _refused_result_8616(ReturnStorageTypeFailure8616.RETURN_USE_UNKNOWN)
    if fact.verdict is not CallerReturnUseVerdict8616.USED:
        return _refused_result_8616(
            ReturnStorageTypeFailure8616.RETURN_NOT_OBSERVED,
            normalized=True,
        )
    if (
        fact.kind is CallsiteReturnUseKind8616.VALUE
        and fact.byte_extension is not None
    ):
        return _classify_byte_extension_8616(fact, output_storages)
    if fact.kind is not CallsiteReturnUseKind8616.CONDITION:
        return _refused_result_8616(
            ReturnStorageTypeFailure8616.RETURN_USE_NOT_CONDITION,
            normalized=True,
        )
    register_range, range_refusal = _output_register_range_8616(output_storages)
    if range_refusal is not None:
        return range_refusal
    assert register_range is not None
    witness = fact.witness_instruction_addr
    if witness is None:
        return _refused_result_8616(ReturnStorageTypeFailure8616.RETURN_USE_UNKNOWN)
    condition, condition_refusal = _witness_condition_8616(
        conditions, witness, register_range,
    )
    if condition_refusal is not None:
        return condition_refusal
    assert condition is not None
    return _signedness_result_8616(condition, register_range)


def _output_register_range_8616(
    output_storages: tuple[StorageIdentity8616, ...],
) -> tuple[_RegisterRange8616 | None, ReturnStorageTypeResult8616 | None]:
    """Resolve the single exact AX output register range or its refusal."""
    if not output_storages:
        return None, _refused_result_8616(
            ReturnStorageTypeFailure8616.OUTPUT_STORAGE_UNKNOWN,
            normalized=True,
        )
    if len(output_storages) != 1:
        return None, _refused_result_8616(
            ReturnStorageTypeFailure8616.SPLIT_OUTPUT_UNSUPPORTED,
            normalized=True,
        )
    register_range = _register_range_8616(output_storages[0])
    if register_range is None:
        return None, _refused_result_8616(
            ReturnStorageTypeFailure8616.OUTPUT_STORAGE_CONFLICT,
            verdict=ReturnStorageTypeVerdict8616.CONFLICT,
            normalized=True,
        )
    if register_range.domain != AX:
        return None, _refused_result_8616(
            ReturnStorageTypeFailure8616.OUTPUT_CARRIER_UNSUPPORTED,
            normalized=True,
        )
    return register_range, None


def _witness_condition_8616(
    conditions: Sequence[ConditionIR],
    witness: int,
    register_range: _RegisterRange8616,
) -> tuple[ConditionIR | None, ReturnStorageTypeResult8616 | None]:
    """Select the unique condition matching the witness and output range."""
    matching = _unique_conditions_8616(
        tuple(
            condition
            for condition in conditions
            if _condition_matches_witness_8616(condition, witness)
            and _condition_uses_output_8616(condition, register_range)
            and condition.width_bits == register_range.width * 8
        )
    )
    if not matching:
        return None, _refused_result_8616(
            ReturnStorageTypeFailure8616.CONDITION_NOT_FOUND,
            normalized=True,
        )
    if len(matching) != 1:
        return None, _refused_result_8616(
            ReturnStorageTypeFailure8616.CONDITION_CONFLICT,
            verdict=ReturnStorageTypeVerdict8616.CONFLICT,
            normalized=True,
        )
    return matching[0], None


def _signedness_result_8616(
    condition: ConditionIR,
    register_range: _RegisterRange8616,
) -> ReturnStorageTypeResult8616:
    """Classify the proven condition's signedness or refuse unknown classes."""
    if condition.is_signed:
        return _proven_scalar_result_8616(
            StorageTrialSignedness8616.SIGNED,
            condition=condition,
        )
    if register_range.width == 1 and condition.op in {"eq", "ne", "zero", "nonzero"}:
        return _proven_scalar_result_8616(
            StorageTrialSignedness8616.SIGN_INSENSITIVE,
            condition=condition,
        )
    if condition.is_unsigned:
        if register_range.width == 1:
            return _proven_scalar_result_8616(
                StorageTrialSignedness8616.UNSIGNED,
                condition=condition,
            )
        return _refused_result_8616(
            ReturnStorageTypeFailure8616.VALUE_CLASS_UNKNOWN,
            normalized=True,
            signedness=StorageTrialSignedness8616.UNSIGNED,
            condition=condition,
        )
    return _refused_result_8616(
        ReturnStorageTypeFailure8616.SIGNEDNESS_UNKNOWN,
        normalized=True,
        condition=condition,
    )
