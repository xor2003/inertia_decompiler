"""Classify near-pointer returns from exact caller SSA address use.

Layer: Types/Lowering.
Responsibility: validate one exact CALL_OUTPUT AX definition and publish pointer
class only when the typed pointer-flow analysis reaches a stable segmented LOAD
or STORE through complete alias, CFG-edge, and phi evidence.
Consumes alias, widening, and typed facts. This module does not traverse SSA,
repair CFG, mutate codegen, or inspect Structuring output.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from inertia.semantics.caller_return_use_contracts import (
    CallerReturnUseFact8616,
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
)

from inertia.alias.domains import AX, FULL16, register_domain_for_name, register_view_for_name
from inertia.ir.logical_memory_contracts import (
    IRMemoryAccessKind8616,
    logical_memory_execution_address_matches_8616,
)
from inertia.ir.ssa_function import SSAFunctionArtifact

from .interprocedural_storage_contracts import (
    StorageDefinitionKind8616,
    StorageIdentityKind8616,
    StorageReachingDefinition8616,
    StorageTrialSignedness8616,
    StorageTrialStats8616,
    StorageTrialValueClass8616,
)
from .interprocedural_storage_return_pointer_block import full_word_pointer_domain_8616
from .interprocedural_storage_return_pointer_flow import scan_pointer_return_flow_8616
from .interprocedural_storage_return_type_contracts import (
    ReturnPointerUseEvidence8616,
    ReturnStorageTypeFailure8616,
    ReturnStorageTypeResult8616,
    ReturnStorageTypeVerdict8616,
)

__all__ = [
    "classify_pointer_return_storage_8616",
    "proven_pointer_return_pointee_width_8616",
]

_CONFLICT_FAILURES_8616 = frozenset(
    {
        ReturnStorageTypeFailure8616.POINTER_WITNESS_CONFLICT,
        ReturnStorageTypeFailure8616.POINTER_PHI_CONFLICT,
    }
)


def _refused_result_8616(
    failure: ReturnStorageTypeFailure8616,
    *,
    verdict: ReturnStorageTypeVerdict8616 = ReturnStorageTypeVerdict8616.UNKNOWN_REFUSE,
    normalized: bool = False,
) -> ReturnStorageTypeResult8616:
    """Build one atomic pointer-class refusal with closed counters."""
    return ReturnStorageTypeResult8616(
        verdict=verdict,
        signedness=None,
        value_class=None,
        condition=None,
        failure=failure,
        stats=StorageTrialStats8616(
            raw_fact_count=1,
            normalized_fact_count=int(normalized),
            failure_count=1,
        ),
    )


def _definition_is_exact_ax_output_8616(
    definition: StorageReachingDefinition8616,
) -> bool:
    """Return whether one complete definition is the exact full AX call output."""
    storage = definition.source_storage
    return (
        definition.is_complete
        and definition.definition_kind is StorageDefinitionKind8616.CALL_OUTPUT
        and storage is not None
        and storage.is_exact
        and storage.kind is StorageIdentityKind8616.REGISTER
        and storage.width == 2
        and register_domain_for_name(storage.register) == AX
        and register_view_for_name(storage.register) == FULL16
        and definition.value.version is None
        and full_word_pointer_domain_8616(definition.value) == AX
    )


def classify_pointer_return_storage_8616(
    artifact: SSAFunctionArtifact,
    fact: CallerReturnUseFact8616,
    definition: StorageReachingDefinition8616,
) -> ReturnStorageTypeResult8616:
    """Prove a near-pointer return from one exact caller SSA dereference."""
    if artifact.function_addr != fact.caller_addr:
        return _refused_result_8616(
            ReturnStorageTypeFailure8616.CALLER_IDENTITY_CONFLICT,
            verdict=ReturnStorageTypeVerdict8616.CONFLICT,
        )
    if not fact.classified:
        return _refused_result_8616(ReturnStorageTypeFailure8616.RETURN_USE_UNKNOWN)
    if fact.verdict is not CallerReturnUseVerdict8616.USED:
        return _refused_result_8616(
            ReturnStorageTypeFailure8616.RETURN_NOT_OBSERVED,
            normalized=True,
        )
    if fact.kind is not CallsiteReturnUseKind8616.VALUE:
        return _refused_result_8616(
            ReturnStorageTypeFailure8616.RETURN_USE_NOT_VALUE,
            normalized=True,
        )
    if not _definition_is_exact_ax_output_8616(definition):
        return _refused_result_8616(
            ReturnStorageTypeFailure8616.CALL_OUTPUT_DEFINITION_UNKNOWN,
            normalized=True,
        )
    if definition.instr_addr != fact.callsite_addr:
        return _refused_result_8616(
            ReturnStorageTypeFailure8616.CALL_OUTPUT_DEFINITION_CONFLICT,
            verdict=ReturnStorageTypeVerdict8616.CONFLICT,
            normalized=True,
        )

    scan = scan_pointer_return_flow_8616(artifact, fact)
    evidence = scan.evidence
    if evidence is not None and evidence.complete:
        return ReturnStorageTypeResult8616(
            verdict=ReturnStorageTypeVerdict8616.PROVEN,
            signedness=StorageTrialSignedness8616.NOT_APPLICABLE,
            value_class=StorageTrialValueClass8616.POINTER,
            condition=None,
            failure=None,
            stats=StorageTrialStats8616(
                raw_fact_count=1,
                normalized_fact_count=1,
                classified_fact_count=1,
                materialized_count=1,
            ),
            pointer_use=evidence,
        )
    failure = scan.failure or ReturnStorageTypeFailure8616.POINTER_WITNESS_CONFLICT
    verdict = (
        ReturnStorageTypeVerdict8616.CONFLICT
        if failure in _CONFLICT_FAILURES_8616
        else ReturnStorageTypeVerdict8616.UNKNOWN_REFUSE
    )
    return _refused_result_8616(failure, verdict=verdict, normalized=True)


def proven_pointer_return_pointee_width_8616(
    artifact: SSAFunctionArtifact,
    pointer_use: ReturnPointerUseEvidence8616,
) -> int | None:
    """Map one byte-sliced SSA pointer use to a unique complete machine operand."""
    logical = artifact.logical_memory
    invalid_pointer_identity = (
        not pointer_use.complete
        or pointer_use.caller_addr != artifact.function_addr
    )
    invalid_logical_artifact = (
        logical is None
        or logical.function_addr != artifact.function_addr
        or not logical.closed
    )
    if invalid_pointer_identity or invalid_logical_artifact:
        return None
    assert logical is not None
    if (
        any(
            refusal.insn_addr == pointer_use.dereference_instruction_addr
            for refusal in logical.refusals
        )
    ):
        return None
    matches = tuple(
        access
        for access in logical.accesses
        if access.key.insn_addr == pointer_use.dereference_instruction_addr
        and access.kind in {IRMemoryAccessKind8616.READ, IRMemoryAccessKind8616.WRITE}
        and any(
            logical_memory_execution_address_matches_8616(
                pointer_use.address,
                access.address,
                execution_slice.source_byte_offset,
                access.address_bits,
            )
            for execution_slice in access.execution_slices
            if execution_slice.insn_addr == pointer_use.dereference_instruction_addr
        )
    )
    return matches[0].address.size if len(matches) == 1 else None
