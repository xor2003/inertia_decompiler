# cython: language_level=3, infer_types=True
"""Resolve exact typed CALL producers for interprocedural return trials.

Layer: Types/Lowering.
Responsibility: bind an observed caller return use to the exact typed CALL and
materialize versionless CALL_OUTPUT reaching definitions with shared provenance.
Consumes alias, widening, and typed facts through Recovery metadata and
function SSA; does not infer return types or mutate codegen. Unknown targets,
uses, or storage identities are refusals.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum

from inertia.frontend.x86_16.frontend_direct_callsite_index import DecodedDirectCallsiteIndex8616
from inertia.ir.core import IRInstr, IRValue, MemSpace
from inertia.ir.ssa_function import SSAFunctionArtifact
from inertia.semantics.call_stack_effect_pipeline import CallSemanticProjection8616
from inertia.semantics.call_target_identity import x86_16_call_targets_equivalent_8616
from inertia.semantics.caller_return_use_contracts import (
    CallerReturnUseFact8616,
    CallerReturnUseVerdict8616,
)

from .call_target_ssa_binder import (
    CallTargetBindResult8616,
    CallTargetBindStage8616,
    bind_ssa_call_target_8616,
)
from .interprocedural_storage_contracts import (
    StorageDefinitionKind8616,
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageReachingDefinition8616,
    StorageTrialStats8616,
    ValueProvenance8616,
)
import dataclasses
import operator
import builtins

__all__ = [
    "CallOutputDefinitionFailure8616",
    "CallOutputDefinitionResult8616",
    "CallOutputDefinitionVerdict8616",
    "call_candidates_at_address_8616",
    "resolve_call_output_definitions_8616",
    "resolve_storage_call_output_definitions_8616",
]


class CallOutputDefinitionVerdict8616(StrEnum):
    """Outcome of resolving one observed call's physical output pieces."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"
    CONFLICT = "conflict"


class CallOutputDefinitionFailure8616(StrEnum):
    """Stable reasons why a call-output definition cannot be published."""

    CALLER_IDENTITY_CONFLICT = "caller_identity_conflict"
    RETURN_USE_UNKNOWN = "return_use_unknown"
    RETURN_NOT_OBSERVED = "return_not_observed"
    CALLSITE_NOT_FOUND = "callsite_not_found"
    CALLSITE_CONFLICT = "callsite_conflict"
    CALL_INSTRUCTION_INVALID = "call_instruction_invalid"
    CALL_TARGET_UNKNOWN = "call_target_unknown"
    CALL_TARGET_CONFLICT = "call_target_conflict"
    OUTPUT_STORAGE_UNKNOWN = "output_storage_unknown"
    OUTPUT_STORAGE_CONFLICT = "output_storage_conflict"


@dataclasses.dataclass(frozen=True, )
class CallOutputDefinitionResult8616:
    """Exact call-output definitions or one atomic typed refusal."""

    verdict: CallOutputDefinitionVerdict8616
    definitions: object
    provenance: ValueProvenance8616 | None
    failure: CallOutputDefinitionFailure8616 | None
    stats: StorageTrialStats8616

    @property
    def complete(self) -> cython.bint:
        """Return whether every requested output piece has one CALL producer."""
        return (
            self.verdict is CallOutputDefinitionVerdict8616.PROVEN
            and bool(self.definitions)
            and self.provenance is not None
            and self.failure is None
            and self.stats.complete
            and all(
                definition.is_complete
                and definition.definition_kind
                is StorageDefinitionKind8616.CALL_OUTPUT
                for definition in iter(self.definitions)
            )
        )


@cython.ccall
def _refused_result_8616(
    verdict: CallOutputDefinitionVerdict8616,
    failure: CallOutputDefinitionFailure8616,
    raw_count: cython.longlong,
    normalized_count: cython.longlong = 0,
) -> CallOutputDefinitionResult8616:
    """Build one atomic refusal without leaking partial definitions."""
    return CallOutputDefinitionResult8616(
        verdict=verdict,
        definitions=(),
        provenance=None,
        failure=failure,
        stats=StorageTrialStats8616(
            raw_fact_count=raw_count,
            normalized_fact_count=normalized_count,
            failure_count=1,
        ),
    )


def call_candidates_at_address_8616(
    artifact: SSAFunctionArtifact,
    callsite_addr: cython.longlong,
) -> tuple[tuple[cython.longlong, cython.longlong, IRInstr], ...]:
    """Return typed CALLs carrying one exact machine-call address."""
    return tuple(
        (block.addr, instr_index, instruction)
        for block in iter(artifact.blocks)
        for instr_index, instruction in builtins.iter(enumerate(block.instrs))
        if instruction.op == "CALL" and operator.eq(instruction.addr, callsite_addr)
    )


@cython.ccall
def _call_output_value_8616(storage: StorageIdentity8616) -> IRValue | None:
    """Project one exact physical output without inventing an SSA version."""
    address: object
    if storage.kind is StorageIdentityKind8616.REGISTER:
        return IRValue(space=MemSpace.REG, name=storage.register, size=storage.width)
    address = storage.address
    if address is None:
        return None
    name = address.base[0] if len(address.base) == 1 else None
    return IRValue(
        space=address.space,
        name=name,
        offset=address.offset,
        size=storage.width,
        expr=("call-output-storage",),
    )


@cython.ccall
def resolve_call_output_definitions_8616(
    artifact: SSAFunctionArtifact,
    fact: CallerReturnUseFact8616,
    callee_addr: cython.longlong,
    accepted_target_addrs: object,
    output_storages: object,
    *,
    project: object | None = None,
    callsite_index: DecodedDirectCallsiteIndex8616 | None = None,
    projection: CallSemanticProjection8616 | None = None,
) -> CallOutputDefinitionResult8616:
    """Bind exact return carriers to one observed typed CALL producer."""
    raw_count = len(output_storages)
    if operator.ne(artifact.function_addr, fact.caller_addr):
        return _refused_result_8616(
            CallOutputDefinitionVerdict8616.CONFLICT,
            CallOutputDefinitionFailure8616.CALLER_IDENTITY_CONFLICT,
            raw_count,
        )
    if not fact.classified:
        return _refused_result_8616(
            CallOutputDefinitionVerdict8616.UNKNOWN_REFUSE,
            CallOutputDefinitionFailure8616.RETURN_USE_UNKNOWN,
            raw_count,
        )
    if fact.verdict is not CallerReturnUseVerdict8616.USED:
        return _refused_result_8616(
            CallOutputDefinitionVerdict8616.UNKNOWN_REFUSE,
            CallOutputDefinitionFailure8616.RETURN_NOT_OBSERVED,
            raw_count,
        )
    return resolve_storage_call_output_definitions_8616(
        artifact,
        fact.caller_addr,
        fact.callsite_addr,
        callee_addr,
        accepted_target_addrs,
        output_storages,
        project=project,
        callsite_index=callsite_index,
        projection=projection,
    )


@cython.ccall
def _validated_call_gate_8616(
    artifact: SSAFunctionArtifact,
    caller_addr: cython.longlong,
    callsite_addr: cython.longlong,
    raw_count: cython.longlong,
) -> object:
    """Return the single proven CALL site or a typed refusal result."""
    if operator.ne(artifact.function_addr, caller_addr):
        return _refused_result_8616(
            CallOutputDefinitionVerdict8616.CONFLICT,
            CallOutputDefinitionFailure8616.CALLER_IDENTITY_CONFLICT,
            raw_count,
        )
    candidates = call_candidates_at_address_8616(artifact, callsite_addr)
    if not candidates:
        return _refused_result_8616(
            CallOutputDefinitionVerdict8616.UNKNOWN_REFUSE,
            CallOutputDefinitionFailure8616.CALLSITE_NOT_FOUND,
            raw_count,
        )
    if len(candidates) != 1:
        return _refused_result_8616(
            CallOutputDefinitionVerdict8616.CONFLICT,
            CallOutputDefinitionFailure8616.CALLSITE_CONFLICT,
            raw_count,
        )
    block_addr, instr_index, instruction = candidates[0]
    if instruction.op != "CALL" or instruction.dst is not None:
        return _refused_result_8616(
            CallOutputDefinitionVerdict8616.CONFLICT,
            CallOutputDefinitionFailure8616.CALL_INSTRUCTION_INVALID,
            raw_count,
        )
    if len(instruction.args) != 1 or not isinstance(instruction.args[0], IRValue):
        return _refused_result_8616(
            CallOutputDefinitionVerdict8616.UNKNOWN_REFUSE,
            CallOutputDefinitionFailure8616.CALL_TARGET_UNKNOWN,
            raw_count,
        )
    return block_addr, instr_index, instruction


def _call_target_match_8616(
    target_const: cython.longlong,
    accepted_target_addrs: object,
    project: object,
) -> cython.bint:
    """Return whether the constant callee matches accepted target evidence."""
    targets = frozenset(
        address
        for address in iter(accepted_target_addrs)
        if isinstance(address, int) and not isinstance(address, bool)
    )
    if not targets:
        return False
    return target_const in targets or (
        project is not None
        and any(
            x86_16_call_targets_equivalent_8616(project, target_const, accepted)
            for accepted in iter(targets)
        )
    )


_BOUND_CONFLICT_FAILURES_8616: dict[
    CallTargetBindStage8616, CallOutputDefinitionFailure8616
] = {
    CallTargetBindStage8616.SSA_CALLER_MISMATCH: CallOutputDefinitionFailure8616.CALLER_IDENTITY_CONFLICT,
    CallTargetBindStage8616.SSA_CALL_AMBIGUOUS: CallOutputDefinitionFailure8616.CALLSITE_CONFLICT,
    CallTargetBindStage8616.SSA_ARTIFACT_STALE: CallOutputDefinitionFailure8616.CALLSITE_CONFLICT,
    CallTargetBindStage8616.SEMANTIC_PROJECTION_INCOMPLETE: CallOutputDefinitionFailure8616.CALLSITE_CONFLICT,
    CallTargetBindStage8616.SEMANTIC_PROJECTION_SSA_MISMATCH: CallOutputDefinitionFailure8616.CALLSITE_CONFLICT,
    CallTargetBindStage8616.SEMANTIC_SSA_CONFLICT: CallOutputDefinitionFailure8616.CALLSITE_CONFLICT,
    CallTargetBindStage8616.SOURCE_IR_CONFLICT: CallOutputDefinitionFailure8616.CALLSITE_CONFLICT,
    CallTargetBindStage8616.SOURCE_IR_BLOCK_MISMATCH: CallOutputDefinitionFailure8616.CALLSITE_CONFLICT,
    CallTargetBindStage8616.EFFECTS_BLOCK_MISMATCH: CallOutputDefinitionFailure8616.CALLSITE_CONFLICT,
    CallTargetBindStage8616.EFFECTS_FACT_MISSING: CallOutputDefinitionFailure8616.CALLSITE_CONFLICT,
    CallTargetBindStage8616.EFFECTS_FACT_AMBIGUOUS: CallOutputDefinitionFailure8616.CALLSITE_CONFLICT,
    CallTargetBindStage8616.OUTPUTS_PREFIX_MISMATCH: CallOutputDefinitionFailure8616.CALLSITE_CONFLICT,
    CallTargetBindStage8616.OUTPUTS_SUFFIX_MISMATCH: CallOutputDefinitionFailure8616.CALLSITE_CONFLICT,
    CallTargetBindStage8616.SSA_ENRICHED_INDEX_MISMATCH: CallOutputDefinitionFailure8616.CALLSITE_CONFLICT,
    CallTargetBindStage8616.SSA_ENRICHED_ORIGIN_MISMATCH: CallOutputDefinitionFailure8616.CALLSITE_CONFLICT,
    CallTargetBindStage8616.SSA_ENRICHED_CALL_MISMATCH: CallOutputDefinitionFailure8616.CALLSITE_CONFLICT,
    CallTargetBindStage8616.RAW_IR_CONFLICT: CallOutputDefinitionFailure8616.CALLSITE_CONFLICT,
    CallTargetBindStage8616.SSA_RAW_BLOCK_MISMATCH: CallOutputDefinitionFailure8616.CALLSITE_CONFLICT,
    CallTargetBindStage8616.SSA_RAW_INDEX_MISMATCH: CallOutputDefinitionFailure8616.CALLSITE_CONFLICT,
    CallTargetBindStage8616.SSA_RAW_CALL_AMBIGUOUS: CallOutputDefinitionFailure8616.CALLSITE_CONFLICT,
    CallTargetBindStage8616.SSA_RAW_ORIGIN_MISMATCH: CallOutputDefinitionFailure8616.CALLSITE_CONFLICT,
    CallTargetBindStage8616.SSA_RAW_OPERAND_MISMATCH: CallOutputDefinitionFailure8616.CALLSITE_CONFLICT,
    CallTargetBindStage8616.PRODUCER_PROJECTION_MISMATCH: CallOutputDefinitionFailure8616.CALLSITE_CONFLICT,
    CallTargetBindStage8616.PRODUCER_AMBIGUOUS: CallOutputDefinitionFailure8616.CALLSITE_CONFLICT,
    CallTargetBindStage8616.PRODUCER_MISMATCH: CallOutputDefinitionFailure8616.CALLSITE_CONFLICT,
    CallTargetBindStage8616.DECODED_TARGET_AMBIGUOUS: CallOutputDefinitionFailure8616.CALL_TARGET_CONFLICT,
    CallTargetBindStage8616.RETAINED_BINDING_CONFLICT: CallOutputDefinitionFailure8616.CALL_TARGET_CONFLICT,
    CallTargetBindStage8616.TARGET_NOT_ADMITTED: CallOutputDefinitionFailure8616.CALL_TARGET_CONFLICT,
}

_BOUND_UNKNOWN_FAILURES_8616: dict[
    CallTargetBindStage8616, CallOutputDefinitionFailure8616
] = {
    CallTargetBindStage8616.SSA_CALL_NOT_FOUND: CallOutputDefinitionFailure8616.CALLSITE_NOT_FOUND,
    CallTargetBindStage8616.SSA_CALL_MALFORMED: CallOutputDefinitionFailure8616.CALL_TARGET_UNKNOWN,
    CallTargetBindStage8616.PROJECT_MISSING: CallOutputDefinitionFailure8616.CALL_TARGET_UNKNOWN,
    CallTargetBindStage8616.SEMANTIC_PROJECTION_MISSING: CallOutputDefinitionFailure8616.CALL_TARGET_UNKNOWN,
    CallTargetBindStage8616.SEMANTIC_SSA_NOT_REGISTERED: CallOutputDefinitionFailure8616.CALL_TARGET_UNKNOWN,
    CallTargetBindStage8616.SOURCE_IR_NOT_REGISTERED: CallOutputDefinitionFailure8616.CALL_TARGET_UNKNOWN,
    CallTargetBindStage8616.RAW_IR_NOT_REGISTERED: CallOutputDefinitionFailure8616.CALL_TARGET_UNKNOWN,
    CallTargetBindStage8616.SSA_ORIGIN_MISSING: CallOutputDefinitionFailure8616.CALL_TARGET_UNKNOWN,
    CallTargetBindStage8616.PRODUCER_UNBOUND: CallOutputDefinitionFailure8616.CALL_TARGET_UNKNOWN,
    CallTargetBindStage8616.DECODED_INDEX_MISSING: CallOutputDefinitionFailure8616.CALL_TARGET_UNKNOWN,
    CallTargetBindStage8616.DECODED_ENTRY_MISSING: CallOutputDefinitionFailure8616.CALL_TARGET_UNKNOWN,
    CallTargetBindStage8616.NATIVE_BINDING_REFUSED: CallOutputDefinitionFailure8616.CALL_TARGET_UNKNOWN,
}


@cython.ccall
def _bound_target_refusal_8616(
    binding: CallTargetBindResult8616,
    raw_count: cython.longlong,
) -> CallOutputDefinitionResult8616:
    """Translate a shared-binder refusal without leaking partial definitions."""
    conflict: object
    unknown: object
    conflict = _BOUND_CONFLICT_FAILURES_8616.get(binding.stage)
    if conflict is not None:
        return _refused_result_8616(
            CallOutputDefinitionVerdict8616.CONFLICT,
            conflict,
            raw_count,
            raw_count,
        )
    unknown = _BOUND_UNKNOWN_FAILURES_8616.get(binding.stage)
    return _refused_result_8616(
        CallOutputDefinitionVerdict8616.UNKNOWN_REFUSE,
        unknown or CallOutputDefinitionFailure8616.CALL_TARGET_UNKNOWN,
        raw_count,
        raw_count,
    )


@cython.ccall
def _proven_call_target_const_8616(
    artifact: SSAFunctionArtifact,
    caller_addr: cython.longlong,
    callsite_addr: cython.longlong,
    target: IRValue,
    accepted_target_addrs: object,
    raw_count: cython.longlong,
    project: object | None,
    callsite_index: DecodedDirectCallsiteIndex8616 | None,
    projection: CallSemanticProjection8616 | None,
) -> int | CallOutputDefinitionResult8616:
    """Return the admitted full-width callee coordinate or a typed refusal.

    A ``CONST`` operand keeps the existing equivalence path verbatim; a
    symbolic operand must close the shared SSA/native binder before its
    proven coordinate re-enters the same admitted-relation check.
    """
    if target.space is MemSpace.CONST and isinstance(target.const, int):
        return target.const
    binding = bind_ssa_call_target_8616(
        artifact,
        caller_addr,
        callsite_addr,
        accepted_target_addrs,
        project=project,
        callsite_index=callsite_index,
        projection=projection,
    )
    if not binding.complete or binding.target_addr is None:
        return _bound_target_refusal_8616(binding, raw_count)
    return binding.target_addr


def resolve_storage_call_output_definitions_8616(
    artifact: SSAFunctionArtifact,
    caller_addr: cython.longlong,
    callsite_addr: cython.longlong,
    callee_addr: cython.longlong,
    accepted_target_addrs: object,
    output_storages: object,
    *,
    project: object | None = None,
    callsite_index: DecodedDirectCallsiteIndex8616 | None = None,
    projection: CallSemanticProjection8616 | None = None,
) -> CallOutputDefinitionResult8616:
    """Bind exact register or addressed storage outputs to one typed CALL."""
    raw_count = len(output_storages)
    gate = _validated_call_gate_8616(artifact, caller_addr, callsite_addr, raw_count)
    if isinstance(gate, CallOutputDefinitionResult8616):
        return gate
    block_addr, instr_index, instruction = gate
    target = instruction.args[0]
    if not isinstance(target, IRValue):
        return _refused_result_8616(
            CallOutputDefinitionVerdict8616.UNKNOWN_REFUSE,
            CallOutputDefinitionFailure8616.CALL_TARGET_UNKNOWN,
            raw_count,
        )
    target_const = _proven_call_target_const_8616(
        artifact,
        caller_addr,
        callsite_addr,
        target,
        accepted_target_addrs,
        raw_count,
        project,
        callsite_index,
        projection,
    )
    if isinstance(target_const, CallOutputDefinitionResult8616):
        return target_const
    if not _call_target_match_8616(target_const, accepted_target_addrs, project):
        return _refused_result_8616(
            CallOutputDefinitionVerdict8616.CONFLICT,
            CallOutputDefinitionFailure8616.CALL_TARGET_CONFLICT,
            raw_count,
            raw_count,
        )
    if not output_storages:
        return _refused_result_8616(
            CallOutputDefinitionVerdict8616.UNKNOWN_REFUSE,
            CallOutputDefinitionFailure8616.OUTPUT_STORAGE_UNKNOWN,
            raw_count,
            raw_count,
        )
    values = tuple(_call_output_value_8616(storage) for storage in iter(output_storages))
    if any(not storage.is_exact for storage in iter(output_storages)) or any(
        value is None for value in iter(values)
    ):
        return _refused_result_8616(
            CallOutputDefinitionVerdict8616.UNKNOWN_REFUSE,
            CallOutputDefinitionFailure8616.OUTPUT_STORAGE_UNKNOWN,
            raw_count,
            raw_count,
        )
    if operator.ne(len({storage.key for storage in iter(output_storages)}), raw_count):
        return _refused_result_8616(
            CallOutputDefinitionVerdict8616.CONFLICT,
            CallOutputDefinitionFailure8616.OUTPUT_STORAGE_CONFLICT,
            raw_count,
            raw_count,
        )
    typed_values = tuple(value for value in iter(values) if value is not None)
    definitions = tuple(
        StorageReachingDefinition8616(
            value=value,
            block_addr=block_addr,
            instr_index=instr_index,
            instr_addr=callsite_addr,
            source_storage=storage,
            definition_kind=StorageDefinitionKind8616.CALL_OUTPUT,
        )
        for storage, value in builtins.iter(zip(output_storages, typed_values, strict=True))
    )
    provenance = ValueProvenance8616(
        function_addr=callee_addr,
        definition_addr=callsite_addr,
        token=callsite_addr,
    )
    return CallOutputDefinitionResult8616(
        verdict=CallOutputDefinitionVerdict8616.PROVEN,
        definitions=definitions,
        provenance=provenance,
        failure=None,
        stats=StorageTrialStats8616(
            raw_fact_count=raw_count,
            normalized_fact_count=raw_count,
            classified_fact_count=raw_count,
            materialized_count=raw_count,
        ),
    )
