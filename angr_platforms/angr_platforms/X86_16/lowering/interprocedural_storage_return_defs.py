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

from dataclasses import dataclass
from enum import StrEnum

from ..call_target_identity import x86_16_call_targets_equivalent_8616
from ..caller_return_use_contracts import (
    CallerReturnUseFact8616,
    CallerReturnUseVerdict8616,
)
from ..ir import IRInstr, IRValue, MemSpace
from ..ir.ssa_function import SSAFunctionArtifact
from .interprocedural_storage_contracts import (
    StorageDefinitionKind8616,
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageReachingDefinition8616,
    StorageTrialStats8616,
    ValueProvenance8616,
)

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


@dataclass(frozen=True, slots=True)
class CallOutputDefinitionResult8616:
    """Exact call-output definitions or one atomic typed refusal."""

    verdict: CallOutputDefinitionVerdict8616
    definitions: tuple[StorageReachingDefinition8616, ...]
    provenance: ValueProvenance8616 | None
    failure: CallOutputDefinitionFailure8616 | None
    stats: StorageTrialStats8616

    @property
    def complete(self) -> bool:
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
                for definition in self.definitions
            )
        )


def _refused_result_8616(
    verdict: CallOutputDefinitionVerdict8616,
    failure: CallOutputDefinitionFailure8616,
    raw_count: int,
    normalized_count: int = 0,
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
    callsite_addr: int,
) -> tuple[tuple[int, int, IRInstr], ...]:
    """Return typed CALLs carrying one exact machine-call address."""
    return tuple(
        (block.addr, instr_index, instruction)
        for block in artifact.blocks
        for instr_index, instruction in enumerate(block.instrs)
        if instruction.op == "CALL" and instruction.addr == callsite_addr
    )


def _call_output_value_8616(storage: StorageIdentity8616) -> IRValue | None:
    """Project one exact physical output without inventing an SSA version."""
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


def resolve_call_output_definitions_8616(
    artifact: SSAFunctionArtifact,
    fact: CallerReturnUseFact8616,
    callee_addr: int,
    accepted_target_addrs: tuple[int, ...],
    output_storages: tuple[StorageIdentity8616, ...],
    *,
    project: object | None = None,
) -> CallOutputDefinitionResult8616:
    """Bind exact return carriers to one observed typed CALL producer."""
    raw_count = len(output_storages)
    if artifact.function_addr != fact.caller_addr:
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
    )


def _validated_call_gate_8616(
    artifact: SSAFunctionArtifact,
    caller_addr: int,
    callsite_addr: int,
    raw_count: int,
) -> tuple[int, int, IRInstr] | CallOutputDefinitionResult8616:
    """Return the single proven CALL site or a typed refusal result."""
    if artifact.function_addr != caller_addr:
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
    target_const: int,
    accepted_target_addrs: tuple[int, ...],
    project: object | None,
) -> bool:
    """Return whether the constant callee matches accepted target evidence."""
    targets = frozenset(
        address
        for address in accepted_target_addrs
        if isinstance(address, int) and not isinstance(address, bool)
    )
    if not targets:
        return False
    return target_const in targets or (
        project is not None
        and any(
            x86_16_call_targets_equivalent_8616(project, target_const, accepted)
            for accepted in targets
        )
    )


def resolve_storage_call_output_definitions_8616(
    artifact: SSAFunctionArtifact,
    caller_addr: int,
    callsite_addr: int,
    callee_addr: int,
    accepted_target_addrs: tuple[int, ...],
    output_storages: tuple[StorageIdentity8616, ...],
    *,
    project: object | None = None,
) -> CallOutputDefinitionResult8616:
    """Bind exact register or addressed storage outputs to one typed CALL."""
    raw_count = len(output_storages)
    gate = _validated_call_gate_8616(artifact, caller_addr, callsite_addr, raw_count)
    if isinstance(gate, CallOutputDefinitionResult8616):
        return gate
    block_addr, instr_index, instruction = gate
    target = instruction.args[0]
    if not isinstance(target, IRValue) or target.space is not MemSpace.CONST or not isinstance(
        target.const, int
    ):
        return _refused_result_8616(
            CallOutputDefinitionVerdict8616.UNKNOWN_REFUSE,
            CallOutputDefinitionFailure8616.CALL_TARGET_UNKNOWN,
            raw_count,
        )
    if not _call_target_match_8616(target.const, accepted_target_addrs, project):
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
    values = tuple(_call_output_value_8616(storage) for storage in output_storages)
    if any(not storage.is_exact for storage in output_storages) or any(
        value is None for value in values
    ):
        return _refused_result_8616(
            CallOutputDefinitionVerdict8616.UNKNOWN_REFUSE,
            CallOutputDefinitionFailure8616.OUTPUT_STORAGE_UNKNOWN,
            raw_count,
            raw_count,
        )
    if len({storage.key for storage in output_storages}) != raw_count:
        return _refused_result_8616(
            CallOutputDefinitionVerdict8616.CONFLICT,
            CallOutputDefinitionFailure8616.OUTPUT_STORAGE_CONFLICT,
            raw_count,
            raw_count,
        )
    typed_values = tuple(value for value in values if value is not None)
    definitions = tuple(
        StorageReachingDefinition8616(
            value=value,
            block_addr=block_addr,
            instr_index=instr_index,
            instr_addr=callsite_addr,
            source_storage=storage,
            definition_kind=StorageDefinitionKind8616.CALL_OUTPUT,
        )
        for storage, value in zip(output_storages, typed_values, strict=True)
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
