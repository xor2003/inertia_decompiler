"""Materialize one typed callsite return into exact storage trials.

Layer: Types/Lowering.
Responsibility: resolve one caller SSA artifact, CALL_OUTPUT producer, scalar or
pointer type proof, and exact use instruction into physical return pieces.
Consumes Semantics-owned terminal storage, Alias identities, function SSA, and
typed conditions. This module does not collect caller censuses, mutate codegen,
run SCC resolution, or publish interfaces.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from ..alias.domains import register_domain_for_name, register_view_for_name
from ..analysis_helpers import resolve_direct_call_target_from_instruction_8616
from ..caller_return_use_contracts import (
    AxValueView8616,
    CallerReturnUseFact8616,
    CallsiteReturnUseKind8616,
)
from ..frontend_function_boundary import ExactFunctionRangeBoundary8616
from ..ir import IRValue, MemSpace
from ..ir.condition_ir import ConditionIR
from ..ir.function_ssa_registry import (
    FunctionSSAArtifactFailure8616,
)
from ..ir.ssa_function import SSAFunctionArtifact
from ..semantics.call_stack_effect_pipeline import (
    semantic_function_ssa_artifact_at_address_8616,
)
from ..semantics.call_target_evidence_8616 import (
    resolve_call_target_evidence_8616,
)
from ..semantics.terminal_return_storage import TerminalReturnStorage8616
from .condition_transfer import collect_typed_condition_artifacts_8616
from .interprocedural_storage_caller_context import CallerSSAContext8616
from .interprocedural_storage_contracts import (
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageTrial8616,
    StorageTrialRole8616,
    StorageTrialValueClass8616,
    StorageUseEvidence8616,
)
from .interprocedural_storage_return_collection_contracts import (
    ReturnStorageTrialCollectionFailure8616,
    ReturnStorageTrialCollectionFailureKind8616,
)
from .interprocedural_storage_return_defs import (
    CallOutputDefinitionFailure8616,
    CallOutputDefinitionResult8616,
    CallOutputDefinitionVerdict8616,
    resolve_call_output_definitions_8616,
)
from .interprocedural_storage_return_pointer import (
    classify_pointer_return_storage_8616,
    proven_pointer_return_pointee_width_8616,
)
from .interprocedural_storage_return_pointer_witness import (
    pointer_return_witness_use_8616,
)
from .interprocedural_storage_return_split import (
    classify_split_return_storage_8616,
)
from .interprocedural_storage_return_type_contracts import (
    ReturnPointerUseEvidence8616,
    ReturnStorageTypeFailure8616,
    ReturnStorageTypeResult8616,
    ReturnStorageTypeVerdict8616,
)
from .interprocedural_storage_return_types import (
    classify_return_storage_type_8616,
)
from .return_witness_source import distinct_return_witness_sources_8616

__all__ = [
    "materialize_callsite_return_trials_8616",
    "return_output_storages_8616",
]


def _failure_8616(
    kind: ReturnStorageTrialCollectionFailureKind8616,
    callee_addr: int,
    fact: CallerReturnUseFact8616,
    *,
    ssa_failure: FunctionSSAArtifactFailure8616 | None = None,
    definition_failure: CallOutputDefinitionFailure8616 | None = None,
    type_failure: ReturnStorageTypeFailure8616 | None = None,
) -> ReturnStorageTrialCollectionFailure8616:
    """Build one callsite-local refusal with retained upstream evidence."""
    return ReturnStorageTrialCollectionFailure8616(
        kind=kind,
        callee_addr=callee_addr,
        caller_addr=fact.caller_addr,
        callsite_addr=fact.callsite_addr,
        ssa_failure=ssa_failure,
        definition_failure=definition_failure,
        type_failure=type_failure,
    )


def return_output_storages_8616(
    storage: TerminalReturnStorage8616,
) -> tuple[StorageIdentity8616, ...]:
    """Lower one Semantics-owned terminal carrier to exact Alias identities."""
    pieces = {
        TerminalReturnStorage8616.NONE: (),
        TerminalReturnStorage8616.CALL_OUTPUT: (),
        TerminalReturnStorage8616.AL: (("al", 1),),
        TerminalReturnStorage8616.AH: (("ah", 1),),
        TerminalReturnStorage8616.AX: (("ax", 2),),
        TerminalReturnStorage8616.DX_AX: (("ax", 2), ("dx", 2)),
    }[storage]
    return tuple(
        StorageIdentity8616(
            kind=StorageIdentityKind8616.REGISTER,
            width=width,
            register=register,
        )
        for register, width in pieces
    )


def _witness_use_8616(
    artifact: SSAFunctionArtifact,
    fact: CallerReturnUseFact8616,
    classification: ReturnStorageTypeResult8616,
    output_storages: tuple[StorageIdentity8616, ...],
) -> tuple[tuple[StorageUseEvidence8616, ...] | None, bool]:
    """Resolve exact SSA uses aligned with every physical output piece."""
    split_use = classification.split_condition_use
    if split_use is not None:
        uses_by_storage = {
            piece.storage.key: piece.use for piece in split_use.pieces
        }
        if len(uses_by_storage) != len(split_use.pieces):
            return None, True
        uses = tuple(
            uses_by_storage[storage.key]
            for storage in output_storages
            if storage.key in uses_by_storage
        )
        return (uses, False) if len(uses) == len(output_storages) else (None, False)

    pointer_use = classification.pointer_use
    if pointer_use is not None:
        result: tuple[tuple[StorageUseEvidence8616, ...] | None, bool] = pointer_return_witness_use_8616(
            artifact,
            fact,
            pointer_use,
            output_storages,
        )
        return result

    def _reads_output(value: object) -> bool:
        """Match one IR operand to an exact Alias-owned output view."""
        if not isinstance(value, IRValue) or value.space is not MemSpace.REG:
            return False
        if fact.kind is CallsiteReturnUseKind8616.CONDITION and value.expr is not None:
            return False
        return any(
            (
                value.size == storage.width
                and register_domain_for_name(value.name)
                == register_domain_for_name(storage.register)
                and register_view_for_name(value.name)
                == register_view_for_name(storage.register)
            )
            or (
                fact.byte_extension is not None
                and fact.observed_value_view is AxValueView8616.AX
                and storage.width == 1
                and register_view_for_name(storage.register)
                == register_view_for_name("al")
                and value.size == 2
                and register_domain_for_name(value.name)
                == register_domain_for_name(storage.register)
                and register_view_for_name(value.name)
                == register_view_for_name("ax")
            )
            for storage in output_storages
        )

    candidates = tuple(
        (block.addr, instr_index, instruction.addr)
        for block in artifact.blocks
        for instr_index, instruction in enumerate(block.instrs)
        if isinstance(instruction.addr, int) and instruction.addr == fact.witness_instruction_addr
        and any(_reads_output(argument) for argument in instruction.args)
    )
    if len(candidates) != 1:
        # A CMP expands into arithmetic and architectural flag operations.
        # These are one physical condition witness, not distinct caller uses.
        # Keep all other use kinds strict and refuse multiple blocks or values.
        sites = {(block_addr, instr_addr) for block_addr, _, instr_addr in candidates}
        values = tuple(
            argument
            for block in artifact.blocks
            for instruction in block.instrs
            if instruction.addr == fact.witness_instruction_addr
            for argument in instruction.args
            if isinstance(argument, IRValue) and _reads_output(argument)
        )
        same_known_value = bool(values) and values[0].version is not None and all(
            value == values[0] for value in values
        )
        if (
            fact.kind is not CallsiteReturnUseKind8616.CONDITION
            or len(sites) != 1
            or not distinct_return_witness_sources_8616(artifact, candidates)
            or not same_known_value
        ):
            return None, bool(candidates)
    block_addr, instr_index, instr_addr = candidates[0]
    return (
        (
            StorageUseEvidence8616(
                block_addr=block_addr,
                instr_index=instr_index,
                instr_addr=instr_addr,
                callsite_addr=fact.callsite_addr,
            ),
        ),
        False,
    )


def _classify_return_8616(
    project: object,
    artifact: SSAFunctionArtifact,
    fact: CallerReturnUseFact8616,
    definitions: CallOutputDefinitionResult8616,
    output_storages: tuple[StorageIdentity8616, ...],
    conditions_by_caller: dict[int, tuple[ConditionIR, ...]],
    caller_function: object | None,
) -> ReturnStorageTypeResult8616 | None:
    """Dispatch one exact use kind to its owning typed classifier."""
    if fact.kind is CallsiteReturnUseKind8616.CONDITION:
        conditions = conditions_by_caller.get(fact.caller_addr)
        if conditions is None:
            collected, _edge_evidence = collect_typed_condition_artifacts_8616(
                project,
                fact.caller_addr,
                function=caller_function,
            )
            conditions = tuple(collected)
            conditions_by_caller[fact.caller_addr] = conditions
        if len(output_storages) == 1:
            return classify_return_storage_type_8616(
                fact,
                output_storages,
                conditions,
            )
        return classify_split_return_storage_8616(
            artifact,
            fact,
            definitions,
            output_storages,
            conditions,
        )
    if (
        fact.kind is CallsiteReturnUseKind8616.VALUE
        and fact.byte_extension is not None
    ):
        return classify_return_storage_type_8616(
            fact,
            output_storages,
            (),
        )
    if (
        fact.kind is CallsiteReturnUseKind8616.VALUE
        and len(definitions.definitions) == 1
    ):
        return classify_pointer_return_storage_8616(
            artifact,
            fact,
            definitions.definitions[0],
        )
    return None


def materialize_callsite_return_trials_8616(
    project: object,
    callee_addr: int,
    fact: CallerReturnUseFact8616,
    output_storages: tuple[StorageIdentity8616, ...],
    accepted_target_addrs: tuple[int, ...],
    conditions_by_caller: dict[int, tuple[ConditionIR, ...]],
    caller_context: CallerSSAContext8616 | None = None,
) -> tuple[tuple[StorageTrial8616, ...] | None, ReturnStorageTrialCollectionFailure8616 | None]:
    """Materialize one callsite's exact return pieces or one typed refusal."""
    caller_project = project if caller_context is None else caller_context.evidence_project
    caller_function = None if caller_context is None else caller_context.caller_function
    if caller_project is None:
        raise TypeError("complete caller SSA context lost its evidence project")
    ssa = semantic_function_ssa_artifact_at_address_8616(
        caller_project, fact.caller_addr, function=caller_function
    )
    artifact = ssa.artifact
    if artifact is None:
        return None, _failure_8616(
            ReturnStorageTrialCollectionFailureKind8616.CALLER_SSA_UNAVAILABLE,
            callee_addr,
            fact,
            ssa_failure=ssa.failure,
        )
    evidence = resolve_call_target_evidence_8616(
        caller_project,
        fact.caller_addr,
        boundary=(
            caller_function
            if isinstance(caller_function, ExactFunctionRangeBoundary8616)
            else None
        ),
        direct_target_resolver=lambda instruction: (
            resolve_direct_call_target_from_instruction_8616(
                caller_project, instruction
            )
        ),
    )
    definitions = resolve_call_output_definitions_8616(
        artifact,
        fact,
        callee_addr,
        accepted_target_addrs,
        output_storages,
        project=caller_project,
        callsite_index=evidence.callsite_index if evidence.complete else None,
        projection=evidence.projection if evidence.complete else None,
    )
    if not definitions.complete:
        kind = (
            ReturnStorageTrialCollectionFailureKind8616.CALL_OUTPUT_DEFINITION_CONFLICT
            if definitions.verdict is CallOutputDefinitionVerdict8616.CONFLICT
            else ReturnStorageTrialCollectionFailureKind8616.CALL_OUTPUT_DEFINITION_REFUSED
        )
        return None, _failure_8616(
            kind,
            callee_addr,
            fact,
            definition_failure=definitions.failure,
        )
    classification = _classify_return_8616(
        caller_project,
        artifact,
        fact,
        definitions,
        output_storages,
        conditions_by_caller,
        caller_function,
    )
    if classification is None:
        return None, _failure_8616(
            ReturnStorageTrialCollectionFailureKind8616.RETURN_USE_UNSUPPORTED,
            callee_addr,
            fact,
        )
    if not classification.complete:
        kind = (
            ReturnStorageTrialCollectionFailureKind8616.RETURN_TYPE_CONFLICT
            if classification.verdict is ReturnStorageTypeVerdict8616.CONFLICT
            else ReturnStorageTrialCollectionFailureKind8616.RETURN_TYPE_REFUSED
        )
        return None, _failure_8616(
            kind,
            callee_addr,
            fact,
            type_failure=classification.failure,
        )
    uses, conflicting_use = _witness_use_8616(
        artifact,
        fact,
        classification,
        output_storages,
    )
    if uses is None:
        return None, _failure_8616(
            (
                ReturnStorageTrialCollectionFailureKind8616.WITNESS_CONFLICT
                if conflicting_use
                else ReturnStorageTrialCollectionFailureKind8616.WITNESS_NOT_FOUND
            ),
            callee_addr,
            fact,
        )
    provenance = definitions.provenance
    signedness = classification.signedness
    value_class = classification.value_class
    if provenance is None or signedness is None or value_class is None:
        raise RuntimeError("complete return classification lost typed evidence")
    pointee_width_bytes: int | None = None
    pointer_use: ReturnPointerUseEvidence8616 | None = None
    if value_class is StorageTrialValueClass8616.POINTER:
        pointer_use = classification.pointer_use
        if pointer_use is None or not pointer_use.complete:
            raise RuntimeError("complete pointer return lost exact dereference evidence")
        pointee_width_bytes = proven_pointer_return_pointee_width_8616(
            artifact, pointer_use,
        )
    piece_count = len(output_storages)
    trials = tuple(
        StorageTrial8616(
            callee_addr=callee_addr,
            caller_addr=fact.caller_addr,
            callsite_addr=fact.callsite_addr,
            role=StorageTrialRole8616.RETURN,
            logical_index=0,
            piece_index=piece_index,
            piece_count=piece_count,
            storage=storage,
            reaching_definition=definition,
            use=use,
            signedness=signedness,
            value_class=value_class,
            provenance=provenance,
            pointee_width_bytes=pointee_width_bytes,
            pointer_use=pointer_use,
        )
        for piece_index, (storage, definition, use) in enumerate(
            zip(
                output_storages,
                definitions.definitions,
                uses,
                strict=True,
            )
        )
    )
    return trials, None
