"""Classify split DX:AX returns from exact typed condition chains.

Layer: Types/Lowering.
Responsibility: prove one lexicographic wide comparison from canonical
ConditionIR, exact function SSA CFG edges, and per-piece Alias identities.
Consumes alias, widening, and typed facts. This module does not decode
assembly, inspect rendered C, mutate codegen, or publish function contracts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Sequence

from ..alias.domains import (
    AX,
    DX,
    FULL16,
    DomainKey,
    register_domain_for_name,
    register_view_for_name,
)
from ..caller_return_use_contracts import (
    CallerReturnUseFact8616,
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
)
from ..ir.condition_ir import ConditionIR
from ..ir.ssa_function import SSAFunctionArtifact
from .interprocedural_storage_contracts import (
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageTrialStats8616,
    StorageTrialValueClass8616,
    StorageUseEvidence8616,
)
from .interprocedural_storage_return_defs import CallOutputDefinitionResult8616
from .interprocedural_storage_return_split_conditions import (
    select_split_return_condition_8616,
    split_return_register_matches_8616,
)
from .interprocedural_storage_return_type_contracts import (
    ReturnSplitConditionUseEvidence8616,
    ReturnSplitPieceUse8616,
    ReturnStorageTypeFailure8616,
    ReturnStorageTypeResult8616,
    ReturnStorageTypeVerdict8616,
)

__all__ = ["classify_split_return_storage_8616"]


def _refused_result_8616(
    failure: ReturnStorageTypeFailure8616,
    *,
    verdict: ReturnStorageTypeVerdict8616 = (
        ReturnStorageTypeVerdict8616.UNKNOWN_REFUSE
    ),
    normalized: bool = False,
) -> ReturnStorageTypeResult8616:
    """Build one atomic split-return refusal with closed counters."""
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


def _output_pieces_8616(
    storages: tuple[StorageIdentity8616, ...],
) -> dict[DomainKey, StorageIdentity8616] | None:
    """Resolve exactly one full-word AX piece and one full-word DX piece."""
    if len(storages) != 2:
        return None
    pieces: dict[DomainKey, StorageIdentity8616] = {}
    for storage in storages:
        domain = _full_word_ax_dx_domain_8616(storage, pieces)
        if domain is None:
            return None
        pieces[domain] = storage
    return pieces if set(pieces) == {AX, DX} else None


def _exact_word_register_8616(storage: StorageIdentity8616) -> bool:
    """Return whether one storage is an exact full-word register piece."""
    return bool(
        storage.is_exact
        and storage.kind is StorageIdentityKind8616.REGISTER
        and storage.width == 2
    )


def _full_word_ax_dx_domain_8616(
    storage: StorageIdentity8616,
    pieces: dict[DomainKey, StorageIdentity8616],
) -> DomainKey | None:
    """Return the exact AX/DX domain for one full-word register piece."""
    domain = register_domain_for_name(storage.register)
    view = register_view_for_name(storage.register)
    if (
        domain is None
        or domain not in {AX, DX}
        or view != FULL16
        or domain in pieces
        or not _exact_word_register_8616(storage)
    ):
        return None
    return domain


def _piece_use_8616(
    artifact: SSAFunctionArtifact,
    storage: StorageIdentity8616,
    condition: ConditionIR,
    callsite_addr: int,
) -> tuple[StorageUseEvidence8616 | None, bool]:
    """Resolve one unique direct register read at a condition producer."""
    producer = condition.producer_insn
    if not isinstance(producer, int):
        return None, False
    candidates = tuple(
        (block.addr, index, producer)
        for block in artifact.blocks
        for index, instruction in enumerate(block.instrs)
        if instruction.addr == producer
        and any(
            split_return_register_matches_8616(argument, storage)
            for argument in instruction.args
        )
    )
    if len(candidates) != 1:
        return None, bool(candidates)
    block_addr, instr_index, instr_addr = candidates[0]
    return (
        StorageUseEvidence8616(
            block_addr=block_addr,
            instr_index=instr_index,
            instr_addr=instr_addr,
            callsite_addr=callsite_addr,
        ),
        False,
    )


def _definition_source_keys_8616(
    definitions: CallOutputDefinitionResult8616,
) -> tuple[tuple[object, ...], ...] | None:
    """Return exact source-storage keys or refuse an absent output source."""
    keys: list[tuple[object, ...]] = []
    for definition in definitions.definitions:
        source_storage = definition.source_storage
        if source_storage is None:
            return None
        keys.append(source_storage.key)
    return tuple(keys)


def _definitions_match_outputs_8616(
    definitions: CallOutputDefinitionResult8616,
    output_storages: tuple[StorageIdentity8616, ...],
) -> bool:
    """Return whether complete definitions name every output storage exactly."""
    definition_source_keys = _definition_source_keys_8616(definitions)
    return bool(
        definitions.complete
        and len(definitions.definitions) == len(output_storages)
        and definition_source_keys == tuple(storage.key for storage in output_storages)
    )


def _split_return_prelude_8616(
    artifact: SSAFunctionArtifact,
    fact: CallerReturnUseFact8616,
) -> ReturnStorageTypeResult8616 | None:
    """Return the refusal when caller identity or return use is unproven."""
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
    if fact.kind is not CallsiteReturnUseKind8616.CONDITION:
        return _refused_result_8616(
            ReturnStorageTypeFailure8616.RETURN_USE_NOT_CONDITION,
            normalized=True,
        )
    return None


def classify_split_return_storage_8616(
    artifact: SSAFunctionArtifact,
    fact: CallerReturnUseFact8616,
    definitions: CallOutputDefinitionResult8616,
    output_storages: tuple[StorageIdentity8616, ...],
    conditions: Sequence[ConditionIR],
) -> ReturnStorageTypeResult8616:
    """Prove a split scalar return from one exact wide condition chain."""
    prelude = _split_return_prelude_8616(artifact, fact)
    if prelude is not None:
        return prelude
    pieces = _output_pieces_8616(output_storages)
    if pieces is None:
        return _refused_result_8616(
            ReturnStorageTypeFailure8616.OUTPUT_STORAGE_CONFLICT,
            verdict=ReturnStorageTypeVerdict8616.CONFLICT,
            normalized=True,
        )
    if not _definitions_match_outputs_8616(definitions, output_storages):
        return _refused_result_8616(
            ReturnStorageTypeFailure8616.SPLIT_OUTPUT_DEFINITION_CONFLICT,
            verdict=ReturnStorageTypeVerdict8616.CONFLICT,
            normalized=True,
        )
    witness = fact.witness_instruction_addr
    if witness is None:
        return _refused_result_8616(ReturnStorageTypeFailure8616.RETURN_USE_UNKNOWN)
    candidate, failure = select_split_return_condition_8616(
        artifact,
        witness,
        conditions,
        pieces[DX],
        pieces[AX],
    )
    if candidate is None:
        conflict = failure in {
            ReturnStorageTypeFailure8616.SPLIT_CONDITION_CONFLICT,
            ReturnStorageTypeFailure8616.SPLIT_OPERAND_CONFLICT,
        }
        return _refused_result_8616(
            failure or ReturnStorageTypeFailure8616.SPLIT_CONDITION_NOT_FOUND,
            verdict=(
                ReturnStorageTypeVerdict8616.CONFLICT
                if conflict
                else ReturnStorageTypeVerdict8616.UNKNOWN_REFUSE
            ),
            normalized=True,
        )
    condition_by_domain = {
        DX: candidate.high_condition,
        AX: candidate.low_condition,
    }
    piece_evidence: list[ReturnSplitPieceUse8616] = []
    for domain, storage in pieces.items():
        condition = condition_by_domain[domain]
        use, conflicting = _piece_use_8616(
            artifact,
            storage,
            condition,
            fact.callsite_addr,
        )
        if use is None:
            return _refused_result_8616(
                (
                    ReturnStorageTypeFailure8616.SPLIT_WITNESS_CONFLICT
                    if conflicting
                    else ReturnStorageTypeFailure8616.SPLIT_WITNESS_NOT_FOUND
                ),
                verdict=(
                    ReturnStorageTypeVerdict8616.CONFLICT
                    if conflicting
                    else ReturnStorageTypeVerdict8616.UNKNOWN_REFUSE
                ),
                normalized=True,
            )
        piece_evidence.append(
            ReturnSplitPieceUse8616(
                storage=storage,
                condition=condition,
                use=use,
            )
        )
    evidence = ReturnSplitConditionUseEvidence8616(
        caller_addr=fact.caller_addr,
        callsite_addr=fact.callsite_addr,
        relation=candidate.relation,
        conditions=candidate.conditions,
        pieces=(piece_evidence[0], piece_evidence[1]),
        true_sink_addr=candidate.true_sink_addr,
        false_sink_addr=candidate.false_sink_addr,
        transparent_block_addrs=candidate.transparent_block_addrs,
    )
    if not evidence.complete:
        raise RuntimeError("complete split-return classification lost evidence")
    return ReturnStorageTypeResult8616(
        verdict=ReturnStorageTypeVerdict8616.PROVEN,
        signedness=candidate.signedness,
        value_class=StorageTrialValueClass8616.VALUE,
        condition=None,
        failure=None,
        stats=StorageTrialStats8616(1, 1, 1, 1),
        split_condition_use=evidence,
    )
