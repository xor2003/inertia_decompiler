"""Classify input trial types and slice exact callee storage pieces.

Layer: Types/Lowering.
Responsibility: join independent signedness and pointer/value evidence for one
logical input, validate logical-memory source slices, then align its callee
stack identity with exact SSA source pieces.
Consumes alias, widening, and typed facts.
This module does not collect callers, resolve SSA, or mutate codegen.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from inertia.semantics.callsite_summary import (
    CallsiteArgumentClass8616,
    CallsitePushSourceKind8616,
    CallsiteSummary8616,
)

from inertia.ir.core import IRAddress, MemSpace
from inertia.ir.logical_memory_contracts import (
    IRLogicalMemoryArtifact8616,
    IRMemoryAccessKind8616,
)

from .callee_pointer_evidence import CalleePointerArgumentEvidence8616
from .condition_argument_type_facts import (
    ConditionArgumentFactsResult8616,
    StackArgumentSignedness8616,
)
from .interprocedural_storage_collection_contracts import (
    StorageTrialCollectionFailureKind8616,
)
from .interprocedural_storage_contracts import (
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageReachingDefinition8616,
    StorageTrialSignedness8616,
    StorageTrialValueClass8616,
)
from .interprocedural_storage_reaching_contracts import (
    CallArgumentDefinitionFailure8616,
    PhysicalCallArgument8616,
    PhysicalCallArgumentPiece8616,
)
from .modular_argument_type_facts import ModularArgumentTypeFacts8616

__all__ = [
    "InputArgumentTypeClassification8616",
    "callee_storage_pieces_8616",
    "classify_input_argument_8616",
    "logical_source_definitions_failure_8616",
]


@dataclass(frozen=True, slots=True)
class InputArgumentTypeClassification8616:
    """Signedness and value class proven for one logical input."""

    signedness: StorageTrialSignedness8616 | None
    value_class: StorageTrialValueClass8616 | None
    failure: StorageTrialCollectionFailureKind8616 | None


def _signedness_for_storage_8616(
    storage: IRAddress,
    facts: ConditionArgumentFactsResult8616,
) -> StorageTrialSignedness8616 | None:
    """Return one exact condition-proven signedness for a callee stack slice."""
    matching = tuple(
        fact
        for fact in facts.facts
        if fact.offset == storage.offset and fact.size == storage.size
    )
    if len(matching) != 1:
        return None
    return {
        StackArgumentSignedness8616.SIGN_INSENSITIVE: StorageTrialSignedness8616.SIGN_INSENSITIVE,
        StackArgumentSignedness8616.SIGNED: StorageTrialSignedness8616.SIGNED,
        StackArgumentSignedness8616.UNSIGNED: StorageTrialSignedness8616.UNSIGNED,
    }[matching[0].signedness]


def _logical_summary_class_8616(
    summary: CallsiteSummary8616,
    logical_index: int,
    argument_count: int,
) -> tuple[CallsiteArgumentClass8616 | None, bool]:
    """Return an independently populated logical class or malformed-shape flag."""
    classes = summary.logical_arg_classes
    if not classes:
        return None, False
    if len(classes) != argument_count:
        return None, True
    return classes[logical_index], False


def _source_is_bp_address_8616(argument: PhysicalCallArgument8616) -> bool:
    """Return whether structured call evidence proves an address-of source."""
    if len(argument.pieces) != 1 or not argument.pieces[0].source:
        return False
    source_kind = argument.pieces[0].source[0]
    return source_kind in {
        CallsitePushSourceKind8616.BP_ADDRESS,
        CallsitePushSourceKind8616.BP_ADDRESS.value,
    }


def _pointer_evidence_for_storage_8616(
    evidence: CalleePointerArgumentEvidence8616 | None,
    storage: IRAddress,
    logical_index: int,
) -> tuple[bool, bool]:
    """Return exact-pointer and ambiguous-pointer flags for one stack slot."""
    if evidence is None:
        return False, False
    start = storage.offset
    end = start + storage.size
    ambiguous_offsets = (
        evidence.ambiguous_displaced_stack_offsets
        + evidence.ambiguous_indexed_stack_offsets
    )
    ambiguous = any(start <= offset < end for offset in ambiguous_offsets)
    proven = logical_index in evidence.pointer_argument_indices or start in evidence.pointer_stack_offsets
    return proven, ambiguous


def _modular_sign_insensitive_proof_8616(
    modular_facts: ModularArgumentTypeFacts8616 | None,
    storage: IRAddress,
) -> bool:
    """Adopt one callee-bound modular word proof only for this exact slot.

    A bare PROVEN verdict is not identity: the retained result must be
    complete and bound to the requested census storage.
    """
    if modular_facts is None:
        return False
    proof = modular_facts.proof_for_8616(storage)
    return bool(proof.complete and proof.storage == storage)


def classify_input_argument_8616(
    summary: CallsiteSummary8616,
    physical: PhysicalCallArgument8616,
    storage: IRAddress,
    logical_index: int,
    argument_count: int,
    signedness_facts: ConditionArgumentFactsResult8616,
    pointer_evidence: CalleePointerArgumentEvidence8616 | None,
    modular_facts: ModularArgumentTypeFacts8616 | None = None,
) -> InputArgumentTypeClassification8616:
    """Join independent type-class evidence and refuse unknown interpretations."""
    summary_class, malformed_classes = _logical_summary_class_8616(
        summary,
        logical_index,
        argument_count,
    )
    if malformed_classes:
        return InputArgumentTypeClassification8616(
            None,
            None,
            StorageTrialCollectionFailureKind8616.VALUE_CLASS_CONFLICT,
        )
    pointer_proven, pointer_ambiguous = _pointer_evidence_for_storage_8616(
        pointer_evidence,
        storage,
        logical_index,
    )
    pointer_proven = pointer_proven or _source_is_bp_address_8616(physical)
    if pointer_ambiguous:
        return InputArgumentTypeClassification8616(
            None,
            None,
            StorageTrialCollectionFailureKind8616.VALUE_CLASS_UNKNOWN,
        )
    if pointer_proven or summary_class is CallsiteArgumentClass8616.POINTER:
        if pointer_proven and summary_class is CallsiteArgumentClass8616.VALUE:
            return InputArgumentTypeClassification8616(
                None,
                None,
                StorageTrialCollectionFailureKind8616.VALUE_CLASS_CONFLICT,
            )
        return InputArgumentTypeClassification8616(
            StorageTrialSignedness8616.NOT_APPLICABLE,
            StorageTrialValueClass8616.POINTER,
            None,
        )
    signedness = _signedness_for_storage_8616(storage, signedness_facts)
    if signedness is None:
        if signedness_facts.failure_count == 0 and _modular_sign_insensitive_proof_8616(
            modular_facts,
            storage,
        ):
            return InputArgumentTypeClassification8616(
                StorageTrialSignedness8616.SIGN_INSENSITIVE,
                StorageTrialValueClass8616.VALUE,
                None,
            )
        failure = (
            StorageTrialCollectionFailureKind8616.SIGNEDNESS_CONFLICT
            if signedness_facts.failure_count > 0
            else StorageTrialCollectionFailureKind8616.SIGNEDNESS_UNKNOWN
        )
        return InputArgumentTypeClassification8616(None, None, failure)
    return InputArgumentTypeClassification8616(
        signedness,
        StorageTrialValueClass8616.VALUE,
        None,
    )


def _definition_width_8616(definition: StorageReachingDefinition8616) -> int:
    """Return one exact SSA source-piece width."""
    source_storage = definition.source_storage
    if source_storage is not None:
        source_width = source_storage.width
        return source_width if isinstance(source_width, int) else 0
    value_width = definition.value.size
    return value_width if isinstance(value_width, int) else 0


def logical_source_definitions_failure_8616(
    logical_memory: IRLogicalMemoryArtifact8616 | None,
    function_addr: int,
    physical: PhysicalCallArgumentPiece8616,
    definitions: tuple[StorageReachingDefinition8616, ...],
) -> CallArgumentDefinitionFailure8616 | None:
    """Verify memory-source definitions against one authoritative logical read."""
    source = physical.source
    source_kind = source[0] if source else None
    is_bp_value = source_kind in {
        CallsitePushSourceKind8616.BP_VALUE,
        CallsitePushSourceKind8616.BP_VALUE.value,
    }
    is_global_value = source_kind in {
        CallsitePushSourceKind8616.GLOBAL_VALUE,
        CallsitePushSourceKind8616.GLOBAL_VALUE.value,
    }
    if not is_bp_value and not is_global_value:
        return None
    if (
        logical_memory is None
        or logical_memory.function_addr != function_addr
        or not logical_memory.closed
    ):
        return CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
    matches = tuple(
        access
        for access in logical_memory.accesses
        if access.kind is IRMemoryAccessKind8616.READ
        and access.key.insn_addr == physical.push_addr
        and access.address.size == physical.width
        and (
            (
                is_bp_value
                and len(source) in {2, 3}
                and access.address.space is MemSpace.SS
                and access.address.base == ("bp",)
                and access.address.offset == source[1]
            )
            or (
                is_global_value
                and len(source) == 3
                and access.address.space in {MemSpace.DS, MemSpace.ES}
                and not access.address.base
                and access.address.offset == source[1]
            )
        )
    )
    if not matches:
        return CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
    if len(matches) != 1:
        return CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_CONFLICT
    slices = matches[0].execution_slices
    definition_sites = tuple(
        (definition.block_addr, definition.instr_index) for definition in definitions
    )
    slice_sites = tuple((item.block_addr, item.instr_index) for item in slices)
    if definition_sites != slice_sites:
        return CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_CONFLICT
    return None


def callee_storage_pieces_8616(
    storage: IRAddress,
    definitions: tuple[StorageReachingDefinition8616, ...],
) -> tuple[StorageIdentity8616, ...] | None:
    """Slice one callee stack slot to match exact reaching-definition pieces."""
    widths = tuple(_definition_width_8616(definition) for definition in definitions)
    if not widths or any(width <= 0 for width in widths) or sum(widths) != storage.size:
        return None
    offset = storage.offset
    pieces: list[StorageIdentity8616] = []
    for width in widths:
        address = replace(storage, offset=offset, size=width)
        identity = StorageIdentity8616(
            kind=StorageIdentityKind8616.STACK,
            width=width,
            address=address,
        )
        if not identity.is_exact:
            return None
        pieces.append(identity)
        offset += width
    return tuple(pieces)
