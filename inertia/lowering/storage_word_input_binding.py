"""Bind accepted split input storage to a callee's proven logical word.

Layer: Types/Lowering.
Responsibility: check the exact contiguous accepted byte envelope, then consume
the existing modular-input owner to obtain its callee-bound proven word address.
The envelope is a query only: no piece gains segment proof or pointer authority.
This receipt does not authorize widening, native pointer representation or C
publication. Missing or conflicting evidence retains an explicit refusal.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum

from inertia.ir.core import IRAddress, MemSpace

from .interprocedural_storage_contracts import (
    StorageIdentityKind8616,
    StorageSlotContract8616,
    StorageTrialRole8616,
)
from .modular_argument_type_facts import ModularArgumentTypeFacts8616, ModularInputProof8616


class StorageWordInputFailure8616(StrEnum):
    """Why a logical word cannot be bound to accepted physical input pieces."""

    PIECE_ENVELOPE_UNPROVEN = "piece_envelope_unproven"
    CALLEE_WORD_UNPROVEN = "callee_word_unproven"


def _word_query_8616(slot: StorageSlotContract8616) -> IRAddress | None:
    """Form a default-proof-preserving query only from an exact word envelope."""
    if slot.role is not StorageTrialRole8616.INPUT or not slot.pieces:
        return None
    first = slot.pieces[0].address
    if first is None or first.space is not MemSpace.SS or first.base != ("bp",):
        return None
    offset = first.offset
    for piece in slot.pieces:
        address = piece.address
        if (
            piece.kind is not StorageIdentityKind8616.STACK
            or type(piece.width) is not int
            or not piece.is_exact
            or address is None
        ):
            return None
        if (
            address.space is not first.space
            or address.base != first.base
            or address.offset != offset
            or address.version != first.version
        ):
            return None
        if (
            address.expr is not None
            or address.base_values
        ):
            return None
        offset += piece.width
    return replace(first, size=2) if offset == first.offset + 2 else None


@dataclass(frozen=True, slots=True)
class StorageWordInputBinding8616:
    """Replayable slot-to-callee receipt with no native-pointer authority."""

    slot: StorageSlotContract8616
    callee_addr: int
    proof: ModularInputProof8616 | None
    failure: StorageWordInputFailure8616 | None
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def complete(self) -> bool:
        """Replay the exact envelope and retained callee-bound word proof."""
        counts = (self.raw_fact_count, self.normalized_fact_count,
                  self.classified_fact_count, self.materialized_count, self.failure_count)
        if self.failure is not None or counts != (1, 1, 1, 1, 0):
            return False
        if any(type(count) is not int for count in counts):
            return False
        query = _word_query_8616(self.slot)
        proof = self.proof
        return bool(query is not None and proof is not None and proof.complete
                    and proof.callee_addr == self.callee_addr and proof.storage == query)


def bind_storage_word_input_8616(
    slot: StorageSlotContract8616, facts: ModularArgumentTypeFacts8616,
) -> StorageWordInputBinding8616:
    """Bind physical input pieces to existing binary word evidence or refuse."""
    query = _word_query_8616(slot)
    proof = facts.proof_for_8616(query) if query is not None else None
    failure = None
    if query is None:
        failure = StorageWordInputFailure8616.PIECE_ENVELOPE_UNPROVEN
    elif proof is None or not proof.complete:
        failure = StorageWordInputFailure8616.CALLEE_WORD_UNPROVEN
    accepted = int(failure is None)
    return StorageWordInputBinding8616(slot, facts.callee_addr, proof, failure,
                                      1, int(query is not None), accepted, accepted, 1 - accepted)
