"""Typed contracts for the single-entry-word value proof.

Layer: Widening.
Responsibility: own the immutable verdict/refusal/fact contracts emitted by
``entry_stack_word_values.prove_entry_stack_word_value_8616``. A word fact is
value-only provenance over two ordered adjacent initial entry-SS byte reads;
it is never a wider memory access, frame, argument, pointer, or return claim.
Consumes alias-proven storage identity.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from ..alias.entry_stack_byte_contracts import (
    EntryStackByteProof8616,
    EntryStackByteRead8616,
    EntryStackByteScope8616,
)
from ..ir.core import IRFunctionArtifact, MemSpace
from .entry_stack_word_bits import EntryStackWordBit8616


class EntryStackWordVerdict8616(StrEnum):
    """Aggregate verdict for one targeted word-value proof."""

    PROVEN = "proven"
    REFUSED = "refused"


class EntryStackWordRefusalKind8616(StrEnum):
    """Typed reasons a targeted word value or its provenance was refused."""

    CROSS_ARTIFACT_PROOF = "cross_artifact_proof"
    BYTE_PREFIX_NOT_PROVEN = "byte_prefix_not_proven"
    STALE_BYTE_PROOF = "stale_byte_proof"
    MISSING_ENTRY_BLOCK = "missing_entry_block"
    BAD_TARGET_INDEX = "bad_target_index"
    NON_SCALAR_TARGET = "non_scalar_target"
    UNSUPPORTED_TARGET_WIDTH = "unsupported_target_width"
    NO_PRODUCER_SITE = "no_producer_site"
    AMBIGUOUS_PRODUCER = "ambiguous_producer"
    FORWARD_TMP_DEFINITION = "forward_tmp_definition"
    STALE_TMP_VERSION = "stale_tmp_version"
    UNSUPPORTED_PRODUCER_OP = "unsupported_producer_op"
    UNSUPPORTED_OPERAND = "unsupported_operand"
    UNPROVEN_LOAD_SEED = "unproven_load_seed"
    BAD_PROJECTION = "bad_projection"
    SHIFT_COUNT_UNPROVEN = "shift_count_unproven"
    MISSING_BYTE_LANES = "missing_byte_lanes"
    WRONG_BIT_LANES = "wrong_bit_lanes"
    DUPLICATE_BYTE_ORIGIN = "duplicate_byte_origin"
    WRONG_BYTE_ORDER = "wrong_byte_order"
    NON_ADJACENT_BYTES = "non_adjacent_bytes"


@dataclass(frozen=True, slots=True)
class EntryStackWord8616:
    """One proven 16-bit definition equal to two ordered adjacent entry bytes.

    ``low_byte`` holds bits 0..7 and ``high_byte`` bits 8..15 of the defined
    value; both are Alias-owned initial entry-SS byte facts. ``target_*``
    identifies the exact defining instruction site in the entry block.
    """

    block_addr: int
    instr_index: int
    instruction_addr: int | None
    target_space: MemSpace
    target_tmp: int | None
    target_name: str | None
    target_version: int | None
    lane_provenance: tuple[EntryStackWordBit8616, ...]
    low_byte: EntryStackByteRead8616
    high_byte: EntryStackByteRead8616

    def to_dict(self) -> dict[str, object]:
        """Serialize this fact deterministically; identity stays object-bound."""
        return {
            "block_addr": self.block_addr,
            "instr_index": self.instr_index,
            "instruction_addr": self.instruction_addr,
            "target_space": self.target_space.value,
            "target_tmp": self.target_tmp,
            "target_name": self.target_name,
            "target_version": self.target_version,
            "lane_provenance": [
                {"producer_index": bit.capture.instr_index, "bit_index": bit.bit_index}
                for bit in self.lane_provenance
            ],
            "low_byte": self.low_byte.to_dict(),
            "high_byte": self.high_byte.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class EntryStackWordRefusal8616:
    """One typed refusal against the targeted word proof."""

    kind: EntryStackWordRefusalKind8616
    detail: str
    instr_index: int | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize this refusal deterministically."""
        return {
            "kind": self.kind.value,
            "detail": self.detail,
            "instr_index": self.instr_index,
        }


@dataclass(frozen=True, slots=True)
class EntryStackWordProof8616:
    """Closed-count result of one targeted entry-word value proof.

    ``artifact`` and ``byte_proof`` are retained by object identity; equal
    addresses or serialization are never proof of source ownership.
    """

    artifact: IRFunctionArtifact = field(compare=False)
    byte_proof: EntryStackByteProof8616 = field(compare=False)
    verdict: EntryStackWordVerdict8616 = EntryStackWordVerdict8616.REFUSED
    scope: EntryStackByteScope8616 = EntryStackByteScope8616.ENTRY_BLOCK_PREFIX
    fact: EntryStackWord8616 | None = None
    refusals: tuple[EntryStackWordRefusal8616, ...] = ()
    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    def to_dict(self) -> dict[str, object]:
        """Serialize counts, fact, and refusals deterministically."""
        return {
            "scope": self.scope.value,
            "verdict": self.verdict.value,
            "execution_scope": "initial_invocation",
            "function_addr": self.artifact.function_addr,
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
            "fact": None if self.fact is None else self.fact.to_dict(),
            "refusals": [refusal.to_dict() for refusal in self.refusals],
        }
