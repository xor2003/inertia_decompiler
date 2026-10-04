"""Typed contracts for the entry-block-prefix SS byte-read proof.

Layer: Alias.
Responsibility: own the immutable scope/verdict/refusal/fact contracts emitted
by ``entry_stack_bytes.prove_entry_stack_bytes_8616``. No frame-coordinate or
producer logic lives here; this module is declarative so the proof consumer
and any diagnostic consumers share one typed truth. A prefix result never
masquerades as a whole-function proof.

Owns storage identity contracts for entry-SP-relative SS byte reads.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from ..ir.core import IRFunctionArtifact
from .stack_pointer_snapshots import FrameRegister8616


class EntryStackByteScope8616(StrEnum):
    """Proof scope; a prefix result never masquerades as a whole-function proof.

    ``ENTRY_BLOCK_PREFIX`` asserts only the initial invocation of the unique
    entry block: coordinates are entry-SP-relative and do not survive a revisit
    of the entry address, which is refused structurally instead.
    """

    ENTRY_BLOCK_PREFIX = "entry_block_prefix"


class EntryStackByteVerdict8616(StrEnum):
    """Aggregate verdict over the entry-block prefix candidates."""

    PROVEN = "proven"
    PARTIAL = "partial"
    REFUSED = "refused"


class EntryStackByteRefusalKind8616(StrEnum):
    """Typed reasons an entry-byte candidate or the whole proof was refused."""

    MISSING_ENTRY_BLOCK = "missing_entry_block"
    DUPLICATE_ENTRY_BLOCK = "duplicate_entry_block"
    ENTRY_REENTRY = "entry_reentry"
    RAW_IR_REFUSAL = "raw_ir_refusal"
    NO_LOAD_CANDIDATES = "no_load_candidates"
    PRIOR_MEMORY_WRITE = "prior_memory_write"
    PRIOR_CALL = "prior_call"
    PRIOR_CONTROL_FLOW = "prior_control_flow"
    PRIOR_UNKNOWN_OPERATION = "prior_unknown_operation"
    SS_IDENTITY_LOST = "ss_identity_lost"
    NON_SS_ADDRESS = "non_ss_address"
    UNSTABLE_ADDRESS = "unstable_address"
    UNPROVEN_SEGMENT = "unproven_segment"
    UNSUPPORTED_WIDTH = "unsupported_width"
    WIDTH_DISAGREEMENT = "width_disagreement"
    MISSING_FRAME_BASE = "missing_frame_base"
    WRAP_GEOMETRY = "wrap_geometry"
    BAD_DESTINATION = "bad_destination"
    BAD_ADDRESS_ARGUMENT = "bad_address_argument"


@dataclass(frozen=True, slots=True)
class EntryStackByteRead8616:
    """One proven LOAD of immutable SS bytes at exact entry-SP offsets.

    ``producer_tmp`` is the LOAD's own destination temporary identity;
    ``base_producer_tmp``/``base_producer_index`` identify the observed
    instruction whose exact production earned the captured frame coordinate.
    """

    block_addr: int
    instr_index: int
    instruction_addr: int | None
    producer_tmp: int
    base_producer_tmp: int | None
    base_producer_index: int | None
    base_register: FrameRegister8616
    base_entry_sp_offset: int
    address_offset: int
    byte_offsets: tuple[int, ...]
    width: int

    def to_dict(self) -> dict[str, object]:
        """Serialize this fact for diagnostics; identity stays object-bound."""
        return {
            "block_addr": self.block_addr,
            "instr_index": self.instr_index,
            "instruction_addr": self.instruction_addr,
            "producer_tmp": self.producer_tmp,
            "base_producer_tmp": self.base_producer_tmp,
            "base_producer_index": self.base_producer_index,
            "base_register": self.base_register,
            "width": self.width,
            "base_entry_sp_offset": self.base_entry_sp_offset,
            "address_offset": self.address_offset,
            "byte_offsets": list(self.byte_offsets),
        }


@dataclass(frozen=True, slots=True)
class EntryStackByteRefusal8616:
    """One typed refusal against a candidate or the whole prefix proof."""

    kind: EntryStackByteRefusalKind8616
    detail: str
    block_addr: int | None = None
    instr_index: int | None = None


@dataclass(frozen=True, slots=True)
class EntryStackByteProof8616:
    """Closed-count result of the entry-block-prefix byte proof.

    ``artifact`` is retained by object identity; serialized hashes or function
    addresses are never proof of source ownership, and no process-local object
    identifier is emitted in the deterministic projection. Counts follow the
    pipeline evidence loop: raw LOADs observed, shape-normalized candidates,
    classified decisions, materialized facts, and failures (all refusals,
    including structural ones).
    """

    artifact: IRFunctionArtifact = field(compare=False)
    verdict: EntryStackByteVerdict8616 = EntryStackByteVerdict8616.REFUSED
    scope: EntryStackByteScope8616 = EntryStackByteScope8616.ENTRY_BLOCK_PREFIX
    facts: tuple[EntryStackByteRead8616, ...] = ()
    refusals: tuple[EntryStackByteRefusal8616, ...] = ()
    prefix_closed_by: EntryStackByteRefusalKind8616 | None = None
    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    def to_dict(self) -> dict[str, object]:
        """Serialize counts, facts, and refusals deterministically."""
        return {
            "scope": self.scope.value,
            "verdict": self.verdict.value,
            "execution_scope": "initial_invocation",
            "function_addr": self.artifact.function_addr,
            "prefix_closed_by": (
                None if self.prefix_closed_by is None else self.prefix_closed_by.value
            ),
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
            "facts": [fact.to_dict() for fact in self.facts],
            "refusals": [
                {
                    "kind": refusal.kind.value,
                    "detail": refusal.detail,
                    "block_addr": refusal.block_addr,
                    "instr_index": refusal.instr_index,
                }
                for refusal in self.refusals
            ],
        }
