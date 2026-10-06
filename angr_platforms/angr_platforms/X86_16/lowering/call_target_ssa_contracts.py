"""Typed contracts for the shared SSA CALL-target binder.

Layer: Types/Lowering (staged candidate under
``.cache/comparator-implementation/call-target-consolidation/``; intended
production home ``lowering/call_target_ssa_contracts.py``).
Responsibility: owns the verdict/stage/result contract, the bound-producer
record both routes return, and the five-stage evidence-accounting
convention every binder refusal follows, so both lowerer gates consume one
typed proof surface.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from angr_platforms.X86_16.ir import IRBlock, IRInstr
from angr_platforms.X86_16.semantics.call_stack_effect_contracts import (
    CallStackEffectFact8616,
)
from angr_platforms.X86_16.semantics.direct_near_call_target_binding import (
    DirectNearCallTargetBinding8616,
)

__all__ = [
    "CallTargetBindResult8616",
    "CallTargetBindStage8616",
    "CallTargetBindStats8616",
    "CallTargetBindVerdict8616",
]


class CallTargetBindVerdict8616(StrEnum):
    """Typed outcome of one shared call-target binding obligation."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"
    CONFLICT = "conflict"


class CallTargetBindStage8616(StrEnum):
    """Earliest staged obligation that failed or closed the binding.

    ``PROVEN`` records that every stage closed. Every other member names the
    first typed evidence obligation that could not be discharged; consumers
    map stages onto their own production failure enums so staged detail
    survives diagnostics while the returned contract stays drop-in
    compatible.
    """

    PROVEN = "proven"
    SSA_CALLER_MISMATCH = "ssa_caller_mismatch"
    SSA_CALL_NOT_FOUND = "ssa_call_not_found"
    SSA_CALL_AMBIGUOUS = "ssa_call_ambiguous"
    SSA_CALL_MALFORMED = "ssa_call_malformed"
    PROJECT_MISSING = "project_missing"
    SSA_ARTIFACT_STALE = "ssa_artifact_stale"
    SEMANTIC_PROJECTION_MISSING = "semantic_projection_missing"
    SEMANTIC_PROJECTION_INCOMPLETE = "semantic_projection_incomplete"
    SEMANTIC_PROJECTION_SSA_MISMATCH = "semantic_projection_ssa_mismatch"
    SEMANTIC_SSA_NOT_REGISTERED = "semantic_ssa_not_registered"
    SEMANTIC_SSA_CONFLICT = "semantic_ssa_conflict"
    SOURCE_IR_NOT_REGISTERED = "source_ir_not_registered"
    SOURCE_IR_CONFLICT = "source_ir_conflict"
    SOURCE_IR_BLOCK_MISMATCH = "source_ir_block_mismatch"
    EFFECTS_BLOCK_MISMATCH = "effects_block_mismatch"
    OUTPUTS_PREFIX_MISMATCH = "outputs_prefix_mismatch"
    OUTPUTS_SUFFIX_MISMATCH = "outputs_suffix_mismatch"
    EFFECTS_FACT_MISSING = "effects_fact_missing"
    EFFECTS_FACT_AMBIGUOUS = "effects_fact_ambiguous"
    SSA_ENRICHED_INDEX_MISMATCH = "ssa_enriched_index_mismatch"
    SSA_ENRICHED_ORIGIN_MISMATCH = "ssa_enriched_origin_mismatch"
    SSA_ENRICHED_CALL_MISMATCH = "ssa_enriched_call_mismatch"
    RAW_IR_NOT_REGISTERED = "raw_ir_not_registered"
    RAW_IR_CONFLICT = "raw_ir_conflict"
    SSA_RAW_BLOCK_MISMATCH = "ssa_raw_block_mismatch"
    SSA_RAW_INDEX_MISMATCH = "ssa_raw_index_mismatch"
    SSA_RAW_CALL_AMBIGUOUS = "ssa_raw_call_ambiguous"
    SSA_ORIGIN_MISSING = "ssa_origin_missing"
    SSA_RAW_ORIGIN_MISMATCH = "ssa_raw_origin_mismatch"
    SSA_RAW_OPERAND_MISMATCH = "ssa_raw_operand_mismatch"
    PRODUCER_PROJECTION_MISMATCH = "producer_projection_mismatch"
    PRODUCER_AMBIGUOUS = "producer_ambiguous"
    PRODUCER_UNBOUND = "producer_unbound"
    PRODUCER_MISMATCH = "producer_mismatch"
    DECODED_INDEX_MISSING = "decoded_index_missing"
    DECODED_ENTRY_MISSING = "decoded_entry_missing"
    DECODED_TARGET_AMBIGUOUS = "decoded_target_ambiguous"
    NATIVE_BINDING_REFUSED = "native_binding_refused"
    RETAINED_BINDING_CONFLICT = "retained_binding_conflict"
    TARGET_NOT_ADMITTED = "target_not_admitted"


@dataclass(frozen=True, slots=True)
class CallTargetBindStats8616:
    """Closed five-stage accounting for one shared binding obligation."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def closed(self) -> bool:
        """Return whether the obligation resolved to one proof or refusal."""
        counts = (
            self.raw_fact_count,
            self.normalized_fact_count,
            self.classified_fact_count,
            self.materialized_count,
            self.failure_count,
        )
        if not all(type(count) is int and count >= 0 for count in counts):
            return False
        return bool(
            self.raw_fact_count == 1
            and self.normalized_fact_count <= self.raw_fact_count
            and self.classified_fact_count <= self.normalized_fact_count
            and self.normalized_fact_count
            == self.materialized_count + self.failure_count
        )

    def to_dict(self) -> dict[str, int]:
        """Serialize the evidence ledger for diagnostics and workers."""
        return {
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
        }


@dataclass(frozen=True, slots=True)
class CallTargetBindResult8616:
    """Proven full-width target or typed refusal for one symbolic SSA CALL.

    ``target_addr`` is the native-proven callee coordinate; ``binding``
    retains the Semantics-owned decoded proof; ``retained_binding`` retains
    the projection's materialization-time proof when a semantic effect fact
    carried one. ``block_addr``/``instr_index`` are the bound SSA
    coordinates so consumers need not rescan the artifact.
    """

    callsite_addr: int
    verdict: CallTargetBindVerdict8616
    stage: CallTargetBindStage8616
    stats: CallTargetBindStats8616
    target_addr: int | None = None
    block_addr: int | None = None
    instr_index: int | None = None
    binding: DirectNearCallTargetBinding8616 | None = None
    retained_binding: DirectNearCallTargetBinding8616 | None = None

    @property
    def complete(self) -> bool:
        """Return whether the binding closed on one admitted proven target."""
        return bool(
            self.verdict is CallTargetBindVerdict8616.PROVEN
            and self.stage is CallTargetBindStage8616.PROVEN
            and type(self.target_addr) is int
            and self.target_addr >= 0
            and self.binding is not None
            and self.binding.complete
            and self.binding.callsite_addr == self.callsite_addr
            and self.binding.target_addr == self.target_addr
            and self.stats == CallTargetBindStats8616(1, 1, 1, 1, 0)
            and self.stats.closed
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize the shared binding result for diagnostics and workers."""
        return {
            "callsite_addr": self.callsite_addr,
            "verdict": self.verdict.value,
            "stage": self.stage.value,
            "target_addr": self.target_addr,
            "block_addr": self.block_addr,
            "instr_index": self.instr_index,
            "stats": self.stats.to_dict(),
            "binding": None if self.binding is None else self.binding.to_dict(),
            "retained_binding": (
                None
                if self.retained_binding is None
                else self.retained_binding.to_dict()
            ),
        }


def _refuse_8616(
    callsite_addr: int,
    verdict: CallTargetBindVerdict8616,
    stage: CallTargetBindStage8616,
    *,
    normalized: bool = False,
    classified: bool = False,
    binding: DirectNearCallTargetBinding8616 | None = None,
) -> CallTargetBindResult8616:
    """Retain one refused binding obligation in the five-stage count.

    Pre-normalization refusals keep ``normalized=0`` so ``stats.closed``
    stays false, matching the Semantics binding owner's accounting
    convention.
    """
    return CallTargetBindResult8616(
        callsite_addr=callsite_addr,
        verdict=verdict,
        stage=stage,
        stats=CallTargetBindStats8616(1, int(normalized), int(classified), 0, 1),
        binding=binding,
    )


@dataclass(frozen=True, slots=True)
class _BoundProducer8616:
    """The raw CALL producer and corroborating evidence one route bound."""

    raw_block: IRBlock
    raw_instr: IRInstr
    fact: CallStackEffectFact8616 | None

