"""Define typed contracts for conservative whole-program segment evidence.

Layer: function/program summaries.
Responsibility: represent program layout inputs, independent verdicts, and their
closed census. Detection and generated-C materialization belong elsewhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from .ir.segment_contract import SegmentFactVerdict
from .pipeline.errors import PipelineHardError
from .segment_function_summary import SegmentControlTransferFact8616

if TYPE_CHECKING:
    from .declared_external_call_evidence import DeclaredCallEffectConsumption8616

_COUNT_FIELDS = (
    "raw_fact_count",
    "normalized_fact_count",
    "classified_fact_count",
    "materialized_count",
    "failure_count",
)


class SegmentProgramEvidenceCoverage8616(StrEnum):
    """Completeness of one independent whole-program evidence producer."""

    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    UNAVAILABLE = "unavailable"


class SegmentProgramLayoutAspect8616(StrEnum):
    """Independent layout question answered by the program contract."""

    DISCOVERY = "discovery"
    FUNCTION_SUMMARIES = "function_summaries"
    CONTROL_FLOW = "control_flow"
    SEGMENT_EFFECTS = "segment_effects"
    OVERLAY_FREE = "overlay_free"
    PRIMARY_STATIC_DATA = "primary_static_data"
    FAR_CODE = "far_code"
    FAR_DATA = "far_data"
    HUGE_POINTER_NORMALIZATION = "huge_pointer_normalization"
    CS_DS_ENTRY_RELATION = "cs_ds_entry_relation"
    SS_DS_ENTRY_RELATION = "ss_ds_entry_relation"


class SegmentProgramLayoutVerdict8616(StrEnum):
    """Evidence-backed answer for one program-layout aspect."""

    PROVEN = "proven"
    PROVEN_PRESENT = "proven_present"
    PROVEN_ABSENT = "proven_absent"
    UNKNOWN_REFUSE = "unknown_refuse"


@dataclass(frozen=True, slots=True)
class SegmentProgramDiscoveryEvidence8616:
    """Exact expected function set and its closed discovery census."""

    expected_function_addrs: tuple[int, ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    failed_addrs: tuple[int, ...] = ()

    @property
    def complete(self) -> bool:
        """Return whether discovery proved and materialized the exact set."""
        expected_count = len(self.expected_function_addrs)
        return (
            expected_count > 0
            and len(set(self.expected_function_addrs)) == expected_count
            and self.raw_fact_count == expected_count
            and self.normalized_fact_count == expected_count
            and self.classified_fact_count == expected_count
            and self.materialized_count == expected_count
            and self.failure_count == 0
            and not self.failed_addrs
        )


@dataclass(frozen=True, slots=True)
class SegmentProgramAccessEvidence8616:
    """Reduced exact segment evidence for one typed memory access."""

    block_addr: int
    instruction_addr: int | None
    segment_register: str | None
    physical_source: str | None
    verdict: SegmentFactVerdict

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "block_addr": self.block_addr,
            "instruction_addr": self.instruction_addr,
            "segment_register": self.segment_register,
            "physical_source": self.physical_source,
            "verdict": self.verdict.value,
        }


@dataclass(frozen=True, slots=True)
class SegmentProgramFunctionEvidence8616:
    """Worker-transportable local facts needed by the program join."""

    function_addr: int
    entry_requirements: tuple[str, ...]
    accesses: tuple[SegmentProgramAccessEvidence8616, ...]
    local_clobbered_registers: tuple[str, ...]
    restored_registers: tuple[str, ...]
    control_transfers: tuple[SegmentControlTransferFact8616, ...]
    summary: dict[str, int] = field(default_factory=dict)
    declared_call_consumptions: tuple[DeclaredCallEffectConsumption8616, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "schema": 1,
            "function_addr": self.function_addr,
            "entry_requirements": list(self.entry_requirements),
            "accesses": [fact.to_dict() for fact in self.accesses],
            "local_clobbered_registers": list(self.local_clobbered_registers),
            "restored_registers": list(self.restored_registers),
            "control_transfers": [fact.to_dict() for fact in self.control_transfers],
            "declared_call_consumptions": [
                consumption.to_record() for consumption in self.declared_call_consumptions
            ],
            "summary": dict(self.summary),
        }


@dataclass(frozen=True, slots=True)
class SegmentProgramSupplementalEvidence8616:
    """Typed completeness supplied by later frontend and pointer analyses."""

    indirect_control_coverage: SegmentProgramEvidenceCoverage8616 = SegmentProgramEvidenceCoverage8616.UNAVAILABLE
    unresolved_indirect_control_sites: tuple[int, ...] = ()
    overlay_coverage: SegmentProgramEvidenceCoverage8616 = SegmentProgramEvidenceCoverage8616.UNAVAILABLE
    overlap_sites: tuple[int, ...] = ()
    primary_static_data_coverage: SegmentProgramEvidenceCoverage8616 = SegmentProgramEvidenceCoverage8616.UNAVAILABLE
    primary_static_data_region: str | None = None
    far_data_coverage: SegmentProgramEvidenceCoverage8616 = SegmentProgramEvidenceCoverage8616.UNAVAILABLE
    far_data_sites: tuple[int, ...] = ()
    huge_pointer_coverage: SegmentProgramEvidenceCoverage8616 = SegmentProgramEvidenceCoverage8616.UNAVAILABLE
    huge_pointer_sites: tuple[int, ...] = ()
    entry_relation_coverage: SegmentProgramEvidenceCoverage8616 = SegmentProgramEvidenceCoverage8616.UNAVAILABLE
    cs_ds_entry_relation: str | None = None
    ss_ds_entry_relation: str | None = None


@dataclass(frozen=True, slots=True)
class SegmentProgramLayoutFact8616:
    """One independently proven or explicitly refused layout conclusion."""

    aspect: SegmentProgramLayoutAspect8616
    verdict: SegmentProgramLayoutVerdict8616
    evidence_sites: tuple[int, ...] = ()
    detail: str = ""

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "aspect": self.aspect.value,
            "verdict": self.verdict.value,
            "evidence_sites": list(self.evidence_sites),
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class SegmentProgramLayoutContract8616:
    """Closed whole-program segment/layout evidence with independent verdicts."""

    function_addrs: tuple[int, ...]
    facts: tuple[SegmentProgramLayoutFact8616, ...]
    summary: dict[str, int] = field(default_factory=dict)

    def fact(self, aspect: SegmentProgramLayoutAspect8616) -> SegmentProgramLayoutFact8616:
        """Return the unique fact for an aspect."""
        for fact in self.facts:
            if fact.aspect is aspect:
                return fact
        raise KeyError(aspect.value)

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "function_addrs": list(self.function_addrs),
            "facts": [fact.to_dict() for fact in self.facts],
            "summary": dict(self.summary),
        }


def validated_segment_program_counts_8616(summary: object, *, owner: str) -> dict[str, int]:
    """Validate one owned evidence census and return its required counts."""
    if not isinstance(summary, dict):
        raise PipelineHardError(f"{owner} has no typed evidence census")
    counts: dict[str, int] = {}
    for field_name in _COUNT_FIELDS:
        value = summary.get(field_name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise PipelineHardError(f"{owner} has invalid {field_name}")
        counts[field_name] = value
    if counts["classified_fact_count"] != counts["materialized_count"]:
        raise PipelineHardError(f"{owner} classified evidence was not fully materialized")
    if not (
        counts["raw_fact_count"] >= counts["normalized_fact_count"] >= counts["classified_fact_count"]
        and counts["classified_fact_count"] + counts["failure_count"] <= counts["normalized_fact_count"]
    ):
        raise PipelineHardError(f"{owner} has an inconsistent evidence census")
    return counts
