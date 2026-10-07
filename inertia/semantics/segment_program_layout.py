"""Join function segment summaries into conservative whole-program evidence.

Layer: function/program summaries.
Responsibility: close program-wide segment and control evidence without inferring
memory objects, pointer types, source memory-model labels, or generated-C fixes.

Package ownership contract (canonical inertia/semantics package):
Layer: Semantics.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from inertia.ir.segment_contract import SegmentFactVerdict
from inertia.pipeline.errors import PipelineHardError

from .segment_function_summary import (
    SegmentControlTransferDistance8616,
)
from .segment_program_layout_contract import (
    SegmentProgramDiscoveryEvidence8616,
    SegmentProgramEvidenceCoverage8616,
    SegmentProgramFunctionEvidence8616,
    SegmentProgramLayoutAspect8616,
    SegmentProgramLayoutContract8616,
    SegmentProgramLayoutFact8616,
    SegmentProgramLayoutVerdict8616,
    SegmentProgramSupplementalEvidence8616,
    validated_segment_program_counts_8616,
)


def _fact_8616(
    aspect: SegmentProgramLayoutAspect8616,
    proven: bool,
    *,
    sites: tuple[int, ...] = (),
    detail: str,
) -> SegmentProgramLayoutFact8616:
    """Build a binary proven/refused fact with deterministic sites."""
    return SegmentProgramLayoutFact8616(
        aspect,
        SegmentProgramLayoutVerdict8616.PROVEN if proven else SegmentProgramLayoutVerdict8616.UNKNOWN_REFUSE,
        tuple(sorted(set(sites))),
        detail,
    )


def _presence_fact_8616(
    aspect: SegmentProgramLayoutAspect8616,
    *,
    coverage: SegmentProgramEvidenceCoverage8616,
    sites: tuple[int, ...],
) -> SegmentProgramLayoutFact8616:
    """Prove presence from a witness and absence only from complete coverage."""
    ordered_sites = tuple(sorted(set(sites)))
    if ordered_sites:
        verdict = SegmentProgramLayoutVerdict8616.PROVEN_PRESENT
    elif coverage is SegmentProgramEvidenceCoverage8616.COMPLETE:
        verdict = SegmentProgramLayoutVerdict8616.PROVEN_ABSENT
    else:
        verdict = SegmentProgramLayoutVerdict8616.UNKNOWN_REFUSE
    return SegmentProgramLayoutFact8616(aspect, verdict, ordered_sites, coverage.value)


def build_x86_16_segment_program_layout(
    discovery: SegmentProgramDiscoveryEvidence8616,
    functions: tuple[SegmentProgramFunctionEvidence8616, ...],
    supplemental: SegmentProgramSupplementalEvidence8616 | None = None,
) -> SegmentProgramLayoutContract8616:
    """Join exact function facts and refuse every unsupported program default."""
    supplemental = supplemental or SegmentProgramSupplementalEvidence8616()
    ordered = tuple(sorted(functions, key=lambda fact: fact.function_addr))
    function_addrs = tuple(fact.function_addr for fact in ordered)
    if len(set(function_addrs)) != len(function_addrs):
        raise PipelineHardError("segment program layout received duplicate function evidence")
    for function in ordered:
        validated_segment_program_counts_8616(
            function.summary,
            owner=f"segment function {function.function_addr:#x}",
        )
    expected = tuple(sorted(discovery.expected_function_addrs))
    discovery_ok = discovery.complete
    functions_ok = discovery_ok and function_addrs == expected
    transfers = tuple(fact for function in ordered for fact in function.control_transfers)
    unresolved_transfer_sites = tuple(
        fact.instruction_addr
        for fact in transfers
        if fact.verdict is SegmentFactVerdict.UNKNOWN_REFUSE or fact.target_addr is None
    )
    control_ok = (
        functions_ok
        and supplemental.indirect_control_coverage is SegmentProgramEvidenceCoverage8616.COMPLETE
        and not supplemental.unresolved_indirect_control_sites
        and not unresolved_transfer_sites
    )
    unknown_access_sites = tuple(
        fact.instruction_addr if fact.instruction_addr is not None else fact.block_addr
        for function in ordered
        for fact in function.accesses
        if fact.verdict is SegmentFactVerdict.UNKNOWN_REFUSE
    )
    external_effect_sites = tuple(
        fact.instruction_addr for fact in transfers if fact.target_addr not in function_addrs
    )
    segment_effects_ok = functions_ok and not unknown_access_sites and not external_effect_sites
    overlay_free = (
        supplemental.overlay_coverage is SegmentProgramEvidenceCoverage8616.COMPLETE
        and not supplemental.overlap_sites
    )
    primary_data_ok = (
        segment_effects_ok
        and overlay_free
        and supplemental.primary_static_data_coverage is SegmentProgramEvidenceCoverage8616.COMPLETE
        and supplemental.primary_static_data_region is not None
    )
    far_code_sites = tuple(
        fact.instruction_addr
        for fact in transfers
        if fact.verdict is SegmentFactVerdict.PROVEN
        and fact.distance is SegmentControlTransferDistance8616.FAR
    )
    facts = (
        _fact_8616(SegmentProgramLayoutAspect8616.DISCOVERY, discovery_ok, detail="exact catalog closure"),
        _fact_8616(
            SegmentProgramLayoutAspect8616.FUNCTION_SUMMARIES,
            functions_ok,
            sites=tuple(sorted(set(expected) ^ set(function_addrs))),
            detail="expected and materialized function summaries match",
        ),
        _fact_8616(
            SegmentProgramLayoutAspect8616.CONTROL_FLOW,
            control_ok,
            sites=(*unresolved_transfer_sites, *supplemental.unresolved_indirect_control_sites),
            detail="resolved direct and indirect program control",
        ),
        _fact_8616(
            SegmentProgramLayoutAspect8616.SEGMENT_EFFECTS,
            segment_effects_ok,
            sites=(*unknown_access_sites, *external_effect_sites),
            detail="local accesses and transitive clobbers are closed",
        ),
        _fact_8616(
            SegmentProgramLayoutAspect8616.OVERLAY_FREE,
            overlay_free,
            sites=supplemental.overlap_sites,
            detail="complete image overlap scan",
        ),
        _fact_8616(
            SegmentProgramLayoutAspect8616.PRIMARY_STATIC_DATA,
            primary_data_ok,
            detail=supplemental.primary_static_data_region or "no loader-owned primary data identity",
        ),
        _presence_fact_8616(
            SegmentProgramLayoutAspect8616.FAR_CODE,
            coverage=(
                SegmentProgramEvidenceCoverage8616.COMPLETE
                if control_ok
                else SegmentProgramEvidenceCoverage8616.INCOMPLETE
            ),
            sites=far_code_sites,
        ),
        _presence_fact_8616(
            SegmentProgramLayoutAspect8616.FAR_DATA,
            coverage=supplemental.far_data_coverage,
            sites=supplemental.far_data_sites,
        ),
        _presence_fact_8616(
            SegmentProgramLayoutAspect8616.HUGE_POINTER_NORMALIZATION,
            coverage=supplemental.huge_pointer_coverage,
            sites=supplemental.huge_pointer_sites,
        ),
        _fact_8616(
            SegmentProgramLayoutAspect8616.CS_DS_ENTRY_RELATION,
            supplemental.entry_relation_coverage is SegmentProgramEvidenceCoverage8616.COMPLETE
            and supplemental.cs_ds_entry_relation is not None,
            detail=supplemental.cs_ds_entry_relation or "entry relation unavailable",
        ),
        _fact_8616(
            SegmentProgramLayoutAspect8616.SS_DS_ENTRY_RELATION,
            supplemental.entry_relation_coverage is SegmentProgramEvidenceCoverage8616.COMPLETE
            and supplemental.ss_ds_entry_relation is not None,
            detail=supplemental.ss_ds_entry_relation or "entry relation unavailable",
        ),
    )
    classified = sum(fact.verdict is not SegmentProgramLayoutVerdict8616.UNKNOWN_REFUSE for fact in facts)
    materialized = classified
    if classified > 0 and materialized == 0:
        raise PipelineHardError("segment program layout classified evidence without materializing its contract")
    return SegmentProgramLayoutContract8616(
        function_addrs=function_addrs,
        facts=facts,
        summary={
            "raw_fact_count": len(facts),
            "normalized_fact_count": len(facts),
            "classified_fact_count": classified,
            "materialized_count": materialized,
            "failure_count": len(facts) - classified,
            "expected_function_count": len(expected),
            "function_summary_count": len(function_addrs),
        },
    )
