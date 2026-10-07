"""Declared-source-scope lowering of verified callee region candidates.

Layer: tools/dosunit comparator callee evidence intake.
Responsibility: lower only scanner-consumed intervals, require exact per-block
source correspondence and full-state closed grouping, and retain refusals.
Lowered parts are input to whole-call proof, never equivalence evidence alone.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

import tools.dosunit.compare.straightline_ssa as S
from tools.dosunit.catalog.binary_callee_intake import (
    IntakeRequest,
    _caller_call_part,
    _catalog_record,
    _IntakeAbort,
    _loader_identity,
    _verify_call_site,
)
from tools.dosunit.catalog.binary_callee_region_intake import RegionIntakeResult, RegionIntakeStatus
from tools.dosunit.catalog.binary_callee_region_pending import (
    PendingDischargeReason,
    verify_pending_summary,
)
from tools.dosunit.compare.real16_call_contracts import Real16CallRefusal
from tools.dosunit.compare.real16_call_evidence import block_source, group_functions
from tools.dosunit.contracts.proof_contracts import FactCounters
from tools.dosunit.contracts.ssa_lowering_scope import SuccessorRangePolicy
from tools.dosunit.reporting import ssa_provenance
from tools.dosunit.reporting.flat32_proof_report import loaded_image_identity


class RegionLoweringStatus(StrEnum):
    """Availability of complete region SSA; not a semantic proof verdict."""

    LOWERED = "lowered"
    REFUSED = "refused"


class RegionLoweringReason(StrEnum):
    """Typed boundary preventing publication of region SSA."""

    CANDIDATE_MISSING = "candidate_missing"
    REQUEST_NOT_BOUND = "request_not_bound"
    INVALID_BUDGET = "invalid_budget"
    SOURCE_CHANGED = "source_changed"
    ENTRY_NOT_FIRST = "entry_not_first"
    LOWERING_REFUSED = "lowering_refused"
    BLOCK_MISMATCH = "block_mismatch"
    GROUP_INCOMPLETE = "group_incomplete"
    PENDING_UNDISCHARGED = "pending_summary_undischarged"
    RESIDUAL_CYCLE = "residual_cycle"


@dataclass(frozen=True)
class RegionLoweringResult:
    """Source-bound lowered region or explicit refusal and partial evidence."""

    status: RegionLoweringStatus
    candidate: RegionIntakeResult
    parts: tuple[dict[str, Any], ...] = ()
    function: dict[str, Any] | None = None
    reason: RegionLoweringReason | None = None
    detail: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        """Keep successful publication distinct from partial lowering."""
        if self.status is RegionLoweringStatus.LOWERED:
            if not self.parts or self.function is None or self.reason is not None:
                raise ValueError("lowered region lacks complete publication evidence")
        elif self.reason is None:
            raise ValueError("refused region lowering must state a reason")

    @property
    def counters(self) -> FactCounters:
        """Account for one lowering decision; scanner retains instruction facts."""
        return FactCounters(1, 1, 1, 1, int(self.status is RegionLoweringStatus.REFUSED))

    def to_dict(self) -> dict[str, Any]:
        """Serialize the region-specific receipt without a leaf proof claim."""
        return {"status": self.status.value, "candidate": self.candidate.to_dict(),
                "parts": list(self.parts), "function": self.function,
                "reason": None if self.reason is None else self.reason.value,
                "detail": self.detail, "size_origin": "source_region_extent",
                "counters": asdict(self.counters),
                "counts": {"lowered_parts": len(self.parts)}}


def _source_matches(request: IntakeRequest, candidate: RegionIntakeResult) -> bool:
    """Revalidate source identity, consumed spans, and the caller instruction."""
    scan, call = candidate.scan, candidate.call_site
    if scan is None or call is None:
        return False
    identity = ssa_provenance.begin_lowering(Path(str(request.document["exe"])))
    return (identity.binary_hash == candidate.image_sha256
            and identity.semantic_hash == candidate.semantic_sha256
            and loaded_image_identity(request.project) == candidate.loaded_image
            and S._loader_bytes(request.project, call.site_linear, call.size) == bytes.fromhex(call.bytes_hex)
            and all(S._loader_bytes(request.project, block.linear, block.size) == bytes.fromhex(block.bytes_hex)
                    for block in scan.blocks))


def _blocks_match(parts: list[dict[str, Any]], candidate: RegionIntakeResult) -> bool:
    """Require one exact lowered block per source-scanned block."""
    scan = candidate.scan
    if scan is None:
        return False
    expected = {block.linear: block for block in scan.blocks}
    if len(parts) != len(expected):
        return False
    for part in parts:
        linear = S._optional_int(part.get("entry", {}).get("linear"))
        if linear is None:
            return False
        block = expected.pop(linear, None)
        source = block_source(part)
        if block is None or (source.get("machine_code_size") != block.size
                or source.get("machine_code_sha256") != hashlib.sha256(bytes.fromhex(block.bytes_hex)).hexdigest()
                or source.get("jumpkind") != block.jumpkind):
            return False
    return not expected


def _binding_failure(request: IntakeRequest, candidate: RegionIntakeResult) -> dict[str, Any] | None:
    """Reverify the request's caller and retain any typed source-bound refusal."""
    try:
        verified = _verify_call_site(request, _caller_call_part(request))
    except _IntakeAbort as error:
        refusal: dict[str, Any] = error.refusal.to_dict()
        return refusal
    if verified != candidate.call_site:
        return {"reason": RegionLoweringReason.REQUEST_NOT_BOUND.value}
    return None


def _group_failure(parts: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Consume authoritative full-state grouping without losing refusal cause."""
    try:
        group_functions({"functions": parts})
    except Real16CallRefusal as error:
        return {"reason": error.reason, "detail": error.detail}
    return None


def _seal_lowered_region(
    request: IntakeRequest, candidate: RegionIntakeResult,
    parts: list[dict[str, Any]], record: dict[str, Any],
) -> RegionLoweringResult:
    """Publish region SSA only while every source identity still matches."""
    if not _source_matches(request, candidate):
        return RegionLoweringResult(RegionLoweringStatus.REFUSED, candidate,
                                    reason=RegionLoweringReason.SOURCE_CHANGED)
    return RegionLoweringResult(RegionLoweringStatus.LOWERED, candidate, tuple(parts), record)


def lower_region_candidate(
    request: IntakeRequest, candidate: RegionIntakeResult, *,
    max_assignments: int = 512, max_lift_block_ms: int = 10000,
) -> RegionLoweringResult:
    """Lower a verified candidate with exact allowed intervals and full state.

    The enclosing source extent is hashed for existing whole-body identity;
    holes are not allowed execution ranges. Every resulting block must match
    one scanner block exactly, and the ordinary callee grouping owner must
    accept complete outputs, ranges, and successor closure. Return restoration
    and whole-caller equality remain the composer's obligations. Zero assignment
    and lift-time limits retain the existing SSA owner's uncapped contract.
    """
    def refuse(reason: RegionLoweringReason, **detail: Any) -> RegionLoweringResult:  # noqa: ANN401
        """Retain the candidate and precise failure boundary without publication."""
        return RegionLoweringResult(RegionLoweringStatus.REFUSED, candidate, reason=reason, detail=detail)

    scan, call = candidate.scan, candidate.call_site
    if candidate.status not in (RegionIntakeStatus.CANDIDATE,
                                RegionIntakeStatus.CANDIDATE_PENDING_SUMMARY) \
            or scan is None or call is None:
        return refuse(RegionLoweringReason.CANDIDATE_MISSING)
    if scan.entry_loader_linear != request.target_linear or scan.spans[0][0] != request.target_linear:
        return refuse(RegionLoweringReason.ENTRY_NOT_FIRST)
    if type(max_assignments) is not int or max_assignments < 0 or type(max_lift_block_ms) is not int or max_lift_block_ms < 0:
        return refuse(RegionLoweringReason.INVALID_BUDGET)
    binding_failure = _binding_failure(request, candidate)
    if binding_failure is not None:
        return refuse(RegionLoweringReason.REQUEST_NOT_BOUND, refusal=binding_failure)
    if not _source_matches(request, candidate):
        return refuse(RegionLoweringReason.SOURCE_CHANGED)
    _, linked_base = _loader_identity(request.project)
    extent = scan.spans[-1][1] - request.target_linear
    entry_ip = request.target_linear - linked_base - (call.segment_para << 4)
    record = _catalog_record(request, call, entry_ip, extent)
    record["sources"] = ["binary_callee_region_intake"]
    parts, refusals, _ = S._lower_function(
        project=request.project, linked_base=linked_base,
        exe_path=Path(str(request.document["exe"])), exe_digest=str(candidate.image_sha256),
        cache_document=None, cache_stats={"hits": 0, "misses": 0, "writes": 0, "errors": 0},
        function=record, segment_paragraphs={}, output_regs=tuple(S.INTERNAL_STATE_REGS),
        source_ir=str(request.document.get("source_ir") or "vex"),
        max_blocks_per_function=len(scan.blocks),
        max_insns_per_function=scan.counters.raw_fact_count,
        max_assignments_per_function=max_assignments, scan_limit=extent,
        follow_call_fallthrough=False, max_lift_block_ms=max_lift_block_ms,
        successor_range_policy=SuccessorRangePolicy.DECLARED_ONLY,
        declared_linear_ranges=scan.spans,
    )
    if refusals:
        return refuse(RegionLoweringReason.LOWERING_REFUSED, refusals=refusals)
    if not _blocks_match(parts, candidate):
        return refuse(RegionLoweringReason.BLOCK_MISMATCH)
    group_failure = _group_failure(parts)
    if group_failure is not None:
        return refuse(RegionLoweringReason.GROUP_INCOMPLETE, refusal=group_failure)
    return _seal_or_discharge(request, candidate, parts, record)


def _seal_or_discharge(
    request: IntakeRequest, candidate: RegionIntakeResult,
    parts: list[dict[str, Any]], record: dict[str, Any],
) -> RegionLoweringResult:
    """Discharge pending self-edges through the repeat contract, then seal."""
    scan = candidate.scan
    if scan is None:
        raise ValueError("candidate reached discharge without a scan")
    pending_failure = verify_pending_summary(parts, scan)
    if pending_failure is None:
        return _seal_lowered_region(request, candidate, parts, record)
    reason = (RegionLoweringReason.RESIDUAL_CYCLE
              if pending_failure.reason is PendingDischargeReason.RESIDUAL_CYCLE
              else RegionLoweringReason.PENDING_UNDISCHARGED)
    return RegionLoweringResult(RegionLoweringStatus.REFUSED, candidate,
                                reason=reason, detail={"refusal": pending_failure.to_dict()})
