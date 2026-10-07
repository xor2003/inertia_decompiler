"""Source-bound multi-block callee candidate intake.

Layer: tools/dosunit comparator binary evidence intake.
Responsibility: verify an actual caller CALL and its full target domain before
bounded region scanning, then revalidate source identity and every consumed
span before publishing a candidate. Candidates carry no semantic admission.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import tools.dosunit.compare.straightline_ssa as S
from tools.dosunit.catalog.binary_callee_intake import (
    CallSiteEvidence,
    IntakeRefusal,
    IntakeRefusalReason,
    IntakeRequest,
    _abort,
    _caller_call_part,
    _check_target_domain,
    _IntakeAbort,
    _loader_identity,
    _resolve_document_identity,
    _verify_call_site,
)
from tools.dosunit.catalog.binary_callee_region_contracts import (
    RegionScanBudget,
    RegionScanOutcome,
    RegionScanRequest,
    RegionScanStatus,
    ScanWindow,
)
from tools.dosunit.catalog.binary_callee_region_scan import scan_candidate_region
from tools.dosunit.reporting import ssa_provenance
from tools.dosunit.reporting.flat32_proof_report import loaded_image_identity


class RegionIntakeStatus(StrEnum):
    """Source-bound candidate availability, separate from proof admission."""

    CANDIDATE = "candidate"
    CANDIDATE_PENDING_SUMMARY = "candidate_pending_summary"
    REFUSED = "refused"


@dataclass(frozen=True)
class RegionIntakeResult:
    """Retained source verification and scan evidence, including partial scans."""

    status: RegionIntakeStatus
    call_site: CallSiteEvidence | None
    scan: RegionScanOutcome | None
    source_refusal: IntakeRefusal | None = None
    image_sha256: str | None = None
    loaded_image: dict[str, Any] | None = None
    semantic_sha256: str | None = None

    def __post_init__(self) -> None:
        """Reject a candidate without fully verified boundary evidence."""
        if self.status in (RegionIntakeStatus.CANDIDATE,
                           RegionIntakeStatus.CANDIDATE_PENDING_SUMMARY):
            pending = self.status is RegionIntakeStatus.CANDIDATE_PENDING_SUMMARY
            expected = (RegionScanStatus.COMPLETED_PENDING_SUMMARY if pending
                        else RegionScanStatus.COMPLETED)
            complete_scan = (self.scan is not None and self.scan.status is expected
                             and bool(self.scan.pending_summary_edges) == pending)
            source_bound = bool(self.image_sha256 and self.loaded_image is not None and self.semantic_sha256)
            if self.call_site is None or not complete_scan or self.source_refusal is not None or not source_bound:
                raise ValueError("candidate region lacks source-bound evidence")
        elif self.source_refusal is None and (self.scan is None or self.scan.refusal is None):
            raise ValueError("refused region must retain its evidence boundary")

    def to_dict(self) -> dict[str, Any]:
        """Serialize candidate evidence without asserting callee admission."""
        return {
            "status": self.status.value,
            "call_site": None if self.call_site is None else self.call_site.to_dict(),
            "scan": None if self.scan is None else self.scan.to_dict(),
            "source_refusal": None if self.source_refusal is None else self.source_refusal.to_dict(),
            "image_sha256": self.image_sha256,
            "loaded_image": self.loaded_image,
            "semantic_sha256": self.semantic_sha256,
        }


def intake_uncatalogued_region_candidate(
    request: IntakeRequest, *, window: ScanWindow, budget: RegionScanBudget,
    max_lift_block_ms: int = 10000,
) -> RegionIntakeResult:
    """Scan an uncatalogued real16 callee only after verifying its caller CALL.

    The window is a work bound, never the callee body size. Scan refusals retain
    decoded partial evidence. A scan with isolated self-edges returns as a
    ``CANDIDATE_PENDING_SUMMARY`` whose edges the lowering owner must discharge;
    it is not an acyclic candidate. Every source span and caller instruction is
    read again before publication; source changes yield an explicit source
    refusal. This does not lower, admit, or prove the candidate's effects or
    return frame.
    """
    call_site: CallSiteEvidence | None = None
    scan: RegionScanOutcome | None = None
    try:
        exe_path, exe_digest = _resolve_document_identity(request)
        identity = ssa_provenance.begin_lowering(exe_path)
        image = loaded_image_identity(request.project)
        if identity.binary_hash != exe_digest:
            _abort(IntakeRefusalReason.SOURCE_CHANGED, boundary="initial_identity")
        _, linked_base = _loader_identity(request.project)
        call_site = _verify_call_site(request, _caller_call_part(request))
        _check_target_domain(request, call_site, linked_base)

        def lift(start: int, size: int) -> S.LiftedBlock:
            """Lift only the requested source interval under the timeout bound."""
            lifted = S._lift_vex_block_cached(
                project=request.project, exe_path=exe_path, exe_digest=exe_digest,
                start=start, size=size, opt_level=0, cache_document=None,
                cache_stats={"hits": 0, "misses": 0, "writes": 0, "errors": 0},
                max_lift_block_ms=max_lift_block_ms,
            )
            if not isinstance(lifted, S.LiftedBlock):
                raise TypeError("binary lifter returned a non-LiftedBlock result")
            return lifted

        def read(start: int, size: int) -> bytes | None:
            """Read source bytes directly from the loaded image."""
            value = S._loader_bytes(request.project, start, size)
            if value is not None and not isinstance(value, bytes):
                raise TypeError("loader byte boundary returned a non-bytes result")
            return value

        scan = scan_candidate_region(RegionScanRequest(
            request.target_linear, window, budget, lift, read, mode_bits=16))
        changed = (
            read(call_site.site_linear, call_site.size) != bytes.fromhex(call_site.bytes_hex)
            or any(read(block.linear, block.size) != bytes.fromhex(block.bytes_hex)
                   for block in scan.blocks)
            or ssa_provenance.begin_lowering(exe_path) != identity
            or loaded_image_identity(request.project) != image
        )
        if changed:
            _abort(IntakeRefusalReason.SOURCE_CHANGED, boundary="region_publication")
        status = (RegionIntakeStatus.CANDIDATE if scan.status is RegionScanStatus.COMPLETED
                  else RegionIntakeStatus.CANDIDATE_PENDING_SUMMARY
                  if scan.status is RegionScanStatus.COMPLETED_PENDING_SUMMARY
                  else RegionIntakeStatus.REFUSED)
        return RegionIntakeResult(status, call_site, scan, image_sha256=exe_digest,
                                  loaded_image=image, semantic_sha256=identity.semantic_hash)
    except _IntakeAbort as error:
        return RegionIntakeResult(RegionIntakeStatus.REFUSED, call_site, scan,
                                  source_refusal=error.refusal)
