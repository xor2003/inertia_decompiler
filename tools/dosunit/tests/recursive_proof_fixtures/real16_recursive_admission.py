"""Binary-derived real16 call-graph admission for joint recursive proofs.

Layer: dosunit recursive-call staging (m5).

Responsibility: re-export the authoritative production admission owner
(``tools.dosunit.compare.real16_call_graph_admission``) for the recursive-proof
test fixtures so no second semantic implementation is maintained here.
Only the listed public names are forwarded; the previous module's private
helpers and module-level internals are gone, so callers and tests that
patched them must use the production module or the public surface.
"""
from __future__ import annotations

from tools.dosunit.compare.real16_call_graph_admission import (
    REPORT_SCHEMA,
    AdmissionCounters,
    AdmissionLimits,
    AdmissionRefusal,
    AdmissionRefusalReason,
    AdmissionReport,
    AdmissionVerdict,
    CallSiteRecord,
    CoverageScope,
    SiteStatus,
    admit_call_graph,
)

__all__ = [
    "REPORT_SCHEMA",
    "AdmissionCounters",
    "AdmissionLimits",
    "AdmissionRefusal",
    "AdmissionRefusalReason",
    "AdmissionReport",
    "AdmissionVerdict",
    "CallSiteRecord",
    "CoverageScope",
    "SiteStatus",
    "admit_call_graph",
]
