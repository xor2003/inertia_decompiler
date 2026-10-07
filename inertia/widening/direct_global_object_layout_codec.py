"""Encode closed direct-global Widening evidence for CLI persistence.

Layer: Widening.
Responsibility: serialize and validate an already-classified direct-global
object-layout census without rebuilding binary, Alias, or Widening evidence.
Consumes alias-proven storage identity.
Do not join values from rendered text, cosmetic shape, postprocess, or
CLI/reporting evidence.
"""

from __future__ import annotations

from inertia.ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin

from .global_object_layout import (
    DirectGlobalObjectLayout8616,
    DirectGlobalObjectLayoutEvidence8616,
)

_SCHEMA_8616 = 1


def _nonnegative_int_8616(value: object, *, field: str) -> int:
    """Parse one strict nonnegative transport integer."""
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"direct-global layout transport has invalid {field}")
    return value


def _layout_record_8616(layout: DirectGlobalObjectLayout8616) -> dict[str, object]:
    """Serialize one proven direct-global object extent."""
    return {
        "space": layout.address.space.value,
        "offset": layout.address.offset,
        "size": layout.address.size,
        "status": layout.address.status.value,
        "segment_origin": layout.address.segment_origin.value,
        "proof_function_addrs": list(layout.proof_function_addrs),
    }


def direct_global_object_layout_evidence_record_8616(
    evidence: DirectGlobalObjectLayoutEvidence8616,
) -> dict[str, object]:
    """Serialize one accepted direct-global Widening census."""
    validate_direct_global_object_layout_evidence_8616(evidence)
    return {
        "schema": _SCHEMA_8616,
        "layouts": [_layout_record_8616(layout) for layout in evidence.layouts],
        "counts": {
            "raw": evidence.raw_fact_count,
            "normalized": evidence.normalized_fact_count,
            "classified": evidence.classified_fact_count,
            "materialized": evidence.materialized_count,
            "failure": evidence.failure_count,
        },
    }


def _layout_from_record_8616(record: object) -> DirectGlobalObjectLayout8616:
    """Restore one validated direct-global object extent."""
    if not isinstance(record, dict):
        raise ValueError("direct-global layout transport entry must be an object")
    raw_proofs = record.get("proof_function_addrs")
    if not isinstance(raw_proofs, list):
        raise ValueError("direct-global layout transport has invalid proof functions")
    proofs = tuple(
        _nonnegative_int_8616(value, field="proof function address")
        for value in raw_proofs
    )
    if not proofs or proofs != tuple(sorted(set(proofs))):
        raise ValueError("direct-global layout proof functions are not canonical")
    layout = DirectGlobalObjectLayout8616(
        address=IRAddress(
            space=MemSpace(record.get("space")),
            offset=_nonnegative_int_8616(record.get("offset"), field="offset"),
            size=_nonnegative_int_8616(record.get("size"), field="size"),
            status=AddressStatus(record.get("status")),
            segment_origin=SegmentOrigin(record.get("segment_origin")),
        ),
        proof_function_addrs=proofs,
    )
    if (
        layout.address.space is not MemSpace.DS
        or layout.address.size < 4
        or layout.address.status is not AddressStatus.STABLE
        or layout.address.segment_origin is not SegmentOrigin.PROVEN
    ):
        raise ValueError("direct-global layout transport contains unproven storage")
    return layout


def validate_direct_global_object_layout_evidence_8616(
    evidence: DirectGlobalObjectLayoutEvidence8616,
) -> None:
    """Refuse open, contradictory, or noncanonical direct-global evidence."""
    counts = (
        evidence.raw_fact_count,
        evidence.normalized_fact_count,
        evidence.classified_fact_count,
        evidence.materialized_count,
        evidence.failure_count,
    )
    if not all(count >= 0 for count in counts):
        raise ValueError("direct-global layout evidence has negative accounting")
    if not (
        evidence.raw_fact_count >= evidence.normalized_fact_count
        >= evidence.classified_fact_count
        >= evidence.materialized_count
        == len(evidence.layouts)
    ):
        raise ValueError("direct-global layout evidence accounting is open")
    if evidence.classified_fact_count > 0 and evidence.materialized_count == 0:
        raise ValueError("classified direct-global layouts were not materialized")
    layout_keys = tuple(
        (layout.address.space.value, layout.address.offset, layout.address.size)
        for layout in evidence.layouts
    )
    if layout_keys != tuple(sorted(set(layout_keys))):
        raise ValueError("direct-global layouts are not canonical")
    for layout in evidence.layouts:
        _layout_from_record_8616(_layout_record_8616(layout))


def direct_global_object_layout_evidence_from_record_8616(
    record: object,
) -> DirectGlobalObjectLayoutEvidence8616:
    """Restore one accepted direct-global Widening census."""
    if not isinstance(record, dict) or record.get("schema") != _SCHEMA_8616:
        raise ValueError("direct-global layout transport has an unsupported schema")
    raw_layouts = record.get("layouts")
    counts = record.get("counts")
    if not isinstance(raw_layouts, list) or not isinstance(counts, dict):
        raise ValueError("direct-global layout transport has invalid collections")
    evidence = DirectGlobalObjectLayoutEvidence8616(
        layouts=tuple(_layout_from_record_8616(item) for item in raw_layouts),
        raw_fact_count=_nonnegative_int_8616(counts.get("raw"), field="raw count"),
        normalized_fact_count=_nonnegative_int_8616(
            counts.get("normalized"),
            field="normalized count",
        ),
        classified_fact_count=_nonnegative_int_8616(
            counts.get("classified"),
            field="classified count",
        ),
        materialized_count=_nonnegative_int_8616(
            counts.get("materialized"),
            field="materialized count",
        ),
        failure_count=_nonnegative_int_8616(
            counts.get("failure"),
            field="failure count",
        ),
    )
    validate_direct_global_object_layout_evidence_8616(evidence)
    return evidence


__all__ = [
    "direct_global_object_layout_evidence_from_record_8616",
    "direct_global_object_layout_evidence_record_8616",
    "validate_direct_global_object_layout_evidence_8616",
]
