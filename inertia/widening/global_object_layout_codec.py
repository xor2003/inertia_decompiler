"""Encode closed indexed-global Widening evidence for clean workers.

Layer: Widening.
Responsibility: reduce and validate an already-classified object-layout artifact
for deterministic CLI transport without rebuilding Alias or Widening per worker.
No layout, type, lowering, structuring, rewrite, or rendering fact is inferred.
Consumes alias-proven storage identity from the authoritative Widening result.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations

from inertia.alias.indexed_address_access_contracts import (
    IndexedAliasAccessFact8616,
    IndexedAliasAccessRefusal8616,
)
from inertia.alias.indexed_address_copy_contracts import (
    IndexedAliasCopyFact8616,
    IndexedAliasCopyRefusal8616,
)
from inertia.alias.indexed_address_program import IndexedAliasFunctionRefusal8616
from inertia.ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin

from .global_object_layout import (
    GlobalObjectLayout8616,
    GlobalObjectLayoutEvidence8616,
    GlobalObjectLayoutFailureKind8616,
    GlobalObjectLayoutRefusal8616,
    GlobalObjectLayoutSourceKind8616,
    TransportedGlobalObjectLayoutSource8616,
)

_SCHEMA_8616 = 1


def _source_record_8616(refusal: GlobalObjectLayoutRefusal8616) -> dict[str, str]:
    """Reduce one typed Alias source to its stable category and verdict."""
    source = refusal.source
    if isinstance(source, IndexedAliasFunctionRefusal8616):
        kind = GlobalObjectLayoutSourceKind8616.FUNCTION_REFUSAL
        summary = source.failure.value
    elif isinstance(source, IndexedAliasAccessFact8616):
        kind = GlobalObjectLayoutSourceKind8616.ACCESS_FACT
        summary = source.role.value
    elif isinstance(source, IndexedAliasAccessRefusal8616):
        kind = GlobalObjectLayoutSourceKind8616.ACCESS_REFUSAL
        summary = source.failure.value
    elif isinstance(source, IndexedAliasCopyFact8616):
        kind = GlobalObjectLayoutSourceKind8616.COPY_FACT
        summary = "accepted_copy"
    elif isinstance(source, IndexedAliasCopyRefusal8616):
        kind = GlobalObjectLayoutSourceKind8616.COPY_REFUSAL
        summary = source.failure.value
    else:
        kind = source.kind
        summary = source.summary
    return {"kind": kind.value, "summary": summary}


def global_object_layout_evidence_record_8616(
    evidence: GlobalObjectLayoutEvidence8616,
) -> dict[str, object]:
    """Serialize one closed Widening artifact to a deterministic record."""
    if not evidence.closed:
        raise ValueError("cannot transport open global-object Widening evidence")
    return {
        "schema": _SCHEMA_8616,
        "layouts": [
            {
                "space": layout.address.space.value,
                "offset": layout.address.offset,
                "size": layout.address.size,
                "status": layout.address.status.value,
                "segment_origin": layout.address.segment_origin.value,
                "element_width": layout.element_width,
                "field_offsets": list(layout.field_offsets),
                "family_base_offset": layout.family_base_offset,
            }
            for layout in evidence.layouts
        ],
        "counts": {
            "raw": evidence.raw_fact_count,
            "normalized": evidence.normalized_fact_count,
            "classified": evidence.classified_fact_count,
            "materialized": evidence.materialized_count,
            "failure": evidence.failure_count,
        },
        "refusals": [
            {
                "function_addr": refusal.function_addr,
                "failure": refusal.failure.value,
                "detail": refusal.detail,
                "source": _source_record_8616(refusal),
            }
            for refusal in evidence.refusals
        ],
    }


def _nonnegative_int_8616(value: object, *, field: str) -> int:
    """Parse one strict nonnegative integer transport field."""
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"global-object transport has invalid {field}")
    return value


def _nonempty_string_8616(value: object, *, field: str) -> str:
    """Parse one strict nonempty string transport field."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"global-object transport has invalid {field}")
    return value


def _layout_from_record_8616(record: object) -> GlobalObjectLayout8616:
    """Validate and restore one transported layout."""
    if not isinstance(record, dict):
        raise ValueError("global-object transport layout must be an object")
    raw_fields = record.get("field_offsets")
    if not isinstance(raw_fields, list):
        raise ValueError("global-object transport has invalid field offsets")
    fields = tuple(
        _nonnegative_int_8616(value, field="field offset") for value in raw_fields
    )
    layout = GlobalObjectLayout8616(
        address=IRAddress(
            space=MemSpace(record.get("space")),
            offset=_nonnegative_int_8616(record.get("offset"), field="layout offset"),
            size=_nonnegative_int_8616(record.get("size"), field="layout size"),
            status=AddressStatus(record.get("status")),
            segment_origin=SegmentOrigin(record.get("segment_origin")),
        ),
        element_width=_nonnegative_int_8616(
            record.get("element_width"),
            field="element width",
        ),
        field_offsets=fields,
        family_base_offset=_nonnegative_int_8616(
            record.get("family_base_offset"),
            field="family base",
        ),
    )
    if not layout.complete:
        raise ValueError("global-object transport contains an incomplete layout")
    return layout


def _refusal_from_record_8616(record: object) -> GlobalObjectLayoutRefusal8616:
    """Validate and restore one transported refusal summary."""
    if not isinstance(record, dict):
        raise ValueError("global-object transport refusal must be an object")
    source_record = record.get("source")
    if not isinstance(source_record, dict):
        raise ValueError("global-object transport has invalid refusal detail")
    detail = _nonempty_string_8616(record.get("detail"), field="refusal detail")
    summary = _nonempty_string_8616(
        source_record.get("summary"),
        field="source summary",
    )
    return GlobalObjectLayoutRefusal8616(
        function_addr=_nonnegative_int_8616(
            record.get("function_addr"),
            field="refusal function address",
        ),
        failure=GlobalObjectLayoutFailureKind8616(
            _nonempty_string_8616(record.get("failure"), field="refusal failure")
        ),
        detail=detail,
        source=TransportedGlobalObjectLayoutSource8616(
            kind=GlobalObjectLayoutSourceKind8616(
                _nonempty_string_8616(
                    source_record.get("kind"),
                    field="source kind",
                )
            ),
            summary=summary,
        ),
    )


def global_object_layout_evidence_from_record_8616(
    record: object,
) -> GlobalObjectLayoutEvidence8616:
    """Restore and close one clean-worker Widening evidence record."""
    if not isinstance(record, dict) or record.get("schema") != _SCHEMA_8616:
        raise ValueError("global-object transport has an unsupported schema")
    raw_layouts = record.get("layouts")
    raw_refusals = record.get("refusals")
    counts = record.get("counts")
    if (
        not isinstance(raw_layouts, list)
        or not isinstance(raw_refusals, list)
        or not isinstance(counts, dict)
    ):
        raise ValueError("global-object transport has invalid evidence collections")
    evidence = GlobalObjectLayoutEvidence8616(
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
        refusals=tuple(_refusal_from_record_8616(item) for item in raw_refusals),
    )
    if not evidence.closed:
        raise ValueError("transported global-object Widening evidence did not close")
    return evidence


__all__ = [
    "global_object_layout_evidence_from_record_8616",
    "global_object_layout_evidence_record_8616",
]
