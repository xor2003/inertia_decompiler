"""Encode final project-wide indexed ranges for clean workers.

Layer: Widening.
Responsibility: serialize and validate already-classified bounded global ranges,
their exact proof sites, refusals, source census, and layout dependency. This
module never rebuilds IR, Alias, bounds, layouts, types, or rendered C.
Consumes alias-proven storage identity and closed Widening evidence.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations

from inertia.ir.core import MemSpace
from inertia.ir.indexed_address_contracts import IndexedAddressAccessKind8616
from inertia.ir.indexed_address_range_witnesses import IndexedLoopProofSite8616

from .global_object_layout_codec import (
    global_object_layout_evidence_from_record_8616,
    global_object_layout_evidence_record_8616,
)
from .indexed_global_object_program_ranges import (
    ProjectBoundedGlobalObjectRangeEvidence8616,
    ProjectBoundedGlobalObjectRangeSource8616,
    ProjectBoundedGlobalObjectRangeSourceKind8616,
    ProjectBoundedGlobalObjectRangeSourceStatus8616,
)
from .indexed_global_object_ranges import (
    BoundedGlobalObjectRange8616,
    BoundedGlobalObjectRangeFailureKind8616,
    BoundedGlobalObjectRangeRefusal8616,
    BoundedGlobalObjectRangeStats8616,
    IndexedGlobalAccessKey8616,
)

_SCHEMA_8616 = 1


def _nonnegative_int_8616(value: object, *, field: str) -> int:
    """Parse one strict nonnegative integer transport field."""
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"project-range transport has invalid {field}")
    return value


def _nonempty_string_8616(value: object, *, field: str) -> str:
    """Parse one strict nonempty string transport field."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"project-range transport has invalid {field}")
    return value


def _access_key_record_8616(key: IndexedGlobalAccessKey8616) -> dict[str, object]:
    """Reduce one exact indexed access identity to stable scalar fields."""
    return {
        "function_addr": key.function_addr,
        "block_addr": key.block_addr,
        "instr_index": key.instr_index,
        "instr_addr": key.instr_addr,
        "kind": key.kind.value,
    }


def _access_key_from_record_8616(record: object) -> IndexedGlobalAccessKey8616:
    """Restore and validate one exact indexed access identity."""
    if not isinstance(record, dict):
        raise ValueError("project-range access key must be an object")
    key = IndexedGlobalAccessKey8616(
        _nonnegative_int_8616(record.get("function_addr"), field="function address"),
        _nonnegative_int_8616(record.get("block_addr"), field="block address"),
        _nonnegative_int_8616(record.get("instr_index"), field="instruction index"),
        _nonnegative_int_8616(record.get("instr_addr"), field="instruction address"),
        IndexedAddressAccessKind8616(
            _nonempty_string_8616(record.get("kind"), field="access kind")
        ),
    )
    if not key.complete:
        raise ValueError("project-range transport contains an incomplete access key")
    return key


def _proof_site_record_8616(site: IndexedLoopProofSite8616) -> dict[str, int]:
    """Reduce one exact IR proof site to stable scalar fields."""
    return {
        "block_addr": site.block_addr,
        "instr_index": site.instr_index,
        "instr_addr": site.instr_addr,
    }


def _proof_site_from_record_8616(record: object) -> IndexedLoopProofSite8616:
    """Restore and validate one exact IR proof site."""
    if not isinstance(record, dict):
        raise ValueError("project-range proof site must be an object")
    site = IndexedLoopProofSite8616(
        _nonnegative_int_8616(record.get("block_addr"), field="proof block address"),
        _nonnegative_int_8616(record.get("instr_index"), field="proof instruction index"),
        _nonnegative_int_8616(record.get("instr_addr"), field="proof instruction address"),
    )
    if not site.complete:
        raise ValueError("project-range transport contains an incomplete proof site")
    return site


def _sequence_8616(record: dict[object, object], field: str) -> list[object]:
    """Return one mandatory JSON array from a transport object."""
    value = record.get(field)
    if not isinstance(value, list):
        raise ValueError(f"project-range transport has invalid {field}")
    return value


def _range_record_8616(item: BoundedGlobalObjectRange8616) -> dict[str, object]:
    """Serialize one accepted bounded global object."""
    return {
        "space": item.space.value,
        "base": item.base,
        "lower_inclusive": item.lower_inclusive,
        "upper_exclusive": item.upper_exclusive,
        "element_width": item.element_width,
        "element_count": item.element_count,
        "byte_extent": item.byte_extent,
        "access_keys": [_access_key_record_8616(key) for key in item.covered_access_keys],
        "proof_sites": [_proof_site_record_8616(site) for site in item.proof_sites],
    }


def _range_from_record_8616(record: object) -> BoundedGlobalObjectRange8616:
    """Restore and validate one accepted bounded global object."""
    if not isinstance(record, dict):
        raise ValueError("project-range accepted item must be an object")
    item = BoundedGlobalObjectRange8616(
        MemSpace(_nonempty_string_8616(record.get("space"), field="range space")),
        _nonnegative_int_8616(record.get("base"), field="range base"),
        _nonnegative_int_8616(record.get("lower_inclusive"), field="lower bound"),
        _nonnegative_int_8616(record.get("upper_exclusive"), field="upper bound"),
        _nonnegative_int_8616(record.get("element_width"), field="element width"),
        _nonnegative_int_8616(record.get("element_count"), field="element count"),
        _nonnegative_int_8616(record.get("byte_extent"), field="byte extent"),
        tuple(_access_key_from_record_8616(value) for value in _sequence_8616(record, "access_keys")),
        tuple(_proof_site_from_record_8616(value) for value in _sequence_8616(record, "proof_sites")),
    )
    if not item.complete:
        raise ValueError("project-range transport contains an incomplete accepted item")
    return item


def _refusal_record_8616(item: BoundedGlobalObjectRangeRefusal8616) -> dict[str, object]:
    """Serialize one atomic object-level refusal."""
    return {
        "space": item.space.value,
        "base": item.base,
        "failure": item.failure.value,
        "detail": item.detail,
        "access_keys": [_access_key_record_8616(key) for key in item.access_keys],
        "proof_sites": [_proof_site_record_8616(site) for site in item.proof_sites],
    }


def _refusal_from_record_8616(record: object) -> BoundedGlobalObjectRangeRefusal8616:
    """Restore and validate one atomic object-level refusal."""
    if not isinstance(record, dict):
        raise ValueError("project-range refusal must be an object")
    item = BoundedGlobalObjectRangeRefusal8616(
        MemSpace(_nonempty_string_8616(record.get("space"), field="refusal space")),
        _nonnegative_int_8616(record.get("base"), field="refusal base"),
        BoundedGlobalObjectRangeFailureKind8616(
            _nonempty_string_8616(record.get("failure"), field="refusal failure")
        ),
        _nonempty_string_8616(record.get("detail"), field="refusal detail"),
        tuple(_access_key_from_record_8616(value) for value in _sequence_8616(record, "access_keys")),
        tuple(_proof_site_from_record_8616(value) for value in _sequence_8616(record, "proof_sites")),
    )
    if not item.complete:
        raise ValueError("project-range transport contains an incomplete refusal")
    return item


def project_bounded_global_ranges_record_8616(
    evidence: ProjectBoundedGlobalObjectRangeEvidence8616,
) -> dict[str, object]:
    """Serialize one closed project bounded-range artifact deterministically."""
    if not evidence.closed:
        raise ValueError("cannot transport open project bounded-range evidence")
    return {
        "schema": _SCHEMA_8616,
        "source": {
            "kind": ProjectBoundedGlobalObjectRangeSourceKind8616.TRANSPORTED_RECORD.value,
            "status": evidence.source.status.value,
            "selected": evidence.source.selected_function_count,
            "materialized": evidence.source.materialized_function_count,
            "refused": evidence.source.refused_function_count,
            "closed_ranges": evidence.source.closed_function_range_count,
        },
        "layouts": global_object_layout_evidence_record_8616(evidence.layouts),
        "ranges": [_range_record_8616(item) for item in evidence.ranges],
        "refusals": [_refusal_record_8616(item) for item in evidence.refusals],
        "counts": {
            "raw": evidence.stats.raw_fact_count,
            "normalized": evidence.stats.normalized_fact_count,
            "classified": evidence.stats.classified_fact_count,
            "materialized": evidence.stats.materialized_count,
            "failure": evidence.stats.failure_count,
        },
    }


def project_bounded_global_ranges_from_record_8616(
    record: object,
) -> ProjectBoundedGlobalObjectRangeEvidence8616:
    """Restore and close one clean-worker project bounded-range record."""
    if not isinstance(record, dict) or record.get("schema") != _SCHEMA_8616:
        raise ValueError("project-range transport has an unsupported schema")
    source_record = record.get("source")
    counts = record.get("counts")
    if not isinstance(source_record, dict) or not isinstance(counts, dict):
        raise ValueError("project-range transport has invalid accounting")
    source_kind = ProjectBoundedGlobalObjectRangeSourceKind8616(
        _nonempty_string_8616(source_record.get("kind"), field="source kind")
    )
    if source_kind is not ProjectBoundedGlobalObjectRangeSourceKind8616.TRANSPORTED_RECORD:
        raise ValueError("project-range transport has a non-transport source kind")
    source = ProjectBoundedGlobalObjectRangeSource8616(
        source_kind,
        ProjectBoundedGlobalObjectRangeSourceStatus8616(
            _nonempty_string_8616(source_record.get("status"), field="source status")
        ),
        _nonnegative_int_8616(source_record.get("selected"), field="selected count"),
        _nonnegative_int_8616(source_record.get("materialized"), field="source materialized count"),
        _nonnegative_int_8616(source_record.get("refused"), field="source refusal count"),
        _nonnegative_int_8616(source_record.get("closed_ranges"), field="closed range count"),
    )
    result = ProjectBoundedGlobalObjectRangeEvidence8616(
        tuple(_range_from_record_8616(value) for value in _sequence_8616(record, "ranges")),
        tuple(_refusal_from_record_8616(value) for value in _sequence_8616(record, "refusals")),
        BoundedGlobalObjectRangeStats8616(
            _nonnegative_int_8616(counts.get("raw"), field="raw count"),
            _nonnegative_int_8616(counts.get("normalized"), field="normalized count"),
            _nonnegative_int_8616(counts.get("classified"), field="classified count"),
            _nonnegative_int_8616(counts.get("materialized"), field="materialized count"),
            _nonnegative_int_8616(counts.get("failure"), field="failure count"),
        ),
        source,
        global_object_layout_evidence_from_record_8616(record.get("layouts")),
    )
    if not result.closed:
        raise ValueError("transported project bounded-range evidence did not close")
    return result


__all__ = [
    "project_bounded_global_ranges_from_record_8616",
    "project_bounded_global_ranges_record_8616",
]
