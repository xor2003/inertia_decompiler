# cython: language_level=3, infer_types=True
"""Encode validated callee pointer evidence without classification.

Layer: Types/Lowering.
Responsibility: round-trip the authoritative pointer-parameter evidence map
across process boundaries and reject malformed or duplicate target records.

Consumes alias, widening, and typed facts. Do not recover semantics from COD,
source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Mapping

from .callee_pointer_contracts import CalleePointerArgumentEvidence8616
import operator

__all__ = [
    "callee_pointer_argument_evidence_from_record_8616",
    "callee_pointer_argument_evidence_map_from_record_8616",
    "callee_pointer_argument_evidence_map_record_8616",
    "callee_pointer_argument_evidence_record_8616",
]


@cython.ccall
def _required_int_8616(record: Mapping[str, object], key: object) -> cython.longlong:
    """Return one strict JSON integer, excluding booleans."""
    value: object
    value = record.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"callee pointer field {key!r} must be an integer")
    return value


def _int_tuple_8616(record: Mapping[str, object], key: object) -> object:
    """Decode one JSON list containing only strict integers."""
    values: object
    values = record.get(key)
    if not isinstance(values, list):
        raise ValueError(f"callee pointer field {key!r} must be a list")
    decoded = tuple(
        value
        for value in iter(values)
        if isinstance(value, int) and not isinstance(value, bool)
    )
    if operator.ne(len(decoded), len(values)):
        raise ValueError(f"callee pointer field {key!r} contains a non-integer")
    return decoded


@cython.ccall
def _optional_int_tuple_8616(
    record: Mapping[str, object], key: object
) -> object:
    """Read an added evidence field while accepting older closed records."""
    if key not in record:
        return ()
    return _int_tuple_8616(record, key)


@cython.ccall
def callee_pointer_argument_evidence_record_8616(
    evidence: CalleePointerArgumentEvidence8616,
) -> dict[str, object]:
    """Encode one structurally valid pointer-parameter census."""
    evidence.validate()
    return {
        "target_addr": evidence.target_addr,
        "raw_fact_count": evidence.raw_fact_count,
        "normalized_fact_count": evidence.normalized_fact_count,
        "classified_fact_count": evidence.classified_fact_count,
        "materialized_count": evidence.materialized_count,
        "failure_count": evidence.failure_count,
        "pointer_stack_offsets": list(evidence.pointer_stack_offsets),
        "pointer_argument_indices": list(evidence.pointer_argument_indices),
        "ambiguous_displaced_stack_offsets": list(
            evidence.ambiguous_displaced_stack_offsets
        ),
        "ambiguous_indexed_stack_offsets": list(
            evidence.ambiguous_indexed_stack_offsets
        ),
    }


@cython.ccall
def callee_pointer_argument_evidence_from_record_8616(
    record: object,
) -> CalleePointerArgumentEvidence8616:
    """Decode one pointer census without recovering semantic facts."""
    if not isinstance(record, Mapping):
        raise ValueError("callee pointer evidence record must be an object")
    evidence = CalleePointerArgumentEvidence8616(
        target_addr=_required_int_8616(record, "target_addr"),
        raw_fact_count=_required_int_8616(record, "raw_fact_count"),
        normalized_fact_count=_required_int_8616(record, "normalized_fact_count"),
        classified_fact_count=_required_int_8616(record, "classified_fact_count"),
        materialized_count=_required_int_8616(record, "materialized_count"),
        failure_count=_required_int_8616(record, "failure_count"),
        pointer_stack_offsets=_int_tuple_8616(record, "pointer_stack_offsets"),
        pointer_argument_indices=_int_tuple_8616(
            record,
            "pointer_argument_indices",
        ),
        ambiguous_displaced_stack_offsets=_int_tuple_8616(
            record,
            "ambiguous_displaced_stack_offsets",
        ),
        ambiguous_indexed_stack_offsets=_optional_int_tuple_8616(
            record,
            "ambiguous_indexed_stack_offsets",
        ),
    )
    evidence.validate()
    return evidence


@cython.ccall
def callee_pointer_argument_evidence_map_record_8616(
    evidence_by_addr: Mapping[cython.longlong, CalleePointerArgumentEvidence8616],
) -> object:
    """Encode a deterministic target-address evidence registry."""
    evidence: object
    target_addr: object
    records: list[dict[str, object]] = []
    for target_addr, evidence in sorted(tuple(evidence_by_addr.items())):
        if not isinstance(target_addr, int) or isinstance(target_addr, bool):
            raise TypeError("callee pointer evidence map key must be an integer")
        if operator.ne(evidence.target_addr, target_addr):
            raise ValueError("callee pointer evidence target disagrees with map key")
        records.append(callee_pointer_argument_evidence_record_8616(evidence))
    return records


@cython.ccall
def callee_pointer_argument_evidence_map_from_record_8616(
    record: object,
) -> object:
    """Decode a unique target-address evidence registry."""
    item: object
    if not isinstance(record, list):
        raise ValueError("callee pointer evidence map must be a list")
    evidence_by_addr: dict[cython.longlong, CalleePointerArgumentEvidence8616] = {}
    for item in record:
        evidence = callee_pointer_argument_evidence_from_record_8616(item)
        if evidence.target_addr in evidence_by_addr:
            raise ValueError("callee pointer evidence map contains duplicate targets")
        evidence_by_addr[evidence.target_addr] = evidence
    return evidence_by_addr
