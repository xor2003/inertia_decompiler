"""Encode project-wide global source evidence without reclassification.

Layer: Types/Lowering.
Responsibility: round-trip complete typed source-family facts across process
boundaries while rejecting malformed counters and index identities.

Consumes alias, widening, and typed facts. Do not recover semantics from COD,
source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Mapping

from inertia.widening.global_object_layout_codec import (
    global_object_layout_evidence_from_record_8616,
    global_object_layout_evidence_record_8616,
)

from .callee_global_object_evidence import CalleeGlobalObjectSourceFamilyFact8616
from .callee_global_object_sources import GlobalObjectSourceEvidence8616

__all__ = [
    "global_object_source_evidence_from_record_8616",
    "global_object_source_evidence_record_8616",
]


def _required_int_8616(record: Mapping[str, object], key: str) -> int:
    """Return one strict JSON integer field, excluding booleans."""
    value = record.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"global source evidence field {key!r} must be an integer")
    return value


def _identity_record_8616(atom: object) -> object:
    """Encode the proven recursive tuple/string/integer index identity."""
    if isinstance(atom, bool):
        raise TypeError("global source index identity cannot contain booleans")
    if isinstance(atom, (int, str)):
        return atom
    if isinstance(atom, tuple):
        return [_identity_record_8616(item) for item in atom]
    raise TypeError("global source index identity contains an unsupported atom")


def _identity_from_record_8616(record: object) -> object:
    """Decode one recursively typed index-identity atom."""
    if isinstance(record, bool):
        raise ValueError("global source index identity cannot contain booleans")
    if isinstance(record, (int, str)):
        return record
    if isinstance(record, list):
        return tuple(_identity_from_record_8616(item) for item in record)
    raise ValueError("global source index identity contains an unsupported record")


def _fact_record_8616(fact: CalleeGlobalObjectSourceFamilyFact8616) -> dict[str, object]:
    """Encode one normalized callee source-family fact."""
    return {
        "target_addr": fact.target_addr,
        "callsite_addr": fact.callsite_addr,
        "argument_index": fact.argument_index,
        "base_offset": fact.base_offset,
        "canonical_base_offset": fact.canonical_base_offset,
        "index_identity": _identity_record_8616(fact.index_identity),
        "family_base_offset": fact.family_base_offset,
        "element_width": fact.element_width,
        "field_offsets": list(fact.field_offsets),
    }


def _fact_from_record_8616(record: object) -> CalleeGlobalObjectSourceFamilyFact8616:
    """Decode and validate one normalized source-family fact."""
    if not isinstance(record, Mapping):
        raise ValueError("global source fact record must be an object")
    raw_identity = _identity_from_record_8616(record.get("index_identity"))
    if not isinstance(raw_identity, tuple):
        raise ValueError("global source index identity must be a tuple")
    raw_field_offsets = record.get("field_offsets")
    if not isinstance(raw_field_offsets, list):
        raise ValueError("global source field offsets must be a list")
    field_offsets = tuple(
        value
        for value in raw_field_offsets
        if isinstance(value, int) and not isinstance(value, bool)
    )
    if len(field_offsets) != len(raw_field_offsets):
        raise ValueError("global source field offsets must contain only integers")
    fact = CalleeGlobalObjectSourceFamilyFact8616(
        target_addr=_required_int_8616(record, "target_addr"),
        callsite_addr=_required_int_8616(record, "callsite_addr"),
        argument_index=_required_int_8616(record, "argument_index"),
        base_offset=_required_int_8616(record, "base_offset"),
        canonical_base_offset=_required_int_8616(record, "canonical_base_offset"),
        index_identity=raw_identity,
        family_base_offset=_required_int_8616(record, "family_base_offset"),
        element_width=_required_int_8616(record, "element_width"),
        field_offsets=field_offsets,
    )
    if min(
        fact.target_addr,
        fact.callsite_addr,
        fact.argument_index,
        fact.base_offset,
        fact.canonical_base_offset,
        fact.family_base_offset,
    ) < 0:
        raise ValueError("global source fact coordinates must be nonnegative")
    if fact.element_width <= 0:
        raise ValueError("global source fact element width must be positive")
    if fact.field_offsets != tuple(sorted(set(fact.field_offsets))) or any(
        offset < 0 for offset in fact.field_offsets
    ):
        raise ValueError("global source fact field offsets are not canonical")
    return fact


def global_object_source_evidence_record_8616(
    evidence: GlobalObjectSourceEvidence8616,
) -> dict[str, object]:
    """Encode one structurally valid global source evidence census."""
    evidence.validate()
    return {
        "scope_addr": evidence.scope_addr,
        "source_facts": [_fact_record_8616(fact) for fact in evidence.source_facts],
        "raw_fact_count": evidence.raw_fact_count,
        "normalized_fact_count": evidence.normalized_fact_count,
        "classified_fact_count": evidence.classified_fact_count,
        "materialized_count": evidence.materialized_count,
        "failure_count": evidence.failure_count,
        "pointer_target_addrs": list(evidence.pointer_target_addrs),
        "layout_evidence": (
            None
            if evidence.layout_evidence is None
            else global_object_layout_evidence_record_8616(evidence.layout_evidence)
        ),
    }


def global_object_source_evidence_from_record_8616(
    record: object,
) -> GlobalObjectSourceEvidence8616:
    """Decode one global source census without deriving new semantic facts."""
    if not isinstance(record, Mapping):
        raise ValueError("global source evidence record must be an object")
    scope_addr = record.get("scope_addr")
    if scope_addr is not None and (
        not isinstance(scope_addr, int) or isinstance(scope_addr, bool) or scope_addr < 0
    ):
        raise ValueError("global source evidence scope must be null or nonnegative")
    raw_facts = record.get("source_facts")
    raw_targets = record.get("pointer_target_addrs")
    if not isinstance(raw_facts, list) or not isinstance(raw_targets, list):
        raise ValueError("global source evidence facts and targets must be lists")
    pointer_targets = tuple(
        value
        for value in raw_targets
        if isinstance(value, int) and not isinstance(value, bool)
    )
    if len(pointer_targets) != len(raw_targets):
        raise ValueError("global source pointer targets must contain only integers")
    raw_layout = record.get("layout_evidence")
    layout_evidence = (
        None
        if raw_layout is None
        else global_object_layout_evidence_from_record_8616(raw_layout)
    )
    evidence = GlobalObjectSourceEvidence8616(
        scope_addr=scope_addr,
        source_facts=tuple(_fact_from_record_8616(fact) for fact in raw_facts),
        raw_fact_count=_required_int_8616(record, "raw_fact_count"),
        normalized_fact_count=_required_int_8616(record, "normalized_fact_count"),
        classified_fact_count=_required_int_8616(record, "classified_fact_count"),
        materialized_count=_required_int_8616(record, "materialized_count"),
        failure_count=_required_int_8616(record, "failure_count"),
        pointer_target_addrs=pointer_targets,
        layout_evidence=layout_evidence,
    )
    evidence.validate()
    return evidence
