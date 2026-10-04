from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.lowering.callee_pointer_codec import (
    callee_pointer_argument_evidence_from_record_8616,
    callee_pointer_argument_evidence_map_from_record_8616,
    callee_pointer_argument_evidence_map_record_8616,
    callee_pointer_argument_evidence_record_8616,
)
from angr_platforms.X86_16.lowering.callee_pointer_contracts import (
    CalleePointerArgumentEvidence8616,
    callee_pointer_argument_evidence_by_addr_8616,
    record_callee_pointer_argument_evidence_8616,
)


def _evidence() -> CalleePointerArgumentEvidence8616:
    return CalleePointerArgumentEvidence8616(
        target_addr=0x107B8,
        raw_fact_count=2,
        normalized_fact_count=2,
        classified_fact_count=2,
        materialized_count=2,
        failure_count=0,
        pointer_stack_offsets=(4, 6),
        pointer_argument_indices=(0, 1),
        ambiguous_displaced_stack_offsets=(),
    )


def test_callee_pointer_codec_round_trips_exact_registry() -> None:
    evidence = _evidence()
    record = callee_pointer_argument_evidence_map_record_8616(
        {evidence.target_addr: evidence}
    )

    assert callee_pointer_argument_evidence_map_from_record_8616(record) == {
        evidence.target_addr: evidence
    }


def test_callee_pointer_codec_reads_older_record_without_index_ambiguity() -> None:
    evidence = _evidence()
    record = callee_pointer_argument_evidence_record_8616(evidence)
    del record["ambiguous_indexed_stack_offsets"]

    assert callee_pointer_argument_evidence_from_record_8616(record) == evidence


def test_callee_pointer_registry_records_validated_snapshot() -> None:
    project = SimpleNamespace()
    evidence = _evidence()

    record_callee_pointer_argument_evidence_8616(project, evidence)

    assert callee_pointer_argument_evidence_by_addr_8616(project) == {
        evidence.target_addr: evidence
    }


def test_callee_pointer_codec_rejects_open_failure_accounting() -> None:
    record = callee_pointer_argument_evidence_record_8616(_evidence())
    record["failure_count"] = 1

    with pytest.raises(ValueError, match="failure count"):
        callee_pointer_argument_evidence_from_record_8616(record)


def test_callee_pointer_codec_rejects_duplicate_targets() -> None:
    record = callee_pointer_argument_evidence_record_8616(_evidence())

    with pytest.raises(ValueError, match="duplicate targets"):
        callee_pointer_argument_evidence_map_from_record_8616([record, record])


def test_callee_pointer_registry_rejects_wrong_target_key() -> None:
    evidence = _evidence()

    with pytest.raises(ValueError, match="map key"):
        callee_pointer_argument_evidence_map_record_8616({0x1234: evidence})
