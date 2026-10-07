from __future__ import annotations

import pytest
from inertia.ir.core import (
    AddressStatus,
    IRAddress,
    MemSpace,
    SegmentOrigin,
)

from inertia.widening.direct_global_object_layout_codec import (
    direct_global_object_layout_evidence_from_record_8616,
    direct_global_object_layout_evidence_record_8616,
)
from inertia.widening.global_object_layout import (
    DirectGlobalObjectLayout8616,
    DirectGlobalObjectLayoutEvidence8616,
)


def _evidence() -> DirectGlobalObjectLayoutEvidence8616:
    return DirectGlobalObjectLayoutEvidence8616(
        layouts=(
            DirectGlobalObjectLayout8616(
                address=IRAddress(
                    space=MemSpace.DS,
                    offset=0x0B4C,
                    size=4,
                    status=AddressStatus.STABLE,
                    segment_origin=SegmentOrigin.PROVEN,
                ),
                proof_function_addrs=(0x108D0, 0x109E8),
            ),
        ),
        raw_fact_count=2,
        normalized_fact_count=2,
        classified_fact_count=2,
        materialized_count=1,
        failure_count=0,
    )


def test_direct_global_layout_evidence_round_trips() -> None:
    evidence = _evidence()

    restored = direct_global_object_layout_evidence_from_record_8616(
        direct_global_object_layout_evidence_record_8616(evidence)
    )

    assert restored == evidence


def test_direct_global_layout_codec_refuses_unmaterialized_classification() -> None:
    evidence = DirectGlobalObjectLayoutEvidence8616(
        (),
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=0,
        failure_count=0,
    )

    with pytest.raises(ValueError, match="not materialized"):
        direct_global_object_layout_evidence_record_8616(evidence)


def test_direct_global_layout_codec_refuses_noncanonical_proofs() -> None:
    record = direct_global_object_layout_evidence_record_8616(_evidence())
    layouts = record["layouts"]
    assert isinstance(layouts, list)
    layout = layouts[0]
    assert isinstance(layout, dict)
    layout["proof_function_addrs"] = [0x109E8, 0x108D0]

    with pytest.raises(ValueError, match="proof functions are not canonical"):
        direct_global_object_layout_evidence_from_record_8616(record)
