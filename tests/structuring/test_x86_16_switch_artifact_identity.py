from __future__ import annotations

from inertia.structuring.switch_artifact_identity import (
    canonicalize_switch_artifacts_8616,
)


def _artifact(
    region_id: int,
    *,
    root_region_id: int | None,
    normalized_values: tuple[int, ...],
    ready: bool,
) -> dict[str, object]:
    return {
        "region_id": region_id,
        "decision_tree_summary": {
            "expanded_root_region_id": root_region_id,
            "expanded_root_normalized_case_values": list(normalized_values),
            "expanded_root_normalization_readiness": {"ready": ready},
        },
    }


def test_switch_artifact_identity_collapses_same_proven_expanded_root() -> None:
    first = _artifact(
        0x1182,
        root_region_id=0x1153,
        normalized_values=(69, 60, 62, 72),
        ready=True,
    )
    duplicate = _artifact(
        0x118A,
        root_region_id=0x1153,
        normalized_values=(69, 60, 62, 72),
        ready=True,
    )

    result = canonicalize_switch_artifacts_8616((first, duplicate))

    assert result.artifacts == (first,)
    assert result.raw_fact_count == 2
    assert result.normalized_fact_count == 2
    assert result.classified_fact_count == 1
    assert result.materialized_count == 1
    assert result.failure_count == 0
    assert result.duplicate_fact_count == 1


def test_switch_artifact_identity_preserves_distinct_switch_roots() -> None:
    first = _artifact(
        0x1182,
        root_region_id=0x1153,
        normalized_values=(60, 62),
        ready=True,
    )
    second = _artifact(
        0x1282,
        root_region_id=0x1253,
        normalized_values=(60, 62),
        ready=True,
    )

    result = canonicalize_switch_artifacts_8616((first, second))

    assert result.artifacts == (first, second)
    assert result.classified_fact_count == 2
    assert result.materialized_count == 2
    assert result.duplicate_fact_count == 0


def test_switch_artifact_identity_keeps_unknown_candidates() -> None:
    unknown = _artifact(
        0x1182,
        root_region_id=None,
        normalized_values=(),
        ready=False,
    )

    result = canonicalize_switch_artifacts_8616((unknown,))

    assert result.artifacts == (unknown,)
    assert result.normalized_fact_count == 0
    assert result.classified_fact_count == 0
    assert result.materialized_count == 1
    assert result.failure_count == 1
    assert result.duplicate_fact_count == 0
