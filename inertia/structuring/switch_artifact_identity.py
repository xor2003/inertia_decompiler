"""Canonicalize typed switch artifacts by normalized decision-tree identity.

Layer: Structuring.
Responsibility: choose one authoritative artifact for candidates that prove the
same expanded switch root and normalized case-value set. Unknown identities are
kept unchanged. CLI diagnostics may project these results but must not invent
or merge switch identity.

Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence. Do not perform alias-state ownership, widening,
type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

type SwitchArtifactRecord8616 = Mapping[str, object]


@dataclass(frozen=True, slots=True)
class CanonicalSwitchArtifactResult8616:
    """Closed evidence result for normalized switch-artifact identity."""

    artifacts: tuple[SwitchArtifactRecord8616, ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    duplicate_fact_count: int


def _int_sequence_8616(value: object) -> tuple[int, ...] | None:
    """Return a non-empty integer sequence from structured artifact data."""
    if not isinstance(value, list | tuple) or not value:
        return None
    if not all(isinstance(item, int) for item in value):
        return None
    return tuple(value)


def _normalized_switch_identity_8616(
    artifact: SwitchArtifactRecord8616,
) -> tuple[int, tuple[int, ...]] | None:
    """Return the proven expanded-root identity for one typed artifact."""
    summary = artifact.get("decision_tree_summary")
    if not isinstance(summary, Mapping):
        return None
    root_region_id = summary.get("expanded_root_region_id")
    normalized_values = _int_sequence_8616(
        summary.get("expanded_root_normalized_case_values")
    )
    readiness = summary.get("expanded_root_normalization_readiness")
    if (
        not isinstance(root_region_id, int)
        or normalized_values is None
        or not isinstance(readiness, Mapping)
        or readiness.get("ready") is not True
    ):
        return None
    return root_region_id, normalized_values


def canonicalize_switch_artifacts_8616(
    artifacts: tuple[SwitchArtifactRecord8616, ...],
) -> CanonicalSwitchArtifactResult8616:
    """Keep one artifact per proven normalized switch and refuse unknown merges."""
    canonical: list[SwitchArtifactRecord8616] = []
    identities: set[tuple[int, tuple[int, ...]]] = set()
    normalized_count = 0
    classified_count = 0
    failure_count = 0
    duplicate_count = 0
    for artifact in artifacts:
        identity = _normalized_switch_identity_8616(artifact)
        if identity is None:
            failure_count += 1
            canonical.append(artifact)
            continue
        normalized_count += 1
        if identity in identities:
            duplicate_count += 1
            continue
        identities.add(identity)
        classified_count += 1
        canonical.append(artifact)
    return CanonicalSwitchArtifactResult8616(
        artifacts=tuple(canonical),
        raw_fact_count=len(artifacts),
        normalized_fact_count=normalized_count,
        classified_fact_count=classified_count,
        materialized_count=len(canonical),
        failure_count=failure_count,
        duplicate_fact_count=duplicate_count,
    )


__all__ = [
    "CanonicalSwitchArtifactResult8616",
    "SwitchArtifactRecord8616",
    "canonicalize_switch_artifacts_8616",
]
