"""Normalize repeated direct-address failure attempts into one stable family key.

Layer: CLI/fallback/reporting.
Responsibility: classify repeated direct-address fallback attempts without recovering semantics.

The x86-16 lane uses this to stop the same retry or fallback family from
running again when it has not gained a new artifact path or a new validator
verdict.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass


def _token(value: object | None, *, default: str) -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


@dataclass(frozen=True, slots=True)
class FailureFamilySnapshot:
    """One normalized failure family attempt."""

    status: str
    failure_stage: str
    sidecar_verdict: str
    non_optimized_verdict: str
    fallback_kind: str
    tail_validation_verdict: str
    artifact_path: str

    @property
    def key(self) -> tuple[str, str, str, str, str, str]:
        """Return the stable family identity, excluding proof freshness."""
        return (
            self.status,
            self.failure_stage,
            self.sidecar_verdict,
            self.non_optimized_verdict,
            self.fallback_kind,
            self.tail_validation_verdict,
        )

    @property
    def proof_token(self) -> tuple[str, str]:
        """Return the fields that show whether this attempt produced new proof."""
        return (self.artifact_path, self.tail_validation_verdict)

    def label(self) -> str:
        """Return a compact diagnostic label for this failure family."""
        status, stage, sidecar, nonopt, fallback, validation = self.key
        return (
            f"status={status} stage={stage} sidecar={sidecar} "
            f"nonopt={nonopt} fallback={fallback} validation={validation}"
        )

    def to_record(self) -> dict[str, str]:
        """Serialize the complete diagnostic snapshot for cache transport."""
        return {
            "status": self.status,
            "failure_stage": self.failure_stage,
            "sidecar_verdict": self.sidecar_verdict,
            "non_optimized_verdict": self.non_optimized_verdict,
            "fallback_kind": self.fallback_kind,
            "tail_validation_verdict": self.tail_validation_verdict,
            "artifact_path": self.artifact_path,
        }

    @classmethod
    def from_record(cls, record: object) -> FailureFamilySnapshot | None:
        """Deserialize a complete snapshot, refusing missing or non-text fields."""
        if not isinstance(record, Mapping):
            return None
        field_names = (
            "status",
            "failure_stage",
            "sidecar_verdict",
            "non_optimized_verdict",
            "fallback_kind",
            "tail_validation_verdict",
            "artifact_path",
        )
        values: dict[str, str] = {}
        for field_name in field_names:
            value = record.get(field_name)
            if not isinstance(value, str) or not value:
                return None
            values[field_name] = value
        return cls(
            status=values["status"],
            failure_stage=values["failure_stage"],
            sidecar_verdict=values["sidecar_verdict"],
            non_optimized_verdict=values["non_optimized_verdict"],
            fallback_kind=values["fallback_kind"],
            tail_validation_verdict=values["tail_validation_verdict"],
            artifact_path=values["artifact_path"],
        )


@dataclass(slots=True)
class FailureFamilyState:
    """Track the last finished direct-address failure lane."""

    previous_snapshot: FailureFamilySnapshot | None = None
    candidate_snapshot: FailureFamilySnapshot | None = None
    new_proof_seen: bool = False
    repeat_detected: bool = False
    same_family_retry_stops: int = 0
    fallback_family_labels: tuple[str, ...] = ()


def build_failure_family_snapshot(
    *,
    status: object | None,
    failure_stage: object | None,
    sidecar_verdict: object | None = None,
    non_optimized_verdict: object | None = None,
    fallback_kind: object | None = None,
    tail_validation_verdict: object | None = None,
    artifact_path: object | None = None,
) -> FailureFamilySnapshot:
    """Build a deterministic family snapshot from one attempt."""
    return FailureFamilySnapshot(
        status=_token(status, default="not_set"),
        failure_stage=_token(failure_stage, default="not_set"),
        sidecar_verdict=_token(sidecar_verdict, default="not_attempted"),
        non_optimized_verdict=_token(non_optimized_verdict, default="not_attempted"),
        fallback_kind=_token(fallback_kind, default="not_set"),
        tail_validation_verdict=_token(tail_validation_verdict, default="not_collected"),
        artifact_path=_token(artifact_path, default="none"),
    )


def failure_family_repeat_reason(
    previous: FailureFamilySnapshot | None,
    candidate: FailureFamilySnapshot,
) -> str | None:
    """Explain why a candidate attempt is a repeat, or return ``None``."""
    if previous is None:
        return None
    if previous.key != candidate.key:
        return None
    if previous.proof_token != candidate.proof_token:
        return None
    return f"same failure family ({candidate.label()})"


def remember_failure_family_candidate(
    state: FailureFamilyState | None,
    candidate: FailureFamilySnapshot,
) -> str | None:
    """Update one shared state holder with the latest candidate snapshot."""
    if state is None:
        return None
    previous = state.previous_snapshot
    state.candidate_snapshot = candidate
    state.new_proof_seen = previous is not None and previous.proof_token != candidate.proof_token
    repeat_reason = failure_family_repeat_reason(previous, candidate)
    state.repeat_detected = repeat_reason is not None
    return repeat_reason


def advance_failure_family_state(state: FailureFamilyState | None) -> None:
    """Promote the current candidate snapshot after one lane finishes."""
    if state is None or state.candidate_snapshot is None:
        return
    state.previous_snapshot = state.candidate_snapshot


def record_failure_family_retry_stop(
    state: FailureFamilyState | None,
    candidate: FailureFamilySnapshot,
) -> None:
    """Record one emitted same-family retry stop for later summaries."""
    if state is None:
        return
    state.same_family_retry_stops += 1
    labels = set(state.fallback_family_labels)
    labels.add(candidate.fallback_kind)
    state.fallback_family_labels = tuple(sorted(labels))
