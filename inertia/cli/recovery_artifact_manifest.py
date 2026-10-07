"""Layer: Recovery/reporting.

Responsibility: describe recovery artifact output surfaces and persistence formats.
Forbidden: writing artifacts, changing recovery behavior, or hiding missing outputs.

Package ownership contract (canonical inertia/cli package):
Layer: CLI/fallback/reporting.
Owns command entrypoints, fallback orchestration, diagnostics, and reporting of recovered evidence.
Do not perform frontend, IR, semantic, alias, widening, lowering, structuring, rewrite,
postprocess, or validation work here.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .recovery_artifact_cache import describe_x86_16_recovery_artifact_cache_surface
from .recovery_artifact_writer import RecoveryArtifactWriteResult

__all__ = [
    "RecoveryArtifactOutputSpec",
    "build_x86_16_recovery_artifact_report",
    "describe_x86_16_recovery_artifact_outputs",
]


@dataclass(frozen=True, slots=True)
class RecoveryArtifactOutputSpec:
    """Persistence contract for one recovery artifact output surface."""

    kind: str
    producer: str
    payload: str
    persistence: str

    def to_dict(self) -> dict[str, str]:
        """Return a deterministic JSON-compatible output specification."""
        return {
            "kind": self.kind,
            "producer": self.producer,
            "payload": self.payload,
            "persistence": self.persistence,
        }


_RECOVERY_ARTIFACT_OUTPUTS: tuple[RecoveryArtifactOutputSpec, ...] = (
    RecoveryArtifactOutputSpec(
        kind="function_recovery",
        producer="write_x86_16_function_recovery_artifact",
        payload="FunctionRecoveryArtifact",
        persistence="json",
    ),
    RecoveryArtifactOutputSpec(
        kind="corpus_recovery",
        producer="write_x86_16_corpus_recovery_artifact",
        payload="CorpusRecoveryArtifact",
        persistence="json",
    ),
    RecoveryArtifactOutputSpec(
        kind="targeted_cod_recovery",
        producer="write_x86_16_targeted_cod_recovery_artifact",
        payload="TargetedRecoveryArtifactResult",
        persistence="json",
    ),
    RecoveryArtifactOutputSpec(
        kind="cod_batch_recovery",
        producer="write_x86_16_cod_corpus_recovery_artifact",
        payload="CorpusCodRecoveryArtifactResult",
        persistence="json",
    ),
)


def describe_x86_16_recovery_artifact_outputs() -> tuple[dict[str, str], ...]:
    """Describe all recovery artifact output surfaces in stable order."""
    return tuple(item.to_dict() for item in _RECOVERY_ARTIFACT_OUTPUTS)


def build_x86_16_recovery_artifact_report(
    writes: Iterable[RecoveryArtifactWriteResult],
) -> dict[str, object]:
    """Build a deterministic report for recovery artifact outputs and writes."""
    write_rows = tuple(
        sorted(
            (item.to_dict() for item in writes),
            key=lambda row: (str(row["artifact_kind"]), str(row["path"])),
        )
    )
    return {
        "outputs": describe_x86_16_recovery_artifact_outputs(),
        "cache_surface": describe_x86_16_recovery_artifact_cache_surface(),
        "writes": write_rows,
    }
