"""Layer: Recovery/reporting.

Responsibility: build corpus-level recovery artifacts from bounded scan results.
Forbidden: replacing scan failures with source-backed or guessed recovery output.

Package ownership contract (canonical inertia/cli package):
Layer: CLI/fallback/reporting.
Owns command entrypoints, fallback orchestration, diagnostics, and reporting of recovered evidence.
Do not perform frontend, IR, semantic, alias, widening, lowering, structuring, rewrite,
postprocess, or validation work here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path

from .corpus_scan import FunctionScanResult, extract_cod_functions, scan_function
from .recovery_artifact_writer import RecoveryArtifactWriteResult, write_x86_16_corpus_recovery_artifact
from .recovery_artifacts import build_x86_16_corpus_recovery_artifact

__all__ = [
    "CorpusCodRecoveryArtifactResult",
    "write_x86_16_cod_corpus_recovery_artifact",
]


def _scan_result_row(result: Mapping[str, object] | FunctionScanResult) -> Mapping[str, object]:
    if isinstance(result, Mapping):
        return result
    return asdict(result)


@dataclass(frozen=True, slots=True)
class CorpusCodRecoveryArtifactResult:
    """Result metadata for one bounded COD corpus recovery artifact."""

    cod_path: Path
    proc_count: int
    write_result: RecoveryArtifactWriteResult
    confidence_status_counts: dict[str, int]
    helper_status_counts: dict[str, int]
    low_memory_read_region_counts: dict[str, int]
    low_memory_write_region_counts: dict[str, int]

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-compatible corpus artifact result."""
        return {
            "cod_path": str(self.cod_path),
            "proc_count": self.proc_count,
            "write_result": self.write_result.to_dict(),
            "confidence_status_counts": dict(self.confidence_status_counts),
            "helper_status_counts": dict(self.helper_status_counts),
            "low_memory_read_region_counts": dict(self.low_memory_read_region_counts),
            "low_memory_write_region_counts": dict(self.low_memory_write_region_counts),
        }


def write_x86_16_cod_corpus_recovery_artifact(
    cod_path: str | Path,
    output_path: str | Path,
    *,
    timeout_sec: int = 5,
    mode: str = "scan-safe",
    max_cfg_bytes: int = 192,
    max_cfg_blocks: int = 8,
    max_cfg_insns: int = 200,
    max_decompile_bytes: int = 384,
    max_loop_bytes: int = 128,
    limit: int | None = None,
) -> CorpusCodRecoveryArtifactResult:
    """Scan bounded COD procedures and write a corpus recovery artifact."""
    source_path = Path(cod_path)
    entries = extract_cod_functions(source_path)
    if limit is not None and limit >= 0:
        entries = entries[:limit]

    results = [
        scan_function(
            source_path,
            proc_name,
            proc_kind,
            code,
            timeout_sec=timeout_sec,
            mode=mode,
            max_cfg_bytes=max_cfg_bytes,
            max_cfg_blocks=max_cfg_blocks,
            max_cfg_insns=max_cfg_insns,
            max_decompile_bytes=max_decompile_bytes,
            max_loop_bytes=max_loop_bytes,
        )
        for proc_name, proc_kind, code in entries
    ]
    result_rows = tuple(_scan_result_row(result) for result in results)
    artifact = build_x86_16_corpus_recovery_artifact(result_rows)
    write_result = write_x86_16_corpus_recovery_artifact(result_rows, output_path)
    return CorpusCodRecoveryArtifactResult(
        cod_path=source_path,
        proc_count=len(results),
        write_result=write_result,
        confidence_status_counts=dict(artifact.confidence_status_counts),
        helper_status_counts=dict(artifact.helper_status_counts),
        low_memory_read_region_counts=dict(artifact.low_memory_read_region_counts),
        low_memory_write_region_counts=dict(artifact.low_memory_write_region_counts),
    )
