# cython: language_level=3, infer_types=True
"""Layer: Recovery/reporting.

Responsibility: build targeted recovery artifacts for one bounded COD procedure.
Forbidden: replacing scan failures with source-backed or guessed recovery output.

Package ownership contract (canonical inertia/cli package):
Layer: CLI/fallback/reporting.
Owns command entrypoints, fallback orchestration, diagnostics, and reporting of recovered evidence.
Do not perform frontend, IR, semantic, alias, widening, lowering, structuring, rewrite,
postprocess, or validation work here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import asdict, dataclass
from pathlib import Path

from .corpus_scan import extract_cod_functions, scan_function
from .recovery_artifact_writer import RecoveryArtifactWriteResult, write_x86_16_function_recovery_artifact
import dataclasses
import builtins

__all__ = [
    "TargetedRecoveryArtifactResult",
    "write_x86_16_targeted_cod_recovery_artifact",
]


@dataclasses.dataclass(frozen=True, )
class TargetedRecoveryArtifactResult:
    """Result metadata for one targeted bounded COD recovery artifact."""

    cod_path: Path
    proc_name: object
    proc_kind: object
    write_result: RecoveryArtifactWriteResult
    confidence_status: object
    fallback_kind: object

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-compatible result payload."""
        return {
            "cod_path": str(self.cod_path),
            "proc_name": self.proc_name,
            "proc_kind": self.proc_kind,
            "write_result": self.write_result.to_dict(),
            "confidence_status": self.confidence_status,
            "fallback_kind": self.fallback_kind,
        }


@cython.ccall
def write_x86_16_targeted_cod_recovery_artifact(
    cod_path: object,
    proc_name: object,
    output_path: object,
    *,
    timeout_sec: cython.longlong = 5,
    mode: object = "scan-safe",
    max_cfg_bytes: cython.longlong = 192,
    max_cfg_blocks: cython.longlong = 8,
    max_cfg_insns: cython.longlong = 200,
    max_decompile_bytes: cython.longlong = 384,
    max_loop_bytes: cython.longlong = 128,
) -> TargetedRecoveryArtifactResult:
    """Scan one COD procedure and write its bounded recovery artifact."""
    source_path = Path(cod_path)
    entries = {name: (kind, code) for name, kind, code in builtins.iter(extract_cod_functions(source_path))}
    if proc_name not in entries:
        raise KeyError(f"{proc_name} not found in {source_path}")
    proc_kind, code = entries[proc_name]
    scan_result = scan_function(
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
    write_result = write_x86_16_function_recovery_artifact(asdict(scan_result), output_path)
    return TargetedRecoveryArtifactResult(
        cod_path=source_path,
        proc_name=proc_name,
        proc_kind=proc_kind,
        write_result=write_result,
        confidence_status=scan_result.confidence_status,
        fallback_kind=scan_result.fallback_kind,
    )
