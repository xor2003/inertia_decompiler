"""Select coverage candidates and run them through the existing DOS harness.

Layer: Tooling/gates.
Responsibility: manifest selection and compact aggregate reporting, without
claiming that successful round trips prove the nominated feature witnesses.
Schema-2 (frozen batch) manifests dispatch each row through the same runner
with its own pinned compiler profile, sources, runtime inputs, and catalogues.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT: Path = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.compiler_toolchain.compiler_coverage_manifest import (  # noqa: E402
    CoverageCase,
    CoverageManifest,
    load_manifest,
)
from tools.compiler_toolchain.compiler_coverage_rerun import failed_cases  # noqa: E402
from tools.compiler_toolchain.compiler_coverage_result import CoverageOutcome  # noqa: E402
from tools.compiler_toolchain.compiler_coverage_runner import run_existing_case, run_source_case  # noqa: E402
from tools.compiler_toolchain.compiler_profile import (  # noqa: E402
    MSC6_AX_PROFILE_ID,
    CompilerProfileSelection,
    CompilerToolchain,
    profile_registry_path,
    resolve_case_toolchain,
    select_manifest_profile,
)


def _sha256(path: Path) -> str:
    """Return the SHA-256 of one host file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _verify_pinned_input(path_text: str, sha256: str, label: str) -> Path:
    """Resolve one manifest-pinned input inside the checkout and verify its bytes."""
    relative = Path(path_text)
    if relative.is_absolute() or "\\" in path_text or ".." in relative.parts:
        raise ValueError(f"{label}: pinned input path must be repo-relative: {path_text!r}")
    path = (ROOT / relative).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError as error:
        raise ValueError(f"{label}: pinned input resolves outside checkout: {path_text!r}") from error
    if not path.is_file():
        raise ValueError(f"{label}: pinned input missing: {path_text}")
    actual = _sha256(path)
    if actual != sha256:
        raise ValueError(
            f"{label}: {path_text} sha256 mismatch (manifest {sha256[:12]}…, host {actual[:12]}…)"
        )
    return path


def _frozen_toolchain(candidate: CoverageCase, evidence_path: Path | None) -> CompilerToolchain:
    """Resolve and verify the pinned compiler profile for one frozen row."""
    if candidate.compiler_profile is None:
        raise ValueError(f"case {candidate.identifier}: missing compiler_profile")
    return resolve_case_toolchain(profile_id=candidate.compiler_profile, evidence_path=evidence_path)


def _run_frozen_case(
    candidate: CoverageCase, artifacts: Path, *, timeout: float,
    stage_budget_seconds: int,
    evidence_path: Path | None,
) -> CoverageOutcome:
    """Verify every pin, then route one frozen row through the shared runner."""
    assert candidate.source is not None  # Guaranteed by schema-2 manifest load.
    source = _verify_pinned_input(
        candidate.source.path, candidate.source.sha256, f"case {candidate.identifier} source")
    headers = {
        item.name: _verify_pinned_input(item.path, item.sha256, f"case {candidate.identifier}")
        for item in candidate.runtime_headers
    }
    runtime_sources = {
        item.name: _verify_pinned_input(item.path, item.sha256, f"case {candidate.identifier}")
        for item in candidate.runtime_sources
    }
    catalogs = tuple(
        _verify_pinned_input(item.path, item.sha256, f"case {candidate.identifier}")
        for item in candidate.signature_catalogs
    )
    toolchain = _frozen_toolchain(candidate, evidence_path)
    selection = CompilerProfileSelection(
        toolchain=toolchain,
        evidence_path=(
            profile_registry_path(evidence_path)
            if toolchain.profile_id != MSC6_AX_PROFILE_ID else None
        ),
    )
    return run_source_case(
        source, artifacts, timeout=timeout,
        expected_exit_code=candidate.expected_exit_code,
        expected_stdout_contains=candidate.expected_stdout_contains,
        stage_budget_seconds=stage_budget_seconds,
        runtime_headers=headers,
        runtime_sources=runtime_sources,
        signature_catalogs=catalogs,
        compiler_profile=selection,
    )


def _run_candidate(
    manifest_schema: int,
    candidate: CoverageCase,
    artifacts: Path,
    *,
    timeout: float,
    stage_budget_seconds: int | None,
    profile: CompilerProfileSelection | None,
    evidence_path: Path | None,
) -> CoverageOutcome:
    """Dispatch one selected row through the existing runner boundary."""
    if manifest_schema == 2:
        if stage_budget_seconds is None:
            raise ValueError("schema-2 dispatch requires its stage budget")
        return _run_frozen_case(
            candidate, artifacts, timeout=timeout,
            stage_budget_seconds=stage_budget_seconds,
            evidence_path=evidence_path,
        )
    assert profile is not None  # Guaranteed for schema-1 manifests.
    return run_existing_case(
        candidate.construct, artifacts, timeout=timeout, compiler_profile=profile)


def _row_profile(candidate: CoverageCase, profile: CompilerProfileSelection | None) -> str | None:
    """Return the recorded profile identity for one summary row."""
    if candidate.compiler_profile is not None:
        return candidate.compiler_profile
    return profile.toolchain.profile_id if profile is not None else None


def _summary_row(
    candidate: CoverageCase,
    artifacts: Path,
    *,
    pending: str,
    profile: CompilerProfileSelection | None,
) -> dict[str, object]:
    """Create a denominator-preserving row before execution begins."""
    return {
        "case": candidate.identifier,
        "construct": candidate.construct,
        "compiler_profile": _row_profile(candidate, profile),
        "source_id": candidate.source.identifier if candidate.source else None,
        "expected_exit_code": candidate.expected_exit_code,
        "obligations": candidate.obligations,
        "outcome": CoverageOutcome.NOT_ATTEMPTED.value,
        "attempted": False,
        "artifacts": str(artifacts),
        "error": pending,
    }


def _write_suite_summary(
    output: Path,
    manifest_path: Path,
    digest: str,
    manifest: CoverageManifest,
    profile: CompilerProfileSelection | None,
    selected: tuple[CoverageCase, ...],
    rows: list[dict[str, object]],
    completed: int,
) -> None:
    """Persist selected rows and the frozen manifest denominator atomically per stage."""
    passed = completed == len(selected) and all(
        row["outcome"] == CoverageOutcome.PASSED.value for row in rows
    )
    summary = {
        "schema": 1,
        "manifest": str(manifest_path.resolve()),
        "manifest_sha256": digest,
        "manifest_schema": manifest.schema,
        "profile": manifest.profile,
        "compiler_profile": profile.to_dict() if profile else None,
        "selected": len(selected),
        "denominator": len(manifest.cases),
        "completed": completed,
        "roundtrips_passed": passed,
        "feature_coverage_verified": False,
        "cases": rows,
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


def run_suite(
    manifest_path: Path, output: Path, *, case: str | None = None,
    obligation: str | None = None, timeout: float = 600,
    rerun_failed: Path | None = None, profile_evidence: Path | None = None,
) -> bool:
    """Execute selected candidates serially to avoid nested decompiler pools."""
    manifest = load_manifest(manifest_path)
    profile = (
        select_manifest_profile(manifest, evidence_path=profile_evidence)
        if manifest.schema == 1 else None
    )
    if manifest.case_budget_seconds is not None:
        timeout = min(timeout, manifest.case_budget_seconds)
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    if rerun_failed is not None and (case is not None or obligation is not None):
        raise ValueError("Failed-case reruns cannot be combined with case/obligation filters")
    selected = (manifest.select(case, obligation) if rerun_failed is None
                else failed_cases(rerun_failed, manifest, digest))
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    artifacts_by_index = [output / f"case-{index:03d}" for index in range(len(selected))]
    rows = [
        _summary_row(
            candidate, artifacts, pending="not attempted: execution pending", profile=profile,
        )
        for candidate, artifacts in zip(selected, artifacts_by_index, strict=True)
    ]
    completed = 0
    _write_suite_summary(output, manifest_path, digest, manifest, profile, selected, rows, completed)
    for index, (candidate, artifacts) in enumerate(zip(selected, artifacts_by_index, strict=True)):
        error: str | None = None
        try:
            outcome = _run_candidate(
                manifest.schema, candidate, artifacts, timeout=timeout,
                stage_budget_seconds=manifest.stage_budget_seconds,
                profile=profile, evidence_path=profile_evidence,
            )
        except (OSError, ValueError) as failure:
            outcome = CoverageOutcome.HARNESS_FAILED
            error = str(failure)
        completed += 1
        rows[index] = {
            **_summary_row(candidate, artifacts, pending="", profile=profile),
            "outcome": outcome.value,
            "attempted": True,
            "error": error,
        }
        print(f"{candidate.identifier}: {outcome.value}; artifacts={artifacts}", flush=True)
        halt_reason = (
            f"stopped after {candidate.identifier}: {outcome.value}"
            if manifest.schema == 2 and error is None
            and outcome in (CoverageOutcome.HARNESS_FAILED, CoverageOutcome.TIMED_OUT)
            else None
        )
        if halt_reason is not None:
            for pending_row in rows[index + 1:]:
                pending_row["error"] = f"not attempted: {halt_reason}"
            _write_suite_summary(
                output, manifest_path, digest, manifest, profile, selected, rows, completed,
            )
            break
        _write_suite_summary(
            output, manifest_path, digest, manifest, profile, selected, rows, completed,
        )
    return completed == len(selected) and all(
        row["outcome"] == CoverageOutcome.PASSED.value for row in rows
    )


def main() -> int:
    """Expose exact candidate selection without silently changing compilation."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "examples/compiler_coverage/pilot.json")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--case")
    parser.add_argument("--obligation")
    parser.add_argument("--rerun-failed", type=Path)
    parser.add_argument("--profile-evidence", type=Path)
    parser.add_argument("--timeout", type=float, default=600)
    args = parser.parse_args()
    try:
        passed = run_suite(args.manifest, args.out_dir, case=args.case,
                           obligation=args.obligation, timeout=args.timeout, rerun_failed=args.rerun_failed,
                           profile_evidence=args.profile_evidence)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
