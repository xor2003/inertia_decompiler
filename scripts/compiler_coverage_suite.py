"""Select coverage candidates and run them through the existing DOS harness.

Layer: Test infrastructure.
Responsibility: manifest selection and compact aggregate reporting, without
claiming that successful round trips prove the nominated feature witnesses.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.compiler_coverage_manifest import CoverageManifest, load_manifest  # noqa: E402
from scripts.compiler_coverage_rerun import failed_cases  # noqa: E402
from scripts.compiler_coverage_result import CoverageOutcome  # noqa: E402
from scripts.compiler_coverage_runner import run_existing_case  # noqa: E402
from scripts.msc6_memory_model import MSCMemoryModel  # noqa: E402


def _check_profile(manifest: CoverageManifest) -> MSCMemoryModel:
    """Refuse settings the existing adapter cannot pass to the compiler yet."""
    if manifest.memory_model is None:
        raise ValueError("Adapter requires an explicit small or large memory model")
    model = MSCMemoryModel(manifest.memory_model)
    if manifest.compiler != "Microsoft C v6ax" or manifest.compiler_flags != ("/Od", model.compiler_flag):
        raise ValueError("Adapter currently supports only Microsoft C v6ax /Od with explicit /AS or /AL")
    return model


def run_suite(
    manifest_path: Path, output: Path, *, case: str | None = None,
    obligation: str | None = None, timeout: float = 600,
    rerun_failed: Path | None = None,
) -> bool:
    """Execute selected candidates serially to avoid nested decompiler pools."""
    manifest = load_manifest(manifest_path)
    model = _check_profile(manifest)
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    if rerun_failed is not None and (case is not None or obligation is not None):
        raise ValueError("Failed-case reruns cannot be combined with case/obligation filters")
    selected = (manifest.select(case, obligation) if rerun_failed is None
                else failed_cases(rerun_failed, manifest, digest))
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    rows: list[dict[str, object]] = []
    passed = True
    for index, candidate in enumerate(selected):
        artifacts = output / f"case-{index:03d}"
        error: str | None = None
        try:
            outcome = run_existing_case(candidate.construct, artifacts, timeout=timeout, memory_model=model)
        except (OSError, ValueError) as failure:
            outcome = CoverageOutcome.HARNESS_FAILED
            error = str(failure)
        passed = passed and outcome is CoverageOutcome.PASSED
        rows.append({"case": candidate.identifier, "construct": candidate.construct,
                     "obligations": candidate.obligations, "outcome": outcome.value,
                     "artifacts": str(artifacts), "error": error})
        summary = {"schema": 1, "manifest": str(manifest_path.resolve()),
                   "manifest_sha256": digest,
                   "profile": manifest.profile, "selected": len(selected), "completed": len(rows),
                   "roundtrips_passed": passed and len(rows) == len(selected),
                   "feature_coverage_verified": False, "cases": rows}
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        print(f"{candidate.identifier}: {outcome.value}; artifacts={artifacts}", flush=True)
    return passed


def main() -> int:
    """Expose exact candidate selection without silently changing compilation."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "examples/compiler_coverage/pilot.json")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--case")
    parser.add_argument("--obligation")
    parser.add_argument("--rerun-failed", type=Path)
    parser.add_argument("--timeout", type=float, default=600)
    args = parser.parse_args()
    try:
        passed = run_suite(args.manifest, args.out_dir, case=args.case,
                           obligation=args.obligation, timeout=args.timeout, rerun_failed=args.rerun_failed)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
