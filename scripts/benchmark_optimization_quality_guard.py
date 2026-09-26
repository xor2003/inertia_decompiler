#!/usr/bin/env python3
"""Compare decompilation quality between optimized and pure-python modes.

Layer: Tooling/gates.
Responsibility: prevent optimization-only changes from decreasing generated-C quality,
including function coverage, validation success, and deterministic quality metric deltas.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path

REPO_ROOT: Path = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from inertia_decompiler.acceptance_scorecard import (  # noqa: E402
    X86_16QualityMetrics,
    measure_x86_16_codegen_quality_8616,
    measure_x86_16_function_quality_8616,
)
from scripts.mypyc_build_cache import (  # noqa: E402
    disable_importable_project_extensions as _disable_repo_extension_modules,
)
from scripts.mypyc_build_cache import (  # noqa: E402
    iter_importable_project_extensions as _iter_repo_extension_modules,
)

DECOMPILE_SCRIPT: Path = REPO_ROOT / "decompile.py"
_ARTIFACT_RE = re.compile(r"^(?P<address>[0-9a-fA-F]{8})-(?P<name>.+)\.c$")


class DecompileMode(StrEnum):
    """Execution mode for a decompile run."""

    DEFAULT = "default"
    PURE_PYTHON = "pure_python"


class ValidationStatus(StrEnum):
    """Typed validation result for a run."""

    PASSED = "passed"
    FAILED = "failed"
    UNCOLLECTED = "uncollected"


@dataclass(frozen=True, slots=True)
class FunctionArtifact:
    """One generated C function with quality evidence."""

    function_addr: int
    function_name: str
    source_path: Path
    quality: X86_16QualityMetrics


@dataclass(frozen=True, slots=True)
class DecompileRunRequest:
    """Own immutable inputs shared by both quality-guard execution modes."""

    binary_path: Path
    decompiler_args: tuple[str, ...]
    timeout_seconds: float
    output_dir_root: Path
    python_executable: Path
    repo_root: Path


@dataclass(frozen=True, slots=True)
class DecompileRunResult:
    """Evidence for one decompilation execution mode."""

    mode: DecompileMode
    command: tuple[str, ...]
    returncode: int
    wall_seconds: float
    validation: ValidationStatus
    artifacts: tuple[FunctionArtifact, ...]

    @property
    def function_count(self) -> int:
        """Return count of generated functions."""
        return len(self.artifacts)

    @property
    def function_map(self) -> dict[int, FunctionArtifact]:
        """Return function artifacts by original address."""
        return {item.function_addr: item for item in self.artifacts}

    @property
    def quality_aggregate(self) -> dict[str, object]:
        """Return aggregate quality for the complete run."""
        return dict(measure_x86_16_function_quality_8616([item.quality for item in self.artifacts]))


def _aggregate_int(aggregate: dict[str, object], name: str) -> int:
    """Read one required integer quality metric from a typed aggregate boundary."""
    value = aggregate.get(name)
    if not isinstance(value, int):
        raise TypeError(f"quality aggregate field {name!r} is not an integer")
    return value


def _aggregate_float(aggregate: dict[str, object], name: str) -> float:
    """Read one required numeric quality metric from a typed aggregate boundary."""
    value = aggregate.get(name)
    if not isinstance(value, (int, float)):
        raise TypeError(f"quality aggregate field {name!r} is not numeric")
    return float(value)


def _parse_validation_status(stdout: str, stderr: str) -> ValidationStatus:
    """Parse run validation status from CLI output."""
    combined = f"{stdout}\n{stderr}"
    if "validation=passed" in combined or "whole-tail validation clean" in combined:
        return ValidationStatus.PASSED
    if "validation=failed" in combined or "tail validation failed" in combined:
        return ValidationStatus.FAILED
    return ValidationStatus.UNCOLLECTED


def _normalize_decompiler_args(decompiler_args: tuple[str, ...]) -> tuple[str, ...]:
    """Strip arguments that are controlled by this gate."""
    normalized: list[str] = []
    skip_next = False
    for arg in decompiler_args:
        if skip_next:
            skip_next = False
            continue
        if arg == "--brief":
            normalized.append("-q")
            continue
        if arg == "--output-c-dir":
            skip_next = True
            continue
        if arg.startswith("--output-c-dir="):
            continue
        # Guard against accidental tail-validation control from caller mode.
        if arg in {"--enable-tail-validation", "--no-enable-tail-validation"}:
            continue
        normalized.append(arg)
    return tuple(normalized)


def _collect_function_artifacts(
    output_dir: Path,
    *,
    validation_uncollected: bool,
) -> tuple[FunctionArtifact, ...]:
    """Parse generated C artifacts and attach quality metrics."""
    artifacts: list[FunctionArtifact] = []
    for path in sorted(output_dir.glob("*.c")):
        match = _ARTIFACT_RE.match(path.name)
        if match is None:
            continue
        address = int(match.group("address"), 16)
        name = match.group("name")
        source_text = path.read_text(encoding="utf-8")
        quality = measure_x86_16_codegen_quality_8616(
            source_text,
            function_name=name,
            function_addr=address,
            validation_uncollected=validation_uncollected,
        )
        artifacts.append(
            FunctionArtifact(
                function_addr=address,
                function_name=name,
                source_path=path,
                quality=quality,
            )
        )
    return tuple(artifacts)


def _execution_modes_are_equivalent(
    baseline_mode: DecompileMode,
    candidate_mode: DecompileMode,
    repo_root: Path,
) -> bool:
    """Return whether both requests execute the same active Python import surface."""
    if baseline_mode is candidate_mode:
        return True
    compared_modes = frozenset((baseline_mode, candidate_mode))
    if compared_modes != frozenset((DecompileMode.DEFAULT, DecompileMode.PURE_PYTHON)):
        return False
    return not _iter_repo_extension_modules(repo_root)


def _run_decompile(
    *,
    mode: DecompileMode,
    request: DecompileRunRequest,
) -> DecompileRunResult:
    """Run one decompiler mode and materialize evidence artifacts."""
    temp_dir = Path(tempfile.mkdtemp(prefix="vextest-opt-guard-", dir=str(request.output_dir_root)))
    decompiler_args = _normalize_decompiler_args(request.decompiler_args)
    run_output_dir = temp_dir / "generated_c"
    run_output_dir.mkdir(parents=True, exist_ok=True)

    command: list[str] = [
        str(request.python_executable),
        str(DECOMPILE_SCRIPT),
        str(request.binary_path),
        *decompiler_args,
        "--output-c-dir",
        str(run_output_dir),
    ]

    env = os.environ.copy()
    env["PYTHONHASHSEED"] = "0"
    env.setdefault("INERTIA_DISABLE_TIMING", "1")
    env.setdefault("INERTIA_ENABLE_TAIL_VALIDATION", "1")

    start = time.perf_counter()
    context: contextlib.AbstractContextManager[None]
    if mode is DecompileMode.PURE_PYTHON:
        context = _disable_repo_extension_modules(request.repo_root)
    else:
        context = contextlib.nullcontext()

    with context:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            env=env,
            timeout=request.timeout_seconds,
            check=False,
            cwd=str(request.repo_root),
        )
    wall_seconds = time.perf_counter() - start

    validation = _parse_validation_status(proc.stdout or "", proc.stderr or "")
    validation_uncollected = validation is ValidationStatus.UNCOLLECTED
    artifacts = _collect_function_artifacts(
        run_output_dir,
        validation_uncollected=validation_uncollected,
    )

    return DecompileRunResult(
        mode=mode,
        command=tuple(command),
        returncode=proc.returncode,
        wall_seconds=wall_seconds,
        validation=validation,
        artifacts=artifacts,
    )


_AGGREGATE_INCREASE_GATES: tuple[str, ...] = (
    "total_tmp_conditions",
    "total_raw_flag_conditions",
    "total_raw_ss_linear_exprs",
    "total_asm_fallbacks",
    "total_validation_uncollected",
)


def _process_gates_8616(
    failures: list[str],
    baseline: DecompileRunResult,
    candidate: DecompileRunResult,
) -> None:
    """Append process-outcome and validation regressions."""
    if baseline.returncode != 0:
        failures.append(f"baseline failed: returncode={baseline.returncode}")
    if candidate.returncode != 0:
        failures.append(f"candidate failed: returncode={candidate.returncode}")

    if baseline.function_count == 0:
        failures.append("baseline produced no generated functions")
    if candidate.function_count == 0:
        failures.append("candidate produced no generated functions")

    if baseline.validation is not ValidationStatus.PASSED:
        failures.append(f"baseline validation not passed: {baseline.validation.value}")
    if candidate.validation is not ValidationStatus.PASSED:
        failures.append(f"candidate validation not passed: {candidate.validation.value}")

    missing = sorted(set(baseline.function_map) - set(candidate.function_map))
    if missing:
        formatted = ", ".join(f"0x{item:x}" for item in missing)
        failures.append(f"candidate lost functions present in baseline: {formatted}")


def _aggregate_gates_8616(
    failures: list[str],
    baseline_total: dict[str, object],
    candidate_total: dict[str, object],
    aggregate_allow_increase: int,
) -> None:
    """Append aggregate-quality regressions beyond the allowed increase."""
    for key in _AGGREGATE_INCREASE_GATES:
        if _aggregate_int(candidate_total, key) > _aggregate_int(baseline_total, key) + aggregate_allow_increase:
            failures.append(
                f"candidate {key} increased "
                f"{baseline_total[key]} -> {candidate_total[key]}"
            )
    if _aggregate_float(candidate_total, "avg_quality_score") < _aggregate_float(baseline_total, "avg_quality_score") - 1e-9:
        failures.append(
            "candidate avg_quality_score decreased "
            f"{baseline_total['avg_quality_score']} -> {candidate_total['avg_quality_score']}"
        )


def _per_function_gates_8616(
    failures: list[str],
    baseline_map: dict[int, FunctionArtifact],
    candidate_map: dict[int, FunctionArtifact],
    per_function_allow_increase: int,
) -> None:
    """Append per-function bad-pattern regressions beyond the allowance."""
    for address, base_artifact in baseline_map.items():
        if address not in candidate_map:
            continue
        cand_artifact = candidate_map[address]
        base_bad = base_artifact.quality.total_bad_patterns
        cand_bad = cand_artifact.quality.total_bad_patterns
        if cand_bad > base_bad + per_function_allow_increase:
            failures.append(
                f"function 0x{address:x} quality regressed: bad_patterns {base_bad} -> {cand_bad}"
            )


def _compare_quality(
    baseline: DecompileRunResult,
    candidate: DecompileRunResult,
    *,
    per_function_allow_increase: int,
    aggregate_allow_increase: int,
) -> tuple[bool, tuple[str, ...]]:
    """Return (ok, regression_lines)."""
    failures: list[str] = []
    _process_gates_8616(failures, baseline, candidate)
    _aggregate_gates_8616(
        failures,
        baseline.quality_aggregate,
        candidate.quality_aggregate,
        aggregate_allow_increase,
    )
    _per_function_gates_8616(
        failures,
        baseline.function_map,
        candidate.function_map,
        per_function_allow_increase,
    )
    return len(failures) == 0, tuple(failures)


def _build_json_report(
    baseline: DecompileRunResult,
    candidate: DecompileRunResult,
    passed: bool,
    regressions: tuple[str, ...],
) -> dict[str, object]:
    """Return a JSON-serializable quality-gate report."""
    return {
        "passed": passed,
        "regressions": list(regressions),
        "baseline": {
            "mode": baseline.mode.value,
            "returncode": baseline.returncode,
            "wall_seconds": baseline.wall_seconds,
            "validation": baseline.validation.value,
            "function_count": baseline.function_count,
            "quality": baseline.quality_aggregate,
            "function_artifacts": [
                {
                    "function_addr": artifact.function_addr,
                    "function_name": artifact.function_name,
                    "quality": artifact.quality.to_dict(),
                }
                for artifact in baseline.artifacts
            ],
        },
        "candidate": {
            "mode": candidate.mode.value,
            "returncode": candidate.returncode,
            "wall_seconds": candidate.wall_seconds,
            "validation": candidate.validation.value,
            "function_count": candidate.function_count,
            "quality": candidate.quality_aggregate,
            "function_artifacts": [
                {
                    "function_addr": artifact.function_addr,
                    "function_name": artifact.function_name,
                    "quality": artifact.quality.to_dict(),
                }
                for artifact in candidate.artifacts
            ],
        },
    }


def _remove_tempdir(path: Path) -> None:
    """Remove helper directories without deleting tracked files."""
    if path.is_dir():
        shutil.rmtree(path, ignore_errors=True)


def _parse_args(argv: list[str] | None = None) -> tuple[argparse.Namespace, tuple[str, ...]]:
    """Parse script configuration and raw decompile args."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="Target binary to decompile")
    parser.add_argument(
        "--baseline-mode",
        type=DecompileMode,
        choices=tuple(item for item in DecompileMode),
        default=DecompileMode.PURE_PYTHON,
        help="Mode used as quality baseline (default: pure_python)",
    )
    parser.add_argument(
        "--candidate-mode",
        type=DecompileMode,
        choices=tuple(item for item in DecompileMode),
        default=DecompileMode.DEFAULT,
        help="Mode used as optimized candidate (default: default)",
    )
    parser.add_argument(
        "--python",
        type=Path,
        default=Path(sys.executable),
        help="Python executable for decompile subprocess",
    )
    parser.add_argument(
        "--mode-timeout",
        type=float,
        default=120.0,
        help="Wall-time budget per decompile mode (seconds)",
    )
    parser.add_argument(
        "--per-function-allow-increase",
        type=int,
        default=0,
        help="Permitted increase in total-bad patterns per function",
    )
    parser.add_argument(
        "--aggregate-allow-increase",
        type=int,
        default=0,
        help="Permitted increase in aggregate metric counts",
    )
    parser.add_argument(
        "--report-json",
        type=Path,
        help="Write detailed JSON report to this path",
    )
    args, decompiler_args = parser.parse_known_args(argv)

    if decompiler_args and decompiler_args[0] == "--":
        decompiler_args = decompiler_args[1:]

    if args.aggregate_allow_increase < 0:
        parser.error("--aggregate-allow-increase must be >= 0")
    if args.per_function_allow_increase < 0:
        parser.error("--per-function-allow-increase must be >= 0")

    return args, tuple(decompiler_args)


def main(argv: list[str] | None = None) -> int:
    """Compare quality between two execution modes."""
    args, decompiler_args = _parse_args(list(sys.argv[1:] if argv is None else argv))

    output_root = tempfile.mkdtemp(prefix="vextest-opt-guard-out-")
    output_root_path = Path(output_root)
    try:
        run_request = DecompileRunRequest(
            binary_path=args.binary,
            decompiler_args=decompiler_args,
            timeout_seconds=args.mode_timeout,
            output_dir_root=output_root_path,
            python_executable=args.python,
            repo_root=REPO_ROOT,
        )
        reused_execution = _execution_modes_are_equivalent(
            args.baseline_mode,
            args.candidate_mode,
            REPO_ROOT,
        )
        if reused_execution:
            execution_mode = (
                DecompileMode.DEFAULT
                if DecompileMode.DEFAULT in (args.baseline_mode, args.candidate_mode)
                else args.baseline_mode
            )
            shared_result = _run_decompile(mode=execution_mode, request=run_request)
            baseline = replace(shared_result, mode=args.baseline_mode)
            candidate = replace(shared_result, mode=args.candidate_mode)
        else:
            baseline = _run_decompile(mode=args.baseline_mode, request=run_request)
            candidate = _run_decompile(mode=args.candidate_mode, request=run_request)

        passed, regressions = _compare_quality(
            baseline,
            candidate,
            per_function_allow_increase=args.per_function_allow_increase,
            aggregate_allow_increase=args.aggregate_allow_increase,
        )

        print(f"[baseline] mode={baseline.mode.value} functions={baseline.function_count} status={baseline.validation.value} "
              f"returncode={baseline.returncode} wall_s={baseline.wall_seconds:.3f}")
        print(f"[baseline] quality={baseline.quality_aggregate}")
        print(f"[candidate] mode={candidate.mode.value} functions={candidate.function_count} status={candidate.validation.value} "
              f"returncode={candidate.returncode} wall_s={candidate.wall_seconds:.3f}")
        print(f"[candidate] quality={candidate.quality_aggregate}")
        if regressions:
            print("[gate] quality regression detected:")
            for line in regressions:
                print(f"  - {line}")
        else:
            print("[gate] quality gate passed: candidate quality is not worse than baseline")
        if reused_execution:
            print("[gate] execution modes share one active import surface; decompiled once")

        speed_delta = candidate.wall_seconds - baseline.wall_seconds
        speed_ratio = candidate.wall_seconds / baseline.wall_seconds if baseline.wall_seconds > 0 else float("inf")
        speedup = 1.0 / speed_ratio if speed_ratio > 0 and speed_ratio != float("inf") else float("nan")
        print(
            f"[metrics] wall_seconds baseline={baseline.wall_seconds:.3f} candidate={candidate.wall_seconds:.3f} "
            f"delta={speed_delta:+.3f} speedup_x={speedup:.3f}"
        )

        if args.report_json is not None:
            args.report_json.parent.mkdir(parents=True, exist_ok=True)
            args.report_json.write_text(
                json.dumps(
                    _build_json_report(
                        baseline=baseline,
                        candidate=candidate,
                        passed=passed,
                        regressions=regressions,
                    ),
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

        return 0 if passed else 1
    except subprocess.TimeoutExpired as ex:
        print(f"decompilation quality guard timed out: {ex}")
        return 2
    except (FileExistsError, OSError, ValueError) as ex:
        print(f"quality guard failed to run: {ex}")
        return 3
    finally:
        _remove_tempdir(output_root_path)


if __name__ == "__main__":
    raise SystemExit(main())
