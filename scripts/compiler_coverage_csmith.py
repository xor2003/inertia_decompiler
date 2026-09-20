"""Generate reproducible, bounded candidate inputs for compiler coverage.

Layer: Test infrastructure.
Responsibility: retain Csmith source, diagnostics and generator provenance.
Generation is not compilation, behavioral acceptance or feature coverage.
"""

from __future__ import annotations

import argparse
import json
import math
import subprocess
import time
from enum import StrEnum
from pathlib import Path

from scripts.compiler_coverage_provenance import input_fingerprint
from scripts.compiler_coverage_result import CoverageOutcome
from scripts.compiler_coverage_runner import run_source_case
from scripts.msc6_memory_model import MSCMemoryModel

BOUNDED_OPTIONS = (
    "--max-funcs", "1", "--max-block-depth", "2", "--max-block-size", "2",
    "--max-expr-complexity", "3", "--max-array-dim", "1", "--max-array-len-per-dim", "4",
)


class GenerationOutcome(StrEnum):
    """Generation-only results; none imply a passing decompiler case."""

    GENERATED = "generated"
    FAILED = "generation_failed"
    TIMED_OUT = "generation_timed_out"


def generate_candidate(csmith: Path, seed: int, output: Path, *, timeout: float = 30) -> GenerationOutcome:
    """Generate one fixed-size candidate in a fresh directory with full evidence."""
    if type(seed) is not int or not 0 <= seed <= 0xFFFFFFFF:
        raise ValueError("Seed must be an unsigned 32-bit integer")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Generator timeout must be positive and finite")
    executable = csmith.resolve(strict=True)
    if not executable.is_file():
        raise ValueError("Csmith executable must be a file")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    # --output embeds its path in the source header, breaking cross-directory replay.
    command = [str(executable), "--seed", str(seed), *BOUNDED_OPTIONS]
    generator = input_fingerprint(executable)
    source = output / "csmith.c"
    outcome = GenerationOutcome.FAILED
    returncode: int | None = None
    error: str | None = None
    start = time.monotonic()
    with source.open("wb") as stdout, (output / "generator.stderr.log").open("wb") as stderr:
        try:
            process = subprocess.run(command, cwd=output, stdout=stdout, stderr=stderr,
                                     timeout=timeout, check=False)
            returncode = process.returncode
            if returncode == 0 and source.stat().st_size > 0:
                outcome = GenerationOutcome.GENERATED
        except subprocess.TimeoutExpired:
            outcome = GenerationOutcome.TIMED_OUT
        except OSError as failure:
            error = str(failure)
    report = {
        "schema": 1, "seed": seed, "command": command, "generator": generator,
        "outcome": outcome.value, "returncode": returncode, "error": error,
        "seconds": time.monotonic() - start, "timeout_seconds": timeout,
        "source": input_fingerprint(source), "roundtrip_attempted": False,
        "feature_coverage_verified": False,
    }
    (output / "generation.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return outcome


def main() -> int:
    """Expose generation separately so candidates cannot be mistaken for passes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csmith", required=True, type=Path)
    parser.add_argument("--seed", required=True, type=int)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--roundtrip", action="store_true")
    parser.add_argument("--runtime-source", type=Path)
    parser.add_argument("--runtime-build", type=Path)
    parser.add_argument("--case-timeout", type=float, default=600)
    parser.add_argument("--memory-model", type=MSCMemoryModel, choices=list(MSCMemoryModel), default=MSCMemoryModel.SMALL)
    args = parser.parse_args()
    headers: dict[str, Path] = {}
    if args.roundtrip:
        if args.runtime_source is None or args.runtime_build is None:
            parser.error("--roundtrip requires --runtime-source and --runtime-build")
        headers = {name: args.runtime_source / name for name in ("csmith.h", "CSMRT.H", "MSCPLAT.H", "MSSTDINT.H")}
        headers["SAFEMATH.H"] = args.runtime_build / "safe_math.h"
        if any(not path.is_file() for path in headers.values()):
            parser.error("Missing Csmith source/generated runtime headers")
    try:
        outcome = generate_candidate(args.csmith, args.seed, args.out_dir, timeout=args.timeout)
        if args.roundtrip and outcome is GenerationOutcome.GENERATED:
            result = run_source_case(
                args.out_dir / "csmith.c", args.out_dir / "roundtrip", timeout=args.case_timeout,
                expected_exit_code=0, runtime_headers=headers, memory_model=args.memory_model,
            )
            print(f"seed={args.seed}: {result.value}; artifacts={args.out_dir / 'roundtrip'}")
            return 0 if result is CoverageOutcome.PASSED else 1
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(f"seed={args.seed}: {outcome.value}; roundtrip=not_attempted; artifacts={args.out_dir}")
    return 0 if outcome is GenerationOutcome.GENERATED else 1


if __name__ == "__main__":
    raise SystemExit(main())
