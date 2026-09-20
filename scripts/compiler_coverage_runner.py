"""Run a selected existing MS C case through the established round-trip owner.

Layer: Test infrastructure.
Responsibility: isolate artifacts, bound the child process tree, and retain a
compact structured result. Compilation and decompilation stay in the old runner.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import TextIO

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.compiler_coverage_provenance import input_fingerprint  # noqa: E402
from scripts.compiler_coverage_result import (  # noqa: E402
    CoverageOutcome,
    classify_roundtrip_report,
    roundtrip_diagnostics,
)
from scripts.msc6_memory_model import MSCMemoryModel  # noqa: E402
from scripts.pytest_process_metrics import process_tree_pids  # noqa: E402

COMPILER_ROOT = Path("/home/xor/inertia_player/dos_compilers/Microsoft C v6ax")
KVIKDOS = Path("/home/xor/kvikdos/kvikdos")


def _kill_and_reap(process: subprocess.Popen[bytes]) -> int:
    """Stop visible descendants, including detached workers, before the root."""
    # Snapshot before killing the root: afterward detached children are reparented.
    descendants = process_tree_pids((process.pid,)) or (process.pid,)
    for pid in reversed(descendants):
        if pid != process.pid:
            with suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
    # The group may exit between the deadline and signal delivery.
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    return process.wait()


def _execute(command: list[str], log: TextIO, timeout: float) -> tuple[int, bool]:
    """Bound the child tree and also clean it up when execution is interrupted."""
    environment = dict(os.environ, PYTHON_JIT="1", PYTHONHASHSEED="0")
    process = subprocess.Popen(command, cwd=ROOT, env=environment, stdout=log, stderr=subprocess.STDOUT,
                               start_new_session=True)
    try:
        return process.wait(timeout=timeout), False
    except subprocess.TimeoutExpired:
        return _kill_and_reap(process), True
    except BaseException:
        _kill_and_reap(process)
        raise


def run_existing_case(
    case: str, output: Path, *, timeout: float = 600,
    memory_model: MSCMemoryModel = MSCMemoryModel.SMALL,
) -> CoverageOutcome:
    """Run one known fixture in a new artifact directory; never reuse stale reports."""
    source = ROOT / "examples" / "msc6_constructs" / f"{case}.c"
    if not case.isidentifier() or not source.is_file():
        raise ValueError(f"Unknown MS C fixture: {case!r}")
    return run_source_case(source, output, timeout=timeout, memory_model=memory_model)


def _validated_runtime_headers(runtime_headers: Mapping[str, Path] | None) -> dict[str, Path]:
    """Reject unsafe or ambiguous header destinations before creating artifacts."""
    headers = dict(runtime_headers or {})
    for name, path in headers.items():
        if Path(name).name != name or Path(name).suffix.lower() != ".h" or not path.is_file():
            raise ValueError(f"Invalid runtime header: {name!r}")
    if len({name.casefold() for name in headers}) != len(headers):
        raise ValueError("Runtime header names collide under DOS case folding")
    return headers


def run_source_case(
    source: Path, output: Path, *, timeout: float = 600,
    memory_model: MSCMemoryModel = MSCMemoryModel.SMALL,
    expected_exit_code: int = 255,
    runtime_headers: Mapping[str, Path] | None = None,
    signature_catalog: Path | None = None,
) -> CoverageOutcome:
    """Feed an external fixture through the same bounded legacy round-trip owner."""
    source = source.resolve(strict=True)
    case = source.stem
    if not case.isidentifier() or source.suffix != ".c" or not source.is_file():
        raise ValueError("Fixture must be a .c file with an identifier stem")
    if type(expected_exit_code) is not int or not 0 <= expected_exit_code <= 255:
        raise ValueError("Expected exit code must be an integer DOS exit status")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Case timeout must be positive and finite")
    headers = _validated_runtime_headers(runtime_headers)
    catalog = signature_catalog.resolve(strict=True) if signature_catalog is not None else None
    if catalog is not None and not catalog.is_file():
        raise ValueError("Signature catalog must be a file")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    for name, path in headers.items():
        shutil.copy2(path, output / name)
    command = [
        sys.executable, str(ROOT / "scripts" / "build_msc6_examples.py"),
        "--only-constructs", case, "--out-dir", str(output),
        "--examples-dir", str(source.parent), "--harvest-success-code", str(expected_exit_code),
        "--decompile-mode", "functions", "--decompile-max-functions", "0",
        "--decompile-timeout", "60", "--decompile-run-timeout", "600",
        "--msc6-root", str(COMPILER_ROOT), "--kvikdos", str(KVIKDOS),
        "--memory-model", memory_model.value,
    ]
    command += ["--signature-catalog", str(catalog)] if catalog is not None else []
    provenance: dict[str, object] = {"source": input_fingerprint(source), "compiler": input_fingerprint(COMPILER_ROOT),
                  "emulator": input_fingerprint(KVIKDOS), "python": input_fingerprint(Path(sys.executable)),
                  "runner": input_fingerprint(ROOT / "scripts/build_msc6_examples.py")}
    provenance["runtime_headers"] = {name: input_fingerprint(path) for name, path in headers.items()}
    provenance["signature_catalog"] = input_fingerprint(catalog) if catalog is not None else None
    start = time.monotonic()
    outcome = CoverageOutcome.HARNESS_FAILED
    returncode: int | None = None
    error: str | None = None
    with (output / "runner.log").open("w", encoding="utf-8") as log:
        try:
            returncode, timed_out = _execute(command, log, timeout)
            if timed_out:
                outcome = CoverageOutcome.TIMED_OUT
        except OSError as failure:
            error = str(failure)
            log.write(f"Harness execution failed: {error}\n")
    report = output / "report.json"
    payload: object = None
    if outcome is not CoverageOutcome.TIMED_OUT and returncode is not None:
        try:
            payload = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = None
        outcome = classify_roundtrip_report(payload, case, returncode)
    summary = {
        "schema": 1, "case": case, "outcome": outcome.value,
        "seconds": time.monotonic() - start, "returncode": returncode,
        "command": command, "report": str(report),
        "error": error,
        "diagnostics": roundtrip_diagnostics(payload),
        "inputs": provenance,
        "memory_model": memory_model.value,
        "scope": "existing_roundtrip_only_not_feature_coverage",
    }
    (output / "coverage-result.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return outcome


def main() -> int:
    """Expose selected-case execution without flooding the console with harness logs."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", required=True)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument("--memory-model", type=MSCMemoryModel, choices=list(MSCMemoryModel), default=MSCMemoryModel.SMALL)
    args = parser.parse_args()
    try:
        outcome = run_existing_case(args.case, args.out_dir, timeout=args.timeout, memory_model=args.memory_model)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(f"{args.case}: {outcome.value}; artifacts={args.out_dir}")
    return 0 if outcome is CoverageOutcome.PASSED else 1


if __name__ == "__main__":
    raise SystemExit(main())
