#!/usr/bin/env python3
"""Run focused CLI jobs in disposable children of one warmed Python parent.

Layer: Tooling/gates.
Responsibility: owns batched focused decompile subprocess orchestration.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import logging
import os
import sys
import time
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from functools import partial
from pathlib import Path
from typing import TextIO

REPO_ROOT: Path = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from inertia_decompiler.cache_runtime_contract import cache_runtime_contract_8616  # noqa: E402


def _ensure_deterministic_python_runtime_8616() -> None:
    """Re-exec the batch entrypoint before decompiler imports with stable hashing."""
    if cache_runtime_contract_8616().allows_semantic_cache and os.environ.get("PYTHON_JIT") == "1":
        return
    env = os.environ.copy()
    env["PYTHONHASHSEED"] = "0"
    env["PYTHON_JIT"] = "1"
    executable = sys.executable
    os.execvpe(executable, [executable, str(Path(__file__).resolve()), *sys.argv[1:]], env)


if __name__ == "__main__":
    _ensure_deterministic_python_runtime_8616()

from inertia_decompiler import cli as decompiler_cli  # noqa: E402
from inertia_decompiler.cli_terminal_status import CliTerminalStatus, emit_terminal_status  # noqa: E402
from inertia_decompiler.fork_timeout import ForkChildExitError, run_with_timeout_in_fork  # noqa: E402
from scripts.compiler_coverage_cross_unit import (  # noqa: E402
    CrossUnitResult,
    CrossUnitStatus,
    check_cross_unit_c,
)
from scripts.decompile_process_budget import focused_decompile_process_timeout  # noqa: E402


@dataclass(frozen=True, slots=True)
class BatchProcResult:
    """Serializable result for one focused proc run."""

    proc: str
    returncode: int
    stdout_path: str
    stderr_path: str
    wall_seconds: float
    argv: list[str]


@dataclass(frozen=True, slots=True)
class BatchDecompileJob:
    """One focused decompile job for batch execution."""

    name: str
    binary: Path
    argv: list[str]
    direct_in_process: bool = False
    timeout: int = 60


@contextlib.contextmanager
def _direct_in_process_env(enabled: bool) -> Iterator[None]:
    """Temporarily disable direct-address fork isolation for one batch job."""

    if not enabled:
        yield
        return
    env_name = "INERTIA_OTEL_PROFILE_IN_PROCESS"
    old_value = os.environ.get(env_name)
    os.environ[env_name] = "1"
    try:
        yield
    finally:
        if old_value is None:
            os.environ.pop(env_name, None)
        else:
            os.environ[env_name] = old_value


def _build_proc_argv(args: argparse.Namespace, proc_name: str) -> list[str]:
    """Select a named procedure without enabling alternate source recovery."""

    argv = [
        "--no-alternate-source-c",
        "--timeout",
        str(args.timeout),
        "--function-discovery-backend",
        str(args.function_discovery_backend),
        "--seed-engine",
        str(args.seed_engine),
        "--rizin-timeout",
        str(args.rizin_timeout),
        "--proc",
        proc_name,
        "--proc-kind",
        str(args.proc_kind),
    ]
    if args.pat_backend is not None:
        argv.extend(["--pat-backend", str(args.pat_backend)])
    if args.signature_catalog is not None:
        argv.extend(["--signature-catalog", str(args.signature_catalog)])
    argv.append(str(args.binary))
    return argv


def _rebind_logging_streams(sources: tuple[TextIO, TextIO], targets: tuple[TextIO, TextIO]) -> None:
    """Retarget only logging handlers attached to the batch's exact console streams."""
    loggers = [logging.getLogger()]
    loggers.extend(item for item in tuple(logging.Logger.manager.loggerDict.values()) if isinstance(item, logging.Logger))
    for logger in loggers:
        for handler in logger.handlers:
            if isinstance(handler, logging.StreamHandler):
                for source, target in zip(sources, targets, strict=True):
                    if handler.stream is source:
                        handler.setStream(target)
                        break


@contextlib.contextmanager
def _job_logging_streams(stdout_file: TextIO, stderr_file: TextIO) -> Iterator[None]:
    """Route existing and lazily created console handlers without leaving closed streams."""
    previous = (sys.stdout, sys.stderr)
    current = (stdout_file, stderr_file)
    _rebind_logging_streams(previous, current)
    try:
        yield
    finally:
        _rebind_logging_streams(current, previous)


def _run_one_job(args: argparse.Namespace, job: BatchDecompileJob) -> BatchProcResult:
    """Run a focused CLI job while retaining completed output lines on interruption."""

    stdout_path = args.out_dir / f"{job.name}.stdout.c"
    stderr_path = args.out_dir / f"{job.name}.stderr.txt"
    original_argv = sys.argv[:]
    start = time.perf_counter()
    try:
        sys.argv = [str(REPO_ROOT / "decompile.py"), *job.argv]
        with (
            # Case deadlines may kill this process before the CLI returns.
            # Line buffering preserves emitted evidence without a final copy.
            stdout_path.open("w", encoding="utf-8", buffering=1) as stdout_file,
            stderr_path.open("w", encoding="utf-8", buffering=1) as stderr_file,
            _direct_in_process_env(job.direct_in_process),
            _job_logging_streams(stdout_file, stderr_file),
            contextlib.redirect_stdout(stdout_file),
            contextlib.redirect_stderr(stderr_file),
        ):
            returncode = int(decompiler_cli.main(job.argv))
    except SystemExit as ex:
        code = ex.code
        returncode = int(code) if isinstance(code, int) else 1
    finally:
        elapsed = time.perf_counter() - start
        sys.argv = original_argv
    return BatchProcResult(
        proc=job.name,
        returncode=returncode,
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
        wall_seconds=elapsed,
        argv=job.argv,
    )


def _run_isolated_job(args: argparse.Namespace, job: BatchDecompileJob) -> BatchProcResult:
    """Contain hard exits and timed-out analysis state within one disposable job."""
    start = time.perf_counter()
    timeout = focused_decompile_process_timeout(job.timeout)
    try:
        result: BatchProcResult = run_with_timeout_in_fork(partial(_run_one_job, args, job), timeout=timeout)
        return result
    except ForkChildExitError as error:
        if error.returncode == 0:
            # A clean exit without its result is transport failure, not success.
            raise
        returncode = error.returncode
        detail = str(error)
        timed_out = False
    except TimeoutError as error:
        returncode = 3
        detail = str(error)
        timed_out = True
    stderr_path = args.out_dir / f"{job.name}.stderr.txt"
    with stderr_path.open("a", encoding="utf-8") as diagnostics, contextlib.redirect_stderr(diagnostics):
        print(f"[batch-process] {detail}", file=diagnostics)
        if timed_out:
            emit_terminal_status(CliTerminalStatus.TIMEOUT)
    return BatchProcResult(
        job.name, returncode, str(args.out_dir / f"{job.name}.stdout.c"), str(stderr_path),
        time.perf_counter() - start, job.argv,
    )


def _run_one_proc(args: argparse.Namespace, proc_name: str) -> BatchProcResult:
    """Run one legacy same-binary focused proc job."""

    return _run_isolated_job(
        args,
        BatchDecompileJob(
            name=proc_name,
            binary=args.binary,
            argv=_build_proc_argv(args, proc_name),
            direct_in_process=bool(args.direct_in_process),
            timeout=args.timeout,
        ),
    )


def _job_name(raw_job: dict[str, object]) -> str:
    name = raw_job.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("batch job missing non-empty name")
    return "".join(char if char.isalnum() or char in {"_", "-", "."} else "_" for char in name.strip())


def _path_field(raw_job: dict[str, object], field_name: str) -> Path:
    value = raw_job.get(field_name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"batch job missing path field: {field_name}")
    return Path(value)


def _optional_str(raw_job: dict[str, object], field_name: str) -> str | None:
    value = raw_job.get(field_name)
    return value if isinstance(value, str) and value else None


def _optional_int(raw_job: dict[str, object], field_name: str) -> int | None:
    value = raw_job.get(field_name)
    return value if isinstance(value, int) else None


def _optional_bool(raw_job: dict[str, object], field_name: str) -> bool | None:
    value = raw_job.get(field_name)
    return value if isinstance(value, bool) else None


def _build_job_argv(raw_job: dict[str, object]) -> list[str]:
    binary = _path_field(raw_job, "binary")
    timeout = _optional_int(raw_job, "timeout") or 60
    argv: list[str] = []
    alternate_source_c = raw_job.get("alternate_source_c")
    if alternate_source_c is False:
        argv.append("--no-alternate-source-c")
    else:
        argv.append("--alternate-source-c")
    if raw_job.get("brief") is True:
        argv.append("--brief")
    argv.extend(["--timeout", str(timeout)])
    _extend_optional_flag_args(argv, raw_job)
    argv.append(str(binary))
    return argv


def _extend_optional_flag_args(argv: list[str], raw_job: dict[str, object]) -> None:
    """Append job-specific CLI flags for each populated optional field."""
    if raw_job.get("ignore_local_sidecar_hints") is True:
        argv.append("--ignore-local-sidecar-hints")
    function_discovery_backend = _optional_str(raw_job, "function_discovery_backend")
    if function_discovery_backend is not None:
        argv.extend(["--function-discovery-backend", function_discovery_backend])
    seed_engine = _optional_str(raw_job, "seed_engine")
    if seed_engine is not None:
        argv.extend(["--seed-engine", seed_engine])
    rizin_timeout = _optional_int(raw_job, "rizin_timeout")
    if rizin_timeout is not None:
        argv.extend(["--rizin-timeout", str(rizin_timeout)])
    proc = _optional_str(raw_job, "proc")
    if proc is not None:
        argv.extend(["--proc", proc, "--proc-kind", _optional_str(raw_job, "proc_kind") or "NEAR"])
    addr = _optional_int(raw_job, "addr")
    if addr is not None:
        argv.extend(["--addr", f"0x{addr:x}"])
    max_functions = _optional_int(raw_job, "max_functions")
    if max_functions is not None:
        argv.extend(["--max-functions", str(max_functions)])
    pat_backend = _optional_str(raw_job, "pat_backend")
    if pat_backend is not None:
        argv.extend(["--pat-backend", pat_backend])
    signature_catalog = _optional_str(raw_job, "signature_catalog")
    if signature_catalog is not None:
        argv.extend(["--signature-catalog", signature_catalog])


def _load_jobs(job_file: Path) -> list[BatchDecompileJob]:
    payload = json.loads(job_file.read_text(encoding="utf-8"))
    raw_jobs = payload.get("jobs") if isinstance(payload, dict) else None
    if not isinstance(raw_jobs, list):
        raise ValueError("batch job file must contain a jobs list")
    jobs: list[BatchDecompileJob] = []
    for raw_job in raw_jobs:
        if not isinstance(raw_job, dict):
            raise ValueError("batch job entries must be objects")
        jobs.append(
            BatchDecompileJob(
                name=_job_name(raw_job),
                binary=_path_field(raw_job, "binary"),
                argv=_build_job_argv(raw_job),
                direct_in_process=bool(_optional_bool(raw_job, "direct_in_process")),
                timeout=_optional_int(raw_job, "timeout") or 60,
            )
        )
    return jobs


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse batch focused-proc arguments."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, nargs="?")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--proc", action="append")
    parser.add_argument("--job-file", type=Path, default=None)
    parser.add_argument("--proc-kind", default="NEAR")
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--function-discovery-backend", default="auto")
    parser.add_argument("--seed-engine", default="auto")
    parser.add_argument("--rizin-timeout", type=int, default=8)
    parser.add_argument("--pat-backend", default=None)
    parser.add_argument("--signature-catalog", type=Path, default=None)
    parser.add_argument(
        "--check-cross-unit", action="store_true",
        help="Link generated C units with GCC LTO and reject conflicting interfaces.",
    )
    parser.add_argument(
        "--direct-in-process",
        action="store_true",
        help="Run direct-address focused jobs in-process instead of through the CLI fork lane.",
    )
    return parser.parse_args(argv)


def _write_batch_report(
    args: argparse.Namespace,
    results: list[BatchProcResult],
    cross_unit: CrossUnitResult | None = None,
) -> None:
    """Atomically checkpoint finished jobs; absent records never imply success."""
    report: dict[str, object] = {
        "schema": "inertia.batch_decompile_procs.v1",
        "binary": str(args.binary) if args.binary is not None else None,
        "results": [asdict(result) for result in results],
    }
    if cross_unit is not None:
        report["cross_unit"] = asdict(cross_unit)
    report_path = args.out_dir / "batch_report.json"
    temporary_path = args.out_dir / f".batch_report.{os.getpid()}.tmp"
    try:
        temporary_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary_path.replace(report_path)
    finally:
        temporary_path.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    """Run focused jobs, checkpointing their report before starting the next job."""

    args = _parse_args(argv)
    if args.job_file is None and (args.binary is None or not args.proc):
        raise SystemExit("--job-file or both binary and --proc are required")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    results: list[BatchProcResult] = []
    _write_batch_report(args, results)
    jobs = _load_jobs(args.job_file) if args.job_file is not None else []
    # Resolve the lazy CLI implementation once, before forking any jobs. Only
    # imports are shared: analysis and its hard exits stay in disposable children.
    _ = decompiler_cli.main
    if jobs:
        for job in jobs:
            results.append(_run_isolated_job(args, job))
            _write_batch_report(args, results)
    else:
        for proc_name in args.proc:
            results.append(_run_one_proc(args, proc_name))
            _write_batch_report(args, results)
    failed_jobs = sum(1 for item in results if item.returncode != 0)
    cross_unit: CrossUnitResult | None = None
    if args.check_cross_unit:
        sources = [Path(item.stdout_path) for item in results]
        cross_unit = (
            check_cross_unit_c(sources, args.out_dir / "batch_cross_unit.o")
            if failed_jobs == 0
            else CrossUnitResult(
                CrossUnitStatus.NOT_ATTEMPTED,
                tuple(str(source) for source in sources),
                (),
                None,
                "",
            )
        )
        _write_batch_report(args, results, cross_unit)
    cross_unit_failed = args.check_cross_unit and (
        cross_unit is None or cross_unit.status is not CrossUnitStatus.PASSED
    )
    print(json.dumps({"failed": failed_jobs, "selected": len(results),
                      "cross_unit": cross_unit.status.value if cross_unit is not None else None}))
    return 1 if failed_jobs or cross_unit_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
