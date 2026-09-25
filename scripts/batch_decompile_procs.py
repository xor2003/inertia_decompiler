#!/usr/bin/env python3
"""Run multiple focused decompile CLI invocations in one Python process.

Layer: Tooling/gates.
Responsibility: owns batched focused decompile subprocess orchestration.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import sys
import time
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from pathlib import Path

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


def _run_one_job(args: argparse.Namespace, job: BatchDecompileJob) -> BatchProcResult:
    """Run one focused decompile job through the public CLI and persist captured output."""

    stdout_path = args.out_dir / f"{job.name}.stdout.c"
    stderr_path = args.out_dir / f"{job.name}.stderr.txt"
    original_argv = sys.argv[:]
    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()
    start = time.perf_counter()
    try:
        sys.argv = [str(REPO_ROOT / "decompile.py"), *job.argv]
        with (
            _direct_in_process_env(job.direct_in_process),
            contextlib.redirect_stdout(stdout_buffer),
            contextlib.redirect_stderr(stderr_buffer),
        ):
            returncode = int(decompiler_cli.main(job.argv))
    except SystemExit as ex:
        code = ex.code
        returncode = int(code) if isinstance(code, int) else 1
    finally:
        elapsed = time.perf_counter() - start
        sys.argv = original_argv
    stdout_path.write_text(stdout_buffer.getvalue(), encoding="utf-8")
    stderr_path.write_text(stderr_buffer.getvalue(), encoding="utf-8")
    return BatchProcResult(
        proc=job.name,
        returncode=returncode,
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
        wall_seconds=elapsed,
        argv=job.argv,
    )


def _run_one_proc(args: argparse.Namespace, proc_name: str) -> BatchProcResult:
    """Run one legacy same-binary focused proc job."""

    return _run_one_job(
        args,
        BatchDecompileJob(
            name=proc_name,
            binary=args.binary,
            argv=_build_proc_argv(args, proc_name),
            direct_in_process=bool(args.direct_in_process),
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
        "--direct-in-process",
        action="store_true",
        help="Run direct-address focused jobs in-process instead of through the CLI fork lane.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run the requested focused proc batch and write ``batch_report.json``."""

    args = _parse_args(argv)
    if args.job_file is None and (args.binary is None or not args.proc):
        raise SystemExit("--job-file or both binary and --proc are required")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    jobs = _load_jobs(args.job_file) if args.job_file is not None else []
    results = [_run_one_job(args, job) for job in jobs] if jobs else [_run_one_proc(args, proc_name) for proc_name in args.proc]
    report = {
        "schema": "inertia.batch_decompile_procs.v1",
        "binary": str(args.binary) if args.binary is not None else None,
        "results": [asdict(result) for result in results],
    }
    (args.out_dir / "batch_report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"failed": sum(1 for item in results if item.returncode != 0), "selected": len(results)}))
    return 1 if any(result.returncode != 0 for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
