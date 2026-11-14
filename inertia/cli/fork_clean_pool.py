# cython: language_level=3, infer_types=True
"""Serve clean function-worker jobs from preforked, fully-imported workers.

Layer: CLI/fallback/reporting.
Responsibility: eliminate the per-function interpreter import tax of the
clean-process lane. Each pool worker is forked once from the fully-imported
batch parent, then forks one disposable grandchild per function job, so every
function still runs in fresh process memory (identical isolation semantics to
``sys.executable -m inertia.cli.serial_clean_worker_cli``) while module
imports are paid once per pool instead of once per function.

Forbidden: owning decompiler semantics; the grandchild delegates to the same
``serial_clean_worker_cli.main`` entry point the subprocess lane executes.
"""

from __future__ import annotations

import contextlib
import faulthandler
import os
import resource
import sys
import typing
from pathlib import Path

import cython

from inertia.cli.fork_timeout import (
    ForkChildExitError as ForkChildExitError,
)
from inertia.cli.fork_timeout import (
    run_with_timeout_in_fork as run_with_timeout_in_fork,
)
from inertia.cli.prefork_job_pool import PreforkJobPool as PreforkJobPool

FORK_CLEAN_POOL_ENV_8616: str = "INERTIA_ENABLE_FORK_CLEAN_POOL"
_FORK_CLEAN_POOL_8616: PreforkJobPool | None = None
_FORK_CLEAN_POOL_FAILED_8616: cython.bint = False


@cython.ccall
def fork_clean_pool_enabled_8616() -> cython.bint:
    """Return whether the opt-in prefork clean lane is available."""
    return (
        os.name == "posix"
        and hasattr(os, "fork")
        and os.environ.get(FORK_CLEAN_POOL_ENV_8616, "").strip().lower()
        in {"1", "true", "yes", "on"}
    )


@cython.ccall
def fork_clean_pool_8616() -> PreforkJobPool | None:
    """Return the live pool, when one was created for this batch."""
    return _FORK_CLEAN_POOL_8616


@cython.ccall
def ensure_fork_clean_pool_8616(max_workers: cython.longlong) -> PreforkJobPool | None:
    """Create the pool once, on a single-threaded main thread.

    Any startup failure is recorded and reported; callers then use the
    existing per-function subprocess lane for identical isolation.
    """
    global _FORK_CLEAN_POOL_8616, _FORK_CLEAN_POOL_FAILED_8616
    if _FORK_CLEAN_POOL_8616 is not None or _FORK_CLEAN_POOL_FAILED_8616:
        return _FORK_CLEAN_POOL_8616
    if not fork_clean_pool_enabled_8616():
        _FORK_CLEAN_POOL_FAILED_8616 = True
        return None
    try:
        _FORK_CLEAN_POOL_8616 = PreforkJobPool(
            max_workers=max_workers,
            worker_func=_run_fork_clean_job_8616,
            name_prefix="func-clean-fork",
            worker_setup=_raise_soft_vsz_limit_8616,
        )
    except RuntimeError as ex:
        _FORK_CLEAN_POOL_FAILED_8616 = True
        print(
            f"[dbg] fork clean pool unavailable ({ex}); using per-function clean subprocesses",
            file=sys.stderr,
        )
        return None
    print(
        f"[dbg] fork clean pool: {_FORK_CLEAN_POOL_8616.worker_count} preforked workers",
        file=sys.stderr,
    )
    return _FORK_CLEAN_POOL_8616


@cython.ccall
def shutdown_fork_clean_pool_8616() -> None:
    """Shut the pool down and reap its workers, when one exists."""
    global _FORK_CLEAN_POOL_8616
    pool = _FORK_CLEAN_POOL_8616
    _FORK_CLEAN_POOL_8616 = None
    if pool is not None:
        pool.shutdown()


@cython.ccall
def _raise_soft_vsz_limit_8616() -> None:
    """Raise this worker's soft address-space cap to the inherited hard cap.

    Prefork workers inherit the batch parent's RLIMIT_AS soft limit while
    already mapping its whole address space; the hard cap stays as the real
    bound. Each grandchild then reapplies ``--max-memory-mb`` as a growth
    budget over its snapshot (INERTIA_MEMORY_LIMIT_RELATIVE_8616).
    """
    with contextlib.suppress(ValueError, OSError):
        _soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        resource.setrlimit(resource.RLIMIT_AS, (hard, hard))


@cython.ccall
def _rebind_child_streams_8616() -> None:
    """Rebind fd-backed sys.stdout/sys.stderr after the dup2 redirect.

    The subprocess lane always observes fd-backed streams. A forked
    grandchild inherits stream objects that may wrap stale state (capture
    buffers, the parent's log file); logging handlers bound before the fork
    hold the same stale objects, so repoint them as well.
    """
    import logging

    old_stdout = sys.stdout
    old_stderr = sys.stderr
    sys.stdout = os.fdopen(os.dup(1), "w")
    sys.stderr = os.fdopen(os.dup(2), "w")
    for logger in (logging.root, *logging.Logger.manager.loggerDict.values()):
        if not isinstance(logger, logging.Logger):
            continue
        for handler in logger.handlers:
            stream = getattr(handler, "stream", None)
            if stream is old_stderr:
                handler.setStream(sys.stderr)
            elif stream is old_stdout:
                handler.setStream(sys.stdout)


@cython.ccall
def _arm_child_stack_dump_8616() -> None:
    """Enable periodic faulthandler stacks when INERTIA_FORK_STACK_DUMP_SEC is set."""
    raw_stack_dump = os.environ.get("INERTIA_FORK_STACK_DUMP_SEC", "").strip()
    if not raw_stack_dump:
        return
    stack_dump_sec: cython.longlong
    try:
        stack_dump_sec = max(1, int(float(raw_stack_dump)))
    except ValueError:
        stack_dump_sec = 0
    if stack_dump_sec:
        fh_stream = os.fdopen(os.dup(2), "w")
        faulthandler.enable(file=fh_stream, all_threads=True)
        faulthandler.dump_traceback_later(stack_dump_sec, repeat=True, file=fh_stream)


@cython.ccall
def _fork_clean_job_child_8616(payload: dict) -> cython.longlong:
    """Run one clean worker inside this disposable grandchild.

    Reproduces the subprocess lane contract: fresh memory, worker stdout and
    stderr captured to owned files, the exact child environment applied, and
    ``sys.argv`` mirroring ``python -m inertia.cli.serial_clean_worker_cli``
    so argument-explicitness probes observe the same flags. Returns the
    worker's exit code.
    """
    err_fd = os.open(payload["stderr_path"], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    out_fd = os.open(payload["stdout_path"], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    os.dup2(err_fd, 2)
    os.dup2(out_fd, 1)
    if err_fd > 2:
        os.close(err_fd)
    if out_fd > 2:
        os.close(out_fd)
    _rebind_child_streams_8616()
    os.environ.clear()
    os.environ.update(payload["env"])
    # This grandchild already maps the prefork snapshot: --max-memory-mb must
    # bound growth over the snapshot, not absolute VSZ.
    os.environ["INERTIA_MEMORY_LIMIT_RELATIVE_8616"] = "1"
    # The architecture guard's verified-parent shortcut compares the env value
    # against getppid(); this process's parent is the pool worker, which
    # inherited the verified state from the batch parent at prefork time.
    from inertia.cli.architecture_runtime_guard import (
        ARCHITECTURE_GUARD_VERIFIED_PARENT_PID_ENV,
    )

    if os.environ.get(ARCHITECTURE_GUARD_VERIFIED_PARENT_PID_ENV) is not None:
        os.environ[ARCHITECTURE_GUARD_VERIFIED_PARENT_PID_ENV] = str(os.getppid())
    argv = list(payload["argv"])
    sys.argv = ["inertia.cli.serial_clean_worker_cli", *argv]
    _arm_child_stack_dump_8616()
    from inertia.cli.serial_clean_worker_cli import main as _worker_main

    return_code: cython.longlong
    try:
        return_code = int(_worker_main(argv))
    except SystemExit as ex:
        return_code = int(ex.code) if isinstance(ex.code, int) else (0 if ex.code is None else 1)
    sys.stdout.flush()
    sys.stderr.flush()
    return return_code


@cython.ccall
def _run_fork_clean_job_8616(payload: dict) -> dict:
    """Pool-worker entry: supervise one grandchild for one function job.

    The worker only forks and waits, so its imported module state stays the
    pristine prefork snapshot; every job sees identical clean memory.
    """
    outer_timeout: cython.longlong = max(1, int(payload["outer_timeout"]))
    try:
        return_code = run_with_timeout_in_fork(
            lambda: _fork_clean_job_child_8616(payload),
            timeout=outer_timeout,
        )
    except TimeoutError as ex:
        return {"timed_out": True, "returncode": None, "detail": str(ex)}
    except ForkChildExitError as ex:
        return {"timed_out": False, "returncode": int(ex.returncode), "detail": str(ex)}
    except Exception as ex:
        return {
            "timed_out": False,
            "returncode": 1,
            "detail": f"{type(ex).__name__}: {ex}",
        }
    return {"timed_out": False, "returncode": int(return_code), "detail": ""}


@cython.ccall
def run_fork_clean_job_8616(
    pool: PreforkJobPool,
    *,
    job_id: object,
    argv: list,
    environment: dict,
    stderr_path: Path,
    stdout_path: Path,
    outer_timeout: cython.longlong,
) -> dict:
    """Submit one clean-worker job from any dispatch thread."""
    return typing.cast(
        dict,
        pool.run_one(
            job_id,
            {
                "argv": list(argv),
                "env": dict(environment),
                "stderr_path": str(stderr_path),
                "stdout_path": str(stdout_path),
                "outer_timeout": int(outer_timeout),
            },
        ),
    )


__all__ = [
    "FORK_CLEAN_POOL_ENV_8616",
    "ensure_fork_clean_pool_8616",
    "fork_clean_pool_8616",
    "run_fork_clean_job_8616",
    "shutdown_fork_clean_pool_8616",
]
