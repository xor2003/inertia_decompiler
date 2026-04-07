#!/usr/bin/env python3

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import io
import json
import hashlib
import logging
import multiprocessing as mp
import os
import resource
import signal
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from concurrent.futures.process import BrokenProcessPool
from pathlib import Path
from typing import TextIO

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MAX_MEMORY_MB = 1024
DEFAULT_MAX_WORKERS = max(1, (os.cpu_count() or 1) - 1)
DEFAULT_FREE_RAM_BUDGET_FRACTION = 0.45
DEFAULT_MAX_TASKS_PER_WORKER = 1
_TAIL_VALIDATION_STDERR_PREFIX = "[tail-validation] "
_TAIL_VALIDATION_METADATA_ENV = "INERTIA_TAIL_VALIDATION_STDERR_JSON"
_TAIL_VALIDATION_METADATA_PREFIX = "@@INERTIA_TAIL_VALIDATION@@ "
_TAIL_VALIDATION_BASELINE_DIR = REPO_ROOT / "angr_platforms" / ".cache" / "tail_validation_baselines"
_TAIL_VALIDATION_CONSOLE_CACHE_DIR = REPO_ROOT / "angr_platforms" / ".cache" / "decompile_cod_dir"
_TAIL_VALIDATION_DETAIL_DIR = REPO_ROOT / "angr_platforms" / ".cache" / "tail_validation_details"

sys.path.insert(0, str(REPO_ROOT / "angr_platforms"))
sys.path.insert(0, str(REPO_ROOT))

try:
    import pyvex_compat

    pyvex_compat.apply_pyvex_runtime_compatibility()
except Exception:
    pass

from angr_platforms.X86_16.corpus_scan import FunctionScanResult, extract_cod_functions, scan_function
from angr_platforms.X86_16.milestone_report import (
    cache_x86_16_tail_validation_detail_artifact,
    render_x86_16_tail_validation_console_summary,
)
from angr_platforms.X86_16.tail_validation import (
    annotate_x86_16_tail_validation_surface_with_baseline,
    build_x86_16_tail_validation_aggregate,
    build_x86_16_tail_validation_baseline,
    compare_x86_16_tail_validation_baseline,
)


_REAL_STDOUT = sys.stdout
_REAL_STDERR = sys.stderr
_THREAD_LOCAL = threading.local()


class _ThreadBoundTextIO(io.TextIOBase):
    def __init__(self, fallback: TextIO):
        self._fallback = fallback
        self._local = threading.local()

    @contextlib.contextmanager
    def target(self, stream: TextIO):
        previous = getattr(self._local, "stream", None)
        self._local.stream = stream
        try:
            yield
        finally:
            if previous is None:
                with contextlib.suppress(AttributeError):
                    delattr(self._local, "stream")
            else:
                self._local.stream = previous

    def _stream(self) -> TextIO:
        return getattr(self._local, "stream", self._fallback)

    def write(self, data: str) -> int:
        return self._stream().write(data)

    def flush(self) -> None:
        self._stream().flush()

    def isatty(self) -> bool:
        target = self._stream()
        return bool(getattr(target, "isatty", lambda: False)())

    @property
    def encoding(self):  # noqa: ANN201
        return getattr(self._stream(), "encoding", getattr(self._fallback, "encoding", "utf-8"))

    @property
    def errors(self):  # noqa: ANN201
        return getattr(self._stream(), "errors", getattr(self._fallback, "errors", "strict"))

    def __getattr__(self, item):  # noqa: ANN001
        return getattr(self._stream(), item)


class _ThreadAwareLoggingHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
        except Exception:  # pragma: no cover - defensive fallback
            return
        try:
            _THREAD_STDERR.write(f"{msg}\n")
        except Exception:  # pragma: no cover - defensive fallback
            _REAL_STDERR.write(f"{msg}\n")


_THREAD_STDOUT = _ThreadBoundTextIO(_REAL_STDOUT)
_THREAD_STDERR = _ThreadBoundTextIO(_REAL_STDERR)
sys.stdout = _THREAD_STDOUT
sys.stderr = _THREAD_STDERR

_ROOT_LOGGER = logging.getLogger()
_ROOT_LOGGER.handlers.clear()
_ROOT_LOGGER.addHandler(_ThreadAwareLoggingHandler())
_ROOT_LOGGER.setLevel(logging.WARNING)
logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)


@dataclasses.dataclass(frozen=True)
class CodWorkItem:
    cod_path: Path
    proc_name: str | None
    proc_kind: str | None
    proc_index: int
    proc_total: int
    code: bytes

    @property
    def label(self) -> str:
        if self.proc_name is None:
            return "<whole-file>"
        return f"{self.proc_name} ({self.proc_kind})"


@dataclasses.dataclass(frozen=True)
class CodWorkResult:
    cod_path: Path
    proc_name: str | None
    proc_kind: str | None
    proc_index: int
    proc_total: int
    stdout_path: Path
    stderr: str
    returncode: int | None
    child_exit_kind: str = "ok"
    child_exit_detail: str = ""
    exit_kind: str = "ok"
    exit_detail: str = ""
    scan_safe_result: FunctionScanResult | None = None
    tail_validation_records: tuple[dict[str, object], ...] = ()
    tail_validation_scanned: int = 0


def _uncollected_tail_validation_record(
    *,
    cod_path: Path,
    proc_name: str | None,
    proc_kind: str | None,
    exit_kind: str,
    exit_detail: str,
) -> dict[str, object]:
    return {
        "cod_file": cod_path.name,
        "proc_name": proc_name,
        "proc_kind": proc_kind,
        "tail_validation_uncollected": True,
        "exit_kind": exit_kind,
        "exit_detail": exit_detail,
    }


def _worker_failure_summary(item: CodWorkItem, ex: BaseException) -> str:
    if isinstance(ex, BrokenProcessPool):
        return f"parent pool breakage while recovering {item.label}"
    return f"worker failed: {type(ex).__name__}: {ex}"


def _format_worker_failure(item: CodWorkItem, ex: BaseException) -> str:
    return f"/* {_worker_failure_summary(item, ex)} */"


def _coerce_output_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _combined_output(stdout_text: str | bytes | None, stderr_text: str | bytes | None) -> str:
    stdout = _coerce_output_text(stdout_text)
    stderr = _coerce_output_text(stderr_text)
    if stdout and stderr:
        return f"{stdout}\n{stderr}"
    return stdout or stderr


def _strip_tail_validation_stderr(stderr_text: str) -> tuple[str, dict[str, object] | None]:
    if not stderr_text:
        return "", None
    kept_lines: list[str] = []
    payload: dict[str, object] | None = None
    for line in stderr_text.splitlines():
        if line.startswith(_TAIL_VALIDATION_METADATA_PREFIX):
            raw_payload = line[len(_TAIL_VALIDATION_METADATA_PREFIX) :].strip()
            try:
                decoded = json.loads(raw_payload)
            except Exception:
                continue
            if isinstance(decoded, dict):
                payload = decoded
            continue
        if line.startswith(_TAIL_VALIDATION_STDERR_PREFIX):
            continue
        kept_lines.append(line)
    cleaned = "\n".join(kept_lines)
    if stderr_text.endswith("\n") and cleaned:
        cleaned += "\n"
    return cleaned, payload


def _output_looks_like_memory_pressure(text: str) -> bool:
    lowered = text.lower()
    return any(
        token in lowered
        for token in (
            "memoryerror",
            "cannot allocate memory",
            "out of memory",
            "malloc failed",
            "bad_alloc",
            "rlimit",
            "killed",
        )
    )


def _describe_returncode(returncode: int | None, stdout_text: str, stderr_text: str, *, subprocess_timed_out: bool = False) -> tuple[str, str]:
    if subprocess_timed_out:
        return "subprocess_timeout", "worker-side subprocess timed out before the CLI returned"
    if returncode is None:
        return "unknown_exit", "child exit status unavailable"
    if returncode == 0:
        return "ok", ""

    combined = _combined_output(stdout_text, stderr_text)
    if returncode == 3 and "timed out while recovering" in combined.lower():
        return "timeout", "decompiler CLI reported a recovery timeout"
    if returncode < 0:
        signum = -returncode
        try:
            sig_name = signal.Signals(signum).name
        except ValueError:
            sig_name = f"SIG{signum}"
        if signum == signal.SIGKILL and _output_looks_like_memory_pressure(combined):
            return "rlimit_kill", f"child terminated by {sig_name} ({signum}) after memory pressure"
        return "signal_termination", f"child terminated by {sig_name} ({signum})"
    if _output_looks_like_memory_pressure(combined):
        return "rlimit_kill", f"child exited with status {returncode} after memory pressure"
    return "cli_exit", f"child exited with status {returncode}"


def _run_scan_safe_fallback(item: CodWorkItem, timeout: int) -> FunctionScanResult | None:
    if item.proc_name is None:
        return None
    try:
        return scan_function(
            item.cod_path,
            item.proc_name,
            item.proc_kind or "NEAR",
            item.code,
            timeout,
            mode="scan-safe",
        )
    except Exception:
        return None


def _describe_scan_safe_result(item: CodWorkItem, scan_result: FunctionScanResult) -> tuple[str, str]:
    if scan_result.ok and scan_result.fallback_kind not in (None, "none"):
        reason = scan_result.reason or scan_result.semantic_family_reason or "scan-safe fallback"
        return "fallback", f"scan-safe {scan_result.fallback_kind} recovery: {reason}"
    if scan_result.ok:
        return "ok", "scan-safe recovery succeeded without fallback"
    failure_class = scan_result.failure_class or "scan_safe_failure"
    reason = scan_result.reason or "scan-safe recovery failed"
    return failure_class, f"scan-safe {failure_class}: {reason}"


def _render_scan_safe_block(result: CodWorkResult, scan_result: FunctionScanResult) -> str:
    parts = [
        f"/* == scan-safe {result.proc_index}/{result.proc_total} {result.cod_path.name}",
    ]
    if result.proc_name is not None:
        parts[0] += f" :: {result.proc_name}"
        if result.proc_kind:
            parts[0] += f" [{result.proc_kind}]"
    else:
        parts[0] += " :: whole-file"
    parts[0] += " == */"
    parts.append(f"/* child exit kind: {result.child_exit_kind} */")
    if result.child_exit_detail:
        parts.append(f"/* child exit detail: {result.child_exit_detail} */")
    parts.append(f"/* scan-safe ok: {scan_result.ok} */")
    if scan_result.fallback_kind not in (None, "none"):
        parts.append(f"/* fallback kind: {scan_result.fallback_kind} */")
    if scan_result.failure_class is not None:
        parts.append(f"/* failure class: {scan_result.failure_class} */")
    if scan_result.reason is not None:
        parts.append(f"/* reason: {scan_result.reason} */")
    if scan_result.stage_reached:
        parts.append(f"/* stage reached: {scan_result.stage_reached} */")
    if scan_result.semantic_family is not None:
        parts.append(f"/* semantic family: {scan_result.semantic_family} */")
    if scan_result.semantic_family_reason is not None:
        parts.append(f"/* family reason: {scan_result.semantic_family_reason} */")
    if scan_result.confidence_scan_safe_classification is not None:
        parts.append(f"/* confidence scan-safe: {scan_result.confidence_scan_safe_classification} */")
    if scan_result.confidence_status is not None:
        parts.append(f"/* confidence status: {scan_result.confidence_status} */")
    if scan_result.confidence_assumption_kinds:
        parts.append(f"/* assumptions: {', '.join(scan_result.confidence_assumption_kinds)} */")
    if scan_result.confidence_evidence_kinds:
        parts.append(f"/* evidence: {', '.join(scan_result.confidence_evidence_kinds)} */")
    return "\n".join(parts)


@dataclasses.dataclass
class CodFileWriter:
    cod_path: Path
    out_path: Path
    proc_total: int
    next_index: int = 1
    handle: TextIO | None = None
    pending_blocks: dict[int, str] = dataclasses.field(default_factory=dict)
    failed: bool = False
    received_count: int = 0
    closed: bool = False
    reported: bool = False

    def add_block(self, proc_index: int, block: str) -> None:
        if self.closed:
            return
        self.received_count += 1
        self.pending_blocks[proc_index] = block
        self._flush_ready()

    def add_failure(self, proc_index: int, message: str) -> None:
        if self.closed:
            return
        self.received_count += 1
        self.pending_blocks[proc_index] = (
            f"/* == {proc_index}/{self.proc_total} {self.cod_path.name} "
            f":: failure == */\n{message}\n"
        ).rstrip() + "\n"
        self._flush_ready()
        self.failed = True

    def _ensure_open(self) -> None:
        if self.handle is not None:
            return
        self.handle = self.out_path.open("w", encoding="utf-8")
        self.handle.write(f"/* loading: {self.cod_path} */\n")
        self.handle.write(f"/* procedures recovered: {self.proc_total} */\n")

    def _flush_ready(self) -> None:
        if self.handle is None and self.next_index not in self.pending_blocks:
            return
        while self.next_index in self.pending_blocks:
            self._ensure_open()
            assert self.handle is not None
            self.handle.write(self.pending_blocks.pop(self.next_index))
            if not self.pending_blocks or self.next_index == self.proc_total:
                self.handle.flush()
            self.next_index += 1

    def close(self) -> None:
        if self.closed:
            return
        if self.handle is not None:
            self.handle.flush()
            self.handle.close()
            self.handle = None
        self.closed = True

    def is_complete(self) -> bool:
        return self.received_count >= self.proc_total and not self.pending_blocks and self.next_index > self.proc_total


def _iter_cod_files(root: Path):
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix.lower() == ".cod":
            yield path


def _lower_process_priority() -> None:
    try:
        os.nice(10)
    except (AttributeError, OSError):
        pass


def _apply_memory_limit(max_memory_mb: int | None) -> None:
    if max_memory_mb is None or max_memory_mb <= 0:
        return
    limit = max_memory_mb * 1024 * 1024
    try:
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    except (ValueError, OSError):
        pass


def _mem_available_mb() -> int | None:
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fp:
            for line in fp:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except OSError:
        return None
    return None


def _choose_parallelism(task_count: int, max_memory_mb: int, max_workers_cap: int) -> int:
    cpu_count = os.cpu_count() or 1
    cpu_workers = max(1, cpu_count - 1)
    if task_count <= 1:
        return 1

    worker_cap = max(1, max_workers_cap)
    if worker_cap == 1:
        return 1

    available_mb = _mem_available_mb()
    if available_mb is None:
        return min(worker_cap, cpu_workers, task_count)

    # Keep the pool under the free-RAM budget, then cap it by CPU and task count.
    # The per-worker RLIMIT_AS already keeps each worker bounded independently.
    budget_mb = int(available_mb * DEFAULT_FREE_RAM_BUDGET_FRACTION)
    worker_floor_mb = max(256, max_memory_mb if max_memory_mb > 0 else 1024)
    if budget_mb < worker_floor_mb * 2:
        return 1

    workers_by_mem = max(1, budget_mb // worker_floor_mb)
    workers = min(worker_cap, cpu_workers, task_count, workers_by_mem)
    return workers if workers > 1 else 1


def _determine_worker_memory_limit_mb(requested_max_memory_mb: int, workers: int) -> int:
    available_mb = _mem_available_mb()
    if available_mb is None:
        return requested_max_memory_mb

    total_budget_mb = max(512, int(available_mb * DEFAULT_FREE_RAM_BUDGET_FRACTION))
    per_worker_mb = max(768, total_budget_mb // max(1, workers))
    if requested_max_memory_mb > 0:
        per_worker_mb = min(per_worker_mb, requested_max_memory_mb)
    return per_worker_mb


def _worker_initializer(max_memory_mb: int) -> None:
    _lower_process_priority()
    _apply_memory_limit(max_memory_mb)


def _make_executor(max_workers: int, worker_memory_limit_mb: int) -> ProcessPoolExecutor:
    try:
        mp_context = mp.get_context("fork")
    except ValueError:
        mp_context = None
    kwargs = {
        "max_workers": max_workers,
        "initializer": _worker_initializer,
        "initargs": (worker_memory_limit_mb,),
    }
    if mp_context is not None:
        kwargs["mp_context"] = mp_context
    return ProcessPoolExecutor(**kwargs)


def _iter_task_batches(
    work_items: list[CodWorkItem], workers: int, max_tasks_per_worker: int
) -> list[list[CodWorkItem]]:
    batch_size = max(1, workers) * max(1, max_tasks_per_worker)
    return [work_items[index : index + batch_size] for index in range(0, len(work_items), batch_size)]


def _build_work_items(cod_path: Path) -> list[CodWorkItem]:
    entries = list(extract_cod_functions(cod_path))
    if not entries:
        return [CodWorkItem(cod_path=cod_path, proc_name=None, proc_kind=None, proc_index=1, proc_total=1, code=b"")]

    total = len(entries)
    return [
        CodWorkItem(
            cod_path=cod_path,
            proc_name=proc_name,
            proc_kind=proc_kind,
            proc_index=index,
            proc_total=total,
            code=code,
        )
        for index, (proc_name, proc_kind, code) in enumerate(entries, start=1)
    ]


def _bounded_child_timeout(timeout: int) -> int:
    # Keep the child process on a short leash so full-COD sweeps honor the per-proc budget.
    return max(10, min(60, timeout * 3))


def _run_work_item(item: CodWorkItem, *, timeout: int, max_memory_mb: int) -> CodWorkResult:
    stdout_fd, stdout_name = tempfile.mkstemp(
        prefix=f"{item.cod_path.stem}.{item.proc_index:04d}.",
        suffix=".dec.stdout",
        dir=item.cod_path.parent,
    )
    os.close(stdout_fd)
    stdout_path = Path(stdout_name)
    stderr_text = ""
    returncode: int | None = None
    child_exit_kind = "ok"
    child_exit_detail = ""
    exit_kind = "ok"
    exit_detail = ""
    scan_safe_result: FunctionScanResult | None = None
    tail_validation_payload: dict[str, object] | None = None
    child_timeout = _bounded_child_timeout(timeout)
    command = [
        sys.executable,
        str(REPO_ROOT / "decompile.py"),
        str(item.cod_path),
        "--timeout",
        str(timeout),
        "--max-memory-mb",
        str(max_memory_mb),
    ]
    if item.proc_name is not None:
        command.extend(["--proc", item.proc_name, "--proc-kind", item.proc_kind or "NEAR"])
    command_env = dict(os.environ)
    command_env[_TAIL_VALIDATION_METADATA_ENV] = "1"

    try:
        with stdout_path.open("w", encoding="utf-8") as stdout_file:
            completed = subprocess.run(
                command,
                cwd=str(REPO_ROOT),
                env=command_env,
                stdout=stdout_file,
                stderr=subprocess.PIPE,
                text=True,
                timeout=child_timeout,
                check=False,
            )
        returncode = int(completed.returncode)
        stderr_text = _coerce_output_text(completed.stderr)
        child_exit_kind, child_exit_detail = _describe_returncode(
            returncode,
            stdout_path.read_text(encoding="utf-8", errors="replace"),
            stderr_text,
        )
        stderr_text, tail_validation_payload = _strip_tail_validation_stderr(stderr_text)
        exit_kind, exit_detail = child_exit_kind, child_exit_detail
        if exit_kind != "ok":
            scan_safe_result = _run_scan_safe_fallback(item, timeout)
            if scan_safe_result is not None:
                exit_kind, exit_detail = _describe_scan_safe_result(item, scan_safe_result)
    except subprocess.TimeoutExpired as ex:
        returncode = None
        timeout_stdout = _coerce_output_text(ex.stdout)
        timeout_stderr = _coerce_output_text(ex.stderr)
        child_exit_kind, child_exit_detail = _describe_returncode(
            None,
            timeout_stdout,
            timeout_stderr,
            subprocess_timed_out=True,
        )
        stderr_text, tail_validation_payload = _strip_tail_validation_stderr(timeout_stderr or timeout_stdout)
        exit_kind, exit_detail = child_exit_kind, child_exit_detail
        scan_safe_result = _run_scan_safe_fallback(item, timeout)
        if scan_safe_result is not None:
            exit_kind, exit_detail = _describe_scan_safe_result(item, scan_safe_result)
    except Exception as ex:  # pragma: no cover - defensive fallback
        returncode = 99
        stderr_text = f"{type(ex).__name__}: {ex}\n"
        child_exit_kind = "worker_exception"
        child_exit_detail = f"worker-side exception: {type(ex).__name__}"
        exit_kind = child_exit_kind
        exit_detail = child_exit_detail
        tail_validation_payload = None
        scan_safe_result = _run_scan_safe_fallback(item, timeout)
        if scan_safe_result is not None:
            exit_kind, exit_detail = _describe_scan_safe_result(item, scan_safe_result)

    tail_validation_records: tuple[dict[str, object], ...] = ()
    tail_validation_scanned = 0
    if isinstance(tail_validation_payload, dict):
        raw_records = tail_validation_payload.get("records", ())
        if isinstance(raw_records, list):
            enriched_records: list[dict[str, object]] = []
            for record in raw_records:
                if not isinstance(record, dict):
                    continue
                enriched = dict(record)
                enriched.setdefault("cod_file", item.cod_path.name)
                if item.proc_name is not None:
                    enriched.setdefault("proc_name", item.proc_name)
                if item.proc_kind is not None:
                    enriched.setdefault("proc_kind", item.proc_kind)
                if "proc_name" not in enriched and isinstance(enriched.get("function_name"), str):
                    enriched["proc_name"] = enriched["function_name"]
                enriched_records.append(enriched)
            tail_validation_records = tuple(enriched_records)
        tail_validation_scanned = int(tail_validation_payload.get("scanned", 0) or 0)

    return CodWorkResult(
        cod_path=item.cod_path,
        proc_name=item.proc_name,
        proc_kind=item.proc_kind,
        proc_index=item.proc_index,
        proc_total=item.proc_total,
        stdout_path=stdout_path,
        stderr=stderr_text,
        returncode=returncode,
        child_exit_kind=child_exit_kind,
        child_exit_detail=child_exit_detail,
        exit_kind=exit_kind,
        exit_detail=exit_detail,
        scan_safe_result=scan_safe_result,
        tail_validation_records=tail_validation_records,
        tail_validation_scanned=tail_validation_scanned,
    )


def _extract_proc_body(raw_output: str) -> str:
    marker = "/* == c == */"
    idx = raw_output.rfind(marker)
    if idx == -1:
        return raw_output.strip()
    return raw_output[idx + len(marker) :].lstrip("\n").rstrip()


def _render_result_block(result: CodWorkResult) -> str:
    raw_output = result.stdout_path.read_text(encoding="utf-8", errors="replace")
    stderr_text = _coerce_output_text(result.stderr)
    if result.exit_kind == "ok":
        body = _extract_proc_body(raw_output)
        if body:
            rendered = body
        else:
            rendered = raw_output.strip()
    elif result.scan_safe_result is not None:
        rendered = _render_scan_safe_block(result, result.scan_safe_result)
    else:
        rendered = raw_output.strip()

    parts = [
        f"/* == {result.proc_index}/{result.proc_total} {result.cod_path.name}",
    ]
    if result.proc_name is not None:
        parts[0] += f" :: {result.proc_name}"
        if result.proc_kind:
            parts[0] += f" [{result.proc_kind}]"
    else:
        parts[0] += " :: whole-file"
    parts[0] += " == */"
    if result.exit_kind not in {"ok"}:
        parts.append(f"/* == exit kind {result.exit_kind} == */")
        detail = result.exit_detail or "no further detail"
        parts.append(f"/* {detail} */")
    if rendered:
        parts.append(rendered)
    if stderr_text.strip():
        parts.append(f"/* == stderr {result.cod_path.name} == */")
        parts.append(stderr_text.rstrip())
    if result.returncode not in (None, 0):
        parts.append(f"/* == exit code {result.cod_path.name} == */")
        parts.append(str(result.returncode))

    with contextlib.suppress(OSError):
        result.stdout_path.unlink()

    return "\n".join(parts).rstrip() + "\n"


def _tail_validation_corpus_label(cod_dir: Path, cod_files: list[Path] | None = None) -> str:
    corpus_files = list(cod_files or [])
    if len(corpus_files) == 1:
        return corpus_files[0].stem
    if corpus_files:
        label = "\n".join(sorted(path.name for path in corpus_files))
        digest = hashlib.sha256(label.encode("utf-8")).hexdigest()[:12]
        return f"{cod_dir.resolve().name or 'cod'}-{digest}"
    return cod_dir.resolve().name or "cod"


def _default_tail_validation_baseline_path(
    cod_dir: Path,
    *,
    timeout: int,
    cod_files: list[Path] | None = None,
) -> Path:
    corpus_name = _tail_validation_corpus_label(cod_dir, cod_files)
    return _TAIL_VALIDATION_BASELINE_DIR / f"{corpus_name}.timeout{timeout}.json"


def _default_tail_validation_console_cache_path(
    cod_dir: Path,
    *,
    timeout: int,
    cod_files: list[Path] | None = None,
) -> Path:
    corpus_name = _tail_validation_corpus_label(cod_dir, cod_files)
    return _TAIL_VALIDATION_CONSOLE_CACHE_DIR / f"{corpus_name}.timeout{timeout}.tail_validation_console.json"


def _default_tail_validation_detail_path(
    cod_dir: Path,
    *,
    timeout: int,
    cod_files: list[Path] | None = None,
) -> Path:
    corpus_name = _tail_validation_corpus_label(cod_dir, cod_files)
    return _TAIL_VALIDATION_DETAIL_DIR / f"{corpus_name}.timeout{timeout}.tail_validation_surface.json"


def _load_tail_validation_baseline(path: Path | None) -> dict[str, object] | None:
    if path is None or not path.exists():
        return None
    try:
        payload = json.loads(path.read_text())
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _write_tail_validation_baseline(path: Path, baseline: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Decompile all .COD files into sibling .dec files.")
    parser.add_argument("cod_dir", type=Path, help="Root directory containing .COD files.")
    parser.add_argument("--timeout", type=int, default=20, help="Per-procedure decompiler timeout in seconds.")
    parser.add_argument(
        "--max-memory-mb",
        type=int,
        default=DEFAULT_MAX_MEMORY_MB,
        help="Per-worker RLIMIT_AS cap in MB, also used as the parallelism memory floor.",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=DEFAULT_MAX_WORKERS,
        help="Hard cap for the worker pool. Lower this if decompilation memory grows too high.",
    )
    parser.add_argument(
        "--max-tasks-per-worker",
        type=int,
        default=DEFAULT_MAX_TASKS_PER_WORKER,
        help="Recycle the worker pool after this many procedures per worker to bound memory growth.",
    )
    parser.add_argument(
        "--subprocess-timeout",
        type=int,
        default=900,
        help="Soft wait timeout in seconds for the worker pool scheduler before outstanding work is marked failed.",
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="Skip files whose sibling .dec already exists.",
    )
    parser.add_argument(
        "--tail-validation-baseline",
        type=Path,
        default=None,
        help="Optional baseline JSON for accepted whole-tail changed verdicts. Defaults to a per-corpus cache path if present.",
    )
    parser.add_argument(
        "--write-tail-validation-baseline",
        action="store_true",
        help="Write the current whole-tail changed-set to the selected baseline path after the run.",
    )
    args = parser.parse_args()

    _lower_process_priority()
    cod_files = list(_iter_cod_files(args.cod_dir))
    print(f"found {len(cod_files)} COD files under {args.cod_dir}")

    work_items: list[CodWorkItem] = []
    items_by_file: dict[Path, list[CodWorkItem]] = {}
    for cod_path in cod_files:
        if args.skip_existing and cod_path.with_suffix(".dec").exists():
            print(f"[skip] {cod_path}")
            continue
        items = _build_work_items(cod_path)
        items_by_file[cod_path] = items
        work_items.extend(items)

    start = time.perf_counter()
    if not work_items:
        print("done in 0.0s; failures=0/0")
        return 0

    workers = _choose_parallelism(len(work_items), args.max_memory_mb, args.max_workers)
    worker_memory_limit_mb = _determine_worker_memory_limit_mb(args.max_memory_mb, workers)
    if workers <= 1:
        print(
            f"/* parallelism: single worker process, "
            f"worker-memory-limit={worker_memory_limit_mb}MB */"
        )
    else:
        available_mb = _mem_available_mb()
        budget_mb = int(available_mb * DEFAULT_FREE_RAM_BUDGET_FRACTION) if available_mb is not None else -1
        print(
            f"/* parallelism: {workers} worker processes, shared imports, n-1 CPU target, "
            f"max-workers={args.max_workers}, budget={budget_mb}MB, "
            f"worker-memory-limit={worker_memory_limit_mb}MB, "
            f"max-tasks-per-worker={args.max_tasks_per_worker}, "
            f"free-ram-fraction={DEFAULT_FREE_RAM_BUDGET_FRACTION:.2f}, "
            f"avail={available_mb if available_mb is not None else 'unknown'}MB */"
        )

    file_writers: dict[Path, CodFileWriter] = {
        cod_path: CodFileWriter(
            cod_path=cod_path,
            out_path=cod_path.with_suffix(".dec"),
            proc_total=len(items),
        )
        for cod_path, items in items_by_file.items()
    }
    failures = 0
    tail_validation_records: list[dict[str, object]] = []
    tail_validation_scanned = 0

    task_batches = _iter_task_batches(work_items, workers, args.max_tasks_per_worker)
    task_counter = 0
    for batch_index, batch in enumerate(task_batches, start=1):
        if workers > 1:
            print(f"/* batch {batch_index}/{len(task_batches)}: recycling worker pool */")
        future_map = {}
        executor = _make_executor(max(1, workers), worker_memory_limit_mb)
        try:
            for item in batch:
                task_counter += 1
                print(f"[{task_counter}/{len(work_items)}] {item.cod_path} :: {item.label}")
                future = executor.submit(
                    _run_work_item,
                    item,
                    timeout=args.timeout,
                    max_memory_mb=worker_memory_limit_mb,
                )
                future_map[future] = item

            pending = set(future_map)
            deadline = time.monotonic() + max(1, args.subprocess_timeout)
            while pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    for future in pending:
                        item = future_map[future]
                        failures += 1
                        print(f"  timeout after {args.subprocess_timeout}s: {item.cod_path} :: {item.label}")
                        writer = file_writers[item.cod_path]
                        tail_validation_records.append(
                            _uncollected_tail_validation_record(
                                cod_path=item.cod_path,
                                proc_name=item.proc_name,
                                proc_kind=item.proc_kind,
                                exit_kind="subprocess_timeout",
                                exit_detail=f"worker pool scheduler timeout after {args.subprocess_timeout}s",
                            )
                        )
                        tail_validation_scanned += 1
                        writer.add_failure(
                            item.proc_index,
                            f"/* timeout after {args.subprocess_timeout}s */",
                        )
                        if writer.is_complete():
                            writer.close()
                            writer.reported = True
                            print(f"  wrote {writer.out_path}")
                    break

                done, pending = wait(pending, timeout=min(1.0, remaining), return_when=FIRST_COMPLETED)
                for future in done:
                    item = future_map[future]
                    writer = file_writers[item.cod_path]
                    try:
                        result = future.result()
                    except Exception as ex:  # pragma: no cover - defensive fallback
                        failures += 1
                        print(f"  {_worker_failure_summary(item, ex)}: {item.cod_path} :: {item.label}")
                        tail_validation_records.append(
                            _uncollected_tail_validation_record(
                                cod_path=item.cod_path,
                                proc_name=item.proc_name,
                                proc_kind=item.proc_kind,
                                exit_kind="worker_exception",
                                exit_detail=f"{type(ex).__name__}: {ex}",
                            )
                        )
                        tail_validation_scanned += 1
                        writer.add_failure(item.proc_index, _format_worker_failure(item, ex))
                        if writer.is_complete():
                            writer.close()
                            writer.reported = True
                            print(f"  wrote {writer.out_path}")
                        continue
                    writer.add_block(item.proc_index, _render_result_block(result))
                    result_scanned = max(0, int(result.tail_validation_scanned or 0))
                    if result_scanned > 0:
                        tail_validation_records.extend(result.tail_validation_records)
                        tail_validation_scanned += result_scanned
                    else:
                        tail_validation_records.append(
                            _uncollected_tail_validation_record(
                                cod_path=result.cod_path,
                                proc_name=result.proc_name,
                                proc_kind=result.proc_kind,
                                exit_kind=result.exit_kind,
                                exit_detail=result.exit_detail,
                            )
                        )
                        tail_validation_scanned += 1
                    if result.exit_kind not in {"ok", "fallback"}:
                        failures += 1
                    print(f"  captured {item.label}")
                    if writer.is_complete():
                        writer.close()
                        writer.reported = True
                        print(f"  wrote {writer.out_path}")
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

    for cod_path, writer in file_writers.items():
        if not writer.closed:
            writer.close()
        if writer.received_count > 0 and not writer.reported and writer.out_path.exists():
            writer.reported = True
            print(f"  wrote {writer.out_path}")

    aggregate = build_x86_16_tail_validation_aggregate(tail_validation_records, scanned=tail_validation_scanned)
    baseline_path = args.tail_validation_baseline or _default_tail_validation_baseline_path(
        args.cod_dir,
        timeout=args.timeout,
        cod_files=cod_files,
    )
    baseline_payload = _load_tail_validation_baseline(baseline_path)
    comparison = compare_x86_16_tail_validation_baseline(aggregate.get("summary", {}), baseline_payload)
    surface = annotate_x86_16_tail_validation_surface_with_baseline(
        dict(aggregate.get("surface", {}) or {}),
        comparison,
    )
    console_cache_path = _default_tail_validation_console_cache_path(
        args.cod_dir,
        timeout=args.timeout,
        cod_files=cod_files,
    )
    detail_cache_path = _default_tail_validation_detail_path(
        args.cod_dir,
        timeout=args.timeout,
        cod_files=cod_files,
    )
    rendered = render_x86_16_tail_validation_console_summary(surface, cache_path=console_cache_path)
    detail_artifact = cache_x86_16_tail_validation_detail_artifact(surface, cache_path=detail_cache_path)
    for line in rendered.get("lines", ()):
        if isinstance(line, str) and line:
            print(f"{_TAIL_VALIDATION_STDERR_PREFIX}{line}")
    if surface.get("severity") != "clean":
        print(f"{_TAIL_VALIDATION_STDERR_PREFIX}detail artifact {detail_cache_path}")
        if rendered.get("cache_hit"):
            print(f"{_TAIL_VALIDATION_STDERR_PREFIX}console summary cache hit")
        if detail_artifact.get("cache_hit"):
            print(f"{_TAIL_VALIDATION_STDERR_PREFIX}detail artifact cache hit")
    if args.write_tail_validation_baseline:
        baseline = build_x86_16_tail_validation_baseline(aggregate.get("summary", {}))
        _write_tail_validation_baseline(baseline_path, baseline)
        print(f"{_TAIL_VALIDATION_STDERR_PREFIX}wrote baseline {baseline_path}")

    elapsed = time.perf_counter() - start
    print(f"done in {elapsed:.1f}s; failures={failures}/{len(work_items)}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
