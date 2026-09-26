#!/usr/bin/env python3
"""Parallel COD-directory decompilation runner with resource and validation reporting.

Layer: Tooling/gates.
Responsibility: run bounded COD-directory decompilation batches with validation reporting.
Diagnostic corpus scans cannot replace generated C or override its validation verdict.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import hashlib
import io
import json
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
from collections.abc import Iterator
from concurrent.futures import FIRST_COMPLETED, Future, ProcessPoolExecutor, wait
from concurrent.futures.process import BrokenProcessPool
from pathlib import Path
from typing import Any, TextIO

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
_SUCCESS_CACHE_DIR = REPO_ROOT / "angr_platforms" / ".cache" / "decompile_cod_dir_success"
_SUCCESS_CACHE_SCHEMA = 1

sys.path.insert(0, str(REPO_ROOT / "angr_platforms"))
sys.path.insert(0, str(REPO_ROOT))

_ARCHITECTURE_GUARD_RAN = False


def _run_runtime_architecture_guard() -> int:
    global _ARCHITECTURE_GUARD_RAN
    if _ARCHITECTURE_GUARD_RAN:
        return 0
    from inertia_decompiler.architecture_runtime_guard import (
        DecompilerArchitectureGuardError,
        assert_decompiler_architecture_clean,
    )

    try:
        assert_decompiler_architecture_clean()
    except DecompilerArchitectureGuardError as ex:
        print(str(ex), file=sys.stderr)
        return 3
    _ARCHITECTURE_GUARD_RAN = True
    return 0


if __name__ == "__main__":
    _guard_exit = _run_runtime_architecture_guard()
    if _guard_exit:
        raise SystemExit(_guard_exit)

try:
    import pyvex_compat

    pyvex_compat.apply_pyvex_runtime_compatibility()
except Exception:
    pass

from angr_platforms.X86_16.corpus_scan import FunctionScanResult, extract_cod_functions, scan_function
from angr_platforms.X86_16.tail_validation import (
    annotate_x86_16_tail_validation_surface_with_baseline,
    build_x86_16_tail_validation_aggregate,
    build_x86_16_tail_validation_baseline,
    compare_x86_16_tail_validation_baseline,
)

from inertia_decompiler.cache import DECOMPILATION_CACHE_SOURCE_FILES, _cache_source_digest
from inertia_decompiler.tail_validation import emit_tail_validation_surface_summary

_REAL_STDOUT = sys.stdout
_REAL_STDERR = sys.stderr
_THREAD_LOCAL = threading.local()


class _ThreadBoundTextIO(io.TextIOBase):
    def __init__(self, fallback: TextIO):
        self._fallback = fallback
        self._local = threading.local()

    @contextlib.contextmanager
    def target(self, stream: TextIO) -> Iterator[None]:
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
        """Flush the active thread-local stream when it is still open."""

        stream = self._stream()
        with contextlib.suppress(ValueError):
            stream.flush()

    def isatty(self) -> bool:
        target = self._stream()
        return bool(getattr(target, "isatty", lambda: False)())

    @property
    def encoding(self) -> str:  # type: ignore[override]
        return getattr(self._stream(), "encoding", getattr(self._fallback, "encoding", "utf-8"))

    @property
    def errors(self) -> str:  # type: ignore[override]
        return getattr(self._stream(), "errors", getattr(self._fallback, "errors", "strict"))

    def __getattr__(self, item: str) -> Any:
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
    from_cache: bool = False


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


def _normalize_tail_validation_record(
    record: dict[str, object],
    *,
    cod_path: Path,
    proc_name: str | None,
    proc_kind: str | None,
) -> dict[str, object]:
    normalized = dict(record)
    if not normalized.get("cod_file"):
        normalized["cod_file"] = cod_path.name
    if proc_name is not None and not normalized.get("proc_name"):
        normalized["proc_name"] = proc_name
    if proc_kind is not None and not normalized.get("proc_kind"):
        normalized["proc_kind"] = proc_kind
    if not normalized.get("proc_name") and isinstance(normalized.get("function_name"), str):
        normalized["proc_name"] = normalized["function_name"]
    return normalized


def _append_uncollected_tail_validation_record(
    records: list[dict[str, object]],
    *,
    cod_path: Path,
    proc_name: str | None,
    proc_kind: str | None,
    exit_kind: str,
    exit_detail: str,
) -> int:
    records.append(
        _uncollected_tail_validation_record(
            cod_path=cod_path,
            proc_name=proc_name,
            proc_kind=proc_kind,
            exit_kind=exit_kind,
            exit_detail=exit_detail,
        )
    )
    return 1


def _append_tail_validation_records_for_result(
    records: list[dict[str, object]],
    result: CodWorkResult,
) -> int:
    result_records = tuple(
        _normalize_tail_validation_record(
            record,
            cod_path=result.cod_path,
            proc_name=result.proc_name,
            proc_kind=result.proc_kind,
        )
        for record in result.tail_validation_records
        if isinstance(record, dict)
    )
    result_scanned = max(0, int(result.tail_validation_scanned or 0))
    if result_records:
        records.extend(result_records)
        missing = max(0, result_scanned - len(result_records))
        for _ in range(missing):
            _append_uncollected_tail_validation_record(
                records,
                cod_path=result.cod_path,
                proc_name=result.proc_name,
                proc_kind=result.proc_kind,
                exit_kind=result.exit_kind,
                exit_detail=result.exit_detail or "tail validation metadata omitted record details",
            )
        return max(result_scanned, len(result_records))

    _append_uncollected_tail_validation_record(
        records,
        cod_path=result.cod_path,
        proc_name=result.proc_name,
        proc_kind=result.proc_kind,
        exit_kind=result.exit_kind,
        exit_detail=result.exit_detail or "tail validation metadata omitted record details",
    )
    return max(1, result_scanned)


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


def _success_cache_key(item: CodWorkItem, *, timeout: int, max_memory_mb: int) -> dict[str, object] | None:
    try:
        stat = item.cod_path.resolve().stat()
    except OSError:
        return None
    return {
        "schema": _SUCCESS_CACHE_SCHEMA,
        "kind": "decompile_cod_dir_success",
        "cod_path": str(item.cod_path.resolve()),
        "cod_size": stat.st_size,
        "cod_mtime_ns": stat.st_mtime_ns,
        "proc_name": item.proc_name,
        "proc_kind": item.proc_kind,
        "proc_index": item.proc_index,
        "proc_total": item.proc_total,
        "code_sha256": hashlib.sha256(item.code).hexdigest(),
        "timeout": timeout,
        "max_memory_mb": max_memory_mb,
        "components": _cache_source_digest(DECOMPILATION_CACHE_SOURCE_FILES),
    }


def _success_cache_path(key: dict[str, object]) -> Path:
    encoded = json.dumps(key, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _SUCCESS_CACHE_DIR / f"{hashlib.sha256(encoded).hexdigest()}.json"


def _write_temp_stdout_for_result(
    item: CodWorkItem,
    stdout_text: str,
    *,
    suffix: str = ".dec.stdout",
    directory: Path | None = None,
) -> Path:
    output_dir = directory or item.cod_path.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    stdout_fd, stdout_name = tempfile.mkstemp(
        prefix=f"{item.cod_path.stem}.{item.proc_index:04d}.",
        suffix=suffix,
        dir=output_dir,
    )
    os.close(stdout_fd)
    stdout_path = Path(stdout_name)
    stdout_path.write_text(stdout_text, encoding="utf-8")
    return stdout_path


def _stdout_is_cacheable_success(stdout_text: str) -> bool:
    if "/* == c == */" not in stdout_text:
        return False
    lowered = stdout_text.lower()
    forbidden_markers = (
        "fallback",
        "function recovery timed out",
        "falling back",
        "scan-safe",
    )
    return not any(marker in lowered for marker in forbidden_markers)


def _load_success_cache(item: CodWorkItem, *, timeout: int, max_memory_mb: int) -> CodWorkResult | None:
    def _impl() -> CodWorkResult | None:
        key = _success_cache_key(item, timeout=timeout, max_memory_mb=max_memory_mb)
        if key is None:
            return None
        try:
            payload = json.loads(_success_cache_path(key).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict) or payload.get("status") != "ok":
            return None
        stdout_text = payload.get("stdout")
        if not isinstance(stdout_text, str):
            return None
        raw_records = payload.get("tail_validation_records", ())
        records: tuple[dict[str, object], ...] = ()
        if isinstance(raw_records, list):
            records = tuple(dict(record) for record in raw_records if isinstance(record, dict))
        scanned = payload.get("tail_validation_scanned", 0)
        if not isinstance(scanned, int):
            scanned = 0
        stdout_path = _write_temp_stdout_for_result(
            item,
            stdout_text,
            suffix=".cached.dec.stdout",
            directory=_SUCCESS_CACHE_DIR,
        )
        return CodWorkResult(
            cod_path=item.cod_path,
            proc_name=item.proc_name,
            proc_kind=item.proc_kind,
            proc_index=item.proc_index,
            proc_total=item.proc_total,
            stdout_path=stdout_path,
            stderr=_coerce_output_text(payload.get("stderr") if isinstance(payload.get("stderr"), str) else ""),
            returncode=0,
            tail_validation_records=records,
            tail_validation_scanned=scanned,
            from_cache=True,
        )

    return _impl()


def _store_success_cache(
    item: CodWorkItem,
    result: CodWorkResult,
    *,
    timeout: int,
    max_memory_mb: int,
) -> None:
    if result.exit_kind != "ok" or result.returncode not in (0, None) or result.scan_safe_result is not None:
        return
    key = _success_cache_key(item, timeout=timeout, max_memory_mb=max_memory_mb)
    if key is None:
        return
    try:
        stdout_text = result.stdout_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    if not _stdout_is_cacheable_success(_combined_output(stdout_text, result.stderr)):
        return
    payload = {
        "schema": _SUCCESS_CACHE_SCHEMA,
        "status": "ok",
        "stdout": stdout_text,
        "stderr": result.stderr,
        "tail_validation_records": list(result.tail_validation_records),
        "tail_validation_scanned": int(result.tail_validation_scanned or 0),
    }
    try:
        path = _success_cache_path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    except OSError:
        return


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


def _describe_returncode(
    returncode: int | None, stdout_text: str, stderr_text: str, *, subprocess_timed_out: bool = False
) -> tuple[str, str]:
    def _impl() -> tuple[str, str]:
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

    return _impl()


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


def _should_run_scan_safe_fallback(exit_kind: str, item: CodWorkItem) -> bool:
    # Keep worker-side scheduler timeouts attributable.
    if exit_kind == "subprocess_timeout":
        return False
    # For timeout exits, run scan-safe fallback only for one-off targets
    # (single proc investigations). In batch sweeps, preserve timeout
    # attribution and avoid extra runner-side work.
    if exit_kind == "timeout":
        return int(getattr(item, "proc_total", 0) or 0) <= 1
    return True


def _render_scan_safe_block(result: CodWorkResult, scan_result: FunctionScanResult) -> str:
    def _impl() -> str:
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
        parts.extend(_scan_result_field_lines(scan_result))
        return "\n".join(parts)

    return _impl()


def _scan_result_field_lines(scan_result: FunctionScanResult) -> list[str]:
    """Render the optional scan-result fields as comment lines."""
    parts: list[str] = []
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
    parts.extend(_scan_result_confidence_lines(scan_result))
    return parts


def _scan_result_confidence_lines(scan_result: FunctionScanResult) -> list[str]:
    """Render the confidence-related scan-result fields as comment lines."""
    parts: list[str] = []
    if scan_result.confidence_scan_safe_classification is not None:
        parts.append(f"/* confidence scan-safe: {scan_result.confidence_scan_safe_classification} */")
    if scan_result.confidence_status is not None:
        parts.append(f"/* confidence status: {scan_result.confidence_status} */")
    if scan_result.confidence_assumption_kinds:
        parts.append(f"/* assumptions: {', '.join(scan_result.confidence_assumption_kinds)} */")
    if scan_result.confidence_evidence_kinds:
        parts.append(f"/* evidence: {', '.join(scan_result.confidence_evidence_kinds)} */")
    return parts


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
            f"/* == {proc_index}/{self.proc_total} {self.cod_path.name} :: failure == */\n{message}\n"
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


def _iter_cod_files(root: Path) -> Iterator[Path]:
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix.lower() == ".cod":
            yield path


def _resolve_selected_cod_files(cod_dir: Path, selectors: list[str] | None) -> list[Path]:
    def _impl() -> list[Path]:
        all_files = list(_iter_cod_files(cod_dir))
        if not selectors:
            return all_files

        selected: dict[Path, Path] = {}
        rel_names = {path.relative_to(cod_dir).as_posix().lower(): path for path in all_files}
        base_names: dict[str, list[Path]] = {}
        for path in all_files:
            base_names.setdefault(path.name.lower(), []).append(path)

        for selector in selectors:
            matches = _selector_matches(selector, cod_dir, rel_names, base_names)
            if not matches:
                raise ValueError(f"COD file selector matched nothing: {selector}")
            for match in matches:
                selected[match.resolve()] = match

        return sorted(selected.values())

    return _impl()


def _selector_matches(
    selector: str,
    cod_dir: Path,
    rel_names: dict[str, Path],
    base_names: dict[str, list[Path]],
) -> list[Path]:
    """Return all COD files matched by one selector token."""
    wanted = Path(selector)
    matches: list[Path] = []
    if wanted.is_absolute():
        if wanted.is_file() and wanted.suffix.lower() == ".cod":
            matches.append(wanted)
        return matches
    direct = cod_dir / wanted
    if direct.is_file() and direct.suffix.lower() == ".cod":
        matches.append(direct)
    matches.extend(base_names.get(selector.lower(), ()))
    rel_match = rel_names.get(selector.lower())
    if rel_match is not None:
        matches.append(rel_match)
    return matches


def _filter_work_items_by_proc_names(
    items: list[CodWorkItem],
    proc_names: list[str] | None,
) -> list[CodWorkItem]:
    if not proc_names:
        return items

    requested = set(proc_names)
    requested_lower = {name.lower() for name in requested}
    filtered = [
        item
        for item in items
        if item.proc_name is not None and (item.proc_name in requested or item.proc_name.lower() in requested_lower)
    ]
    total = len(filtered)
    return [
        dataclasses.replace(item, proc_index=index, proc_total=total) for index, item in enumerate(filtered, start=1)
    ]


def _lower_process_priority() -> None:
    with contextlib.suppress(AttributeError, OSError):
        os.nice(10)


def _apply_memory_limit(max_memory_mb: int | None) -> None:
    if max_memory_mb is None or max_memory_mb <= 0:
        return
    limit = max_memory_mb * 1024 * 1024
    with contextlib.suppress(ValueError, OSError):
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))


def _mem_available_mb() -> int | None:
    try:
        with open("/proc/meminfo", encoding="utf-8") as fp:
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
    if mp_context is None:
        return ProcessPoolExecutor(
            max_workers=max_workers,
            initializer=_worker_initializer,
            initargs=(worker_memory_limit_mb,),
        )
    return ProcessPoolExecutor(
        max_workers=max_workers,
        mp_context=mp_context,
        initializer=_worker_initializer,
        initargs=(worker_memory_limit_mb,),
    )


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


def _run_decompiler_child(
    command: list[str],
    *,
    command_env: dict[str, str],
    stdout_path: Path,
    child_timeout: int,
) -> tuple[int | None, str, bool]:
    start_new_session = os.name == "posix"
    with stdout_path.open("w", encoding="utf-8") as stdout_file:
        try:
            completed = subprocess.run(
                command,
                cwd=str(REPO_ROOT),
                env=command_env,
                stdout=stdout_file,
                stderr=subprocess.PIPE,
                text=True,
                timeout=child_timeout,
                check=False,
                start_new_session=start_new_session,
            )
            return int(completed.returncode), _coerce_output_text(completed.stderr), False
        except subprocess.TimeoutExpired as ex:
            return None, _coerce_output_text(ex.stderr), True


def _run_work_item(item: CodWorkItem, *, timeout: int, max_memory_mb: int) -> CodWorkResult:
    """Capture the child artifact and verdict, retaining scans only as diagnostics."""
    def _impl() -> CodWorkResult:
        cached_result = _load_success_cache(item, timeout=timeout, max_memory_mb=max_memory_mb)
        if cached_result is not None:
            return cached_result

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
            returncode, stderr_text, child_timed_out = _run_decompiler_child(
                command,
                command_env=command_env,
                stdout_path=stdout_path,
                child_timeout=child_timeout,
            )
            child_exit_kind, child_exit_detail = _describe_returncode(
                returncode,
                stdout_path.read_text(encoding="utf-8", errors="replace"),
                stderr_text,
                subprocess_timed_out=child_timed_out,
            )
            stderr_text, tail_validation_payload = _strip_tail_validation_stderr(stderr_text)
            exit_kind, exit_detail = child_exit_kind, child_exit_detail
            if exit_kind != "ok" and _should_run_scan_safe_fallback(exit_kind, item):
                # Scans provide diagnostics, not replacement C. The emitted
                # child's status and tail-validation evidence remain authoritative.
                scan_safe_result = _run_scan_safe_fallback(item, timeout)
        except Exception as ex:  # pragma: no cover - defensive fallback
            returncode = 99
            stderr_text = f"{type(ex).__name__}: {ex}\n"
            child_exit_kind = "worker_exception"
            child_exit_detail = f"worker-side exception: {type(ex).__name__}"
            exit_kind = child_exit_kind
            exit_detail = child_exit_detail
            tail_validation_payload = None
            scan_safe_result = _run_scan_safe_fallback(item, timeout)

        tail_validation_records: tuple[dict[str, object], ...] = ()
        tail_validation_scanned = 0
        if isinstance(tail_validation_payload, dict):
            raw_records = tail_validation_payload.get("records", ())
            if isinstance(raw_records, list):
                enriched_records: list[dict[str, object]] = []
                for record in raw_records:
                    if not isinstance(record, dict):
                        continue
                    enriched_records.append(
                        _normalize_tail_validation_record(
                            record,
                            cod_path=item.cod_path,
                            proc_name=item.proc_name,
                            proc_kind=item.proc_kind,
                        )
                    )
                tail_validation_records = tuple(enriched_records)
            raw_scanned = tail_validation_payload.get("scanned", 0)
            tail_validation_scanned = raw_scanned if isinstance(raw_scanned, int) else 0

        result = CodWorkResult(
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
        _store_success_cache(item, result, timeout=timeout, max_memory_mb=max_memory_mb)
        return result

    return _impl()


def _extract_proc_body(raw_output: str) -> str:
    marker = "/* == c == */"
    idx = raw_output.rfind(marker)
    body = raw_output.strip() if idx == -1 else raw_output[idx + len(marker):].lstrip("\n").rstrip()
    return _strip_nonsemantic_fallback_markers(body)


def _strip_nonsemantic_fallback_markers(body: str) -> str:
    if not body:
        return body
    filtered_lines = [
        line
        for line in body.splitlines()
        if line.strip()
        not in {
            "/* == c (string intrinsic fallback) == */",
            "/* -- c (string intrinsic fallback) -- */",
        }
    ]
    return "\n".join(filtered_lines).rstrip()


def _render_result_block(result: CodWorkResult) -> str:
    """Render the child artifact and keep secondary scans diagnostic-only."""
    def _impl() -> str:
        raw_output = result.stdout_path.read_text(encoding="utf-8", errors="replace")
        stderr_text = _coerce_output_text(result.stderr)
        if result.exit_kind == "ok":
            body = _extract_proc_body(raw_output)
            rendered = body or raw_output.strip()
        else:
            rendered = raw_output.strip()
        if result.scan_safe_result is not None:
            rendered += "\n" + _render_scan_safe_block(result, result.scan_safe_result)

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
        parts.append(
            f"/* == end {result.proc_index}/{result.proc_total} {result.cod_path.name}"
            + (
                f" :: {result.proc_name}" + (f" [{result.proc_kind}]" if result.proc_kind else "")
                if result.proc_name is not None
                else " :: whole-file"
            )
            + " == */"
        )
        if stderr_text.strip():
            parts.append(f"/* == stderr {result.cod_path.name} == */")
            parts.append(stderr_text.rstrip())
        if result.returncode not in (None, 0):
            parts.append(f"/* == exit code {result.cod_path.name} == */")
            parts.append(str(result.returncode))

        with contextlib.suppress(OSError):
            result.stdout_path.unlink()

        return "\n".join(parts).rstrip() + "\n"

    return _impl()


def _cache_label_part(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value).strip(".-")
    if not cleaned:
        cleaned = "selection"
    if len(cleaned) <= 80:
        return cleaned
    digest = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()[:12]
    return f"{cleaned[:60]}-{digest}"


def _tail_validation_corpus_label(
    cod_dir: Path,
    cod_files: list[Path] | None = None,
    proc_names: list[str] | None = None,
) -> str:
    corpus_files = list(cod_files or [])
    if len(corpus_files) == 1:
        label = corpus_files[0].stem
    elif corpus_files:
        label = "\n".join(sorted(path.name for path in corpus_files))
        digest = hashlib.sha256(label.encode("utf-8")).hexdigest()[:12]
        label = f"{cod_dir.resolve().name or 'cod'}-{digest}"
    else:
        label = cod_dir.resolve().name or "cod"
    if proc_names:
        proc_label = "\n".join(sorted(set(proc_names), key=str.lower))
        if len(set(proc_names)) == 1:
            proc_suffix = _cache_label_part(next(iter(set(proc_names))))
        else:
            proc_suffix = hashlib.sha256(proc_label.encode("utf-8")).hexdigest()[:12]
        label = f"{label}-{proc_suffix}"
    return _cache_label_part(label)


def _default_tail_validation_baseline_path(
    cod_dir: Path,
    *,
    timeout: int,
    cod_files: list[Path] | None = None,
    proc_names: list[str] | None = None,
) -> Path:
    corpus_name = _tail_validation_corpus_label(cod_dir, cod_files, proc_names)
    return _TAIL_VALIDATION_BASELINE_DIR / f"{corpus_name}.timeout{timeout}.json"


def _default_tail_validation_console_cache_path(
    cod_dir: Path,
    *,
    timeout: int,
    cod_files: list[Path] | None = None,
    proc_names: list[str] | None = None,
) -> Path:
    corpus_name = _tail_validation_corpus_label(cod_dir, cod_files, proc_names)
    return _TAIL_VALIDATION_CONSOLE_CACHE_DIR / f"{corpus_name}.timeout{timeout}.tail_validation_console.json"


def _default_tail_validation_detail_path(
    cod_dir: Path,
    *,
    timeout: int,
    cod_files: list[Path] | None = None,
    proc_names: list[str] | None = None,
) -> Path:
    corpus_name = _tail_validation_corpus_label(cod_dir, cod_files, proc_names)
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


def _build_arg_parser() -> argparse.ArgumentParser:
    """Build the decompile-cod-dir CLI argument parser."""
    parser = argparse.ArgumentParser(description="Decompile all .COD files into sibling .dec files.")
    parser.add_argument("cod_dir", type=Path, help="Root directory containing .COD files.")
    parser.add_argument(
        "--cod-file",
        action="append",
        default=None,
        help=(
            "Limit the run to one COD file. Can be repeated. "
            "Accepts a basename, a path relative to cod_dir, or an absolute path."
        ),
    )
    parser.add_argument(
        "--proc-name",
        action="append",
        default=None,
        help="Limit the run to one PROC name. Can be repeated. Matching is case-insensitive.",
    )
    parser.add_argument("--timeout", type=int, default=60, help="Per-procedure decompiler timeout in seconds.")
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
    return parser


def _collect_work_items(
    cod_files: list[Path], args: argparse.Namespace
) -> tuple[list[CodWorkItem], dict[Path, list[CodWorkItem]]]:
    """Build the selected per-file work-item lists, honoring skip filters."""
    work_items: list[CodWorkItem] = []
    items_by_file: dict[Path, list[CodWorkItem]] = {}
    for cod_path in cod_files:
        if args.skip_existing and cod_path.with_suffix(".dec").exists():
            print(f"[skip] {cod_path}")
            continue
        items = _filter_work_items_by_proc_names(_build_work_items(cod_path), args.proc_name)
        if args.proc_name and not items:
            print(f"[skip] {cod_path}: no selected PROC matched")
            continue
        items_by_file[cod_path] = items
        work_items.extend(items)
    return work_items, items_by_file


def _print_parallelism_banner(workers: int, args: argparse.Namespace, worker_memory_limit_mb: int) -> None:
    """Print the selected worker-pool configuration line."""
    if workers <= 1:
        print(f"/* parallelism: single worker process, worker-memory-limit={worker_memory_limit_mb}MB */")
        return
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


@dataclasses.dataclass
class _RunAccumulator:
    """Shared counters, writers, and tail-validation records for the run."""

    file_writers: dict[Path, CodFileWriter]
    tail_validation_records: list[dict[str, object]]
    failures: int = 0
    tail_validation_scanned: int = 0

    def handle_result(self, item: CodWorkItem, result: CodWorkResult) -> None:
        """Record one completed work item."""
        writer = self.file_writers[item.cod_path]
        writer.add_block(item.proc_index, _render_result_block(result))
        self.tail_validation_scanned += _append_tail_validation_records_for_result(
            self.tail_validation_records,
            result,
        )
        if result.exit_kind not in {"ok", "fallback"}:
            self.failures += 1
        source = "cache" if result.from_cache else "child"
        print(f"  captured {item.label} ({source})")
        if writer.is_complete():
            writer.close()
            writer.reported = True
            print(f"  wrote {writer.out_path}")

    def handle_failure(self, item: CodWorkItem, ex: BaseException) -> None:
        """Record one work item that raised in the worker."""
        self.failures += 1
        print(f"  {_worker_failure_summary(item, ex)}: {item.cod_path} :: {item.label}")
        self.tail_validation_scanned += _append_uncollected_tail_validation_record(
            self.tail_validation_records,
            cod_path=item.cod_path,
            proc_name=item.proc_name,
            proc_kind=item.proc_kind,
            exit_kind="worker_exception",
            exit_detail=f"{type(ex).__name__}: {ex}",
        )
        writer = self.file_writers[item.cod_path]
        writer.add_failure(item.proc_index, _format_worker_failure(item, ex))
        if writer.is_complete():
            writer.close()
            writer.reported = True
            print(f"  wrote {writer.out_path}")

    def handle_scheduler_timeout(self, item: CodWorkItem, subprocess_timeout: int) -> None:
        """Record one work item dropped by the pool scheduler deadline."""
        self.failures += 1
        print(f"  timeout after {subprocess_timeout}s: {item.cod_path} :: {item.label}")
        writer = self.file_writers[item.cod_path]
        self.tail_validation_scanned += _append_uncollected_tail_validation_record(
            self.tail_validation_records,
            cod_path=item.cod_path,
            proc_name=item.proc_name,
            proc_kind=item.proc_kind,
            exit_kind="subprocess_timeout",
            exit_detail=f"worker pool scheduler timeout after {subprocess_timeout}s",
        )
        writer.add_failure(
            item.proc_index,
            f"/* timeout after {subprocess_timeout}s */",
        )
        if writer.is_complete():
            writer.close()
            writer.reported = True
            print(f"  wrote {writer.out_path}")


def _run_single_worker_lane(
    work_items: list[CodWorkItem], state: _RunAccumulator, args: argparse.Namespace, worker_memory_limit_mb: int
) -> None:
    """Run all work items inline when parallelism is disabled."""
    # Avoid wrapping the CLI child in a memory-limited forked worker.  The CLI
    # applies its own limit after imports; inheriting RLIMIT_AS before Python
    # startup changes COD fallback behavior and can turn clean direct runs into
    # timeouts.
    for task_counter, item in enumerate(work_items, start=1):
        print(f"[{task_counter}/{len(work_items)}] {item.cod_path} :: {item.label}")
        cached_result = _load_success_cache(item, timeout=args.timeout, max_memory_mb=worker_memory_limit_mb)
        if cached_result is not None:
            state.handle_result(item, cached_result)
            continue
        try:
            result = _run_work_item(item, timeout=args.timeout, max_memory_mb=worker_memory_limit_mb)
        except Exception as ex:  # pragma: no cover - defensive fallback
            state.handle_failure(item, ex)
            continue
        state.handle_result(item, result)


def _drain_batch_futures(
    future_map: dict[Future[CodWorkResult], CodWorkItem],
    state: _RunAccumulator,
    args: argparse.Namespace,
) -> bool:
    """Drain submitted futures until done or the scheduler deadline; return True on timeout."""
    pending = set(future_map)
    deadline = time.monotonic() + max(1, args.subprocess_timeout)
    while pending:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            for future in pending:
                state.handle_scheduler_timeout(future_map[future], args.subprocess_timeout)
            return True
        done, pending = wait(pending, timeout=min(1.0, remaining), return_when=FIRST_COMPLETED)
        for future in done:
            item = future_map[future]
            try:
                result = future.result()
            except Exception as ex:  # pragma: no cover - defensive fallback
                state.handle_failure(item, ex)
                continue
            state.handle_result(item, result)
    return False


def _run_task_batches(
    task_batches: list[list[CodWorkItem]],
    work_items: list[CodWorkItem],
    state: _RunAccumulator,
    args: argparse.Namespace,
    workers: int,
    worker_memory_limit_mb: int,
) -> None:
    """Run work items through the recycling worker-pool scheduler."""
    task_counter = 0
    for batch_index, batch in enumerate(task_batches, start=1):
        print(f"/* batch {batch_index}/{len(task_batches)}: recycling worker pool */")
        future_map: dict[Future[CodWorkResult], CodWorkItem] = {}
        executor = None
        scheduler_timed_out = False
        try:
            for item in batch:
                task_counter += 1
                print(f"[{task_counter}/{len(work_items)}] {item.cod_path} :: {item.label}")
                cached_result = _load_success_cache(
                    item, timeout=args.timeout, max_memory_mb=worker_memory_limit_mb
                )
                if cached_result is not None:
                    state.handle_result(item, cached_result)
                    continue
                if executor is None:
                    executor = _make_executor(max(1, workers), worker_memory_limit_mb)
                future = executor.submit(
                    _run_work_item,
                    item,
                    timeout=args.timeout,
                    max_memory_mb=worker_memory_limit_mb,
                )
                future_map[future] = item

            if not future_map:
                continue
            scheduler_timed_out = _drain_batch_futures(future_map, state, args)
        finally:
            if executor is not None:
                executor.shutdown(wait=not scheduler_timed_out, cancel_futures=True)


def _finish_writers(file_writers: dict[Path, CodFileWriter]) -> None:
    """Close all writers and report unreported completed outputs."""
    for writer in file_writers.values():
        if not writer.closed:
            writer.close()
        if writer.received_count > 0 and not writer.reported and writer.out_path.exists():
            writer.reported = True
            print(f"  wrote {writer.out_path}")


def _emit_tail_validation_report(
    state: _RunAccumulator, args: argparse.Namespace, cod_files: list[Path]
) -> None:
    """Aggregate, compare against baseline, and emit the tail-validation surface."""
    aggregate = build_x86_16_tail_validation_aggregate(state.tail_validation_records, scanned=state.tail_validation_scanned)
    baseline_path = args.tail_validation_baseline or _default_tail_validation_baseline_path(
        args.cod_dir,
        timeout=args.timeout,
        cod_files=cod_files,
        proc_names=args.proc_name,
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
        proc_names=args.proc_name,
    )
    detail_cache_path = _default_tail_validation_detail_path(
        args.cod_dir,
        timeout=args.timeout,
        cod_files=cod_files,
        proc_names=args.proc_name,
    )
    sys.stdout.flush()
    emit_tail_validation_surface_summary(
        records=state.tail_validation_records,
        scanned=state.tail_validation_scanned,
        summary=dict(aggregate.get("summary", {}) or {}),
        surface=surface,
        console_cache_path=console_cache_path,
        detail_cache_path=detail_cache_path,
    )
    if args.write_tail_validation_baseline:
        baseline = build_x86_16_tail_validation_baseline(aggregate.get("summary", {}))
        _write_tail_validation_baseline(baseline_path, baseline)
        print(f"{_TAIL_VALIDATION_STDERR_PREFIX}wrote baseline {baseline_path}", file=sys.stderr)


def main() -> int:
    """Run COD-directory decompilation after the architecture guard passes."""

    guard_exit = _run_runtime_architecture_guard()
    if guard_exit:
        return guard_exit

    def _impl() -> int:
        parser = _build_arg_parser()
        args = parser.parse_args()

        _lower_process_priority()
        try:
            cod_files = _resolve_selected_cod_files(args.cod_dir, args.cod_file)
        except ValueError as ex:
            parser.error(str(ex))
        print(f"found {len(cod_files)} COD files under {args.cod_dir}")
        if args.cod_file:
            print(f"/* COD file filter: {', '.join(args.cod_file)} */")
        if args.proc_name:
            print(f"/* PROC name filter: {', '.join(args.proc_name)} */")

        work_items, items_by_file = _collect_work_items(cod_files, args)

        start = time.perf_counter()
        if not work_items:
            print("done in 0.0s; failures=0/0")
            return 0

        workers = _choose_parallelism(len(work_items), args.max_memory_mb, args.max_workers)
        worker_memory_limit_mb = _determine_worker_memory_limit_mb(args.max_memory_mb, workers)
        _print_parallelism_banner(workers, args, worker_memory_limit_mb)

        state = _RunAccumulator(
            file_writers={
                cod_path: CodFileWriter(
                    cod_path=cod_path,
                    out_path=cod_path.with_suffix(".dec"),
                    proc_total=len(items),
                )
                for cod_path, items in items_by_file.items()
            },
            tail_validation_records=[],
        )

        if workers <= 1:
            _run_single_worker_lane(work_items, state, args, worker_memory_limit_mb)
        else:
            task_batches = _iter_task_batches(work_items, workers, args.max_tasks_per_worker)
            _run_task_batches(task_batches, work_items, state, args, workers, worker_memory_limit_mb)

        _finish_writers(state.file_writers)
        _emit_tail_validation_report(state, args, cod_files)

        elapsed = time.perf_counter() - start
        print(f"done in {elapsed:.1f}s; failures={state.failures}/{len(work_items)}")
        return 0 if state.failures == 0 else 1

    return _impl()


if __name__ == "__main__":
    raise SystemExit(main())
