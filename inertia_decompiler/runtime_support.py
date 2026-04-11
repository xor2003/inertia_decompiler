from __future__ import annotations

import contextlib
import io
import logging
import os
import pickle
import re
import resource
import select
import signal
import sys
import threading
import time
import weakref
from collections.abc import Callable
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures.thread import _threads_queues, _worker
from datetime import datetime
from _pytest.capture import EncodedFile


DEFAULT_FREE_RAM_BUDGET_FRACTION = 0.45
DEFAULT_WORKER_MEMORY_FLOOR_MB = 1536
FORCE_SERIAL_FUNCTION_DECOMP_ENV = "INERTIA_FORCE_SERIAL_FUNCTION_DECOMPILATION"

START_TIME = time.perf_counter()
LAST_STEP_TIME = START_TIME
DECOMPILATION_PREP_LOCK = threading.Lock()
_REAL_STDOUT = sys.stdout
_REAL_STDERR = sys.stderr
_CURRENT_PROJECT = None
_FORMAT_FIRST_BLOCK_ASM: Callable[[object, int], str] | None = None


def install_jumpkind_logging_context(project, formatter: Callable[[object, int], str] | None) -> None:
    global _CURRENT_PROJECT, _FORMAT_FIRST_BLOCK_ASM
    _CURRENT_PROJECT = project
    _FORMAT_FIRST_BLOCK_ASM = formatter


def default_exe_showcase_cap(total_functions: int, timeout: int) -> int:
    if total_functions > 256:
        return 4
    return min(24, max(8, timeout))


def install_angr_peephole_expr_bitwidth_guard(walker_cls) -> object:
    original_handle_expr = walker_cls._handle_expr

    def _guarded_handle_expr(self, expr_idx, expr, stmt_idx, stmt, block):
        expr = super(walker_cls, self)._handle_expr(expr_idx, expr, stmt_idx, stmt, block)
        old_expr = expr
        redo = True
        while redo:
            redo = False
            for expr_opt in self.expr_opts:
                if isinstance(expr, expr_opt.expr_classes):
                    replacement = expr_opt.optimize(expr, stmt_idx=stmt_idx, block=block)
                    if replacement is not None and replacement is not expr:
                        if getattr(expr, "bits", None) != getattr(replacement, "bits", None):
                            continue
                        expr = replacement
                        redo = True
                        break
        if expr is not old_expr:
            self.any_update = True
        return expr

    walker_cls._handle_expr = _guarded_handle_expr
    return original_handle_expr


def enable_line_buffered_stdio() -> None:
    for stream in (_REAL_STDOUT, _REAL_STDERR):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(line_buffering=True)
            except Exception:
                pass


def install_angr_variable_recovery_binop_sub_size_guard(
    engine_cls,
    *,
    richr_cls=None,
    typevars_module=None,
) -> object:
    if richr_cls is None or typevars_module is None:
        from angr.analyses.typehoon import typevars as angr_typevars
        from angr.analyses.variable_recovery import engine_ail as variable_recovery_engine

        richr_cls = variable_recovery_engine.RichR
        typevars_module = angr_typevars

    original_handle_binop_sub = engine_cls._handle_binop_Sub

    def _guarded_handle_binop_sub(self, expr):
        arg0, arg1 = expr.operands
        r0, r1 = self._expr_pair(arg0, arg1)
        compute = r0.data - r1.data if r0.data.size() == r1.data.size() else self.state.top(expr.bits)

        type_constraints = set()
        if r0.typevar is not None and r1.data.concrete and isinstance(r0.typevar, typevars_module.TypeVariable):
            typevar = typevars_module.new_dtv(r0.typevar, label=typevars_module.SubN(r1.data.concrete_value))
        else:
            typevar = typevars_module.TypeVariable()
            if r0.typevar is not None and r1.typevar is not None:
                type_constraints.add(typevars_module.Sub(r0.typevar, r1.typevar, typevar))

        return richr_cls(compute, typevar=typevar, type_constraints=type_constraints)

    engine_cls._handle_binop_Sub = _guarded_handle_binop_sub
    return original_handle_binop_sub


@contextlib.contextmanager
def guard_angr_peephole_expr_bitwidth_assertion():
    from angr.analyses.decompiler import utils as decompiler_utils

    walker_cls = decompiler_utils._PeepholeExprsWalker
    original_handle_expr = install_angr_peephole_expr_bitwidth_guard(walker_cls)
    try:
        yield
    finally:
        walker_cls._handle_expr = original_handle_expr


@contextlib.contextmanager
def guard_angr_variable_recovery_binop_sub_size_mismatch():
    from angr.analyses.variable_recovery import engine_ail as variable_recovery_engine

    engine_cls = variable_recovery_engine.SimEngineVRAIL
    original_handle_binop_sub = install_angr_variable_recovery_binop_sub_size_guard(engine_cls)
    try:
        yield
    finally:
        engine_cls._handle_binop_Sub = original_handle_binop_sub


class ThreadBoundTextIO(io.TextIOBase):
    def __init__(self, fallback: EncodedFile) -> None:
        self._fallback = fallback
        self._local = threading.local()

    @contextlib.contextmanager
    def target(self, stream):
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

    def _stream(self):
        return getattr(self._local, "stream", self._fallback)

    def write(self, data):
        return self._stream().write(data)

    def flush(self):
        try:
            return self._stream().flush()
        except ValueError:
            return None

    def isatty(self):
        target = self._stream()
        return bool(getattr(target, "isatty", lambda: False)())

    @property
    def encoding(self):
        return getattr(self._stream(), "encoding", getattr(self._fallback, "encoding", "utf-8"))

    @property
    def errors(self):
        return getattr(self._stream(), "errors", getattr(self._fallback, "errors", "strict"))

    def __getattr__(self, item):
        return getattr(self._stream(), item)


_THREAD_STDOUT = ThreadBoundTextIO(_REAL_STDOUT)
_THREAD_STDERR = ThreadBoundTextIO(_REAL_STDERR)
sys.stdout = _THREAD_STDOUT
sys.stderr = _THREAD_STDERR


class DaemonThreadPoolExecutor(ThreadPoolExecutor):
    def _adjust_thread_count(self):  # noqa: D401
        if self._idle_semaphore.acquire(timeout=0):
            return

        def weakref_cb(_, q=self._work_queue):
            q.put(None)

        num_threads = len(self._threads)
        if num_threads < self._max_workers:
            thread_name = "%s_%d" % (self._thread_name_prefix or self, num_threads)
            t = threading.Thread(
                name=thread_name,
                target=_worker,
                args=(
                    weakref.ref(self, weakref_cb),
                    self._create_worker_context(),
                    self._work_queue,
                ),
                daemon=True,
            )
            t.start()
            self._threads.add(t)
            _threads_queues[t] = self._work_queue

    def shutdown(self, wait=True, *, cancel_futures=False):  # noqa: D401
        try:
            return super().shutdown(wait=wait, cancel_futures=cancel_futures)
        finally:
            if not wait:
                for thread in list(self._threads):
                    _threads_queues.pop(thread, None)


def log_step(step: str) -> None:
    global LAST_STEP_TIME
    now = time.perf_counter()
    elapsed_total = now - START_TIME
    since_last = now - LAST_STEP_TIME
    LAST_STEP_TIME = now
    timestamp = datetime.utcnow().isoformat()
    print(f"[dbg][{timestamp}] {step} (total {elapsed_total:.2f}s, +{since_last:.2f}s)")
    sys.stdout.flush()


def format_address(addr: int) -> str:
    return f"{addr:#x}"


class JumpkindLoggingHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        msg = record.getMessage()
        if "Unsupported jumpkind" in msg and "address" in msg:
            match = re.search(r"address\s+(0x[0-9a-fA-F]+|[0-9]+)", msg)
            if match and _CURRENT_PROJECT is not None and _FORMAT_FIRST_BLOCK_ASM is not None:
                try:
                    addr = int(match.group(1), 0)
                    asm = _FORMAT_FIRST_BLOCK_ASM(_CURRENT_PROJECT, addr)
                    print(f"[dbg][{datetime.utcnow().isoformat()}] NON-DECODED BLOCK {addr:#x}:\n{asm}")
                except Exception as exc:
                    print(f"[dbg] failed to format assembly for {msg}: {exc}")
            else:
                print(f"[dbg] {msg}")


class AnalysisTimeout(Exception):
    pass


def raise_timeout(_signum, _frame):
    raise AnalysisTimeout()


@contextlib.contextmanager
def analysis_timeout(timeout: int):
    if timeout <= 0 or threading.current_thread() is not threading.main_thread():
        yield
        return

    old_handler = signal.signal(signal.SIGALRM, raise_timeout)
    signal.alarm(timeout)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


def run_with_timeout_in_daemon_thread(
    func,
    *,
    timeout: int,
    thread_name_prefix: str,
):
    executor = DaemonThreadPoolExecutor(max_workers=1, thread_name_prefix=thread_name_prefix)
    future = executor.submit(func)
    try:
        return future.result(timeout=max(1, timeout))
    finally:
        finished = future.done()
        executor.shutdown(wait=finished, cancel_futures=not finished)


def run_with_timeout_in_fork(
    func,
    *,
    timeout: int,
) -> object:
    if os.name != "posix" or not hasattr(os, "fork"):
        raise RuntimeError("fork unavailable")
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError("fork-only supported from main thread")
    if threading.active_count() != 1:
        raise RuntimeError("fork-only supported without extra live threads")

    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(read_fd)
            try:
                payload = ("ok", func())
            except BaseException as ex:  # noqa: BLE001
                payload = ("err", type(ex).__name__, str(ex))
            try:
                data = pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL)
            except BaseException as ex:  # noqa: BLE001
                payload = ("err", type(ex).__name__, f"fork result is not pickleable: {ex}")
                data = pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL)
            os.write(write_fd, len(data).to_bytes(8, "little"))
            os.write(write_fd, data)
        finally:
            with contextlib.suppress(OSError):
                os.close(write_fd)
            os._exit(0)

    os.close(write_fd)
    try:
        ready, _, _ = select.select([read_fd], [], [], max(1, timeout))
        if not ready:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            raise TimeoutError(f"Timed out after {timeout}s.")
        header = b""
        while len(header) < 8:
            chunk = os.read(read_fd, 8 - len(header))
            if not chunk:
                break
            header += chunk
        if len(header) != 8:
            os.waitpid(pid, 0)
            raise RuntimeError("fork child exited without result")
        expected = int.from_bytes(header, "little")
        data = bytearray()
        while len(data) < expected:
            chunk = os.read(read_fd, min(65536, expected - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        os.waitpid(pid, 0)
        if len(data) != expected:
            raise RuntimeError("fork child returned incomplete result")
        payload = pickle.loads(bytes(data))
        if not isinstance(payload, tuple) or not payload:
            raise RuntimeError("fork child returned invalid payload")
        if payload[0] == "ok":
            return payload[1]
        if payload[0] == "err":
            if payload[1] in {"TimeoutError", "AnalysisTimeout"}:
                raise TimeoutError(payload[2] or f"Timed out after {timeout}s.")
            raise RuntimeError(f"{payload[1]}: {payload[2]}")
        raise RuntimeError("fork child returned unknown status")
    finally:
        with contextlib.suppress(OSError):
            os.close(read_fd)


def _read_framed_pickle(fd: int):
    header = b""
    while len(header) < 8:
        chunk = os.read(fd, 8 - len(header))
        if not chunk:
            return None
        header += chunk
    expected = int.from_bytes(header, "little")
    data = bytearray()
    while len(data) < expected:
        chunk = os.read(fd, min(65536, expected - len(data)))
        if not chunk:
            return None
        data.extend(chunk)
    return pickle.loads(bytes(data))


def _write_framed_pickle(fd: int, payload) -> None:
    data = pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL)
    os.write(fd, len(data).to_bytes(8, "little"))
    os.write(fd, data)


class PreforkJobPool:
    def __init__(self, *, max_workers: int, worker_func: Callable[[object], object], name_prefix: str = "prefork"):
        if os.name != "posix" or not hasattr(os, "fork"):
            raise RuntimeError("prefork unavailable")
        if threading.current_thread() is not threading.main_thread():
            raise RuntimeError("prefork must start on main thread")
        if threading.active_count() != 1:
            raise RuntimeError("prefork requires a single-threaded parent")
        self._worker_func = worker_func
        self._workers: list[dict[str, object]] = []
        self._closed = False
        worker_count = max(1, int(max_workers))
        for index in range(worker_count):
            job_read, job_write = os.pipe()
            result_read, result_write = os.pipe()
            pid = os.fork()
            if pid == 0:
                try:
                    os.close(job_write)
                    os.close(result_read)
                    while True:
                        job = _read_framed_pickle(job_read)
                        if job is None or job == ("shutdown",):
                            break
                        job_id, payload = job
                        try:
                            result = self._worker_func(payload)
                            _write_framed_pickle(result_write, (job_id, "ok", result))
                        except BaseException as ex:  # noqa: BLE001
                            _write_framed_pickle(result_write, (job_id, "err", type(ex).__name__, str(ex)))
                finally:
                    with contextlib.suppress(OSError):
                        os.close(job_read)
                    with contextlib.suppress(OSError):
                        os.close(result_write)
                    os._exit(0)
            os.close(job_read)
            os.close(result_write)
            self._workers.append(
                {
                    "pid": pid,
                    "job_write": job_write,
                    "result_read": result_read,
                    "busy": False,
                    "job_id": None,
                    "name": f"{name_prefix}_{index}",
                }
            )

    def run_unordered(self, jobs: list[tuple[object, object]], *, poll_timeout: float = 0.25):
        pending = deque(jobs)
        remaining = len(jobs)

        def _dispatch_available() -> None:
            for worker in self._workers:
                if not pending:
                    break
                if worker["busy"]:
                    continue
                job_id, payload = pending.popleft()
                _write_framed_pickle(worker["job_write"], (job_id, payload))
                worker["busy"] = True
                worker["job_id"] = job_id

        _dispatch_available()
        while remaining > 0:
            ready_fds = [
                int(worker["result_read"])
                for worker in self._workers
                if worker["busy"]
            ]
            if not ready_fds:
                break
            ready, _, _ = select.select(ready_fds, [], [], poll_timeout)
            if not ready:
                continue
            for fd in ready:
                worker = next(
                    worker for worker in self._workers if int(worker["result_read"]) == fd
                )
                payload = _read_framed_pickle(fd)
                worker["busy"] = False
                worker["job_id"] = None
                remaining -= 1
                if payload is None:
                    yield None, RuntimeError(f"{worker['name']} exited without result")
                elif payload[1] == "ok":
                    yield payload[0], payload[2]
                else:
                    yield payload[0], RuntimeError(f"{payload[2]}: {payload[3]}")
                _dispatch_available()

    def shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True
        for worker in self._workers:
            with contextlib.suppress(Exception):
                _write_framed_pickle(worker["job_write"], ("shutdown",))
        for worker in self._workers:
            with contextlib.suppress(OSError):
                os.close(int(worker["job_write"]))
            with contextlib.suppress(OSError):
                os.close(int(worker["result_read"]))
            with contextlib.suppress(Exception):
                os.waitpid(int(worker["pid"]), 0)


def emit_timeout_and_exit(args_timeout: int, recovery_detail: str | None) -> None:
    if recovery_detail is None:
        print(f"/* Timed out while recovering a function after {args_timeout}s. */")
    else:
        print(f"/* Timed out while recovering a function after {args_timeout}s {recovery_detail}. */")
    print("/* Tip: try a larger --timeout for larger binaries. */")
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(3)


def apply_memory_limit(max_memory_mb: int | None) -> None:
    if max_memory_mb is None or max_memory_mb <= 0:
        return
    limit = max_memory_mb * 1024 * 1024
    try:
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    except (ValueError, OSError):
        pass


def memory_available_mb() -> int | None:
    try:
        meminfo = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as fp:
            for line in fp:
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                parts = value.strip().split()
                if parts:
                    meminfo[key] = int(parts[0])
        available = meminfo.get("MemAvailable")
        if available:
            return available // 1024
    except OSError:
        pass
    return None


def prefer_low_memory_path() -> bool:
    available_mb = memory_available_mb()
    return available_mb is not None and available_mb < 4096


def lower_process_priority() -> None:
    try:
        os.nice(10)
    except (AttributeError, OSError):
        pass


def choose_function_parallelism(function_count: int) -> int:
    if function_count <= 1:
        return 1
    if os.environ.get(FORCE_SERIAL_FUNCTION_DECOMP_ENV, "").strip().lower() in {"1", "true", "yes", "on"}:
        return 1
    if prefer_low_memory_path():
        return 1
    cpu_count = os.cpu_count() or 1
    workers = max(1, cpu_count - 1)
    available_mb = memory_available_mb()
    if available_mb is None:
        return min(workers, function_count)
    budget_mb = int(available_mb * DEFAULT_FREE_RAM_BUDGET_FRACTION)
    if budget_mb < DEFAULT_WORKER_MEMORY_FLOOR_MB:
        return 1
    workers_by_mem = max(1, budget_mb // DEFAULT_WORKER_MEMORY_FLOOR_MB)
    return min(workers, function_count, workers_by_mem)


def should_force_serial_supplemental_decompilation(function_count: int) -> bool:
    if function_count > 8:
        return False
    if prefer_low_memory_path():
        return True
    available_mb = memory_available_mb()
    if available_mb is None:
        return True
    return available_mb < (DEFAULT_WORKER_MEMORY_FLOOR_MB * 4)


@contextlib.contextmanager
def capture_thread_output():
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    with _THREAD_STDOUT.target(stdout_buf), _THREAD_STDERR.target(stderr_buf):
        yield stdout_buf, stderr_buf


enable_line_buffered_stdio()
