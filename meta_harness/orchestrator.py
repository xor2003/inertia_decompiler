from __future__ import annotations

import fcntl
import json
import hashlib
import os
import re
import shutil
import subprocess
import sys
import time
import threading
from collections import Counter
from datetime import datetime
from pathlib import Path

from .config import LlmConfig, RuntimeConfig
from .llm import backend_supports_sessions, build_effective_prompt, extract_session_id, run_provider_once, validate_output
from .policy import (
    GREEN_RED,
    CycleOutcomeContext,
    GreenLevelContext,
    WorkerRuntimeContext,
    WorkerTimeoutContext,
    decide_cycle_followup,
    decide_green_level,
    decide_worker_runtime,
    decide_worker_timeout,
)
from .procguard import cleanup_stale_child_processes, install_child_cleanup_handler, register_child_process, unregister_child_process
from .prompts import (
    build_checker_prompt,
    build_crash_reviewer_prompt,
    build_planner_prompt,
    build_resume_prompt,
    build_reviewer_prompt,
    build_worker_prompt,
)
from .runtime_records import (
    CYCLE_STATE_SCHEMA_VERSION,
    PREFLIGHT_STATE_SCHEMA_VERSION,
    SESSION_LEDGER_SCHEMA_VERSION,
    append_jsonl,
    build_history_event,
    compact_runtime_signals,
    iso_now,
    load_jsonl,
    parse_usage_metrics,
    read_json,
    summarize_session_rows,
    write_json,
)
from .task_packet import TASK_PACKET_SCHEMA_VERSION, TaskPacket, parse_plan_task_packets
from .webui import append_chat_entry


class HarnessError(RuntimeError):
    pass


class ResourceBlockedError(HarnessError):
    def __init__(self, context: str, message: str, *, exit_code: int = 75):
        super().__init__(message)
        self.context = context
        self.exit_code = exit_code


class RoleRunError(HarnessError):
    def __init__(self, role: str, log_file: Path, message: str, exit_code: int | None = None):
        super().__init__(message)
        self.role = role
        self.log_file = log_file
        self.exit_code = exit_code


class MetaHarness:
    step_order = ("full-sweep", "checker", "planner", "worker", "reviewer")
    completed_step_statuses = {"done", "done-with-failures"}
    graceful_exit_codes = {124, 130, 143}
    _SWEEP_THREAD_EXHAUSTION_MARKER = "RuntimeError: can't start new thread"

    def __init__(self, cfg: RuntimeConfig, llm_cfg: LlmConfig):
        self.cfg = cfg
        self.llm_cfg = llm_cfg
        self.current_cycle_dir: Path | None = None
        self.current_cycle_index = 0
        self.cycle_state: dict[str, object] | None = None
        self.crash_review_active = False
        self.lock_fp: object | None = None
        self.status_lock = threading.Lock()
        self.log_lock = threading.Lock()
        self.script_checksums = self._compute_script_checksums()
        self.next_cycle_start_step: str | None = None
        self.worker_stall_streak = 0
        self.current_plan_item = ""
        self.current_plan_item_stall_count = 0
        self.plan_rewrite_target = ""
        self.current_task_packet: dict[str, object] = {}
        self.current_task_packet_status = ""
        self.current_green_level = GREEN_RED
        self.last_policy_decision: dict[str, object] = {}
        self.last_closeout_action = ""
        self.manual_worker_model_override = ""
        self.manual_worker_failure_limit_override = 0
        self.last_completed_task_packet: dict[str, object] = {}
        self.auto_committed_packets: list[str] = []
        self._ensure_dirs()

    def _ensure_dirs(self) -> None:
        for path in (self.cfg.state_dir, self.cfg.log_dir, self.cfg.prompt_dir, self.cfg.runs_dir):
            path.mkdir(parents=True, exist_ok=True)
        install_child_cleanup_handler(self.cfg.state_dir, self.cfg.root_dir)

    def record_event(
        self,
        event: str,
        status: str,
        message: str,
        *,
        failure_class: str | None = None,
        **details: object,
    ) -> None:
        append_jsonl(
            self.cfg.history_log_file,
            build_history_event(
                event=event,
                status=status,
                message=message,
                at=iso_now(),
                cycle=self.current_cycle_index,
                current_plan_item=self.current_plan_item,
                failure_class=failure_class,
                details=details,
            ),
        )

    def update_preflight_state(self, **updates: object) -> None:
        payload = read_json(self.cfg.preflight_state_file)
        payload.setdefault("schema_version", PREFLIGHT_STATE_SCHEMA_VERSION)
        payload.update(updates)
        payload["updated_at"] = iso_now()
        write_json(self.cfg.preflight_state_file, payload)

    def record_role_session(
        self,
        *,
        role: str,
        provider: str,
        model: str,
        mode: str,
        log_file: Path,
        exit_code: int | None,
        duration_secs: int,
        outcome: str,
    ) -> None:
        text = log_file.read_text(encoding="utf-8", errors="replace") if log_file.exists() else ""
        usage = parse_usage_metrics(text)
        append_jsonl(
            self.cfg.session_ledger_file,
            {
                "schema_version": SESSION_LEDGER_SCHEMA_VERSION,
                "at": iso_now(),
                "role": role,
                "provider": provider,
                "model": model,
                "mode": mode,
                "log_file": log_file.name,
                "exit_code": exit_code,
                "duration_secs": duration_secs,
                "outcome": outcome,
                "current_plan_item": self.current_plan_item,
                **usage,
            },
        )

    def timestamp(self) -> str:
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def iso_now(self) -> str:
        return datetime.now().astimezone().isoformat(timespec="seconds")

    def log(self, msg: str) -> None:
        line = f"[{self.iso_now()}] {msg}"
        print(line, file=sys.stderr)
        try:
            self.cfg.last_log_file.parent.mkdir(parents=True, exist_ok=True)
            with self.log_lock:
                with self.cfg.last_log_file.open("a", encoding="utf-8") as fp:
                    fp.write(line + "\n")
        except OSError:
            pass

    def die(self, msg: str) -> None:
        raise HarnessError(msg)

    def write_status(self, step: str, status: str, extra: str = "") -> None:
        lines = [f"step={step}", f"status={status}"]
        if extra:
            lines.append(f"extra={extra}")
        lines.append(f"updated_at={self.iso_now()}")
        with self.status_lock:
            self.cfg.status_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _start_status_heartbeat(self, step: str, status: str, extra: str = ""):
        interval = float(self.cfg.status_heartbeat_secs)
        if interval <= 0:
            return None

        started = time.monotonic()
        stop_event = threading.Event()

        def _run() -> None:
            while not stop_event.wait(interval):
                elapsed = int(time.monotonic() - started)
                heartbeat_extra = extra
                if heartbeat_extra:
                    heartbeat_extra += " "
                heartbeat_extra += f"heartbeat_elapsed={elapsed}s"
                self.write_status(step, status, heartbeat_extra)
                self.log(f"{step} still {status}; elapsed={elapsed}s")

        thread = threading.Thread(target=_run, name=f"{step}-status-heartbeat", daemon=True)
        thread.start()
        return stop_event, thread

    def check_stop_file(self) -> None:
        if self.cfg.stop_file.exists():
            self.write_status("stopped", "stop-file-detected", str(self.cfg.stop_file))
            raise SystemExit(10)

    def ensure_prereqs(self) -> None:
        command_status: dict[str, bool] = {}
        for cmd in ("timeout", "df", "du"):
            command_status[cmd] = shutil.which(cmd) is not None
            if not command_status[cmd]:
                self.update_preflight_state(ready=False, commands=command_status, missing=[cmd])
                self.record_event(
                    "role.failed",
                    "blocked",
                    f"missing required command: {cmd}",
                    failure_class="resource_blocked",
                    role="harness",
                    command=cmd,
                )
                self.die(f"{cmd} command not found in PATH")
        provider_status: dict[str, bool] = {}
        if not self.cfg.python_bin.exists():
            self.update_preflight_state(ready=False, commands=command_status, python_bin=str(self.cfg.python_bin), python_ok=False)
            self.record_event(
                "role.failed",
                "blocked",
                "missing harness python binary",
                failure_class="resource_blocked",
                role="harness",
                python_bin=str(self.cfg.python_bin),
            )
            self.die(f"Missing {self.cfg.python_bin}")
        profiler_status = self.ensure_profiler_tools()
        providers = {
            self.llm_cfg.planner_provider,
            self.llm_cfg.checker_provider,
            self.llm_cfg.worker_provider,
            self.llm_cfg.reviewer_provider,
            self.llm_cfg.crash_reviewer_provider,
        }
        for provider in providers:
            provider_status[provider] = True
            if provider == "codex" and shutil.which("codex") is None:
                provider_status[provider] = False
                self.update_preflight_state(ready=False, commands=command_status, providers=provider_status, python_ok=True)
                self.record_event(
                    "role.failed",
                    "blocked",
                    "codex CLI not found in PATH",
                    failure_class="provider_failure",
                    role="harness",
                    provider=provider,
                )
                self.die("codex CLI not found in PATH")
            if provider == "ollama" and shutil.which(self.llm_cfg.ollama_cmd) is None:
                provider_status[provider] = False
                self.update_preflight_state(ready=False, commands=command_status, providers=provider_status, python_ok=True)
                self.record_event(
                    "role.failed",
                    "blocked",
                    f"ollama command not found: {self.llm_cfg.ollama_cmd}",
                    failure_class="provider_failure",
                    role="harness",
                    provider=provider,
                )
                self.die(f"ollama command not found: {self.llm_cfg.ollama_cmd}")
            if provider == "llamacpp" and shutil.which(self.llm_cfg.llamacpp_cmd) is None:
                provider_status[provider] = False
                self.update_preflight_state(ready=False, commands=command_status, providers=provider_status, python_ok=True)
                self.record_event(
                    "role.failed",
                    "blocked",
                    f"llama.cpp command not found: {self.llm_cfg.llamacpp_cmd}",
                    failure_class="provider_failure",
                    role="harness",
                    provider=provider,
                )
                self.die(f"llama.cpp command not found: {self.llm_cfg.llamacpp_cmd}")
        self.update_preflight_state(
            ready=True,
            commands=command_status,
            providers=provider_status,
            profilers=profiler_status,
            python_bin=str(self.cfg.python_bin),
            python_ok=True,
            root_dir=str(self.cfg.root_dir),
            stop_file_present=self.cfg.stop_file.exists(),
        )

    def python_module_available(self, module: str) -> bool:
        try:
            result = subprocess.run(
                [str(self.cfg.python_bin), "-c", f"import {module}"],
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError:
            return False
        return result.returncode == 0

    def py_spy_available(self) -> bool:
        candidates = [
            self.cfg.python_bin.parent / "py-spy",
            shutil.which("py-spy"),
        ]
        for candidate in candidates:
            if not candidate:
                continue
            try:
                result = subprocess.run(
                    [str(candidate), "--version"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            except OSError:
                continue
            if result.returncode == 0:
                return True
        return False

    def ensure_profiler_tools(self) -> dict[str, object]:
        required_modules = {"line_profiler": "line_profiler", "memray": "memray"}
        status: dict[str, object] = {
            "line_profiler": self.python_module_available(required_modules["line_profiler"]),
            "memray": self.python_module_available(required_modules["memray"]),
            "py-spy": self.py_spy_available(),
            "install_attempted": False,
            "install_ok": None,
            "install_missing": [],
        }
        missing = [name for name in ("line_profiler", "memray", "py-spy") if not bool(status.get(name))]
        if not missing:
            return status
        status["install_attempted"] = True
        status["install_missing"] = missing
        self.log(f"Installing missing profiler tools into active environment: {', '.join(missing)}")
        install = subprocess.run(
            [str(self.cfg.python_bin), "-m", "pip", "install", "line_profiler", "memray", "py-spy"],
            capture_output=True,
            text=True,
            check=False,
        )
        status["install_ok"] = install.returncode == 0
        status["install_rc"] = install.returncode
        status["install_stdout_tail"] = install.stdout[-2000:]
        status["install_stderr_tail"] = install.stderr[-2000:]
        status["line_profiler"] = self.python_module_available(required_modules["line_profiler"])
        status["memray"] = self.python_module_available(required_modules["memray"])
        status["py-spy"] = self.py_spy_available()
        still_missing = [name for name in ("line_profiler", "memray", "py-spy") if not bool(status.get(name))]
        status["still_missing"] = still_missing
        if still_missing:
            self.record_event(
                "preflight.profilers_missing",
                "warning",
                "one or more profiling tools remain unavailable after install attempt",
                failure_class="resource_blocked",
                missing=still_missing,
                install_rc=install.returncode,
            )
        return status

    def acquire_lock(self) -> None:
        self.cfg.lock_file.parent.mkdir(parents=True, exist_ok=True)
        fp = self.cfg.lock_file.open("w")
        try:
            fcntl.flock(fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            holders = ""
            if shutil.which("fuser"):
                result = subprocess.run(
                    ["fuser", "-v", str(self.cfg.lock_file)], capture_output=True, text=True, check=False
                )
                holders = result.stdout + result.stderr
            self.die(f"Another run instance is already active\n{holders}".rstrip())
        self.lock_fp = fp

    def trim_old_logs(self) -> None:
        logs = sorted(self.cfg.log_dir.glob("*.log"))
        for old in logs[: max(0, len(logs) - self.cfg.keep_log_count)]:
            old.unlink(missing_ok=True)

    def free_disk_mb(self) -> int:
        result = subprocess.run(["df", "-Pm", str(self.cfg.root_dir)], capture_output=True, text=True, check=True)
        return int(result.stdout.splitlines()[1].split()[3])

    def free_ram_mb(self) -> int | None:
        try:
            for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
        except OSError:
            return None
        return None

    def state_dir_mb(self) -> int:
        result = subprocess.run(["du", "-sm", str(self.cfg.state_dir)], capture_output=True, text=True, check=False)
        return int(result.stdout.split()[0]) if result.returncode == 0 and result.stdout.strip() else 0

    def cleanup_large_artifacts(self) -> None:
        threshold = self.cfg.max_single_artifact_mb * 1024 * 1024
        for path in sorted(self.cfg.state_dir.rglob("*")):
            if path.is_file() and path.stat().st_size > threshold:
                self.log(f"Removing oversized artifact {path}")
                path.unlink(missing_ok=True)

    def trim_old_cycles(self) -> None:
        cycles = sorted(p for p in self.cfg.runs_dir.iterdir() if p.is_dir()) if self.cfg.runs_dir.exists() else []
        total_mb = self.state_dir_mb()
        while total_mb > self.cfg.max_state_dir_mb and len(cycles) > 1:
            victim = cycles.pop(0)
            self.log(f"State dir is {total_mb}MB, pruning old cycle {victim.name}")
            shutil.rmtree(victim, ignore_errors=True)
            total_mb = self.state_dir_mb()

    def cleanup_state_dir(self) -> None:
        self.trim_old_logs()
        self.cleanup_large_artifacts()
        self.trim_old_cycles()

    def wait_for_memory_headroom(self, context: str) -> None:
        while True:
            self.check_stop_file()
            avail = self.free_ram_mb()
            if avail is None or avail >= self.cfg.pause_when_ram_below_mb:
                return
            self.write_status(context, "paused-low-ram", f"avail={avail}MB threshold={self.cfg.pause_when_ram_below_mb}MB")
            self.log(f"Low RAM before {context}: {avail}MB available; waiting {self.cfg.planner_pause_secs}s")
            time.sleep(self.cfg.planner_pause_secs)

    def preflight_resource_check(self, context: str) -> None:
        self.cleanup_state_dir()
        disk = self.free_disk_mb()
        ram = self.free_ram_mb()
        state_mb = self.state_dir_mb()
        self.update_preflight_state(
            last_context=context,
            free_disk_mb=disk,
            free_ram_mb=ram,
            state_dir_mb=state_mb,
            min_free_disk_mb=self.cfg.min_free_disk_mb,
            min_free_ram_mb=self.cfg.min_free_ram_mb,
            max_state_dir_mb=self.cfg.max_state_dir_mb,
        )
        if disk < self.cfg.min_free_disk_mb:
            self.cleanup_state_dir()
            disk = self.free_disk_mb()
            if disk < self.cfg.min_free_disk_mb:
                self.mark_cycle_step(context, "blocked-low-disk", f"free={disk}MB required={self.cfg.min_free_disk_mb}MB")
                self.write_status(context, "blocked-low-disk", f"free={disk}MB required={self.cfg.min_free_disk_mb}MB")
                self.record_event(
                    "role.failed",
                    "blocked",
                    "preflight blocked on low disk",
                    failure_class="resource_blocked",
                    role=context,
                    free_disk_mb=disk,
                    min_free_disk_mb=self.cfg.min_free_disk_mb,
                )
                raise ResourceBlockedError(
                    context,
                    f"Not enough free disk space for {context}: {disk}MB available, need at least {self.cfg.min_free_disk_mb}MB",
                )
        ram = self.free_ram_mb()
        if ram is not None and ram < self.cfg.min_free_ram_mb:
            self.wait_for_memory_headroom(context)
            ram = self.free_ram_mb()
            if ram is not None and ram < self.cfg.min_free_ram_mb:
                self.mark_cycle_step(context, "blocked-low-ram", f"avail={ram}MB required={self.cfg.min_free_ram_mb}MB")
                self.write_status(context, "blocked-low-ram", f"avail={ram}MB required={self.cfg.min_free_ram_mb}MB")
                self.record_event(
                    "role.failed",
                    "blocked",
                    "preflight blocked on low RAM",
                    failure_class="resource_blocked",
                    role=context,
                    free_ram_mb=ram,
                    min_free_ram_mb=self.cfg.min_free_ram_mb,
                )
                raise ResourceBlockedError(
                    context,
                    f"Not enough free RAM for {context}: {ram}MB available, need at least {self.cfg.min_free_ram_mb}MB",
                )
        self.write_status(context, "resources-ok", f"disk={disk}MB ram={ram if ram is not None else 'unknown'}MB state={self.state_dir_mb()}MB")

    def sha256_file(self, path: Path) -> str:
        if not path.exists():
            return ""
        h = hashlib.sha256()
        with path.open("rb") as fp:
            for chunk in iter(lambda: fp.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def _compute_script_checksums(self) -> dict[str, str]:
        package_root = self.cfg.root_dir / "meta_harness"
        return {
            "run.sh": self.sha256_file(self.cfg.run_sh_path),
            "meta_harness": self.sha256_tree(package_root),
        }

    def sha256_tree(self, root: Path) -> str:
        if not root.exists():
            return ""
        h = hashlib.sha256()
        for path in sorted(root.rglob("*")):
            if path.is_file():
                h.update(path.relative_to(root).as_posix().encode("utf-8"))
                with path.open("rb") as fp:
                    for chunk in iter(lambda: fp.read(1024 * 1024), b""):
                        h.update(chunk)
        return h.hexdigest()

    def latest_cycle_dir(self) -> Path | None:
        if not self.cfg.runs_dir.exists():
            return None
        cycles = sorted(p for p in self.cfg.runs_dir.iterdir() if p.is_dir())
        return cycles[-1] if cycles else None

    def cycle_state_file(self, cycle_dir: Path | None = None) -> Path | None:
        base = cycle_dir or self.current_cycle_dir
        return None if base is None else base / "cycle.state.json"

    def _empty_cycle_state(self, cycle_index: int) -> dict[str, object]:
        return {
            "schema_version": CYCLE_STATE_SCHEMA_VERSION,
            "cycle": cycle_index,
            "started_at": self.iso_now(),
            "updated_at": self.iso_now(),
            "completed": False,
            "current_plan_item": self.current_plan_item,
            "current_plan_item_stall_count": self.current_plan_item_stall_count,
            "current_task_packet": self.current_task_packet,
            "current_task_packet_status": self.current_task_packet_status,
            "current_green_level": self.current_green_level,
            "last_policy_decision": self.last_policy_decision,
            "last_closeout_action": self.last_closeout_action,
            "manual_worker_model_override": self.manual_worker_model_override,
            "manual_worker_failure_limit_override": self.manual_worker_failure_limit_override,
            "last_completed_task_packet": self.last_completed_task_packet,
            "auto_committed_packets": list(self.auto_committed_packets),
            "git_clean_start": False,
            "branch_name": "",
            "branch_freshness": {},
            "next_cycle_start_step": self.next_cycle_start_step or "",
            "plan_rewrite_target": self.plan_rewrite_target,
            "steps": {step: {"status": "pending", "updated_at": "", "extra": ""} for step in self.step_order},
            "worker_stall_streak": self.worker_stall_streak,
        }

    def _normalize_next_cycle_start_step(self, value: object) -> str | None:
        if isinstance(value, str) and value in self.step_order:
            return value
        return None

    def _reviewer_completed_in_state(self, state: dict[str, object]) -> bool:
        steps = state.get("steps")
        if not isinstance(steps, dict):
            return False
        entry = steps.get("reviewer")
        return isinstance(entry, dict) and entry.get("status") in self.completed_step_statuses

    def _hydrate_runtime_hints_from_state(self, state: dict[str, object]) -> None:
        raw_streak = state.get("worker_stall_streak", 0)
        try:
            self.worker_stall_streak = max(0, int(raw_streak))
        except (TypeError, ValueError):
            self.worker_stall_streak = 0
        self.current_plan_item = str(state.get("current_plan_item", "") or "")
        raw_item_stall_count = state.get("current_plan_item_stall_count", 0)
        try:
            self.current_plan_item_stall_count = max(0, int(raw_item_stall_count))
        except (TypeError, ValueError):
            self.current_plan_item_stall_count = 0
        self.next_cycle_start_step = self._normalize_next_cycle_start_step(state.get("next_cycle_start_step"))
        self.plan_rewrite_target = str(state.get("plan_rewrite_target", "") or "")
        packet = state.get("current_task_packet", {})
        self.current_task_packet = packet if isinstance(packet, dict) else {}
        self.current_task_packet_status = str(state.get("current_task_packet_status", "") or "")
        self.current_green_level = str(state.get("current_green_level", GREEN_RED) or GREEN_RED)
        decision = state.get("last_policy_decision", {})
        self.last_policy_decision = decision if isinstance(decision, dict) else {}
        self.last_closeout_action = str(state.get("last_closeout_action", "") or "")
        self.manual_worker_model_override = str(state.get("manual_worker_model_override", "") or "")
        raw_manual_limit = state.get("manual_worker_failure_limit_override", 0)
        try:
            self.manual_worker_failure_limit_override = max(0, int(raw_manual_limit))
        except (TypeError, ValueError):
            self.manual_worker_failure_limit_override = 0
        packet = state.get("last_completed_task_packet", {})
        self.last_completed_task_packet = packet if isinstance(packet, dict) else {}
        committed_packets = state.get("auto_committed_packets", [])
        self.auto_committed_packets = [str(value) for value in committed_packets] if isinstance(committed_packets, list) else []

    def _state_has_next_cycle_handoff(self, state: dict[str, object]) -> bool:
        return self._reviewer_completed_in_state(state) and self._normalize_next_cycle_start_step(
            state.get("next_cycle_start_step")
        ) is not None

    def _save_cycle_state(self) -> None:
        if self.current_cycle_dir is None or self.cycle_state is None:
            return
        self.cycle_state["schema_version"] = CYCLE_STATE_SCHEMA_VERSION
        self.cycle_state["current_plan_item"] = self.current_plan_item
        self.cycle_state["current_plan_item_stall_count"] = self.current_plan_item_stall_count
        self.cycle_state["current_task_packet"] = self.current_task_packet
        self.cycle_state["current_task_packet_status"] = self.current_task_packet_status
        self.cycle_state["current_green_level"] = self.current_green_level
        self.cycle_state["last_policy_decision"] = self.last_policy_decision
        self.cycle_state["last_closeout_action"] = self.last_closeout_action
        self.cycle_state["manual_worker_model_override"] = self.manual_worker_model_override
        self.cycle_state["manual_worker_failure_limit_override"] = self.manual_worker_failure_limit_override
        self.cycle_state["last_completed_task_packet"] = self.last_completed_task_packet
        self.cycle_state["auto_committed_packets"] = list(self.auto_committed_packets)
        self.cycle_state["next_cycle_start_step"] = self.next_cycle_start_step or ""
        self.cycle_state["plan_rewrite_target"] = self.plan_rewrite_target
        self.cycle_state["worker_stall_streak"] = self.worker_stall_streak
        self.cycle_state["updated_at"] = self.iso_now()
        state_file = self.cycle_state_file()
        if state_file is not None:
            state_file.write_text(json.dumps(self.cycle_state, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def _load_cycle_state(self, cycle_dir: Path) -> dict[str, object] | None:
        state_file = cycle_dir / "cycle.state.json"
        if not state_file.exists():
            return None
        try:
            return json.loads(state_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None

    def _resume_step_from_state(self, state: dict[str, object]) -> str | None:
        if self._state_has_next_cycle_handoff(state):
            return None
        steps = state.get("steps")
        if not isinstance(steps, dict):
            return None
        for step in self.step_order:
            entry = steps.get(step)
            if not isinstance(entry, dict) or entry.get("status") not in self.completed_step_statuses:
                return step
        return None

    def current_cycle_step(self) -> str | None:
        if self.cycle_state is None:
            return None
        steps = self.cycle_state.get("steps")
        if not isinstance(steps, dict):
            return None
        for step in self.step_order:
            entry = steps.get(step)
            if isinstance(entry, dict) and entry.get("status") in {"running", "paused-low-ram", "blocked-low-ram", "blocked-low-disk"}:
                return step
        return self._resume_step_from_state(self.cycle_state)

    def cycle_step_status(self, step: str) -> str:
        if self.cycle_state is None:
            return ""
        steps = self.cycle_state.get("steps")
        if not isinstance(steps, dict):
            return ""
        entry = steps.get(step)
        if not isinstance(entry, dict):
            return ""
        return str(entry.get("status", ""))

    def peek_resume_step(self) -> str | None:
        latest = self.latest_cycle_dir()
        if latest is None:
            return None
        state = self._load_cycle_state(latest)
        if state is None or state.get("completed") is True:
            return None
        return self._resume_step_from_state(state)

    def resume_latest_cycle(self) -> str | None:
        latest = self.latest_cycle_dir()
        if latest is None:
            return None
        state = self._load_cycle_state(latest)
        if state is None or state.get("completed") is True:
            return None
        self.current_cycle_index = int(state.get("cycle", 0) or 0)
        self._hydrate_runtime_hints_from_state(state)
        resume_step = self._resume_step_from_state(state)
        if resume_step is None:
            return None
        self.current_cycle_dir = latest
        self.cycle_state = state
        latest_link = self.cfg.state_dir / "latest_cycle"
        if latest_link.exists() or latest_link.is_symlink():
            latest_link.unlink()
        latest_link.symlink_to(self.current_cycle_dir)
        self.log(f"Resuming cycle {self.current_cycle_index:03d} from {resume_step}")
        self.record_event("cycle.resumed", "ready", f"resuming cycle from {resume_step}", resume_step=resume_step)
        return resume_step

    def prime_next_cycle_handoff_from_latest_cycle(self) -> None:
        latest = self.latest_cycle_dir()
        if latest is None:
            return
        state = self._load_cycle_state(latest)
        if state is None or state.get("completed") is True or not self._state_has_next_cycle_handoff(state):
            return
        self.current_cycle_index = int(state.get("cycle", 0) or 0)
        self._hydrate_runtime_hints_from_state(state)

    def evidence_failure_count(self) -> int | None:
        if not self.cfg.evidence_log_file.exists():
            return None
        text = self.cfg.evidence_log_file.read_text(encoding="utf-8", errors="replace")
        matches = re.findall(r"failures=(\d+)/(\d+)", text)
        if not matches:
            return None
        failed, _total = matches[-1]
        return int(failed)

    def prepare_cycle_workspace(self) -> None:
        self.cleanup_state_dir()
        self.current_cycle_index += 1
        self.current_cycle_dir = self.cfg.runs_dir / f"{self.timestamp()}_cycle{self.current_cycle_index:03d}"
        self.current_cycle_dir.mkdir(parents=True, exist_ok=True)
        self.cycle_state = self._empty_cycle_state(self.current_cycle_index)
        self._save_cycle_state()
        latest = self.cfg.state_dir / "latest_cycle"
        if latest.exists() or latest.is_symlink():
            latest.unlink()
        latest.symlink_to(self.current_cycle_dir)
        meta = (
            f"cycle={self.current_cycle_index}\n"
            f"started_at={self.iso_now()}\n"
            f"root={self.cfg.root_dir}\n"
            f"script={self.cfg.root_dir / 'meta_harness'}\n"
        )
        (self.current_cycle_dir / "cycle.meta").write_text(meta, encoding="utf-8")
        self.capture_git_state("start")
        if self.cycle_state is not None:
            self.cycle_state["git_clean_start"] = self.git_is_clean()
            self.cycle_state["branch_name"] = self.current_branch_name()
            self.cycle_state["branch_freshness"] = self.branch_freshness()
        if self.cfg.plan_path.exists():
            shutil.copy2(self.cfg.plan_path, self.current_cycle_dir / "PLAN.start.md")
        for role in ("checker", "planner", "worker", "reviewer", "crash-reviewer"):
            self.clear_role_session(role)
        self._save_cycle_state()
        self.record_event("cycle.started", "running", "prepared new cycle", cycle_dir=self.current_cycle_dir.name)
        if self.cycle_state is not None:
            freshness = self.cycle_state.get("branch_freshness", {})
            if isinstance(freshness, dict) and freshness.get("stale"):
                self.record_event(
                    "branch.stale_against_main",
                    "warning",
                    "branch is behind main at cycle start",
                    failure_class="restart_required",
                    branch=freshness.get("branch", ""),
                    behind=freshness.get("behind", 0),
                    ahead=freshness.get("ahead", 0),
                )

    def capture_git_state(self, tag: str) -> None:
        if self.current_cycle_dir is None:
            return
        status = subprocess.run(["git", "-C", str(self.cfg.root_dir), "status", "--short"], capture_output=True, text=True, check=False).stdout
        diff_stat = subprocess.run(["git", "-C", str(self.cfg.root_dir), "diff", "--stat"], capture_output=True, text=True, check=False).stdout
        (self.current_cycle_dir / f"git-status.{tag}.txt").write_text(status, encoding="utf-8")
        (self.current_cycle_dir / f"git-diff-stat.{tag}.txt").write_text(diff_stat, encoding="utf-8")

    def git_status_porcelain(self) -> str:
        result = subprocess.run(
            ["git", "-C", str(self.cfg.root_dir), "status", "--porcelain"],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.stdout

    def changed_tracked_paths(self) -> list[str]:
        paths: list[str] = []
        for raw_line in self.git_status_porcelain().splitlines():
            if not raw_line or raw_line.startswith("?? "):
                continue
            path_text = raw_line[3:]
            if " -> " in path_text:
                path_text = path_text.split(" -> ", 1)[1]
            if path_text and path_text not in paths:
                paths.append(path_text)
        return paths

    def git_is_clean(self) -> bool:
        return not self.git_status_porcelain().strip()

    def current_branch_name(self) -> str:
        result = subprocess.run(
            ["git", "-C", str(self.cfg.root_dir), "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.stdout.strip() if result.returncode == 0 else ""

    def branch_freshness(self) -> dict[str, object]:
        branch = self.current_branch_name()
        result = subprocess.run(
            ["git", "-C", str(self.cfg.root_dir), "rev-parse", "--verify", "main"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return {"branch": branch, "main_available": False, "stale": False}
        counts = subprocess.run(
            ["git", "-C", str(self.cfg.root_dir), "rev-list", "--left-right", "--count", "HEAD...main"],
            capture_output=True,
            text=True,
            check=False,
        )
        if counts.returncode != 0:
            return {"branch": branch, "main_available": True, "stale": False}
        parts = counts.stdout.strip().split()
        ahead = int(parts[0]) if len(parts) >= 1 and parts[0].isdigit() else 0
        behind = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
        return {
            "branch": branch,
            "main_available": True,
            "ahead": ahead,
            "behind": behind,
            "stale": behind > 0,
        }

    def capture_cycle_artifact(self, src: Path, dst_name: str | None = None) -> None:
        if self.current_cycle_dir is None or not src.exists():
            return
        shutil.copy2(src, self.current_cycle_dir / (dst_name or src.name))

    def role_session_file(self, role: str) -> Path:
        if self.current_cycle_dir is not None:
            return self.current_cycle_dir / f"{role}.session"
        return self.cfg.state_dir / f"{role}.session"

    def clear_role_session(self, role: str) -> None:
        self.role_session_file(role).unlink(missing_ok=True)
        (self.cfg.state_dir / f"{role}.session").unlink(missing_ok=True)

    def consume_operator_comments(self, role: str) -> str:
        path = self.cfg.operator_comments_file
        if not path.exists():
            return ""
        text = path.read_text(encoding="utf-8", errors="replace").strip()
        if not text:
            return ""
        append_chat_entry(
            self.cfg.chat_log_file,
            "system",
            f"Delivered operator guidance to {role}.",
            at=self.iso_now(),
        )
        if self.current_cycle_dir is not None:
            archived = self.current_cycle_dir / f"operator-comments.{self.timestamp()}.{role}.md"
            archived.write_text(text + "\n", encoding="utf-8")
        path.write_text("", encoding="utf-8")
        self.log(f"Consumed operator comments for {role} from {path}")
        self.record_event(
            "operator.comments_consumed",
            "completed",
            "consumed operator comments",
            role=role,
            source=str(path),
        )
        return text

    def capture_cycle_snapshot(self, tag: str) -> None:
        self.capture_cycle_artifact(self.cfg.status_file, f"status.{tag}.txt")
        self.capture_cycle_artifact(self.cfg.last_log_file, f"last.{tag}.log")
        self.capture_cycle_artifact(self.cfg.evidence_log_file, f"evidence_sweep.{tag}.log")
        state_file = self.cycle_state_file()
        if state_file is not None and state_file.exists():
            self.capture_cycle_artifact(state_file, f"cycle.{tag}.json")
        if self.current_cycle_dir is not None and self.cfg.plan_path.exists():
            shutil.copy2(self.cfg.plan_path, self.current_cycle_dir / f"PLAN.{tag}.md")
        self.capture_git_state(tag)

    def recent_worker_iteration_logs(self, limit: int = 6) -> list[Path]:
        if self.current_cycle_dir is None:
            return []
        return sorted(self.current_cycle_dir.glob("worker.iter*.log"))[-limit:]

    def build_worker_stall_context(self) -> str:
        if self.cycle_step_status("worker") != "stalled":
            return ""
        logs = self.recent_worker_iteration_logs()
        if not logs:
            return "Recent worker logs were not archived for this stalled cycle."
        lines = ["Recent worker iteration logs for this stalled cycle:"]
        for path in logs:
            text = path.read_text(encoding="utf-8", errors="replace")
            rc_match = re.search(r"end rc=(\d+)", text)
            remaining_match = re.findall(r"Global Remaining steps:\s*(\d+)", text)
            timeout = "yes" if ("timed out" in text or "end rc=124" in text) else "no"
            failure = "yes" if ("FAILED " in text or "failed" in text.lower()) else "no"
            lines.append(
                f"- {path}: rc={rc_match.group(1) if rc_match else '?'} "
                f"remaining={remaining_match[-1] if remaining_match else '-'} timeout={timeout} failed_test_or_error={failure}"
            )
        lines.append("Inspect those logs before deciding whether to keep retrying worker unchanged.")
        return "\n".join(lines)

    def recent_worker_escalation_reason(self) -> str:
        if self.worker_stall_streak >= self.cfg.worker_stall_escalation_threshold:
            return f"stall-streak={self.worker_stall_streak}"
        logs = self.recent_worker_iteration_logs(limit=4)
        if not logs:
            return ""
        failed_tests: Counter[str] = Counter()
        saw_timeout = False
        for path in logs:
            text = path.read_text(encoding="utf-8", errors="replace")
            if "timeout" in path.name or "end rc=124" in text or "timed out" in text:
                saw_timeout = True
            for test_name in re.findall(r"^FAILED\s+(\S+)", text, re.MULTILINE):
                failed_tests[test_name] += 1
        repeated_test, repeated_count = failed_tests.most_common(1)[0] if failed_tests else ("", 0)
        if repeated_count >= 2:
            return f"repeated-failed-test={repeated_test}"
        if saw_timeout:
            return "recent-timeout"
        return ""

    def repeated_failed_test_name(self) -> str:
        logs = self.recent_worker_iteration_logs(limit=4)
        if not logs:
            return ""
        failed_tests: Counter[str] = Counter()
        for path in logs:
            text = path.read_text(encoding="utf-8", errors="replace")
            for test_name in re.findall(r"^FAILED\s+(\S+)", text, re.MULTILINE):
                failed_tests[test_name] += 1
        repeated_test, repeated_count = failed_tests.most_common(1)[0] if failed_tests else ("", 0)
        return repeated_test if repeated_count >= 2 else ""

    def worker_retry_out_of_packet_scope_reason(self) -> str:
        packet = self.current_task_packet_obj()
        if packet is None:
            return ""
        repeated_test = self.repeated_failed_test_name()
        if not repeated_test:
            return ""
        packet_text = packet.raw_text
        acceptance_tests = " ".join(packet.acceptance_tests)
        if repeated_test in packet_text or repeated_test in acceptance_tests:
            return ""
        short_name = repeated_test.split("::", 1)[-1]
        if short_name and (short_name in packet_text or short_name in acceptance_tests):
            return ""
        return f"repeated-failed-test-outside-packet={repeated_test}"

    def current_worker_model(self) -> str:
        self.refresh_runtime_overrides_from_state()
        if self.manual_worker_model_override:
            self.update_policy_decision(
                "manual_worker_model_override",
                "operator forced stronger worker model",
                model=self.manual_worker_model_override,
            )
            return self.manual_worker_model_override
        decision = decide_worker_runtime(
            WorkerRuntimeContext(
                escalation_reason=self.recent_worker_escalation_reason(),
                default_model=self.cfg.worker_model,
                escalated_model=self.cfg.worker_stall_model,
                default_failure_limit=self.cfg.max_consecutive_worker_failures,
                escalated_failure_limit=self.cfg.worker_stall_failure_limit,
                current_plan_item_stall_count=self.current_plan_item_stall_count,
            )
        )
        self.update_policy_decision(decision.name, decision.reason, **decision.details)
        for action in decision.actions:
            if action.name == "switch_worker_model":
                return str(action.details.get("model", self.cfg.worker_stall_model))
        return self.cfg.worker_model

    def current_worker_failure_limit(self) -> int:
        self.refresh_runtime_overrides_from_state()
        if self.manual_worker_failure_limit_override > 0:
            return self.manual_worker_failure_limit_override
        decision = decide_worker_runtime(
            WorkerRuntimeContext(
                escalation_reason=self.recent_worker_escalation_reason(),
                default_model=self.cfg.worker_model,
                escalated_model=self.cfg.worker_stall_model,
                default_failure_limit=self.cfg.max_consecutive_worker_failures,
                escalated_failure_limit=self.cfg.worker_stall_failure_limit,
                current_plan_item_stall_count=self.current_plan_item_stall_count,
            )
        )
        for action in decision.actions:
            if action.name in {"reduce_failure_limit", "use_default_failure_limit"}:
                try:
                    return int(action.details.get("failure_limit", self.cfg.max_consecutive_worker_failures))
                except (TypeError, ValueError):
                    break
        return self.cfg.max_consecutive_worker_failures

    def current_plan_item_requires_replan(self) -> bool:
        item = self.current_plan_item_text()
        if not item:
            return False
        return (
            self.plan_item_needs_split(item)
            or self.current_plan_item_stall_count >= 2
            or (self.plan_rewrite_target.strip() == item.strip() and bool(item.strip()))
        )

    def note_cycle_outcome(self, reviewer_remaining: str) -> None:
        decision = decide_cycle_followup(
            CycleOutcomeContext(
                reviewer_remaining=reviewer_remaining,
                worker_stalled=self.cycle_step_status("worker") == "stalled",
                current_plan_item_requires_replan=self.current_plan_item_requires_replan(),
                current_plan_item_stall_count=self.current_plan_item_stall_count,
            )
        )
        self.update_policy_decision(decision.name, decision.reason, **decision.details)
        if reviewer_remaining == "0":
            self.worker_stall_streak = 0
            self.current_plan_item = ""
            self.current_plan_item_stall_count = 0
            self.current_task_packet = {}
            self.current_task_packet_status = "done"
            self.next_cycle_start_step = None
            self.plan_rewrite_target = ""
            self.manual_worker_model_override = ""
            self.manual_worker_failure_limit_override = 0
            self.last_closeout_action = "stop"
            self._save_cycle_state()
            self.record_event(
                "cycle.outcome",
                "completed",
                "reviewer cleared all remaining steps",
                reviewer_remaining=reviewer_remaining,
            )
            return
        self.sync_current_plan_item()
        if self.cycle_step_status("worker") == "stalled":
            self.worker_stall_streak += 1
            self.current_plan_item_stall_count += 1
            if decision.primary_action() == "rewrite_current_item":
                self.next_cycle_start_step = "planner"
                self.plan_rewrite_target = self.current_plan_item
                self.last_closeout_action = "rewrite"
            else:
                self.next_cycle_start_step = "worker"
                self.plan_rewrite_target = ""
                self.last_closeout_action = "continue"
            self._save_cycle_state()
            self.log(
                f"Worker stalled with {reviewer_remaining} steps remaining; "
                f"next cycle will resume directly at {self.next_cycle_start_step} "
                f"(stall_streak={self.worker_stall_streak} item_stalls={self.current_plan_item_stall_count})"
            )
            if self.plan_rewrite_target:
                self.record_event(
                    "planner.rewrite_requested",
                    "warning",
                    "current plan item requires rewrite before more worker attempts",
                    failure_class="plan_item_too_broad",
                    reviewer_remaining=reviewer_remaining,
                    next_cycle_start_step=self.next_cycle_start_step,
                    stall_streak=self.worker_stall_streak,
                    current_plan_item_stalls=self.current_plan_item_stall_count,
                    rewrite_target=self.plan_rewrite_target,
                )
            self.record_event(
                "worker.stalled",
                "failed",
                "worker stalled; scheduled focused follow-up",
                failure_class="worker_no_progress",
                reviewer_remaining=reviewer_remaining,
                next_cycle_start_step=self.next_cycle_start_step,
                stall_streak=self.worker_stall_streak,
                current_plan_item_stalls=self.current_plan_item_stall_count,
                rewrite_target=self.plan_rewrite_target,
            )
            return
        self.worker_stall_streak = 0
        self.current_plan_item_stall_count = 0
        self.current_task_packet_status = ""
        self.next_cycle_start_step = None
        self.plan_rewrite_target = ""
        self.last_closeout_action = "continue"
        self._save_cycle_state()
        self.record_event(
            "cycle.outcome",
            "warning",
            "reviewer kept loop open",
            failure_class="reviewer_plan_mismatch",
            reviewer_remaining=reviewer_remaining,
        )

    def mark_cycle_step(self, step: str, status: str, extra: str = "") -> None:
        if self.cycle_state is None:
            return
        steps = self.cycle_state.setdefault("steps", {})
        if isinstance(steps, dict):
            steps[step] = {
                "status": status,
                "updated_at": self.iso_now(),
                "extra": extra,
            }
        if status == "done" and step == self.step_order[-1]:
            self.cycle_state["completed"] = True
        self._save_cycle_state()

    def maybe_self_restart(self, reason: str) -> bool:
        current = self._compute_script_checksums()
        if current == self.script_checksums:
            return False
        if self.cfg.self_restart_count >= self.cfg.max_self_restarts:
            self.die(f"Harness files changed during {reason}, but MAX_SELF_RESTARTS={self.cfg.max_self_restarts} was reached")
        self.capture_cycle_snapshot(f"restart-{reason}")
        self.write_status(
            "harness",
            "restarting",
            f"reason={reason} cycle={self.current_cycle_index} self_restart_count={self.cfg.self_restart_count + 1}",
        )
        self.log(f"Harness files changed during {reason}; restarting with updated code")
        self.record_event(
            "harness.restarting",
            "warning",
            "harness files changed; restarting",
            failure_class="restart_required",
            reason=reason,
            cycle=self.current_cycle_index,
            self_restart_count=self.cfg.self_restart_count + 1,
        )
        env = self.cfg.export_env()
        env["SELF_RESTART_COUNT"] = str(self.cfg.self_restart_count + 1)
        env["EVIDENCE_INPUT_FILES"] = "\n".join(self.cfg.evidence_input_files)
        os.execvpe(self.cfg.python_bin.as_posix(), [self.cfg.python_bin.as_posix(), "-m", "meta_harness", *self.cfg.original_args], env)

    def perform_maintenance(self, reason: str) -> None:
        sessions = load_jsonl(self.cfg.session_ledger_file, limit=max(50, self.cfg.maintenance_compaction_limit))
        history = load_jsonl(self.cfg.history_log_file, limit=max(50, self.cfg.maintenance_compaction_limit))
        summary = summarize_session_rows(sessions)
        failure_counts: Counter[str] = Counter()
        event_counts: Counter[str] = Counter()
        for row in history:
            event_counts[str(row.get("event", ""))] += 1
            failure_class = str(row.get("failure_class", "") or "")
            if failure_class:
                failure_counts[failure_class] += 1
        recommendations: list[str] = []
        if failure_counts.get("worker_timeout", 0) >= 2:
            recommendations.append("worker timeout pressure is high; prefer stronger model or smaller task packets")
        if summary.get("total_tokens") and isinstance(summary["total_tokens"], int) and summary["total_tokens"] > 200000:
            recommendations.append("recent token spend is high; tighten retry context and avoid repeated test reruns")
        compaction = compact_runtime_signals(history, sessions) if self.cfg.background_maintenance_enabled else {}
        payload = {
            "schema_version": "meta_harness.maintenance.v1",
            "updated_at": self.iso_now(),
            "reason": reason,
            "session_summary": summary,
            "event_counts": dict(event_counts),
            "failure_counts": dict(failure_counts),
            "recommendations": recommendations,
            "background_maintenance_enabled": self.cfg.background_maintenance_enabled,
            "compaction": compaction,
        }
        write_json(self.cfg.maintenance_file, payload)
        self.record_event(
            "cycle.outcome",
            "completed",
            "maintenance summary updated",
            reason=reason,
            recommendation_count=len(recommendations),
        )

    def maybe_run_scheduled_maintenance(self, cycles_run: int) -> bool:
        if not self.cfg.background_maintenance_enabled:
            return False
        interval = max(0, self.cfg.scheduled_maintenance_interval_cycles)
        if interval <= 0 or cycles_run <= 0 or cycles_run % interval != 0:
            return False
        self.record_event(
            "maintenance.scheduled",
            "warning",
            "running scheduled maintenance interval",
            interval_cycles=interval,
            cycles_run=cycles_run,
        )
        self.perform_maintenance("scheduled-cycle-interval")
        return True

    def refresh_runtime_overrides_from_state(self) -> None:
        state_file = self.cycle_state_file()
        if state_file is None or not state_file.exists():
            return
        payload = read_json(state_file)
        if not payload:
            return
        self.manual_worker_model_override = str(payload.get("manual_worker_model_override", self.manual_worker_model_override) or "")
        raw_manual_limit = payload.get("manual_worker_failure_limit_override", self.manual_worker_failure_limit_override)
        try:
            self.manual_worker_failure_limit_override = max(0, int(raw_manual_limit))
        except (TypeError, ValueError):
            pass
        packet = payload.get("last_completed_task_packet", self.last_completed_task_packet)
        if isinstance(packet, dict):
            self.last_completed_task_packet = packet
        committed_packets = payload.get("auto_committed_packets", self.auto_committed_packets)
        if isinstance(committed_packets, list):
            self.auto_committed_packets = [str(value) for value in committed_packets]

    def auto_commit_current_cycle(self) -> tuple[bool, str]:
        if not self.cfg.auto_commit_enabled:
            return False, "auto-commit disabled"
        if self.current_cycle_dir is None or self.cycle_state is None:
            return False, "no active cycle"
        if self.current_green_level not in {"cycle-green", "merge-safe-green"}:
            return False, f"green level {self.current_green_level or GREEN_RED} is below auto-commit threshold"
        if self.cfg.auto_commit_require_clean_start and not bool(self.cycle_state.get("git_clean_start", False)):
            return False, "cycle did not start from a clean worktree"
        status = self.git_status_porcelain().splitlines()
        if not status:
            return False, "no changes to commit"
        if any(line.startswith("?? ") for line in status):
            return False, "untracked files present; refusing broad auto-commit"
        add_rc = subprocess.run(
            ["git", "-C", str(self.cfg.root_dir), "add", "-u"],
            capture_output=True,
            text=True,
            check=False,
        ).returncode
        if add_rc != 0:
            return False, "git add -u failed"
        commit = subprocess.run(
            [
                "git",
                "-C",
                str(self.cfg.root_dir),
                "commit",
                "-m",
                f"meta_harness: cycle {self.current_cycle_index:03d} complete",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if commit.returncode != 0:
            return False, (commit.stderr or commit.stdout or "git commit failed").strip()
        return True, (commit.stdout or "commit created").strip()

    def auto_commit_current_packet(self) -> tuple[bool, str]:
        if not self.cfg.auto_commit_enabled:
            return False, "auto-commit disabled"
        if self.current_cycle_dir is None or self.cycle_state is None:
            return False, "no active cycle"
        packet = self.last_completed_task_packet if isinstance(self.last_completed_task_packet, dict) else {}
        packet_id = str(packet.get("item_id", "") or "")
        if not packet_id:
            return False, "no completed task packet available"
        if packet_id in self.auto_committed_packets:
            return False, f"task packet {packet_id} already auto-committed"
        if self.current_green_level not in {"focused-item-green", "cycle-green", "merge-safe-green"}:
            return False, f"green level {self.current_green_level or GREEN_RED} is below packet auto-commit threshold"
        if self.cfg.auto_commit_require_clean_start and not bool(self.cycle_state.get("git_clean_start", False)):
            return False, "cycle did not start from a clean worktree"
        status = self.git_status_porcelain().splitlines()
        if not status:
            return False, "no changes to commit"
        if any(line.startswith("?? ") for line in status):
            return False, "untracked files present; refusing broad auto-commit"
        target_files = packet.get("target_files", [])
        if not isinstance(target_files, list) or not target_files:
            return False, "task packet has no target files for scoped auto-commit"
        changed_paths = self.changed_tracked_paths()
        if not changed_paths:
            return False, "no tracked changes to commit"
        normalized_targets = {str(path) for path in target_files}
        unrelated = [path for path in changed_paths if path not in normalized_targets]
        if unrelated:
            return False, f"unrelated tracked changes present outside task packet scope: {', '.join(unrelated[:3])}"
        add_rc = subprocess.run(
            ["git", "-C", str(self.cfg.root_dir), "add", "-u", "--", *target_files],
            capture_output=True,
            text=True,
            check=False,
        ).returncode
        if add_rc != 0:
            return False, "git add -u failed"
        commit = subprocess.run(
            [
                "git",
                "-C",
                str(self.cfg.root_dir),
                "commit",
                "-m",
                f"meta_harness: packet {packet_id} complete",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if commit.returncode != 0:
            return False, (commit.stderr or commit.stdout or "git commit failed").strip()
        self.auto_committed_packets.append(packet_id)
        self._save_cycle_state()
        return True, (commit.stdout or "commit created").strip()

    def pause_requested_by_operator(self) -> dict[str, object]:
        self.cfg.stop_file.write_text("paused by web ui\n", encoding="utf-8")
        self.write_status("operator", "pause-requested", f"stop_file={self.cfg.stop_file}")
        self.record_event("operator.action_requested", "warning", "operator requested harness pause", closeout_action="pause")
        return {"ok": True, "action": "pause", "message": "pause requested"}

    def resume_requested_by_operator(self) -> dict[str, object]:
        self.cfg.stop_file.unlink(missing_ok=True)
        self.write_status("operator", "resume-requested", "stop-file-cleared")
        self.record_event("operator.action_requested", "ready", "operator cleared pause request", closeout_action="resume")
        return {"ok": True, "action": "resume", "message": "resume requested"}

    def request_planner_rewrite(self) -> dict[str, object]:
        self.sync_current_plan_item()
        self.plan_rewrite_target = self.current_plan_item_text()
        self.next_cycle_start_step = "planner"
        self.last_closeout_action = "rewrite"
        self.update_policy_decision(
            "operator_force_planner_rewrite",
            "operator requested planner rewrite for current task packet",
            rewrite_target=self.plan_rewrite_target,
        )
        self.record_event(
            "operator.action_requested",
            "warning",
            "operator requested planner rewrite",
            closeout_action="rewrite",
            rewrite_target=self.plan_rewrite_target,
        )
        self.record_event(
            "planner.rewrite_requested",
            "warning",
            "operator requested planner rewrite for current task packet",
            failure_class="plan_item_too_broad",
            rewrite_target=self.plan_rewrite_target,
        )
        self._save_cycle_state()
        return {"ok": True, "action": "force-planner-rewrite", "message": "planner rewrite queued"}

    def request_stronger_worker(self) -> dict[str, object]:
        self.manual_worker_model_override = self.cfg.worker_stall_model
        self.manual_worker_failure_limit_override = self.cfg.worker_stall_failure_limit
        self.update_policy_decision(
            "operator_force_stronger_worker",
            "operator requested stronger worker configuration",
            model=self.manual_worker_model_override,
            failure_limit=self.manual_worker_failure_limit_override,
        )
        self.record_event(
            "operator.action_requested",
            "warning",
            "operator forced stronger worker configuration",
            closeout_action="force-stronger-worker",
            model=self.manual_worker_model_override,
            failure_limit=self.manual_worker_failure_limit_override,
        )
        self._save_cycle_state()
        return {"ok": True, "action": "force-stronger-worker", "message": "stronger worker queued"}

    def run_background_maintenance(self) -> dict[str, object]:
        self.record_event(
            "operator.action_requested",
            "warning",
            "operator requested maintenance refresh",
            closeout_action="run-maintenance",
        )
        self.perform_maintenance("manual-ui-request")
        self.write_status("maintenance", "done", "manual-ui-request")
        return {"ok": True, "action": "run-maintenance", "message": "maintenance refreshed"}

    def finalize_run(self, reason: str, exit_code: int | None = None) -> None:
        if self.cycle_state is None:
            return
        status_text = self.cfg.status_file.read_text(encoding="utf-8", errors="replace") if self.cfg.status_file.exists() else ""
        if "status=done" in status_text or "status=stop-file-detected" in status_text or "status=restart-requested" in status_text:
            return
        current_step = self.current_cycle_step() or "cycle"
        step_state = self.cycle_state.get("steps", {})
        if isinstance(step_state, dict):
            for step, entry in step_state.items():
                if isinstance(entry, dict) and entry.get("status") == "running":
                    step_state[step] = {
                        "status": reason,
                        "updated_at": self.iso_now(),
                        "extra": f"exit_code={exit_code}" if exit_code is not None else "",
                    }
                    break
        self.cycle_state["completed"] = False
        self._save_cycle_state()
        self.write_status("harness", reason, f"cycle={self.current_cycle_index} step={current_step} exit_code={exit_code}")
        self.capture_cycle_snapshot(reason)

    def prepare_evidence_subset(self) -> None:
        if self.cfg.evidence_subset_dir.exists():
            shutil.rmtree(self.cfg.evidence_subset_dir, ignore_errors=True)
        self.cfg.evidence_subset_dir.mkdir(parents=True, exist_ok=True)
        for rel in self.cfg.evidence_input_files:
            src = self.cfg.root_dir / rel
            if not src.exists():
                self.die(f"Evidence input file missing: {src}")
            dst = self.cfg.evidence_subset_dir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.exists() or dst.is_symlink():
                dst.unlink()
            dst.symlink_to(src)

    def extract_remaining_steps(self, log_file: Path) -> str:
        text = log_file.read_text(encoding="utf-8", errors="replace") if log_file.exists() else ""
        for pat in (r"Global Remaining steps:\s*(\d+)", r"Remaining steps:\s*(\d+)"):
            match = re.search(pat, text)
            if match:
                return match.group(1)
        return ""

    def plan_remaining_steps(self) -> int | None:
        if not self.cfg.plan_path.exists():
            return None
        text = self.cfg.plan_path.read_text(encoding="utf-8", errors="replace")
        for pat in (r"Global Remaining steps:\s*(\d+)", r"Remaining steps:\s*(\d+)"):
            match = re.search(pat, text)
            if match:
                return int(match.group(1))

        capture = False
        numbered = 0
        unchecked = 0
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if re.match(r"^##+\s+Remaining steps\b", line, re.IGNORECASE):
                capture = True
                continue
            if capture and re.match(r"^##+\s+", line):
                break
            if not capture:
                continue
            if re.match(r"^\d+\.\s+\S", line):
                numbered += 1
            elif re.match(r"^[-*]\s+\[\s\]\s+\S", line):
                unchecked += 1

        if numbered or unchecked:
            return numbered + unchecked
        return None

    def plan_task_packets(self) -> list[TaskPacket]:
        if not self.cfg.plan_path.exists():
            return []
        return parse_plan_task_packets(self.cfg.plan_path.read_text(encoding="utf-8", errors="replace"))

    def plan_items(self) -> list[str]:
        if not self.cfg.plan_path.exists():
            return []
        lines = self.cfg.plan_path.read_text(encoding="utf-8", errors="replace").splitlines()
        items: list[str] = []
        current: list[str] = []
        for raw_line in lines:
            if re.match(r"^\d+\.\s+\S", raw_line):
                if current:
                    items.append("\n".join(current).strip())
                    current = []
                current.append(raw_line.rstrip())
                continue
            if not current:
                continue
            if raw_line.strip():
                current.append(raw_line.rstrip())
        if current:
            items.append("\n".join(current).strip())
        return [item for item in items if item]

    @staticmethod
    def _plan_item_is_finished(item: str) -> bool:
        first_line = item.splitlines()[0].strip() if item.strip() else ""
        match = re.match(r"^\d+\.\s+\[([^\]]+)\]", first_line)
        if not match:
            return False
        status = match.group(1).strip().lower()
        return status.startswith("completed") or status == "superseded"

    def unfinished_plan_items(self) -> list[str]:
        return [item for item in self.plan_items() if not self._plan_item_is_finished(item)]

    def first_plan_item_text(self) -> str:
        items = self.unfinished_plan_items() or self.plan_items()
        return items[0] if items else ""

    def current_plan_item_text(self) -> str:
        items = self.unfinished_plan_items() or self.plan_items()
        if not items:
            return ""
        if self.current_plan_item and self.current_plan_item in items:
            return self.current_plan_item
        return items[0]

    def current_task_packet_obj(self) -> TaskPacket | None:
        packets = self.plan_task_packets()
        if not packets:
            return None
        current_item = self.current_plan_item_text()
        for packet in packets:
            if packet.raw_text == current_item:
                return packet
        return packets[0]

    def current_task_packet_block(self) -> str:
        packet = self.current_task_packet_obj()
        return packet.to_prompt_block() if packet is not None else ""

    def _sync_current_task_packet(self) -> None:
        packet = self.current_task_packet_obj()
        self.current_task_packet = packet.to_dict() if packet is not None else {}

    def plan_item_needs_split(self, item: str) -> bool:
        if not item.strip():
            return False
        lines = [line for line in item.splitlines() if line.strip()]
        code_refs = item.count("`")
        return len(lines) > 3 or len(item) > 1200 or code_refs > 18

    def sync_current_plan_item(self, *, reset_stall_count: bool = False) -> str:
        next_item = self.current_plan_item_text()
        if next_item != self.current_plan_item:
            self.current_plan_item = next_item
            self.current_plan_item_stall_count = 0
        elif reset_stall_count:
            self.current_plan_item_stall_count = 0
        if not next_item:
            self.current_plan_item = ""
            self.current_plan_item_stall_count = 0
        self._sync_current_task_packet()
        self._save_cycle_state()
        return self.current_plan_item

    def build_worker_retry_context(self, limit: int = 3) -> str:
        logs = self.recent_worker_iteration_logs(limit=limit)
        if not logs:
            return ""
        failed_tests: Counter[str] = Counter()
        lines: list[str] = []
        for path in logs:
            text = path.read_text(encoding="utf-8", errors="replace")
            status_bits: list[str] = []
            if "timeout" in path.name or "end rc=124" in text or "timed out" in text:
                status_bits.append("timeout")
            if "FAILED " in text or "failed" in text.lower():
                status_bits.append("failed-test-or-error")
            for test_name in re.findall(r"^FAILED\s+(\S+)", text, re.MULTILINE):
                failed_tests[test_name] += 1
            if status_bits:
                lines.append(f"- {path.name}: {', '.join(status_bits)}")
        repeated_test, repeated_count = failed_tests.most_common(1)[0] if failed_tests else ("", 0)
        if repeated_count >= 2:
            lines.append(f"- repeated failing test: {repeated_test} ({repeated_count} times)")
        deduped: list[str] = []
        for line in lines:
            if line not in deduped:
                deduped.append(line)
        return "\n".join(deduped[:6])

    def _normalize_worker_progress_text(self, text: str) -> str:
        normalized_lines: list[str] = []
        skip_next_numeric_line = False
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if skip_next_numeric_line and re.fullmatch(r"[\d,]+", line):
                skip_next_numeric_line = False
                continue
            skip_next_numeric_line = False
            if line.startswith("[") and (" start " in line or " end rc=" in line):
                continue
            if line.startswith("session id: "):
                continue
            if line == "tokens used":
                skip_next_numeric_line = True
                continue
            if re.match(r"- worker\.iter\d+", line):
                normalized_lines.append("- worker.iterN.log: prior-attempt")
                continue
            normalized_lines.append(line)
        return "\n".join(normalized_lines)

    def worker_iteration_is_repeated_no_progress(self, log_file: Path, *, threshold: int = 3) -> bool:
        if self.current_cycle_dir is None or threshold <= 1 or not log_file.exists():
            return False
        current_text = self._normalize_worker_progress_text(log_file.read_text(encoding="utf-8", errors="replace"))
        if not current_text:
            return False
        recent_logs = self.recent_worker_iteration_logs(limit=threshold - 1)
        if len(recent_logs) < threshold - 1:
            return False
        normalized_recent = [
            self._normalize_worker_progress_text(path.read_text(encoding="utf-8", errors="replace")) for path in recent_logs
        ]
        if any(not text for text in normalized_recent):
            return False
        return all(text == current_text for text in normalized_recent)

    def build_worker_focus_context(self) -> str:
        parts: list[str] = []
        current_packet = self.current_task_packet_block()
        if current_packet:
            parts.append("Primary task packet:\n" + current_packet)
        retry_context = self.build_worker_retry_context()
        if retry_context:
            parts.append("Recent retry context:\n" + retry_context)
        return "\n\n".join(parts)

    def update_policy_decision(self, decision_name: str, reason: str, **details: object) -> None:
        self.last_policy_decision = {
            "decision": decision_name,
            "reason": reason,
            "details": details,
            "updated_at": self.iso_now(),
        }
        self._save_cycle_state()

    def extract_green_level(self, log_file: Path) -> str:
        text = log_file.read_text(encoding="utf-8", errors="replace") if log_file.exists() else ""
        match = re.search(r"Green level:\s*([A-Za-z0-9_-]+)", text)
        return match.group(1).strip().lower() if match else ""

    def extract_task_packet_status(self, log_file: Path) -> str:
        text = log_file.read_text(encoding="utf-8", errors="replace") if log_file.exists() else ""
        match = re.search(r"Task packet status:\s*(done|partial|blocked|rewrite)", text, re.IGNORECASE)
        return match.group(1).strip().lower() if match else ""

    def save_role_markers(self, role: str, log_file: Path, remaining: str | None = None) -> None:
        if remaining is not None:
            (self.cfg.state_dir / f"{role}.remaining").write_text(remaining + "\n", encoding="utf-8")
        (self.cfg.state_dir / f"{role}.lastlog").write_text(str(log_file) + "\n", encoding="utf-8")

    def last_role_log_file(self, role: str) -> str:
        path = self.cfg.state_dir / f"{role}.lastlog"
        return path.read_text(encoding="utf-8").strip() if path.exists() else ""

    def _reset_oversized_worker_resume_session(self, role: str, resume: bool) -> bool:
        if role != "worker" or not resume:
            return False
        session_file = self.role_session_file(role)
        if not session_file.exists():
            return False
        max_bytes = self.cfg.max_worker_session_log_bytes
        if max_bytes <= 0:
            return False
        previous_log = self.last_role_log_file(role)
        if not previous_log:
            return False
        log_path = Path(previous_log)
        if not log_path.exists():
            return False
        log_size = log_path.stat().st_size
        if log_size <= max_bytes:
            return False
        self.log(
            f"Discarding {role} session before resume because {log_path.name} reached "
            f"{log_size} bytes (limit {max_bytes})"
        )
        self.clear_role_session(role)
        self.write_status(
            role,
            "restarting-fresh-context",
            f"previous_log={log_path.name} size={log_size} limit={max_bytes}",
        )
        return True

    def _run_llm_attempt(self, role: str, model: str, prompt: str, resume: bool = False) -> Path:
        provider = self.llm_cfg.provider_for_key(role)
        prompt_file = self.cfg.prompt_dir / f"{role}.prompt.txt"
        log_file = self.cfg.log_dir / f"{self.timestamp()}_{role}.log"
        session_file = self.role_session_file(role)
        previous_log = self.last_role_log_file(role)
        started = time.monotonic()
        mode = "new"

        def _raise_role_error(message: str, exit_code: int | None = None) -> None:
            if log_file.exists():
                shutil.copy2(log_file, self.cfg.last_log_file)
                self.save_role_markers(role, log_file)
                self.record_role_session(
                    role=role,
                    provider=provider,
                    model=model,
                    mode=mode,
                    log_file=log_file,
                    exit_code=exit_code,
                    duration_secs=max(0, int(time.monotonic() - started)),
                    outcome="error",
                )
            self.record_event(
                "role.failed",
                "failed",
                f"{role} failed",
                failure_class="provider_failure",
                role=role,
                provider=provider,
                model=model,
                mode=mode,
                exit_code=exit_code,
            )
            raise RoleRunError(role, log_file, message, exit_code=exit_code)

        prompt_file.write_text(prompt, encoding="utf-8")
        effective = build_effective_prompt(role, provider, prompt, self.llm_cfg, previous_log)
        prompt_file.write_text(effective, encoding="utf-8")
        mode = "resume" if resume and backend_supports_sessions(provider) and session_file.exists() else "new"
        self.write_status(role, "running", f"provider={provider} model={model} log={log_file.name}")
        self.log(f"Starting {role} with {provider}/{model}{' via resume' if mode == 'resume' else ''}")
        self.record_event(
            "role.started",
            "running",
            f"starting {role}",
            role=role,
            provider=provider,
            model=model,
            mode=mode,
            log=log_file.name,
        )
        heartbeat = self._start_status_heartbeat(role, "running", f"provider={provider} model={model} log={log_file.name}")

        try:
            if mode == "resume":
                session_id = session_file.read_text(encoding="utf-8").strip()
                rc = run_provider_once(provider, "resume", model, effective, prompt_file, log_file, self.llm_cfg, session_id)
                if rc != 0:
                    _raise_role_error(f"{role} resume failed", exit_code=rc)
            else:
                max_attempts = self.llm_cfg.local_model_max_retries + 1 if provider in {"ollama", "llamacpp"} else 1
                for attempt in range(1, max_attempts + 1):
                    rc = run_provider_once(provider, "new", model, effective, prompt_file, log_file, self.llm_cfg)
                    if rc == 0 and validate_output(role, provider, log_file, self.llm_cfg):
                        break
                    if provider not in {"ollama", "llamacpp"}:
                        _raise_role_error(f"{role} failed", exit_code=rc)
                    self.log(f"{role} produced invalid output via {provider}/{model}; retry {attempt}/{self.llm_cfg.local_model_max_retries}")
                else:
                    fallback_provider = self.llm_cfg.local_model_fallback_provider
                    fallback_model = self.llm_cfg.local_model_fallback_model
                    if fallback_provider and fallback_model:
                        effective = build_effective_prompt(
                            role,
                            fallback_provider,
                            prompt + "\n\nFallback instruction:\n" + self.llm_cfg.local_model_fallback_context,
                            self.llm_cfg,
                            previous_log,
                        )
                        prompt_file.write_text(effective, encoding="utf-8")
                        rc = run_provider_once(fallback_provider, "new", fallback_model, effective, prompt_file, log_file, self.llm_cfg)
                        provider = fallback_provider
                        if rc != 0 or not validate_output(role, provider, log_file, self.llm_cfg):
                            _raise_role_error(f"{role} failed after retries", exit_code=rc)
                    else:
                        _raise_role_error(f"{role} failed after retries", exit_code=rc)
        finally:
            if heartbeat is not None:
                stop_event, thread = heartbeat
                stop_event.set()
                thread.join(timeout=max(1.0, float(self.cfg.status_heartbeat_secs)))

        shutil.copy2(log_file, self.cfg.last_log_file)
        text = log_file.read_text(encoding="utf-8", errors="replace")
        session_id = extract_session_id(text)
        if session_id:
            session_file.write_text(session_id + "\n", encoding="utf-8")
        self.write_status(role, "done", f"provider={provider} log={log_file.name}")
        self.record_role_session(
            role=role,
            provider=provider,
            model=model,
            mode=mode,
            log_file=log_file,
            exit_code=0,
            duration_secs=max(0, int(time.monotonic() - started)),
            outcome="done",
        )
        self.record_event(
            "role.finished",
            "completed",
            f"finished {role}",
            role=role,
            provider=provider,
            model=model,
            mode=mode,
            log=log_file.name,
        )
        self.trim_old_logs()
        return log_file

    def run_role(self, role: str, model: str, prompt: str, resume: bool = False, *, resume_context: str = "") -> Path:
        comments = self.consume_operator_comments(role)
        provider = self.llm_cfg.provider_for_key(role)
        if backend_supports_sessions(provider):
            self._reset_oversized_worker_resume_session(role, resume)
        session_file = self.role_session_file(role)
        if (
            resume
            and self.cfg.delta_resume_prompts
            and backend_supports_sessions(provider)
            and session_file.exists()
        ):
            effective_prompt = build_resume_prompt(role, self.cfg, comments=comments, role_context=resume_context)
        else:
            effective_prompt = prompt
            if comments:
                effective_prompt += (
                    "\n\nOperator comments to apply now:\n"
                    "Treat these as highest-priority human guidance for this step.\n"
                    f"{comments}\n"
                )
        return self._run_llm_attempt(role, model, effective_prompt, resume=resume)

    def _handle_worker_timeout(
        self,
        iteration: int,
        exc: RoleRunError,
        *,
        resumed: bool,
        consecutive_failures: int,
        failure_limit: int,
    ) -> int:
        suffix = "resume-timeout" if resumed else "timeout"
        self.capture_cycle_artifact(exc.log_file, f"worker.iter{iteration:02d}.{suffix}.log")
        self.clear_role_session("worker")
        consecutive_failures += 1
        self.log(
            f"Worker iteration {iteration} timed out"
            f"{' during resume' if resumed else ''}; retrying next iteration with fresh context"
        )
        self.write_status(
            "worker",
            "retrying-after-timeout",
            f"iteration={iteration} exit_code={exc.exit_code} consecutive_failures={consecutive_failures}",
        )
        self.record_event(
            "role.timed_out",
            "retrying",
            "worker iteration timed out",
            failure_class="worker_timeout",
            role="worker",
            iteration=iteration,
            resumed=resumed,
            exit_code=exc.exit_code,
            consecutive_failures=consecutive_failures,
            failure_limit=failure_limit,
        )
        timeout_decision = decide_worker_timeout(
            WorkerTimeoutContext(consecutive_failures=consecutive_failures, failure_limit=failure_limit)
        )
        self.update_policy_decision(timeout_decision.name, timeout_decision.reason)
        if timeout_decision.primary_action() == "escalate_to_reviewer":
            self.log(
                f"Worker stalled after {consecutive_failures} consecutive timeouts/failures; handing control to reviewer"
            )
            self.mark_cycle_step(
                "worker",
                "stalled",
                f"iteration={iteration} consecutive_failures={consecutive_failures} exit_code={exc.exit_code}",
            )
            return consecutive_failures
        self.mark_cycle_step(
            "worker",
            "running",
            f"iteration={iteration} consecutive_failures={consecutive_failures} exit_code={exc.exit_code}",
        )
        return consecutive_failures

    def sweep_step(self) -> None:
        self.check_stop_file()
        self.preflight_resource_check("full-sweep")
        self.mark_cycle_step("full-sweep", "running", f"phase=preparing-subset log={self.cfg.evidence_log_file.name}")
        self.prepare_evidence_subset()
        self.write_status("full-sweep", "running", f"phase=preparing-subset log={self.cfg.evidence_log_file.name}")
        self.log(f"Starting {self.cfg.sweep_label}")
        self.record_event(
            "sweep.started",
            "running",
            "starting evidence sweep",
            label=self.cfg.sweep_label,
            log=self.cfg.evidence_log_file.name,
        )
        self.write_status("full-sweep", "running", f"phase=executing log={self.cfg.evidence_log_file.name}")
        self.mark_cycle_step("full-sweep", "running", f"phase=executing log={self.cfg.evidence_log_file.name}")
        env = self.cfg.export_env()
        env["EVIDENCE_INPUT_FILES"] = "\n".join(self.cfg.evidence_input_files)
        env["EVIDENCE_SUBSET_DIR"] = str(self.cfg.evidence_subset_dir)
        header = f"[{self.iso_now()}] start sweep={self.cfg.sweep_label} root={self.cfg.root_dir}\n"
        cmd = [
            "timeout",
            "--foreground",
            f"{self.cfg.codex_timeout_secs}s",
            "bash",
            "-lc",
            self.cfg.sweep_cmd,
        ]
        retry_reason = ""
        self.cfg.last_log_file.parent.mkdir(parents=True, exist_ok=True)
        with (
            self.cfg.evidence_log_file.open("w", encoding="utf-8") as out,
            self.cfg.last_log_file.open("w", encoding="utf-8") as mirror,
        ):
            for fp in (out, mirror):
                fp.write(header)
                fp.flush()
            rc = self._run_logged_sweep_command(cmd, env, out, mirror)
            log_text = self.cfg.evidence_log_file.read_text(encoding="utf-8", errors="replace")
            if rc != 0 and self._SWEEP_THREAD_EXHAUSTION_MARKER in log_text:
                retry_reason = "thread-start failure; retrying full sweep with forced serial function decompilation"
                retry_header = f"[{self.iso_now()}] retry reason={retry_reason}\n"
                for fp in (out, mirror):
                    fp.write(retry_header)
                    fp.flush()
                retry_env = dict(env)
                retry_env["INERTIA_FORCE_SERIAL_FUNCTION_DECOMPILATION"] = "1"
                rc = self._run_logged_sweep_command(cmd, retry_env, out, mirror)
        footer = f"[{self.iso_now()}] end rc={rc}\n"
        with (
            self.cfg.evidence_log_file.open("a", encoding="utf-8") as out,
            self.cfg.last_log_file.open("a", encoding="utf-8") as mirror,
        ):
            for fp in (out, mirror):
                fp.write(footer)
                fp.flush()
        log_text = self.cfg.evidence_log_file.read_text(encoding="utf-8", errors="replace") if self.cfg.evidence_log_file.exists() else ""
        completed_sweep = "done in" in log_text
        if retry_reason:
            self.record_event(
                "sweep.finished",
                "warning",
                retry_reason,
                failure_class="sweep_failure",
                retry_mode="forced_serial_function_decompilation",
            )
        if rc != 0 and completed_sweep:
            self.log(f"{self.cfg.sweep_label} completed with non-zero rc={rc}; continuing because evidence was produced")
            self.record_event(
                "sweep.finished",
                "warning",
                "evidence sweep completed with failures",
                failure_class="sweep_failure",
                rc=rc,
                completed_sweep=completed_sweep,
            )
            if self.cfg.evidence_log_file.exists():
                shutil.copy2(self.cfg.evidence_log_file, self.cfg.last_log_file)
            self.write_status("full-sweep", "done-with-failures", f"log={self.cfg.evidence_log_file.name} rc={rc}")
            self.mark_cycle_step("full-sweep", "done-with-failures", f"rc={rc}")
            self.capture_cycle_artifact(self.cfg.evidence_log_file, "evidence_sweep.log")
            self.capture_cycle_snapshot("sweep")
            self.trim_old_logs()
            return
        if rc != 0:
            self.record_event(
                "sweep.failed",
                "failed",
                "evidence sweep failed",
                failure_class="sweep_failure",
                rc=rc,
                completed_sweep=completed_sweep,
            )
            if self.cfg.evidence_log_file.exists():
                shutil.copy2(self.cfg.evidence_log_file, self.cfg.last_log_file)
            self.write_status("full-sweep", "failed", f"see {self.cfg.evidence_log_file.name}")
            self.mark_cycle_step("full-sweep", "failed", f"rc={rc}")
            self.die(f"{self.cfg.sweep_label} failed")
        self.record_event(
            "sweep.finished",
            "completed",
            "evidence sweep completed",
            rc=rc,
            log=self.cfg.evidence_log_file.name,
        )
        shutil.copy2(self.cfg.evidence_log_file, self.cfg.last_log_file)
        self.write_status("full-sweep", "done", f"log={self.cfg.evidence_log_file.name}")
        self.mark_cycle_step("full-sweep", "done", f"log={self.cfg.evidence_log_file.name}")
        self.capture_cycle_artifact(self.cfg.evidence_log_file, "evidence_sweep.log")
        self.capture_cycle_snapshot("sweep")
        self.trim_old_logs()

    def _run_logged_sweep_command(self, cmd: list[str], env: dict[str, str], out, mirror) -> int:
        proc = subprocess.Popen(
            cmd,
            cwd=self.cfg.root_dir,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        register_child_process(self.cfg.state_dir, proc.pid, self.cfg.sweep_cmd, str(self.cfg.root_dir), self.iso_now())
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                for fp in (out, mirror):
                    fp.write(line)
                    fp.flush()
            return proc.wait()
        finally:
            unregister_child_process(self.cfg.state_dir, proc.pid)

    def checker_step(self) -> None:
        self.check_stop_file()
        self.preflight_resource_check("checker")
        self.mark_cycle_step("checker", "running")
        log_file = self.run_role("checker", self.cfg.checker_model, build_checker_prompt(self.cfg))
        remaining = self.extract_remaining_steps(log_file)
        if not remaining:
            self.die("Checker did not print remaining step count")
        self.save_role_markers("checker", log_file, remaining)
        self.capture_cycle_artifact(log_file, "checker.log")
        self.mark_cycle_step("checker", "done", f"remaining={remaining}")
        self.capture_cycle_snapshot("checker")

    def planner_step(self) -> None:
        self.check_stop_file()
        self.preflight_resource_check("planner")
        self.mark_cycle_step("planner", "running")
        log_file = self.run_role(
            "planner",
            self.cfg.planner_model,
            build_planner_prompt(
                self.cfg,
                current_item=self.current_plan_item_text(),
                rewrite_target=self.plan_rewrite_target,
                task_packet=self.current_task_packet_block(),
            ),
        )
        remaining = self.extract_remaining_steps(log_file)
        if not remaining:
            self.die("Planner did not print remaining step count")
        if remaining == "0":
            print("Global Remaining steps: 0")
            raise SystemExit(0)
        if not self.cfg.plan_path.exists():
            self.die(f"Planner did not create or update {self.cfg.plan_path}")
        self.sync_current_plan_item(reset_stall_count=True)
        self.plan_rewrite_target = ""
        self.current_task_packet_status = ""
        self.current_green_level = GREEN_RED
        self.save_role_markers("planner", log_file, remaining)
        self.capture_cycle_artifact(log_file, "planner.log")
        self.mark_cycle_step("planner", "done", f"remaining={remaining}")
        self.capture_cycle_snapshot("planner")

    def worker_cycle(self) -> None:
        self.mark_cycle_step("worker", "running")
        consecutive_failures = 0
        for i in range(1, self.cfg.max_worker_iters + 1):
            self.check_stop_file()
            self.preflight_resource_check("worker")
            packet_scope_reason = self.worker_retry_out_of_packet_scope_reason()
            if packet_scope_reason:
                self.plan_rewrite_target = self.current_plan_item_text()
                self.current_task_packet_status = "rewrite"
                self.update_policy_decision(
                    "worker_out_of_packet_scope",
                    "recent worker retries drifted outside the current task packet scope",
                    reason_detail=packet_scope_reason,
                    current_plan_item=self.current_plan_item_text(),
                )
                self.mark_cycle_step("worker", "stalled", f"iteration={i} {packet_scope_reason}")
                self.log(
                    "Worker retry context drifted outside the current task packet; "
                    f"routing back to planner ({packet_scope_reason})"
                )
                self.record_event(
                    "worker.stalled",
                    "failed",
                    "worker retries drifted outside the current task packet scope",
                    failure_class="worker_no_progress",
                    iteration=i,
                    packet_scope_reason=packet_scope_reason,
                    rewrite_target=self.plan_rewrite_target,
                )
                return
            worker_model = self.current_worker_model()
            failure_limit = self.current_worker_failure_limit()
            escalation_reason = self.recent_worker_escalation_reason()
            worker_focus_context = self.build_worker_focus_context()
            self.log(
                f"Worker iteration {i}/{self.cfg.max_worker_iters}"
                f" model={worker_model} failure_limit={failure_limit}"
                f"{f' escalation={escalation_reason}' if escalation_reason else ''}"
            )
            try:
                log_file = self.run_role(
                    "worker",
                    worker_model,
                    build_worker_prompt(
                        self.cfg,
                        focus_item=self.current_plan_item_text(),
                        retry_context=self.build_worker_retry_context(),
                        task_packet=self.current_task_packet_block(),
                    ),
                    resume=True,
                    resume_context=worker_focus_context,
                )
            except HarnessError as exc:
                if isinstance(exc, RoleRunError):
                    if exc.exit_code in self.graceful_exit_codes:
                        consecutive_failures = self._handle_worker_timeout(
                            i,
                            exc,
                            resumed=True,
                            consecutive_failures=consecutive_failures,
                            failure_limit=failure_limit,
                        )
                        if consecutive_failures >= failure_limit:
                            return
                        time.sleep(self.cfg.worker_sleep_secs)
                        continue
                    self.capture_cycle_artifact(exc.log_file, f"worker.iter{i:02d}.resume-failed.log")
                self.clear_role_session("worker")
                try:
                    log_file = self.run_role(
                        "worker",
                        worker_model,
                        build_worker_prompt(
                            self.cfg,
                            focus_item=self.current_plan_item_text(),
                            retry_context=self.build_worker_retry_context(),
                            task_packet=self.current_task_packet_block(),
                        ),
                        resume=False,
                        resume_context=worker_focus_context,
                    )
                except HarnessError as final_exc:
                    failed_log = final_exc.log_file if isinstance(final_exc, RoleRunError) else None
                    if isinstance(final_exc, RoleRunError) and final_exc.exit_code in self.graceful_exit_codes:
                        consecutive_failures = self._handle_worker_timeout(
                            i,
                            final_exc,
                            resumed=False,
                            consecutive_failures=consecutive_failures,
                            failure_limit=failure_limit,
                        )
                        if consecutive_failures >= failure_limit:
                            return
                        time.sleep(self.cfg.worker_sleep_secs)
                        continue
                    if failed_log is not None:
                        self.capture_cycle_artifact(failed_log, f"worker.iter{i:02d}.failed.log")
                    consecutive_failures += 1
                    self.log(f"Worker iteration {i} failed: {final_exc}")
                    self.write_status("worker", "retrying-after-error", f"iteration={i} error={final_exc}")
                    if consecutive_failures >= failure_limit:
                        self.log(
                            f"Worker stalled after {consecutive_failures} consecutive failures; handing control to reviewer"
                        )
                        self.mark_cycle_step(
                            "worker",
                            "stalled",
                            f"iteration={i} consecutive_failures={consecutive_failures} error={final_exc}",
                        )
                        return
                    self.mark_cycle_step(
                        "worker",
                        "running",
                        f"iteration={i} consecutive_failures={consecutive_failures} error={final_exc}",
                    )
                    time.sleep(self.cfg.worker_sleep_secs)
                    continue
            remaining = self.extract_remaining_steps(log_file)
            reported_green = self.extract_green_level(log_file)
            green_decision = decide_green_level(
                GreenLevelContext(
                    worker_remaining=remaining,
                    worker_reported_green=reported_green,
                )
            )
            for action in green_decision.actions:
                if action.name == "set_green_level":
                    self.current_green_level = str(action.details.get("green_level", GREEN_RED))
                    break
            if not remaining:
                self.die("Worker did not print remaining step count")
            consecutive_failures = 0
            repeated_no_progress = self.worker_iteration_is_repeated_no_progress(log_file)
            self.save_role_markers("worker", log_file, remaining)
            self.capture_cycle_artifact(log_file, f"worker.iter{i:02d}.log")
            self.capture_cycle_snapshot(f"worker-iter{i:02d}")
            if self.cfg.worker_finish_token in log_file.read_text(encoding="utf-8", errors="replace"):
                plan_remaining = self.plan_remaining_steps()
                if plan_remaining is not None and plan_remaining > 0:
                    self.log(
                        f"Worker reported 0 remaining steps but {self.cfg.plan_path.name} still has {plan_remaining}; "
                        "discarding worker session and retrying fresh"
                    )
                    self.clear_role_session("worker")
                    self.write_status(
                        "worker",
                        "retrying-after-mismatch",
                        f"iteration={i} worker_remaining=0 plan_remaining={plan_remaining}",
                    )
                    self.mark_cycle_step("worker", "running", f"iteration={i} mismatch plan_remaining={plan_remaining}")
                    time.sleep(self.cfg.worker_sleep_secs)
                    continue
                self.mark_cycle_step("worker", "done", f"remaining={remaining}")
                return
            if repeated_no_progress:
                self.clear_role_session("worker")
                self.log(
                    f"Worker iteration {i} repeated the same non-zero result across recent attempts; "
                    "marking worker stalled for reviewer follow-up"
                )
                self.write_status("worker", "stalled-no-progress", f"iteration={i} repeated_nonzero_result")
                self.mark_cycle_step("worker", "stalled", f"iteration={i} repeated_nonzero_result")
                return
            time.sleep(self.cfg.worker_sleep_secs)
        self.clear_role_session("worker")
        self.log(
            f"Worker reached MAX_WORKER_ITERS={self.cfg.max_worker_iters} with non-zero remaining work; "
            "marking worker stalled for reviewer follow-up"
        )
        self.write_status(
            "worker",
            "stalled-max-iters",
            f"iterations={self.cfg.max_worker_iters} remaining={remaining}",
        )
        self.mark_cycle_step(
            "worker",
            "stalled",
            f"iteration={self.cfg.max_worker_iters} max_worker_iters_exhausted remaining={remaining}",
        )
        self.record_event(
            "worker.stalled",
            "failed",
            "worker exhausted max iterations; scheduled reviewer follow-up",
            failure_class="worker_no_progress",
            remaining=remaining,
            max_worker_iters=self.cfg.max_worker_iters,
        )
        return

    def reviewer_step(self) -> str:
        self.check_stop_file()
        self.preflight_resource_check("reviewer")
        self.mark_cycle_step("reviewer", "running")
        completed_packet = self.current_task_packet_obj()
        log_file = self.run_role(
            "reviewer",
            self.cfg.reviewer_model,
            build_reviewer_prompt(
                self.cfg,
                stall_context=self.build_worker_stall_context(),
                task_packet=self.current_task_packet_block(),
            ),
        )
        remaining = self.extract_remaining_steps(log_file)
        if not remaining:
            self.die("Reviewer did not print remaining step count")
        self.current_task_packet_status = self.extract_task_packet_status(log_file)
        if self.current_task_packet_status == "done" and completed_packet is not None:
            self.last_completed_task_packet = completed_packet.to_dict()
        reported_green = self.extract_green_level(log_file)
        green_decision = decide_green_level(
            GreenLevelContext(
                reviewer_remaining=remaining,
                evidence_failures=self.evidence_failure_count() or 0,
                reviewer_reported_green=reported_green,
            )
        )
        for action in green_decision.actions:
            if action.name == "set_green_level":
                self.current_green_level = str(action.details.get("green_level", GREEN_RED))
                break
        self.update_policy_decision(
            green_decision.name,
            green_decision.reason,
            green_level=self.current_green_level,
            task_packet_status=self.current_task_packet_status,
        )
        self.sync_current_plan_item()
        self.save_role_markers("reviewer", log_file, remaining)
        self.capture_cycle_artifact(log_file, "reviewer.log")
        self.mark_cycle_step("reviewer", "done", f"remaining={remaining}")
        self.capture_cycle_snapshot("reviewer")
        return remaining

    def run_crash_review(self, exit_code: int) -> None:
        if self.crash_review_active:
            return
        self.crash_review_active = True
        try:
            log_file = self.run_role(
                "crash-reviewer",
                self.cfg.crash_reviewer_model,
                build_crash_reviewer_prompt(self.cfg, str(self.current_cycle_dir), exit_code),
            )
        except Exception:
            return
        self.capture_cycle_artifact(log_file, "crash-reviewer.log")
        self.capture_cycle_snapshot("crash-reviewer")
        if "Harness restart required" in log_file.read_text(encoding="utf-8", errors="replace"):
            self.write_status("crash-reviewer", "restart-requested", f"log={log_file.name}")
            self.maybe_self_restart("crash-reviewer")

    def run(self, resume: bool = False) -> int:
        self.ensure_prereqs()
        self.acquire_lock()
        cleanup_stale_child_processes(self.cfg.state_dir, self.cfg.root_dir)
        if not resume:
            self.prime_next_cycle_handoff_from_latest_cycle()
        self.write_status("startup", "ready", f"timeout={self.cfg.codex_timeout_secs}s")
        cycles_run = 0
        while True:
            start_step = self.resume_latest_cycle() if resume else None
            if start_step is None:
                self.prepare_cycle_workspace()
                start_step = self.next_cycle_start_step or self.step_order[0]
                self.next_cycle_start_step = None
                self.write_status("cycle", "fresh", f"cycle={self.current_cycle_index} start={start_step}")
            else:
                self.write_status("cycle", "resumed", f"cycle={self.current_cycle_index} start={start_step}")
            self.sync_current_plan_item()
            if start_step == "worker" and self.current_plan_item_requires_replan():
                self.plan_rewrite_target = self.current_plan_item_text()
                start_step = "planner"
                self.update_policy_decision(
                    "rewrite_current_item",
                    "start step rerouted through planner because current item requires replan",
                    next_cycle_start_step=start_step,
                    current_plan_item=self.current_plan_item,
                )
                self._save_cycle_state()
                self.log("Current plan item is too broad or repeatedly stalled; routing cycle through planner first")
            self.capture_cycle_snapshot("cycle-start")
            self.check_stop_file()
            start_idx = self.step_order.index(start_step)
            if start_idx <= 0:
                self.sweep_step()
            if start_idx <= 1:
                self.checker_step()
            if start_idx <= 2:
                self.planner_step()
            if start_idx <= 3:
                self.worker_cycle()
            remaining = self.reviewer_step()
            self.log(f"Reviewer says {remaining} steps remain")
            evidence_failures = self.evidence_failure_count()
            if remaining == "0" and evidence_failures and evidence_failures > 0:
                self.log(
                    f"Reviewer reported 0 remaining steps but {self.cfg.evidence_log_file.name} "
                    f"still reports failures={evidence_failures}; keeping the loop open"
                )
                self.write_status(
                    "reviewer",
                    "evidence-failures-remain",
                    f"reviewer_remaining=0 evidence_failures={evidence_failures}",
                )
                self.mark_cycle_step(
                    "reviewer",
                    "done",
                    f"remaining=0 evidence_failures={evidence_failures} forced_remaining=1",
                )
                remaining = "1"
            self.note_cycle_outcome(remaining)
            self.maybe_self_restart("reviewer")
            if remaining == "0":
                self.last_closeout_action = "stop"
                self.perform_maintenance("cycle-complete")
                committed, commit_reason = self.auto_commit_current_cycle()
                if committed:
                    self.last_closeout_action = "commit"
                    self.record_event(
                        "cycle.outcome",
                        "completed",
                        "auto-commit created after successful cycle",
                        closeout_action="commit",
                        commit_reason=commit_reason,
                    )
                else:
                    self.record_event(
                        "cycle.outcome",
                        "warning",
                        "auto-commit skipped after successful cycle",
                        closeout_action="stop",
                        commit_reason=commit_reason,
                    )
                self._save_cycle_state()
                self.capture_cycle_snapshot("complete")
                print("Global Remaining steps: 0")
                return 0
            if self.current_task_packet_status == "done":
                committed, commit_reason = self.auto_commit_current_packet()
                if committed:
                    self.last_closeout_action = "packet-commit"
                    self.record_event(
                        "cycle.outcome",
                        "completed",
                        "auto-commit created after task packet completion",
                        closeout_action="packet-commit",
                        commit_reason=commit_reason,
                        task_packet_id=self.last_completed_task_packet.get("item_id", ""),
                    )
                else:
                    self.record_event(
                        "cycle.outcome",
                        "warning",
                        "task packet auto-commit skipped",
                        closeout_action=self.last_closeout_action or "continue",
                        commit_reason=commit_reason,
                        task_packet_id=self.last_completed_task_packet.get("item_id", ""),
                    )
            cycles_run += 1
            self.perform_maintenance("cycle-open")
            self.maybe_run_scheduled_maintenance(cycles_run)
            if self.cfg.unattended_max_cycles > 0 and cycles_run >= self.cfg.unattended_max_cycles:
                self.last_closeout_action = "stop"
                self._save_cycle_state()
                self.write_status("cycle", "unattended-budget-reached", f"cycles_run={cycles_run}")
                self.record_event(
                    "cycle.outcome",
                    "warning",
                    "unattended cycle budget reached; stopping loop",
                    closeout_action="stop",
                    cycles_run=cycles_run,
                    unattended_max_cycles=self.cfg.unattended_max_cycles,
                )
                return 0
            if self.last_closeout_action != "packet-commit":
                self.last_closeout_action = "continue"
            self._save_cycle_state()
