from __future__ import annotations

import atexit
import json
import os
import signal
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ChildProcessRecord:
    pid: int
    command: str
    root_dir: str
    started_at: str


_REGISTERED = False


def _records_file(state_dir: Path) -> Path:
    return state_dir / "child_processes.json"


def _load_records(state_dir: Path) -> list[dict[str, object]]:
    path = _records_file(state_dir)
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return data if isinstance(data, list) else []


def _save_records(state_dir: Path, records: list[dict[str, object]]) -> None:
    path = _records_file(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def register_child_process(state_dir: Path, pid: int, command: str, root_dir: str, started_at: str) -> None:
    records = _load_records(state_dir)
    records = [record for record in records if int(record.get("pid", -1)) != pid]
    records.append(
        {
            "pid": pid,
            "command": command,
            "root_dir": root_dir,
            "started_at": started_at,
        }
    )
    _save_records(state_dir, records)


def unregister_child_process(state_dir: Path, pid: int) -> None:
    records = _load_records(state_dir)
    filtered = [record for record in records if int(record.get("pid", -1)) != pid]
    if filtered != records:
        _save_records(state_dir, filtered)


def _cmdline_text(path: Path) -> str:
    try:
        return path.read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="replace")
    except OSError:
        return ""


def _record_matches(root_dir: Path, record: dict[str, object]) -> bool:
    pid = int(record.get("pid", -1))
    proc_path = Path("/proc") / str(pid)
    if not proc_path.exists():
        return False
    command = str(record.get("command", ""))
    recorded_root = str(record.get("root_dir", ""))
    cmdline = _cmdline_text(proc_path / "cmdline")
    return bool(cmdline) and command in cmdline and (recorded_root in cmdline or str(root_dir) in cmdline)


def cleanup_stale_child_processes(state_dir: Path, root_dir: Path) -> list[int]:
    records = _load_records(state_dir)
    if not records:
        return []
    survivors: list[dict[str, object]] = []
    cleaned: list[int] = []
    for record in records:
        try:
            pid = int(record.get("pid", -1))
        except (TypeError, ValueError):
            continue
        proc_path = Path("/proc") / str(pid)
        if not proc_path.exists():
            continue
        if not _record_matches(root_dir, record):
            survivors.append(record)
            continue
        try:
            pgid = os.getpgid(pid)
        except ProcessLookupError:
            cleaned.append(pid)
            continue
        try:
            os.killpg(pgid, signal.SIGTERM)
            time.sleep(0.2)
            if proc_path.exists():
                os.killpg(pgid, signal.SIGKILL)
            cleaned.append(pid)
        except ProcessLookupError:
            cleaned.append(pid)
        except PermissionError:
            survivors.append(record)
    _save_records(state_dir, survivors)
    return cleaned


def install_child_cleanup_handler(state_dir: Path, root_dir: Path) -> None:
    global _REGISTERED
    if _REGISTERED:
        return

    def _cleanup(*_args: object) -> None:
        cleanup_stale_child_processes(state_dir, root_dir)

    atexit.register(_cleanup)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        try:
            def _handler(_signum: int, _frame: object, _sig: signal.Signals = sig) -> None:
                _cleanup()
                raise SystemExit(128 + int(_sig))

            signal.signal(sig, _handler)
        except (ValueError, OSError):
            continue
    _REGISTERED = True
