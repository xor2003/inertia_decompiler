"""Regression tests for reservation-aware pytest worker backfilling."""

from __future__ import annotations

import json
from pathlib import Path

from tools.dev.pytest_dynamic_schedule import ScheduledWorkerSpec, run_pytest_schedule
from tools.dev.pytest_partition_execution import WorkerSpec

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_schedule_backfills_worker_past_blocked_large_reservation(tmp_path: Path) -> None:
    """Keep admissible work moving while a larger pending worker cannot fit."""

    marker_path = tmp_path / "backfilled"
    wait_path = tmp_path / "test_wait.py"
    wait_path.write_text(
        "\n".join(
            (
                "import time",
                "from pathlib import Path",
                "",
                "def test_waits_for_backfill():",
                "    deadline = time.monotonic() + 5.0",
                f"    marker = Path({str(marker_path)!r})",
                "    while time.monotonic() < deadline and not marker.exists():",
                "        time.sleep(0.02)",
                "    assert marker.exists()",
                "",
            )
        ),
        encoding="utf-8",
    )
    fast_path = tmp_path / "test_fast.py"
    fast_path.write_text("def test_fast():\n    assert True\n", encoding="utf-8")
    blocked_path = tmp_path / "test_blocked.py"
    blocked_path.write_text("def test_blocked():\n    assert True\n", encoding="utf-8")
    backfill_path = tmp_path / "test_backfill.py"
    backfill_path.write_text(
        f"from pathlib import Path\n\ndef test_backfill():\n    Path({str(marker_path)!r}).touch()\n",
        encoding="utf-8",
    )
    scheduled = (
        ScheduledWorkerSpec(WorkerSpec("wait", (str(wait_path),)), 700),
        ScheduledWorkerSpec(WorkerSpec("fast", (str(fast_path),)), 100),
        ScheduledWorkerSpec(WorkerSpec("blocked", (str(blocked_path),)), 700),
        ScheduledWorkerSpec(WorkerSpec("backfill", (str(backfill_path),)), 100),
    )
    run_root = tmp_path / "run"
    run_root.mkdir()
    weights_path = run_root / "weights.json"
    weights_path.write_text(json.dumps({}), encoding="utf-8")

    result = run_pytest_schedule(
        scheduled,
        repo_root=REPO_ROOT,
        run_root=run_root,
        weights_path=weights_path,
        durations=5,
        max_workers=2,
        reservation_limit_kib=800,
        max_rss_kib=2 * 1024 * 1024,
    )

    assert marker_path.is_file()
    assert not result.memory_exceeded
    assert result.exit_codes == dict.fromkeys(("wait", "fast", "blocked", "backfill"), 0)
    assert len(result.reports) == 4
    assert sum(len(report.selected_nodeids) for report in result.reports) == 4
