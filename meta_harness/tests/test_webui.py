from __future__ import annotations

import json
from urllib.request import Request, urlopen

from meta_harness.config import LlmConfig, RuntimeConfig
from meta_harness.orchestrator import MetaHarness
from meta_harness.webui import HarnessWebUI, _usage_summary


def _make_cfg(monkeypatch, tmp_path):
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    monkeypatch.setenv("WEB_UI_PORT", "0")
    monkeypatch.setenv("WEB_UI_AUTO_OPEN", "0")
    cfg = RuntimeConfig.from_env([])
    llm_cfg = LlmConfig.from_env()
    return cfg, llm_cfg


def test_web_ui_serves_state_and_accepts_comments(monkeypatch, tmp_path):
    cfg, _llm_cfg = _make_cfg(monkeypatch, tmp_path)
    cfg.status_file.parent.mkdir(parents=True, exist_ok=True)
    cfg.log_dir.mkdir(parents=True, exist_ok=True)
    cfg.status_file.write_text("step=worker\nstatus=running\nupdated_at=2026-04-04T00:00:00+00:00\n", encoding="utf-8")
    cfg.last_log_file.write_text("worker output\n", encoding="utf-8")
    cfg.preflight_state_file.write_text(
        json.dumps(
            {
                "schema_version": "meta_harness.preflight.v1",
                "ready": True,
                "python_ok": True,
                "python_bin": "/tmp/venv/bin/python",
                "commands": {"timeout": True},
                "providers": {"codex": True},
                "free_disk_mb": 12345,
                "free_ram_mb": 6789,
                "state_dir_mb": 42,
                "updated_at": "2026-04-04T00:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    cfg.history_log_file.write_text(
        json.dumps(
            {
                "schema_version": "meta_harness.event.v1",
                "at": "2026-04-04T00:00:00+00:00",
                "event": "cycle.started",
                "status": "running",
                "message": "prepared new cycle",
                "failure_class": "",
                "details": {"cycle_dir": "cycle001"},
            }
        )
        + "\n"
        + json.dumps(
            {
                "schema_version": "meta_harness.event.v1",
                "at": "2026-04-04T00:00:02+00:00",
                "event": "role.timed_out",
                "status": "warning",
                "message": "worker timed out during focused retry",
                "failure_class": "worker_timeout",
                "details": {"role": "worker", "attempt": 2},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    cfg.session_ledger_file.write_text(
        json.dumps(
            {
                "schema_version": "meta_harness.session.v1",
                "at": "2026-04-04T00:00:01+00:00",
                "role": "worker",
                "provider": "codex",
                "model": "gpt-5.4",
                "mode": "new",
                "log_file": "20260404_000000_worker.log",
                "exit_code": 0,
                "duration_secs": 12,
                "outcome": "done",
                "total_tokens": 1234,
                "cost_usd": 0.25,
            }
        ) + "\n",
        encoding="utf-8",
    )
    cfg.maintenance_file.write_text(
        json.dumps(
            {
                "schema_version": "meta_harness.maintenance.v1",
                "updated_at": "2026-04-04T00:00:03+00:00",
                "reason": "cycle-open",
                "recommendations": ["prefer stronger model or smaller task packets"],
                "compaction": {
                    "top_failure_classes": [{"name": "worker_timeout", "count": 1}],
                },
            }
        ),
        encoding="utf-8",
    )
    worker_log = cfg.log_dir / "20260404_000000_worker.log"
    worker_log.write_text("worker output\n", encoding="utf-8")
    (cfg.state_dir / "worker.lastlog").write_text(str(worker_log) + "\n", encoding="utf-8")
    (cfg.state_dir / "worker.remaining").write_text("7\n", encoding="utf-8")
    cycle_dir = cfg.runs_dir / "20260404_000000_cycle001"
    cycle_dir.mkdir(parents=True, exist_ok=True)
    (cfg.state_dir / "latest_cycle").symlink_to(cycle_dir)
    (cycle_dir / "cycle.state.json").write_text(
        json.dumps(
            {
                "schema_version": "meta_harness.cycle_state.v1",
                "cycle": 1,
                "completed": False,
                "current_task_packet": {
                    "item_id": "1",
                    "objective": "fix byteops",
                    "target_files": ["decompile.py"],
                    "target_refs": ["decompile.py:10-20"],
                    "acceptance_tests": ["pytest tests/test_byteops.py -k byteops"],
                    "done_conditions": ["BYTEOPS.dec contains printf"],
                },
                "current_task_packet_status": "partial",
                "current_green_level": "focused-item-green",
                "last_policy_decision": {
                    "decision": "worker_runtime_escalated",
                    "reason": "recent worker history indicates escalation",
                    "updated_at": "2026-04-04T00:00:01+00:00",
                },
                "last_closeout_action": "continue",
                "branch_name": "feature/harness",
                "branch_freshness": {"main_available": True, "stale": True, "behind": 2, "ahead": 1},
                "steps": {},
            }
        ),
        encoding="utf-8",
    )

    harness = MetaHarness(cfg, _llm_cfg)
    harness.current_cycle_dir = cycle_dir
    harness.current_cycle_index = 1
    harness.cycle_state = json.loads((cycle_dir / "cycle.state.json").read_text(encoding="utf-8"))
    harness._hydrate_runtime_hints_from_state(harness.cycle_state)

    ui = HarnessWebUI(cfg, harness=harness)
    try:
        base = ui.start().rstrip("/")
        with urlopen(f"{base}/api/state") as response:
            payload = json.loads(response.read().decode("utf-8"))
            assert response.headers["Cache-Control"] == "no-store, max-age=0"
        assert payload["status"]["step"] == "worker"
        assert "worker output" in payload["console"]["text"]
        assert payload["resources"]["active_process_count"] == 0
        assert payload["resources"]["state_dir_mb"] is not None
        worker = next(role for role in payload["roles"] if role["name"] == "worker")
        assert worker["provider"] == "codex"
        assert worker["model"] == cfg.worker_model
        assert worker["latest_log"] == worker_log.name
        assert worker["remaining_steps"] == "7"
        assert worker["status"] == "running"
        assert payload["usage"]["available"] is True
        assert payload["usage"]["total_tokens"] == 1234
        assert payload["usage"]["cost_usd"] == 0.25
        assert payload["preflight"]["ready"] is True
        assert payload["preflight"]["schema_version"] == "meta_harness.preflight.v1"
        assert payload["session_summary"]["total_sessions"] == 1
        assert payload["session_summary"]["by_role"]["worker"] == 1
        assert payload["sessions"][0]["schema_version"] == "meta_harness.session.v1"
        assert payload["history"][0]["event"] == "cycle.started"
        assert payload["history"][0]["status"] == "running"
        assert payload["history"][0]["message"] == "prepared new cycle"
        assert payload["actions"] == []
        assert payload["current_task_packet"]["item_id"] == "1"
        assert payload["current_task_packet_status"] == "partial"
        assert payload["current_green_level"] == "focused-item-green"
        assert payload["last_policy_decision"]["decision"] == "worker_runtime_escalated"
        assert payload["autonomy"]["last_closeout_action"] == "continue"
        assert payload["autonomy"]["branch_name"] == "feature/harness"
        assert "behind main by 2" in payload["autonomy"]["branch_note"]
        assert payload["autonomy"]["compaction_note"] == "worker_timeout: 1"
        assert payload["autonomy"]["top_recommendation"] == "prefer stronger model or smaller task packets"
        assert len(payload["blockers"]) == 1
        assert payload["blockers"][0]["title"] == "worker timed out during focused retry"
        assert "worker_timeout" in payload["blockers"][0]["meta"]
        assert payload["blockers"][0]["status"] == "warning"

        request = Request(
            f"{base}/api/comment",
            data=json.dumps({"message": "Please focus on the worker timeout path."}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request) as response:
            posted = json.loads(response.read().decode("utf-8"))
        assert posted["ok"] is True
        assert "worker timeout path" in cfg.operator_comments_file.read_text(encoding="utf-8")
        chat_text = cfg.chat_log_file.read_text(encoding="utf-8")
        assert "operator" in chat_text

        pause_request = Request(
            f"{base}/api/action",
            data=json.dumps({"action": "pause"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(pause_request) as response:
            paused = json.loads(response.read().decode("utf-8"))
        assert paused["ok"] is True
        assert cfg.stop_file.exists()

        stronger_request = Request(
            f"{base}/api/action",
            data=json.dumps({"action": "force-stronger-worker"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(stronger_request) as response:
            stronger = json.loads(response.read().decode("utf-8"))
        assert stronger["ok"] is True
        updated_state = json.loads((cycle_dir / "cycle.state.json").read_text(encoding="utf-8"))
        assert updated_state["manual_worker_model_override"] == cfg.worker_stall_model

        rewrite_request = Request(
            f"{base}/api/action",
            data=json.dumps({"action": "force-planner-rewrite"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(rewrite_request) as response:
            rewrite = json.loads(response.read().decode("utf-8"))
        assert rewrite["ok"] is True
        updated_state = json.loads((cycle_dir / "cycle.state.json").read_text(encoding="utf-8"))
        assert updated_state["next_cycle_start_step"] == "planner"

        resume_request = Request(
            f"{base}/api/action",
            data=json.dumps({"action": "resume"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(resume_request) as response:
            resumed = json.loads(response.read().decode("utf-8"))
        assert resumed["ok"] is True
        assert not cfg.stop_file.exists()

        with urlopen(f"{base}/api/state") as response:
            payload = json.loads(response.read().decode("utf-8"))
        assert len(payload["actions"]) >= 3
        assert payload["actions"][-1]["event"] == "operator.action_requested"
    finally:
        ui.stop()


def test_web_ui_console_endpoint_tracks_last_log_updates(monkeypatch, tmp_path):
    cfg, _llm_cfg = _make_cfg(monkeypatch, tmp_path)
    cfg.status_file.parent.mkdir(parents=True, exist_ok=True)
    cfg.last_log_file.write_text("first line\n", encoding="utf-8")

    ui = HarnessWebUI(cfg)
    try:
        base = ui.start().rstrip("/")
        with urlopen(f"{base}/api/console") as response:
            payload = json.loads(response.read().decode("utf-8"))
        assert "first line" in payload["text"]

        cfg.last_log_file.write_text("first line\nsecond line\n", encoding="utf-8")
        with urlopen(f"{base}/api/console") as response:
            payload = json.loads(response.read().decode("utf-8"))
        assert "second line" in payload["text"]
        assert payload["size_bytes"] >= len("first line\nsecond line\n")
    finally:
        ui.stop()


def test_usage_summary_parses_codex_tokens_used(tmp_path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / "20260404_000000_worker.log").write_text(
        "work happened\n\ntokens used\n141,689\n",
        encoding="utf-8",
    )
    usage = _usage_summary(log_dir)
    assert usage["available"] is True
    assert usage["total_tokens"] == 141689


def test_web_ui_root_embeds_bootstrap_state(monkeypatch, tmp_path):
    cfg, _llm_cfg = _make_cfg(monkeypatch, tmp_path)
    cfg.status_file.parent.mkdir(parents=True, exist_ok=True)
    cfg.status_file.write_text("step=planner\nstatus=running\nupdated_at=2026-04-04T00:00:00+00:00\n", encoding="utf-8")
    cfg.last_log_file.write_text("planner output\n", encoding="utf-8")
    cfg.history_log_file.write_text(
        json.dumps(
            {
                "schema_version": "meta_harness.event.v1",
                "at": "2026-04-04T00:00:01+00:00",
                "event": "cycle.started",
                "status": "running",
                "message": "prepared new cycle",
                "failure_class": "",
                "details": {},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    ui = HarnessWebUI(cfg)
    try:
        base = ui.start().rstrip("/")
        with urlopen(f"{base}/") as response:
            html = response.read().decode("utf-8")
            assert response.headers["Cache-Control"] == "no-store, max-age=0"
        assert "Meta Harness Control Room" in html
        assert '"step": "planner"' in html
        assert '"status": "running"' in html
        assert '"event": "cycle.started"' in html or '"event":"cycle.started"' in html
        assert "Loading..." not in html
        assert "Connecting..." not in html
        assert "Task Packet" in html
        assert "Policy And Green" in html
        assert "Blockers And Recovery" in html
        assert "Autonomy And Maintenance" in html
        assert "Preflight" in html
        assert "Session Ledger" in html
        assert "Recent Events" in html
        assert "Operator Action History" in html
        assert "AbortController" in html
        assert "window.location.reload()" in html
        assert "fetch(`/api/console?tail_bytes=65536&ts=${Date.now()}`" in html
        assert "node.scrollTop = node.scrollHeight;" in html
        assert "Force Planner Rewrite" in html
        assert "Force Stronger Worker" in html
        assert "Run Maintenance" in html
    finally:
        ui.stop()


def test_web_ui_root_escapes_script_breakers(monkeypatch, tmp_path):
    cfg, _llm_cfg = _make_cfg(monkeypatch, tmp_path)
    cfg.status_file.parent.mkdir(parents=True, exist_ok=True)
    cfg.status_file.write_text("step=planner\nstatus=running\nupdated_at=2026-04-04T00:00:00+00:00\n", encoding="utf-8")
    cfg.last_log_file.write_text("</script>\nplanner output\n", encoding="utf-8")

    ui = HarnessWebUI(cfg)
    try:
        base = ui.start().rstrip("/")
        with urlopen(f"{base}/") as response:
            html = response.read().decode("utf-8")
        assert "<\\/script>" in html
        assert "&lt;/script&gt;" in html
    finally:
        ui.stop()
