from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from meta_harness.config import LlmConfig, RuntimeConfig
from meta_harness.orchestrator import MetaHarness, ResourceBlockedError, RoleRunError
from meta_harness.runtime_records import (
    CYCLE_STATE_SCHEMA_VERSION,
    EVENT_NAMES,
    FAILURE_CLASSES,
    HISTORY_EVENT_SCHEMA_VERSION,
    PREFLIGHT_STATE_SCHEMA_VERSION,
    SESSION_LEDGER_SCHEMA_VERSION,
)


def _make_cfg(monkeypatch, tmp_path: Path) -> tuple[RuntimeConfig, LlmConfig]:
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    cfg = RuntimeConfig.from_env([])
    llm_cfg = LlmConfig.from_env()
    return cfg, llm_cfg


def _write_cycle_state(
    cycle_dir: Path,
    steps: dict[str, str],
    cycle: int = 1,
    *,
    current_plan_item: str = "",
    current_plan_item_stall_count: int = 0,
    next_cycle_start_step: str = "",
    plan_rewrite_target: str = "",
    worker_stall_streak: int = 0,
) -> None:
    cycle_dir.mkdir(parents=True, exist_ok=True)
    state = {
        "cycle": cycle,
        "started_at": "2026-04-01T00:00:00+00:00",
        "updated_at": "2026-04-01T00:00:00+00:00",
        "completed": False,
        "current_plan_item": current_plan_item,
        "current_plan_item_stall_count": current_plan_item_stall_count,
        "next_cycle_start_step": next_cycle_start_step,
        "plan_rewrite_target": plan_rewrite_target,
        "steps": {
            name: {"status": status, "updated_at": "2026-04-01T00:00:00+00:00", "extra": ""}
            for name, status in steps.items()
        },
        "worker_stall_streak": worker_stall_streak,
    }
    (cycle_dir / "cycle.state.json").write_text(json.dumps(state), encoding="utf-8")


def test_peek_resume_step_reads_latest_cycle_state(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    latest = cfg.runs_dir / "20260401_000001_cycle001"
    _write_cycle_state(
        latest,
        {
            "full-sweep": "done",
            "checker": "done",
            "planner": "done",
            "worker": "running",
            "reviewer": "pending",
        },
    )

    harness = MetaHarness(cfg, llm_cfg)
    assert harness.peek_resume_step() == "worker"


def test_peek_resume_step_treats_done_with_failures_as_completed(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    latest = cfg.runs_dir / "20260401_000001_cycle001"
    _write_cycle_state(
        latest,
        {
            "full-sweep": "done-with-failures",
            "checker": "done",
            "planner": "done",
            "worker": "running",
            "reviewer": "pending",
        },
    )

    harness = MetaHarness(cfg, llm_cfg)

    assert harness.peek_resume_step() == "worker"


def test_run_resume_skips_completed_steps(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    latest = cfg.runs_dir / "20260401_000001_cycle001"
    _write_cycle_state(
        latest,
        {
            "full-sweep": "done",
            "checker": "done",
            "planner": "done",
            "worker": "running",
            "reviewer": "pending",
        },
    )

    harness = MetaHarness(cfg, llm_cfg)
    calls: list[str] = []

    monkeypatch.setattr(harness, "ensure_prereqs", lambda: None)
    monkeypatch.setattr(harness, "acquire_lock", lambda: None)
    monkeypatch.setattr(harness, "check_stop_file", lambda: None)
    monkeypatch.setattr(harness, "preflight_resource_check", lambda _context: None)
    monkeypatch.setattr(harness, "capture_cycle_snapshot", lambda _tag: calls.append(f"snapshot:{_tag}"))
    monkeypatch.setattr(harness, "maybe_self_restart", lambda _reason: False)
    monkeypatch.setattr(harness, "sweep_step", lambda: calls.append("sweep"))
    monkeypatch.setattr(harness, "checker_step", lambda: calls.append("checker"))
    monkeypatch.setattr(harness, "planner_step", lambda: calls.append("planner"))
    monkeypatch.setattr(harness, "worker_cycle", lambda: calls.append("worker"))
    monkeypatch.setattr(harness, "reviewer_step", lambda: "0")

    assert harness.run(resume=True) == 0
    assert "sweep" not in calls
    assert "checker" not in calls
    assert "planner" not in calls
    assert "worker" in calls


def test_run_keeps_loop_open_when_reviewer_claims_zero_but_evidence_has_failures(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    cfg.evidence_log_file.parent.mkdir(parents=True, exist_ok=True)
    cfg.evidence_log_file.write_text("done in 1.0s; failures=4/21\n", encoding="utf-8")

    harness = MetaHarness(cfg, llm_cfg)
    cycle_starts: list[int] = []

    monkeypatch.setattr(harness, "ensure_prereqs", lambda: None)
    monkeypatch.setattr(harness, "acquire_lock", lambda: None)
    monkeypatch.setattr(harness, "check_stop_file", lambda: None)
    monkeypatch.setattr(harness, "preflight_resource_check", lambda _context: None)
    monkeypatch.setattr(harness, "capture_cycle_snapshot", lambda _tag: None)
    monkeypatch.setattr(harness, "maybe_self_restart", lambda _reason: False)
    monkeypatch.setattr(harness, "sweep_step", lambda: None)
    monkeypatch.setattr(harness, "checker_step", lambda: None)
    monkeypatch.setattr(harness, "planner_step", lambda: None)
    monkeypatch.setattr(harness, "worker_cycle", lambda: None)
    monkeypatch.setattr(harness, "reviewer_step", lambda: "0")

    original_prepare = harness.prepare_cycle_workspace

    def fake_prepare() -> None:
        cycle_starts.append(len(cycle_starts) + 1)
        if len(cycle_starts) > 1:
            raise RuntimeError("stop-after-second-cycle")
        original_prepare()

    monkeypatch.setattr(harness, "prepare_cycle_workspace", fake_prepare)

    with pytest.raises(RuntimeError, match="stop-after-second-cycle"):
        harness.run(resume=False)

    assert cycle_starts == [1, 2]
    state = json.loads((harness.current_cycle_dir / "cycle.state.json").read_text(encoding="utf-8"))
    assert state["steps"]["reviewer"]["status"] == "done"
    assert "evidence_failures=4" in state["steps"]["reviewer"]["extra"]


def test_run_fresh_uses_persisted_worker_stall_handoff_after_restart(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    latest = cfg.runs_dir / "20260404_000001_cycle001"
    _write_cycle_state(
        latest,
        {
            "full-sweep": "done",
            "checker": "done",
            "planner": "done",
            "worker": "stalled",
            "reviewer": "done",
        },
        cycle=1,
        next_cycle_start_step="worker",
        worker_stall_streak=1,
    )

    harness = MetaHarness(cfg, llm_cfg)
    calls: list[str] = []
    worker_state: dict[str, object] = {}

    monkeypatch.setattr(harness, "ensure_prereqs", lambda: None)
    monkeypatch.setattr(harness, "acquire_lock", lambda: None)
    monkeypatch.setattr(harness, "check_stop_file", lambda: None)
    monkeypatch.setattr(harness, "preflight_resource_check", lambda _context: None)
    monkeypatch.setattr(harness, "capture_cycle_snapshot", lambda _tag: None)
    monkeypatch.setattr(harness, "maybe_self_restart", lambda _reason: False)
    monkeypatch.setattr(harness, "sweep_step", lambda: calls.append("sweep"))
    monkeypatch.setattr(harness, "checker_step", lambda: calls.append("checker"))
    monkeypatch.setattr(harness, "planner_step", lambda: calls.append("planner"))

    def fake_worker() -> None:
        calls.append("worker")
        worker_state["model"] = harness.current_worker_model()
        worker_state["failure_limit"] = harness.current_worker_failure_limit()
        worker_state["cycle"] = harness.current_cycle_index

    monkeypatch.setattr(harness, "worker_cycle", fake_worker)
    monkeypatch.setattr(harness, "reviewer_step", lambda: "0")

    assert harness.run(resume=False) == 0
    assert calls == ["worker"]
    assert worker_state == {
        "model": cfg.worker_stall_model,
        "failure_limit": cfg.worker_stall_failure_limit,
        "cycle": 2,
    }


def test_run_fresh_uses_persisted_planner_handoff_for_stuck_item(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    current_item = "1. `decompile.py:10` giant item still too broad"
    latest = cfg.runs_dir / "20260404_000001_cycle001"
    _write_cycle_state(
        latest,
        {
            "full-sweep": "done",
            "checker": "done",
            "planner": "done",
            "worker": "stalled",
            "reviewer": "done",
        },
        cycle=1,
        current_plan_item=current_item,
        current_plan_item_stall_count=2,
        next_cycle_start_step="planner",
        plan_rewrite_target=current_item,
        worker_stall_streak=2,
    )

    harness = MetaHarness(cfg, llm_cfg)
    calls: list[str] = []

    monkeypatch.setattr(harness, "ensure_prereqs", lambda: None)
    monkeypatch.setattr(harness, "acquire_lock", lambda: None)
    monkeypatch.setattr(harness, "check_stop_file", lambda: None)
    monkeypatch.setattr(harness, "preflight_resource_check", lambda _context: None)
    monkeypatch.setattr(harness, "capture_cycle_snapshot", lambda _tag: None)
    monkeypatch.setattr(harness, "maybe_self_restart", lambda _reason: False)
    monkeypatch.setattr(harness, "sweep_step", lambda: calls.append("sweep"))
    monkeypatch.setattr(harness, "checker_step", lambda: calls.append("checker"))
    monkeypatch.setattr(harness, "planner_step", lambda: calls.append("planner"))
    monkeypatch.setattr(harness, "worker_cycle", lambda: calls.append("worker"))
    monkeypatch.setattr(harness, "reviewer_step", lambda: "0")

    assert harness.run(resume=False) == 0
    assert calls == ["planner", "worker"]


def test_worker_cycle_stalls_when_repeated_failed_test_is_outside_current_task_packet(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    cfg.plan_path.write_text(
        "1. `scripts/repro_decompiler_boundary.py:11-140`, `angr_platforms/tests/test_x86_16_cli.py:2103-2178`: "
        "fix far pointer boundary. Required tests: pytest /home/xor/vextest/angr_platforms/tests/test_x86_16_cli.py "
        "-k 'far_pointer_stack_local_width or far_pointer_store'.\n",
        encoding="utf-8",
    )
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()
    harness.sync_current_plan_item()

    recent_a = harness.current_cycle_dir / "worker.iter01.log"
    recent_b = harness.current_cycle_dir / "worker.iter02.log"
    repeated_failure = "angr_platforms/tests/test_x86_16_cli.py::test_main_uses_cached_exe_catalog_addresses_before_cfg"
    log_text = f"FAILED {repeated_failure}\nGlobal Remaining steps: 1\n"
    recent_a.write_text(log_text, encoding="utf-8")
    recent_b.write_text(log_text, encoding="utf-8")

    monkeypatch.setattr(harness, "check_stop_file", lambda: None)
    monkeypatch.setattr(harness, "preflight_resource_check", lambda _context: None)
    monkeypatch.setattr(harness, "run_role", lambda *args, **kwargs: pytest.fail("worker should not run once drift is detected"))

    harness.worker_cycle()

    assert harness.cycle_step_status("worker") == "stalled"
    assert harness.current_task_packet_status == "rewrite"
    assert harness.plan_rewrite_target == harness.current_plan_item_text()
    assert harness.last_policy_decision["decision"] == "worker_out_of_packet_scope"
    assert repeated_failure in str(harness.last_policy_decision["details"]["reason_detail"])


def test_current_plan_item_requires_replan_when_rewrite_target_matches_item(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    current_item = "1. `decompile.py:10` fix boundary.\n"
    cfg.plan_path.write_text(current_item, encoding="utf-8")
    harness.sync_current_plan_item()
    harness.plan_rewrite_target = harness.current_plan_item_text()

    assert harness.current_plan_item_requires_replan() is True


def test_run_role_uses_delta_resume_prompt_for_codex_sessions(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()
    harness.role_session_file("worker").write_text("session-123\n", encoding="utf-8")

    captured: dict[str, object] = {}

    monkeypatch.setattr(harness, "consume_operator_comments", lambda _role: "Use only the current plan delta.")

    def fake_run(role, model, prompt, resume=False):
        captured["role"] = role
        captured["model"] = model
        captured["prompt"] = prompt
        captured["resume"] = resume
        return cfg.log_dir / "worker.log"

    monkeypatch.setattr(harness, "_run_llm_attempt", fake_run)

    harness.run_role(
        "worker",
        cfg.worker_model,
        "FULL WORKER PROMPT",
        resume=True,
        resume_context="Primary plan item:\n1. `decompile.py:10` fix BYTEOPS",
    )

    assert captured["role"] == "worker"
    assert captured["resume"] is True
    assert "Continue the existing worker session." in str(captured["prompt"])
    assert "FULL WORKER PROMPT" not in str(captured["prompt"])
    assert "Use only the current plan delta." in str(captured["prompt"])
    assert "Primary plan item:" in str(captured["prompt"])


def test_run_role_emits_status_heartbeat_during_long_provider_call(monkeypatch, tmp_path):
    monkeypatch.setenv("STATUS_HEARTBEAT_SECS", "0.01")
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()

    status_updates: list[tuple[str, str, str]] = []

    def fake_write_status(step: str, status: str, extra: str = "") -> None:
        status_updates.append((step, status, extra))

    def fake_run_provider_once(provider, mode, model, prompt, prompt_file, log_file, config, session_id=""):
        time.sleep(0.05)
        log_file.write_text("x" * 200 + "\nGlobal Remaining steps: 1\n", encoding="utf-8")
        return 0

    monkeypatch.setattr(harness, "write_status", fake_write_status)
    monkeypatch.setattr("meta_harness.orchestrator.run_provider_once", fake_run_provider_once)

    log_file = harness.run_role("worker", cfg.worker_model, "WORKER PROMPT", resume=False)

    assert log_file.exists()
    assert any(step == "worker" and status == "running" for step, status, _ in status_updates)
    assert any("heartbeat_elapsed=" in extra for _, _, extra in status_updates)
    assert status_updates[-1][1] == "done"


def test_ensure_prereqs_writes_preflight_state(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)

    monkeypatch.setattr("meta_harness.orchestrator.shutil.which", lambda _cmd: "/usr/bin/fake")
    monkeypatch.setattr(
        harness,
        "ensure_profiler_tools",
        lambda: {"line_profiler": True, "memray": True, "py-spy": True, "install_attempted": False},
    )

    harness.ensure_prereqs()

    payload = json.loads(cfg.preflight_state_file.read_text(encoding="utf-8"))
    assert payload["schema_version"] == PREFLIGHT_STATE_SCHEMA_VERSION
    assert payload["ready"] is True
    assert payload["commands"]["timeout"] is True
    assert payload["providers"]["codex"] is True
    assert payload["profilers"]["memray"] is True
    assert payload["python_ok"] is True


def test_ensure_profiler_tools_installs_missing_tools(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    probes = {"line_profiler": False, "memray": True}
    install_calls: list[list[str]] = []

    monkeypatch.setattr(harness, "python_module_available", lambda module: probes.get(module, False))
    monkeypatch.setattr(harness, "py_spy_available", lambda: False)

    class FakeCompleted:
        returncode = 0
        stdout = "installed\n"
        stderr = ""

    def fake_run(cmd, **_kwargs):
        install_calls.append([str(part) for part in cmd])
        probes["line_profiler"] = True
        return FakeCompleted()

    monkeypatch.setattr("meta_harness.orchestrator.subprocess.run", fake_run)

    status = harness.ensure_profiler_tools()

    assert status["install_attempted"] is True
    assert status["install_ok"] is True
    assert status["line_profiler"] is True
    assert install_calls
    assert install_calls[0][-3:] == ["line_profiler", "memray", "py-spy"]


def test_run_role_records_session_ledger_and_history(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()

    def fake_run_provider_once(provider, mode, model, prompt, prompt_file, log_file, config, session_id=""):
        log_file.write_text("tokens used: 1234\nGlobal Remaining steps: 1\n", encoding="utf-8")
        return 0

    monkeypatch.setattr("meta_harness.orchestrator.run_provider_once", fake_run_provider_once)

    harness.run_role("worker", cfg.worker_model, "WORKER PROMPT", resume=False)

    session_rows = [json.loads(line) for line in cfg.session_ledger_file.read_text(encoding="utf-8").splitlines()]
    assert len(session_rows) == 1
    assert session_rows[0]["schema_version"] == SESSION_LEDGER_SCHEMA_VERSION
    assert session_rows[0]["role"] == "worker"
    assert session_rows[0]["total_tokens"] == 1234
    assert session_rows[0]["outcome"] == "done"

    history_rows = [json.loads(line) for line in cfg.history_log_file.read_text(encoding="utf-8").splitlines()]
    assert history_rows[0]["schema_version"] == HISTORY_EVENT_SCHEMA_VERSION
    assert [row["event"] for row in history_rows] == ["cycle.started", "role.started", "role.finished"]
    assert [row["status"] for row in history_rows] == ["running", "running", "completed"]
    assert history_rows[-1]["message"] == "finished worker"


def test_cycle_state_uses_explicit_schema_version(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)

    harness.prepare_cycle_workspace()

    payload = json.loads((harness.current_cycle_dir / "cycle.state.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == CYCLE_STATE_SCHEMA_VERSION


def test_event_taxonomy_has_expected_surface_area():
    assert len(EVENT_NAMES) >= 10
    assert {
        "cycle.started",
        "cycle.resumed",
        "branch.stale_against_main",
        "role.started",
        "role.finished",
        "role.failed",
        "role.timed_out",
        "worker.stalled",
        "planner.rewrite_requested",
        "sweep.started",
        "sweep.failed",
        "operator.action_requested",
        "maintenance.scheduled",
        "harness.restarting",
    }.issubset(EVENT_NAMES)
    assert len(FAILURE_CLASSES) >= 8


def test_sync_current_plan_item_populates_task_packet(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    cfg.plan_path.write_text(
        "1. `decompile.py:10-20`, `tests/test_byteops.py:1-20`: fix byteops. Done when pytest tests/test_byteops.py -k byteops passes.\n",
        encoding="utf-8",
    )
    harness = MetaHarness(cfg, llm_cfg)

    harness.sync_current_plan_item()

    assert harness.current_task_packet["item_id"] == "1"
    assert "decompile.py" in harness.current_task_packet["target_files"]
    assert harness.current_task_packet["acceptance_tests"]


def test_sync_current_plan_item_skips_completed_items(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    cfg.plan_path.write_text(
        "1. [completed] `done.py`: already landed.\n"
        "2. [pending] `decompile.py:10-20`, `tests/test_byteops.py:1-20`: fix byteops. Done when pytest tests/test_byteops.py -k byteops passes.\n",
        encoding="utf-8",
    )
    harness = MetaHarness(cfg, llm_cfg)

    harness.sync_current_plan_item()

    assert harness.current_plan_item.startswith("2. [pending]")
    assert harness.current_task_packet["item_id"] == "2"
    assert "decompile.py" in harness.current_task_packet["target_files"]


def test_reviewer_step_updates_green_level(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()
    cfg.plan_path.write_text(
        "1. `decompile.py:10-20`: fix byteops. Done when pytest tests/test_byteops.py -k byteops passes.\n",
        encoding="utf-8",
    )
    harness.sync_current_plan_item()

    def fake_run_role(role, model, prompt, resume=False, **_kwargs):
        log_file = cfg.log_dir / "reviewer.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_file.write_text(
            "Task packet status: done\nGreen level: cycle-green\nGlobal Remaining steps: 0\n",
            encoding="utf-8",
        )
        return log_file

    monkeypatch.setattr(harness, "check_stop_file", lambda: None)
    monkeypatch.setattr(harness, "preflight_resource_check", lambda _context: None)
    monkeypatch.setattr(harness, "run_role", fake_run_role)
    monkeypatch.setattr(harness, "capture_cycle_artifact", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(harness, "capture_cycle_snapshot", lambda *_args, **_kwargs: None)

    remaining = harness.reviewer_step()

    assert remaining == "0"
    assert harness.current_green_level == "cycle-green"
    assert harness.current_task_packet_status == "done"


def test_run_role_with_mock_provider_uses_deterministic_script(monkeypatch, tmp_path):
    monkeypatch.setenv("WORKER_PROVIDER", "mock")
    monkeypatch.setenv("MOCK_PROVIDER_SCRIPT", str(tmp_path / "mock.jsonl"))
    monkeypatch.setenv("MOCK_PROVIDER_INDEX_FILE", str(tmp_path / "mock.idx"))
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()

    (tmp_path / "mock.jsonl").write_text(
        '{"role":"worker","mode":"new","output":"Green level: focused-item-green\\nGlobal Remaining steps: 0","exit_code":0}\n',
        encoding="utf-8",
    )

    log_file = harness.run_role("worker", cfg.worker_model, "WORKER PROMPT", resume=False)

    assert "focused-item-green" in log_file.read_text(encoding="utf-8")


def test_perform_maintenance_writes_summary(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    cfg.session_ledger_file.parent.mkdir(parents=True, exist_ok=True)
    cfg.session_ledger_file.write_text(
        json.dumps({"schema_version": "meta_harness.session.v1", "role": "worker", "duration_secs": 5, "total_tokens": 250001})
        + "\n",
        encoding="utf-8",
    )
    cfg.history_log_file.write_text(
        json.dumps({"schema_version": "meta_harness.event.v1", "event": "role.timed_out", "failure_class": "worker_timeout"})
        + "\n"
        + json.dumps({"schema_version": "meta_harness.event.v1", "event": "role.timed_out", "failure_class": "worker_timeout"})
        + "\n",
        encoding="utf-8",
    )

    harness.perform_maintenance("cycle-open")

    payload = json.loads(cfg.maintenance_file.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "meta_harness.maintenance.v1"
    assert payload["reason"] == "cycle-open"
    assert payload["failure_counts"]["worker_timeout"] == 2
    assert payload["recommendations"]
    assert payload["compaction"]["top_failure_classes"][0]["name"] == "worker_timeout"


def test_auto_commit_current_cycle_respects_gates_and_can_commit(monkeypatch, tmp_path):
    monkeypatch.setenv("AUTO_COMMIT_ENABLED", "1")
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()
    harness.current_green_level = "cycle-green"
    harness.cycle_state["git_clean_start"] = True

    class Result:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    calls: list[list[str]] = []

    def fake_run(cmd, *args, **kwargs):
        calls.append(cmd)
        if cmd[-2:] == ["status", "--porcelain"]:
            return Result(stdout=" M meta_harness/orchestrator.py\n")
        if cmd[-2:] == ["add", "-u"]:
            return Result(returncode=0)
        if "commit" in cmd:
            return Result(returncode=0, stdout="[main abc123] meta_harness: cycle 001 complete\n")
        return Result(returncode=0)

    monkeypatch.setattr("meta_harness.orchestrator.subprocess.run", fake_run)

    committed, reason = harness.auto_commit_current_cycle()

    assert committed is True
    assert "meta_harness: cycle 001 complete" in reason
    assert any("commit" in cmd for cmd in calls)


def test_auto_commit_current_packet_uses_packet_commit_message(monkeypatch, tmp_path):
    monkeypatch.setenv("AUTO_COMMIT_ENABLED", "1")
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()
    harness.current_green_level = "focused-item-green"
    harness.cycle_state["git_clean_start"] = True
    harness.last_completed_task_packet = {"item_id": "3", "objective": "finish focused item", "target_files": ["meta_harness/orchestrator.py"]}

    class Result:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    calls: list[list[str]] = []

    def fake_run(cmd, *args, **kwargs):
        calls.append(cmd)
        if cmd[-2:] == ["status", "--porcelain"]:
            return Result(stdout=" M meta_harness/orchestrator.py\n")
        if cmd[:5] == ["git", "-C", str(cfg.root_dir), "add", "-u"]:
            return Result(returncode=0)
        if "commit" in cmd:
            return Result(returncode=0, stdout="[main def456] meta_harness: packet 3 complete\n")
        return Result(returncode=0)

    monkeypatch.setattr("meta_harness.orchestrator.subprocess.run", fake_run)

    committed, reason = harness.auto_commit_current_packet()

    assert committed is True
    assert "packet 3 complete" in reason
    assert "3" in harness.auto_committed_packets
    add_cmd = next(cmd for cmd in calls if cmd[:5] == ["git", "-C", str(cfg.root_dir), "add", "-u"])
    assert add_cmd[-2:] == ["--", "meta_harness/orchestrator.py"]
    assert any("commit" in cmd for cmd in calls)


def test_auto_commit_current_packet_skips_when_changes_escape_packet_scope(monkeypatch, tmp_path):
    monkeypatch.setenv("AUTO_COMMIT_ENABLED", "1")
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()
    harness.current_green_level = "focused-item-green"
    harness.cycle_state["git_clean_start"] = True
    harness.last_completed_task_packet = {"item_id": "2", "target_files": ["meta_harness/orchestrator.py"]}

    class Result:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(cmd, *args, **kwargs):
        if cmd[-2:] == ["status", "--porcelain"]:
            return Result(stdout=" M meta_harness/orchestrator.py\n M meta_harness/webui.py\n")
        return Result(returncode=0)

    monkeypatch.setattr("meta_harness.orchestrator.subprocess.run", fake_run)

    committed, reason = harness.auto_commit_current_packet()

    assert committed is False
    assert "outside task packet scope" in reason


def test_current_worker_model_uses_manual_override_from_cycle_state(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()
    harness.manual_worker_model_override = cfg.worker_stall_model
    harness.manual_worker_failure_limit_override = cfg.worker_stall_failure_limit
    harness._save_cycle_state()

    assert harness.current_worker_model() == cfg.worker_stall_model
    assert harness.current_worker_failure_limit() == cfg.worker_stall_failure_limit


def test_run_background_maintenance_writes_compaction(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    cfg.session_ledger_file.parent.mkdir(parents=True, exist_ok=True)
    cfg.session_ledger_file.write_text(
        json.dumps(
            {
                "schema_version": "meta_harness.session.v1",
                "role": "worker",
                "duration_secs": 5,
                "total_tokens": 1000,
                "current_plan_item": "1. focused packet",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    cfg.history_log_file.write_text(
        json.dumps(
            {
                "schema_version": "meta_harness.event.v1",
                "event": "role.timed_out",
                "failure_class": "worker_timeout",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    result = harness.run_background_maintenance()

    payload = json.loads(cfg.maintenance_file.read_text(encoding="utf-8"))
    assert result["ok"] is True
    assert payload["background_maintenance_enabled"] is True
    assert payload["compaction"]["top_failure_classes"][0]["name"] == "worker_timeout"
    assert payload["compaction"]["top_plan_items_by_sessions"][0]["item"] == "1. focused packet"


def test_maybe_run_scheduled_maintenance_fires_on_interval(monkeypatch, tmp_path):
    monkeypatch.setenv("SCHEDULED_MAINTENANCE_INTERVAL_CYCLES", "2")
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    calls: list[str] = []

    monkeypatch.setattr(harness, "perform_maintenance", lambda reason: calls.append(reason))

    assert harness.maybe_run_scheduled_maintenance(1) is False
    assert harness.maybe_run_scheduled_maintenance(2) is True
    assert calls == ["scheduled-cycle-interval"]


def test_run_stops_when_unattended_cycle_budget_reached(monkeypatch, tmp_path):
    monkeypatch.setenv("UNATTENDED_MAX_CYCLES", "1")
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)

    monkeypatch.setattr(harness, "ensure_prereqs", lambda: None)
    monkeypatch.setattr(harness, "acquire_lock", lambda: None)
    monkeypatch.setattr(harness, "check_stop_file", lambda: None)
    monkeypatch.setattr(harness, "preflight_resource_check", lambda _context: None)
    monkeypatch.setattr(harness, "capture_cycle_snapshot", lambda _tag: None)
    monkeypatch.setattr(harness, "maybe_self_restart", lambda _reason: False)
    monkeypatch.setattr(harness, "sweep_step", lambda: None)
    monkeypatch.setattr(harness, "checker_step", lambda: None)
    monkeypatch.setattr(harness, "planner_step", lambda: None)
    monkeypatch.setattr(harness, "worker_cycle", lambda: None)
    monkeypatch.setattr(harness, "reviewer_step", lambda: "1")
    monkeypatch.setattr(harness, "perform_maintenance", lambda _reason: cfg.maintenance_file.write_text('{"schema_version":"meta_harness.maintenance.v1"}\n', encoding="utf-8"))

    assert harness.run(resume=False) == 0
    assert "unattended-budget-reached" in cfg.status_file.read_text(encoding="utf-8")


def test_log_appends_harness_events_to_last_log(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)

    harness.log("Starting curated evidence sweep")

    assert "Starting curated evidence sweep" in cfg.last_log_file.read_text(encoding="utf-8")


def test_run_role_drops_oversized_worker_session_before_resume(monkeypatch, tmp_path):
    monkeypatch.setenv("MAX_WORKER_SESSION_LOG_BYTES", "100")
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()

    session_file = harness.role_session_file("worker")
    session_file.write_text("session-123\n", encoding="utf-8")

    old_log = cfg.log_dir / "old_worker.log"
    old_log.parent.mkdir(parents=True, exist_ok=True)
    old_log.write_text("x" * 200, encoding="utf-8")
    harness.save_role_markers("worker", old_log)

    captured: dict[str, object] = {}

    def fake_run(role, model, prompt, resume=False):
        captured["resume"] = resume
        captured["prompt"] = prompt
        return cfg.log_dir / "worker.log"

    monkeypatch.setattr(harness, "_run_llm_attempt", fake_run)

    harness.run_role("worker", cfg.worker_model, "FULL WORKER PROMPT", resume=True)

    assert captured["resume"] is True
    assert "Continue the existing worker session." not in str(captured["prompt"])
    assert "FULL WORKER PROMPT" in str(captured["prompt"])
    assert not session_file.exists()


def test_sweep_step_does_not_tee_back_into_evidence_log(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()
    cfg.evidence_log_file.parent.mkdir(parents=True, exist_ok=True)

    for rel in cfg.evidence_input_files:
        path = cfg.root_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("stub\n", encoding="utf-8")

    calls = {}

    class DummyProc:
        pid = 4321
        stdout = iter(["sweep output\n"])

        def wait(self):
            return 0

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_popen(cmd, cwd=None, env=None, stdout=None, stderr=None, **kwargs):
        calls["cmd"] = cmd
        return DummyProc()

    class RunResult:
        def __init__(self, stdout=""):
            self.stdout = stdout
            self.returncode = 0

    def fake_run(*args, **kwargs):
        return RunResult("")

    monkeypatch.setattr(harness, "check_stop_file", lambda: None)
    monkeypatch.setattr(harness, "preflight_resource_check", lambda _context: None)
    monkeypatch.setattr(harness, "trim_old_logs", lambda: None)
    monkeypatch.setattr("meta_harness.orchestrator.register_child_process", lambda *args, **kwargs: None)
    monkeypatch.setattr("meta_harness.orchestrator.unregister_child_process", lambda *args, **kwargs: None)
    monkeypatch.setattr("meta_harness.orchestrator.subprocess.run", fake_run)
    monkeypatch.setattr("meta_harness.orchestrator.subprocess.Popen", fake_popen)

    harness.sweep_step()

    assert calls["cmd"][-1] == cfg.sweep_cmd
    assert "tee -a" not in calls["cmd"][-1]
    last_log = cfg.last_log_file.read_text(encoding="utf-8")
    assert "start sweep=curated evidence sweep" in last_log
    assert "sweep output" in last_log


def test_sweep_step_allows_completed_sweep_with_failures(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()
    cfg.evidence_log_file.parent.mkdir(parents=True, exist_ok=True)

    for rel in cfg.evidence_input_files:
        path = cfg.root_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("stub\n", encoding="utf-8")

    class DummyProc:
        pid = 4322
        stdout = iter(["done in 1.0s; failures=1/2\n"])

        def wait(self):
            return 1

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_popen(cmd, cwd=None, env=None, stdout=None, stderr=None, **kwargs):
        return DummyProc()

    class RunResult:
        def __init__(self):
            self.stdout = ""
            self.returncode = 0

    monkeypatch.setattr(harness, "check_stop_file", lambda: None)
    monkeypatch.setattr(harness, "preflight_resource_check", lambda _context: None)
    monkeypatch.setattr(harness, "trim_old_logs", lambda: None)
    monkeypatch.setattr("meta_harness.orchestrator.register_child_process", lambda *args, **kwargs: None)
    monkeypatch.setattr("meta_harness.orchestrator.unregister_child_process", lambda *args, **kwargs: None)
    monkeypatch.setattr("meta_harness.orchestrator.subprocess.run", lambda *args, **kwargs: RunResult())
    monkeypatch.setattr("meta_harness.orchestrator.subprocess.Popen", fake_popen)

    harness.sweep_step()

    state = json.loads((harness.current_cycle_dir / "cycle.state.json").read_text(encoding="utf-8"))
    assert state["steps"]["full-sweep"]["status"] == "done-with-failures"


def test_sweep_step_retries_thread_exhaustion_in_forced_serial_mode(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()
    cfg.evidence_log_file.parent.mkdir(parents=True, exist_ok=True)

    for rel in cfg.evidence_input_files:
        path = cfg.root_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("stub\n", encoding="utf-8")

    popen_envs: list[dict[str, str]] = []

    class DummyProc:
        def __init__(self, lines: list[str], rc: int, pid: int):
            self.pid = pid
            self.stdout = iter(lines)
            self._rc = rc

        def wait(self):
            return self._rc

    attempts = [
        DummyProc(
            [
                "/* parallel function decompilation: 2 workers, shared imports */\n",
                "RuntimeError: can't start new thread\n",
            ],
            1,
            4322,
        ),
        DummyProc(
            [
                "/* parallel function decompilation: disabled (forced serial) */\n",
                "done in 1.0s; failures=0/2\n",
            ],
            0,
            4323,
        ),
    ]

    def fake_popen(cmd, cwd=None, env=None, stdout=None, stderr=None, **kwargs):
        popen_envs.append(dict(env))
        return attempts.pop(0)

    class RunResult:
        def __init__(self):
            self.stdout = ""
            self.returncode = 0

    monkeypatch.setattr(harness, "check_stop_file", lambda: None)
    monkeypatch.setattr(harness, "preflight_resource_check", lambda _context: None)
    monkeypatch.setattr(harness, "trim_old_logs", lambda: None)
    monkeypatch.setattr("meta_harness.orchestrator.register_child_process", lambda *args, **kwargs: None)
    monkeypatch.setattr("meta_harness.orchestrator.unregister_child_process", lambda *args, **kwargs: None)
    monkeypatch.setattr("meta_harness.orchestrator.subprocess.run", lambda *args, **kwargs: RunResult())
    monkeypatch.setattr("meta_harness.orchestrator.subprocess.Popen", fake_popen)

    harness.sweep_step()

    state = json.loads((harness.current_cycle_dir / "cycle.state.json").read_text(encoding="utf-8"))
    assert state["steps"]["full-sweep"]["status"] == "done"
    assert len(popen_envs) == 2
    assert "INERTIA_FORCE_SERIAL_FUNCTION_DECOMPILATION" not in popen_envs[0]
    assert popen_envs[1]["INERTIA_FORCE_SERIAL_FUNCTION_DECOMPILATION"] == "1"
    evidence = cfg.evidence_log_file.read_text(encoding="utf-8")
    assert "retry reason=thread-start failure; retrying full sweep with forced serial function decompilation" in evidence
    assert "disabled (forced serial)" in evidence


def test_finalize_run_marks_terminated_cycle_and_captures_snapshot(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()
    harness.mark_cycle_step("planner", "running")

    captured = []
    monkeypatch.setattr(harness, "capture_cycle_snapshot", lambda tag: captured.append(tag))

    harness.finalize_run("terminated", 143)

    state = json.loads((harness.current_cycle_dir / "cycle.state.json").read_text(encoding="utf-8"))
    assert state["steps"]["planner"]["status"] == "terminated"
    assert state["steps"]["planner"]["extra"] == "exit_code=143"
    assert captured == ["terminated"]


def test_preflight_resource_check_marks_low_disk_as_blocked(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()

    monkeypatch.setattr(harness, "cleanup_state_dir", lambda: None)
    monkeypatch.setattr(harness, "free_disk_mb", lambda: 100)
    monkeypatch.setattr(harness, "free_ram_mb", lambda: 8192)
    monkeypatch.setattr(harness, "state_dir_mb", lambda: 32)

    with pytest.raises(ResourceBlockedError) as excinfo:
        harness.preflight_resource_check("full-sweep")

    assert excinfo.value.context == "full-sweep"
    state = json.loads((harness.current_cycle_dir / "cycle.state.json").read_text(encoding="utf-8"))
    assert state["steps"]["full-sweep"]["status"] == "blocked-low-disk"
    assert "required=8192MB" in state["steps"]["full-sweep"]["extra"]


def test_maybe_self_restart_writes_restarting_status_before_exec(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()

    monkeypatch.setattr(harness, "_compute_script_checksums", lambda: {"run.sh": "new", "meta_harness": "new"})
    monkeypatch.setattr("meta_harness.orchestrator.os.execvpe", lambda *args, **kwargs: (_ for _ in ()).throw(SystemExit(0)))

    with pytest.raises(SystemExit):
        harness.maybe_self_restart("reviewer")

    status_text = cfg.status_file.read_text(encoding="utf-8")
    assert "step=harness" in status_text
    assert "status=restarting" in status_text
    assert "reason=reviewer" in status_text


def test_note_cycle_outcome_persists_worker_stall_handoff(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()
    harness.mark_cycle_step("worker", "stalled", "iteration=3")
    harness.mark_cycle_step("reviewer", "done", "remaining=3")

    harness.note_cycle_outcome("3")

    state = json.loads((harness.current_cycle_dir / "cycle.state.json").read_text(encoding="utf-8"))
    assert state["next_cycle_start_step"] == "worker"
    assert state["worker_stall_streak"] == 1


def test_note_cycle_outcome_routes_to_planner_when_current_item_is_broad(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    cfg.plan_path.write_text(
        "1. `decompile.py:10`, `a.py:20`, `b.py:30`, `c.py:40`, `d.py:50`, `e.py:60`, `f.py:70`, `g.py:80`, `h.py:90`, `i.py:100` giant item\n",
        encoding="utf-8",
    )
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()
    harness.mark_cycle_step("worker", "stalled", "iteration=3")
    harness.mark_cycle_step("reviewer", "done", "remaining=1")

    harness.note_cycle_outcome("1")

    state = json.loads((harness.current_cycle_dir / "cycle.state.json").read_text(encoding="utf-8"))
    assert state["next_cycle_start_step"] == "planner"
    assert state["plan_rewrite_target"]
    assert state["current_plan_item_stall_count"] == 1


def test_worker_cycle_retries_after_failed_fresh_run(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()

    failed_log = cfg.log_dir / "failed_worker.log"
    failed_log.parent.mkdir(parents=True, exist_ok=True)
    failed_log.write_text("partial output\n", encoding="utf-8")

    success_log = cfg.log_dir / "ok_worker.log"
    success_log.write_text("correctness\nrecompilation\nGlobal Remaining steps: 0\n", encoding="utf-8")

    calls = {"count": 0}

    def fake_run_role(role, model, prompt, resume=False, **_kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise RoleRunError(role, failed_log, "worker resume failed")
        if calls["count"] == 2:
            raise RoleRunError(role, failed_log, "worker failed")
        return success_log

    monkeypatch.setattr(harness, "check_stop_file", lambda: None)
    monkeypatch.setattr(harness, "preflight_resource_check", lambda _context: None)
    monkeypatch.setattr(harness, "run_role", fake_run_role)
    monkeypatch.setattr("meta_harness.orchestrator.time.sleep", lambda _secs: None)

    harness.worker_cycle()

    state = json.loads((harness.current_cycle_dir / "cycle.state.json").read_text(encoding="utf-8"))
    assert calls["count"] == 3
    assert state["steps"]["worker"]["status"] == "done"
    assert (harness.current_cycle_dir / "worker.iter01.resume-failed.log").exists()
    assert (harness.current_cycle_dir / "worker.iter01.failed.log").exists()
    assert (harness.current_cycle_dir / "worker.iter02.log").exists()


def test_worker_cycle_does_not_retry_fresh_immediately_after_resume_timeout(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()

    timed_out_log = cfg.log_dir / "timed_out_worker.log"
    timed_out_log.parent.mkdir(parents=True, exist_ok=True)
    timed_out_log.write_text("partial output before timeout\n", encoding="utf-8")

    success_log = cfg.log_dir / "ok_worker.log"
    success_log.write_text("correctness\nrecompilation\nGlobal Remaining steps: 0\n", encoding="utf-8")

    calls = {"count": 0}

    def fake_run_role(role, model, prompt, resume=False, **_kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise RoleRunError(role, timed_out_log, "worker resume timed out", 124)
        return success_log

    monkeypatch.setattr(harness, "check_stop_file", lambda: None)
    monkeypatch.setattr(harness, "preflight_resource_check", lambda _context: None)
    monkeypatch.setattr(harness, "run_role", fake_run_role)
    monkeypatch.setattr("meta_harness.orchestrator.time.sleep", lambda _secs: None)

    harness.worker_cycle()

    state = json.loads((harness.current_cycle_dir / "cycle.state.json").read_text(encoding="utf-8"))
    assert calls["count"] == 2
    assert state["steps"]["worker"]["status"] == "done"
    assert (harness.current_cycle_dir / "worker.iter01.resume-timeout.log").exists()
    assert not (harness.current_cycle_dir / "worker.iter01.failed.log").exists()
    assert (harness.current_cycle_dir / "worker.iter02.log").exists()


def test_worker_cycle_retries_when_worker_claims_zero_but_plan_has_steps(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    cfg.plan_path.write_text("## Remaining steps\n\n1. First\n2. Second\n\nGlobal Remaining steps: 2\n", encoding="utf-8")
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()

    stale_log = cfg.log_dir / "stale_worker.log"
    stale_log.parent.mkdir(parents=True, exist_ok=True)
    stale_log.write_text("correctness\nrecompilation\nGlobal Remaining steps: 0\n", encoding="utf-8")

    good_log = cfg.log_dir / "good_worker.log"
    good_log.write_text("correctness\nrecompilation\nGlobal Remaining steps: 0\n", encoding="utf-8")

    session_file = cfg.state_dir / "worker.session"
    session_file.parent.mkdir(parents=True, exist_ok=True)
    session_file.write_text("stale-session\n", encoding="utf-8")

    calls = {"count": 0}

    def fake_run_role(role, model, prompt, resume=False, **_kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            return stale_log
        cfg.plan_path.write_text("Global Remaining steps: 0\n", encoding="utf-8")
        return good_log

    monkeypatch.setattr(harness, "check_stop_file", lambda: None)
    monkeypatch.setattr(harness, "preflight_resource_check", lambda _context: None)
    monkeypatch.setattr(harness, "run_role", fake_run_role)
    monkeypatch.setattr("meta_harness.orchestrator.time.sleep", lambda _secs: None)

    harness.worker_cycle()

    state = json.loads((harness.current_cycle_dir / "cycle.state.json").read_text(encoding="utf-8"))
    assert calls["count"] == 2
    assert not session_file.exists()
    assert state["steps"]["worker"]["status"] == "done"
    assert (harness.current_cycle_dir / "worker.iter01.log").exists()
    assert (harness.current_cycle_dir / "worker.iter02.log").exists()


def test_role_timeout_secs_uses_shorter_budget_for_non_worker(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)

    assert harness.role_timeout_secs("worker") == cfg.codex_timeout_secs
    assert harness.role_timeout_secs("planner") == min(cfg.codex_timeout_secs, 300)
    assert harness.role_timeout_secs("reviewer") == min(cfg.codex_timeout_secs, 180)
    assert harness.role_timeout_secs("checker") == min(cfg.codex_timeout_secs, 180)


def test_planner_timeout_continues_with_existing_plan(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    cfg.plan_path.write_text("1. existing item\n", encoding="utf-8")
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()

    timed_out_log = cfg.log_dir / "timed_out_planner.log"
    timed_out_log.parent.mkdir(parents=True, exist_ok=True)
    timed_out_log.write_text("partial planner output before timeout\n", encoding="utf-8")

    synced = {"count": 0}

    monkeypatch.setattr(harness, "check_stop_file", lambda: None)
    monkeypatch.setattr(harness, "preflight_resource_check", lambda _context: None)
    monkeypatch.setattr(
        harness,
        "run_role",
        lambda role, model, prompt, **_kwargs: (_ for _ in ()).throw(RoleRunError(role, timed_out_log, "planner timed out", 124)),
    )
    monkeypatch.setattr(harness, "sync_current_plan_item", lambda *args, **kwargs: synced.__setitem__("count", synced["count"] + 1))

    harness.planner_step()

    state = json.loads((harness.current_cycle_dir / "cycle.state.json").read_text(encoding="utf-8"))
    assert synced["count"] == 1
    assert state["steps"]["planner"]["status"] == "done-with-failures"
    assert (harness.current_cycle_dir / "planner.timeout.log").exists()


def test_reviewer_timeout_returns_plan_remaining(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    cfg.plan_path.write_text("1. one\n2. two\n", encoding="utf-8")
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()

    timed_out_log = cfg.log_dir / "timed_out_reviewer.log"
    timed_out_log.parent.mkdir(parents=True, exist_ok=True)
    timed_out_log.write_text("partial reviewer output before timeout\n", encoding="utf-8")

    monkeypatch.setattr(harness, "check_stop_file", lambda: None)
    monkeypatch.setattr(harness, "preflight_resource_check", lambda _context: None)
    monkeypatch.setattr(
        harness,
        "run_role",
        lambda role, model, prompt, **_kwargs: (_ for _ in ()).throw(RoleRunError(role, timed_out_log, "reviewer timed out", 124)),
    )
    monkeypatch.setattr(harness, "plan_remaining_steps", lambda: 2)

    remaining = harness.reviewer_step()

    state = json.loads((harness.current_cycle_dir / "cycle.state.json").read_text(encoding="utf-8"))
    assert remaining == "2"
    assert harness.current_task_packet_status == "partial"
    assert state["steps"]["reviewer"]["status"] == "done-with-failures"
    assert (harness.current_cycle_dir / "reviewer.timeout.log").exists()


def test_consume_operator_comments_archives_and_clears_file(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()
    cfg.operator_comments_file.write_text("Please improve harness retry logic.\n", encoding="utf-8")

    comments = harness.consume_operator_comments("worker")

    assert "retry logic" in comments
    assert cfg.operator_comments_file.read_text(encoding="utf-8") == ""
    archived = list(harness.current_cycle_dir.glob("operator-comments.*.worker.md"))
    assert len(archived) == 1
    assert "retry logic" in archived[0].read_text(encoding="utf-8")


def test_prepare_cycle_workspace_clears_legacy_worker_session(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    legacy = cfg.state_dir / "worker.session"
    legacy.parent.mkdir(parents=True, exist_ok=True)
    legacy.write_text("old-session\n", encoding="utf-8")

    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()

    assert not legacy.exists()


def test_worker_cycle_stalls_after_consecutive_failures(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()

    failed_log = cfg.log_dir / "failed_worker.log"
    failed_log.parent.mkdir(parents=True, exist_ok=True)
    failed_log.write_text("partial output\n", encoding="utf-8")

    def fake_run_role(role, model, prompt, resume=False, **_kwargs):
        raise RoleRunError(role, failed_log, "worker failed")

    monkeypatch.setattr(harness, "check_stop_file", lambda: None)
    monkeypatch.setattr(harness, "preflight_resource_check", lambda _context: None)
    monkeypatch.setattr(harness, "run_role", fake_run_role)
    monkeypatch.setattr("meta_harness.orchestrator.time.sleep", lambda _secs: None)

    harness.worker_cycle()

    state = json.loads((harness.current_cycle_dir / "cycle.state.json").read_text(encoding="utf-8"))
    assert state["steps"]["worker"]["status"] == "stalled"
    assert "consecutive_failures=3" in state["steps"]["worker"]["extra"]


def test_worker_cycle_stalls_after_repeated_no_progress_logs(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()

    repeated_log = cfg.log_dir / "repeated_worker.log"
    repeated_log.parent.mkdir(parents=True, exist_ok=True)
    repeated_log.write_text(
        "codex\n"
        "Item 8 remains blocked. Local tree remains unchanged.\n\n"
        "Global Remaining steps: 1\n"
        "tokens used\n"
        "1,234\n",
        encoding="utf-8",
    )

    calls = {"count": 0}

    def fake_run_role(role, model, prompt, resume=False, **_kwargs):
        calls["count"] += 1
        return repeated_log

    monkeypatch.setattr(harness, "check_stop_file", lambda: None)
    monkeypatch.setattr(harness, "preflight_resource_check", lambda _context: None)
    monkeypatch.setattr(harness, "run_role", fake_run_role)
    monkeypatch.setattr("meta_harness.orchestrator.time.sleep", lambda _secs: None)

    harness.worker_cycle()

    state = json.loads((harness.current_cycle_dir / "cycle.state.json").read_text(encoding="utf-8"))
    assert state["steps"]["worker"]["status"] == "stalled"
    assert "repeated_nonzero_result" in state["steps"]["worker"]["extra"]
    assert calls["count"] == 3


def test_worker_cycle_stalls_after_max_worker_iters(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    cfg = cfg.__class__(**{**cfg.__dict__, "max_worker_iters": 2})
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()

    progress_log = cfg.log_dir / "progress_worker.log"
    progress_log.parent.mkdir(parents=True, exist_ok=True)
    progress_log.write_text(
        "codex\n"
        "Item 11 remains blocked; the upstream hook is still absent.\n"
        "Global Remaining steps: 3\n",
        encoding="utf-8",
    )

    calls = {"count": 0}

    def fake_run_role(role, model, prompt, resume=False, **_kwargs):
        calls["count"] += 1
        return progress_log

    monkeypatch.setattr(harness, "check_stop_file", lambda: None)
    monkeypatch.setattr(harness, "preflight_resource_check", lambda _context: None)
    monkeypatch.setattr(harness, "run_role", fake_run_role)
    monkeypatch.setattr("meta_harness.orchestrator.time.sleep", lambda _secs: None)

    harness.worker_cycle()

    state = json.loads((harness.current_cycle_dir / "cycle.state.json").read_text(encoding="utf-8"))
    assert state["steps"]["worker"]["status"] == "stalled"
    assert "max_worker_iters_exhausted" in state["steps"]["worker"]["extra"]
    assert calls["count"] == 2


def test_reviewer_step_receives_worker_stall_context(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()
    harness.mark_cycle_step("worker", "stalled", "iteration=3 consecutive_failures=3")
    stalled_log = harness.current_cycle_dir / "worker.iter03.resume-timeout.log"
    stalled_log.write_text("partial output\n[2026-04-04T00:00:00+00:00] end rc=124\n", encoding="utf-8")

    captured: dict[str, object] = {}
    reviewer_log = cfg.log_dir / "reviewer.log"
    reviewer_log.parent.mkdir(parents=True, exist_ok=True)
    reviewer_log.write_text("correctness\nrecompilation\nGlobal Remaining steps: 1\n", encoding="utf-8")

    monkeypatch.setattr(harness, "check_stop_file", lambda: None)
    monkeypatch.setattr(harness, "preflight_resource_check", lambda _context: None)

    def fake_run_role(role, model, prompt, resume=False, **_kwargs):
        captured["role"] = role
        captured["prompt"] = prompt
        return reviewer_log

    monkeypatch.setattr(harness, "run_role", fake_run_role)

    remaining = harness.reviewer_step()

    assert remaining == "1"
    assert captured["role"] == "reviewer"
    assert "Worker stall diagnosis for this cycle" in str(captured["prompt"])
    assert "worker.iter03.resume-timeout.log" in str(captured["prompt"])


def test_run_fast_resumes_next_cycle_at_worker_after_stall(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    calls: list[str] = []
    cycle_numbers: list[int] = []

    monkeypatch.setattr(harness, "ensure_prereqs", lambda: None)
    monkeypatch.setattr(harness, "acquire_lock", lambda: None)
    monkeypatch.setattr(harness, "check_stop_file", lambda: None)
    monkeypatch.setattr(harness, "preflight_resource_check", lambda _context: None)
    monkeypatch.setattr(harness, "capture_cycle_snapshot", lambda _tag: None)
    monkeypatch.setattr(harness, "maybe_self_restart", lambda _reason: False)

    original_prepare = harness.prepare_cycle_workspace

    def fake_prepare() -> None:
        original_prepare()
        cycle_numbers.append(harness.current_cycle_index)

    def fake_sweep() -> None:
        calls.append(f"sweep:{harness.current_cycle_index}")
        harness.mark_cycle_step("full-sweep", "done")

    def fake_checker() -> None:
        calls.append(f"checker:{harness.current_cycle_index}")
        harness.mark_cycle_step("checker", "done", "remaining=4")

    def fake_planner() -> None:
        calls.append(f"planner:{harness.current_cycle_index}")
        harness.mark_cycle_step("planner", "done", "remaining=4")

    def fake_worker() -> None:
        calls.append(f"worker:{harness.current_cycle_index}")
        if harness.current_cycle_index == 1:
            harness.mark_cycle_step("worker", "stalled", "iteration=3 consecutive_failures=3")
        else:
            harness.mark_cycle_step("worker", "done", "remaining=0")

    reviewer_returns = iter(["4", "0"])

    def fake_reviewer() -> str:
        calls.append(f"reviewer:{harness.current_cycle_index}")
        remaining = next(reviewer_returns)
        harness.mark_cycle_step("reviewer", "done", f"remaining={remaining}")
        return remaining

    monkeypatch.setattr(harness, "prepare_cycle_workspace", fake_prepare)
    monkeypatch.setattr(harness, "sweep_step", fake_sweep)
    monkeypatch.setattr(harness, "checker_step", fake_checker)
    monkeypatch.setattr(harness, "planner_step", fake_planner)
    monkeypatch.setattr(harness, "worker_cycle", fake_worker)
    monkeypatch.setattr(harness, "reviewer_step", fake_reviewer)

    assert harness.run(resume=False) == 0
    assert calls == [
        "sweep:1",
        "checker:1",
        "planner:1",
        "worker:1",
        "reviewer:1",
        "worker:2",
        "reviewer:2",
    ]
    assert cycle_numbers == [1, 2]


def test_worker_cycle_uses_escalated_model_and_failure_limit_after_stall(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()
    harness.worker_stall_streak = 1

    timed_out_log = cfg.log_dir / "timed_out_worker.log"
    timed_out_log.parent.mkdir(parents=True, exist_ok=True)
    timed_out_log.write_text("partial output before timeout\n", encoding="utf-8")

    calls: list[tuple[str, bool]] = []

    def fake_run_role(role, model, prompt, resume=False, **_kwargs):
        calls.append((model, resume))
        raise RoleRunError(role, timed_out_log, "worker timed out", 124)

    monkeypatch.setattr(harness, "check_stop_file", lambda: None)
    monkeypatch.setattr(harness, "preflight_resource_check", lambda _context: None)
    monkeypatch.setattr(harness, "run_role", fake_run_role)
    monkeypatch.setattr("meta_harness.orchestrator.time.sleep", lambda _secs: None)

    harness.worker_cycle()

    state = json.loads((harness.current_cycle_dir / "cycle.state.json").read_text(encoding="utf-8"))
    assert state["steps"]["worker"]["status"] == "stalled"
    assert len(calls) == cfg.worker_stall_failure_limit
    assert all(model == cfg.worker_stall_model for model, _resume in calls)


def test_current_worker_model_auto_escalates_after_recent_timeout_log(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()

    timeout_log = harness.current_cycle_dir / "worker.iter01.resume-timeout.log"
    timeout_log.write_text("partial output\n[2026-04-04T00:00:00+00:00] end rc=124\n", encoding="utf-8")

    assert harness.recent_worker_escalation_reason() == "recent-timeout"
    assert harness.current_worker_model() == cfg.worker_stall_model
    assert harness.current_worker_failure_limit() == cfg.worker_stall_failure_limit


def test_first_plan_item_text_returns_first_numbered_item(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    cfg.plan_path.write_text(
        "1. `decompile.py:10` fix BYTEOPS first\n"
        "still same item detail\n"
        "2. `other.py:20` later item\n",
        encoding="utf-8",
    )
    harness = MetaHarness(cfg, llm_cfg)

    assert harness.first_plan_item_text() == "1. `decompile.py:10` fix BYTEOPS first\nstill same item detail"


def test_build_worker_retry_context_reports_recent_failures(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()
    (harness.current_cycle_dir / "worker.iter01.resume-timeout.log").write_text("partial output\n", encoding="utf-8")
    (harness.current_cycle_dir / "worker.iter02.log").write_text(
        "FAILED angr_platforms/tests/test_x86_16_cod_samples.py::test_byteops_cod_main_renders_named_byte_locals_without_generic_staging_names\n",
        encoding="utf-8",
    )
    (harness.current_cycle_dir / "worker.iter03.log").write_text(
        "FAILED angr_platforms/tests/test_x86_16_cod_samples.py::test_byteops_cod_main_renders_named_byte_locals_without_generic_staging_names\n",
        encoding="utf-8",
    )

    context = harness.build_worker_retry_context()

    assert "worker.iter01.resume-timeout.log: timeout" in context
    assert "repeated failing test:" in context


def test_current_worker_model_auto_escalates_on_repeated_failed_test(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()

    (harness.current_cycle_dir / "worker.iter01.log").write_text(
        "FAILED angr_platforms/tests/test_x86_16_cod_samples.py::test_byteops_cod_main_renders_named_byte_locals_without_generic_staging_names\n",
        encoding="utf-8",
    )
    (harness.current_cycle_dir / "worker.iter02.log").write_text(
        "FAILED angr_platforms/tests/test_x86_16_cod_samples.py::test_byteops_cod_main_renders_named_byte_locals_without_generic_staging_names\n",
        encoding="utf-8",
    )

    assert "repeated-failed-test=" in harness.recent_worker_escalation_reason()
    assert harness.current_worker_model() == cfg.worker_stall_model
    assert harness.current_worker_failure_limit() == cfg.worker_stall_failure_limit


def test_worker_cycle_recomputes_model_after_first_timeout(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()

    timeout_log = cfg.log_dir / "timed_out_worker.log"
    timeout_log.parent.mkdir(parents=True, exist_ok=True)
    timeout_log.write_text("partial output before timeout\n", encoding="utf-8")

    success_log = cfg.log_dir / "ok_worker.log"
    success_log.write_text("correctness\nrecompilation\nGlobal Remaining steps: 0\n", encoding="utf-8")

    calls: list[tuple[str, bool]] = []

    def fake_run_role(role, model, prompt, resume=False, **_kwargs):
        calls.append((model, resume))
        if len(calls) == 1:
            raise RoleRunError(role, timeout_log, "worker timed out", 124)
        return success_log

    monkeypatch.setattr(harness, "check_stop_file", lambda: None)
    monkeypatch.setattr(harness, "preflight_resource_check", lambda _context: None)
    monkeypatch.setattr(harness, "run_role", fake_run_role)
    monkeypatch.setattr("meta_harness.orchestrator.time.sleep", lambda _secs: None)

    harness.worker_cycle()

    assert calls == [
        (cfg.worker_model, True),
        (cfg.worker_stall_model, True),
    ]
