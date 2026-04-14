from __future__ import annotations

from meta_harness.config import RuntimeConfig
from meta_harness.prompts import (
    build_checker_prompt,
    build_crash_reviewer_prompt,
    build_planner_prompt,
    build_resume_prompt,
    build_reviewer_prompt,
    build_worker_prompt,
)


def _cfg(monkeypatch, tmp_path):
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    return RuntimeConfig.from_env([])


def test_planner_prompt_mentions_plan_and_remaining_steps(monkeypatch, tmp_path):
    cfg = _cfg(monkeypatch, tmp_path)
    prompt = build_planner_prompt(cfg)
    assert str(cfg.plan_path) in prompt
    assert "Global Remaining steps: N" in prompt
    assert "small enough for one focused worker cycle" in prompt
    assert "Do not rerun the evidence sweep" in prompt
    assert "flat numbered checklist" in prompt
    assert "source line numbers" in prompt
    assert "exact implementation steps" in prompt
    assert "what to edit in those files in execution order" in prompt
    assert "definition of done" in prompt
    assert "execution specification" in prompt
    assert (
        "Goal, Why now, Edit targets, Required edits, Required tests, Verification commands, Definition of done, Stop conditions"
        in prompt
    )
    assert "Required edits must be imperative and executable" in prompt
    assert "Verification commands must be concrete shell commands" in prompt
    assert "Do not emit vague planner language" in prompt
    assert "Do not emit phase headers, aspirational themes, or research bullets" in prompt
    assert "If you cannot fill the required fields for an item, inspect the code and existing tests until you can" in prompt
    assert "Preserve unfinished strategic items" in prompt
    assert "Do not drop user-added unfinished goals" in prompt
    assert "Pause for minute" not in prompt
    assert "Speak in compact cave-man English" in prompt
    assert "Short words. Short lines." in prompt
    assert "Avoid spending tokens on implementation" in prompt
    assert "Use task packets, typed summaries, and artifact paths instead of replaying full history" in prompt
    assert "Trim tool output to the signal before reusing it in a prompt" in prompt
    assert "Do not run pytest, corpus scans, or large validation commands" in prompt
    assert "Read the current evidence and debug logs first" in prompt
    assert "brainstorm the earliest correct architectural layer" in prompt
    assert "simplify it instead of layering on more policy" in prompt
    assert "cannot be solved cleanly inside the current project architecture" in prompt
    assert "Prefer architecturally correct placement over convenience" in prompt
    assert "compare them briefly and pick the one with the least semantic debt" in prompt
    assert "harness-side change and a decompiler-side change are both plausible" in prompt
    assert "tail-validation summary or detail-artifact paths" in prompt
    assert "identify the concrete failing family from the logs" in prompt
    assert "Use the logs to determine where the problem lives" in prompt
    assert "plan the smallest repro and the profiling command before planning an optimization" in prompt
    assert "Cite the specific log file, artifact path, function name, or warning/error family" in prompt
    assert "Do not claim a root cause unless the current logs or artifacts support it" in prompt
    assert "If the existing logs do not explain the current tail-validation failure family well enough" in prompt
    assert "Green level: red" in prompt


def test_planner_prompt_accepts_current_item_and_rewrite_target(monkeypatch, tmp_path):
    cfg = _cfg(monkeypatch, tmp_path)
    prompt = build_planner_prompt(
        cfg,
        current_item="1. `decompile.py:10` current item",
        rewrite_target="1. giant item to split",
    )
    assert "Current plan item in progress" in prompt
    assert "current item" in prompt
    assert "Planner rewrite request" in prompt
    assert "giant item to split" in prompt


def test_planner_prompt_avoids_duplicate_rewrite_body_when_task_packet_matches(monkeypatch, tmp_path):
    cfg = _cfg(monkeypatch, tmp_path)
    item = "1. [rewrite] giant item to split"
    packet = "Task packet id: 1\nObjective: split item"
    prompt = build_planner_prompt(cfg, current_item=item, rewrite_target=item, task_packet=packet)

    assert prompt.count(item) == 0
    assert "Rewrite the active task packet into smaller numbered items" in prompt
    assert "Current task packet" in prompt


def test_worker_prompt_mentions_implementation_role(monkeypatch, tmp_path):
    cfg = _cfg(monkeypatch, tmp_path)
    prompt = build_worker_prompt(cfg)
    assert "Continue implementing the unfinished steps" in prompt
    assert "one unfinished top-level plan item at a time" in prompt
    assert "Never use source-specific hacks" in prompt
    assert "If the harness itself is the blocker, simplify or improve it" in prompt
    assert "If the current decompiler architecture blocks an honest fix" in prompt
    assert "Speak in compact cave-man English" in prompt
    assert "Run the smallest test that proves the touched behavior" in prompt
    assert "Use task packets, typed summaries, and artifact paths instead of replaying full history" in prompt
    assert "change code or the hypothesis before rerunning that same test" in prompt
    assert "capture a concrete profile/trace/log snapshot before the first fix" in prompt
    assert "Use cProfile/line_profiler/memray/py-spy through the active virtualenv" in prompt
    assert "wall time, RSS, timeout behavior" in prompt
    assert "Green level: focused-item-green|cycle-green|merge-safe-green|red" in prompt


def test_worker_prompt_accepts_focus_item_and_retry_context(monkeypatch, tmp_path):
    cfg = _cfg(monkeypatch, tmp_path)
    prompt = build_worker_prompt(
        cfg,
        focus_item="1. `decompile.py:10` fix BYTEOPS first",
        retry_context="- worker.iter01.resume-timeout.log: timeout\n- repeated failing test: test_byteops (2 times)",
    )
    assert "Current focus item" in prompt
    assert "fix BYTEOPS first" in prompt
    assert "Recent worker retry context" in prompt
    assert "repeated failing test: test_byteops" in prompt
    assert "more detail line" not in build_worker_prompt(
        cfg,
        focus_item="1. `decompile.py:10` fix BYTEOPS first\nmore detail line",
    )


def test_worker_and_planner_prompts_accept_task_packet(monkeypatch, tmp_path):
    cfg = _cfg(monkeypatch, tmp_path)
    task_packet = "Task packet id: 1\nObjective: fix BYTEOPS\nAcceptance tests: pytest test_byteops"
    worker = build_worker_prompt(cfg, task_packet=task_packet)
    planner = build_planner_prompt(cfg, task_packet=task_packet)
    assert "Active task packet" in worker
    assert "fix BYTEOPS" in worker
    assert "Current task packet" in planner
    assert "pytest test_byteops" in planner


def test_master_prompts_include_repo_standing_tasks(monkeypatch, tmp_path):
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    monkeypatch.setenv("REPO_STANDING_TASKS", "keep COD tail validation active\nfix remaining COD deltas")
    cfg = RuntimeConfig.from_env([])

    planner = build_planner_prompt(cfg)
    worker = build_worker_prompt(cfg)

    assert "Repo standing tasks" in planner
    assert "keep COD tail validation active" in planner
    assert "fix remaining COD deltas" in planner
    assert "Repo standing tasks" in worker


def test_reviewer_prompt_allows_harness_improvements(monkeypatch, tmp_path):
    cfg = _cfg(monkeypatch, tmp_path)
    prompt = build_reviewer_prompt(cfg)
    assert "improve the harness itself" in prompt
    assert "prefer fewer moving parts over more retries" in prompt
    assert "blocked by project architecture" in prompt
    assert "Speak in compact cave-man English" in prompt
    assert "Avoid pytest, sweep reruns, or broad repository exploration" in prompt
    assert "Evaluate the current active task packet explicitly" in prompt
    assert "Task packet status: done|partial|blocked|rewrite" in prompt
    assert "Green level: focused-item-green|cycle-green|merge-safe-green|red" in prompt


def test_reviewer_prompt_accepts_worker_stall_context(monkeypatch, tmp_path):
    cfg = _cfg(monkeypatch, tmp_path)
    prompt = build_reviewer_prompt(
        cfg,
        stall_context="Recent worker iteration logs for this stalled cycle:\n- worker.iter01.log",
        task_packet="Task packet id: 1\nObjective: fix BYTEOPS",
    )
    assert "Worker stall diagnosis for this cycle" in prompt
    assert "without profiling, route the next cycle to a smaller diagnostic plan item" in prompt
    assert "worker.iter01.log" in prompt
    assert "Active task packet" in prompt


def test_checker_and_crash_prompts_reference_evidence(monkeypatch, tmp_path):
    cfg = _cfg(monkeypatch, tmp_path)
    checker = build_checker_prompt(cfg)
    crash = build_crash_reviewer_prompt(cfg, "/tmp/cycle", 7)
    assert str(cfg.evidence_log_file) in checker
    assert "Do not run pytest, corpus scans, or broad repository searches" in checker
    assert "Harness restart required" in crash
    assert "/tmp/cycle" in crash
    assert "too complex for the current lane" in crash


def test_resume_prompt_is_short_and_keeps_required_marker(monkeypatch, tmp_path):
    cfg = _cfg(monkeypatch, tmp_path)
    prompt = build_resume_prompt(
        "worker",
        cfg,
        comments="Use current DOSFUNC evidence only.",
        role_context="Primary plan item:\n1. `decompile.py:10` fix BYTEOPS",
    )
    assert "Continue the existing worker session." in prompt
    assert "Use the existing session context" in prompt
    assert "Global Remaining steps: N" in prompt
    assert "Use current DOSFUNC evidence only." in prompt
    assert "Primary plan item:" in prompt
    assert str(cfg.rules_file) not in prompt
    assert "Avoid re-reading evidence already established in the session" in prompt
