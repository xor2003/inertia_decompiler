from __future__ import annotations

from meta_harness.policy import (
    GREEN_CYCLE,
    GREEN_FOCUSED,
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
from meta_harness.task_packet import (
    TASK_PACKET_SCHEMA_VERSION,
    count_remaining_plan_steps,
    parse_plan_task_packets,
    parse_task_packet,
    plan_item_is_finished,
    prune_completed_plan_file,
    prune_completed_plan_text,
    split_plan_items,
)


def test_parse_task_packet_extracts_core_fields():
    item = (
        "1. `decompile.py:10-20`, `tests/test_byteops.py:1-20`: fix byteops handling. "
        "Done when `BYTEOPS.dec` contains `printf` and pytest tests/test_byteops.py -k byteops passes."
    )
    packet = parse_task_packet(item)
    assert packet.schema_version == TASK_PACKET_SCHEMA_VERSION
    assert packet.item_id == "1"
    assert "fix byteops handling" in packet.objective
    assert "decompile.py" in packet.target_files
    assert any("pytest tests/test_byteops.py -k byteops" in test for test in packet.acceptance_tests)
    assert packet.done_conditions


def test_task_packet_prompt_block_filters_noise_and_compacts_fields():
    item = (
        "6. [rewrite] Goal: Keep wrapper and direct fallback aligned. "
        "Edit `/tmp/repo/a.py:1-2`, `detail_cache_path`, `/tmp/repo/b.py:3-4`, "
        "`emit_tail_validation_snapshot_or_uncollected()`, "
        "`pytest /tmp/repo/tests/test_a.py -k tail_validation`. "
        "Done when wrapper and direct output match and pytest /tmp/repo/tests/test_a.py -k tail_validation passes."
    )
    packet = parse_task_packet(item)
    block = packet.to_prompt_block()

    assert "detail_cache_path" not in block
    assert "pytest /tmp/repo/tests/test_a.py -k tail_validation" in block
    assert "Target files: /tmp/repo/a.py, /tmp/repo/b.py" in block
    assert "Callable refs: emit_tail_validation_snapshot_or_uncollected()" in block
    assert "Escalation policy:" not in block
    assert "Objective: Keep wrapper and direct fallback aligned." in block


def test_parse_plan_task_packets_splits_numbered_items():
    plan = (
        "1. `a.py:1-2`: first item. Done when pytest tests/test_a.py passes.\n"
        "2. `b.py:3-4`: second item. Done when pytest tests/test_b.py passes.\n"
    )
    packets = parse_plan_task_packets(plan)
    assert [packet.item_id for packet in packets] == ["1", "2"]


def test_prune_completed_plan_text_removes_done_items_and_keeps_unfinished():
    plan = (
        "1. Done: finish the first item.\n"
        "Why now: the first item is finished.\n\n"
        "2. [pending] keep the second item.\n"
        "Why now: the second item is still open.\n\n"
        "3. Completed: finish the third item.\n"
    )
    result = prune_completed_plan_text(plan)
    assert result.changed is True
    assert result.original_item_count == 3
    assert result.kept_item_count == 1
    assert result.removed_item_count == 2
    assert "finish the first item" not in result.updated_text
    assert "keep the second item" in result.updated_text
    assert "finish the third item" not in result.updated_text


def test_prune_completed_plan_file_writes_pruned_text(tmp_path):
    plan_path = tmp_path / "PLAN.md"
    plan_path.write_text(
        "1. Done: remove me.\n"
        "Why now: already completed.\n\n"
        "2. [pending] keep me.\n"
        "Why now: still active.\n",
        encoding="utf-8",
    )

    result = prune_completed_plan_file(plan_path)

    assert result.changed is True
    assert result.removed_item_count == 1
    assert plan_path.read_text(encoding="utf-8") == "2. [pending] keep me.\nWhy now: still active.\n"


def test_split_and_count_remaining_plan_steps_ignore_done_numbered_items():
    plan = (
        "1. Done: completed item.\n"
        "Why now: already done.\n\n"
        "2. Goal: active item.\n"
        "Why now: still open.\n\n"
        "3. [completed] also done.\n"
    )
    assert len(split_plan_items(plan)) == 3
    assert plan_item_is_finished("1. Done: completed item.") is True
    assert plan_item_is_finished("2. Goal: active item.") is False
    assert count_remaining_plan_steps(plan) == 1


def test_worker_runtime_policy_escalates_on_recent_reason():
    decision = decide_worker_runtime(
        WorkerRuntimeContext(
            escalation_reason="recent-timeout",
            default_model="gpt-5.4-mini",
            escalated_model="gpt-5.4",
            default_failure_limit=3,
            escalated_failure_limit=2,
            current_plan_item_stall_count=0,
        )
    )
    assert decision.primary_action() == "switch_worker_model"
    assert decision.actions[0].details["model"] == "gpt-5.4"


def test_worker_timeout_policy_escalates_at_limit():
    decision = decide_worker_timeout(WorkerTimeoutContext(consecutive_failures=3, failure_limit=3))
    assert decision.primary_action() == "escalate_to_reviewer"


def test_cycle_followup_policy_requests_rewrite_for_broad_stalled_item():
    decision = decide_cycle_followup(
        CycleOutcomeContext(
            reviewer_remaining="3",
            worker_stalled=True,
            current_plan_item_requires_replan=True,
            current_plan_item_stall_count=2,
        )
    )
    assert decision.primary_action() == "rewrite_current_item"


def test_green_level_policy_infers_focused_and_cycle_levels():
    focused = decide_green_level(GreenLevelContext(worker_remaining="0"))
    cycle = decide_green_level(GreenLevelContext(reviewer_remaining="0", evidence_failures=0))
    red = decide_green_level(GreenLevelContext(reviewer_remaining="1", evidence_failures=0))
    assert focused.actions[0].details["green_level"] == GREEN_FOCUSED
    assert cycle.actions[0].details["green_level"] == GREEN_CYCLE
    assert red.actions[0].details["green_level"] == GREEN_RED
