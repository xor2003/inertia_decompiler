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
from meta_harness.task_packet import TASK_PACKET_SCHEMA_VERSION, parse_plan_task_packets, parse_task_packet


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


def test_parse_plan_task_packets_splits_numbered_items():
    plan = (
        "1. `a.py:1-2`: first item. Done when pytest tests/test_a.py passes.\n"
        "2. `b.py:3-4`: second item. Done when pytest tests/test_b.py passes.\n"
    )
    packets = parse_plan_task_packets(plan)
    assert [packet.item_id for packet in packets] == ["1", "2"]


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
