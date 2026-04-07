from __future__ import annotations

from dataclasses import dataclass, field


GREEN_RED = "red"
GREEN_FOCUSED = "focused-item-green"
GREEN_CYCLE = "cycle-green"
GREEN_MERGE_SAFE = "merge-safe-green"


@dataclass(frozen=True)
class PolicyAction:
    name: str
    details: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyDecision:
    name: str
    reason: str
    actions: tuple[PolicyAction, ...] = ()
    details: dict[str, object] = field(default_factory=dict)

    def primary_action(self) -> str:
        return self.actions[0].name if self.actions else self.name


@dataclass(frozen=True)
class WorkerRuntimeContext:
    escalation_reason: str
    default_model: str
    escalated_model: str
    default_failure_limit: int
    escalated_failure_limit: int
    current_plan_item_stall_count: int


def decide_worker_runtime(context: WorkerRuntimeContext) -> PolicyDecision:
    if context.escalation_reason:
        reason = context.escalation_reason
        if context.current_plan_item_stall_count >= 2 and "repeated-failed-test=" in reason:
            return PolicyDecision(
                name="worker_runtime_escalated",
                reason="repeated failed test on a stalled item",
                actions=(
                    PolicyAction("switch_worker_model", {"model": context.escalated_model}),
                    PolicyAction("reduce_failure_limit", {"failure_limit": max(1, context.escalated_failure_limit - 1)}),
                ),
                details={"escalation_reason": reason},
            )
        return PolicyDecision(
            name="worker_runtime_escalated",
            reason="recent worker history indicates escalation",
            actions=(
                PolicyAction("switch_worker_model", {"model": context.escalated_model}),
                PolicyAction("reduce_failure_limit", {"failure_limit": context.escalated_failure_limit}),
            ),
            details={"escalation_reason": reason},
        )
    return PolicyDecision(
        name="worker_runtime_default",
        reason="no recent escalation trigger",
        actions=(
            PolicyAction("use_default_worker_model", {"model": context.default_model}),
            PolicyAction("use_default_failure_limit", {"failure_limit": context.default_failure_limit}),
        ),
    )


@dataclass(frozen=True)
class WorkerTimeoutContext:
    consecutive_failures: int
    failure_limit: int


def decide_worker_timeout(context: WorkerTimeoutContext) -> PolicyDecision:
    if context.consecutive_failures >= context.failure_limit:
        return PolicyDecision(
            name="worker_timeout_stall",
            reason="timeout/failure limit reached",
            actions=(PolicyAction("escalate_to_reviewer", {"failure_limit": context.failure_limit}),),
        )
    return PolicyDecision(
        name="worker_timeout_retry",
        reason="timeout budget not yet exhausted",
        actions=(PolicyAction("retry_worker_fresh", {"remaining_budget": context.failure_limit - context.consecutive_failures}),),
    )


@dataclass(frozen=True)
class CycleOutcomeContext:
    reviewer_remaining: str
    worker_stalled: bool
    current_plan_item_requires_replan: bool
    current_plan_item_stall_count: int


def decide_cycle_followup(context: CycleOutcomeContext) -> PolicyDecision:
    if context.reviewer_remaining == "0":
        return PolicyDecision(
            name="cycle_complete",
            reason="reviewer reports no remaining work",
            actions=(PolicyAction("close_cycle"),),
        )
    if context.worker_stalled and context.current_plan_item_requires_replan:
        return PolicyDecision(
            name="rewrite_current_item",
            reason="current item is too broad or repeatedly stalled",
            actions=(PolicyAction("rewrite_current_item"), PolicyAction("route_next_cycle_to_planner")),
            details={"current_plan_item_stall_count": context.current_plan_item_stall_count},
        )
    if context.worker_stalled:
        return PolicyDecision(
            name="resume_worker_directly",
            reason="worker stalled but current item is still focused enough",
            actions=(PolicyAction("resume_worker"),),
            details={"current_plan_item_stall_count": context.current_plan_item_stall_count},
        )
    return PolicyDecision(
        name="continue_cycle",
        reason="work remains after review",
        actions=(PolicyAction("continue_cycle"),),
    )


@dataclass(frozen=True)
class GreenLevelContext:
    worker_remaining: str = ""
    reviewer_remaining: str = ""
    evidence_failures: int = 0
    reviewer_reported_green: str = ""
    worker_reported_green: str = ""


def normalize_green_level(value: str) -> str:
    lowered = value.strip().lower()
    mapping = {
        GREEN_RED: GREEN_RED,
        GREEN_FOCUSED: GREEN_FOCUSED,
        GREEN_CYCLE: GREEN_CYCLE,
        GREEN_MERGE_SAFE: GREEN_MERGE_SAFE,
        "focused": GREEN_FOCUSED,
        "cycle": GREEN_CYCLE,
        "merge-safe": GREEN_MERGE_SAFE,
        "merge_safe": GREEN_MERGE_SAFE,
    }
    return mapping.get(lowered, "")


def decide_green_level(context: GreenLevelContext) -> PolicyDecision:
    reviewer_green = normalize_green_level(context.reviewer_reported_green)
    if reviewer_green:
        return PolicyDecision(
            name="green_level_reported",
            reason="reviewer reported explicit green level",
            actions=(PolicyAction("set_green_level", {"green_level": reviewer_green}),),
        )
    worker_green = normalize_green_level(context.worker_reported_green)
    if worker_green:
        return PolicyDecision(
            name="green_level_reported",
            reason="worker reported explicit green level",
            actions=(PolicyAction("set_green_level", {"green_level": worker_green}),),
        )
    if context.reviewer_remaining == "0" and context.evidence_failures == 0:
        return PolicyDecision(
            name="green_level_cycle",
            reason="reviewer finished and evidence has no failures",
            actions=(PolicyAction("set_green_level", {"green_level": GREEN_CYCLE}),),
        )
    if context.worker_remaining == "0":
        return PolicyDecision(
            name="green_level_focused",
            reason="worker reports current item completed",
            actions=(PolicyAction("set_green_level", {"green_level": GREEN_FOCUSED}),),
        )
    return PolicyDecision(
        name="green_level_red",
        reason="remaining work or failures still present",
        actions=(PolicyAction("set_green_level", {"green_level": GREEN_RED}),),
    )
