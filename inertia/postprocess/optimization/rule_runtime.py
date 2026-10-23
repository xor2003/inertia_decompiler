"""Layer: Rewrite/Postprocess cleanup.

Responsibility: own the shared typed runtime contract for the named cleanup
optimization rules in ``pass_driver.OPTIMIZATION_PASSES``: precondition checks,
per-rule skip policy, audited decision outcomes, and a single-flight
same-codegen reentry guard. The codegen object crosses a dynamic third-party
angr boundary; dynamic attribute access stays limited to that boundary and
diagnostic counters. Consumes already-proven IR, alias, widening, typed, and
structuring facts. Do not recover new semantics, storage identity, types, call
signatures, control flow, or facts from rendered text, COD, source, or
CLI/reporting evidence here. Rule names are configuration and diagnostics
only; they are never semantic evidence.
"""

from __future__ import annotations

import contextlib
import os
import sys
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

__all__ = [
    "OPTIMIZATION_RULE_PASS_PREFIX_8616",
    "OptimizationRuleDecision8616",
    "OptimizationRuleOutcome8616",
    "OptimizationRuleSpec8616",
    "OptimizationRunReport8616",
    "optimization_rule_canonical_name_8616",
    "optimization_rule_skip_names_8616",
    "run_optimization_rules_8616",
]

OPTIMIZATION_RULE_PASS_PREFIX_8616: str = "optimization:"

_OPTIMIZATION_SKIP_ENV_8616: str = "INERTIA_SKIP_POSTPROCESS_PASSES"
_OPTIMIZATION_DEBUG_ENV_8616: str = "INERTIA_DEBUG_OPTIMIZATION"
_TRUTHY_ENV_VALUES_8616: frozenset[str] = frozenset({"1", "true", "yes", "on"})
_DECISIONS_ATTR_8616: str = "_inertia_optimization_rule_decisions_8616"

# Process-local set of ``id(codegen)`` values currently inside one run. The
# guarded codegen object stays alive on the caller stack for the whole run, so
# its id cannot be recycled while the entry is present.
_ACTIVE_RUN_CODEGEN_IDS_8616: set[int] = set()


class OptimizationRuleOutcome8616(Enum):
    """Typed audited outcome for one named cleanup optimization rule."""

    PRECONDITION_MISSING = "precondition_missing"
    REFUSED_REENTRY = "refused_reentry"
    SKIPPED = "skipped"
    NOT_EXECUTED = "not_executed"
    FAILED = "failed"
    CHANGED = "changed"
    STABLE = "stable"


class OptimizationRuleSpec8616(Protocol):
    """Minimal runtime shape of one named cleanup optimization rule."""

    @property
    def name(self) -> str:
        """Return the bare rule name used for skip policy and diagnostics."""
        ...

    @property
    def func(self) -> Callable[..., bool]:
        """Return the rule body; it reports True when it modified the codegen."""
        ...


@dataclass(frozen=True, slots=True)
class OptimizationRuleDecision8616:
    """Audited decision recorded for one named cleanup optimization rule."""

    name: str
    canonical_name: str
    outcome: OptimizationRuleOutcome8616

    @property
    def executed(self) -> bool:
        """Return True when the rule body was invoked at all."""
        return self.outcome in {
            OptimizationRuleOutcome8616.CHANGED,
            OptimizationRuleOutcome8616.STABLE,
            OptimizationRuleOutcome8616.FAILED,
        }

    @property
    def changed(self) -> bool:
        """Return True only when the rule reported a modification."""
        return self.outcome is OptimizationRuleOutcome8616.CHANGED


@dataclass(frozen=True, slots=True)
class OptimizationRunReport8616:
    """Aggregate audited result of one optimization rule run."""

    decisions: tuple[OptimizationRuleDecision8616, ...]
    halted: bool = False

    @property
    def changed(self) -> bool:
        """Return True when any rule body reported a modification.

        This is body-reported evidence only; under a guarded executor it is
        not acceptance evidence and must not be read as a validated semantic
        improvement.
        """
        return any(decision.changed for decision in self.decisions)


@dataclass(slots=True)
class _RuleExecutionTrace8616:
    """Mutable per-rule execution trace shared with the abort accountant."""

    executed: bool = False
    failed: bool = False
    changed: bool = False


def optimization_rule_canonical_name_8616(name: str) -> str:
    """Return the canonical ``optimization:<rule>`` configuration name."""
    return f"{OPTIMIZATION_RULE_PASS_PREFIX_8616}{name}"


def optimization_rule_skip_names_8616(
    env: Mapping[str, str] | None = None,
) -> frozenset[str]:
    """Return bare rule names disabled via ``INERTIA_SKIP_POSTPROCESS_PASSES``.

    Only canonical ``optimization:<rule>`` entries select cleanup rules; bare
    entries keep their existing meaning for top-level postprocess passes.
    """
    environment = os.environ if env is None else env
    raw = environment.get(_OPTIMIZATION_SKIP_ENV_8616, "")
    skipped: set[str] = set()
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry.startswith(OPTIMIZATION_RULE_PASS_PREFIX_8616):
            continue
        rule_name = entry[len(OPTIMIZATION_RULE_PASS_PREFIX_8616) :].strip()
        if rule_name:
            skipped.add(rule_name)
    return frozenset(skipped)


def _optimization_rules_debug_enabled_8616(env: Mapping[str, str] | None) -> bool:
    """Return True when optimization diagnostics are enabled for this run."""
    environment = os.environ if env is None else env
    value = environment.get(_OPTIMIZATION_DEBUG_ENV_8616, "")
    return value.strip().lower() in _TRUTHY_ENV_VALUES_8616


def _run_level_decisions_8616(
    specs: tuple[OptimizationRuleSpec8616, ...],
    outcome: OptimizationRuleOutcome8616,
    env: Mapping[str, str] | None,
) -> tuple[OptimizationRuleDecision8616, ...]:
    """Build one uniform audited decision per rule for a run-level outcome."""
    decisions = tuple(
        OptimizationRuleDecision8616(
            name=spec.name,
            canonical_name=optimization_rule_canonical_name_8616(spec.name),
            outcome=outcome,
        )
        for spec in specs
    )
    if _optimization_rules_debug_enabled_8616(env):
        for decision in decisions:
            print(
                f"[optimization] pass_{decision.outcome.value}={decision.name}",
                file=sys.stderr,
                flush=True,
            )
    return decisions


def _publish_run_decisions_8616(
    codegen: object,
    decisions: tuple[OptimizationRuleDecision8616, ...],
) -> None:
    """Publish audited decisions on the dynamic codegen boundary.

    Codegen objects without an attribute dictionary cannot carry the audit
    surface; the returned report remains the authoritative record.
    """
    if codegen is not None and isinstance(getattr(codegen, "__dict__", None), dict):
        setattr(codegen, _DECISIONS_ATTR_8616, decisions)


@contextlib.contextmanager
def _optimization_run_guard_8616(codegen: object) -> Iterator[bool]:
    """Yield False on same-codegen reentry; otherwise hold a single-flight slot.

    Guard state is process-local and is always released on exit, including
    exceptional exit; exceptions propagate to the caller unchanged.
    """
    codegen_id = id(codegen)
    if codegen_id in _ACTIVE_RUN_CODEGEN_IDS_8616:
        yield False
        return
    _ACTIVE_RUN_CODEGEN_IDS_8616.add(codegen_id)
    try:
        yield True
    finally:
        _ACTIVE_RUN_CODEGEN_IDS_8616.discard(codegen_id)


def _invoke_rule_body_8616(
    codegen: object,
    spec: OptimizationRuleSpec8616,
    trace: _RuleExecutionTrace8616,
) -> bool:
    """Invoke the rule body once; account failure through ``finally``.

    The original exception propagates unchanged when the body raises; no
    exception type is caught, swallowed, or widened for bookkeeping.
    """
    trace.executed = True
    completed = False
    try:
        trace.changed = bool(spec.func(codegen))
        completed = True
        return trace.changed
    finally:
        if not completed:
            trace.failed = True


def _interrupted_rule_outcome_8616(
    trace: _RuleExecutionTrace8616,
) -> OptimizationRuleOutcome8616:
    """Classify an interrupted rule from its execution trace."""
    if trace.failed:
        return OptimizationRuleOutcome8616.FAILED
    if not trace.executed:
        return OptimizationRuleOutcome8616.NOT_EXECUTED
    if trace.changed:
        return OptimizationRuleOutcome8616.CHANGED
    return OptimizationRuleOutcome8616.STABLE


def _aborted_run_decisions_8616(
    specs: tuple[OptimizationRuleSpec8616, ...],
    decisions: list[OptimizationRuleDecision8616],
    trace: _RuleExecutionTrace8616,
) -> tuple[OptimizationRuleDecision8616, ...]:
    """Account the interrupted rule and the unevaluated remainder.

    Called while an exception propagates so the latest run's audit replaces
    any earlier run's decisions instead of leaving stale successes visible.
    """
    partial = list(decisions)
    index = len(partial)
    if index < len(specs):
        interrupted = specs[index]
        partial.append(
            OptimizationRuleDecision8616(
                name=interrupted.name,
                canonical_name=optimization_rule_canonical_name_8616(interrupted.name),
                outcome=_interrupted_rule_outcome_8616(trace),
            )
        )
        index += 1
    for spec in specs[index:]:
        partial.append(
            OptimizationRuleDecision8616(
                name=spec.name,
                canonical_name=optimization_rule_canonical_name_8616(spec.name),
                outcome=OptimizationRuleOutcome8616.NOT_EXECUTED,
            )
        )
    return tuple(partial)


def _execute_guarded_rule_8616(
    codegen: object,
    spec: OptimizationRuleSpec8616,
    canonical_name: str,
    apply_rule_step: Callable[[str, Callable[[], bool]], bool],
    trace: _RuleExecutionTrace8616,
) -> tuple[OptimizationRuleOutcome8616, bool]:
    """Execute one rule through the guarded apply callback.

    Returns the audited outcome plus the executor's keep-running verdict.
    """
    def _step() -> bool:
        return _invoke_rule_body_8616(codegen, spec, trace)

    keep_running = bool(apply_rule_step(canonical_name, _step))
    if not trace.executed:
        return OptimizationRuleOutcome8616.NOT_EXECUTED, keep_running
    if trace.failed:
        return OptimizationRuleOutcome8616.FAILED, keep_running
    if trace.changed:
        return OptimizationRuleOutcome8616.CHANGED, keep_running
    return OptimizationRuleOutcome8616.STABLE, keep_running


def _emit_optimization_counters_debug_8616(
    codegen: object,
    env: Mapping[str, str] | None,
    *,
    halted: bool,
) -> None:
    """Emit the per-run diagnostic counters when the run fully completed."""
    if halted or not _optimization_rules_debug_enabled_8616(env):
        return
    print(
        "[optimization] counters "
        f"dce_candidates={int(getattr(codegen, 'dce_candidates', 0) or 0)} "
        f"dce_deleted={int(getattr(codegen, 'dce_deleted', 0) or 0)} "
        f"dce_keep_live_use={int(getattr(codegen, 'dce_keep_live_use', 0) or 0)} "
        f"dce_keep_side_effect={int(getattr(codegen, 'dce_keep_side_effect', 0) or 0)} "
        f"dce_keep_protected={int(getattr(codegen, 'dce_keep_protected', 0) or 0)} "
        f"dce_keep_observable={int(getattr(codegen, 'dce_keep_observable', 0) or 0)} "
        f"dce_keep_unknown={int(getattr(codegen, 'dce_keep_unknown', 0) or 0)} "
        f"dce_duplicate_assignment_candidates="
        f"{int(getattr(codegen, 'dce_duplicate_assignment_candidates', 0) or 0)} "
        f"dce_duplicate_assignment_deleted="
        f"{int(getattr(codegen, 'dce_duplicate_assignment_deleted', 0) or 0)} "
        f"dce_duplicate_assignment_refused="
        f"{int(getattr(codegen, 'dce_duplicate_assignment_refused', 0) or 0)}",
        file=sys.stderr,
        flush=True,
    )


def _execute_optimization_rules_8616(
    codegen: object,
    specs: tuple[OptimizationRuleSpec8616, ...],
    apply_rule_step: Callable[[str, Callable[[], bool]], bool] | None,
    env: Mapping[str, str] | None,
) -> OptimizationRunReport8616:
    """Iterate the registry order once and record each audited decision.

    When a rule body or the guarded executor propagates an exception, the
    ``finally`` clause publishes the interrupted run's partial audit (FAILED
    for a body that raised, NOT_EXECUTED for rules never invoked) so stale
    decisions from an earlier run are never mistaken for the latest outcome;
    the original exception then propagates unchanged.
    """
    skip_names = optimization_rule_skip_names_8616(env)
    debug_enabled = _optimization_rules_debug_enabled_8616(env)
    decisions: list[OptimizationRuleDecision8616] = []
    halted = False
    run_completed = False
    trace = _RuleExecutionTrace8616()
    try:
        for spec in specs:
            trace = _RuleExecutionTrace8616()
            canonical_name = optimization_rule_canonical_name_8616(spec.name)
            keep_running = True
            if spec.name in skip_names:
                outcome = OptimizationRuleOutcome8616.SKIPPED
            elif apply_rule_step is None:
                changed = _invoke_rule_body_8616(codegen, spec, trace)
                outcome = (
                    OptimizationRuleOutcome8616.CHANGED
                    if changed
                    else OptimizationRuleOutcome8616.STABLE
                )
            else:
                outcome, keep_running = _execute_guarded_rule_8616(
                    codegen, spec, canonical_name, apply_rule_step, trace
                )
            decisions.append(
                OptimizationRuleDecision8616(
                    name=spec.name,
                    canonical_name=canonical_name,
                    outcome=outcome,
                )
            )
            if debug_enabled:
                print(
                    f"[optimization] pass_{outcome.value}={spec.name}",
                    file=sys.stderr,
                    flush=True,
                )
            if not keep_running:
                halted = True
                break
        run_completed = True
    finally:
        if not run_completed:
            _publish_run_decisions_8616(
                codegen, _aborted_run_decisions_8616(specs, decisions, trace)
            )
    return OptimizationRunReport8616(decisions=tuple(decisions), halted=halted)


def run_optimization_rules_8616(
    codegen: object,
    specs: tuple[OptimizationRuleSpec8616, ...],
    apply_rule_step: Callable[[str, Callable[[], bool]], bool] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    prepare: Callable[[object], None] | None = None,
) -> OptimizationRunReport8616:
    """Run named cleanup optimization rules under the shared runtime contract.

    ``codegen`` crosses a dynamic third-party angr boundary. Rules run in
    registry order; ``INERTIA_SKIP_POSTPROCESS_PASSES`` entries named
    ``optimization:<rule>`` are recorded as skipped without executing. When
    ``apply_rule_step`` is provided, each runnable rule executes inside that
    guarded step under its canonical name and the callback's return value
    decides whether the run continues; otherwise the rule body is invoked
    directly. A run that reenters on the same codegen is refused without
    executing any rule. ``prepare`` runs once after admission and before the
    first rule, mirroring the historical normalization step. The audited
    decisions are recorded on the codegen as
    ``_inertia_optimization_rule_decisions_8616``, including the partial
    FAILED/NOT_EXECUTED audit when a rule or the executor raises.

    The ``cfunc`` precondition is structural admission only, not semantic
    readiness evidence. ``CHANGED`` records that a rule body reported a
    modification; under a guarded executor it is not acceptance evidence and
    must not be read as a validated semantic improvement.
    """
    report = _run_optimization_rules_report_8616(
        codegen, specs, apply_rule_step, env=env, prepare=prepare
    )
    _publish_run_decisions_8616(codegen, report.decisions)
    return report


def _run_optimization_rules_report_8616(
    codegen: object,
    specs: tuple[OptimizationRuleSpec8616, ...],
    apply_rule_step: Callable[[str, Callable[[], bool]], bool] | None,
    *,
    env: Mapping[str, str] | None,
    prepare: Callable[[object], None] | None,
) -> OptimizationRunReport8616:
    """Evaluate the run precondition, guard, and rule loop for one report."""
    if getattr(codegen, "cfunc", None) is None:
        return OptimizationRunReport8616(
            decisions=_run_level_decisions_8616(
                specs, OptimizationRuleOutcome8616.PRECONDITION_MISSING, env
            ),
        )
    with _optimization_run_guard_8616(codegen) as admitted:
        if not admitted:
            return OptimizationRunReport8616(
                decisions=_run_level_decisions_8616(
                    specs, OptimizationRuleOutcome8616.REFUSED_REENTRY, env
                ),
            )
        if prepare is not None:
            prepared = False
            try:
                prepare(codegen)
                prepared = True
            finally:
                if not prepared:
                    _publish_run_decisions_8616(
                        codegen,
                        _run_level_decisions_8616(
                            specs, OptimizationRuleOutcome8616.NOT_EXECUTED, env
                        ),
                    )
        report = _execute_optimization_rules_8616(
            codegen, specs, apply_rule_step, env
        )
        _emit_optimization_counters_debug_8616(codegen, env, halted=report.halted)
        return report
