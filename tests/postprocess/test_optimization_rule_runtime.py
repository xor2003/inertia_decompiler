"""Regression tests for the shared cleanup-optimization rule runtime contract.

Covers selective per-rule skip through ``INERTIA_SKIP_POSTPROCESS_PASSES``
canonical ``optimization:<rule>`` names, all-on registry order, standalone and
guarded runner parity, same-codegen reentry refusal, separate-codegen
independence, the missing-cfunc precondition, and guard cleanup after a rule
exception. Rule names exercise configuration/diagnostics plumbing only; no
semantic recovery behavior is asserted here.
"""

from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace

import pytest

import inertia.postprocess.decompiler_postprocess_stage as post_stage
from inertia.postprocess.decompiler_postprocess_stage import (
    _postprocess_run_optimization_step_8616,
)
from inertia.postprocess.optimization import pass_driver
from inertia.postprocess.optimization.rule_runtime import (
    OptimizationRuleOutcome8616,
    OptimizationRunReport8616,
    optimization_rule_skip_names_8616,
    run_optimization_rules_8616,
)

pytestmark = pytest.mark.decompiler


def _codegen() -> SimpleNamespace:
    """Return a minimal codegen-shaped namespace crossing the dynamic boundary."""
    return SimpleNamespace(cfunc=SimpleNamespace(statements=None))


def _guarded_codegen() -> SimpleNamespace:
    """Return a codegen namespace carrying the guarded-run failure flag."""
    return SimpleNamespace(
        cfunc=SimpleNamespace(statements=None),
        _inertia_postprocess_validation_failed=False,
    )


def _spec(
    name: str, calls: list[str], *, changed: bool = False
) -> pass_driver.OptimizationPassSpec:
    """Build a deterministic sentinel rule that records its execution."""
    return pass_driver.OptimizationPassSpec(
        name, lambda _codegen: calls.append(name) or changed, f"{name} control"
    )


def _patch_standalone_registry(
    monkeypatch: pytest.MonkeyPatch, specs: tuple[pass_driver.OptimizationPassSpec, ...]
) -> None:
    """Point the standalone driver's registry lookup at the sentinel specs."""
    monkeypatch.setattr(pass_driver, "OPTIMIZATION_PASSES", specs)


def _patch_guarded_registry(
    monkeypatch: pytest.MonkeyPatch,
    specs: tuple[pass_driver.OptimizationPassSpec, ...],
    normalize_calls: list[str] | None = None,
) -> None:
    """Point the guarded stage step at sentinel specs with a recording prepare."""
    monkeypatch.setattr(post_stage, "OPTIMIZATION_PASSES", specs)
    monkeypatch.setattr(post_stage, "_postprocess_optimization_enabled_8616", lambda: True)
    if normalize_calls is not None:
        monkeypatch.setattr(
            post_stage,
            "_normalize_cfunc_root_for_optimization_8616",
            lambda _codegen: normalize_calls.append("normalize"),
        )


def _applying_step(applied: list[str]) -> Callable[[str, Callable[[], bool]], bool]:
    """Return an apply_step double that invokes each rule step and records names."""

    def apply_step(name: str, step: Callable[[], bool]) -> bool:
        applied.append(name)
        step()
        return True

    return apply_step


def test_skip_names_accept_canonical_rule_names_only() -> None:
    env = {
        "INERTIA_SKIP_POSTPROCESS_PASSES": (
            "optimization:dce, _some_top_level_pass_8616, "
            "optimization:const_prop, optimization:, , optimization:dead_setup_prune"
        ),
    }

    assert optimization_rule_skip_names_8616(env) == frozenset(
        {"dce", "const_prop", "dead_setup_prune"}
    )
    assert optimization_rule_skip_names_8616({}) == frozenset()


def test_standalone_runner_skips_named_rule_and_audits_decisions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    specs = (
        _spec("first", calls),
        _spec("second", calls),
        _spec("third", calls, changed=True),
    )
    _patch_standalone_registry(monkeypatch, specs)
    monkeypatch.setenv("INERTIA_SKIP_POSTPROCESS_PASSES", "optimization:second")
    monkeypatch.delenv("INERTIA_DEBUG_OPTIMIZATION", raising=False)

    codegen = _codegen()

    assert pass_driver._run_optimization_passes_8616(codegen) is True
    assert calls == ["first", "third"]
    decisions = codegen._inertia_optimization_rule_decisions_8616
    assert [decision.outcome for decision in decisions] == [
        OptimizationRuleOutcome8616.STABLE,
        OptimizationRuleOutcome8616.SKIPPED,
        OptimizationRuleOutcome8616.CHANGED,
    ]
    assert [decision.canonical_name for decision in decisions] == [
        "optimization:first",
        "optimization:second",
        "optimization:third",
    ]


def test_standalone_runner_executes_all_rules_in_registry_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    specs = (
        _spec("first", calls),
        _spec("second", calls),
        _spec("third", calls),
    )
    _patch_standalone_registry(monkeypatch, specs)
    monkeypatch.delenv("INERTIA_SKIP_POSTPROCESS_PASSES", raising=False)
    monkeypatch.delenv("INERTIA_DEBUG_OPTIMIZATION", raising=False)

    codegen = _codegen()

    assert pass_driver._run_optimization_passes_8616(codegen) is False
    assert calls == ["first", "second", "third"]
    assert [
        decision.outcome
        for decision in codegen._inertia_optimization_rule_decisions_8616
    ] == [
        OptimizationRuleOutcome8616.STABLE,
        OptimizationRuleOutcome8616.STABLE,
        OptimizationRuleOutcome8616.STABLE,
    ]


def test_guarded_runner_parity_with_standalone_skip_and_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    standalone_calls: list[str] = []
    guarded_calls: list[str] = []
    normalize_calls: list[str] = []
    applied: list[str] = []
    specs = (
        _spec("first", standalone_calls),
        _spec("second", standalone_calls),
        _spec("third", standalone_calls, changed=True),
    )
    _patch_standalone_registry(monkeypatch, specs)
    monkeypatch.setenv("INERTIA_SKIP_POSTPROCESS_PASSES", "optimization:second")
    monkeypatch.delenv("INERTIA_DEBUG_OPTIMIZATION", raising=False)

    standalone_codegen = _codegen()
    assert pass_driver._run_optimization_passes_8616(standalone_codegen) is True

    guarded_specs = (
        _spec("first", guarded_calls),
        _spec("second", guarded_calls),
        _spec("third", guarded_calls, changed=True),
    )
    _patch_guarded_registry(monkeypatch, guarded_specs, normalize_calls)
    guarded_codegen = _guarded_codegen()

    assert (
        _postprocess_run_optimization_step_8616(
            SimpleNamespace(), guarded_codegen, False, _applying_step(applied)
        )
        is True
    )

    assert guarded_calls == standalone_calls == ["first", "third"]
    assert applied == ["optimization:first", "optimization:third"]
    assert normalize_calls == ["normalize"]
    assert [
        decision.outcome
        for decision in guarded_codegen._inertia_optimization_rule_decisions_8616
    ] == [
        decision.outcome
        for decision in standalone_codegen._inertia_optimization_rule_decisions_8616
    ]


def test_same_codegen_reentry_is_refused_through_both_entry_points(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    inner_applied: list[str] = []
    inner_runtime_reports: list[OptimizationRunReport8616] = []
    inner_driver_results: list[bool] = []
    inner_guarded_results: list[bool] = []
    inner_specs = (_spec("inner", calls),)
    codegen = _guarded_codegen()

    def reentering(codegen_arg: SimpleNamespace) -> bool:
        calls.append("reentering")
        inner_runtime_reports.append(
            run_optimization_rules_8616(codegen_arg, inner_specs)
        )
        inner_driver_results.append(
            pass_driver._run_optimization_passes_8616(codegen_arg)
        )
        inner_guarded_results.append(
            _postprocess_run_optimization_step_8616(
                SimpleNamespace(),
                codegen_arg,
                False,
                _applying_step(inner_applied),
            )
        )
        return False

    specs = (
        pass_driver.OptimizationPassSpec("reentering", reentering, "reentry control"),
        _spec("tail", calls),
    )
    _patch_standalone_registry(monkeypatch, specs)
    _patch_guarded_registry(monkeypatch, inner_specs)
    monkeypatch.delenv("INERTIA_SKIP_POSTPROCESS_PASSES", raising=False)

    report = run_optimization_rules_8616(codegen, specs)

    assert calls == ["reentering", "tail"]
    assert inner_applied == []
    assert report.changed is False
    assert [
        decision.outcome for decision in inner_runtime_reports[0].decisions
    ] == [OptimizationRuleOutcome8616.REFUSED_REENTRY]
    assert inner_driver_results == [False]
    assert inner_guarded_results == [True]


def test_nested_run_on_different_codegen_executes_independently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    inner_reports: list[OptimizationRunReport8616] = []
    inner_codegen = _codegen()
    inner_specs = (_spec("inner", calls, changed=True),)

    def outer(codegen_arg: SimpleNamespace) -> bool:
        calls.append("outer")
        inner_reports.append(run_optimization_rules_8616(inner_codegen, inner_specs))
        return False

    specs = (
        pass_driver.OptimizationPassSpec("outer", outer, "outer control"),
        _spec("tail", calls),
    )
    monkeypatch.delenv("INERTIA_SKIP_POSTPROCESS_PASSES", raising=False)

    report = run_optimization_rules_8616(_codegen(), specs)

    assert calls == ["outer", "inner", "tail"]
    assert inner_reports[0].changed is True
    assert [
        decision.outcome for decision in inner_reports[0].decisions
    ] == [OptimizationRuleOutcome8616.CHANGED]
    assert report.changed is False


def test_missing_cfunc_precondition_refuses_without_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    applied: list[str] = []
    specs = (_spec("first", calls),)
    _patch_standalone_registry(monkeypatch, specs)
    _patch_guarded_registry(monkeypatch, specs)
    monkeypatch.delenv("INERTIA_SKIP_POSTPROCESS_PASSES", raising=False)

    codegen = SimpleNamespace()
    report = run_optimization_rules_8616(codegen, specs)

    assert report.changed is False
    assert report.halted is False
    assert calls == []
    assert [decision.outcome for decision in report.decisions] == [
        OptimizationRuleOutcome8616.PRECONDITION_MISSING
    ]
    assert codegen._inertia_optimization_rule_decisions_8616 == report.decisions
    assert pass_driver._run_optimization_passes_8616(SimpleNamespace()) is False
    assert calls == []
    assert (
        _postprocess_run_optimization_step_8616(
            SimpleNamespace(), SimpleNamespace(), False, _applying_step(applied)
        )
        is True
    )
    assert applied == []


def test_guard_state_clears_after_rule_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    boom = RuntimeError("sentinel rule failure")

    def bad(_codegen: SimpleNamespace) -> bool:
        calls.append("bad")
        raise boom

    specs = (
        pass_driver.OptimizationPassSpec("bad", bad, "failing control"),
        _spec("after", calls),
    )
    _patch_standalone_registry(monkeypatch, specs)
    monkeypatch.delenv("INERTIA_SKIP_POSTPROCESS_PASSES", raising=False)
    codegen = _codegen()

    with pytest.raises(RuntimeError) as excinfo:
        pass_driver._run_optimization_passes_8616(codegen)
    assert excinfo.value is boom
    assert calls == ["bad"]
    assert [
        decision.outcome
        for decision in codegen._inertia_optimization_rule_decisions_8616
    ] == [
        OptimizationRuleOutcome8616.FAILED,
        OptimizationRuleOutcome8616.NOT_EXECUTED,
    ]

    ok_specs = (_spec("ok", calls),)
    _patch_standalone_registry(monkeypatch, ok_specs)

    assert pass_driver._run_optimization_passes_8616(codegen) is False
    assert calls == ["bad", "ok"]
    assert [
        decision.outcome
        for decision in codegen._inertia_optimization_rule_decisions_8616
    ] == [OptimizationRuleOutcome8616.STABLE]


def test_failed_run_replaces_prior_success_audit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    boom = ValueError("prior success must not survive a failed run")
    ok_specs = (_spec("ok", calls),)
    _patch_standalone_registry(monkeypatch, ok_specs)
    monkeypatch.delenv("INERTIA_SKIP_POSTPROCESS_PASSES", raising=False)
    codegen = _codegen()

    assert pass_driver._run_optimization_passes_8616(codegen) is False
    assert [
        decision.outcome
        for decision in codegen._inertia_optimization_rule_decisions_8616
    ] == [OptimizationRuleOutcome8616.STABLE]

    def bad(_codegen: SimpleNamespace) -> bool:
        calls.append("bad")
        raise boom

    failing_specs = (
        pass_driver.OptimizationPassSpec("bad", bad, "failing control"),
        _spec("after", calls),
    )
    _patch_standalone_registry(monkeypatch, failing_specs)

    with pytest.raises(ValueError) as excinfo:
        pass_driver._run_optimization_passes_8616(codegen)
    assert excinfo.value is boom
    assert calls == ["ok", "bad"]
    assert [
        decision.outcome
        for decision in codegen._inertia_optimization_rule_decisions_8616
    ] == [
        OptimizationRuleOutcome8616.FAILED,
        OptimizationRuleOutcome8616.NOT_EXECUTED,
    ]


def test_propagating_guarded_executor_preserves_failed_audit() -> None:
    calls: list[str] = []
    boom = RuntimeError("executor propagated failure")

    def bad(_codegen: SimpleNamespace) -> bool:
        calls.append("bad")
        raise boom

    def apply_step(_name: str, step: Callable[[], bool]) -> bool:
        step()
        return True

    specs = (
        pass_driver.OptimizationPassSpec("bad", bad, "failing control"),
        _spec("after", calls),
    )
    codegen = _codegen()

    with pytest.raises(RuntimeError) as excinfo:
        run_optimization_rules_8616(codegen, specs, apply_step)
    assert excinfo.value is boom
    assert calls == ["bad"]
    assert [
        decision.outcome
        for decision in codegen._inertia_optimization_rule_decisions_8616
    ] == [
        OptimizationRuleOutcome8616.FAILED,
        OptimizationRuleOutcome8616.NOT_EXECUTED,
    ]


def test_guarded_rule_failure_is_audited_not_reported_changed() -> None:
    calls: list[str] = []

    def bad(_codegen: SimpleNamespace) -> bool:
        calls.append("bad")
        raise RuntimeError("guarded failure")

    def apply_step(_name: str, step: Callable[[], bool]) -> bool:
        try:
            step()
        except RuntimeError:
            return False
        return True

    specs = (
        pass_driver.OptimizationPassSpec("bad", bad, "failing control"),
        _spec("after", calls),
    )

    report = run_optimization_rules_8616(_codegen(), specs, apply_step)

    assert report.halted is True
    assert report.changed is False
    assert calls == ["bad"]
    assert [decision.outcome for decision in report.decisions] == [
        OptimizationRuleOutcome8616.FAILED
    ]
    assert report.decisions[0].executed is True


def test_guarded_declined_rule_is_audited_not_executed() -> None:
    calls: list[str] = []
    applied: list[str] = []

    def apply_step(name: str, step: Callable[[], bool]) -> bool:
        applied.append(name)
        if name == "optimization:declined":
            return True
        step()
        return True

    specs = (
        _spec("declined", calls),
        _spec("after", calls),
    )

    report = run_optimization_rules_8616(_codegen(), specs, apply_step)

    assert report.halted is False
    assert report.changed is False
    assert calls == ["after"]
    assert applied == ["optimization:declined", "optimization:after"]
    assert [decision.outcome for decision in report.decisions] == [
        OptimizationRuleOutcome8616.NOT_EXECUTED,
        OptimizationRuleOutcome8616.STABLE,
    ]
    assert report.decisions[0].executed is False
