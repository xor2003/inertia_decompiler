"""Tests for typed postprocess runtime policy."""

from types import SimpleNamespace

import pytest
import inertia.postprocess.decompiler_postprocess_stage as postprocess_stage

from inertia.postprocess.pass_runtime import (
    build_postprocess_runtime_config_8616,
    postprocess_optional_reject_budget_8616,
)
from inertia.postprocess.pass_transaction import PostprocessPassTransactionState8616
from inertia.postprocess.runtime_configuration import configure_postprocess_runtime_8616
from inertia.postprocess.validation_contracts import (
    PostprocessFunctionComplexity8616,
)
from inertia.validation.tail_validation import X86_16TailValidationSummary


@pytest.mark.parametrize("cached", [False, True])
@pytest.mark.parametrize("enabled", [False, True])
def test_runtime_to_transaction_preserves_exact_validation_baseline(cached: bool, enabled: bool) -> None:
    summary = X86_16TailValidationSummary(("callee",), (), (), (), (), (), (), ())
    project = SimpleNamespace(_inertia_tail_validation_enabled=enabled)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000),
        _inertia_postprocess_pre_validation_summary=summary if cached else None,
    )
    collected = []

    def collect(active_project: object, active_codegen: object) -> X86_16TailValidationSummary:
        assert active_project is project and active_codegen is codegen
        collected.append(summary)
        return summary

    config = configure_postprocess_runtime_8616(
        project, codegen, (),
        complexity_resolver=lambda *_args: PostprocessFunctionComplexity8616(),
        baseline_summary_collector=collect,
        fact_backed_stack_normalize_enabled=True,
    )
    state = PostprocessPassTransactionState8616(config.baseline_summary, None)

    assert config.validation_enabled is enabled
    assert state.baseline_summary is (summary if enabled else None)
    assert collected == ([summary] if enabled and not cached else [])
    assert state.accepted_mutation_count == 0


def test_large_function_disables_requested_per_pass_validation() -> None:
    config = build_postprocess_runtime_config_8616(
        validation_enabled=True,
        per_pass_validation_requested=True,
        large_function_for_per_pass_validation=True,
        fact_backed_stack_normalize_enabled=True,
        baseline_summary=None,
        env={},
    )

    assert config.per_pass_validation_enabled is False
    assert config.pass_timeout_seconds == 2


def test_force_validation_overrides_large_function_policy() -> None:
    config = build_postprocess_runtime_config_8616(
        validation_enabled=True,
        per_pass_validation_requested=False,
        large_function_for_per_pass_validation=True,
        fact_backed_stack_normalize_enabled=True,
        baseline_summary=None,
        env={"INERTIA_FORCE_PER_PASS_TV": "1"},
    )

    assert config.per_pass_validation_enabled is True


def test_skip_policy_preserves_required_stack_normalization_refusal() -> None:
    config = build_postprocess_runtime_config_8616(
        validation_enabled=False,
        per_pass_validation_requested=False,
        large_function_for_per_pass_validation=False,
        fact_backed_stack_normalize_enabled=False,
        baseline_summary=None,
        env={"INERTIA_SKIP_POSTPROCESS_PASSES": " first,second "},
    )

    assert config.skip_names == {
        "first",
        "second",
        "_normalize_fact_backed_stack_accesses_8616",
    }


def test_invalid_reject_budget_uses_owned_default() -> None:
    assert postprocess_optional_reject_budget_8616(
        {"INERTIA_POSTPROCESS_OPTIONAL_REJECT_BUDGET": "invalid"}
    ) == postprocess_optional_reject_budget_8616({})


def test_initialized_change_flag_does_not_bypass_baseline_clone(monkeypatch) -> None:
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1234),
        _inertia_postprocess_changed=False,
    )
    clone = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1234))
    collected: list[object] = []
    monkeypatch.setattr(
        postprocess_stage,
        "_postprocess_function_complexity_8616",
        lambda *_args: PostprocessFunctionComplexity8616(),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_prepare_tail_validation_baseline_clone_8616",
        lambda *_args, **_kwargs: clone,
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_repair_cfunc_statements_wrapper",
        lambda _codegen: False,
    )
    monkeypatch.setattr(
        postprocess_stage._post,
        "_repair_unresolved_function_exit_gotos_8616",
        lambda *_args: False,
    )
    monkeypatch.setattr(
        postprocess_stage,
        "collect_x86_16_tail_validation_summary",
        lambda _project, active_codegen, **_kwargs: collected.append(active_codegen),
    )

    postprocess_stage._collect_tail_validation_summary_with_baseline_canonicalization_8616(
        SimpleNamespace(),
        codegen,
        mode="live_out",
    )

    assert collected == [clone]


def test_completed_transaction_uses_direct_final_summary(monkeypatch) -> None:
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1234),
        _inertia_postprocess_mutation_generation_8616=object(),
    )
    collected: list[object] = []
    monkeypatch.setattr(
        postprocess_stage,
        "collect_x86_16_tail_validation_summary",
        lambda _project, active_codegen, **_kwargs: collected.append(active_codegen),
    )

    postprocess_stage._collect_tail_validation_summary_with_baseline_canonicalization_8616(
        SimpleNamespace(),
        codegen,
        mode="live_out",
    )

    assert collected == [codegen]
