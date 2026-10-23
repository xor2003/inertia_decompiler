from __future__ import annotations

from types import SimpleNamespace

import inertia.structuring.decompiler_structuring_stage as stage


def test_typed_switch_replacement_prepares_artifacts_without_leaking_environment(monkeypatch) -> None:
    forced: list[bool] = []
    monkeypatch.setenv("INERTIA_ENABLE_TYPED_SWITCH_AST_REPLACEMENT", "1")
    monkeypatch.delenv("INERTIA_ENABLE_TYPED_SWITCH_AST_ARTIFACTS", raising=False)
    monkeypatch.setattr(stage, "prepare_typed_edge_switch_artifacts_8616", lambda _codegen, *, force=False: forced.append(force))
    monkeypatch.setattr(
        stage._codegen,
        "replace_typed_edge_switch_ast_8616",
        lambda _codegen: SimpleNamespace(changed=False),
    )
    codegen = SimpleNamespace(project=None, cfunc=None)

    assert stage.apply_typed_edge_switch_ast_replacement_if_enabled_8616(codegen) is False
    assert forced == [True]
    assert "INERTIA_ENABLE_TYPED_SWITCH_AST_ARTIFACTS" not in stage.os.environ


import pytest

from inertia.validation.tail_validation import (
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
    x86_16_tail_validation_result_passed,
)
from tests.ir.test_declared_entry_scoped_view import native_scope as native_scope
from tests.validation.test_declared_entry_tail import attached as attached


@pytest.mark.parametrize("outcome", ["conditional", "refused", "changed", "damaged", "semantic_failure", "premise_failure"])
def test_structuring_retains_only_preserved_conditional_result(attached, monkeypatch, outcome):
    """A real entry premise admits a local equal transform, never global success."""
    project, codegen = attached
    summary = collect_x86_16_tail_validation_summary(project, codegen)
    result = compare_x86_16_tail_validation_summaries(summary, summary)
    receipt = result["entry_premise"]
    result.update(status=outcome if outcome in {"refused", "changed"} else "conditional", changed=outcome == "changed")
    if outcome == "damaged":
        receipt["sha256"] = "0" * 64
    elif outcome == "semantic_failure":
        result["semantic_failures"] = ["retained failure"]
    elif outcome == "premise_failure":
        result["premise_failure"] = "entry_premise_missing_or_invalid"
    monkeypatch.setattr(stage, "_try_accept_structuring_validation_delta_from_evidence_8616", lambda *a, **kw: False)
    transaction = stage._StructuringPassValidation8616(project, codegen, "local", "live_out", "before", summary)
    transaction._publish(result, summary)
    assert bool(getattr(codegen, "_inertia_structuring_validation_failed", False)) == (outcome != "conditional")
    assert codegen._inertia_structuring_pass_validation["local"] is result
    assert result["entry_premise"] is receipt
    assert not x86_16_tail_validation_result_passed(result)


@pytest.mark.parametrize("encoded", [True, False])
def test_terminal_refresh_sees_canonical_guard_and_original_origin(monkeypatch, encoded: bool) -> None:
    """Normalize once before refresh; stable input must not request replay."""
    from angr.rustylib.ailment import Tags

    from tests.structuring.test_x86_16_boolean_condition_ites import (
        _branch_with_ite,
        _wrap_condition_in_logical_nots,
    )

    codegen, branch, comparison, _encoding = _branch_with_ite(0, 1)
    if encoded:
        wrapper = _wrap_condition_in_logical_nots(codegen, branch, 1)
        wrapper.tags = Tags({"ins_addr": 0x101E, "vex_block_addr": 0x1010})
    else:
        comparison.tags = Tags({"ins_addr": 0x101E, "vex_block_addr": 0x1010})
        branch.condition_and_nodes = [(comparison, branch.condition_and_nodes[0][1])]
    surface = SimpleNamespace(project=codegen.project, codegen=codegen)
    calls: list[str] = []

    def refresh(project, current_codegen):
        calls.append("refresh")
        assert project is surface.project
        assert current_codegen is codegen
        guard = branch.condition_and_nodes[0][0]
        assert guard is comparison
        assert guard.tags["ins_addr"] == 0x101E
        assert guard.tags["vex_block_addr"] == 0x1010
        return stage._condition_refresh.StructuringConditionRefreshResult8616.stable()

    def close_loop_breaks(_project, _codegen):
        calls.append("loop-break")
        return False

    monkeypatch.setattr(stage, "_refresh_structuring_condition_semantics_8616", refresh)
    monkeypatch.setattr(stage, "_materialize_structuring_unconsumed_loop_break_jcc_8616", close_loop_breaks)
    monkeypatch.setattr(stage, "record_ast_condition_trace_8616", lambda *args, **kwargs: None)
    flags = stage._ValidatedStructuringFlags8616()

    changed = stage._validated_terminal_mid_phases_8616(surface, 0x1000, False, flags)

    assert calls == ["refresh", "loop-break"]
    assert changed is encoded
    assert flags.boolean_ite is encoded
    assert stage._final_lowering_boundary_changed_8616(flags) is encoded
