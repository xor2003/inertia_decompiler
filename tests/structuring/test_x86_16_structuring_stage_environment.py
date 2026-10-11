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
