from __future__ import annotations

from types import SimpleNamespace

import inertia.postprocess.decompiler_postprocess_stage as stage


def test_prevalidation_stack_prototype_reconciles_after_return_address_pruning(
    monkeypatch,
) -> None:
    """Expose exact argument types before Tail Validation captures its baseline."""
    project = SimpleNamespace()
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1009E))
    events: list[str] = []

    def materialize(materialized_project, materialized_codegen) -> bool:
        assert materialized_project is project
        assert materialized_codegen is codegen
        events.append("materialize")
        return True

    def prune(pruned_project, pruned_codegen) -> bool:
        assert pruned_project is project
        assert pruned_codegen is codegen
        events.append("prune-return-address")
        return True

    def reconcile(reconciled_project, reconciled_codegen) -> bool:
        assert reconciled_project is project
        assert reconciled_codegen is codegen
        events.append("reconcile-exact-types")
        return True

    monkeypatch.setattr(stage, "materialize_annotated_stack_prototype_8616", materialize)
    monkeypatch.setattr(stage._post, "_prune_return_address_stack_arguments_8616", prune)
    monkeypatch.setattr(stage, "reconcile_exact_stack_argument_prototype_8616", reconcile)
    monkeypatch.setattr(
        stage,
        "_invalidate_tail_validation_derived_caches_8616",
        lambda invalidated_codegen: events.append("invalidate"),
    )

    assert stage._prime_stack_prototype_before_validation_baseline_8616(project, codegen)
    assert events == [
        "materialize",
        "prune-return-address",
        "reconcile-exact-types",
        "invalidate",
    ]
    assert codegen._inertia_pre_validation_return_address_pruned_8616 is True
    assert codegen._inertia_pre_validation_stack_prototype_primed is True
