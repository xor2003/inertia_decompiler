from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr_platforms.X86_16 import decompiler_postprocess as legacy_postprocess
from angr_platforms.X86_16 import decompiler_postprocess_stage as post_stage
from angr_platforms.X86_16 import decompiler_structuring_stage as stage
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering import real_mode_linear, segment_global_materialization
from angr_platforms.X86_16.lowering.real_mode_linear import DirectStackMoveSourceKind8616
from angr_platforms.X86_16.lowering.segmented_global_loads import (
    DwordGlobalZeroTestEvidence8616,
    DwordGlobalZeroTestMaterializationRecord8616,
    IndexedGlobalReadCarrierMaterializationRecord8616,
    IndexedSegmentedGlobalEvidence8616,
    IndexedSegmentedGlobalLoadSiteEvidence8616,
    IndexedSegmentedGlobalMaterializationRecord8616,
)
from angr_platforms.X86_16.structuring.guard_decisions import (
    VoidTailCallGuardDecision8616 as _VoidTailCallGuardDecision8616,
)
from angr_platforms.X86_16.structuring.loop_break_jcc import (
    LoopHeaderDuplicateGuardRemovalFact8616,
)
from angr_platforms.X86_16.tail_validation import (
    X86_16TailValidationSummary,
    loop_exit_return_guard_repair_delta_8616,
)


def _recorded_stub_8616(
    calls: list[str],
    *labels: str,
    result: object = False,
):
    """Return a monkeypatch stub that records `labels` and returns `result`."""

    def stub(*_args, **_kwargs):
        calls.extend(labels)
        return result

    return stub


def test_structuring_return_shape_materializes_void_return_ast_after_classification(monkeypatch):
    calls = []
    project = SimpleNamespace()
    codegen = SimpleNamespace()
    monkeypatch.setattr(
        legacy_postprocess,
        "_classify_return_shape_8616",
        lambda actual_project, actual_codegen: calls.append(("classify", actual_project, actual_codegen)) or True,
    )
    monkeypatch.setattr(
        legacy_postprocess,
        "_prune_void_function_return_values_8616",
        lambda actual_project, actual_codegen: calls.append(("materialize", actual_project, actual_codegen)) or True,
    )

    changed = stage._materialize_structuring_return_shape_8616(project, codegen)

    assert changed is True
    assert calls == [("classify", project, codegen), ("materialize", project, codegen)]


def test_structuring_stage_records_validation_for_semantic_passes(monkeypatch):
    project = SimpleNamespace(
        _inertia_tail_validation_enabled=True,
        _inertia_decompiler_stage=None,
        kb=SimpleNamespace(functions=None),
    )
    codegen = SimpleNamespace(
        project=project,
        cfunc=SimpleNamespace(addr=0x4010),
        _inertia_ss_stack_lowered=True,
    )
    cycle_scans = []

    monkeypatch.setattr(
        stage,
        "_c_ast_cycle_path_8616",
        lambda root: cycle_scans.append(root) or (),
    )
    monkeypatch.setattr(stage, "fingerprint_x86_16_tail_validation_boundary", lambda *_args, **_kwargs: ("fp",))
    monkeypatch.setattr(stage, "collect_x86_16_tail_validation_summary", lambda *_args, **_kwargs: {"conditions": ()})
    monkeypatch.setattr(
        stage,
        "build_x86_16_tail_validation_cached_result",
        lambda **kwargs: {
            "changed": False,
            "cache_hit": False,
            "stage": kwargs["stage"],
            "mode": kwargs["mode"],
        },
    )
    monkeypatch.setattr(
        stage, "build_x86_16_tail_validation_verdict", lambda pass_name, _validation: f"{pass_name}: stable"
    )
    monkeypatch.setattr(
        stage,
        "_replay_structuring_lowering_before_validation_8616",
        lambda _project, _codegen: False,
    )
    monkeypatch.setattr(
        stage,
        "_decompiler_structuring_passes_for_function",
        lambda _project, _codegen: (
            stage.DecompilerStructuringPassSpec("_segmented_memory_reasoning_8616", lambda _codegen: False, False),
            stage.DecompilerStructuringPassSpec("_induction_summary_artifact_8616", lambda _codegen: False, False),
        ),
    )

    changed = stage._structuring_codegen_8616(project, codegen)

    assert changed is False
    validation = codegen._inertia_structuring_pass_validation
    assert validation["_segmented_memory_reasoning_8616"]["stage"] == "structuring:_segmented_memory_reasoning_8616"
    assert (
        validation["_segmented_memory_reasoning_8616"]["verdict"]
        == "structuring:_segmented_memory_reasoning_8616: stable"
    )
    assert "_induction_summary_artifact_8616" not in validation
    assert len(cycle_scans) == 3


def test_current_structuring_function_uses_rebased_project_local_addr():
    function = SimpleNamespace(addr=0x1000)
    placeholder = SimpleNamespace(addr=0x10CE0)
    calls = []

    class _Functions:
        def function(self, addr, create=False):
            calls.append((addr, create))
            if addr == 0x1000:
                return function
            if addr == 0x10CE0:
                return placeholder
            return None

    project = SimpleNamespace(
        _inertia_original_linear_delta=0xFCE0,
        kb=SimpleNamespace(functions=_Functions()),
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x10CE0))

    resolved = stage._current_structuring_function_8616(project, codegen)

    assert resolved is function
    assert calls == [(0x1000, False)]


def test_current_structuring_function_keeps_already_mapped_slice_addr():
    function = SimpleNamespace(addr=0x1000)
    original_placeholder = SimpleNamespace(addr=0x10808)
    calls = []

    class _Functions:
        def function(self, addr, create=False):
            calls.append((addr, create))
            if addr == 0x1000:
                return function
            if addr == 0x10808:
                return original_placeholder
            return None

    project = SimpleNamespace(
        _inertia_original_linear_delta=-0xF808,
        loader=SimpleNamespace(main_object=SimpleNamespace(min_addr=0x1000, max_addr=0x10B7)),
        kb=SimpleNamespace(functions=_Functions()),
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000))

    resolved = stage._current_structuring_function_8616(project, codegen)

    assert resolved is function
    assert calls == [(0x1000, False)]


def test_active_structuring_function_context_overrides_stale_kb_function():
    active_function = SimpleNamespace(addr=0x4010)
    stale_function = SimpleNamespace(addr=0x4010)
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda *, addr, create: stale_function if addr == 0x4010 else None)
        )
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x4010))

    with stage.active_structuring_function_8616(project, active_function):
        assert stage._current_structuring_function_8616(project, codegen) is active_function

    assert not hasattr(project, "_inertia_active_structuring_function_8616")
    assert stage._current_structuring_function_8616(project, codegen) is stale_function


def test_structuring_return_chain_owner_runs_cfg_mask_accumulator(monkeypatch):
    calls: list[str] = []
    project = SimpleNamespace()
    codegen = SimpleNamespace()

    monkeypatch.setattr(
        stage,
        "materialize_tagged_terminal_return_values_8616",
        lambda *_args, **_kwargs: SimpleNamespace(changed=False),
    )
    monkeypatch.setattr(
        post_stage,
        "_materialize_missing_terminal_ax_return_8616",
        lambda *_args: calls.append("terminal_ax") and False,
    )
    monkeypatch.setattr(
        post_stage,
        "_materialize_empty_if_return_branches_8616",
        lambda *_args: calls.append("empty_if") and False,
    )
    monkeypatch.setattr(
        post_stage,
        "_materialize_cfg_mask_accumulator_8616",
        lambda *_args: calls.append("cfg_mask") is None,
    )
    monkeypatch.setattr(
        post_stage,
        "_materialize_stack_byte_pair_return_pass_8616",
        lambda *_args: calls.append("stack_byte_pair") and False,
    )

    changed = stage._materialize_structuring_return_chains_8616(project, codegen)

    assert changed is True
    assert calls == ["terminal_ax", "empty_if", "cfg_mask", "stack_byte_pair"]
    assert codegen._inertia_return_chains_structuring_pass_ran_8616 is True
    assert codegen._inertia_missing_terminal_ax_return_structuring_pass_ran_8616 is True
    assert codegen._inertia_cfg_mask_accumulator_structuring_pass_ran_8616 is True
    assert codegen._inertia_stack_byte_pair_return_structuring_pass_ran_8616 is True


def test_structuring_unresolved_exit_goto_owner_records_pass(monkeypatch):
    calls = []
    project = SimpleNamespace()
    codegen = SimpleNamespace()

    def _repair(_project, _codegen):
        calls.append((_project, _codegen))
        return False

    monkeypatch.setattr(legacy_postprocess, "_repair_unresolved_function_exit_gotos_8616", _repair)

    changed = stage._repair_structuring_unresolved_function_exit_gotos_8616(project, codegen)

    assert changed is False
    assert calls == [(project, codegen)]
    assert codegen._inertia_unresolved_exit_goto_structuring_pass_ran_8616 is True


def test_structuring_stable_stack_semantics_owner_records_pass(monkeypatch):
    calls: list[str] = []
    project = SimpleNamespace()
    codegen = SimpleNamespace(_inertia_semantic_stack_materialized_count=0)

    def _transfer(_project, _codegen):
        calls.append("transfer")
        _codegen._inertia_semantic_alias_facts = ["fact"]
        return 1

    def _alias_lowering(_codegen, alias_facts):
        calls.append(f"alias:{len(alias_facts)}")
        _codegen._inertia_semantic_stack_materialized_count = 1

    def _ss_lowering(_codegen, *, project=None):
        del project
        calls.append("ss")
        return False

    def _runtime_ss_lowering(_codegen, *, project=None):
        del project
        calls.append("runtime-ss")
        return False

    def _prune_carriers(_codegen):
        calls.append("carrier")
        return False

    monkeypatch.setattr(stage, "transfer_semantic_alias_facts_to_codegen_8616", _transfer)
    monkeypatch.setattr(stage, "lower_stack_accesses_from_alias_facts_8616", _alias_lowering)
    monkeypatch.setattr(
        stage._vex_ir,
        "apply_x86_16_vex_ir_artifact",
        lambda *_args: calls.append("vex-ir") or False,
    )
    monkeypatch.setattr(
        stage._stack_memory_ssa,
        "apply_x86_16_stack_memory_ssa_alias_artifact",
        lambda *_args: calls.append("memory-alias") or False,
    )
    monkeypatch.setattr(
        stage,
        "lower_x86_16_stack_memory_ssa_alias_artifact",
        lambda *_args: calls.append("memory-lowering") or None,
    )
    monkeypatch.setattr(stage, "lower_runtime_ss_segment_helpers_to_stack_8616", _runtime_ss_lowering)
    monkeypatch.setattr(stage, "lower_stable_ss_linear_stack_dereferences_8616", _ss_lowering)
    monkeypatch.setattr(stage, "prune_unread_stack_lowered_register_carriers_8616", _prune_carriers)
    monkeypatch.setattr(
        stage,
        "materialize_positive_bp_arguments_8616",
        lambda *_args: calls.append("positive-bp") or False,
    )

    changed = stage._apply_structuring_stable_stack_semantics_8616(project, codegen)

    assert changed is True
    assert calls == [
        "vex-ir",
        "memory-alias",
        "memory-lowering",
        "transfer",
        "alias:1",
        "positive-bp",
        "runtime-ss",
        "ss",
        "carrier",
    ]
    assert codegen._inertia_stable_stack_semantics_structuring_pass_ran_8616 is True
    assert codegen._inertia_codegen_decl_refresh_required_8616 is True


def test_structuring_stable_stack_semantics_prefers_memory_ssa_lowering(monkeypatch):
    calls: list[str] = []
    project = SimpleNamespace()
    codegen = SimpleNamespace(_inertia_semantic_stack_materialized_count=0)

    monkeypatch.setattr(
        stage._vex_ir,
        "apply_x86_16_vex_ir_artifact",
        lambda *_args: calls.append("vex-ir") or False,
    )
    monkeypatch.setattr(
        stage._stack_memory_ssa,
        "apply_x86_16_stack_memory_ssa_alias_artifact",
        lambda *_args: calls.append("memory-alias") or False,
    )

    def memory_lowering(actual_codegen):
        calls.append("memory-lowering")
        actual_codegen._inertia_semantic_stack_materialized_count = 1
        return object()

    monkeypatch.setattr(stage, "lower_x86_16_stack_memory_ssa_alias_artifact", memory_lowering)
    monkeypatch.setattr(
        stage,
        "transfer_semantic_alias_facts_to_codegen_8616",
        lambda *_args: pytest.fail("legacy Alias re-lift must not run"),
    )
    monkeypatch.setattr(
        stage,
        "lower_runtime_ss_segment_helpers_to_stack_8616",
        lambda *_args, **_kwargs: calls.append("runtime-ss") or False,
    )
    monkeypatch.setattr(
        stage,
        "materialize_positive_bp_arguments_8616",
        lambda *_args: calls.append("positive-bp") or False,
    )
    monkeypatch.setattr(
        stage,
        "lower_stable_ss_linear_stack_dereferences_8616",
        lambda *_args, **_kwargs: calls.append("ss") or False,
    )
    monkeypatch.setattr(
        stage,
        "prune_unread_stack_lowered_register_carriers_8616",
        lambda *_args: calls.append("carrier") or False,
    )

    changed = stage._apply_structuring_stable_stack_semantics_8616(project, codegen)

    assert changed is True
    assert calls == [
        "vex-ir",
        "memory-alias",
        "memory-lowering",
        "positive-bp",
        "runtime-ss",
        "ss",
        "carrier",
    ]


def test_structuring_codegen_replays_only_consumers_invalidated_by_rebuild(monkeypatch):
    calls: list[str] = []
    project = SimpleNamespace()
    codegen = SimpleNamespace()

    monkeypatch.setattr(
        stage._codegen,
        "apply_structuring_codegen_8616",
        lambda actual_codegen: calls.append("codegen") or actual_codegen is codegen,
    )
    monkeypatch.setattr(
        stage,
        "_apply_structuring_direct_stack_materialization_8616",
        lambda actual_project, actual_codegen: calls.append("direct")
        or (actual_project is project and actual_codegen is codegen),
    )
    monkeypatch.setattr(
        stage,
        "_prime_structuring_segment_global_semantics_8616",
        lambda actual_project, actual_codegen: calls.append("segment-global")
        or (actual_project is project and actual_codegen is codegen),
    )
    monkeypatch.setattr(
        stage,
        "_replay_materialized_call_stack_metadata_8616",
        lambda actual_project, actual_codegen: calls.append("call-stack")
        or (actual_project is project and actual_codegen is codegen),
    )
    monkeypatch.setattr(
        stage._condition_refresh,
        "refresh_structuring_condition_semantics_8616",
        lambda actual_project, actual_codegen: calls.append("condition")
        or stage._condition_refresh.StructuringConditionRefreshResult8616.stable(),
    )
    monkeypatch.setattr(
        stage,
        "_replay_structuring_lowering_before_validation_8616",
        lambda *_args: pytest.fail("intermediate codegen must not replay all Lowering"),
    )
    monkeypatch.setattr(
        stage,
        "prune_unread_stack_lowered_register_carriers_8616",
        lambda actual_codegen: calls.append("carrier") or actual_codegen is codegen,
    )

    changed = stage._run_structuring_codegen_with_lowering_replay_8616(project, codegen)

    assert changed is True
    assert calls == [
        "codegen",
        "direct",
        "segment-global",
        "call-stack",
        "condition",
        "carrier",
    ]


def test_structuring_codegen_skips_lowering_replay_without_rebuild(monkeypatch):
    calls: list[str] = []
    project = SimpleNamespace()
    codegen = SimpleNamespace()

    monkeypatch.setattr(
        stage._codegen,
        "apply_structuring_codegen_8616",
        lambda actual_codegen: calls.append("codegen") or False,
    )
    monkeypatch.setattr(
        stage,
        "_apply_structuring_direct_stack_materialization_8616",
        lambda *_args: pytest.fail("unchanged codegen must not replay direct-stack lowering"),
    )
    monkeypatch.setattr(
        stage,
        "_prime_structuring_segment_global_semantics_8616",
        lambda *_args: pytest.fail("unchanged codegen must not replay segmented-global lowering"),
    )
    monkeypatch.setattr(
        stage,
        "_replay_materialized_call_stack_metadata_8616",
        lambda actual_project, actual_codegen: calls.append("call-stack") or False,
    )
    monkeypatch.setattr(
        stage._condition_refresh,
        "refresh_structuring_condition_semantics_8616",
        lambda *_args: pytest.fail("unchanged codegen must not refresh conditions"),
    )
    monkeypatch.setattr(
        stage,
        "prune_unread_stack_lowered_register_carriers_8616",
        lambda actual_codegen: calls.append("carrier") or False,
    )

    changed = stage._run_structuring_codegen_with_lowering_replay_8616(project, codegen)

    assert changed is False
    assert calls == ["codegen", "call-stack", "carrier"]


def test_structuring_codegen_refuses_unclosed_condition_refresh(monkeypatch):
    project = SimpleNamespace()
    codegen = SimpleNamespace()
    monkeypatch.setattr(stage._codegen, "apply_structuring_codegen_8616", lambda *_args: True)
    monkeypatch.setattr(
        stage,
        "_apply_structuring_direct_stack_materialization_8616",
        lambda *_args: False,
    )
    monkeypatch.setattr(
        stage,
        "_prime_structuring_segment_global_semantics_8616",
        lambda *_args: False,
    )
    monkeypatch.setattr(
        stage,
        "_replay_materialized_call_stack_metadata_8616",
        lambda *_args: False,
    )
    monkeypatch.setattr(
        stage._condition_refresh,
        "refresh_structuring_condition_semantics_8616",
        lambda *_args: stage._condition_refresh.StructuringConditionRefreshResult8616.unclosed(),
    )

    with pytest.raises(stage.PipelineHardError, match="condition refresh remained unclosed"):
        stage._run_structuring_codegen_with_lowering_replay_8616(project, codegen)


def test_structuring_pointer_arg_indirect_owner_records_pass(monkeypatch):
    calls: list[tuple[object, str]] = []
    widening_calls: list[object] = []
    project = SimpleNamespace(_inertia_c_target="msc-dos")
    codegen = SimpleNamespace()

    def _materialize(_codegen, *, target):
        calls.append((_codegen, target))
        return False

    monkeypatch.setattr(stage, "apply_runtime_segment_lowering_8616", _materialize)
    monkeypatch.setattr(
        stage,
        "apply_segmented_load_widening_8616",
        lambda actual_codegen: widening_calls.append(actual_codegen) or False,
    )

    changed = stage._materialize_structuring_pointer_arg_indirect_loads_8616(project, codegen)

    assert changed is False
    assert calls == [(codegen, "msc-dos")]
    assert widening_calls == [codegen]
    assert codegen._inertia_pointer_arg_indirect_structuring_pass_ran_8616 is True


def test_structuring_pointer_memory_idiom_owner_records_pass(monkeypatch):
    calls: list[tuple[object, object, object]] = []
    project = SimpleNamespace()
    codegen = SimpleNamespace()

    def materialize(_project, _codegen, callbacks):
        calls.append((_project, _codegen, callbacks))
        return True

    monkeypatch.setattr(stage, "materialize_pointer_memory_idioms_from_evidence_8616", materialize)

    changed = stage._apply_structuring_pointer_memory_idioms_8616(project, codegen)

    assert changed is True
    assert calls and calls[0][0] is project and calls[0][1] is codegen
    assert codegen._inertia_pointer_memory_idiom_lowering_pass_ran_8616 is True
    assert codegen._inertia_codegen_decl_refresh_required_8616 is True
    assert codegen._inertia_force_codegen_regeneration_8616 is True


def test_structuring_callsite_prototypes_owner_records_pass(monkeypatch):
    calls: list[str] = []
    project = SimpleNamespace()
    codegen = SimpleNamespace()

    def _attach(_project, _codegen):
        assert _project is project
        assert _codegen is codegen
        calls.append("attach")
        return False

    def _prototypes(_project, _codegen):
        assert _project is project
        assert _codegen is codegen
        calls.append("prototypes")
        return True

    def _split(_codegen):
        assert _codegen is codegen
        calls.append("split")
        return True

    def _targets(_project, _codegen):
        assert _project is project
        assert _codegen is codegen
        calls.append("targets")
        return True

    monkeypatch.setattr(post_stage._calls, "_attach_callsite_summaries_8616", _attach)
    monkeypatch.setattr(stage._codegen, "split_distinct_condition_call_occurrences_8616", _split)
    monkeypatch.setattr(post_stage._calls, "_recover_missing_direct_calls_from_evidence_8616", _targets)
    monkeypatch.setattr(post_stage._calls, "_materialize_callsite_prototypes_8616", _prototypes)

    changed = stage._materialize_structuring_callsite_prototypes_8616(project, codegen)

    assert changed is True
    assert calls == ["attach", "split", "targets", "attach", "split", "prototypes"]
    assert codegen._inertia_call_target_structuring_pass_ran_8616 is True
    assert codegen._inertia_callsite_prototypes_structuring_pass_ran_8616 is True


def test_final_structuring_callsite_closure_requires_published_inventory(monkeypatch):
    project = SimpleNamespace()
    codegen = SimpleNamespace()
    monkeypatch.setattr(
        stage,
        "_materialize_structuring_callsite_prototypes_8616",
        lambda *_args: pytest.fail("closure must refuse without typed inventory"),
    )

    assert stage._close_final_structuring_callsites_8616(project, codegen) is False


@pytest.mark.parametrize("materialized,pruned", [(False, False), (False, True), (True, False), (True, True)])
def test_final_structuring_callsite_closure_replays_published_inventory(monkeypatch, materialized, pruned):
    from angr_platforms.X86_16.lowering import consumed_stack_address_setup

    project = SimpleNamespace()
    inventory = {0x4012: object()}
    statements = object()
    codegen = SimpleNamespace(
        _inertia_callsite_summary_inventory_8616=inventory,
        cfunc=SimpleNamespace(statements=statements),
    )
    calls: list[tuple[object, object]] = []
    monkeypatch.setattr(
        stage,
        "_materialize_structuring_callsite_prototypes_8616",
        lambda actual_project, actual_codegen: calls.append((actual_project, actual_codegen)) or materialized,
    )

    def prune(actual_project, actual_codegen, actual_statements, actual_inventory):
        assert calls == [(project, codegen)]
        assert (actual_project, actual_codegen) == (project, codegen)
        assert actual_statements is statements
        assert actual_inventory is inventory
        return pruned

    monkeypatch.setattr(consumed_stack_address_setup, "prune_consumed_stack_address_setup_8616", prune)
    assert stage._close_final_structuring_callsites_8616(project, codegen) is (materialized or pruned)
    assert calls == [(project, codegen)]


def test_structuring_callsite_stack_arguments_owner_records_pass(monkeypatch):
    calls: list[str] = []
    project = SimpleNamespace()
    codegen = SimpleNamespace()

    def stack_args(_project, _codegen):
        assert _project is project
        assert _codegen is codegen
        assert _codegen._inertia_callsite_disable_consumed_arg_store_prune_8616 is False
        assert _codegen._inertia_callsite_disable_stack_probe_setup_prune_8616 is True
        calls.append("stack-args")
        return True

    def refuse_recovery(*_args, **_kwargs):
        raise AssertionError("Structuring must not synthesize missing calls")

    def argument_joins(_project, _codegen):
        assert _project is project
        assert _codegen is codegen
        calls.append("argument-joins")
        return True

    def consumed_pushes(_project, _codegen):
        assert _project is project
        assert _codegen is codegen
        calls.append("consumed-pushes")
        return True

    def target_identity(_project, _codegen):
        assert _project is project
        assert _codegen is codegen
        calls.append("target-identity")
        return False

    monkeypatch.setattr(
        post_stage._calls,
        "_recover_missing_direct_calls_from_evidence_8616",
        refuse_recovery,
    )
    monkeypatch.setattr(post_stage._calls, "_materialize_callsite_stack_arguments_8616", stack_args)
    monkeypatch.setattr(stage, "materialize_call_argument_joins_8616", argument_joins)
    monkeypatch.setattr(
        stage,
        "prune_materialized_call_push_stack_assignments_8616",
        consumed_pushes,
    )
    monkeypatch.setattr(
        post_stage._calls,
        "_replay_call_target_identity_consumer_8616",
        target_identity,
    )
    monkeypatch.setattr(
        stage,
        "finalize_shared_call_occurrences_8616",
        lambda _project, _codegen: calls.append("finalize-occurrences") or True,
    )

    changed = stage._materialize_structuring_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert calls == [
        "stack-args",
        "argument-joins",
        "consumed-pushes",
        "target-identity",
        "finalize-occurrences",
    ]
    assert codegen._inertia_callsite_stack_arguments_structuring_pass_ran_8616 is True
    assert codegen._inertia_callsite_disable_consumed_arg_store_prune_8616 is False
    assert codegen._inertia_callsite_disable_stack_probe_setup_prune_8616 is False


def test_callsite_materialization_controls_reject_malformed_owned_return_state():
    codegen = SimpleNamespace(_inertia_callsite_return_exprs_8616=())

    with pytest.raises(TypeError, match="callsite return-expression state must be a dict"):
        post_stage._calls._ensure_callsite_materialization_controls_8616(codegen)


def test_structuring_stdlib_call_chains_owner_records_pass(monkeypatch):
    calls: list[tuple[object, object]] = []
    project = SimpleNamespace()
    codegen = SimpleNamespace()

    def materialize(_project, _codegen):
        calls.append((_project, _codegen))
        return True

    monkeypatch.setattr(post_stage._calls, "_materialize_stdlib_call_chains_8616", materialize)

    changed = stage._materialize_structuring_stdlib_call_chains_8616(project, codegen)

    assert changed is True
    assert calls == [(project, codegen)]
    assert codegen._inertia_stdlib_call_chains_structuring_pass_ran_8616 is True


def test_structuring_loop_idiom_owner_records_pass(monkeypatch):
    calls: list[str] = []
    project = SimpleNamespace()
    codegen = SimpleNamespace()

    monkeypatch.setattr(
        post_stage,
        "_materialize_global_byte_index_sum_loop_8616",
        lambda *_args: calls.append("global") is None,
    )

    changed = stage._materialize_structuring_loop_idioms_8616(project, codegen)

    assert changed is True
    assert calls == ["global"]
    assert codegen._inertia_loop_idiom_structuring_pass_ran_8616 is True


def test_structuring_loop_break_jcc_owner_records_pass(monkeypatch):
    project = SimpleNamespace()
    codegen = SimpleNamespace()
    calls: list[tuple[object, object]] = []
    monkeypatch.setattr(
        post_stage,
        "_materialize_unconsumed_loop_break_jcc_8616",
        lambda current_project, current_codegen: calls.append(
            (current_project, current_codegen)
        )
        is None,
    )

    changed = stage._materialize_structuring_unconsumed_loop_break_jcc_8616(
        project,
        codegen,
    )

    assert changed is True
    assert calls == [(project, codegen)]
    assert (
        codegen._inertia_unconsumed_loop_break_jcc_structuring_pass_ran_8616
        is True
    )


def test_structuring_stage_transfers_typed_conditions_before_final_validation_baseline(monkeypatch):
    calls = []
    function = SimpleNamespace(addr=0x4010, name="fn", info={})

    class _Functions:
        def function(self, addr, create=False):
            del addr, create
            return function

    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_tail_validation_enabled=True,
        _inertia_decompiler_stage=None,
        kb=SimpleNamespace(functions=_Functions()),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4010),
        _inertia_ss_stack_lowered=True,
        _inertia_structuring_validation_failed=True,
        _inertia_structuring_validation_failure_pass="_segmented_memory_reasoning_8616",
        _inertia_structuring_validation_failure_error="stale per-pass failure",
    )
    decompiler = SimpleNamespace(project=project, codegen=codegen, function=function, func=function, clinic=None)

    monkeypatch.setattr(stage.Decompiler, "_orig_before_structuring", lambda _self: calls.append("core"), raising=False)
    monkeypatch.setattr(
        stage._decompile_structuring_8616,
        "_orig_decompiler_decompile",
        lambda _self: calls.append("core"),
        raising=False,
    )
    monkeypatch.setattr(stage, "_prime_structuring_validation_semantics_8616", lambda *_args: calls.append("prime"))

    def _transfer(_project, func_addr, _codegen):
        calls.append(("transfer", func_addr))
        return 1

    def _fingerprint(*_args, **_kwargs):
        calls.append("fingerprint")
        return ("fp", len(calls))

    def _summary(*_args, **_kwargs):
        calls.append("summary")
        return {"conditions": ()}

    monkeypatch.setattr(stage, "transfer_typed_conditions_to_codegen_8616", _transfer)
    monkeypatch.setattr(stage, "fingerprint_x86_16_tail_validation_boundary", _fingerprint)
    monkeypatch.setattr(stage, "collect_x86_16_tail_validation_summary", _summary)
    monkeypatch.setattr(stage, "_structuring_codegen_8616", lambda *_args: False)
    monkeypatch.setattr(
        stage,
        "_apply_structuring_direct_stack_materialization_8616",
        lambda *_args: calls.append("direct_stack") and False,
    )
    monkeypatch.setattr(stage, "_prime_structuring_segment_global_semantics_8616", lambda *_args: False)
    monkeypatch.setattr(
        stage,
        "run_structuring_condition_cleanup_8616",
        lambda *_args: calls.append("condition_cleanup") and False,
    )
    monkeypatch.setattr(
        stage,
        "_materialize_structuring_selector_return_branches_8616",
        lambda *_args: calls.append("selector_return") and False,
    )
    monkeypatch.setattr(
        stage,
        "_materialize_structuring_return_chains_8616",
        lambda *_args, **_kwargs: calls.append("return_chains") and False,
    )
    monkeypatch.setattr(stage, "recover_structuring_canonical_for_loops_8616", lambda *_args: False)
    monkeypatch.setattr(
        stage,
        "_repair_structuring_loop_exit_return_guards_8616",
        lambda *_args: calls.append("loop_exit_guards") and False,
    )
    monkeypatch.setattr(
        stage,
        "_repair_structuring_unresolved_function_exit_gotos_8616",
        lambda *_args: calls.append("unresolved_exit_gotos") and False,
    )
    monkeypatch.setattr(
        stage,
        "_materialize_structuring_unconsumed_loop_break_jcc_8616",
        lambda *_args: calls.append("unconsumed_loop_break_jcc") and False,
    )
    monkeypatch.setattr(
        stage,
        "_repair_structuring_conditional_continue_guards_8616",
        lambda *_args: calls.append("conditional_continue") and False,
    )
    monkeypatch.setattr(
        stage,
        "_repair_structuring_pretest_loop_break_guards_8616",
        lambda *_args: calls.append("pretest_loop_break") and False,
    )
    monkeypatch.setattr(
        stage,
        "_repair_structuring_hoisted_jcc_target_copies_8616",
        lambda *_args: calls.append("hoisted_jcc_target_copy") and False,
    )
    monkeypatch.setattr(
        stage,
        "_repair_structuring_switch_loop_exit_returns_8616",
        lambda *_args: calls.append("switch_loop_exit_return") and False,
    )
    monkeypatch.setattr(
        stage,
        "_materialize_structuring_return_shape_8616",
        lambda *_args: calls.append("return_shape") and False,
    )
    monkeypatch.setattr(
        stage,
        "_materialize_structuring_void_tail_call_guard_8616",
        lambda *_args: calls.append("void_tail_guard") and False,
    )
    monkeypatch.setattr(
        stage,
        "_refresh_structuring_condition_semantics_8616",
        lambda *_args: calls.append("condition_refresh")
        or stage._condition_refresh.StructuringConditionRefreshResult8616.stable(),
    )
    monkeypatch.setattr(stage, "_restore_not_shift_conditions_structuring_8616", lambda *_args: False)
    monkeypatch.setattr(stage, "record_ast_condition_trace_8616", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        stage,
        "_replay_structuring_lowering_before_validation_8616",
        lambda *_args: calls.append("lowering_replay") and False,
    )
    monkeypatch.setattr(
        stage,
        "_replay_structuring_gp_state_after_late_cleanup_8616",
        lambda *_args: calls.append("gp-state-final") and False,
    )
    monkeypatch.setattr(
        stage,
        "build_x86_16_tail_validation_cached_result",
        lambda **kwargs: {
            "changed": False,
            "status": "stable",
            "cache_hit": False,
            "stage": kwargs["stage"],
            "mode": kwargs["mode"],
        },
    )
    monkeypatch.setattr(stage, "build_x86_16_tail_validation_verdict", lambda pass_name, _validation: pass_name)
    monkeypatch.setattr(stage, "_try_accept_structuring_validation_delta_from_evidence_8616", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(stage, "persist_x86_16_tail_validation_snapshot", lambda *_args, **_kwargs: None)

    stage._decompile_structuring_8616(decompiler)

    first_loop_guard = calls.index("unconsumed_loop_break_jcc")
    final_loop_guard = calls.index(
        "unconsumed_loop_break_jcc",
        first_loop_guard + 1,
    )
    assert calls[:3] == ["core", "prime", ("transfer", 0x4010)]
    assert calls.index(("transfer", 0x4010)) < calls.index("fingerprint")
    assert calls.index("return_chains") < calls.index("loop_exit_guards")
    assert calls.index("loop_exit_guards") < calls.index("unresolved_exit_gotos")
    assert calls.index("unresolved_exit_gotos") < first_loop_guard
    assert first_loop_guard < calls.index("conditional_continue")
    assert calls.index("conditional_continue") < calls.index("pretest_loop_break")
    assert calls.index("pretest_loop_break") < calls.index("hoisted_jcc_target_copy")
    assert calls.index("hoisted_jcc_target_copy") < calls.index("return_shape")
    assert calls.index("return_shape") < calls.index("void_tail_guard")
    first_lowering_replay = calls.index("lowering_replay")
    assert calls.index("void_tail_guard") < first_lowering_replay
    assert first_lowering_replay < final_loop_guard
    final_condition_refresh = len(calls) - 1 - calls[::-1].index("condition_refresh")
    final_fingerprint = len(calls) - 1 - calls[::-1].index("fingerprint")
    assert final_condition_refresh < final_loop_guard < calls.index("switch_loop_exit_return")
    assert calls.index("switch_loop_exit_return") < calls.index("gp-state-final")
    assert calls.index("gp-state-final") < final_fingerprint
    assert calls.count("lowering_replay") == 1
    assert calls.count("unconsumed_loop_break_jcc") == 2
    assert codegen._inertia_typed_conditions_transferred is True
    assert codegen._inertia_structuring_validation_failed is False
    assert codegen._inertia_structuring_validation_failure_pass is None
    assert codegen._inertia_structuring_validation_failure_error is None


@pytest.mark.parametrize(("prime_changed", "return_chain_changed"), ((False, True), (True, False)))
def test_structuring_return_chain_materialization_triggers_regeneration_before_final_validation(
    monkeypatch, prime_changed, return_chain_changed
):
    calls = []
    function = SimpleNamespace(addr=0x4010, name="fn", info={})

    class _Functions:
        def function(self, addr, create=False):
            del addr, create
            return function

    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_tail_validation_enabled=True,
        _inertia_decompiler_stage=None,
        kb=SimpleNamespace(functions=_Functions()),
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x4010), _inertia_ss_stack_lowered=True)
    decompiler = SimpleNamespace(project=project, codegen=codegen, function=function, func=function, clinic=None)

    monkeypatch.setattr(
        stage._decompile_structuring_8616,
        "_orig_decompiler_decompile",
        lambda _self: calls.append("core"),
        raising=False,
    )
    monkeypatch.setattr(stage, "_prime_structuring_validation_semantics_8616", lambda *_args: prime_changed)
    monkeypatch.setattr(stage, "transfer_typed_conditions_to_codegen_8616", lambda *_args: 0)
    monkeypatch.setattr(stage, "fingerprint_x86_16_tail_validation_boundary", lambda *_args, **_kwargs: ("fp",))
    monkeypatch.setattr(stage, "collect_x86_16_tail_validation_summary", lambda *_args, **_kwargs: {"conditions": ()})
    monkeypatch.setattr(stage, "_structuring_codegen_8616", lambda *_args: False)
    monkeypatch.setattr(stage, "_apply_structuring_direct_stack_materialization_8616", lambda *_args: False)
    monkeypatch.setattr(stage, "_prime_structuring_segment_global_semantics_8616", lambda *_args: False)
    monkeypatch.setattr(stage, "_materialize_structuring_selector_return_branches_8616", lambda *_args: False)
    monkeypatch.setattr(
        stage,
        "_materialize_structuring_return_chains_8616",
        lambda *_args, **_kwargs: return_chain_changed,
    )
    monkeypatch.setattr(stage, "recover_structuring_canonical_for_loops_8616", lambda *_args: False)
    monkeypatch.setattr(stage, "_repair_structuring_loop_exit_return_guards_8616", lambda *_args: False)
    monkeypatch.setattr(stage, "_repair_structuring_unresolved_function_exit_gotos_8616", lambda *_args: False)
    monkeypatch.setattr(stage, "_materialize_structuring_unconsumed_loop_break_jcc_8616", lambda *_args: False)
    monkeypatch.setattr(stage, "_repair_structuring_conditional_continue_guards_8616", lambda *_args: False)
    monkeypatch.setattr(stage, "_repair_structuring_pretest_loop_break_guards_8616", lambda *_args: False)
    monkeypatch.setattr(stage, "_repair_structuring_hoisted_jcc_target_copies_8616", lambda *_args: False)
    monkeypatch.setattr(stage, "_repair_structuring_switch_loop_exit_returns_8616", lambda *_args: False)
    monkeypatch.setattr(stage, "_materialize_structuring_return_shape_8616", lambda *_args: False)
    monkeypatch.setattr(stage, "_materialize_structuring_void_tail_call_guard_8616", lambda *_args: False)
    monkeypatch.setattr(
        stage,
        "_refresh_structuring_condition_semantics_8616",
        lambda *_args: stage._condition_refresh.StructuringConditionRefreshResult8616.stable(),
    )
    monkeypatch.setattr(stage, "_restore_not_shift_conditions_structuring_8616", lambda *_args: False)
    monkeypatch.setattr(stage, "record_ast_condition_trace_8616", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        stage,
        "_replay_structuring_lowering_before_validation_8616",
        lambda *_args: calls.append("lowering_replay") and False,
    )
    monkeypatch.setattr(
        stage,
        "_replay_structuring_gp_state_after_late_cleanup_8616",
        lambda *_args: False,
    )
    monkeypatch.setattr(
        stage,
        "_regenerate_structuring_text_safely_8616",
        lambda *_args, **_kwargs: calls.append("regenerate") or True,
    )
    monkeypatch.setattr(
        stage,
        "build_x86_16_tail_validation_cached_result",
        lambda **kwargs: {
            "changed": False,
            "status": "stable",
            "cache_hit": False,
            "stage": kwargs["stage"],
            "mode": kwargs["mode"],
        },
    )
    monkeypatch.setattr(stage, "build_x86_16_tail_validation_verdict", lambda pass_name, _validation: pass_name)
    monkeypatch.setattr(stage, "_try_accept_structuring_validation_delta_from_evidence_8616", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(stage, "persist_x86_16_tail_validation_snapshot", lambda *_args, **_kwargs: None)

    stage._decompile_structuring_8616(decompiler)

    assert "regenerate" in calls
    assert calls.index("regenerate") < calls.index("lowering_replay")
    assert codegen._inertia_structuring_validation_failed is False


def test_condition_evidence_transfer_materializes_conditions_before_region_structuring(monkeypatch):
    calls = []
    project = SimpleNamespace()
    statements = object()
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x4010, statements=statements))
    edge_evidence = (object(), object())

    def _transfer(_project, func_addr, _codegen):
        calls.append(("transfer", func_addr))
        _codegen._inertia_condition_edge_evidence = edge_evidence
        return 3

    def _materialize(_project, _codegen):
        calls.append("materialize")
        return True

    monkeypatch.setattr(stage, "transfer_typed_conditions_to_codegen_8616", _transfer)
    monkeypatch.setattr(stage._structuring_conditions, "apply_structuring_condition_materialization_8616", _materialize)

    changed = stage._condition_evidence_transfer_8616(project, codegen)

    assert changed is True
    assert calls == [("transfer", 0x4010), "materialize"]
    assert codegen._inertia_typed_conditions_transferred is True
    assert codegen._inertia_structuring_conditions_materialized_after_transfer_8616 is True
    assert codegen._inertia_structuring_conditions_materialized_root_8616 is statements
    assert codegen._inertia_structuring_conditions_materialized_surface_8616 == ()
    assert codegen._inertia_condition_edge_evidence_for_structuring_8616 == edge_evidence
    assert codegen._inertia_condition_evidence_transfer_8616 == {
        "condition_count": 3,
        "edge_evidence_count": 2,
        "materialization_changed": True,
        "owner": "structuring.condition_evidence_transfer",
    }


def test_condition_evidence_transfer_materializes_pretransferred_conditions(monkeypatch):
    calls = []
    project = SimpleNamespace()
    statements = object()
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4010, statements=statements),
        _inertia_typed_conditions_transferred=True,
    )

    monkeypatch.setattr(
        stage,
        "transfer_typed_conditions_to_codegen_8616",
        lambda *_args: pytest.fail("pretransferred conditions must not be transferred again"),
    )
    monkeypatch.setattr(
        stage._structuring_conditions,
        "apply_structuring_condition_materialization_8616",
        lambda *_args: calls.append("materialize") or True,
    )

    changed = stage._condition_evidence_transfer_8616(project, codegen)

    assert changed is True
    assert calls == ["materialize"]
    assert codegen._inertia_structuring_conditions_materialized_after_transfer_8616 is True
    assert codegen._inertia_structuring_conditions_materialized_root_8616 is statements
    assert codegen._inertia_condition_evidence_transfer_8616["condition_count"] == 0
    assert codegen._inertia_condition_evidence_transfer_8616["materialization_changed"] is True


def test_condition_evidence_transfer_skips_current_materialized_surface(monkeypatch):
    calls = []
    project = SimpleNamespace()
    statements = object()
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4010, statements=statements),
        _inertia_typed_conditions_transferred=True,
        _inertia_structuring_conditions_materialized_after_transfer_8616=True,
        _inertia_structuring_conditions_materialized_root_8616=statements,
        _inertia_structuring_conditions_materialized_surface_8616=(),
    )

    monkeypatch.setattr(
        stage,
        "transfer_typed_conditions_to_codegen_8616",
        lambda *_args: calls.append("transfer") or 1,
    )
    monkeypatch.setattr(
        stage._structuring_conditions,
        "apply_structuring_condition_materialization_8616",
        lambda *_args: calls.append("materialize") or True,
    )

    changed = stage._condition_evidence_transfer_8616(project, codegen)

    assert changed is False
    assert calls == []


def test_condition_refresh_skips_after_transfer_materialization(monkeypatch):
    calls = []
    project = SimpleNamespace()
    statements = object()
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4010, statements=statements),
        _inertia_typed_conditions_transferred=True,
        _inertia_structuring_conditions_materialized_after_transfer_8616=True,
        _inertia_structuring_conditions_materialized_root_8616=statements,
        _inertia_structuring_conditions_materialized_surface_8616=(),
    )

    monkeypatch.setattr(
        stage._condition_refresh,
        "transfer_typed_conditions_to_codegen_8616",
        lambda *_args: calls.append("transfer") or 1,
    )
    monkeypatch.setattr(
        stage._condition_refresh,
        "materialize_structuring_conditions_8616",
        lambda *_args: calls.append("materialize"),
    )

    result = stage._refresh_structuring_condition_semantics_8616(project, codegen)

    assert result.closure is stage._condition_refresh.ConditionRefreshClosure8616.STABLE
    assert result.changed is False
    assert calls == []


def test_condition_refresh_replays_after_structured_root_replacement(monkeypatch):
    calls = []
    project = SimpleNamespace()
    previous_statements = object()
    replacement_statements = object()
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4010, statements=replacement_statements),
        _inertia_typed_conditions_transferred=True,
        _inertia_structuring_conditions_materialized_after_transfer_8616=True,
        _inertia_structuring_conditions_materialized_root_8616=previous_statements,
    )

    monkeypatch.setattr(
        stage._condition_refresh,
        "transfer_typed_conditions_to_codegen_8616",
        lambda *_args: calls.append("transfer") or 1,
    )
    monkeypatch.setattr(
        stage._condition_refresh,
        "materialize_structuring_conditions_8616",
        lambda *_args: calls.append("materialize")
        or stage._structuring_conditions.StructuringConditionMaterializationResult8616(
            True,
            False,
            False,
            False,
            False,
        ),
    )
    monkeypatch.setattr(
        stage._condition_refresh,
        "run_segment_global_materialization_8616",
        lambda *_args, **_kwargs: calls.append("segment-global")
        or SimpleNamespace(changed=True),
    )
    result = stage._refresh_structuring_condition_semantics_8616(project, codegen)

    assert result.closure is stage._condition_refresh.ConditionRefreshClosure8616.CLOSED
    assert result.changed is True
    assert result.requires_broad_lowering_replay is False
    assert calls == ["materialize", "segment-global"]
    assert codegen._inertia_structuring_conditions_materialized_root_8616 is replacement_statements
    assert codegen._inertia_codegen_decl_refresh_required_8616 is True


def test_condition_refresh_replays_after_in_place_branch_surface_mutation(monkeypatch):
    calls = []
    project = SimpleNamespace()
    statements = object()
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4010, statements=statements),
        _inertia_typed_conditions_transferred=True,
        _inertia_structuring_conditions_materialized_after_transfer_8616=True,
        _inertia_structuring_conditions_materialized_root_8616=statements,
        _inertia_structuring_conditions_materialized_surface_8616=(("before",),),
    )

    monkeypatch.setattr(
        stage._condition_refresh,
        "transfer_typed_conditions_to_codegen_8616",
        lambda *_args: calls.append("transfer") or 1,
    )
    monkeypatch.setattr(
        stage._condition_refresh,
        "materialize_structuring_conditions_8616",
        lambda *_args: calls.append("materialize")
        or stage._structuring_conditions.StructuringConditionMaterializationResult8616(
            True,
            False,
            False,
            False,
            False,
        ),
    )
    monkeypatch.setattr(
        stage._condition_refresh,
        "structuring_condition_surface_token_8616",
        lambda _codegen: (("after",),),
    )
    monkeypatch.setattr(
        stage._condition_refresh,
        "run_segment_global_materialization_8616",
        lambda *_args, **_kwargs: calls.append("segment-global")
        or SimpleNamespace(changed=False),
    )
    result = stage._refresh_structuring_condition_semantics_8616(project, codegen)

    assert result.closure is stage._condition_refresh.ConditionRefreshClosure8616.CLOSED
    assert result.changed is True
    assert calls == ["materialize", "segment-global"]
    assert codegen._inertia_structuring_conditions_materialized_root_8616 is statements
    assert codegen._inertia_structuring_conditions_materialized_surface_8616 == (("after",),)


@pytest.mark.parametrize(
    ("refresh_result", "expected_changed", "expected_calls"),
    [
        (
            stage._condition_refresh.StructuringConditionRefreshResult8616.stable(),
            False,
            ["refresh"],
        ),
        (
            stage._condition_refresh.StructuringConditionRefreshResult8616(
                stage._condition_refresh.ConditionRefreshClosure8616.CLOSED,
                condition_changed=True,
            ),
            True,
            ["refresh"],
        ),
        (
            stage._condition_refresh.StructuringConditionRefreshResult8616.unclosed(),
            True,
            ["refresh", "lowering"],
        ),
    ],
)
def test_condition_refresh_gates_structuring_lowering_replay(
    monkeypatch,
    refresh_result,
    expected_changed,
    expected_calls,
):
    calls: list[str] = []
    project = SimpleNamespace()
    codegen = SimpleNamespace()
    monkeypatch.setattr(
        stage,
        "_refresh_structuring_condition_semantics_8616",
        lambda *_args: calls.append("refresh") or refresh_result,
    )
    monkeypatch.setattr(
        stage,
        "_replay_structuring_lowering_before_validation_8616",
        lambda *_args: calls.append("lowering") or False,
    )

    changed = stage._replay_structuring_lowering_after_condition_refresh_8616(project, codegen)

    assert changed is expected_changed
    assert calls == expected_calls


def test_typed_switch_finalizer_replays_after_replacement(monkeypatch):
    calls = []
    project = SimpleNamespace()
    codegen = SimpleNamespace()
    synthetic_globals = object()
    cod_metadata = object()
    def _replace(_codegen):
        calls.append(("replace", _codegen))
        return True

    def _replay(_project, _codegen, _synthetic_globals, *, cod_metadata=None):
        calls.append(("replay", _project, _codegen, _synthetic_globals, cod_metadata))
        return True

    monkeypatch.setattr(stage, "apply_typed_edge_switch_ast_replacement_if_enabled_8616", _replace)
    monkeypatch.setattr(stage, "replay_typed_edge_switch_segment_lowering_after_replacement_8616", _replay)

    result = stage.finalize_typed_edge_switch_replacement_if_enabled_8616(
        project,
        codegen,
        synthetic_globals,
        cod_metadata=cod_metadata,
    )

    assert result.changed is True
    assert result.replacement_changed is True
    assert result.segment_replay_changed is True
    assert calls == [
        ("replace", codegen),
        ("replay", project, codegen, synthetic_globals, cod_metadata),
    ]
    assert codegen._inertia_codegen_decl_refresh_required_8616 is True
    assert codegen._inertia_force_codegen_regeneration_8616 is True
    assert codegen._inertia_late_typed_switch_finalize_8616 == {
        "replacement_changed": True,
        "segment_replay_changed": True,
        "changed": True,
        "owner": "structuring.stage",
    }


def test_typed_switch_finalizer_skips_replay_when_replacement_unchanged(monkeypatch):
    calls = []
    project = SimpleNamespace()
    codegen = SimpleNamespace()

    def _replace(_codegen):
        calls.append("replace")
        return False

    def _replay(*_args, **_kwargs):
        calls.append("replay")
        return True

    monkeypatch.setattr(stage, "apply_typed_edge_switch_ast_replacement_if_enabled_8616", _replace)
    monkeypatch.setattr(stage, "replay_typed_edge_switch_segment_lowering_after_replacement_8616", _replay)

    result = stage.finalize_typed_edge_switch_replacement_if_enabled_8616(project, codegen, object())

    assert result.changed is False
    assert result.replacement_changed is False
    assert result.segment_replay_changed is False
    assert calls == ["replace"]
    assert not hasattr(codegen, "_inertia_codegen_decl_refresh_required_8616")
    assert not hasattr(codegen, "_inertia_force_codegen_regeneration_8616")


def test_seqnode_switch_replay_finalizer_sequences_replay_and_guarded_dce(monkeypatch):
    calls = []
    project = SimpleNamespace()
    codegen = SimpleNamespace()
    synthetic_globals = object()
    cod_metadata = object()
    segment_results = iter((True, True, True))

    def _segment(_project, _codegen, _synthetic_globals, *, cod_metadata=None):
        calls.append(("segment", _project, _codegen, _synthetic_globals, cod_metadata))
        return next(segment_results)

    def _condition(_project, _codegen):
        calls.append(("condition", _project, _codegen))
        return True

    def _selector(_codegen):
        calls.append(("selector", _codegen))
        return True

    def _word_projection(_codegen):
        calls.append(("word_projection", _codegen))
        return True

    def _dce(message):
        calls.append(("dce", message))
        return SimpleNamespace(changed=True)

    monkeypatch.setattr(stage, "replay_seqnode_switch_segment_lowering_after_replacement_8616", _segment)
    monkeypatch.setattr(stage, "replay_seqnode_switch_condition_materialization_after_replacement_8616", _condition)
    monkeypatch.setattr(stage, "seqnode_switch_replacement_changed_for_codegen_8616", lambda *_args: True)
    monkeypatch.setattr(stage, "materialize_word_projection_recompositions_8616", _word_projection)
    monkeypatch.setattr(stage, "replay_call_return_switch_selectors_8616", _selector)

    result = stage.finalize_seqnode_switch_replay_after_replacement_8616(
        project,
        codegen,
        synthetic_globals,
        _dce,
        cod_metadata=cod_metadata,
    )

    assert result.changed is True
    assert result.segment_replay_changed is True
    assert result.segment_dce_changed is True
    assert result.post_dce_segment_replay_changed is True
    assert result.post_dce_segment_dce_changed is True
    assert result.condition_replay_changed is True
    assert result.condition_dce_changed is True
    assert result.post_condition_segment_replay_changed is True
    assert result.post_condition_segment_dce_changed is True
    assert result.word_projection_replay_changed is True
    assert result.word_projection_dce_changed is True
    assert result.selector_replay_changed is True
    assert calls == [
        ("segment", project, codegen, synthetic_globals, cod_metadata),
        ("dce", "SeqNode switch segment replay DCE removed call expressions"),
        ("segment", project, codegen, synthetic_globals, cod_metadata),
        ("dce", "SeqNode switch post-DCE segment replay removed call expressions"),
        ("condition", project, codegen),
        ("dce", "SeqNode switch condition replay DCE removed call expressions"),
        ("segment", project, codegen, synthetic_globals, cod_metadata),
        ("dce", "SeqNode switch post-condition segment replay DCE removed call expressions"),
        ("word_projection", codegen),
        ("dce", "SeqNode switch Widening replay DCE removed call expressions"),
        ("selector", codegen),
    ]
    assert codegen._inertia_codegen_decl_refresh_required_8616 is True
    assert codegen._inertia_force_codegen_regeneration_8616 is True
    assert codegen._inertia_seqnode_switch_replay_finalize_8616 == {
        "segment_replay_changed": True,
        "segment_dce_changed": True,
        "post_dce_segment_replay_changed": True,
        "post_dce_segment_dce_changed": True,
        "condition_replay_changed": True,
        "condition_dce_changed": True,
        "post_condition_segment_replay_changed": True,
        "post_condition_segment_dce_changed": True,
        "word_projection_replay_changed": True,
        "word_projection_dce_changed": True,
        "selector_replay_changed": True,
        "changed": True,
        "owner": "structuring.stage",
    }


def test_seqnode_switch_replay_finalizer_leaves_refresh_clear_when_unchanged(monkeypatch):
    calls = []
    project = SimpleNamespace()
    codegen = SimpleNamespace()

    def _segment(*_args, **_kwargs):
        calls.append("segment")
        return False

    def _condition(*_args, **_kwargs):
        calls.append("condition")
        return False

    def _dce(_message):
        calls.append("dce")
        return SimpleNamespace(changed=True)

    monkeypatch.setattr(stage, "replay_seqnode_switch_segment_lowering_after_replacement_8616", _segment)
    monkeypatch.setattr(stage, "replay_seqnode_switch_condition_materialization_after_replacement_8616", _condition)
    monkeypatch.setattr(stage, "seqnode_switch_replacement_changed_for_codegen_8616", lambda *_args: False)

    result = stage.finalize_seqnode_switch_replay_after_replacement_8616(project, codegen, object(), _dce)

    assert result.changed is False
    assert result.word_projection_replay_changed is False
    assert result.word_projection_dce_changed is False
    assert result.selector_replay_changed is False
    assert calls == ["segment", "condition"]
    assert not hasattr(codegen, "_inertia_codegen_decl_refresh_required_8616")
    assert not hasattr(codegen, "_inertia_force_codegen_regeneration_8616")
    assert codegen._inertia_seqnode_switch_replay_finalize_8616["changed"] is False


def test_seqnode_switch_replay_finalizer_rejects_malformed_dce_result(monkeypatch):
    project = SimpleNamespace()
    codegen = SimpleNamespace()

    monkeypatch.setattr(
        stage,
        "replay_seqnode_switch_segment_lowering_after_replacement_8616",
        lambda *_args, **_kwargs: True,
    )

    with pytest.raises(TypeError, match="boolean changed field"):
        stage.finalize_seqnode_switch_replay_after_replacement_8616(
            project,
            codegen,
            object(),
            lambda _message: object(),
        )


def test_structuring_condition_cleanup_transfers_and_records_cleanup(monkeypatch):
    project = object()
    codegen = SimpleNamespace()
    calls = []

    def _transfer(_project, func_addr, _codegen):
        calls.append(("transfer", func_addr))
        return 3

    cleanup = SimpleNamespace(
        changed=True,
        materialization=SimpleNamespace(
            typed_conditions_changed=True,
            decoded_jcc_changed=False,
        ),
        flag_condition_pairs_changed=True,
        flag_bit_values_changed=False,
        interval_guards_changed=True,
        unused_flag_assignments_pruned=True,
        overwritten_flag_assignments_pruned=False,
    )

    def _cleanup(_project, _codegen):
        calls.append("cleanup")
        return cleanup

    monkeypatch.setattr(stage, "transfer_typed_conditions_to_codegen_8616", _transfer)
    monkeypatch.setattr(stage._structuring_conditions, "cleanup_structuring_conditions_after_replay_8616", _cleanup)

    changed = stage.run_structuring_condition_cleanup_8616(project, codegen, 0x4010)

    assert changed is True
    assert calls == [("transfer", 0x4010), "cleanup"]
    assert codegen._inertia_typed_conditions_transferred is True
    assert codegen._inertia_structuring_condition_cleanup_8616 == {
        "transferred_count": 3,
        "typed_conditions_changed": True,
        "decoded_jcc_changed": False,
        "flag_condition_pairs_changed": True,
        "flag_bit_values_changed": False,
        "interval_guards_changed": True,
        "unused_flag_assignments_pruned": True,
        "overwritten_flag_assignments_pruned": False,
        "changed": True,
        "owner": "structuring.stage",
    }
    assert codegen._inertia_condition_cleanup_structuring_pass_ran_8616 is True


def test_segment_global_materialization_sequences_lowering_owned_passes(monkeypatch):
    calls = []
    project = SimpleNamespace(_inertia_c_target="msc6")
    codegen = SimpleNamespace()
    synthetic_globals = object()
    cod_metadata = object()
    named_results = iter((False, True))

    def _runtime(_codegen, *, target):
        calls.append(("runtime", _codegen, target))
        return True

    def _named(_project, _codegen, _synthetic_globals, *, cod_metadata=None):
        calls.append(("named", _project, _codegen, _synthetic_globals, cod_metadata))
        return next(named_results)

    def _reconcile(_codegen):
        calls.append(("reconcile", _codegen))
        return True

    def _compare(_project, _codegen, _synthetic_globals, *, cod_metadata=None):
        calls.append(("compare", _project, _codegen, _synthetic_globals, cod_metadata))
        return True

    def _direct(_project, _codegen, _synthetic_globals, *, cod_metadata=None):
        assert _codegen.indexed_global_lvalues_ready is True
        calls.append(("direct", _project, _codegen, _synthetic_globals, cod_metadata))
        return False

    def _indexed(_project, _codegen, *, cod_metadata=None):
        _codegen.indexed_global_lvalues_ready = True
        calls.append(("indexed", _project, _codegen, cod_metadata))
        return True

    def _widen(_codegen):
        calls.append(("widen", _codegen))
        return True

    def _dos_interrupt(_codegen):
        calls.append(("dos_interrupt", _codegen))
        return True

    monkeypatch.setattr(segment_global_materialization, "apply_runtime_segment_lowering_8616", _runtime)
    monkeypatch.setattr(segment_global_materialization, "materialize_named_segmented_global_loads_8616", _named)
    monkeypatch.setattr(
        segment_global_materialization,
        "reconcile_recorded_cod_global_storage_identities_8616",
        _reconcile,
    )
    monkeypatch.setattr(
        segment_global_materialization,
        "materialize_compare_register_global_carriers_8616",
        _compare,
    )
    monkeypatch.setattr(segment_global_materialization, "materialize_direct_global_symbol_stores_8616", _direct)
    monkeypatch.setattr(segment_global_materialization, "materialize_indexed_segmented_global_loads_8616", _indexed)
    monkeypatch.setattr(
        segment_global_materialization,
        "materialize_dos_interrupt_aggregate_globals_8616",
        _dos_interrupt,
    )
    monkeypatch.setattr(segment_global_materialization, "apply_segmented_load_widening_8616", _widen)

    result = segment_global_materialization.run_segment_global_materialization_8616(
        project,
        codegen,
        synthetic_globals,
        cod_metadata=cod_metadata,
        include_runtime_segment=True,
    )

    assert result.changed is True
    assert result.runtime_segment_changed is True
    assert result.segmented_load_widening_changed is True
    assert result.named_global_changed is True
    assert result.compare_register_global_changed is True
    assert result.direct_global_store_changed is False
    assert result.indexed_global_changed is True
    assert result.dos_interrupt_aggregate_changed is True
    assert calls == [
        ("named", project, codegen, synthetic_globals, cod_metadata),
        ("compare", project, codegen, synthetic_globals, cod_metadata),
        ("indexed", project, codegen, cod_metadata),
        ("direct", project, codegen, synthetic_globals, cod_metadata),
        ("dos_interrupt", codegen),
        ("widen", codegen),
        ("runtime", codegen, "msc6"),
        ("named", project, codegen, synthetic_globals, cod_metadata),
        ("reconcile", codegen),
    ]
    assert codegen._inertia_segment_global_materialization_8616 == {
        "runtime_segment_changed": True,
        "segmented_load_widening_changed": True,
        "named_global_changed": True,
        "compare_register_global_changed": True,
        "direct_global_store_changed": False,
        "indexed_global_changed": True,
        "dos_interrupt_aggregate_changed": True,
        "changed": True,
        "owner": "lowering.segment_global_materialization",
    }


def test_late_switch_segment_replay_refreshes_condition_provenance_first(monkeypatch):
    calls: list[str] = []
    project = SimpleNamespace()
    codegen = SimpleNamespace()

    def replay_provenance(_codegen):
        calls.append("provenance")
        return SimpleNamespace(changed=True)

    def replay_lowering(*_args, **_kwargs):
        calls.append("lowering")
        return SimpleNamespace(changed=False)

    monkeypatch.setattr(
        stage,
        "replay_codegen_structured_condition_segment_provenance_8616",
        replay_provenance,
    )
    monkeypatch.setattr(stage, "run_segment_global_materialization_8616", replay_lowering)

    changed = stage._replay_segment_global_lowering_after_switch_replacement_8616(
        project,
        codegen,
        object(),
    )

    assert changed is True
    assert calls == ["provenance", "lowering"]


def test_redundant_loop_break_carrier_replay_stays_stage_owned(monkeypatch) -> None:
    codegen = SimpleNamespace()
    calls: list[object] = []

    def prune(candidate: object) -> bool:
        calls.append(candidate)
        return True

    monkeypatch.setattr(stage, "prune_redundant_loop_break_carriers_8616", prune)

    changed = stage.prune_redundant_loop_break_carriers_after_lowering_8616(codegen)

    assert changed is True
    assert calls == [codegen]


def test_direct_instruction_materialization_sequences_stage_owned_passes(monkeypatch):
    calls = []
    project = SimpleNamespace()
    codegen = SimpleNamespace()
    function = object()

    def _direct_stack_mov(
        _codegen,
        *,
        project=None,
        function=None,
        allow_stack_slot_fallback=True,
        source_kinds=None,
        materialize_reloads=True,
    ):
        calls.append(
            (
                "stack_mov",
                _codegen,
                project,
                function,
                allow_stack_slot_fallback,
                source_kinds,
                materialize_reloads,
            )
        )
        return True

    def _direct_global_incdec(_codegen, *, project=None, function=None):
        calls.append(("global_incdec", _codegen, project, function))
        return False

    def _direct_stack_incdec(_codegen, *, project=None, function=None):
        calls.append(("stack_incdec", _codegen, project, function))
        return False

    def _callee_saved_spills(_codegen, _project, *, function=None):
        assert function is function_under_test
        calls.append(("callee_saved", _codegen, _project))
        return True

    monkeypatch.setattr(stage, "materialize_direct_stack_mov_instructions_8616", _direct_stack_mov)
    monkeypatch.setattr(stage, "materialize_direct_stack_incdec_instructions_8616", _direct_stack_incdec)
    monkeypatch.setattr(stage, "materialize_direct_global_incdec_instructions_8616", _direct_global_incdec)
    monkeypatch.setattr(stage, "prune_callee_saved_stack_spills_8616", _callee_saved_spills)

    function_under_test = function
    result = stage.run_direct_instruction_materialization_8616(project, codegen, function=function_under_test)

    assert result.changed is True
    assert result.direct_stack_mov_changed is True
    assert result.direct_stack_incdec_changed is False
    assert result.direct_global_incdec_changed is False
    assert result.callee_saved_spill_prune_changed is True
    assert calls == [
        ("callee_saved", codegen, project),
        ("stack_mov", codegen, project, function, True, None, True),
        ("stack_incdec", codegen, project, function),
        ("global_incdec", codegen, project, function),
    ]
    assert codegen._inertia_direct_instruction_materialization_8616 == {
        "direct_stack_mov_changed": True,
        "direct_stack_incdec_changed": False,
        "direct_global_incdec_changed": False,
        "callee_saved_spill_prune_changed": True,
        "changed": True,
        "owner": "structuring.stage",
    }
    assert codegen._inertia_direct_global_incdec_materialization_structuring_pass_ran_8616 is True


def test_direct_instruction_materialization_can_run_filtered_stage_owned_pass(monkeypatch):
    calls = []
    project = SimpleNamespace()
    codegen = SimpleNamespace()
    source_kinds = frozenset({"signed-idiv"})

    def _direct_stack_mov(
        _codegen,
        *,
        project=None,
        function=None,
        allow_stack_slot_fallback=True,
        source_kinds=None,
        materialize_reloads=True,
    ):
        calls.append(
            (
                "stack_mov",
                _codegen,
                project,
                function,
                allow_stack_slot_fallback,
                source_kinds,
                materialize_reloads,
            )
        )
        return True

    def _direct_global_incdec(_codegen, *, project=None, function=None):
        calls.append(("global_incdec", _codegen, project, function))
        return True

    def _direct_stack_incdec(_codegen, *, project=None, function=None):
        calls.append(("stack_incdec", _codegen, project, function))
        return True

    monkeypatch.setattr(stage, "materialize_direct_stack_mov_instructions_8616", _direct_stack_mov)
    monkeypatch.setattr(stage, "materialize_direct_stack_incdec_instructions_8616", _direct_stack_incdec)
    monkeypatch.setattr(stage, "materialize_direct_global_incdec_instructions_8616", _direct_global_incdec)

    result = stage.run_direct_instruction_materialization_8616(
        project,
        codegen,
        include_direct_global_incdec=False,
        include_direct_stack_incdec=False,
        allow_stack_slot_fallback=False,
        source_kinds=source_kinds,
        materialize_stack_reloads=False,
    )

    assert result.changed is True
    assert result.direct_stack_mov_changed is True
    assert result.direct_stack_incdec_changed is False
    assert result.direct_global_incdec_changed is False
    assert calls == [("stack_mov", codegen, project, None, False, source_kinds, False)]


def test_direct_instruction_materialization_can_run_global_incdec_only(monkeypatch):
    calls = []
    project = SimpleNamespace()
    codegen = SimpleNamespace()

    def _direct_stack_mov(*_args, **_kwargs):
        calls.append("stack_mov")
        return True

    def _direct_global_incdec(_codegen, *, project=None, function=None):
        calls.append(("global_incdec", _codegen, project, function))
        return True

    def _direct_stack_incdec(_codegen, *, project=None, function=None):
        calls.append(("stack_incdec", _codegen, project, function))
        return True

    monkeypatch.setattr(stage, "materialize_direct_stack_mov_instructions_8616", _direct_stack_mov)
    monkeypatch.setattr(stage, "materialize_direct_stack_incdec_instructions_8616", _direct_stack_incdec)
    monkeypatch.setattr(stage, "materialize_direct_global_incdec_instructions_8616", _direct_global_incdec)

    result = stage.run_direct_instruction_materialization_8616(
        project,
        codegen,
        include_direct_stack_mov=False,
        include_direct_stack_incdec=False,
    )

    assert result.changed is True
    assert result.direct_stack_mov_changed is False
    assert result.direct_stack_incdec_changed is False
    assert result.direct_global_incdec_changed is True
    assert calls == [("global_incdec", codegen, project, None)]
    assert codegen._inertia_direct_global_incdec_materialization_structuring_pass_ran_8616 is True


def test_direct_instruction_materialization_records_global_owner_run_without_change(monkeypatch):
    calls = []
    project = SimpleNamespace()
    codegen = SimpleNamespace()

    def _direct_global_incdec(_codegen, *, project=None, function=None):
        calls.append(("global_incdec", _codegen, project, function))
        return False

    monkeypatch.setattr(stage, "materialize_direct_global_incdec_instructions_8616", _direct_global_incdec)

    result = stage.run_direct_instruction_materialization_8616(
        project,
        codegen,
        include_direct_stack_mov=False,
        include_direct_stack_incdec=False,
    )

    assert result.changed is False
    assert result.direct_global_incdec_changed is False
    assert calls == [("global_incdec", codegen, project, None)]
    assert codegen._inertia_direct_global_incdec_materialization_structuring_pass_ran_8616 is True


def test_structuring_direct_stack_materialization_records_owner_run_flag(monkeypatch):
    calls: list[str] = []
    cod_metadata = object()
    project = SimpleNamespace(_inertia_cod_metadata_by_func_addr_8616={0x4010: cod_metadata})
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x4010))
    function = object()

    def stack_mov(_codegen, *, project=None, function=None, allow_stack_slot_fallback=True, source_kinds=None):
        del project, function, allow_stack_slot_fallback, source_kinds
        calls.append("mov")
        return False

    def stack_incdec(_codegen, *, project=None, function=None):
        del project, function
        calls.append("incdec")
        return False

    def global_incdec(_codegen, *, project=None, function=None):
        del project, function
        calls.append("global_incdec")
        return False

    def callee_saved(_codegen, _project, *, function=None):
        del _codegen, _project, function
        calls.append("callee_saved")
        return False

    def loop_entry(_project, _codegen, _function):
        assert (_project, _codegen, _function) == (project, codegen, function)
        calls.append("loop_entry")
        return True

    def branch(_project, _codegen, _function):
        assert (_project, _codegen, _function) == (project, codegen, function)
        calls.append("branch")
        return True

    monkeypatch.setattr(stage, "_current_structuring_function_8616", lambda *_args: function)
    monkeypatch.setattr(stage, "_bind_direct_stack_move_branch_ownership_8616", lambda *_args: None)
    monkeypatch.setattr(stage, "materialize_direct_stack_mov_instructions_8616", stack_mov)
    monkeypatch.setattr(stage, "materialize_direct_stack_incdec_instructions_8616", stack_incdec)
    monkeypatch.setattr(stage, "materialize_direct_global_incdec_instructions_8616", global_incdec)
    monkeypatch.setattr(stage, "prune_callee_saved_stack_spills_8616", callee_saved)
    monkeypatch.setattr(stage, "materialize_direct_stack_move_loop_entry_ownership_8616", loop_entry)
    monkeypatch.setattr(stage, "materialize_direct_stack_move_branch_ownership_8616", branch)

    assert stage._apply_structuring_direct_stack_materialization_8616(project, codegen) is True
    assert calls == [
        "callee_saved",
        "mov",
        "incdec",
        "global_incdec",
        "branch",
        "loop_entry",
    ]
    assert codegen._inertia_direct_stack_materialization_structuring_pass_ran_8616 is True
    assert codegen._inertia_direct_global_incdec_materialization_structuring_pass_ran_8616 is True
    assert codegen._inertia_codegen_decl_refresh_required_8616 is True


def test_structuring_direct_stack_materialization_does_not_repeat_callback_ownership(monkeypatch):
    calls: list[str] = []
    project = SimpleNamespace()
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x4010))
    function = object()

    def stack_mov(_codegen, **_kwargs):
        calls.append("mov")
        return _codegen._inertia_direct_stack_move_branch_ownership_replay_8616()

    def record(name, changed=False):
        def operation(*_args, **_kwargs):
            calls.append(name)
            return changed

        return operation

    monkeypatch.setattr(stage, "_current_structuring_function_8616", lambda *_args: function)
    monkeypatch.setattr(stage, "prune_callee_saved_stack_spills_8616", record("callee_saved"))
    monkeypatch.setattr(stage, "materialize_direct_stack_mov_instructions_8616", stack_mov)
    monkeypatch.setattr(stage, "materialize_direct_stack_incdec_instructions_8616", record("incdec"))
    monkeypatch.setattr(stage, "materialize_direct_global_incdec_instructions_8616", record("global_incdec"))
    monkeypatch.setattr(stage, "materialize_direct_stack_move_branch_ownership_8616", record("branch"))
    monkeypatch.setattr(stage, "materialize_direct_stack_move_loop_entry_ownership_8616", record("loop_entry", True))
    monkeypatch.setattr(stage, "materialize_direct_stack_move_loop_tail_ownership_8616", record("loop_tail"))

    assert stage._apply_structuring_direct_stack_materialization_8616(project, codegen) is True
    assert calls == [
        "callee_saved",
        "mov",
        "branch",
        "loop_entry",
        "loop_tail",
        "incdec",
        "global_incdec",
    ]


def test_structuring_segment_global_prime_uses_stage_owned_order_before_validation(monkeypatch):
    calls: list[tuple[object, object, object, object | None]] = []
    parity_calls: list[tuple[object, object]] = []
    cod_metadata = object()
    synthetic_globals = {"clStart": object()}
    project = SimpleNamespace(
        _inertia_cod_metadata_by_func_addr_8616={0x4010: cod_metadata},
        _inertia_synthetic_globals={"project_only": object()},
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4010),
        _inertia_synthetic_globals=synthetic_globals,
    )

    def segment_global_materialization(
        actual_project,
        actual_codegen,
        actual_synthetic_globals,
        *,
        cod_metadata=None,
        include_runtime_segment=False,
    ):
        assert include_runtime_segment is True
        calls.append(
            (
                actual_project,
                actual_codegen,
                actual_synthetic_globals,
                cod_metadata,
            )
        )
        return SimpleNamespace(changed=True)

    monkeypatch.setattr(
        stage,
        "run_segment_global_materialization_8616",
        segment_global_materialization,
    )
    monkeypatch.setattr(
        stage,
        "collect_indexed_address_collector_parity_8616",
        lambda actual_project, actual_codegen: parity_calls.append(
            (actual_project, actual_codegen)
        ),
    )

    changed = stage._prime_structuring_segment_global_semantics_8616(
        project,
        codegen,
    )

    assert changed is True
    assert parity_calls == [(project, codegen)]
    assert calls == [(project, codegen, synthetic_globals, cod_metadata)]
    assert codegen._inertia_segment_global_structuring_prime_ran_8616 is True
    assert codegen._inertia_codegen_decl_refresh_required_8616 is True


def test_structuring_validation_prime_refreshes_conditions_after_final_lowering_replay(
    monkeypatch,
):
    calls: list[str] = []
    project = SimpleNamespace()
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x4010))

    unchanged = _recorded_stub_8616(calls)

    for name in (
        "_apply_structuring_stable_stack_semantics_8616",
        "_apply_structuring_direct_stack_materialization_8616",
        "_materialize_structuring_selector_return_branches_8616",
        "_materialize_structuring_return_chains_8616",
        "_materialize_structuring_pointer_arg_indirect_loads_8616",
        "_materialize_structuring_callsite_prototypes_8616",
        "_materialize_structuring_callsite_stack_arguments_8616",
        "_repair_structuring_synthetic_internal_calls_8616",
        "_materialize_structuring_stdlib_call_chains_8616",
        "reconcile_callsite_interface_declarations_8616",
        "_repair_structuring_loop_exit_return_guards_8616",
        "_repair_structuring_unresolved_function_exit_gotos_8616",
        "_materialize_structuring_unconsumed_loop_break_jcc_8616",
        "_repair_structuring_conditional_continue_guards_8616",
        "_repair_structuring_pretest_loop_break_guards_8616",
        "_repair_structuring_hoisted_jcc_target_copies_8616",
        "_repair_structuring_switch_loop_exit_returns_8616",
        "_materialize_structuring_return_shape_8616",
        "run_structuring_condition_cleanup_8616",
    ):
        monkeypatch.setattr(stage, name, unchanged)
    monkeypatch.setattr(stage._codegen, "split_distinct_condition_call_occurrences_8616", unchanged)
    monkeypatch.setattr(stage._segmented_mem, "apply_x86_16_segmented_memory_reasoning", unchanged)
    monkeypatch.setattr(stage, "transfer_typed_conditions_to_codegen_8616", unchanged)
    monkeypatch.setattr(
        real_mode_linear,
        "lower_stable_ds_es_linear_global_dereferences_8616",
        unchanged,
    )

    segment_replay = _recorded_stub_8616(calls, "segment")
    consumed_push_replay = _recorded_stub_8616(calls, "consumed-push")
    pointer_memory_replay = _recorded_stub_8616(calls, "pointer-memory")
    loop_idiom_replay = _recorded_stub_8616(calls, "loop")
    terminal_call_result_replay = _recorded_stub_8616(calls, "terminal-call")
    condition_refresh = _recorded_stub_8616(
        calls,
        "condition-refresh",
        result=stage._condition_refresh.StructuringConditionRefreshResult8616.unclosed(),
    )
    widening_replay = _recorded_stub_8616(calls, "widening")
    carrier_prune = _recorded_stub_8616(calls, "carrier-prune")
    dead_flag_cleanup = _recorded_stub_8616(
        calls,
        "dead-flags",
        result=SimpleNamespace(changed=False),
    )
    lowering_replay = _recorded_stub_8616(
        calls,
        "segment",
        "consumed-push",
        "carrier-prune",
    )

    monkeypatch.setattr(
        stage._vex_ir,
        "apply_x86_16_vex_ir_artifact",
        lambda *_args, **_kwargs: calls.append("vex-ir") or False,
    )
    monkeypatch.setattr(
        stage._stack_memory_ssa,
        "apply_x86_16_stack_memory_ssa_alias_artifact",
        lambda *_args, **_kwargs: calls.append("memory-alias") or False,
    )
    monkeypatch.setattr(
        stage._segment_state,
        "apply_x86_16_segment_state_artifact",
        lambda *_args, **_kwargs: calls.append("segment-state") or False,
    )
    monkeypatch.setattr(stage, "_prime_structuring_segment_global_semantics_8616", segment_replay)
    monkeypatch.setattr(
        stage,
        "prune_materialized_call_push_stack_assignments_8616",
        consumed_push_replay,
    )
    monkeypatch.setattr(
        stage,
        "_apply_structuring_pointer_memory_idioms_8616",
        pointer_memory_replay,
    )
    monkeypatch.setattr(
        stage,
        "_materialize_structuring_loop_idioms_8616",
        loop_idiom_replay,
    )
    monkeypatch.setattr(
        stage,
        "_materialize_structuring_terminal_call_result_return_8616",
        terminal_call_result_replay,
    )
    monkeypatch.setattr(
        stage,
        "_refresh_structuring_condition_semantics_8616",
        condition_refresh,
    )
    monkeypatch.setattr(
        stage,
        "_run_structuring_widening_copy_propagation_8616",
        widening_replay,
    )
    monkeypatch.setattr(
        stage,
        "prune_unread_stack_lowered_register_carriers_8616",
        carrier_prune,
    )
    monkeypatch.setattr(stage, "_replay_structuring_lowering_before_validation_8616", lowering_replay)
    monkeypatch.setattr(
        stage._structuring_conditions,
        "prune_dead_flag_assignments_after_structuring_8616",
        dead_flag_cleanup,
    )
    monkeypatch.setattr(
        stage,
        "lower_architectural_gp_register_state_8616",
        lambda *_args, **_kwargs: calls.append("gp-state") or False,
    )
    stage._prime_structuring_validation_semantics_8616(project, codegen)

    assert calls == [
        "vex-ir",
        "memory-alias",
        "segment-state",
        "segment",
        "segment",
        "pointer-memory",
        "loop",
        "segment",
        "consumed-push",
        "carrier-prune",
        "terminal-call",
        "carrier-prune",
        "condition-refresh",
        "segment",
        "consumed-push",
        "carrier-prune",
        "condition-refresh",
        "segment",
        "consumed-push",
        "carrier-prune",
        "widening",
        "carrier-prune",
        "dead-flags",
        "gp-state",
    ]
    assert codegen._inertia_structuring_validation_semantics_primed is True
    assert codegen._inertia_structuring_gp_state_cleanup_replay_count_8616 == 1


def test_late_structuring_gp_state_replay_is_explicit_and_repeatable(monkeypatch):
    """Every late cleanup boundary reconsumes typed GP projections."""
    calls: list[object] = []
    codegen = SimpleNamespace()

    monkeypatch.setattr(
        stage,
        "lower_architectural_gp_register_state_8616",
        lambda actual_codegen: calls.append(actual_codegen) or True,
    )

    assert stage._replay_structuring_gp_state_after_late_cleanup_8616(codegen) is True
    assert stage._replay_structuring_gp_state_after_late_cleanup_8616(codegen) is True
    assert calls == [codegen, codegen]
    assert codegen._inertia_structuring_gp_state_cleanup_replay_count_8616 == 2


def test_structuring_lowering_replay_orders_call_and_pointer_consumers_before_consumed_pushes(
    monkeypatch,
):
    calls: list[str] = []
    project = SimpleNamespace()
    codegen = SimpleNamespace()

    callsite_prototypes = _recorded_stub_8616(calls, "callsite-prototypes")
    callsite_arguments = _recorded_stub_8616(calls, "callsite-arguments")
    call_return_selectors = _recorded_stub_8616(calls, "call-return-selectors")
    pointer_arguments = _recorded_stub_8616(calls, "pointer-arguments")
    stdlib_call_chains = _recorded_stub_8616(calls, "stdlib-call-chains")
    stable_stack_replay = _recorded_stub_8616(calls, "stable-stack")
    direct_stack_replay = _recorded_stub_8616(calls, "direct-stack")
    segment_replay = _recorded_stub_8616(calls, "segment", result=True)
    frame_prologue_replay = _recorded_stub_8616(calls, "frame-prologue")
    consumed_push_replay = _recorded_stub_8616(calls, "consumed-push")
    structured_intrinsics = _recorded_stub_8616(calls, "structured-intrinsics")
    prune_structured_intrinsics = _recorded_stub_8616(
        calls,
        "prune-structured-intrinsics",
    )
    no_op_type_consumer = _recorded_stub_8616(calls)

    monkeypatch.setattr(
        stage,
        "_materialize_structuring_callsite_prototypes_8616",
        callsite_prototypes,
    )
    monkeypatch.setattr(stage, "materialize_annotated_stack_prototype_8616", no_op_type_consumer)
    monkeypatch.setattr(stage, "materialize_call_return_conditions_8616", no_op_type_consumer)
    monkeypatch.setattr(
        stage,
        "_materialize_structuring_callsite_stack_arguments_8616",
        callsite_arguments,
    )
    monkeypatch.setattr(
        stage,
        "replay_call_return_switch_selectors_8616",
        call_return_selectors,
    )
    monkeypatch.setattr(
        stage,
        "_materialize_structuring_pointer_arg_indirect_loads_8616",
        pointer_arguments,
    )
    monkeypatch.setattr(
        stage,
        "_materialize_structuring_stdlib_call_chains_8616",
        stdlib_call_chains,
    )
    monkeypatch.setattr(
        stage,
        "_apply_structuring_stable_stack_semantics_8616",
        stable_stack_replay,
    )
    monkeypatch.setattr(
        stage,
        "_apply_structuring_direct_stack_materialization_8616",
        direct_stack_replay,
    )
    monkeypatch.setattr(stage, "_prime_structuring_segment_global_semantics_8616", segment_replay)
    monkeypatch.setattr(stage, "prune_frame_prologue_stack_assignments_8616", frame_prologue_replay)
    monkeypatch.setattr(
        stage,
        "_replay_materialized_call_stack_metadata_8616",
        consumed_push_replay,
    )
    monkeypatch.setattr(stage, "materialize_software_interrupt_calls_8616", no_op_type_consumer)
    monkeypatch.setattr(
        stage,
        "materialize_software_interrupt_status_outputs_8616",
        no_op_type_consumer,
    )
    monkeypatch.setattr(
        stage,
        "prune_unused_structured_insert_intrinsics_8616",
        prune_structured_intrinsics,
    )
    monkeypatch.setattr(
        stage,
        "lower_structured_insert_intrinsics_8616",
        structured_intrinsics,
    )
    monkeypatch.setattr(stage, "materialize_signed_global_declarations_8616", no_op_type_consumer)
    monkeypatch.setattr(
        stage, "materialize_loop_carried_terminal_return_8616", lambda *_args: SimpleNamespace(changed=False)
    )
    monkeypatch.setattr(stage, "apply_condition_scalar_types_8616", no_op_type_consumer)
    monkeypatch.setattr(stage, "materialize_explicit_scalar_char_types_8616", no_op_type_consumer)
    monkeypatch.setattr(
        stage,
        "finalize_typed_register_locals_8616",
        lambda *_args: SimpleNamespace(changed=False),
    )

    changed = stage._replay_structuring_lowering_before_validation_8616(
        project,
        codegen,
    )

    assert changed is True
    assert calls == [
        "callsite-prototypes",
        "callsite-arguments",
        "call-return-selectors",
        "pointer-arguments",
        "stdlib-call-chains",
        "stable-stack",
        "direct-stack",
        "segment",
        "frame-prologue",
        "consumed-push",
        "prune-structured-intrinsics",
        "structured-intrinsics",
    ]


def test_structuring_stage_skips_per_pass_validation_for_large_functions(monkeypatch):
    class _Functions:
        def function(self, addr, create=False):
            del addr, create
            return SimpleNamespace(block_addrs_set=set(range(40)))

    project = SimpleNamespace(
        _inertia_tail_validation_enabled=True,
        _inertia_decompiler_stage=None,
        kb=SimpleNamespace(functions=_Functions()),
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x4010), _inertia_ss_stack_lowered=True)
    validation_calls = []

    monkeypatch.setattr(
        stage,
        "collect_x86_16_tail_validation_summary",
        lambda *_args, **_kwargs: validation_calls.append("collect") or {"conditions": ()},
    )
    monkeypatch.setattr(
        stage,
        "_decompiler_structuring_passes_for_function",
        lambda _project, _codegen: (
            stage.DecompilerStructuringPassSpec("_segmented_memory_reasoning_8616", lambda _codegen: False, False),
        ),
    )

    changed = stage._structuring_codegen_8616(project, codegen)

    assert changed is False
    assert validation_calls == []
    assert codegen._inertia_structuring_pass_validation_skipped_large_function_8616 is True
    assert (
        codegen._inertia_structuring_pass_validation_skip_reason_8616
        is stage.StructuringPassValidationSkipReason8616.LARGE_FUNCTION_BLOCK_COUNT
    )
    assert not hasattr(codegen, "_inertia_structuring_pass_validation")


def test_structuring_stage_skips_per_pass_validation_for_byte_heavy_functions(monkeypatch):
    class _Functions:
        def function(self, addr, create=False):
            del addr, create
            return SimpleNamespace(
                block_addrs_set=set(range(20)),
                info={"_inertia_function_complexity": {"blocks": 20, "bytes": 0x180}},
            )

    project = SimpleNamespace(
        _inertia_tail_validation_enabled=True,
        _inertia_decompiler_stage=None,
        kb=SimpleNamespace(functions=_Functions()),
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x4010), _inertia_ss_stack_lowered=True)
    validation_calls = []

    monkeypatch.setattr(
        stage,
        "collect_x86_16_tail_validation_summary",
        lambda *_args, **_kwargs: validation_calls.append("collect") or {"conditions": ()},
    )
    monkeypatch.setattr(
        stage,
        "_decompiler_structuring_passes_for_function",
        lambda _project, _codegen: (
            stage.DecompilerStructuringPassSpec("_segmented_memory_reasoning_8616", lambda _codegen: False, False),
        ),
    )

    changed = stage._structuring_codegen_8616(project, codegen)

    assert changed is False
    assert validation_calls == []
    assert codegen._inertia_structuring_pass_validation_skipped_large_function_8616 is True
    assert (
        codegen._inertia_structuring_pass_validation_skip_reason_8616
        is stage.StructuringPassValidationSkipReason8616.LARGE_FUNCTION_BYTE_SIZE
    )
    assert not hasattr(codegen, "_inertia_structuring_pass_validation")


def test_structuring_stage_records_non_stable_per_pass_validation_without_aborting(monkeypatch):
    project = SimpleNamespace(
        _inertia_tail_validation_enabled=True,
        _inertia_decompiler_stage=None,
        kb=SimpleNamespace(functions=None),
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x4010), order=[], _inertia_ss_stack_lowered=True)

    def _semantic_pass(_codegen):
        _codegen.order.append("semantic")
        return True

    def _later_pass(_codegen):
        _codegen.order.append("later")
        return True

    monkeypatch.setattr(stage, "fingerprint_x86_16_tail_validation_boundary", lambda *_args, **_kwargs: ("fp",))
    empty_summary = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )
    monkeypatch.setattr(
        stage,
        "collect_x86_16_tail_validation_summary",
        lambda *_args, **_kwargs: empty_summary,
    )
    monkeypatch.setattr(
        stage,
        "build_x86_16_tail_validation_cached_result",
        lambda **kwargs: {
            "changed": False,
            "status": "unknown",
            "summary_text": "validation metadata missing",
            "cache_hit": False,
            "stage": kwargs["stage"],
            "mode": kwargs["mode"],
        },
    )
    monkeypatch.setattr(
        stage, "build_x86_16_tail_validation_verdict", lambda pass_name, _validation: f"{pass_name}: unknown"
    )
    monkeypatch.setattr(
        stage,
        "_replay_structuring_lowering_before_validation_8616",
        lambda *_args, **_kwargs: False,
    )
    monkeypatch.setattr(
        stage,
        "_decompiler_structuring_passes_for_function",
        lambda _project, _codegen: (
            stage.DecompilerStructuringPassSpec("_segmented_memory_reasoning_8616", _semantic_pass, False),
            stage.DecompilerStructuringPassSpec("_structuring_codegen_8616", _later_pass, False),
        ),
    )

    changed = stage._structuring_codegen_8616(project, codegen)

    assert changed is True
    assert codegen.order == ["semantic", "later"]
    validation = codegen._inertia_structuring_pass_validation
    assert validation["_segmented_memory_reasoning_8616"]["status"] == "unknown"
    assert validation["_structuring_codegen_8616"]["status"] == "unknown"
    assert codegen._inertia_structuring_validation_failed is True
    assert codegen._inertia_structuring_validation_failure_pass == "_structuring_codegen_8616"
    assert codegen._inertia_structuring_validation_failure_error == "validation metadata missing"


@pytest.mark.parametrize(
    ("pass_changed", "expected_prefix"),
    (
        (True, ["conditions", "lowering", "switch-exit", "selector-return", "fingerprint"]),
        (False, ["fingerprint"]),
    ),
)
def test_structuring_pass_validation_closes_only_reported_ast_mutations(
    monkeypatch,
    pass_changed,
    expected_prefix,
):
    events: list[str] = []
    project = SimpleNamespace(_inertia_tail_validation_enabled=True)
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x4010))

    monkeypatch.setattr(
        stage,
        "_prime_structuring_validation_semantics_8616",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        stage,
        "_ensure_structuring_typed_conditions_transferred_8616",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        stage,
        "_replay_structuring_lowering_before_validation_8616",
        lambda *_args: events.append("lowering") or False,
    )
    monkeypatch.setattr(
        stage,
        "_refresh_structuring_condition_semantics_8616",
        lambda *_args: events.append("conditions")
        or stage._condition_refresh.StructuringConditionRefreshResult8616.unclosed(),
    )
    monkeypatch.setattr(
        stage,
        "_repair_structuring_switch_loop_exit_returns_8616",
        lambda *_args: events.append("switch-exit") or False,
    )
    monkeypatch.setattr(
        stage,
        "_materialize_structuring_selector_return_branches_8616",
        lambda *_args: events.append("selector-return") or False,
    )
    monkeypatch.setattr(
        stage,
        "fingerprint_x86_16_tail_validation_boundary",
        lambda *_args, **_kwargs: events.append("fingerprint") or ("fp", len(events)),
    )
    monkeypatch.setattr(
        stage,
        "collect_x86_16_tail_validation_summary",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(
        stage,
        "build_x86_16_tail_validation_cached_result",
        lambda **_kwargs: {"changed": False, "status": "stable"},
    )
    monkeypatch.setattr(
        stage,
        "build_x86_16_tail_validation_verdict",
        lambda *_args: "stable",
    )
    monkeypatch.setattr(
        stage,
        "_try_accept_structuring_validation_delta_from_evidence_8616",
        lambda *_args, **_kwargs: False,
    )

    finalize = stage._maybe_validate_structuring_pass_8616(
        project,
        codegen,
        "_structuring_codegen_8616",
    )
    assert finalize is not None
    events.clear()

    finalize(pass_changed)

    assert events[: len(expected_prefix)] == expected_prefix


def test_structuring_call_return_materialization_accepts_direct_call_delta_without_condition_change() -> None:
    codegen = SimpleNamespace(
        _inertia_call_return_condition_stats_8616=SimpleNamespace(
            classified_fact_count=4,
            materialized_count=4,
            failure_count=0,
        )
    )
    validation = {
        "delta": {
            "helper_calls": {
                "added": ("addr:0x10040", "addr:0x10040", "addr:0x1006f"),
                "removed": (
                    "missing-callsite:addr:0x10040",
                    "missing-callsite:addr:0x10040",
                    "missing-callsite:addr:0x1006f",
                ),
            },
            "conditions": {"added": (), "removed": ()},
            "control_flow_effects": {
                "added": ("if-else-body-calls:else:addr:0x10040,addr:0x1006f",),
                "removed": (),
            },
        }
    }

    assert stage._is_structuring_call_chain_materialization_delta_8616(codegen, validation) is True


def test_structuring_call_return_materialization_accepts_missing_callsite_delta():
    codegen = SimpleNamespace(
        _inertia_call_return_condition_stats_8616=SimpleNamespace(
            classified_fact_count=2,
            materialized_count=2,
            failure_count=0,
        )
    )
    validation = {
        "delta": {
            "helper_calls": {
                "added": ("addr:0x10010", "addr:0x10010"),
                "removed": ("missing-callsite:addr:0x10010", "missing-callsite:addr:0x10010"),
            },
            "conditions": {
                "added": (
                    "CmpNE(call:addr:0x10010(arg_a),const:0)",
                    "CmpNE(call:addr:0x10010(arg_b),const:0)",
                ),
                "removed": ("CmpNE(const:1,const:0)",),
            },
            "control_flow_effects": {
                "added": ("for-body-calls:loop:addr:0x10010", "if:call:addr:0x10010"),
                "removed": ("for-body-calls:loop:addr:0x106d6", "if:CmpNE(const:1,const:0)"),
            },
        }
    }

    assert stage._is_structuring_call_chain_materialization_delta_8616(codegen, validation) is True

    codegen._inertia_call_return_condition_stats_8616 = SimpleNamespace(
        classified_fact_count=2,
        materialized_count=1,
        failure_count=1,
    )
    assert stage._is_structuring_call_chain_materialization_delta_8616(codegen, validation) is False


def test_structuring_call_return_store_bridge_accepts_exact_register_alias_projection() -> None:
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()),
        _inertia_call_return_condition_stats_8616=SimpleNamespace(
            classified_fact_count=1,
            materialized_count=1,
            failure_count=0,
            store_bridge_materialized_count=1,
            store_bridge_return_registers=("ax",),
        ),
    )
    validation = {
        "delta": {
            "register_writes": {"added": (), "removed": ("reg:eax",)},
        }
    }

    assert stage._is_structuring_call_chain_materialization_delta_8616(codegen, validation) is True

    validation["delta"]["register_writes"]["removed"] = ("reg:bx",)
    assert stage._is_structuring_call_chain_materialization_delta_8616(codegen, validation) is False


def test_structuring_validation_accepts_evidenced_direct_stack_update_delta():
    project = SimpleNamespace(kb=SimpleNamespace(functions=None))
    previous_delta = {"stage": "earlier"}
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4010),
        _inertia_direct_stack_update_lowering_8616={"materialized_count": 1},
        _inertia_direct_stack_update_evidence_8616=((("offset", -4),),),
        _inertia_structuring_direct_stack_update_validation_deltas_8616=(previous_delta,),
    )
    validation = {
        "changed": True,
        "status": "changed",
        "mode": "live_out",
        "delta": {
            "stack_writes": {
                "added": ("stack_slot:SS:BP-0x4:size2",),
                "removed": (),
            },
            "control_flow_effects": {
                "added": ("for-body-writes:cmp:stack_slot:SS:BP-0x4:size2",),
                "removed": (),
            },
        },
    }

    accepted = stage._try_accept_structuring_validation_delta_from_evidence_8616(
        project,
        codegen,
        validation,
        spec_name="final",
    )

    assert accepted is True
    assert validation["changed"] is False
    assert validation["status"] == "stable"
    assert "delta" not in validation
    assert codegen._inertia_structuring_direct_stack_update_validation_accepts_8616 == 1
    records = codegen._inertia_structuring_direct_stack_update_validation_deltas_8616
    assert len(records) == 2 and records[0] is previous_delta
    assert records[1]["stage"] == "structuring:final"


def test_structuring_validation_accepts_exact_loop_header_duplicate_guard_removal():
    project = SimpleNamespace(kb=SimpleNamespace(functions=None))
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4010),
        _inertia_loop_header_duplicate_guard_removal_facts_8616=(
            LoopHeaderDuplicateGuardRemovalFact8616(
                jcc_addr=0x101D,
                block_addr=0x1013,
                removed_guard_fingerprint=(
                    "CmpEQ(stack_slot:SS:BP-0x4:size2,const:0)"
                ),
                retained_loop_fingerprint=(
                    "CmpNE(stack_slot:SS:BP-0x4:size2,const:0)"
                ),
            ),
        ),
    )
    validation = {
        "changed": True,
        "status": "changed",
        "mode": "live_out",
        "delta": {
            "control_flow_effects": {
                "added": (),
                "removed": (
                    "ifbreak:CmpEQ(stack_slot:SS:BP-0x4:size2,const:0)",
                ),
            },
        },
    }

    accepted = stage._try_accept_structuring_validation_delta_from_evidence_8616(
        project,
        codegen,
        validation,
        spec_name="_unconsumed_loop_break_jcc_materialization_8616",
    )

    assert accepted is True
    assert validation["changed"] is False
    assert validation["status"] == "stable"
    assert "delta" not in validation
    assert (
        codegen._inertia_structuring_loop_header_duplicate_guard_validation_accepts_8616
        == 1
    )


def test_structuring_validation_restricts_loop_guard_removal_to_owning_pass():
    project = SimpleNamespace(kb=SimpleNamespace(functions=None))
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4010),
        _inertia_loop_header_duplicate_guard_removal_facts_8616=(
            LoopHeaderDuplicateGuardRemovalFact8616(
                jcc_addr=0x101D,
                block_addr=0x1013,
                removed_guard_fingerprint=(
                    "CmpEQ(stack_slot:SS:BP-0x4:size2,const:0)"
                ),
                retained_loop_fingerprint=(
                    "CmpNE(stack_slot:SS:BP-0x4:size2,const:0)"
                ),
            ),
        ),
    )
    validation = {
        "changed": True,
        "status": "changed",
        "mode": "live_out",
        "delta": {
            "control_flow_effects": {
                "added": (),
                "removed": (
                    "ifbreak:CmpEQ(stack_slot:SS:BP-0x4:size2,const:0)",
                ),
            },
        },
    }

    accepted = stage._try_accept_structuring_validation_delta_from_evidence_8616(
        project,
        codegen,
        validation,
        spec_name="_structuring_codegen_8616",
    )

    assert accepted is False
    assert validation["changed"] is True
    assert "delta" in validation


def test_structuring_validation_accepts_proven_loop_exit_return_to_break_delta():
    project = SimpleNamespace(kb=SimpleNamespace(functions=None))
    condition = "CmpGT(call:addr:0x1137e(),stack_slot:SS:BP-0x4:size4)"
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4010),
        _inertia_loop_exit_guard_stats_8616={"repaired": 1},
    )
    validation = {
        "changed": True,
        "status": "changed",
        "mode": "live_out",
        "delta": {
            "returns": {"added": (), "removed": ("none",)},
            "control_flow_effects": {
                "added": (f"ifbreak:{condition}",),
                "removed": (f"if:{condition}",),
            },
        },
    }

    accepted = stage._try_accept_structuring_validation_delta_from_evidence_8616(
        project,
        codegen,
        validation,
        spec_name="_loop_exit_return_guard_repair_8616",
    )

    assert accepted is True
    assert validation["changed"] is False
    assert validation["status"] == "stable"
    assert "delta" not in validation
    assert codegen._inertia_structuring_loop_exit_return_guard_validation_accepts_8616 == 1


def test_structuring_validation_accepts_live_empty_return_fingerprint():
    validation = {
        "changed": True,
        "delta": {
            "returns": {"added": (), "removed": ("return",)},
            "control_flow_effects": {
                "added": ("ifbreak:CmpGT(call:clock())",),
                "removed": ("if:CmpGT(call:clock())", "return"),
            },
        },
    }

    assert loop_exit_return_guard_repair_delta_8616(1, validation)


def test_structuring_validation_refuses_loop_exit_return_delta_with_condition_change():
    project = SimpleNamespace(kb=SimpleNamespace(functions=None))
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4010),
        _inertia_loop_exit_guard_stats_8616={"repaired": 1},
    )
    validation = {
        "changed": True,
        "status": "changed",
        "mode": "live_out",
        "delta": {
            "returns": {"added": (), "removed": ("none",)},
            "control_flow_effects": {
                "added": ("ifbreak:CmpGT(call:addr:0x1137e(),stack_slot:SS:BP-0x4:size4)",),
                "removed": ("if:CmpGT(call:addr:0x1137e(),stack_slot:SS:BP-0x5:size4)",),
            },
        },
    }

    accepted = stage._try_accept_structuring_validation_delta_from_evidence_8616(
        project,
        codegen,
        validation,
        spec_name="_loop_exit_return_guard_repair_8616",
    )

    assert accepted is False
    assert validation["changed"] is True
    assert "delta" in validation


def test_structuring_validation_accepts_evidenced_stack_move_out_of_loop_delta():
    project = SimpleNamespace(kb=SimpleNamespace(functions=None))
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4010),
        _inertia_direct_stack_move_lowering_8616={"materialized_count": 2},
        _inertia_direct_stack_move_evidence_8616=(
            (
                ("dst_offset", -2),
                ("width", 2),
                ("source_kind", DirectStackMoveSourceKind8616.IMMEDIATE),
                ("source_value", 0),
                ("ins_addr", 0x100B),
            ),
        ),
    )
    before_loop = (
        "while-body-writes:const:True:global:0xbaa,global:0xbab,reg:ax,"
        "stack_slot:SS:BP-0x4:size2"
    )
    after_loop = (
        "while-body-writes:const:True:global:0xbaa,global:0xbab,reg:ax,"
        "stack_slot:SS:BP-0x2:size2,"
        "stack_slot:SS:BP-0x4:size2"
    )
    validation = {
        "changed": True,
        "status": "changed",
        "mode": "live_out",
        "delta": {
            "stack_writes": {
                "added": ("stack_slot:SS:BP-0x2:size2",),
                "removed": (),
            },
            "control_flow_effects": {
                "added": (after_loop,),
                "removed": (before_loop,),
            },
        },
    }

    accepted = stage._try_accept_structuring_validation_delta_from_evidence_8616(
        project,
        codegen,
        validation,
        spec_name="final",
    )

    assert accepted is True
    assert validation["changed"] is False
    assert validation["status"] == "stable"
    assert "delta" not in validation
    assert codegen._inertia_structuring_direct_stack_move_validation_accepts_8616 == 1


def test_structuring_validation_accepts_evidenced_indexed_global_precision_delta():
    project = SimpleNamespace(kb=SimpleNamespace(functions=None))
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4010),
        _inertia_indexed_global_materialization_record_8616=IndexedSegmentedGlobalMaterializationRecord8616(
            evidence=(IndexedSegmentedGlobalEvidence8616(0x132, "clPause", 0, 2),),
            materialized_count=1,
        ),
    )
    before_effect = "while-body-writes:const:True:ds_global:0x132,ds_global:0x134"
    after_effect = (
        "while-body-writes:const:True:ds_global:0x132,ds_global:0x133,ds_global:0x134"
    )
    validation = {
        "changed": True,
        "status": "changed",
        "mode": "live_out",
        "delta": {
            "global_writes": {"added": ("ds_global:0x133",), "removed": ()},
            "control_flow_effects": {"added": (after_effect,), "removed": (before_effect,)},
        },
    }

    accepted = stage._try_accept_structuring_validation_delta_from_evidence_8616(
        project,
        codegen,
        validation,
        spec_name="final",
    )

    assert accepted is True
    assert validation["changed"] is False
    assert validation["status"] == "stable"
    assert "delta" not in validation
    assert codegen._inertia_structuring_indexed_global_validation_accepts_8616 == 1


def test_structuring_validation_accepts_evidenced_indexed_read_carrier_delta():
    project = SimpleNamespace(kb=SimpleNamespace(functions=None))
    load_site = IndexedSegmentedGlobalLoadSiteEvidence8616(
        base_offset=0xB4C,
        width=1,
        index_stack_offset=6,
        index_shift=1,
        ins_addr=0x1030,
        destination_register="ax",
        index_stack_width=2,
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4010),
        _inertia_indexed_global_read_carrier_record_8616=(
            IndexedGlobalReadCarrierMaterializationRecord8616(
                evidence=(load_site,),
                raw_fact_count=1,
                normalized_fact_count=1,
                classified_fact_count=1,
                materialized_count=1,
                failure_count=0,
            )
        ),
    )
    before_condition = (
        "CmpGT(Dereference(Add(Mul(reg:ds,const:16),"
        "Shl(stack_slot:SS:BP+0x4:size2,const:1),const:2892)),reg:ax)"
    )
    after_condition = (
        "CmpGT(Dereference(Add(Mul(reg:ds,const:16),"
        "Shl(stack_slot:SS:BP+0x4:size2,const:1),const:2892)),"
        "Dereference(Add(Mul(reg:ds,const:16),"
        "Shl(stack_slot:SS:BP+0x6:size2,const:1),const:2892)))"
    )
    validation = {
        "changed": True,
        "status": "changed",
        "mode": "live_out",
        "delta": {
            "register_writes": {"added": (), "removed": ("reg:ax",)},
            "conditions": {"added": (after_condition,), "removed": (before_condition,)},
            "control_flow_effects": {
                "added": (
                    "dowhile-body-writes:const:True:global:0xbaa",
                    f"if-body-calls:{after_condition}:addr:0x10794",
                    f"if:{after_condition}",
                ),
                "removed": (
                    "dowhile-body-writes:const:True:global:0xbaa,reg:ax",
                    f"if-body-calls:{before_condition}:addr:0x10794",
                    f"if:{before_condition}",
                ),
            },
        },
    }

    accepted = stage._try_accept_structuring_validation_delta_from_evidence_8616(
        project,
        codegen,
        validation,
        spec_name="final",
    )

    assert accepted is True
    assert validation["changed"] is False
    assert validation["status"] == "stable"
    assert "delta" not in validation
    assert codegen._inertia_structuring_indexed_global_read_validation_accepts_8616 == 1


def test_structuring_validation_refuses_unmatched_indexed_read_carrier_delta():
    project = SimpleNamespace(kb=SimpleNamespace(functions=None))
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4010),
        _inertia_indexed_global_read_carrier_record_8616=(
            IndexedGlobalReadCarrierMaterializationRecord8616(
                evidence=(
                    IndexedSegmentedGlobalLoadSiteEvidence8616(
                        base_offset=0xB4C,
                        width=1,
                        index_stack_offset=6,
                        index_shift=1,
                        ins_addr=0x1030,
                        destination_register="bx",
                        index_stack_width=2,
                    ),
                ),
                raw_fact_count=1,
                normalized_fact_count=1,
                classified_fact_count=1,
                materialized_count=1,
                failure_count=0,
            )
        ),
    )
    validation = {
        "changed": True,
        "status": "changed",
        "mode": "live_out",
        "delta": {
            "register_writes": {"added": (), "removed": ("reg:ax",)},
            "conditions": {"added": ("CmpGT(global:0xb4c,const:0)",), "removed": ("CmpGT(reg:ax,const:0)",)},
            "control_flow_effects": {
                "added": ("if:CmpGT(global:0xb4c,const:0)",),
                "removed": ("if:CmpGT(reg:ax,const:0)",),
            },
        },
    }

    accepted = stage._try_accept_structuring_validation_delta_from_evidence_8616(
        project,
        codegen,
        validation,
        spec_name="final",
    )

    assert accepted is False
    assert validation["changed"] is True
    assert validation["status"] == "changed"
    assert "delta" in validation


def test_structuring_validation_accepts_evidenced_dword_zero_test_precision_delta():
    project = SimpleNamespace(kb=SimpleNamespace(functions=None))
    evidence = DwordGlobalZeroTestEvidence8616(0x132, 0x132, 0x134, "ax")
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4010),
        _inertia_dword_global_zero_test_materialization_record_8616=(
            DwordGlobalZeroTestMaterializationRecord8616(
                evidence=(evidence,),
                raw_fact_count=1,
                normalized_fact_count=1,
                classified_fact_count=1,
                materialized_count=1,
                failure_count=0,
            )
        ),
    )
    before_condition = "CmpNE(Or(ds_global:0x134,ds_global:0x132),const:0)"
    after_condition = "CmpNE(ds_global:0x132,const:0)"
    validation = {
        "changed": True,
        "status": "changed",
        "mode": "live_out",
        "delta": {
            "conditions": {
                "added": (after_condition,),
                "removed": (before_condition,),
            },
            "control_flow_effects": {
                "added": (
                    f"if:{after_condition}",
                    f"if-body-calls:{after_condition}:addr:0x128e4,addr:0x12756",
                ),
                "removed": (
                    f"if:{before_condition}",
                    f"if-body-calls:{before_condition}:addr:0x128e4,addr:0x12756",
                ),
            },
        },
    }

    accepted = stage._try_accept_structuring_validation_delta_from_evidence_8616(
        project,
        codegen,
        validation,
        spec_name="final",
    )

    assert accepted is True
    assert validation["changed"] is False
    assert validation["status"] == "stable"
    assert "delta" not in validation
    assert codegen._inertia_structuring_dword_zero_test_validation_accepts_8616 == 1


def test_structuring_validation_accepts_cfg_proven_void_tail_suffix_diamond_regrouping():
    project = SimpleNamespace(kb=SimpleNamespace(functions=None))
    previous_delta = {"stage": "earlier"}
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4010),
        _inertia_void_tail_call_guard_materialized_8616=1,
        _inertia_structuring_void_tail_call_guard_validation_deltas_8616=(previous_delta,),
        _inertia_void_tail_call_guard_decision_8616=_VoidTailCallGuardDecision8616.MATERIALIZE_SUFFIX_DIAMOND.value,
    )
    validation = {
        "changed": True,
        "status": "changed",
        "mode": "live_out",
        "delta": {
            "control_flow_effects": {
                "added": (
                    "if-body-calls:CmpNE(global:0xb46,const:0):addr:0x10e70,addr:0x10f38",
                    "if-else-body-calls:else:addr:0x10f38",
                ),
                "removed": (
                    "if-body-calls:CmpNE(global:0xb46,const:0):addr:0x10e70",
                    "if-else-body-calls:else:addr:0x10f38,addr:0x10f38",
                ),
            },
        },
    }

    accepted = stage._try_accept_structuring_validation_delta_from_evidence_8616(
        project,
        codegen,
        validation,
        spec_name="_void_tail_call_guard_repair_8616",
    )

    assert accepted is True
    assert validation["changed"] is False
    assert validation["status"] == "stable"
    assert "delta" not in validation
    assert codegen._inertia_structuring_void_tail_call_guard_validation_accepts_8616 == 1
    records = codegen._inertia_structuring_void_tail_call_guard_validation_deltas_8616
    assert len(records) == 2 and records[0] is previous_delta
    assert records[1]["stage"] == "structuring:_void_tail_call_guard_repair_8616"


def test_structuring_validation_refuses_void_tail_suffix_diamond_call_loss():
    project = SimpleNamespace(kb=SimpleNamespace(functions=None))
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4010),
        _inertia_void_tail_call_guard_materialized_8616=1,
        _inertia_void_tail_call_guard_decision_8616=_VoidTailCallGuardDecision8616.MATERIALIZE_SUFFIX_DIAMOND.value,
    )
    validation = {
        "changed": True,
        "status": "changed",
        "mode": "live_out",
        "delta": {
            "control_flow_effects": {
                "added": ("if-body-calls:CmpNE(global:0xb46,const:0):addr:0x10e70",),
                "removed": (
                    "if-body-calls:CmpNE(global:0xb46,const:0):addr:0x10e70",
                    "if-else-body-calls:else:addr:0x10f38",
                ),
            },
        },
    }

    accepted = stage._try_accept_structuring_validation_delta_from_evidence_8616(
        project,
        codegen,
        validation,
        spec_name="_void_tail_call_guard_repair_8616",
    )

    assert accepted is False
    assert validation["changed"] is True
