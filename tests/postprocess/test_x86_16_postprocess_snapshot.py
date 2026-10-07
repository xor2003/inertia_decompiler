from __future__ import annotations

from types import SimpleNamespace

import inertia.postprocess.decompiler_postprocess_stage as post_stage
from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeFunction, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.postprocess.decompiler_postprocess_stage import (
    _canonical_cod_global_name_8616,
    _classify_postprocess_validation_delta_8616,
    _clear_proven_destructive_rejection_8616,
    _clear_proven_rejected_pass_restore_8616,
    _cod_global_name_refs_by_address_8616,
    _codegen_instruction_window_addrs_8616,
    _direct_stack_move_validation_delta_kind_8616,
    _has_recovered_source_calls_in_codegen_8616,
    _is_callsite_stack_argument_materialization_delta_8616,
    _is_cfg_mask_accumulator_materialization_delta_8616,
    _is_direct_global_update_materialization_delta_8616,
    _is_direct_stack_move_idiv_remainder_materialization_delta_8616,
    _is_direct_stack_move_materialization_delta_8616,
    _is_direct_stack_update_materialization_delta_8616,
    _is_global_byte_sum_loop_materialization_delta_8616,
    _is_jcc_call_return_condition_rebinding_delta_8616,
    _is_jcc_condition_materialization_validation_delta_8616,
    _is_segmented_global_symbol_materialization_delta_8616,
    _is_stack_prototype_width_reconciliation_delta_8616,
    _mark_destructive_postprocess_validation_failure_8616,
    _postprocess_restored_step_matches_baseline_8616,
    _postprocess_run_bootstrap_steps_8616,
    _postprocess_run_optimization_step_8616,
    _postprocess_validation_blocking_reasons_8616,
    _PostprocessValidationBlockingReason8616,
    _PostprocessValidationDeltaKind8616,
    _record_postprocess_validation_blocking_reason_8616,
    _record_unchanged_postprocess_validation_skip_8616,
    _restore_codegen_inertia_metadata_8616,
    _snapshot_codegen_cfunc,
    _snapshot_codegen_inertia_metadata_8616,
    _try_accept_failed_postprocess_validation_8616,
)
from inertia.lowering.real_mode_linear import DirectStackMoveSourceKind8616

from inertia.frontend.x86_16.cod_extract import CODGlobalRef
from inertia.postprocess.pass_validation_policy import (
    LOCAL_PROOF_REQUIRED_POSTPROCESS_PASS_NAMES_8616,
    MANDATORY_VALIDATION_PASS_NAMES_8616,
    PASS_LOCAL_REJECT_CONTINUE_PASS_NAMES_8616,
)


class _FakeCodegen:
    def __init__(self, cfunc):
        self.cfunc = cfunc


class _FakeCFunc:
    addr = 0x1000

    def __init__(self, statements):
        self.statements = statements
        self.body = statements


class _SlottedFunction:
    __slots__ = ()


def test_codegen_instruction_window_addresses_follow_explicit_rebase_delta() -> None:
    insns = tuple(SimpleNamespace(address=addr) for addr in (0x107B8, 0x107BA, 0x107BD))

    rebased = _codegen_instruction_window_addrs_8616(
        SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000)), insns, 1, 3
    )
    identity = _codegen_instruction_window_addrs_8616(
        SimpleNamespace(cfunc=SimpleNamespace(addr=0x107B8)), insns, 1, 3
    )

    assert rebased == frozenset({0x1002, 0x1005})
    assert identity == frozenset({0x107BA, 0x107BD})


def test_authoritative_signature_marker_does_not_mutate_angr_function() -> None:
    slotted_function = _SlottedFunction()
    codegen = SimpleNamespace(
        _func=slotted_function,
        function=slotted_function,
        cfunc=SimpleNamespace(addr=0x1000, function=slotted_function),
    )
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: slotted_function),
        )
    )

    post_stage._mark_codegen_signature_authoritative_8616(project, codegen, "pointer_swap")

    assert codegen._inertia_codegen_signature_authoritative_8616 == "pointer_swap"


def test_bootstrap_runs_direct_stack_mov_and_update_as_separate_validated_steps():
    seen: list[str] = []
    codegen = SimpleNamespace(_inertia_postprocess_validation_failed=False)

    def apply_step(name, _step):
        seen.append(name)
        return True

    assert _postprocess_run_bootstrap_steps_8616(SimpleNamespace(), codegen, set(), apply_step) is True
    assert seen[0] == "_normalize_fact_backed_stack_accesses_8616"
    assert "_materialize_direct_stack_mov_incdec_instructions_bootstrap_8616" not in seen
    assert "_materialize_direct_stack_mov_instructions_8616" in seen
    assert "_materialize_direct_stack_incdec_instructions_8616" in seen
    assert "_materialize_stable_stack_semantics_bootstrap_8616" not in seen


def test_cod_global_name_refs_ignore_listing_text():
    metadata = SimpleNamespace(
        cod_raw_entries=(
            {"offset": 39, "text": "mov\tax,WORD PTR $S100_g_counter"},
            {"offset": 68, "text": "mov\tal,BYTE PTR $S101_g_table[bx]"},
        )
    )
    insns = (
        SimpleNamespace(address=0x1027),
        SimpleNamespace(address=0x1044),
    )

    direct_refs = _cod_global_name_refs_by_address_8616(metadata, insns, indexed=False)
    indexed_refs = _cod_global_name_refs_by_address_8616(metadata, insns, indexed=True)

    assert _canonical_cod_global_name_8616("$S100_g_counter") == "g_counter"
    assert direct_refs == {}
    assert indexed_refs == {}


def test_cod_global_name_refs_require_byte_matched_structured_refs():
    metadata = SimpleNamespace(
        global_refs=(
            CODGlobalRef(
                offset=39,
                name="g_counter",
                relative_disp=0,
                width=2,
                indexed=False,
                instruction_bytes=bytes.fromhex("a10000"),
            ),
            CODGlobalRef(
                offset=68,
                name="g_table",
                relative_disp=0,
                width=1,
                indexed=True,
                instruction_bytes=bytes.fromhex("8a870200"),
            ),
        )
    )
    insns = (
        SimpleNamespace(address=0x1027),
        SimpleNamespace(address=0x1044),
    )
    bytes_by_address = {
        0x1027: bytes.fromhex("a14200"),
        0x1044: bytes.fromhex("8a874400"),
    }

    direct_refs = _cod_global_name_refs_by_address_8616(
        metadata, insns, indexed=False, bytes_by_address=bytes_by_address
    )
    indexed_refs = _cod_global_name_refs_by_address_8616(
        metadata, insns, indexed=True, bytes_by_address=bytes_by_address
    )

    assert direct_refs[0x1027].name == "g_counter"
    assert indexed_refs[0x1044].name == "g_table"


def test_positive_bp_arg_unifier_is_owned_by_lowering_not_postprocess():
    pass_names = {
        "_unify_positive_bp_arg_stack_variables_8616",
        "_unify_positive_bp_arg_stack_variables_final_8616",
    }
    registered_pass_names = {
        spec.name for spec in post_stage.DECOMPILER_POSTPROCESS_PASSES
    }

    assert pass_names.isdisjoint(registered_pass_names)
    assert pass_names.isdisjoint(LOCAL_PROOF_REQUIRED_POSTPROCESS_PASS_NAMES_8616)
    assert pass_names.isdisjoint(MANDATORY_VALIDATION_PASS_NAMES_8616)
    assert pass_names.isdisjoint(PASS_LOCAL_REJECT_CONTINUE_PASS_NAMES_8616)


def test_after_ss_callsite_materialization_disables_consumed_store_prune(monkeypatch):
    observed: list[bool] = []

    def fake_materialize(_project, codegen):
        observed.append(codegen._inertia_callsite_disable_consumed_arg_store_prune_8616)
        return True

    monkeypatch.setattr(post_stage._calls, "_materialize_callsite_stack_arguments_8616", fake_materialize)
    codegen = SimpleNamespace(_inertia_call_target_identity_consumer_8616=lambda _project, _codegen: False)

    assert post_stage._materialize_callsite_stack_arguments_after_ss_lowering_8616(SimpleNamespace(), codegen) is True
    assert observed == [True]
    assert codegen._inertia_callsite_disable_consumed_arg_store_prune_8616 is False
    assert codegen._inertia_callsite_disable_stack_probe_setup_prune_8616 is False


def test_after_ss_callsite_dce_is_validated_and_locally_rejectable():
    pass_name = "_dead_code_elimination_after_ss_callsite_stack_arguments_8616"

    assert pass_name in LOCAL_PROOF_REQUIRED_POSTPROCESS_PASS_NAMES_8616
    assert pass_name in MANDATORY_VALIDATION_PASS_NAMES_8616
    assert pass_name in PASS_LOCAL_REJECT_CONTINUE_PASS_NAMES_8616


def test_pre_validation_callsite_prime_materializes_arguments_before_baseline(monkeypatch):
    calls: list[str] = []
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000),
        _inertia_call_target_identity_consumer_8616=lambda _project, _codegen: False,
    )

    monkeypatch.setattr(post_stage._calls, "_attach_callsite_summaries_8616", lambda *_args: calls.append("attach") or True)
    monkeypatch.setattr(
        post_stage._calls,
        "_materialize_callsite_stack_arguments_8616",
        lambda *_args: calls.append("materialize") or True,
    )
    monkeypatch.setattr(
        post_stage,
        "_invalidate_tail_validation_derived_caches_8616",
        lambda _codegen: calls.append("invalidate"),
    )
    assert post_stage._prime_callsite_summaries_before_validation_baseline_8616(SimpleNamespace(), codegen) is True
    assert codegen._inertia_pre_validation_callsite_summaries_primed is True
    assert calls == ["attach", "materialize", "invalidate"]


def test_pre_validation_typed_condition_prime_runs_before_baseline(monkeypatch):
    calls: list[str] = []
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000))

    monkeypatch.setattr(
        post_stage,
        "transfer_typed_conditions_to_codegen_8616",
        lambda *_args: calls.append("transfer") or 1,
    )
    monkeypatch.setattr(
        post_stage,
        "_apply_typed_conditions_to_codegen_8616",
        lambda *_args: calls.append("conditions") or True,
    )
    monkeypatch.setattr(
        post_stage,
        "apply_condition_argument_types_8616",
        lambda *_args: calls.append("types")
        or SimpleNamespace(changed=True, stats=SimpleNamespace(normalized_fact_count=1)),
    )
    monkeypatch.setattr(
        post_stage,
        "_apply_typed_condition_stack_arg_signedness_8616",
        lambda *_args: calls.append("legacy-signedness") or True,
    )
    monkeypatch.setattr(
        post_stage,
        "reconcile_callsite_interface_declarations_8616",
        lambda *_args: calls.append("interface") or True,
    )
    monkeypatch.setattr(
        post_stage._jcc,
        "_rewrite_decoded_jcc_conditions_8616",
        lambda *_args: calls.append("jcc") or True,
    )
    monkeypatch.setattr(
        post_stage,
        "_invalidate_tail_validation_derived_caches_8616",
        lambda _codegen: calls.append("invalidate"),
    )

    assert post_stage._prime_typed_conditions_before_validation_baseline_8616(SimpleNamespace(), codegen) is True
    assert codegen._inertia_pre_validation_typed_conditions_primed is True
    assert codegen._inertia_typed_conditions_transferred is True
    assert calls == [
        "transfer",
        "conditions",
        "jcc",
        "types",
        "interface",
        "invalidate",
    ]


def test_optimization_runner_applies_validation_step_per_subpass(monkeypatch):
    seen: list[str] = []
    codegen = SimpleNamespace(cfunc=object(), _inertia_postprocess_validation_failed=False)
    specs = (
        SimpleNamespace(name="const_like", func=lambda _codegen: True),
        SimpleNamespace(name="stable_like", func=lambda _codegen: False),
    )

    monkeypatch.setattr(post_stage, "OPTIMIZATION_PASSES", specs)
    monkeypatch.setattr(post_stage, "_postprocess_optimization_enabled_8616", lambda: True)
    monkeypatch.setattr(
        post_stage,
        "_normalize_cfunc_root_for_optimization_8616",
        lambda _codegen: seen.append("normalize"),
    )

    def apply_step(name, step):
        seen.append(name)
        step()
        return True

    assert _postprocess_run_optimization_step_8616(SimpleNamespace(), codegen, False, apply_step) is True
    assert seen == ["normalize", "optimization:const_like", "optimization:stable_like"]


def test_unchanged_postprocess_pass_skips_validation_summary_collection(monkeypatch):
    baseline_summary = object()
    collected_summaries: list[object] = []
    compared_summaries: list[tuple[object, object]] = []
    regenerated_contexts: list[str] = []
    project = SimpleNamespace()
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1234,
            functy=SimTypeFunction([], SimTypeShort(False)),
            statements=SimpleNamespace(),
        ),
        project=project,
        _inertia_postprocess_validation_failed=False,
    )
    pass_specs = (
        post_stage.DecompilerPostprocessPassSpec("stable_pass", lambda _project, _codegen: False, True),
        post_stage.DecompilerPostprocessPassSpec("changed_pass", lambda _project, _codegen: True, True),
    )
    cycle_scans: list[object] = []

    monkeypatch.setattr(
        post_stage,
        "_c_ast_cycle_path_8616",
        lambda root: cycle_scans.append(root) or (),
    )
    monkeypatch.setattr(post_stage, "_decompiler_postprocess_passes_for_function", lambda _project, _codegen: pass_specs)
    monkeypatch.setattr(
        post_stage,
        "_postprocess_runtime_config_8616",
        lambda _project, _codegen, _pass_specs: (None, True, True, set(), baseline_summary),
    )
    monkeypatch.setattr(post_stage, "_postprocess_run_bootstrap_steps_8616", lambda *_args: True)

    def run_stable_optimization(_project, _codegen, _per_pass_validation_enabled, apply_step):
        return apply_step("optimization:const_prop", lambda: False)

    monkeypatch.setattr(post_stage, "_postprocess_run_optimization_step_8616", run_stable_optimization)
    monkeypatch.setattr(post_stage, "_repair_cfunc_statements_wrapper", lambda _codegen: None)
    monkeypatch.setattr(post_stage, "_snapshot_codegen_cfunc", lambda _codegen: object())
    monkeypatch.setattr(post_stage, "_snapshot_codegen_inertia_metadata_8616", lambda _codegen: {})
    monkeypatch.setattr(post_stage, "_snapshot_codegen_text_state_8616", lambda _codegen: {})
    monkeypatch.setattr(post_stage, "_snapshot_project_function_metadata_8616", lambda *_args: {})
    monkeypatch.setattr(post_stage, "_return_chain_expected_counts_8616", lambda _codegen: None)
    monkeypatch.setattr(post_stage, "_invalidate_tail_validation_derived_caches_8616", lambda _codegen: None)
    monkeypatch.setattr(post_stage, "_debug_condition_progress_8616", lambda *_args, **_kwargs: None)

    def collect_summary(_project, _codegen, *, mode):
        collected = object()
        collected_summaries.append(collected)
        assert mode == "live_out"
        return collected

    def compare_summary(before, after):
        compared_summaries.append((before, after))
        return {"changed": False, "status": "stable"}

    def regenerate(_codegen, *, context):
        regenerated_contexts.append(context)
        return True

    monkeypatch.setattr(post_stage, "collect_x86_16_tail_validation_summary", collect_summary)
    monkeypatch.setattr(post_stage, "compare_x86_16_tail_validation_summaries", compare_summary)
    monkeypatch.setattr(post_stage, "x86_16_tail_validation_result_passed", lambda _validation: True)
    monkeypatch.setattr(post_stage, "_regenerate_text_safely", regenerate)
    monkeypatch.setattr(post_stage, "_dump_postprocess_trace_text_8616", lambda *_args, **_kwargs: None)

    assert post_stage._postprocess_codegen_8616(project, codegen) is True

    assert codegen._inertia_postprocess_unchanged_validation_skipped_passes_8616 == (
        "optimization:const_prop",
        "stable_pass",
    )
    assert codegen._inertia_postprocess_unchanged_validation_skip_count_8616 == 2
    assert len(collected_summaries) == 1
    assert compared_summaries == [(baseline_summary, collected_summaries[0])]
    assert any("changed_pass:validation" in context for context in regenerated_contexts)
    assert len(cycle_scans) == 4


def test_records_unchanged_postprocess_validation_skip():
    codegen = SimpleNamespace()

    _record_unchanged_postprocess_validation_skip_8616(codegen, "stable_pass")
    _record_unchanged_postprocess_validation_skip_8616(codegen, "other_stable_pass")

    assert codegen._inertia_postprocess_unchanged_validation_skipped_passes_8616 == (
        "stable_pass",
        "other_stable_pass",
    )
    assert codegen._inertia_postprocess_unchanged_validation_skip_count_8616 == 2


def test_regeneration_replays_stack_aggregate_types_before_render(monkeypatch) -> None:
    calls: list[str] = []
    cfunc = SimpleNamespace(addr=0x1234)
    codegen = SimpleNamespace(
        cfunc=cfunc,
        project=SimpleNamespace(arch=Arch86_16()),
        _inertia_postprocess_regeneration_disabled=False,
        _inertia_last_postprocess_pass=None,
    )

    monkeypatch.setattr(
        post_stage,
        "_repair_missing_cnode_codegen_metadata_8616",
        lambda *_args: calls.append("repair_metadata"),
    )
    monkeypatch.setattr(
        post_stage,
        "repair_cfunctioncall_render_targets_8616",
        lambda *_args: calls.append("repair_calls"),
    )
    monkeypatch.setattr(
        post_stage,
        "_normalize_stack_variable_identifiers_8616",
        lambda *_args: calls.append("normalize_stack"),
    )
    monkeypatch.setattr(
        post_stage,
        "reapply_stack_aggregate_object_facts_8616",
        lambda *_args: calls.append("replay_aggregate") or True,
    )
    monkeypatch.setattr(
        post_stage,
        "reapply_stack_variable_projection_names_8616",
        lambda *_args: calls.append("replay_stack_names") or True,
    )
    monkeypatch.setattr(
        post_stage,
        "_bind_codegen_variable_types_to_arch_8616",
        lambda *_args: calls.append("bind_types"),
    )

    def render_text(_cfunc):
        calls.append("render")
        return "void sub_1234(void) {\n}\n"

    codegen.render_text = render_text

    assert post_stage._regenerate_text_safely(codegen, context="test:final") is True
    assert calls == [
        "repair_metadata",
        "repair_calls",
        "normalize_stack",
        "replay_aggregate",
        "replay_stack_names",
        "bind_types",
        "render",
    ]


def test_destructive_postprocess_failure_forces_changed_snapshot():
    project = SimpleNamespace()
    codegen = SimpleNamespace()
    validation = {"changed": False, "status": "stable", "summary_text": "no observable whole-tail changes"}
    function_info: dict[str, object] = {}

    _mark_destructive_postprocess_validation_failure_8616(
        project,
        codegen,
        validation,
        pass_name="_materialize_direct_stack_mov_instructions_8616",
        summary_text="stack_writes removed BP-0x2",
        function_info=function_info,
    )

    assert validation["changed"] is True
    assert validation["status"] == "changed"
    assert validation["destructive_postprocess_validation_failure"] is True
    assert _postprocess_validation_blocking_reasons_8616(validation) == (
        _PostprocessValidationBlockingReason8616.DESTRUCTIVE_POSTPROCESS_VALIDATION_DELTA,
    )
    assert codegen._inertia_postprocess_validation_failed is True
    assert codegen._inertia_tail_validation_snapshot["postprocess"]["status"] == "changed"
    assert project._inertia_last_tail_validation_snapshot["postprocess"]["changed"] is True
    assert function_info["x86_16_tail_validation"]["postprocess"]["status"] == "changed"


def test_postprocess_validation_blocking_reasons_are_typed():
    validation: dict[str, object] = {
        "postprocess_validation_blocking_reasons": ("missing_source_evidenced_calls", "unknown")
    }

    _record_postprocess_validation_blocking_reason_8616(
        validation,
        _PostprocessValidationBlockingReason8616.MISSING_SOURCE_EVIDENCED_CALLS,
    )
    _record_postprocess_validation_blocking_reason_8616(
        validation,
        _PostprocessValidationBlockingReason8616.SOURCE_EVIDENCED_CALL_ORDER_MISMATCH,
    )

    assert _postprocess_validation_blocking_reasons_8616(validation) == (
        _PostprocessValidationBlockingReason8616.MISSING_SOURCE_EVIDENCED_CALLS,
        _PostprocessValidationBlockingReason8616.SOURCE_EVIDENCED_CALL_ORDER_MISMATCH,
    )


def test_restored_destructive_step_identity_proof_accepts_clean_baseline(monkeypatch):
    project = SimpleNamespace()
    codegen = SimpleNamespace()
    baseline = object()
    restored = object()
    calls: list[str] = []

    monkeypatch.setattr(
        post_stage,
        "_invalidate_tail_validation_derived_caches_8616",
        lambda _codegen: calls.append("invalidate"),
    )
    monkeypatch.setattr(
        post_stage,
        "collect_x86_16_tail_validation_summary",
        lambda got_project, got_codegen, *, mode: restored
        if got_project is project and got_codegen is codegen and mode == "live_out"
        else None,
    )
    monkeypatch.setattr(
        post_stage,
        "compare_x86_16_tail_validation_summaries",
        lambda before, after: {"changed": before is not baseline or after is not restored},
    )

    assert _postprocess_restored_step_matches_baseline_8616(project, codegen, baseline) is True
    assert calls == ["invalidate"]


def test_restored_destructive_step_identity_proof_accepts_exact_restored_snapshot(monkeypatch):
    project = SimpleNamespace()
    restored = object()
    codegen = SimpleNamespace(cfunc=restored)

    monkeypatch.setattr(
        post_stage,
        "collect_x86_16_tail_validation_summary",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("summary should not be collected")),
    )

    assert (
        _postprocess_restored_step_matches_baseline_8616(
            project,
            codegen,
            object(),
            restored_cfunc_snapshot=restored,
        )
        is True
    )
    assert codegen._inertia_postprocess_restored_snapshot_identity_proven_8616 == 1


def test_restored_destructive_step_identity_proof_refuses_changed_baseline(monkeypatch):
    project = SimpleNamespace()
    codegen = SimpleNamespace()
    baseline = object()

    monkeypatch.setattr(post_stage, "_invalidate_tail_validation_derived_caches_8616", lambda _codegen: None)
    monkeypatch.setattr(
        post_stage,
        "collect_x86_16_tail_validation_summary",
        lambda _project, _codegen, *, mode: object(),
    )
    monkeypatch.setattr(
        post_stage,
        "compare_x86_16_tail_validation_summaries",
        lambda _before, _after: {"changed": True, "status": "changed"},
    )

    assert _postprocess_restored_step_matches_baseline_8616(project, codegen, baseline) is False


def test_proven_destructive_rejection_clears_only_transient_failure_state() -> None:
    codegen = SimpleNamespace(
        _inertia_postprocess_validation_failed=True,
        _inertia_postprocess_validation_failure_pass="_dead_code_elimination_final_cleanup_8616",
        _inertia_postprocess_validation_failure_error="changed",
        _inertia_postprocess_rejected_passes=("_dead_code_elimination_final_cleanup_8616",),
    )

    _clear_proven_destructive_rejection_8616(codegen)
    _clear_proven_destructive_rejection_8616(codegen)

    assert codegen._inertia_postprocess_validation_failed is False
    assert codegen._inertia_postprocess_validation_failure_pass is None
    assert codegen._inertia_postprocess_validation_failure_error is None
    assert codegen._inertia_postprocess_destructive_rejected_restore_proven_8616 == 2
    assert codegen._inertia_postprocess_rejected_restore_proven_8616 == 2
    assert codegen._inertia_postprocess_rejected_passes == ("_dead_code_elimination_final_cleanup_8616",)


def test_proven_nondestructive_rejection_clears_failure_without_destructive_marker() -> None:
    codegen = SimpleNamespace(
        _inertia_postprocess_validation_failed=True,
        _inertia_postprocess_validation_failure_pass="_dead_code_elimination_final_cleanup_8616",
        _inertia_postprocess_validation_failure_error="changed",
    )

    _clear_proven_rejected_pass_restore_8616(codegen)

    assert codegen._inertia_postprocess_validation_failed is False
    assert codegen._inertia_postprocess_validation_failure_pass is None
    assert codegen._inertia_postprocess_validation_failure_error is None
    assert codegen._inertia_postprocess_rejected_restore_proven_8616 == 1
    assert not hasattr(codegen, "_inertia_postprocess_destructive_rejected_restore_proven_8616")


def test_discard_cleanup_salvage_runs_virtual_cleanup_when_dce_is_stable(monkeypatch):
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000, statements=[]))
    stage = SimpleNamespace(project=SimpleNamespace(), codegen=codegen)
    calls: list[str] = []

    monkeypatch.setattr(post_stage, "_snapshot_codegen_cfunc", lambda _codegen: SimpleNamespace())
    monkeypatch.setattr(post_stage, "_snapshot_codegen_inertia_metadata_8616", lambda _codegen: {})
    monkeypatch.setattr(post_stage, "fingerprint_x86_16_tail_validation_boundary", lambda *_args, **_kwargs: "fp")
    monkeypatch.setattr(
        post_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        lambda *_args, **_kwargs: {"stack_writes": []},
    )
    monkeypatch.setattr(post_stage, "_dead_code_elimination_8616", lambda _codegen: False)
    monkeypatch.setattr(
        post_stage._simplify,
        "_inline_single_assignment_virtual_expressions_8616",
        lambda _codegen: calls.append("virtual-cleanup") or True,
    )
    monkeypatch.setattr(
        post_stage,
        "normalize_multi_statement_braces_8616",
        lambda _codegen: calls.append("braces") or True,
    )
    monkeypatch.setattr(
        post_stage,
        "apply_affine_compound_assignment_identity_8616",
        lambda _codegen: calls.append("affine") or True,
    )
    monkeypatch.setattr(post_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: calls.append("regenerate"))
    monkeypatch.setattr(
        post_stage,
        "build_x86_16_tail_validation_cached_result",
        lambda **_kwargs: {"changed": False, "status": "stable"},
    )
    monkeypatch.setattr(post_stage, "build_x86_16_tail_validation_verdict", lambda *_args: "stable")
    monkeypatch.setattr(post_stage, "persist_x86_16_tail_validation_snapshot", lambda **_kwargs: calls.append("persist"))
    log = SimpleNamespace(warning=lambda *_args, **_kwargs: None, debug=lambda *_args, **_kwargs: None)

    changed = post_stage._salvage_dce_after_discard_8616(
        stage,
        validation_mode="live_out",
        snapshot_function_info={},
        log=log,
    )

    assert changed is True
    assert calls == ["virtual-cleanup", "braces", "affine", "regenerate", "persist"]
    assert codegen._inertia_dce_salvaged_after_discard_8616 is True


def test_destructive_discard_runs_evidenced_salvage_and_stable_dce_before_identity_proof(monkeypatch):
    project = SimpleNamespace()
    restored_cfunc = SimpleNamespace(addr=0x1000, statements=[])
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000, statements=[]))
    codegen._inertia_structuring_validation_failed = False
    stage = SimpleNamespace(project=project, codegen=codegen)
    calls: list[str] = []

    def forbidden_unsafe_salvage(*_args, **_kwargs):
        raise AssertionError("destructive rollback must not run unsafe post-restore salvage")

    def stable_dce_salvage(*_args, **_kwargs):
        calls.append("dce")
        return True

    monkeypatch.setattr(post_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: calls.append("regenerate"))
    monkeypatch.setattr(post_stage, "_invalidate_tail_validation_derived_caches_8616", lambda _codegen: None)
    monkeypatch.setattr(
        post_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        lambda *_args, **_kwargs: {"stack_writes": ["changed"]},
    )
    monkeypatch.setattr(
        post_stage,
        "compare_x86_16_tail_validation_summaries",
        lambda _before, _after: {"changed": True, "status": "changed", "delta": {"stack_writes": {"removed": ["x"]}}},
    )
    monkeypatch.setattr(post_stage, "build_x86_16_tail_validation_verdict", lambda _stage, validation: validation["summary_text"])
    monkeypatch.setattr(post_stage, "persist_x86_16_tail_validation_snapshot", lambda **_kwargs: None)
    monkeypatch.setattr(post_stage, "_salvage_direct_stack_update_after_discard_8616", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(post_stage, "_salvage_direct_global_update_after_discard_8616", forbidden_unsafe_salvage)
    monkeypatch.setattr(post_stage, "_salvage_signed_idiv_stack_move_after_discard_8616", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(post_stage, "_salvage_direct_stack_move_after_discard_8616", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(post_stage, "_salvage_segmented_global_materialization_after_discard_8616", forbidden_unsafe_salvage)
    monkeypatch.setattr(post_stage, "_salvage_flag_cleanup_after_discard_8616", forbidden_unsafe_salvage)
    monkeypatch.setattr(post_stage, "_salvage_dce_after_discard_8616", stable_dce_salvage)

    post_stage._discard_failed_postprocess_result_8616(
        stage,
        validation={
            "verdict": "changed",
            "delta": {"stack_writes": {"removed": ["stack_slot:SS:BP-0x2:size2"]}},
        },
        validation_verdict_text="changed",
        validation_mode="live_out",
        snapshot_function_info={},
        before_fingerprint="before",
        before_summary={"stack_writes": ["baseline"]},
        pre_postprocess_cfunc_snapshot=restored_cfunc,
        pre_postprocess_metadata_snapshot={"_inertia_structuring_validation_failed": False},
        validation_timings={},
        function=SimpleNamespace(addr=0x1000),
        log=SimpleNamespace(warning=lambda *_args, **_kwargs: None, info=lambda *_args, **_kwargs: None),
    )

    assert codegen.cfunc is restored_cfunc
    assert not getattr(codegen, "_inertia_postprocess_final_c_identity_proven_8616", False)
    assert calls == ["regenerate", "dce"]


def test_destructive_callsite_discard_skips_unrelated_direct_stack_salvage(monkeypatch):
    project = SimpleNamespace()
    restored_cfunc = SimpleNamespace(addr=0x1000, statements=[])
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, statements=[]),
        _inertia_structuring_validation_failed=False,
        _inertia_postprocess_validation_failure_pass="_materialize_callsite_stack_arguments_8616",
    )
    stage = SimpleNamespace(project=project, codegen=codegen)
    calls: list[str] = []

    monkeypatch.setattr(post_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: calls.append("regenerate"))
    monkeypatch.setattr(post_stage, "_invalidate_tail_validation_derived_caches_8616", lambda _codegen: None)
    monkeypatch.setattr(
        post_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        lambda *_args, **_kwargs: {"stack_writes": ["changed"]},
    )
    monkeypatch.setattr(
        post_stage,
        "compare_x86_16_tail_validation_summaries",
        lambda _before, _after: {"changed": True, "status": "changed", "delta": {"stack_writes": {"removed": ["x"]}}},
    )
    monkeypatch.setattr(post_stage, "build_x86_16_tail_validation_verdict", lambda _stage, validation: validation["summary_text"])
    monkeypatch.setattr(post_stage, "persist_x86_16_tail_validation_snapshot", lambda **_kwargs: None)
    monkeypatch.setattr(
        post_stage,
        "_salvage_direct_stack_update_after_discard_8616",
        lambda *_args, **_kwargs: calls.append("stack-update"),
    )
    monkeypatch.setattr(
        post_stage,
        "_salvage_signed_idiv_stack_move_after_discard_8616",
        lambda *_args, **_kwargs: calls.append("signed-idiv"),
    )
    monkeypatch.setattr(
        post_stage,
        "_salvage_direct_stack_move_after_discard_8616",
        lambda *_args, **_kwargs: calls.append("stack-move"),
    )
    monkeypatch.setattr(post_stage, "_salvage_dce_after_discard_8616", lambda *_args, **_kwargs: calls.append("dce"))

    post_stage._discard_failed_postprocess_result_8616(
        stage,
        validation={
            "verdict": "changed",
            "delta": {"stack_writes": {"removed": ["stack_slot:SS:BP-0x2:size2"]}},
        },
        validation_verdict_text="changed",
        validation_mode="live_out",
        snapshot_function_info={},
        before_fingerprint="before",
        before_summary={"stack_writes": ["baseline"]},
        pre_postprocess_cfunc_snapshot=restored_cfunc,
        pre_postprocess_metadata_snapshot={
            "_inertia_structuring_validation_failed": False,
            "_inertia_postprocess_validation_failure_pass": "_materialize_callsite_stack_arguments_8616",
        },
        validation_timings={},
        function=SimpleNamespace(addr=0x1000),
        log=SimpleNamespace(warning=lambda *_args, **_kwargs: None, info=lambda *_args, **_kwargs: None),
    )

    assert codegen.cfunc is restored_cfunc
    assert calls == ["regenerate", "dce"]


def test_failed_structuring_skips_all_postprocess_salvage_after_discard(monkeypatch):
    project = SimpleNamespace()
    restored_cfunc = SimpleNamespace(addr=0x1000, statements=[])
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, statements=[]),
        _inertia_structuring_validation_failed=True,
    )
    stage = SimpleNamespace(project=project, codegen=codegen)
    calls: list[str] = []

    def forbidden_salvage(*_args, **_kwargs):
        raise AssertionError("postprocess cannot salvage a failed Structuring baseline")

    monkeypatch.setattr(post_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: calls.append("regenerate"))
    monkeypatch.setattr(post_stage, "_invalidate_tail_validation_derived_caches_8616", lambda _codegen: None)
    monkeypatch.setattr(
        post_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        lambda *_args, **_kwargs: {"stack_writes": ["baseline"]},
    )
    monkeypatch.setattr(
        post_stage,
        "compare_x86_16_tail_validation_summaries",
        lambda _before, _after: {"changed": False, "status": "stable"},
    )
    monkeypatch.setattr(post_stage, "build_x86_16_tail_validation_verdict", lambda _stage, _validation: "stable")
    monkeypatch.setattr(post_stage, "persist_x86_16_tail_validation_snapshot", lambda **_kwargs: None)
    for name in (
        "_salvage_direct_stack_update_after_discard_8616",
        "_salvage_direct_global_update_after_discard_8616",
        "_salvage_signed_idiv_stack_move_after_discard_8616",
        "_salvage_direct_stack_move_after_discard_8616",
        "_salvage_segmented_global_materialization_after_discard_8616",
        "_salvage_callsite_stack_args_after_discard_8616",
        "_salvage_flag_cleanup_after_discard_8616",
        "_salvage_dce_after_discard_8616",
    ):
        monkeypatch.setattr(post_stage, name, forbidden_salvage)

    post_stage._discard_failed_postprocess_result_8616(
        stage,
        validation={"verdict": "changed", "delta": {}},
        validation_verdict_text="changed",
        validation_mode="live_out",
        snapshot_function_info={},
        before_fingerprint="before",
        before_summary={"stack_writes": ["baseline"]},
        pre_postprocess_cfunc_snapshot=restored_cfunc,
        pre_postprocess_metadata_snapshot={"_inertia_structuring_validation_failed": True},
        validation_timings={},
        function=SimpleNamespace(addr=0x1000),
        log=SimpleNamespace(warning=lambda *_args, **_kwargs: None, info=lambda *_args, **_kwargs: None),
    )

    assert codegen.cfunc is restored_cfunc
    assert calls == ["regenerate"]
    assert codegen._inertia_postprocess_discarded is True


def test_generic_return_artifact_detects_unified_vvar_dereference():
    codegen = _CodegenWithIndexes()
    word_type = SimTypeShort(False)
    vvar_base = SimRegisterVariable(0, 2, name=None)
    vvar_base_unified = SimRegisterVariable(0, 2, name="vvar_59")
    vvar_base_expr = CVariable(vvar_base, unified_variable=vvar_base_unified, variable_type=word_type, codegen=codegen)
    deref = CUnaryOp("Dereference", vvar_base_expr, codegen=codegen)
    expr = CBinaryOp("Sub", CConstant(1, word_type, codegen=codegen), deref, codegen=codegen)

    assert post_stage._return_expr_has_generic_register_artifact_8616(expr) is True


def test_untyped_dereference_return_artifact_refuses_pointer_typed_operand():
    codegen = _CodegenWithIndexes()
    word_type = SimTypeShort(False)
    temp = CVariable(SimRegisterVariable(1, 2, name="tmp_1"), variable_type=word_type, codegen=codegen)
    pointer_arg = CVariable(
        SimStackVariable(4, 2, base="bp", name="p"),
        variable_type=SimTypePointer(word_type),
        codegen=codegen,
    )

    assert (
        post_stage._return_expr_has_untyped_dereference_artifact_8616(CUnaryOp("Dereference", temp, codegen=codegen))
        is True
    )
    assert (
        post_stage._return_expr_has_untyped_dereference_artifact_8616(
            CUnaryOp("Dereference", pointer_arg, codegen=codegen)
        )
        is False
    )


def test_pointer_cast_dirty_dereference_return_artifact_is_not_pointer_proof():
    codegen = _CodegenWithIndexes()
    word_type = SimTypeShort(False)
    dirty_pointer_carrier = CTypeCast(
        None,
        SimTypePointer(word_type),
        CDirtyExpression("vvar_59 + vvar_60", codegen=codegen),
        codegen=codegen,
    )

    assert (
        post_stage._return_expr_has_untyped_dereference_artifact_8616(
            CUnaryOp("Dereference", dirty_pointer_carrier, codegen=codegen)
        )
        is True
    )


def test_dirty_carrier_return_artifact_detects_unlowered_expression():
    codegen = _CodegenWithIndexes()
    word_type = SimTypeShort(False)
    expr = CBinaryOp(
        "Mul",
        CVariable(SimStackVariable(4, 2, base="bp", name="a"), variable_type=word_type, codegen=codegen),
        CDirtyExpression("vvar_60 | vvar_61 * 0x100", codegen=codegen),
        codegen=codegen,
    )

    assert post_stage._return_expr_has_dirty_carrier_artifact_8616(expr) is True


class _SlotCFunc:
    __slots__ = ("addr", "arg_list", "body", "codegen", "statements")

    def __init__(self, statements, arg_list):
        self.addr = 0x1000
        self.statements = statements
        self.body = statements
        self.arg_list = arg_list
        self.codegen = None


class _UncopyableStatements:
    def __deepcopy__(self, memo):
        raise TypeError("not independently copyable")


class _UncopyableCodegen:
    project = object()

    def __deepcopy__(self, memo):
        raise ValueError("ctypes objects containing pointers cannot be pickled")


class _StatementNodeWithCodegen:
    def __init__(self, codegen):
        self.codegen = codegen
        self.values = [1]


class _CtypesLikeMetadata:
    def __reduce_ex__(self, protocol):
        raise ValueError("ctypes objects containing pointers cannot be pickled")


class _DeepcopyPoisonMetadata:
    def __deepcopy__(self, memo):
        raise AssertionError("metadata snapshot should not deep-copy arbitrary objects")


class _StatementNodeWithCtypesMetadata:
    def __init__(self, metadata):
        self.metadata = metadata
        self.values = [1]


class _FakeFunctions:
    def __init__(self, names_by_addr):
        self._names_by_addr = dict(names_by_addr)

    def function(self, addr, create=False):
        del create
        name = self._names_by_addr.get(addr)
        return SimpleNamespace(name=name) if name is not None else None


def _fake_project_with_functions(names_by_addr):
    return SimpleNamespace(kb=SimpleNamespace(functions=_FakeFunctions(names_by_addr)))


class _CodegenWithIndexes:
    def __init__(self):
        self._idx = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=Arch86_16())

    def next_idx(self, _name):
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _jcc_condition_materialization_validation(*, helper="addr:0x11222", global_token="global:0xbab"):
    return {
        "before": {
            "helper_calls": (),
            "global_writes": ("global:0xbaa",),
        },
        "after": {
            "helper_calls": (helper,),
            "global_writes": ("global:0xbaa", global_token),
        },
        "delta": {
            "helper_calls": {
                "added": (helper,),
                "removed": (),
            },
            "global_writes": {
                "added": (global_token,),
                "removed": (),
            },
        },
    }


def _callsite_materialization_codegen():
    return SimpleNamespace(_inertia_callsite_materialization_stats=SimpleNamespace(call_arg_materialized_count=2))


def _callsite_global_precision_validation(*, global_token="global:0xbab"):
    return {
        "before": {
            "global_writes": ("global:0xbaa",),
        },
        "after": {
            "global_writes": ("global:0xbaa", global_token),
        },
        "delta": {
            "global_writes": {
                "added": (global_token,),
                "removed": (),
            },
        },
    }


def _direct_global_update_codegen(*, displacement: int = 0x135, width: int = 1):
    codegen = _FakeCodegen(_FakeCFunc([]))
    codegen._inertia_direct_global_update_lowering_8616 = {
        "raw_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 1,
        "failure_count": 0,
    }
    codegen._inertia_direct_global_update_evidence_8616 = (
        (
            ("displacement", displacement),
            ("width", width),
            ("delta", 1),
            ("ins_addr", 0x10420),
            ("name", "c"),
        ),
    )
    return codegen


def _segmented_global_symbol_codegen(*, spans: tuple[tuple[int, int], ...]):
    codegen = _FakeCodegen(_FakeCFunc([]))
    codegen._inertia_segmented_global_load_stats_8616 = SimpleNamespace(
        direct_symbol_materialized_count=1,
        direct_symbol_store_materialized_count=1,
    )
    codegen._inertia_direct_global_symbol_store_spans_8616 = spans
    return codegen


def test_direct_global_update_materialization_delta_accepts_evidenced_ds_write_precision():
    validation = {
        "delta": {
            "segmented_writes": {
                "added": ("deref:Add(Mul(reg:ds,const:16),const:309)",),
                "removed": ("deref:Add(Add(Mul(reg:ds,const:16),const:308),const:1)",),
            },
        }
    }

    assert _is_direct_global_update_materialization_delta_8616(_direct_global_update_codegen(), validation) is True


def test_global_byte_sum_loop_materialization_delta_accepts_evidenced_loop_writes():
    codegen = SimpleNamespace(
        _inertia_global_byte_sum_loop_stats_8616={"materialized_count": 1},
        _inertia_global_byte_sum_loop_evidence_8616={"index_disp": -4, "total_disp": -2, "limit": 4},
    )
    validation = {
        "delta": {
            "helper_calls": {"added": (), "removed": ()},
            "register_writes": {"added": (), "removed": ()},
            "stack_writes": {"added": ("stack_slot:SS:BP-0x4:size2",), "removed": ()},
            "global_writes": {"added": (), "removed": ()},
            "segmented_writes": {"added": (), "removed": ()},
            "returns": {"added": (), "removed": ()},
            "conditions": {"added": (), "removed": ()},
            "control_flow_effects": {
                "added": (
                    "for-body-writes:CmpLT(stack_slot:SS:BP-0x4:size2,const:4):"
                    "stack_slot:SS:BP-0x2:size2",
                ),
                "removed": (),
            },
        }
    }

    assert _is_global_byte_sum_loop_materialization_delta_8616(codegen, validation) is True


def test_global_byte_sum_loop_materialization_delta_refuses_unrelated_stack_write():
    codegen = SimpleNamespace(
        _inertia_global_byte_sum_loop_stats_8616={"materialized_count": 1},
        _inertia_global_byte_sum_loop_evidence_8616={"index_disp": -4, "total_disp": -2, "limit": 4},
    )
    validation = {
        "delta": {
            "stack_writes": {"added": ("stack_slot:SS:BP-0x6:size2",), "removed": ()},
            "control_flow_effects": {
                "added": (
                    "for-body-writes:CmpLT(stack_slot:SS:BP-0x4:size2,const:4):"
                    "stack_slot:SS:BP-0x2:size2",
                ),
                "removed": (),
            },
        }
    }

    assert _is_global_byte_sum_loop_materialization_delta_8616(codegen, validation) is False


def test_direct_global_update_materialization_delta_accepts_word_high_byte_write():
    validation = {
        "delta": {
            "global_writes": {
                "added": ("global:0xbab",),
                "removed": ("global:0xbaa",),
            },
        }
    }

    assert (
        _is_direct_global_update_materialization_delta_8616(
            _direct_global_update_codegen(displacement=0xBAA, width=2),
            validation,
        )
        is True
    )


def test_direct_global_update_materialization_delta_accepts_word_high_byte_loop_fingerprint():
    validation = {
        "delta": {
            "global_writes": {
                "added": (),
                "removed": ("global:0xbab",),
            },
            "control_flow_effects": {
                "added": ("while-body-writes:const:True:global:0xbaa",),
                "removed": ("while-body-writes:const:True:global:0xbaa,global:0xbab",),
            },
        }
    }

    assert (
        _is_direct_global_update_materialization_delta_8616(
            _direct_global_update_codegen(displacement=0xBAA, width=2),
            validation,
        )
        is True
    )


def test_direct_global_update_materialization_delta_accepts_evidence_covered_loop_write_repair():
    codegen = _direct_global_update_codegen(displacement=0xBAA, width=2)
    codegen._inertia_direct_global_update_evidence_8616 = (
        (
            ("displacement", 0xBAA),
            ("width", 2),
            ("delta", 1),
            ("ins_addr", 0x104A),
            ("name", "iCompares"),
        ),
        (
            ("displacement", 0xBA4),
            ("width", 2),
            ("delta", 1),
            ("ins_addr", 0x1060),
            ("name", "iSwaps"),
        ),
    )
    validation = {
        "delta": {
            "global_writes": {
                "added": ("global:0xbaa",),
                "removed": ("global:0xba5",),
            },
            "control_flow_effects": {
                "added": (
                    "for-body-writes:CmpNE(stack_slot:SS:BP-0x4:size2,const:0):"
                    "global:0xba4,global:0xbaa",
                ),
                "removed": (
                    "for-body-writes:CmpNE(stack_slot:SS:BP-0x4:size2,const:0):"
                    "global:0xba4,global:0xba5",
                ),
            },
        }
    }

    assert _is_direct_global_update_materialization_delta_8616(codegen, validation) is True


def test_segmented_global_symbol_materialization_delta_accepts_word_high_byte_loop_fingerprint():
    validation = {
        "delta": {
            "global_writes": {
                "added": (),
                "removed": ("global:0xbab", "global:0xbad"),
            },
            "control_flow_effects": {
                "added": ("while-body-writes:const:True:global:0xbaa,global:0xbac",),
                "removed": (
                    "while-body-writes:const:True:global:0xbaa,global:0xbab,global:0xbac,global:0xbad",
                ),
            },
        }
    }

    assert (
        _is_segmented_global_symbol_materialization_delta_8616(
            None,
            _segmented_global_symbol_codegen(spans=((0xBAA, 2), (0xBAC, 2))),
            validation,
        )
        is True
    )


def test_segmented_global_symbol_materialization_delta_refuses_byte_neighbor_write():
    validation = {
        "delta": {
            "global_writes": {
                "added": (),
                "removed": ("global:0xbab",),
            },
        }
    }

    assert (
        _is_segmented_global_symbol_materialization_delta_8616(
            None,
            _segmented_global_symbol_codegen(spans=((0xBAA, 1),)),
            validation,
        )
        is False
    )


def test_direct_global_update_materialization_delta_refuses_loop_fingerprint_stack_drift():
    validation = {
        "delta": {
            "global_writes": {
                "added": (),
                "removed": ("global:0xbab",),
            },
            "control_flow_effects": {
                "added": ("while-body-writes:const:True:global:0xbaa",),
                "removed": (
                    "while-body-writes:const:True:global:0xbaa,global:0xbab,stack_slot:SS:BP-0x2:size2",
                ),
            },
        }
    }

    assert (
        _is_direct_global_update_materialization_delta_8616(
            _direct_global_update_codegen(displacement=0xBAA, width=2),
            validation,
        )
        is False
    )


def test_direct_global_update_materialization_delta_refuses_byte_neighbor_write():
    validation = {
        "delta": {
            "global_writes": {
                "added": ("global:0xbab",),
                "removed": (),
            },
        }
    }

    assert (
        _is_direct_global_update_materialization_delta_8616(
            _direct_global_update_codegen(displacement=0xBAA, width=1),
            validation,
        )
        is False
    )


def test_direct_global_update_materialization_delta_refuses_condition_change():
    validation = {
        "delta": {
            "segmented_writes": {
                "added": ("deref:Add(Mul(reg:ds,const:16),const:309)",),
                "removed": ("deref:Add(Add(Mul(reg:ds,const:16),const:308),const:1)",),
            },
            "conditions": {
                "added": ("CmpEQ(global:0x135,const:0)",),
                "removed": (),
            },
        }
    }

    assert _is_direct_global_update_materialization_delta_8616(_direct_global_update_codegen(), validation) is False


def test_direct_global_update_materialization_delta_accepts_evidenced_return_precision():
    validation = {
        "delta": {
            "returns": {
                "added": ("Or(Dereference(Add(Mul(Reference(CIndexedVariable),const:16),const:309)),const:0)",),
                "removed": ("Or(Dereference(Add(Mul(reg:ds,const:16),const:309)),const:0)",),
            },
        }
    }

    assert _is_direct_global_update_materialization_delta_8616(_direct_global_update_codegen(), validation) is True


def test_direct_global_update_materialization_delta_refuses_unrelated_return_constant():
    validation = {
        "delta": {
            "returns": {
                "added": ("Or(Dereference(Add(Mul(reg:ds,const:16),const:57005)),const:0)",),
                "removed": (),
            },
        }
    }

    assert _is_direct_global_update_materialization_delta_8616(_direct_global_update_codegen(), validation) is False


def test_direct_global_update_materialization_delta_refuses_unrelated_address():
    validation = {
        "delta": {
            "global_writes": {
                "added": ("global:0x222",),
                "removed": (),
            },
        }
    }

    assert _is_direct_global_update_materialization_delta_8616(_direct_global_update_codegen(), validation) is False


def test_postprocess_snapshot_uses_manual_fallback_for_uncopyable_statement_container():
    cfunc = _FakeCFunc(_UncopyableStatements())

    snapshot = _snapshot_codegen_cfunc(_FakeCodegen(cfunc))

    assert snapshot is not None
    assert snapshot.statements is not cfunc.statements
    assert snapshot._inertia_validation_snapshot_fallback == "manual"


def test_postprocess_snapshot_does_not_share_statement_tree():
    cfunc = _FakeCFunc([{"value": [1]}])

    snapshot = _snapshot_codegen_cfunc(_FakeCodegen(cfunc))
    cfunc.statements[0]["value"].append(2)

    assert snapshot is not None
    assert snapshot.statements == [{"value": [1]}]


def test_postprocess_snapshot_body_uses_cloned_statement_root():
    cfunc = _FakeCFunc([{"value": [1]}])

    snapshot = _snapshot_codegen_cfunc(_FakeCodegen(cfunc))
    cfunc.body[0]["value"].append(2)

    assert snapshot is not None
    assert snapshot.body is snapshot.statements
    assert snapshot.body == [{"value": [1]}]


def test_postprocess_snapshot_clones_slot_backed_arg_list():
    cfunc = _SlotCFunc([{"stmt": [1]}], [{"arg": [10]}])

    snapshot = _snapshot_codegen_cfunc(_FakeCodegen(cfunc))
    cfunc.arg_list[0]["arg"].append(11)
    cfunc.statements[0]["stmt"].append(2)

    assert snapshot is not None
    assert snapshot.arg_list == [{"arg": [10]}]
    assert snapshot.statements == [{"stmt": [1]}]
    assert snapshot.body is snapshot.statements


def test_postprocess_snapshot_preserves_live_codegen_backpointer_identity():
    live_codegen = _UncopyableCodegen()
    cfunc = _FakeCFunc([_StatementNodeWithCodegen(live_codegen)])
    cfunc.codegen = live_codegen

    snapshot = _snapshot_codegen_cfunc(_FakeCodegen(cfunc))
    cfunc.statements[0].values.append(2)

    assert snapshot is not None
    assert snapshot.statements[0].codegen is live_codegen
    assert snapshot.statements[0].values == [1]


def test_postprocess_snapshot_preserves_ctypes_metadata_identity_but_clones_tree():
    metadata = _CtypesLikeMetadata()
    cfunc = _FakeCFunc([_StatementNodeWithCtypesMetadata(metadata)])

    snapshot = _snapshot_codegen_cfunc(_FakeCodegen(cfunc))
    cfunc.statements[0].values.append(2)

    assert snapshot is not None
    assert snapshot.statements[0] is not cfunc.statements[0]
    assert snapshot.statements[0].metadata is metadata
    assert snapshot.statements[0].values == [1]
    assert snapshot._inertia_validation_snapshot_fallback == "ctypes_metadata_identity"


def test_postprocess_validation_delta_classifies_name_only_helper_annotations():
    validation = {
        "delta": {
            "helper_calls": {
                "added": (),
                "removed": ("name:addr:0x1d1c", "name:addr:0x1d91"),
            },
            "returns": {"added": (), "removed": ()},
        }
    }

    assert (
        _classify_postprocess_validation_delta_8616(validation)
        is _PostprocessValidationDeltaKind8616.NAME_ONLY_HELPER_ANNOTATION
    )


def test_postprocess_validation_delta_rejects_raw_helper_and_mixed_semantic_delta():
    assert (
        _classify_postprocess_validation_delta_8616(
            {
                "delta": {
                    "helper_calls": {
                        "added": (),
                        "removed": ("addr:0x1d1c",),
                    }
                }
            }
        )
        is _PostprocessValidationDeltaKind8616.BLOCKING
    )


def test_jcc_call_return_condition_delta_accepts_virtual_carrier_fingerprint_churn():
    codegen = _FakeCodegen(_FakeCFunc([]))
    codegen._inertia_jcc_call_return_register_rebindings = 3
    validation = {
        "delta": {
            "conditions": {
                "added": ("CmpNE(virtual:vvar_42,const:35)",),
                "removed": ("CmpNE(reg:ax,const:35)",),
            },
            "control_flow_effects": {
                "added": ("if:CmpNE(virtual:vvar_42,const:35)",),
                "removed": ("if:CmpNE(reg:ax,const:35)",),
            },
            "segmented_writes": {
                "added": ("deref:Add(Mul(virtual:vvar_1146,const:16),virtual:vvar_1142,const:-2)",),
                "removed": ("deref:Add(Mul(virtual:vvar_11,const:16),virtual:vvar_6,const:-2)",),
            },
        }
    }

    assert _is_jcc_call_return_condition_rebinding_delta_8616(codegen, validation) is True


def test_jcc_call_return_condition_delta_refuses_without_consumed_rebinding_evidence():
    codegen = _FakeCodegen(_FakeCFunc([]))
    validation = {
        "delta": {
            "conditions": {
                "added": ("CmpNE(virtual:vvar_42,const:35)",),
                "removed": ("CmpNE(reg:ax,const:35)",),
            }
        }
    }

    assert _is_jcc_call_return_condition_rebinding_delta_8616(codegen, validation) is False


def test_jcc_condition_materialization_delta_accepts_stack_probe_and_high_byte_precision_churn():
    codegen = _FakeCodegen(_FakeCFunc([]))
    codegen._inertia_semantic_condition_materialized_count = 2
    project = _fake_project_with_functions({0x11222: "aNchkstk"})

    assert (
        _is_jcc_condition_materialization_validation_delta_8616(
            project,
            codegen,
            _jcc_condition_materialization_validation(),
        )
        is True
    )


def test_jcc_condition_materialization_delta_refuses_without_consumed_condition_evidence():
    codegen = _FakeCodegen(_FakeCFunc([]))
    project = _fake_project_with_functions({0x11222: "aNchkstk"})

    assert (
        _is_jcc_condition_materialization_validation_delta_8616(
            project,
            codegen,
            _jcc_condition_materialization_validation(),
        )
        is False
    )


def test_jcc_condition_materialization_delta_accepts_exact_inverted_guard_pair():
    codegen = _FakeCodegen(_FakeCFunc([]))
    project = _fake_project_with_functions({})
    validation = {
        "delta": {
            "conditions": {
                "added": (
                    "CmpEQ(stack_slot:SS:BP-0x2:size2,const:0)",
                    "CmpGT(stack_slot:SS:BP-0x4:size2,stack_slot:SS:BP-0x6:size2)",
                ),
                "removed": (),
            },
            "control_flow_effects": {
                "added": (
                    "ifbreak:CmpEQ(stack_slot:SS:BP-0x2:size2,const:0)",
                    "ifbreak:CmpGT(stack_slot:SS:BP-0x4:size2,stack_slot:SS:BP-0x6:size2)",
                ),
                "removed": (
                    "ifbreak:CmpLE(stack_slot:SS:BP-0x4:size2,stack_slot:SS:BP-0x6:size2)",
                    "ifbreak:CmpNE(stack_slot:SS:BP-0x2:size2,const:0)",
                ),
            },
        },
    }

    assert (
        _is_jcc_condition_materialization_validation_delta_8616(
            project,
            codegen,
            validation,
        )
        is True
    )


def test_jcc_condition_materialization_delta_refuses_non_stack_probe_helper():
    codegen = _FakeCodegen(_FakeCFunc([]))
    codegen._inertia_semantic_condition_materialized_count = 1
    project = _fake_project_with_functions({0x11222: "printf"})

    assert (
        _is_jcc_condition_materialization_validation_delta_8616(
            project,
            codegen,
            _jcc_condition_materialization_validation(),
        )
        is False
    )


def test_jcc_condition_materialization_delta_refuses_unrelated_global_write():
    codegen = _FakeCodegen(_FakeCFunc([]))
    codegen._inertia_semantic_condition_materialized_count = 1
    project = _fake_project_with_functions({0x11222: "aNchkstk"})

    assert (
        _is_jcc_condition_materialization_validation_delta_8616(
            project,
            codegen,
            _jcc_condition_materialization_validation(global_token="global:0xbc0"),
        )
        is False
    )


def test_callsite_materialization_delta_accepts_adjacent_global_precision_churn():
    validation = _callsite_global_precision_validation(global_token="global:0xbab")

    assert (
        _is_callsite_stack_argument_materialization_delta_8616(_callsite_materialization_codegen(), validation) is True
    )


def test_callsite_materialization_delta_refuses_unrelated_global_write():
    validation = _callsite_global_precision_validation(global_token="global:0xbc0")

    assert (
        _is_callsite_stack_argument_materialization_delta_8616(_callsite_materialization_codegen(), validation) is False
    )


def test_callsite_materialization_delta_accepts_stack_arg_slot_alias_conditions():
    codegen = _callsite_materialization_codegen()
    arg_codegen = _CodegenWithIndexes()
    arg_i_low = CVariable(SimStackVariable(4, 2, base="bp", name="iLow"), codegen=arg_codegen)
    arg_i_high = CVariable(SimStackVariable(6, 2, base="bp", name="iHigh"), codegen=arg_codegen)
    codegen.cfunc = _SlotCFunc(CStatements([], codegen=arg_codegen), [arg_i_low, arg_i_high])
    validation = {
        "delta": {
            "conditions": {
                "added": ("CmpLT(stack_arg:iLow:size2,stack_arg:iHigh:size2)",),
                "removed": ("CmpLT(stack_slot:SS:BP+0x4:size2,stack_slot:SS:BP+0x6:size2)",),
            },
            "control_flow_effects": {
                "added": ("if:CmpLT(stack_arg:iLow:size2,stack_arg:iHigh:size2)",),
                "removed": ("if:CmpLT(stack_slot:SS:BP+0x4:size2,stack_slot:SS:BP+0x6:size2)",),
            },
        },
    }

    assert _is_callsite_stack_argument_materialization_delta_8616(codegen, validation) is True
    assert codegen._inertia_callsite_stack_arg_alias_delta_accepts_8616 == 1


def test_callsite_materialization_delta_accepts_stack_arg_size_precision_with_push_evidence():
    codegen = _callsite_materialization_codegen()
    codegen._inertia_callsite_summaries = {
        0x1027: SimpleNamespace(push_arg_sources=(("bp", 6), ("bp", -2))),
    }
    validation = {
        "delta": {
            "returns": {
                "added": ("call:addr:0xfd1(stack_slot:SS:BP-0x2:size2,stack_arg:value:size2)",),
                "removed": ("call:addr:0xfd1(stack_slot:SS:BP-0x2:size2,stack_arg:value:size4)",),
            },
        },
    }

    assert _is_callsite_stack_argument_materialization_delta_8616(codegen, validation) is True
    assert codegen._inertia_callsite_stack_arg_size_precision_delta_accepts_8616 == 1


def test_stack_prototype_width_delta_requires_materialized_push_source_evidence():
    validation = {
        "delta": {
            "returns": {
                "added": ("call:addr:0xfd1(stack_slot:SS:BP-0x2:size2,stack_slot:SS:BP+0x6:size2)",),
                "removed": ("call:addr:0xfd1(stack_slot:SS:BP-0x2:size2,stack_slot:SS:BP+0x6:size4)",),
            },
        },
    }
    codegen = SimpleNamespace(
        _inertia_stack_prototype_width_stats_8616=SimpleNamespace(materialized_count=1),
        _inertia_callsite_summaries={
            0x1027: SimpleNamespace(push_arg_sources=(("bp", 6), ("bp", -2))),
        },
    )

    assert _is_stack_prototype_width_reconciliation_delta_8616(codegen, validation) is True
    assert codegen._inertia_stack_prototype_width_validation_accepts_8616 == 1


def test_callsite_materialization_delta_accepts_mixed_helper_stack_control_delta():
    codegen = _callsite_materialization_codegen()
    codegen._inertia_callsite_summaries = {
        0x100: SimpleNamespace(target_addr=0x1075B),
        0x102: SimpleNamespace(target_addr=0x10CE0),
    }
    codegen._inertia_callsite_pruned_stack_write_tokens_8616 = ("stack_slot:SS:BP-0x2:size2",)
    validation = {
        "delta": {
            "helper_calls": {
                "added": ("addr:0x1075b", "addr:0x10ce0"),
                "removed": ("addr:0x11cd4", "name:<indirect>"),
            },
            "stack_writes": {
                "added": (),
                "removed": ("stack_slot:SS:BP-0x2:size2",),
            },
            "control_flow_effects": {
                "added": (
                    "if-body-calls:CmpGT(stack_slot:SS:BP-0x2:size2,stack_slot:SS:BP-0x6:size2):name:addr:0x1075b",
                ),
                "removed": (
                    "if-body-calls:CmpGT(stack_slot:SS:BP-0x2:size2,stack_slot:SS:BP-0x6:size2):name:<indirect>",
                ),
            },
        }
    }

    assert _is_callsite_stack_argument_materialization_delta_8616(codegen, validation) is True
    assert codegen._inertia_callsite_mixed_helper_stack_control_delta_accepts_8616 == 1


def test_callsite_materialization_delta_refuses_unrecorded_mixed_stack_write_removal():
    codegen = _callsite_materialization_codegen()
    codegen._inertia_callsite_summaries = {
        0x100: SimpleNamespace(target_addr=0x1075B),
    }
    validation = {
        "delta": {
            "helper_calls": {
                "added": ("addr:0x1075b",),
                "removed": ("name:<indirect>",),
            },
            "stack_writes": {
                "added": (),
                "removed": ("stack_slot:SS:BP-0x6:size2",),
            },
            "control_flow_effects": {
                "added": (
                    "if-body-calls:CmpGT(stack_slot:SS:BP-0x2:size2,stack_slot:SS:BP-0x6:size2):name:addr:0x1075b",
                ),
                "removed": (
                    "if-body-calls:CmpGT(stack_slot:SS:BP-0x2:size2,stack_slot:SS:BP-0x6:size2):name:<indirect>",
                ),
            },
        }
    }

    assert _is_callsite_stack_argument_materialization_delta_8616(codegen, validation) is False


def test_callsite_materialization_delta_refuses_mixed_stack_body_write_removal():
    codegen = _callsite_materialization_codegen()
    codegen._inertia_callsite_summaries = {
        0x100: SimpleNamespace(target_addr=0x10768),
        0x102: SimpleNamespace(target_addr=0x10794),
    }
    codegen._inertia_callsite_pruned_stack_write_tokens_8616 = ("stack_slot:SS:BP-0x6:size2",)
    validation = {
        "delta": {
            "helper_calls": {
                "added": ("addr:0x10768", "addr:0x10794"),
                "removed": ("addr:0x10ce0", "addr:0x11cd4"),
            },
            "stack_writes": {
                "added": (),
                "removed": ("stack_slot:SS:BP-0x6:size2",),
            },
            "control_flow_effects": {
                "added": (
                    "dowhile-body-writes:CmpLE(stack_slot:SS:BP-0x2:size2,stack_slot:SS:BP-0x6:size2):"
                    "global:0xbaa,global:0xbab,stack_slot:SS:BP-0x2:size2",
                ),
                "removed": (
                    "dowhile-body-writes:CmpLE(stack_slot:SS:BP-0x2:size2,stack_slot:SS:BP-0x6:size2):"
                    "global:0xbaa,global:0xbab,stack_slot:SS:BP-0x2:size2,stack_slot:SS:BP-0x6:size2",
                ),
            },
        }
    }

    assert _is_callsite_stack_argument_materialization_delta_8616(codegen, validation) is False


def test_callsite_materialization_delta_accepts_mixed_direct_addr_target_correction():
    codegen = _callsite_materialization_codegen()
    codegen._inertia_callsite_summaries = {0x100: SimpleNamespace(target_addr=0x10CE0)}
    codegen._inertia_callsite_pruned_stack_write_tokens_8616 = ("stack_slot:SS:BP-0x2:size2",)
    validation = {
        "delta": {
            "helper_calls": {
                "added": ("addr:0x10ce0", "addr:0x10ce0"),
                "removed": ("addr:0x11cd4", "addr:0x11cd4"),
            },
            "stack_writes": {
                "added": (),
                "removed": ("stack_slot:SS:BP-0x2:size2",),
            },
            "control_flow_effects": {
                "added": (
                    "if-body-calls:CmpLT(stack_slot:SS:BP+0x4:size2,stack_slot:SS:BP+0x6:size2):name:addr:0x10ce0",
                ),
                "removed": (
                    "if-body-calls:CmpLT(stack_slot:SS:BP+0x4:size2,stack_slot:SS:BP+0x6:size2):name:addr:0x11cd4",
                ),
            },
        }
    }

    assert _is_callsite_stack_argument_materialization_delta_8616(codegen, validation) is True


def test_callsite_materialization_delta_accepts_helper_control_target_correction_without_stack_delta():
    codegen = _callsite_materialization_codegen()
    codegen._inertia_callsite_summaries = {
        0x100: SimpleNamespace(target_addr=0x10768),
        0x102: SimpleNamespace(target_addr=0x10794),
    }
    validation = {
        "delta": {
            "helper_calls": {
                "added": ("addr:0x10768", "addr:0x10794"),
                "removed": ("addr:0x11cd4", "addr:0x10ce0"),
            },
            "control_flow_effects": {
                "added": (
                    "if-body-calls:CmpLT(stack_slot:SS:BP+0x4:size2,stack_slot:SS:BP+0x6:size2):"
                    "addr:0x10794,name:addr:0x10768",
                ),
                "removed": (
                    "if-body-calls:CmpLT(stack_slot:SS:BP+0x4:size2,stack_slot:SS:BP+0x6:size2):"
                    "addr:0x10ce0,name:addr:0x11cd4",
                ),
            },
        }
    }

    assert _is_callsite_stack_argument_materialization_delta_8616(codegen, validation) is True
    assert codegen._inertia_callsite_helper_control_target_delta_accepts_8616 == 1


def test_callsite_materialization_delta_refuses_mixed_delta_with_condition_change():
    codegen = _callsite_materialization_codegen()
    validation = {
        "delta": {
            "helper_calls": {"added": ("addr:0x1075b",), "removed": ("name:<indirect>",)},
            "stack_writes": {"added": (), "removed": ("stack_slot:SS:BP-0x2:size2",)},
            "conditions": {"added": ("CmpLT(global:0x1,const:2)",), "removed": ()},
            "control_flow_effects": {
                "added": ("if-body-calls:CmpGT(stack_slot:SS:BP-0x2:size2,const:0):name:addr:0x1075b",),
                "removed": ("if-body-calls:CmpGT(stack_slot:SS:BP-0x2:size2,const:0):name:<indirect>",),
            },
        }
    }

    assert _is_callsite_stack_argument_materialization_delta_8616(codegen, validation) is False


def test_jcc_condition_materialization_accepts_evidenced_stack_write_delta():
    condition = (
        "CmpLE(Dereference(Add(Mul(reg:ds,const:16),Shl(stack_slot:SS:BP-0x4:size2,const:1),const:2890)),"
        "stack_slot:SS:BP-0x6:size2)"
    )
    codegen = SimpleNamespace(
        _inertia_semantic_condition_materialized_count=1,
        _inertia_direct_stack_move_evidence_8616=(
            (("dst_offset", -6), ("width", 2), ("source_kind", DirectStackMoveSourceKind8616.STACK_SLOT)),
        ),
        _inertia_structuring_jcc_condition_validation_deltas_8616=(
            {
                "conditions": {"added": (condition,), "removed": ()},
                "control_flow_effects": {"added": (f"ifbreak:{condition}",), "removed": ()},
            },
        ),
    )
    validation = {
        "delta": {
            "stack_writes": {"added": ("stack_slot:SS:BP-0x6:size2",), "removed": ()},
            "conditions": {"added": (condition,), "removed": ()},
            "control_flow_effects": {
                "added": (
                    "for-body-writes:CmpGT(global:0xbaa,stack_slot:SS:BP-0x2:size2):"
                    "global:0xba4,stack_slot:SS:BP-0x4:size2,stack_slot:SS:BP-0x6:size2",
                    f"ifbreak:{condition}",
                ),
                "removed": (
                    "for-body-writes:CmpGT(global:0xbaa,stack_slot:SS:BP-0x2:size2):"
                    "global:0xba4,stack_slot:SS:BP-0x4:size2",
                ),
            },
        }
    }

    assert _is_jcc_condition_materialization_validation_delta_8616(
        SimpleNamespace(),
        codegen,
        validation,
    )


def test_cfg_mask_accumulator_delta_refuses_removed_materialized_condition():
    condition = "CmpEQ(stack_arg:b:size2,stack_arg:a:size2)"
    codegen = SimpleNamespace(
        _inertia_mask_accumulator_materialized_8616=True,
        _inertia_mask_accumulator_condition_fingerprints_8616=(condition,),
    )
    validation = {
        "delta": {
            "conditions": {"added": (), "removed": (condition,)},
            "control_flow_effects": {"added": (), "removed": (f"if:{condition}",)},
        },
    }

    assert (
        _is_cfg_mask_accumulator_materialization_delta_8616(
            SimpleNamespace(), SimpleNamespace(), codegen, validation
        )
        is False
    )


def test_cfg_mask_accumulator_delta_refuses_unpaired_removed_condition():
    expected_condition = "CmpNE(stack_arg:b:size2,stack_arg:a:size2)"
    removed_condition = "CmpEQ(stack_arg:b:size2,stack_arg:a:size2)"
    codegen = SimpleNamespace(
        _inertia_mask_accumulator_materialized_8616=True,
        _inertia_mask_accumulator_condition_fingerprints_8616=(expected_condition,),
    )
    validation = {
        "delta": {
            "conditions": {"added": (), "removed": (removed_condition,)},
            "control_flow_effects": {"added": (), "removed": (f"if:{removed_condition}",)},
        },
    }

    assert (
        _is_cfg_mask_accumulator_materialization_delta_8616(
            SimpleNamespace(), SimpleNamespace(), codegen, validation
        )
        is False
    )


def test_callsite_materialization_delta_accepts_far_pointer_high_byte_remnant_prune():
    codegen = _callsite_materialization_codegen()
    codegen._inertia_callsite_pre_call_farptr_high_byte_remnants_pruned_8616 = 4
    validation = {
        "delta": {
            "stack_writes": {
                "added": (),
                "removed": ("stack_slot:SS:BP+0x2:size4",),
            },
            "control_flow_effects": {
                "added": ("for-body-writes:cond:deref:Add(global:0x8f0),reg:ax",),
                "removed": (
                    "for-body-writes:cond:deref:Add(global:0x8f0),reg:ax,stack_slot:SS:BP+0x2:size4",
                ),
            },
        },
    }

    assert _is_callsite_stack_argument_materialization_delta_8616(codegen, validation) is True
    assert codegen._inertia_callsite_farptr_high_byte_remnant_delta_accepts_8616 == 1


def test_callsite_materialization_delta_accepts_resolved_indirect_helpers_with_local_stack_precision():
    codegen = _callsite_materialization_codegen()
    validation = {
        "delta": {
            "helper_calls": {
                "added": ("addr:0x1123a", "addr:0x12756"),
                "removed": ("name:<indirect>", "name:<indirect>"),
            },
            "stack_writes": {
                "added": ("stack_slot:SS:BP-0x2:size2",),
                "removed": (),
            },
            "control_flow_effects": {
                "added": ("control_flow_effects:sha256:35fe2b643a18d34e:len:1045",),
                "removed": ("control_flow_effects:sha256:fc4fe433fd0b11d5:len:1018",),
            },
        },
    }

    assert _is_callsite_stack_argument_materialization_delta_8616(codegen, validation) is True
    assert codegen._inertia_callsite_resolved_indirect_helper_stack_delta_accepts_8616 == 1


def test_callsite_materialization_delta_accepts_resolved_helpers_with_outgoing_segmented_write_prune():
    codegen = _callsite_materialization_codegen()
    codegen._inertia_callsite_pre_call_farptr_high_byte_remnants_pruned_8616 = 8
    validation = {
        "delta": {
            "helper_calls": {
                "added": ("addr:0x1123a", "addr:0x128e4"),
                "removed": ("name:<indirect>", "name:<indirect>"),
            },
            "stack_writes": {
                "added": ("stack_slot:SS:BP-0x2:size2",),
                "removed": (),
            },
            "segmented_writes": {
                "added": (),
                "removed": (
                    "deref:Add(Mul(reg:ss,const:16),reg:sp,const:-7)",
                    "deref:Add(Mul(reg:ss,const:16),reg:sp,const:-8)",
                ),
            },
            "control_flow_effects": {
                "added": (
                    "while-body-writes:const:True:"
                    "deref:Add(Mul(reg:ss,const:16),Add(reg:sp,const:-8),const:1),"
                    "deref:Add(Mul(reg:ss,const:16),Add(reg:sp,const:-8)),"
                    "stack_slot:SS:BP-0x2:size2",
                ),
                "removed": ("control_flow_effects:sha256:fc4fe433fd0b11d5:len:1018",),
            },
        },
    }

    assert _is_callsite_stack_argument_materialization_delta_8616(codegen, validation) is True
    assert codegen._inertia_callsite_resolved_indirect_helper_stack_delta_accepts_8616 == 1


def test_callsite_materialization_delta_accepts_resolved_helpers_in_control_flow_calls():
    codegen = _callsite_materialization_codegen()
    validation = {
        "delta": {
            "helper_calls": {
                "added": ("name:addr:0x1123a", "name:addr:0x12756", "name:addr:0x128e4"),
                "removed": ("name:<indirect>", "name:<indirect>", "name:<indirect>"),
            },
            "segmented_writes": {
                "added": (),
                "removed": (
                    "deref:Add(Mul(reg:ss,const:16),reg:sp,const:-7)",
                    "deref:Add(Mul(reg:ss,const:16),reg:sp,const:-8)",
                ),
            },
            "control_flow_effects": {
                "added": (
                    "if-body-calls:CmpEQ(global:0x132,const:900):name:addr:0x128e4,name:addr:0x12756",
                    "if-else-body-calls:else:name:addr:0x1123a",
                ),
                "removed": (
                    "control_flow_effects:sha256:35fe2b643a18d34e:len:1045",
                    "if-body-calls:CmpEQ(global:0x132,const:900):name:<indirect>,name:<indirect>",
                    "if-else-body-calls:else:name:<indirect>",
                ),
            },
        },
    }

    assert _is_callsite_stack_argument_materialization_delta_8616(codegen, validation) is True
    assert codegen._inertia_callsite_resolved_indirect_helper_stack_delta_accepts_8616 == 1


def test_callsite_materialization_delta_refuses_resolved_helper_delta_with_nonlocal_stack_write():
    codegen = _callsite_materialization_codegen()
    validation = {
        "delta": {
            "helper_calls": {
                "added": ("addr:0x1123a",),
                "removed": ("name:<indirect>",),
            },
            "stack_writes": {
                "added": ("stack_slot:SS:BP+0x4:size2",),
                "removed": (),
            },
        },
    }

    assert _is_callsite_stack_argument_materialization_delta_8616(codegen, validation) is False


def test_callsite_materialization_delta_refuses_resolved_helper_delta_with_nonstack_segmented_write():
    codegen = _callsite_materialization_codegen()
    validation = {
        "delta": {
            "helper_calls": {
                "added": ("addr:0x1123a",),
                "removed": ("name:<indirect>",),
            },
            "segmented_writes": {
                "added": (),
                "removed": ("deref:Add(Mul(reg:ds,const:16),reg:sp,const:-8)",),
            },
        },
    }

    assert _is_callsite_stack_argument_materialization_delta_8616(codegen, validation) is False


def test_callsite_materialization_delta_refuses_resolved_helper_delta_without_indirect_source():
    codegen = _callsite_materialization_codegen()
    validation = {
        "delta": {
            "helper_calls": {
                "added": ("addr:0x1123a",),
                "removed": ("name:strcpy",),
            },
            "stack_writes": {
                "added": ("stack_slot:SS:BP-0x2:size2",),
                "removed": (),
            },
        },
    }

    assert _is_callsite_stack_argument_materialization_delta_8616(codegen, validation) is False


def test_direct_stack_move_validation_accepts_proven_callsite_arg_size_precision_delta():
    codegen = _callsite_materialization_codegen()
    codegen._inertia_callsite_summaries = {
        0x1027: SimpleNamespace(push_arg_sources=(("bp", 6), ("bp", -2))),
    }
    validation = {
        "delta": {
            "returns": {
                "added": ("call:addr:0xfd1(stack_slot:SS:BP-0x2:size2,stack_arg:value:size2)",),
                "removed": ("call:addr:0xfd1(stack_slot:SS:BP-0x2:size2,stack_arg:value:size4)",),
            },
        },
    }

    assert (
        _direct_stack_move_validation_delta_kind_8616(codegen, validation)
        is _PostprocessValidationDeltaKind8616.CALLSITE_STACK_ARGUMENT_MATERIALIZATION
    )


def test_final_validation_accepts_proven_callsite_arg_size_precision_delta(monkeypatch):
    codegen = _callsite_materialization_codegen()
    codegen._inertia_callsite_summaries = {
        0x1027: SimpleNamespace(push_arg_sources=(("bp", 6), ("bp", -2))),
    }
    accepted = []
    monkeypatch.setattr(
        post_stage,
        "_postprocess_stable_accept_8616",
        lambda _self, _validation, _snapshot_function_info: accepted.append(True),
    )
    validation = {
        "delta": {
            "returns": {
                "added": ("call:addr:0xfd1(stack_slot:SS:BP-0x2:size2,stack_arg:value:size2)",),
                "removed": ("call:addr:0xfd1(stack_slot:SS:BP-0x2:size2,stack_arg:value:size4)",),
            },
        },
    }
    owner = SimpleNamespace(codegen=codegen, project=SimpleNamespace())

    assert (
        _try_accept_failed_postprocess_validation_8616(
            owner,
            validation=validation,
            validation_verdict_text="changed",
            function=None,
            snapshot_function_info=SimpleNamespace(),
            pre_postprocess_cfunc_snapshot=None,
            func_addr=0x1000,
            log=SimpleNamespace(warning=lambda *args, **kwargs: None),
        )
        is True
    )
    assert accepted == [True]


def test_final_validation_source_call_override_rejects_structured_reason(monkeypatch):
    monkeypatch.setenv("INERTIA_ALLOW_POSTPROCESS_VALIDATION_OVERRIDE", "1")
    accepted = []
    monkeypatch.setattr(
        post_stage,
        "_postprocess_stable_accept_8616",
        lambda _self, _validation, _snapshot_function_info: accepted.append(True),
    )
    validation = {
        "postprocess_validation_blocking_reasons": (
            _PostprocessValidationBlockingReason8616.MISSING_SOURCE_EVIDENCED_CALLS.value,
        )
    }
    owner = SimpleNamespace(
        codegen=SimpleNamespace(_inertia_direct_call_floor_recovered_count=1),
        project=SimpleNamespace(),
    )

    assert (
        _try_accept_failed_postprocess_validation_8616(
            owner,
            validation=validation,
            validation_verdict_text="changed",
            function=None,
            snapshot_function_info=SimpleNamespace(),
            pre_postprocess_cfunc_snapshot=None,
            func_addr=0x1000,
            log=SimpleNamespace(warning=lambda *args, **kwargs: None),
        )
        is False
    )
    assert accepted == []


def test_final_validation_source_call_override_ignores_verdict_text(monkeypatch):
    monkeypatch.setenv("INERTIA_ALLOW_POSTPROCESS_VALIDATION_OVERRIDE", "1")
    monkeypatch.setattr(
        post_stage,
        "_postprocess_stable_accept_8616",
        lambda _self, _validation, _snapshot_function_info: None,
    )
    owner = SimpleNamespace(
        codegen=SimpleNamespace(_inertia_direct_call_floor_recovered_count=1),
        project=SimpleNamespace(),
    )

    assert (
        _try_accept_failed_postprocess_validation_8616(
            owner,
            validation={},
            validation_verdict_text="Missing source-evidenced calls",
            function=None,
            snapshot_function_info=SimpleNamespace(),
            pre_postprocess_cfunc_snapshot=None,
            func_addr=0x1000,
            log=SimpleNamespace(warning=lambda *args, **kwargs: None),
        )
        is False
    )


def test_recovered_source_call_presence_ignores_structured_c_ast(monkeypatch):
    codegen = _CodegenWithIndexes()
    codegen._inertia_direct_call_floor_recovered_count = 1
    call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)
    codegen.cfunc = _FakeCFunc(CStatements([CExpressionStatement(call, codegen=codegen)], codegen=codegen))
    function = SimpleNamespace(addr=0x1000)
    monkeypatch.setattr(post_stage._calls, "_cod_source_call_names_8616", lambda _project, _addr: ("DrawBar",))

    assert _has_recovered_source_calls_in_codegen_8616(SimpleNamespace(), codegen, function) is False


def test_recovered_source_call_presence_ignores_rendered_text(monkeypatch):
    codegen = _CodegenWithIndexes()
    codegen._inertia_direct_call_floor_recovered_count = 1
    codegen.cfunc = _FakeCFunc(CStatements([], codegen=codegen))
    codegen.render_text = lambda _cfunc: "void f(void) { DrawBar(); }"
    function = SimpleNamespace(addr=0x1000)
    monkeypatch.setattr(post_stage._calls, "_cod_source_call_names_8616", lambda _project, _addr: ("DrawBar",))

    assert _has_recovered_source_calls_in_codegen_8616(SimpleNamespace(), codegen, function) is False


def _direct_stack_update_codegen():
    codegen = _FakeCodegen(_FakeCFunc([]))
    codegen._inertia_direct_stack_update_lowering_8616 = {
        "raw_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 1,
        "failure_count": 0,
    }
    codegen._inertia_direct_stack_update_evidence_8616 = (
        (
            ("offset", -2),
            ("width", 2),
            ("delta", 1),
            ("ins_addr", 0x105CB),
            ("name", "iRow"),
        ),
    )
    return codegen


def _direct_stack_move_idiv_codegen():
    codegen = _FakeCodegen(_FakeCFunc([]))
    codegen._inertia_direct_stack_move_lowering_8616 = {
        "raw_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 1,
        "failure_count": 0,
    }
    codegen._inertia_direct_stack_move_evidence_8616 = (
        (
            ("dst_offset", -118),
            ("width", 2),
            ("source_kind", "SIGNED_IDIV_REMAINDER"),
            ("source_offset", -4),
            ("source_op", "MOD"),
            ("source_immediate", 1),
            ("ins_addr", 0x10611),
        ),
    )
    return codegen


def _direct_stack_move_stack_slot_codegen():
    codegen = _FakeCodegen(_FakeCFunc([]))
    codegen._inertia_direct_stack_move_lowering_8616 = {
        "raw_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 1,
        "failure_count": 0,
    }
    codegen._inertia_direct_stack_move_evidence_8616 = (
        (
            ("dst_offset", -6),
            ("width", 2),
            ("source_kind", DirectStackMoveSourceKind8616.STACK_SLOT),
            ("source_offset", -2),
            ("ins_addr", 0x1070),
        ),
    )
    return codegen


def test_direct_stack_update_materialization_delta_accepts_evidenced_stack_slot_rebind():
    validation = {
        "delta": {
            "segmented_writes": {
                "added": ("deref:Add(Reference(global:0x8f0),Shl(stack_slot:SS:BP-0x2:size4,const:1))",),
                "removed": ("deref:Add(Reference(global:0x8f0),Shl(stack_slot:SS:BP+0x0:size2,const:1))",),
            },
            "conditions": {
                "added": ("CmpGT(global:0xba2,stack_slot:SS:BP-0x2:size4)",),
                "removed": ("CmpGT(global:0xba2,stack_slot:SS:BP+0x0:size2)",),
            },
            "control_flow_effects": {
                "added": ("for:CmpGT(global:0xba2,stack_slot:SS:BP-0x2:size4)",),
                "removed": ("for:CmpGT(global:0xba2,stack_slot:SS:BP+0x0:size2)",),
            },
        }
    }

    assert _is_direct_stack_update_materialization_delta_8616(_direct_stack_update_codegen(), validation) is True


def test_direct_stack_update_materialization_delta_accepts_while_body_write_evidence():
    validation = {
        "delta": {
            "stack_writes": {
                "added": ("stack_slot:SS:BP-0x2:size2",),
                "removed": (),
            },
            "control_flow_effects": {
                "added": ("while-body-writes:const:True:global:0xbaa,stack_slot:SS:BP-0x2:size2",),
                "removed": ("while-body-writes:const:True:global:0xbaa",),
            },
        }
    }

    assert _is_direct_stack_update_materialization_delta_8616(_direct_stack_update_codegen(), validation) is True


def test_direct_stack_update_materialization_delta_accepts_combined_global_high_byte_delta():
    codegen = _direct_stack_update_codegen()
    codegen._inertia_direct_stack_update_evidence_8616 = (
        (
            ("offset", -4),
            ("width", 2),
            ("delta", 1),
            ("ins_addr", 0x10AD5),
            ("name", "iChild"),
        ),
    )
    global_codegen = _direct_global_update_codegen(displacement=0xBAA, width=2)
    codegen._inertia_direct_global_update_lowering_8616 = global_codegen._inertia_direct_global_update_lowering_8616
    codegen._inertia_direct_global_update_evidence_8616 = global_codegen._inertia_direct_global_update_evidence_8616
    validation = {
        "delta": {
            "stack_writes": {
                "added": (),
                "removed": ("stack_slot:SS:BP-0x2:size2", "stack_slot:SS:BP-0x4:size2"),
            },
            "global_writes": {
                "added": ("global:0xbab",),
                "removed": (),
            },
            "control_flow_effects": {
                "added": ("while-body-writes:const:True:global:0xbaa,global:0xbab",),
                "removed": (
                    "ifbreak:CmpGE(Dereference(Add(Mul(reg:ds,const:16),"
                    "Shl(stack_slot:SS:BP-0x2:size2,const:1),const:2892)),"
                    "Dereference(Add(Mul(reg:ds,const:16),"
                    "Shl(stack_slot:SS:BP-0x4:size2,const:1),const:2892)))",
                    "while-body-writes:const:True:global:0xbaa,"
                    "stack_slot:SS:BP-0x2:size2,stack_slot:SS:BP-0x4:size2",
                ),
            },
        }
    }

    assert _is_direct_stack_update_materialization_delta_8616(codegen, validation) is True


def test_direct_stack_update_materialization_delta_accepts_raw_global_fact_span(monkeypatch):
    codegen = _direct_stack_update_codegen()
    codegen._inertia_direct_stack_update_evidence_8616 = (
        (
            ("offset", -4),
            ("width", 2),
            ("delta", 1),
            ("ins_addr", 0x10AD5),
            ("name", "iChild"),
        ),
    )
    codegen.project = SimpleNamespace()
    codegen._inertia_current_function_8616 = SimpleNamespace()
    monkeypatch.setattr(
        post_stage,
        "_direct_global_update_instruction_facts_8616",
        lambda _project, _function: (SimpleNamespace(displacement=0xBAA, width=2),),
    )
    validation = {
        "delta": {
            "stack_writes": {
                "added": (),
                "removed": ("stack_slot:SS:BP-0x4:size2",),
            },
            "global_writes": {
                "added": ("global:0xbab",),
                "removed": (),
            },
        }
    }

    assert _is_direct_stack_update_materialization_delta_8616(codegen, validation) is True


def test_direct_stack_update_materialization_delta_refuses_combined_unrelated_global_delta():
    codegen = _direct_stack_update_codegen()
    global_codegen = _direct_global_update_codegen(displacement=0xBAA, width=2)
    codegen._inertia_direct_global_update_lowering_8616 = global_codegen._inertia_direct_global_update_lowering_8616
    codegen._inertia_direct_global_update_evidence_8616 = global_codegen._inertia_direct_global_update_evidence_8616
    validation = {
        "delta": {
            "stack_writes": {
                "added": ("stack_slot:SS:BP-0x2:size2",),
                "removed": (),
            },
            "global_writes": {
                "added": ("global:0x222",),
                "removed": (),
            },
        }
    }

    assert _is_direct_stack_update_materialization_delta_8616(codegen, validation) is False


def test_direct_stack_update_materialization_delta_refuses_unrelated_while_body_write_drift():
    validation = {
        "delta": {
            "stack_writes": {
                "added": ("stack_slot:SS:BP-0x2:size2",),
                "removed": (),
            },
            "control_flow_effects": {
                "added": ("while-body-writes:const:True:global:0xbaa,stack_slot:SS:BP-0x4:size2",),
                "removed": ("while-body-writes:const:True:global:0xbaa",),
            },
        }
    }

    assert _is_direct_stack_update_materialization_delta_8616(_direct_stack_update_codegen(), validation) is False


def test_direct_stack_update_materialization_delta_refuses_partial_sortdemo_salvage():
    validation = {
        "delta": {
            "stack_writes": {
                "added": ("stack_slot:SS:BP-0x4:size2",),
                "removed": ("stack_slot:SS:BP-0x2:size2", "stack_slot:SS:BP-0x6:size2"),
            },
            "control_flow_effects": {
                "added": (
                    "for-body-writes:CmpLT(stack_slot:SS:BP-0x2:size2,expr_cycle):stack_slot:SS:BP-0x4:size2",
                ),
                "removed": (
                    "for-body-writes:CmpLT(stack_slot:SS:BP-0x2:size2,expr_cycle):"
                    "stack_slot:SS:BP-0x4:size2,stack_slot:SS:BP-0x6:size2",
                ),
            },
        }
    }

    assert _is_direct_stack_update_materialization_delta_8616(_direct_stack_update_codegen(), validation) is False


def test_direct_stack_update_materialization_delta_refuses_added_raw_flags_condition():
    validation = {
        "delta": {
            "conditions": {
                "added": ("CmpEQ(CmpNE(And(reg:flags,const:128),const:0),CmpNE(And(reg:flags,const:2048),const:0))",),
                "removed": (
                    "CmpLT(Dereference(Add(Mul(reg:ds,const:16),Shl(stack_slot:SS:BP-0x2:size2,const:1),const:2892)),"
                    "Dereference(Add(Mul(reg:ds,const:16),Shl(stack_slot:SS:BP-0x4:size2,const:1),const:2892)))",
                ),
            },
            "control_flow_effects": {
                "added": (
                    "if:CmpEQ(CmpNE(And(reg:flags,const:128),const:0),CmpNE(And(reg:flags,const:2048),const:0))",
                ),
                "removed": (
                    "if:CmpLT(Dereference(Add(Mul(reg:ds,const:16),Shl(stack_slot:SS:BP-0x2:size2,const:1),const:2892)),"
                    "Dereference(Add(Mul(reg:ds,const:16),Shl(stack_slot:SS:BP-0x4:size2,const:1),const:2892)))",
                ),
            },
        }
    }

    assert _is_direct_stack_update_materialization_delta_8616(_direct_stack_update_codegen(), validation) is False


def test_direct_stack_update_materialization_delta_refuses_condition_polarity_change():
    codegen = _direct_stack_update_codegen()
    codegen._inertia_direct_stack_update_evidence_8616 = (
        (("offset", -2), ("width", 2), ("delta", -1), ("ins_addr", 0x10C5)),
        (("offset", -6), ("width", 2), ("delta", 1), ("ins_addr", 0x109E)),
    )
    validation = {
        "delta": {
            "conditions": {
                "added": (
                    "CmpGE(Dereference(Add(Mul(reg:ds,const:16),"
                    "Shl(stack_slot:SS:BP-0x2:size2,const:1),const:2892)),stack_slot:SS:BP-0x4:size2)",
                    "CmpLE(Dereference(Add(Mul(reg:ds,const:16),"
                    "Shl(stack_slot:SS:BP-0x6:size2,const:1),const:2892)),stack_slot:SS:BP-0x4:size2)",
                ),
                "removed": (
                    "CmpGT(Dereference(Add(Mul(reg:ds,const:16),"
                    "Shl(stack_slot:SS:BP-0x6:size2,const:1),const:2892)),stack_slot:SS:BP-0x4:size2)",
                    "CmpLT(Dereference(Add(Mul(reg:ds,const:16),"
                    "Shl(stack_slot:SS:BP-0x2:size2,const:1),const:2892)),stack_slot:SS:BP-0x4:size2)",
                ),
            },
            "control_flow_effects": {
                "added": (
                    "if:CmpGE(Dereference(Add(Mul(reg:ds,const:16),"
                    "Shl(stack_slot:SS:BP-0x2:size2,const:1),const:2892)),stack_slot:SS:BP-0x4:size2)",
                    "if:CmpLE(Dereference(Add(Mul(reg:ds,const:16),"
                    "Shl(stack_slot:SS:BP-0x6:size2,const:1),const:2892)),stack_slot:SS:BP-0x4:size2)",
                ),
                "removed": (
                    "if:CmpGT(Dereference(Add(Mul(reg:ds,const:16),"
                    "Shl(stack_slot:SS:BP-0x6:size2,const:1),const:2892)),stack_slot:SS:BP-0x4:size2)",
                    "if:CmpLT(Dereference(Add(Mul(reg:ds,const:16),"
                    "Shl(stack_slot:SS:BP-0x2:size2,const:1),const:2892)),stack_slot:SS:BP-0x4:size2)",
                ),
            },
        }
    }

    assert _is_direct_stack_update_materialization_delta_8616(codegen, validation) is False


def test_direct_stack_move_materialization_delta_accepts_evidenced_stack_slot_copy():
    validation = {
        "delta": {
            "stack_writes": {
                "added": ("stack_slot:SS:BP-0x6:size2=stack_slot:SS:BP-0x2:size2",),
                "removed": (),
            },
        }
    }

    assert _is_direct_stack_move_materialization_delta_8616(_direct_stack_move_stack_slot_codegen(), validation) is True


def test_callsite_stack_argument_delta_accepts_consumed_stack_store_prune():
    codegen = SimpleNamespace(
        _inertia_callsite_materialization_stats=SimpleNamespace(call_arg_materialized_count=1),
        _inertia_consumed_segmented_stack_byte_arg_store_pruned_8616=1,
    )
    validation = {
        "delta": {
            "stack_writes": {
                "added": (),
                "removed": ("stack_slot:SS:BP-0x2:size2",),
            },
            "control_flow_effects": {
                "added": (),
                "removed": ("while-body-writes:const:True:stack_slot:SS:BP-0x2:size2",),
            },
        }
    }

    assert _is_callsite_stack_argument_materialization_delta_8616(codegen, validation) is True


def test_direct_stack_move_materialization_delta_accepts_function_pointer_overwrite_prune():
    codegen = _direct_stack_move_stack_slot_codegen()
    codegen._inertia_direct_stack_move_lowering_8616["unsupported_function_pointer_assignment_pruned_count"] = 1
    codegen._inertia_direct_stack_move_evidence_8616 = (
        (
            ("dst_offset", -2),
            ("width", 2),
            ("source_kind", DirectStackMoveSourceKind8616.IMMEDIATE),
            ("source_value", 0x10010),
            ("ins_addr", 0x1014),
        ),
        (
            ("dst_offset", -2),
            ("width", 2),
            ("source_kind", DirectStackMoveSourceKind8616.IMMEDIATE),
            ("source_value", 0x10028),
            ("ins_addr", 0x101C),
        ),
    )
    validation = {
        "delta": {
            "stack_writes": {
                "added": (),
                "removed": ("stack_slot:SS:BP-0x2:size2",),
            }
        }
    }

    assert _is_direct_stack_move_materialization_delta_8616(codegen, validation) is True


def test_direct_stack_move_materialization_delta_rejects_function_pointer_prune_call_arg_loss():
    codegen = _direct_stack_move_stack_slot_codegen()
    codegen._inertia_direct_stack_move_lowering_8616["unsupported_function_pointer_assignment_pruned_count"] = 1
    codegen._inertia_direct_stack_move_evidence_8616 = (
        (
            ("dst_offset", -2),
            ("width", 2),
            ("source_kind", DirectStackMoveSourceKind8616.IMMEDIATE),
            ("source_value", 0x10010),
            ("ins_addr", 0x1014),
        ),
    )
    validation = {
        "delta": {
            "stack_writes": {
                "added": (),
                "removed": ("stack_slot:SS:BP-0x2:size2",),
            },
            "returns": {
                "added": ("call:addr:0xfd1()",),
                "removed": ("call:addr:0xfd1(stack_slot:SS:BP-0x2:size2,stack_slot:SS:BP+0x6:size2)",),
            },
        }
    }

    assert _is_direct_stack_move_materialization_delta_8616(codegen, validation) is False


def test_direct_stack_move_materialization_delta_accepts_evidenced_loop_body_write_precision():
    codegen = _direct_stack_move_stack_slot_codegen()
    codegen._inertia_direct_stack_move_evidence_8616 = (
        (("dst_offset", -8), ("width", 2), ("source_kind", DirectStackMoveSourceKind8616.IMMEDIATE)),
        (("dst_offset", -6), ("width", 2), ("source_kind", DirectStackMoveSourceKind8616.STACK_SLOT)),
        (("dst_offset", -4), ("width", 2), ("source_kind", DirectStackMoveSourceKind8616.IMMEDIATE)),
        (("source_offset", -2), ("width", 2), ("source_kind", DirectStackMoveSourceKind8616.STACK_SLOT)),
    )
    validation = {
        "delta": {
            "stack_writes": {
                "added": (),
                "removed": (
                    "stack_slot:SS:BP-0x4:size2",
                    "stack_slot:SS:BP-0x6:size2",
                    "stack_slot:SS:BP-0x8:size2",
                ),
            },
            "control_flow_effects": {
                "added": (
                    "for-body-writes:CmpLT(stack_slot:SS:BP-0x2:size2,expr_cycle):"
                    "stack_slot:SS:BP-0x2:size2",
                    "for-body-writes:CmpLT(stack_slot:SS:BP-0x8:size2,expr_cycle):"
                    "stack_slot:SS:BP-0x2:size2",
                ),
                "removed": (
                    "for-body-writes:CmpLT(stack_slot:SS:BP-0x2:size2,expr_cycle):"
                    "stack_slot:SS:BP-0x2:size2,stack_slot:SS:BP-0x4:size2,stack_slot:SS:BP-0x6:size2",
                    "for-body-writes:CmpLT(stack_slot:SS:BP-0x8:size2,expr_cycle):"
                    "stack_slot:SS:BP-0x2:size2,stack_slot:SS:BP-0x4:size2,stack_slot:SS:BP-0x6:size2",
                    "ifbreak:CmpLT(stack_slot:SS:BP-0x2:size2,expr_cycle)",
                ),
            },
        }
    }

    assert _is_direct_stack_move_materialization_delta_8616(codegen, validation) is True


def test_direct_stack_move_materialization_delta_accepts_for_body_global_high_byte_precision():
    codegen = _direct_stack_move_stack_slot_codegen()
    global_codegen = _direct_global_update_codegen(displacement=0xBAA, width=2)
    codegen._inertia_direct_global_update_lowering_8616 = global_codegen._inertia_direct_global_update_lowering_8616
    codegen._inertia_direct_global_update_evidence_8616 = global_codegen._inertia_direct_global_update_evidence_8616
    validation = {
        "delta": {
            "global_writes": {
                "added": ("global:0xbab",),
                "removed": (),
            },
            "control_flow_effects": {
                "added": (
                    "for-body-writes:CmpNE(stack_slot:SS:BP-0x4:size2,const:0):"
                    "global:0xbaa,global:0xbab,stack_slot:SS:BP-0x2:size2",
                ),
                "removed": (
                    "for-body-writes:CmpNE(stack_slot:SS:BP-0x4:size2,const:0):"
                    "global:0xbaa,stack_slot:SS:BP-0x2:size2",
                ),
            },
        }
    }

    assert _is_direct_stack_move_materialization_delta_8616(codegen, validation) is True


def test_direct_stack_move_materialization_delta_accepts_stack_move_with_global_precision():
    codegen = _direct_stack_move_stack_slot_codegen()
    codegen._inertia_direct_stack_move_evidence_8616 = (
        (("dst_offset", -8), ("width", 2), ("source_kind", DirectStackMoveSourceKind8616.SEGMENTED_MEMORY)),
        (("dst_offset", -6), ("width", 2), ("source_kind", DirectStackMoveSourceKind8616.STACK_SLOT)),
        (("dst_offset", -4), ("width", 2), ("source_kind", DirectStackMoveSourceKind8616.STACK_SLOT)),
    )
    global_a = _direct_global_update_codegen(displacement=0xBAA, width=2)
    global_b = _direct_global_update_codegen(displacement=0xBA4, width=2)
    codegen._inertia_direct_global_update_evidence_8616 = (
        *global_a._inertia_direct_global_update_evidence_8616,
        *global_b._inertia_direct_global_update_evidence_8616,
    )
    validation = {
        "delta": {
            "global_writes": {
                "added": ("global:0xba5",),
                "removed": ("global:0xbaa",),
            },
            "conditions": {
                "added": (),
                "removed": (
                    "CmpLE(Dereference(Add(Mul(reg:ds,const:16),"
                    "Shl(stack_slot:SS:BP-0x4:size2,const:1),const:2890)),"
                    "stack_slot:SS:BP-0x6:size2)",
                ),
            },
            "control_flow_effects": {
                "added": (
                    "for-body-writes:CmpNE(stack_slot:SS:BP-0x4:size2,const:0):"
                    "global:0xba4,global:0xba5",
                ),
                "removed": (
                    "for-body-writes:CmpNE(stack_slot:SS:BP-0x4:size2,const:0):"
                    "global:0xba4,global:0xbaa",
                    "ifbreak:CmpLE(Dereference(Add(Mul(reg:ds,const:16),"
                    "Shl(stack_slot:SS:BP-0x4:size2,const:1),const:2890)),"
                    "stack_slot:SS:BP-0x6:size2)",
                ),
            },
        }
    }

    assert _is_direct_stack_move_materialization_delta_8616(codegen, validation) is True


def test_direct_stack_move_materialization_delta_refuses_unrelated_for_body_global_precision():
    codegen = _direct_stack_move_stack_slot_codegen()
    global_codegen = _direct_global_update_codegen(displacement=0xBAA, width=2)
    codegen._inertia_direct_global_update_lowering_8616 = global_codegen._inertia_direct_global_update_lowering_8616
    codegen._inertia_direct_global_update_evidence_8616 = global_codegen._inertia_direct_global_update_evidence_8616
    validation = {
        "delta": {
            "global_writes": {
                "added": ("global:0x222",),
                "removed": (),
            },
            "control_flow_effects": {
                "added": (
                    "for-body-writes:CmpNE(stack_slot:SS:BP-0x4:size2,const:0):"
                    "global:0xbaa,global:0x222,stack_slot:SS:BP-0x2:size2",
                ),
                "removed": (
                    "for-body-writes:CmpNE(stack_slot:SS:BP-0x4:size2,const:0):"
                    "global:0xbaa,stack_slot:SS:BP-0x2:size2",
                ),
            },
        }
    }

    assert _is_direct_stack_move_materialization_delta_8616(codegen, validation) is False


def test_direct_stack_move_materialization_delta_refuses_control_flow_changes():
    validation = {
        "delta": {
            "stack_writes": {
                "added": (),
                "removed": ("stack_slot:SS:BP-0x2:size2",),
            },
            "control_flow_effects": {
                "added": ("for-body-writes:CmpNE(stack_slot:SS:BP-0x4:size2,const:0):global:0xbaa",),
                "removed": (
                    "for-body-writes:CmpNE(stack_slot:SS:BP-0x4:size2,const:0):"
                    "global:0xbaa,stack_slot:SS:BP-0x2:size2"
                ),
            },
        }
    }

    assert (
        _is_direct_stack_move_materialization_delta_8616(_direct_stack_move_stack_slot_codegen(), validation) is False
    )


def test_direct_stack_move_materialization_delta_refuses_unrelated_stack_slot_copy():
    validation = {
        "delta": {
            "stack_writes": {
                "added": ("stack_slot:SS:BP-0x8:size2=stack_slot:SS:BP-0xa:size2",),
                "removed": (),
            },
        }
    }

    assert (
        _is_direct_stack_move_materialization_delta_8616(_direct_stack_move_stack_slot_codegen(), validation) is False
    )


def test_direct_stack_move_idiv_remainder_delta_accepts_insert_helper_and_ax_churn():
    validation = {
        "delta": {
            "helper_calls": {
                "added": ("name:_INSERT",),
                "removed": (),
            },
            "register_writes": {
                "added": ("reg:ax",),
                "removed": (),
            },
        }
    }

    assert (
        _is_direct_stack_move_idiv_remainder_materialization_delta_8616(
            _direct_stack_move_idiv_codegen(),
            validation,
        )
        is True
    )


def test_direct_stack_move_idiv_remainder_delta_accepts_combined_stack_update_delta():
    codegen = _direct_stack_update_codegen()
    move_codegen = _direct_stack_move_idiv_codegen()
    codegen._inertia_direct_stack_move_lowering_8616 = move_codegen._inertia_direct_stack_move_lowering_8616
    codegen._inertia_direct_stack_move_evidence_8616 = move_codegen._inertia_direct_stack_move_evidence_8616
    validation = {
        "delta": {
            "helper_calls": {
                "added": ("name:_INSERT",),
                "removed": (),
            },
            "register_writes": {
                "added": ("reg:ax",),
                "removed": (),
            },
            "conditions": {
                "added": ("CmpGT(global:0xba2,stack_slot:SS:BP-0x2:size4)",),
                "removed": ("CmpGT(global:0xba2,stack_slot:SS:BP+0x0:size2)",),
            },
            "control_flow_effects": {
                "added": ("for:CmpGT(global:0xba2,stack_slot:SS:BP-0x2:size4)",),
                "removed": ("for:CmpGT(global:0xba2,stack_slot:SS:BP+0x0:size2)",),
            },
        }
    }

    assert _is_direct_stack_move_idiv_remainder_materialization_delta_8616(codegen, validation) is True


def test_direct_stack_move_idiv_remainder_delta_refuses_without_evidence():
    codegen = _FakeCodegen(_FakeCFunc([]))
    validation = {
        "delta": {
            "helper_calls": {
                "added": ("name:_INSERT",),
                "removed": (),
            }
        }
    }

    assert _is_direct_stack_move_idiv_remainder_materialization_delta_8616(codegen, validation) is False


def test_direct_stack_update_materialization_delta_refuses_without_consumed_evidence():
    codegen = _FakeCodegen(_FakeCFunc([]))
    codegen._inertia_direct_stack_update_lowering_8616 = {
        "raw_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 0,
        "failure_count": 1,
    }
    validation = {
        "delta": {
            "conditions": {
                "added": ("CmpGT(global:0xba2,stack_slot:SS:BP-0x2:size4)",),
                "removed": ("CmpGT(global:0xba2,stack_slot:SS:BP+0x0:size2)",),
            },
        }
    }

    assert _is_direct_stack_update_materialization_delta_8616(codegen, validation) is False


def test_postprocess_metadata_restore_removes_rejected_return_chain_evidence():
    codegen = _FakeCodegen(_FakeCFunc([]))
    codegen._inertia_return_chain_flattened_8616 = False
    codegen._inertia_postprocess_rejected_passes = ("earlier",)

    snapshot = _snapshot_codegen_inertia_metadata_8616(codegen)
    codegen._inertia_return_chain_flattened_8616 = True
    codegen._inertia_return_chain_materialized_values_8616 = (1, 2, 3)
    codegen._inertia_postprocess_rejected_passes = ("earlier", "current")

    _restore_codegen_inertia_metadata_8616(codegen, snapshot)

    assert codegen._inertia_return_chain_flattened_8616 is False
    assert not hasattr(codegen, "_inertia_return_chain_materialized_values_8616")
    assert codegen._inertia_postprocess_rejected_passes == ("earlier", "current")

    assert (
        _classify_postprocess_validation_delta_8616(
            {
                "delta": {
                    "helper_calls": {
                        "added": (),
                        "removed": ("name:addr:0x1d1c",),
                    },
                    "returns": {
                        "added": ("const:255",),
                        "removed": (),
                    },
                }
            }
        )
        is _PostprocessValidationDeltaKind8616.BLOCKING
    )


def test_postprocess_metadata_restore_invalidates_ast_replay_generations():
    codegen = _FakeCodegen(_FakeCFunc([]))
    codegen._inertia_direct_stack_replay_stable_generation_8616 = object()
    codegen._inertia_direct_stack_ownership_replay_stable_generation_8616 = object()
    codegen._inertia_direct_stack_move_ownership_replayed_8616 = True

    snapshot = _snapshot_codegen_inertia_metadata_8616(codegen)
    _restore_codegen_inertia_metadata_8616(codegen, snapshot)

    assert codegen._inertia_direct_stack_replay_stable_generation_8616 is None
    assert codegen._inertia_direct_stack_ownership_replay_stable_generation_8616 is None
    assert codegen._inertia_direct_stack_move_ownership_replayed_8616 is None


def test_postprocess_metadata_snapshot_rolls_back_top_level_containers_without_deepcopying_objects():
    codegen = _FakeCodegen(_FakeCFunc([]))
    marker = _DeepcopyPoisonMetadata()
    codegen._inertia_example_metadata = {"items": [marker], "count": 1}

    snapshot = _snapshot_codegen_inertia_metadata_8616(codegen)
    codegen._inertia_example_metadata["items"].append("mutated")
    codegen._inertia_example_metadata["count"] = 2

    _restore_codegen_inertia_metadata_8616(codegen, snapshot)

    assert codegen._inertia_example_metadata["items"] == [marker]
    assert codegen._inertia_example_metadata["count"] == 1
