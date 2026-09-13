from __future__ import annotations

from types import SimpleNamespace

import angr_platforms.X86_16.decompiler_postprocess_stage as post_stage
from angr.ailment.statement import Return as AILReturn
from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CDirtyExpression,
    CExpressionStatement,
    CFunctionCall,
    CIfElse,
    CReturn,
    CStatements,
    CUnsupportedStatement,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.decompiler_postprocess_calls import CallsiteMaterializationDecision8616
from angr_platforms.X86_16.decompiler_postprocess_stage import (
    _collapse_unsupported_ail_return_before_materialized_return_8616,
    _flatten_conditional_return_chain_8616,
    _is_cfg_return_chain_callsite_materialization_delta_8616,
    _is_cfg_return_expr_chain_materialization_delta_8616,
    _is_proven_surplus_empty_guard_cleanup_delta_8616,
    _materialize_cfg_mask_accumulator_8616,
    _materialize_cfg_selector_return_branches_pass_8616,
    _materialize_empty_if_return_branches_pass_8616,
    _materialize_missing_terminal_ax_return_8616,
    _materialize_void_tail_call_guard_from_cfg_pass_8616,
    _prune_duplicate_empty_return_guard_before_cfg_suffix_8616,
)
from angr_platforms.X86_16.structuring.surplus_guard_contracts import (
    SurplusGuardCleanupEvidence8616,
    SurplusGuardCleanupStats8616,
)


def test_materialized_terminal_return_supersedes_adjacent_unsupported_ail_return():
    codegen = _DummyCodegen()
    unsupported = CUnsupportedStatement(AILReturn(1, []), codegen=codegen)
    materialized = CReturn(_const(7, codegen), codegen=codegen)
    root = CStatements([unsupported, materialized], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)
    codegen._inertia_missing_terminal_ax_return_materialized_8616 = 1

    changed = _collapse_unsupported_ail_return_before_materialized_return_8616(codegen)

    assert changed is True
    assert root.statements == [materialized]
    assert codegen._inertia_unsupported_ail_returns_superseded_8616 == 1


class _DummyCodegen:
    def __init__(self):
        self._idx = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=Arch86_16())

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _if_return(cond_value: int, return_value: int, codegen):
    body = CStatements(
        statements=[CReturn(_const(return_value, codegen), codegen=codegen)],
        codegen=codegen,
    )
    return CIfElse([(_const(cond_value, codegen), body)], else_node=None, cstyle_ifs=True, codegen=codegen)


def test_direct_stack_postprocess_fallbacks_refuse_after_structuring_pass(monkeypatch):
    codegen = SimpleNamespace(_inertia_direct_stack_materialization_structuring_pass_ran_8616=True)
    calls: list[str] = []

    def stack_mov(_codegen, *, project=None, function=None, allow_stack_slot_fallback=True, source_kinds=None):
        del project, function, allow_stack_slot_fallback, source_kinds
        calls.append("mov")
        return True

    def stack_incdec(_codegen, *, project=None, function=None):
        del project, function
        calls.append("incdec")
        return True

    monkeypatch.setattr(post_stage, "materialize_direct_stack_mov_instructions_8616", stack_mov)
    monkeypatch.setattr(post_stage, "materialize_direct_stack_incdec_instructions_8616", stack_incdec)

    assert post_stage._materialize_direct_stack_mov_instructions_postprocess_8616(object(), codegen) is False
    assert post_stage._materialize_direct_stack_incdec_instructions_postprocess_8616(object(), codegen) is False
    assert calls == []


def test_stable_stack_postprocess_fallback_refuses_after_structuring_pass(monkeypatch):
    codegen = SimpleNamespace(_inertia_stable_stack_semantics_structuring_pass_ran_8616=True)
    calls: list[str] = []

    def transfer(_project, _codegen):
        calls.append("transfer")
        return 1

    monkeypatch.setattr(post_stage, "transfer_semantic_alias_facts_to_codegen_8616", transfer)

    assert post_stage._materialize_stable_stack_semantics_postprocess_8616(object(), codegen) is False
    assert calls == []


def test_pointer_arg_indirect_postprocess_fallback_refuses_after_structuring_pass(monkeypatch):
    codegen = SimpleNamespace(_inertia_pointer_arg_indirect_structuring_pass_ran_8616=True)
    calls: list[str] = []

    def materialize(_project, _codegen, _func):
        calls.append("pointer")
        return True

    monkeypatch.setattr(post_stage._post, "_materialize_pointer_arg_indirect_loads_8616", materialize)

    assert post_stage._materialize_pointer_arg_indirect_loads_postprocess_8616(object(), codegen) is False
    assert calls == []


def test_pointer_arg_indirect_postprocess_slot_never_recovers_semantics(monkeypatch):
    codegen = SimpleNamespace()
    calls: list[str] = []

    def materialize(_project, _codegen, _func):
        calls.append("pointer")
        return True

    monkeypatch.setattr(post_stage._post, "_materialize_pointer_arg_indirect_loads_8616", materialize)

    assert post_stage._materialize_pointer_arg_indirect_loads_postprocess_8616(object(), codegen) is False
    assert calls == []


def test_pointer_memory_idiom_postprocess_fallback_refuses_after_lowering_pass(monkeypatch):
    codegen = SimpleNamespace(_inertia_pointer_memory_idiom_lowering_pass_ran_8616=True)
    calls: list[str] = []

    def materialize(_project, _codegen):
        calls.append("pointer-memory")
        return True

    monkeypatch.setattr(post_stage, "_materialize_pointer_memory_idioms_8616", materialize)

    assert post_stage._materialize_pointer_memory_idioms_postprocess_8616(object(), codegen) is False
    assert calls == []


def test_callsite_prototypes_postprocess_fallback_refuses_after_structuring_pass(monkeypatch):
    codegen = SimpleNamespace(_inertia_callsite_prototypes_structuring_pass_ran_8616=True)
    calls: list[str] = []

    def prototypes(_project, _codegen):
        calls.append("prototypes")
        return True

    monkeypatch.setattr(post_stage._calls, "_materialize_callsite_prototypes_8616", prototypes)

    assert post_stage._materialize_callsite_prototypes_postprocess_8616(object(), codegen) is False
    assert calls == []


def test_callsite_stack_argument_postprocess_fallbacks_refuse_after_structuring_pass(monkeypatch):
    codegen = SimpleNamespace(_inertia_callsite_stack_arguments_structuring_pass_ran_8616=True)
    calls: list[str] = []

    def recover(_project, _codegen):
        calls.append("recover")
        return True

    def stack_args(_project, _codegen):
        calls.append("stack-args")
        return True

    monkeypatch.setattr(post_stage._calls, "_recover_missing_direct_calls_from_evidence_8616", recover)
    monkeypatch.setattr(post_stage, "_materialize_callsite_stack_arguments_preserve_setup_8616", stack_args)
    monkeypatch.setattr(
        post_stage,
        "_snapshot_codegen_cfunc",
        lambda _codegen: calls.append("rollback-snapshot"),
    )

    assert post_stage._recover_missing_direct_calls_from_evidence_early_postprocess_8616(object(), codegen) is False
    assert post_stage._recover_missing_direct_calls_final_postprocess_8616(object(), codegen) is False
    assert post_stage._materialize_callsite_stack_arguments_postprocess_8616(object(), codegen) is False
    assert post_stage._materialize_callsite_stack_arguments_final_postprocess_8616(object(), codegen) is False
    assert post_stage._materialize_callsite_stack_arguments_after_ss_lowering_8616(object(), codegen) is False
    assert post_stage._materialize_recovered_callsite_stack_arguments_postprocess_8616(object(), codegen) is False
    assert (
        post_stage._salvage_callsite_stack_args_after_discard_8616(
            SimpleNamespace(codegen=codegen),
            validation_mode="live_out",
            snapshot_function_info=object(),
            function=object(),
            log=object(),
        )
        is False
    )
    assert calls == []


def test_stdlib_call_chains_postprocess_fallback_refuses_after_structuring_pass(monkeypatch):
    codegen = SimpleNamespace(_inertia_stdlib_call_chains_structuring_pass_ran_8616=True)
    calls: list[str] = []

    def stdlib(_project, _codegen):
        calls.append("stdlib")
        return True

    monkeypatch.setattr(post_stage._calls, "_materialize_stdlib_call_chains_8616", stdlib)

    assert post_stage._materialize_stdlib_call_chains_postprocess_8616(object(), codegen) is False
    assert calls == []


def test_stack_byte_pair_return_postprocess_fallback_refuses_after_structuring_pass(monkeypatch):
    codegen = SimpleNamespace(_inertia_stack_byte_pair_return_structuring_pass_ran_8616=True)
    calls: list[str] = []

    def materialize(_project, _codegen):
        calls.append("stack-byte")
        return True

    monkeypatch.setattr(post_stage, "_materialize_stack_byte_pair_return_8616", materialize)

    assert post_stage._materialize_stack_byte_pair_return_pass_8616(object(), codegen) is False
    assert calls == []


def test_loop_idiom_postprocess_fallback_refuses_after_structuring_pass(monkeypatch):
    codegen = SimpleNamespace(_inertia_loop_idiom_structuring_pass_ran_8616=True)
    calls: list[str] = []

    def global_byte_sum(_project, _codegen):
        calls.append("global")
        return True

    monkeypatch.setattr(post_stage, "_materialize_global_byte_index_sum_loop_8616", global_byte_sum)

    assert post_stage._materialize_global_byte_index_sum_loop_postprocess_8616(object(), codegen) is False
    assert calls == []


def test_direct_global_postprocess_fallback_refuses_after_structuring_pass(monkeypatch):
    codegen = SimpleNamespace(_inertia_direct_global_incdec_materialization_structuring_pass_ran_8616=True)
    calls: list[str] = []

    def global_incdec(_codegen, *, project=None, function=None):
        del project, function
        calls.append("global")
        return True

    monkeypatch.setattr(post_stage, "materialize_direct_global_incdec_instructions_8616", global_incdec)

    assert post_stage._materialize_direct_global_incdec_instructions_postprocess_8616(object(), codegen) is False
    assert calls == []


def test_unresolved_exit_goto_postprocess_fallback_refuses_after_structuring_pass(monkeypatch):
    codegen = SimpleNamespace(_inertia_unresolved_exit_goto_structuring_pass_ran_8616=True)
    calls: list[str] = []

    def repair(_project, _codegen):
        calls.append("repair")
        return True

    monkeypatch.setattr(post_stage._post, "_repair_unresolved_function_exit_gotos_8616", repair)

    assert post_stage._repair_unresolved_function_exit_gotos_pass_8616(object(), codegen) is False
    assert calls == []


def test_selector_return_postprocess_fallback_refuses_after_structuring_pass(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    codegen._inertia_selector_return_structuring_pass_ran_8616 = True

    def fail_materialization(*_args, **_kwargs):
        raise AssertionError("postprocess fallback should not materialize selector returns after structuring ran")

    monkeypatch.setattr(post_stage, "_structuring_materialize_cfg_selector_return_branches_8616", fail_materialization)

    changed = _materialize_cfg_selector_return_branches_pass_8616(project, codegen)

    assert changed is False


def test_empty_if_return_chain_postprocess_fallback_refuses_after_structuring_pass(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    codegen._inertia_return_chains_structuring_pass_ran_8616 = True

    def fail_materialization(*_args, **_kwargs):
        raise AssertionError("postprocess fallback should not materialize return chains after structuring ran")

    monkeypatch.setattr(post_stage, "_structuring_materialize_empty_if_return_branches_8616", fail_materialization)

    changed = _materialize_empty_if_return_branches_pass_8616(project, codegen)

    assert changed is False


def test_cfg_mask_accumulator_postprocess_fallback_refuses_after_structuring_pass(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    codegen._inertia_cfg_mask_accumulator_structuring_pass_ran_8616 = True

    def fail_materialization(*_args, **_kwargs):
        raise AssertionError("postprocess fallback should not materialize CFG masks after structuring ran")

    monkeypatch.setattr(post_stage, "_structuring_materialize_cfg_mask_accumulator_8616", fail_materialization)

    changed = _materialize_cfg_mask_accumulator_8616(project, codegen)

    assert changed is False


def test_missing_terminal_ax_return_postprocess_fallback_refuses_after_structuring_pass(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    codegen._inertia_missing_terminal_ax_return_structuring_pass_ran_8616 = True

    def fail_return_scan(*_args, **_kwargs):
        raise AssertionError("postprocess fallback should not scan terminal AX after structuring ran")

    monkeypatch.setattr(post_stage, "_linear_terminal_ax_return_expr_8616", fail_return_scan)

    changed = _materialize_missing_terminal_ax_return_8616(project, codegen)

    assert changed is False


def test_void_tail_call_guard_postprocess_fallback_refuses_after_structuring_pass(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    codegen._inertia_void_tail_call_guard_structuring_pass_ran_8616 = True

    def fail_materialization(*_args, **_kwargs):
        raise AssertionError("postprocess fallback should not materialize void tail-call guards after structuring ran")

    monkeypatch.setattr(post_stage, "_materialize_void_tail_call_guard_from_cfg_8616", fail_materialization)

    changed = _materialize_void_tail_call_guard_from_cfg_pass_8616(project, codegen)

    assert changed is False


def test_flatten_conditional_return_chain_is_idempotent(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    cond_one = _const(1, codegen)
    cond_two = _const(2, codegen)
    root = CStatements(
        statements=[
            CIfElse(
                [
                    (
                        cond_one,
                        CStatements(statements=[CReturn(_const(7, codegen), codegen=codegen)], codegen=codegen),
                    )
                ],
                else_node=None,
                cstyle_ifs=True,
                codegen=codegen,
            ),
            CIfElse(
                [
                    (
                        cond_two,
                        CStatements(statements=[CReturn(_const(9, codegen), codegen=codegen)], codegen=codegen),
                    )
                ],
                else_node=None,
                cstyle_ifs=True,
                codegen=codegen,
            ),
            CReturn(_const(11, codegen), codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    monkeypatch.setattr(post_stage, "_last_ax_return_value_8616", lambda _project, _codegen: 11)

    changed = _flatten_conditional_return_chain_8616(project, codegen, [(cond_one, 7), (cond_two, 9)])

    assert changed is False
    assert codegen.cfunc.statements is root
    assert codegen._inertia_return_chain_flattened_8616 is True
    assert codegen._inertia_return_chain_materialized_values_8616 == (7, 9)
    assert codegen._inertia_return_chain_final_value_8616 == 11


def test_prune_duplicate_empty_return_accepts_single_statement_wrapper_before_cfg_suffix():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    wrapped_empty_return = CStatements(statements=[CReturn(None, codegen=codegen)], codegen=codegen)
    root = CStatements(
        statements=[
            wrapped_empty_return,
            _if_return(1, -1, codegen),
            _if_return(2, 0, codegen),
            _if_return(3, 1, codegen),
            CReturn(_const(2, codegen), codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    codegen._inertia_return_chain_suffix_materialized_8616 = True
    codegen._inertia_return_chain_materialized_values_8616 = (-1, 0, 1)

    changed = _prune_duplicate_empty_return_guard_before_cfg_suffix_8616(project, codegen)

    assert changed is True
    assert codegen._inertia_return_chain_empty_prefix_pruned_8616 is True
    assert codegen.cfunc.statements.statements[0] is not wrapped_empty_return


def test_duplicate_return_guard_probe_uses_value_only_cfg_evidence(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    root = CStatements(statements=[], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    monkeypatch.setattr(
        post_stage,
        "_ordered_conditional_return_values_8616",
        lambda _project, _codegen: [1],
    )
    monkeypatch.setattr(
        post_stage,
        "_last_ax_return_value_8616",
        lambda _project, _codegen: 2,
    )

    def reject_expression_materialization(_project, _codegen):
        raise AssertionError("value-only proof must not decode C conditions")

    monkeypatch.setattr(
        post_stage,
        "_ordered_conditional_return_pairs_from_cfg_8616",
        reject_expression_materialization,
    )

    assert _prune_duplicate_empty_return_guard_before_cfg_suffix_8616(
        project,
        codegen,
    ) is False


def test_cfg_return_chain_delta_accepts_suffix_materialization_with_refused_full_flatten(monkeypatch):
    codegen = SimpleNamespace(
        _inertia_return_chain_flattened_8616=False,
        _inertia_return_chain_suffix_materialized_8616=True,
        _inertia_empty_return_branch_stats_8616={"materialized": 3, "refused": 3},
        _inertia_return_chain_materialized_values_8616=(1, 2, 3),
        _inertia_return_chain_final_value_8616=255,
        _inertia_return_chain_materialized_condition_fingerprints_8616=(),
    )
    validation = {
        "delta": {
            "returns": {
                "added": ("const:1", "const:2", "const:3", "const:255"),
                "removed": ("none",),
            },
        }
    }

    monkeypatch.setattr(post_stage, "_ordered_conditional_return_values_8616", lambda _project, _codegen: ())
    monkeypatch.setattr(
        post_stage,
        "_ordered_conditional_return_pairs_from_cfg_8616",
        lambda _project, _codegen: (("cond1", 1), ("cond2", 2), ("cond3", 3)),
    )
    monkeypatch.setattr(post_stage, "_last_ax_return_value_8616", lambda _project, _codegen: 255)

    assert _is_cfg_return_chain_callsite_materialization_delta_8616(
        SimpleNamespace(arch=Arch86_16()),
        SimpleNamespace(),
        codegen,
        validation,
    )


def test_cfg_return_chain_delta_refuses_helper_call_changes(monkeypatch):
    codegen = SimpleNamespace(
        _inertia_return_chain_flattened_8616=False,
        _inertia_return_chain_suffix_materialized_8616=True,
        _inertia_empty_return_branch_stats_8616={"materialized": 3, "refused": 3},
        _inertia_return_chain_materialized_values_8616=(1, 2, 3),
        _inertia_return_chain_final_value_8616=255,
        _inertia_return_chain_materialized_condition_fingerprints_8616=(),
    )
    validation = {
        "delta": {
            "helper_calls": {"added": ("addr:0xd368",), "removed": ()},
            "returns": {
                "added": ("const:1", "const:2", "const:3", "const:255"),
                "removed": ("none",),
            },
        }
    }

    monkeypatch.setattr(post_stage, "_ordered_conditional_return_values_8616", lambda _project, _codegen: ())
    monkeypatch.setattr(
        post_stage,
        "_ordered_conditional_return_pairs_from_cfg_8616",
        lambda _project, _codegen: (("cond1", 1), ("cond2", 2), ("cond3", 3)),
    )
    monkeypatch.setattr(post_stage, "_last_ax_return_value_8616", lambda _project, _codegen: 255)

    assert not _is_cfg_return_chain_callsite_materialization_delta_8616(
        SimpleNamespace(arch=Arch86_16()),
        SimpleNamespace(),
        codegen,
        validation,
    )


def _surplus_empty_guard_codegen() -> SimpleNamespace:
    return SimpleNamespace(
        _inertia_void_empty_return_guard_decision_8616="prune",
        _inertia_void_empty_return_guard_pruned_8616=2,
        _inertia_void_empty_return_guard_noop_pruned_8616=2,
        _inertia_void_empty_return_guard_empty_return_pruned_8616=0,
        _inertia_void_empty_return_guard_identical_arms_collapsed_8616=0,
        _inertia_void_empty_return_guard_branch_count_8616=10,
        _inertia_void_empty_return_guard_total_ifs_8616=12,
    )


def _surplus_empty_guard_validation() -> dict[str, object]:
    return {
        "delta": {
            "conditions": {
                "added": (),
                "removed": ("CmpLT(arg:a1,arg:a0)", "CmpLT(local:i,arg:a0)"),
            },
            "control_flow_effects": {
                "added": (),
                "removed": ("if:CmpLT(arg:a1,arg:a0)", "if:CmpLT(local:i,arg:a0)"),
            },
        }
    }


def test_surplus_empty_guard_delta_accepts_exact_structuring_proof() -> None:
    assert _is_proven_surplus_empty_guard_cleanup_delta_8616(
        _surplus_empty_guard_codegen(),
        _surplus_empty_guard_validation(),
    )


def test_surplus_empty_guard_delta_uses_durable_artifact_after_later_scan() -> None:
    codegen = _surplus_empty_guard_codegen()
    codegen._inertia_void_empty_return_guard_decision_8616 = "keep_within_branch_budget"
    codegen._inertia_surplus_empty_guard_cleanup_artifact_8616 = (
        SurplusGuardCleanupEvidence8616(
            branch_count=10,
            total_if_count=12,
            noop_materialized_count=2,
            empty_return_materialized_count=0,
            identical_arms_materialized_count=0,
            stats=SurplusGuardCleanupStats8616(2, 2, 2, 2, 0),
        )
    )

    assert _is_proven_surplus_empty_guard_cleanup_delta_8616(
        codegen,
        _surplus_empty_guard_validation(),
    )


def test_surplus_empty_guard_pass_declares_its_internal_local_proof() -> None:
    codegen = SimpleNamespace()

    assert post_stage._postprocess_pass_has_local_evidence_8616(
        "_prune_surplus_void_empty_return_guards_8616",
        codegen,
    )
    assert post_stage._postprocess_pass_has_local_evidence_8616(
        "_prune_surplus_void_empty_return_guards_final_8616",
        codegen,
    )


def test_surplus_empty_guard_delta_refuses_unrelated_effect() -> None:
    validation = _surplus_empty_guard_validation()
    validation["delta"]["helper_calls"] = {"added": (), "removed": ("addr:0x1234",)}

    assert not _is_proven_surplus_empty_guard_cleanup_delta_8616(
        _surplus_empty_guard_codegen(),
        validation,
    )


def test_surplus_empty_guard_delta_refuses_incomplete_evidence_census() -> None:
    codegen = _surplus_empty_guard_codegen()
    codegen._inertia_void_empty_return_guard_noop_pruned_8616 = 1

    assert not _is_proven_surplus_empty_guard_cleanup_delta_8616(
        codegen,
        _surplus_empty_guard_validation(),
    )


def test_surplus_empty_guard_delta_refuses_fingerprint_count_mismatch() -> None:
    validation = _surplus_empty_guard_validation()
    validation["delta"]["conditions"]["removed"] = ("CmpLT(arg:a1,arg:a0)",)

    assert not _is_proven_surplus_empty_guard_cleanup_delta_8616(
        _surplus_empty_guard_codegen(),
        validation,
    )


def test_empty_if_return_materialization_refuses_unsafe_effect_function(monkeypatch):
    codegen = _DummyCodegen()
    empty_body = CStatements(statements=[], codegen=codegen)
    root = CStatements(
        statements=[
            CIfElse([(_const(1, codegen), empty_body)], else_node=None, cstyle_ifs=True, codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    monkeypatch.setattr(
        post_stage, "_selector_function_has_unsafe_effects_8616", lambda _project, _codegen, allowed_call_addrs: True
    )
    monkeypatch.setattr(post_stage, "_ordered_conditional_return_values_8616", lambda _project, _codegen: (7,))

    changed = post_stage._materialize_empty_if_return_branches_8616(SimpleNamespace(arch=Arch86_16()), codegen)

    assert changed is False
    assert empty_body.statements == []
    assert codegen._inertia_empty_return_branch_stats_8616["candidates"] == 1
    assert codegen._inertia_empty_return_branch_stats_8616["materialized"] == 0
    assert codegen._inertia_empty_return_branch_stats_8616["refused"] >= 1
    assert codegen._inertia_empty_return_branch_refused_unsafe_effects_8616 == 1


def test_selector_effect_scan_ignores_stale_rewrite_function_cache() -> None:
    codegen = _DummyCodegen()
    root = CStatements(statements=[], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x2000, statements=root, body=root)
    stale_write = SimpleNamespace(
        address=0x1000,
        size=2,
        mnemonic="add",
        operands=(SimpleNamespace(type=3), SimpleNamespace(type=2)),
    )
    current_register_write = SimpleNamespace(
        address=0x2000,
        size=2,
        mnemonic="add",
        operands=(SimpleNamespace(type=1), SimpleNamespace(type=2)),
    )
    codegen._inertia_jcc_function_insns_8616 = (stale_write,)
    function = SimpleNamespace(block_addrs_set={0x2000})
    project = SimpleNamespace(
        arch=Arch86_16(),
        factory=SimpleNamespace(
            block=lambda addr, opt_level=0: SimpleNamespace(
                capstone=SimpleNamespace(
                    insns=(current_register_write,) if addr == 0x2000 else ()
                )
            )
        ),
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda *, addr, create=False: function
                if addr == 0x2000 and create is False
                else None
            )
        ),
    )

    assert post_stage._selector_function_has_unsafe_effects_8616(project, codegen) is False


def test_cfg_selector_return_scans_explicit_return_ast(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    cond = _const(1, codegen)
    true_body = CStatements(statements=[CReturn(_const(7, codegen), codegen=codegen)], codegen=codegen)
    root = CStatements(
        statements=[
            CIfElse([(cond, true_body)], else_node=None, cstyle_ifs=True, codegen=codegen),
            CReturn(_const(3, codegen), codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    calls = {"decrement_switch": 0}

    def fake_decrement_switch(_project, _codegen):
        calls["decrement_switch"] += 1
        return False

    monkeypatch.setattr(post_stage, "_materialize_decrement_switch_return_chain_8616", fake_decrement_switch)
    monkeypatch.setattr(post_stage, "_ordered_32bit_selector_return_expr_pairs_from_cfg_8616", lambda *_args: [])
    monkeypatch.setattr(post_stage, "_ordered_conditional_return_expr_pairs_from_cfg_8616", lambda *_args: [])

    changed = post_stage._materialize_cfg_selector_return_branches_8616(project, codegen)

    assert changed is False
    assert calls["decrement_switch"] == 1
    assert not hasattr(codegen, "_inertia_cfg_selector_return_skipped_explicit_return_ast_8616")


def test_cfg_selector_return_scans_dirty_return_artifact(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    dirty_return = CReturn(CDirtyExpression("vvar_10", codegen=codegen), codegen=codegen)
    root = CStatements(statements=[dirty_return], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    calls = {"decrement_switch": 0}

    def fake_decrement_switch(_project, _codegen):
        calls["decrement_switch"] += 1
        return False

    monkeypatch.setattr(post_stage, "_materialize_decrement_switch_return_chain_8616", fake_decrement_switch)
    monkeypatch.setattr(post_stage, "_ordered_32bit_selector_return_expr_pairs_from_cfg_8616", lambda *_args: [])
    monkeypatch.setattr(post_stage, "_ordered_conditional_return_expr_pairs_from_cfg_8616", lambda *_args: [])

    changed = post_stage._materialize_cfg_selector_return_branches_8616(project, codegen)

    assert changed is False
    assert calls["decrement_switch"] == 1
    assert not hasattr(codegen, "_inertia_cfg_selector_return_skipped_explicit_return_ast_8616")


def test_cfg_selector_return_allows_calls_consumed_as_condition_evidence(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    root = CStatements(statements=[], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    condition_call = CFunctionCall("cmp_i16", None, [_const(1, codegen), _const(2, codegen)], codegen=codegen)
    condition_call.tags = {"condition_call_ins_addr": 0x1013}
    captured: dict[str, frozenset[int]] = {}

    def fake_has_unsafe_effects(_project, _codegen, *, allowed_call_addrs=frozenset()):
        captured["allowed_call_addrs"] = allowed_call_addrs
        return False

    monkeypatch.setattr(post_stage, "_materialize_decrement_switch_return_chain_8616", lambda *_args: False)
    monkeypatch.setattr(post_stage, "_ordered_32bit_selector_return_expr_pairs_from_cfg_8616", lambda *_args: [])
    monkeypatch.setattr(
        post_stage,
        "_ordered_conditional_return_expr_pairs_from_cfg_8616",
        lambda *_args: [(condition_call, _const(1, codegen), _const(255, codegen))],
    )
    monkeypatch.setattr(post_stage, "_selector_function_has_unsafe_effects_8616", fake_has_unsafe_effects)

    changed = post_stage._materialize_cfg_selector_return_branches_8616(project, codegen)

    assert changed is True
    assert captured["allowed_call_addrs"] == frozenset({0x1013})
    assert codegen._inertia_return_expr_chain_materialized_8616 is True


def test_void_tail_call_guard_repair_moves_cfg_proven_call_into_if_body(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    cond = _const(1, codegen)
    empty_return_body = CStatements(statements=[CReturn(None, codegen=codegen)], codegen=codegen)
    tail_call = CFunctionCall("outp", None, [_const(97, codegen)], codegen=codegen)
    root = CStatements(
        statements=[
            CIfElse([(cond, empty_return_body)], else_node=None, cstyle_ifs=True, codegen=codegen),
            CReturn(tail_call, codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    monkeypatch.setattr(post_stage, "_codegen_has_explicit_void_return_8616", lambda _project, _codegen: True)
    monkeypatch.setattr(
        post_stage,
        "_ordered_conditional_void_tail_call_proofs_from_cfg_8616",
        lambda _project, _codegen: [(cond, _const(97, codegen))],
    )

    changed = post_stage._materialize_void_tail_call_guard_from_cfg_8616(project, codegen)

    assert changed is True
    assert len(root.statements) == 1
    repaired_if = root.statements[0]
    repaired_body = repaired_if.condition_and_nodes[0][1]
    assert [statement.expr for statement in repaired_body.statements] == [tail_call]
    assert codegen._inertia_void_tail_call_guard_stats_8616 == {
        "candidates": 1,
        "materialized": 1,
        "refused": 0,
    }


def test_void_tail_call_guard_repair_handles_else_node_tail_call(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    cond = _const(1, codegen)
    empty_return_body = CStatements(statements=[CReturn(None, codegen=codegen)], codegen=codegen)
    tail_call = CFunctionCall("outp", None, [_const(97, codegen)], codegen=codegen)
    else_body = CStatements(statements=[CReturn(tail_call, codegen=codegen)], codegen=codegen)
    root = CStatements(
        statements=[
            CIfElse([(cond, empty_return_body)], else_node=else_body, cstyle_ifs=True, codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    monkeypatch.setattr(post_stage, "_codegen_has_explicit_void_return_8616", lambda _project, _codegen: True)
    monkeypatch.setattr(
        post_stage,
        "_ordered_conditional_void_tail_call_proofs_from_cfg_8616",
        lambda _project, _codegen: [(cond, _const(97, codegen))],
    )

    changed = post_stage._materialize_void_tail_call_guard_from_cfg_8616(project, codegen)

    assert changed is True
    repaired_if = root.statements[0]
    assert repaired_if.else_node is None
    repaired_body = repaired_if.condition_and_nodes[0][1]
    assert [statement.expr for statement in repaired_body.statements] == [tail_call]


def test_void_tail_call_guard_repair_handles_wrapped_else_tail_call(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    cond = _const(1, codegen)
    empty_return_body = CStatements(statements=[CReturn(None, codegen=codegen)], codegen=codegen)
    tail_call = CFunctionCall("outp", None, [_const(97, codegen)], codegen=codegen)
    else_body = CStatements(
        statements=[
            CStatements(statements=[], codegen=codegen),
            CStatements(statements=[CReturn(tail_call, codegen=codegen)], codegen=codegen),
        ],
        codegen=codegen,
    )
    root = CStatements(
        statements=[
            CIfElse([(cond, empty_return_body)], else_node=else_body, cstyle_ifs=True, codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    monkeypatch.setattr(post_stage, "_codegen_has_explicit_void_return_8616", lambda _project, _codegen: True)
    monkeypatch.setattr(
        post_stage,
        "_ordered_conditional_void_tail_call_proofs_from_cfg_8616",
        lambda _project, _codegen: [(cond, _const(97, codegen))],
    )

    changed = post_stage._materialize_void_tail_call_guard_from_cfg_8616(project, codegen)

    assert changed is True
    repaired_if = root.statements[0]
    assert repaired_if.else_node is None
    repaired_body = repaired_if.condition_and_nodes[0][1]
    assert [statement.expr for statement in repaired_body.statements] == [tail_call]


def test_void_tail_call_guard_repair_preserves_setup_sequence(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    cond = _const(1, codegen)
    empty_return_body = CStatements(statements=[CReturn(None, codegen=codegen)], codegen=codegen)
    setup_a = post_stage.CAssignment(
        CVariable(SimStackVariable(-2, 2, base="bp", name="tmp_a"), codegen=codegen),
        _const(97, codegen),
        codegen=codegen,
    )
    setup_b = post_stage.CAssignment(
        CVariable(SimStackVariable(-4, 2, base="bp", name="tmp_b"), codegen=codegen),
        _const(3, codegen),
        codegen=codegen,
    )
    tail_call = CFunctionCall("outp", None, [_const(97, codegen)], codegen=codegen)
    else_body = CStatements(
        statements=[
            CStatements(
                statements=[
                    setup_a,
                    setup_b,
                    CExpressionStatement(tail_call, codegen=codegen),
                ],
                codegen=codegen,
            ),
            CStatements(statements=[CReturn(None, codegen=codegen)], codegen=codegen),
        ],
        codegen=codegen,
    )
    root = CStatements(
        statements=[
            CIfElse([(cond, empty_return_body)], else_node=else_body, cstyle_ifs=True, codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    monkeypatch.setattr(post_stage, "_codegen_has_explicit_void_return_8616", lambda _project, _codegen: True)
    monkeypatch.setattr(
        post_stage,
        "_ordered_conditional_void_tail_call_proofs_from_cfg_8616",
        lambda _project, _codegen: [(cond, _const(97, codegen))],
    )

    changed = post_stage._materialize_void_tail_call_guard_from_cfg_8616(project, codegen)

    assert changed is True
    repaired_if = root.statements[0]
    assert repaired_if.else_node is None
    repaired_body = repaired_if.condition_and_nodes[0][1]
    assert setup_a in repaired_body.statements
    assert setup_b in repaired_body.statements
    assert any(isinstance(stmt, CExpressionStatement) for stmt in repaired_body.statements)


def test_void_tail_call_guard_repair_accepts_exact_condition_with_unmaterialized_args(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    cond = _const(1, codegen)
    empty_return_body = CStatements(statements=[CReturn(None, codegen=codegen)], codegen=codegen)
    tail_call = CFunctionCall("outp", None, [], codegen=codegen)
    else_body = CStatements(statements=[CReturn(tail_call, codegen=codegen)], codegen=codegen)
    root = CStatements(
        statements=[
            CIfElse([(cond, empty_return_body)], else_node=else_body, cstyle_ifs=True, codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    monkeypatch.setattr(post_stage, "_codegen_has_explicit_void_return_8616", lambda _project, _codegen: True)
    monkeypatch.setattr(
        post_stage,
        "_ordered_conditional_void_tail_call_proofs_from_cfg_8616",
        lambda _project, _codegen: [(cond, _const(97, codegen))],
    )

    changed = post_stage._materialize_void_tail_call_guard_from_cfg_8616(project, codegen)

    assert changed is True
    repaired_if = root.statements[0]
    assert repaired_if.else_node is None
    repaired_body = repaired_if.condition_and_nodes[0][1]
    assert [statement.expr for statement in repaired_body.statements] == [tail_call]


def test_void_tail_call_guard_repair_inverts_cfg_proven_suffix_diamond(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    cond = _const(1, codegen)
    false_call = CFunctionCall("sleep", None, [_const(30, codegen)], codegen=codegen)
    false_body = CStatements(
        statements=[
            CExpressionStatement(false_call, codegen=codegen),
            CReturn(None, codegen=codegen),
        ],
        codegen=codegen,
    )
    setup = post_stage.CAssignment(
        CVariable(SimStackVariable(-2, 2, base="bp", name="tmp"), codegen=codegen),
        _const(97, codegen),
        codegen=codegen,
    )
    true_call = CFunctionCall("outp", None, [_const(97, codegen), _const(3, codegen)], codegen=codegen)
    true_sleep = CFunctionCall("sleep", None, [_const(25, codegen)], codegen=codegen)
    root = CStatements(
        statements=[
            CIfElse([(cond, false_body)], else_node=None, cstyle_ifs=True, codegen=codegen),
            setup,
            CExpressionStatement(true_call, codegen=codegen),
            CExpressionStatement(true_sleep, codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    monkeypatch.setattr(post_stage, "_codegen_has_explicit_void_return_8616", lambda _project, _codegen: True)
    monkeypatch.setattr(
        post_stage,
        "_ordered_conditional_void_tail_call_proofs_from_cfg_8616",
        lambda _project, _codegen: [(cond, _const(97, codegen))],
    )

    changed = post_stage._materialize_void_tail_call_guard_from_cfg_8616(project, codegen)

    assert changed is True
    assert len(root.statements) == 1
    repaired_if = root.statements[0]
    true_body = repaired_if.condition_and_nodes[0][1]
    assert len(true_body.statements) == 3
    assert true_body.statements[0] is setup
    assert true_body.statements[1].expr is true_call
    assert true_body.statements[2].expr is true_sleep
    assert repaired_if.else_node is false_body


def test_void_tail_call_guard_suffix_diamond_refuses_non_void_return(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    cond = _const(1, codegen)
    false_body = CStatements(statements=[CReturn(_const(0, codegen), codegen=codegen)], codegen=codegen)
    true_call = CFunctionCall("outp", None, [_const(97, codegen)], codegen=codegen)
    true_return = CReturn(true_call, codegen=codegen)
    root = CStatements(
        statements=[
            CIfElse([(cond, false_body)], else_node=None, cstyle_ifs=True, codegen=codegen),
            true_return,
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    monkeypatch.setattr(post_stage, "_codegen_has_explicit_void_return_8616", lambda _project, _codegen: False)
    monkeypatch.setattr(
        post_stage,
        "_ordered_conditional_void_tail_call_proofs_from_cfg_8616",
        lambda _project, _codegen: [(cond, _const(97, codegen))],
    )

    changed = post_stage._materialize_void_tail_call_guard_from_cfg_8616(project, codegen)

    assert changed is False
    assert root.statements[0].condition_and_nodes[0][1] is false_body
    assert root.statements[1] is true_return
    assert codegen._inertia_void_tail_call_guard_decision_8616 == "keep_not_void"
    assert codegen._inertia_void_tail_call_guard_stats_8616 == {
        "candidates": 1,
        "materialized": 0,
        "refused": 1,
    }


def test_cfg_selector_return_delta_accepts_proven_stack_probe_helper_cleanup():
    cond_fp = "CmpGE(stack_slot:SS:BP+0x6:size2,stack_slot:SS:BP+0x4:size2)"
    codegen = SimpleNamespace(
        _inertia_return_expr_chain_materialized_8616=True,
        _inertia_return_selector_materialized_8616=True,
        _inertia_return_expr_chain_materialized_return_fingerprints_8616=(
            "stack_slot:SS:BP+0x4:size2",
            "stack_slot:SS:BP+0x6:size2",
        ),
        _inertia_return_chain_materialized_condition_fingerprints_8616=(cond_fp,),
        _inertia_stack_probe_helper_target_fingerprints_8616=("addr:0xd5d2",),
        _inertia_stack_probe_fact_stats={"stack_probe_summaries": 1},
    )
    validation = {
        "delta": {
            "helper_calls": {"added": (), "removed": ("addr:0xd5d2",)},
            "returns": {"added": ("stack_slot:SS:BP+0x4:size2",), "removed": ("CDirtyExpression",)},
            "conditions": {"added": (cond_fp,), "removed": ()},
            "control_flow_effects": {"added": (f"if:{cond_fp}",), "removed": ()},
        }
    }

    assert _is_cfg_return_expr_chain_materialization_delta_8616(
        SimpleNamespace(arch=Arch86_16()),
        SimpleNamespace(),
        codegen,
        validation,
    )


def test_cfg_selector_return_delta_accepts_condition_only_selector_materialization():
    cond_fp = "CmpNE(call:addr:0xe69(const:65534,const:5),const:-1)"
    codegen = SimpleNamespace(
        _inertia_return_expr_chain_materialized_8616=True,
        _inertia_return_selector_materialized_8616=True,
        _inertia_return_expr_chain_materialized_return_fingerprints_8616=("const:1", "const:255"),
        _inertia_return_chain_materialized_condition_fingerprints_8616=(cond_fp,),
        _inertia_stack_probe_helper_target_fingerprints_8616=(),
        _inertia_stack_probe_fact_stats={},
    )
    validation = {
        "delta": {
            "conditions": {"added": (cond_fp,), "removed": ()},
            "control_flow_effects": {"added": (f"if:{cond_fp}",), "removed": ()},
        }
    }

    assert _is_cfg_return_expr_chain_materialization_delta_8616(
        SimpleNamespace(arch=Arch86_16()),
        SimpleNamespace(),
        codegen,
        validation,
    )


def test_cfg_selector_return_delta_accepts_structuring_push_store_removal():
    returns = ("const:1", "const:2", "const:255")
    codegen = SimpleNamespace(
        _inertia_return_expr_chain_materialized_8616=True,
        _inertia_return_selector_materialized_8616=True,
        _inertia_return_expr_chain_materialized_return_fingerprints_8616=returns,
        _inertia_return_chain_materialized_condition_fingerprints_8616=(
            "CmpNE(call:addr:0xe69(const:65534,const:5),const:-1)",
            "CmpNE(call:addr:0xe69(const:9,const:3),const:1)",
        ),
        _inertia_stack_probe_helper_target_fingerprints_8616=(),
        _inertia_stack_probe_fact_stats={},
    )
    validation = {
        "delta": {
            "segmented_writes": {
                "added": (),
                "removed": (
                    "deref:Add(Mul(reg:ss,const:16),reg:sp,const:-2)",
                    "deref:Add(Mul(reg:ss,const:16),reg:sp,const:-4)",
                ),
            },
            "returns": {"added": returns, "removed": ("reg:ax",)},
            "conditions": {"added": ("CmpNE(call:addr:0xe69(const:65534,const:5),const:1)",), "removed": ()},
            "control_flow_effects": {
                "added": ("if:CmpNE(call:addr:0xe69(const:65534,const:5),const:1)",),
                "removed": ("if-else-body-calls:else:addr:0x10010", "if:else"),
            },
        }
    }

    assert _is_cfg_return_expr_chain_materialization_delta_8616(
        SimpleNamespace(arch=Arch86_16()),
        SimpleNamespace(),
        codegen,
        validation,
    )


def test_cfg_selector_return_delta_refuses_unproven_helper_cleanup():
    cond_fp = "CmpGE(stack_slot:SS:BP+0x6:size2,stack_slot:SS:BP+0x4:size2)"
    codegen = SimpleNamespace(
        _inertia_return_expr_chain_materialized_8616=True,
        _inertia_return_selector_materialized_8616=True,
        _inertia_return_expr_chain_materialized_return_fingerprints_8616=(
            "stack_slot:SS:BP+0x4:size2",
            "stack_slot:SS:BP+0x6:size2",
        ),
        _inertia_return_chain_materialized_condition_fingerprints_8616=(cond_fp,),
        _inertia_stack_probe_helper_target_fingerprints_8616=(),
        _inertia_stack_probe_fact_stats={},
    )
    validation = {
        "delta": {
            "helper_calls": {"added": (), "removed": ("addr:0xd5d2",)},
            "returns": {"added": ("stack_slot:SS:BP+0x4:size2",), "removed": ("CDirtyExpression",)},
            "conditions": {"added": (cond_fp,), "removed": ()},
            "control_flow_effects": {"added": (f"if:{cond_fp}",), "removed": ()},
        }
    }

    assert not _is_cfg_return_expr_chain_materialization_delta_8616(
        SimpleNamespace(arch=Arch86_16()),
        SimpleNamespace(),
        codegen,
        validation,
    )


def test_cfg_selector_return_delta_accepts_raw_stack_slot_consumed_as_source_arg(monkeypatch):
    dummy_codegen = _DummyCodegen()
    project = dummy_codegen.project
    arg_b_var = SimStackVariable(6, 2, base="bp", name="b")
    arg_b = CVariable(arg_b_var, codegen=dummy_codegen)
    cond = _const(1, dummy_codegen)
    body = CStatements(statements=[CReturn(arg_b, codegen=dummy_codegen)], codegen=dummy_codegen)
    root = CStatements(
        statements=[CIfElse([(cond, body)], else_node=None, cstyle_ifs=True, codegen=dummy_codegen)],
        codegen=dummy_codegen,
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(arg_list=(arg_b,), statements=root),
        _inertia_return_expr_chain_materialized_8616=True,
        _inertia_return_selector_materialized_8616=True,
        _inertia_return_expr_chain_materialized_return_fingerprints_8616=("stack_arg:b:size2",),
        _inertia_return_chain_materialized_condition_fingerprints_8616=("CmpNE(stack_arg:b:size2,const:0)",),
        _inertia_stack_probe_helper_target_fingerprints_8616=(),
        _inertia_stack_probe_fact_stats={},
    )
    validation = {
        "delta": {
            "returns": {
                "added": ("stack_arg:b:size2",),
                "removed": ("stack_slot:SS:BP+0x6:size2",),
            },
            "conditions": {
                "added": ("CmpNE(stack_arg:which:size2,const:0)",),
                "removed": ("CmpNE(stack_arg:b:size2,const:0)",),
            },
            "control_flow_effects": {
                "added": ("if:CmpNE(stack_arg:which:size2,const:0)",),
                "removed": ("if:CmpNE(stack_arg:b:size2,const:0)",),
            },
        }
    }

    def fake_expr_fingerprint(expr, _project):
        if expr is arg_b:
            return "stack_arg:b:size2"
        if expr is cond:
            return "CmpNE(stack_arg:which:size2,const:0)"
        return "<unexpected>"

    monkeypatch.setattr(post_stage, "_expr_fingerprint", fake_expr_fingerprint)

    assert _is_cfg_return_expr_chain_materialization_delta_8616(
        project,
        None,
        codegen,
        validation,
    )


def test_cfg_selector_return_delta_accepts_source_view_stack_bias_alias():
    codegen = SimpleNamespace(
        _inertia_return_expr_chain_materialized_8616=True,
        _inertia_return_selector_materialized_8616=True,
        _inertia_return_selector_raw_stack_slot_aliases_8616={
            "stack_arg:x:size2": (
                "stack_slot:SS:BP+0x4:size2",
                "stack_slot:SS:BP+0x8:size2",
            ),
        },
        _inertia_return_expr_chain_materialized_return_fingerprints_8616=(
            "Add(stack_arg:x:size2,const:-5)",
            "Add(stack_arg:x:size2,const:20)",
            "Shl(stack_arg:x:size2,const:1)",
            "const:10",
        ),
        _inertia_return_chain_materialized_condition_fingerprints_8616=(
            "CmpEQ(stack_arg:x:size2,const:0)",
            "CmpLT(stack_arg:x:size2,const:1)",
            "CmpLE(stack_arg:x:size2,const:2)",
            "CmpEQ(stack_arg:x:size2,const:3)",
        ),
        _inertia_stack_probe_helper_target_fingerprints_8616=(),
        _inertia_stack_probe_fact_stats={},
    )
    validation = {
        "delta": {
            "returns": {
                "added": (
                    "Add(stack_arg:x:size2,const:-5)",
                    "Add(stack_arg:x:size2,const:20)",
                    "Shl(stack_arg:x:size2,const:1)",
                ),
                "removed": (
                    "Add(stack_arg:x:size2,const:-1)",
                    "Add(stack_slot:SS:BP+0x8:size2,const:20)",
                ),
            },
        }
    }

    assert _is_cfg_return_expr_chain_materialization_delta_8616(
        SimpleNamespace(arch=Arch86_16()),
        None,
        codegen,
        validation,
    )


def test_after_call_stack_lowering_rerun_is_single_round(monkeypatch):
    captured = {}

    def fake_run_stack_lowering_pass_8616(**kwargs):
        captured.update(kwargs)
        return False

    monkeypatch.setattr(post_stage, "run_stack_lowering_pass_8616", fake_run_stack_lowering_pass_8616)

    codegen = SimpleNamespace()
    changed = post_stage._rerun_stack_lowering_consumers_after_calls_8616(SimpleNamespace(), codegen)

    assert changed is False
    assert captured["max_rounds"] == 1
    assert captured["lower_global_segment_accesses"] is False
    assert captured["lower_runtime_segment_accesses"] is True
    assert captured["codegen"]._inertia_stack_lowering_after_call_canonicalize_budget_8616 == 16
    assert not hasattr(codegen, "_inertia_stack_lowering_canonicalize_max_depth_8616")


def test_pre_validation_stack_prime_refuses_materialized_pointer_memory(monkeypatch):
    def unexpected_alias_transfer(*_args, **_kwargs):
        raise AssertionError("postprocess priming must not reverse typed pointer lowering")

    monkeypatch.setattr(post_stage, "transfer_semantic_alias_facts_to_codegen_8616", unexpected_alias_transfer)
    monkeypatch.setattr(post_stage, "_invalidate_tail_validation_derived_caches_8616", lambda _codegen: None)
    codegen = SimpleNamespace(_inertia_pointer_memory_materialized_8616="pointer_swap")

    changed = post_stage._prime_stack_semantics_before_validation_baseline_8616(SimpleNamespace(), codegen)

    assert changed is False
    assert codegen._inertia_pre_validation_stack_semantics_refused_pointer_memory_8616 == 1
    assert codegen._inertia_pre_validation_stack_semantics_primed is True


def test_pre_validation_segment_global_replay_runs_after_ast_regeneration(monkeypatch):
    calls: list[tuple[object, object, object, object | None, bool]] = []
    order: list[str] = []
    invalidated: list[object] = []
    cod_metadata = object()

    def replay(project, codegen, synthetic_globals, *, cod_metadata=None, include_runtime_segment=False):
        order.append("lowering")
        calls.append((project, codegen, synthetic_globals, cod_metadata, include_runtime_segment))
        return SimpleNamespace(changed=True)

    monkeypatch.setattr(
        post_stage,
        "replay_codegen_structured_condition_segment_provenance_8616",
        lambda _codegen: order.append("provenance") or SimpleNamespace(changed=False),
    )
    monkeypatch.setattr(post_stage, "run_segment_global_materialization_8616", replay)
    monkeypatch.setattr(post_stage, "cod_metadata_for_codegen_8616", lambda *_args: cod_metadata)
    monkeypatch.setattr(
        post_stage,
        "_invalidate_tail_validation_derived_caches_8616",
        invalidated.append,
    )
    synthetic_globals = object()
    codegen = SimpleNamespace(_inertia_pointer_memory_materialized_8616="pointer_swap")
    project = SimpleNamespace(_inertia_synthetic_globals=synthetic_globals)

    changed = post_stage._replay_segment_global_lowering_before_validation_baseline_8616(project, codegen)

    assert changed is True
    assert order == ["provenance", "lowering"]
    assert calls == [(project, codegen, synthetic_globals, cod_metadata, True)]
    assert invalidated == [codegen]
    assert codegen._inertia_pre_validation_segment_global_lowering_replayed_8616 is True


def test_pre_validation_segment_global_replay_is_single_round(monkeypatch):
    calls: list[object] = []

    def replay(project, codegen, synthetic_globals, **_kwargs):
        del project, synthetic_globals
        calls.append(codegen)
        return SimpleNamespace(changed=False)

    monkeypatch.setattr(post_stage, "run_segment_global_materialization_8616", replay)
    monkeypatch.setattr(post_stage, "cod_metadata_for_codegen_8616", lambda *_args: None)
    codegen = SimpleNamespace()
    project = SimpleNamespace()

    assert post_stage._replay_segment_global_lowering_before_validation_baseline_8616(project, codegen) is False
    assert post_stage._replay_segment_global_lowering_before_validation_baseline_8616(project, codegen) is False
    assert calls == [codegen]


def test_after_call_stack_lowering_rerun_large_function_uses_byte_only_path(monkeypatch):
    import inertia_decompiler.cli_c_ast_rewrites as ast_rewrites

    def fake_run_stack_lowering_pass_8616(**_kwargs):
        raise AssertionError("large function must not run broad stack lowering rerun")

    calls: list[str] = []

    def fake_rewrite_ss_stack_byte_offsets(_project, _codegen):
        calls.append("byte-only")
        return True

    monkeypatch.setattr(post_stage, "run_stack_lowering_pass_8616", fake_run_stack_lowering_pass_8616)
    monkeypatch.setattr(ast_rewrites, "_rewrite_ss_stack_byte_offsets", fake_rewrite_ss_stack_byte_offsets)

    codegen = SimpleNamespace(_inertia_skip_per_pass_validation_large_function=True)
    changed = post_stage._rerun_stack_lowering_consumers_after_calls_8616(SimpleNamespace(), codegen)

    assert changed is True
    assert calls == ["byte-only"]
    assert codegen._inertia_stack_lowering_large_function_byte_only_8616 == 1


def test_after_call_stack_lowering_rerun_large_ast_uses_byte_only_path(monkeypatch):
    import inertia_decompiler.cli_c_ast_rewrites as ast_rewrites

    def fake_run_stack_lowering_pass_8616(**_kwargs):
        raise AssertionError("large AST must not run broad stack lowering rerun")

    calls: list[str] = []

    def fake_rewrite_ss_stack_byte_offsets(_project, _codegen):
        calls.append("byte-only")
        return True

    monkeypatch.setattr(post_stage, "run_stack_lowering_pass_8616", fake_run_stack_lowering_pass_8616)
    monkeypatch.setattr(ast_rewrites, "_rewrite_ss_stack_byte_offsets", fake_rewrite_ss_stack_byte_offsets)

    codegen = _DummyCodegen()
    root = CStatements(
        [CExpressionStatement(_const(index, codegen), codegen=codegen) for index in range(1301)],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(statements=root, body=root)

    changed = post_stage._rerun_stack_lowering_consumers_after_calls_8616(SimpleNamespace(), codegen)

    assert changed is True
    assert calls == ["byte-only"]
    assert codegen._inertia_stack_lowering_rerun_ast_large_byte_only_8616 == 1
    assert codegen._inertia_stack_lowering_rerun_ast_node_count_8616 > 1200


def test_after_call_stack_lowering_rerun_refuses_selector_return_contract(monkeypatch):
    def fake_run_stack_lowering_pass_8616(**_kwargs):
        raise AssertionError("stack lowering rerun must not run after selector-return materialization")

    monkeypatch.setattr(post_stage, "run_stack_lowering_pass_8616", fake_run_stack_lowering_pass_8616)
    codegen = SimpleNamespace(
        _inertia_return_selector_materialized_8616=True,
        _inertia_postprocess_validation_failed=False,
    )

    changed = post_stage._rerun_stack_lowering_consumers_after_calls_8616(SimpleNamespace(), codegen)

    assert changed is False
    assert codegen._inertia_stack_lowering_rerun_refused_selector_return_8616 == 1


def test_after_call_stack_lowering_rerun_refuses_materialized_pointer_memory(monkeypatch):
    def fake_run_stack_lowering_pass_8616(**_kwargs):
        raise AssertionError("late stack lowering must not rewrite typed pointer memory")

    monkeypatch.setattr(post_stage, "run_stack_lowering_pass_8616", fake_run_stack_lowering_pass_8616)
    codegen = SimpleNamespace(_inertia_pointer_memory_materialized_8616="pointer_swap")

    changed = post_stage._rerun_stack_lowering_consumers_after_calls_8616(SimpleNamespace(), codegen)

    assert changed is False
    assert codegen._inertia_stack_lowering_rerun_refused_pointer_memory_8616 == 1


def test_after_call_stack_lowering_rerun_refuses_callsite_cache_hit():
    def fake_run_stack_lowering_pass_8616(**_kwargs):
        raise AssertionError("cache-hit should skip stack-lowering rerun")

    original = post_stage.run_stack_lowering_pass_8616
    post_stage.run_stack_lowering_pass_8616 = fake_run_stack_lowering_pass_8616
    try:
        codegen = SimpleNamespace(
            _inertia_callsite_materialization_last_decision_8616=CallsiteMaterializationDecision8616.CACHE_HIT,
            _inertia_callsite_materialization_last_changed_8616=False,
        )
        changed = post_stage._rerun_stack_lowering_consumers_after_calls_8616(SimpleNamespace(), codegen)

        assert changed is False
        assert codegen._inertia_stack_lowering_rerun_refused_callsite_cache_hit_8616 == 1
    finally:
        post_stage.run_stack_lowering_pass_8616 = original


def test_after_call_stack_lowering_rerun_skips_processed_no_change_without_gaps(monkeypatch):
    def fake_run_stack_lowering_pass_8616(**_kwargs):
        raise AssertionError("completed no-change callsite materialization should skip stack-lowering rerun")

    monkeypatch.setattr(post_stage, "run_stack_lowering_pass_8616", fake_run_stack_lowering_pass_8616)
    codegen = SimpleNamespace(
        _inertia_callsite_materialization_complete_8616=True,
        _inertia_callsite_materialization_last_decision_8616=CallsiteMaterializationDecision8616.PROCESSED_NO_CHANGE,
        _inertia_callsite_materialization_last_changed_8616=False,
        _inertia_callsite_unmaterialized_arg_gaps_8616=(),
    )

    changed = post_stage._rerun_stack_lowering_consumers_after_calls_8616(SimpleNamespace(), codegen)

    assert changed is False
    assert codegen._inertia_stack_lowering_rerun_skipped_callsite_no_input_8616 == 1


def test_after_call_stack_lowering_rerun_keeps_gapped_processed_no_change(monkeypatch):
    captured = {}

    def fake_run_stack_lowering_pass_8616(**kwargs):
        captured.update(kwargs)
        return False

    monkeypatch.setattr(post_stage, "run_stack_lowering_pass_8616", fake_run_stack_lowering_pass_8616)
    codegen = SimpleNamespace(
        _inertia_callsite_materialization_complete_8616=True,
        _inertia_callsite_materialization_last_decision_8616=CallsiteMaterializationDecision8616.PROCESSED_NO_CHANGE,
        _inertia_callsite_materialization_last_changed_8616=False,
        _inertia_callsite_unmaterialized_arg_gaps_8616=({"kind": "summary_arg_proof_unconsumed"},),
    )

    changed = post_stage._rerun_stack_lowering_consumers_after_calls_8616(SimpleNamespace(), codegen)

    assert changed is False
    assert captured["max_rounds"] == 1
    assert not hasattr(codegen, "_inertia_stack_lowering_rerun_skipped_callsite_no_input_8616")


def test_postprocess_scheduler_skips_stack_identity_passes_after_selector_return():
    calls = []
    project = SimpleNamespace()
    codegen = SimpleNamespace(
        _inertia_return_selector_materialized_8616=True,
        _inertia_postprocess_validation_failed=False,
    )
    pass_specs = (
        post_stage.DecompilerPostprocessPassSpec(
            "_apply_annotations_8616",
            lambda _project, _codegen: calls.append("bad_annotation_pass") or True,
            True,
        ),
        post_stage.DecompilerPostprocessPassSpec(
            "_promote_stack_prototype_from_bp_loads_8616",
            lambda _project, _codegen: calls.append("bad_stack_identity_pass") or True,
            True,
        ),
        post_stage.DecompilerPostprocessPassSpec(
            "_materialize_callsite_stack_arguments_8616",
            lambda _project, _codegen: calls.append("bad_callsite_pass") or True,
            True,
        ),
        post_stage.DecompilerPostprocessPassSpec(
            "_rerun_stack_lowering_consumers_after_calls_8616",
            lambda _project, _codegen: calls.append("stack_rerun_pass") or True,
            True,
        ),
        post_stage.DecompilerPostprocessPassSpec(
            "_unit_test_unrelated_cleanup_8616",
            lambda _codegen: calls.append("unrelated_cleanup") or False,
            False,
        ),
    )

    post_stage._postprocess_run_pass_specs_8616(
        project,
        codegen,
        pass_specs,
        None,
        lambda name, step: calls.append(name) or step(),
    )

    assert calls == [
        "_rerun_stack_lowering_consumers_after_calls_8616",
        "stack_rerun_pass",
        "_unit_test_unrelated_cleanup_8616",
        "unrelated_cleanup",
    ]
    assert codegen._inertia_postprocess_selector_return_skipped_passes_8616 == (
        "_apply_annotations_8616",
        "_promote_stack_prototype_from_bp_loads_8616",
        "_materialize_callsite_stack_arguments_8616",
    )


def test_postprocess_scheduler_disables_direct_call_floor_recovery_by_default(monkeypatch):
    monkeypatch.delenv("INERTIA_ENABLE_DIRECT_CALL_FLOOR_RECOVERY", raising=False)

    pass_names = {
        spec.name
        for spec in post_stage._decompiler_postprocess_passes_for_function(
            SimpleNamespace(),
            SimpleNamespace(),
        )
    }

    assert "_recover_missing_direct_calls_from_evidence_early_8616" not in pass_names
    assert "_recover_missing_direct_calls_from_evidence_8616" not in pass_names
    assert "_recover_missing_direct_calls_final_8616" not in pass_names


def test_postprocess_scheduler_allows_explicit_direct_call_floor_rescue(monkeypatch):
    monkeypatch.setenv("INERTIA_ENABLE_DIRECT_CALL_FLOOR_RECOVERY", "1")

    pass_names = {
        spec.name
        for spec in post_stage._decompiler_postprocess_passes_for_function(
            SimpleNamespace(),
            SimpleNamespace(),
        )
    }

    assert "_recover_missing_direct_calls_from_evidence_early_8616" in pass_names
    assert "_recover_missing_direct_calls_from_evidence_8616" in pass_names
    assert "_recover_missing_direct_calls_final_8616" in pass_names
