from __future__ import annotations

import importlib
from types import SimpleNamespace

import angr_platforms.X86_16.tail_validation as tail_validation_module
import angr_platforms.X86_16.tail_validation_condition_context as condition_context_module
import angr_platforms.X86_16.tail_validation_fingerprint as tail_validation_fingerprint_module
import pytest
from angr.ailment.expression import VirtualVariable, VirtualVariableCategory
from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CContinue,
    CDirtyExpression,
    CDoWhileLoop,
    CExpressionStatement,
    CForLoop,
    CFunctionCall,
    CIfBreak,
    CIfElse,
    CIndexedVariable,
    CReturn,
    CStatements,
    CSwitchCase,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeInt, SimTypePointer, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16 import decompiler_postprocess_stage as postprocess_stage
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import (
    CallerReturnUseEvidence8616,
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
    CallsiteSummary8616,
    record_caller_return_use_evidence_8616,
)
from angr_platforms.X86_16.lowering.call_output_stack_objects import (
    CallOutputStackObjectFact8616,
)
from angr_platforms.X86_16.lowering.segmented_global_loads import (
    DwordGlobalZeroTestEvidence8616,
    IndexedSegmentedGlobalEvidence8616,
    IndexedSegmentedGlobalStoreEvidence8616,
)
from angr_platforms.X86_16.postprocess import pass_validation_policy
from angr_platforms.X86_16.structuring.loop_break_jcc import (
    LoopHeaderDuplicateGuardRemovalFact8616,
)
from angr_platforms.X86_16.tail_validation import (
    X86_16TailValidationSummary,
    X86_16ValidationCacheDescriptor,
    annotate_x86_16_tail_validation_surface_with_baseline,
    build_x86_16_tail_validation_aggregate,
    build_x86_16_tail_validation_baseline,
    build_x86_16_tail_validation_cached_result,
    build_x86_16_tail_validation_surface,
    build_x86_16_tail_validation_verdict,
    build_x86_16_validation_cache_descriptor,
    callsite_consumed_stack_store_prune_delta_8616,
    callsite_far_pointer_remnant_prune_delta_8616,
    callsite_helper_control_target_delta_8616,
    callsite_mixed_helper_stack_control_delta_8616,
    callsite_resolved_indirect_helper_control_delta_8616,
    callsite_resolved_indirect_helper_stack_delta_8616,
    callsite_stack_arg_slot_alias_condition_delta_8616,
    callsite_stack_precision_control_delta_8616,
    check_x86_16_tail_validation_surface_consistency,
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_baseline,
    compare_x86_16_tail_validation_summaries,
    conditional_continue_guard_repair_delta_8616,
    describe_x86_16_tail_validation_scope,
    direct_stack_move_function_pointer_prune_delta_8616,
    direct_stack_move_idiv_remainder_aux_delta_8616,
    dword_global_zero_test_precision_delta_8616,
    exit_goto_repair_delta_8616,
    extract_x86_16_tail_validation_snapshot,
    fingerprint_x86_16_tail_validation_boundary,
    format_x86_16_tail_validation_diff,
    indexed_segmented_global_precision_delta_8616,
    loop_header_duplicate_guard_removal_delta_8616,
    name_only_helper_annotation_delta_8616,
    persist_x86_16_tail_validation_snapshot,
    resolve_x86_16_validation_cached_artifact,
    segmented_stack_slot_size_precision_delta_8616,
    summarize_x86_16_tail_validation_records,
    switch_loop_exit_return_repair_delta_8616,
    validation_delta_removes_stack_or_control_effects_8616,
    validation_delta_touched_fields_8616,
    validation_stack_offsets_in_token_8616,
    validation_stack_write_delta_offsets_are_evidenced_8616,
    validation_without_delta_fields_8616,
    void_tail_call_guard_materialization_delta_8616,
    x86_16_tail_validation_result_passed,
    x86_16_tail_validation_snapshot_passed,
)
from angr_platforms.X86_16.tail_validation_condition_context import build_x86_16_contextual_condition_fingerprints
from angr_platforms.X86_16.tail_validation_fingerprint import build_x86_16_contextual_call_fingerprints
from angr_platforms.X86_16.tail_validation_stack_policy import include_x86_16_tail_validation_stack_write

from inertia_decompiler.tail_validation import tail_validation_snapshot_for_function_run


class _DummyCodegen:
    def __init__(self):
        self._idx = 0
        self.cfunc = None
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def test_call_output_definitions_rebind_regenerated_call_by_exact_tag() -> None:
    """Tail validation must consume exact call-output facts after AST cloning."""
    codegen = _DummyCodegen()
    output_variable = SimStackVariable(
        -8,
        4,
        base="bp",
        name="output",
        region=0x1000,
    )
    output_cvar = CVariable(
        output_variable,
        variable_type=SimTypeBottom(),
        codegen=codegen,
    )
    call = CFunctionCall(
        CConstant(0x3000, SimTypeShort(False), codegen=codegen),
        None,
        [CUnaryOp("Reference", output_cvar, codegen=codegen)],
        tags={"ins_addr": 0x1035},
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=CStatements(
            [CExpressionStatement(call, codegen=codegen)],
            codegen=codegen,
        )
    )
    summary = CallsiteSummary8616(
        callsite_addr=0x1035,
        target_addr=0x3000,
        return_addr=0x103A,
        kind="direct_far",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register=None,
        return_used=False,
        push_arg_sources=(("seg", "ss"), ("bp_addr", -8)),
    )
    codegen._inertia_callsite_summaries = {0xDEAD: summary}
    codegen._inertia_callsite_summary_inventory_8616 = {
        summary.callsite_addr: summary,
    }
    codegen._inertia_call_output_stack_object_facts_8616 = (
        CallOutputStackObjectFact8616(
            callsite_addr=summary.callsite_addr,
            base_offset=-8,
            boundary_offset=-4,
            base_variable=output_variable,
            base_cvar=output_cvar,
            fields=(),
        ),
    )

    definitions = tail_validation_module._def_use_call_output_definitions_8616(
        codegen,
    )

    assert definitions == {
        id(call): (
            tail_validation_module.DefUseCallOutputDefinition8616(
                base_offset=-8,
                width=4,
            ),
        ),
    }


def _project():
    return SimpleNamespace(arch=Arch86_16())


def _postprocess_cfunc(**fields):
    """Build the complete cfunc boundary required by postprocess-stage tests."""
    return SimpleNamespace(
        functy=None,
        statements=None,
        body=None,
        variables_in_use={},
        unified_local_vars={},
        **fields,
    )


def test_conditional_continue_guard_repair_delta_accepts_removed_ifbreak_and_condition():
    validation = {
        "delta": {
            "conditions": {"added": (), "removed": ("CmpNE(reg:ax,const:0)",)},
            "control_flow_effects": {"added": (), "removed": ("ifbreak:CmpNE(reg:ax,const:0)",)},
        }
    }

    assert conditional_continue_guard_repair_delta_8616(1, validation)


def test_conditional_continue_guard_repair_delta_requires_materialized_guard():
    validation = {
        "delta": {
            "control_flow_effects": {"added": (), "removed": ("ifbreak:CmpNE(reg:ax,const:0)",)},
        }
    }

    assert not conditional_continue_guard_repair_delta_8616(0, validation)


def test_conditional_continue_guard_repair_delta_refuses_additions_or_unrelated_fields():
    added_condition = {
        "delta": {
            "conditions": {"added": ("CmpNE(reg:ax,const:0)",), "removed": ()},
            "control_flow_effects": {"added": (), "removed": ("ifbreak:CmpNE(reg:ax,const:0)",)},
        }
    }
    helper_delta = {
        "delta": {
            "helper_calls": {"added": (), "removed": ("addr:0x1234",)},
            "control_flow_effects": {"added": (), "removed": ("ifbreak:CmpNE(reg:ax,const:0)",)},
        }
    }

    assert not conditional_continue_guard_repair_delta_8616(1, added_condition)
    assert not conditional_continue_guard_repair_delta_8616(1, helper_delta)


def test_loop_header_duplicate_guard_removal_accepts_exact_inverse_guard() -> None:
    facts = (
        LoopHeaderDuplicateGuardRemovalFact8616(
            jcc_addr=0x101D,
            block_addr=0x1013,
            removed_guard_fingerprint="CmpEQ(stack_slot:SS:BP-0x4:size2,const:0)",
            retained_loop_fingerprint="CmpNE(stack_slot:SS:BP-0x4:size2,const:0)",
        ),
    )
    validation = {
        "delta": {
            "control_flow_effects": {
                "added": (),
                "removed": (
                    "ifbreak:CmpEQ(stack_slot:SS:BP-0x4:size2,const:0)",
                ),
            },
        },
    }

    assert loop_header_duplicate_guard_removal_delta_8616(
        facts,
        validation,
    )


def test_loop_header_duplicate_guard_removal_refuses_unrelated_delta() -> None:
    facts = (
        LoopHeaderDuplicateGuardRemovalFact8616(
            jcc_addr=0x101D,
            block_addr=0x1013,
            removed_guard_fingerprint="CmpEQ(stack_slot:SS:BP-0x4:size2,const:0)",
            retained_loop_fingerprint="CmpNE(stack_slot:SS:BP-0x4:size2,const:0)",
        ),
    )
    wrong_guard = {
        "delta": {
            "control_flow_effects": {
                "added": (),
                "removed": (
                    "ifbreak:CmpEQ(stack_slot:SS:BP-0x6:size2,const:0)",
                ),
            },
        },
    }
    call_loss = {
        "delta": {
            "control_flow_effects": {
                "added": (),
                "removed": (
                    "ifbreak:CmpEQ(stack_slot:SS:BP-0x4:size2,const:0)",
                ),
            },
            "helper_calls": {"added": (), "removed": ("addr:0x1234",)},
        },
    }

    assert not loop_header_duplicate_guard_removal_delta_8616(
        facts,
        wrong_guard,
    )
    assert not loop_header_duplicate_guard_removal_delta_8616(
        facts,
        call_loss,
    )


def test_void_tail_call_guard_materialization_delta_accepts_if_body_call_addition_only():
    validation = {
        "delta": {
            "helper_calls": {"added": (), "removed": ()},
            "register_writes": {"added": (), "removed": ()},
            "stack_writes": {"added": (), "removed": ()},
            "global_writes": {"added": (), "removed": ()},
            "segmented_writes": {"added": (), "removed": ()},
            "returns": {"added": (), "removed": ()},
            "conditions": {"added": (), "removed": ()},
            "control_flow_effects": {
                "added": ("if-body-calls:CmpNE(global:0xb46,const:0):addr:0x10e70,addr:0x10f38",),
                "removed": (),
            },
        }
    }

    assert void_tail_call_guard_materialization_delta_8616(1, validation)


def test_void_tail_call_guard_materialization_delta_requires_materialized_guard():
    validation = {
        "delta": {
            "control_flow_effects": {
                "added": ("if-body-calls:CmpNE(global:0xb46,const:0):addr:0x10e70,addr:0x10f38",),
                "removed": (),
            },
        }
    }

    assert not void_tail_call_guard_materialization_delta_8616(0, validation)


def test_void_tail_call_guard_materialization_delta_refuses_observable_or_removed_effects():
    helper_delta = {
        "delta": {
            "helper_calls": {"added": ("addr:0x10f38",), "removed": ()},
            "control_flow_effects": {
                "added": ("if-body-calls:CmpNE(global:0xb46,const:0):addr:0x10e70,addr:0x10f38",),
                "removed": (),
            },
        }
    }
    removed_control = {
        "delta": {
            "control_flow_effects": {
                "added": ("if-body-calls:CmpNE(global:0xb46,const:0):addr:0x10e70,addr:0x10f38",),
                "removed": ("if-body-calls:CmpNE(global:0xb46,const:0):addr:0x10e70",),
            },
        }
    }

    assert not void_tail_call_guard_materialization_delta_8616(1, helper_delta)
    assert not void_tail_call_guard_materialization_delta_8616(1, removed_control)


def test_exit_goto_repair_delta_accepts_single_goto_replaced_by_return():
    validation = {
        "delta": {
            "control_flow_effects": {"added": ("return",), "removed": ("goto:0x1234",)},
            "returns": {"added": ("none",), "removed": ()},
        }
    }

    assert exit_goto_repair_delta_8616(validation)
    assert postprocess_stage._postprocess_exit_goto_repair_delta_8616(validation)


def test_exit_goto_repair_delta_refuses_extra_or_non_goto_control_flow():
    extra_control = {
        "delta": {
            "control_flow_effects": {"added": ("return", "case:const:1"), "removed": ("goto:0x1234",)},
            "returns": {"added": ("none",), "removed": ()},
        }
    }
    non_goto = {
        "delta": {
            "control_flow_effects": {"added": ("return",), "removed": ("break",)},
            "returns": {"added": ("none",), "removed": ()},
        }
    }

    assert not exit_goto_repair_delta_8616(extra_control)
    assert not exit_goto_repair_delta_8616(non_goto)


def test_segmented_stack_slot_size_precision_delta_accepts_size_only_change():
    before = "deref:Add(Mul(reg:ss,const:16),stack_slot:SS:BP-0x8:size4,const:-17)"
    after = "deref:Add(Mul(reg:ss,const:16),stack_slot:SS:BP-0x8:size2,const:-17)"
    validation = {
        "delta": {
            "segmented_writes": {"added": (after,), "removed": (before,)},
        }
    }

    assert segmented_stack_slot_size_precision_delta_8616(validation)
    assert postprocess_stage._is_segmented_stack_slot_size_precision_delta_8616(validation)


def test_segmented_stack_slot_size_precision_delta_refuses_address_or_field_changes():
    address_change = {
        "delta": {
            "segmented_writes": {
                "added": ("deref:Add(Mul(reg:ss,const:16),stack_slot:SS:BP-0xa:size2,const:-17)",),
                "removed": ("deref:Add(Mul(reg:ss,const:16),stack_slot:SS:BP-0x8:size4,const:-17)",),
            },
        }
    }
    helper_delta = {
        "delta": {
            "segmented_writes": {
                "added": ("deref:Add(Mul(reg:ss,const:16),stack_slot:SS:BP-0x8:size2,const:-17)",),
                "removed": ("deref:Add(Mul(reg:ss,const:16),stack_slot:SS:BP-0x8:size4,const:-17)",),
            },
            "helper_calls": {"added": ("addr:0x1234",), "removed": ()},
        }
    }

    assert not segmented_stack_slot_size_precision_delta_8616(address_change)
    assert not segmented_stack_slot_size_precision_delta_8616(helper_delta)


def test_name_only_helper_annotation_delta_accepts_named_address_helper_removals():
    validation = {
        "delta": {
            "helper_calls": {
                "added": (),
                "removed": ("name:addr:0x1d1c", "name:addr:0x1d91"),
            },
            "returns": {"added": (), "removed": ()},
        }
    }

    assert name_only_helper_annotation_delta_8616(validation)


def test_name_only_helper_annotation_delta_refuses_raw_or_mixed_helper_changes():
    raw_helper = {
        "delta": {
            "helper_calls": {
                "added": (),
                "removed": ("addr:0x1d1c",),
            },
        }
    }
    mixed_delta = {
        "delta": {
            "helper_calls": {
                "added": (),
                "removed": ("name:addr:0x1d1c",),
            },
            "returns": {"added": ("none",), "removed": ()},
        }
    }

    assert not name_only_helper_annotation_delta_8616(raw_helper)
    assert not name_only_helper_annotation_delta_8616(mixed_delta)


def test_direct_stack_move_idiv_remainder_aux_delta_accepts_insert_and_ax_churn():
    validation = {
        "delta": {
            "helper_calls": {"added": ("name:_INSERT",), "removed": ()},
            "register_writes": {"added": ("reg:ax",), "removed": ()},
        }
    }

    assert direct_stack_move_idiv_remainder_aux_delta_8616(validation)


def test_direct_stack_move_idiv_remainder_aux_delta_refuses_other_helpers_or_registers():
    wrong_helper = {
        "delta": {
            "helper_calls": {"added": ("name:printf",), "removed": ()},
            "register_writes": {"added": ("reg:ax",), "removed": ()},
        }
    }
    wrong_register = {
        "delta": {
            "helper_calls": {"added": ("name:_INSERT",), "removed": ()},
            "register_writes": {"added": ("reg:dx",), "removed": ()},
        }
    }
    mixed_delta = {
        "delta": {
            "helper_calls": {"added": ("name:_INSERT",), "removed": ()},
            "stack_writes": {"added": ("stack_slot:SS:BP-0x2:size2",), "removed": ()},
        }
    }

    assert not direct_stack_move_idiv_remainder_aux_delta_8616(wrong_helper)
    assert not direct_stack_move_idiv_remainder_aux_delta_8616(wrong_register)
    assert not direct_stack_move_idiv_remainder_aux_delta_8616(mixed_delta)


def test_direct_stack_move_function_pointer_prune_delta_accepts_evidenced_stack_removal():
    validation = {
        "delta": {
            "stack_writes": {
                "added": (),
                "removed": ("stack_slot:SS:BP-0x2:size2",),
            }
        }
    }

    assert direct_stack_move_function_pointer_prune_delta_8616(
        validation,
        {-2},
        has_prune_evidence=True,
    )


def test_direct_stack_move_function_pointer_prune_delta_refuses_call_arg_loss_or_missing_evidence():
    call_arg_loss = {
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
    unevidenced_offset = {
        "delta": {
            "stack_writes": {
                "added": (),
                "removed": ("stack_slot:SS:BP-0x4:size2",),
            }
        }
    }

    assert not direct_stack_move_function_pointer_prune_delta_8616(
        call_arg_loss,
        {-2},
        has_prune_evidence=True,
    )
    assert not direct_stack_move_function_pointer_prune_delta_8616(
        unevidenced_offset,
        {-2},
        has_prune_evidence=True,
    )
    assert not direct_stack_move_function_pointer_prune_delta_8616(
        unevidenced_offset,
        {-4},
        has_prune_evidence=False,
    )


def test_validation_stack_offsets_in_token_extracts_signed_bp_offsets():
    token = "call:addr:0xfd1(stack_slot:SS:BP-0x2:size2,stack_slot:SS:BP+0x6:size2)"

    assert validation_stack_offsets_in_token_8616(token) == frozenset({-2, 6})


def test_validation_stack_write_delta_offsets_are_evidenced_accepts_absent_or_covered_stack_delta():
    no_stack_delta = {"delta": {"conditions": {"added": ("CmpEQ(const:1,const:1)",), "removed": ()}}}
    stack_delta = {
        "delta": {
            "stack_writes": {
                "added": (),
                "removed": ("stack_slot:SS:BP-0x2:size2",),
            }
        }
    }

    assert validation_stack_write_delta_offsets_are_evidenced_8616(no_stack_delta, {-2}) is True
    assert validation_stack_write_delta_offsets_are_evidenced_8616(stack_delta, {-2}) is True


def test_validation_stack_write_delta_offsets_are_evidenced_refuses_bad_or_unevidenced_tokens():
    bad_token = {"delta": {"stack_writes": {"added": (object(),), "removed": ()}}}
    unevidenced = {
        "delta": {
            "stack_writes": {
                "added": (),
                "removed": ("stack_slot:SS:BP-0x4:size2",),
            }
        }
    }

    assert validation_stack_write_delta_offsets_are_evidenced_8616({}, {-2}) is False
    assert validation_stack_write_delta_offsets_are_evidenced_8616(bad_token, {-2}) is False
    assert validation_stack_write_delta_offsets_are_evidenced_8616(unevidenced, {-2}) is False


def test_validation_without_delta_fields_strips_selected_delta_fields_without_mutating_input():
    validation = {
        "status": "changed",
        "delta": {
            "helper_calls": {"added": ("name:_INSERT",), "removed": ()},
            "register_writes": {"added": ("reg:ax",), "removed": ()},
            "stack_writes": {"added": (), "removed": ("stack_slot:SS:BP-0x2:size2",)},
        },
    }

    stripped = validation_without_delta_fields_8616(validation, {"helper_calls", "register_writes"})

    assert stripped == {
        "status": "changed",
        "delta": {
            "stack_writes": {"added": (), "removed": ("stack_slot:SS:BP-0x2:size2",)},
        },
    }
    assert "helper_calls" in validation["delta"]
    assert stripped is not validation


def test_validation_without_delta_fields_preserves_non_delta_payload_as_copy():
    validation = {"status": "stable", "summary_text": "unchanged"}

    stripped = validation_without_delta_fields_8616(validation, {"helper_calls"})

    assert stripped == validation
    assert stripped is not validation


def test_validation_delta_removes_stack_or_control_effects_detects_destructive_removals():
    stack_removal = {
        "delta": {
            "stack_writes": {"added": (), "removed": ("stack_slot:SS:BP-0x2:size2",)},
        }
    }
    control_removal = {
        "delta": {
            "control_flow_effects": {"added": (), "removed": ("ifbreak:CmpEQ(reg:ax,const:0)",)},
        }
    }

    assert validation_delta_removes_stack_or_control_effects_8616(stack_removal) is True
    assert validation_delta_removes_stack_or_control_effects_8616(control_removal) is True


def test_validation_delta_removes_stack_or_control_effects_ignores_additions_and_other_fields():
    stack_addition = {
        "delta": {
            "stack_writes": {"added": ("stack_slot:SS:BP-0x2:size2",), "removed": ()},
        }
    }
    helper_removal = {
        "delta": {
            "helper_calls": {"added": (), "removed": ("addr:0x1234",)},
        }
    }

    assert validation_delta_removes_stack_or_control_effects_8616(stack_addition) is False
    assert validation_delta_removes_stack_or_control_effects_8616(helper_removal) is False
    assert validation_delta_removes_stack_or_control_effects_8616({}) is False


def test_validation_delta_touched_fields_reports_fields_with_added_or_removed_tokens():
    delta = {
        "helper_calls": {"added": ("addr:0x1234",), "removed": ()},
        "stack_writes": {"added": (), "removed": ("stack_slot:SS:BP-0x2:size2",)},
        "returns": {"added": (), "removed": ()},
    }

    assert validation_delta_touched_fields_8616(delta) == {"helper_calls", "stack_writes"}


def test_validation_delta_touched_fields_ignores_non_delta_or_empty_values():
    delta = {
        "helper_calls": {"added": (), "removed": ()},
        "summary_text": "changed",
        "conditions": ("not", "a", "field-delta"),
    }

    assert validation_delta_touched_fields_8616(delta) == set()


def test_callsite_stack_precision_control_delta_accepts_stack_only_hash_replacement():
    control_delta = {
        "added": (
            "for-body-writes:CmpLT(reg:sp,const:0):deref:Add(Mul(reg:ss,const:16),stack_slot:SS:BP-0x2:size2)",
        ),
        "removed": ("control_flow_effects:sha256:old",),
    }

    assert callsite_stack_precision_control_delta_8616(control_delta)


def test_callsite_stack_precision_control_delta_refuses_global_or_non_stack_registers():
    global_delta = {
        "added": ("for-body-writes:CmpLT(reg:sp,const:0):global:0x100",),
        "removed": ("control_flow_effects:sha256:old",),
    }
    register_delta = {
        "added": (
            "for-body-writes:CmpLT(reg:ax,const:0):deref:Add(Mul(reg:ss,const:16),stack_slot:SS:BP-0x2:size2)",
        ),
        "removed": ("control_flow_effects:sha256:old",),
    }

    assert not callsite_stack_precision_control_delta_8616(global_delta)
    assert not callsite_stack_precision_control_delta_8616(register_delta)


def test_callsite_resolved_indirect_helper_control_delta_accepts_resolved_name_rewrite():
    control_delta = {
        "added": ("if-body-calls:CmpNE(reg:ax,const:0):name:addr:0x1234",),
        "removed": ("if-body-calls:CmpNE(reg:ax,const:0):name:<indirect>",),
    }

    assert callsite_resolved_indirect_helper_control_delta_8616(control_delta)


def test_callsite_resolved_indirect_helper_control_delta_refuses_hash_added_or_mismatch():
    hash_added = {
        "added": ("control_flow_effects:sha256:new",),
        "removed": ("if-body-calls:CmpNE(reg:ax,const:0):name:<indirect>",),
    }
    mismatch = {
        "added": ("if-body-calls:CmpNE(reg:ax,const:0):name:addr:0x1234",),
        "removed": ("while-body-calls:CmpNE(reg:ax,const:0):name:<indirect>",),
    }

    assert not callsite_resolved_indirect_helper_control_delta_8616(hash_added)
    assert not callsite_resolved_indirect_helper_control_delta_8616(mismatch)


def test_callsite_helper_control_target_delta_accepts_target_evidence_rewrite():
    delta = {
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

    assert callsite_helper_control_target_delta_8616(delta, {0x10768, 0x10794})


def test_callsite_helper_control_target_delta_refuses_missing_evidence_or_mixed_fields():
    missing_evidence = {
        "helper_calls": {"added": ("addr:0x10768",), "removed": ("addr:0x11cd4",)},
        "control_flow_effects": {
            "added": ("if-body-calls:CmpNE(reg:ax,const:0):addr:0x10768",),
            "removed": ("if-body-calls:CmpNE(reg:ax,const:0):addr:0x11cd4",),
        },
    }
    mixed_fields = {
        **missing_evidence,
        "conditions": {"added": ("CmpNE(reg:ax,const:0)",), "removed": ()},
    }

    assert not callsite_helper_control_target_delta_8616(missing_evidence, {0x1234})
    assert not callsite_helper_control_target_delta_8616(mixed_fields, {0x10768})


def test_callsite_consumed_stack_store_prune_delta_accepts_stack_and_body_write_removal():
    delta = {
        "stack_writes": {"added": (), "removed": ("stack_slot:SS:BP-0x2:size2",)},
        "control_flow_effects": {
            "added": (),
            "removed": ("while-body-writes:const:True:stack_slot:SS:BP-0x2:size2",),
        },
    }

    assert callsite_consumed_stack_store_prune_delta_8616(1, delta)


def test_callsite_consumed_stack_store_prune_delta_refuses_missing_evidence_or_nonlocal_stack():
    missing_evidence = {
        "stack_writes": {"added": (), "removed": ("stack_slot:SS:BP-0x2:size2",)},
    }
    nonlocal_stack = {
        "stack_writes": {"added": (), "removed": ("stack_slot:SS:BP+0x4:size2",)},
    }
    missing_control_reference = {
        "stack_writes": {"added": (), "removed": ("stack_slot:SS:BP-0x2:size2",)},
        "control_flow_effects": {"added": (), "removed": ("while-body-writes:const:True:reg:ax",)},
    }

    assert not callsite_consumed_stack_store_prune_delta_8616(0, missing_evidence)
    assert not callsite_consumed_stack_store_prune_delta_8616(1, nonlocal_stack)
    assert not callsite_consumed_stack_store_prune_delta_8616(1, missing_control_reference)


def test_callsite_far_pointer_remnant_prune_delta_accepts_stack_fragment_only_change():
    delta = {
        "stack_writes": {"added": (), "removed": ("stack_slot:SS:BP+0x2:size4",)},
        "control_flow_effects": {
            "added": ("for-body-writes:cond:deref:Add(global:0x8f0),reg:ax",),
            "removed": ("for-body-writes:cond:deref:Add(global:0x8f0),reg:ax,stack_slot:SS:BP+0x2:size4",),
        },
    }

    assert callsite_far_pointer_remnant_prune_delta_8616(1, delta)


def test_callsite_far_pointer_remnant_prune_delta_refuses_missing_evidence_or_mismatched_control():
    missing_evidence = {
        "stack_writes": {"added": (), "removed": ("stack_slot:SS:BP+0x2:size4",)},
    }
    added_stack = {
        "stack_writes": {"added": ("stack_slot:SS:BP+0x2:size4",), "removed": ()},
    }
    mismatched_control = {
        "stack_writes": {"added": (), "removed": ("stack_slot:SS:BP+0x2:size4",)},
        "control_flow_effects": {
            "added": ("for-body-writes:cond:reg:ax",),
            "removed": ("for-body-writes:other:reg:ax,stack_slot:SS:BP+0x2:size4",),
        },
    }

    assert not callsite_far_pointer_remnant_prune_delta_8616(0, missing_evidence)
    assert not callsite_far_pointer_remnant_prune_delta_8616(1, added_stack)
    assert not callsite_far_pointer_remnant_prune_delta_8616(1, mismatched_control)


def test_callsite_resolved_indirect_helper_stack_delta_accepts_local_stack_and_control_precision():
    delta = {
        "helper_calls": {
            "added": ("addr:0x1123a", "addr:0x12756"),
            "removed": ("name:<indirect>", "name:<indirect>"),
        },
        "stack_writes": {"added": ("stack_slot:SS:BP-0x2:size2",), "removed": ()},
        "control_flow_effects": {
            "added": ("control_flow_effects:sha256:35fe2b643a18d34e:len:1045",),
            "removed": ("control_flow_effects:sha256:fc4fe433fd0b11d5:len:1018",),
        },
    }

    assert callsite_resolved_indirect_helper_stack_delta_8616(delta)


def test_callsite_resolved_indirect_helper_stack_delta_accepts_outgoing_segmented_write_prune():
    delta = {
        "helper_calls": {
            "added": ("addr:0x1123a", "addr:0x128e4"),
            "removed": ("name:<indirect>", "name:<indirect>"),
        },
        "stack_writes": {"added": ("stack_slot:SS:BP-0x2:size2",), "removed": ()},
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
    }

    assert callsite_resolved_indirect_helper_stack_delta_8616(delta)


def test_callsite_resolved_indirect_helper_stack_delta_refuses_nonlocal_stack_or_helper_source():
    nonlocal_stack = {
        "helper_calls": {"added": ("addr:0x1123a",), "removed": ("name:<indirect>",)},
        "stack_writes": {"added": ("stack_slot:SS:BP+0x4:size2",), "removed": ()},
    }
    wrong_helper = {
        "helper_calls": {"added": ("addr:0x1123a",), "removed": ("name:strcpy",)},
        "stack_writes": {"added": ("stack_slot:SS:BP-0x2:size2",), "removed": ()},
    }
    nonstack_segment = {
        "helper_calls": {"added": ("addr:0x1123a",), "removed": ("name:<indirect>",)},
        "segmented_writes": {"added": (), "removed": ("deref:Add(Mul(reg:ds,const:16),reg:sp,const:-8)",)},
    }

    assert not callsite_resolved_indirect_helper_stack_delta_8616(nonlocal_stack)
    assert not callsite_resolved_indirect_helper_stack_delta_8616(wrong_helper)
    assert not callsite_resolved_indirect_helper_stack_delta_8616(nonstack_segment)


def test_callsite_mixed_helper_stack_control_delta_accepts_indirect_and_pruned_stack_evidence():
    delta = {
        "helper_calls": {
            "added": ("addr:0x1075b", "addr:0x10ce0"),
            "removed": ("addr:0x11cd4", "name:<indirect>"),
        },
        "stack_writes": {"added": (), "removed": ("stack_slot:SS:BP-0x2:size2",)},
        "control_flow_effects": {
            "added": (
                "if-body-calls:CmpGT(stack_slot:SS:BP-0x2:size2,stack_slot:SS:BP-0x6:size2):name:addr:0x1075b",
            ),
            "removed": (
                "if-body-calls:CmpGT(stack_slot:SS:BP-0x2:size2,stack_slot:SS:BP-0x6:size2):name:<indirect>",
            ),
        },
    }

    assert callsite_mixed_helper_stack_control_delta_8616(
        delta,
        target_evidence={0x1075B, 0x10CE0},
        pruned_stack_tokens={"stack_slot:SS:BP-0x2:size2"},
    )


def test_callsite_mixed_helper_stack_control_delta_accepts_direct_target_correction_with_evidence():
    delta = {
        "helper_calls": {
            "added": ("addr:0x10ce0", "addr:0x10ce0"),
            "removed": ("addr:0x11cd4", "addr:0x11cd4"),
        },
        "stack_writes": {"added": (), "removed": ("stack_slot:SS:BP-0x2:size2",)},
        "control_flow_effects": {
            "added": ("if-body-calls:CmpLT(stack_slot:SS:BP+0x4:size2,stack_slot:SS:BP+0x6:size2):name:addr:0x10ce0",),
            "removed": ("if-body-calls:CmpLT(stack_slot:SS:BP+0x4:size2,stack_slot:SS:BP+0x6:size2):name:addr:0x11cd4",),
        },
    }

    assert callsite_mixed_helper_stack_control_delta_8616(
        delta,
        target_evidence={0x10CE0},
        pruned_stack_tokens={"stack_slot:SS:BP-0x2:size2"},
    )


def test_callsite_mixed_helper_stack_control_delta_refuses_missing_stack_or_body_write_removal():
    missing_stack_evidence = {
        "helper_calls": {"added": ("addr:0x1075b",), "removed": ("name:<indirect>",)},
        "stack_writes": {"added": (), "removed": ("stack_slot:SS:BP-0x6:size2",)},
        "control_flow_effects": {
            "added": ("if-body-calls:CmpGT(stack_slot:SS:BP-0x2:size2,const:0):name:addr:0x1075b",),
            "removed": ("if-body-calls:CmpGT(stack_slot:SS:BP-0x2:size2,const:0):name:<indirect>",),
        },
    }
    body_write_removal = {
        "helper_calls": {"added": ("addr:0x10768", "addr:0x10794"), "removed": ("addr:0x10ce0", "addr:0x11cd4")},
        "stack_writes": {"added": (), "removed": ("stack_slot:SS:BP-0x6:size2",)},
        "control_flow_effects": {
            "added": ("dowhile-body-writes:CmpLE(stack_slot:SS:BP-0x2:size2,const:0):global:0xbaa",),
            "removed": (
                "dowhile-body-writes:CmpLE(stack_slot:SS:BP-0x2:size2,const:0):"
                "global:0xbaa,stack_slot:SS:BP-0x6:size2"
            ),
        },
    }

    assert not callsite_mixed_helper_stack_control_delta_8616(
        missing_stack_evidence,
        target_evidence={0x1075B},
        pruned_stack_tokens={"stack_slot:SS:BP-0x2:size2"},
    )
    assert not callsite_mixed_helper_stack_control_delta_8616(
        body_write_removal,
        target_evidence={0x10768, 0x10794},
        pruned_stack_tokens={"stack_slot:SS:BP-0x6:size2"},
    )


def test_callsite_stack_arg_slot_alias_condition_delta_accepts_alias_equivalence():
    aliases = {
        ("iLow", 2): "stack_slot:SS:BP+0x4:size2",
        ("iHigh", 2): "stack_slot:SS:BP+0x6:size2",
    }
    delta = {
        "conditions": {
            "added": ("CmpLT(stack_arg:iLow:size2,stack_arg:iHigh:size2)",),
            "removed": ("CmpLT(stack_slot:SS:BP+0x4:size2,stack_slot:SS:BP+0x6:size2)",),
        },
        "control_flow_effects": {
            "added": ("if:CmpLT(stack_arg:iLow:size2,stack_arg:iHigh:size2)",),
            "removed": ("if:CmpLT(stack_slot:SS:BP+0x4:size2,stack_slot:SS:BP+0x6:size2)",),
        },
    }

    assert callsite_stack_arg_slot_alias_condition_delta_8616(delta, aliases) is True


def test_callsite_stack_arg_slot_alias_condition_delta_refuses_missing_alias_or_extra_field():
    aliases = {("iLow", 2): "stack_slot:SS:BP+0x4:size2"}
    delta = {
        "conditions": {
            "added": ("CmpLT(stack_arg:iLow:size2,stack_arg:iHigh:size2)",),
            "removed": ("CmpLT(stack_slot:SS:BP+0x4:size2,stack_slot:SS:BP+0x6:size2)",),
        },
    }
    extra_field_delta = {
        **delta,
        "helper_calls": {"added": ("addr:0x1234",), "removed": ()},
    }

    assert callsite_stack_arg_slot_alias_condition_delta_8616(delta, {}) is False
    assert callsite_stack_arg_slot_alias_condition_delta_8616(delta, aliases) is False
    assert callsite_stack_arg_slot_alias_condition_delta_8616(extra_field_delta, aliases) is False


def _callsite_summary(
    callsite_addr: int,
    target_addr: int | None,
    *,
    arg_count: int | None = 0,
    stack_probe_helper: bool = False,
    push_arg_sources: tuple[tuple | None, ...] = (),
) -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr,
        target_addr,
        None,
        "direct_near",
        arg_count,
        (),
        None,
        None,
        False,
        stack_probe_helper=stack_probe_helper,
        push_arg_sources=push_arg_sources,
    )


class _Memory:
    def __init__(self, chunks: dict[int, bytes]):
        self._chunks = chunks

    def load(self, addr: int, size: int) -> bytes:
        for base, data in self._chunks.items():
            if base <= addr < base + len(data):
                offset = addr - base
                return data[offset : offset + size]
        raise KeyError(addr)


def test_tail_validation_call_fingerprint_resolves_original_project_function_alias():
    class CurrentFunctions:
        def function(self, **_kwargs):
            return None

    class OriginalFunctions:
        def function(self, *, name=None, create=False, **_kwargs):
            if not create and name in {"rel_i16", "_rel_i16"}:
                return SimpleNamespace(addr=0x1005A, name="rel_i16")
            return None

    project = _project()
    project.kb = SimpleNamespace(functions=CurrentFunctions(), labels={})
    project._inertia_original_project = SimpleNamespace(kb=SimpleNamespace(functions=OriginalFunctions(), labels={}))
    codegen = _DummyCodegen()
    call = CFunctionCall("rel_i16", None, [], codegen=codegen)

    assert tail_validation_fingerprint_module._call_target_name(call, project) == "addr:0x1005a"
    assert tail_validation_fingerprint_module._expr_fingerprint(call, project) == "call:addr:0x1005a()"


def test_tail_validation_call_fingerprint_canonicalizes_padding_target_to_prologue():
    class OriginalFunctions:
        def function(self, *, name=None, create=False, **_kwargs):
            if not create and name in {"SwapBars", "_SwapBars"}:
                return SimpleNamespace(addr=0x1075B, name="SwapBars")
            return None

    project = _project()
    project.kb = SimpleNamespace(functions=OriginalFunctions(), labels={})
    project.loader = SimpleNamespace(memory=_Memory({0x1075B: b"\x90" * 13 + b"\x55\x8b\xec"}))
    codegen = _DummyCodegen()
    call = CFunctionCall("SwapBars", None, [], codegen=codegen)

    assert tail_validation_fingerprint_module._call_target_name(call, project) == "addr:0x10768"
    assert tail_validation_fingerprint_module._expr_fingerprint(call, project) == "call:addr:0x10768()"


def test_tail_validation_summary_normalizes_padding_target_to_prologue():
    project = _project()
    project.loader = SimpleNamespace(memory=_Memory({0x1075B: b"\x90" * 13 + b"\x55\x8b\xec"}))

    assert tail_validation_module._normalized_call_target_addr_8616(project, 0x1075B) == 0x10768
    assert tail_validation_module._normalize_helper_call_fingerprint_8616(project, "name:addr:0x1075b") == (
        "name:addr:0x10768"
    )


def test_tail_validation_summary_reuses_matching_boundary_context_once(monkeypatch):
    project = _project()
    codegen = _DummyCodegen()
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=CStatements([], codegen=codegen))
    boundary_fingerprint = fingerprint_x86_16_tail_validation_boundary(project, codegen, mode="live_out")

    def fail_context_rebuild(*_args, **_kwargs):
        raise AssertionError("boundary context should be reused")

    monkeypatch.setattr(tail_validation_module, "build_x86_16_contextual_call_fingerprints", fail_context_rebuild)
    monkeypatch.setattr(tail_validation_module, "_build_contextual_call_summary_map", fail_context_rebuild)
    monkeypatch.setattr(tail_validation_module, "build_x86_16_contextual_condition_fingerprints", fail_context_rebuild)

    summary = collect_x86_16_tail_validation_summary(
        project,
        codegen,
        mode="live_out",
        boundary_fingerprint=boundary_fingerprint,
    )

    assert isinstance(summary, X86_16TailValidationSummary)
    assert codegen._inertia_tail_validation_boundary_context_reused_8616 == 1
    assert not hasattr(codegen, "_inertia_tail_validation_boundary_context_8616")


def test_tail_validation_summary_refuses_mismatched_boundary_context(monkeypatch):
    project = _project()
    codegen = _DummyCodegen()
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=CStatements([], codegen=codegen))
    codegen._inertia_tail_validation_boundary_context_8616 = (
        tail_validation_module._TailValidationBoundaryContext8616(
            mode="live_out",
            root_id=id(codegen.cfunc.body),
            boundary_fingerprint="stale",
            summary_input_generation=(
                tail_validation_module.tail_validation_summary_input_generation_8616(
                    project,
                    codegen,
                )
            ),
            contextual_call_fingerprints={},
            contextual_call_summaries={},
            contextual_condition_fingerprints={},
        )
    )
    rebuilds = {"count": 0}

    def rebuild_empty(*_args, **_kwargs):
        rebuilds["count"] += 1
        return {}

    monkeypatch.setattr(tail_validation_module, "build_x86_16_contextual_call_fingerprints", rebuild_empty)
    monkeypatch.setattr(tail_validation_module, "_build_contextual_call_summary_map", rebuild_empty)
    monkeypatch.setattr(tail_validation_module, "build_x86_16_contextual_condition_fingerprints", rebuild_empty)

    summary = collect_x86_16_tail_validation_summary(
        project,
        codegen,
        mode="live_out",
        boundary_fingerprint="current",
    )

    assert isinstance(summary, X86_16TailValidationSummary)
    assert rebuilds["count"] == 3
    assert not hasattr(codegen, "_inertia_tail_validation_boundary_context_reused_8616")
    assert not hasattr(codegen, "_inertia_tail_validation_boundary_context_8616")


def test_tail_validation_boundary_binary_nodes_do_not_probe_full_expr_fingerprint(monkeypatch):
    project = _project()
    codegen = _DummyCodegen()
    lhs = CConstant(1, SimTypeShort(False), codegen=codegen)
    rhs = CConstant(2, SimTypeShort(False), codegen=codegen)
    expr = CBinaryOp("Add", lhs, rhs, codegen=codegen)
    ret = CReturn(expr, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=CStatements([ret], codegen=codegen))

    def fail_full_expr_fingerprint(*_args, **_kwargs):
        raise AssertionError("boundary fingerprint should not run full expression fingerprint for CBinaryOp")

    monkeypatch.setattr(tail_validation_module, "_expr_fingerprint", fail_full_expr_fingerprint)

    fingerprint = fingerprint_x86_16_tail_validation_boundary(project, codegen, mode="live_out")

    assert isinstance(fingerprint, str)
    assert fingerprint


def test_jcc_condition_delta_accepts_body_call_complement_rewrite():
    codegen = _DummyCodegen()
    validation = {
        "delta": {
            "conditions": {
                "added": ("CmpNE(reg:ax,const:69)",),
                "removed": ("CmpEQ(reg:ax,const:69)",),
            },
            "control_flow_effects": {
                "added": (
                    "if:CmpNE(reg:ax,const:69)",
                    "if-body-calls:CmpNE(reg:ax,const:69):name:addr:0x10672,name:addr:0x10b2c",
                ),
                "removed": (
                    "if:CmpEQ(reg:ax,const:69)",
                    "if-body-calls:CmpEQ(reg:ax,const:69):name:addr:0x10672,name:addr:0x10b2c",
                ),
            },
        }
    }

    assert postprocess_stage._is_jcc_condition_materialization_validation_delta_8616(
        _project(),
        codegen,
        validation,
    )


def test_switch_loop_exit_return_delta_accepts_case_materialization():
    codegen = _DummyCodegen()
    codegen._inertia_switch_loop_exit_return_materialized_8616 = True
    validation = {
        "delta": {
            "returns": {"added": ("none",), "removed": ()},
            "control_flow_effects": {"added": ("case:const:27",), "removed": ()},
        }
    }

    assert postprocess_stage._is_switch_loop_exit_return_repair_delta_8616(codegen, validation)


def test_switch_loop_exit_return_delta_accepts_cfg_proven_void_tail_replacement():
    codegen = _DummyCodegen()
    codegen._inertia_switch_loop_exit_return_materialized_8616 = True
    validation = {
        "delta": {
            "returns": {"added": ("none",), "removed": ("Add(reg:ax,const:-27)",)},
        }
    }

    assert postprocess_stage._is_switch_loop_exit_return_repair_delta_8616(codegen, validation)


def test_switch_loop_exit_return_delta_accepts_combined_case_and_void_tail_replacement():
    codegen = _DummyCodegen()
    codegen._inertia_switch_loop_exit_return_materialized_8616 = True
    validation = {
        "delta": {
            "returns": {"added": ("none",), "removed": ("Add(reg:ax,const:-27)",)},
            "control_flow_effects": {"added": ("case:const:27",), "removed": ()},
        }
    }

    assert postprocess_stage._is_switch_loop_exit_return_repair_delta_8616(codegen, validation)


def test_switch_loop_exit_return_delta_rejects_unproven_value_removal():
    codegen = _DummyCodegen()
    codegen._inertia_switch_loop_exit_return_materialized_8616 = True
    validation = {
        "delta": {
            "returns": {"added": ("none",), "removed": ("reg:ax",)},
        }
    }

    assert not postprocess_stage._is_switch_loop_exit_return_repair_delta_8616(codegen, validation)


def test_switch_loop_exit_return_validation_delta_accepts_case_materialization():
    validation = {
        "delta": {
            "returns": {"added": ("none",), "removed": ()},
            "control_flow_effects": {"added": ("case:const:27",), "removed": ()},
        }
    }

    assert switch_loop_exit_return_repair_delta_8616(1, validation)


def test_switch_loop_exit_return_validation_delta_accepts_void_tail_replacement():
    validation = {
        "delta": {
            "returns": {"added": ("none",), "removed": ("Add(reg:ax,const:-27)",)},
        }
    }

    assert switch_loop_exit_return_repair_delta_8616(1, validation)


def test_switch_loop_exit_return_validation_delta_refuses_unproven_or_removed_control():
    unproven = {
        "delta": {
            "returns": {"added": ("none",), "removed": ("Add(reg:ax,const:-27)",)},
        }
    }
    removed_control = {
        "delta": {
            "returns": {"added": ("none",), "removed": ()},
            "control_flow_effects": {"added": ("case:const:27",), "removed": ("case:const:9",)},
        }
    }

    assert not switch_loop_exit_return_repair_delta_8616(0, unproven)
    assert not switch_loop_exit_return_repair_delta_8616(1, removed_control)


def test_tail_validation_compare_canonicalizes_resolved_name_addr_helper_calls():
    before = X86_16TailValidationSummary(
        helper_calls=("addr:0x128e4",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )
    after = X86_16TailValidationSummary(
        helper_calls=("name:addr:0x128E4",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["helper_calls"] == {"added": (), "removed": ()}


def test_tail_validation_compare_canonicalizes_loop_body_name_addr_helper_calls():
    condition = "CmpGT(global:0xba2,stack_slot:SS:BP-0x2:size2)"
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(f"for-body-calls:{condition}:addr:0x11414",),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(f"for-body-calls:{condition}:name:addr:0x11414",),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["control_flow_effects"] == {"added": (), "removed": ()}


def test_tail_validation_compact_limit_env_allows_uncompacted_debug(monkeypatch):
    value = "CmpNE(" + "x" * 600 + ",const:0)"

    monkeypatch.delenv("INERTIA_TAIL_VALIDATION_FINGERPRINT_LIMIT", raising=False)
    compacted = tail_validation_module._compact_tail_validation_observable_8616("conditions", value)
    assert compacted.startswith("conditions:sha256:")

    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_FINGERPRINT_LIMIT", "1000")
    assert tail_validation_module._compact_tail_validation_observable_8616("conditions", value) == value


def test_tail_validation_compacts_canonical_loop_write_effects_to_same_digest(monkeypatch):
    nested_write = "deref:Add(Mul(reg:ss,const:16),Add(reg:sp,const:-2))"
    before = f"while-body-writes:const:True:{nested_write},deref:ds:0x132,global:0xba4"
    after = f"while-body-writes:const:True:{nested_write},global:0x132,global:0xba4"
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_FINGERPRINT_LIMIT", "1")

    compact_before = tail_validation_module._compact_tail_validation_observable_8616(
        "control_flow_effects", before
    )
    compact_after = tail_validation_module._compact_tail_validation_observable_8616(
        "control_flow_effects", after
    )

    assert compact_before.startswith("control_flow_effects:sha256:")
    assert compact_before == compact_after
    compact_split = tail_validation_module._split_control_flow_loop_body_write_effect_8616(compact_before)
    assert compact_split is not None
    assert compact_split[1] == (
        "deref:Add(Mul(reg:ss,const:16),reg:sp,const:-2)",
        "ds_global:0x132",
        "ds_global:0xba4",
    )


def test_indexed_segmented_global_precision_accepts_compacted_control_prefix():
    condition = "CmpNE(" + "x" * 600 + ",const:0)"
    before = tail_validation_module._compact_tail_validation_observable_8616(
        "control_flow_effects",
        f"while-body-writes:{condition}:global:0x132,global:0x134",
    )
    after = tail_validation_module._compact_tail_validation_observable_8616(
        "control_flow_effects",
        f"while-body-writes:{condition}:global:0x132,global:0x133,global:0x134",
    )
    validation = {
        "delta": {
            "global_writes": {"added": ("ds_global:0x133",), "removed": ()},
            "control_flow_effects": {"added": (after,), "removed": (before,)},
        }
    }

    assert indexed_segmented_global_precision_delta_8616(
        1,
        (IndexedSegmentedGlobalEvidence8616(0x132, "clPause", 0, 2),),
        validation,
    )


def test_tail_validation_compare_preserves_duplicate_helper_call_loss():
    before = X86_16TailValidationSummary(
        helper_calls=("addr:0x128e4", "addr:0x128e4"),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )
    after = X86_16TailValidationSummary(
        helper_calls=("name:addr:0x128E4",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is True
    assert diff["delta"]["helper_calls"] == {"added": (), "removed": ("addr:0x128e4",)}


def test_tail_validation_compare_fails_missing_callsite_coverage_even_when_stable():
    before = X86_16TailValidationSummary(
        helper_calls=("missing-callsite:addr:0x128e4",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )
    after = X86_16TailValidationSummary(
        helper_calls=("missing-callsite:addr:0x128e4",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is True
    assert diff["delta"]["helper_calls"] == {
        "added": (),
        "removed": ("missing-callsite:addr:0x128e4",),
    }


def test_tail_validation_compare_treats_global_byte_pair_condition_as_word_global():
    before_condition = "CmpLT(stack_slot:SS:BP-0x2:size2,Or(global:0x160,Shl(global:0x161,const:8)))"
    after_condition = "CmpLT(stack_slot:SS:BP-0x2:size2,global:0x160)"
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(before_condition,),
        control_flow_effects=(f"if:{before_condition}",),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(after_condition,),
        control_flow_effects=(f"if:{after_condition}",),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["conditions"] == {"added": (), "removed": ()}
    assert diff["delta"]["control_flow_effects"] == {"added": (), "removed": ()}


def test_tail_validation_compare_treats_source_arg_bp_suffix_as_stack_slot_identity():
    before_condition = "CmpLT(stack_slot:SS:BP+0x4:size2,stack_slot:SS:BP+0x6:size2)"
    after_condition = "CmpLT(stack_arg:iLow:size2:bp+0x4,stack_arg:iHigh:size2:bp+0x6)"
    before = X86_16TailValidationSummary(
        helper_calls=("addr:0xfd1(stack_slot:SS:BP+0x4:size2)",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(before_condition,),
        control_flow_effects=(f"if:{before_condition}",),
    )
    after = X86_16TailValidationSummary(
        helper_calls=("addr:0xfd1(stack_arg:iLow:size2:bp+0x4)",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(after_condition,),
        control_flow_effects=(f"if:{after_condition}",),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["helper_calls"] == {"added": (), "removed": ()}
    assert diff["delta"]["conditions"] == {"added": (), "removed": ()}
    assert diff["delta"]["control_flow_effects"] == {"added": (), "removed": ()}


def test_tail_validation_live_out_ignores_direct_positive_bp_argument_slot_writes():
    observed = {"stack_slot:SS:BP+0x4:size2"}

    assert (
        include_x86_16_tail_validation_stack_write(
            "stack_slot:SS:BP+0x4:size2",
            mode="live_out",
            observed_locations=observed,
        )
        is False
    )


def test_tail_validation_detects_call_moved_out_of_if_body():
    project = _project()
    before_codegen = _DummyCodegen()
    before_cond = _reg(project, "ax", before_codegen)
    before_call = CFunctionCall("outp", None, [_const(97, before_codegen)], codegen=before_codegen)
    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [CIfElse([(before_cond, CStatements([before_call], codegen=before_codegen))], codegen=before_codegen)],
            before_codegen,
        ),
        mode="live_out",
    )

    after_codegen = _DummyCodegen()
    after_cond = _reg(project, "ax", after_codegen)
    after_call = CFunctionCall("outp", None, [_const(97, after_codegen)], codegen=after_codegen)
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CIfElse([(after_cond, CStatements([], codegen=after_codegen))], codegen=after_codegen),
                after_call,
            ],
            after_codegen,
        ),
        mode="live_out",
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert before.helper_calls == after.helper_calls
    assert diff["changed"] is True
    assert "if-body-calls:reg:ax:name:outp" in diff["delta"]["control_flow_effects"]["removed"]


def test_tail_validation_switch_list_cases_record_case_body_calls():
    project = _project()
    codegen = _DummyCodegen()
    selector = _reg(project, "ax", codegen)
    call = CFunctionCall("outp", None, [_const(97, codegen)], codegen=codegen)
    switch = CSwitchCase(
        selector,
        [(1, CStatements([call], codegen=codegen))],
        CStatements([], codegen=codegen),
        codegen=codegen,
    )

    summary = collect_x86_16_tail_validation_summary(project, _codegen([switch], codegen), mode="live_out")

    assert "case:const:1" in summary.control_flow_effects
    assert "case-body-calls:const:1:name:outp" in summary.control_flow_effects
    assert "case:default" in summary.control_flow_effects


def test_tail_validation_compare_classifies_switch_helper_structuring_precision():
    before_conditions = (
        "CmpGE(stack_slot:SS:BP+0x4:size2,const:1)",
        "CmpGT(Add(stack_slot:SS:BP+0x4:size2,const:-1),const:1)",
        "CmpNE(Add(stack_slot:SS:BP+0x4:size2,const:-2),const:1)",
        "CmpNE(stack_slot:SS:BP+0x4:size2,const:0)",
    )
    after_conditions = (
        "CmpEQ(stack_arg:x:size2:bp+0x4,const:0)",
        "CmpEQ(stack_arg:x:size2:bp+0x4,const:3)",
        "CmpLE(stack_arg:x:size2:bp+0x4,const:2)",
        "CmpLT(stack_arg:x:size2:bp+0x4,const:1)",
    )
    before = X86_16TailValidationSummary(
        helper_calls=("addr:0x1043c",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(
            "Add(Dereference(Add(Mul(reg:ss,const:16),CFakeVariable,const:2)),const:-5)",
            "Add(Dereference(Add(Mul(reg:ss,const:16),CFakeVariable,const:2)),const:20)",
            "Mul(Dereference(Add(Mul(reg:ss,const:16),CFakeVariable,const:2)),const:2)",
            "const:10",
        ),
        conditions=before_conditions,
        control_flow_effects=(*tuple(f"if:{condition}" for condition in before_conditions), "if:else", "return"),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(
            "Add(stack_arg:x:size2:bp+0x4,const:-5)",
            "Add(stack_arg:x:size2:bp+0x4,const:20)",
            "Shl(stack_arg:x:size2:bp+0x4,const:1)",
            "const:10",
        ),
        conditions=after_conditions,
        control_flow_effects=(*tuple(f"if:{condition}" for condition in after_conditions), "return"),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert "switch_helper_structuring" in diff["precision_improvements"]


def test_tail_validation_compare_classifies_switch_decision_tree_without_helper_delta():
    before_conditions = (
        "CmpGE(stack_slot:SS:BP+0x4:size2,const:1)",
        "CmpGT(Add(stack_slot:SS:BP+0x4:size2,const:-1),const:1)",
        "CmpNE(Add(stack_slot:SS:BP+0x4:size2,const:-2),const:1)",
        "CmpNE(stack_slot:SS:BP+0x4:size2,const:0)",
    )
    after_conditions = (
        "CmpEQ(stack_slot:SS:BP+0x4:size2,const:0)",
        "CmpEQ(stack_slot:SS:BP+0x4:size2,const:3)",
        "CmpLE(stack_slot:SS:BP+0x4:size2,const:2)",
        "CmpLT(stack_slot:SS:BP+0x4:size2,const:1)",
    )
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(
            "Add(Dereference(Add(stack_slot:SS:BP+0x4:size2,const:-2)),const:-5)",
            "Add(stack_slot:SS:BP+0x4:size2,const:-1)",
        ),
        conditions=before_conditions,
        control_flow_effects=(*tuple(f"if:{condition}" for condition in before_conditions), "if:else", "return"),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(
            "Add(stack_slot:SS:BP+0x4:size2,const:-5)",
            "Add(stack_slot:SS:BP+0x4:size2,const:20)",
            "Shl(stack_slot:SS:BP+0x4:size2,const:1)",
        ),
        conditions=after_conditions,
        control_flow_effects=(*tuple(f"if:{condition}" for condition in after_conditions), "return"),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert "switch_helper_structuring" in diff["precision_improvements"]


def test_tail_validation_compare_classifies_switch_decision_tree_condition_only_delta():
    before_conditions = (
        "CmpGE(stack_slot:SS:BP+0x4:size2,const:1)",
        "CmpGT(Add(stack_slot:SS:BP+0x4:size2,const:-1),const:1)",
        "CmpNE(stack_slot:SS:BP+0x4:size2,const:0)",
    )
    after_conditions = (
        "CmpEQ(stack_slot:SS:BP+0x4:size2,const:0)",
        "CmpEQ(stack_slot:SS:BP+0x4:size2,const:3)",
        "CmpLE(stack_slot:SS:BP+0x4:size2,const:2)",
        "CmpLT(stack_slot:SS:BP+0x4:size2,const:1)",
    )
    returns = (
        "Add(stack_slot:SS:BP+0x4:size2,const:-5)",
        "Add(stack_slot:SS:BP+0x4:size2,const:20)",
        "Shl(stack_slot:SS:BP+0x4:size2,const:1)",
        "const:10",
    )
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=returns,
        conditions=before_conditions,
        control_flow_effects=(*tuple(f"if:{condition}" for condition in before_conditions), "if:else"),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=returns,
        conditions=after_conditions,
        control_flow_effects=tuple(f"if:{condition}" for condition in after_conditions),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert "switch_helper_structuring" in diff["precision_improvements"]


def test_tail_validation_compare_suppresses_loop_continue_exit_guard_inverse():
    before_condition = "CmpGE(stack_slot:SS:BP-0x2:size2,Or(ds_global:0x160,Shl(ds_global:0x161,const:8)))"
    after_condition = "CmpLT(stack_slot:SS:BP-0x2:size2,Or(ds_global:0x160,Shl(ds_global:0x161,const:8)))"
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(before_condition,),
        control_flow_effects=(f"if:{before_condition}",),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=("reg:ax",),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(after_condition,),
        control_flow_effects=(f"if:{after_condition}",),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert "loop_continue_exit_guard_inverse_structuring" in diff["precision_improvements"]


def test_tail_validation_compare_classifies_switch_helper_fake_variable_returns_without_helper_delta():
    before_conditions = (
        "CmpGE(stack_slot:SS:BP+0x4:size2,const:7)",
        "CmpGT(stack_slot:SS:BP+0x4:size2,const:8)",
        "CmpNE(stack_slot:SS:BP+0x4:size2,const:0)",
    )
    after_conditions = (
        "CmpEQ(stack_slot:SS:BP+0x4:size2,const:0)",
        "CmpEQ(stack_slot:SS:BP+0x4:size2,const:3)",
        "CmpLE(stack_slot:SS:BP+0x4:size2,const:2)",
        "CmpLT(stack_slot:SS:BP+0x4:size2,const:1)",
    )
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(
            "Add(Dereference(Add(Mul(reg:ss,const:16),CFakeVariable,const:2)),const:-5)",
            "Add(Dereference(Add(Mul(reg:ss,const:16),CFakeVariable,const:2)),const:20)",
            "Mul(Dereference(Add(Mul(reg:ss,const:16),CFakeVariable,const:2)),const:2)",
        ),
        conditions=before_conditions,
        control_flow_effects=(*tuple(f"if:{condition}" for condition in before_conditions), "if:else"),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(
            "Add(stack_slot:SS:BP+0x4:size2,const:-5)",
            "Add(stack_slot:SS:BP+0x4:size2,const:20)",
            "Shl(stack_slot:SS:BP+0x4:size2,const:1)",
        ),
        conditions=after_conditions,
        control_flow_effects=tuple(f"if:{condition}" for condition in after_conditions),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert "switch_helper_structuring" in diff["precision_improvements"]


def test_tail_validation_compare_classifies_switch_helper_cite_and_ax_scratch_delta():
    before_conditions = (
        "CITE",
        "CmpGE(stack_slot:SS:BP+0x4:size2,const:1)",
        "CmpGT(Add(stack_slot:SS:BP+0x4:size2,const:-1),const:1)",
        "CmpNE(reg:ax,const:0)",
    )
    after_conditions = (
        "CmpEQ(stack_slot:SS:BP+0x4:size2,const:0)",
        "CmpEQ(stack_slot:SS:BP+0x4:size2,const:3)",
        "CmpLE(stack_slot:SS:BP+0x4:size2,const:2)",
        "CmpLT(stack_slot:SS:BP+0x4:size2,const:1)",
    )
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=("reg:ax",),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(
            "Add(Dereference(Add(Mul(reg:ss,const:16),CFakeVariable,const:2)),const:-5)",
            "Add(Dereference(Add(Mul(reg:ss,const:16),CFakeVariable,const:2)),const:20)",
            "Mul(Dereference(Add(Mul(reg:ss,const:16),CFakeVariable,const:2)),const:2)",
        ),
        conditions=before_conditions,
        control_flow_effects=(*tuple(f"if:{condition}" for condition in before_conditions), "if:else"),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(
            "Add(stack_slot:SS:BP+0x4:size2,const:-5)",
            "Add(stack_slot:SS:BP+0x4:size2,const:20)",
            "Shl(stack_slot:SS:BP+0x4:size2,const:1)",
        ),
        conditions=after_conditions,
        control_flow_effects=tuple(f"if:{condition}" for condition in after_conditions),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["precision_improvements"]["switch_helper_structuring"]["register_writes"] == {
        "added": (),
        "removed": ("reg:ax",),
    }


def test_tail_validation_compare_classifies_switch_helper_eq_ax_zero_selector_delta():
    before_conditions = (
        "CmpEQ(reg:ax,const:0)",
        "CmpGE(stack_slot:SS:BP+0x4:size2,const:1)",
        "CmpGT(Add(stack_slot:SS:BP+0x4:size2,const:-1),const:1)",
    )
    after_conditions = (
        "CmpEQ(stack_slot:SS:BP+0x4:size2,const:0)",
        "CmpEQ(stack_slot:SS:BP+0x4:size2,const:3)",
        "CmpLE(stack_slot:SS:BP+0x4:size2,const:2)",
        "CmpLT(stack_slot:SS:BP+0x4:size2,const:1)",
    )
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=("reg:ax",),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(
            "Add(Dereference(Add(Mul(reg:ss,const:16),CFakeVariable,const:2)),const:-5)",
            "Add(Dereference(Add(Mul(reg:ss,const:16),CFakeVariable,const:2)),const:20)",
            "Mul(Dereference(Add(Mul(reg:ss,const:16),CFakeVariable,const:2)),const:2)",
        ),
        conditions=before_conditions,
        control_flow_effects=(*tuple(f"if:{condition}" for condition in before_conditions), "if:else"),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(
            "Add(stack_slot:SS:BP+0x4:size2,const:-5)",
            "Add(stack_slot:SS:BP+0x4:size2,const:20)",
            "Shl(stack_slot:SS:BP+0x4:size2,const:1)",
        ),
        conditions=after_conditions,
        control_flow_effects=tuple(f"if:{condition}" for condition in after_conditions),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert "switch_helper_structuring" in diff["precision_improvements"]


def test_tail_validation_compare_treats_dword_scalar_projections_as_word_globals():
    before_low = "CmpEQ(global:0x132,const:900)"
    before_high = "CmpEQ(global:0x134,const:0)"
    after_low = "CmpEQ(And(global:0x132,const:65535),const:900)"
    after_high = "CmpEQ(Shr(global:0x132,const:16),const:0)"
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(before_low, before_high),
        control_flow_effects=(f"if:{before_low}", f"if:{before_high}"),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(after_low, after_high),
        control_flow_effects=(f"if:{after_low}", f"if:{after_high}"),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["conditions"] == {"added": (), "removed": ()}
    assert diff["delta"]["control_flow_effects"] == {"added": (), "removed": ()}


def test_tail_validation_compare_compacts_global_byte_pair_condition_after_canonicalization():
    lhs = "Add(" + ",".join(f"reg:r{idx}" for idx in range(90)) + ")"
    before_condition = f"CmpLT({lhs},Or(global:0x160,Shl(global:0x161,const:8)))"
    after_condition = f"CmpLT({lhs},global:0x160)"
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(f"if:{before_condition}",),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(f"if:{after_condition}",),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["control_flow_effects"] == {"added": (), "removed": ()}


def test_tail_validation_compare_compacts_identical_oversized_conditions():
    long_condition = "CmpNE(" + ",".join(f"Add(reg:sp,const:{idx})" for idx in range(128)) + ")"
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(long_condition,),
        control_flow_effects=(),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(long_condition,),
        control_flow_effects=(),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["conditions"] == {"added": (), "removed": ()}


def test_tail_validation_compare_compacts_changed_oversized_conditions():
    long_before = "CmpNE(" + ",".join(f"Add(reg:sp,const:{idx})" for idx in range(128)) + ")"
    long_after = "CmpNE(" + ",".join(f"Add(reg:sp,const:{idx + 1})" for idx in range(128)) + ")"
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(long_before,),
        control_flow_effects=(),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(long_after,),
        control_flow_effects=(),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)
    formatted = format_x86_16_tail_validation_diff(diff)

    assert diff["changed"] is True
    assert diff["delta"]["conditions"]["added"][0].startswith("conditions:sha256:")
    assert diff["delta"]["conditions"]["removed"][0].startswith("conditions:sha256:")
    assert len(formatted) < 220


def test_large_function_local_evidence_only_allows_primary_callsite_materialization():
    codegen = SimpleNamespace(
        _inertia_postprocess_function_complexity_8616={"blocks": 42, "bytes": 0x180},
        _inertia_callsite_summaries={
            1: SimpleNamespace(push_arg_sources=("ax", None)),
        },
    )
    very_large_codegen = SimpleNamespace(
        _inertia_postprocess_function_complexity_8616={"blocks": 76, "bytes": 0x1AE},
        _inertia_callsite_summaries={
            1: SimpleNamespace(push_arg_sources=("ax", None)),
        },
    )

    assert (
        postprocess_stage._postprocess_pass_has_local_evidence_8616(
            "_materialize_callsite_stack_arguments_8616",
            codegen,
        )
        is True
    )
    assert (
        postprocess_stage._postprocess_pass_has_local_evidence_8616(
            "_materialize_recovered_callsite_stack_arguments_8616",
            codegen,
        )
        is False
    )
    assert (
        postprocess_stage._postprocess_pass_has_local_evidence_8616(
            "_materialize_callsite_stack_arguments_8616",
            very_large_codegen,
        )
        is False
    )
    assert (
        postprocess_stage._postprocess_pass_has_local_evidence_8616(
            "_materialize_callsite_stack_arguments_final_8616",
            codegen,
        )
        is False
    )


def test_tail_validation_normalizes_named_helper_call_with_project_label_to_addr():
    project = _project()
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(function=lambda **_kwargs: None), labels={0x112BA: "_sprintf"}
    )

    assert tail_validation_module._normalize_helper_call_fingerprint_8616(project, "name:sprintf") == "addr:0x112ba"


def test_tail_validation_normalizes_cod_helper_call_with_project_label_to_addr():
    project = _project()
    project.kb = SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: None), labels={0x11414: "_rand"})

    assert tail_validation_module._normalize_helper_call_fingerprint_8616(project, "codcall:rand") == "addr:0x11414"


def test_tail_validation_normalizes_active_callsite_addr_helper_to_target(monkeypatch):
    project = _project()
    codegen = _DummyCodegen()
    _codegen([], codegen)
    codegen.cfunc.get_call_sites = lambda: (0x10678,)
    project._inertia_tail_validation_active_codegen = codegen
    monkeypatch.setattr(
        tail_validation_module,
        "summarize_x86_16_callsite",
        lambda _function, callsite_addr: _callsite_summary(callsite_addr, 0x11414),
    )

    try:
        normalized = tail_validation_module._normalize_helper_call_fingerprint_8616(project, "addr:0x10678")
    finally:
        delattr(project, "_inertia_tail_validation_active_codegen")

    assert normalized == "addr:0x11414"


def test_tail_validation_does_not_reinterpret_callee_target_addr_as_active_callsite(monkeypatch):
    project = _project()
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, create=False, **_kwargs: (
                SimpleNamespace(addr=0x10010, name="sub_10010") if addr == 0x10010 and not create else None
            )
        )
    )
    codegen = _DummyCodegen()
    _codegen([], codegen)
    codegen.cfunc.get_call_sites = lambda: (0x10010, 0x1005E)
    project._inertia_tail_validation_active_codegen = codegen
    monkeypatch.setattr(
        tail_validation_module,
        "summarize_x86_16_callsite",
        lambda _function, callsite_addr: _callsite_summary(callsite_addr, 0x1038E),
    )

    try:
        normalized = tail_validation_module._normalize_helper_call_fingerprint_8616(project, "addr:0x10010")
    finally:
        delattr(project, "_inertia_tail_validation_active_codegen")

    assert normalized == "addr:0x10010"


def test_tail_validation_identifies_binary_stack_probe_target_without_symbol_name():
    probe_pattern = bytes.fromhex("59 8b dc 2b d8 72 0a 3b 1e b6 00 72 04 8b e3 ff e1")
    mapped_addr = 0x138E

    def _load(addr: int, size: int) -> bytes:
        offset = addr - mapped_addr
        if offset < 0:
            raise KeyError(addr)
        return probe_pattern[offset : offset + size]

    project = _project()
    project.loader = SimpleNamespace(
        memory=SimpleNamespace(load=_load),
        main_object=SimpleNamespace(linked_base=0x1000),
    )

    assert tail_validation_module._target_addr_is_stack_probe_helper_8616(project, 0x1038E)


def test_tail_validation_refuses_stack_probe_summary_for_nonprobe_call_node():
    probe_pattern = bytes.fromhex("59 8b dc 2b d8 72 0a 3b 1e b6 00 72 04 8b e3 ff e1")

    def _load(addr: int, size: int) -> bytes:
        offset = addr - 0x138E
        if offset < 0:
            raise KeyError(addr)
        return probe_pattern[offset : offset + size]

    project = _project()
    project.loader = SimpleNamespace(
        memory=SimpleNamespace(load=_load),
        main_object=SimpleNamespace(linked_base=0x1000),
    )
    codegen = _DummyCodegen()
    call = CFunctionCall("sub_10010", SimpleNamespace(addr=0x10010, name="sub_10010"), [], codegen=codegen)
    summary = _callsite_summary(0x1005E, 0x1038E)

    assert not tail_validation_module._call_node_matches_summary_8616(project, call, summary)


def test_tail_validation_preserves_stack_probe_identity_for_wrapped_summary():
    project = _project()
    summary = _callsite_summary(0x1005E, 0x1038E, stack_probe_helper=True)
    wrapped = {"summary": summary, "target_addr": 0x1038E, "callsite_addr": 0x1005E}
    call = CFunctionCall("sub_10010", SimpleNamespace(addr=0x10010, name="sub_10010"), [], codegen=_DummyCodegen())

    assert tail_validation_module._summary_is_stack_probe_helper_8616(wrapped)
    assert tail_validation_module._call_summary_target_addr_8616(project, wrapped) == 0x1038E
    assert tail_validation_module._call_node_is_stack_probe_helper_8616(project, call, wrapped)


def test_tail_validation_recognizes_stack_probe_helper_call_fingerprints():
    probe_pattern = bytes.fromhex("59 8b dc 2b d8 72 0a 3b 1e b6 00 72 04 8b e3 ff e1")

    def _load(addr: int, size: int) -> bytes:
        offset = addr - 0x138E
        if offset < 0:
            raise KeyError(addr)
        return probe_pattern[offset : offset + size]

    project = _project()
    project.loader = SimpleNamespace(
        memory=SimpleNamespace(load=_load),
        main_object=SimpleNamespace(linked_base=0x1000),
    )

    assert tail_validation_module._helper_call_fingerprint_targets_stack_probe_8616(project, "addr:0x1038e")
    assert tail_validation_module._helper_call_fingerprint_targets_stack_probe_8616(project, "name:addr:0x1038e")
    assert not tail_validation_module._helper_call_fingerprint_targets_stack_probe_8616(project, "addr:0x10010")


def test_tail_validation_accounts_condition_owned_call_when_body_call_membership_changes():
    before = X86_16TailValidationSummary(
        helper_calls=("addr:0x10010", "addr:0x106d6"),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=("none",),
        conditions=("CmpEQ(call:addr:0x10010(),const:0)",),
        control_flow_effects=(
            "if-body-calls:CmpEQ(call:addr:0x10010(),const:0):addr:0x10010,addr:0x106d6",
            "return",
        ),
    )
    after = X86_16TailValidationSummary(
        helper_calls=("addr:0x106d6",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=("none",),
        conditions=("CmpEQ(call:addr:0x10010(),const:0)",),
        control_flow_effects=(
            "if-body-calls:Not(CmpNE(call:addr:0x10010(),const:0)):name:addr:0x106d6",
            "return",
        ),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert "helper_calls_accounted_by_conditions" in diff["precision_improvements"]


def test_tail_validation_accounts_condition_owned_call_when_stack_arg_is_reconciled():
    before = X86_16TailValidationSummary(
        helper_calls=("addr:0x10010", "addr:0x106d6"),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=("none",),
        conditions=("CmpEQ(call:addr:0x10010(),const:0)",),
        control_flow_effects=(
            "for-body-calls:CmpGE(stack_arg:arg_4:size2:bp+0x4,stack_slot:SS:BP-0x2:size2):addr:0x10010,addr:0x106d6",
            "if-body-calls:CmpEQ(call:addr:0x10010(),const:0):addr:0x10010,addr:0x106d6",
            "if-body-calls:CmpEQ(call:addr:0x10010(),const:0):addr:0x106d6",
            "if-body-calls:CmpLT(stack_slot:SS:BP+0x4:size2,const:2):addr:0x10010,addr:0x106d6",
            "return",
        ),
    )
    after = X86_16TailValidationSummary(
        helper_calls=("addr:0x106d6",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=("none",),
        conditions=("CmpEQ(call:addr:0x10010(),const:0)",),
        control_flow_effects=(
            "for-body-calls:CmpGE(stack_slot:SS:BP+0x4:size2,stack_slot:SS:BP-0x2:size2):addr:0x106d6",
            "if-body-calls:Not(CmpNE(call:addr:0x10010(),const:0)):addr:0x106d6",
            "if-body-calls:CmpLT(stack_slot:SS:BP+0x4:size2,const:2):addr:0x106d6",
            "return",
        ),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert "helper_calls_accounted_by_conditions" in diff["precision_improvements"]


def test_tail_validation_normalizes_exact_slice_call_target_to_original_addr():
    project = _project()
    project.loader = SimpleNamespace(main_object=SimpleNamespace(linked_base=0x1000, max_addr=0x10A8))
    project._inertia_original_linear_delta = 0xFE70
    project._inertia_original_project = SimpleNamespace(
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x5000))
    )

    assert tail_validation_module._normalized_call_target_addr_8616(project, 0x14AE) == 0x1131E
    assert tail_validation_module._normalized_call_target_addr_8616(project, 0x1131E) == 0x1131E


def test_postprocess_validation_accepts_direct_helper_callsite_rename():
    class Functions:
        def function(self, *, addr=None, create=False, **_kwargs):
            if addr == 0x105D2 and not create:
                return SimpleNamespace(addr=addr, name="sub_105d2")
            return None

    project = _project()
    project.kb = SimpleNamespace(functions=Functions(), labels={})
    function = SimpleNamespace(
        get_call_sites=lambda: (0x10016,),
        get_call_target=lambda _addr: 0x105D2,
    )
    validation = {
        "delta": {
            "helper_calls": {
                "added": ("name:aNchkstk",),
                "removed": ("name:addr:0x105d2",),
            },
            "returns": {"added": (), "removed": ()},
            "conditions": {"added": (), "removed": ()},
        }
    }

    assert postprocess_stage._is_direct_callsite_helper_delta_only_8616(project, function, validation) is True


def test_tail_validation_counts_helper_call_in_assignment_rhs():
    project = _project()
    codegen = _DummyCodegen()
    call = CFunctionCall("::0x112ba::sprintf", None, [_const(1, codegen)], codegen=codegen)
    _codegen(
        [
            CAssignment(
                _reg(project, "ax", codegen, var_name="ret"),
                call,
                codegen=codegen,
            )
        ],
        codegen,
    )

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ("name:sprintf",)


def test_tail_validation_counts_call_nested_in_direct_call_argument():
    project = _project()
    codegen = _DummyCodegen()
    division = CFunctionCall(
        "aNldiv",
        None,
        [_const(1000, codegen), _const(10, codegen)],
        codegen=codegen,
    )
    sprintf = CFunctionCall(
        "sprintf",
        None,
        [_const(1, codegen), division],
        codegen=codegen,
    )
    _codegen([sprintf], codegen)
    codegen._inertia_callsite_summaries = {id(division): _callsite_summary(0x1042, 0x1137E)}

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ("name:sprintf", "addr:0x1137e")


def test_contextual_call_completion_normalizes_observed_names_before_counting(monkeypatch):
    project = _project()
    helper_calls = ["name:aNldiv"]
    monkeypatch.setattr(
        tail_validation_module,
        "_function_for_call_context_8616",
        lambda _root, _project: object(),
    )
    monkeypatch.setattr(
        tail_validation_module,
        "_function_callsite_addrs_for_validation_8616",
        lambda _function: (0x1042,),
    )
    monkeypatch.setattr(
        tail_validation_module,
        "_callsite_expected_fingerprint_8616",
        lambda _function, _project, _callsite, _summary_inventory=None: "addr:0x1137e",
    )
    monkeypatch.setattr(
        tail_validation_module,
        "_normalize_helper_call_fingerprint_8616",
        lambda _project, fingerprint: (
            "addr:0x1137e" if fingerprint in {"name:aNldiv", "addr:0x1137e"} else fingerprint
        ),
    )

    tail_validation_module._append_missing_contextual_callsite_fingerprints_8616(
        object(),
        project,
        helper_calls,
    )

    assert helper_calls == ["name:aNldiv"]


def test_tail_validation_counts_helper_call_nested_in_assignment_rhs():
    project = _project()
    codegen = _DummyCodegen()
    call = CFunctionCall("rand", None, [], codegen=codegen)
    signed_call = CTypeCast(SimTypeShort(False), SimTypeShort(True), call, codegen=codegen)
    rhs = CBinaryOp(
        "Mod",
        signed_call,
        CVariable(
            SimStackVariable(-4, 2, base="bp", name="iRowMax"),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    _codegen(
        [
            CAssignment(
                CVariable(
                    SimStackVariable(-0x76, 2, base="bp", name="iRand"),
                    variable_type=SimTypeShort(False),
                    codegen=codegen,
                ),
                rhs,
                codegen=codegen,
            )
        ],
        codegen,
    )

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ("name:rand",)


def test_tail_validation_counts_loop_body_call_nested_in_assignment_rhs():
    project = _project()
    codegen = _DummyCodegen()
    cond = CBinaryOp(
        "CmpGT",
        _global(0xBA2, codegen, name="cRow"),
        CVariable(
            SimStackVariable(-2, 2, base="bp", name="iRow"),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    call = CFunctionCall("rand", None, [], codegen=codegen)
    signed_call = CTypeCast(SimTypeShort(False), SimTypeShort(True), call, codegen=codegen)
    rhs = CBinaryOp(
        "Mod",
        signed_call,
        CBinaryOp(
            "Add",
            CVariable(
                SimStackVariable(-4, 2, base="bp", name="iRowMax"),
                variable_type=SimTypeShort(False),
                codegen=codegen,
            ),
            _const(1, codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    body = CStatements(
        [
            CAssignment(
                CVariable(
                    SimStackVariable(-0x76, 2, base="bp", name="iRand"),
                    variable_type=SimTypeShort(False),
                    codegen=codegen,
                ),
                rhs,
                codegen=codegen,
            )
        ],
        codegen=codegen,
    )
    _codegen([CForLoop(None, cond, None, body, codegen=codegen)], codegen)

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert "for-body-calls:CmpGT(ds_global:0xba2,stack_slot:SS:BP-0x2:size2):name:rand" in summary.control_flow_effects


def test_tail_validation_fingerprints_do_while_condition_after_terminal_induction() -> None:
    project = _project()
    codegen = _DummyCodegen()
    iterator_lhs = _reg(project, "si", codegen)
    iterator = CAssignment(
        iterator_lhs,
        CBinaryOp(
            "Add",
            _reg(project, "si", codegen),
            _const(2, codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    condition = CBinaryOp(
        "CmpLT",
        CBinaryOp(
            "Add",
            _reg(project, "si", codegen),
            _const(2, codegen),
            codegen=codegen,
        ),
        _reg(project, "ax", codegen),
        codegen=codegen,
    )
    loop = CDoWhileLoop(
        condition,
        CStatements([iterator], codegen=codegen),
        codegen=codegen,
    )

    summary = collect_x86_16_tail_validation_summary(
        project,
        _codegen([loop], codegen),
        mode="live_out",
    )

    expected = "CmpLT(Add(Add(reg:si,const:2),const:2),reg:ax)"
    assert expected in summary.conditions
    assert f"dowhile:{expected}" in summary.control_flow_effects


def test_tail_validation_counts_shared_loop_body_call_node_once():
    project = _project()
    codegen = _DummyCodegen()
    cond = CBinaryOp("CmpNE", _reg(project, "ax", codegen), _const(0, codegen), codegen=codegen)
    call = CFunctionCall("rand", None, [], codegen=codegen)
    rhs = CBinaryOp("Add", call, call, codegen=codegen)
    body = CStatements(
        [
            CAssignment(
                CVariable(
                    SimStackVariable(-0x76, 2, base="bp", name="iRand"),
                    variable_type=SimTypeShort(False),
                    codegen=codegen,
                ),
                rhs,
                codegen=codegen,
            )
        ],
        codegen=codegen,
    )
    _codegen([CForLoop(None, cond, None, body, codegen=codegen)], codegen)

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert "for-body-calls:CmpNE(reg:ax,const:0):name:rand" in summary.control_flow_effects
    assert "for-body-calls:CmpNE(reg:ax,const:0):name:rand,name:rand" not in summary.control_flow_effects


def test_tail_validation_counts_same_callsite_loop_body_call_once():
    project = _project()
    codegen = _DummyCodegen()
    cond = CBinaryOp("CmpNE", _reg(project, "ax", codegen), _const(0, codegen), codegen=codegen)
    first = CFunctionCall("rand", None, [], codegen=codegen)
    second = CFunctionCall("rand", None, [], codegen=codegen)
    first.tags["ins_addr"] = 0x4012
    second.tags["ins_addr"] = 0x4012
    body = CStatements([first, second], codegen=codegen)
    _codegen([CForLoop(None, cond, None, body, codegen=codegen)], codegen)

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ("name:rand",)
    assert "for-body-calls:CmpNE(reg:ax,const:0):name:rand" in summary.control_flow_effects
    assert "for-body-calls:CmpNE(reg:ax,const:0):name:rand,name:rand" not in summary.control_flow_effects


def test_tail_validation_counts_contextual_callsite_loop_body_call_once(monkeypatch):
    project = _project()
    codegen = _DummyCodegen()
    cond = CBinaryOp("CmpNE", _reg(project, "ax", codegen), _const(0, codegen), codegen=codegen)
    unlocated = CFunctionCall("addr:0x11414", None, [], codegen=codegen)
    located = CFunctionCall("addr:0x11414", None, [], codegen=codegen)
    body = CStatements([unlocated, located], codegen=codegen)
    _codegen([CForLoop(None, cond, None, body, codegen=codegen)], codegen)
    codegen.cfunc.get_call_sites = lambda: (0x10678,)

    monkeypatch.setattr(
        tail_validation_module,
        "summarize_x86_16_callsite",
        lambda _function, callsite_addr: _callsite_summary(callsite_addr, 0x11414),
    )

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ("addr:0x11414",)
    assert "for-body-calls:CmpNE(reg:ax,const:0):addr:0x11414" in summary.control_flow_effects
    assert "for-body-calls:CmpNE(reg:ax,const:0):addr:0x11414,addr:0x11414" not in summary.control_flow_effects


def test_tail_validation_collapses_mixed_addr_name_addr_loop_body_call():
    collapsed = tail_validation_module._collapse_mixed_addr_name_addr_duplicates_8616(
        ("addr:0x11414", "name:addr:0x11414")
    )

    assert collapsed == ("addr:0x11414",)


def test_tail_validation_expected_helper_counts_suppress_duplicate_unknown_indirect():
    project = _project()
    expected = {"addr:0x11414": 1}

    assert tail_validation_module._helper_call_fingerprints_satisfy_expected_8616(
        project,
        ("addr:0x11414",),
        expected,
    )
    assert not tail_validation_module._helper_call_fingerprints_satisfy_expected_8616(
        project,
        (),
        expected,
    )


def test_tail_validation_summary_uses_precomputed_boundary_fingerprint(monkeypatch):
    project = _project()
    codegen = _DummyCodegen()
    _codegen([], codegen)

    def fail_fingerprint(*_args, **_kwargs):
        raise AssertionError("boundary fingerprint was recomputed")

    monkeypatch.setattr(tail_validation_module, "fingerprint_x86_16_tail_validation_boundary", fail_fingerprint)

    summary = collect_x86_16_tail_validation_summary(
        project,
        codegen,
        mode="live_out",
        boundary_fingerprint="precomputed:empty",
    )

    assert summary == X86_16TailValidationSummary((), (), (), (), (), (), (), ())


def test_tail_validation_summary_cache_hit_skips_ast_walk(monkeypatch):
    project = _project()
    codegen = _DummyCodegen()
    _codegen([], codegen)

    first = collect_x86_16_tail_validation_summary(
        project,
        codegen,
        mode="live_out",
        boundary_fingerprint="precomputed:empty",
    )

    def fail_iter(*_args, **_kwargs):
        raise AssertionError("cached summary walked AST")

    monkeypatch.setattr(tail_validation_module, "_iter_c_nodes_deep_8616", fail_iter)

    second = collect_x86_16_tail_validation_summary(
        project,
        codegen,
        mode="live_out",
        boundary_fingerprint="precomputed:empty",
    )

    assert second == first
    assert codegen._inertia_tail_validation_last_summary_cache_hit is True


def test_tail_validation_fresh_boundary_cache_hit_skips_semantic_validators(monkeypatch):
    project = _project()
    codegen = _DummyCodegen()
    _codegen([], codegen)

    first = collect_x86_16_tail_validation_summary(project, codegen)
    boundary_fingerprint = fingerprint_x86_16_tail_validation_boundary(project, codegen)

    def fail_validator(*_args, **_kwargs):
        raise AssertionError("fresh boundary cache reran semantic validator")

    for validator_name in (
        "validate_structured_def_use_8616",
        "validate_required_callsites_8616",
        "validate_required_callsite_multiplicity_8616",
        "validate_call_interfaces_8616",
        "validate_call_argument_classes_8616",
        "validate_function_parameters_8616",
        "validate_function_return_class_8616",
        "_validate_final_control_flow_8616",
        "validate_storage_identities_8616",
    ):
        monkeypatch.setattr(tail_validation_module, validator_name, fail_validator)

    second = collect_x86_16_tail_validation_summary(
        project,
        codegen,
        boundary_fingerprint=boundary_fingerprint,
    )

    assert second is first
    assert codegen._inertia_tail_validation_last_summary_cache_hit is True


def test_tail_validation_fresh_boundary_cache_misses_after_evidence_generation_change(monkeypatch):
    project = _project()
    codegen = _DummyCodegen()
    _codegen([], codegen)

    first = collect_x86_16_tail_validation_summary(project, codegen)
    codegen._inertia_function_parameter_width_facts_8616 = ()
    boundary_fingerprint = fingerprint_x86_16_tail_validation_boundary(project, codegen)
    original_validator = tail_validation_module.validate_required_callsites_8616
    validator_calls = 0

    def count_validator(*args, **kwargs):
        nonlocal validator_calls
        validator_calls += 1
        return original_validator(*args, **kwargs)

    monkeypatch.setattr(
        tail_validation_module,
        "validate_required_callsites_8616",
        count_validator,
    )

    second = collect_x86_16_tail_validation_summary(
        project,
        codegen,
        boundary_fingerprint=boundary_fingerprint,
    )

    assert second is first
    assert validator_calls == 1


def test_tail_validation_collects_duplicate_helper_calls():
    project = _project()
    codegen = _DummyCodegen()
    first = CFunctionCall("::0x112ba::sprintf", None, [_const(1, codegen)], codegen=codegen)
    second = CFunctionCall("::0x112ba::sprintf", None, [_const(2, codegen)], codegen=codegen)
    _codegen(
        [
            CAssignment(
                _reg(project, "ax", codegen, var_name="ret1"),
                first,
                codegen=codegen,
            ),
            CAssignment(
                _reg(project, "ax", codegen, var_name="ret2"),
                second,
                codegen=codegen,
            ),
        ],
        codegen,
    )
    codegen._inertia_callsite_summaries = {
        id(first): _callsite_summary(0x1042, 0x112BA),
        id(second): _callsite_summary(0x1048, 0x112BA),
    }

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ("addr:0x112ba", "addr:0x112ba")


def test_tail_validation_counts_cloned_nodes_for_one_callsite_once():
    project = _project()
    codegen = _DummyCodegen()
    named = CFunctionCall("aNldiv", None, [_const(1000, codegen)], codegen=codegen)
    addressed = CFunctionCall("::0x1137e::aNldiv", None, [_const(1000, codegen)], codegen=codegen)
    _codegen([named, addressed], codegen)
    codegen._inertia_callsite_summaries = {
        id(named): _callsite_summary(0x1042, 0x1137E),
        id(addressed): _callsite_summary(0x1042, 0x1137E),
    }

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ("addr:0x1137e",)


def test_tail_validation_matches_unmapped_clone_by_canonical_target():
    project = _project()
    codegen = _DummyCodegen()
    addressed = CFunctionCall("::0x1137e::aNldiv", None, [_const(1000, codegen)], codegen=codegen)
    cloned = CFunctionCall("addr:0x1137e", None, [_const(1000, codegen)], codegen=codegen)
    _codegen([addressed, cloned], codegen)
    codegen._inertia_callsite_summaries = {
        id(addressed): _callsite_summary(0x1042, 0x1137E),
    }

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ("addr:0x1137e",)


def test_tail_validation_collects_missing_original_callsite(monkeypatch):
    project = _project()
    codegen = _DummyCodegen()
    _codegen([], codegen)
    codegen.cfunc.get_call_sites = lambda: (0x4012,)
    monkeypatch.setattr(
        tail_validation_module,
        "summarize_x86_16_callsite",
        lambda _function, callsite_addr: _callsite_summary(callsite_addr, 0x5000),
    )

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ("missing-callsite:addr:0x5000",)


def test_tail_validation_ignores_observed_stack_probe_helper_call():
    project = _project()
    codegen = _DummyCodegen()
    call = CFunctionCall("__aNchkstk", None, [], codegen=codegen)
    _codegen([call], codegen)

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ()


def test_tail_validation_missing_callsite_ignores_stack_probe_resolved_by_label(monkeypatch):
    project = _project()
    project.kb = SimpleNamespace(labels={0x5000: "__aNchkstk"})
    codegen = _DummyCodegen()
    _codegen([], codegen)
    codegen.cfunc.get_call_sites = lambda: (0x4012,)
    monkeypatch.setattr(
        tail_validation_module,
        "summarize_x86_16_callsite",
        lambda _function, callsite_addr: _callsite_summary(callsite_addr, 0x5000),
    )

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ()


def test_live_out_tail_validation_observes_loop_condition_stack_writes():
    project = _project()
    codegen = _DummyCodegen()
    loop_var = CVariable(
        SimStackVariable(-2, 2, base="bp", name="i"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    condition = CBinaryOp("CmpLT", loop_var, _const(7, codegen), codegen=codegen)
    body = CStatements(
        [
            CAssignment(
                loop_var,
                CBinaryOp("Add", loop_var, _const(1, codegen), codegen=codegen),
                codegen=codegen,
            )
        ],
        codegen=codegen,
    )
    loop = CForLoop(None, condition, None, body, codegen=codegen)
    _codegen([loop], codegen)

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert "stack_slot:SS:BP-0x2:size2" in summary.stack_writes
    assert any(
        item.startswith("for-body-writes:") and "stack_slot:SS:BP-0x2:size2" in item
        for item in summary.control_flow_effects
    )


def test_tail_validation_missing_callsite_gate_ignores_stack_probe(monkeypatch):
    project = _project()
    codegen = _DummyCodegen()
    _codegen([], codegen)
    codegen.cfunc.get_call_sites = lambda: (0x4012,)
    monkeypatch.setattr(
        tail_validation_module,
        "summarize_x86_16_callsite",
        lambda _function, callsite_addr: _callsite_summary(callsite_addr, 0x5000, stack_probe_helper=True),
    )

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ()


def _codegen(statements, codegen=None):
    codegen = codegen or _DummyCodegen()
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=CStatements(statements, addr=0x4010, codegen=codegen))
    return codegen


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _reg(
    project,
    name: str,
    codegen,
    *,
    var_name: str | None = None,
    ident: int | str | None = None,
    region: int | None = None,
):
    reg_offset, reg_size = project.arch.registers[name]
    return CVariable(
        SimRegisterVariable(
            reg_offset,
            reg_size,
            ident=ident,
            name=var_name or name,
            region=region,
        ),
        codegen=codegen,
    )


def _stack(offset: int, codegen, *, name: str = "local"):
    return CVariable(SimStackVariable(offset, 2, name=name), codegen=codegen)


def _global(addr: int, codegen, *, name: str = "g"):
    return CVariable(SimMemoryVariable(addr, 2, name=name), codegen=codegen)


def test_tail_validation_summary_does_not_reuse_stale_expr_cache_after_condition_mutation():
    project = _project()
    codegen = _DummyCodegen()
    lhs = _stack(-2, codegen)
    rhs = _const(10, codegen)
    cond = CBinaryOp("CmpLT", lhs, rhs, codegen=codegen)
    stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    _codegen([stmt], codegen)

    before = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")
    cond.op = "CmpGT"
    after = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert "CmpLT(stack_slot:SS:BP-0x2:size2,const:10)" in before.conditions
    assert "CmpGT(stack_slot:SS:BP-0x2:size2,const:10)" in after.conditions
    assert "CmpLT(stack_slot:SS:BP-0x2:size2,const:10)" not in after.conditions


def test_tail_validation_source_stack_arg_uses_x86_16_int_width():
    function = SimpleNamespace(
        addr=0x1000,
        prototype=SimTypeFunction((SimTypeInt(signed=True),), SimTypeInt(signed=True), arg_names=("x",)),
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, **_kwargs: function if addr == 0x1000 else None)
        ),
    )
    codegen = _DummyCodegen()
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=(CVariable(SimStackVariable(4, 4, base="bp", name="x"), codegen=codegen),),
    )
    node = CVariable(SimStackVariable(4, 4, base="bp", name="x"), codegen=codegen)

    assert tail_validation_fingerprint_module._source_arg_location_fingerprint_8616(node, project) == (
        "stack_arg:x:size2:bp+0x4"
    )

    wrong_offset = CVariable(SimStackVariable(8, 2, base="bp", name="x"), codegen=codegen)
    assert tail_validation_fingerprint_module._source_arg_location_fingerprint_8616(wrong_offset, project) is None


def test_tail_validation_source_stack_arg_prefers_source_offset_over_mutated_cfunc_arg_name():
    function = SimpleNamespace(
        addr=0x1000,
        prototype=SimTypeFunction(
            (SimTypeInt(signed=True), SimTypeInt(signed=True)),
            SimTypeInt(signed=True),
            arg_names=("a", "b"),
        ),
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, **_kwargs: function if addr == 0x1000 else None)
        ),
    )
    codegen = _DummyCodegen()
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=(
            CVariable(SimStackVariable(4, 2, base="bp", name="b"), codegen=codegen),
            CVariable(SimStackVariable(6, 2, base="bp", name="arg_6"), codegen=codegen),
        ),
    )
    node = CVariable(SimStackVariable(4, 2, base="bp", name="b"), codegen=codegen)

    assert tail_validation_fingerprint_module._source_arg_location_fingerprint_8616(node, project) == (
        "stack_arg:a:size2:bp+0x4"
    )


def test_tail_validation_positive_bp_stack_slot_fingerprint_uses_source_arg_offset():
    function = SimpleNamespace(
        addr=0x1000,
        prototype=SimTypeFunction(
            (SimTypeInt(signed=True), SimTypeInt(signed=True)),
            SimTypeInt(signed=True),
            arg_names=("iLow", "iHigh"),
        ),
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, **_kwargs: function if addr == 0x1000 else None)
        ),
    )
    codegen = _DummyCodegen()
    codegen.project = project
    codegen.cfunc = SimpleNamespace(addr=0x1000)

    assert tail_validation_fingerprint_module._canonical_or_unresolved_stack_fingerprint_8616(
        6,
        codegen,
        source="word_pair",
    ) == "stack_arg:iHigh:size2:bp+0x6"


def test_tail_validation_positive_bp_stack_slot_fingerprint_uses_cfunc_arg_offset_fallback():
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr=None, **_kwargs: None)),
    )
    codegen = _DummyCodegen()
    codegen.project = project
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=(
            CVariable(SimStackVariable(4, 2, base="bp", name="iLow"), codegen=codegen),
            CVariable(SimStackVariable(6, 2, base="bp", name="iHigh"), codegen=codegen),
        ),
    )

    assert tail_validation_fingerprint_module._canonical_or_unresolved_stack_fingerprint_8616(
        4,
        codegen,
        source="indexed_combined",
    ) == "stack_arg:iLow:size2:bp+0x4"


def test_tail_validation_positive_bp_stack_slot_uses_active_codegen_fallback():
    function = SimpleNamespace(
        addr=0x1000,
        prototype=SimTypeFunction(
            (SimTypeInt(signed=True), SimTypeInt(signed=True)),
            SimTypeInt(signed=True),
            arg_names=("iLow", "iHigh"),
        ),
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr=None, **_kwargs: function if addr == 0x1000 else None)
        ),
    )
    active_codegen = _DummyCodegen()
    active_codegen.project = project
    active_codegen.cfunc = SimpleNamespace(addr=0x1000)
    project._inertia_tail_validation_active_codegen = active_codegen
    stale_codegen = _DummyCodegen()
    stale_codegen.project = project
    stale_codegen.cfunc = SimpleNamespace(addr=None)

    assert tail_validation_fingerprint_module._canonical_or_unresolved_stack_fingerprint_8616(
        4,
        stale_codegen,
        source="bp_deref",
    ) == "stack_arg:iLow:size2:bp+0x4"


def test_tail_validation_bp_stack_fingerprint_is_not_reused_after_source_arg_context_arrives():
    function = SimpleNamespace(
        addr=0x1000,
        prototype=SimTypeFunction((SimTypeInt(signed=True),), SimTypeInt(signed=True), arg_names=("iLow",)),
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        _inertia_tv_active_function_addr=0x1000,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr=None, **_kwargs: function if addr == 0x1000 else None)
        ),
    )
    stale_codegen = _DummyCodegen()
    stale_codegen.project = project
    node = CVariable(SimStackVariable(4, 2, base="bp", name="arg_4"), codegen=stale_codegen)

    assert tail_validation_fingerprint_module._expr_fingerprint(node, project) == "stack_slot:SS:BP+0x4:size2"

    active_codegen = _DummyCodegen()
    active_codegen.project = project
    active_codegen.cfunc = SimpleNamespace(addr=0x1000)
    project._inertia_tail_validation_active_codegen = active_codegen

    assert tail_validation_fingerprint_module._expr_fingerprint(node, project) == "stack_arg:iLow:size2:bp+0x4"


def test_tail_validation_canonicalizes_dereference_of_indexed_lvalue_reference():
    project = _project()
    codegen = _DummyCodegen()
    base = CVariable(SimStackVariable(-44, 43, base="bp", name="achT"), codegen=codegen)
    indexed = CIndexedVariable(
        base,
        CConstant(3, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    wrapped = CUnaryOp(
        "Dereference",
        CUnaryOp("Reference", indexed, codegen=codegen),
        codegen=codegen,
    )

    assert tail_validation_fingerprint_module._expr_fingerprint(
        wrapped, project
    ) == tail_validation_fingerprint_module._expr_fingerprint(indexed, project)


def test_tail_validation_matches_dynamic_indexed_word_write_to_byte_store_pair():
    project = _project()
    raw_codegen = _DummyCodegen()
    raw_index = _stack(-2, raw_codegen, name="iRow")
    scaled_index = CBinaryOp("Mul", raw_index, _const(2, raw_codegen), codegen=raw_codegen)
    raw_stores = []
    for byte_offset in range(2):
        base = CVariable(
            SimMemoryVariable(0xB4C + byte_offset, 1, name="abarWork"),
            codegen=raw_codegen,
        )
        address = CBinaryOp(
            "Add",
            CUnaryOp("Reference", base, codegen=raw_codegen),
            scaled_index,
            codegen=raw_codegen,
        )
        raw_stores.append(
            CAssignment(
                CUnaryOp("Dereference", address, codegen=raw_codegen),
                _const(byte_offset, raw_codegen),
                codegen=raw_codegen,
            )
        )
    raw_loop = CForLoop(
        None,
        _const(1, raw_codegen),
        None,
        CStatements(raw_stores, codegen=raw_codegen),
        codegen=raw_codegen,
    )
    _codegen([raw_loop], raw_codegen)

    indexed_codegen = _DummyCodegen()
    indexed_index = _stack(-2, indexed_codegen, name="iRow")
    indexed_base = CVariable(
        SimMemoryVariable(0xB4C, 2, name="abarWork"),
        variable_type=SimTypeShort(False),
        codegen=indexed_codegen,
    )
    indexed_store = CAssignment(
        CIndexedVariable(
            indexed_base,
            indexed_index,
            variable_type=SimTypeShort(False),
            codegen=indexed_codegen,
        ),
        _const(0, indexed_codegen),
        codegen=indexed_codegen,
    )
    indexed_loop = CForLoop(
        None,
        _const(1, indexed_codegen),
        None,
        CStatements([indexed_store], codegen=indexed_codegen),
        codegen=indexed_codegen,
    )
    _codegen([indexed_loop], indexed_codegen)

    raw_summary = collect_x86_16_tail_validation_summary(project, raw_codegen, mode="live_out")
    indexed_summary = collect_x86_16_tail_validation_summary(project, indexed_codegen, mode="live_out")

    assert compare_x86_16_tail_validation_summaries(raw_summary, indexed_summary)["status"] == "stable"

    helper_codegen = _DummyCodegen()
    helper_index = _stack(-2, helper_codegen, name="iRow")
    helper_base = CVariable(
        SimMemoryVariable(0xB4C, 2, name="abarWork"),
        variable_type=SimTypeShort(False),
        codegen=helper_codegen,
    )
    helper_indexed = CIndexedVariable(
        helper_base,
        helper_index,
        variable_type=SimTypeShort(False),
        codegen=helper_codegen,
    )
    helper_address = CUnaryOp("Reference", helper_indexed, codegen=helper_codegen)
    helper_stores = []
    for byte_offset in range(2):
        address = helper_address
        if byte_offset:
            address = CBinaryOp("Add", address, _const(byte_offset, helper_codegen), codegen=helper_codegen)
        helper_stores.append(
            CAssignment(
                CFunctionCall("MEM_U8", None, [address], codegen=helper_codegen),
                _const(byte_offset, helper_codegen),
                codegen=helper_codegen,
            )
        )
    helper_loop = CForLoop(
        None,
        _const(1, helper_codegen),
        None,
        CStatements(helper_stores, codegen=helper_codegen),
        codegen=helper_codegen,
    )
    _codegen([helper_loop], helper_codegen)
    helper_summary = collect_x86_16_tail_validation_summary(project, helper_codegen, mode="live_out")

    assert compare_x86_16_tail_validation_summaries(raw_summary, helper_summary)["status"] == "stable"


def test_tail_validation_uses_decoded_indexed_store_stack_identity_for_raw_pair():
    project = _project()
    raw_codegen = _DummyCodegen()
    stale_index = CVariable(
        SimStackVariable(2, 4, base="bp", name="stale_index"),
        codegen=raw_codegen,
    )
    scaled_index = CBinaryOp("Mul", stale_index, _const(2, raw_codegen), codegen=raw_codegen)
    raw_stores = []
    for byte_offset in range(2):
        base = CVariable(
            SimMemoryVariable(0xB4C + byte_offset, 1, name="abarWork"),
            codegen=raw_codegen,
        )
        address = CBinaryOp(
            "Add",
            CUnaryOp("Reference", base, codegen=raw_codegen),
            scaled_index,
            codegen=raw_codegen,
        )
        raw_stores.append(
            CAssignment(
                CUnaryOp("Dereference", address, codegen=raw_codegen),
                _const(byte_offset, raw_codegen),
                codegen=raw_codegen,
            )
        )
    raw_codegen._inertia_indexed_global_store_evidence_8616 = (
        IndexedSegmentedGlobalStoreEvidence8616(0xB4C, 2, -4, 1, 0x10870),
    )
    raw_init = CAssignment(stale_index, _const(0, raw_codegen), codegen=raw_codegen)
    _codegen([raw_init, *raw_stores], raw_codegen)

    indexed_codegen = _DummyCodegen()
    indexed_index = _stack(-4, indexed_codegen, name="iRowTmp")
    indexed_base = CVariable(
        SimMemoryVariable(0xB4C, 2, name="abarWork"),
        variable_type=SimTypeShort(False),
        codegen=indexed_codegen,
    )
    indexed_store = CAssignment(
        CIndexedVariable(
            indexed_base,
            indexed_index,
            variable_type=SimTypeShort(False),
            codegen=indexed_codegen,
        ),
        _const(0, indexed_codegen),
        codegen=indexed_codegen,
    )
    indexed_codegen._inertia_indexed_global_store_evidence_8616 = (
        IndexedSegmentedGlobalStoreEvidence8616(0xB4C, 2, -4, 1, 0x10870),
    )
    indexed_init = CAssignment(indexed_index, _const(0, indexed_codegen), codegen=indexed_codegen)
    _codegen([indexed_init, indexed_store], indexed_codegen)

    raw_summary = collect_x86_16_tail_validation_summary(project, raw_codegen, mode="live_out")
    indexed_summary = collect_x86_16_tail_validation_summary(project, indexed_codegen, mode="live_out")

    assert compare_x86_16_tail_validation_summaries(raw_summary, indexed_summary)["status"] == "stable"


def test_tail_validation_boundary_does_not_reuse_stale_expr_cache_after_condition_mutation():
    project = _project()
    codegen = _DummyCodegen()
    lhs = _stack(-2, codegen)
    rhs = _const(10, codegen)
    cond = CBinaryOp("CmpLT", lhs, rhs, codegen=codegen)
    stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    _codegen([stmt], codegen)

    before = fingerprint_x86_16_tail_validation_boundary(project, codegen, mode="live_out")
    cond.op = "CmpGT"
    after = fingerprint_x86_16_tail_validation_boundary(project, codegen, mode="live_out")

    assert before != after


def test_tail_validation_boundary_and_summary_prefer_canonical_statements_over_stale_body():
    project = _project()
    codegen = _DummyCodegen()
    stale_condition = CBinaryOp(
        "CmpNE",
        _stack(-4, codegen),
        _const(0, codegen),
        codegen=codegen,
    )
    stale_body = CStatements(
        [CIfBreak(stale_condition, codegen=codegen)],
        codegen=codegen,
    )
    current_statements = CStatements([], codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        body=stale_body,
        statements=current_statements,
    )

    before = fingerprint_x86_16_tail_validation_boundary(
        project,
        codegen,
        mode="live_out",
    )
    summary = collect_x86_16_tail_validation_summary(
        project,
        codegen,
        mode="live_out",
        boundary_fingerprint=before,
    )
    current_statements.statements.append(
        CReturn(None, codegen=codegen),
    )
    after = fingerprint_x86_16_tail_validation_boundary(
        project,
        codegen,
        mode="live_out",
    )

    assert summary.control_flow_effects == ()
    assert before != after


def test_contextual_condition_fingerprint_matches_dirty_register_flags_by_register_identity():
    codegen = _DummyCodegen()
    project = codegen.project
    flags_assignment_lhs = CDirtyExpression(SimpleNamespace(varid=10, reg=18, bits=16), codegen=codegen)
    flags_condition_var = CDirtyExpression(SimpleNamespace(varid=20, reg=18, bits=16), codegen=codegen)
    predicate = CBinaryOp(
        "CmpEQ",
        _global(0x134, codegen),
        _const(0, codegen),
        codegen=codegen,
    )
    assignment = CAssignment(
        flags_assignment_lhs,
        CBinaryOp(
            "Or",
            _const(0x1234, codegen),
            CBinaryOp("Shl", predicate, _const(6, codegen), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    condition = CBinaryOp(
        "CmpNE",
        CBinaryOp("And", flags_condition_var, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
    )
    root = CStatements(
        [assignment, CIfElse([(condition, CStatements([], codegen=codegen))], None, codegen=codegen)], codegen=codegen
    )

    mapping = build_x86_16_contextual_condition_fingerprints(root, project)

    assert mapping[id(condition)] == "CmpEQ(global:0x134,const:0)"


def test_contextual_condition_fingerprint_preserves_owned_typed_condition(monkeypatch):
    codegen = _DummyCodegen()
    project = codegen.project
    conditions = tuple(
        CBinaryOp(
            "CmpLT",
            _stack(-2, codegen),
            _global(0xBA2, codegen),
            codegen=codegen,
            tags={
                marker: True,
                "ins_addr": 0x103A,
                "vex_block_addr": 0x1034,
            },
        )
        for marker in ("typed_condition", "inertia_jcc_materialized_8616")
    )
    stale_decoded = SimpleNamespace(
        op="CmpLT",
        lhs=_stack(-2, codegen),
        rhs=_stack(-6, codegen),
        expr=None,
    )
    monkeypatch.setattr(
        condition_context_module,
        "_translate_cmp_jcc_guard_8616",
        lambda *_args: stale_decoded,
    )
    monkeypatch.setattr(
        condition_context_module,
        "_direct_cmp_immediate_jcc_fingerprint",
        lambda *_args: None,
    )
    root = CStatements(
        [
            CForLoop(
                None,
                condition,
                None,
                CStatements([], codegen=codegen),
                codegen=codegen,
            )
            for condition in conditions
        ],
        codegen=codegen,
    )

    mapping = build_x86_16_contextual_condition_fingerprints(root, project)

    assert {
        mapping[id(condition)]
        for condition in conditions
    } == {"CmpLT(stack_slot:SS:BP-0x2:size2,global:0xba2)"}


def _ds_deref(project, linear: int, codegen):
    ds = _reg(project, "ds", codegen)
    return CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add", CBinaryOp("Mul", ds, _const(16, codegen), codegen=codegen), _const(linear, codegen), codegen=codegen
        ),
        codegen=codegen,
    )


def _ss_stack_deref(project, stack_offset: int, addend: int, codegen):
    ss = _reg(project, "ss", codegen)
    return CUnaryOp(
        "Dereference",
        CTypeCast(
            SimTypeShort(False),
            SimTypeShort(False),
            CBinaryOp(
                "Add",
                CBinaryOp("Mul", ss, _const(16, codegen), codegen=codegen),
                CTypeCast(
                    SimTypeShort(False),
                    SimTypeShort(False),
                    CBinaryOp(
                        "Add",
                        CUnaryOp("Reference", _stack(stack_offset, codegen), codegen=codegen),
                        _const(addend, codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )


def test_tail_validation_summary_collects_observable_effects():
    project = _project()
    codegen_stub = _DummyCodegen()
    codegen = _codegen(
        [
            CAssignment(_reg(project, "ax", codegen_stub), _const(1, codegen_stub), codegen=codegen_stub),
            CAssignment(_stack(4, codegen_stub), _const(2, codegen_stub), codegen=codegen_stub),
            CAssignment(_global(0x1234, codegen_stub), _const(3, codegen_stub), codegen=codegen_stub),
            CAssignment(_ds_deref(project, 0x234, codegen_stub), _const(4, codegen_stub), codegen=codegen_stub),
            CReturn(
                CFunctionCall("print_dos_string", None, [_const(0x80, codegen_stub)], codegen=codegen_stub),
                codegen=codegen_stub,
            ),
        ],
        codegen_stub,
    )

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="coarse")

    assert summary.register_writes == ("reg:ax",)
    assert summary.stack_writes == ("stack_slot:SS:BP+0x4:size2",)
    assert summary.global_writes == ("global:0x1234", "global:0x1235")
    assert summary.segmented_writes == ("deref:ds:0x234",)
    assert summary.helper_calls == ("name:print_dos_string",)
    assert summary.returns == ("call:print_dos_string(const:128)",)
    assert summary.control_flow_effects == ("return",)


def test_tail_validation_void_return_call_matches_call_then_return():
    project = _project()

    return_call_codegen = _DummyCodegen()
    return_call_codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        functy=SimTypeFunction([], SimTypeBottom(label="void")),
        body=CStatements(
            [
                CReturn(
                    CFunctionCall("Sleep", None, [_const(1, return_call_codegen)], codegen=return_call_codegen),
                    codegen=return_call_codegen,
                )
            ],
            addr=0x4010,
            codegen=return_call_codegen,
        ),
    )

    split_codegen = _DummyCodegen()
    split_codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        functy=SimTypeFunction([], SimTypeBottom(label="void")),
        body=CStatements(
            [
                CExpressionStatement(
                    CFunctionCall("Sleep", None, [_const(1, split_codegen)], codegen=split_codegen),
                    codegen=split_codegen,
                ),
                CReturn(None, codegen=split_codegen),
            ],
            addr=0x4010,
            codegen=split_codegen,
        ),
    )

    return_summary = collect_x86_16_tail_validation_summary(project, return_call_codegen, mode="coarse")
    split_summary = collect_x86_16_tail_validation_summary(project, split_codegen, mode="coarse")

    assert return_summary == split_summary
    assert return_summary.helper_calls == ("name:Sleep",)


def test_tail_validation_call_statement_unwraps_assignment_and_expression_wrappers():
    codegen = _DummyCodegen()
    call = CFunctionCall("Sleep", None, [_const(1, codegen)], codegen=codegen)
    result = CVariable(SimRegisterVariable(0, 2, name="tmp_result"), codegen=codegen)
    assignment = CAssignment(result, call, codegen=codegen)
    expression = CExpressionStatement(call, codegen=codegen)

    assert tail_validation_module._call_from_statement_8616(assignment) is call
    assert tail_validation_module._call_from_statement_8616(expression) is call


def test_tail_validation_nonvoid_split_tail_call_matches_return_call(monkeypatch):
    project = _project()

    split_codegen = _DummyCodegen()
    split_call = CFunctionCall("apply_twice", None, [_const(1, split_codegen)], codegen=split_codegen)
    split_codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        functy=SimTypeFunction([], SimTypeShort(False)),
        body=CStatements(
            [
                CExpressionStatement(split_call, codegen=split_codegen),
                CReturn(None, codegen=split_codegen),
            ],
            addr=0x4010,
            codegen=split_codegen,
        ),
    )
    split_codegen.cfunc.body.codegen = split_codegen
    def _lookup_function(addr=None, name=None, create=False):
        if addr == 0x4010:
            return split_codegen.cfunc
        if name == "apply_twice":
            return SimpleNamespace(addr=0x5000, name="apply_twice")
        return None

    project.kb = SimpleNamespace(functions=SimpleNamespace(function=_lookup_function))

    monkeypatch.setattr(
        tail_validation_module,
        "summarize_x86_16_callsite",
        lambda _function, callsite_addr: CallsiteSummary8616(
            callsite_addr=callsite_addr,
            target_addr=0x5000,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register="ax",
            return_used=True,
            return_use_kind=CallsiteReturnUseKind8616.FUNCTION_RETURN,
        ),
    )
    split_codegen.cfunc.get_call_sites = lambda: (0x4012,)

    return_codegen = _DummyCodegen()
    return_call = CFunctionCall("apply_twice", None, [_const(1, return_codegen)], codegen=return_codegen)
    return_codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        functy=SimTypeFunction([], SimTypeShort(False)),
        body=CStatements([CReturn(return_call, codegen=return_codegen)], addr=0x4010, codegen=return_codegen),
    )

    split_summary = collect_x86_16_tail_validation_summary(project, split_codegen, mode="live_out")
    return_summary = collect_x86_16_tail_validation_summary(project, return_codegen, mode="live_out")
    diff = compare_x86_16_tail_validation_summaries(split_summary, return_summary)

    assert split_summary.returns == ("call:addr:0x5000(const:1)",)
    assert diff["changed"] is False


def test_tail_validation_void_return_value_does_not_observe_ax_live_out():
    project = _project()
    codegen = _DummyCodegen()
    ax = _reg(project, "ax", codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        functy=SimTypeFunction([], SimTypeBottom(label="void")),
        body=CStatements(
            [
                CAssignment(ax, _const(7, codegen), codegen=codegen),
                CReturn(ax, codegen=codegen),
            ],
            addr=0x4010,
            codegen=codegen,
        ),
    )

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.register_writes == ()
    assert summary.returns == ("none",)


def test_tail_validation_closed_unused_result_does_not_observe_ax_live_out() -> None:
    project = _project()
    record_caller_return_use_evidence_8616(
        project,
        0x4010,
        CallerReturnUseEvidence8616(
            target_addr=0x4010,
            verdict=CallerReturnUseVerdict8616.UNUSED,
            raw_fact_count=2,
            normalized_fact_count=2,
            classified_fact_count=2,
            materialized_count=2,
            failure_count=0,
            used_callsite_count=0,
            unused_callsite_count=2,
            callsite_addrs=(0x3010, 0x3020),
        ),
    )
    codegen = _DummyCodegen()
    ax = _reg(project, "ax", codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        functy=SimTypeFunction([], SimTypeShort(False)),
        body=CStatements(
            [
                CAssignment(ax, _const(7, codegen), codegen=codegen),
                CReturn(ax, codegen=codegen),
            ],
            addr=0x4010,
            codegen=codegen,
        ),
    )

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.register_writes == ()
    assert summary.returns == ("none",)
    assert isinstance(codegen.cfunc.functy.returnty, SimTypeShort)


def test_tail_validation_ignores_void_return_evidence_from_source_annotation():
    project = _project()
    codegen = _DummyCodegen()
    ax = _reg(project, "ax", codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        functy=SimTypeFunction([], SimTypeShort(False)),
        body=CStatements(
            [
                CAssignment(ax, _const(7, codegen), codegen=codegen),
                CReturn(ax, codegen=codegen),
            ],
            addr=0x4010,
            codegen=codegen,
        ),
    )
    codegen._inertia_current_function_8616 = SimpleNamespace(
        info={"x86_16_annotations": {"source_lines": ("void DrawTime(int iCurrentRow)",)}}
    )

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.register_writes == ("reg:ax",)
    assert summary.returns == ("reg:ax",)


def test_tail_validation_legacy_and_canonical_modules_share_identity():
    canonical = importlib.import_module("angr_platforms.X86_16.tail_validation")
    legacy = importlib.import_module("angr_platforms.angr_platforms.X86_16.tail_validation")

    assert legacy is canonical


def test_tail_validation_negative_memory_addr_is_not_counted_as_global():
    project = _project()
    codegen_stub = _DummyCodegen()
    codegen = _codegen(
        [
            CAssignment(_global(-8, codegen_stub, name="g_-8"), _const(3, codegen_stub), codegen=codegen_stub),
            CReturn(None, codegen=codegen_stub),
        ],
        codegen_stub,
    )

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="coarse")

    assert summary.global_writes == ()
    assert summary.stack_writes == ("stack:-0x8",)


def test_tail_validation_live_out_ignores_nonsemantic_zero_stack_slot_write():
    assert (
        include_x86_16_tail_validation_stack_write(
            "stack:+0x0",
            mode="live_out",
            observed_locations={"stack:+0x0"},
        )
        is False
    )
    assert (
        include_x86_16_tail_validation_stack_write(
            "stack:+0x4",
            mode="live_out",
            observed_locations={"stack:+0x4"},
        )
        is False
    )
    assert (
        include_x86_16_tail_validation_stack_write(
            "stack:-0x2",
            mode="live_out",
            observed_locations={"stack:-0x2"},
        )
        is True
    )
    assert (
        include_x86_16_tail_validation_stack_write(
            "stack:-0x4",
            mode="live_out",
            observed_locations={"stack:-0x2"},
        )
        is False
    )


def test_tail_validation_uses_callsite_summary_target_for_unknown_direct_call(monkeypatch):
    project = _project()
    function = SimpleNamespace(get_call_sites=lambda: (0x4012,))
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, name=None, create=False: function if addr == 0x4010 else None
        )
    )
    codegen_stub = _DummyCodegen()
    codegen = _codegen(
        [
            CFunctionCall(None, None, [], codegen=codegen_stub),
            CReturn(None, codegen=codegen_stub),
        ],
        codegen_stub,
    )

    codegen._inertia_callsite_summary_inventory_8616 = {
        0x4012: _callsite_summary(0x4012, 0x104D),
    }
    monkeypatch.setattr(
        tail_validation_module,
        "summarize_x86_16_callsite",
        lambda *_args, **_kwargs: pytest.fail("owned callsite inventory was not consumed"),
    )
    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ("addr:0x104d",)


def test_tail_validation_context_ignores_wrapper_assignment_before_outer_condition():
    project = _project()
    codegen = _DummyCodegen()
    flags_tmp = _reg(project, "flags", codegen, var_name="flags_tmp")
    predicate = CBinaryOp("CmpEQ", _reg(project, "ax", codegen), _reg(project, "bx", codegen), codegen=codegen)
    wrapped_assignment = CStatements(
        [
            CAssignment(
                flags_tmp,
                CBinaryOp("Mul", predicate, _const(0x40, codegen), codegen=codegen),
                codegen=codegen,
            )
        ],
        codegen=codegen,
    )
    condition = CBinaryOp(
        "CmpNE",
        CBinaryOp("And", flags_tmp, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
    )
    body = CStatements(
        [
            wrapped_assignment,
            CIfElse([(condition, CStatements([], codegen=codegen))], codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )

    mapping = build_x86_16_contextual_condition_fingerprints(body, project)

    assert mapping == {}


def test_tail_validation_uses_direct_capstone_callsite_fingerprint_when_cfg_callsites_missing(monkeypatch):
    project = _project()
    function = SimpleNamespace(get_call_sites=lambda: (), block_addrs_set={0x4010}, project=project)
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, name=None, create=False: function if addr == 0x4010 else None
        )
    )
    project.factory = SimpleNamespace(
        block=lambda _addr, opt_level=0: SimpleNamespace(
            capstone=SimpleNamespace(
                insns=(SimpleNamespace(address=0x4012, mnemonic="call"),),
            )
        )
    )
    codegen_stub = _DummyCodegen()
    codegen = _codegen(
        [
            CFunctionCall(None, None, [], codegen=codegen_stub),
            CReturn(None, codegen=codegen_stub),
        ],
        codegen_stub,
    )

    monkeypatch.setattr(
        tail_validation_module,
        "summarize_x86_16_callsite",
        lambda _function, _callsite_addr: None,
    )
    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ("callsite:0x4012",)


def test_contextual_call_fingerprints_descend_through_expr_wrappers():
    project = _project()
    codegen = _DummyCodegen()
    wrapped_call = SimpleNamespace(expr=CFunctionCall("InitBars", None, [], codegen=codegen))
    root = CStatements([wrapped_call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root, get_call_sites=lambda: (0x4012,))

    fingerprints = build_x86_16_contextual_call_fingerprints(root, project)

    inner_call = wrapped_call.expr
    assert fingerprints == {id(inner_call): "callsite:0x4012"}


def test_tail_validation_fingerprint_normalizes_stack_variable_byte_pair_to_word_slot():
    project = _project()
    codegen = _DummyCodegen()
    expr = CBinaryOp(
        "Or",
        _stack(-0xA, codegen, name="low"),
        CBinaryOp("Mul", _stack(-0x9, codegen, name="high"), _const(0x100, codegen), codegen=codegen),
        codegen=codegen,
    )

    fp = tail_validation_fingerprint_module._expr_fingerprint(expr, project)

    assert fp == "stack_slot:SS:BP-0xa:size2"


def test_tail_validation_live_out_ignores_consumed_ss_outgoing_arg_store(monkeypatch):
    project = _project()
    function = SimpleNamespace(get_call_sites=lambda: (0x4012,))
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, name=None, create=False: function if addr == 0x4010 else None
        )
    )

    before_codegen = _DummyCodegen()
    temp_var = CVariable(SimRegisterVariable(2, 2, name="vvar_67"), codegen=before_codegen)
    _codegen(
        [
            CAssignment(
                _ss_stack_deref(project, -2, -2, before_codegen), _const(97, before_codegen), codegen=before_codegen
            ),
            CAssignment(
                temp_var,
                CBinaryOp("Sub", _stack(-2, before_codegen), _const(2, before_codegen), codegen=before_codegen),
                codegen=before_codegen,
            ),
            CAssignment(
                _reg(project, "ax", before_codegen, var_name="frequency"),
                CFunctionCall("::0x14ae::inp", None, [], codegen=before_codegen),
                codegen=before_codegen,
            ),
        ],
        before_codegen,
    )
    before_codegen.cfunc.get_call_sites = lambda: (0x4012,)

    after_codegen = _DummyCodegen()
    _codegen(
        [
            CAssignment(
                _reg(project, "ax", after_codegen, var_name="frequency"),
                CFunctionCall("::0x14ae::inp", None, [_const(97, after_codegen)], codegen=after_codegen),
                codegen=after_codegen,
            ),
        ],
        after_codegen,
    )
    after_codegen.cfunc.get_call_sites = lambda: (0x4012,)

    monkeypatch.setattr(
        tail_validation_module,
        "summarize_x86_16_callsite",
        lambda _function, callsite_addr: _callsite_summary(callsite_addr, 0x14AE, arg_count=1),
    )

    before = collect_x86_16_tail_validation_summary(project, before_codegen, mode="live_out")
    after = collect_x86_16_tail_validation_summary(project, after_codegen, mode="live_out")
    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert before.helper_calls == ("addr:0x14ae",)
    assert after.helper_calls == ("addr:0x14ae",)
    assert diff["changed"] is False
    assert diff["delta"]["segmented_writes"] == {"added": (), "removed": ()}


def test_tail_validation_live_out_ignores_materialized_call_leftover_outgoing_arg_store(monkeypatch):
    project = _project()
    function = SimpleNamespace(get_call_sites=lambda: (0x4012,))
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, name=None, create=False: function if addr == 0x4010 else None
        )
    )

    before_codegen = _DummyCodegen()
    _codegen(
        [
            CAssignment(
                _ss_stack_deref(project, -2, -2, before_codegen), _const(97, before_codegen), codegen=before_codegen
            ),
            CAssignment(
                _reg(project, "ax", before_codegen, var_name="frequency"),
                CFunctionCall("::0x14ae::inp", None, [_const(97, before_codegen)], codegen=before_codegen),
                codegen=before_codegen,
            ),
        ],
        before_codegen,
    )
    before_codegen.cfunc.get_call_sites = lambda: (0x4012,)

    after_codegen = _DummyCodegen()
    _codegen(
        [
            CAssignment(
                _reg(project, "ax", after_codegen, var_name="frequency"),
                CFunctionCall("::0x14ae::inp", None, [_const(97, after_codegen)], codegen=after_codegen),
                codegen=after_codegen,
            ),
        ],
        after_codegen,
    )
    after_codegen.cfunc.get_call_sites = lambda: (0x4012,)

    monkeypatch.setattr(
        tail_validation_module,
        "summarize_x86_16_callsite",
        lambda _function, callsite_addr: _callsite_summary(
            callsite_addr,
            0x14AE,
            arg_count=1,
            push_arg_sources=(("imm", 97),),
        ),
    )

    before = collect_x86_16_tail_validation_summary(project, before_codegen, mode="live_out")
    after = collect_x86_16_tail_validation_summary(project, after_codegen, mode="live_out")
    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert before.helper_calls == ("addr:0x14ae",)
    assert after.helper_calls == ("addr:0x14ae",)
    assert diff["changed"] is False
    assert diff["delta"]["segmented_writes"] == {"added": (), "removed": ()}


def test_tail_validation_canonicalizes_ds_linear_segmented_write_when_global_write_matches():
    segmented = {
        "deref:Add(Mul(reg:ds,const:16),const:2986)",
        "deref:Add(Mul(reg:ss,const:16),const:2986)",
    }
    global_writes = {"global:0xbaa"}

    canonical = tail_validation_module._canonicalize_segmented_write_aliases_8616(segmented, global_writes)

    assert "deref:Add(Mul(reg:ds,const:16),const:2986)" not in canonical
    assert "deref:Add(Mul(reg:ss,const:16),const:2986)" in canonical


def test_tail_validation_compare_treats_linear_ds_byte_writes_as_global_precision_improvement():
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(
            "deref:Add(Mul(reg:ds,const:16),const:2986)",
            "deref:Add(Add(Mul(reg:ds,const:16),const:2986),const:1)",
        ),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=("global:0xbaa",),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["global_writes"] == {"added": (), "removed": ()}
    assert diff["delta"]["segmented_writes"] == {"added": (), "removed": ()}


def test_tail_validation_compare_treats_compact_ds_write_as_global_precision_improvement():
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=("deref:ds:0x132",),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=("global:0x132",),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["global_writes"] == {"added": (), "removed": ()}
    assert diff["delta"]["segmented_writes"] == {"added": (), "removed": ()}


def test_tail_validation_compare_canonicalizes_ds_write_inside_loop_body_effect():
    before_effect = "while-body-writes:const:True:deref:ds:0x132,global:0xba4"
    after_effect = "while-body-writes:const:True:global:0x132,global:0xba4"
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(before_effect,),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(after_effect,),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["control_flow_effects"] == {"added": (), "removed": ()}


def test_tail_validation_compare_parses_nested_loop_write_addresses_before_ds_global():
    nested_write = "deref:Add(Mul(reg:ss,const:16),Add(reg:sp,const:-2))"
    before_effect = f"while-body-writes:const:True:{nested_write},deref:ds:0x132,global:0xba4"
    after_effect = f"while-body-writes:const:True:global:0xba4,{nested_write},global:0x132"
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(before_effect,),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(after_effect,),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False


def test_tail_validation_compare_treats_linear_ds_condition_as_typed_global_alias():
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=("CmpLE(Dereference(Add(Mul(reg:ds,const:16),const:306)),const:900)",),
        control_flow_effects=("if:CmpNE(Or(global:0x134,Dereference(Add(Mul(reg:ds,const:16),const:306))),const:0)",),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=("CmpLE(global:0x132,const:900)",),
        control_flow_effects=("if:CmpNE(Or(global:0x134,global:0x132),const:0)",),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["conditions"] == {"added": (), "removed": ()}
    assert diff["delta"]["control_flow_effects"] == {"added": (), "removed": ()}


def test_tail_validation_compare_flattens_duplicate_or_condition_terms():
    before_condition = "CmpNE(Or(Or(global:0x134,global:0x132),global:0x132),const:0)"
    after_condition = "CmpNE(Or(global:0x134,global:0x132),const:0)"
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(before_condition,),
        control_flow_effects=(f"if:{before_condition}",),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(after_condition,),
        control_flow_effects=(f"if:{after_condition}",),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["conditions"] == {"added": (), "removed": ()}
    assert diff["delta"]["control_flow_effects"] == {"added": (), "removed": ()}


def test_tail_validation_compare_flattens_equivalent_ss_stack_byte_write_locations():
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(
            "deref:Add(Add(Mul(reg:ss,const:16),Add(Add(reg:sp,const:-2),const:-2)),const:1)",
            "deref:Add(Add(Mul(reg:ss,const:16),Add(Add(reg:sp,const:-2),const:-6)),const:1)",
        ),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(
            "deref:Add(Mul(reg:ss,const:16),reg:sp,const:-3)",
            "deref:Add(Mul(reg:ss,const:16),reg:sp,const:-7)",
        ),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["segmented_writes"] == {"added": (), "removed": ()}


def test_tail_validation_compare_treats_stack_slot_reference_as_same_segmented_write_location():
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=("deref:Add(Mul(reg:ss,const:16),Reference(stack_slot:SS:BP-0x8:size1),const:-17)",),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=("deref:Add(Mul(reg:ss,const:16),stack_slot:SS:BP-0x8:size1,const:-17)",),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["segmented_writes"] == {"added": (), "removed": ()}


def test_tail_validation_pairs_named_call_with_matching_target_after_prior_call_is_folded(monkeypatch):
    project = _project()
    function = SimpleNamespace(get_call_sites=lambda: (0x4012, 0x4018))
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, name=None, create=False: function if addr == 0x4010 else None
        ),
        labels={0x112BA: "_sprintf"},
    )
    codegen = _DummyCodegen()
    _codegen(
        [
            CAssignment(
                _reg(project, "ax", codegen, var_name="retval"),
                CFunctionCall("sprintf", None, [], codegen=codegen),
                codegen=codegen,
            )
        ],
        codegen,
    )

    def _fake_summary(_function, callsite_addr):
        return _callsite_summary(callsite_addr, {0x4012: 0x10D3, 0x4018: 0x112BA}[callsite_addr])

    monkeypatch.setattr(tail_validation_module, "summarize_x86_16_callsite", _fake_summary)

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ("addr:0x112ba", "missing-callsite:addr:0x10d3")


def test_tail_validation_completes_partial_callsite_summary_map_after_probe_is_folded(monkeypatch):
    project = _project()
    function = SimpleNamespace(get_call_sites=lambda: (0x4012, 0x4018, 0x4020))
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, name=None, create=False: function if addr == 0x4010 else None
        ),
        labels={0x5000: "__aNchkstk", 0x6000: "settextrows", 0x7000: "setvideomode"},
    )
    codegen = _DummyCodegen()
    first = CFunctionCall(
        "settextrows",
        SimpleNamespace(addr=0x6000, name="settextrows"),
        [],
        codegen=codegen,
    )
    final = CFunctionCall(
        "setvideomode",
        SimpleNamespace(addr=0x7000, name="setvideomode"),
        [],
        codegen=codegen,
    )
    _codegen([first, CReturn(final, codegen=codegen)], codegen)
    codegen._inertia_callsite_summaries = {
        id(first): _callsite_summary(0x4018, 0x6000),
    }

    def _fake_summary(_function, callsite_addr):
        return _callsite_summary(
            callsite_addr,
            {0x4012: 0x5000, 0x4018: 0x6000, 0x4020: 0x7000}[callsite_addr],
            stack_probe_helper=callsite_addr == 0x4012,
        )

    monkeypatch.setattr(tail_validation_module, "summarize_x86_16_callsite", _fake_summary)

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ("addr:0x6000", "addr:0x7000")


def test_tail_validation_live_out_ignores_virtual_offset_ss_stack_frame_store():
    project = _project()
    codegen = _DummyCodegen()
    sp_carrier = CDirtyExpression(SimpleNamespace(varid=24, name="vvar_24"), codegen=codegen)
    raw_stack_store = CAssignment(
        CUnaryOp(
            "Dereference",
            CBinaryOp(
                "Add",
                CBinaryOp("Mul", _reg(project, "ss", codegen), _const(16, codegen), codegen=codegen),
                CBinaryOp("Sub", sp_carrier, _const(2, codegen), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        _const(1, codegen),
        codegen=codegen,
    )
    _codegen(
        [
            raw_stack_store,
        ],
        codegen,
    )

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.segmented_writes == ()


def test_tail_validation_prefers_kb_function_for_callsite_summary_over_codegen_stub(monkeypatch):
    project = _project()
    kb_function = SimpleNamespace(get_call_sites=lambda: (0x4012,))
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, name=None, create=False: kb_function if addr == 0x4010 else None
        )
    )
    codegen = _DummyCodegen()
    _codegen(
        [
            CAssignment(
                _reg(project, "ax", codegen, var_name="frequency"),
                CFunctionCall("::0x14ae::inp", None, [], codegen=codegen),
                codegen=codegen,
            ),
        ],
        codegen,
    )
    codegen.cfunc.get_call_sites = lambda: (0x4012,)

    seen = []

    def _fake_summary(function, callsite_addr):
        seen.append(function)
        return _callsite_summary(callsite_addr, 0x14AE, arg_count=1)

    monkeypatch.setattr(tail_validation_module, "summarize_x86_16_callsite", _fake_summary)

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ("addr:0x14ae",)
    assert seen
    assert kb_function in seen


def test_tail_validation_live_out_ignores_dynamic_dirty_ss_segment_writes():
    project = _project()
    before_codegen = _DummyCodegen()
    dirty_ss_store = CAssignment(
        CUnaryOp(
            "Dereference",
            CTypeCast(
                SimTypeShort(False),
                SimTypeShort(False),
                CBinaryOp(
                    "Add",
                    CBinaryOp(
                        "Shl", _reg(project, "ss", before_codegen), _const(4, before_codegen), codegen=before_codegen
                    ),
                    CBinaryOp(
                        "Sub",
                        CBinaryOp(
                            "Sub",
                            CDirtyExpression("vvar_85", codegen=before_codegen),
                            _const(2, before_codegen),
                            codegen=before_codegen,
                        ),
                        _const(2, before_codegen),
                        codegen=before_codegen,
                    ),
                    codegen=before_codegen,
                ),
                codegen=before_codegen,
            ),
            codegen=before_codegen,
        ),
        _const(97, before_codegen),
        codegen=before_codegen,
    )
    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen([dirty_ss_store, CReturn(None, codegen=before_codegen)], before_codegen),
        mode="live_out",
    )
    after_codegen = _DummyCodegen()
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen([CReturn(None, codegen=after_codegen)], after_codegen),
        mode="live_out",
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert before.segmented_writes == ()
    assert diff["changed"] is False
    assert diff["delta"]["segmented_writes"] == {"added": (), "removed": ()}


def test_tail_validation_live_out_ignores_indexed_ss_frame_segment_write_fingerprint():
    assert tail_validation_module._is_dynamic_dirty_ss_location_8616(
        "deref:Add(Mul(reg:ss,const:16),Reference(CIndexedVariable),const:1)"
    )
    assert not tail_validation_module._is_dynamic_dirty_ss_location_8616("deref:Add(Mul(reg:ss,const:16),reg:ax)")


def test_tail_validation_ignores_cod_call_name_fingerprint_when_cfg_and_direct_targets_missing(monkeypatch):
    project = _project()
    codegen_stub = _DummyCodegen()
    known_call = CFunctionCall("InitBars", None, [], codegen=codegen_stub)
    unknown_call = CFunctionCall(None, None, [], codegen=codegen_stub)
    codegen = _codegen(
        [
            known_call,
            unknown_call,
            CReturn(None, codegen=codegen_stub),
        ],
        codegen_stub,
    )

    monkeypatch.setattr(
        tail_validation_module,
        "_function_for_call_context_8616",
        lambda _root, _project: None,
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.tail_validation_fingerprint._function_for_call_context_8616",
        lambda _root, _project: None,
    )
    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ("name:InitBars", "name:<indirect>")


def test_tail_validation_diff_ignores_variable_name_churn():
    project = _project()
    before_codegen = _DummyCodegen()
    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(
                    _reg(project, "ax", before_codegen, var_name="tmp_a"),
                    _const(1, before_codegen),
                    codegen=before_codegen,
                ),
                CReturn(_reg(project, "ax", before_codegen, var_name="tmp_a"), codegen=before_codegen),
            ],
            before_codegen,
        ),
    )
    after_codegen = _DummyCodegen()
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(
                    _reg(project, "ax", after_codegen, var_name="tmp_b"),
                    _const(1, after_codegen),
                    codegen=after_codegen,
                ),
                CReturn(_reg(project, "ax", after_codegen, var_name="tmp_b"), codegen=after_codegen),
            ],
            after_codegen,
        ),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["register_writes"] == {"added": (), "removed": ()}
    assert diff["delta"]["returns"] == {"added": (), "removed": ()}
    assert diff["delta"]["control_flow_effects"] == {"added": (), "removed": ()}


def test_tail_validation_live_out_mode_ignores_unused_temp_writes():
    project = _project()
    before_codegen = _DummyCodegen()
    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen([CReturn(_reg(project, "ax", before_codegen), codegen=before_codegen)], before_codegen),
        mode="live_out",
    )
    after_codegen = _DummyCodegen()
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(
                    _reg(project, "cx", after_codegen, var_name="tmp_bool"),
                    _const(1, after_codegen),
                    codegen=after_codegen,
                ),
                CReturn(_reg(project, "ax", after_codegen), codegen=after_codegen),
            ],
            after_codegen,
        ),
        mode="live_out",
    )
    coarse_after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(
                    _reg(project, "cx", after_codegen, var_name="tmp_bool"),
                    _const(1, after_codegen),
                    codegen=after_codegen,
                ),
                CReturn(_reg(project, "ax", after_codegen), codegen=after_codegen),
            ],
            after_codegen,
        ),
        mode="coarse",
    )

    live_out_diff = compare_x86_16_tail_validation_summaries(before, after)
    coarse_diff = compare_x86_16_tail_validation_summaries(before, coarse_after)

    assert live_out_diff["changed"] is False
    assert coarse_diff["changed"] is True
    assert coarse_diff["delta"]["register_writes"] == {"added": ("reg:cx",), "removed": ()}


def test_tail_validation_diff_keeps_global_and_segmented_models_distinct():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()

    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen([CReturn(_global(0x7000, before_codegen), codegen=before_codegen)], before_codegen),
    )
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CReturn(
                    CBinaryOp(
                        "Or",
                        _ds_deref(project, 0x7000, after_codegen),
                        CBinaryOp(
                            "Mul",
                            _ds_deref(project, 0x7001, after_codegen),
                            _const(0x100, after_codegen),
                            codegen=after_codegen,
                        ),
                        codegen=after_codegen,
                    ),
                    codegen=after_codegen,
                )
            ],
            after_codegen,
        ),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is True
    assert diff["delta"]["returns"]["added"]
    assert diff["delta"]["returns"]["removed"]


def test_tail_validation_diff_treats_segmented_and_global_DoCRT_word_write_as_equivalent_when_proven():
    project = _project()
    before_codegen = _DummyCodegen()
    before_codegen._inertia_segmented_memory_lowering = {
        "DS": {
            "classification": "const",
            "associated_space": "data",
            "allow_linear_lowering": True,
            "allow_object_lowering": True,
        }
    }
    after_codegen = _DummyCodegen()

    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(
                    CTypeCast(
                        SimTypeShort(False),
                        SimTypeShort(False),
                        _ds_deref(project, 0x7000, before_codegen),
                        codegen=before_codegen,
                    ),
                    _const(1, before_codegen),
                    codegen=before_codegen,
                )
            ],
            before_codegen,
        ),
    )
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(
                    _global(0x7000, after_codegen),
                    _const(1, after_codegen),
                    codegen=after_codegen,
                )
            ],
            after_codegen,
        ),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert before.global_writes == ("global:0x7000", "global:0x7001")
    assert before.segmented_writes == ()
    assert diff["changed"] is False
    assert diff["delta"]["global_writes"] == {"added": (), "removed": ()}
    assert diff["delta"]["segmented_writes"] == {"added": (), "removed": ()}


def test_tail_validation_live_out_ignores_register_writes_only_used_by_conditions():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()

    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CIfElse(
                    [
                        (
                            CBinaryOp(
                                "Sub",
                                _reg(project, "ax", before_codegen),
                                _const(2, before_codegen),
                                codegen=before_codegen,
                            ),
                            CStatements([], codegen=before_codegen),
                        )
                    ],
                    codegen=before_codegen,
                )
            ],
            before_codegen,
        ),
        mode="live_out",
    )
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(
                    _reg(project, "ax", after_codegen),
                    _const(1, after_codegen),
                    codegen=after_codegen,
                ),
                CIfElse(
                    [
                        (
                            _reg(project, "ax", after_codegen),
                            CStatements([], codegen=after_codegen),
                        )
                    ],
                    codegen=after_codegen,
                ),
            ],
            after_codegen,
        ),
        mode="live_out",
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert before.register_writes == ()
    assert after.register_writes == ("reg:ax",)
    assert diff["delta"]["register_writes"] == {"added": ("reg:ax",), "removed": ()}


def test_tail_validation_normalizes_identical_assignment_arm_diamond() -> None:
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()
    before_carrier = _reg(project, "ax", before_codegen)
    after_carrier = _reg(project, "ax", after_codegen)
    before_value = CBinaryOp(
        "Mul",
        before_carrier,
        _const(60, before_codegen),
        codegen=before_codegen,
    )
    after_value = CBinaryOp(
        "Mul",
        after_carrier,
        _const(60, after_codegen),
        codegen=after_codegen,
    )
    before_assignment = CAssignment(
        before_carrier,
        before_value,
        codegen=before_codegen,
    )
    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CIfElse(
                    [
                        (
                            _reg(project, "dx", before_codegen),
                            CStatements([before_assignment], codegen=before_codegen),
                        )
                    ],
                    else_node=CStatements(
                        [
                            CAssignment(
                                before_carrier,
                                before_value,
                                codegen=before_codegen,
                            )
                        ],
                        codegen=before_codegen,
                    ),
                    codegen=before_codegen,
                )
            ],
            before_codegen,
        ),
        mode="live_out",
    )
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(
                    after_carrier,
                    after_value,
                    codegen=after_codegen,
                )
            ],
            after_codegen,
        ),
        mode="live_out",
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert before.conditions == ()
    assert before.control_flow_effects == ()
    assert diff["changed"] is False


def test_tail_validation_boundary_fingerprint_is_stable_for_unchanged_shape():
    project = _project()
    codegen = _DummyCodegen()
    codegen = _codegen([CReturn(_const(1, codegen), codegen=codegen)], codegen)
    first = fingerprint_x86_16_tail_validation_boundary(project, codegen)
    second = fingerprint_x86_16_tail_validation_boundary(project, codegen)

    assert first == second


def test_tail_validation_boundary_caches_shared_bp_stack_exprs_without_leaking(monkeypatch):
    project = _project()
    codegen = _DummyCodegen()
    codegen.project = project
    shared_stack = _stack(-2, codegen, name="shared")
    statements = [
        CAssignment(
            _reg(project, "ax", codegen, var_name=f"ax_{index}"),
            CBinaryOp("Add", shared_stack, _const(index, codegen), codegen=codegen),
            codegen=codegen,
        )
        for index in range(24)
    ]
    codegen = _codegen(statements, codegen)
    calls = {"count": 0}
    original = tail_validation_fingerprint_module._location_fingerprint

    def counted_location(node, got_project):
        if node is shared_stack:
            calls["count"] += 1
        return original(node, got_project)

    monkeypatch.setattr(tail_validation_fingerprint_module, "_location_fingerprint", counted_location)

    fingerprint_x86_16_tail_validation_boundary(project, codegen)

    assert calls["count"] <= 2
    assert not hasattr(project, "_inertia_tail_validation_boundary_node_cache_8616")
    assert not hasattr(project, "_inertia_tail_validation_snapshot_expr_cache_enabled_8616")


def test_tail_validation_cache_descriptor_is_deterministic():
    first = build_x86_16_validation_cache_descriptor(
        "tail_validation.test", {"stage": "postprocess", "mode": "live_out"}
    )
    second = build_x86_16_validation_cache_descriptor(
        "tail_validation.test", {"stage": "postprocess", "mode": "live_out"}
    )

    assert isinstance(first, X86_16ValidationCacheDescriptor)
    assert first == second
    assert first.cache_key == f"{first.namespace}:{first.fingerprint}"


def test_tail_validation_cache_descriptor_handles_non_json_payload_members():
    class _Opaque:
        pass

    first = build_x86_16_validation_cache_descriptor(
        "tail_validation.test",
        {"stage": "postprocess", "opaque": _Opaque()},
    )
    second = build_x86_16_validation_cache_descriptor(
        "tail_validation.test",
        {"stage": "postprocess", "opaque": _Opaque()},
    )

    assert isinstance(first, X86_16ValidationCacheDescriptor)
    assert first == second
    assert first.cache_key == f"{first.namespace}:{first.fingerprint}"


def test_tail_validation_cached_artifact_helper_reuses_shared_key_space():
    cache = {}
    descriptor = build_x86_16_validation_cache_descriptor("tail_validation.test", {"value": 7})

    first = resolve_x86_16_validation_cached_artifact(
        cache=cache,
        descriptor=descriptor,
        build=lambda: {"value": 7, "items": ["a"]},
        clone_on_hit=dict,
        store_value=dict,
    )
    second = resolve_x86_16_validation_cached_artifact(
        cache=cache,
        descriptor=descriptor,
        build=lambda: {"value": 9},
        clone_on_hit=dict,
        store_value=dict,
    )

    assert first["cache_hit"] is False
    assert second["cache_hit"] is True
    assert first["cache_key"] == second["cache_key"] == descriptor.cache_key
    assert second["value"] == {"value": 7, "items": ["a"]}


def test_tail_validation_summary_uses_cache_when_boundary_fingerprint_matches():
    project = _project()
    codegen = _DummyCodegen()
    codegen = _codegen([CReturn(_reg(project, "ax", codegen), codegen=codegen)], codegen)

    first = collect_x86_16_tail_validation_summary(project, codegen)
    second = collect_x86_16_tail_validation_summary(project, codegen)

    assert first == second
    assert first is second
    assert codegen._inertia_tail_validation_last_summary_cache_hit is True
    assert codegen._inertia_tail_validation_summary_cache["stats"] == {"hits": 1, "misses": 1}


def test_tail_validation_summary_cache_misses_after_boundary_change():
    project = _project()
    codegen = _DummyCodegen()
    ax = _reg(project, "ax", codegen)
    codegen = _codegen([CReturn(ax, codegen=codegen)], codegen)

    first = collect_x86_16_tail_validation_summary(project, codegen)
    codegen.cfunc.body.statements.append(CFunctionCall("helper_ping", None, [], codegen=codegen))
    second = collect_x86_16_tail_validation_summary(project, codegen)

    assert first is not second
    assert codegen._inertia_tail_validation_last_summary_cache_hit is False


def test_tail_validation_cached_result_reuses_stage_comparison():
    owner = {}
    project = _project()
    before_codegen = _DummyCodegen()
    before_codegen = _codegen([CReturn(_const(1, before_codegen), codegen=before_codegen)], before_codegen)
    after_codegen = _DummyCodegen()
    after_codegen = _codegen(
        [
            CFunctionCall("helper_ping", None, [], codegen=after_codegen),
            CReturn(_const(1, after_codegen), codegen=after_codegen),
        ],
        after_codegen,
    )
    before_fp = fingerprint_x86_16_tail_validation_boundary(project, before_codegen)
    after_fp = fingerprint_x86_16_tail_validation_boundary(project, after_codegen)
    before_summary = collect_x86_16_tail_validation_summary(project, before_codegen)
    after_summary = collect_x86_16_tail_validation_summary(project, after_codegen)

    first = build_x86_16_tail_validation_cached_result(
        owner=owner,
        stage="postprocess",
        mode="live_out",
        before_fingerprint=before_fp,
        after_fingerprint=after_fp,
        before_summary=before_summary,
        after_summary=after_summary,
    )
    second = build_x86_16_tail_validation_cached_result(
        owner=owner,
        stage="postprocess",
        mode="live_out",
        before_fingerprint=before_fp,
        after_fingerprint=after_fp,
        before_summary=before_summary,
        after_summary=after_summary,
    )

    assert first["cache_hit"] is False
    assert second["cache_hit"] is True
    assert second["verdict"] == first["verdict"]


def test_tail_validation_cached_result_keys_on_summary_payload_when_fingerprint_is_stable():
    owner = {}
    empty = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )
    partial = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=("const:1",),
        conditions=(),
        control_flow_effects=("return",),
    )
    complete = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=("const:1", "const:2"),
        conditions=(),
        control_flow_effects=("return",),
    )

    first = build_x86_16_tail_validation_cached_result(
        owner=owner,
        stage="structuring",
        mode="live_out",
        before_fingerprint="stable-before",
        after_fingerprint="stable-after",
        before_summary=empty,
        after_summary=partial,
    )
    second = build_x86_16_tail_validation_cached_result(
        owner=owner,
        stage="structuring",
        mode="live_out",
        before_fingerprint="stable-before",
        after_fingerprint="stable-after",
        before_summary=empty,
        after_summary=complete,
    )

    assert first["cache_hit"] is False
    assert second["cache_hit"] is False
    assert second["delta"]["returns"]["added"] == ("const:1", "const:2")


def test_tail_validation_suppresses_signed_i16_return_else_structuring_precision():
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=("const:65535",),
        conditions=("CmpLT(stack_slot:SS:BP+0x4:size2,const:0)",),
        control_flow_effects=("if:CmpLT(stack_slot:SS:BP+0x4:size2,const:0)", "if:else", "return"),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=("const:-1",),
        conditions=("CmpLT(stack_slot:SS:BP+0x4:size2,const:0)",),
        control_flow_effects=("if:CmpLT(stack_slot:SS:BP+0x4:size2,const:0)", "return"),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert "signed_i16_return_else_structuring" in diff["precision_improvements"]


def test_tail_validation_does_not_suppress_signed_i16_return_when_conditions_change():
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=("const:65535",),
        conditions=("CmpLT(stack_slot:SS:BP+0x4:size2,const:0)",),
        control_flow_effects=("if:CmpLT(stack_slot:SS:BP+0x4:size2,const:0)", "if:else", "return"),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=("const:-1",),
        conditions=(),
        control_flow_effects=("return",),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is True
    assert "signed_i16_return_else_structuring" not in diff["precision_improvements"]


def test_tail_validation_collects_control_flow_effects():
    project = _project()
    codegen = _DummyCodegen()
    ax = _reg(project, "ax", codegen)
    cond = CBinaryOp("CmpEQ", ax, _const(0, codegen), codegen=codegen)
    codegen = _codegen(
        [
            CIfElse(
                [(cond, CStatements([CBreak(codegen=codegen)], codegen=codegen))],
                else_node=CStatements([CContinue(codegen=codegen)], codegen=codegen),
                codegen=codegen,
            ),
            CWhileLoop(cond, CStatements([], codegen=codegen), codegen=codegen),
        ],
        codegen,
    )

    summary = collect_x86_16_tail_validation_summary(project, codegen)

    assert summary.conditions == ("CmpEQ(reg:ax,const:0)",)
    assert summary.control_flow_effects == (
        "break",
        "continue",
        "if:CmpEQ(reg:ax,const:0)",
        "if:else",
        "while:CmpEQ(reg:ax,const:0)",
    )


def test_tail_validation_does_not_count_insert_intrinsic_as_helper_call():
    project = _project()
    codegen = _DummyCodegen()
    cond = CBinaryOp("CmpNE", _reg(project, "ax", codegen), _const(0, codegen), codegen=codegen)
    insert_intrinsic = CFunctionCall(
        "_INSERT",
        None,
        [_reg(project, "ax", codegen), _const(0, codegen), _const(1, codegen)],
        codegen=codegen,
    )
    draw_call = CFunctionCall("DrawBar", None, [], codegen=codegen)
    body = CStatements([insert_intrinsic, draw_call], codegen=codegen)
    _codegen([CForLoop(None, cond, None, body, codegen=codegen)], codegen)

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ("name:DrawBar",)
    assert all("_INSERT" not in item for item in summary.control_flow_effects)
    assert "for-body-calls:CmpNE(reg:ax,const:0):name:DrawBar" in summary.control_flow_effects


def test_tail_validation_insert_intrinsic_does_not_consume_callsite_fingerprint(monkeypatch):
    project = _project()
    codegen = _DummyCodegen()
    insert_intrinsic = CFunctionCall(
        "_INSERT",
        None,
        [_reg(project, "ax", codegen), _const(0, codegen), _const(1, codegen)],
        codegen=codegen,
    )
    real_call = CFunctionCall(None, None, [], codegen=codegen)
    _codegen([insert_intrinsic, real_call], codegen)
    codegen.cfunc.get_call_sites = lambda: (0x4012,)

    monkeypatch.setattr(
        tail_validation_module,
        "summarize_x86_16_callsite",
        lambda _function, callsite_addr: _callsite_summary(callsite_addr, 0x5000),
    )

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert summary.helper_calls == ("addr:0x5000",)


def test_tail_validation_boundary_treats_global_byte_pair_as_word_global_condition():
    project = _project()

    before_codegen = _DummyCodegen()
    i_before = _stack(-2, before_codegen, name="i")
    low = CVariable(SimMemoryVariable(0x160, 1, name="mem_0160"), codegen=before_codegen)
    high = CVariable(SimMemoryVariable(0x161, 1, name="mem_0161"), codegen=before_codegen)
    byte_pair = CBinaryOp(
        "Or",
        low,
        CBinaryOp("Shl", high, _const(8, before_codegen), codegen=before_codegen),
        codegen=before_codegen,
    )
    before_cond = CBinaryOp("CmpLT", i_before, byte_pair, codegen=before_codegen)
    before_codegen = _codegen(
        [
            CIfElse(
                [(before_cond, CStatements([CBreak(codegen=before_codegen)], codegen=before_codegen))],
                codegen=before_codegen,
            )
        ],
        before_codegen,
    )

    after_codegen = _DummyCodegen()
    after_cond = CBinaryOp(
        "CmpLT",
        _stack(-2, after_codegen, name="i"),
        _global(0x160, after_codegen, name="cszMenu"),
        codegen=after_codegen,
    )
    after_codegen = _codegen(
        [
            CIfElse(
                [(after_cond, CStatements([CBreak(codegen=after_codegen)], codegen=after_codegen))],
                codegen=after_codegen,
            )
        ],
        after_codegen,
    )

    assert fingerprint_x86_16_tail_validation_boundary(project, before_codegen) == (
        fingerprint_x86_16_tail_validation_boundary(project, after_codegen)
    )
    assert collect_x86_16_tail_validation_summary(project, before_codegen).control_flow_effects == (
        collect_x86_16_tail_validation_summary(project, after_codegen).control_flow_effects
    )


def test_tail_validation_normalizes_for_loop_break_guard_equivalence():
    project = _project()
    before_codegen = _DummyCodegen()
    before_cond = CBinaryOp(
        "CmpNE",
        _reg(project, "ax", before_codegen),
        _const(0, before_codegen),
        codegen=before_codegen,
    )
    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CForLoop(
                    None,
                    before_cond,
                    None,
                    CStatements([], codegen=before_codegen),
                    codegen=before_codegen,
                )
            ],
            before_codegen,
        ),
        mode="live_out",
    )

    after_codegen = _DummyCodegen()
    after_break_cond = CBinaryOp(
        "CmpEQ",
        _reg(project, "ax", after_codegen),
        _const(0, after_codegen),
        codegen=after_codegen,
    )
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CForLoop(
                    None,
                    _const(1, after_codegen),
                    None,
                    CStatements([CIfBreak(after_break_cond, codegen=after_codegen)], codegen=after_codegen),
                    codegen=after_codegen,
                )
            ],
            after_codegen,
        ),
        mode="live_out",
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert before.conditions == ("CmpNE(reg:ax,const:0)",)
    assert before.control_flow_effects == ("for:CmpNE(reg:ax,const:0)",)
    assert after.conditions == before.conditions
    assert after.control_flow_effects == before.control_flow_effects


def test_tail_validation_normalizes_boolean_cite_projection_noise():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()

    before_cond = CUnaryOp(
        "Not",
        CITE(
            CBinaryOp("Sub", _reg(project, "ax", before_codegen), _const(2, before_codegen), codegen=before_codegen),
            _const(0, before_codegen),
            _const(1, before_codegen),
            codegen=before_codegen,
        ),
        codegen=before_codegen,
    )
    after_cond = CUnaryOp(
        "Not",
        CUnaryOp(
            "Not",
            CBinaryOp("Sub", _reg(project, "ax", after_codegen), _const(2, after_codegen), codegen=after_codegen),
            codegen=after_codegen,
        ),
        codegen=after_codegen,
    )

    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CIfElse(
                    [(before_cond, CStatements([], codegen=before_codegen))],
                    codegen=before_codegen,
                )
            ],
            before_codegen,
        ),
    )
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CIfElse(
                    [(after_cond, CStatements([], codegen=after_codegen))],
                    codegen=after_codegen,
                )
            ],
            after_codegen,
        ),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert before.conditions == ("Add(reg:ax,const:-2)",)
    assert after.conditions == ("Add(reg:ax,const:-2)",)


def test_tail_validation_normalizes_zero_flag_compare_projection_noise():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()

    before_cond = CBinaryOp(
        "Sub", _reg(project, "ax", before_codegen), _const(2, before_codegen), codegen=before_codegen
    )
    after_cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp(
            "Mul",
            CBinaryOp(
                "CmpEQ",
                CBinaryOp("Sub", _reg(project, "ax", after_codegen), _const(2, after_codegen), codegen=after_codegen),
                _const(0, after_codegen),
                codegen=after_codegen,
            ),
            _const(64, after_codegen),
            codegen=after_codegen,
        ),
        _const(0, after_codegen),
        codegen=after_codegen,
    )

    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [CIfElse([(before_cond, CStatements([], codegen=before_codegen))], codegen=before_codegen)], before_codegen
        ),
    )
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [CIfElse([(after_cond, CStatements([], codegen=after_codegen))], codegen=after_codegen)], after_codegen
        ),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert before.conditions == ("Add(reg:ax,const:-2)",)
    assert after.conditions == ("Add(reg:ax,const:-2)",)


def test_tail_validation_normalizes_adjacent_flag_assignment_guard_pairs():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()
    before_word = CBinaryOp(
        "Or",
        _reg(project, "si", before_codegen),
        CBinaryOp("Mul", _reg(project, "di", before_codegen), _const(0x100, before_codegen), codegen=before_codegen),
        codegen=before_codegen,
    )
    after_word = CBinaryOp(
        "Or",
        _reg(project, "si", after_codegen),
        CBinaryOp("Mul", _reg(project, "di", after_codegen), _const(0x100, after_codegen), codegen=after_codegen),
        codegen=after_codegen,
    )
    before_predicate = CBinaryOp(
        "CmpEQ",
        CBinaryOp("Add", before_word, _const(1, before_codegen), codegen=before_codegen),
        _const(0, before_codegen),
        codegen=before_codegen,
    )
    after_predicate = CBinaryOp(
        "CmpEQ",
        CBinaryOp("Add", after_word, _const(1, after_codegen), codegen=after_codegen),
        _const(0, after_codegen),
        codegen=after_codegen,
    )

    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(
                    _reg(project, "flags", before_codegen),
                    CBinaryOp("Mul", before_predicate, _const(64, before_codegen), codegen=before_codegen),
                    codegen=before_codegen,
                ),
                CIfElse(
                    [
                        (
                            CUnaryOp(
                                "Not",
                                CBinaryOp(
                                    "CmpEQ",
                                    CBinaryOp(
                                        "And",
                                        _reg(project, "flags", before_codegen),
                                        _const(64, before_codegen),
                                        codegen=before_codegen,
                                    ),
                                    _const(0, before_codegen),
                                    codegen=before_codegen,
                                ),
                                codegen=before_codegen,
                            ),
                            CStatements([], codegen=before_codegen),
                        )
                    ],
                    codegen=before_codegen,
                ),
            ],
            before_codegen,
        ),
    )
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [CIfElse([(after_predicate, CStatements([], codegen=after_codegen))], codegen=after_codegen)], after_codegen
        ),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert before.conditions == ("CmpEQ(Add(Or(reg:si,Mul(reg:di,const:256)),const:1),const:0)",)
    assert before.control_flow_effects == ("if:CmpEQ(Add(Or(reg:si,Mul(reg:di,const:256)),const:1),const:0)",)
    assert after.conditions == before.conditions
    assert after.control_flow_effects == before.control_flow_effects


def test_tail_validation_normalizes_ss_stack_dereference_to_stack_write():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()

    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(
                    _ss_stack_deref(project, -2, 2, before_codegen),
                    _const(7, before_codegen),
                    codegen=before_codegen,
                )
            ],
            before_codegen,
        ),
        mode="coarse",
    )
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(
                    _stack(0, after_codegen),
                    _const(7, after_codegen),
                    codegen=after_codegen,
                )
            ],
            after_codegen,
        ),
        mode="coarse",
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert before.stack_writes == ("stack:+0x0",)
    assert before.segmented_writes == ()


def test_tail_validation_live_out_ignores_negative_stack_local_writes():
    project = _project()
    codegen = _DummyCodegen()

    summary = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(
                    _stack(-12, codegen, name="pos"),
                    _const(7, codegen),
                    codegen=codegen,
                ),
                CReturn(_const(0, codegen), codegen=codegen),
            ],
            codegen,
        ),
    )

    assert summary.stack_writes == ()


def test_tail_validation_keeps_ds_byte_pair_distinct_from_word_global_write():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()

    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(
                    _ds_deref(project, 0x7002, before_codegen), _const(0x34, before_codegen), codegen=before_codegen
                ),
                CAssignment(
                    _ds_deref(project, 0x7003, before_codegen), _const(0x12, before_codegen), codegen=before_codegen
                ),
            ],
            before_codegen,
        ),
        mode="coarse",
    )
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CAssignment(_global(0x7002, after_codegen), _const(0x1234, after_codegen), codegen=after_codegen),
            ],
            after_codegen,
        ),
        mode="coarse",
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is True
    assert diff["delta"]["global_writes"] == {"added": ("ds_global:0x7002",), "removed": ()}
    assert diff["delta"]["segmented_writes"] == {"added": (), "removed": ("deref:ds:0x7002", "deref:ds:0x7003")}


def test_tail_validation_canonicalizes_ds_word_load_as_global_word_condition():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()
    before_word = CBinaryOp(
        "Or",
        _ds_deref(project, 0x7000, before_codegen),
        CBinaryOp(
            "Mul",
            _ds_deref(project, 0x7001, before_codegen),
            _const(256, before_codegen),
            codegen=before_codegen,
        ),
        codegen=before_codegen,
    )
    before_condition = CBinaryOp(
        "CmpEQ",
        _ds_deref(project, 0x7002, before_codegen),
        before_word,
        codegen=before_codegen,
    )
    after_condition = CBinaryOp(
        "CmpEQ",
        _ds_deref(project, 0x7002, after_codegen),
        _global(0x7000, after_codegen),
        codegen=after_codegen,
    )

    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [CIfElse([(before_condition, CStatements([], codegen=before_codegen))], None, codegen=before_codegen)],
            before_codegen,
        ),
        mode="live_out",
    )
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [CIfElse([(after_condition, CStatements([], codegen=after_codegen))], None, codegen=after_codegen)],
            after_codegen,
        ),
        mode="live_out",
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["delta"]["conditions"] == {"added": (), "removed": ()}
    assert diff["delta"]["control_flow_effects"] == {"added": (), "removed": ()}


def test_tail_validation_diff_formatter_reports_observable_delta():
    project = _project()
    before_codegen = _DummyCodegen()
    before = collect_x86_16_tail_validation_summary(
        project,
        _codegen([CReturn(_const(1, before_codegen), codegen=before_codegen)], before_codegen),
    )
    after_codegen = _DummyCodegen()
    after = collect_x86_16_tail_validation_summary(
        project,
        _codegen(
            [
                CFunctionCall("helper_ping", None, [], codegen=after_codegen),
                CReturn(_const(1, after_codegen), codegen=after_codegen),
            ],
            after_codegen,
        ),
    )

    formatted = format_x86_16_tail_validation_diff(compare_x86_16_tail_validation_summaries(before, after))

    assert "helper_calls: +helper_ping" in formatted


def test_tail_validation_verdict_builder_includes_stage_mode_and_status():
    validation = {
        "changed": True,
        "status": "changed",
        "mode": "live_out",
        "summary_text": "helper_calls: +helper_ping",
    }

    verdict = build_x86_16_tail_validation_verdict("postprocess", validation)

    assert verdict == "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping"


def test_tail_validation_verdict_builder_preserves_non_success_status():
    verdict = build_x86_16_tail_validation_verdict(
        "postprocess",
        {
            "status": "unknown",
            "mode": "live_out",
            "summary_text": "validation metadata was not collected",
        },
    )

    assert verdict == "postprocess whole-tail validation [live_out] unknown: validation metadata was not collected"


def test_tail_validation_snapshot_extracts_known_stage_fields():
    snapshot = extract_x86_16_tail_validation_snapshot(
        {
            "x86_16_tail_validation": {
                "structuring": {
                    "changed": False,
                    "status": "stable",
                    "mode": "live_out",
                    "verdict": "structuring whole-tail validation [live_out] stable: no observable whole-tail changes",
                    "summary_text": "no observable whole-tail changes",
                    "scope": {"ignored": ("temporary names",)},
                }
            }
        }
    )

    assert snapshot == {
        "structuring": {
            "changed": False,
            "status": "stable",
            "mode": "live_out",
            "verdict": "structuring whole-tail validation [live_out] stable: no observable whole-tail changes",
            "summary_text": "no observable whole-tail changes",
        }
    }


def test_tail_validation_snapshot_preserves_delta_for_aggregate_family_reports():
    delta = {"helper_calls": {"added": ("helper_ping",), "removed": ()}}
    snapshot = extract_x86_16_tail_validation_snapshot(
        {
            "x86_16_tail_validation": {
                "postprocess": {
                    "changed": True,
                    "mode": "live_out",
                    "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
                    "summary_text": "helper_calls: +helper_ping",
                    "delta": delta,
                }
            }
        }
    )

    assert snapshot["postprocess"]["delta"] == delta


def test_tail_validation_snapshot_without_status_or_changed_stays_unknown():
    snapshot = extract_x86_16_tail_validation_snapshot(
        {
            "x86_16_tail_validation": {
                "postprocess": {
                    "mode": "live_out",
                    "verdict": "postprocess whole-tail validation [live_out] unknown: not collected",
                    "summary_text": "not collected",
                }
            }
        }
    )

    assert snapshot == {
        "postprocess": {
            "changed": False,
            "status": "unknown",
            "mode": "live_out",
            "verdict": "postprocess whole-tail validation [live_out] unknown: not collected",
            "summary_text": "not collected",
        }
    }


def test_tail_validation_snapshot_can_be_persisted_on_codegen_without_function_info():
    codegen = _DummyCodegen()
    persisted = persist_x86_16_tail_validation_snapshot(
        function_info=None,
        codegen=codegen,
        stage="postprocess",
        validation={
            "changed": True,
            "mode": "live_out",
            "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
            "summary_text": "helper_calls: +helper_ping",
        },
    )

    assert persisted == {
        "changed": True,
        "status": "changed",
        "mode": "live_out",
        "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
        "summary_text": "helper_calls: +helper_ping",
    }
    assert codegen._inertia_tail_validation_snapshot == {
        "postprocess": {
            "changed": True,
            "status": "changed",
            "mode": "live_out",
            "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
            "summary_text": "helper_calls: +helper_ping",
        }
    }


def test_tail_validation_snapshot_persists_changed_postprocess_verdict_for_later_consumers():
    function_info = {}
    codegen = _DummyCodegen()
    validation = {
        "changed": True,
        "status": "changed",
        "mode": "live_out",
        "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
        "summary_text": "helper_calls: +helper_ping",
    }

    persisted = persist_x86_16_tail_validation_snapshot(
        function_info=function_info,
        codegen=codegen,
        stage="postprocess",
        validation=validation,
    )

    assert persisted == validation
    assert function_info == {"x86_16_tail_validation": {"postprocess": validation}}
    assert extract_x86_16_tail_validation_snapshot(function_info) == {"postprocess": validation}
    assert codegen._inertia_tail_validation_snapshot == {"postprocess": validation}


def test_tail_validation_snapshot_persists_compact_stage_entry_in_function_info():
    function_info = {}
    codegen = _DummyCodegen()
    validation = {
        "changed": True,
        "status": "changed",
        "mode": "live_out",
        "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
        "summary_text": "helper_calls: +helper_ping",
        "delta": {
            "added": ["CmpGT(big, fat, delta)"],
            "removed": ["CmpLE(old, fat, delta)"],
        },
        "before_summary": {"conditions": tuple(range(256))},
        "after_summary": {"conditions": tuple(range(256, 512))},
    }

    persist_x86_16_tail_validation_snapshot(
        function_info=function_info,
        codegen=codegen,
        stage="postprocess",
        validation=validation,
    )

    assert function_info == {
        "x86_16_tail_validation": {
            "postprocess": {
                "changed": True,
                "status": "changed",
                "mode": "live_out",
                "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
                "summary_text": "helper_calls: +helper_ping",
                "delta": {
                    "added": ["CmpGT(big, fat, delta)"],
                    "removed": ["CmpLE(old, fat, delta)"],
                },
            }
        }
    }


def test_tail_validation_snapshot_for_function_run_prefers_complete_project_snapshot():
    project = SimpleNamespace(
        _inertia_last_tail_validation_snapshot={
            "structuring": {"status": "stable", "changed": False},
            "postprocess": {"status": "stable", "changed": False},
        }
    )
    function = SimpleNamespace(
        info={
            "x86_16_tail_validation": {
                "structuring": {
                    "status": "changed",
                    "changed": True,
                    "delta": {"added": list(range(1024))},
                }
            }
        }
    )

    snapshot = tail_validation_snapshot_for_function_run(project, function)

    assert snapshot == {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "stable", "changed": False},
    }


def test_tail_validation_snapshot_passed_rejects_non_stable_statuses():
    snapshot = {"postprocess": {"status": "stable"}}
    assert x86_16_tail_validation_snapshot_passed(snapshot, expected_stages=("postprocess",)) is True
    assert (
        x86_16_tail_validation_snapshot_passed({"postprocess": {"status": "changed"}}, expected_stages=("postprocess",))
        is False
    )
    assert (
        x86_16_tail_validation_snapshot_passed({"postprocess": {"status": "unknown"}}, expected_stages=("postprocess",))
        is False
    )
    assert (
        x86_16_tail_validation_snapshot_passed(
            {"postprocess": {"status": "uncollected"}}, expected_stages=("postprocess",)
        )
        is False
    )


def test_tail_validation_result_passed_only_accepts_stable_or_passed_status():
    assert x86_16_tail_validation_result_passed({"status": "stable"}) is True
    assert x86_16_tail_validation_result_passed({"status": "passed"}) is True
    assert x86_16_tail_validation_result_passed({"changed": False}) is True
    assert x86_16_tail_validation_result_passed({"status": "unknown", "changed": False}) is False
    assert x86_16_tail_validation_result_passed({"status": "uncollected", "changed": False}) is False
    assert x86_16_tail_validation_result_passed({"changed": True}) is False


def test_tail_validation_record_summary_aggregates_stage_status():
    summary = summarize_x86_16_tail_validation_records(
        [
            {
                "cod_file": "A.COD",
                "proc_name": "_a",
                "proc_kind": "NEAR",
                "structuring": {
                    "changed": False,
                    "mode": "live_out",
                    "verdict": "structuring whole-tail validation [live_out] stable: no observable whole-tail changes",
                },
                "postprocess": {
                    "changed": True,
                    "mode": "live_out",
                    "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
                },
            },
            {
                "cod_file": "B.COD",
                "proc_name": "_b",
                "proc_kind": "FAR",
            },
        ]
    )

    assert summary["severity"] == "changed"
    assert summary["changed_function_count"] == 1
    assert summary["coverage_count"] == 2
    assert summary["missing_count"] == 2
    assert summary["unknown_count"] == 0
    assert summary["structuring"]["stable_count"] == 1
    assert summary["structuring"]["unknown_count"] == 0
    assert summary["structuring"]["missing_count"] == 1
    assert summary["structuring"]["coverage_count"] == 1
    assert summary["postprocess"]["changed_count"] == 1
    assert summary["postprocess"]["missing_count"] == 1
    assert summary["postprocess"]["coverage_count"] == 1
    assert summary["postprocess"]["mode_counts"] == {"live_out": 1}
    assert summary["postprocess"]["top_verdicts"] == [
        {"verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping", "count": 1}
    ]


def test_tail_validation_surface_summarizes_headline_rates_and_hotspots():
    surface = build_x86_16_tail_validation_surface(
        {
            "severity": "changed",
            "changed_function_count": 2,
            "structuring": {
                "stable_count": 3,
                "changed_count": 1,
                "unknown_count": 1,
                "missing_count": 0,
                "coverage_count": 5,
                "mode_counts": {"live_out": 4},
                "top_verdicts": [
                    {"verdict": "structuring whole-tail validation [live_out] changed: guard", "count": 1}
                ],
            },
            "postprocess": {
                "stable_count": 2,
                "changed_count": 2,
                "unknown_count": 1,
                "missing_count": 0,
                "coverage_count": 5,
                "mode_counts": {"live_out": 4},
                "top_verdicts": [
                    {"verdict": "postprocess whole-tail validation [live_out] changed: helper", "count": 2}
                ],
            },
            "changed_functions": [
                {
                    "cod_file": "DOSFUNC.COD",
                    "proc_name": "_dos_alloc",
                    "proc_kind": "NEAR",
                    "stage": "postprocess",
                    "verdict": "postprocess whole-tail validation [live_out] changed: helper",
                },
                {
                    "cod_file": "DOSFUNC.COD",
                    "proc_name": "_dos_resize",
                    "proc_kind": "NEAR",
                    "stage": "structuring",
                    "verdict": "structuring whole-tail validation [live_out] changed: guard",
                },
                {
                    "cod_file": "DOSFUNC.COD",
                    "proc_name": "_dos_resize",
                    "proc_kind": "NEAR",
                    "stage": "postprocess",
                    "verdict": "postprocess whole-tail validation [live_out] changed: helper",
                },
            ],
        },
        scanned=5,
    )

    assert surface["headline"] == "whole-tail validation failed across 2 functions"
    assert surface["severity"] == "changed"
    assert surface["merge_gate"] is False
    assert surface["changed_stage_total"] == 3
    assert surface["coverage_count"] == 10
    assert surface["missing_stage_total"] == 0
    assert surface["unknown_stage_total"] == 2
    assert surface["stage_rows"] == [
        {
            "stage": "structuring",
            "changed_count": 1,
            "stable_count": 3,
            "unknown_count": 1,
            "missing_count": 0,
            "coverage_count": 5,
            "changed_rate": 0.2,
            "coverage_rate": 1.0,
            "mode_counts": {"live_out": 4},
            "top_verdicts": [{"verdict": "structuring whole-tail validation [live_out] changed: guard", "count": 1}],
        },
        {
            "stage": "postprocess",
            "changed_count": 2,
            "stable_count": 2,
            "unknown_count": 1,
            "missing_count": 0,
            "coverage_count": 5,
            "changed_rate": 0.4,
            "coverage_rate": 1.0,
            "mode_counts": {"live_out": 4},
            "top_verdicts": [{"verdict": "postprocess whole-tail validation [live_out] changed: helper", "count": 2}],
        },
    ]
    assert surface["stage_hotspots"] == [
        {
            "stage": "postprocess",
            "changed_count": 2,
            "changed_rate": 0.4,
            "top_verdicts": [{"verdict": "postprocess whole-tail validation [live_out] changed: helper", "count": 2}],
        },
        {
            "stage": "structuring",
            "changed_count": 1,
            "changed_rate": 0.2,
            "top_verdicts": [{"verdict": "structuring whole-tail validation [live_out] changed: guard", "count": 1}],
        },
    ]
    assert surface["top_changed_verdicts"] == [
        {"verdict": "postprocess whole-tail validation [live_out] changed: helper", "count": 2},
        {"verdict": "structuring whole-tail validation [live_out] changed: guard", "count": 1},
    ]
    assert surface["top_changed_functions"] == [
        {
            "cod_file": "DOSFUNC.COD",
            "proc_name": "_dos_resize",
            "proc_kind": "NEAR",
            "stages": ("postprocess", "structuring"),
            "verdicts": (
                "structuring whole-tail validation [live_out] changed: guard",
                "postprocess whole-tail validation [live_out] changed: helper",
            ),
            "changed_stage_count": 2,
        },
        {
            "cod_file": "DOSFUNC.COD",
            "proc_name": "_dos_alloc",
            "proc_kind": "NEAR",
            "stages": ("postprocess",),
            "verdicts": ("postprocess whole-tail validation [live_out] changed: helper",),
            "changed_stage_count": 1,
        },
    ]


def test_tail_validation_surface_groups_changed_observables_into_families():
    summary = summarize_x86_16_tail_validation_records(
        [
            {
                "cod_file": "COCKPIT.COD",
                "proc_name": "_DoCRT",
                "proc_kind": "NEAR",
                "postprocess": {
                    "changed": True,
                    "mode": "live_out",
                    "verdict": "postprocess whole-tail validation [live_out] changed: global_writes: +global:0x7000; segmented_writes: -deref:ds:0x7000",
                    "delta": {
                        "global_writes": {"added": ("global:0x7000",), "removed": ()},
                        "segmented_writes": {"added": (), "removed": ("deref:ds:0x7000",)},
                    },
                },
            },
            {
                "cod_file": "CARR.COD",
                "proc_name": "_SetGear",
                "proc_kind": "NEAR",
                "structuring": {
                    "changed": True,
                    "mode": "live_out",
                    "verdict": "structuring whole-tail validation [live_out] changed: conditions: +cmp; control_flow_effects: +if:cmp",
                    "delta": {
                        "conditions": {"added": ("cmp",), "removed": ()},
                        "control_flow_effects": {"added": ("if:cmp",), "removed": ()},
                    },
                },
            },
            {
                "cod_file": "EGAME11.COD",
                "proc_name": "_strcpyFromDot",
                "proc_kind": "NEAR",
                "structuring": {
                    "changed": True,
                    "mode": "live_out",
                    "verdict": "structuring whole-tail validation [live_out] changed: conditions: +cmp",
                    "delta": {
                        "conditions": {"added": ("cmp",), "removed": ()},
                    },
                },
            },
            {
                "cod_file": "OUTPUT.COD",
                "proc_name": "_hexdump",
                "proc_kind": "NEAR",
                "structuring": {
                    "changed": True,
                    "mode": "live_out",
                    "verdict": "structuring whole-tail validation [live_out] changed: control_flow_effects: +if:cmp",
                    "delta": {
                        "control_flow_effects": {"added": ("if:cmp",), "removed": ()},
                    },
                },
            },
            {
                "cod_file": "PLANES3.COD",
                "proc_name": "_CheckIfCanIntercept",
                "proc_kind": "NEAR",
                "structuring": {
                    "changed": True,
                    "mode": "live_out",
                    "verdict": "structuring whole-tail validation [live_out] changed: conditions: +cmp",
                    "delta": {
                        "conditions": {"added": ("cmp",), "removed": ()},
                    },
                },
            },
            {
                "cod_file": "START1.COD",
                "proc_name": "_waitMdaCgaStatus",
                "proc_kind": "NEAR",
                "structuring": {
                    "changed": True,
                    "mode": "live_out",
                    "verdict": "structuring whole-tail validation [live_out] changed: conditions: +cmp",
                    "delta": {
                        "conditions": {"added": ("cmp",), "removed": ()},
                    },
                },
            },
        ]
    )
    surface = build_x86_16_tail_validation_surface(summary, scanned=6)

    assert summary["changed_families"] == [
        {
            "family": "control-flow/guard delta",
            "count": 5,
            "function_count": 5,
            "stages": ("structuring",),
            "examples": (
                {"cod_file": "CARR.COD", "proc_name": "_SetGear", "proc_kind": "NEAR"},
                {"cod_file": "EGAME11.COD", "proc_name": "_strcpyFromDot", "proc_kind": "NEAR"},
                {"cod_file": "OUTPUT.COD", "proc_name": "_hexdump", "proc_kind": "NEAR"},
                {"cod_file": "PLANES3.COD", "proc_name": "_CheckIfCanIntercept", "proc_kind": "NEAR"},
                {"cod_file": "START1.COD", "proc_name": "_waitMdaCgaStatus", "proc_kind": "NEAR"},
            ),
        },
        {
            "family": "segmented/global write delta",
            "count": 1,
            "function_count": 1,
            "stages": ("postprocess",),
            "examples": ({"cod_file": "COCKPIT.COD", "proc_name": "_DoCRT", "proc_kind": "NEAR"},),
        },
    ]
    assert surface["changed_families"] == summary["changed_families"]


def test_tail_validation_record_summary_marks_uncollected_separately_from_unknown():
    summary = summarize_x86_16_tail_validation_records(
        [
            {"cod_file": "A.COD", "proc_name": "_a", "proc_kind": "NEAR"},
            {"cod_file": "B.COD", "proc_name": "_b", "proc_kind": "NEAR"},
        ]
    )
    surface = build_x86_16_tail_validation_surface(summary, scanned=2)

    assert summary["severity"] == "uncollected"
    assert summary["coverage_count"] == 0
    assert summary["missing_count"] == 4
    assert summary["unknown_count"] == 0
    assert summary["function_status_counts"] == {"uncollected": 2}
    assert summary["uncollected_function_count"] == 2
    assert summary["uncollected_functions"] == [
        {
            "cod_file": "A.COD",
            "proc_name": "_a",
            "proc_kind": "NEAR",
            "status": "uncollected",
            "stage_statuses": {"postprocess": "uncollected", "structuring": "uncollected"},
            "exit_kind": None,
            "exit_detail": None,
            "tail_validation_uncollected": False,
        },
        {
            "cod_file": "B.COD",
            "proc_name": "_b",
            "proc_kind": "NEAR",
            "status": "uncollected",
            "stage_statuses": {"postprocess": "uncollected", "structuring": "uncollected"},
            "exit_kind": None,
            "exit_detail": None,
            "tail_validation_uncollected": False,
        },
    ]
    assert surface["headline"] == "whole-tail validation not collected across 2 functions"
    assert surface["coverage_count"] == 0
    assert surface["missing_stage_total"] == 4
    assert surface["unknown_stage_total"] == 0
    assert surface["function_status_counts"] == {"uncollected": 2}
    assert surface["uncollected_function_count"] == 2
    assert surface["top_uncollected_functions"] == summary["uncollected_functions"]
    assert surface["consistency_issues"] == ()


def test_tail_validation_partial_surface_uses_failed_headline():
    surface = build_x86_16_tail_validation_surface(
        {
            "severity": "partial",
            "changed_function_count": 0,
            "structuring": {"stable_count": 1, "missing_count": 1, "coverage_count": 1},
            "postprocess": {"stable_count": 1, "missing_count": 1, "coverage_count": 1},
            "changed_functions": [],
            "function_status_counts": {"passed": 1, "uncollected": 1},
            "function_statuses": [],
            "uncollected_functions": [{"cod_file": "B.COD", "proc_name": "_b", "proc_kind": "NEAR"}],
            "unknown_functions": [],
        },
        scanned=2,
    )

    assert surface["headline"] == "whole-tail validation failed across 2 functions"


def test_tail_validation_uncollected_records_fall_back_to_function_name_identity():
    summary = summarize_x86_16_tail_validation_records(
        [
            {
                "cod_file": "LIFE2.EXE",
                "function_name": "sub_119d3",
                "tail_validation_uncollected": True,
                "exit_kind": "timeout",
                "exit_detail": "Timed out after 5s.",
            }
        ]
    )
    surface = build_x86_16_tail_validation_surface(summary, scanned=1)

    assert summary["uncollected_functions"] == [
        {
            "cod_file": "LIFE2.EXE",
            "proc_name": "sub_119d3",
            "proc_kind": None,
            "status": "uncollected",
            "stage_statuses": {"postprocess": "uncollected", "structuring": "uncollected"},
            "exit_kind": "timeout",
            "exit_detail": "Timed out after 5s.",
            "tail_validation_uncollected": True,
        }
    ]
    assert surface["top_uncollected_functions"] == summary["uncollected_functions"]
    assert surface["function_statuses"] == summary["function_statuses"]


def test_tail_validation_surface_consistency_checker_reports_counter_drift():
    summary = summarize_x86_16_tail_validation_records(
        [
            {
                "cod_file": "A.COD",
                "proc_name": "_a",
                "proc_kind": "NEAR",
                "structuring": {"changed": False, "mode": "live_out"},
                "postprocess": {"changed": False, "mode": "live_out"},
            }
        ]
    )
    surface = build_x86_16_tail_validation_surface(summary, scanned=1)
    broken_surface = dict(surface)
    broken_surface["coverage_count"] = 0
    broken_surface["function_status_counts"] = {"uncollected": 1}

    issues = check_x86_16_tail_validation_surface_consistency(summary, broken_surface, scanned=1)

    assert "coverage_count: surface=0 summary=2" in issues
    assert "function_status_counts mismatch" in issues


def test_tail_validation_aggregate_reuses_record_fingerprint_cache():
    records = [
        {
            "cod_file": "A.COD",
            "proc_name": "_a",
            "proc_kind": "NEAR",
            "postprocess": {
                "changed": True,
                "mode": "live_out",
                "verdict": "postprocess whole-tail validation [live_out] changed: helper",
            },
        }
    ]

    first = build_x86_16_tail_validation_aggregate(records, scanned=1)
    second = build_x86_16_tail_validation_aggregate(records, scanned=1)

    assert first["cache_hit"] is False
    assert second["cache_hit"] is True
    assert second["summary"] == first["summary"]
    assert second["surface"] == first["surface"]


def test_tail_validation_function_accounting_covers_passed_changed_unknown_and_uncollected():
    summary = summarize_x86_16_tail_validation_records(
        [
            {
                "cod_file": "A.COD",
                "proc_name": "_passed",
                "proc_kind": "NEAR",
                "structuring": {"changed": False, "mode": "live_out"},
                "postprocess": {"changed": False, "mode": "live_out"},
            },
            {
                "cod_file": "B.COD",
                "proc_name": "_changed",
                "proc_kind": "NEAR",
                "structuring": {"changed": False, "mode": "live_out"},
                "postprocess": {
                    "changed": True,
                    "mode": "live_out",
                    "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
                },
            },
            {
                "cod_file": "C.COD",
                "proc_name": "_unknown",
                "proc_kind": "NEAR",
                "structuring": {"mode": "live_out"},
                "postprocess": {"changed": False, "mode": "live_out"},
            },
            {
                "cod_file": "D.COD",
                "proc_name": "_uncollected",
                "proc_kind": "NEAR",
                "tail_validation_uncollected": True,
                "exit_kind": "timeout",
            },
        ]
    )
    surface = build_x86_16_tail_validation_surface(summary, scanned=4)

    assert summary["function_status_counts"] == {
        "changed": 1,
        "passed": 1,
        "uncollected": 1,
        "unknown": 1,
    }
    assert summary["passed_function_count"] == 1
    assert summary["changed_function_count"] == 1
    assert summary["unknown_function_count"] == 1
    assert summary["uncollected_function_count"] == 1
    assert surface["function_status_counts"] == summary["function_status_counts"]
    assert surface["top_unknown_functions"][0]["proc_name"] == "_unknown"
    assert surface["top_uncollected_functions"][0]["proc_name"] == "_uncollected"


def test_tail_validation_aggregate_marks_missing_records_as_uncollected():
    aggregate = build_x86_16_tail_validation_aggregate([], scanned=1)

    assert aggregate["summary"]["severity"] == "uncollected"
    assert aggregate["summary"]["coverage_count"] == 0
    assert aggregate["summary"]["missing_count"] == 2
    assert aggregate["summary"]["function_status_counts"] == {"uncollected": 1}
    assert aggregate["summary"]["uncollected_function_count"] == 1
    assert aggregate["surface"]["function_status_counts"] == {"uncollected": 1}
    assert aggregate["surface"]["uncollected_function_count"] == 1
    assert aggregate["surface"]["headline"] == "whole-tail validation not collected across 1 functions"


def test_tail_validation_baseline_comparison_distinguishes_match_improve_and_regress():
    summary = {
        "changed_functions": [
            {
                "cod_file": "DOSFUNC.COD",
                "proc_name": "_dos_alloc",
                "proc_kind": "NEAR",
                "stage": "postprocess",
                "verdict": "postprocess whole-tail validation [live_out] changed: helper",
            }
        ]
    }
    baseline = build_x86_16_tail_validation_baseline(summary)

    matched = compare_x86_16_tail_validation_baseline(summary, baseline)
    improved = compare_x86_16_tail_validation_baseline({"changed_functions": []}, baseline)
    regressed = compare_x86_16_tail_validation_baseline(
        {
            "changed_functions": [
                *summary["changed_functions"],
                {
                    "cod_file": "DOSFUNC.COD",
                    "proc_name": "_dos_resize",
                    "proc_kind": "NEAR",
                    "stage": "structuring",
                    "verdict": "structuring whole-tail validation [live_out] changed: guard",
                },
            ]
        },
        baseline,
    )

    assert matched["status"] == "matches_baseline"
    assert improved["status"] == "improved"
    assert regressed["status"] == "regressed"
    assert len(regressed["unexpected"]) == 1


def test_tail_validation_surface_annotation_includes_baseline_counts():
    surface = annotate_x86_16_tail_validation_surface_with_baseline(
        {"headline": "whole-tail validation failed across 1 functions"},
        {
            "status": "regressed",
            "unexpected": [{"proc_name": "_dos_resize"}],
            "missing": [{"proc_name": "_dos_alloc"}],
        },
    )

    assert surface["baseline_status"] == "regressed"
    assert surface["baseline_unexpected_count"] == 1
    assert surface["baseline_missing_count"] == 1


def test_tail_validation_diff_formatter_reports_no_change_cleanly():
    summary = collect_x86_16_tail_validation_summary(_project(), _codegen([], _DummyCodegen()))

    assert (
        format_x86_16_tail_validation_diff(compare_x86_16_tail_validation_summaries(summary, summary))
        == "no observable whole-tail changes"
    )


def test_tail_validation_scope_description_exposes_whole_tail_boundary():
    desc = describe_x86_16_tail_validation_scope()

    assert desc["preferred_mode"] == "live_out"
    assert desc["modes"] == ("coarse", "live_out")
    assert desc["layers"] == ("structuring", "postprocess")
    assert "helper_calls" in desc["observables"]
    assert "control_flow_effects" in desc["observables"]
    assert "temporary names" in desc["ignored"]


def test_tail_validation_verdict_omits_collection_timing_suffix_by_default(monkeypatch):
    monkeypatch.delenv("INERTIA_DEBUG_TIMING", raising=False)

    verdict = build_x86_16_tail_validation_verdict(
        "postprocess",
        {
            "mode": "live_out",
            "changed": True,
            "summary_text": "register_writes: +reg:ax",
            "timings": {
                "collect_before_ms": 1.25,
                "collect_after_ms": 2.5,
                "compare_ms": 0.75,
                "total_ms": 4.5,
            },
        },
    )

    assert "collect=" not in verdict
    assert "compare=" not in verdict
    assert "tail_validation=" not in verdict


def test_tail_validation_verdict_includes_collection_timing_suffix_when_enabled(monkeypatch):
    monkeypatch.setenv("INERTIA_DEBUG_TIMING", "1")

    verdict = build_x86_16_tail_validation_verdict(
        "postprocess",
        {
            "mode": "live_out",
            "changed": True,
            "summary_text": "register_writes: +reg:ax",
            "timings": {
                "collect_before_ms": 1.25,
                "collect_after_ms": 2.5,
                "compare_ms": 0.75,
                "total_ms": 4.5,
            },
        },
    )

    assert "collect=1.2+2.5ms" in verdict
    assert "compare=0.8ms" in verdict
    assert "tail_validation=4.5ms" in verdict


def test_postprocess_codegen_restores_last_clean_state_on_live_out_delta(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_postprocess_per_pass_validation_enabled=True,
    )
    codegen = SimpleNamespace(cfunc=_postprocess_cfunc(state="baseline"), project=project)

    def _summary(_project, codegen_arg, *, mode="live_out", **_kwargs):
        return SimpleNamespace(state=codegen_arg.cfunc.state, mode=mode)

    def _compare(before, after):
        return {
            "changed": after.state == "bad",
            "summary_text": "state changed" if after.state == "bad" else "state stable",
        }

    def _bad_pass(codegen_arg):
        codegen_arg.cfunc.state = "bad"
        return True

    def _later_pass(codegen_arg):
        codegen_arg.cfunc.state = "later"
        return True

    monkeypatch.setattr(
        postprocess_stage._globals, "_coalesce_word_global_loads_8616", lambda _project, _codegen: set()
    )
    monkeypatch.setattr(
        postprocess_stage._globals,
        "_coalesce_word_global_constant_stores_8616",
        lambda _project, _codegen: set(),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_decompiler_postprocess_passes_for_function",
        lambda _project, _codegen: (
            postprocess_stage.DecompilerPostprocessPassSpec("_bad_pass", _bad_pass, False),
            postprocess_stage.DecompilerPostprocessPassSpec("_later_pass", _later_pass, False),
        ),
    )
    monkeypatch.setattr(postprocess_stage, "collect_x86_16_tail_validation_summary", _summary)
    monkeypatch.setattr(postprocess_stage, "compare_x86_16_tail_validation_summaries", _compare)
    monkeypatch.setattr(postprocess_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: True)

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert codegen.cfunc.state == "baseline"
    assert codegen._inertia_postprocess_validation_failed is True
    assert codegen._inertia_postprocess_validation_failure_pass == "_bad_pass"
    assert codegen._inertia_postprocess_validation_failure_error == "state changed"
    assert codegen._inertia_last_postprocess_pass is None


def test_postprocess_codegen_keeps_accepted_changes_when_live_out_stays_stable(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_postprocess_per_pass_validation_enabled=True,
    )
    codegen = SimpleNamespace(cfunc=_postprocess_cfunc(state="baseline"), project=project)

    def _summary(_project, codegen_arg, *, mode="live_out", **_kwargs):
        return SimpleNamespace(state=codegen_arg.cfunc.state, mode=mode)

    def _compare(_before, after):
        return {
            "changed": after.state == "bad",
            "summary_text": "state changed" if after.state == "bad" else "state stable",
        }

    def _first_pass(codegen_arg):
        codegen_arg.cfunc.state = "accepted-1"
        return True

    def _second_pass(codegen_arg):
        codegen_arg.cfunc.state = "accepted-2"
        return True

    monkeypatch.setattr(
        postprocess_stage._globals, "_coalesce_word_global_loads_8616", lambda _project, _codegen: set()
    )
    monkeypatch.setattr(
        postprocess_stage._globals,
        "_coalesce_word_global_constant_stores_8616",
        lambda _project, _codegen: set(),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_decompiler_postprocess_passes_for_function",
        lambda _project, _codegen: (
            postprocess_stage.DecompilerPostprocessPassSpec("_first_pass", _first_pass, False),
            postprocess_stage.DecompilerPostprocessPassSpec("_second_pass", _second_pass, False),
        ),
    )
    monkeypatch.setattr(postprocess_stage, "collect_x86_16_tail_validation_summary", _summary)
    monkeypatch.setattr(postprocess_stage, "compare_x86_16_tail_validation_summaries", _compare)
    monkeypatch.setattr(postprocess_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: True)

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is True
    assert codegen.cfunc.state == "accepted-2"
    assert codegen._inertia_postprocess_validation_failed is False
    assert codegen._inertia_postprocess_validation_failure_pass is None
    assert codegen._inertia_last_postprocess_pass == "_second_pass"


def test_postprocess_codegen_rejects_non_stable_per_pass_validation_status(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_postprocess_per_pass_validation_enabled=True,
    )
    codegen = SimpleNamespace(cfunc=_postprocess_cfunc(state="baseline"), project=project)

    def _summary(_project, codegen_arg, *, mode="live_out", **_kwargs):
        return SimpleNamespace(state=codegen_arg.cfunc.state, mode=mode)

    def _compare(_before, _after):
        if _after.state == "accepted":
            return {
                "changed": False,
                "status": "unknown",
                "summary_text": "validation metadata missing",
            }
        return {
            "changed": False,
            "status": "stable",
            "summary_text": "state stable",
        }

    def _pass(codegen_arg):
        codegen_arg.cfunc.state = "accepted"
        return True

    monkeypatch.setattr(
        postprocess_stage._globals, "_coalesce_word_global_loads_8616", lambda _project, _codegen: set()
    )
    monkeypatch.setattr(
        postprocess_stage._globals,
        "_coalesce_word_global_constant_stores_8616",
        lambda _project, _codegen: set(),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_decompiler_postprocess_passes_for_function",
        lambda _project, _codegen: (postprocess_stage.DecompilerPostprocessPassSpec("_pass", _pass, False),),
    )
    monkeypatch.setattr(postprocess_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(postprocess_stage, "collect_x86_16_tail_validation_summary", _summary)
    monkeypatch.setattr(postprocess_stage, "compare_x86_16_tail_validation_summaries", _compare)

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert codegen.cfunc.state == "baseline"
    assert codegen._inertia_postprocess_validation_failed is True
    assert codegen._inertia_postprocess_validation_failure_pass == "_pass"
    assert codegen._inertia_postprocess_validation_failure_error == "validation metadata missing"


def test_postprocess_codegen_validates_small_function_typed_conditions(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_tail_validation_enabled=True,
        _inertia_postprocess_per_pass_validation_enabled=False,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr=None, **_kwargs: None),
        ),
    )
    codegen = SimpleNamespace(cfunc=_postprocess_cfunc(addr=0x1234, state="baseline"), project=project)
    calls: list[str] = []

    def _typed_condition_pass(_project, codegen_arg):
        calls.append("typed")
        codegen_arg.cfunc.state = "bad"
        return True

    def _summary(_project, codegen_arg, *, mode="live_out"):
        return SimpleNamespace(state=codegen_arg.cfunc.state, mode=mode)

    def _compare(_before, after):
        return {
            "changed": after.state == "bad",
            "summary_text": "condition changed" if after.state == "bad" else "state stable",
        }

    monkeypatch.setenv(
        "INERTIA_SKIP_POSTPROCESS_PASSES",
        ",".join(
            (
                "_normalize_fact_backed_stack_accesses_8616",
                "_materialize_global_byte_index_sum_loop_8616",
                "_materialize_cfg_selector_return_branches_early_8616",
                "_rewrite_decoded_jcc_conditions_8616",
            )
        ),
    )
    monkeypatch.setattr(postprocess_stage, "_decompiler_postprocess_passes_for_function", lambda _project, _codegen: ())
    monkeypatch.setattr(postprocess_stage, "_apply_typed_conditions_to_codegen_8616", _typed_condition_pass)
    monkeypatch.setattr(
        postprocess_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        _summary,
    )
    monkeypatch.setattr(postprocess_stage, "collect_x86_16_tail_validation_summary", _summary)
    monkeypatch.setattr(postprocess_stage, "compare_x86_16_tail_validation_summaries", _compare)
    monkeypatch.setattr(postprocess_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: True)

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert calls == ["typed"]
    assert codegen.cfunc.state == "baseline"
    assert codegen._inertia_postprocess_validation_failed is False
    assert "_apply_typed_conditions_to_codegen_8616" in codegen._inertia_postprocess_rejected_passes


def test_postprocess_codegen_validates_small_function_global_byte_index_loop(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_tail_validation_enabled=True,
        _inertia_postprocess_per_pass_validation_enabled=False,
    )
    codegen = SimpleNamespace(cfunc=_postprocess_cfunc(addr=0x1234, state="baseline"), project=project)
    calls: list[str] = []

    def _global_byte_index_pass(_project, codegen_arg):
        calls.append("global-byte")
        codegen_arg.cfunc.state = "bad"
        return True

    def _summary(_project, codegen_arg, *, mode="live_out"):
        return SimpleNamespace(state=codegen_arg.cfunc.state, mode=mode)

    def _compare(_before, after):
        return {
            "changed": after.state == "bad",
            "summary_text": "guard changed" if after.state == "bad" else "state stable",
        }

    monkeypatch.setenv(
        "INERTIA_SKIP_POSTPROCESS_PASSES",
        ",".join(
            (
                "_normalize_fact_backed_stack_accesses_8616",
                "_apply_typed_conditions_to_codegen_8616",
                "_materialize_cfg_selector_return_branches_early_8616",
                "_rewrite_decoded_jcc_conditions_8616",
            )
        ),
    )
    monkeypatch.setattr(postprocess_stage, "_decompiler_postprocess_passes_for_function", lambda _project, _codegen: ())
    monkeypatch.setattr(postprocess_stage, "_materialize_global_byte_index_sum_loop_8616", _global_byte_index_pass)
    monkeypatch.setattr(
        postprocess_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        _summary,
    )
    monkeypatch.setattr(postprocess_stage, "collect_x86_16_tail_validation_summary", _summary)
    monkeypatch.setattr(postprocess_stage, "compare_x86_16_tail_validation_summaries", _compare)
    monkeypatch.setattr(postprocess_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: True)

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert calls == ["global-byte"]
    assert codegen.cfunc.state == "baseline"
    assert codegen._inertia_postprocess_validation_failed is False
    assert "_materialize_global_byte_index_sum_loop_8616" in codegen._inertia_postprocess_rejected_passes


def test_postprocess_codegen_validates_small_function_global_byte_loop(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_tail_validation_enabled=True,
        _inertia_postprocess_per_pass_validation_enabled=False,
    )
    codegen = SimpleNamespace(cfunc=_postprocess_cfunc(addr=0x1234, state="baseline"), project=project)
    calls: list[str] = []

    def _global_byte_pass(_project, codegen_arg):
        calls.append("global-byte")
        codegen_arg.cfunc.state = "bad"
        return True

    def _summary(_project, codegen_arg, *, mode="live_out"):
        return SimpleNamespace(state=codegen_arg.cfunc.state, mode=mode)

    def _compare(_before, after):
        return {
            "changed": after.state == "bad",
            "summary_text": "loop guard changed" if after.state == "bad" else "state stable",
        }

    monkeypatch.setenv(
        "INERTIA_SKIP_POSTPROCESS_PASSES",
        ",".join(
            (
                "_normalize_fact_backed_stack_accesses_8616",
                "_apply_typed_conditions_to_codegen_8616",
                "_materialize_cfg_selector_return_branches_early_8616",
                "_rewrite_decoded_jcc_conditions_8616",
            )
        ),
    )
    monkeypatch.setattr(postprocess_stage, "_decompiler_postprocess_passes_for_function", lambda _project, _codegen: ())
    monkeypatch.setattr(
        postprocess_stage,
        "_materialize_global_byte_index_sum_loop_8616",
        _global_byte_pass,
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        _summary,
    )
    monkeypatch.setattr(postprocess_stage, "collect_x86_16_tail_validation_summary", _summary)
    monkeypatch.setattr(postprocess_stage, "compare_x86_16_tail_validation_summaries", _compare)
    monkeypatch.setattr(postprocess_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: True)

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert calls == ["global-byte"]
    assert codegen.cfunc.state == "baseline"
    assert codegen._inertia_postprocess_validation_failed is False
    assert "_materialize_global_byte_index_sum_loop_8616" in codegen._inertia_postprocess_rejected_passes


def test_postprocess_codegen_continues_after_global_byte_accumulator_validation_delta(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_tail_validation_enabled=True,
        _inertia_postprocess_per_pass_validation_enabled=False,
    )
    codegen = SimpleNamespace(cfunc=_postprocess_cfunc(addr=0x1234, state="baseline"), project=project)
    calls: list[str] = []

    def _global_pass(_project, codegen_arg):
        calls.append("global-byte")
        codegen_arg.cfunc.state = "bad"
        return True

    def _later_pass(codegen_arg):
        calls.append("later")
        assert codegen_arg.cfunc.state == "baseline"
        return False

    def _summary(_project, codegen_arg, *, mode="live_out"):
        return SimpleNamespace(state=codegen_arg.cfunc.state, mode=mode)

    def _compare(_before, after):
        return {
            "changed": after.state == "bad",
            "summary_text": "global byte loop changed" if after.state == "bad" else "state stable",
        }

    monkeypatch.setenv(
        "INERTIA_SKIP_POSTPROCESS_PASSES",
        ",".join(
            (
                "_normalize_fact_backed_stack_accesses_8616",
                "_apply_typed_conditions_to_codegen_8616",
                "_materialize_cfg_selector_return_branches_early_8616",
                "_rewrite_decoded_jcc_conditions_8616",
            )
        ),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_decompiler_postprocess_passes_for_function",
        lambda _project, _codegen: (
            postprocess_stage.DecompilerPostprocessPassSpec("_later_after_global_byte_reject_8616", _later_pass, False),
        ),
    )
    monkeypatch.setattr(postprocess_stage, "_materialize_global_byte_index_sum_loop_8616", _global_pass)
    monkeypatch.setattr(
        postprocess_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        _summary,
    )
    monkeypatch.setattr(postprocess_stage, "collect_x86_16_tail_validation_summary", _summary)
    monkeypatch.setattr(postprocess_stage, "compare_x86_16_tail_validation_summaries", _compare)
    monkeypatch.setattr(postprocess_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: True)

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert calls == ["global-byte", "later"]
    assert codegen.cfunc.state == "baseline"
    assert codegen._inertia_postprocess_validation_failed is False
    assert "_materialize_global_byte_index_sum_loop_8616" in codegen._inertia_postprocess_rejected_passes


def test_postprocess_mandatory_validation_covers_late_semantic_rewriters():
    expected = {
        "_classify_return_shape_8616",
        "_apply_typed_condition_stack_arg_signedness_8616",
        "_dead_code_elimination_after_callsite_stack_arguments_8616",
        "_dead_code_elimination_after_flag_prune_8616",
        "_dead_code_elimination_after_stable_stack_final_8616",
        "_materialize_callsite_stack_arguments_8616",
        "_materialize_callsite_stack_arguments_final_8616",
        "_materialize_direct_global_incdec_instructions_8616",
        "_materialize_direct_global_incdec_instructions_final_8616",
        "_materialize_direct_stack_incdec_instructions_8616",
        "_materialize_direct_stack_incdec_instructions_final_8616",
        "_materialize_direct_stack_mov_instructions_8616",
        "_materialize_direct_stack_mov_instructions_final_8616",
        "_materialize_stable_stack_semantics_bootstrap_8616",
        "_materialize_stable_stack_semantics_early_8616",
        "_materialize_stable_stack_semantics_final_8616",
        "_materialize_stable_stack_semantics_postprocess_8616",
        "_materialize_unconsumed_loop_break_jcc_8616",
        "_materialize_recovered_callsite_stack_arguments_8616",
        "_lower_runtime_ss_segment_helpers_to_stack_final_8616",
        "_lower_stable_ss_stack_accesses_8616",
        "_normalize_call_target_names_8616",
        "_normalize_recovered_call_target_names_8616",
        "_promote_stack_prototype_from_bp_loads_8616",
        "_prune_overwritten_flag_assignments_8616",
        "_prune_return_address_stack_arguments_8616",
        "_prune_unused_flag_assignments_8616",
        "_recover_missing_direct_calls_final_8616",
        "_recover_missing_direct_calls_from_evidence_8616",
        "_recover_missing_direct_calls_from_evidence_early_8616",
        "_rerun_stack_lowering_consumers_after_calls_8616",
        "_simplify_structured_expressions_8616",
        "_simplify_structured_expressions_after_call_stack_lowering_8616",
        "_simplify_structured_expressions_after_final_call_materialization_8616",
        "_simplify_structured_expressions_after_stack_lowering_8616",
    }
    expected |= pass_validation_policy.OPTIMIZATION_VALIDATION_PASS_NAMES_8616

    assert (
        pass_validation_policy.OPTIMIZATION_VALIDATION_PASS_NAMES_8616
        <= pass_validation_policy.LOCAL_PROOF_REQUIRED_POSTPROCESS_PASS_NAMES_8616
    )
    assert expected <= pass_validation_policy.MANDATORY_VALIDATION_PASS_NAMES_8616
    assert expected <= pass_validation_policy.PASS_LOCAL_REJECT_CONTINUE_PASS_NAMES_8616


def test_postprocess_codegen_validates_small_function_after_ss_callsite_args(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_tail_validation_enabled=True,
        _inertia_postprocess_per_pass_validation_enabled=False,
    )
    codegen = SimpleNamespace(cfunc=_postprocess_cfunc(addr=0x1234, state="baseline"), project=project)
    calls: list[str] = []

    def _callsite_pass(_project, codegen_arg):
        calls.append("callsite")
        codegen_arg.cfunc.state = "bad"
        return True

    def _summary(_project, codegen_arg, *, mode="live_out"):
        return SimpleNamespace(state=codegen_arg.cfunc.state, mode=mode)

    def _compare(_before, after):
        return {
            "changed": after.state == "bad",
            "summary_text": "callsite changed" if after.state == "bad" else "state stable",
        }

    monkeypatch.setenv(
        "INERTIA_SKIP_POSTPROCESS_PASSES",
        ",".join(
            (
                "_normalize_fact_backed_stack_accesses_8616",
                "_apply_typed_conditions_to_codegen_8616",
                "_materialize_global_byte_index_sum_loop_8616",
                "_materialize_cfg_selector_return_branches_early_8616",
                "_rewrite_decoded_jcc_conditions_8616",
            )
        ),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_decompiler_postprocess_passes_for_function",
        lambda _project, _codegen: (
            postprocess_stage.DecompilerPostprocessPassSpec(
                "_materialize_callsite_stack_arguments_after_ss_lowering_8616",
                _callsite_pass,
                True,
            ),
        ),
    )
    monkeypatch.setattr(postprocess_stage, "_postprocess_optimization_enabled_8616", lambda: False)
    monkeypatch.setattr(
        postprocess_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        _summary,
    )
    monkeypatch.setattr(postprocess_stage, "collect_x86_16_tail_validation_summary", _summary)
    monkeypatch.setattr(postprocess_stage, "compare_x86_16_tail_validation_summaries", _compare)
    monkeypatch.setattr(postprocess_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: True)

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert calls == ["callsite"]
    assert codegen.cfunc.state == "baseline"
    assert codegen._inertia_postprocess_validation_failed is False
    assert "_materialize_callsite_stack_arguments_after_ss_lowering_8616" in (
        codegen._inertia_postprocess_rejected_passes
    )


def test_postprocess_codegen_skips_heapsort_debug_regeneration_without_env(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_postprocess_per_pass_validation_enabled=False,
    )
    codegen = SimpleNamespace(
        cfunc=_postprocess_cfunc(addr=0x10970, state="baseline"),
        project=project,
    )
    calls: list[str] = []

    def _apply_word_globals(_project, _codegen):
        return set()

    def _pass(_project, codegen_arg):
        codegen_arg.cfunc.state = "after-callsite"
        return True

    monkeypatch.delenv("INERTIA_DEBUG_HEAPSORT_CALLS", raising=False)
    monkeypatch.delenv("INERTIA_DEBUG_STACK_NOISE", raising=False)
    monkeypatch.setattr(postprocess_stage._globals, "_coalesce_word_global_loads_8616", _apply_word_globals)
    monkeypatch.setattr(
        postprocess_stage._globals,
        "_coalesce_word_global_constant_stores_8616",
        lambda _project, _codegen: set(),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_decompiler_postprocess_passes_for_function",
        lambda _project, _codegen: (
            postprocess_stage.DecompilerPostprocessPassSpec(
                "_materialize_callsite_stack_arguments_8616",
                _pass,
                True,
            ),
            postprocess_stage.DecompilerPostprocessPassSpec("_later_pass", lambda _codegen: False, False),
        ),
    )
    monkeypatch.setattr(
        postprocess_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: calls.append("regen") or True
    )
    monkeypatch.setattr(
        postprocess_stage, "_debug_heap_call_lines_8616", lambda *_args, **_kwargs: calls.append("heap")
    )
    monkeypatch.setattr(postprocess_stage, "_debug_stack_noise_8616", lambda *_args, **_kwargs: calls.append("noise"))

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is True
    assert calls == ["regen", "regen"]


def test_postprocess_codegen_does_not_regenerate_when_no_pass_changed(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_tail_validation_enabled=False,
        _inertia_postprocess_per_pass_validation_enabled=False,
    )
    codegen = SimpleNamespace(cfunc=_postprocess_cfunc(addr=0x1234), project=project, text="int f(void) { return 0; }")
    calls: list[str] = []
    monkeypatch.setenv(
        "INERTIA_SKIP_POSTPROCESS_PASSES",
        ",".join(
            (
                "_materialize_stable_stack_semantics_bootstrap_8616",
                "_normalize_fact_backed_stack_accesses_8616",
                "_apply_typed_conditions_to_codegen_8616",
                "_materialize_global_byte_index_sum_loop_8616",
                "_materialize_cfg_selector_return_branches_early_8616",
                "_rewrite_decoded_jcc_conditions_8616",
            )
        ),
    )

    monkeypatch.setattr(postprocess_stage, "_decompiler_postprocess_passes_for_function", lambda _project, _codegen: ())
    monkeypatch.setattr(
        postprocess_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: calls.append("regen") or True
    )

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert calls == []


def test_postprocess_codegen_refuses_large_function_semantic_pass_without_local_validation(monkeypatch):
    class _Functions:
        def function(self, _addr=None, **_kwargs):
            return SimpleNamespace(block_addrs_set=tuple(range(40)), info={})

    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        kb=SimpleNamespace(functions=_Functions()),
        _inertia_tail_validation_enabled=True,
        _inertia_postprocess_per_pass_validation_enabled=False,
    )
    codegen = SimpleNamespace(cfunc=_postprocess_cfunc(addr=0x1234), project=project, text="int f(void) { return 0; }")
    calls: list[str] = []
    monkeypatch.setenv("INERTIA_DISABLE_POSTPROCESS_OPT", "1")
    monkeypatch.setenv(
        "INERTIA_SKIP_POSTPROCESS_PASSES",
        ",".join(
            (
                "_materialize_stable_stack_semantics_bootstrap_8616",
                "_normalize_fact_backed_stack_accesses_8616",
                "_apply_typed_conditions_to_codegen_8616",
                "_materialize_global_byte_index_sum_loop_8616",
                "_materialize_cfg_selector_return_branches_early_8616",
            )
        ),
    )

    def _semantic_pass(_codegen):
        calls.append("semantic")
        return True

    monkeypatch.setattr(
        postprocess_stage,
        "_decompiler_postprocess_passes_for_function",
        lambda _project, _codegen: (
            postprocess_stage.DecompilerPostprocessPassSpec(
                "_rewrite_decoded_jcc_conditions_8616",
                _semantic_pass,
                False,
            ),
        ),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        lambda *_args, **_kwargs: SimpleNamespace(state="stable"),
    )

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert calls == []
    assert {
        "pass": "_rewrite_decoded_jcc_conditions_8616",
        "reason": postprocess_stage._PostprocessPassRefusalReason8616.LARGE_FUNCTION_LOCAL_VALIDATION_UNAVAILABLE.value,
    } in codegen._inertia_postprocess_refused_passes_8616


def test_postprocess_codegen_refuses_large_function_final_simplifier_without_local_validation(monkeypatch):
    class _Functions:
        def function(self, _addr=None, **_kwargs):
            return SimpleNamespace(block_addrs_set=tuple(range(40)), info={})

    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        kb=SimpleNamespace(functions=_Functions()),
        _inertia_tail_validation_enabled=True,
        _inertia_postprocess_per_pass_validation_enabled=False,
    )
    codegen = SimpleNamespace(cfunc=_postprocess_cfunc(addr=0x1234), project=project, text="int f(void) { return 0; }")
    calls: list[str] = []
    monkeypatch.setenv("INERTIA_DISABLE_POSTPROCESS_OPT", "1")
    monkeypatch.setenv(
        "INERTIA_SKIP_POSTPROCESS_PASSES",
        ",".join(
            (
                "_materialize_stable_stack_semantics_bootstrap_8616",
                "_normalize_fact_backed_stack_accesses_8616",
                "_apply_typed_conditions_to_codegen_8616",
                "_materialize_global_byte_index_sum_loop_8616",
                "_materialize_cfg_selector_return_branches_early_8616",
            )
        ),
    )

    def _simplify_pass(_codegen):
        calls.append("simplify")
        return True

    monkeypatch.setattr(
        postprocess_stage,
        "_decompiler_postprocess_passes_for_function",
        lambda _project, _codegen: (
            postprocess_stage.DecompilerPostprocessPassSpec(
                "_simplify_structured_expressions_after_final_call_materialization_8616",
                _simplify_pass,
                False,
            ),
        ),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        lambda *_args, **_kwargs: SimpleNamespace(state="stable"),
    )

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert calls == []
    assert {
        "pass": "_simplify_structured_expressions_after_final_call_materialization_8616",
        "reason": postprocess_stage._PostprocessPassRefusalReason8616.LARGE_FUNCTION_LOCAL_VALIDATION_UNAVAILABLE.value,
    } in codegen._inertia_postprocess_refused_passes_8616


def test_postprocess_codegen_refuses_large_function_annotations_without_local_validation(monkeypatch):
    function_record = SimpleNamespace(
        block_addrs_set=tuple(range(40)),
        info={"before": True},
        prototype="old-prototype",
    )

    class _Functions:
        def function(self, _addr=None, **_kwargs):
            return function_record

    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        kb=SimpleNamespace(functions=_Functions(), labels={0x7000: "old_label"}),
        _inertia_tail_validation_enabled=True,
        _inertia_postprocess_per_pass_validation_enabled=False,
    )
    codegen = SimpleNamespace(cfunc=_postprocess_cfunc(addr=0x1234, state="baseline"), project=project)
    calls: list[str] = []

    def _annotation_pass(_project, codegen_arg):
        calls.append("annotation")
        function_record.info["x86_16_annotations"] = {"stack_vars": {0: {"name": "local_0"}}}
        function_record.prototype = "new-prototype"
        _project.kb.labels[0x7000] = "new_label"
        codegen_arg.cfunc.state = "bad"
        return True

    def _summary(_project, codegen_arg, *, mode="live_out"):
        return SimpleNamespace(state=codegen_arg.cfunc.state, mode=mode)

    def _compare(_before, after):
        return {
            "changed": after.state == "bad",
            "summary_text": "condition changed" if after.state == "bad" else "state stable",
        }

    monkeypatch.setenv(
        "INERTIA_SKIP_POSTPROCESS_PASSES",
        ",".join(
            (
                "_materialize_stable_stack_semantics_bootstrap_8616",
                "_normalize_fact_backed_stack_accesses_8616",
                "_apply_typed_conditions_to_codegen_8616",
                "_materialize_global_byte_index_sum_loop_8616",
                "_materialize_cfg_selector_return_branches_early_8616",
            )
        ),
    )
    monkeypatch.setattr(
        postprocess_stage._globals, "_coalesce_word_global_loads_8616", lambda _project, _codegen: set()
    )
    monkeypatch.setattr(
        postprocess_stage._globals,
        "_coalesce_word_global_constant_stores_8616",
        lambda _project, _codegen: set(),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_decompiler_postprocess_passes_for_function",
        lambda _project, _codegen: (
            postprocess_stage.DecompilerPostprocessPassSpec(
                "_apply_annotations_8616",
                _annotation_pass,
                True,
            ),
        ),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        _summary,
    )
    monkeypatch.setattr(postprocess_stage, "collect_x86_16_tail_validation_summary", _summary)
    monkeypatch.setattr(postprocess_stage, "compare_x86_16_tail_validation_summaries", _compare)
    monkeypatch.setattr(postprocess_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: True)

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert calls == []
    assert codegen.cfunc.state == "baseline"
    assert function_record.info == {"before": True}
    assert function_record.prototype == "old-prototype"
    assert project.kb.labels == {0x7000: "old_label"}
    assert codegen._inertia_postprocess_validation_failed is False
    assert {
        "pass": "_apply_annotations_8616",
        "reason": postprocess_stage._PostprocessPassRefusalReason8616.LARGE_FUNCTION_LOCAL_VALIDATION_UNAVAILABLE.value,
    } in codegen._inertia_postprocess_refused_passes_8616


def test_postprocess_force_validates_nonmandatory_large_function_pass(monkeypatch):
    class _Functions:
        def function(self, _addr=None, **_kwargs):
            return SimpleNamespace(block_addrs_set=tuple(range(80)), info={})

    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        kb=SimpleNamespace(functions=_Functions(), labels={}),
        _inertia_tail_validation_enabled=True,
        _inertia_postprocess_per_pass_validation_enabled=False,
    )
    codegen = SimpleNamespace(cfunc=_postprocess_cfunc(addr=0x1234, state="baseline"), project=project)
    calls: list[str] = []
    monkeypatch.setenv("INERTIA_FORCE_PER_PASS_TV", "1")
    monkeypatch.setenv(
        "INERTIA_SKIP_POSTPROCESS_PASSES",
        ",".join(
            (
                "_materialize_stable_stack_semantics_bootstrap_8616",
                "_normalize_fact_backed_stack_accesses_8616",
                "_apply_typed_conditions_to_codegen_8616",
                "_materialize_global_byte_index_sum_loop_8616",
                "_materialize_cfg_selector_return_branches_early_8616",
            )
        ),
    )

    def _bad_return_address_prune(_project, codegen_arg):
        calls.append("return-prune")
        codegen_arg.cfunc.state = "bad"
        return True

    def _noop_pointer_memory(_project, _codegen_arg):
        calls.append("pointer-memory")
        return False

    def _bad_annotation(_project, codegen_arg):
        calls.append("annotation")
        codegen_arg.cfunc.state = "bad_annotation"
        return True

    def _bad_dce(_codegen_arg):
        calls.append("dce")
        _codegen_arg.cfunc.state = "bad_dce"
        return True

    def _summary(_project, codegen_arg, *, mode="live_out"):
        return SimpleNamespace(state=codegen_arg.cfunc.state, mode=mode)

    def _compare(before, after):
        return {
            "changed": before.state != after.state,
            "summary_text": "state changed" if before.state != after.state else "state stable",
        }

    monkeypatch.setattr(
        postprocess_stage,
        "_decompiler_postprocess_passes_for_function",
        lambda _project, _codegen: (
            postprocess_stage.DecompilerPostprocessPassSpec(
                "_prune_return_address_stack_arguments_8616",
                _bad_return_address_prune,
                True,
            ),
            postprocess_stage.DecompilerPostprocessPassSpec(
                "_non_mandatory_debug_probe_8616",
                _bad_annotation,
                True,
            ),
            postprocess_stage.DecompilerPostprocessPassSpec(
                "optimization:dce",
                _bad_dce,
                False,
            ),
            postprocess_stage.DecompilerPostprocessPassSpec(
                "_materialize_pointer_memory_idioms_8616",
                _noop_pointer_memory,
                True,
            ),
        ),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        _summary,
    )
    monkeypatch.setattr(postprocess_stage, "collect_x86_16_tail_validation_summary", _summary)
    monkeypatch.setattr(postprocess_stage, "compare_x86_16_tail_validation_summaries", _compare)
    monkeypatch.setattr(postprocess_stage, "x86_16_tail_validation_result_passed", lambda result: not result["changed"])
    monkeypatch.setattr(postprocess_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: True)

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert calls == ["return-prune", "annotation"]
    assert codegen.cfunc.state == "baseline"
    assert codegen._inertia_postprocess_validation_failed is True
    assert codegen._inertia_postprocess_rejected_passes == (
        "_prune_return_address_stack_arguments_8616",
        "_non_mandatory_debug_probe_8616",
    )


def test_postprocess_optimization_reuses_witness_without_hiding_mutation(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_tail_validation_enabled=True,
        _inertia_postprocess_per_pass_validation_enabled=False,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr=None, **_kwargs: None),
        ),
    )
    codegen = SimpleNamespace(cfunc=_postprocess_cfunc(addr=0x1234, state="baseline"), project=project)
    calls: list[str] = []

    def _optimization_noop_pass(_codegen):
        calls.append("optimization")
        if len(calls) == 2:
            _codegen.cfunc.state = "changed"
        return False

    def _summary(_project, codegen_arg, *, mode="live_out"):
        return SimpleNamespace(state=codegen_arg.cfunc.state, mode=mode)

    def _compare(before, after):
        return {"changed": before.state != after.state, "summary_text": "optimization pass changed state"}

    monkeypatch.setenv(
        "INERTIA_SKIP_POSTPROCESS_PASSES",
        ",".join(
            (
                "_materialize_stable_stack_semantics_bootstrap_8616",
                "_normalize_fact_backed_stack_accesses_8616",
                "_apply_typed_conditions_to_codegen_8616",
                "_materialize_global_byte_index_sum_loop_8616",
                "_materialize_cfg_selector_return_branches_early_8616",
                "_rewrite_decoded_jcc_conditions_8616",
            )
        ),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_decompiler_postprocess_passes_for_function",
        lambda _project, _codegen: (),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "OPTIMIZATION_PASSES",
        (
            SimpleNamespace(name="dce", func=_optimization_noop_pass),
            SimpleNamespace(name="const_prop", func=_optimization_noop_pass),
        ),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        _summary,
    )
    monkeypatch.setattr(postprocess_stage, "collect_x86_16_tail_validation_summary", _summary)
    monkeypatch.setattr(postprocess_stage, "compare_x86_16_tail_validation_summaries", _compare)
    monkeypatch.setattr(postprocess_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: True)

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert calls == ["optimization", "optimization"]
    assert codegen.cfunc.state == "baseline"
    assert codegen._inertia_postprocess_validation_failed is False
    assert codegen._inertia_postprocess_rejected_passes == ("optimization:const_prop",)
    witness_stats = codegen._inertia_postprocess_optimization_witness_stats_8616
    assert witness_stats.lookup_count == 2
    assert witness_stats.rebuild_count == 1
    assert witness_stats.reuse_count == 1
    assert witness_stats.record_count == 2
    assert witness_stats.invalidation_count == 1
    assert witness_stats.closed is True


def test_postprocess_codegen_validates_small_function_annotations(monkeypatch):
    function_record = SimpleNamespace(
        block_addrs_set=(0x1234,),
        info={"before": True},
        prototype="old-prototype",
    )

    class _Functions:
        def function(self, _addr=None, **_kwargs):
            return function_record

    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        kb=SimpleNamespace(functions=_Functions(), labels={0x7000: "old_label"}),
        _inertia_tail_validation_enabled=True,
        _inertia_postprocess_per_pass_validation_enabled=False,
    )
    codegen = SimpleNamespace(cfunc=_postprocess_cfunc(addr=0x1234, state="baseline"), project=project)
    calls: list[str] = []

    def _annotation_pass(_project, codegen_arg):
        calls.append("annotation")
        function_record.info["x86_16_annotations"] = {"stack_vars": {0: {"name": "local_0"}}}
        function_record.prototype = "new-prototype"
        _project.kb.labels[0x7000] = "new_label"
        codegen_arg.cfunc.state = "bad"
        return True

    def _summary(_project, codegen_arg, *, mode="live_out"):
        return SimpleNamespace(state=codegen_arg.cfunc.state, mode=mode)

    def _compare(_before, after):
        return {
            "changed": after.state == "bad",
            "summary_text": "condition changed" if after.state == "bad" else "state stable",
        }

    monkeypatch.setenv(
        "INERTIA_SKIP_POSTPROCESS_PASSES",
        ",".join(
            (
                "_materialize_stable_stack_semantics_bootstrap_8616",
                "_normalize_fact_backed_stack_accesses_8616",
                "_apply_typed_conditions_to_codegen_8616",
                "_materialize_global_byte_index_sum_loop_8616",
                "_materialize_cfg_selector_return_branches_early_8616",
            )
        ),
    )
    monkeypatch.setattr(
        postprocess_stage._globals, "_coalesce_word_global_loads_8616", lambda _project, _codegen: set()
    )
    monkeypatch.setattr(
        postprocess_stage._globals,
        "_coalesce_word_global_constant_stores_8616",
        lambda _project, _codegen: set(),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_decompiler_postprocess_passes_for_function",
        lambda _project, _codegen: (
            postprocess_stage.DecompilerPostprocessPassSpec(
                "_apply_annotations_8616",
                _annotation_pass,
                True,
            ),
        ),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        _summary,
    )
    monkeypatch.setattr(postprocess_stage, "collect_x86_16_tail_validation_summary", _summary)
    monkeypatch.setattr(postprocess_stage, "compare_x86_16_tail_validation_summaries", _compare)
    monkeypatch.setattr(postprocess_stage, "_regenerate_text_safely", lambda *_args, **_kwargs: True)

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert calls == ["annotation"]
    assert codegen.cfunc.state == "baseline"
    assert function_record.info == {"before": True}
    assert function_record.prototype == "old-prototype"
    assert project.kb.labels == {0x7000: "old_label"}
    assert codegen._inertia_postprocess_validation_failed is False
    assert "_apply_annotations_8616" in codegen._inertia_postprocess_rejected_passes


def test_postprocess_complexity_uses_current_function_cached_byte_count():
    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    codegen = SimpleNamespace(
        _inertia_current_function_8616=SimpleNamespace(
            info={
                "_inertia_function_complexity": {
                    "blocks": 37,
                    "bytes": 379,
                    "source": "bounded_local_blocks",
                }
            }
        )
    )

    complexity = postprocess_stage._postprocess_function_complexity_8616(project, codegen, 0x1000)

    assert complexity.block_count == 37
    assert complexity.byte_count == 379
    assert complexity.source == "current_function:bounded_local_blocks"
    assert complexity.is_expensive_for_local_validation is True


def test_postprocess_refuses_structuring_tail_validation_baseline_without_summary_equivalence_key():
    summary = object()
    codegen = SimpleNamespace(
        _inertia_structuring_tail_validation_artifacts_8616={
            "mode": "live_out",
            "after_fingerprint": ("fp",),
            "after_summary": summary,
        }
    )

    reused = postprocess_stage._structuring_tail_validation_baseline_summary_8616(
        codegen,
        mode="live_out",
        before_fingerprint=("fp",),
    )
    refused = postprocess_stage._structuring_tail_validation_baseline_summary_8616(
        codegen,
        mode="live_out",
        before_fingerprint=("different",),
    )

    assert reused is None
    assert refused is None
    assert codegen._inertia_tail_validation_structuring_baseline_reuse_refused_8616 == 2


def test_postprocess_codegen_refuses_byte_heavy_function_semantic_pass_without_local_validation(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_tail_validation_enabled=True,
        _inertia_postprocess_per_pass_validation_enabled=False,
    )
    codegen = SimpleNamespace(
        cfunc=_postprocess_cfunc(addr=0x1234),
        project=project,
        text="int f(void) { return 0; }",
        _inertia_current_function_8616=SimpleNamespace(
            info={
                "_inertia_function_complexity": {
                    "blocks": 37,
                    "bytes": 700,
                    "source": "bounded_local_blocks",
                }
            }
        ),
    )
    calls: list[str] = []
    monkeypatch.setenv("INERTIA_DISABLE_POSTPROCESS_OPT", "1")
    monkeypatch.setenv(
        "INERTIA_SKIP_POSTPROCESS_PASSES",
        ",".join(
            (
                "_materialize_stable_stack_semantics_bootstrap_8616",
                "_normalize_fact_backed_stack_accesses_8616",
                "_apply_typed_conditions_to_codegen_8616",
                "_materialize_global_byte_index_sum_loop_8616",
                "_materialize_cfg_selector_return_branches_early_8616",
            )
        ),
    )

    def _semantic_pass(_codegen):
        calls.append("semantic")
        return True

    monkeypatch.setattr(
        postprocess_stage,
        "_decompiler_postprocess_passes_for_function",
        lambda _project, _codegen: (
            postprocess_stage.DecompilerPostprocessPassSpec(
                "_rewrite_decoded_jcc_conditions_8616",
                _semantic_pass,
                False,
            ),
        ),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        lambda *_args, **_kwargs: SimpleNamespace(state="stable"),
    )

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert calls == []
    assert codegen._inertia_postprocess_function_complexity_8616 == {
        "blocks": 37,
        "bytes": 700,
        "source": "current_function:bounded_local_blocks",
        "expensive": True,
        "baseline_validation_cost_ms": 0,
        "expensive_validation_baseline": False,
    }


def test_postprocess_codegen_refuses_semantic_pass_after_expensive_validation_baseline(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_tail_validation_enabled=True,
        _inertia_postprocess_per_pass_validation_enabled=False,
    )
    codegen = SimpleNamespace(
        cfunc=_postprocess_cfunc(addr=0x1234),
        project=project,
        text="int f(void) { return 0; }",
        _inertia_postprocess_pre_validation_cost_ms_8616=2500,
        _inertia_current_function_8616=SimpleNamespace(
            info={
                "_inertia_function_complexity": {
                    "blocks": 10,
                    "bytes": 90,
                    "source": "bounded_local_blocks",
                }
            }
        ),
    )
    calls: list[str] = []
    monkeypatch.setenv("INERTIA_DISABLE_POSTPROCESS_OPT", "1")

    def _semantic_pass(_codegen):
        calls.append("semantic")
        return True

    monkeypatch.setattr(
        postprocess_stage,
        "_decompiler_postprocess_passes_for_function",
        lambda _project, _codegen: (
            postprocess_stage.DecompilerPostprocessPassSpec(
                "_rewrite_decoded_jcc_conditions_8616",
                _semantic_pass,
                False,
            ),
        ),
    )
    monkeypatch.setattr(
        postprocess_stage,
        "_collect_tail_validation_summary_with_baseline_canonicalization_8616",
        lambda *_args, **_kwargs: SimpleNamespace(state="stable"),
    )

    changed = postprocess_stage._postprocess_codegen_8616(project, codegen)

    assert changed is False
    assert calls == []
    assert codegen._inertia_postprocess_function_complexity_8616 == {
        "blocks": 10,
        "bytes": 90,
        "source": "current_function:bounded_local_blocks",
        "expensive": True,
        "baseline_validation_cost_ms": 2500,
        "expensive_validation_baseline": True,
    }


def test_tail_validation_compare_summaries_treats_negated_compare_and_inverted_compare_as_stable():
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=("Not(CmpLE(reg:ax,stack:+0x6))",),
        control_flow_effects=("if:Not(CmpLE(reg:ax,stack:+0x6))",),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=("CmpGT(reg:ax,stack:+0x6)",),
        control_flow_effects=("if:CmpGT(reg:ax,stack:+0x6)",),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["status"] == "stable"


def test_tail_validation_compare_suppresses_loop_body_local_stack_write_precision():
    condition = "CmpGE(stack_slot:SS:BP-0x6:size2,stack_slot:SS:BP+0x4:size2)"
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(f"dowhile-body-writes:{condition}:stack_slot:SS:BP-0x4:size2",),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(
            f"dowhile-body-writes:{condition}:stack_slot:SS:BP-0x4:size2,stack_slot:SS:BP-0x6:size2",
        ),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["status"] == "stable"
    assert diff["precision_improvements"]["loop_body_local_stack_write_precision"] == {
        "control_flow_effects": {
            "added": (
                f"dowhile-body-writes:{condition}:stack_slot:SS:BP-0x4:size2,stack_slot:SS:BP-0x6:size2",
            ),
            "removed": (f"dowhile-body-writes:{condition}:stack_slot:SS:BP-0x4:size2",),
        }
    }


def test_tail_validation_compare_suppresses_added_loop_body_local_stack_write_precision():
    condition = "CmpLE(stack_slot:SS:BP+0x4:size2,const:0)"
    after_effect = f"for-body-writes:{condition}:stack_slot:SS:BP-0x2:size2"
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(after_effect,),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["status"] == "stable"
    assert diff["precision_improvements"]["loop_body_local_stack_write_precision"] == {
        "control_flow_effects": {"added": (after_effect,), "removed": ()}
    }


def test_tail_validation_compare_suppresses_straight_line_local_stack_write_precision():
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=("stack_slot:SS:BP-0x2:size2",),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["precision_improvements"]["straight_line_local_stack_write_precision"] == {
        "stack_writes": {"added": ("stack_slot:SS:BP-0x2:size2",), "removed": ()}
    }


def test_tail_validation_straight_line_local_stack_write_keeps_call_delta_observable():
    before = X86_16TailValidationSummary(
        helper_calls=("name:before",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )
    after = X86_16TailValidationSummary(
        helper_calls=("name:after",),
        register_writes=(),
        stack_writes=("stack_slot:SS:BP-0x2:size2",),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is True
    assert "straight_line_local_stack_write_precision" not in diff["precision_improvements"]


def test_tail_validation_compare_keeps_loop_body_global_write_delta_observable():
    condition = "CmpLE(stack_slot:SS:BP+0x4:size2,const:0)"
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(f"for-body-writes:{condition}:global:0x100",),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is True
    assert diff["delta"]["control_flow_effects"]["added"] == (
        f"for-body-writes:{condition}:ds_global:0x100",
    )


def test_indexed_segmented_global_precision_accepts_exact_evidenced_byte_expansion():
    before = "while-body-writes:const:True:ds_global:0x132,ds_global:0x134"
    after = "while-body-writes:const:True:ds_global:0x132,ds_global:0x133,ds_global:0x134"
    validation = {
        "delta": {
            "global_writes": {"added": ("ds_global:0x133",), "removed": ()},
            "control_flow_effects": {"added": (after,), "removed": (before,)},
        }
    }

    assert indexed_segmented_global_precision_delta_8616(
        1,
        (IndexedSegmentedGlobalEvidence8616(0x132, "clPause", 0, 2),),
        validation,
    )


def test_indexed_segmented_global_precision_refuses_unrelated_effect_or_byte():
    before = "while-body-writes:const:True:global:0x132"
    after = "while-body-writes:const:True:global:0x132,global:0x134"
    validation = {
        "delta": {
            "global_writes": {"added": ("global:0x134",), "removed": ()},
            "helper_calls": {"added": ("addr:0x1234",), "removed": ()},
            "control_flow_effects": {"added": (after,), "removed": (before,)},
        }
    }

    assert not indexed_segmented_global_precision_delta_8616(
        1,
        (IndexedSegmentedGlobalEvidence8616(0x132, "clPause", 0, 2),),
        validation,
    )


def test_dword_global_zero_test_precision_accepts_exact_condition_and_calls():
    before_condition = "CmpNE(Or(ds_global:0x134,ds_global:0x132),const:0)"
    after_condition = "CmpNE(ds_global:0x132,const:0)"
    validation = {
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
        }
    }
    evidence = (DwordGlobalZeroTestEvidence8616(0x132, 0x132, 0x134, "ax"),)

    assert dword_global_zero_test_precision_delta_8616(1, evidence, validation)
    control_only_validation = {
        "delta": {"control_flow_effects": validation["delta"]["control_flow_effects"]}
    }
    assert dword_global_zero_test_precision_delta_8616(1, evidence, control_only_validation)

    changed_calls = {
        "delta": {
            **validation["delta"],
            "control_flow_effects": {
                "added": (
                    f"if:{after_condition}",
                    f"if-body-calls:{after_condition}:addr:0x128e4",
                ),
                "removed": validation["delta"]["control_flow_effects"]["removed"],
            },
        }
    }
    assert not dword_global_zero_test_precision_delta_8616(1, evidence, changed_calls)

    unrelated_effect = {
        "delta": {
            **validation["delta"],
            "global_writes": {"added": ("global:0x132",), "removed": ()},
        }
    }
    assert not dword_global_zero_test_precision_delta_8616(1, evidence, unrelated_effect)


def test_tail_validation_expands_dirty_global_write_from_exact_virtual_width(monkeypatch):
    codegen = _DummyCodegen()
    dirty = VirtualVariable(0, 1, 16, VirtualVariableCategory.MEMORY, oident=0x132)
    lhs = CDirtyExpression(dirty, codegen=codegen)
    monkeypatch.setattr(
        tail_validation_module,
        "_location_fingerprint",
        lambda *_args, **_kwargs: "global:0x132",
    )

    locations = tail_validation_module._assignment_write_locations_8616(lhs, _project())

    assert locations == ("global:0x132", "global:0x133")


def test_tail_validation_does_not_resolve_dirty_tmp_lhs_as_global_write(monkeypatch):
    codegen = _DummyCodegen()
    dirty = VirtualVariable(0, 1, 16, VirtualVariableCategory.TMP, oident=74)
    lhs = CDirtyExpression(dirty, codegen=codegen)
    monkeypatch.setattr(
        tail_validation_module,
        "_location_fingerprint",
        lambda *_args, **_kwargs: "global:0x132",
    )

    locations = tail_validation_module._assignment_write_locations_8616(lhs, _project())

    assert locations == ()
    assert not tail_validation_module._assignment_lhs_writes_memory_8616(lhs, _project())


def test_tail_validation_keeps_dirty_register_lhs_location_when_value_aliases_global() -> None:
    codegen = _DummyCodegen()
    project = codegen.project
    ax_offset, ax_size = project.arch.registers["ax"]
    dirty_register = SimpleNamespace(
        varid=72,
        name="vvar_72",
        reg=ax_offset,
        bits=ax_size * 8,
        size=ax_size,
        category=VirtualVariableCategory.REGISTER,
    )
    lhs = CDirtyExpression(dirty_register, codegen=codegen)
    rhs = CVariable(
        SimMemoryVariable(0x160, 2, name="mem_0160"),
        codegen=codegen,
    )
    assignment = CAssignment(lhs, rhs, codegen=codegen)
    root = CStatements([assignment], codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x10060,
        statements=root,
        body=root,
        variables_in_use={},
    )

    assert (
        tail_validation_fingerprint_module._expr_fingerprint(lhs, project)
        == "global:0x160"
    )
    assert tail_validation_module._assignment_write_locations_8616(
        lhs,
        project,
    ) == ("reg:ax",)
    assert not tail_validation_module._assignment_lhs_writes_memory_8616(
        lhs,
        project,
    )


def test_tail_validation_refuses_inconsistent_dirty_global_write_width(monkeypatch):
    codegen = _DummyCodegen()
    dirty = SimpleNamespace(
        size=2,
        bits=8,
        category=VirtualVariableCategory.MEMORY,
    )
    lhs = CDirtyExpression(dirty, codegen=codegen)
    monkeypatch.setattr(
        tail_validation_module,
        "_location_fingerprint",
        lambda *_args, **_kwargs: "global:0x132",
    )

    locations = tail_validation_module._assignment_write_locations_8616(lhs, _project())

    assert locations == ("global:0x132",)


def test_tail_validation_keeps_indexed_near_pointer_argument_write_symbolic():
    codegen = _DummyCodegen()
    pointer_type = SimTypePointer(SimTypeShort(False)).with_arch(codegen.project.arch)
    pointer_arg = CVariable(
        SimMemoryVariable(4, 2, name="bar1"),
        variable_type=pointer_type,
        codegen=codegen,
    )
    lhs = CIndexedVariable(
        pointer_arg,
        _const(0, codegen),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    locations = tail_validation_module._assignment_write_locations_8616(lhs, _project())

    assert len(locations) == 1
    assert locations[0].startswith("deref:Add(Mul(reg:ds,const:16),")
    assert not locations[0].startswith("global:")


def test_tail_validation_tracks_dynamic_indexed_near_pointer_argument_write():
    codegen = _DummyCodegen()
    pointer_type = SimTypePointer(SimTypeShort(False)).with_arch(codegen.project.arch)
    pointer_arg = CVariable(
        SimStackVariable(4, 2, base="bp", name="dst"),
        variable_type=pointer_type,
        codegen=codegen,
    )
    index = CVariable(
        SimStackVariable(-2, 2, base="bp", name="index"),
        variable_type=SimTypeShort(False).with_arch(codegen.project.arch),
        codegen=codegen,
    )
    lhs = CIndexedVariable(
        pointer_arg,
        index,
        variable_type=SimTypeShort(False).with_arch(codegen.project.arch),
        codegen=codegen,
    )

    locations = tail_validation_module._assignment_write_locations_8616(lhs, _project())

    assert locations == (
        "deref:Add(Mul(reg:ds,const:16),stack_slot:SS:BP+0x4:size2,"
        "Shl(stack_slot:SS:BP-0x2:size2,const:1))",
    )


def test_tail_validation_normalizes_void_return_loop_exit_guard_to_loop_condition():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()
    before_cond = CBinaryOp(
        "CmpLE",
        _reg(project, "ax", before_codegen),
        _stack(-4, before_codegen, name="goal"),
        codegen=before_codegen,
    )
    after_cond = CBinaryOp(
        "CmpGT",
        _reg(project, "ax", after_codegen),
        _stack(-4, after_codegen, name="goal"),
        codegen=after_codegen,
    )
    before = _codegen(
        [CWhileLoop(before_cond, CStatements([], codegen=before_codegen), codegen=before_codegen)],
        before_codegen,
    )
    after = _codegen(
        [
            CWhileLoop(
                _const(1, after_codegen),
                CStatements(
                    [
                        CIfElse(
                            [
                                (
                                    after_cond,
                                    CStatements([CReturn(None, codegen=after_codegen)], codegen=after_codegen),
                                )
                            ],
                            else_node=None,
                            codegen=after_codegen,
                        )
                    ],
                    codegen=after_codegen,
                ),
                codegen=after_codegen,
            )
        ],
        after_codegen,
    )

    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before, mode="live_out"),
        collect_x86_16_tail_validation_summary(project, after, mode="live_out"),
    )

    assert diff["changed"] is False
    assert diff["status"] == "stable"


def test_tail_validation_normalizes_void_return_loop_exit_guard_after_call_feeder(monkeypatch):
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()
    before_call = CFunctionCall("clock", None, [], codegen=before_codegen)
    after_call = CFunctionCall("clock", None, [], codegen=after_codegen)
    before_cond = CBinaryOp(
        "CmpLE",
        before_call,
        _stack(-4, before_codegen, name="goal"),
        codegen=before_codegen,
    )
    after_carrier = _reg(
        project,
        "ax",
        after_codegen,
        var_name="t",
        ident="clock_result",
        region=0x1000,
    )
    feeder = CAssignment(after_carrier, after_call, codegen=after_codegen)
    after_cond = CBinaryOp(
        "CmpGT",
        after_carrier,
        _stack(-4, after_codegen, name="goal"),
        codegen=after_codegen,
    )
    before = _codegen(
        [CWhileLoop(before_cond, CStatements([], codegen=before_codegen), codegen=before_codegen)],
        before_codegen,
    )
    after = _codegen(
        [
            CWhileLoop(
                _const(1, after_codegen),
                CStatements(
                    [
                        feeder,
                        CIfElse(
                            [
                                (
                                    after_cond,
                                    CStatements([CReturn(None, codegen=after_codegen)], codegen=after_codegen),
                                )
                            ],
                            else_node=None,
                            codegen=after_codegen,
                        ),
                    ],
                    codegen=after_codegen,
                ),
                codegen=after_codegen,
            )
        ],
        after_codegen,
    )

    monkeypatch.setattr(
        tail_validation_module,
        "build_x86_16_contextual_condition_fingerprints",
        lambda _root, _project: {id(after_cond): "CmpGT(call:clock(),stack_slot:SS:BP-0x4:size2)"},
    )

    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before, mode="live_out"),
        collect_x86_16_tail_validation_summary(project, after, mode="live_out"),
    )

    assert diff["changed"] is False
    assert diff["status"] == "stable"


def test_tail_validation_compare_suppresses_void_return_loop_exit_guard_structuring_bundle():
    before_condition = "CmpLE(call:addr:0x1446(),stack_slot:SS:BP-0x4:size4)"
    after_condition = "CmpGT(call:addr:0x1446(),stack_slot:SS:BP-0x4:size4)"
    before = X86_16TailValidationSummary(
        helper_calls=("addr:0x1137e", "addr:0x1137e"),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=("none",),
        conditions=("const:True", before_condition),
        control_flow_effects=(
            f"if:{before_condition}",
            "return",
            "while:const:True",
            "while-body-calls:const:True:addr:0x1137e",
        ),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(after_condition,),
        control_flow_effects=(
            f"while:{after_condition}",
            f"while-body-calls:{after_condition}:addr:0x1137e",
        ),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["status"] == "stable"
    assert "void_return_loop_exit_guard_structuring" in diff["precision_improvements"]


def test_tail_validation_compare_suppresses_loop_condition_call_result_carrier_delta():
    before = X86_16TailValidationSummary(
        helper_calls=("addr:0x1137e", "addr:0x1137e"),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=("CmpLE(call:addr:0x1446(),stack_slot:SS:BP-0x4:size4)", "const:True"),
        control_flow_effects=(
            "if:CmpLE(call:addr:0x1446(),stack_slot:SS:BP-0x4:size4)",
            "return",
            "while:const:True",
            "while-body-calls:const:True:addr:0x1137e",
            "while-body-writes:const:True:reg:ax",
        ),
    )
    after = X86_16TailValidationSummary(
        helper_calls=("addr:0x1137e",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=("CmpLE(call:addr:0x1446(),stack_slot:SS:BP-0x4:size4)", "const:True"),
        control_flow_effects=(
            "if:CmpLE(call:addr:0x1446(),stack_slot:SS:BP-0x4:size4)",
            "return",
            "while:const:True",
            "while-body-calls:const:True:addr:0x1137e",
        ),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["status"] == "stable"
    assert "loop_condition_call_result_carrier_structuring" in diff["precision_improvements"]


def test_tail_validation_compare_accepts_inverse_break_condition_call_carrier_restructure():
    call_condition = "call:addr:0x1446(),stack_slot:SS:BP-0x4:size4"
    break_condition = f"CmpGT({call_condition})"
    loop_condition = f"CmpLE({call_condition})"
    before = X86_16TailValidationSummary(
        helper_calls=("addr:0x1137e", "addr:0x1137e"),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(break_condition, "const:True"),
        control_flow_effects=(
            f"ifbreak:{break_condition}",
            "while:const:True",
            "while-body-calls:const:True:addr:0x1137e",
        ),
    )
    after = X86_16TailValidationSummary(
        helper_calls=("addr:0x1137e",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(loop_condition,),
        control_flow_effects=(
            f"while:{loop_condition}",
            f"while-body-calls:{loop_condition}:addr:0x1137e",
        ),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["status"] == "stable"
    assert "loop_condition_call_result_carrier_structuring" in diff["precision_improvements"]


def test_tail_validation_compare_refuses_noninverse_break_condition_call_carrier_restructure():
    call_condition = "call:addr:0x1446(),stack_slot:SS:BP-0x4:size4"
    before = X86_16TailValidationSummary(
        helper_calls=("addr:0x1137e", "addr:0x1137e"),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(f"CmpGT({call_condition})", "const:True"),
        control_flow_effects=(
            f"ifbreak:CmpGT({call_condition})",
            "while:const:True",
            "while-body-calls:const:True:addr:0x1137e",
        ),
    )
    after = X86_16TailValidationSummary(
        helper_calls=("addr:0x1137e",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(f"CmpLT({call_condition})",),
        control_flow_effects=(
            f"while:CmpLT({call_condition})",
            f"while-body-calls:CmpLT({call_condition}):addr:0x1137e",
        ),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is True
    assert diff["status"] == "changed"


def test_tail_validation_compare_suppresses_if_body_call_membership_structuring_bundle():
    condition = "CmpNE(global:0xb46,const:0)"
    before = X86_16TailValidationSummary(
        helper_calls=("addr:0x10e70", "addr:0x10f38", "addr:0x10f38"),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(condition,),
        control_flow_effects=(
            f"if:{condition}",
            f"if-body-calls:{condition}:addr:0x10e70",
            "return",
        ),
    )
    after = X86_16TailValidationSummary(
        helper_calls=("addr:0x10e70", "addr:0x10f38", "addr:0x10f38"),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(condition,),
        control_flow_effects=(
            f"if:{condition}",
            f"if-body-calls:{condition}:addr:0x10e70,addr:0x10f38",
            "return",
        ),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["status"] == "stable"
    assert "if_body_call_membership_structuring" in diff["precision_improvements"]


def test_tail_validation_suppresses_added_only_if_body_call_membership_structuring_bundle():
    condition = "CmpLT(stack_slot:SS:BP-0x2:size2,global:0x160)"
    before = X86_16TailValidationSummary(
        helper_calls=("addr:0x128e4", "addr:0x12756"),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(condition,),
        control_flow_effects=(f"if:{condition}",),
    )
    after = X86_16TailValidationSummary(
        helper_calls=("addr:0x128e4", "addr:0x12756"),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(condition,),
        control_flow_effects=(f"if:{condition}", f"if-body-calls:{condition}:addr:0x128e4,addr:0x12756"),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["status"] == "stable"
    assert "if_body_call_membership_structuring" in diff["precision_improvements"]


def test_tail_validation_suppresses_removed_only_if_else_body_membership_structuring_bundle():
    before = X86_16TailValidationSummary(
        helper_calls=("addr:0x10e70", "addr:0x10f38"),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=("if:else", "if-else-body-calls:else:addr:0x10f38"),
    )
    after = X86_16TailValidationSummary(
        helper_calls=("addr:0x10e70", "addr:0x10f38"),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["status"] == "stable"
    assert "if_else_body_membership_structuring" in diff["precision_improvements"]


def test_tail_validation_suppresses_empty_then_inverse_guard_structuring_bundle():
    equal = "CmpEQ(stack_slot:SS:BP+0x4:size2,const:0)"
    not_equal = "CmpNE(stack_slot:SS:BP+0x4:size2,const:0)"
    before = X86_16TailValidationSummary(
        helper_calls=("addr:0x1131e",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(equal, not_equal),
        control_flow_effects=(
            f"if:{equal}",
            f"if:{not_equal}",
            "if:else",
            "if-else-body-calls:else:addr:0x1131e",
        ),
    )
    after = X86_16TailValidationSummary(
        helper_calls=("addr:0x1131e",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(not_equal,),
        control_flow_effects=(
            f"if:{not_equal}",
            f"if-body-calls:{not_equal}:addr:0x1131e",
        ),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["status"] == "stable"
    assert "if_else_inverse_guard_structuring" in diff["precision_improvements"]


def test_tail_validation_inverse_guard_structuring_refuses_changed_else_call():
    equal = "CmpEQ(stack_slot:SS:BP+0x4:size2,const:0)"
    not_equal = "CmpNE(stack_slot:SS:BP+0x4:size2,const:0)"
    before = X86_16TailValidationSummary(
        helper_calls=("addr:0x1131e",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(equal, not_equal),
        control_flow_effects=(
            f"if:{equal}",
            f"if:{not_equal}",
            "if:else",
            "if-else-body-calls:else:addr:0x1131e",
        ),
    )
    after = X86_16TailValidationSummary(
        helper_calls=("addr:0x1131e",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(not_equal,),
        control_flow_effects=(
            f"if:{not_equal}",
            f"if-body-calls:{not_equal}:addr:0x1143a",
        ),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is True
    assert "if_else_inverse_guard_structuring" not in diff["precision_improvements"]


def test_tail_validation_inverse_guard_structuring_refuses_noninverse_guard():
    equal = "CmpEQ(stack_slot:SS:BP+0x4:size2,const:0)"
    different = "CmpEQ(stack_slot:SS:BP+0x4:size2,const:1)"
    before = X86_16TailValidationSummary(
        helper_calls=("addr:0x1131e",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(equal,),
        control_flow_effects=(
            f"if:{equal}",
            "if:else",
            "if-else-body-calls:else:addr:0x1131e",
        ),
    )
    after = X86_16TailValidationSummary(
        helper_calls=("addr:0x1131e",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(different,),
        control_flow_effects=(
            f"if:{different}",
            f"if-body-calls:{different}:addr:0x1131e",
        ),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is True
    assert "if_else_inverse_guard_structuring" not in diff["precision_improvements"]


def test_tail_validation_if_else_body_membership_keeps_real_helper_delta():
    before = X86_16TailValidationSummary(
        helper_calls=("addr:0x10e70", "addr:0x10f38"),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=("if:else", "if-else-body-calls:else:addr:0x10f38"),
    )
    after = X86_16TailValidationSummary(
        helper_calls=("addr:0x10e70",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is True
    assert diff["delta"]["helper_calls"] == {"added": (), "removed": ("addr:0x10f38",)}


def test_tail_validation_if_body_call_membership_keeps_real_helper_delta():
    condition = "CmpNE(global:0xb46,const:0)"
    before = X86_16TailValidationSummary(
        helper_calls=("addr:0x10e70",),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(condition,),
        control_flow_effects=(f"if-body-calls:{condition}:addr:0x10e70",),
    )
    after = X86_16TailValidationSummary(
        helper_calls=("addr:0x10e70", "addr:0x10f38"),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(condition,),
        control_flow_effects=(f"if-body-calls:{condition}:addr:0x10e70,addr:0x10f38",),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is True
    assert diff["delta"]["helper_calls"] == {"added": ("addr:0x10f38",), "removed": ()}


def test_tail_validation_suppresses_helper_calls_accounted_by_body_calls():
    condition = "CmpNE(global:0xb46,const:0)"
    before = X86_16TailValidationSummary(
        helper_calls=("addr:0x10e70", "addr:0x10f38", "addr:0x10f38"),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(condition,),
        control_flow_effects=(
            f"if-body-calls:{condition}:addr:0x10e70,addr:0x10f38",
            "if-else-body-calls:else:addr:0x10f38",
            "return",
        ),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(condition,),
        control_flow_effects=(
            f"if-body-calls:{condition}:addr:0x10e70,addr:0x10f38",
            "if-else-body-calls:else:addr:0x10f38",
            "return",
        ),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["status"] == "stable"
    assert "helper_calls_accounted_by_control_body_calls" in diff["precision_improvements"]


def test_tail_validation_helper_body_accounting_keeps_real_call_loss():
    condition = "CmpNE(global:0xb46,const:0)"
    before = X86_16TailValidationSummary(
        helper_calls=("addr:0x10e70", "addr:0x10f38"),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(condition,),
        control_flow_effects=(f"if-body-calls:{condition}:addr:0x10e70,addr:0x10f38",),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(condition,),
        control_flow_effects=(f"if-body-calls:{condition}:addr:0x10e70",),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is True
    assert diff["delta"]["helper_calls"] == {
        "added": (),
        "removed": ("addr:0x10e70", "addr:0x10f38"),
    }


def test_tail_validation_normalizes_multi_branch_void_return_loop_exit_guard(monkeypatch):
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()
    before_cond = CBinaryOp(
        "CmpLE",
        CFunctionCall("clock", None, [], codegen=before_codegen),
        _stack(-4, before_codegen, name="goal"),
        codegen=before_codegen,
    )
    after_goal_hi = _stack(4, after_codegen, name="goal_hi")
    first_exit_carrier = _reg(
        project,
        "dx",
        after_codegen,
        ident="entry_dx",
        region=0x1000,
    )
    first_exit_cond = CBinaryOp(
        "CmpGT",
        first_exit_carrier,
        after_goal_hi,
        codegen=after_codegen,
    )
    after_carrier = _reg(
        project,
        "ax",
        after_codegen,
        var_name="t",
        ident="clock_result",
        region=0x1000,
    )
    second_exit_cond = CBinaryOp(
        "CmpGT",
        after_carrier,
        _stack(-4, after_codegen, name="goal_lo"),
        codegen=after_codegen,
    )
    before = _codegen(
        [CWhileLoop(before_cond, CStatements([], codegen=before_codegen), codegen=before_codegen)],
        before_codegen,
    )
    after = _codegen(
        [
            CWhileLoop(
                _const(1, after_codegen),
                CStatements(
                    [
                        CAssignment(
                            after_carrier,
                            CFunctionCall("clock", None, [], codegen=after_codegen),
                            codegen=after_codegen,
                        ),
                        CIfElse(
                            [
                                (
                                    first_exit_cond,
                                    CStatements([CReturn(None, codegen=after_codegen)], codegen=after_codegen),
                                ),
                                (
                                    second_exit_cond,
                                    CStatements([CReturn(None, codegen=after_codegen)], codegen=after_codegen),
                                ),
                            ],
                            else_node=None,
                            codegen=after_codegen,
                        ),
                    ],
                    codegen=after_codegen,
                ),
                codegen=after_codegen,
            )
        ],
        after_codegen,
    )
    after.cfunc.arg_list = [first_exit_carrier, after_goal_hi]
    after_goal_hi.variable_type = SimTypeShort(False).with_arch(project.arch)

    monkeypatch.setattr(
        tail_validation_module,
        "build_x86_16_contextual_condition_fingerprints",
        lambda _root, _project: {id(first_exit_cond): "CmpGT(call:clock(),stack_slot:SS:BP-0x4:size2)"},
    )

    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before, mode="live_out"),
        collect_x86_16_tail_validation_summary(project, after, mode="live_out"),
    )

    assert diff["changed"] is False
    assert diff["status"] == "stable"


def test_tail_validation_suppresses_mixed_loop_body_local_stack_write_precision():
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=("global:0xbaa", "global:0xbab"),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(
            "for-body-writes:CmpNE(stack_slot:SS:BP-0x2:size2,const:0):"
            "global:0xbaa,global:0xbab,stack_slot:SS:BP-0x2:size2",
        ),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=("stack_slot:SS:BP-0x4:size2", "stack_slot:SS:BP-0x6:size2"),
        global_writes=("global:0xbaa", "global:0xbab"),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(
            "for-body-writes:CmpNE(stack_slot:SS:BP-0x2:size2,const:0):"
            "global:0xbaa,global:0xbab,stack_slot:SS:BP-0x2:size2,"
            "stack_slot:SS:BP-0x4:size2,stack_slot:SS:BP-0x6:size2",
        ),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["status"] == "stable"
    precision = diff["precision_improvements"]["loop_body_local_stack_write_precision"]
    assert precision["stack_writes"]["added"] == (
        "stack_slot:SS:BP-0x4:size2",
        "stack_slot:SS:BP-0x6:size2",
    )


def test_tail_validation_compare_suppresses_local_stack_abi_int_width_noise():
    before_condition = "CmpLE(stack_slot:SS:BP-0x2:size4,stack_slot:SS:BP+0xa:size2)"
    after_condition = "CmpLE(stack_slot:SS:BP-0x2:size2,stack_slot:SS:BP+0xa:size2)"
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=("stack_slot:SS:BP-0x2:size4",),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(before_condition,),
        control_flow_effects=(
            f"for:{before_condition}",
            f"for-body-calls:{before_condition}:addr:0x128e4,addr:0x12756",
            f"for-body-writes:{before_condition}:stack_slot:SS:BP-0x2:size4",
        ),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=("stack_slot:SS:BP-0x2:size2",),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(after_condition,),
        control_flow_effects=(
            f"for:{after_condition}",
            f"for-body-calls:{after_condition}:addr:0x128e4,addr:0x12756",
            f"for-body-writes:{after_condition}:stack_slot:SS:BP-0x2:size2",
        ),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["status"] == "stable"
    precision = diff["precision_improvements"]["local_stack_abi_int_width"]
    assert precision["stack_writes"] == {
        "added": ("stack_slot:SS:BP-0x2:size2",),
        "removed": ("stack_slot:SS:BP-0x2:size4",),
    }


def test_tail_validation_local_stack_abi_int_width_noise_keeps_real_call_delta():
    before_condition = "CmpLE(stack_slot:SS:BP-0x2:size4,stack_slot:SS:BP+0xa:size2)"
    after_condition = "CmpLE(stack_slot:SS:BP-0x2:size2,stack_slot:SS:BP+0xa:size2)"
    before = X86_16TailValidationSummary(
        helper_calls=("addr:0x128e4",),
        register_writes=(),
        stack_writes=("stack_slot:SS:BP-0x2:size4",),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(before_condition,),
        control_flow_effects=(f"for:{before_condition}",),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=("stack_slot:SS:BP-0x2:size2",),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(after_condition,),
        control_flow_effects=(f"for:{after_condition}",),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is True
    assert diff["delta"]["helper_calls"] == {"added": (), "removed": ("addr:0x128e4",)}


def test_tail_validation_compare_suppresses_initbars_structuring_precision_bundle():
    before_condition = "CmpGT(ds_global:0xba2,stack_slot:SS:BP-0x2:size4)"
    before_embedded_condition = "CmpGT(Dereference(Add(Mul(reg:ds,const:16),const:2978)),stack_slot:SS:BP-0x2:size4)"
    after_condition = "CmpGT(ds_global:0xba2,stack_slot:SS:BP-0x2:size2)"
    after_embedded_condition = "CmpGT(Dereference(Add(Mul(reg:ds,const:16),const:2978)),stack_slot:SS:BP-0x2:size2)"
    before_writes = (
        "deref:Add(Reference(global:0x8f0),Shl(stack_slot:SS:BP+0x0:size2,const:1)),"
        "deref:Add(Reference(global:0x8f1),Shl(stack_slot:SS:BP+0x0:size2,const:1)),"
        "reg:ax"
    )
    after_writes = (
        "deref:Add(Reference(global:0x8f0),Shl(stack_slot:SS:BP+0x0:size2,const:1)),"
        "deref:Add(Reference(global:0x8f1),Shl(stack_slot:SS:BP+0x0:size2,const:1))"
    )
    before = X86_16TailValidationSummary(
        helper_calls=("addr:0x10678",),
        register_writes=("reg:ax",),
        stack_writes=("stack_slot:SS:BP-0x2:size4",),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(before_condition,),
        control_flow_effects=(
            f"for-body-calls:{before_embedded_condition}:addr:0x11414",
            f"for-body-writes:{before_embedded_condition}:{before_writes}",
            f"for-body-writes:{before_embedded_condition}:reg:ax",
            f"for:{before_condition}",
        ),
    )
    after = X86_16TailValidationSummary(
        helper_calls=("addr:0x11414", "name:<indirect>"),
        register_writes=(),
        stack_writes=("stack_slot:SS:BP-0x2:size2", "stack_slot:SS:BP-0x74:size2"),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(after_condition,),
        control_flow_effects=(
            f"for-body-calls:{after_embedded_condition}:addr:0x11414",
            f"for-body-writes:{after_condition}:{after_writes}",
            f"for:{after_condition}",
        ),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["status"] == "stable"
    assert "structuring_callsite_target_local_int_precision" in diff["precision_improvements"]


def test_tail_validation_compare_canonicalizes_ds_global_and_duplicate_or_operands():
    before_condition = (
        "CmpNE(Or(ds_global:0x134,ds_global:0x132,"
        "Shl(ds_global:0x133,const:8)),const:0)"
    )
    after_condition = (
        "CmpNE(Or(ds_global:0x134,global:0x132,"
        "Shl(ds_global:0x133,const:8),global:0x132),const:0)"
    )
    before = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(before_condition,),
        control_flow_effects=(f"if:{before_condition}",),
    )
    after = X86_16TailValidationSummary(
        helper_calls=(),
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(after_condition,),
        control_flow_effects=(f"if:{after_condition}",),
    )

    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is False
    assert diff["status"] == "stable"
