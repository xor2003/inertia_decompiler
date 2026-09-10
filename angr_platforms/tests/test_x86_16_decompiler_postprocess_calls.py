from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler import structured_codegen as _scg
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CExpressionStatement,
    CForLoop,
    CFunctionCall,
    CIndexedVariable,
    CReturn,
    CStatements,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeBottom, SimTypeChar, SimTypeFunction, SimTypeLong, SimTypePointer, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_stack_metadata import _prune_dead_stack_carrier_assignments_8616
from angr_platforms.X86_16.callsite_summary import (
    CallerReturnUseEvidence8616,
    CallerReturnUseVerdict8616,
    CallsitePushExprOp8616,
    CallsiteReturnUseKind8616,
    CallsiteSummary8616,
    bind_structured_callsite_identity_8616,
    record_caller_return_use_evidence_8616,
)
from angr_platforms.X86_16.decompiler_postprocess_calls import (
    CallsiteMaterializationStats,
    _accumulate_callsite_materialization_stats_8616,
    _align_cod_call_names_8616,
    _annotated_function_pointer_stack_offsets_8616,
    _attach_callsite_summaries_8616,
    _bind_call_argument_setup_liveness_classifier_8616,
    _bind_callee_pointer_argument_classifier_8616,
    _bind_function_result_observation_provider_8616,
    _bind_segment_push_source_lowerer_8616,
    _cod_metadata_for_function_8616,
    _conservative_call_arg_seed_8616,
    _ensure_callsite_materialization_controls_8616,
    _known_default_args_for_missing_8616,
    _materialize_callsite_prototypes_8616,
    _materialize_callsite_stack_arguments_8616,
    _missing_calls_from_sequences_8616,
    _normalize_call_target_names_8616,
    _ordered_missing_from_source_8616,
    _prune_scalar_global_high_byte_call_arg_remnants_8616,
    _recover_expected_calls_8616,
    _recover_missing_direct_calls_from_evidence_8616,
    _refresh_callsite_summary_node_ids_8616,
    _structured_root_8616,
    _summary_looks_loop_carried_arg_8616,
    prune_consumed_segmented_stack_byte_arg_stores_8616,
)
from angr_platforms.X86_16.decompiler_postprocess_utils import (
    _iter_c_nodes_deep_8616,
    _match_bp_stack_load_8616,
    _same_c_expression_8616,
)
from angr_platforms.X86_16.lowering.call_argument_carrier_liveness import (
    call_argument_setup_is_proven_dead_8616,
)
from angr_platforms.X86_16.lowering.call_argument_state import ProtectedCallArgumentStore8616
from angr_platforms.X86_16.lowering.return_type_evidence import proven_function_result_observation_8616
from angr_platforms.X86_16.lowering.segmented_global_loads import DirectGlobalSymbolRef8616
from angr_platforms.X86_16.lowering.segmented_memory_lowering import (
    runtime_segment_push_source_cvar_8616,
)
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)
from angr_platforms.X86_16.pipeline.errors import PipelineHardError
from angr_platforms.X86_16.postprocess.call_argument_transaction import (
    accepted_call_argument_mutation_8616,
)
from angr_platforms.X86_16.tail_validation import (
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
)
from angr_platforms.X86_16.tail_validation_fingerprint import _expr_fingerprint
from call_store_fixtures import ss_word_store, word_dereference


def _args_match(args: list, expected: list) -> bool:
    if len(args) != len(expected):
        return False
    return all(_same_c_expression_8616(a, e) for a, e in zip(args, expected, strict=False))


class _DummyCodegen:
    def __init__(self, project):
        self._idx = 0
        self.project = project
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


class _LoopLikeNode:
    def __init__(self, body):
        self.body = body
        self.statements = None
        self.else_node = None
        self.condition_and_nodes = ()


def _project():
    return SimpleNamespace(arch=Arch86_16())


def test_structured_root_prefers_current_statements_over_stale_body():
    current = SimpleNamespace(name="current")
    stale = SimpleNamespace(name="stale")
    cfunc = SimpleNamespace(statements=current, body=stale)

    assert _structured_root_8616(cfunc) is current


class _ByteMemory:
    def __init__(self, base: int, data: bytes):
        self.base = base
        self.data = data

    def load(self, addr: int, size: int) -> bytes:
        start = addr - self.base
        if start < 0 or start + size > len(self.data):
            raise KeyError(addr)
        return self.data[start : start + size]


def _project_with_bytes(base: int, data: bytes):
    project = _project()
    project.loader = SimpleNamespace(memory=_ByteMemory(base, data))
    return project


def _codegen(project, statements):
    codegen = _DummyCodegen(project)
    _bind_call_argument_setup_liveness_classifier_8616(codegen, call_argument_setup_is_proven_dead_8616)
    root = CStatements(statements, addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    return codegen


def _empty_codegen(project):
    return _codegen(project, [])


def _project_with_call_recovery_functions():
    project = _project()
    current = SimpleNamespace(
        addr=0x4010,
        get_call_sites=lambda: (),
        get_call_target=lambda _addr: None,
    )
    callees = {"DrawBar": SimpleNamespace(addr=0x1544, name="DrawBar")}

    class _Functions:
        def function(self, addr=None, name=None, create=False):
            if addr == 0x4010:
                return current
            if isinstance(name, str):
                return callees.get(name)
            return None

    project.kb = SimpleNamespace(functions=_Functions())
    return project


def test_annotated_function_pointer_stack_offsets_uses_structured_types():
    project = _project()
    fnptr_type = SimTypePointer(SimTypeFunction((), SimTypeBottom(label="void")), offset=0)
    function = SimpleNamespace(
        info={
            "x86_16_annotations": {
                "stack_vars": {
                    -2: {"name": "fn", "type": fnptr_type},
                    -4: {"name": "value", "type": SimTypeShort(False)},
                }
            }
        }
    )
    project.kb = SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: function))
    cfunc = SimpleNamespace(addr=0x4010)

    assert _annotated_function_pointer_stack_offsets_8616(project, cfunc) == frozenset({-2})


def test_annotated_function_pointer_stack_offsets_ignores_source_lines_without_type():
    project = _project()
    function = SimpleNamespace(
        info={
            "x86_16_annotations": {
                "source_lines": ("void (*fn)(void);",),
                "stack_vars": {-2: {"name": "fn"}},
            }
        }
    )
    project.kb = SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: function))
    cfunc = SimpleNamespace(addr=0x4010)

    assert _annotated_function_pointer_stack_offsets_8616(project, cfunc) == frozenset()


def _ss_sp_stack_store(codegen, project, displacement: int, rhs):
    structured_c = _scg.c
    sp_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["sp"][0], 2, name="sp"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    return CAssignment(
        structured_c.CUnaryOp(
            "Dereference",
            structured_c.CBinaryOp(
                "Add",
                structured_c.CBinaryOp(
                    "Mul",
                    ss_reg,
                    structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                structured_c.CBinaryOp(
                    "Sub",
                    sp_reg,
                    structured_c.CConstant(-displacement, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        rhs,
        codegen=codegen,
    )


def test_normalize_call_target_names_rewrites_namespaced_callee_target():
    project = _project()
    codegen = _empty_codegen(project)
    call = CFunctionCall("::0x1544::InitBars", None, [], codegen=codegen)
    codegen.cfunc.statements = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _normalize_call_target_names_8616(codegen)

    call = codegen.cfunc.statements.statements[0]
    assert changed is True
    assert call.callee_target == "InitBars"


def test_missing_call_recovery_uses_binary_callsite_multiplicity_over_unique_source_names():
    ordered, missing = _missing_calls_from_sequences_8616(
        ["Swaps", "SwapBars", "QuickSort"],
        ["Swaps", "SwapBars", "Swaps", "SwapBars", "QuickSort", "QuickSort"],
        ["Swaps", "SwapBars", "QuickSort"],
    )

    assert ordered == ["Swaps", "SwapBars", "Swaps", "SwapBars", "QuickSort", "QuickSort"]
    assert _ordered_missing_from_source_8616(ordered, missing) == ["Swaps", "SwapBars", "QuickSort"]


def test_normalize_call_target_names_strips_wrapper_suffix_parens():
    project = _project()
    codegen = _empty_codegen(project)
    call = CFunctionCall("::0x1544::InitBars()", None, [], codegen=codegen)
    codegen.cfunc.statements = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _normalize_call_target_names_8616(codegen)

    call = codegen.cfunc.statements.statements[0]
    assert changed is True
    assert call.callee_target == "InitBars"


def test_normalize_call_target_names_rewrites_namespaced_callee_func_name():
    project = _project()
    codegen = _empty_codegen(project)
    callee_func = SimpleNamespace(name="::0x1544::InitBars")
    call = CFunctionCall(None, callee_func, [], codegen=codegen)
    codegen.cfunc.statements = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _normalize_call_target_names_8616(codegen)

    assert changed is True
    assert callee_func.name == "InitBars"


def test_normalize_call_target_names_keeps_tail_validation_stable():
    project = _project()
    before_codegen = _empty_codegen(project)
    call = CFunctionCall("::0x1544::InitBars", None, [], codegen=before_codegen)
    ret = CReturn(None, codegen=before_codegen)
    before_codegen.cfunc.statements = CStatements([call, ret], addr=0x4010, codegen=before_codegen)
    before_codegen.cfunc.body = before_codegen.cfunc.statements

    after_codegen = deepcopy(before_codegen)
    changed = _normalize_call_target_names_8616(after_codegen)

    assert changed is True
    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before_codegen),
        collect_x86_16_tail_validation_summary(project, after_codegen),
    )
    assert diff["changed"] is False


def test_normalize_call_target_names_keeps_tail_validation_stable_for_same_addr_sidecar_rename():
    project = _project()
    project._inertia_original_project = SimpleNamespace(
        kb=SimpleNamespace(labels={0x1005D: "_InitMenu"}),
        _inertia_lst_metadata=SimpleNamespace(code_labels={0x1005D: "_InitMenu"}),
    )
    project._inertia_original_linear_delta = 0xF010
    before_codegen = _empty_codegen(project)
    call = CFunctionCall("sub_104d", SimpleNamespace(addr=0x104D, name="sub_104d"), [], codegen=before_codegen)
    ret = CReturn(None, codegen=before_codegen)
    before_codegen.cfunc.statements = CStatements([call, ret], addr=0x4010, codegen=before_codegen)
    before_codegen.cfunc.body = before_codegen.cfunc.statements

    after_codegen = deepcopy(before_codegen)
    changed = _normalize_call_target_names_8616(after_codegen)

    assert changed is True
    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before_codegen),
        collect_x86_16_tail_validation_summary(project, after_codegen),
    )
    assert diff["changed"] is False


def test_normalize_call_target_names_prefers_sidecar_label_for_sub_target_without_summary():
    project = _project()
    project._inertia_original_project = SimpleNamespace(
        kb=SimpleNamespace(labels={0x1005D: "_InitMenu"}),
        _inertia_lst_metadata=SimpleNamespace(code_labels={0x1005D: "_InitMenu"}),
    )
    project._inertia_original_linear_delta = 0xF010
    codegen = _empty_codegen(project)
    call = CFunctionCall("sub_104d", SimpleNamespace(addr=0x104D, name="sub_104d"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _normalize_call_target_names_8616(codegen)

    assert changed is True
    assert call.callee_func.name == "InitMenu"
    assert call.callee_target == "InitMenu"


def test_normalize_call_target_names_replaces_unproved_name_with_direct_target():
    project = _project()
    generated = SimpleNamespace(addr=0x13AE0, name="generated_target", is_default_name=True)
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda **kwargs: generated if kwargs.get("addr") == 0x13AE0 else None
        ),
        labels={},
    )
    codegen = _empty_codegen(project)
    call = CFunctionCall("generated_target", generated, [], codegen=codegen)
    codegen.cfunc.statements = CStatements([call], addr=0x13D27, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x13D27,
            target_addr=0x13AE0,
            return_addr=0x13D2A,
            kind="near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=None,
            return_register=None,
            return_used=False,
        )
    }

    changed = _normalize_call_target_names_8616(codegen)

    assert changed is True
    assert call.callee_func is None
    assert call.callee_target == "sub_13ae0"


def test_normalize_call_target_names_refuses_unproved_source_name_for_unknown_call(monkeypatch):
    project = _project()
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda **kwargs: (
                SimpleNamespace(addr=0x1005A, name="rel_i16")
                if kwargs.get("name") in {"rel_i16", "_rel_i16"}
                else (
                    SimpleNamespace(addr=0x1016E, name="in_window_i16")
                    if kwargs.get("name") in {"in_window_i16", "_in_window_i16"}
                    else None
                )
            )
        ),
        labels={},
    )
    codegen = _empty_codegen(project)
    call = CFunctionCall("sub_1005a", None, [], codegen=codegen)
    codegen.cfunc.statements = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1005A,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register="ax",
            return_used=True,
        )
    }
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._cod_source_call_names_8616",
        lambda _project, _addr: ("in_window_i16",),
    )

    changed = _normalize_call_target_names_8616(codegen)

    assert changed is False
    assert call.callee_target == "sub_1005a"


def test_normalize_call_target_names_rejects_source_only_stack_probe_shape(monkeypatch):
    project = _project()
    project.kb = SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: None), labels={})
    codegen = _empty_codegen(project)
    call = CFunctionCall("sub_5d2", None, [], codegen=codegen)
    codegen.cfunc.statements = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x105D2,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=None,
            return_register=None,
            return_used=False,
        )
    }
    codegen._inertia_callsite_final_gate_active_8616 = False
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._cod_source_call_names_8616",
        lambda _project, _addr: ("aNchkstk",),
    )

    changed = _normalize_call_target_names_8616(codegen)

    assert changed is False
    assert call.callee_target == "sub_5d2"


def test_normalize_call_target_names_rejects_stack_probe_target_summary_for_named_user_call():
    probe_pattern = bytes.fromhex("59 8b dc 2b d8 72 0a 3b 1e 00 00 72 04 8b e3 ff e1")
    project = _project_with_bytes(0x1038E, probe_pattern)
    user_helper = SimpleNamespace(addr=0x10010, name="sub_10010")
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, create=False, **_kwargs: user_helper if addr == 0x10010 else None
        ),
        labels={},
    )
    codegen = _empty_codegen(project)
    call = CFunctionCall("sub_10010", user_helper, [], codegen=codegen)
    codegen.cfunc.statements = CStatements([call], addr=0x4058, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x405E,
            target_addr=0x1038E,
            return_addr=0x4061,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=None,
            return_register=None,
            return_used=False,
        )
    }
    codegen._inertia_callsite_final_gate_active_8616 = False

    changed = _normalize_call_target_names_8616(codegen)

    assert changed is False
    assert call.callee_func is user_helper
    assert call.callee_target == "sub_10010"
    assert codegen._inertia_callsite_summaries == {}


def test_attach_callsite_summaries_does_not_upgrade_source_only_stack_probe_summary(monkeypatch):
    project = _project()
    function = SimpleNamespace(get_call_sites=lambda: (0x4012,))
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr, create=False: (
                function
                if addr == 0x4010
                else SimpleNamespace(addr=addr, name=f"sub_{addr:x}")
                if addr == 0x105D2
                else None
            )
        ),
        labels={},
    )
    codegen = _empty_codegen(project)
    probe_arg = _scg.c.CConstant(375, SimTypeShort(False), codegen=codegen)
    call = CFunctionCall("sub_105d2", SimpleNamespace(addr=0x105D2, name="sub_105d2"), [probe_arg], codegen=codegen)
    codegen.cfunc.statements = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, _callsite_addr, **_kwargs: CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x105D2,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=None,
            return_register=None,
            return_used=False,
        ),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._cod_source_call_names_8616",
        lambda _project, _addr: ("aNchkstk",),
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert call.callee_func is not None
    assert call.callee_target == "sub_105d2"
    summary = codegen._inertia_callsite_summaries[id(call)]
    assert summary.stack_probe_helper is False
    assert summary.helper_return_state == "none"
    assert summary.helper_return_space is None
    assert summary.helper_return_width is None
    assert summary.helper_return_address_kind == "none"
    assert codegen._inertia_callsite_materialization_stats.source_proven_stack_probe_count == 0


def test_attach_callsite_summaries_upgrades_named_stack_probe_summary(monkeypatch):
    project = _project()
    function = SimpleNamespace(get_call_sites=lambda: (0x4012,))
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr, create=False: (
                function
                if addr == 0x4010
                else SimpleNamespace(addr=addr, name="aNchkstk")
                if addr == 0x105D2
                else None
            )
        ),
        labels={},
    )
    codegen = _empty_codegen(project)
    call = CFunctionCall("aNchkstk", SimpleNamespace(addr=0x105D2, name="aNchkstk"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, _callsite_addr, **_kwargs: CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x105D2,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
            stack_probe_helper=True,
        ),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._cod_source_call_names_8616",
        lambda _project, _addr: (),
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    summary = codegen._inertia_callsite_summaries[id(call)]
    assert summary.stack_probe_helper is True
    assert summary.helper_return_state == "stack_address"
    assert summary.helper_return_space == "ss"
    assert summary.helper_return_width == 2
    assert summary.helper_return_address_kind == "stack"


def test_attach_callsite_summaries_prefers_sidecar_labels_for_sub_targets(monkeypatch):
    project = _project()
    project._inertia_original_project = SimpleNamespace(
        kb=SimpleNamespace(labels={0x1005D: "_InitMenu"}),
        _inertia_lst_metadata=SimpleNamespace(code_labels={0x1005D: "_InitMenu"}),
    )
    project._inertia_original_linear_delta = 0xF010
    function = SimpleNamespace(get_call_sites=lambda: (0x4012,))
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr, create=False: (
                function if addr == 0x4010 else SimpleNamespace(addr=addr, name="sub_104d")
            )
        )
    )
    codegen = _empty_codegen(project)
    call = CFunctionCall("sub_104d", SimpleNamespace(addr=0x104D, name="sub_104d"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, _callsite_addr, **_kwargs: CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x104D,
            return_addr=0x4015,
            kind="near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        ),
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert call.callee_func.name == "InitMenu"
    assert call.callee_target == "InitMenu"


def test_attach_callsite_summaries_matches_unaddressed_calls_by_target_instead_of_zip_order(monkeypatch):
    project = _project()
    function = SimpleNamespace(get_call_sites=lambda: (0x4010, 0x4012))
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr, create=False: (
                function
                if addr == 0x4010
                else SimpleNamespace(addr=addr, name={0x1001: "aNchkstk", 0x14A0: "outp"}.get(addr, f"sub_{addr:x}"))
            )
        )
    )
    codegen = _empty_codegen(project)
    call_outp = CFunctionCall("outp", SimpleNamespace(addr=0x14A0, name="outp"), [], codegen=codegen)
    call_probe = CFunctionCall("aNchkstk", SimpleNamespace(addr=0x1001, name="aNchkstk"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements([call_outp, call_probe], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    summarized_callsites: list[int] = []

    def _summary_for_callsite(_function, callsite_addr, **_kwargs):
        summarized_callsites.append(callsite_addr)
        if callsite_addr == 0x4010:
            return CallsiteSummary8616(
                callsite_addr=0x4010,
                target_addr=0x1001,
                return_addr=0x4011,
                kind="near",
                arg_count=0,
                arg_widths=(),
                stack_cleanup=0,
                return_register="ax",
                return_used=True,
                stack_probe_helper=True,
            )
        return CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x14A0,
            return_addr=0x4015,
            kind="near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
        )

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls.summarize_x86_16_callsite",
        _summary_for_callsite,
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._cod_metadata_for_function_8616",
        lambda _project, _addr: SimpleNamespace(call_names=("speaker", "outp")),
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert call_probe.callee_target == "aNchkstk"
    assert call_outp.callee_target == "outp"
    assert summarized_callsites == [0x4010, 0x4012]
    assert codegen._inertia_callsite_summaries[id(call_probe)].target_addr == 0x1001
    assert codegen._inertia_callsite_summaries[id(call_outp)].target_addr == 0x14A0
    _attach_callsite_summaries_8616(project, codegen)
    assert summarized_callsites == [0x4010, 0x4012]


def test_conservative_call_arg_seed_uses_known_default_for_zero_arg_helper_summary():
    project = _project()
    codegen = _empty_codegen(project)
    call = CFunctionCall(
        "displaycursor",
        SimpleNamespace(addr=0x10020, name="displaycursor"),
        [],
        codegen=codegen,
    )
    root = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    summary_map = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x10020,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
            push_arg_sources=(),
        )
    }

    def _set_args(node, args, *, call_name, force_replace=False):
        node.args = list(args)
        return accepted_call_argument_mutation_8616(arguments_changed=True, target_changed=False)

    def _refresh_shape(node, summary):
        if summary is not None:
            summary_map[id(node)] = summary.__class__(
                callsite_addr=summary.callsite_addr,
                target_addr=summary.target_addr,
                return_addr=summary.return_addr,
                kind=summary.kind,
                arg_count=len(tuple(getattr(node, "args", ()) or ())),
                arg_widths=tuple(2 for _ in tuple(getattr(node, "args", ()) or ())),
                stack_cleanup=summary.stack_cleanup,
                return_register=summary.return_register,
                return_used=summary.return_used,
                push_arg_sources=summary.push_arg_sources,
            )

    changed = _conservative_call_arg_seed_8616(
        root=root,
        summary_map=summary_map,
        codegen=codegen,
        has_unverified_non_ss_stack_probe=False,
        call_name_fn=lambda node: getattr(node, "callee_target", None),
        expected_arg_count_fn=lambda name: 1 if name == "displaycursor" else None,
        known_default_args_fn=_known_default_args_for_missing_8616,
        direct_expr_from_push_source_fn=lambda *_args, **_kwargs: None,
        normalize_materialized_call_args_fn=lambda args, *_args, **_kwargs: tuple(args),
        all_arg_exprs_are_non_segment_registers_fn=lambda _args: True,
        set_materialized_call_args_fn=_set_args,
        refresh_summary_arg_shape_fn=_refresh_shape,
        call_args_need_rematerialization_fn=lambda *_args, **_kwargs: False,
    )

    assert changed is True
    assert len(call.args) == 1
    assert getattr(call.args[0], "value", None) == 0
    assert summary_map[id(call)].arg_count == 1


def test_conservative_call_arg_seed_forwards_ordered_arithmetic_push_sources():
    project = _project()
    codegen = _empty_codegen(project)
    call = CFunctionCall(
        "SwapBars",
        SimpleNamespace(addr=0x10768, name="SwapBars"),
        [object(), object()],
        codegen=codegen,
    )
    root = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    push_sources = (
        ("expr", ("bp", -2), ((CallsitePushExprOp8616.ADD.value, 1),)),
        ("bp", -2),
    )
    summary_map = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4067,
            target_addr=0x10768,
            return_addr=0x406A,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register="ax",
            return_used=False,
            push_arg_sources=push_sources,
        )
    }
    received_push_sources = None

    def _normalize_args(args, *_args, push_sources=(), **_kwargs):
        nonlocal received_push_sources
        received_push_sources = push_sources
        return list(args)

    def _set_args(node, args, *, call_name, force_replace=False):
        node.args = list(args)
        return accepted_call_argument_mutation_8616(arguments_changed=True, target_changed=False)

    changed = _conservative_call_arg_seed_8616(
        root=root,
        summary_map=summary_map,
        codegen=codegen,
        has_unverified_non_ss_stack_probe=False,
        call_name_fn=lambda node: node.callee_target,
        expected_arg_count_fn=lambda name: 2 if name == "SwapBars" else None,
        known_default_args_fn=lambda _name, _codegen: None,
        direct_expr_from_push_source_fn=lambda source, **_kwargs: source,
        normalize_materialized_call_args_fn=_normalize_args,
        all_arg_exprs_are_non_segment_registers_fn=lambda _args: True,
        set_materialized_call_args_fn=_set_args,
        refresh_summary_arg_shape_fn=lambda _node, _summary: None,
        call_args_need_rematerialization_fn=lambda *_args, **_kwargs: True,
    )

    assert changed is True
    assert received_push_sources == tuple(reversed(push_sources))


def test_loop_carried_call_summary_uses_owned_push_arg_sources():
    summary = CallsiteSummary8616(
        callsite_addr=0x4012,
        target_addr=0x10020,
        return_addr=0x4015,
        kind="direct_near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register=None,
        return_used=False,
        push_arg_sources=(("bp", -4),),
    )

    assert _summary_looks_loop_carried_arg_8616(summary) is True


def test_loop_carried_call_summary_refuses_non_bp_push_source():
    summary = CallsiteSummary8616(
        callsite_addr=0x4012,
        target_addr=0x10020,
        return_addr=0x4015,
        kind="direct_near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register=None,
        return_used=False,
        push_arg_sources=(("global", 0x120, 2),),
    )

    assert _summary_looks_loop_carried_arg_8616(summary) is False


def test_align_cod_call_names_ignores_cod_target_proof(monkeypatch):
    monkeypatch.setenv("INERTIA_ENABLE_SOURCE_CALL_FLOOR_RECOVERY", "1")
    project = _project()
    function_by_addr = {
        0x104D: SimpleNamespace(addr=0x104D, name="InitMenu"),
    }
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, name=None, create=False: (
                function_by_addr.get(addr)
                if addr is not None
                else next((func for func in function_by_addr.values() if func.name == name), None)
            )
        )
    )
    codegen = _empty_codegen(project)
    calls = [
        CFunctionCall("aNchkstk", SimpleNamespace(addr=0x1001, name="aNchkstk"), [], codegen=codegen),
        CFunctionCall("InitBars", SimpleNamespace(addr=0x1040, name="InitBars"), [], codegen=codegen),
        CFunctionCall("sub_104d", SimpleNamespace(addr=0x104D, name="sub_104d"), [], codegen=codegen),
        CFunctionCall("RunMenu", SimpleNamespace(addr=0x1060, name="RunMenu"), [], codegen=codegen),
    ]
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=CStatements(calls, addr=0x4010, codegen=codegen),
        body=None,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._cod_metadata_for_function_8616",
        lambda _project, _addr: SimpleNamespace(call_names=("aNchkstk", "InitBars", "InitMenu", "RunMenu")),
    )
    codegen._inertia_callsite_summaries = {
        id(calls[2]): CallsiteSummary8616(0x4020, 0x104D, 0x4023, "near", 0, (), 0, None, False),
    }

    changed = _align_cod_call_names_8616(project, codegen)

    assert changed is False
    assert calls[2].callee_func.name == "sub_104d"
    assert calls[2].callee_target == "sub_104d"


def test_align_cod_call_names_ignores_ordered_arity_proof(monkeypatch):
    monkeypatch.setenv("INERTIA_ENABLE_SOURCE_CALL_FLOOR_RECOVERY", "1")
    project = _project()
    codegen = _empty_codegen(project)
    calls = [
        CFunctionCall("DrawBar", SimpleNamespace(addr=0x1544, name="DrawBar"), [], codegen=codegen),
        CFunctionCall("DrawBar", SimpleNamespace(addr=0x1544, name="DrawBar"), [], codegen=codegen),
        CFunctionCall("sub_d29", SimpleNamespace(addr=0x1666, name="sub_d29"), [], codegen=codegen),
    ]
    calls[2].args = [
        _scg.c.CVariable(
            SimStackVariable(4, 2, base="bp", name="iRow1"),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        )
    ]
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=CStatements(calls, addr=0x4010, codegen=codegen),
        body=None,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(calls[2]): CallsiteSummary8616(0x4020, 0x1666, 0x4023, "near", 1, (2,), 2, "ax", True),
    }
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._cod_metadata_for_function_8616",
        lambda _project, _addr: SimpleNamespace(call_names=("DrawBar", "DrawTime")),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._source_name_matches_target_8616",
        lambda _project, _target_addr, _source_name: False,
    )

    changed = _align_cod_call_names_8616(project, codegen)

    assert changed is False
    assert calls[0].callee_target == "DrawBar"
    assert calls[1].callee_target == "DrawBar"
    assert calls[2].callee_func.name == "sub_d29"
    assert calls[2].callee_target == "sub_d29"


def test_align_cod_call_names_does_not_override_known_repeated_calls_without_unknown_nodes(monkeypatch):
    monkeypatch.setenv("INERTIA_ENABLE_SOURCE_CALL_FLOOR_RECOVERY", "1")
    project = _project()
    codegen = _empty_codegen(project)
    calls = [
        CFunctionCall("aNchkstk", SimpleNamespace(addr=0x1001, name="aNchkstk"), [], codegen=codegen),
        CFunctionCall("DrawBar", SimpleNamespace(addr=0x1040, name="DrawBar"), [], codegen=codegen),
        CFunctionCall("DrawBar", SimpleNamespace(addr=0x1041, name="DrawBar"), [], codegen=codegen),
    ]
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=CStatements(calls, addr=0x4010, codegen=codegen),
        body=None,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._cod_metadata_for_function_8616",
        lambda _project, _addr: SimpleNamespace(call_names=("aNchkstk", "DrawBar", "DrawTime")),
    )

    changed = _align_cod_call_names_8616(project, codegen)

    assert changed is False
    assert calls[2].callee_func.name == "DrawBar"
    assert calls[2].callee_target == "DrawBar"


def test_align_cod_call_names_ignores_duplicate_unknown_call(monkeypatch):
    monkeypatch.setenv("INERTIA_ENABLE_SOURCE_CALL_FLOOR_RECOVERY", "1")
    project = _project()
    function_by_addr = {
        0x10010: SimpleNamespace(addr=0x10010, name="cmp_i16"),
        0x1005A: SimpleNamespace(addr=0x1005A, name="rel_i16"),
    }
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, name=None, create=False: (
                function_by_addr.get(addr)
                if addr is not None
                else next((func for func in function_by_addr.values() if func.name == name), None)
            )
        )
    )
    codegen = _empty_codegen(project)
    calls = [
        CFunctionCall("sub_10010", SimpleNamespace(addr=0x10010, name="sub_10010"), [], codegen=codegen),
        # Generated duplicate of the first call expression: no callsite summary, so
        # it must not consume a COD call-name slot.
        CFunctionCall("sub_dup", SimpleNamespace(addr=0xDEAD, name="sub_dup"), [], codegen=codegen),
        CFunctionCall("sub_1005a", SimpleNamespace(addr=0x1005A, name="sub_1005a"), [], codegen=codegen),
    ]
    codegen.cfunc = SimpleNamespace(
        addr=0x101A7,
        statements=CStatements(calls, addr=0x101A7, codegen=codegen),
        body=None,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(calls[0]): CallsiteSummary8616(0x101AA, 0x10010, 0x101AD, "near", 2, (2, 2), 4, "ax", True),
        id(calls[2]): CallsiteSummary8616(0x101F7, 0x1005A, 0x101FA, "near", 2, (2, 2), 4, "ax", True),
    }
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._cod_metadata_for_function_8616",
        lambda _project, _addr: SimpleNamespace(call_names=("cmp_i16", "rel_i16")),
    )

    changed = _align_cod_call_names_8616(project, codegen)

    assert changed is False
    assert calls[0].callee_target == "sub_10010"
    assert calls[1].callee_target == "sub_dup"
    assert calls[2].callee_target == "sub_1005a"


def test_align_cod_call_names_ignores_rebased_original_function_metadata(monkeypatch):
    monkeypatch.setenv("INERTIA_ENABLE_SOURCE_CALL_FLOOR_RECOVERY", "1")
    project = _project()
    original_project = _project()
    project._inertia_original_project = original_project
    project._inertia_original_linear_delta = 0xF010
    project._inertia_lst_metadata = SimpleNamespace(cod_path="/tmp/missing.cod", cod_proc_kinds={})
    original_project._inertia_lst_metadata = SimpleNamespace(
        cod_path="/tmp/fake.cod",
        cod_proc_kinds={0x10010: "NEAR"},
    )
    original_project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr, create=False: SimpleNamespace(addr=addr, name="main") if addr == 0x10010 else None
        )
    )
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, name=None, create=False: (
                SimpleNamespace(addr=0x104D, name="InitMenu") if addr == 0x104D or name == "InitMenu" else None
            )
        )
    )
    codegen = _empty_codegen(project)
    calls = [
        CFunctionCall("InitBars", SimpleNamespace(addr=0x1040, name="InitBars"), [], codegen=codegen),
        CFunctionCall("sub_104d", SimpleNamespace(addr=0x104D, name="sub_104d"), [], codegen=codegen),
        CFunctionCall("RunMenu", SimpleNamespace(addr=0x1060, name="RunMenu"), [], codegen=codegen),
    ]
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=CStatements(calls, addr=0x1000, codegen=codegen),
        body=None,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls.extract_cod_proc_metadata",
        lambda _path, _name, _kind: SimpleNamespace(call_names=("InitBars", "InitMenu", "RunMenu")),
    )
    codegen._inertia_callsite_summaries = {
        id(calls[1]): CallsiteSummary8616(0x101F7, 0x104D, 0x101FA, "near", 0, (), 0, None, False),
    }

    changed = _align_cod_call_names_8616(project, codegen)

    assert changed is False
    assert calls[1].callee_func.name == "sub_104d"
    assert calls[1].callee_target == "sub_104d"


def test_cod_metadata_for_function_keeps_original_project_in_original_address_space(monkeypatch):
    project = _project()
    original_project = _project()
    project._inertia_original_project = original_project
    project._inertia_original_linear_delta = 0xF9E8
    project._inertia_lst_metadata = SimpleNamespace(
        cod_path="/tmp/fake.cod",
        cod_proc_kinds={0x1000: "NEAR", 0x109E8: "NEAR"},
    )
    original_project._inertia_lst_metadata = SimpleNamespace(
        cod_path="/tmp/fake.cod",
        cod_proc_kinds={0x1000: "NEAR", 0x109E8: "NEAR"},
    )

    functions_by_addr = {
        0x1000: SimpleNamespace(addr=0x1000, name="_flsbuf"),
        0x109E8: SimpleNamespace(addr=0x109E8, name="_PercolateUp"),
    }
    original_project.kb = SimpleNamespace(
        functions=SimpleNamespace(function=lambda addr=None, create=False: functions_by_addr.get(addr))
    )
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(function=lambda addr=None, create=False: functions_by_addr.get(addr))
    )
    seen: list[str] = []

    def _extract(_path, name, _kind):
        seen.append(name)
        return SimpleNamespace(call_names=(name,))

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls.extract_cod_proc_metadata",
        _extract,
    )

    metadata = _cod_metadata_for_function_8616(project, 0x1000)

    assert metadata.call_names == ("_PercolateUp",)
    assert "_flsbuf" not in seen


def test_recover_expected_calls_ignores_cod_call_names_over_rebased_target_guess(monkeypatch):
    project = _project()
    cfunc = SimpleNamespace(addr=0x1000, name="PercolateUp")
    function = SimpleNamespace(
        addr=0x1000,
        get_call_sites=lambda: [0x1006, 0x1052, 0x105E],
        get_call_target=lambda callsite: {0x1006: 0x11222, 0x1052: 0x10794, 0x105E: 0x1075B}[callsite],
    )
    wrong_names = {
        0x11222: "aNchkstk",
        0x10794: "flsbuf",
        0x1075B: "flsbuf",
    }

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._lookup_callee_function_8616",
        lambda _project, target, **_kwargs: SimpleNamespace(name=wrong_names[target]),
    )
    summaries = {
        callsite: CallsiteSummary8616(
            callsite, function.get_call_target(callsite), callsite + 3, "near", 0, (), 0, None, False
        )
        for callsite in function.get_call_sites()
    }
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, callsite, **_kwargs: summaries[callsite],
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._cod_source_call_names_8616",
        lambda _project, _func_addr: ("aNchkstk", "Swaps", "SwapBars"),
    )

    expected, summary_by_name, source = _recover_expected_calls_8616(project, cfunc, function, 0x1000)

    assert expected == ["aNchkstk", "flsbuf", "flsbuf"]
    assert source == []
    assert summary_by_name["flsbuf"] == [summaries[0x1052], summaries[0x105E]]


def test_materialize_callsite_stack_arguments_rewrites_preceding_stack_store_into_call_arg():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Mul",
                structured_c.CVariable(
                    SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
                    codegen=codegen,
                ),
                structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Add",
                structured_c.CUnaryOp(
                    "Reference",
                    structured_c.CVariable(
                        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
                        variable_type=SimTypeShort(False),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                structured_c.CConstant(-2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(outgoing, arg_slot, codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    only_stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(only_stmt, CExpressionStatement)
    assert _args_match(only_stmt.expr.args, [arg_slot])


def test_materialize_callsite_stack_arguments_groups_named_word_pushes_as_scalar(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    long_arg_proto = SimTypeFunction(
        [SimTypeLong(False)],
        SimTypeBottom(label="void"),
        arg_names=("wait",),
        variadic=False,
    ).with_arch(project.arch)
    callee = SimpleNamespace(name="Sleep", prototype=long_arg_proto)
    call = CFunctionCall("Sleep", callee, [], codegen=codegen)
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    ds = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ds"][0], 2, name="ds"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    old_low = CFunctionCall(
        "SEG_U16",
        None,
        [ds, structured_c.CConstant(0x132, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
    )
    old_high = CFunctionCall(
        "SEG_U16",
        None,
        [ds, structured_c.CConstant(0x134, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
    )
    protected_store = ProtectedCallArgumentStore8616()
    protected_store.remember(call, 0, old_low, 4)
    protected_store.remember(call, 1, old_high, 4)
    codegen._inertia_protected_call_args_8616 = protected_store
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("global", 0x134, 2), ("global", 0x132, 2)),
        )
    }
    direct_refs = (
        DirectGlobalSymbolRef8616(0x132, "clPause", 0, 2, 2),
        DirectGlobalSymbolRef8616(0x134, "clPause", 2, 2, 2),
        DirectGlobalSymbolRef8616(0x132, "clPause", 0, 4, 0),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._collect_direct_global_symbol_refs_8616",
        lambda *_args, **_kwargs: direct_refs,
    )

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    only_stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(only_stmt, CExpressionStatement)
    args = only_stmt.expr.args
    assert len(args) == 1
    assert isinstance(args[0], CVariable)
    assert args[0].variable.name == "clPause"
    assert args[0].variable.size == 4
    summary = codegen._inertia_callsite_summaries[id(call)]
    assert summary.arg_count == 2
    assert summary.arg_widths == (2, 2)
    protected = codegen._inertia_protected_call_args_8616
    assert protected.get(call, 1) is None

    changed_again = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed_again is False
    args = only_stmt.expr.args
    assert len(args) == 1
    assert isinstance(args[0], CVariable)
    assert args[0].variable.name == "clPause"


def test_materialize_callsite_stack_arguments_groups_signed_stack_word_pushes_for_long_arg():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    long_arg_proto = SimTypeFunction(
        [SimTypeLong(False)],
        SimTypeBottom(label="void"),
        arg_names=("wait",),
        variadic=False,
    ).with_arch(project.arch)
    callee = SimpleNamespace(name="Sleep", prototype=long_arg_proto)
    call = CFunctionCall("Sleep", callee, [], codegen=codegen)
    duration_slot = SimStackVariable(6, 2, base="bp", name="duration", region=0x4010)
    duration_var = structured_c.CVariable(duration_slot, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use = {duration_slot: duration_var}
    codegen.cfunc.unified_local_vars = {duration_slot: {(duration_var, duration_var.variable_type)}}
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    summary = CallsiteSummary8616(
        callsite_addr=0x4012,
        target_addr=0x1544,
        return_addr=0x4015,
        kind="direct_near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register=None,
        return_used=False,
        push_arg_sources=(
            (
                "expr",
                ("bp", 6),
                ((CallsitePushExprOp8616.SIGN_EXT_HI.value, 16),),
            ),
            ("bp", 6),
        ),
    )
    codegen._inertia_callsite_summaries = {id(call): summary}
    codegen._inertia_callsite_summary_inventory_8616 = {summary.callsite_addr: summary}

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    only_stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(only_stmt, CExpressionStatement)
    args = only_stmt.expr.args
    assert len(args) == 1
    assert isinstance(args[0], _scg.c.CTypeCast)
    assert getattr(getattr(args[0].expr, "variable", None), "name", None) == "duration"
    summary = codegen._inertia_callsite_summaries[id(call)]
    assert summary.arg_count == 2
    assert summary.arg_widths == (2, 2)
    assert summary.logical_arg_widths == (4,)
    assert codegen._inertia_callsite_summary_inventory_8616[0x4012].logical_arg_widths == (4,)


def test_materialize_callsite_stack_arguments_ignores_source_width_over_generated_word_prototype(tmp_path):
    project = _project()
    cod_path = tmp_path / "sample.cod"
    cod_path.write_text(";|*** void Delay( unsigned long wait );\n", encoding="utf-8")
    project._inertia_lst_metadata = SimpleNamespace(cod_path=str(cod_path))
    codegen = _empty_codegen(project)
    stale_word_proto = SimTypeFunction(
        [SimTypeShort(False), SimTypeShort(False)],
        SimTypeBottom(label="void"),
        variadic=False,
    ).with_arch(project.arch)
    callee = SimpleNamespace(name="Delay", prototype=stale_word_proto)
    call = CFunctionCall("Delay", callee, [], codegen=codegen)
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("global", 0x134, 2), ("global", 0x132, 2)),
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    only_stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(only_stmt, CExpressionStatement)
    args = only_stmt.expr.args
    assert len(args) == 2
    summary = codegen._inertia_callsite_summaries[id(call)]
    assert summary.arg_count == 2
    assert summary.arg_widths == (2, 2)


def test_materialize_callsite_stack_arguments_prefers_validated_summary_logical_widths():
    project = _project()
    codegen = _empty_codegen(project)
    stale_word_proto = SimTypeFunction(
        [SimTypeShort(False), SimTypeShort(False)],
        SimTypeBottom(label="void"),
        variadic=False,
    ).with_arch(project.arch)
    callee = SimpleNamespace(name="Sleep", prototype=stale_word_proto)
    call = CFunctionCall("Sleep", callee, [], codegen=codegen)
    duration_slot = SimStackVariable(6, 2, base="bp", name="duration", region=0x4010)
    duration_var = _scg.c.CVariable(
        duration_slot,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {duration_slot: duration_var}
    codegen.cfunc.unified_local_vars = {duration_slot: {(duration_var, duration_var.variable_type)}}
    codegen.cfunc.statements = CStatements(
        [CExpressionStatement(call, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(
                (
                    "expr",
                    ("bp", 6),
                    ((CallsitePushExprOp8616.SIGN_EXT_HI.value, 16),),
                ),
                ("bp", 6),
            ),
            logical_arg_widths=(4,),
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    args = codegen.cfunc.statements.statements[0].expr.args
    assert len(args) == 1
    assert isinstance(args[0], _scg.c.CTypeCast)
    assert args[0].expr.variable.name == "duration"
    summary = codegen._inertia_callsite_summaries[id(call)]
    assert summary.arg_count == 2
    assert summary.arg_widths == (2, 2)
    assert summary.logical_arg_widths == (4,)


def test_materialize_callsite_stack_arguments_groups_long_global_sub_borrow_source():
    project = _project()
    codegen = _empty_codegen(project)
    long_arg_proto = SimTypeFunction(
        [SimTypeLong(False)],
        SimTypeBottom(label="void"),
        arg_names=("wait",),
        variadic=False,
    ).with_arch(project.arch)
    callee = SimpleNamespace(name="Delay", prototype=long_arg_proto)
    call = CFunctionCall("Delay", callee, [], codegen=codegen)
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(
                ("expr", ("global", 0x134, 2), (("sbb", 0),)),
                ("expr", ("global", 0x132, 2), (("sub", 75),)),
            ),
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    only_stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(only_stmt, CExpressionStatement)
    args = only_stmt.expr.args
    assert len(args) == 1
    arg = args[0]
    assert getattr(arg, "op", None) == "Sub"
    assert isinstance(arg.lhs, CFunctionCall)
    assert arg.lhs.callee_target == "SEG_U32"
    assert getattr(arg.lhs.args[1], "value", None) == 0x132
    assert getattr(arg.rhs, "value", None) == 75
    summary = codegen._inertia_callsite_summaries[id(call)]
    assert summary.arg_count == 2
    assert summary.arg_widths == (2, 2)


def test_materialize_callsite_stack_arguments_preserves_existing_grouped_long_global_arg():
    project = _project()
    codegen = _empty_codegen(project)
    long_arg_proto = SimTypeFunction(
        [SimTypeLong(False)],
        SimTypeBottom(label="void"),
        arg_names=("wait",),
        variadic=False,
    ).with_arch(project.arch)
    callee = SimpleNamespace(name="Delay", prototype=long_arg_proto)
    ds_reg = _scg.c.CVariable(
        SimRegisterVariable(project.arch.registers["ds"][0], 2, name="ds"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    grouped_arg = CFunctionCall(
        "SEG_U32",
        None,
        [ds_reg, _scg.c.CConstant(0x132, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
    )
    call = CFunctionCall("Delay", callee, [grouped_arg], codegen=codegen)
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("global", 0x134, 2), ("global", 0x132, 2)),
        )
    }

    _materialize_callsite_stack_arguments_8616(project, codegen)

    only_stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(only_stmt, CExpressionStatement)
    args = only_stmt.expr.args
    assert len(args) == 1
    assert isinstance(args[0], CFunctionCall)
    assert args[0].callee_target == "SEG_U32"
    assert getattr(args[0].args[1], "value", None) == 0x132


def test_materialize_callsite_stack_arguments_publishes_nested_grouped_shape():
    project = _project()
    codegen = _empty_codegen(project)
    long_type = SimTypeLong(False).with_arch(project.arch)
    callee = SimpleNamespace(
        name="sub_1544",
        prototype=SimTypeFunction([long_type, long_type], long_type, variadic=False).with_arch(project.arch),
    )
    inner_call = CFunctionCall(
        "sub_1544",
        callee,
        [
            _scg.c.CConstant(30, long_type, codegen=codegen),
            _scg.c.CConstant(0x1234, long_type, codegen=codegen),
        ],
        codegen=codegen,
    )
    outer_call = CFunctionCall("consume", SimpleNamespace(name="consume"), [inner_call], codegen=codegen)
    codegen.cfunc.statements = CStatements([outer_call], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(inner_call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=4,
            arg_widths=(2, 2, 2, 2),
            stack_cleanup=8,
            return_register="ax",
            return_used=True,
            push_arg_sources=(("imm", 0), ("imm", 30), ("global", 0x134, 2), ("global", 0x132, 2)),
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    summary = codegen._inertia_callsite_summaries[id(inner_call)]
    assert summary.arg_widths == (2, 2, 2, 2)
    assert summary.logical_arg_widths == (4, 4)


def test_materialize_callsite_stack_arguments_publishes_variadic_wide_suffix():
    project = _project()
    codegen = _empty_codegen(project)
    short_type = SimTypeShort(False).with_arch(project.arch)
    long_type = SimTypeLong(False).with_arch(project.arch)
    inner_callee = SimpleNamespace(
        name="aNldiv",
        prototype_libname=None,
        prototype=SimTypeFunction([long_type, long_type], long_type).with_arch(project.arch),
    )
    inner_call = CFunctionCall(
        "aNldiv",
        inner_callee,
        [
            _scg.c.CConstant(30, long_type, codegen=codegen),
            _scg.c.CConstant(0x1234, long_type, codegen=codegen),
        ],
        codegen=codegen,
    )
    outer_callee = SimpleNamespace(
        name="sprintf",
        prototype=SimTypeFunction(
            [short_type, short_type],
            short_type,
            variadic=True,
        ).with_arch(project.arch),
    )
    outer_call = CFunctionCall(
        "sprintf",
        outer_callee,
        [
            _scg.c.CConstant(1, short_type, codegen=codegen),
            _scg.c.CConstant(2, short_type, codegen=codegen),
            inner_call,
        ],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([outer_call], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(outer_call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=4,
            arg_widths=(2, 2, 2, 2),
            stack_cleanup=8,
            return_register="ax",
            return_used=True,
            push_arg_sources=(
                ("ret_reg", 0x4008, "dx"),
                ("ret_reg", 0x4008, "ax"),
                ("imm", 2),
                ("imm", 1),
            ),
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    summary = codegen._inertia_callsite_summaries[id(outer_call)]
    assert summary.arg_widths == (2, 2, 2, 2)
    assert summary.logical_arg_widths == (2, 2, 4)


def test_materialize_callsite_stack_arguments_prefers_current_statements_and_syncs_body():
    project = _project()
    codegen = _empty_codegen(project)
    long_arg_proto = SimTypeFunction(
        [SimTypeLong(False)],
        SimTypeBottom(label="void"),
        arg_names=("wait",),
        variadic=False,
    ).with_arch(project.arch)
    callee = SimpleNamespace(name="Delay", prototype=long_arg_proto)
    current_call = CFunctionCall("Delay", callee, [], codegen=codegen)
    stale_call = CFunctionCall("Delay", callee, [], codegen=codegen)
    current_root = CStatements([CExpressionStatement(current_call, codegen=codegen)], addr=0x4010, codegen=codegen)
    stale_root = CStatements([CExpressionStatement(stale_call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = stale_root
    codegen.cfunc.statements = current_root
    codegen._inertia_callsite_summaries = {
        id(current_call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("global", 0x134, 2), ("global", 0x132, 2)),
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert codegen.cfunc.statements is current_root
    assert codegen.cfunc.body is current_root
    assert len(current_call.args) == 1
    assert isinstance(current_call.args[0], CFunctionCall)
    assert current_call.args[0].callee_target == "SEG_U32"


def test_materialize_callsite_stack_arguments_uses_global_expr_push_source():
    project = _project()
    codegen = _empty_codegen(project)
    call = CFunctionCall(
        "settextposition",
        SimpleNamespace(name="settextposition"),
        [],
        codegen=codegen,
    )
    root = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x101F,
            target_addr=0x128E4,
            return_addr=0x1024,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("imm", 75), ("expr", ("global", 0x160, 2), ((CallsitePushExprOp8616.ADD.value, 1),))),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(call.args) == 2
    row_arg, column_arg = call.args
    assert isinstance(row_arg, _scg.c.CBinaryOp)
    assert row_arg.op == "Add"
    assert isinstance(row_arg.lhs, CFunctionCall)
    assert row_arg.lhs.callee_target == "SEG_U16"
    assert getattr(row_arg.lhs.args[1], "value", None) == 0x160
    assert getattr(row_arg.rhs, "value", None) == 1
    assert getattr(column_arg, "value", None) == 75


def test_materialize_callsite_stack_arguments_resolves_register_carrier_before_materializing():
    project = _project()
    before_codegen = _empty_codegen(project)
    structured_c = _scg.c
    ax = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax"),
        variable_type=SimTypeShort(False),
        codegen=before_codegen,
    )
    computed_arg = structured_c.CBinaryOp(
        "Add",
        structured_c.CConstant(0x0BAA, SimTypeShort(False), codegen=before_codegen),
        structured_c.CConstant(2, SimTypeShort(False), codegen=before_codegen),
        codegen=before_codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Mul",
                structured_c.CVariable(
                    SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
                    codegen=before_codegen,
                ),
                structured_c.CConstant(16, SimTypeShort(False), codegen=before_codegen),
                codegen=before_codegen,
            ),
            structured_c.CBinaryOp(
                "Add",
                structured_c.CUnaryOp(
                    "Reference",
                    structured_c.CVariable(
                        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
                        variable_type=SimTypeShort(False),
                        codegen=before_codegen,
                    ),
                    codegen=before_codegen,
                ),
                structured_c.CConstant(-2, SimTypeShort(False), codegen=before_codegen),
                codegen=before_codegen,
            ),
            codegen=before_codegen,
        ),
        codegen=before_codegen,
    )
    call = CFunctionCall("Swaps", SimpleNamespace(name="Swaps"), [], codegen=before_codegen)
    before_codegen.cfunc.statements = CStatements(
        [
            CAssignment(ax, computed_arg, codegen=before_codegen),
            CAssignment(outgoing, ax, codegen=before_codegen),
            CExpressionStatement(call, codegen=before_codegen),
        ],
        addr=0x4010,
        codegen=before_codegen,
    )
    before_codegen.cfunc.body = before_codegen.cfunc.statements
    before_codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        )
    }

    after_codegen = deepcopy(before_codegen)
    after_call = after_codegen.cfunc.statements.statements[2].expr
    after_codegen._inertia_callsite_summaries = {
        id(after_call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        )
    }
    changed = _materialize_callsite_stack_arguments_8616(project, after_codegen)

    assert changed is True
    only_stmt = after_codegen.cfunc.statements.statements[1]
    assert isinstance(only_stmt, CExpressionStatement)
    assert len(only_stmt.expr.args) == 1
    actual_fp = _expr_fingerprint(only_stmt.expr.args[0], project)
    # Register-carried values are intentionally resolved to their proven
    # computed value during materialization, because this path has hard value
    # evidence and keeps the call-arg semantics explicit.
    assert actual_fp == "Add(const:2988)"

    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before_codegen),
        collect_x86_16_tail_validation_summary(project, after_codegen),
    )
    assert diff["changed"] is False


def test_materialize_callsite_stack_arguments_preserves_setup_after_zero_arity_refusal():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Mul",
                structured_c.CVariable(
                    SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
                    codegen=codegen,
                ),
                structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Add",
                structured_c.CUnaryOp(
                    "Reference",
                    structured_c.CVariable(
                        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
                        variable_type=SimTypeShort(False),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                structured_c.CConstant(-2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(
        CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen
    )
    call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(outgoing, arg_slot, codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_width=2,
            helper_return_address_kind="stack",
            helper_return_state="stack_address",
            helper_return_space="ss",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    assert isinstance(codegen.cfunc.statements.statements[0], CAssignment)
    final_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert final_stmt.expr is call
    assert final_stmt.expr.args == []
    assert codegen._inertia_callsite_summaries[id(call)].arg_count == 0


def test_materialize_callsite_stack_arguments_materializes_binary_proven_multi_args_after_stack_probe_helper():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot_a = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iParent", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    arg_slot_b = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing_a = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Mul",
                structured_c.CVariable(
                    SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
                    codegen=codegen,
                ),
                structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Add",
                structured_c.CUnaryOp(
                    "Reference",
                    structured_c.CVariable(
                        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
                        variable_type=SimTypeShort(False),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                structured_c.CConstant(-2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    outgoing_b = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Mul",
                structured_c.CVariable(
                    SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
                    codegen=codegen,
                ),
                structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Add",
                structured_c.CUnaryOp(
                    "Reference",
                    structured_c.CVariable(
                        SimStackVariable(-8, 2, base="bp", name="s_8", region=0x4010),
                        variable_type=SimTypeShort(False),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                structured_c.CConstant(-2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(
        CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen
    )
    call = CFunctionCall("SwapBars", SimpleNamespace(name="SwapBars"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(outgoing_a, arg_slot_a, codegen=codegen),
            CAssignment(outgoing_b, arg_slot_b, codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
            helper_return_width=2,
            helper_return_address_kind="stack",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    only_call_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(only_call_stmt, CExpressionStatement)
    assert only_call_stmt.expr is call
    assert _args_match(only_call_stmt.expr.args, [arg_slot_b, arg_slot_a])
    assert codegen._inertia_callsite_summaries[id(call)].arg_count == 2
    assert codegen._inertia_callsite_summaries[id(call)].arg_widths == (2, 2)


def test_materialize_callsite_stack_arguments_keeps_generic_ss_backtracking_without_typed_probe_fact():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    frequency = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="frequency", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    sp_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["sp"][0], 2, name="sp"),
        codegen=codegen,
    )

    def _ss_sp_store(displacement: int, rhs):
        return CAssignment(
            structured_c.CUnaryOp(
                "Dereference",
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CBinaryOp(
                        "Shl",
                        ss_reg,
                        structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    structured_c.CBinaryOp(
                        "Sub",
                        sp_reg,
                        structured_c.CConstant(-displacement, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            rhs,
            codegen=codegen,
        )

    probe = CExpressionStatement(
        CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen
    )
    call = CFunctionCall("DemoCall", SimpleNamespace(name="DemoCall"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            _ss_sp_store(-4, structured_c.CConstant(97, SimTypeShort(False), codegen=codegen)),
            _ss_sp_store(-2, frequency),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
            helper_return_width=2,
            helper_return_address_kind="stack",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x2400,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    assert codegen.cfunc.statements.statements[0] is probe
    only_call_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(only_call_stmt, CExpressionStatement)
    assert len(only_call_stmt.expr.args) == 2
    assert _same_c_expression_8616(only_call_stmt.expr.args[0], frequency)
    assert only_call_stmt.expr.args[1].value == 97


def test_materialize_callsite_stack_arguments_accepts_virtual_dirty_ss_carrier_without_typed_probe_fact():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    frequency = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="frequency", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )

    def _ss_dirty_store(displacement: int, rhs):
        return CAssignment(
            structured_c.CUnaryOp(
                "Dereference",
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CBinaryOp(
                        "Shl",
                        ss_reg,
                        structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    structured_c.CBinaryOp(
                        "Sub",
                        CDirtyExpression("vvar_85", codegen=codegen),
                        structured_c.CConstant(-displacement, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            rhs,
            codegen=codegen,
        )

    probe = CExpressionStatement(
        CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen
    )
    call = CFunctionCall("DemoCall", SimpleNamespace(name="DemoCall"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            _ss_dirty_store(-4, structured_c.CConstant(97, SimTypeShort(False), codegen=codegen)),
            _ss_dirty_store(-2, frequency),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
            helper_return_width=2,
            helper_return_address_kind="stack",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x2400,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    assert codegen.cfunc.statements.statements[0] is probe
    only_call_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(only_call_stmt, CExpressionStatement)
    assert len(only_call_stmt.expr.args) == 2
    assert _same_c_expression_8616(only_call_stmt.expr.args[0], frequency)
    assert only_call_stmt.expr.args[1].value == 97


def test_materialize_callsite_stack_arguments_unknown_call_does_not_overcollect():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    call = CFunctionCall("classify", SimpleNamespace(name="classify"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            _ss_sp_stack_store(
                codegen,
                project,
                -4,
                structured_c.CConstant(0x1234, SimTypeShort(False), codegen=codegen),
            ),
            _ss_sp_stack_store(
                codegen,
                project,
                -2,
                structured_c.CConstant(0x4567, SimTypeShort(False), codegen=codegen),
            ),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1020,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=None,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        )
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True
    only_call_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(only_call_stmt, CExpressionStatement)
    assert len(only_call_stmt.expr.args) == 1
    assert only_call_stmt.expr.args[0].value == 0x4567


def test_materialize_callsite_stack_arguments_matches_same_register_with_renamed_carrier():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    row_index = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    carrier_def = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier_use = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax_7"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    def _ss_dirty_store(displacement: int, rhs):
        return ss_word_store(codegen, ss_reg, displacement, rhs)

    probe = CExpressionStatement(
        CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen
    )
    call = CFunctionCall("DemoCall", SimpleNamespace(name="DemoCall"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(carrier_def, row_index, codegen=codegen),
            _ss_dirty_store(
                -2,
                structured_c.CBinaryOp(
                    "Add",
                    carrier_use,
                    structured_c.CConstant(2892, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
            ),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="unknown",
            helper_return_space=None,
            helper_return_width=None,
            helper_return_address_kind="stack",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x2400,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 3
    probe_assignment = codegen.cfunc.statements.statements[0]
    assert isinstance(probe_assignment, CAssignment)
    assert probe_assignment.rhs is probe.expr
    only_call_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(only_call_stmt, CExpressionStatement)
    assert len(only_call_stmt.expr.args) == 1
    arg = only_call_stmt.expr.args[0]
    assert isinstance(getattr(arg, "variable", None), SimStackVariable)
    assert isinstance(getattr(getattr(arg, "variable", None), "offset", None), int)
    assert not any(
        (getattr(getattr(node, "variable", None), "name", None) or getattr(node, "name", None)) in {"ax", "ax_7"}
        for node in (arg, *_iter_c_nodes_deep_8616(arg))
    )


def test_materialize_callsite_stack_arguments_walks_same_register_chain_across_shorter_prefixes():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    row_index = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iParent", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    ax_0 = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ax_7 = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax_7"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ax_9 = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax_9"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    def _ss_dirty_store(displacement: int, rhs):
        return ss_word_store(codegen, ss_reg, displacement, rhs)

    probe = CExpressionStatement(
        CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen
    )
    call = CFunctionCall("DemoCall", SimpleNamespace(name="DemoCall"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(ax_0, row_index, codegen=codegen),
            CAssignment(ax_7, ax_0, codegen=codegen),
            CAssignment(
                ax_9,
                structured_c.CBinaryOp(
                    "Shl",
                    ax_7,
                    structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            _ss_dirty_store(
                -2,
                structured_c.CBinaryOp(
                    "Add",
                    ax_9,
                    structured_c.CConstant(2892, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
            ),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="unknown",
            helper_return_space=None,
            helper_return_width=None,
            helper_return_address_kind="stack",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x2400,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    only_call_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(only_call_stmt, CExpressionStatement)
    arg = only_call_stmt.expr.args[0]
    assert any(_same_c_expression_8616(node, row_index) for node in (arg, *_iter_c_nodes_deep_8616(arg)))
    assert not any(
        (getattr(getattr(node, "variable", None), "name", None) or getattr(node, "name", None))
        in {"ax", "ax_7", "ax_9"}
        for node in (arg, *_iter_c_nodes_deep_8616(arg))
    )


def test_materialize_callsite_stack_arguments_keeps_nested_indexed_offsets_without_push_sources():
    project = _project()
    _bind_callee_pointer_argument_classifier_8616(project, lambda _project, _name, index: index in {0, 1})
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    outgoing_base = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )

    def _ss_dirty_store(displacement: int, rhs):
        return ss_word_store(codegen, ss_reg, displacement, rhs)

    def _work_offset(index_value: int):
        return structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Shl",
                structured_c.CIndexedVariable(
                    structured_c.CUnaryOp("Reference", outgoing_base, codegen=codegen),
                    structured_c.CConstant(index_value, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CConstant(2892, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    probe = CExpressionStatement(
        CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen
    )
    call = CFunctionCall("Swaps", SimpleNamespace(name="Swaps"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            _ss_dirty_store(-4, _work_offset(6)),
            _ss_dirty_store(-2, _work_offset(8)),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="unknown",
            helper_return_space=None,
            helper_return_width=None,
            helper_return_address_kind="stack",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    final_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert len(final_stmt.expr.args) == 2
    arg_nodes = [(arg, *_iter_c_nodes_deep_8616(arg)) for arg in final_stmt.expr.args]
    stack_offsets = {
        getattr(getattr(node, "variable", None), "offset", None)
        for nodes in arg_nodes
        for node in nodes
        if isinstance(getattr(node, "variable", None), SimStackVariable)
    }
    assert stack_offsets == {-6}
    assert any(
        (getattr(getattr(node, "variable", None), "name", None) or getattr(node, "name", None)) == "s_6"
        for nodes in arg_nodes
        for node in nodes
    )


def test_materialize_callsite_stack_arguments_falls_back_to_recent_dirty_value_carrier():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    row_index = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    ax_6 = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax_6"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ax_7 = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax_7"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    def _ss_dirty_store(displacement: int, rhs):
        return ss_word_store(codegen, ss_reg, displacement, rhs)

    probe = CExpressionStatement(
        CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen
    )
    call = CFunctionCall("DemoCall", SimpleNamespace(name="DemoCall"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(
                CDirtyExpression("vvar_90", codegen=codegen),
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CBinaryOp(
                        "Shl",
                        row_index,
                        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    structured_c.CConstant(2892, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CAssignment(
                ax_7,
                structured_c.CBinaryOp(
                    "Shl",
                    ax_6,
                    structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            _ss_dirty_store(
                -2,
                structured_c.CBinaryOp(
                    "Add",
                    ax_7,
                    structured_c.CConstant(2892, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
            ),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="unknown",
            helper_return_space=None,
            helper_return_width=None,
            helper_return_address_kind="stack",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x2400,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    only_call_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(only_call_stmt, CExpressionStatement)
    assert len(only_call_stmt.expr.args) == 1
    arg = only_call_stmt.expr.args[0]
    assert any(_same_c_expression_8616(node, row_index) for node in (arg, *_iter_c_nodes_deep_8616(arg)))
    assert not any(
        (getattr(getattr(node, "variable", None), "name", None) or getattr(node, "name", None)) in {"ax_6", "ax_7"}
        for node in (arg, *_iter_c_nodes_deep_8616(arg))
    )


def test_materialize_callsite_stack_arguments_prefers_named_dirty_value_carrier_over_placeholder():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    row_index = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    placeholder = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="s_fffa_2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    ax_6 = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax_6"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ax_7 = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax_7"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    def _ss_dirty_store(displacement: int, rhs):
        return ss_word_store(codegen, ss_reg, displacement, rhs)

    probe = CExpressionStatement(
        CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen
    )
    call = CFunctionCall("DemoCall", SimpleNamespace(name="DemoCall"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(
                CDirtyExpression("vvar_91", codegen=codegen),
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CBinaryOp(
                        "Shl",
                        row_index,
                        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    structured_c.CConstant(2892, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CAssignment(
                CDirtyExpression("vvar_92", codegen=codegen),
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CBinaryOp(
                        "Shl",
                        placeholder,
                        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    structured_c.CConstant(2892, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CAssignment(
                ax_7,
                structured_c.CBinaryOp(
                    "Shl",
                    ax_6,
                    structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            _ss_dirty_store(
                -2,
                structured_c.CBinaryOp(
                    "Add",
                    ax_7,
                    structured_c.CConstant(2892, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
            ),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="unknown",
            helper_return_space=None,
            helper_return_width=None,
            helper_return_address_kind="stack",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x2400,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    only_call_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(only_call_stmt, CExpressionStatement)
    arg = only_call_stmt.expr.args[0]
    assert any(_same_c_expression_8616(node, row_index) for node in (arg, *_iter_c_nodes_deep_8616(arg)))
    assert not any(
        (getattr(getattr(node, "variable", None), "name", None) or getattr(node, "name", None)) == "s_fffa_2"
        for node in (arg, *_iter_c_nodes_deep_8616(arg))
    )


def test_materialize_callsite_stack_arguments_accepts_vvar_carrier_store_with_typed_probe_fact():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    outgoing_base = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_11"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Sub",
            carrier,
            structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(
        CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen
    )
    call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(
                carrier,
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CUnaryOp("Reference", outgoing_base, codegen=codegen),
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CAssignment(outgoing, arg_slot, codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
            helper_return_width=2,
            helper_return_address_kind="stack",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    final_stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(final_stmt, CExpressionStatement)
    assert _args_match(final_stmt.expr.args, [arg_slot])


def test_materialize_callsite_stack_arguments_prefers_typed_probe_stores_over_push_arg_sources():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    outgoing_base = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_11"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Sub",
            carrier,
            structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(
        CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen
    )
    call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(
                carrier,
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CUnaryOp("Reference", outgoing_base, codegen=codegen),
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CAssignment(outgoing, arg_slot, codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
            helper_return_width=2,
            helper_return_address_kind="stack",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
            push_arg_sources=(("imm", 3),),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    final_stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(final_stmt, CExpressionStatement)
    assert _args_match(final_stmt.expr.args, [arg_slot])


@pytest.mark.parametrize("matching_value", [False, True])
@pytest.mark.parametrize("instruction", [None, 0x400F, 0x4011])
def test_materialize_callsite_stack_arguments_requires_exact_consumed_push_evidence(matching_value, instruction):
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    outgoing_base = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_11"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing = word_dereference(
        structured_c.CBinaryOp(
            "Sub",
            carrier,
            structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(
        CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen
    )
    call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)
    recorded_value = structured_c.CConstant(3, SimTypeShort(False), codegen=codegen)
    stored_value = recorded_value if matching_value else arg_slot
    store = CAssignment(outgoing, stored_value, tags={"ins_addr": instruction}, codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(
                carrier,
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CUnaryOp("Reference", outgoing_base, codegen=codegen),
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            store,
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="unknown",
            helper_return_space=None,
            helper_return_width=None,
            helper_return_address_kind="stack",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
            push_arg_sources=(("imm", 3),),
            push_arg_instruction_addrs=(0x4011,),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    consumed = matching_value and instruction == 0x4011
    assert (store not in codegen.cfunc.statements.statements) is consumed
    assert codegen.cfunc.statements.statements[0] is probe
    final_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert _args_match(final_stmt.expr.args, [recorded_value])


def test_materialize_callsite_stack_arguments_rematerializes_typed_probe_call_even_with_existing_args():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    outgoing_base = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_11"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    store = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Sub",
            carrier,
            structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(
        CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen
    )
    ds_expr = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ds"][0], 2, name="ds"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall(
        "DrawBar",
        SimpleNamespace(name="DrawBar"),
        [
            CFunctionCall(
                "SEG_PTR",
                None,
                [ds_expr, structured_c.CConstant(3, SimTypeShort(False), codegen=codegen)],
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(
                carrier,
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CUnaryOp("Reference", outgoing_base, codegen=codegen),
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CAssignment(store, arg_slot, codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
            helper_return_width=2,
            helper_return_address_kind="stack",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    final_stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(final_stmt, CExpressionStatement)
    assert _args_match(final_stmt.expr.args, [arg_slot])


def test_materialize_callsite_stack_arguments_allows_temp_carrier_between_store_and_call():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot_a = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iParent", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    arg_slot_b = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing_a = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Mul",
                structured_c.CVariable(
                    SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
                    codegen=codegen,
                ),
                structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Add",
                structured_c.CUnaryOp(
                    "Reference",
                    structured_c.CVariable(
                        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
                        variable_type=SimTypeShort(False),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                structured_c.CConstant(-2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    outgoing_b = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Mul",
                structured_c.CVariable(
                    SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
                    codegen=codegen,
                ),
                structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Add",
                structured_c.CUnaryOp(
                    "Reference",
                    structured_c.CVariable(
                        SimStackVariable(-8, 2, base="bp", name="s_8", region=0x4010),
                        variable_type=SimTypeShort(False),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                structured_c.CConstant(-2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(
        CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen
    )
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_72"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall("SwapBars", SimpleNamespace(name="SwapBars"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(outgoing_a, arg_slot_a, codegen=codegen),
            CAssignment(outgoing_b, arg_slot_b, codegen=codegen),
            CAssignment(
                carrier,
                structured_c.CBinaryOp(
                    "Sub",
                    structured_c.CConstant(0x200, SimTypeShort(False), codegen=codegen),
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_width=2,
            helper_return_address_kind="stack",
            helper_return_state="stack_address",
            helper_return_space="ss",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    final_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert _args_match(final_stmt.expr.args, [arg_slot_b, arg_slot_a])


def test_materialize_callsite_stack_arguments_overrides_conflicting_bp_slot_existing_args():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    i_parent = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="iParent", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    i_value = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    wrong_arg0 = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iMaxLevel", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    wrong_arg1 = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="arg_6", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall("SwapBars", SimpleNamespace(name="SwapBars"), [wrong_arg0, wrong_arg1], codegen=codegen)
    codegen.cfunc.variables_in_use = {
        i_parent.variable: i_parent,
        i_value.variable: i_value,
        wrong_arg0.variable: wrong_arg0,
        wrong_arg1.variable: wrong_arg1,
    }
    codegen.cfunc.statements = CStatements(
        [CExpressionStatement(call, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("bp", -4), ("bp", -2)),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    final_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert _args_match(final_stmt.expr.args, [i_parent, i_value])


def test_materialize_callsite_stack_arguments_respects_push_sources_without_positive_alias_around():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    wrong_arg0 = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iMaxLevel", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    wrong_arg1 = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="arg_6", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    expected_arg0 = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    expected_arg1 = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="local_2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall("SwapBars", SimpleNamespace(name="SwapBars"), [wrong_arg0, wrong_arg1], codegen=codegen)
    codegen.cfunc.variables_in_use = {
        wrong_arg0.variable: wrong_arg0,
        wrong_arg1.variable: wrong_arg1,
        expected_arg0.variable: expected_arg0,
        expected_arg1.variable: expected_arg1,
    }
    for cvar, bp_offset in ((expected_arg0, -2), (expected_arg1, -4)):
        record_stack_variable_coordinate_projection_8616(
            codegen,
            variable=cvar.variable,
            cvar=cvar,
            bp_offset=bp_offset,
            entry_sp_offset=cvar.variable.offset,
            size=2,
        )
    codegen.cfunc.statements = CStatements(
        [CExpressionStatement(call, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("bp", -4), ("bp", -2)),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    final_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert _args_match(final_stmt.expr.args, [expected_arg0, expected_arg1])


def test_materialize_callsite_stack_arguments_overrides_stack_base_existing_arg_from_bp_push_sources():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    i_parent = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="iParent", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    i_value = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    wrong_arg0 = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iMaxLevel", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    wrong_arg1 = structured_c.CIndexedVariable(
        structured_c.CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen),
        structured_c.CConstant(6, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    call = CFunctionCall("SwapBars", SimpleNamespace(name="SwapBars"), [wrong_arg0, wrong_arg1], codegen=codegen)
    codegen.cfunc.variables_in_use = {
        i_parent.variable: i_parent,
        i_value.variable: i_value,
        wrong_arg0.variable: wrong_arg0,
    }
    codegen.cfunc.statements = CStatements(
        [CExpressionStatement(call, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("bp", -4), ("bp", -2)),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    final_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert _args_match(final_stmt.expr.args, [i_parent, i_value])


def test_materialize_callsite_stack_arguments_overrides_plain_stack_base_existing_arg_from_bp_push_sources():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    i_parent = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="iParent", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    i_value = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    wrong_arg0 = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iMaxLevel", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    wrong_arg1 = structured_c.CVariable(
        structured_c.CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall("SwapBars", SimpleNamespace(name="SwapBars"), [wrong_arg0, wrong_arg1], codegen=codegen)
    codegen.cfunc.variables_in_use = {
        i_parent.variable: i_parent,
        i_value.variable: i_value,
        wrong_arg0.variable: wrong_arg0,
    }
    codegen.cfunc.statements = CStatements(
        [CExpressionStatement(call, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("bp", -4), ("bp", -2)),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    final_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert _args_match(final_stmt.expr.args, [i_parent, i_value])


def test_materialize_callsite_stack_arguments_scans_past_value_assignments_between_stores():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot_a = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iParent", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    arg_slot_b = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_11"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier_next = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["bx"][0], 2, name="vvar_65"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier_after = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["cx"][0], 2, name="vvar_72"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ax_7 = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax_7"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ax_8 = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax_8"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    def _ss_store(offset_expr):
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CBinaryOp(
                "Add",
                structured_c.CBinaryOp(
                    "Shl",
                    ss_reg,
                    structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                offset_expr,
                codegen=codegen,
            ),
            codegen=codegen,
        )

    probe = CExpressionStatement(
        CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen
    )
    call = CFunctionCall("Swaps", SimpleNamespace(name="Swaps"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(
                _ss_store(
                    structured_c.CBinaryOp(
                        "Sub",
                        carrier,
                        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    )
                ),
                arg_slot_a,
                codegen=codegen,
            ),
            CAssignment(
                carrier_next,
                structured_c.CBinaryOp(
                    "Sub",
                    carrier,
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CAssignment(ax_7, structured_c.CConstant(3, SimTypeShort(False), codegen=codegen), codegen=codegen),
            CAssignment(
                ax_8,
                structured_c.CBinaryOp(
                    "Shl",
                    ax_7,
                    structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CAssignment(
                _ss_store(
                    structured_c.CBinaryOp(
                        "Sub",
                        carrier_next,
                        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    )
                ),
                arg_slot_b,
                codegen=codegen,
            ),
            CAssignment(
                carrier_after,
                structured_c.CBinaryOp(
                    "Sub",
                    carrier_next,
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CExpressionStatement(call, codegen=codegen),
            CReturn(carrier_after, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_width=2,
            helper_return_address_kind="stack",
            helper_return_state="stack_address",
            helper_return_space="ss",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    final_stmt = next(
        stmt
        for stmt in codegen.cfunc.statements.statements
        if isinstance(stmt, CExpressionStatement) and stmt.expr is call
    )
    assert isinstance(final_stmt, CExpressionStatement)
    assert len(final_stmt.expr.args) == 2
    assert carrier_next in [getattr(stmt, "lhs", None) for stmt in codegen.cfunc.statements.statements]
    assert carrier_after in [getattr(stmt, "lhs", None) for stmt in codegen.cfunc.statements.statements]
    assert ax_7 in [getattr(stmt, "lhs", None) for stmt in codegen.cfunc.statements.statements]
    assert ax_8 in [getattr(stmt, "lhs", None) for stmt in codegen.cfunc.statements.statements]
    assert codegen._inertia_callsite_materialization_stats.live_setup_definition_preserved_count == 1


def test_materialize_callsite_stack_arguments_refuses_name_only_probe_summary_upgrade():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot_a = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iParent", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    arg_slot_b = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_11"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier_next = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["bx"][0], 2, name="vvar_65"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier_after = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["cx"][0], 2, name="vvar_72"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    def _ss_store(offset_expr):
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CBinaryOp(
                "Add",
                structured_c.CBinaryOp(
                    "Shl",
                    ss_reg,
                    structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                offset_expr,
                codegen=codegen,
            ),
            codegen=codegen,
        )

    probe = CExpressionStatement(
        CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen
    )
    call = CFunctionCall("Swaps", SimpleNamespace(name="Swaps"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(
                _ss_store(
                    structured_c.CBinaryOp(
                        "Sub",
                        carrier,
                        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    )
                ),
                arg_slot_a,
                codegen=codegen,
            ),
            CAssignment(
                carrier_next,
                structured_c.CBinaryOp(
                    "Sub",
                    carrier,
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CAssignment(
                _ss_store(
                    structured_c.CBinaryOp(
                        "Sub",
                        carrier_next,
                        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    )
                ),
                arg_slot_b,
                codegen=codegen,
            ),
            CAssignment(
                carrier_after,
                structured_c.CBinaryOp(
                    "Sub",
                    carrier_next,
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_width=2,
            helper_return_address_kind="stack",
            helper_return_state="stack_address",
            helper_return_space="ss",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    final_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert _args_match(final_stmt.expr.args, [arg_slot_b])
    assert codegen._inertia_callsite_summaries[id(call)].arg_count == 1
    assert codegen._inertia_callsite_summaries[id(call)].arg_widths == (2,)


def test_materialize_callsite_stack_arguments_refuses_conflicting_physical_and_logical_arity():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    arg_slot0 = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    arg_slot1 = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="i_2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    arg_expr0 = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    arg_expr1 = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="i_2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall("SwapBars", SimpleNamespace(name="SwapBars"), [], codegen=codegen)
    call_stmt = CExpressionStatement(call, codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(arg_slot0, arg_expr0, codegen=codegen),
            CAssignment(arg_slot1, arg_expr1, codegen=codegen),
            call_stmt,
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("bp", -4), ("bp", -2)),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is False
    assert len(codegen.cfunc.statements.statements) == 3
    final_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert final_stmt.expr.args == []
    assert codegen._inertia_callsite_summaries[id(call)].arg_count == 1
    assert codegen._inertia_callsite_summaries[id(call)].arg_widths == (2,)


def test_materialize_callsite_stack_arguments_carries_probe_evidence_into_loop_body():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iParent", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    stack_carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_11"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing = word_dereference(
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Shl",
                ss_reg,
                structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Sub",
                stack_carrier,
                structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(
        CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen
    )
    call = CFunctionCall("Swaps", SimpleNamespace(name="Swaps"), [], codegen=codegen)
    loop_body = CStatements(
        [
            CAssignment(outgoing, arg_slot, codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4020,
        codegen=codegen,
    )
    loop = CForLoop(None, None, None, loop_body, codegen=codegen)
    codegen.cfunc.statements = CStatements([probe, loop], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=None,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(loop_body.statements) == 1
    final_stmt = loop_body.statements[0]
    assert isinstance(final_stmt, CExpressionStatement)
    assert len(final_stmt.expr.args) == 1
    assert codegen._inertia_callsite_summaries[id(call)].arg_count == 1
    assert codegen._inertia_callsite_summaries[id(call)].arg_widths == (2,)


def test_materialize_callsite_stack_arguments_does_not_delete_loop_for_nested_ss_return_store():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    probe = CExpressionStatement(
        CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen),
        codegen=codegen,
    )
    loop_body = CStatements(
        [_ss_sp_stack_store(codegen, project, 2, ss_reg)],
        addr=0x4020,
        codegen=codegen,
    )
    loop = CForLoop(None, None, None, loop_body, codegen=codegen)
    codegen.cfunc.statements = CStatements([probe, loop], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {}

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert any(isinstance(node, CForLoop) for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements))
    assert codegen.cfunc.statements.statements == [loop]


def test_materialize_callsite_stack_arguments_does_not_promote_segment_carrier_as_arg():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    cs_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["cs"][0], 2, name="cs"),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    stack_carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_31"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Shl",
                ss_reg,
                structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            stack_carrier,
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(
        CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen
    )
    call = CFunctionCall("RunMenu", SimpleNamespace(name="RunMenu"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(outgoing, cs_reg, codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is False
    assert call.args == []


def test_materialize_callsite_stack_arguments_skips_segment_metadata_store():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    zero_arg = structured_c.CConstant(0, SimTypeShort(False), codegen=codegen)
    cs_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["cs"][0], 2, name="cs"),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    stack_carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_31"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    stack_carrier_next = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["bx"][0], 2, name="vvar_33"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    def _ss_store(offset_expr):
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CBinaryOp(
                "Add",
                structured_c.CBinaryOp(
                    "Shl",
                    ss_reg,
                    structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                offset_expr,
                codegen=codegen,
            ),
            codegen=codegen,
        )

    probe = CExpressionStatement(
        CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen
    )
    call = CFunctionCall("clearscreen", SimpleNamespace(name="clearscreen"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(
                _ss_store(
                    structured_c.CBinaryOp(
                        "Sub",
                        stack_carrier,
                        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    )
                ),
                zero_arg,
                codegen=codegen,
            ),
            CAssignment(
                stack_carrier_next,
                structured_c.CBinaryOp(
                    "Sub",
                    stack_carrier,
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CAssignment(
                _ss_store(
                    structured_c.CBinaryOp(
                        "Sub",
                        stack_carrier_next,
                        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    )
                ),
                cs_reg,
                codegen=codegen,
            ),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_width=2,
            helper_return_address_kind="stack",
            helper_return_state="stack_address",
            helper_return_space="ss",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert _args_match(call.args, [zero_arg])


def test_materialize_callsite_stack_arguments_refuses_unnamed_segment_register_arg():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    cs_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["cs"][0], 2, name=None),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name=None),
        codegen=codegen,
    )
    stack_carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_31"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Shl",
                ss_reg,
                structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            stack_carrier,
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(
        CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen
    )
    call = CFunctionCall("RunMenu", SimpleNamespace(name="RunMenu"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(outgoing, cs_reg, codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is False
    assert call.args == []


def test_materialize_callsite_prototypes_keeps_materialized_stack_probe_args_visible():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    callee = SimpleNamespace(name="DrawBar", prototype=None, is_prototype_guessed=False)
    call = CFunctionCall("DrawBar", callee, [arg_slot], codegen=codegen)
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        )
    }

    changed = _materialize_callsite_prototypes_8616(project, codegen)

    assert changed is False
    assert getattr(callee, "prototype", None) is None


def test_materialize_callsite_stack_arguments_clears_known_zero_arg_helper_args():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    call = CFunctionCall(
        "clock",
        SimpleNamespace(name="clock", prototype=None, is_prototype_guessed=False),
        [
            structured_c.CConstant(45, SimTypeShort(False), codegen=codegen),
            structured_c.CConstant(14, SimTypeShort(False), codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert call.args == []
    assert codegen._inertia_callsite_summaries[id(call)].arg_count == 0
    assert codegen._inertia_callsite_summaries[id(call)].arg_widths == ()


def test_callsite_materialization_preserves_structured_insert_intrinsic_arguments():
    project = _project()
    codegen = _empty_codegen(project)
    args = [
        CConstant(0x1234, SimTypeShort(False), codegen=codegen),
        CConstant(0, SimTypeShort(False), codegen=codegen),
        CConstant(0x56, SimTypeChar(False), codegen=codegen),
    ]
    insert = CFunctionCall("_INSERT", None, list(args), codegen=codegen)
    lhs = CVariable(
        SimRegisterVariable(0, 2, ident=7, region=0x4010, name="ax"),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [CAssignment(lhs, insert, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is False
    assert insert.args == args
    assert codegen._inertia_callsite_structured_intrinsic_refusal_count_8616 == 1


def test_materialize_callsite_stack_arguments_handles_tuple_statement_blocks():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Mul",
                structured_c.CVariable(
                    SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
                    codegen=codegen,
                ),
                structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Add",
                structured_c.CUnaryOp(
                    "Reference",
                    structured_c.CVariable(
                        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
                        variable_type=SimTypeShort(False),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                structured_c.CConstant(-2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen)
    call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        (
            probe,
            CAssignment(outgoing, arg_slot, codegen=codegen),
            call,
        ),
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {}

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    final_call = codegen.cfunc.statements.statements[1]
    assert isinstance(final_call, CFunctionCall)
    assert _args_match(final_call.args, [arg_slot])


def test_materialize_callsite_stack_arguments_accepts_ss_shift_linear_store_shape():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Shl",
                ss_reg,
                structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Sub",
                structured_c.CVariable(
                    SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
                    variable_type=SimTypeShort(False),
                    codegen=codegen,
                ),
                structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(
        CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen
    )
    call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [probe, CAssignment(outgoing, arg_slot, codegen=codegen), CExpressionStatement(call, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_width=2,
            helper_return_address_kind="stack",
            helper_return_state="stack_address",
            helper_return_space="ss",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=None,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    assert codegen.cfunc.statements.statements[0] is probe
    final_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert _args_match(final_stmt.expr.args, [arg_slot])


def test_materialize_callsite_stack_arguments_refuses_dirty_probe_offset_store_shape():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Shl",
                ss_reg,
                structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Sub",
                CDirtyExpression("probe_ret", codegen=codegen),
                structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(
        CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen
    )
    call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [probe, CAssignment(outgoing, arg_slot, codegen=codegen), CExpressionStatement(call, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_width=2,
            helper_return_address_kind="stack",
            helper_return_state="stack_address",
            helper_return_space="ss",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is False
    assert call.args == []
    assert len(codegen.cfunc.statements.statements) == 3


def test_materialize_callsite_stack_arguments_extracts_inline_store_before_call_from_cstatements_wrapper():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    def _ss_store(rhs_expr):
        return CAssignment(
            structured_c.CUnaryOp(
                "Dereference",
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CBinaryOp(
                        "Mul",
                        structured_c.CVariable(
                            SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
                            codegen=codegen,
                        ),
                        structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    structured_c.CBinaryOp(
                        "Add",
                        structured_c.CUnaryOp(
                            "Reference",
                            structured_c.CVariable(
                                SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
                                variable_type=SimTypeShort(False),
                                codegen=codegen,
                            ),
                            codegen=codegen,
                        ),
                        structured_c.CConstant(-2, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            rhs_expr,
            codegen=codegen,
        )

    probe_call = CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen)
    drawbar_call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)
    drawtime_call = CFunctionCall("DrawTime", SimpleNamespace(name="DrawTime"), [], codegen=codegen)
    irow2 = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="iRow2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    irow1 = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    codegen.cfunc.statements = CStatements(
        [
            CStatements([CExpressionStatement(probe_call, codegen=codegen)], codegen=codegen),
            CStatements([_ss_store(irow2), CExpressionStatement(drawbar_call, codegen=codegen)], codegen=codegen),
            CStatements([_ss_store(irow1), CExpressionStatement(drawtime_call, codegen=codegen)], codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe_call): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
            helper_return_width=2,
            helper_return_address_kind="stack",
        ),
        id(drawbar_call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
        id(drawtime_call): CallsiteSummary8616(
            callsite_addr=0x4016,
            target_addr=0x1550,
            return_addr=0x4019,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    wrapped_drawbar = codegen.cfunc.statements.statements[1]
    wrapped_drawtime = codegen.cfunc.statements.statements[2]
    assert isinstance(wrapped_drawbar, CStatements)
    assert isinstance(wrapped_drawtime, CStatements)
    assert len(wrapped_drawbar.statements) == 1
    assert len(wrapped_drawtime.statements) == 1
    assert isinstance(wrapped_drawbar.statements[0], CExpressionStatement)
    assert isinstance(wrapped_drawtime.statements[0], CExpressionStatement)
    assert _args_match(wrapped_drawbar.statements[0].expr.args, [irow2])
    assert _args_match(wrapped_drawtime.statements[0].expr.args, [irow1])


def test_materialize_callsite_stack_arguments_consumes_repeated_value_carrier_assignments():
    project = _project()
    _bind_callee_pointer_argument_classifier_8616(project, lambda _project, _name, index: index in {0, 1})
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_31"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    second_arg = structured_c.CBinaryOp(
        "Add",
        structured_c.CConstant(0x0B4C, SimTypeShort(False), codegen=codegen),
        structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    first_arg = structured_c.CBinaryOp(
        "Add",
        structured_c.CConstant(0x0B4C, SimTypeShort(False), codegen=codegen),
        structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    call = CFunctionCall("Swaps", SimpleNamespace(name="Swaps"), [], codegen=codegen)

    codegen.cfunc.statements = CStatements(
        [
            CStatements(
                [
                    CAssignment(carrier, second_arg, codegen=codegen),
                    CAssignment(carrier, first_arg, codegen=codegen),
                    CExpressionStatement(call, codegen=codegen),
                ],
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1794,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    wrapped = codegen.cfunc.statements.statements[0]
    assert isinstance(wrapped, CStatements)
    assert len(wrapped.statements) == 1
    assert isinstance(wrapped.statements[0], CExpressionStatement)
    assert len(wrapped.statements[0].expr.args) == 2
    assert wrapped.statements[0].expr.args[0].callee_target == "SEG_PTR"
    assert wrapped.statements[0].expr.args[1].callee_target == "SEG_PTR"
    first_offset = wrapped.statements[0].expr.args[0].args[1]
    second_offset = wrapped.statements[0].expr.args[1].args[1]
    assert any(getattr(node, "value", None) == 0x0B4C for node in _iter_c_nodes_deep_8616(first_offset))
    assert any(getattr(node, "value", None) == 8 for node in _iter_c_nodes_deep_8616(first_offset))
    assert any(getattr(node, "value", None) == 0x0B4C for node in _iter_c_nodes_deep_8616(second_offset))
    assert any(getattr(node, "value", None) == 4 for node in _iter_c_nodes_deep_8616(second_offset))


def test_materialize_callsite_stack_arguments_consumes_trailing_store_after_previous_call_wrapper():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    def _ss_store(rhs_expr):
        return CAssignment(
            structured_c.CUnaryOp(
                "Dereference",
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CBinaryOp(
                        "Mul",
                        structured_c.CVariable(
                            SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
                            codegen=codegen,
                        ),
                        structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    structured_c.CBinaryOp(
                        "Add",
                        structured_c.CUnaryOp(
                            "Reference",
                            structured_c.CVariable(
                                SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
                                variable_type=SimTypeShort(False),
                                codegen=codegen,
                            ),
                            codegen=codegen,
                        ),
                        structured_c.CConstant(-2, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            rhs_expr,
            codegen=codegen,
        )

    irow = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRowTmp", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_82"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier_value = structured_c.CBinaryOp(
        "Add",
        structured_c.CConstant(0x0B4A, SimTypeShort(False), codegen=codegen),
        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    probe_call = CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen)
    drawbar_call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [irow], codegen=codegen)
    drawtime_call = CFunctionCall("DrawTime", SimpleNamespace(name="DrawTime"), [], codegen=codegen)

    codegen.cfunc.statements = CStatements(
        [
            CStatements([CExpressionStatement(probe_call, codegen=codegen)], codegen=codegen),
            CStatements(
                [
                    CExpressionStatement(drawbar_call, codegen=codegen),
                    CAssignment(carrier, carrier_value, codegen=codegen),
                    _ss_store(irow),
                ],
                codegen=codegen,
            ),
            CExpressionStatement(drawtime_call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe_call): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
            helper_return_width=2,
            helper_return_address_kind="stack",
        ),
        id(drawtime_call): CallsiteSummary8616(
            callsite_addr=0x4016,
            target_addr=0x1550,
            return_addr=0x4019,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert _args_match(drawtime_call.args, [irow])


@pytest.mark.parametrize("call_shell", ["assignment", "return"])
def test_materialize_callsite_stack_arguments_handles_wrapped_call(call_shell):
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    def _ss_store(rhs_expr):
        return CAssignment(
            structured_c.CUnaryOp(
                "Dereference",
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CBinaryOp(
                        "Mul",
                        structured_c.CVariable(
                            SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
                            codegen=codegen,
                        ),
                        structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    structured_c.CBinaryOp(
                        "Add",
                        structured_c.CUnaryOp(
                            "Reference",
                            structured_c.CVariable(
                                SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
                                variable_type=SimTypeShort(False),
                                codegen=codegen,
                            ),
                            codegen=codegen,
                        ),
                        structured_c.CConstant(-2, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            rhs_expr,
            codegen=codegen,
        )

    irow = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRowTmp", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    result_var = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax_5"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    drawtime_call = CFunctionCall("DrawTime", SimpleNamespace(name="DrawTime"), [], codegen=codegen)

    wrapped_call = (
        CAssignment(result_var, drawtime_call, codegen=codegen)
        if call_shell == "assignment"
        else CReturn(drawtime_call, codegen=codegen)
    )
    codegen.cfunc.statements = CStatements([_ss_store(irow), wrapped_call], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(drawtime_call): CallsiteSummary8616(
            callsite_addr=0x4016,
            target_addr=0x1550,
            return_addr=0x4019,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register="ax",
            return_used=True,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert _args_match(drawtime_call.args, [irow])


def test_materialize_callsite_stack_arguments_consumes_inline_stack_placeholder_assignment_before_call():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    irow1 = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    vvar_2 = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_2"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing_slot = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="s_2_2_2_2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)

    codegen.cfunc.statements = CStatements(
        [
            CStatements(
                [
                    CAssignment(vvar_2, irow1, codegen=codegen),
                    CAssignment(
                        outgoing_slot,
                        CDirtyExpression(SimpleNamespace(varid=2, name="vvar_2"), codegen=codegen),
                        codegen=codegen,
                    ),
                    CExpressionStatement(call, codegen=codegen),
                ],
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    wrapped = codegen.cfunc.statements.statements[0]
    assert isinstance(wrapped, CStatements)
    assert isinstance(wrapped.statements[-1], CExpressionStatement)
    assert len(wrapped.statements[-1].expr.args) == 1
    arg0 = wrapped.statements[-1].expr.args[0]
    assert getattr(getattr(arg0, "variable", None), "name", None) == "iRow1"


def test_materialize_callsite_stack_arguments_refuses_return_frame_placeholder_as_argument():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    probe_call = CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen)
    target_call = CFunctionCall("InitBars", SimpleNamespace(name="InitBars"), [], codegen=codegen)
    outgoing_slot = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="outgoing", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CExpressionStatement(probe_call, codegen=codegen),
            CAssignment(
                outgoing_slot,
                structured_c.CConstant(0x4015, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            CExpressionStatement(target_call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe_call): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
            helper_return_width=2,
            helper_return_address_kind="stack",
        ),
        id(target_call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=None,
            return_register=None,
            return_used=False,
        ),
    }

    original_statements = tuple(codegen.cfunc.statements.statements)
    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    # Coincidence with a return address does not prove this store is dead.
    assert changed is False
    assert target_call.args == []
    assert tuple(codegen.cfunc.statements.statements) == original_statements
    assert codegen.cfunc.statements.statements[-1].expr is target_call


def test_materialize_callsite_stack_arguments_prefers_bp_push_source_metadata_for_real_arg():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    irow1 = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing_bp0 = structured_c.CVariable(
        SimStackVariable(0, 2, base="bp", name="arg_1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing_slot = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="s_2_2_2_2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)

    codegen.cfunc.statements = CStatements(
        [
            CStatements(
                [
                    CAssignment(outgoing_bp0, irow1, codegen=codegen),
                    CAssignment(outgoing_slot, outgoing_bp0, codegen=codegen),
                    CExpressionStatement(call, codegen=codegen),
                ],
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
            push_arg_sources=(("bp", 4),),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    wrapped = codegen.cfunc.statements.statements[0]
    assert isinstance(wrapped, CStatements)
    assert isinstance(wrapped.statements[-1], CExpressionStatement)
    assert len(wrapped.statements[-1].expr.args) == 1
    arg0 = wrapped.statements[-1].expr.args[0]
    assert getattr(getattr(arg0, "variable", None), "name", None) == "iRow1"


def test_materialize_callsite_stack_arguments_projects_positive_bp_high_byte_source():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    frequency_slot = SimStackVariable(4, 2, base="bp", name="frequency", region=0x4010)
    frequency_var = structured_c.CVariable(
        frequency_slot,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {frequency_slot: frequency_var}
    codegen.cfunc.unified_local_vars = {frequency_slot: {(frequency_var, frequency_var.variable_type)}}
    call = CFunctionCall("outp", SimpleNamespace(name="outp"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("bp", 5), ("imm", 66)),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(call.args) == 2
    assert getattr(call.args[0], "value", None) == 66
    high_byte = call.args[1]
    assert isinstance(high_byte, structured_c.CBinaryOp)
    assert high_byte.op == "Shr"
    assert getattr(getattr(high_byte.lhs, "variable", None), "name", None) == "frequency"
    assert getattr(high_byte.rhs, "value", None) == 8


def test_materialize_callsite_stack_arguments_keeps_exact_imm_push_source_over_return_frame_store():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    frame_slot = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall("classify", SimpleNamespace(name="classify"), [], codegen=codegen)

    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                frame_slot,
                structured_c.CConstant(0x012D, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x10010,
            return_addr=0x012D,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
            push_arg_sources=(("imm", 0xFFFC),),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    call_arg = call.args[0]
    assert isinstance(call_arg, structured_c.CConstant)
    assert call_arg.value == 0xFFFC


def test_materialize_callsite_stack_arguments_prunes_proven_local_expr_push_setup_assignment():
    project = _project_with_bytes(0x1058, b"\x8b\x46\xfe\x05\x02\x00\x50")
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    i_slot = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    i_var = structured_c.CVariable(i_slot, variable_type=SimTypeShort(False), codegen=codegen)
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_1123"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    row_arg = structured_c.CBinaryOp(
        "Add",
        i_var,
        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    col_arg = structured_c.CConstant(48, SimTypeShort(False), codegen=codegen)
    call = CFunctionCall("settextposition", SimpleNamespace(name="settextposition"), [row_arg, col_arg], codegen=codegen)

    setup = CAssignment(i_var, carrier, codegen=codegen, tags={"ins_addr": 0x105E})
    codegen.cfunc.statements = CStatements(
        [setup, CExpressionStatement(call, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x105F,
            target_addr=0x128E4,
            return_addr=0x1064,
            kind="direct_far",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("imm", 48), ("expr", ("bp", -2), ((CallsitePushExprOp8616.ADD.value, 2),))),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == [codegen.cfunc.statements.statements[0]]
    assert codegen.cfunc.statements.statements[0].expr is call
    assert call.args == [row_arg, col_arg]


def test_materialize_callsite_stack_arguments_prunes_exact_direct_bp_push_alias_assignment():
    project = _project_with_bytes(0x105E, b"\xff\x76\xfe\xff\x76\xfa")
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    down_slot = SimStackVariable(-2, 2, base="bp", name="iDown", region=0x4010)
    down_var = structured_c.CVariable(down_slot, variable_type=SimTypeShort(False), codegen=codegen)
    up_slot = SimStackVariable(-6, 2, base="bp", name="iUp", region=0x4010)
    up_var = structured_c.CVariable(up_slot, variable_type=SimTypeShort(False), codegen=codegen)
    high_slot = SimStackVariable(6, 2, base="bp", name="iHigh", region=0x4010)
    high_var = structured_c.CVariable(high_slot, variable_type=SimTypeShort(False), codegen=codegen)
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_1215"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall("consume", SimpleNamespace(name="consume"), [high_var, up_var], codegen=codegen)
    # The regenerated destination is stale: this tag belongs to push [bp-6],
    # which cannot write iDown regardless of the assignment's rendered shape.
    setup = CAssignment(down_var, carrier, codegen=codegen, tags={"ins_addr": 0x1061})
    codegen.cfunc.statements = CStatements(
        [setup, CExpressionStatement(call, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x1064,
            target_addr=0x128E4,
            return_addr=0x1067,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("bp", 6), ("bp", -6)),
            push_arg_instruction_addrs=(0x105E, 0x1061),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    statements = list(codegen.cfunc.statements.statements)
    assert len(statements) == 1
    assert statements[0].expr is call
    assert len(call.args) == 2
    assert [arg.variable.offset for arg in call.args] == [-6, 6]


def test_materialize_callsite_stack_arguments_keeps_unproved_local_expr_setup_assignment():
    project = _project_with_bytes(0x105A, b"\xc7\x46\xfe\x02\x00")
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    i_slot = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    i_var = structured_c.CVariable(i_slot, variable_type=SimTypeShort(False), codegen=codegen)
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_1123"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    row_arg = structured_c.CBinaryOp(
        "Add",
        i_var,
        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    col_arg = structured_c.CConstant(48, SimTypeShort(False), codegen=codegen)
    call = CFunctionCall("settextposition", SimpleNamespace(name="settextposition"), [row_arg, col_arg], codegen=codegen)

    setup = CAssignment(i_var, carrier, codegen=codegen, tags={"ins_addr": 0x105E})
    codegen.cfunc.statements = CStatements(
        [setup, CExpressionStatement(call, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x105F,
            target_addr=0x128E4,
            return_addr=0x1064,
            kind="direct_far",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("imm", 48), ("expr", ("bp", -2), ((CallsitePushExprOp8616.ADD.value, 2),))),
        ),
    }

    _materialize_callsite_stack_arguments_8616(project, codegen)

    assert codegen.cfunc.statements.statements[0] is setup


def test_materialize_callsite_stack_arguments_prunes_proven_local_immediate_push_setup_assignment():
    project = _project_with_bytes(0x105B, b"\xb8\x30\x00\x50")
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    i_slot = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    i_var = structured_c.CVariable(i_slot, variable_type=SimTypeShort(False), codegen=codegen)
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_1115"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    row_arg = structured_c.CBinaryOp(
        "Add",
        i_var,
        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    col_arg = structured_c.CConstant(48, SimTypeShort(False), codegen=codegen)
    call = CFunctionCall("settextposition", SimpleNamespace(name="settextposition"), [row_arg, col_arg], codegen=codegen)

    setup = CAssignment(i_var, carrier, codegen=codegen, tags={"ins_addr": 0x105E})
    codegen.cfunc.statements = CStatements(
        [setup, CExpressionStatement(call, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x105F,
            target_addr=0x128E4,
            return_addr=0x1064,
            kind="direct_far",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("imm", 48), ("expr", ("bp", -2), ((CallsitePushExprOp8616.ADD.value, 2),))),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == [codegen.cfunc.statements.statements[0]]
    assert codegen.cfunc.statements.statements[0].expr is call
    assert call.args == [row_arg, col_arg]


def test_materialize_callsite_stack_arguments_keeps_unproved_local_immediate_setup_assignment():
    project = _project_with_bytes(0x105A, b"\xc7\x46\xfe\x30\x00")
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    i_slot = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    i_var = structured_c.CVariable(i_slot, variable_type=SimTypeShort(False), codegen=codegen)
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_1115"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    row_arg = structured_c.CBinaryOp(
        "Add",
        i_var,
        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    col_arg = structured_c.CConstant(48, SimTypeShort(False), codegen=codegen)
    call = CFunctionCall("settextposition", SimpleNamespace(name="settextposition"), [row_arg, col_arg], codegen=codegen)

    setup = CAssignment(i_var, carrier, codegen=codegen, tags={"ins_addr": 0x105E})
    codegen.cfunc.statements = CStatements(
        [setup, CExpressionStatement(call, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x105F,
            target_addr=0x128E4,
            return_addr=0x1064,
            kind="direct_far",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("imm", 48), ("expr", ("bp", -2), ((CallsitePushExprOp8616.ADD.value, 2),))),
        ),
    }

    _materialize_callsite_stack_arguments_8616(project, codegen)

    assert codegen.cfunc.statements.statements[0] is setup


def test_materialize_callsite_stack_arguments_projected_positive_bp_source_uses_local_name():
    project = _project()
    codegen = _empty_codegen(project)

    local = CVariable(
        SimStackVariable(4, 2, base="bp", name="local_2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {local.variable: local}
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=local.variable,
        cvar=local,
        bp_offset=4,
        entry_sp_offset=4,
        size=2,
    )

    call = CFunctionCall("sortproc", SimpleNamespace(name="sortproc"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
            push_arg_sources=(("bp", 4),),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    final_stmt = codegen.cfunc.statements.statements[-1]
    if isinstance(final_stmt, CExpressionStatement):
        call_stmt = final_stmt
    elif isinstance(final_stmt, CStatements):
        call_stmt = final_stmt.statements[-1]
    else:
        raise AssertionError(type(final_stmt))
    assert isinstance(call_stmt, CExpressionStatement)
    assert len(call_stmt.expr.args) == 1
    arg0 = call_stmt.expr.args[0]
    assert getattr(getattr(arg0, "variable", None), "name", None) == "local_2"


def test_materialize_callsite_stack_arguments_known_positive_bp_source_keeps_arg_name():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    known_arg = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="arg_2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.arg_list = [known_arg]

    call = CFunctionCall("sortproc", SimpleNamespace(name="sortproc"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
            push_arg_sources=(("bp", 4),),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    final_stmt = codegen.cfunc.statements.statements[-1]
    if isinstance(final_stmt, CExpressionStatement):
        call_stmt = final_stmt
    elif isinstance(final_stmt, CStatements):
        call_stmt = final_stmt.statements[-1]
    else:
        raise AssertionError(type(final_stmt))
    assert isinstance(call_stmt, CExpressionStatement)
    assert len(call_stmt.expr.args) == 1
    arg0 = call_stmt.expr.args[0]
    assert getattr(getattr(arg0, "variable", None), "name", None) == "arg_2"


def test_materialize_callsite_stack_arguments_keeps_stack_value_arithmetic_as_value():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    i_slot = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    i_var = structured_c.CVariable(i_slot, variable_type=SimTypeShort(False), codegen=codegen)
    stale_slot = SimStackVariable(-3, 2, base="bp", name="i", region=0x4010)
    stale_var = structured_c.CVariable(stale_slot, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use = {i_slot: i_var, stale_slot: stale_var}
    codegen.cfunc.unified_local_vars = {
        i_slot: {(i_var, SimTypeShort(False))},
        stale_slot: {(stale_var, SimTypeShort(False))},
    }
    call = CFunctionCall("PercolateDown", SimpleNamespace(name="PercolateDown"), [stale_var], codegen=codegen)
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x10A61,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
            push_arg_sources=(("expr", ("bp", -2), (("sub", 1),)),),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    arg = call.args[0]
    assert isinstance(arg, structured_c.CBinaryOp)
    assert arg.op == "Sub"
    assert getattr(arg.lhs.variable, "offset", None) == -2
    assert arg.rhs.value == 1


def test_materialize_callsite_stack_arguments_preserves_verified_arithmetic_push_sources_on_repeat_pass():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    low_slot = SimStackVariable(4, 2, base="bp", name="arg_4", region=0x4010)
    pivot_slot = SimStackVariable(-6, 2, base="bp", name="local_6", region=0x4010)
    low_var = structured_c.CVariable(low_slot, variable_type=SimTypeShort(False), codegen=codegen)
    pivot_var = structured_c.CVariable(pivot_slot, variable_type=SimTypeShort(False), codegen=codegen)
    pivot_minus_one = structured_c.CBinaryOp(
        "Sub",
        pivot_var,
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {low_slot: low_var, pivot_slot: pivot_var}
    codegen.cfunc.unified_local_vars = {
        low_slot: {(low_var, SimTypeShort(False))},
        pivot_slot: {(pivot_var, SimTypeShort(False))},
    }
    call = CFunctionCall(
        "QuickSort",
        SimpleNamespace(name="QuickSort"),
        [low_var, pivot_minus_one],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x10CE0,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(
                ("expr", ("bp", -6), ((CallsitePushExprOp8616.SUB.value, 1),)),
                ("bp", 4),
            ),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is False
    assert call.args == [low_var, pivot_minus_one]


def test_materialize_callsite_stack_arguments_restores_duplicate_arithmetic_arg_from_exact_push_source():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    row_slot = SimStackVariable(-2, 2, base="bp", name="iRow", region=0x4010)
    row_var = structured_c.CVariable(row_slot, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use = {row_slot: row_var}
    codegen.cfunc.unified_local_vars = {
        row_slot: {(row_var, SimTypeShort(False))},
    }
    row_count_slot = SimMemoryVariable(0x0B48, 2, name="cRow")
    row_count_var = structured_c.CVariable(
        row_count_slot,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    stale_pointer_arg = CFunctionCall(
        "MK_FP",
        None,
        [
            row_count_var,
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        ],
        codegen=codegen,
    )
    call = CFunctionCall(
        "SwapBars",
        SimpleNamespace(name="SwapBars"),
        [row_var, stale_pointer_arg],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [CExpressionStatement(call, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4067,
            target_addr=0x10768,
            return_addr=0x406A,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register="ax",
            return_used=False,
            push_arg_sources=(
                ("expr", ("bp", -2), ((CallsitePushExprOp8616.ADD.value, 1),)),
                ("bp", -2),
            ),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(call.args) == 2
    assert call.args[0].variable.offset == -2
    incremented_row = call.args[1]
    assert isinstance(incremented_row, structured_c.CBinaryOp)
    assert incremented_row.op == "Add"
    assert incremented_row.lhs.variable.offset == -2
    assert incremented_row.rhs.value == 1


def test_materialize_missing_quicksort_args_preserves_arithmetic_push_source():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    low_slot = SimStackVariable(4, 2, base="bp", name="arg_4", region=0x4010)
    pivot_slot = SimStackVariable(-6, 2, base="bp", name="local_6", region=0x4010)
    low_var = structured_c.CVariable(low_slot, variable_type=SimTypeShort(False), codegen=codegen)
    pivot_var = structured_c.CVariable(pivot_slot, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use = {low_slot: low_var, pivot_slot: pivot_var}
    codegen.cfunc.unified_local_vars = {
        low_slot: {(low_var, SimTypeShort(False))},
        pivot_slot: {(pivot_var, SimTypeShort(False))},
    }
    call = CFunctionCall("QuickSort", SimpleNamespace(name="QuickSort"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x10CE0,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(
                ("expr", ("bp", -6), ((CallsitePushExprOp8616.SUB.value, 1),)),
                ("bp", 4),
            ),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(call.args) == 2
    assert getattr(call.args[0].variable, "offset", None) == 4
    assert isinstance(call.args[1], structured_c.CBinaryOp)
    assert call.args[1].op == "Sub"
    assert getattr(call.args[1].lhs.variable, "offset", None) == -6
    assert call.args[1].rhs.value == 1


def test_materialize_quicksort_args_prefers_exact_arithmetic_push_source_over_stale_stack_store():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    low_slot = SimStackVariable(4, 2, base="bp", name="arg_4", region=0x4010)
    pivot_slot = SimStackVariable(-6, 2, base="bp", name="local_6", region=0x4010)
    low_var = structured_c.CVariable(low_slot, variable_type=SimTypeShort(False), codegen=codegen)
    pivot_var = structured_c.CVariable(pivot_slot, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use = {low_slot: low_var, pivot_slot: pivot_var}
    codegen.cfunc.unified_local_vars = {
        low_slot: {(low_var, SimTypeShort(False))},
        pivot_slot: {(pivot_var, SimTypeShort(False))},
    }
    call = CFunctionCall("QuickSort", SimpleNamespace(name="QuickSort"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            _ss_sp_stack_store(codegen, project, -4, pivot_var),
            _ss_sp_stack_store(codegen, project, -2, low_var),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x10CE0,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(
                ("expr", ("bp", -6), ((CallsitePushExprOp8616.SUB.value, 1),)),
                ("bp", 4),
            ),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(call.args) == 2
    assert getattr(call.args[0].variable, "offset", None) == 4
    assert isinstance(call.args[1], structured_c.CBinaryOp)
    assert call.args[1].op == "Sub"
    assert getattr(call.args[1].lhs.variable, "offset", None) == -6
    assert call.args[1].rhs.value == 1


def test_materialize_callsite_stack_arguments_binds_source_op_operand_types():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    lhs_slot = SimStackVariable(-4, 2, base="bp", name="lhs", region=0x4010)
    rhs_slot = SimStackVariable(-2, 2, base="bp", name="rhs", region=0x4010)
    lhs_var = structured_c.CVariable(lhs_slot, variable_type=SimTypeShort(False), codegen=codegen)
    rhs_var = structured_c.CVariable(rhs_slot, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use = {lhs_slot: lhs_var, rhs_slot: rhs_var}
    codegen.cfunc.unified_local_vars = {
        lhs_slot: {(lhs_var, SimTypeShort(False))},
        rhs_slot: {(rhs_var, SimTypeShort(False))},
    }
    call = CFunctionCall("DrawFrame", SimpleNamespace(name="DrawFrame"), [lhs_var], codegen=codegen)
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x101F0,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
            push_arg_sources=(
                (
                    "expr",
                    ("bp", -4),
                    ((CallsitePushExprOp8616.ADD_SOURCE.value, ("bp", -2)),),
                ),
            ),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    arg = call.args[0]
    assert isinstance(arg, structured_c.CBinaryOp)
    assert arg.op == "Add"
    assert getattr(arg.lhs.variable, "offset", None) == -4
    assert getattr(arg.rhs.variable, "offset", None) == -2
    assert arg.type.size == 16


def test_callsite_stats_count_materialized_args():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    irow1 = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    vvar_2 = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_2"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing_slot = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="s_2_2_2_2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall(
        "DrawBar",
        SimpleNamespace(addr=0x1544, name="DrawBar", block_addrs_set={0x1544}),
        [],
        codegen=codegen,
    )

    codegen.cfunc.statements = CStatements(
        [
            CStatements(
                [
                    CAssignment(vvar_2, irow1, codegen=codegen),
                    CAssignment(
                        outgoing_slot,
                        CDirtyExpression(SimpleNamespace(varid=2, name="vvar_2"), codegen=codegen),
                        codegen=codegen,
                    ),
                    CExpressionStatement(call, codegen=codegen),
                ],
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True
    assert _normalize_call_target_names_8616(codegen) is False

    assert _normalize_call_target_names_8616(codegen) is False
    stats = codegen._inertia_callsite_materialization_stats
    assert stats.callsite_count == 1
    assert stats.call_target_fact_count == 1
    assert stats.call_target_materialized_count == 1
    assert stats.call_arg_fact_count == 1
    assert stats.call_arg_materialized_count == 1
    assert stats.known_prototype_arg_mismatch_count == 0


def test_callsite_target_stats_accept_persisted_typed_target_identity() -> None:
    """A cloned call keeps its exact callee fact even without angr callee metadata."""
    project = _project()
    codegen = _empty_codegen(project)
    summary = CallsiteSummary8616(
        callsite_addr=0x4012,
        target_addr=0x1544,
        return_addr=0x4015,
        kind="direct_near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=0,
        return_register=None,
        return_used=False,
    )
    call = CFunctionCall("DrawBar", None, [], codegen=codegen)
    bind_structured_callsite_identity_8616(call, summary)
    stats = CallsiteMaterializationStats()

    _accumulate_callsite_materialization_stats_8616(
        stats=stats,
        node=call,
        summary=summary,
        expected_source_name=None,
        project=project,
    )

    assert stats.call_target_fact_count == 1
    assert stats.call_target_materialized_count == 1


def test_materialize_callsite_stack_arguments_normalizes_bp_slot_values_and_pointer_args():
    project = _project()
    _bind_callee_pointer_argument_classifier_8616(project, lambda _project, _name, index: index in {0, 1})
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    local_i = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    local_base = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="s_4", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing_first = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing_second = structured_c.CVariable(
        SimStackVariable(-8, 2, base="bp", name="s_8", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    bp_load = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CUnaryOp("Reference", local_base, codegen=codegen),
            structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    call = CFunctionCall(
        "Swaps",
        SimpleNamespace(addr=0x1544, name="Swaps", block_addrs_set={0x1544}),
        [],
        codegen=codegen,
    )

    codegen.cfunc.statements = CStatements(
        [
            CAssignment(local_i, structured_c.CConstant(7, SimTypeShort(False), codegen=codegen), codegen=codegen),
            CAssignment(
                outgoing_first, structured_c.CConstant(2892, SimTypeShort(False), codegen=codegen), codegen=codegen
            ),
            CAssignment(
                outgoing_second,
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CBinaryOp(
                        "Shl",
                        bp_load,
                        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    structured_c.CConstant(2892, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    final_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert len(final_stmt.expr.args) == 2
    assert final_stmt.expr.args[0].callee_target == "SEG_PTR"
    assert final_stmt.expr.args[1].callee_target == "SEG_PTR"
    offset_expr = final_stmt.expr.args[1].args[1]
    assert not any(
        _match_bp_stack_load_8616(node, project) is not None for node in _iter_c_nodes_deep_8616(offset_expr)
    )

    assert _normalize_call_target_names_8616(codegen) is False
    stats = codegen._inertia_callsite_materialization_stats
    assert stats.call_arg_materialized_count == 2
    assert stats.bp_slot_arg_value_normalized_count >= 1
    assert stats.pointer_arg_materialized_count == 2
    assert stats.push_order_reversed_count >= 1


def test_materialize_callsite_stack_arguments_normalizes_existing_pointer_helper_args():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    ds_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ds"][0], 2, name="ds"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    named_local = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="iParent", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    other_local = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    offset_carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ir_9"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall(
        "Swaps",
        SimpleNamespace(addr=0x1544, name="Swaps", block_addrs_set={0x1544}),
        [
            CFunctionCall(
                "SEG_PTR",
                None,
                [
                    ds_reg,
                    structured_c.CBinaryOp(
                        "Add",
                        offset_carrier,
                        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                ],
                codegen=codegen,
            ),
            CFunctionCall("SEG_PTR", None, [ds_reg, other_local], codegen=codegen),
        ],
        codegen=codegen,
    )

    codegen.cfunc.variables_in_use = {
        named_local.variable: named_local,
        other_local.variable: other_local,
    }
    codegen.cfunc.unified_local_vars = {
        named_local.variable: {(named_local, named_local.variable_type)},
        other_local.variable: {(other_local, other_local.variable_type)},
    }
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(offset_carrier, named_local, codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    final_call = codegen.cfunc.statements.statements[1].expr
    first_offset = final_call.args[0].args[1]
    assert "ir_" not in _expr_fingerprint(first_offset, project)


def test_materialize_callsite_stack_arguments_types_strcpy_immediate_as_ds_pointer():
    project = _project()
    project._inertia_c_target = "portable-flat"
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    destination = structured_c.CVariable(
        SimStackVariable(-18, 2, base="bp", name="ach", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall(
        "strcpy",
        SimpleNamespace(addr=0x1544, name="strcpy", block_addrs_set={0x1544}),
        [
            structured_c.CUnaryOp("Reference", destination, codegen=codegen),
            structured_c.CConstant(354, SimTypeShort(False), codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [CExpressionStatement(call, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register="ax",
            return_used=False,
            push_arg_sources=(("imm", 354), ("bp_addr", -18)),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    assert len(call.args) == 2
    source_arg = call.args[1]
    assert isinstance(source_arg, CFunctionCall)
    assert source_arg.callee_target == "SEG_PTR"
    assert source_arg.args[1].value == 354
    assert codegen._inertia_callsite_materialization_stats.pointer_arg_materialized_count >= 1


def test_materialize_callsite_stack_arguments_keeps_indexed_global_pointer_args_aligned_to_push_sources():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    i_row = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="iRow", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    base = structured_c.CVariable(
        SimMemoryVariable(0xB4C, 2, name="abarWork", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    next_index = structured_c.CBinaryOp(
        "Add",
        i_row,
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    first_arg = structured_c.CUnaryOp(
        "Reference",
        CIndexedVariable(base, i_row, variable_type=SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    second_arg = structured_c.CUnaryOp(
        "Reference",
        CIndexedVariable(base, next_index, variable_type=SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    call = CFunctionCall(
        "Swaps",
        SimpleNamespace(addr=0x1544, name="Swaps", block_addrs_set={0x1544}),
        [first_arg, second_arg],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x1059,
            target_addr=0x1544,
            return_addr=0x105C,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(
                ("expr", ("bp", -2), ((CallsitePushExprOp8616.SHL.value, 1), (CallsitePushExprOp8616.ADD.value, 0xB4E))),
                ("expr", ("bp", -2), ((CallsitePushExprOp8616.SHL.value, 1), (CallsitePushExprOp8616.ADD.value, 0xB4C))),
            ),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is False

    final_call = codegen.cfunc.statements.statements[0].expr
    assert final_call.args == [first_arg, second_arg]


def test_materialize_callsite_stack_arguments_groups_ss_bp_address_far_pointer_arg():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    local_buf = structured_c.CVariable(
        SimStackVariable(-44, 44, base="bp", name="achT", region=0x4010),
        variable_type=SimTypeBottom(),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {local_buf.variable: local_buf}
    codegen.cfunc.unified_local_vars = {local_buf.variable: {(local_buf, local_buf.variable_type)}}
    call = CFunctionCall(
        "outtext",
        SimpleNamespace(addr=0x1544, name="outtext", block_addrs_set={0x1544}),
        [],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("seg", "ss"), ("bp_addr", -44)),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    final_call = codegen.cfunc.statements.statements[0].expr
    assert len(final_call.args) == 1
    arg = final_call.args[0]
    assert isinstance(arg, structured_c.CUnaryOp)
    assert arg.op == "Reference"
    assert getattr(getattr(arg.operand, "variable", None), "name", None) == "achT"
    stats = codegen._inertia_callsite_materialization_stats
    assert stats.known_prototype_arg_mismatch_count == 0
    assert stats.pointer_arg_materialized_count >= 1
    summary = codegen._inertia_callsite_summaries[id(final_call)]
    assert summary.arg_widths == (2, 2)
    assert summary.logical_arg_widths == (4,)
    assert codegen._inertia_callsite_unmaterialized_arg_gaps_8616 == ()


def test_materialize_anonymous_call_keeps_physical_ss_bp_address_arguments():
    project = _project()
    codegen = _empty_codegen(project)
    _bind_segment_push_source_lowerer_8616(
        codegen,
        runtime_segment_push_source_cvar_8616,
    )
    structured_c = _scg.c
    local_buf = structured_c.CVariable(
        SimStackVariable(-44, 44, base="bp", name="local_2c", region=0x4010),
        variable_type=SimTypeBottom(),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {local_buf.variable: local_buf}
    codegen.cfunc.unified_local_vars = {
        local_buf.variable: {(local_buf, local_buf.variable_type)}
    }
    call = CFunctionCall(
        "sub_1544",
        SimpleNamespace(addr=0x1544, name="sub_1544", block_addrs_set={0x1544}),
        [],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [CExpressionStatement(call, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("seg", "ss"), ("bp_addr", -44)),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    final_call = codegen.cfunc.statements.statements[0].expr
    assert len(final_call.args) == 2
    buffer_arg, segment_arg = final_call.args
    assert isinstance(buffer_arg, structured_c.CUnaryOp)
    assert (
        getattr(getattr(buffer_arg.operand, "variable", None), "name", None)
        == "local_2c"
    )
    assert isinstance(segment_arg, structured_c.CVariable)
    assert isinstance(segment_arg.variable, SimMemoryVariable)
    assert segment_arg.variable.name == "inertia_ss"


def test_materialize_callsite_stack_arguments_keeps_unproven_far_pointer_stores():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    local_buf = structured_c.CVariable(
        SimStackVariable(-44, 44, base="bp", name="achT", region=0x4010),
        variable_type=SimTypeBottom(),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {local_buf.variable: local_buf}
    codegen.cfunc.unified_local_vars = {local_buf.variable: {(local_buf, local_buf.variable_type)}}
    call = CFunctionCall(
        "outtext",
        SimpleNamespace(addr=0x1544, name="outtext", block_addrs_set={0x1544}),
        [],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            _ss_sp_stack_store(codegen, project, -4, local_buf),
            _ss_sp_stack_store(codegen, project, -2, ss_reg),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("seg", "ss"), ("bp_addr", -44)),
        ),
    }

    original_stores = tuple(codegen.cfunc.statements.statements[:-1])
    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    assert tuple(codegen.cfunc.statements.statements[:-1]) == original_stores
    final_call = codegen.cfunc.statements.statements[-1].expr
    assert len(final_call.args) == 1
    arg = final_call.args[0]
    assert isinstance(arg, structured_c.CUnaryOp)
    assert arg.op == "Reference"
    assert getattr(getattr(arg.operand, "variable", None), "name", None) == "achT"
    assert not hasattr(codegen, "_inertia_callsite_direct_push_source_stores_pruned_8616")


def test_materialize_callsite_stack_arguments_keeps_unproven_scalar_byte_pair_stores():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    source = CVariable(SimRegisterVariable(0x40, 2, name="vvar_source"), codegen=codegen)
    slot = CVariable(SimRegisterVariable(0x42, 2, name="vvar_slot"), codegen=codegen)
    stack_segment = CVariable(SimRegisterVariable(0x44, 2, name="vvar_stack_segment"), codegen=codegen)
    sp_carrier = CVariable(SimRegisterVariable(0x46, 2, name="vvar_sp"), codegen=codegen)
    one = structured_c.CConstant(1, SimTypeShort(False), codegen=codegen)
    eight = structured_c.CConstant(8, SimTypeShort(False), codegen=codegen)

    def byte_store(*, high: bool):
        offset = structured_c.CBinaryOp("Add", slot, one, codegen=codegen) if high else slot
        rhs = structured_c.CBinaryOp("Shr", source, eight, codegen=codegen) if high else source
        return CAssignment(
            CFunctionCall("SEG_U8", None, [stack_segment, offset], codegen=codegen),
            rhs,
            codegen=codegen,
        )

    call = CFunctionCall(
        "settextposition",
        SimpleNamespace(addr=0x128E4, name="settextposition", block_addrs_set={0x128E4}),
        [
            structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
            structured_c.CConstant(48, SimTypeShort(False), codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(source, structured_c.CConstant(48, SimTypeShort(False), codegen=codegen), codegen=codegen),
            CAssignment(
                slot,
                structured_c.CBinaryOp(
                    "Sub",
                    sp_carrier,
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CAssignment(stack_segment, ss_reg, codegen=codegen),
            byte_store(high=False),
            byte_store(high=True),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x105F,
            target_addr=0x128E4,
            return_addr=0x1062,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("imm", 48), ("imm", 2)),
        ),
    }

    original_statements = tuple(codegen.cfunc.statements.statements)
    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    statements = codegen.cfunc.statements.statements
    assert tuple(statements) == original_statements
    assert statements[-1].expr is call
    assert [arg.value for arg in call.args] == [2, 48]
    assert not hasattr(codegen, "_inertia_callsite_direct_push_source_stores_pruned_8616")


def test_materialize_callsite_stack_arguments_refuses_direct_ds_byte_pair_store_prune():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    ds_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ds"][0], 2, name="ds"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    def byte_store(offset: int):
        return CAssignment(
            CFunctionCall(
                "SEG_U8",
                None,
                [
                    ds_reg,
                    structured_c.CConstant(offset, SimTypeShort(False), codegen=codegen),
                ],
                codegen=codegen,
            ),
            structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    low_store = byte_store(0x134)
    high_store = byte_store(0x135)
    call = CFunctionCall(
        "settextposition",
        SimpleNamespace(addr=0x128E4, name="settextposition", block_addrs_set={0x128E4}),
        [
            structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
            structured_c.CConstant(48, SimTypeShort(False), codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [low_store, high_store, CExpressionStatement(call, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_direct_push_source_stores_pruned_8616 = 0
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x105F,
            target_addr=0x128E4,
            return_addr=0x1062,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("imm", 48), ("imm", 2)),
        ),
    }

    _materialize_callsite_stack_arguments_8616(project, codegen)

    statements = codegen.cfunc.statements.statements
    assert len(statements) == 3
    assert statements[0] is low_store
    assert statements[1] is high_store
    assert statements[2].expr is call
    assert codegen._inertia_callsite_direct_push_source_stores_pruned_8616 == 0


def test_prune_consumed_segmented_stack_arg_stores_prunes_ss_word_store():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    stack_offset = CVariable(SimRegisterVariable(0x46, 2, name="vvar_sp"), codegen=codegen)
    source = CVariable(SimRegisterVariable(0x48, 2, name="vvar_source"), codegen=codegen)
    call = CFunctionCall(
        "QuickSort",
        SimpleNamespace(addr=0x10CE0, name="QuickSort", block_addrs_set={0x10CE0}),
        [
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                CFunctionCall("SEG_U16", None, [ss_reg, stack_offset], codegen=codegen),
                source,
                codegen=codegen,
            ),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x105F,
            target_addr=0x10CE0,
            return_addr=0x1062,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("imm", 2), ("imm", 1)),
        ),
    }

    assert prune_consumed_segmented_stack_byte_arg_stores_8616(project, codegen) is True

    statements = codegen.cfunc.statements.statements
    assert len(statements) == 1
    assert statements[0].expr is call


def test_prune_consumed_segmented_stack_arg_stores_prunes_raw_ss_word_store():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    stack_offset = CVariable(SimRegisterVariable(0x46, 2, name="vvar_sp"), codegen=codegen)
    source = CVariable(SimRegisterVariable(0x48, 2, name="vvar_source"), codegen=codegen)
    linear_addr = CBinaryOp(
        "Add",
        CBinaryOp("Shl", ss_reg, CConstant(4, SimTypeShort(False), codegen=codegen), codegen=codegen),
        stack_offset,
        codegen=codegen,
    )
    call = CFunctionCall(
        "QuickSort",
        SimpleNamespace(addr=0x10CE0, name="QuickSort", block_addrs_set={0x10CE0}),
        [
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(CUnaryOp("Dereference", linear_addr, codegen=codegen), source, codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x105F,
            target_addr=0x10CE0,
            return_addr=0x1062,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("imm", 2), ("imm", 1)),
        ),
    }

    assert prune_consumed_segmented_stack_byte_arg_stores_8616(project, codegen) is True

    statements = codegen.cfunc.statements.statements
    assert len(statements) == 1
    assert statements[0].expr is call


def test_prune_consumed_segmented_stack_arg_store_crosses_pure_sp_carrier():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    stack_offset = CDirtyExpression(SimpleNamespace(varid=0x7300, name="vvar_sp_before"), codegen=codegen)
    stack_after_push = CDirtyExpression(SimpleNamespace(varid=0x7500, name="vvar_sp_after"), codegen=codegen)
    source = CDirtyExpression(SimpleNamespace(varid=0x7400, name="vvar_ss_value"), codegen=codegen)
    carrier = CAssignment(
        stack_after_push,
        CBinaryOp(
            "Sub",
            stack_offset,
            CConstant(2, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    call = CFunctionCall(
        "outtext",
        SimpleNamespace(addr=0x12000, name="outtext", block_addrs_set={0x12000}),
        [CVariable(SimStackVariable(-44, 43, base="bp", name="achT"), codegen=codegen)],
        codegen=codegen,
    )
    store = CAssignment(
        CFunctionCall("SEG_U8", None, [ss_reg, stack_offset], codegen=codegen),
        source,
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [store, carrier, CExpressionStatement(call, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x1073D,
            target_addr=0x12000,
            return_addr=0x10742,
            kind="direct_far",
            arg_count=1,
            arg_widths=(4,),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("segment", "ss"), ("reg", "ax")),
        ),
    }

    assert prune_consumed_segmented_stack_byte_arg_stores_8616(project, codegen) is True

    statements = codegen.cfunc.statements.statements
    assert len(statements) == 2
    assert statements[0] is carrier
    assert statements[-1].expr is call


def test_prune_consumed_segmented_stack_arg_store_refuses_across_local_assignment():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    stack_offset = CDirtyExpression(SimpleNamespace(varid=0x7300, name="vvar_sp"), codegen=codegen)
    source = CDirtyExpression(SimpleNamespace(varid=0x7400, name="vvar_ss_value"), codegen=codegen)
    local = CVariable(SimStackVariable(-2, 2, base="bp", name="local_2"), codegen=codegen)
    call = CFunctionCall(
        "outtext",
        SimpleNamespace(addr=0x12000, name="outtext", block_addrs_set={0x12000}),
        [local],
        codegen=codegen,
    )
    store = CAssignment(
        CFunctionCall("SEG_U8", None, [ss_reg, stack_offset], codegen=codegen),
        source,
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            store,
            CAssignment(local, CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x1073D,
            target_addr=0x12000,
            return_addr=0x10742,
            kind="direct_far",
            arg_count=1,
            arg_widths=(4,),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("segment", "ss"), ("reg", "ax")),
        ),
    }

    assert prune_consumed_segmented_stack_byte_arg_stores_8616(project, codegen) is False
    assert codegen.cfunc.statements.statements[0] is store


def test_materialize_callsite_stack_arguments_groups_getvideoconfig_ss_bp_far_pointer_arg():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    local_config = structured_c.CVariable(
        SimStackVariable(-112, 112, base="bp", name="vc", region=0x4010),
        variable_type=SimTypeBottom(),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {local_config.variable: local_config}
    codegen.cfunc.unified_local_vars = {local_config.variable: {(local_config, local_config.variable_type)}}
    call = CFunctionCall(
        "getvideoconfig",
        SimpleNamespace(addr=0x3568, name="getvideoconfig", block_addrs_set={0x3568}),
        [structured_c.CUnaryOp("Reference", local_config, codegen=codegen)],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4035,
            target_addr=0x3568,
            return_addr=0x4038,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("seg", "ss"), ("bp_addr", -112)),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    final_call = codegen.cfunc.statements.statements[0].expr
    assert len(final_call.args) == 1
    arg = final_call.args[0]
    assert isinstance(arg, structured_c.CUnaryOp)
    assert arg.op == "Reference"
    assert getattr(getattr(arg.operand, "variable", None), "name", None) == "vc"
    summary = codegen._inertia_callsite_summaries[id(final_call)]
    assert summary.arg_widths == (2, 2)
    assert summary.logical_arg_widths == (4,)
    assert codegen._inertia_callsite_unmaterialized_arg_gaps_8616 == ()


def test_materialize_callsite_stack_arguments_prunes_getvideoconfig_far_pointer_high_byte_remnants():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    local_config = structured_c.CVariable(
        SimStackVariable(-112, 112, base="bp", name="vc", region=0x4010),
        variable_type=SimTypeBottom(),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {local_config.variable: local_config}
    codegen.cfunc.unified_local_vars = {local_config.variable: {(local_config, local_config.variable_type)}}
    ss = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    sp_carrier = CVariable(SimRegisterVariable(0x40, 2, name="vvar_46"), codegen=codegen)
    segment_slot = CVariable(SimRegisterVariable(0x42, 2, name="vvar_51"), codegen=codegen)
    offset_slot = CVariable(SimRegisterVariable(0x44, 2, name="vvar_53"), codegen=codegen)
    bp_addr = CVariable(SimRegisterVariable(0x46, 2, name="v9"), codegen=codegen)
    one = structured_c.CConstant(1, SimTypeShort(False), codegen=codegen)
    eight = structured_c.CConstant(8, SimTypeShort(False), codegen=codegen)

    def high_byte_stack_store(slot, source):
        return CAssignment(
            CFunctionCall(
                "SEG_U8",
                None,
                [
                    ss,
                    structured_c.CBinaryOp("Add", slot, one, codegen=codegen),
                ],
                codegen=codegen,
            ),
            structured_c.CBinaryOp("Shr", source, eight, codegen=codegen),
            codegen=codegen,
        )

    call = CFunctionCall(
        "getvideoconfig",
        SimpleNamespace(addr=0x3568, name="getvideoconfig", block_addrs_set={0x3568}),
        [structured_c.CUnaryOp("Reference", local_config, codegen=codegen)],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                segment_slot,
                structured_c.CBinaryOp(
                    "Add",
                    sp_carrier,
                    structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            high_byte_stack_store(segment_slot, ss),
            CAssignment(
                offset_slot,
                structured_c.CBinaryOp(
                    "Sub",
                    segment_slot,
                    structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            high_byte_stack_store(offset_slot, bp_addr),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4035,
            target_addr=0x3568,
            return_addr=0x4038,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("seg", "ss"), ("bp_addr", -112)),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    statements = codegen.cfunc.statements.statements
    assert len(statements) == 1
    final_call = statements[0].expr
    assert len(final_call.args) == 1
    arg = final_call.args[0]
    assert isinstance(arg, structured_c.CUnaryOp)
    assert arg.op == "Reference"
    assert getattr(getattr(arg.operand, "variable", None), "name", None) == "vc"
    assert codegen._inertia_callsite_pre_call_farptr_high_byte_remnants_pruned_8616 == 4


def test_materialize_callsite_stack_arguments_prunes_scalar_global_high_byte_remnant():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    i_compares = structured_c.CVariable(
        SimMemoryVariable(0xBAA, 2, name="iCompares", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = CDirtyExpression(SimpleNamespace(varid=0x9000, name="vvar_40"), codegen=codegen)
    ss = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    one = structured_c.CConstant(1, SimTypeShort(False), codegen=codegen)
    eight = structured_c.CConstant(8, SimTypeShort(False), codegen=codegen)
    setup_alias = CAssignment(
        carrier,
        structured_c.CUnaryOp(
            "Reference",
            structured_c.CVariable(
                SimStackVariable(-4, 2, base="bp", name="tmp", region=0x4010),
                variable_type=SimTypeShort(False),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    high_byte_store = CAssignment(
        CFunctionCall(
            "SEG_U8",
            None,
            [ss, structured_c.CBinaryOp("Add", carrier, one, codegen=codegen)],
            codegen=codegen,
        ),
        structured_c.CBinaryOp("Shr", i_compares, eight, codegen=codegen),
        codegen=codegen,
    )
    call = CFunctionCall(
        "sprintf",
        SimpleNamespace(addr=0x1122, name="sprintf", block_addrs_set={0x1122}),
        [i_compares],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [setup_alias, high_byte_store, CExpressionStatement(call, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4040,
            target_addr=0x1122,
            return_addr=0x4043,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
            push_arg_sources=(("global", 0xBAA, 2),),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    statements = codegen.cfunc.statements.statements
    assert len(statements) == 1
    assert statements[0].expr is call
    assert codegen._inertia_callsite_pre_call_scalar_high_byte_remnants_pruned_8616 == 2


def test_materialize_callsite_stack_arguments_prunes_byte_sized_scalar_global_high_byte_remnant():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    byte_sized_alias = structured_c.CVariable(
        SimMemoryVariable(0xBAA, 1, name="g_baa", region=0x4010),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )
    carrier = CDirtyExpression(SimpleNamespace(varid=0x9000, name="vvar_40"), codegen=codegen)
    ss = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    setup_alias = CAssignment(
        carrier,
        structured_c.CConstant(6, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    high_byte_store = CAssignment(
        CFunctionCall(
            "SEG_U8",
            None,
            [
                ss,
                structured_c.CBinaryOp(
                    "Add",
                    carrier,
                    structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
            ],
            codegen=codegen,
        ),
        structured_c.CBinaryOp(
            "Shr",
            byte_sized_alias,
            structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    call = CFunctionCall(
        "sprintf",
        SimpleNamespace(addr=0x1122, name="sprintf", block_addrs_set={0x1122}),
        [byte_sized_alias],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [setup_alias, high_byte_store, CExpressionStatement(call, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4040,
            target_addr=0x1122,
            return_addr=0x4043,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
            push_arg_sources=(("global", 0xBAA, 2),),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    statements = codegen.cfunc.statements.statements
    assert len(statements) == 1
    assert statements[0].expr is call
    assert codegen._inertia_callsite_pre_call_scalar_high_byte_remnants_pruned_8616 == 2


def test_final_pruner_removes_byte_pair_scalar_global_high_byte_remnant_with_carriers():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    i_compares = structured_c.CVariable(
        SimMemoryVariable(0xBAA, 2, name="iCompares", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    low_byte_alias = structured_c.CVariable(
        SimMemoryVariable(0xBAA, 1, name="g_baa", region=0x4010),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )
    high_byte_alias = structured_c.CVariable(
        SimMemoryVariable(0xBAB, 1, name="g_bab", region=0x4010),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )
    carrier = CDirtyExpression(SimpleNamespace(varid=0x9000, name="vvar_40"), codegen=codegen)
    ss = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    eight = structured_c.CConstant(8, SimTypeShort(False), codegen=codegen)
    setup_alias = CAssignment(
        carrier,
        structured_c.CConstant(6, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    byte_pair_word = structured_c.CBinaryOp(
        "Or",
        low_byte_alias,
        structured_c.CBinaryOp("Shl", high_byte_alias, eight, codegen=codegen),
        codegen=codegen,
    )
    high_byte_store = CAssignment(
        CFunctionCall(
            "SEG_U8",
            None,
            [
                ss,
                structured_c.CBinaryOp(
                    "Add",
                    carrier,
                    structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
            ],
            codegen=codegen,
        ),
        structured_c.CBinaryOp("Shr", byte_pair_word, eight, codegen=codegen),
        codegen=codegen,
    )

    def post_store_carrier(varid: int):
        return CAssignment(
            CDirtyExpression(SimpleNamespace(varid=varid, name=f"tmp_{varid:x}"), codegen=codegen),
            structured_c.CBinaryOp(
                "Add",
                CDirtyExpression(SimpleNamespace(varid=varid + 0x100, name=f"tmp_{varid + 0x100:x}"), codegen=codegen),
                structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        )

    call = CFunctionCall(
        "sprintf",
        SimpleNamespace(addr=0x1122, name="sprintf", block_addrs_set={0x1122}),
        [i_compares],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            setup_alias,
            high_byte_store,
            post_store_carrier(0x9010),
            post_store_carrier(0x9020),
            post_store_carrier(0x9030),
            post_store_carrier(0x9040),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4040,
            target_addr=0x1122,
            return_addr=0x4043,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
            push_arg_sources=(("global", 0xBAA, 2),),
        ),
    }

    assert _prune_scalar_global_high_byte_call_arg_remnants_8616(project, codegen) is True

    statements = codegen.cfunc.statements.statements
    assert len(statements) == 1
    assert statements[0].expr is call
    assert codegen._inertia_callsite_pre_call_scalar_high_byte_remnants_pruned_8616 == 6


def test_materialize_callsite_stack_arguments_prunes_dirty_lhs_far_pointer_high_byte_remnants():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    local_config = structured_c.CVariable(
        SimStackVariable(-112, 112, base="bp", name="vc", region=0x4010),
        variable_type=SimTypeBottom(),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {local_config.variable: local_config}
    codegen.cfunc.unified_local_vars = {local_config.variable: {(local_config, local_config.variable_type)}}
    ss = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    sp_carrier = CVariable(SimRegisterVariable(0x40, 2, name="vvar_46"), codegen=codegen)
    segment_slot = CVariable(SimRegisterVariable(0x42, 2, name="vvar_51"), codegen=codegen)
    offset_slot = CVariable(SimRegisterVariable(0x44, 2, name="vvar_53"), codegen=codegen)
    bp_addr = CVariable(SimRegisterVariable(0x46, 2, name="v9"), codegen=codegen)
    eight = structured_c.CConstant(8, SimTypeShort(False), codegen=codegen)

    def high_byte_dirty_store(name, source):
        return CAssignment(
            CDirtyExpression(SimpleNamespace(varid=0x9000, name=name), codegen=codegen),
            structured_c.CBinaryOp("Shr", source, eight, codegen=codegen),
            codegen=codegen,
        )

    call = CFunctionCall(
        "getvideoconfig",
        SimpleNamespace(addr=0x3568, name="getvideoconfig", block_addrs_set={0x3568}),
        [structured_c.CUnaryOp("Reference", local_config, codegen=codegen)],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                segment_slot,
                structured_c.CBinaryOp(
                    "Add",
                    sp_carrier,
                    structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            high_byte_dirty_store("SEG_U8(ss, vvar_51 + 1)", ss),
            CAssignment(
                offset_slot,
                structured_c.CBinaryOp(
                    "Sub",
                    segment_slot,
                    structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            high_byte_dirty_store("SEG_U8(ss, vvar_53 + 1)", bp_addr),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4035,
            target_addr=0x3568,
            return_addr=0x4038,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("seg", "ss"), ("bp_addr", -112)),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    statements = codegen.cfunc.statements.statements
    assert len(statements) == 1
    final_call = statements[0].expr
    assert len(final_call.args) == 1
    arg = final_call.args[0]
    assert isinstance(arg, structured_c.CUnaryOp)
    assert arg.op == "Reference"
    assert getattr(getattr(arg.operand, "variable", None), "name", None) == "vc"
    assert codegen._inertia_callsite_pre_call_farptr_high_byte_remnants_pruned_8616 == 4


def test_materialize_callsite_stack_arguments_prunes_dirty_source_far_pointer_byte_store_pairs():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    local_buf = structured_c.CVariable(
        SimStackVariable(-18, 15, base="bp", name="ach", region=0x4010),
        variable_type=SimTypeBottom(),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {local_buf.variable: local_buf}
    codegen.cfunc.unified_local_vars = {local_buf.variable: {(local_buf, local_buf.variable_type)}}
    ss = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    one = structured_c.CConstant(1, SimTypeShort(False), codegen=codegen)
    two = structured_c.CConstant(2, SimTypeShort(False), codegen=codegen)
    eight = structured_c.CConstant(8, SimTypeShort(False), codegen=codegen)
    sp_carrier = CDirtyExpression(SimpleNamespace(varid=0x9000, name="vvar_sp"), codegen=codegen)
    segment_source = CDirtyExpression(SimpleNamespace(varid=0x9001, name="vvar_seg_source"), codegen=codegen)
    offset_source = CDirtyExpression(SimpleNamespace(varid=0x9002, name="vvar_offset_source"), codegen=codegen)
    segment_slot = CDirtyExpression(SimpleNamespace(varid=0x9003, name="vvar_segment_slot"), codegen=codegen)
    offset_slot = CDirtyExpression(SimpleNamespace(varid=0x9004, name="vvar_offset_slot"), codegen=codegen)
    stack_segment_a = CDirtyExpression(SimpleNamespace(varid=0x9005, name="vvar_stack_segment_a"), codegen=codegen)
    stack_segment_b = CDirtyExpression(SimpleNamespace(varid=0x9006, name="vvar_stack_segment_b"), codegen=codegen)

    def byte_store(slot, source, *, high: bool):
        offset = structured_c.CBinaryOp("Add", slot, one, codegen=codegen) if high else slot
        rhs = structured_c.CBinaryOp("Shr", source, eight, codegen=codegen) if high else source
        return CAssignment(
            CFunctionCall("SEG_U8", None, [stack_segment_a if slot is segment_slot else stack_segment_b, offset], codegen=codegen),
            rhs,
            codegen=codegen,
        )

    call = CFunctionCall(
        "outtext",
        SimpleNamespace(addr=0x1544, name="outtext", block_addrs_set={0x1544}),
        [structured_c.CUnaryOp("Reference", local_buf, codegen=codegen)],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(segment_source, ss, codegen=codegen),
            CAssignment(segment_slot, structured_c.CBinaryOp("Add", sp_carrier, two, codegen=codegen), codegen=codegen),
            CAssignment(stack_segment_a, ss, codegen=codegen),
            byte_store(segment_slot, segment_source, high=False),
            byte_store(segment_slot, segment_source, high=True),
            CAssignment(offset_source, structured_c.CUnaryOp("Reference", local_buf, codegen=codegen), codegen=codegen),
            CAssignment(offset_slot, structured_c.CBinaryOp("Sub", segment_slot, two, codegen=codegen), codegen=codegen),
            CAssignment(stack_segment_b, ss, codegen=codegen),
            byte_store(offset_slot, offset_source, high=False),
            byte_store(offset_slot, offset_source, high=True),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x10BD,
            target_addr=0x1544,
            return_addr=0x10C0,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("seg", "ss"), ("bp_addr", -18)),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    statements = codegen.cfunc.statements.statements
    assert len(statements) == 1
    final_call = statements[0].expr
    assert len(final_call.args) == 1
    arg = final_call.args[0]
    assert isinstance(arg, structured_c.CUnaryOp)
    assert arg.op == "Reference"
    assert getattr(getattr(arg.operand, "variable", None), "name", None) == "ach"
    assert codegen._inertia_callsite_pre_call_farptr_high_byte_remnants_pruned_8616 == 10


def test_materialize_callsite_stack_arguments_prunes_global_index_far_pointer_byte_store_pairs():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    ds = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ds"][0], 2, name="ds"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    one = structured_c.CConstant(1, SimTypeShort(False), codegen=codegen)
    two = structured_c.CConstant(2, SimTypeShort(False), codegen=codegen)
    eight = structured_c.CConstant(8, SimTypeShort(False), codegen=codegen)
    sp_carrier = CDirtyExpression(SimpleNamespace(varid=0x9100, name="vvar_sp"), codegen=codegen)
    segment_source = CDirtyExpression(SimpleNamespace(varid=0x9101, name="vvar_ds_source"), codegen=codegen)
    offset_source = CDirtyExpression(SimpleNamespace(varid=0x9102, name="vvar_indexed_offset"), codegen=codegen)
    segment_slot = CDirtyExpression(SimpleNamespace(varid=0x9103, name="vvar_segment_slot"), codegen=codegen)
    offset_slot = CDirtyExpression(SimpleNamespace(varid=0x9104, name="vvar_offset_slot"), codegen=codegen)
    stack_segment = CDirtyExpression(SimpleNamespace(varid=0x9105, name="vvar_stack_segment"), codegen=codegen)

    def byte_store(slot, source, *, high: bool):
        offset = structured_c.CBinaryOp("Add", slot, one, codegen=codegen) if high else slot
        rhs = structured_c.CBinaryOp("Shr", source, eight, codegen=codegen) if high else source
        return CAssignment(
            CFunctionCall("SEG_U8", None, [stack_segment, offset], codegen=codegen),
            rhs,
            codegen=codegen,
        )

    call_arg = CVariable(SimMemoryVariable(0x0136, 2, name="aszMenu_i", region=0x4010), codegen=codegen)
    call = CFunctionCall(
        "outtext",
        SimpleNamespace(addr=0x1544, name="outtext", block_addrs_set={0x1544}),
        [call_arg],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(segment_source, ds, codegen=codegen),
            CAssignment(segment_slot, structured_c.CBinaryOp("Add", sp_carrier, two, codegen=codegen), codegen=codegen),
            CAssignment(stack_segment, ds, codegen=codegen),
            byte_store(segment_slot, segment_source, high=False),
            byte_store(segment_slot, segment_source, high=True),
            CAssignment(offset_source, call_arg, codegen=codegen),
            CAssignment(offset_slot, structured_c.CBinaryOp("Sub", segment_slot, two, codegen=codegen), codegen=codegen),
            byte_store(offset_slot, offset_source, high=False),
            byte_store(offset_slot, offset_source, high=True),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x1071,
            target_addr=0x1544,
            return_addr=0x1074,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(
                ("seg", "ds"),
                ("global_index", 310, 2, ("bp", -2), ((CallsitePushExprOp8616.SHL.value, 1),)),
            ),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    statements = codegen.cfunc.statements.statements
    assert len(statements) == 1
    assert statements[0].expr is call
    assert codegen._inertia_callsite_pre_call_farptr_high_byte_remnants_pruned_8616 == 9


def test_materialize_callsite_stack_arguments_prunes_far_pointer_remnants_before_safe_suffix_assignment():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    local_config = structured_c.CVariable(
        SimStackVariable(-112, 112, base="bp", name="vc", region=0x4010),
        variable_type=SimTypeBottom(),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {local_config.variable: local_config}
    codegen.cfunc.unified_local_vars = {local_config.variable: {(local_config, local_config.variable_type)}}
    ss = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    sp_carrier = CVariable(SimRegisterVariable(0x40, 2, name="vvar_46"), codegen=codegen)
    segment_slot = CVariable(SimRegisterVariable(0x42, 2, name="vvar_51"), codegen=codegen)
    offset_slot = CVariable(SimRegisterVariable(0x44, 2, name="vvar_53"), codegen=codegen)
    bp_addr = CVariable(SimRegisterVariable(0x46, 2, name="v9"), codegen=codegen)
    safe_suffix_lhs = CVariable(
        SimStackVariable(0, 2, base="bp", name="local_0", region=0x4010),
        codegen=codegen,
    )
    one = structured_c.CConstant(1, SimTypeShort(False), codegen=codegen)
    eight = structured_c.CConstant(8, SimTypeShort(False), codegen=codegen)

    def high_byte_stack_store(slot, source):
        return CAssignment(
            CFunctionCall(
                "SEG_U8",
                None,
                [
                    ss,
                    structured_c.CBinaryOp("Add", slot, one, codegen=codegen),
                ],
                codegen=codegen,
            ),
            structured_c.CBinaryOp("Shr", source, eight, codegen=codegen),
            codegen=codegen,
        )

    call = CFunctionCall(
        "getvideoconfig",
        SimpleNamespace(addr=0x3568, name="getvideoconfig", block_addrs_set={0x3568}),
        [structured_c.CUnaryOp("Reference", local_config, codegen=codegen)],
        codegen=codegen,
    )
    safe_suffix = CAssignment(safe_suffix_lhs, bp_addr, codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                segment_slot,
                structured_c.CBinaryOp(
                    "Add",
                    sp_carrier,
                    structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            high_byte_stack_store(segment_slot, ss),
            safe_suffix,
            CAssignment(
                CDirtyExpression(SimpleNamespace(varid=0x9001, name="vvar_53"), codegen=codegen),
                structured_c.CBinaryOp(
                    "Sub",
                    CDirtyExpression(SimpleNamespace(varid=0x9002, name="vvar_51"), codegen=codegen),
                    structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            high_byte_stack_store(offset_slot, bp_addr),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4035,
            target_addr=0x3568,
            return_addr=0x4038,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("seg", "ss"), ("bp_addr", -112)),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    statements = codegen.cfunc.statements.statements
    assert len(statements) == 2
    assert statements[0] is safe_suffix
    final_call = statements[-1].expr
    assert len(final_call.args) == 1
    arg = final_call.args[0]
    assert isinstance(arg, structured_c.CUnaryOp)
    assert arg.op == "Reference"
    assert getattr(getattr(arg.operand, "variable", None), "name", None) == "vc"
    assert codegen._inertia_callsite_pre_call_farptr_high_byte_remnants_pruned_8616 == 4


def test_materialize_callsite_stack_arguments_keeps_existing_stack_address_pointer_arg():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    local_config = structured_c.CVariable(
        SimStackVariable(-112, 112, base="bp", name="vc", region=0x4010),
        variable_type=SimTypeBottom(),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {local_config.variable: local_config}
    codegen.cfunc.unified_local_vars = {local_config.variable: {(local_config, local_config.variable_type)}}
    call = CFunctionCall(
        "getvideoconfig",
        SimpleNamespace(addr=0x3568, name="getvideoconfig", block_addrs_set={0x3568}),
        [structured_c.CUnaryOp("Reference", local_config, codegen=codegen)],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4035,
            target_addr=0x3568,
            return_addr=0x4038,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("seg", "ss"), ("bp_addr", -112)),
        ),
    }

    _materialize_callsite_stack_arguments_8616(project, codegen)

    final_call = codegen.cfunc.statements.statements[0].expr
    assert len(final_call.args) == 1
    arg = final_call.args[0]
    assert isinstance(arg, structured_c.CUnaryOp)
    assert arg.op == "Reference"
    assert getattr(getattr(arg.operand, "variable", None), "name", None) == "vc"


def test_materialize_callsite_stack_arguments_consumes_dx_ax_return_push_pair():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    local_buf = structured_c.CVariable(
        SimStackVariable(-18, 18, base="bp", name="ach", region=0x4010),
        variable_type=SimTypeBottom(),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {local_buf.variable: local_buf}
    codegen.cfunc.unified_local_vars = {local_buf.variable: {(local_buf, local_buf.variable_type)}}

    div_call = CFunctionCall(
        "aNldiv",
        SimpleNamespace(addr=0x10D3, name="aNldiv", block_addrs_set={0x10D3}),
        [
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
            structured_c.CConstant(30, SimTypeShort(False), codegen=codegen),
            structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
        ],
        codegen=codegen,
    )
    sprintf_call = CFunctionCall(
        "sprintf",
        SimpleNamespace(addr=0x10E0, name="sprintf", block_addrs_set={0x10E0}),
        [],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CExpressionStatement(div_call, codegen=codegen),
            CExpressionStatement(sprintf_call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(div_call): CallsiteSummary8616(
            callsite_addr=0x10D3,
            target_addr=0x143A,
            return_addr=0x10D6,
            kind="direct_near",
            arg_count=4,
            arg_widths=(2, 2, 2, 2),
            stack_cleanup=8,
            return_register="ax",
            return_used=False,
            return_shape=None,
        ),
        id(sprintf_call): CallsiteSummary8616(
            callsite_addr=0x10E0,
            target_addr=0x12BA,
            return_addr=0x10E3,
            kind="direct_near",
            arg_count=4,
            arg_widths=(2, 2, 2, 2),
            stack_cleanup=8,
            return_register="ax",
            return_used=False,
            push_arg_sources=(
                ("ret_reg", 0x10D3, "dx"),
                ("ret_reg", 0x10D3, "ax"),
                ("imm", 0x16A),
                ("bp_addr", -18),
            ),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    statements = codegen.cfunc.statements.statements
    assert len(statements) == 1
    final_call = statements[0].expr
    assert final_call.callee_target == "sprintf"
    assert len(final_call.args) == 3
    assert isinstance(final_call.args[2], CFunctionCall)
    assert final_call.args[2].callee_target == "aNldiv"
    assert final_call.args[2].tags["ins_addr"] == 0x10D3
    assert (
        _refresh_callsite_summary_node_ids_8616(
            codegen,
            codegen._inertia_callsite_summaries,
        )
        is True
    )
    rebound_summary = codegen._inertia_callsite_summaries[id(final_call.args[2])]
    assert rebound_summary.callsite_addr == 0x10D3
    outer_summary = codegen._inertia_callsite_summaries[id(final_call)]
    assert outer_summary.logical_arg_widths == (2, 2, 4)
    assert not any(
        isinstance(getattr(node, "variable", None), SimRegisterVariable)
        and getattr(getattr(node, "variable", None), "name", None) in {"ax", "dx"}
        for arg in final_call.args
        for node in (arg, *_iter_c_nodes_deep_8616(arg))
    )
    assert getattr(codegen, "_inertia_return_register_call_args_materialized_8616", 0) == 1

    duplicate_call = CFunctionCall(
        "aNldiv",
        final_call.args[2].callee_func,
        [deepcopy(arg) for arg in final_call.args[2].args],
        codegen=codegen,
    )
    duplicate_call.tags = dict(final_call.args[2].tags)
    statements.insert(0, CExpressionStatement(duplicate_call, codegen=codegen))
    codegen._inertia_callsite_materialization_complete_8616 = False

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True
    assert len(codegen.cfunc.statements.statements) == 1


def test_materialize_callsite_stack_arguments_restores_protected_dx_ax_return_call():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    local_buf = structured_c.CVariable(
        SimStackVariable(-18, 18, base="bp", name="ach", region=0x4010),
        variable_type=SimTypeBottom(),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {local_buf.variable: local_buf}
    codegen.cfunc.unified_local_vars = {local_buf.variable: {(local_buf, local_buf.variable_type)}}

    div_call = CFunctionCall(
        "aNldiv",
        SimpleNamespace(addr=0x10D3, name="aNldiv", block_addrs_set={0x10D3}),
        [
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
            structured_c.CConstant(30, SimTypeShort(False), codegen=codegen),
            structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
        ],
        codegen=codegen,
    )
    sprintf_call = CFunctionCall(
        "sprintf",
        SimpleNamespace(addr=0x10E0, name="sprintf", block_addrs_set={0x10E0}),
        [],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CExpressionStatement(div_call, codegen=codegen),
            CExpressionStatement(sprintf_call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(div_call): CallsiteSummary8616(
            callsite_addr=0x10D3,
            target_addr=0x143A,
            return_addr=0x10D6,
            kind="direct_near",
            arg_count=4,
            arg_widths=(2, 2, 2, 2),
            stack_cleanup=8,
            return_register="ax",
            return_used=False,
            return_shape=None,
        ),
        id(sprintf_call): CallsiteSummary8616(
            callsite_addr=0x10E0,
            target_addr=0x12BA,
            return_addr=0x10E3,
            kind="direct_near",
            arg_count=4,
            arg_widths=(2, 2, 2, 2),
            stack_cleanup=8,
            return_register="ax",
            return_used=False,
            push_arg_sources=(
                ("ret_reg", 0x10D3, "dx"),
                ("ret_reg", 0x10D3, "ax"),
                ("imm", 0x16A),
                ("bp_addr", -18),
            ),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True
    final_call = codegen.cfunc.statements.statements[0].expr
    assert isinstance(final_call.args[2], CFunctionCall)
    assert final_call.args[2].callee_target == "aNldiv"

    final_call.args[2] = CFunctionCall(
        "clock",
        SimpleNamespace(addr=0x1234, name="clock", block_addrs_set={0x1234}),
        [],
        codegen=codegen,
    )

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True
    assert isinstance(final_call.args[2], CFunctionCall)
    assert final_call.args[2].callee_target == "aNldiv"


def test_materialize_callsite_stack_arguments_consumes_assignment_wrapped_ax_return_call():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    carrier = CVariable(
        SimStackVariable(-2, 2, base="bp", name="time_seed", region=0x4010),
        variable_type=SimTypeBottom(),
        codegen=codegen,
    )
    time_call = CFunctionCall(
        "time",
        SimpleNamespace(addr=0x2000, name="time", block_addrs_set={0x2000}),
        [structured_c.CConstant(0, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
    )
    srand_call = CFunctionCall(
        "srand",
        SimpleNamespace(addr=0x2004, name="srand", block_addrs_set={0x2004}),
        [],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(carrier, time_call, codegen=codegen),
            CExpressionStatement(srand_call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(time_call): CallsiteSummary8616(
            callsite_addr=0x1001,
            target_addr=0x2000,
            return_addr=0x1004,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register="ax",
            return_used=True,
            return_shape="ax",
        ),
        id(srand_call): CallsiteSummary8616(
            callsite_addr=0x1008,
            target_addr=0x2004,
            return_addr=0x100B,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register="ax",
            return_used=False,
            push_arg_sources=(("ret_reg", 0x1001, "ax"),),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    statements = codegen.cfunc.statements.statements
    assert len(statements) == 1
    final_call = statements[0].expr
    assert final_call.callee_target == "srand"
    assert len(final_call.args) == 1
    assert isinstance(final_call.args[0], CFunctionCall)
    assert final_call.args[0].callee_target == "time"
    assert getattr(codegen, "_inertia_return_register_call_args_materialized_8616", 0) == 1


def test_materialize_callsite_stack_arguments_assigns_ax_return_before_switch_selector():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    ch_var = CVariable(
        SimStackVariable(-2, 2, base="bp", name="ch", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ax_var = CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    toupper_call = CFunctionCall(
        "toupper",
        SimpleNamespace(addr=0x2048, name="toupper", block_addrs_set={0x2048}),
        [],
        codegen=codegen,
    )
    switch_stmt = structured_c.CSwitchCase(ax_var, [], None, codegen=codegen)
    codegen.cfunc.variables_in_use = {ch_var.variable: ch_var}
    codegen.cfunc.unified_local_vars = {ch_var.variable: {(ch_var, ch_var.variable_type)}}
    codegen.cfunc.statements = CStatements(
        [
            CExpressionStatement(toupper_call, codegen=codegen),
            switch_stmt,
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(toupper_call): CallsiteSummary8616(
            callsite_addr=0x1048,
            target_addr=0x2048,
            return_addr=0x104B,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register="ax",
            return_used=True,
            return_shape="ax",
            push_arg_sources=(("bp", -2),),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    statements = codegen.cfunc.statements.statements
    assert len(statements) == 2
    assignment = statements[0]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.lhs, CVariable)
    assert getattr(assignment.lhs.variable, "name", None) == "ax"
    assert assignment.rhs is toupper_call
    assert len(toupper_call.args) == 1
    assert _same_c_expression_8616(toupper_call.args[0], ch_var)
    assert statements[1] is switch_stmt
    assert getattr(codegen, "_inertia_call_return_switch_selector_materialized_8616", 0) == 1


def test_materialize_callsite_stack_arguments_assigns_ax_return_before_ax_condition():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    ch_var = CVariable(
        SimStackVariable(-2, 2, base="bp", name="ch", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ax_var = CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    toupper_call = CFunctionCall(
        "toupper",
        SimpleNamespace(addr=0x2048, name="toupper", block_addrs_set={0x2048}),
        [],
        codegen=codegen,
    )
    condition = structured_c.CBinaryOp(
        "CmpNE",
        ax_var,
        structured_c.CConstant(69, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    if_stmt = structured_c.CIfElse([(condition, CStatements([], codegen=codegen))], None, codegen=codegen)
    codegen.cfunc.variables_in_use = {ch_var.variable: ch_var}
    codegen.cfunc.unified_local_vars = {ch_var.variable: {(ch_var, ch_var.variable_type)}}
    codegen.cfunc.statements = CStatements(
        [
            CExpressionStatement(toupper_call, codegen=codegen),
            if_stmt,
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(toupper_call): CallsiteSummary8616(
            callsite_addr=0x1048,
            target_addr=0x2048,
            return_addr=0x104B,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register="ax",
            return_used=True,
            return_shape="ax",
            push_arg_sources=(("bp", -2),),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    statements = codegen.cfunc.statements.statements
    assert len(statements) == 2
    assignment = statements[0]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.lhs, CVariable)
    assert getattr(assignment.lhs.variable, "name", None) == "ax"
    assert assignment.rhs is toupper_call
    assert len(toupper_call.args) == 1
    assert _same_c_expression_8616(toupper_call.args[0], ch_var)
    assert statements[1] is if_stmt
    assert getattr(codegen, "_inertia_call_return_switch_selector_materialized_8616", 0) == 1


def test_materialize_callsite_stack_arguments_rebinds_assignment_wrapped_ax_return_before_switch_selector():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    carrier = CVariable(
        SimRegisterVariable(0x315, 2, name="vvar_315"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ch_var = CVariable(
        SimStackVariable(-2, 2, base="bp", name="ch", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ax_var = CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    toupper_call = CFunctionCall(
        "toupper",
        SimpleNamespace(addr=0x2048, name="toupper", block_addrs_set={0x2048}),
        [ch_var],
        codegen=codegen,
    )
    call_assignment = CAssignment(carrier, toupper_call, codegen=codegen)
    switch_stmt = structured_c.CSwitchCase(ax_var, [], None, codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            call_assignment,
            switch_stmt,
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(toupper_call): CallsiteSummary8616(
            callsite_addr=0x1048,
            target_addr=0x2048,
            return_addr=0x104B,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register="ax",
            return_used=True,
            return_shape="ax",
            push_arg_sources=(("bp", -2),),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    statements = codegen.cfunc.statements.statements
    assert statements[0] is call_assignment
    assert isinstance(call_assignment.lhs, CVariable)
    assert getattr(call_assignment.lhs.variable, "name", None) == "ax"
    assert call_assignment.rhs is toupper_call
    assert statements[1] is switch_stmt
    assert getattr(codegen, "_inertia_call_return_switch_selector_materialized_8616", 0) == 1

    materialized_lhs = call_assignment.lhs
    codegen._inertia_callsite_materialization_complete_8616 = False
    assert _materialize_callsite_stack_arguments_8616(project, codegen) is False
    assert call_assignment.lhs is materialized_lhs
    assert getattr(codegen, "_inertia_call_return_switch_selector_materialized_8616", 0) == 1


def test_materialize_callsite_stack_arguments_consumes_recorded_dx_ax_return_push_pair():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    local_buf = structured_c.CVariable(
        SimStackVariable(-18, 18, base="bp", name="ach", region=0x4010),
        variable_type=SimTypeBottom(),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {local_buf.variable: local_buf}
    codegen.cfunc.unified_local_vars = {local_buf.variable: {(local_buf, local_buf.variable_type)}}

    div_call = CFunctionCall(
        "aNldiv",
        SimpleNamespace(addr=0x10D3, name="aNldiv", block_addrs_set={0x10D3}),
        [
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
            structured_c.CConstant(30, SimTypeShort(False), codegen=codegen),
            structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
        ],
        codegen=codegen,
    )
    sprintf_call = CFunctionCall(
        "sprintf",
        SimpleNamespace(addr=0x10E0, name="sprintf", block_addrs_set={0x10E0}),
        [],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [CExpressionStatement(sprintf_call, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_return_exprs_8616 = {0x10D3: div_call}
    codegen._inertia_callsite_summaries = {
        id(sprintf_call): CallsiteSummary8616(
            callsite_addr=0x10E0,
            target_addr=0x12BA,
            return_addr=0x10E3,
            kind="direct_near",
            arg_count=4,
            arg_widths=(2, 2, 2, 2),
            stack_cleanup=8,
            return_register="ax",
            return_used=False,
            push_arg_sources=(
                ("ret_reg", 0x10D3, "dx"),
                ("ret_reg", 0x10D3, "ax"),
                ("imm", 0x16A),
                ("bp_addr", -18),
            ),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    statements = codegen.cfunc.statements.statements
    assert len(statements) == 1
    final_call = statements[0].expr
    assert final_call.callee_target == "sprintf"
    assert len(final_call.args) == 3
    assert isinstance(final_call.args[2], CFunctionCall)
    assert final_call.args[2].callee_target == "aNldiv"
    assert not any(
        isinstance(getattr(node, "variable", None), SimRegisterVariable)
        and getattr(getattr(node, "variable", None), "name", None) in {"ax", "dx"}
        for arg in final_call.args
        for node in (arg, *_iter_c_nodes_deep_8616(arg))
    )
    assert getattr(codegen, "_inertia_return_register_call_args_materialized_8616", 0) == 1


def test_materialize_callsite_stack_arguments_synthesizes_missing_dx_ax_return_call_from_summary():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    local_buf = structured_c.CVariable(
        SimStackVariable(-18, 18, base="bp", name="ach", region=0x4010),
        variable_type=SimTypeBottom(),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {local_buf.variable: local_buf}
    codegen.cfunc.unified_local_vars = {local_buf.variable: {(local_buf, local_buf.variable_type)}}

    detached_div_call = CFunctionCall(
        "aNldiv",
        SimpleNamespace(addr=0x10D3, name="aNldiv", block_addrs_set={0x10D3}),
        [],
        codegen=codegen,
    )
    sprintf_call = CFunctionCall(
        "sprintf",
        SimpleNamespace(addr=0x10E0, name="sprintf", block_addrs_set={0x10E0}),
        [],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [CExpressionStatement(sprintf_call, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_synthetic_globals = {0x143A: ("aNldiv", 2)}
    codegen._inertia_callsite_summaries = {
        id(detached_div_call): CallsiteSummary8616(
            callsite_addr=0x10D3,
            target_addr=0x143A,
            return_addr=0x10D6,
            kind="direct_near",
            arg_count=4,
            arg_widths=(2, 2, 2, 2),
            stack_cleanup=8,
            return_register="ax",
            return_used=False,
            return_shape=None,
            push_arg_sources=(
                ("imm", 0),
                ("imm", 30),
                ("imm", 0),
                ("imm", 1),
            ),
        ),
        id(sprintf_call): CallsiteSummary8616(
            callsite_addr=0x10E0,
            target_addr=0x12BA,
            return_addr=0x10E3,
            kind="direct_near",
            arg_count=4,
            arg_widths=(2, 2, 2, 2),
            stack_cleanup=8,
            return_register="ax",
            return_used=False,
            push_arg_sources=(
                ("ret_reg", 0x10D3, "dx"),
                ("ret_reg", 0x10D3, "ax"),
                ("imm", 0x16A),
                ("bp_addr", -18),
            ),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    statements = codegen.cfunc.statements.statements
    assert len(statements) == 1
    final_call = statements[0].expr
    assert final_call.callee_target == "sprintf"
    assert len(final_call.args) == 3
    assert isinstance(final_call.args[2], CFunctionCall)
    assert final_call.args[2].callee_target == "aNldiv"
    assert len(final_call.args[2].args) == 2
    assert getattr(codegen, "_inertia_return_register_call_args_materialized_8616", 0) == 1


def test_materialize_callsite_stack_arguments_folds_dx_ax_return_pair_assignment():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    low_carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="v9"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    high_carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["dx"][0], 2, name="v11"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    dx_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["dx"][0], 2, name="dx"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    cl_finish = structured_c.CVariable(
        SimMemoryVariable(0xB48, 4, name="clFinish", region=0x4010),
        variable_type=SimTypeLong(False),
        codegen=codegen,
    )
    clock_call = CFunctionCall(
        "clock",
        SimpleNamespace(addr=0x1017, name="clock", block_addrs_set={0x1017}),
        [],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(low_carrier, clock_call, codegen=codegen),
            CAssignment(high_carrier, dx_reg, codegen=codegen),
            CAssignment(
                cl_finish,
                structured_c.CBinaryOp(
                    "Or",
                    low_carrier,
                    structured_c.CBinaryOp(
                        "Shl",
                        high_carrier,
                        structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(clock_call): CallsiteSummary8616(
            callsite_addr=0x1017,
            target_addr=0x12A0,
            return_addr=0x101A,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            return_shape="dx_ax",
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    statements = codegen.cfunc.statements.statements
    assert len(statements) == 1
    assert isinstance(statements[0], CAssignment)
    assert _same_c_expression_8616(statements[0].lhs, cl_finish)
    assert statements[0].rhs is clock_call
    assert getattr(codegen, "_inertia_dx_ax_return_pair_assignments_folded_8616", 0) == 1


def test_materialize_callsite_stack_arguments_folds_dx_ax_return_pair_through_statement_shells():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    low_carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="v10"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    high_carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["dx"][0], 2, name="v12"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    cl_finish = structured_c.CVariable(
        SimMemoryVariable(0xB48, 4, name="clFinish", region=0x4010),
        variable_type=SimTypeLong(False),
        codegen=codegen,
    )
    clock_call = CFunctionCall(
        "clock",
        SimpleNamespace(addr=0x1017, name="clock", block_addrs_set={0x1017}),
        [],
        codegen=codegen,
    )
    call_assignment = CAssignment(low_carrier, clock_call, codegen=codegen)
    combine_assignment = CAssignment(
        cl_finish,
        structured_c.CBinaryOp(
            "Or",
            low_carrier,
            structured_c.CBinaryOp(
                "Shl",
                high_carrier,
                structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CStatements([call_assignment], addr=0x4010, codegen=codegen),
            CStatements([combine_assignment], addr=0x4010, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(clock_call): CallsiteSummary8616(
            callsite_addr=0x1017,
            target_addr=0x12A0,
            return_addr=0x101A,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            return_shape="dx_ax",
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    statements = codegen.cfunc.statements.statements
    assert len(statements) == 1
    assert isinstance(statements[0], CAssignment)
    assert _same_c_expression_8616(statements[0].lhs, cl_finish)
    assert statements[0].rhs is clock_call
    assert getattr(codegen, "_inertia_dx_ax_return_pair_assignments_folded_8616", 0) == 1


def test_materialize_callsite_stack_arguments_prunes_stale_dx_ax_pair_after_destination_rewrite():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    low_carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="v10"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    high_carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["dx"][0], 2, name="v12"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    cl_finish = structured_c.CVariable(
        SimMemoryVariable(0xB48, 4, name="clFinish", region=0x4010),
        variable_type=SimTypeLong(False),
        codegen=codegen,
    )
    clock_call = CFunctionCall(
        "clock",
        SimpleNamespace(addr=0x1017, name="clock", block_addrs_set={0x1017}),
        [],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(cl_finish, clock_call, codegen=codegen),
            CStatements([], codegen=codegen),
            CAssignment(
                cl_finish,
                structured_c.CBinaryOp(
                    "Or",
                    low_carrier,
                    structured_c.CBinaryOp(
                        "Shl",
                        high_carrier,
                        structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(clock_call): CallsiteSummary8616(
            callsite_addr=0x1017,
            target_addr=0x12A0,
            return_addr=0x101A,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            return_shape="dx_ax",
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    statements = codegen.cfunc.statements.statements
    assert len(statements) == 1
    assert isinstance(statements[0], CAssignment)
    assert _same_c_expression_8616(statements[0].lhs, cl_finish)
    assert statements[0].rhs is clock_call
    assert getattr(codegen, "_inertia_dx_ax_return_pair_assignments_folded_8616", 0) == 1


def test_materialize_callsite_return_destination_consumes_exact_adjacent_stale_alias():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_223"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ch_slot = SimStackVariable(-2, 2, base="bp", name="ch", region=0x4010)
    ch = structured_c.CVariable(ch_slot, variable_type=SimTypeShort(False), codegen=codegen)
    call = CFunctionCall(
        "getch",
        SimpleNamespace(addr=0x1234, name="getch", block_addrs_set={0x1234}),
        [],
        codegen=codegen,
    )
    call_assignment = CAssignment(carrier, call, codegen=codegen)
    stale_alias = CAssignment(ch, carrier, codegen=codegen)
    root = CStatements([call_assignment, stale_alias], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variables_in_use={ch_slot: ch},
        unified_local_vars={ch_slot: {(ch, ch.variable_type)}},
    )
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4050,
            target_addr=0x1234,
            return_addr=0x4053,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            return_store_destination=("bp", -2),
            return_store_width=2,
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    assert root.statements == [call_assignment]
    assert _same_c_expression_8616(call_assignment.lhs, ch)
    assert call_assignment.rhs is call
    assert codegen._inertia_call_return_destination_stale_alias_pruned_8616 == 1


def test_materialize_callsite_return_destination_crosses_unrelated_carriers_for_exact_stale_alias():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_223"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    unrelated_lhs = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["dx"][0], 2, name="vvar_224"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    unrelated_rhs = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["cx"][0], 2, name="vvar_23"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ch_slot = SimStackVariable(-2, 2, base="bp", name="ch", region=0x4010)
    ch = structured_c.CVariable(ch_slot, variable_type=SimTypeShort(False), codegen=codegen)
    call = CFunctionCall(
        "getch",
        SimpleNamespace(addr=0x1234, name="getch", block_addrs_set={0x1234}),
        [],
        codegen=codegen,
    )
    call_assignment = CAssignment(carrier, call, codegen=codegen)
    unrelated_assignment = CAssignment(unrelated_lhs, unrelated_rhs, codegen=codegen)
    stale_alias = CAssignment(ch, carrier, codegen=codegen)
    root = CStatements([call_assignment, unrelated_assignment, stale_alias], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variables_in_use={ch_slot: ch},
        unified_local_vars={ch_slot: {(ch, ch.variable_type)}},
    )
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4050,
            target_addr=0x1234,
            return_addr=0x4053,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            return_store_destination=("bp", -2),
            return_store_width=2,
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    assert root.statements == [call_assignment, unrelated_assignment]
    assert _same_c_expression_8616(call_assignment.lhs, ch)
    assert codegen._inertia_call_return_destination_stale_alias_pruned_8616 == 1


def test_materialize_callsite_return_destination_prefers_binary_proven_stack_width():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    ax_offset = project.arch.registers["ax"][0]
    carrier = CDirtyExpression(
        SimpleNamespace(varid=223, reg=ax_offset, bits=16, name="vvar_223"),
        codegen=codegen,
    )
    unrelated_lhs = CDirtyExpression(
        SimpleNamespace(varid=224, reg=ax_offset, bits=16, name="vvar_224"),
        codegen=codegen,
    )
    unrelated_rhs = CDirtyExpression(
        SimpleNamespace(varid=23, reg=project.arch.registers["cx"][0], bits=16, name="vvar_23"),
        codegen=codegen,
    )
    word_slot = SimStackVariable(-2, 2, base="bp", name="ch", region=0x4010)
    word_view = structured_c.CVariable(word_slot, variable_type=SimTypeShort(False), codegen=codegen)
    byte_slot = SimStackVariable(-2, 1, base="bp", name="local_2", region=0x4010)
    byte_view = structured_c.CVariable(byte_slot, variable_type=SimTypeChar(False), codegen=codegen)
    call = CFunctionCall(
        "getch",
        SimpleNamespace(addr=0x1234, name="getch", block_addrs_set={0x1234}),
        [],
        codegen=codegen,
    )
    call_assignment = CAssignment(carrier, call, codegen=codegen)
    unrelated_assignment = CAssignment(unrelated_lhs, unrelated_rhs, codegen=codegen)
    stale_alias = CAssignment(byte_view, carrier, codegen=codegen)
    root = CStatements([call_assignment, unrelated_assignment, stale_alias], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variables_in_use={word_slot: word_view, byte_slot: byte_view},
        unified_local_vars={
            word_slot: {(word_view, word_view.variable_type)},
            byte_slot: {(byte_view, byte_view.variable_type)},
        },
    )
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4050,
            target_addr=0x1234,
            return_addr=0x4053,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            return_store_destination=("bp", -2),
            return_store_width=1,
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    assert root.statements == [call_assignment, unrelated_assignment]
    assert _same_c_expression_8616(call_assignment.lhs, byte_view)
    assert codegen._inertia_call_return_destination_stale_alias_pruned_8616 == 1


def test_materialize_callsite_return_destination_refuses_to_cross_competing_return_use():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_223"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    competing_lhs = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["dx"][0], 2, name="observed_result"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ch_slot = SimStackVariable(-2, 2, base="bp", name="ch", region=0x4010)
    ch = structured_c.CVariable(ch_slot, variable_type=SimTypeShort(False), codegen=codegen)
    call = CFunctionCall(
        "getch",
        SimpleNamespace(addr=0x1234, name="getch", block_addrs_set={0x1234}),
        [],
        codegen=codegen,
    )
    call_assignment = CAssignment(carrier, call, codegen=codegen)
    competing_use = CAssignment(competing_lhs, carrier, codegen=codegen)
    stale_alias = CAssignment(ch, carrier, codegen=codegen)
    root = CStatements([call_assignment, competing_use, stale_alias], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variables_in_use={ch_slot: ch},
        unified_local_vars={ch_slot: {(ch, ch.variable_type)}},
    )
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4050,
            target_addr=0x1234,
            return_addr=0x4053,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            return_store_destination=("bp", -2),
            return_store_width=2,
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is False

    assert root.statements == [call_assignment, competing_use, stale_alias]
    assert _same_c_expression_8616(call_assignment.lhs, carrier)
    assert not hasattr(codegen, "_inertia_call_return_destination_stale_alias_pruned_8616")


def test_materialize_callsite_return_destination_keeps_carrier_read_after_stale_alias():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_223"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    competing_lhs = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["dx"][0], 2, name="observed_result"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ch_slot = SimStackVariable(-2, 2, base="bp", name="ch", region=0x4010)
    ch = structured_c.CVariable(ch_slot, variable_type=SimTypeShort(False), codegen=codegen)
    call = CFunctionCall(
        "getch",
        SimpleNamespace(addr=0x1234, name="getch", block_addrs_set={0x1234}),
        [],
        codegen=codegen,
    )
    call_assignment = CAssignment(carrier, call, codegen=codegen)
    stale_alias = CAssignment(ch, carrier, codegen=codegen)
    competing_use = CAssignment(competing_lhs, carrier, codegen=codegen)
    root = CStatements([call_assignment, stale_alias, competing_use], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variables_in_use={ch_slot: ch},
        unified_local_vars={ch_slot: {(ch, ch.variable_type)}},
    )
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4050,
            target_addr=0x1234,
            return_addr=0x4053,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            return_store_destination=("bp", -2),
            return_store_width=2,
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is False

    assert root.statements == [call_assignment, stale_alias, competing_use]
    assert _same_c_expression_8616(call_assignment.lhs, carrier)
    assert not hasattr(codegen, "_inertia_call_return_destination_stale_alias_pruned_8616")


def test_materialize_callsite_stack_arguments_prunes_stale_dx_ax_pair_with_renamed_low_carrier():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    low_carrier = structured_c.CVariable(
        SimStackVariable(-2, 2, name="local_2"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    high_carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["dx"][0], 2, name="v9"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    cl_start = structured_c.CVariable(
        SimMemoryVariable(0x100, 4, name="clStart", region=0x4010),
        variable_type=SimTypeLong(False),
        codegen=codegen,
    )
    clock_call = CFunctionCall(
        "clock",
        SimpleNamespace(addr=0x1017, name="clock", block_addrs_set={0x1017}),
        [],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(cl_start, clock_call, codegen=codegen),
            CAssignment(
                cl_start,
                structured_c.CBinaryOp(
                    "Or",
                    low_carrier,
                    structured_c.CBinaryOp(
                        "Shl",
                        high_carrier,
                        structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(clock_call): CallsiteSummary8616(
            callsite_addr=0x1017,
            target_addr=0x12A0,
            return_addr=0x101A,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            return_shape="dx_ax",
            return_store_destination=("global", 0x100),
            return_store_width=4,
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    statements = codegen.cfunc.statements.statements
    assert len(statements) == 1
    assert isinstance(statements[0], CAssignment)
    assert _same_c_expression_8616(statements[0].lhs, cl_start)
    assert statements[0].rhs is clock_call
    assert getattr(codegen, "_inertia_dx_ax_return_pair_assignments_folded_8616", 0) == 1


def test_materialize_callsite_stack_arguments_prunes_adjacent_stale_dx_ax_pair_without_summary_key():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    low_carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="v9"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    high_carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["dx"][0], 2, name="v11"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    cl_finish = structured_c.CVariable(
        SimMemoryVariable(0xB48, 4, name="clFinish", region=0x4010),
        variable_type=SimTypeLong(False),
        codegen=codegen,
    )
    clock_call = CFunctionCall(
        "clock",
        SimpleNamespace(addr=0x1017, name="clock", block_addrs_set={0x1017}),
        [],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(cl_finish, clock_call, codegen=codegen),
            CAssignment(
                cl_finish,
                structured_c.CBinaryOp(
                    "Or",
                    low_carrier,
                    structured_c.CBinaryOp(
                        "Shl",
                        high_carrier,
                        structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    statements = codegen.cfunc.statements.statements
    assert len(statements) == 1
    assert isinstance(statements[0], CAssignment)
    assert _same_c_expression_8616(statements[0].lhs, cl_finish)
    assert statements[0].rhs is clock_call
    assert getattr(codegen, "_inertia_dx_ax_return_pair_assignments_folded_8616", 0) == 1


def test_materialize_callsite_prunes_ret_reg_pre_call_stack_carriers_after_return_arg_materialized():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    local_buf = structured_c.CVariable(
        SimStackVariable(-18, 18, base="bp", name="ach", region=0x4010),
        variable_type=SimTypeBottom(),
        codegen=codegen,
    )
    i_var = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    div_call = CFunctionCall(
        "aNldiv",
        SimpleNamespace(addr=0x10D3, name="aNldiv", block_addrs_set={0x10D3}),
        [
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
            structured_c.CConstant(30, SimTypeShort(False), codegen=codegen),
            structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
        ],
        codegen=codegen,
    )
    stale_local = CAssignment(
        i_var,
        CDirtyExpression("tmp_ret_ax", codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x10DF},
    )
    stale_dirty = CAssignment(
        CDirtyExpression("tmp_ret_dx", codegen=codegen),
        CDirtyExpression("tmp_ret_rhs", codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x10DF},
    )
    sprintf_call = CFunctionCall(
        "sprintf",
        SimpleNamespace(addr=0x10E0, name="sprintf", block_addrs_set={0x10E0}),
        [],
        codegen=codegen,
    )
    call_stmt = CExpressionStatement(sprintf_call, codegen=codegen)
    codegen.cfunc.statements = CStatements([stale_local, stale_dirty, call_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen.cfunc.variables_in_use = {local_buf.variable: local_buf, i_var.variable: i_var}
    codegen.cfunc.unified_local_vars = {
        local_buf.variable: {(local_buf, local_buf.variable_type)},
        i_var.variable: {(i_var, i_var.variable_type)},
    }
    codegen._inertia_callsite_return_exprs_8616 = {0x10D3: div_call}
    codegen._inertia_callsite_summaries = {
        id(sprintf_call): CallsiteSummary8616(
            callsite_addr=0x10E0,
            target_addr=0x12BA,
            return_addr=0x10E3,
            kind="direct_near",
            arg_count=4,
            arg_widths=(2, 2, 2, 2),
            stack_cleanup=8,
            return_register="ax",
            return_used=False,
            push_arg_sources=(
                ("ret_reg", 0x10D3, "dx"),
                ("ret_reg", 0x10D3, "ax"),
                ("imm", 0x16A),
                ("bp_addr", -18),
            ),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    statements = codegen.cfunc.statements.statements
    assert statements == [call_stmt]
    assert len(sprintf_call.args) == 3
    assert isinstance(sprintf_call.args[2], CFunctionCall)
    assert sprintf_call.args[2].callee_target == "aNldiv"


def test_materialize_callsite_keeps_ret_reg_pre_call_stack_carriers_without_recorded_return_arg():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    i_var = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    stale_local = CAssignment(
        i_var,
        CDirtyExpression("tmp_ret_ax", codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x10DF},
    )
    sprintf_call = CFunctionCall(
        "sprintf",
        SimpleNamespace(addr=0x10E0, name="sprintf", block_addrs_set={0x10E0}),
        [structured_c.CConstant(0, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
    )
    call_stmt = CExpressionStatement(sprintf_call, codegen=codegen)
    codegen.cfunc.statements = CStatements([stale_local, call_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(sprintf_call): CallsiteSummary8616(
            callsite_addr=0x10E0,
            target_addr=0x12BA,
            return_addr=0x10E3,
            kind="direct_near",
            arg_count=4,
            arg_widths=(2, 2, 2, 2),
            stack_cleanup=8,
            return_register="ax",
            return_used=False,
            push_arg_sources=(
                ("ret_reg", 0x10D3, "dx"),
                ("ret_reg", 0x10D3, "ax"),
                ("imm", 0x16A),
                ("bp_addr", -18),
            ),
        ),
    }

    _materialize_callsite_stack_arguments_8616(project, codegen)

    assert stale_local in codegen.cfunc.statements.statements
    assert call_stmt in codegen.cfunc.statements.statements


def test_callsite_prototype_mismatch_defers_until_final_gate():
    project = _project()
    codegen = _empty_codegen(project)

    call = CFunctionCall(
        "memset",
        SimpleNamespace(addr=0x1544, name="memset", block_addrs_set={0x1544}),
        [],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=3,
            arg_widths=(2, 2, 2),
            stack_cleanup=6,
            return_register=None,
            return_used=False,
            push_arg_sources=(None, ("imm", 223), ("bp_addr", -44)),
        ),
    }

    codegen._inertia_callsite_final_gate_active_8616 = False
    _normalize_call_target_names_8616(codegen)
    stats = codegen._inertia_callsite_materialization_stats
    assert stats.known_prototype_arg_mismatch_count == 1

    codegen = _empty_codegen(project)
    call = CFunctionCall(
        "memset",
        SimpleNamespace(addr=0x1544, name="memset", block_addrs_set={0x1544}),
        [],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=3,
            arg_widths=(2, 2, 2),
            stack_cleanup=6,
            return_register=None,
            return_used=False,
            push_arg_sources=(None, ("imm", 223), ("bp_addr", -44)),
        ),
    }
    codegen._inertia_callsite_final_gate_active_8616 = True
    with pytest.raises(PipelineHardError, match="known prototype call argument mismatch"):
        _normalize_call_target_names_8616(codegen)


def test_materialize_callsite_stack_arguments_uses_indexed_global_push_source():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    i_row = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {i_row.variable: i_row}
    codegen.cfunc.unified_local_vars = {i_row.variable: {(i_row, i_row.variable_type)}}
    call = CFunctionCall(
        "settextcolor",
        SimpleNamespace(addr=0x1544, name="settextcolor", block_addrs_set={0x1544}),
        [],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
            push_arg_sources=(("global_index", 0x0B4D, 1, ("bp", 4), (("shl", 1),)),),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    final_call = codegen.cfunc.statements.statements[0].expr
    assert len(final_call.args) == 1
    arg = final_call.args[0]
    assert isinstance(arg, CFunctionCall)
    assert arg.callee_target == "SEG_U8"
    assert len(arg.args) == 2
    offset = arg.args[1]
    assert isinstance(offset, structured_c.CBinaryOp)
    assert offset.op == "Add"
    offset_nodes = (offset, *_iter_c_nodes_deep_8616(offset))
    assert any(getattr(node, "value", None) == 0x0B4D for node in offset_nodes)
    assert any(
        isinstance(node, structured_c.CBinaryOp)
        and node.op == "Shl"
        and getattr(getattr(node.lhs, "variable", None), "offset", None) == 4
        and getattr(node.rhs, "value", None) == 1
        for node in offset_nodes
    )


def test_materialize_callsite_stack_arguments_uses_segmented_indirect_push_source():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    argv = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="argv", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    index = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="index", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {argv.variable: argv, index.variable: index}
    codegen.cfunc.unified_local_vars = {
        argv.variable: {(argv, argv.variable_type)},
        index.variable: {(index, index.variable_type)},
    }
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=argv.variable,
        cvar=argv,
        bp_offset=6,
        entry_sp_offset=4,
        size=2,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=index.variable,
        cvar=index,
        bp_offset=-2,
        entry_sp_offset=-4,
        size=2,
    )
    call = CFunctionCall(
        "settextcolor",
        SimpleNamespace(addr=0x1544, name="settextcolor", block_addrs_set={0x1544}),
        [],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
            push_arg_sources=(
                (
                    "seg_indirect",
                    "ds",
                    2,
                    (
                        "expr",
                        ("bp", 6),
                        (
                            (
                                CallsitePushExprOp8616.ADD_SOURCE.value,
                                ("expr", ("bp", -2), ((CallsitePushExprOp8616.SHL.value, 1),)),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    final_call = codegen.cfunc.statements.statements[0].expr
    assert len(final_call.args) == 1
    arg = final_call.args[0]
    assert isinstance(arg, CFunctionCall)
    assert arg.callee_target == "SEG_U16"
    assert len(arg.args) == 2
    address = arg.args[1]
    assert isinstance(address, structured_c.CBinaryOp)
    assert address.op == "Add"
    assert getattr(getattr(address.lhs, "variable", None), "name", None) == "argv"
    assert isinstance(address.rhs, structured_c.CBinaryOp)
    assert address.rhs.op == "Shl"
    assert getattr(getattr(address.rhs.lhs, "variable", None), "name", None) == "index"
    assert getattr(address.rhs.rhs, "value", None) == 1


def test_materialize_callsite_stack_arguments_uses_bp_index_address_source():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    buffer_var = structured_c.CVariable(
        SimStackVariable(-44, 44, base="bp", name="achT", region=0x4010),
        variable_type=SimTypeBottom(),
        codegen=codegen,
    )
    count_var = structured_c.CVariable(
        SimStackVariable(-46, 2, base="bp", name="cSpace", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {buffer_var.variable: buffer_var, count_var.variable: count_var}
    codegen.cfunc.unified_local_vars = {
        buffer_var.variable: {(buffer_var, buffer_var.variable_type)},
        count_var.variable: {(count_var, count_var.variable_type)},
    }
    call = CFunctionCall(
        "memset",
        SimpleNamespace(addr=0x1544, name="memset", block_addrs_set={0x1544}),
        [],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=3,
            arg_widths=(2, 2, 2),
            stack_cleanup=6,
            return_register=None,
            return_used=False,
            push_arg_sources=(("bp", -46), ("imm", 32), ("bp_index_addr", -44, "si", 1)),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    final_call = codegen.cfunc.statements.statements[0].expr
    assert len(final_call.args) == 3
    dst = final_call.args[0]
    assert isinstance(dst, structured_c.CBinaryOp)
    assert dst.op == "Add"
    assert isinstance(dst.lhs, structured_c.CUnaryOp)
    assert dst.lhs.op == "Reference"
    assert getattr(getattr(dst.lhs.operand, "variable", None), "name", None) == "achT"
    assert getattr(getattr(dst.rhs, "variable", None), "name", None) == "si"
    assert getattr(final_call.args[1], "value", None) == 32
    assert getattr(getattr(final_call.args[2], "variable", None), "name", None) == "cSpace"
    stats = codegen._inertia_callsite_materialization_stats
    assert stats.known_prototype_arg_mismatch_count == 0


def test_materialize_callsite_stack_arguments_prefers_one_push_widths_over_portable_prototype():
    project = _project()
    codegen = _empty_codegen(project)

    def stack_cvar(offset: int, name: str) -> CVariable:
        variable = SimStackVariable(offset, 2, base="bp", name=name, region=0x4010)
        return CVariable(variable, variable_type=SimTypeShort(False), codegen=codegen)

    buffer_var = stack_cvar(-82, "achTmp")
    width_var = stack_cvar(8, "iWidth")
    left_var = stack_cvar(6, "iLeft")
    stale_linear_offset = stack_cvar(80, "local_50")
    cvars = (buffer_var, width_var, left_var, stale_linear_offset)
    codegen.cfunc.variables_in_use = {cvar.variable: cvar for cvar in cvars}
    codegen.cfunc.unified_local_vars = {
        cvar.variable: {(cvar, cvar.variable_type)} for cvar in cvars
    }
    call = CFunctionCall(
        "memset",
        SimpleNamespace(addr=0x1544, name="memset", block_addrs_set={0x1544}),
        [],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [CExpressionStatement(call, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=3,
            arg_widths=(2, 2, 2),
            stack_cleanup=6,
            return_register=None,
            return_used=False,
            push_arg_sources=(("bp", 8), ("imm", 205), ("bp_addr", -82)),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    final_call = codegen.cfunc.statements.statements[0].expr
    assert len(final_call.args) == 3
    assert isinstance(final_call.args[0], CUnaryOp)
    assert final_call.args[0].op == "Reference"
    assert getattr(getattr(final_call.args[0].operand, "variable", None), "offset", None) == -82
    assert getattr(final_call.args[1], "value", None) == 205
    assert getattr(getattr(final_call.args[2], "variable", None), "offset", None) == 8
    assert codegen._inertia_callsite_materialization_stats.physical_arg_width_override_count == 1


def test_materialize_callsite_stack_arguments_uses_bp_index_address_source_proven_index():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    buffer_var = structured_c.CVariable(
        SimStackVariable(-44, 44, base="bp", name="achT", region=0x4010),
        variable_type=SimTypeBottom(),
        codegen=codegen,
    )
    count_var = structured_c.CVariable(
        SimStackVariable(-46, 2, base="bp", name="cSpace", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    i_row = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {
        buffer_var.variable: buffer_var,
        count_var.variable: count_var,
        i_row.variable: i_row,
    }
    codegen.cfunc.unified_local_vars = {
        buffer_var.variable: {(buffer_var, buffer_var.variable_type)},
        count_var.variable: {(count_var, count_var.variable_type)},
        i_row.variable: {(i_row, i_row.variable_type)},
    }
    call = CFunctionCall(
        "memset",
        SimpleNamespace(addr=0x1544, name="memset", block_addrs_set={0x1544}),
        [],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=3,
            arg_widths=(2, 2, 2),
            stack_cleanup=6,
            return_register=None,
            return_used=False,
            push_arg_sources=(
                ("bp", -46),
                ("imm", 32),
                ("bp_index_addr", -44, "si", 1, ("global_index", 0x0B4C, 1, ("bp", 4), (("shl", 1),))),
            ),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    final_call = codegen.cfunc.statements.statements[0].expr
    assert len(final_call.args) == 3
    dst = final_call.args[0]
    assert isinstance(dst, structured_c.CBinaryOp)
    assert dst.op == "Add"
    assert not any(
        (getattr(getattr(node, "variable", None), "name", None) or getattr(node, "name", None)) == "si"
        for node in (dst, *_iter_c_nodes_deep_8616(dst))
    )
    assert any(
        isinstance(node, CFunctionCall) and node.callee_target == "SEG_U8" for node in _iter_c_nodes_deep_8616(dst)
    )
    assert getattr(final_call.args[1], "value", None) == 32
    assert getattr(getattr(final_call.args[2], "variable", None), "name", None) == "cSpace"


def test_materialize_callsite_stack_arguments_resolves_bp_index_register_from_byte_carrier():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    buffer_var = structured_c.CVariable(
        SimStackVariable(-44, 44, base="bp", name="achT", region=0x4010),
        variable_type=SimTypeBottom(),
        codegen=codegen,
    )
    count_var = structured_c.CVariable(
        SimStackVariable(-46, 2, base="bp", name="cSpace", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    i_row = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ds_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ds"][0], 2, name="ds"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    stale_ax = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ir_5"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ax_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    si_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["si"][0], 2, name="si"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    byte_load = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Mul",
                ds_reg,
                structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Add",
                structured_c.CConstant(0x0B4C, SimTypeShort(False), codegen=codegen),
                structured_c.CBinaryOp(
                    "Mul",
                    i_row,
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    widened_byte = structured_c.CBinaryOp(
        "Or",
        structured_c.CBinaryOp(
            "And",
            stale_ax,
            structured_c.CConstant(0xFF00, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        byte_load,
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {
        buffer_var.variable: buffer_var,
        count_var.variable: count_var,
        i_row.variable: i_row,
    }
    codegen.cfunc.unified_local_vars = {
        buffer_var.variable: {(buffer_var, buffer_var.variable_type)},
        count_var.variable: {(count_var, count_var.variable_type)},
        i_row.variable: {(i_row, i_row.variable_type)},
    }
    call = CFunctionCall(
        "memset",
        SimpleNamespace(addr=0x1544, name="memset", block_addrs_set={0x1544}),
        [],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(ax_reg, widened_byte, codegen=codegen),
            CAssignment(si_reg, ax_reg, codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=3,
            arg_widths=(2, 2, 2),
            stack_cleanup=6,
            return_register=None,
            return_used=False,
            push_arg_sources=(("bp", -46), ("imm", 32), ("bp_index_addr", -44, "si", 1)),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    final_call = codegen.cfunc.statements.statements[-1].expr
    assert len(final_call.args) == 3
    dst = final_call.args[0]
    assert isinstance(dst, structured_c.CBinaryOp)
    assert dst.op == "Add"
    assert not any(
        (getattr(getattr(node, "variable", None), "name", None) or getattr(node, "name", None)) == "si"
        for node in (dst, *_iter_c_nodes_deep_8616(dst))
    )
    assert any(_same_c_expression_8616(node, byte_load) for node in (dst, *_iter_c_nodes_deep_8616(dst)))
    assert getattr(final_call.args[1], "value", None) == 32
    assert getattr(getattr(final_call.args[2], "variable", None), "name", None) == "cSpace"
    stats = codegen._inertia_callsite_materialization_stats
    assert stats.known_prototype_arg_mismatch_count == 0


def test_normalize_call_target_names_repairs_unmaterialized_far_pointer_args_before_final_gate():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    local_buf = structured_c.CVariable(
        SimStackVariable(-44, 44, base="bp", name="achT", region=0x4010),
        variable_type=SimTypeBottom(),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {local_buf.variable: local_buf}
    codegen.cfunc.unified_local_vars = {local_buf.variable: {(local_buf, local_buf.variable_type)}}
    call = CFunctionCall(
        "outtext",
        SimpleNamespace(addr=0x1544, name="outtext", block_addrs_set={0x1544}),
        [],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("seg", "ss"), ("bp_addr", -44)),
        ),
    }

    assert _normalize_call_target_names_8616(codegen) is True

    final_call = codegen.cfunc.statements.statements[0].expr
    assert len(final_call.args) == 1
    arg = final_call.args[0]
    assert isinstance(arg, structured_c.CUnaryOp)
    assert arg.op == "Reference"
    assert getattr(getattr(arg.operand, "variable", None), "name", None) == "achT"
    stats = codegen._inertia_callsite_materialization_stats
    assert stats.known_prototype_arg_mismatch_count == 0
    assert stats.call_arg_fact_count == 1
    assert stats.call_arg_materialized_count == 1
    assert stats.failure_count == 0
    assert stats.pointer_arg_materialized_count >= 1


def test_materialize_callsite_stack_arguments_normalizes_byte_merge_value_arg():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    ds_carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ds"][0], 2, name="ir_3"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    stale_ax = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ir_1"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    i_row = structured_c.CVariable(
        SimStackVariable(2, 2, base="bp", name="iRow", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    byte_load = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Mul",
                ds_carrier,
                structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Add",
                structured_c.CConstant(0x0B4C, SimTypeShort(False), codegen=codegen),
                structured_c.CBinaryOp(
                    "Mul",
                    i_row,
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    widened_byte_arg = structured_c.CBinaryOp(
        "Or",
        structured_c.CBinaryOp(
            "And",
            stale_ax,
            structured_c.CConstant(0xFF00, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        byte_load,
        codegen=codegen,
    )
    call = CFunctionCall(
        "memset",
        SimpleNamespace(addr=0x1544, name="memset", block_addrs_set={0x1544}),
        [
            structured_c.CConstant(0x1200, SimTypeShort(False), codegen=codegen),
            structured_c.CConstant(0xDF, SimTypeShort(False), codegen=codegen),
            widened_byte_arg,
        ],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=3,
            arg_widths=(2, 2, 2),
            stack_cleanup=6,
            return_register="ax",
            return_used=True,
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    final_call = codegen.cfunc.statements.statements[0].expr
    assert len(final_call.args) == 3
    count_arg = final_call.args[2]
    assert isinstance(count_arg, structured_c.CUnaryOp)
    assert count_arg.op == "Dereference"
    assert "ir_1" not in _expr_fingerprint(count_arg, project)
    stats = codegen._inertia_callsite_materialization_stats
    assert stats.byte_merge_raw_fact_count == 1
    assert stats.byte_merge_classified_fact_count == 1
    assert stats.byte_merge_materialized_count == 1
    assert stats.byte_merge_refused_count == 0


def test_tail_validation_call_fingerprint_prefers_resolved_function_addr_for_named_target():
    project = _project()
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, name=None, create=False: (
                SimpleNamespace(addr=0x104D, name="InitMenu") if name == "InitMenu" else None
            )
        )
    )
    codegen = _empty_codegen(project)
    call = CFunctionCall("InitMenu", None, [], codegen=codegen)

    fingerprint = _expr_fingerprint(call, project)

    assert fingerprint == "call:addr:0x104d()"


def test_tail_validation_stays_stable_for_unknown_to_named_call_when_callsite_matches():
    project = _project()
    function = SimpleNamespace(get_call_sites=lambda: (0x4012,))
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, name=None, create=False: (
                function
                if addr == 0x4010
                else SimpleNamespace(addr=0x104D, name="InitMenu")
                if name == "InitMenu"
                else None
            )
        )
    )
    before_codegen = _empty_codegen(project)
    before_call = CFunctionCall(None, None, [], codegen=before_codegen)
    before_codegen.cfunc.statements = CStatements(
        [before_call, CReturn(None, codegen=before_codegen)], addr=0x4010, codegen=before_codegen
    )
    before_codegen.cfunc.body = before_codegen.cfunc.statements

    after_codegen = _empty_codegen(project)
    after_call = CFunctionCall("InitMenu", None, [], codegen=after_codegen)
    after_codegen.cfunc.statements = CStatements(
        [after_call, CReturn(None, codegen=after_codegen)], addr=0x4010, codegen=after_codegen
    )
    after_codegen.cfunc.body = after_codegen.cfunc.statements

    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before_codegen),
        collect_x86_16_tail_validation_summary(project, after_codegen),
    )

    assert diff["changed"] is False


@pytest.mark.parametrize(
    "caller_verdict",
    (None, CallerReturnUseVerdict8616.UNUSED),
)
def test_materialize_callsite_stack_arguments_respects_terminal_caller_liveness(
    caller_verdict: CallerReturnUseVerdict8616 | None,
):
    project = _project()
    if caller_verdict is not None:
        record_caller_return_use_evidence_8616(
            project,
            0x4010,
            CallerReturnUseEvidence8616(
                target_addr=0x4010,
                verdict=caller_verdict,
                raw_fact_count=1,
                normalized_fact_count=1,
                classified_fact_count=1,
                materialized_count=1,
                failure_count=0,
                used_callsite_count=0,
                unused_callsite_count=1,
                callsite_addrs=(0x5010,),
            ),
        )
    codegen = _empty_codegen(project)
    _bind_function_result_observation_provider_8616(codegen, proven_function_result_observation_8616)
    projected_args = tuple(
        CVariable(
            SimStackVariable(offset, 2, base="bp", name=name, region=0x4010),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        )
        for offset, name in ((-2, "local_2"), (4, "arg_4"))
    )
    codegen.cfunc.variables_in_use = {cvar.variable: cvar for cvar in projected_args}
    for cvar in projected_args:
        record_stack_variable_coordinate_projection_8616(
            codegen,
            variable=cvar.variable,
            cvar=cvar,
            bp_offset=cvar.variable.offset,
            entry_sp_offset=cvar.variable.offset,
            size=2,
        )
    setup_lhs = _scg.c.CVariable(
        SimRegisterVariable(project.arch.registers["bx"][0], 2, name="setup"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    setup_rhs = _scg.c.CVariable(
        SimRegisterVariable(project.arch.registers["cx"][0], 2, name="source"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall("callee", None, [], codegen=codegen)
    setup_stmt = CAssignment(setup_lhs, setup_rhs, codegen=codegen)
    call_stmt = CExpressionStatement(call, codegen=codegen)
    tail_block = CStatements([setup_stmt, call_stmt], addr=0x4012, codegen=codegen)
    return_block = CStatements([CReturn(None, codegen=codegen)], addr=0x4015, codegen=codegen)
    codegen.cfunc.functy = SimTypeFunction([], SimTypeBottom(label="void")).with_arch(project.arch)
    codegen.cfunc.prototype = codegen.cfunc.functy
    codegen.cfunc.statements = CStatements([tail_block, return_block], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register="ax",
            return_used=True,
            return_use_kind=CallsiteReturnUseKind8616.FUNCTION_RETURN,
            push_arg_sources=(("bp", 4), ("bp", -2)),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    if caller_verdict is CallerReturnUseVerdict8616.UNUSED:
        assert codegen.cfunc.statements.statements[0].statements == [setup_stmt, call_stmt]
        assert codegen.cfunc.statements.statements[1].statements[0].retval is None
        assert type(codegen.cfunc.functy.returnty) is SimTypeBottom
        return
    assert codegen.cfunc.statements.statements[0].statements == [setup_stmt]
    ret_stmt = codegen.cfunc.statements.statements[1].statements[0]
    assert isinstance(ret_stmt, CReturn)
    assert isinstance(ret_stmt.retval, CFunctionCall)
    assert ret_stmt.retval.callee_target == "callee"
    assert [arg.variable.offset for arg in ret_stmt.retval.args] == [-2, 4]
    assert type(codegen.cfunc.functy.returnty) is SimTypeShort


def test_call_floor_recognizes_summary_proven_return_call_without_duplication(monkeypatch):
    project = _project()
    codegen = _empty_codegen(project)
    irow1 = _scg.c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    irow2 = _scg.c.CVariable(
        SimStackVariable(6, 2, base="bp", name="iRow2"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    first_draw = CFunctionCall("DrawBar", None, [irow1], codegen=codegen)
    second_draw = CFunctionCall("DrawBar", None, [irow2], codegen=codegen)
    tail_call = CFunctionCall("sub_d29", None, [irow1], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            CExpressionStatement(first_draw, codegen=codegen),
            CExpressionStatement(second_draw, codegen=codegen),
            CReturn(tail_call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(first_draw): CallsiteSummary8616(
            0x4012, 0x1544, 0x4015, "direct_near", 1, (2,), 2, "ax", True, push_arg_sources=(("bp", 4),)
        ),
        id(second_draw): CallsiteSummary8616(
            0x4018, 0x1544, 0x401B, "direct_near", 1, (2,), 2, "ax", True, push_arg_sources=(("bp", 6),)
        ),
        id(tail_call): CallsiteSummary8616(
            0x4020, 0x1666, 0x4023, "direct_near", 1, (2,), 2, "ax", True, push_arg_sources=(("bp", 4),)
        ),
    }

    function = SimpleNamespace(
        addr=0x4010,
        get_call_sites=lambda: [0x4012, 0x4018, 0x4020],
        get_call_target=lambda callsite: {0x4012: 0x1544, 0x4018: 0x1544, 0x4020: 0x1666}[callsite],
    )
    by_addr = {
        0x4010: function,
        0x1544: SimpleNamespace(addr=0x1544, name="DrawBar"),
        0x1666: SimpleNamespace(addr=0x1666, name="sub_d29"),
    }

    class _Functions:
        def function(self, addr=None, name=None, create=False):
            if isinstance(addr, int):
                return by_addr.get(addr)
            if name == "DrawBar":
                return by_addr[0x1544]
            if name == "DrawTime":
                return SimpleNamespace(addr=0x1666, name="DrawTime")
            return None

    project.kb = SimpleNamespace(functions=_Functions())
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._cod_source_call_names_8616",
        lambda _project, _func_addr: ("DrawBar", "DrawBar", "DrawTime"),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._source_name_matches_target_8616",
        lambda _project, target_addr, source_name: False,
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, callsite, **_kwargs: codegen._inertia_callsite_summaries[
            {
                0x4012: id(first_draw),
                0x4018: id(second_draw),
                0x4020: id(tail_call),
            }[callsite]
        ],
    )

    changed = _recover_missing_direct_calls_from_evidence_8616(project, codegen)

    assert changed is False
    calls = [node for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements) if isinstance(node, CFunctionCall)]
    assert [getattr(call, "callee_target", None) for call in calls] == ["DrawBar", "DrawBar", "sub_d29"]
    assert len(codegen.cfunc.statements.statements) == 3


def test_recover_missing_direct_calls_uses_structured_presence(monkeypatch):
    project = _project_with_call_recovery_functions()
    codegen = _codegen(project, [])
    call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)
    codegen.cfunc.statements.statements = [CExpressionStatement(call, codegen=codegen)]
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._cod_source_call_names_8616",
        lambda _project, _func_addr: ("DrawBar",),
    )

    changed = _recover_missing_direct_calls_from_evidence_8616(project, codegen)

    assert changed is False
    calls = [node for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements) if isinstance(node, CFunctionCall)]
    assert [getattr(call, "callee_target", None) for call in calls] == ["DrawBar"]


def test_recover_missing_direct_calls_skips_no_call_instruction_functions(monkeypatch):
    project = _project_with_call_recovery_functions()
    codegen = _codegen(project, [])
    summaries = (
        SimpleNamespace(mnemonic="mov"),
        SimpleNamespace(mnemonic="cmp"),
        SimpleNamespace(mnemonic="ret"),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._function_instruction_summaries_8616",
        lambda _project, _function: summaries,
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._prepare_call_recovery_context_8616",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("call recovery context should be skipped")),
    )

    changed = _recover_missing_direct_calls_from_evidence_8616(project, codegen)

    assert changed is False
    assert codegen._inertia_call_recovery_skipped_no_call_instructions_8616 == 1
    assert codegen._inertia_call_recovery_callsite_count_8616 == 0


def test_recover_missing_direct_calls_skips_stack_probe_only_functions(monkeypatch):
    project = _project()
    current = SimpleNamespace(
        addr=0x4010,
        get_call_sites=lambda: (0x4012,),
        get_call_target=lambda _addr: 0x5000,
    )

    class _Functions:
        def function(self, addr=None, name=None, create=False):
            if addr == 0x4010:
                return current
            if addr == 0x5000:
                return SimpleNamespace(addr=0x5000, name="aNchkstk")
            return None

    project.kb = SimpleNamespace(functions=_Functions())
    codegen = _codegen(project, [])
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._prepare_call_recovery_context_8616",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("stack-probe-only context should be skipped")),
    )

    changed = _recover_missing_direct_calls_from_evidence_8616(project, codegen)

    assert changed is False
    assert codegen._inertia_call_recovery_callsite_count_8616 == 1
    assert codegen._inertia_call_recovery_non_probe_callsite_count_8616 == 0
    assert codegen._inertia_call_recovery_skipped_no_call_instructions_8616 == 1


def test_recover_missing_direct_calls_materializes_frontend_proven_tail_jump(monkeypatch):
    from angr_platforms.X86_16.analysis_helpers import CallTargetKind8616, CallTargetSeed

    project = _project()
    codegen = _codegen(project, [])
    current = SimpleNamespace(
        addr=0x4010,
        get_call_sites=lambda: (0x4011,),
        get_call_target=lambda addr: 0x4800 if addr == 0x4011 else None,
    )
    ordinary = SimpleNamespace(addr=0x4800, name="ordinary_target")
    tail = SimpleNamespace(addr=0x5000, name="tail_target")

    class _Functions:
        def function(self, addr=None, name=None, create=False):
            if addr == current.addr:
                return current
            if addr == ordinary.addr or name == ordinary.name:
                return ordinary
            if addr == tail.addr or name == tail.name:
                return tail
            return None

    project.kb = SimpleNamespace(functions=_Functions())
    ordinary_call = CFunctionCall(ordinary.name, ordinary, [], codegen=codegen)
    codegen.cfunc.statements.statements = [CExpressionStatement(ordinary_call, codegen=codegen)]
    inventory = {
        0x4011: CallsiteSummary8616(0x4011, ordinary.addr, 0x4012, "direct_near", 0, (), 0, "ax", False),
        0x4012: CallsiteSummary8616(0x4012, tail.addr, None, "tail_jump", 0, (), 0, "ax", False),
    }
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._callsite_summary_inventory_8616",
        lambda _codegen: inventory,
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.lowering.callsite_inventory_presence.structured_callsite_addr_8616",
        lambda call: 0x4011 if call is ordinary_call else None,
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls.collect_neighbor_call_targets",
        lambda _function: [
            CallTargetSeed(
                callsite_addr=0x4011,
                target_addr=ordinary.addr,
                return_addr=0x4012,
                kind=CallTargetKind8616.DIRECT_NEAR_CALL,
            ),
            CallTargetSeed(
                callsite_addr=0x4012,
                target_addr=tail.addr,
                return_addr=None,
                kind=CallTargetKind8616.DIRECT_NEAR_TAIL_JUMP,
            )
        ],
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._source_call_floor_enabled_8616",
        lambda: True,
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._cod_source_call_names_8616",
        lambda _project, _func_addr: (ordinary.name,),
    )

    changed = _recover_missing_direct_calls_from_evidence_8616(project, codegen)

    assert changed is True
    calls = [node for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements) if isinstance(node, CFunctionCall)]
    assert [call.callee_target for call in calls] == ["ordinary_target", "tail_target"]


def test_recover_missing_direct_calls_ignores_rendered_text_presence(monkeypatch):
    project = _project_with_call_recovery_functions()
    codegen = _codegen(project, [])
    codegen.render_text = lambda _cfunc: "void f(void) { DrawBar(); }"
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._cod_source_call_names_8616",
        lambda _project, _func_addr: ("DrawBar",),
    )

    changed = _recover_missing_direct_calls_from_evidence_8616(project, codegen)

    assert changed is False
    calls = [node for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements) if isinstance(node, CFunctionCall)]
    assert [getattr(call, "callee_target", None) for call in calls] == []


def test_materialize_callsite_prunes_consumed_immediate_bp_setup_assignment():
    project = _project()
    codegen = _DummyCodegen(project)
    irow1 = CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    irow2 = CVariable(
        SimStackVariable(6, 2, base="bp", name="iRow2", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    probe = CFunctionCall(
        "aNchkstk",
        SimpleNamespace(addr=0x1001, name="aNchkstk"),
        [],
        tags={"ins_addr": 0x1006},
        codegen=codegen,
    )
    setup = CAssignment(
        irow2,
        irow1,
        tags={"ins_addr": 0x1014, "vex_block_addr": 0x1013, "vex_stmt_idx": 89},
        codegen=codegen,
    )
    call = CFunctionCall(
        "DrawBar",
        SimpleNamespace(addr=0x1040, name="DrawBar"),
        [irow2],
        tags={"ins_addr": 0x1017},
        codegen=codegen,
    )
    root = CStatements(
        [
            CExpressionStatement(probe, codegen=codegen),
            setup,
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x1000,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(probe): CallsiteSummary8616(0x1006, 0x1001, 0x1009, "near", 0, (), 0, None, False, True),
        id(call): CallsiteSummary8616(
            0x1017,
            0x1040,
            0x101A,
            "near",
            1,
            (2,),
            2,
            "ax",
            True,
            push_arg_sources=(("bp", 6),),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert setup not in root.statements
    assert call in [getattr(stmt, "expr", None) for stmt in root.statements]
    assert codegen._inertia_call_arg_setup_assignments_pruned_8616 == 1


def test_materialize_callsite_context_preserves_nested_live_stack_setup_assignment():
    project = _project()
    codegen = _DummyCodegen(project)
    irow1 = CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    irow2 = CVariable(
        SimStackVariable(6, 2, base="bp", name="iRow2", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    probe = CFunctionCall(
        "aNchkstk",
        SimpleNamespace(addr=0x1001, name="aNchkstk"),
        [],
        tags={"ins_addr": 0x1006},
        codegen=codegen,
    )
    setup = CAssignment(
        irow2,
        irow1,
        tags={"ins_addr": 0x1014, "vex_block_addr": 0x1013, "vex_stmt_idx": 89},
        codegen=codegen,
    )
    call = CFunctionCall(
        "DrawBar",
        SimpleNamespace(addr=0x1040, name="DrawBar"),
        [irow2],
        tags={"ins_addr": 0x1017},
        codegen=codegen,
    )
    nested = CStatements(
        [setup, CExpressionStatement(call, codegen=codegen)],
        addr=0x1013,
        codegen=codegen,
    )
    root = CStatements(
        [CExpressionStatement(probe, codegen=codegen), nested],
        addr=0x1000,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(probe): CallsiteSummary8616(0x1006, 0x1001, 0x1009, "near", 0, (), 0, None, False, True),
        id(call): CallsiteSummary8616(
            0x1017,
            0x1040,
            0x101A,
            "near",
            1,
            (2,),
            2,
            "ax",
            True,
            push_arg_sources=(("bp", 6),),
        ),
    }
    controls = _ensure_callsite_materialization_controls_8616(codegen)
    controls._inertia_callsite_disable_consumed_arg_store_prune_8616 = True
    controls._inertia_callsite_disable_stack_probe_setup_prune_8616 = True

    _materialize_callsite_stack_arguments_8616(project, codegen)

    assert setup in nested.statements
    assert controls._inertia_callsite_consumed_arg_store_prune_refused_by_context_8616 == 1
    assert controls._inertia_callsite_stack_probe_setup_prune_refused_by_context_8616 == 1


def test_materialize_callsite_relocates_future_stack_source_write_after_call():
    project = _project()
    codegen = _DummyCodegen(project)
    i_slot = CVariable(
        SimStackVariable(-2, 2, base="bp", name="i", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    child_slot = CVariable(
        SimStackVariable(-4, 2, base="bp", name="iChild", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    future_update = CAssignment(
        i_slot,
        child_slot,
        tags={"ins_addr": 0x1092, "vex_block_addr": 0x1080},
        codegen=codegen,
    )
    call = CFunctionCall(
        "SwapBars",
        SimpleNamespace(addr=0x2000, name="SwapBars"),
        [i_slot, child_slot],
        tags={"ins_addr": 0x1089},
        codegen=codegen,
    )
    call_stmt = CExpressionStatement(call, codegen=codegen)
    root = CStatements([future_update, call_stmt], addr=0x1000, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            0x1089,
            0x2000,
            0x108C,
            "near",
            2,
            (2, 2),
            4,
            None,
            False,
            push_arg_sources=(("bp", -4), ("bp", -2)),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert root.statements == [call_stmt, future_update]
    assert _args_match(call.args, [i_slot, child_slot])
    assert codegen._inertia_callsite_post_call_stack_source_writes_relocated_8616 == 1


def test_materialize_callsite_prunes_duplicate_pre_call_stack_source_clobber():
    project = _project()
    codegen = _DummyCodegen(project)
    dst_slot = CVariable(
        SimStackVariable(-2, 2, base="bp", name="dst", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    src_slot = CVariable(
        SimStackVariable(-4, 2, base="bp", name="src", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    pre_call_copy = CAssignment(dst_slot, src_slot, codegen=codegen)
    post_call_copy = CAssignment(dst_slot, src_slot, codegen=codegen)
    call = CFunctionCall(
        "DemoCall",
        SimpleNamespace(addr=0x2000, name="DemoCall"),
        [dst_slot, src_slot],
        codegen=codegen,
    )
    call_stmt = CExpressionStatement(call, codegen=codegen)
    root = CStatements([pre_call_copy, call_stmt, post_call_copy], addr=0x1000, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            0x1089,
            0x2000,
            0x108C,
            "near",
            2,
            (2, 2),
            4,
            None,
            False,
            push_arg_sources=(("bp", -4), ("bp", -2)),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert root.statements == [call_stmt, post_call_copy]
    assert _args_match(call.args, [dst_slot, src_slot])
    assert codegen._inertia_callsite_pre_call_source_clobbers_pruned_8616 == 1


def test_materialize_callsite_consumes_dirty_setup_assignments_at_callsite():
    project = _project()
    codegen = _DummyCodegen(project)
    dst_slot = CVariable(
        SimStackVariable(-2, 2, base="bp", name="dst", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    src_slot = CVariable(
        SimStackVariable(-4, 2, base="bp", name="src", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    def _dirty_setup(delta: int):
        dirty = CDirtyExpression(f"tmp_{delta}", codegen=codegen)
        return CAssignment(
            dirty,
            _scg.c.CBinaryOp(
                "Sub",
                CDirtyExpression(f"tmp_rhs_{delta}", codegen=codegen),
                _scg.c.CConstant(delta, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            tags={"ins_addr": 0x1089, "vex_block_addr": 0x1080},
            codegen=codegen,
        )

    setup_first = _dirty_setup(2)
    setup_second = _dirty_setup(4)
    call = CFunctionCall(
        "DemoCall",
        SimpleNamespace(addr=0x2000, name="DemoCall"),
        [dst_slot, src_slot],
        codegen=codegen,
    )
    call_stmt = CExpressionStatement(call, codegen=codegen)
    root = CStatements([setup_first, setup_second, call_stmt], addr=0x1000, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            0x1089,
            0x2000,
            0x108C,
            "near",
            2,
            (2, 2),
            4,
            None,
            False,
            push_arg_sources=(("bp", -4), ("bp", -2)),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert root.statements == [call_stmt]
    assert _args_match(call.args, [dst_slot, src_slot])
    assert codegen._inertia_callsite_dirty_setup_assignments_consumed_8616 == 2


def test_materialize_callsite_consumes_dirty_setup_assignments_in_pre_call_push_window():
    project = _project()
    codegen = _DummyCodegen(project)
    dst_slot = CVariable(
        SimStackVariable(-2, 2, base="bp", name="dst", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    src_slot = CVariable(
        SimStackVariable(-4, 2, base="bp", name="src", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    def _dirty_setup(delta: int):
        dirty = CDirtyExpression(f"tmp_{delta}", codegen=codegen)
        return CAssignment(
            dirty,
            _scg.c.CBinaryOp(
                "Sub",
                CDirtyExpression(f"tmp_rhs_{delta}", codegen=codegen),
                _scg.c.CConstant(delta, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            tags={"ins_addr": 0x1084, "vex_block_addr": 0x1080},
            codegen=codegen,
        )

    setup_first = _dirty_setup(2)
    setup_second = _dirty_setup(4)
    call = CFunctionCall(
        "DemoCall",
        SimpleNamespace(addr=0x2000, name="DemoCall"),
        [dst_slot, src_slot],
        codegen=codegen,
    )
    call_stmt = CExpressionStatement(call, codegen=codegen)
    root = CStatements([setup_first, setup_second, call_stmt], addr=0x1000, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            0x1089,
            0x2000,
            0x108C,
            "near",
            2,
            (2, 2),
            4,
            None,
            False,
            push_arg_sources=(("bp", -4), ("bp", -2)),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert root.statements == [call_stmt]
    assert _args_match(call.args, [dst_slot, src_slot])
    assert codegen._inertia_callsite_dirty_setup_assignments_consumed_8616 == 2


def test_materialize_callsite_prunes_byte_proven_dirty_source_alias_after_dirty_suffix():
    project = _project_with_bytes(0x1056, b"\x8b\x46\xfe\x05\x02\x00\x50")
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    i_slot = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    i_var = structured_c.CVariable(i_slot, variable_type=SimTypeShort(False), codegen=codegen)
    alias_rhs = CDirtyExpression("tmp_i_push", codegen=codegen)
    alias = CAssignment(i_var, alias_rhs, codegen=codegen, tags={"ins_addr": 0x105C})
    dirty_setup = CAssignment(
        CDirtyExpression("tmp_setup", codegen=codegen),
        CDirtyExpression("tmp_setup_rhs", codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x105E},
    )
    call_arg = structured_c.CBinaryOp(
        "Add",
        i_var,
        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    call = CFunctionCall(
        "settextposition",
        SimpleNamespace(name="settextposition"),
        [call_arg, structured_c.CConstant(48, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
    )
    call_stmt = CExpressionStatement(call, codegen=codegen)
    root = CStatements([alias, dirty_setup, call_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x105F,
            target_addr=0x128E4,
            return_addr=0x1064,
            kind="direct_far",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("imm", 48), ("expr", ("bp", -2), ((CallsitePushExprOp8616.ADD.value, 2),))),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert root.statements == [call_stmt]
    assert codegen._inertia_callsite_dirty_setup_assignments_consumed_8616 == 1
    assert codegen._inertia_callsite_pre_call_source_alias_artifacts_pruned_8616 == 1


def test_materialize_callsite_prunes_full_byte_proven_pre_call_setup_window():
    project = _project_with_bytes(0x1052, b"\xb8\x30\x00\x50\x8b\x46\xfe\x05\x02\x00\x50")
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    i_slot = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    i_var = structured_c.CVariable(i_slot, variable_type=SimTypeShort(False), codegen=codegen)
    leading_dirty = CAssignment(
        CDirtyExpression("tmp_imm", codegen=codegen),
        structured_c.CConstant(48, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1055},
    )
    alias = CAssignment(i_var, CDirtyExpression("tmp_i_push", codegen=codegen), codegen=codegen, tags={"ins_addr": 0x1055})
    dirty_suffix = CAssignment(
        CDirtyExpression("tmp_expr", codegen=codegen),
        CDirtyExpression("tmp_expr_rhs", codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x105C},
    )
    row_arg = structured_c.CBinaryOp(
        "Add",
        i_var,
        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    call = CFunctionCall(
        "settextposition",
        SimpleNamespace(name="settextposition"),
        [row_arg, structured_c.CConstant(48, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
    )
    call_stmt = CExpressionStatement(call, codegen=codegen)
    root = CStatements([leading_dirty, alias, dirty_suffix, call_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x105F,
            target_addr=0x128E4,
            return_addr=0x1064,
            kind="direct_far",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("imm", 48), ("expr", ("bp", -2), ((CallsitePushExprOp8616.ADD.value, 2),))),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert root.statements == [call_stmt]


def test_materialize_callsite_keeps_pre_call_setup_window_without_full_byte_evidence():
    project = _project_with_bytes(0x1056, b"\x8b\x46\xfe\x05\x02\x00\x50")
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    i_slot = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    i_var = structured_c.CVariable(i_slot, variable_type=SimTypeShort(False), codegen=codegen)
    leading_dirty = CAssignment(
        CDirtyExpression("tmp_imm", codegen=codegen),
        structured_c.CConstant(48, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1055},
    )
    alias = CAssignment(i_var, CDirtyExpression("tmp_i_push", codegen=codegen), codegen=codegen, tags={"ins_addr": 0x105C})
    dirty_suffix = CAssignment(
        CDirtyExpression("tmp_expr", codegen=codegen),
        CDirtyExpression("tmp_expr_rhs", codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x105C},
    )
    row_arg = structured_c.CBinaryOp(
        "Add",
        i_var,
        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    call = CFunctionCall(
        "settextposition",
        SimpleNamespace(name="settextposition"),
        [row_arg, structured_c.CConstant(48, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
    )
    call_stmt = CExpressionStatement(call, codegen=codegen)
    root = CStatements([leading_dirty, alias, dirty_suffix, call_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x105F,
            target_addr=0x128E4,
            return_addr=0x1064,
            kind="direct_far",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("imm", 48), ("expr", ("bp", -2), ((CallsitePushExprOp8616.ADD.value, 2),))),
        ),
    }

    _materialize_callsite_stack_arguments_8616(project, codegen)

    assert leading_dirty in root.statements
    assert call_stmt in root.statements


def test_prune_dead_stack_carriers_only_recurses_into_plain_statement_blocks():
    project = _project()
    codegen = _DummyCodegen(project)
    structured_c = _scg.c
    local_slot = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_11"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    loop_body = CStatements(
        [
            CAssignment(
                carrier,
                structured_c.CUnaryOp("Reference", local_slot, codegen=codegen),
                codegen=codegen,
            ),
            CExpressionStatement(
                CFunctionCall("Inner", SimpleNamespace(name="Inner"), [], codegen=codegen), codegen=codegen
            ),
        ],
        addr=0x4020,
        codegen=codegen,
    )
    loop_like = _LoopLikeNode(loop_body)
    prefix = CStatements([], addr=0x4000, codegen=codegen)
    suffix = CStatements([CReturn(None, codegen=codegen)], addr=0x4030, codegen=codegen)
    root = CStatements([prefix, loop_like, suffix], addr=0x4010, codegen=codegen)
    loop_like.statements = root.statements

    codegen._inertia_enable_safe_dead_carrier_prune = True
    codegen._inertia_callsite_materialization_stats = SimpleNamespace(
        call_target_fact_count=1,
        call_target_materialized_count=1,
        call_arg_fact_count=1,
        call_arg_materialized_count=1,
    )
    changed = _prune_dead_stack_carrier_assignments_8616(root, codegen=codegen)

    assert changed is True
    assert root.statements[1] is loop_like
    assert len(loop_body.statements) == 1
    assert isinstance(loop_body.statements[0], CExpressionStatement)


def test_prune_dead_stack_carriers_disabled_by_default():
    project = _project()
    codegen = _DummyCodegen(project)
    structured_c = _scg.c
    local_slot = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_11"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    root = CStatements(
        [
            CAssignment(carrier, structured_c.CUnaryOp("Reference", local_slot, codegen=codegen), codegen=codegen),
            CReturn(None, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )

    changed = _prune_dead_stack_carrier_assignments_8616(root, codegen=codegen)

    assert changed is False
    assert len(root.statements) == 2


def test_prune_dead_stack_carriers_refuses_without_materialization_evidence():
    project = _project()
    codegen = _DummyCodegen(project)
    structured_c = _scg.c
    local_slot = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_11"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    root = CStatements(
        [
            CAssignment(carrier, structured_c.CUnaryOp("Reference", local_slot, codegen=codegen), codegen=codegen),
            CReturn(None, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )

    changed = _prune_dead_stack_carrier_assignments_8616(root, codegen=codegen)

    assert changed is False
    assert len(root.statements) == 2


def test_refresh_callsite_summary_node_ids_preserves_non_dict_exact_callsite_tags():
    """Rust-backed tag maps must prevent same-target calls from being swapped."""

    class _TagMap:
        def __init__(self, values):
            self._values = dict(values)

        def items(self):
            return self._values.items()

    project = _project()
    codegen = _empty_codegen(project)
    callee = SimpleNamespace(addr=0x5000, name="sub_5000")
    first = CFunctionCall("sub_5000", callee, [], codegen=codegen)
    second = CFunctionCall("sub_5000", callee, [], codegen=codegen)
    first.tags = _TagMap({"ins_addr": 0x4010})
    second.tags = _TagMap({"ins_addr": 0x4020})
    codegen.cfunc.statements = CStatements(
        [
            CExpressionStatement(second, codegen=codegen),
            CExpressionStatement(first, codegen=codegen),
        ],
        addr=0x4000,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    first_summary = CallsiteSummary8616(
        callsite_addr=0x4010,
        target_addr=0x5000,
        return_addr=0x4013,
        kind="direct_near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=None,
        return_register=None,
        return_used=False,
    )
    second_summary = CallsiteSummary8616(
        callsite_addr=0x4020,
        target_addr=0x5000,
        return_addr=0x4023,
        kind="direct_near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=None,
        return_register=None,
        return_used=False,
    )
    summaries = {1: first_summary, 2: second_summary}

    assert _refresh_callsite_summary_node_ids_8616(codegen, summaries) is True
    assert summaries[id(first)].callsite_addr == 0x4010
    assert summaries[id(second)].callsite_addr == 0x4020
