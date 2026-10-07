from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import inertia.postprocess.decompiler_postprocess_calls as postprocess_calls
import inertia.structuring.decompiler_structuring_stage as structuring_stage
import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypePointer, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.postprocess.callsite_stack_metadata import _callsite_materialization_complete_8616
from inertia.semantics.callsite_summary import CallsitePushExprOp8616, CallsiteSummary8616
from inertia.semantics.callsite_summary_program import (
    ProgramCallsiteSummaryFact8616,
    attach_program_callsite_summary_evidence_8616,
    program_callsite_summary_evidence_from_facts_8616,
)
from inertia.postprocess.decompiler_postprocess_calls import (
    CallArgSemanticKind8616,
    CallsiteMaterializationDecision8616,
    CallsiteMaterializationStats,
    _annotated_function_pointer_stack_offsets_8616,
    _attach_callsite_summaries_8616,
    _call_arg_semantic_kind_8616,
    _finalize_callsite_materialization_stats_8616,
    _logical_expected_arg_count_for_summary_8616,
    _lookup_callee_function_8616,
    _materialize_callsite_stack_arguments_8616,
    _mov_reg_imm_setup_matches_push_source_8616,
    _normalize_call_target_names_8616,
    _ordered_callsite_pairs_8616,
    _refresh_callsite_summary_node_ids_8616,
    _reg_expr_setup_matches_push_source_8616,
    _sidecar_label_for_target_8616,
    _target_addr_is_recovered_function_entry_8616,
)
from inertia.postprocess.decompiler_postprocess_stage import (
    _materialize_callsite_stack_arguments_after_ss_lowering_8616,
)
from inertia.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)
from inertia.pipeline.errors import PipelineHardError

from inertia.lowering.analysis_helpers import (
    collect_neighbor_call_targets,
    resolve_direct_call_target_from_block,
    resolve_stored_near_call_target_from_function,
    sanitize_direct_call_sites_8616,
)


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


class _Memory:
    def __init__(self, data: bytes, base: int):
        self._data = data
        self._base = base

    def load(self, addr: int, size: int) -> bytes:
        start = addr - self._base
        return self._data[start : start + size]


def test_regeneration_replay_applies_bound_target_identity_before_arguments(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    codegen = SimpleNamespace(
        project=project,
        cfunc=object(),
        _inertia_callsite_summaries={1: object()},
    )
    calls: list[str] = []

    monkeypatch.setattr(
        postprocess_calls,
        "_attach_callsite_summaries_8616",
        lambda _project, _codegen: calls.append("attach") or False,
    )
    monkeypatch.setattr(
        postprocess_calls,
        "_materialize_callsite_stack_arguments_8616",
        lambda _project, _codegen: calls.append("stack-args") or True,
    )
    postprocess_calls._bind_call_target_identity_consumer_8616(
        codegen,
        lambda _project, _codegen: calls.append("target-identity") or False,
    )

    changed = postprocess_calls.replay_callsite_stack_arguments_after_regeneration_8616(
        project,
        codegen,
    )

    assert changed is True
    assert calls == ["attach", "target-identity", "stack-args"]


def test_regeneration_replay_refuses_missing_target_identity_binding(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    codegen = SimpleNamespace(
        project=project,
        cfunc=object(),
        _inertia_callsite_summaries={1: object()},
    )

    monkeypatch.setattr(
        postprocess_calls,
        "_attach_callsite_summaries_8616",
        lambda _project, _codegen: False,
    )
    monkeypatch.setattr(
        postprocess_calls,
        "_materialize_callsite_stack_arguments_8616",
        lambda _project, _codegen: False,
    )

    with pytest.raises(PipelineHardError, match="Structuring-bound Types/Lowering consumer"):
        postprocess_calls.replay_callsite_stack_arguments_after_regeneration_8616(
            project,
            codegen,
        )


def test_structuring_binds_target_identity_before_validation_mode_diverges(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    codegen = SimpleNamespace(project=project, cfunc=object(), _inertia_callsite_summaries={})
    calls: list[str] = []
    monkeypatch.setattr(
        structuring_stage,
        "canonicalize_callsite_target_identities_8616",
        lambda _project, _codegen: calls.append("target-identity") or False,
    )

    structuring_stage._bind_structuring_callsite_consumers_8616(codegen)
    changed = postprocess_calls._replay_call_target_identity_consumer_8616(project, codegen)

    assert changed is False
    assert calls == ["target-identity"]


def test_callsite_materialization_stats_expose_standard_evidence_counters():
    stats = CallsiteMaterializationStats(
        callsite_count=2,
        call_target_fact_count=2,
        call_target_materialized_count=1,
        call_arg_fact_count=3,
        call_arg_materialized_count=2,
        byte_merge_raw_fact_count=1,
        byte_merge_classified_fact_count=1,
        byte_merge_materialized_count=1,
        failure_count=2,
    )

    assert stats.evidence_counters() == {
        "raw_fact_count": 3,
        "normalized_fact_count": 3,
        "classified_fact_count": 6,
        "materialized_count": 4,
        "failure_count": 2,
    }
    assert stats.report_counters() == {
        "raw_fact_count": 3,
        "normalized_fact_count": 3,
        "classified_fact_count": 6,
        "materialized_count": 4,
        "failure_count": 2,
        "callsite_count": 2,
        "call_target_fact_count": 2,
        "call_target_materialized_count": 1,
        "call_arg_fact_count": 3,
        "call_arg_materialized_count": 2,
        "physical_arg_width_override_count": 0,
        "direct_push_override_recent_store_count": 0,
        "live_setup_definition_preserved_count": 0,
        "known_prototype_arg_mismatch_count": 0,
        "no_live_summarized_call_refusal_count": 0,
    }


def test_callsite_materialization_complete_uses_typed_stats_fields():
    codegen = SimpleNamespace(
        _inertia_callsite_materialization_stats=CallsiteMaterializationStats(
            call_target_fact_count=1,
            call_target_materialized_count=1,
            call_arg_fact_count=2,
            call_arg_materialized_count=2,
        )
    )

    assert _callsite_materialization_complete_8616(codegen) is True

    codegen._inertia_callsite_materialization_stats.call_arg_materialized_count = 1

    assert _callsite_materialization_complete_8616(codegen) is False


def test_callsite_materialization_complete_refuses_untyped_partial_stats():
    codegen = SimpleNamespace(
        _inertia_callsite_materialization_stats=SimpleNamespace(
            call_arg_materialized_count=1,
        )
    )

    assert _callsite_materialization_complete_8616(codegen) is False


def test_logical_summary_width_keeps_one_wide_arg_across_regeneration() -> None:
    summary = CallsiteSummary8616(
        callsite_addr=0x1010,
        target_addr=0x2000,
        return_addr=0x1013,
        kind="near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register=None,
        return_used=False,
        push_arg_sources=(("global", 0x102, 2), ("global", 0x100, 2)),
        logical_arg_widths=(4,),
    )

    assert _logical_expected_arg_count_for_summary_8616(None, None, summary) == 1


def test_callsite_materialization_hard_fails_when_classified_facts_materialize_none():
    project = SimpleNamespace()
    codegen = _DummyCodegen(project)
    call = CFunctionCall(
        "unresolved",
        SimpleNamespace(addr=0x7777, name="unresolved", block_addrs_set={0x7777}),
        [],
        codegen=codegen,
    )
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=None,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        )
    }

    try:
        _finalize_callsite_materialization_stats_8616(codegen)
    except PipelineHardError as ex:
        assert ex.layer == "callsite_materialization"
        assert ex.details["classified_fact_count"] == 1
        assert ex.details["materialized_count"] == 0
    else:
        raise AssertionError("expected PipelineHardError")


def test_callsite_materialization_stats_accept_exact_slice_rebased_target():
    project = SimpleNamespace(_inertia_original_linear_delta=0xFF38)
    codegen = _DummyCodegen(project)
    call = CFunctionCall(
        "clock",
        SimpleNamespace(addr=0x1446, name="clock", block_addrs_set={0x1446}),
        [],
        codegen=codegen,
    )
    root = CStatements([call], addr=0x1000, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x100B,
            target_addr=0x1137E,
            return_addr=0x100E,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="dx:ax",
            return_used=True,
        )
    }

    stats = _finalize_callsite_materialization_stats_8616(codegen)

    assert stats.call_target_fact_count == 1
    assert stats.call_target_materialized_count == 1
    assert stats.failure_count == 0


def test_sanitize_direct_call_sites_prunes_proven_non_call_entry():
    blocks = {
        0x1005A: SimpleNamespace(
            capstone=SimpleNamespace(
                insns=(
                    SimpleNamespace(address=0x1005A, mnemonic="push"),
                    SimpleNamespace(address=0x10060, mnemonic="call"),
                )
            )
        ),
        0x10060: SimpleNamespace(capstone=SimpleNamespace(insns=(SimpleNamespace(address=0x10060, mnemonic="call"),))),
    }
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: blocks[addr]),
    )
    function = SimpleNamespace(
        project=project,
        _call_sites={0x1005A: (0x5D2, None), 0x10060: (0x105D2, 0x10063)},
    )

    evidence = sanitize_direct_call_sites_8616(function)

    assert evidence.raw_fact_count == 2
    assert evidence.classified_fact_count == 2
    assert evidence.materialized_count == 1
    assert evidence.failure_count == 0
    assert function._call_sites == {0x10060: (0x105D2, 0x10063)}


def test_call_arg_semantic_kind_ignores_cod_source_pointer_evidence(tmp_path):
    cod_path = tmp_path / "TEST.COD"
    cod_path.write_text(
        "\n".join(
            (
                ";|*** void Swaps( BAR *bar1, BAR *bar2 )",
                ";|*** void SwapBars( int iRow1, int iRow2 )",
            )
        ),
        encoding="utf-8",
    )
    project = SimpleNamespace(_inertia_lst_metadata=SimpleNamespace(cod_path=cod_path))

    assert _call_arg_semantic_kind_8616("Swaps", 0, project=project) is CallArgSemanticKind8616.UNKNOWN
    assert _call_arg_semantic_kind_8616("Swaps", 1, project=project) is CallArgSemanticKind8616.UNKNOWN
    assert _call_arg_semantic_kind_8616("SwapBars", 0, project=project) is CallArgSemanticKind8616.UNKNOWN


def test_call_arg_semantic_kind_ignores_cod_source_call_when_reading_prototypes(tmp_path):
    cod_path = tmp_path / "TEST.COD"
    cod_path.write_text(
        "\n".join(
            (
                ";|*** #define _outtextxy( ach, x, y )   { _settextposition( y, x ); \\",
                ";|***                                     _outtext( ach ); }",
            )
        ),
        encoding="utf-8",
    )
    project = SimpleNamespace(_inertia_lst_metadata=SimpleNamespace(cod_path=cod_path))

    assert _call_arg_semantic_kind_8616("outtext", 0, project=project) is CallArgSemanticKind8616.POINTER


def test_mov_reg_imm_setup_matches_push_source_from_instruction_bytes():
    project = SimpleNamespace(loader=SimpleNamespace(memory=_Memory(b"\xb8\x4c\x0b\x50\x31\xc0", 0x1000)))

    assert _mov_reg_imm_setup_matches_push_source_8616(project, 0x1000, ("imm", 0x0B4C))
    assert _mov_reg_imm_setup_matches_push_source_8616(project, 0x1003, ("imm", 0x0B4C))
    assert not _mov_reg_imm_setup_matches_push_source_8616(project, 0x1000, ("imm", 0x1234))
    assert not _mov_reg_imm_setup_matches_push_source_8616(project, 0x1004, ("imm", 0))


def test_reg_expr_setup_matches_push_source_from_instruction_bytes():
    project = SimpleNamespace(loader=SimpleNamespace(memory=_Memory(b"\x8b\x46\xfe\xd1\xe0\x05\x4c\x0b\x50", 0x1000)))
    source = ("expr", ("bp", -2), (("shl", 1), ("add", 0x0B4C)))

    assert _reg_expr_setup_matches_push_source_8616(project, 0x1008, source)
    assert not _reg_expr_setup_matches_push_source_8616(project, 0x1008, ("expr", ("bp", -4), (("shl", 1),)))
    assert not _reg_expr_setup_matches_push_source_8616(project, 0x1007, source)


def test_reg_expr_setup_matches_dec_push_source_from_instruction_bytes():
    project = SimpleNamespace(loader=SimpleNamespace(memory=_Memory(b"\x8b\x46\xfe\x48\x50", 0x1000)))
    source = ("expr", ("bp", -2), (("sub", 1),))

    assert _reg_expr_setup_matches_push_source_8616(project, 0x1004, source)
    assert not _reg_expr_setup_matches_push_source_8616(project, 0x1004, ("expr", ("bp", -2), (("add", 1),)))


def test_callsite_materialization_prunes_proven_expr_push_source_alias_clobber(tmp_path):
    cod_path = tmp_path / "TEST.COD"
    cod_path.write_text(";|*** void Swaps( BAR *bar1, BAR *bar2 )\n", encoding="utf-8")
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(memory=_Memory(b"\x8b\x46\xfc\xd1\xe0\x05\x4c\x0b\x50", 0x1040)),
        _inertia_c_target="portable-flat",
        _inertia_lst_metadata=SimpleNamespace(cod_path=cod_path, code_labels={}),
    )
    codegen = _DummyCodegen(project)
    i_var = SimStackVariable(-4, 2, base="bp", name="i", region=0x4010)
    parent_var = SimStackVariable(-2, 2, base="bp", name="iParent", region=0x4010)
    ds_reg = project.arch.registers["ds"][0]
    ds_var = SimRegisterVariable(ds_reg, 2, name="ds")
    i_cvar = CVariable(i_var, variable_type=SimTypeShort(False), codegen=codegen)
    parent_cvar = CVariable(parent_var, variable_type=SimTypeShort(False), codegen=codegen)
    ds_cvar = CVariable(ds_var, variable_type=SimTypeShort(False), codegen=codegen)

    def indexed_seg_ptr(index):
        offset = CBinaryOp(
            "Add",
            CBinaryOp("Shl", index, CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen),
            CConstant(0x0B4C, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
        return CFunctionCall("SEG_PTR", None, [ds_cvar, offset], codegen=codegen)

    seed_parent = CAssignment(
        parent_cvar,
        CBinaryOp("Div", i_cvar, CConstant(2, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x100A},
    )
    clobber_parent = CAssignment(
        parent_cvar,
        CBinaryOp("Add", parent_cvar, CConstant(0x0B4C, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1048},
    )
    call = CFunctionCall(
        "Swaps",
        None,
        [indexed_seg_ptr(parent_cvar), indexed_seg_ptr(i_cvar)],
        codegen=codegen,
        tags={"ins_addr": 0x1052},
    )
    root = CStatements([seed_parent, clobber_parent, call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variables_in_use={i_var: i_cvar, parent_var: parent_cvar, ds_var: ds_cvar},
        unified_local_vars={},
    )
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x1052,
            target_addr=0x10794,
            return_addr=0x1055,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(
                ("expr", ("bp", -4), (("shl", 1), ("add", 0x0B4C))),
                ("expr", ("bp", -2), (("shl", 1), ("add", 0x0B4C))),
            ),
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert root.statements == [seed_parent, call]
    assert codegen._inertia_callsite_pre_call_source_alias_artifacts_pruned_8616 == 1


def test_callsite_materialization_counts_direct_bp_arg_materialization():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen(project)
    row_var = SimStackVariable(-2, 2, base="bp", name="iRowNext", region=0x4010)
    row_cvar = CVariable(row_var, variable_type=SimTypeShort(False), codegen=codegen)
    call = CFunctionCall("DrawTime", None, [], tags={"ins_addr": 0x4020}, codegen=codegen)
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variables_in_use={row_var: row_cvar},
        unified_local_vars={},
    )
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4020,
            target_addr=0x1544,
            return_addr=0x4023,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
            push_arg_sources=(("bp", -2),),
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(call.args) == 1
    assert call.args[0].variable is row_var
    assert codegen._inertia_callsite_materialization_stats.call_arg_materialized_count == 1


def test_callsite_materialization_rebinds_target_with_projected_pointer_args(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen(project)
    projected_args = tuple(
        CVariable(
            SimStackVariable(offset, 2, base="bp", name=name, region=0x4010),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        )
        for offset, name in ((-2, "local_2"), (-4, "local_4"))
    )
    call = CFunctionCall("SwapBars", None, [], codegen=codegen)
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variables_in_use={cvar.variable: cvar for cvar in projected_args},
        unified_local_vars={},
    )
    for cvar in projected_args:
        record_stack_variable_coordinate_projection_8616(
            codegen,
            variable=cvar.variable,
            cvar=cvar,
            bp_offset=cvar.variable.offset,
            entry_sp_offset=cvar.variable.offset,
            size=2,
        )
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x1052,
            target_addr=0x10794,
            return_addr=0x1055,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("bp", -4), ("bp", -2)),
        )
    }
    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls._sidecar_label_for_target_8616",
        lambda _project, target_addr: "Swaps" if target_addr == 0x10794 else None,
    )

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert call.callee_target == "Swaps"
    assert all(isinstance(arg, CVariable) for arg in call.args)
    assert tuple(arg.variable.offset for arg in call.args) == (-2, -4)
    stats = codegen._inertia_callsite_materialization_stats
    assert stats.call_arg_materialized_count == 2


def test_callsite_materialization_cache_hit_decision_short_circuits_second_pass(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen(project)
    call = CFunctionCall("DrawTime", None, [], tags={"ins_addr": 0x4020}, codegen=codegen)
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variables_in_use={},
        unified_local_vars={},
    )
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4020,
            target_addr=0x1544,
            return_addr=0x4023,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
            push_arg_sources=(("imm", 3),),
        )
    }

    changed_first = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed_first is True
    assert codegen._inertia_callsite_materialization_stats.callsite_materialization_attempt_count == 1
    assert codegen._inertia_callsite_materialization_stats.callsite_materialization_cache_hit_count == 0
    assert codegen._inertia_callsite_materialization_last_decision_8616 is CallsiteMaterializationDecision8616.PROCESSED_CHANGED

    changed_second = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed_second is False
    assert codegen._inertia_callsite_materialization_last_decision_8616 is CallsiteMaterializationDecision8616.CACHE_HIT
    assert codegen._inertia_callsite_materialization_last_changed_8616 is False
    assert codegen._inertia_callsite_materialization_stats.callsite_materialization_attempt_count == 1
    assert codegen._inertia_callsite_materialization_stats.callsite_materialization_cache_hit_count == 1

    changed_third = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed_third is False
    assert codegen._inertia_callsite_materialization_last_decision_8616 is CallsiteMaterializationDecision8616.CACHE_HIT
    assert codegen._inertia_callsite_materialization_stats.callsite_materialization_attempt_count == 1
    assert codegen._inertia_callsite_materialization_stats.callsite_materialization_cache_hit_count == 2


def test_after_ss_lowering_callsite_materialization_skips_when_no_gaps(monkeypatch):
    import inertia.postprocess.decompiler_postprocess_stage as stage

    calls = []
    codegen = SimpleNamespace(
        _inertia_callsite_materialization_complete_8616=True,
        _inertia_callsite_unmaterialized_arg_gaps_8616=(),
    )

    monkeypatch.setattr(
        stage,
        "_materialize_callsite_stack_arguments_preserve_setup_8616",
        lambda *_args: calls.append("materialize") or True,
    )

    changed = _materialize_callsite_stack_arguments_after_ss_lowering_8616(object(), codegen)

    assert changed is False
    assert calls == []
    assert codegen._inertia_callsite_after_ss_lowering_skipped_no_gaps_8616 == 1


def test_callsite_materialization_uses_proven_direct_global_for_push_source(monkeypatch):
    function = SimpleNamespace(addr=0x4010)

    class _Functions:
        def function(self, addr=None, create=False):
            return function if addr == 0x4010 else None

    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=_Functions()),
        _inertia_synthetic_globals={0x0BA2: ("cRow", 2)},
    )
    codegen = _DummyCodegen(project)
    call = CFunctionCall("QuickSort", None, [], tags={"ins_addr": 0x4020}, codegen=codegen)
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variables_in_use={},
        unified_local_vars={},
    )
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4020,
            target_addr=0x10CE0,
            return_addr=0x4023,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
            push_arg_sources=(("global", 0x0BA2, 2),),
        )
    }
    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls._function_instruction_summaries_8616",
        lambda _project, _function: [
            SimpleNamespace(
                op0_kind="direct_mem",
                op0_value=0x0BA2,
                op0_size=2,
                op1_kind=None,
                op1_value=None,
                op1_size=None,
            )
        ],
    )

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(call.args) == 1
    assert isinstance(call.args[0], CVariable)
    assert call.args[0].variable.name == "cRow"
    assert codegen._inertia_callsite_materialization_stats.call_arg_materialized_count == 1


def test_callsite_materialization_prunes_consumed_global_arg_byte_stores_only_with_summary():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen(project)
    ss_reg = project.arch.registers["ss"][0]
    ss_var = SimRegisterVariable(ss_reg, 2, name="ss")
    c_row_var = SimMemoryVariable(0x0BA2, 2, name="cRow", region=0x4010)
    ss_cvar = CVariable(ss_var, variable_type=SimTypeShort(False), codegen=codegen)
    c_row_cvar = CVariable(c_row_var, variable_type=SimTypeShort(False), codegen=codegen)
    stack_offset = CConstant(0xFFFC, SimTypeShort(False), codegen=codegen)
    stack_offset_high = CBinaryOp(
        "Add",
        stack_offset,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    low_store = CAssignment(
        CFunctionCall("SEG_U8", None, [ss_cvar, stack_offset], codegen=codegen),
        c_row_cvar,
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    high_store = CAssignment(
        CFunctionCall("SEG_U8", None, [ss_cvar, stack_offset_high], codegen=codegen),
        CBinaryOp("Shr", c_row_cvar, CConstant(8, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4019},
    )
    call = CFunctionCall(
        "QuickSort",
        None,
        [CConstant(0, SimTypeShort(False), codegen=codegen), c_row_cvar],
        tags={"ins_addr": 0x4020},
        codegen=codegen,
    )
    root = CStatements([low_store, high_store, call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variables_in_use={ss_var: ss_cvar, c_row_var: c_row_cvar},
        unified_local_vars={},
    )
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4020,
            target_addr=0x10CE0,
            return_addr=0x4023,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("global", 0x0BA2, 2), ("imm", 0)),
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert root.statements == [call]
    assert call.args[0].value == 0
    assert call.args[1] is c_row_cvar
    assert codegen._inertia_callsite_pre_call_scalar_high_byte_remnants_pruned_8616 == 2


def test_reg_expr_setup_matches_imul_ax_memory_push_source_from_instruction_bytes():
    project = SimpleNamespace(loader=SimpleNamespace(memory=_Memory(b"\xb8\x3c\x00\xf7\x6e\x04\x50", 0x1000)))
    source = ("expr", ("bp", 4), ((CallsitePushExprOp8616.MUL.value, 60),))

    assert _reg_expr_setup_matches_push_source_8616(project, 0x1006, source)
    assert not _reg_expr_setup_matches_push_source_8616(
        project,
        0x1006,
        ("expr", ("bp", 6), ((CallsitePushExprOp8616.MUL.value, 60),)),
    )
    assert not _reg_expr_setup_matches_push_source_8616(
        project,
        0x1006,
        ("expr", ("bp", 4), ((CallsitePushExprOp8616.MUL.value, 75),)),
    )


def test_sidecar_label_for_target_matches_unique_16bit_offset_for_linear_target():
    project = SimpleNamespace(
        _inertia_lst_metadata=SimpleNamespace(code_labels={0x0794: "_Swaps", 0x075B: "_SwapBars"}),
        kb=SimpleNamespace(labels={}),
    )

    assert _sidecar_label_for_target_8616(project, 0x10794) == "Swaps"


def test_sidecar_exact_generic_entry_blocks_unrelated_range_label():
    project = SimpleNamespace(
        _inertia_lst_metadata=SimpleNamespace(
            code_labels={0x1000: "_NamedOuter", 0x1010: "sub_1010"},
            code_ranges={0x1000: (0x1000, 0x1020)},
        ),
        kb=SimpleNamespace(labels={}),
    )

    assert _sidecar_label_for_target_8616(project, 0x1010) is None


def test_sidecar_label_for_target_prefers_exact_target_over_delta_candidate():
    labels = {0x10794: "_Swaps", 0x109E8: "_PercolateUp"}
    project = SimpleNamespace(
        _inertia_lst_metadata=SimpleNamespace(code_labels=labels),
        _inertia_original_linear_delta=0x254,
        kb=SimpleNamespace(labels={}),
    )

    assert _sidecar_label_for_target_8616(project, 0x10794) == "Swaps"


def test_attach_callsite_summaries_sets_summary_and_binds_callee(monkeypatch):
    project = SimpleNamespace()
    codegen = _DummyCodegen(project)
    call = CFunctionCall(None, None, [], codegen=codegen)
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    callee = SimpleNamespace(name="::0x1544::InitBars")
    function = SimpleNamespace(
        addr=0x4010,
        get_call_sites=lambda: [0x4012],
    )
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr, create=False: function if addr == 0x4010 else (callee if addr == 0x1544 else None)
        )
    )
    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, callsite_addr, *, target_inventory=None: CallsiteSummary8616(
            callsite_addr=callsite_addr,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=None,
            return_register=None,
            return_used=False,
        ),
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert codegen._inertia_callsite_summaries[id(call)] == CallsiteSummary8616(
        callsite_addr=0x4012,
        target_addr=0x1544,
        return_addr=0x4015,
        kind="direct_near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=None,
        return_register=None,
        return_used=False,
    )
    assert call.callee_func is callee
    assert call.callee_target == "InitBars"


def test_attach_callsite_summaries_preserves_proven_logical_projection(monkeypatch):
    project = SimpleNamespace()
    codegen = _DummyCodegen(project)
    call = CFunctionCall("load", None, [], tags={"ins_addr": 0x4012}, codegen=codegen)
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    function = SimpleNamespace(addr=0x4010, get_call_sites=lambda: [0x4012])
    callee = SimpleNamespace(addr=0x1544, name="load")
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr, create=False: function if addr == 0x4010 else callee if addr == 0x1544 else None
        )
    )
    fresh = CallsiteSummary8616(
        callsite_addr=0x4012,
        target_addr=0x1544,
        return_addr=0x4015,
        kind="direct_near",
        arg_count=5,
        arg_widths=(2, 2, 2, 2, 2),
        stack_cleanup=10,
        return_register="ax",
        return_used=True,
        push_arg_sources=(("bp", 8), ("bp", 6), ("imm", 1), ("imm", 0), ("bp", 4)),
    )
    previous = replace(fresh, logical_arg_widths=(2, 2, 2, 4))
    codegen._inertia_callsite_summary_inventory_8616 = {fresh.callsite_addr: previous}
    monkeypatch.setattr(
        postprocess_calls,
        "summarize_x86_16_callsite",
        lambda _function, _callsite_addr, *, target_inventory=None: fresh,
    )

    _attach_callsite_summaries_8616(project, codegen)

    assert codegen._inertia_callsite_summary_inventory_8616[0x4012].logical_arg_widths == (2, 2, 2, 4)
    assert codegen._inertia_callsite_summaries[id(call)].logical_arg_widths == (2, 2, 2, 4)


def test_attach_callsite_summaries_reuses_complete_program_evidence(monkeypatch):
    project = SimpleNamespace()
    codegen = _DummyCodegen(project)
    call = CFunctionCall("load", None, [], tags={"ins_addr": 0x4012}, codegen=codegen)
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    function = SimpleNamespace(addr=0x4010, get_call_sites=lambda: [0x4012])
    callee = SimpleNamespace(addr=0x1544, name="load")
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr, create=False: (
                function if addr == 0x4010 else callee if addr == 0x1544 else None
            )
        )
    )
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
    attach_program_callsite_summary_evidence_8616(
        project,
        program_callsite_summary_evidence_from_facts_8616(
            (ProgramCallsiteSummaryFact8616(0x4010, 0x4012, summary),)
        ),
    )
    monkeypatch.setattr(
        postprocess_calls,
        "summarize_x86_16_callsite",
        lambda *_args, **_kwargs: pytest.fail("complete program evidence was rebuilt"),
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert codegen._inertia_callsite_summary_inventory_8616 == {0x4012: summary}
    assert codegen._inertia_callsite_summaries[id(call)] == summary


def test_attach_callsite_summaries_retains_unrepresented_binary_callsite(monkeypatch):
    project = SimpleNamespace()
    codegen = _DummyCodegen(project)
    represented_call = CFunctionCall(
        "is_flag",
        None,
        [],
        tags={"ins_addr": 0x4010},
        codegen=codegen,
    )
    root = CStatements([represented_call], addr=0x4000, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4000, statements=root, body=root)

    callee = SimpleNamespace(addr=0x2000, name="is_flag")
    function = SimpleNamespace(
        addr=0x4000,
        get_call_sites=lambda: [0x4010, 0x4020],
    )
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr, create=False: (
                function if addr == 0x4000 else callee if addr == 0x2000 else None
            )
        )
    )

    def _summary_for_callsite(_function, callsite_addr, *, target_inventory=None):
        return CallsiteSummary8616(
            callsite_addr,
            0x2000,
            callsite_addr + 3,
            "direct_near",
            2,
            (2, 2),
            4,
            None,
            False,
            push_arg_sources=(
                ("imm", 104 if callsite_addr == 0x4010 else 118),
                ("reg", "ax"),
            ),
        )

    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls.summarize_x86_16_callsite",
        _summary_for_callsite,
    )

    _attach_callsite_summaries_8616(project, codegen)

    inventory = codegen._inertia_callsite_summary_inventory_8616
    assert tuple(inventory) == (0x4010, 0x4020)
    assert inventory[0x4010].push_arg_sources[0] == ("imm", 104)
    assert inventory[0x4020].push_arg_sources[0] == ("imm", 118)


def test_missing_owned_callsite_uses_exact_address_without_name_metadata():
    project = SimpleNamespace(
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda *args, **kwargs: None))
    )
    codegen = _DummyCodegen(project)
    root = CStatements([], addr=0x4000, codegen=codegen)
    summary = CallsiteSummary8616(
        callsite_addr=0x4030,
        target_addr=0x14590,
        return_addr=None,
        kind="direct_near_tail_jump",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=0,
        return_register=None,
        return_used=False,
    )
    codegen._inertia_callsite_summary_inventory_8616 = {
        summary.callsite_addr: summary,
    }

    missing = postprocess_calls._missing_calls_from_owned_inventory_8616(
        project,
        codegen,
        root,
    )

    assert missing == (["sub_14590"], {"sub_14590": [summary]})


def test_attach_callsite_summaries_recovers_empty_direct_callsite_inventory_from_blocks(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    codegen = _DummyCodegen(project)
    call = CFunctionCall(None, None, [], codegen=codegen)
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    class _Operand:
        def __init__(self, type_, imm):
            self.type = type_
            self.imm = imm

    class _Insn:
        def __init__(self):
            self.address = 0x4012
            self.mnemonic = "call"
            self.size = 3
            self.insn = SimpleNamespace(operands=(_Operand(2, 0x1544),), size=3)

    block = SimpleNamespace(capstone=SimpleNamespace(insns=(_Insn(),)), size=3)
    project.factory = SimpleNamespace(block=lambda addr, opt_level=0: block)

    callee = SimpleNamespace(name="::0x1544::InitBars")
    function = SimpleNamespace(
        addr=0x4010,
        project=project,
        block_addrs_set={0x4012},
        _call_sites={},
        get_call_sites=lambda: tuple(sorted(function._call_sites)),
        get_call_target=lambda callsite: function._call_sites[callsite][0],
        get_call_return=lambda callsite: function._call_sites[callsite][1],
    )
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr, create=False: function if addr == 0x4010 else (callee if addr == 0x1544 else None)
        )
    )
    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, callsite_addr, *, target_inventory=None: CallsiteSummary8616(
            callsite_addr=callsite_addr,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=None,
            return_register=None,
            return_used=False,
        ),
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert function.get_call_sites() == (0x4012,)
    assert call.callee_func is callee
    assert call.callee_target == "InitBars"


def test_attach_callsite_summaries_prefers_call_tags_over_ast_zip_order(monkeypatch):
    project = SimpleNamespace()
    codegen = _DummyCodegen(project)
    first = CFunctionCall(None, None, [], tags={"ins_addr": 0x4015}, codegen=codegen)
    second = CFunctionCall(None, None, [], tags={"ins_addr": 0x4012}, codegen=codegen)
    root = CStatements([first, second], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    callee_a = SimpleNamespace(name="::0x1544::InitBars")
    callee_b = SimpleNamespace(name="::0x1666::DrawTime")
    function = SimpleNamespace(
        addr=0x4010,
        get_call_sites=lambda: [0x4012, 0x4015],
    )
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr, create=False: (
                function if addr == 0x4010 else callee_a if addr == 0x1544 else callee_b if addr == 0x1666 else None
            )
        )
    )

    def _fake_summary(_function, callsite_addr, *, target_inventory=None):
        if callsite_addr == 0x4012:
            return CallsiteSummary8616(0x4012, 0x1544, 0x4015, "direct_near", 0, (), None, None, False)
        return CallsiteSummary8616(0x4015, 0x1666, 0x4018, "direct_near", 0, (), None, None, False)

    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls.summarize_x86_16_callsite",
        _fake_summary,
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert second.callee_func is callee_a
    assert second.callee_target == "InitBars"
    assert first.callee_func is callee_b
    assert first.callee_target == "DrawTime"


def test_attach_callsite_summaries_covers_regenerated_nodes_with_same_call_tag(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen(project)
    first = CFunctionCall(
        "displaycursor",
        None,
        [CConstant(1, SimTypeShort(False), tags={"ins_addr": 0x4010}, codegen=codegen)],
        tags={"ins_addr": 0x4012},
        codegen=codegen,
    )
    regenerated = CFunctionCall(
        "displaycursor",
        None,
        [CConstant(1, SimTypeShort(False), tags={"ins_addr": 0x4010}, codegen=codegen)],
        tags={"ins_addr": 0x4012},
        codegen=codegen,
    )
    root = CStatements([first, regenerated], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    callee = SimpleNamespace(addr=0x2000, name="displaycursor")
    function = SimpleNamespace(addr=0x4010, get_call_sites=lambda: [0x4012])
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, create=False, **_kwargs: (
                function if addr == 0x4010 else callee if addr == 0x2000 else None
            )
        ),
        labels={},
    )
    summary = CallsiteSummary8616(
        callsite_addr=0x4012,
        target_addr=0x2000,
        return_addr=0x4015,
        kind="direct_near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register=None,
        return_used=False,
        push_arg_sources=(("imm", 1),),
    )
    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, _callsite_addr, *, target_inventory=None: summary,
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert codegen._inertia_callsite_summaries[id(first)] is summary
    assert codegen._inertia_callsite_summaries[id(regenerated)] is summary
    assert first.callee_func is callee
    assert regenerated.callee_func is callee


def test_attach_callsite_summaries_does_not_shift_duplicate_target_names(monkeypatch):
    project = SimpleNamespace()
    codegen = _DummyCodegen(project)
    first_memset = CFunctionCall("memset", None, [], tags={"ins_addr": 0x4012}, codegen=codegen)
    second_memset = CFunctionCall("memset", None, [], tags={"ins_addr": 0x4020}, codegen=codegen)
    root = CStatements([first_memset, second_memset], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    memset_func = SimpleNamespace(addr=0x2000, name="memset")
    caller = SimpleNamespace(
        addr=0x4010,
        get_call_sites=lambda: [0x4012, 0x4020],
    )
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, create=False, **_kwargs: (
                caller if addr == 0x4010 else memset_func if addr == 0x2000 else None
            )
        ),
        labels={},
    )

    def _summary_for_callsite(_function, callsite_addr, *, target_inventory=None):
        return CallsiteSummary8616(
            callsite_addr=callsite_addr,
            target_addr=0x2000,
            return_addr=callsite_addr + 3,
            kind="direct_near",
            arg_count=3,
            arg_widths=(2, 2, 2),
            stack_cleanup=6,
            return_register="ax",
            return_used=True,
        )

    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls.summarize_x86_16_callsite",
        _summary_for_callsite,
    )
    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls._cod_metadata_for_function_8616",
        lambda _project, _addr: SimpleNamespace(call_names=("memset", "settextcolor")),
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert memset_func.name == "memset"
    assert first_memset.callee_func is memset_func
    assert second_memset.callee_func is memset_func
    assert first_memset.callee_target == "memset"
    assert second_memset.callee_target == "memset"


def test_attach_callsite_summaries_does_not_bind_unproved_source_name_to_known_target(monkeypatch):
    project = SimpleNamespace()
    codegen = _DummyCodegen(project)
    first_memset = CFunctionCall("memset", None, [], tags={"ins_addr": 0x4012}, codegen=codegen)
    second_memset = CFunctionCall("memset", None, [], tags={"ins_addr": 0x4020}, codegen=codegen)
    root = CStatements([first_memset, second_memset], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    caller = SimpleNamespace(
        addr=0x4010,
        get_call_sites=lambda: [0x4012, 0x4020],
    )
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, create=False, **_kwargs: caller if addr == 0x4010 else None
        ),
        labels={},
    )

    def _summary_for_callsite(_function, callsite_addr, *, target_inventory=None):
        return CallsiteSummary8616(
            callsite_addr=callsite_addr,
            target_addr=0x2000,
            return_addr=callsite_addr + 3,
            kind="direct_near",
            arg_count=3,
            arg_widths=(2, 2, 2),
            stack_cleanup=6,
            return_register="ax",
            return_used=True,
        )

    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls.summarize_x86_16_callsite",
        _summary_for_callsite,
    )
    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls._cod_metadata_for_function_8616",
        lambda _project, _addr: SimpleNamespace(call_names=("memset", "settextcolor")),
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert first_memset.callee_func is None
    assert second_memset.callee_func is None
    assert first_memset.callee_target == "memset"
    assert second_memset.callee_target == "memset"


def test_refresh_callsite_summaries_repairs_shifted_current_node_ids():
    project = SimpleNamespace()
    codegen = _DummyCodegen(project)
    percolate_up = CFunctionCall("PercolateUp", None, [], tags={"ins_addr": 0x1025}, codegen=codegen)
    swaps = CFunctionCall("Swaps", None, [], tags={"ins_addr": 0x1051}, codegen=codegen)
    swap_bars = CFunctionCall("SwapBars", None, [], tags={"ins_addr": 0x105E}, codegen=codegen)
    percolate_down = CFunctionCall("PercolateDown", None, [], tags={"ins_addr": 0x1069}, codegen=codegen)
    root = CStatements([percolate_up, swaps, swap_bars, percolate_down], addr=0x1000, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root, body=root)

    summary_up = CallsiteSummary8616(0x1025, 0x109E8, 0x1028, "direct_near", 1, (2,), 2, None, False)
    summary_swaps = CallsiteSummary8616(0x1051, 0x10794, 0x1054, "direct_near", 2, (2, 2), 4, None, False)
    summary_swap_bars = CallsiteSummary8616(0x105E, 0x10768, 0x1061, "direct_near", 2, (2, 2), 4, None, False)
    summary_down = CallsiteSummary8616(0x1069, 0x10A61, 0x106C, "direct_near", 1, (2,), 2, None, False)
    summary_map = {
        id(percolate_up): summary_swaps,
        id(swaps): summary_swap_bars,
        id(swap_bars): summary_down,
        id(percolate_down): summary_up,
    }
    codegen._inertia_callsite_summaries = summary_map

    changed = _refresh_callsite_summary_node_ids_8616(codegen, summary_map)

    assert changed is True
    assert summary_map[id(percolate_up)] is summary_up
    assert summary_map[id(swaps)] is summary_swaps
    assert summary_map[id(swap_bars)] is summary_swap_bars
    assert summary_map[id(percolate_down)] is summary_down


def test_refresh_callsite_summaries_prefers_named_duplicate_callsite_node():
    project = SimpleNamespace()
    codegen = _DummyCodegen(project)
    unknown_wrapper = CFunctionCall(None, None, [], tags={"ins_addr": 0x1025}, codegen=codegen)
    percolate_up = CFunctionCall("PercolateUp", None, [], tags={"ins_addr": 0x1025}, codegen=codegen)
    root = CStatements([unknown_wrapper, percolate_up], addr=0x1000, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root, body=root)

    summary_up = CallsiteSummary8616(0x1025, 0x109E8, 0x1028, "direct_near", 1, (2,), 2, None, False)
    summary_map = {0xDEADBEEF: summary_up}
    codegen._inertia_callsite_summaries = summary_map

    changed = _refresh_callsite_summary_node_ids_8616(codegen, summary_map)

    assert changed is True
    assert summary_map[id(percolate_up)] is summary_up
    assert id(unknown_wrapper) not in summary_map


def test_refresh_callsite_summaries_restores_missing_repeated_callee_from_inventory():
    project = SimpleNamespace()
    codegen = _DummyCodegen(project)
    first = CFunctionCall("is_flag", None, [], tags={"ins_addr": 0x4010}, codegen=codegen)
    second = CFunctionCall("is_flag", None, [], tags={"ins_addr": 0x4020}, codegen=codegen)
    root = CStatements([first, second], addr=0x4000, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4000, statements=root, body=root)

    first_summary = CallsiteSummary8616(
        0x4010,
        0x2000,
        0x4013,
        "direct_near",
        2,
        (2, 2),
        4,
        None,
        False,
        push_arg_sources=(("imm", 104), ("reg", "ax")),
    )
    second_summary = CallsiteSummary8616(
        0x4020,
        0x2000,
        0x4023,
        "direct_near",
        2,
        (2, 2),
        4,
        None,
        False,
        push_arg_sources=(("imm", 118), ("reg", "ax")),
    )
    summary_map = {id(first): first_summary}
    codegen._inertia_callsite_summaries = summary_map
    codegen._inertia_callsite_summary_inventory_8616 = {
        first_summary.callsite_addr: first_summary,
        second_summary.callsite_addr: second_summary,
    }

    changed = _refresh_callsite_summary_node_ids_8616(codegen, summary_map)

    assert changed is True
    assert summary_map[id(first)] is first_summary
    assert summary_map[id(second)] is second_summary
    assert summary_map[id(first)].push_arg_sources[0] == ("imm", 104)
    assert summary_map[id(second)].push_arg_sources[0] == ("imm", 118)


def test_refresh_callsite_summaries_never_rebinds_a_different_tagged_repeated_callee():
    project = SimpleNamespace()
    codegen = _DummyCodegen(project)
    surviving_call = CFunctionCall("is_flag", None, [], tags={"ins_addr": 0x4020}, codegen=codegen)
    root = CStatements([surviving_call], addr=0x4000, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4000, statements=root, body=root)

    removed_summary = CallsiteSummary8616(
        0x4010,
        0x2000,
        0x4013,
        "direct_near",
        2,
        (2, 2),
        4,
        None,
        False,
    )
    summary_map = {0xDEADBEEF: removed_summary}
    codegen._inertia_callsite_summaries = summary_map
    codegen._inertia_callsite_summary_inventory_8616 = {removed_summary.callsite_addr: removed_summary}

    changed = _refresh_callsite_summary_node_ids_8616(codegen, summary_map)

    assert changed is True
    assert summary_map == {}
    assert surviving_call.tags["ins_addr"] == 0x4020


def test_ordered_callsite_pairs_refuses_single_mismatched_named_node(monkeypatch):
    project = SimpleNamespace()
    codegen = _DummyCodegen(project)
    generated_internal_call = CFunctionCall(
        "sub_10079",
        SimpleNamespace(addr=0x10079, name="sub_10079"),
        [],
        codegen=codegen,
    )
    root = CStatements([generated_internal_call], addr=0x1005A, codegen=codegen)
    function = SimpleNamespace(addr=0x1005A, get_call_target=lambda _addr: 0x105D2)
    callee = SimpleNamespace(addr=0x105D2, name="aNchkstk")
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, create=False, name=None: (
                function if addr == 0x1005A else callee if addr == 0x105D2 else None
            )
        )
    )

    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, callsite_addr, *, target_inventory=None: CallsiteSummary8616(
            callsite_addr=callsite_addr,
            target_addr=0x105D2,
            return_addr=0x10063,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=None,
            return_register=None,
            return_used=False,
            stack_probe_helper=True,
        ),
    )

    pairs = _ordered_callsite_pairs_8616(
        project=project,
        function=function,
        root=root,
        call_nodes=[generated_internal_call],
        callsite_addrs=[0x10060],
        node_callsite_addr_resolver=lambda _node: None,
    )

    assert pairs == []


def test_ordered_callsite_pairs_refuses_tagged_stack_probe_for_normal_summary(monkeypatch):
    project = SimpleNamespace()
    codegen = _DummyCodegen(project)
    stack_probe = CFunctionCall(
        "aNchkstk",
        SimpleNamespace(addr=0x11222, name="aNchkstk", block_addrs_set={0x11222}),
        [],
        tags={"ins_addr": 0x1025},
        codegen=codegen,
    )
    root = CStatements([stack_probe], addr=0x1000, codegen=codegen)
    function = SimpleNamespace(addr=0x1000, get_call_target=lambda _addr: 0x109E8)
    percolate = SimpleNamespace(addr=0x109E8, name="PercolateUp", block_addrs_set={0x109E8})
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, create=False, name=None: (
                function if addr == 0x1000 else percolate if addr == 0x109E8 else None
            )
        )
    )

    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, callsite_addr, *, target_inventory=None: CallsiteSummary8616(
            callsite_addr=callsite_addr,
            target_addr=0x109E8,
            return_addr=0x1028,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
            stack_probe_helper=False,
        ),
    )

    pairs = _ordered_callsite_pairs_8616(
        project=project,
        function=function,
        root=root,
        call_nodes=[stack_probe],
        callsite_addrs=[0x1025],
        node_callsite_addr_resolver=lambda node: node.tags.get("ins_addr"),
    )

    assert pairs == []


def test_normalize_call_target_names_uses_binary_target_when_source_floor_disabled(monkeypatch):
    project = SimpleNamespace()
    codegen = _DummyCodegen(project)
    call = CFunctionCall(None, None, [], codegen=codegen)
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    target = SimpleNamespace(addr=0x2000, name="UserFunc", block_addrs_set={0x2000})
    function = SimpleNamespace(addr=0x4010, get_call_sites=lambda: [0x4012])

    class _Functions:
        def function(self, addr=None, create=False, name=None):
            if addr == 0x4010:
                return function
            if addr == 0x2000 or name == "UserFunc":
                return target
            return None

    project.kb = SimpleNamespace(functions=_Functions())
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x2000,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=None,
            return_register=None,
            return_used=False,
            stack_probe_helper=False,
        )
    }
    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls._cod_source_call_names_8616",
        lambda _project, _func_addr: ("aNchkstk", "UserFunc"),
    )

    changed = _normalize_call_target_names_8616(codegen)

    assert changed is True
    assert call.callee_target == "sub_2000"
    assert call.callee_func is None


def test_normalize_call_target_prefers_sidecar_range_label_over_conflicting_callee():
    project = SimpleNamespace(
        arch=Arch86_16(),
        _inertia_lst_metadata=SimpleNamespace(
            code_labels={0x1075B: "_SwapBars"},
            code_ranges={0x1075B: (0x1075B, 0x10794)},
        )
    )
    codegen = _DummyCodegen(project)
    stale_callee = SimpleNamespace(addr=0x10768, name="flsbuf", block_addrs_set={0x10768})
    call = CFunctionCall(
        "flsbuf",
        stale_callee,
        [
            CConstant(1, SimTypeShort(False), codegen=codegen),
            CConstant(2, SimTypeShort(False), codegen=codegen),
        ],
        tags={"ins_addr": 0x105E},
        codegen=codegen,
    )
    root = CStatements([call], addr=0x1000, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x105E,
            target_addr=0x10768,
            return_addr=0x1061,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            stack_probe_helper=False,
        )
    }

    class _Functions:
        def function(self, addr=None, create=False, name=None):
            if addr == 0x10768:
                return stale_callee
            return None

    project.kb = SimpleNamespace(functions=_Functions(), labels={})

    changed = _normalize_call_target_names_8616(codegen)

    assert changed is True
    assert call.callee_func is None
    assert call.callee_target == "SwapBars"


def test_sidecar_label_for_target_uses_containing_code_range():
    project = SimpleNamespace(
        _inertia_lst_metadata=SimpleNamespace(
            code_labels={0x1075B: "_SwapBars"},
            code_ranges={0x1075B: (0x1075B, 0x10794)},
        ),
        kb=SimpleNamespace(labels={}),
    )

    assert _sidecar_label_for_target_8616(project, 0x10768) == "SwapBars"


def test_function_pointer_stack_store_refuses_label_without_function_entry():
    project = SimpleNamespace(
        kb=SimpleNamespace(
            labels={1: "flsbuf"},
            functions=SimpleNamespace(function=lambda addr=None, create=False: None),
        )
    )

    assert _target_addr_is_recovered_function_entry_8616(project, 1) is False


def test_function_pointer_stack_store_accepts_recovered_function_entry():
    target = SimpleNamespace(addr=0x2000, name="Target", block_addrs_set={0x2000})
    project = SimpleNamespace(
        kb=SimpleNamespace(
            labels={0x2000: "Target"},
            functions=SimpleNamespace(function=lambda addr=None, create=False: target if addr == 0x2000 else None),
        )
    )

    assert _target_addr_is_recovered_function_entry_8616(project, 0x2000) is True


def test_function_pointer_stack_store_accepts_rebased_near_offset_function_entry():
    target = SimpleNamespace(addr=0x1010, name="Target", block_addrs_set={0x1010})

    class _Functions:
        def function(self, addr=None, create=False):
            return target if addr == 0x1010 else None

    project = SimpleNamespace(
        loader=SimpleNamespace(main_object=SimpleNamespace(min_addr=0x1000)),
        kb=SimpleNamespace(labels={0x1010: "Target"}, functions=_Functions()),
    )

    assert _target_addr_is_recovered_function_entry_8616(project, 0x10) is True


def test_function_pointer_stack_store_accepts_labeled_near_offset_with_prologue():
    class _Memory:
        def load(self, addr, size):
            if addr != 0x10010:
                raise KeyError(addr)
            return b"\x55\x8b\xec\x90"[:size]

    original_project = SimpleNamespace(
        loader=SimpleNamespace(main_object=SimpleNamespace(min_addr=0x10000), memory=_Memory()),
        kb=SimpleNamespace(labels={0x10010: "Target"}, functions=SimpleNamespace(function=lambda **_: None)),
    )
    project = SimpleNamespace(
        _inertia_original_project=original_project,
        kb=SimpleNamespace(labels={}, functions=SimpleNamespace(function=lambda **_: None)),
    )

    assert _target_addr_is_recovered_function_entry_8616(project, 0x10) is True


def test_function_pointer_stack_store_slot_evidence_requires_typed_annotation():
    fnptr_type = SimTypePointer(SimTypeFunction((SimTypeShort(False),), SimTypeBottom(label="void")), offset=0)
    function = SimpleNamespace(
        info={
            "x86_16_annotations": {
                "stack_vars": {
                    -2: {"name": "fn", "type": fnptr_type},
                    -4: {"name": "mask", "type": SimTypeShort(False)},
                }
            }
        }
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: function)),
    )

    assert _annotated_function_pointer_stack_offsets_8616(project, SimpleNamespace(addr=0x1000)) == frozenset({-2})


def test_function_pointer_stack_store_slot_evidence_ignores_source_lines_without_type():
    function = SimpleNamespace(
        info={
            "x86_16_annotations": {
                "source_lines": ("int (*fn)(int);", "int mask;"),
                "stack_vars": {-2: {"name": "fn"}, -4: {"name": "mask"}},
            }
        }
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: function)),
    )

    assert _annotated_function_pointer_stack_offsets_8616(project, SimpleNamespace(addr=0x1000)) == frozenset()


def test_normalize_call_targets_refuses_source_order_stack_probe_without_summary(monkeypatch):
    project = SimpleNamespace()
    codegen = _DummyCodegen(project)
    generated_internal_call = CFunctionCall(
        "sub_10079",
        SimpleNamespace(addr=0x10079, name="sub_10079"),
        [],
        codegen=codegen,
    )
    root = CStatements([generated_internal_call], addr=0x1005A, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1005A, statements=root, body=root)
    codegen._inertia_callsite_summaries = {}
    function = SimpleNamespace(addr=0x1005A, get_call_sites=lambda: [0x10060])
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, create=False, name=None: function if addr == 0x1005A else None
        )
    )
    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls._cod_source_call_names_8616",
        lambda _project, _func_addr: ("aNchkstk",),
    )

    changed = _normalize_call_target_names_8616(codegen)

    assert changed is False
    assert generated_internal_call.callee_target == "sub_10079"
    assert generated_internal_call.callee_func.name == "sub_10079"


def test_resolve_direct_call_target_rebases_exact_slice_linear_target():
    class _Operand:
        def __init__(self, type_, imm):
            self.type = type_
            self.imm = imm

    class _Insn:
        def __init__(self):
            self.address = 0x100E
            self.mnemonic = "call"
            self.insn = SimpleNamespace(operands=(_Operand(2, 0x0F60),))

    block = SimpleNamespace(capstone=SimpleNamespace(insns=(_Insn(),)))
    slice_project = SimpleNamespace(
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x1000, max_addr=0x2B)),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
        _inertia_original_project=SimpleNamespace(
            loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0xAC37))
        ),
        _inertia_original_linear_delta=0xF768,
    )

    assert resolve_direct_call_target_from_block(slice_project, 0x100E) == 0x106C8


def test_collect_neighbor_call_targets_classifies_rebased_exact_slice_near_call():
    class _Operand:
        def __init__(self, type_, imm):
            self.type = type_
            self.imm = imm

    class _Insn:
        def __init__(self):
            self.address = 0x100E
            self.mnemonic = "call"
            self.size = 3
            self.insn = SimpleNamespace(operands=(_Operand(2, 0x0F60),), size=3)

    block = SimpleNamespace(capstone=SimpleNamespace(insns=(_Insn(),)), size=3)
    slice_project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x1000, max_addr=0x2B)),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
        _inertia_original_project=SimpleNamespace(
            loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0xAC37))
        ),
        _inertia_original_linear_delta=0xF768,
    )
    function = SimpleNamespace(
        project=slice_project,
        get_call_sites=lambda: (0x100E,),
        get_call_target=lambda callsite: None,
        get_call_return=lambda callsite: 0x1011,
        block_addrs_set={0x1009},
    )

    recovered = collect_neighbor_call_targets(function)

    assert len(recovered) == 1
    assert recovered[0].callsite_addr == 0x100E
    assert recovered[0].target_addr == 0x106C8
    assert recovered[0].kind == "direct_near"


def test_collect_neighbor_call_targets_refuses_malformed_function_project_without_crashing():
    function = SimpleNamespace(
        project=None,
        get_call_sites=lambda: (0x1000,),
        get_call_return=lambda _callsite: 0x1003,
        block_addrs_set={0x1000},
    )
    function.project = function

    assert collect_neighbor_call_targets(function) == []
    assert resolve_stored_near_call_target_from_function(function, 0x1000) is None


def test_stored_near_call_target_refuses_non_mapping_initial_registers_without_crashing():
    class _Operand:
        type = 3
        mem = SimpleNamespace(base=0, index=0, disp=0x60)

    class _Insn:
        address = 0x1000
        mnemonic = "call"
        size = 2
        insn = SimpleNamespace(operands=(_Operand(),), size=2)

    block = SimpleNamespace(capstone=SimpleNamespace(insns=(_Insn(),)), size=2)

    def bad_initial_regs():
        return None

    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(initial_register_values=bad_initial_regs)),
        factory=SimpleNamespace(block=lambda _addr, opt_level=0: block),
    )
    function = SimpleNamespace(
        project=project,
        block_addrs_set={0x1000},
    )

    assert resolve_stored_near_call_target_from_function(function, 0x1000) is None


def test_resolve_direct_call_target_from_block_uses_exact_mid_block_callsite_address():
    class _Operand:
        def __init__(self, type_, imm):
            self.type = type_
            self.imm = imm

    class _Insn:
        def __init__(self, address, mnemonic, operands, size=3):
            self.address = address
            self.mnemonic = mnemonic
            self.size = size
            self.insn = SimpleNamespace(operands=tuple(operands), size=size)

    block = SimpleNamespace(
        capstone=SimpleNamespace(
            insns=(
                _Insn(0x1000, "mov", []),
                _Insn(0x1003, "call", [_Operand(2, 0x0F60)]),
                _Insn(0x1006, "add", []),
            )
        )
    )
    slice_project = SimpleNamespace(
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
        _inertia_original_project=SimpleNamespace(
            loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0xAC37))
        ),
        _inertia_original_linear_delta=0xF768,
    )

    assert resolve_direct_call_target_from_block(slice_project, 0x1003) == 0x106C8


def test_attach_callsite_summaries_recovers_multiple_mid_block_direct_calls(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    codegen = _DummyCodegen(project)
    first = CFunctionCall(None, None, [], tags={"ins_addr": 0x4013}, codegen=codegen)
    second = CFunctionCall(None, None, [], tags={"ins_addr": 0x4018}, codegen=codegen)
    root = CStatements([first, second], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    class _Operand:
        def __init__(self, type_, imm):
            self.type = type_
            self.imm = imm

    class _Insn:
        def __init__(self, address, mnemonic, operands, size=3):
            self.address = address
            self.mnemonic = mnemonic
            self.size = size
            self.insn = SimpleNamespace(operands=tuple(operands), size=size)

    block = SimpleNamespace(
        capstone=SimpleNamespace(
            insns=(
                _Insn(0x4010, "push", []),
                _Insn(0x4013, "call", [_Operand(2, 0x1544)]),
                _Insn(0x4016, "add", []),
                _Insn(0x4018, "call", [_Operand(2, 0x1666)]),
                _Insn(0x401B, "add", []),
            )
        ),
        size=0x0E,
    )
    project.factory = SimpleNamespace(block=lambda addr, opt_level=0: block)

    callee_a = SimpleNamespace(name="::0x1544::InitBars")
    callee_b = SimpleNamespace(name="::0x1666::DrawTime")
    function = SimpleNamespace(
        addr=0x4010,
        project=project,
        block_addrs_set={0x4010},
        _call_sites={},
        get_call_sites=lambda: tuple(sorted(function._call_sites)),
        get_call_target=lambda callsite: function._call_sites[callsite][0],
        get_call_return=lambda callsite: function._call_sites[callsite][1],
    )
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr, create=False: (
                function if addr == 0x4010 else callee_a if addr == 0x1544 else callee_b if addr == 0x1666 else None
            )
        )
    )

    def _fake_summary(_function, callsite_addr, *, target_inventory=None):
        if callsite_addr == 0x4013:
            return CallsiteSummary8616(0x4013, 0x1544, 0x4016, "direct_near", 0, (), None, None, False)
        return CallsiteSummary8616(0x4018, 0x1666, 0x401B, "direct_near", 0, (), None, None, False)

    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls.summarize_x86_16_callsite",
        _fake_summary,
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert function.get_call_sites() == (0x4013, 0x4018)
    assert first.callee_func is callee_a
    assert first.callee_target == "InitBars"
    assert second.callee_func is callee_b
    assert second.callee_target == "DrawTime"


def test_attach_callsite_summaries_binds_original_project_callee_for_rebased_exact_slice(monkeypatch):
    project = SimpleNamespace(
        _inertia_original_project=SimpleNamespace(
            kb=SimpleNamespace(
                functions=SimpleNamespace(
                    function=lambda addr, create=False: (
                        SimpleNamespace(addr=addr, name="DrawBar") if addr == 0x106C8 else None
                    )
                )
            )
        ),
        _inertia_original_linear_delta=0xF768,
    )
    codegen = _DummyCodegen(project)
    call = CFunctionCall(None, None, [], tags={"ins_addr": 0x100E}, codegen=codegen)
    root = CStatements([call], addr=0x1000, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root, body=root)

    function = SimpleNamespace(addr=0x1000, get_call_sites=lambda: [0x100E])
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(function=lambda addr, create=False: function if addr == 0x1000 else None)
    )
    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, callsite_addr, *, target_inventory=None: CallsiteSummary8616(
            callsite_addr=callsite_addr,
            target_addr=0x106C8,
            return_addr=0x1011,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert call.callee_func is not None
    assert call.callee_func.name == "DrawBar"
    assert call.callee_target == "DrawBar"


def test_attach_callsite_summaries_replaces_conflicting_empty_stub_name_with_sidecar_label(monkeypatch):
    target = SimpleNamespace(addr=0x1666, name="DrawBar", block_addrs_set=())
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: function if addr == 0x4010 else (target if addr == 0x1666 else None)
            )
        )
    )
    codegen = _DummyCodegen(project)
    call = CFunctionCall("DrawBar", target, [], tags={"ins_addr": 0x4018}, codegen=codegen)
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    function = SimpleNamespace(addr=0x4010, get_call_sites=lambda: [0x4018])

    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, callsite_addr, *, target_inventory=None: CallsiteSummary8616(
            callsite_addr=callsite_addr,
            target_addr=0x1666,
            return_addr=0x401B,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=None,
            return_register=None,
            return_used=False,
        ),
    )
    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls._sidecar_label_for_target_8616",
        lambda _project, target_addr: "DrawTime" if target_addr == 0x1666 else None,
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert call.callee_func is target
    assert call.callee_func.name == "DrawTime"
    assert call.callee_target == "DrawTime"


def test_attach_callsite_summaries_ignores_cod_source_call_order_for_repeated_non_probe_calls(monkeypatch):
    project = SimpleNamespace()
    codegen = _DummyCodegen(project)
    probe = CFunctionCall(
        "aNchkstk", SimpleNamespace(addr=0x1222, name="aNchkstk", block_addrs_set=()), [], codegen=codegen
    )
    draw_a = CFunctionCall(
        "DrawBar", SimpleNamespace(addr=0x1544, name="DrawBar", block_addrs_set=()), [], codegen=codegen
    )
    draw_b = CFunctionCall(
        "DrawBar", SimpleNamespace(addr=0x1544, name="DrawBar", block_addrs_set=()), [], codegen=codegen
    )
    draw_c = CFunctionCall(
        "DrawBar", SimpleNamespace(addr=0x1666, name="DrawBar", block_addrs_set=()), [], codegen=codegen
    )
    root = CStatements([probe, draw_a, draw_b, draw_c], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    function = SimpleNamespace(addr=0x4010, get_call_sites=lambda: [0x4012, 0x4015, 0x4018, 0x401B])
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(function=lambda addr, create=False: function if addr == 0x4010 else None)
    )

    summaries = {
        0x4012: CallsiteSummary8616(0x4012, 0x1222, 0x4015, "direct_far", 0, (), None, None, False, True),
        0x4015: CallsiteSummary8616(0x4015, 0x1544, 0x4018, "direct_far", 1, (2,), 2, "ax", True),
        0x4018: CallsiteSummary8616(0x4018, 0x1544, 0x401B, "direct_far", 1, (2,), 2, "ax", True),
        0x401B: CallsiteSummary8616(0x401B, 0x1666, 0x401E, "direct_far", 1, (2,), 2, "ax", True),
    }
    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, callsite_addr, *, target_inventory=None: summaries[callsite_addr],
    )
    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls._cod_metadata_for_function_8616",
        lambda _project, _addr: SimpleNamespace(
            call_names=("DrawBar", "DrawBar", "DrawTime")
        ),
    )
    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls._sidecar_label_for_target_8616",
        lambda _project, _target_addr: None,
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert draw_a.callee_target == "DrawBar"
    assert draw_b.callee_target == "DrawBar"
    assert draw_c.callee_target == "DrawBar"
    assert draw_c.callee_func.name == "DrawBar"


def test_attach_callsite_summaries_ignores_source_order_for_zero_arg_stale_name(monkeypatch):
    target = SimpleNamespace(addr=0x10060, name="displaycursor", block_addrs_set={0x10060})
    function = SimpleNamespace(addr=0x4010, get_call_sites=lambda: [0x4018])

    class _Functions:
        def function(self, addr=None, name=None, create=False):
            if addr == 0x4010:
                return function
            if addr == 0x10060:
                return target
            if name in {"InitMenu", "_InitMenu"}:
                return SimpleNamespace(addr=0x10060, name="InitMenu", block_addrs_set={0x10060})
            return None

    project = SimpleNamespace(kb=SimpleNamespace(functions=_Functions()))
    codegen = _DummyCodegen(project)
    call = CFunctionCall("displaycursor", target, [], tags={"ins_addr": 0x4018}, codegen=codegen)
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, _callsite_addr, *, target_inventory=None: CallsiteSummary8616(
            callsite_addr=0x4018,
            target_addr=0x10060,
            return_addr=0x401B,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=None,
            return_register=None,
            return_used=False,
        ),
    )
    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls._cod_metadata_for_function_8616",
        lambda _project, _addr: SimpleNamespace(call_names=("InitMenu",)),
    )
    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls._sidecar_label_for_target_8616",
        lambda _project, _target_addr: None,
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert call.callee_target == "displaycursor"
    assert call.callee_func.name == "displaycursor"


def test_attach_callsite_summaries_rebinds_non_entry_direct_target_to_containing_function(monkeypatch):
    drawtime = SimpleNamespace(addr=0x1666, name="DrawTime", block_addrs_set={0x1666})
    stale = SimpleNamespace(addr=0x1544, name="DrawBar", block_addrs_set={0x1544})
    function = SimpleNamespace(addr=0x4010, get_call_sites=lambda: [0x4018])

    class _Functions:
        def function(self, addr=None, create=False):
            if addr == 0x4010:
                return function
            if addr == 0x1544:
                return stale
            return None

        def floor_func(self, addr):
            if 0x1666 <= addr < 0x1700:
                return drawtime
            return None

        def ceiling_addr(self, addr):
            if addr < 0x1700:
                return 0x1700
            return None

    project = SimpleNamespace(kb=SimpleNamespace(functions=_Functions()))
    codegen = _DummyCodegen(project)
    call = CFunctionCall("DrawBar", stale, [], tags={"ins_addr": 0x4018}, codegen=codegen)
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, _callsite_addr, *, target_inventory=None: CallsiteSummary8616(
            callsite_addr=0x4018,
            target_addr=0x166B,
            return_addr=0x401B,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert call.callee_func is drawtime


def test_attach_callsite_summaries_does_not_use_source_call_order_to_identify_target(monkeypatch):
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: (
                    SimpleNamespace(addr=0x4010, get_call_sites=lambda: [0x401B]) if addr == 0x4010 else None
                )
            )
        )
    )
    codegen = _DummyCodegen(project)
    stale = SimpleNamespace(addr=0x1544, name="DrawBar", block_addrs_set={0x1544})
    call = CFunctionCall("DrawBar", stale, [], tags={"ins_addr": 0x401B}, codegen=codegen)
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, _callsite_addr, *, target_inventory=None: CallsiteSummary8616(
            callsite_addr=0x401B,
            target_addr=0x166B,
            return_addr=0x401E,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    )
    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls._cod_metadata_for_function_8616",
        lambda _project, _addr: SimpleNamespace(call_names=("DrawTime",)),
    )
    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls._sidecar_label_for_target_8616",
        lambda _project, _target_addr: None,
    )
    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls._lookup_callee_function_8616",
        lambda _project, _target_addr, **_kwargs: None,
    )
    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls._source_name_matches_target_8616",
        lambda _project, _target_addr, _name: _target_addr == 0x166B and _name == "DrawTime",
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert call.callee_func is None
    assert call.callee_target == "DrawBar"


def test_normalize_call_target_names_drops_detached_angr_callee_func():
    class _DetachedFunction:
        __module__ = "angr.knowledge_plugins.functions.function"

        name = "Sleep"

        @property
        def project(self):
            raise AssertionError

    project = SimpleNamespace()
    codegen = _DummyCodegen(project)
    detached = _DetachedFunction()
    call = CFunctionCall(None, detached, [], codegen=codegen)
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = _normalize_call_target_names_8616(codegen)

    assert changed is True
    assert call.callee_func is None
    assert call.callee_target == "Sleep"


def test_lookup_callee_function_rejects_mismatched_exact_lookup_and_uses_containing_function():
    drawbar = SimpleNamespace(addr=0x1F60, name="DrawBar", block_addrs_set={0x1F60})
    drawtime = SimpleNamespace(addr=0x1048B, name="DrawTime", block_addrs_set={0x1048B, 0x10491})

    class _Functions:
        def function(self, addr=None, create=False):
            if addr == 0x10491:
                return drawbar
            return None

        def floor_func(self, addr):
            if 0x1048B <= addr < 0x10498:
                return drawtime
            return None

        def ceiling_addr(self, addr):
            if addr <= 0x10498:
                return 0x10498
            return None

    project = SimpleNamespace(kb=SimpleNamespace(functions=_Functions()))

    resolved = _lookup_callee_function_8616(project, 0x10491)

    assert resolved is drawtime


def test_callsite_stats_reject_known_prototype_arg_mismatch():
    project = SimpleNamespace()
    codegen = _DummyCodegen(project)
    call = CFunctionCall(
        "memset", SimpleNamespace(addr=0x1544, name="memset", block_addrs_set={0x1544}), [], codegen=codegen
    )
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
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
        )
    }

    try:
        _normalize_call_target_names_8616(codegen)
    except PipelineHardError as ex:
        assert "known prototype call argument mismatch" in str(ex)
    else:
        raise AssertionError("expected PipelineHardError")

    stats = codegen._inertia_callsite_materialization_stats
    assert stats.known_prototype_arg_mismatch_count == 1
    assert stats.failure_count >= 1


def test_callsite_stats_allow_variadic_known_helper_extra_args():
    project = SimpleNamespace()
    codegen = _DummyCodegen(project)
    call = CFunctionCall(
        "sprintf",
        SimpleNamespace(addr=0x12BA, name="sprintf", block_addrs_set={0x12BA}),
        [SimpleNamespace(), SimpleNamespace(), SimpleNamespace(), SimpleNamespace()],
        codegen=codegen,
    )
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4050,
            target_addr=0x12BA,
            return_addr=0x4053,
            kind="direct_near",
            arg_count=4,
            arg_widths=(2, 2, 4, 2),
            stack_cleanup=12,
            return_register=None,
            return_used=False,
        )
    }

    changed = _normalize_call_target_names_8616(codegen)
    stats = codegen._inertia_callsite_materialization_stats

    assert changed is False
    assert stats.call_arg_fact_count == 4
    assert stats.call_arg_materialized_count == 4
    assert stats.known_prototype_arg_mismatch_count == 0
    assert stats.failure_count == 0


def test_callsite_stats_ignore_summary_arg_facts_for_known_zero_arg_helper():
    project = SimpleNamespace()
    codegen = _DummyCodegen(project)
    call = CFunctionCall(
        "clock", SimpleNamespace(addr=0x1544, name="clock", block_addrs_set={0x1544}), [], codegen=codegen
    )
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
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
        )
    }

    changed = _normalize_call_target_names_8616(codegen)
    stats = codegen._inertia_callsite_materialization_stats

    assert changed is False
    assert stats.call_arg_fact_count == 0
    assert stats.call_arg_materialized_count == 0
    assert stats.known_prototype_arg_mismatch_count == 0
    assert stats.failure_count == 0


def test_callsite_stats_count_stale_target_rejection(monkeypatch):
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: (
                    SimpleNamespace(addr=0x4010, get_call_sites=lambda: [0x401B]) if addr == 0x4010 else None
                )
            )
        )
    )
    codegen = _DummyCodegen(project)
    stale = SimpleNamespace(addr=0x1544, name="DrawBar", block_addrs_set={0x1544})
    call = CFunctionCall("DrawBar", stale, [], tags={"ins_addr": 0x401B}, codegen=codegen)
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, _callsite_addr, *, target_inventory=None: CallsiteSummary8616(
            callsite_addr=0x401B,
            target_addr=0x166B,
            return_addr=0x401E,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    )
    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls._cod_metadata_for_function_8616",
        lambda _project, _addr: SimpleNamespace(call_names=("DrawTime",)),
    )
    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls._sidecar_label_for_target_8616",
        lambda _project, _target_addr: None,
    )
    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls._lookup_callee_function_8616",
        lambda _project, _target_addr, **_kwargs: stale,
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert codegen._inertia_callsite_materialization_stats.stale_target_rejected_count == 1
