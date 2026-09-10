from __future__ import annotations

import contextlib
import importlib.util
import inspect
import io
import os
import subprocess
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import TimeoutError as FuturesTimeoutError
from concurrent.futures.thread import _threads_queues
from pathlib import Path
from types import SimpleNamespace

import angr
import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.caller_return_use_contracts import (
    CallerReturnUseFact8616,
    CallsiteReturnUseKind8616,
)
from angr_platforms.X86_16.cod_extract import CODProcMetadata, extract_cod_listing_metadata
from angr_platforms.X86_16.codeview_nb00 import find_codeview_nb00, parse_codeview_nb00
from angr_platforms.X86_16.compiler_helpers import (
    CompilerHelperEvidence8616,
    CompilerHelperEvidenceKind8616,
)
from angr_platforms.X86_16.fast_tracer import trace_16bit_seed_candidates
from angr_platforms.X86_16.flair_extract import list_flair_sig_libraries, match_flair_startup_entry
from angr_platforms.X86_16.load_dos_mz import DOSMZ
from angr_platforms.X86_16.lowering.segmented_global_loads import SegmentedGlobalLoadStats8616
from angr_platforms.X86_16.lowering.segmented_lowering import _SegmentedAccess
from angr_platforms.X86_16.lst_extract import LSTMetadata, extract_lst_metadata
from angr_platforms.X86_16.turbo_debug_tdinfo import TDInfoSymbolClass, parse_tdinfo_exe
from angr_platforms.X86_16.widening.global_object_layout import (
    GlobalObjectLayoutEvidence8616,
)
from angr_platforms.X86_16.widening.indexed_global_object_program_ranges import (
    ProjectBoundedGlobalObjectRangeEvidence8616,
    ProjectBoundedGlobalObjectRangeSource8616,
    ProjectBoundedGlobalObjectRangeSourceKind8616,
    ProjectBoundedGlobalObjectRangeSourceStatus8616,
)
from angr_platforms.X86_16.widening.indexed_global_object_ranges import (
    BoundedGlobalObjectRangeStats8616,
)
from x86_16_dosfunc_behavior import assert_dos_free_behavior
from x86_16_timeout_support import scaled_decompile_timeout

import decompile
import inertia_decompiler.cache as recovery_cache
import inertia_decompiler.cli_core as cli_core
import inertia_decompiler.cli_decompilation as cli_decompilation
import inertia_decompiler.cli_function_discovery as cli_function_discovery
import inertia_decompiler.cli_linear_recurrence_state as cli_linear_recurrence_state
import inertia_decompiler.cli_output as cli_output
import inertia_decompiler.decompile_file_summary as file_summary
import inertia_decompiler.non_optimized_fallback as non_optimized_fallback
import inertia_decompiler.runtime_support as runtime_support
import inertia_decompiler.sidecar_cache as sidecar_cache
import inertia_decompiler.tail_validation as cli_tail_validation
from inertia_decompiler import sidecar_metadata, sidecar_parsers
from inertia_decompiler.direct_addr_failure_family import (
    FailureFamilySnapshot,
    FailureFamilyState,
    advance_failure_family_state,
    build_failure_family_snapshot,
    failure_family_repeat_reason,
    remember_failure_family_candidate,
)
from inertia_decompiler.direct_addr_stage_bundle import (
    DirectAddrStageBundleInput,
    write_direct_addr_stage_bundle,
)
from inertia_decompiler.rizin_discovery import RizinDiscoveryResult, RizinDiscoveryStatus
from inertia_decompiler.rizin_evidence import RizinEvidence, RizinEvidenceStatus, RizinFunctionFact
from inertia_decompiler.slice_recovery import SliceRecoveryAttemptOutcome
from inertia_decompiler.work_items import FunctionWorkItem
from inertia_decompiler.x86_16_exact_slice import mark_function_original_addr
from omf_pat import (
    CachedPatRegexSpec,
    PatModule,
    PatPublicName,
    _normalize_pat_backend_choice,
    ensure_pat_from_omf_input,
    enumerate_microsoft_lib_dictionary_symbols,
    enumerate_omf_lib_dictionary_symbols,
    extract_omf_modules_from_lib,
    generate_pat_from_omf_lib,
    generate_pat_from_omf_obj,
    load_cached_pat_regex_specs,
    lookup_microsoft_lib_symbol,
    lookup_omf_lib_symbol,
    match_pat_modules,
    parse_microsoft_lib,
    parse_omf_lib,
    parse_pat_file,
)
from signature_catalog import build_signature_catalog, match_signature_catalog

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "decompile.py"
TRACE_PATH = REPO_ROOT / "angr_platforms" / "scripts" / "trace_x86_16_paths.py"
MONOPRIN_COD = REPO_ROOT / "cod" / "f14" / "MONOPRIN.COD"
NHORZ_COD = REPO_ROOT / "cod" / "f14" / "NHORZ.COD"
MAX_COD = REPO_ROOT / "cod" / "default" / "MAX.COD"
DOSFUNC_COD = REPO_ROOT / "cod" / "DOSFUNC.COD"
ICOMDO_COM = REPO_ROOT / "angr_platforms" / "x16_samples" / "ICOMDO.COM"
ISOD_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "ISOD.COD"
IMOD_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "IMOD.COD"
ISOT_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "ISOT.COD"
ISOX_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "ISOX.COD"
IHOD_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "IHOD.COD"
IHOT_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "IHOT.COD"
ILOD_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "ILOD.COD"
ILOT_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "ILOT.COD"
IMOT_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "IMOT.COD"
IMOX_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "IMOX.COD"


def test_preserve_source_label_for_recovered_function_keeps_non_generic_same_addr():
    source = SimpleNamespace(addr=0x100F4, name="main")
    recovered = SimpleNamespace(addr=0x100F4, name="sub_100f4")

    assert cli_core._preserve_source_label_for_recovered_function_8616(source, recovered) is True
    assert recovered.name == "main"


def test_preserve_source_label_for_recovered_function_refuses_addr_or_named_conflict():
    source = SimpleNamespace(addr=0x100F4, name="main")
    wrong_addr = SimpleNamespace(addr=0x100F6, name="sub_100f6")
    named = SimpleNamespace(addr=0x100F4, name="real_name")

    assert cli_core._preserve_source_label_for_recovered_function_8616(source, wrong_addr) is False
    assert wrong_addr.name == "sub_100f6"
    assert cli_core._preserve_source_label_for_recovered_function_8616(source, named) is False
    assert named.name == "real_name"


def test_direct_addr_stage_bundle_is_deterministic_and_reused(tmp_path):
    request = DirectAddrStageBundleInput(
        binary_path=tmp_path / "SORTDEMO.EXE",
        function_addr=0x102E0,
        function_name="RunMenu",
        family_label="status=empty stage=structuring fallback=direct_addr validation=failed",
        raw_asm="mov ax, bx\n",
        cod_window=";|*** source\n",
        raw_codegen="void RunMenu(void) {}\n",
        final_stdout="/* stop */\n",
        final_stderr="[dbg] stop\n",
    )

    first = write_direct_addr_stage_bundle(request, root=tmp_path / "stage_debug")
    second = write_direct_addr_stage_bundle(request, root=tmp_path / "stage_debug")

    assert first.path == second.path
    assert first.reused is False
    assert second.reused is True
    for name in (
        "raw_asm.txt",
        "cod_window.txt",
        "raw_codegen.c",
        "post_callsite.c",
        "post_stack_lowering.c",
        "final_stdout.txt",
        "final_stderr.txt",
        "manifest.json",
    ):
        assert (first.path / name).exists()
    assert (first.path / "post_callsite.c").read_text(encoding="utf-8") == "unavailable\n"


def test_minimal_codegen_output_keeps_unresolved_cod_text_instead_of_source_fallback(monkeypatch, tmp_path):
    monkeypatch.setattr(
        cli_decompilation,
        "_format_known_helper_calls",
        lambda _project, _function, rendered_text, *_args, **_kwargs: rendered_text,
    )
    cod_path = tmp_path / "demo.cod"
    cod_path.write_text(";|*** func() {\n;|*** source = 1;\n;|*** }\n", encoding="latin-1")
    rendered = """int func(void)
{
    vvar_1 = ...;
    vvar_2 = ...;
    return vvar_1;
}
"""
    metadata = SimpleNamespace(source_lines=("func() {", "source = 1;", "}"))

    formatted = cli_decompilation._format_minimal_codegen_output(
        SimpleNamespace(),
        SimpleNamespace(name="func"),
        rendered,
        "default",
        cod_path,
        metadata,
    )

    assert "source = 1" not in formatted
    assert "vvar_1" in formatted
    assert "..." in formatted


def test_decompilation_preserves_source_label_for_same_addr_retry_function():
    source = SimpleNamespace(addr=0x10054, name="sum_to")
    recovered = SimpleNamespace(addr=0x10054, name="sub_10054")

    assert cli_decompilation._preserve_source_label_for_same_addr_function_8616(source, recovered) is True
    assert recovered.name == "sum_to"


def test_decompilation_preserves_source_label_refuses_named_retry_conflict():
    source = SimpleNamespace(addr=0x10054, name="sum_to")
    recovered = SimpleNamespace(addr=0x10054, name="other_name")

    assert cli_decompilation._preserve_source_label_for_same_addr_function_8616(source, recovered) is False
    assert recovered.name == "other_name"


def test_codegen_render_refresh_signal_is_structured_and_consumed():
    codegen = SimpleNamespace()

    assert cli_decompilation._codegen_requires_render_refresh_8616(codegen) is False

    codegen._inertia_codegen_decl_refresh_required_8616 = True
    assert cli_decompilation._codegen_requires_render_refresh_8616(codegen) is True

    cli_decompilation._clear_codegen_render_refresh_8616(codegen)
    assert cli_decompilation._codegen_requires_render_refresh_8616(codegen) is False


def test_retry_function_tail_validation_snapshot_prefers_retry_function_info():
    stale_project_snapshot = {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "changed", "changed": True},
    }
    retry_snapshot = {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "stable", "changed": False},
    }
    project = SimpleNamespace(
        _inertia_last_tail_validation_snapshot=stale_project_snapshot,
        _inertia_last_validated_function_payload_snapshot=None,
    )
    function = SimpleNamespace(info={"x86_16_tail_validation": retry_snapshot})

    snapshot = cli_core._retry_function_tail_validation_snapshot_8616(project, function)

    assert snapshot["structuring"]["status"] == "stable"
    assert snapshot["structuring"]["changed"] is False
    assert snapshot["postprocess"]["status"] == "stable"
    assert snapshot["postprocess"]["changed"] is False


def test_postprocess_regenerated_text_is_reused_as_current_render():
    codegen = SimpleNamespace(
        text="int f(void) { return 0; }\n",
        _inertia_regeneration_failed=False,
        _inertia_regeneration_context="0x1000 f",
    )

    assert cli_decompilation._postprocess_regenerated_text_available_8616(codegen) is True

    codegen._inertia_regeneration_failed = True
    assert cli_decompilation._postprocess_regenerated_text_available_8616(codegen) is False

    codegen._inertia_regeneration_failed = False
    codegen._inertia_regeneration_context = ""
    assert cli_decompilation._postprocess_regenerated_text_available_8616(codegen) is False


def test_segmented_global_materialization_blocks_cached_render_reuse():
    codegen = SimpleNamespace(
        text="int f(void) { return SEG_U16(ds, 2978); }\n",
        _inertia_regeneration_failed=False,
        _inertia_regeneration_context="0x1000 f",
        _inertia_segmented_global_load_stats_8616=SegmentedGlobalLoadStats8616(indexed_materialized_count=1),
    )

    assert cli_decompilation._codegen_has_semantic_materialization_8616(codegen) is True
    assert cli_decompilation._postprocess_regenerated_text_available_8616(codegen) is False


def test_render_refresh_preservation_detects_lost_stack_writes():
    before = """int f(void)
{
    unsigned short local_4;  // [bp-0x4]
    unsigned short local_6;  // [bp-0x6]
    local_4 = 0;
    local_6 = local_8;
    local_4 += 1;
    local_6 = local_2;
    return local_4;
}
"""
    after = """int f(void)
{
    unsigned short iCompares; // [bp-0x4] iCompares
    unsigned short iRowMin;  // [bp-0x6] iRowMin
    iRowMin = iRowCur;
    return iCompares;
}
"""

    evidence = cli_decompilation._render_refresh_preservation_evidence_8616(before, after)

    assert evidence.decision == cli_decompilation.RenderRefreshPreservationDecision8616.RESTORE_STACK_WRITE_EFFECTS
    assert evidence.lost_stack_slots == ("bp-0x4", "bp-0x6")


def test_render_refresh_preservation_ignores_reserved_frame_slots():
    before = """int f(void)
{
    unsigned short saved_bp;  // [bp+0x0]
    unsigned short ret_ip_lo;  // [bp+0x2]
    unsigned short real_arg;  // [bp+0x4]
    saved_bp = 0;
    ret_ip_lo = 1;
    real_arg = 2;
}
"""
    after = """int f(void)
{
    unsigned short real_arg;  // [bp+0x4]
    real_arg = 2;
}
"""

    evidence = cli_decompilation._render_refresh_preservation_evidence_8616(before, after)

    assert evidence.decision == cli_decompilation.RenderRefreshPreservationDecision8616.PRESERVE_REPLAY
    assert evidence.lost_stack_slots == ()


def test_render_refresh_accepts_validated_direct_stack_materialization_losses():
    evidence = cli_decompilation.RenderRefreshPreservationEvidence8616(
        decision=cli_decompilation.RenderRefreshPreservationDecision8616.RESTORE_STACK_WRITE_EFFECTS,
        before_stack_writes={"bp-0x4": 1, "bp-0x6": 1, "bp+0x7": 1},
        after_stack_writes={},
        lost_stack_slots=("bp+0x7", "bp-0x4", "bp-0x6"),
    )
    codegen = SimpleNamespace(
        _inertia_tail_validation_snapshot={
            "structuring": {"status": "stable"},
            "postprocess": {"status": "stable"},
        },
        _inertia_direct_stack_move_evidence_8616=(
            (("dst_offset", -4), ("width", 2)),
            (("dst_offset", -6), ("width", 2)),
        ),
        _inertia_direct_stack_update_evidence_8616=(),
    )

    assert cli_decompilation._render_refresh_lost_stack_writes_are_validated_materialization_8616(
        codegen,
        evidence,
    )


def test_render_refresh_accepts_validated_direct_stack_materialization_high_byte_losses():
    evidence = cli_decompilation.RenderRefreshPreservationEvidence8616(
        decision=cli_decompilation.RenderRefreshPreservationDecision8616.RESTORE_STACK_WRITE_EFFECTS,
        before_stack_writes={"bp-0x2": 1, "bp-0x3": 1, "bp-0x4": 1},
        after_stack_writes={},
        lost_stack_slots=("bp-0x2", "bp-0x3", "bp-0x4"),
    )
    codegen = SimpleNamespace(
        _inertia_tail_validation_snapshot={
            "structuring": {"status": "stable"},
            "postprocess": {"status": "stable"},
        },
        _inertia_direct_stack_move_evidence_8616=(
            (("dst_offset", -4), ("width", 2), ("source_offset", -6)),
            (("dst_offset", -2), ("width", 2)),
        ),
        _inertia_direct_stack_update_evidence_8616=(),
    )

    assert cli_decompilation._render_refresh_lost_stack_writes_are_validated_materialization_8616(
        codegen,
        evidence,
    )
    assert cli_decompilation._render_refresh_lost_stack_writes_have_direct_stack_evidence_8616(codegen, evidence)


def test_render_refresh_accepts_project_tail_validation_snapshot():
    evidence = cli_decompilation.RenderRefreshPreservationEvidence8616(
        decision=cli_decompilation.RenderRefreshPreservationDecision8616.RESTORE_STACK_WRITE_EFFECTS,
        before_stack_writes={"bp-0x2": 1},
        after_stack_writes={},
        lost_stack_slots=("bp-0x2",),
    )
    project = SimpleNamespace(
        _inertia_last_tail_validation_snapshot={
            "structuring": {"status": "stable"},
            "postprocess": {"status": "stable"},
        }
    )
    codegen = SimpleNamespace(
        project=project,
        _inertia_direct_stack_update_evidence_8616=((("offset", -2), ("width", 2)),),
        _inertia_direct_stack_move_evidence_8616=(),
    )

    assert cli_decompilation._render_refresh_lost_stack_writes_are_validated_materialization_8616(
        codegen,
        evidence,
    )


def test_render_refresh_does_not_treat_marker_neutral_candidate_as_quality_improvement():
    evidence = cli_decompilation.RenderRefreshPreservationEvidence8616(
        decision=cli_decompilation.RenderRefreshPreservationDecision8616.RESTORE_STACK_WRITE_EFFECTS,
        before_stack_writes={"bp-0x2": 1},
        after_stack_writes={},
        lost_stack_slots=("bp-0x2",),
    )
    codegen = SimpleNamespace(
        _inertia_direct_stack_update_evidence_8616=((("offset", -2), ("width", 2)),),
        _inertia_direct_stack_move_evidence_8616=(),
    )
    before = "void f(void) {\n    int i; // [bp-0x2]\n    i = SEG_U16(ds, 2978);\n}\n"
    after = "void f(void) {\n    cRow;\n}\n"

    assert cli_decompilation._render_refresh_lost_stack_writes_have_direct_stack_evidence_8616(codegen, evidence)
    assert not cli_decompilation._render_refresh_candidate_strictly_improves_quality_8616(before, after)


def test_render_refresh_refuses_direct_stack_evidence_without_quality_improvement():
    evidence = cli_decompilation.RenderRefreshPreservationEvidence8616(
        decision=cli_decompilation.RenderRefreshPreservationDecision8616.RESTORE_STACK_WRITE_EFFECTS,
        before_stack_writes={"bp-0x2": 1},
        after_stack_writes={},
        lost_stack_slots=("bp-0x2",),
    )
    codegen = SimpleNamespace(
        _inertia_direct_stack_update_evidence_8616=(),
        _inertia_direct_stack_move_evidence_8616=(),
    )
    before = "void f(void) {\n    int i; // [bp-0x2]\n    i = SEG_U16(ds, 2978);\n}\n"
    after = "void f(void) {\n    int i; // [bp-0x2]\n    SEG_U16(ds, 2978);\n}\n"

    assert not cli_decompilation._render_refresh_lost_stack_writes_have_direct_stack_evidence_8616(codegen, evidence)
    assert not cli_decompilation._render_refresh_candidate_strictly_improves_quality_8616(before, after)


def test_render_refresh_accepts_validated_postprocess_candidate_without_stack_evidence():
    evidence = cli_decompilation.RenderRefreshPreservationEvidence8616(
        decision=cli_decompilation.RenderRefreshPreservationDecision8616.RESTORE_STACK_WRITE_EFFECTS,
        before_stack_writes={"bp-0x4": 1},
        after_stack_writes={},
        lost_stack_slots=("bp-0x4",),
    )
    codegen = SimpleNamespace(
        _inertia_postprocess_changed=True,
        _inertia_tail_validation_snapshot={
            "structuring": {"status": "stable"},
            "postprocess": {"status": "stable"},
        },
    )

    assert cli_decompilation._render_refresh_lost_stack_writes_are_validated_materialization_8616(
        codegen,
        evidence,
    )


def test_regenerate_text_skips_callsite_replay_after_selector_return_materialization(monkeypatch):
    replay_calls = 0

    def fake_replay(_project, _codegen):
        nonlocal replay_calls
        replay_calls += 1
        raise AssertionError("callsite replay must not run under selector-return contract")

    monkeypatch.setattr(
        cli_decompilation,
        "replay_callsite_stack_arguments_after_regeneration_8616",
        fake_replay,
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(c_repr=lambda: "int f(void)\n{\n    if (which)\n        return a;\n    return b;\n}\n"),
        text="int f(void)\n{\n    return old;\n}\n",
        project=None,
        _inertia_callsite_args_ast_materialized_8616=True,
        _inertia_return_selector_materialized_8616=True,
        _inertia_postprocess_changed=True,
    )

    text, regenerated = cli_decompilation._regenerate_codegen_text_safely(codegen, context="0x1000 f")

    assert regenerated is True
    assert "if (which)" in text
    assert "return b;" in text
    assert replay_calls == 0


def test_evidence_recovered_c_does_not_override_valid_ast_text():
    formatted = "int f(void)\n{\n    return 1;\n}\n"
    evidence = "int f(void)\n{\n    return 2;\n}\n"

    assert cli_decompilation._select_evidence_recovered_c_8616(formatted, evidence) == formatted


def test_evidence_recovered_c_rescues_rejected_ast_text():
    formatted = "int f(void)\n{\n    return stack_base;\n}\n"
    evidence = "int f(void)\n{\n    return 2;\n}\n"

    assert cli_decompilation._select_evidence_recovered_c_8616(formatted, evidence) == evidence


def test_evidence_recovered_c_replaces_split_abi_signature_text():
    formatted = (
        "unsigned long select_max(unsigned long a, short b, unsigned long b_2, short b_3)\n"
        "{\n"
        "    if (b <= a)\n"
        "        return a;\n"
        "    return b;\n"
        "}\n"
    )
    evidence = (
        "long select_max(long a, long b)\n"
        "{\n"
        "    if (a >= b) {\n"
        "        return a;\n"
        "    }\n"
        "    return b;\n"
        "}\n"
    )

    assert cli_decompilation._select_evidence_recovered_c_8616(formatted, evidence) == evidence


def test_nontrivial_x86_16_refuses_legacy_cli_semantic_rewrite():
    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))

    assert (
        cli_decompilation._should_refuse_legacy_cli_rewrite_8616(
            project,
            small_function=False,
            sidecar_free=True,
        )
        is True
    )
    assert (
        cli_decompilation._should_refuse_legacy_cli_rewrite_8616(
            project,
            small_function=True,
            sidecar_free=True,
        )
        is False
    )
    assert (
        cli_decompilation._should_refuse_legacy_cli_rewrite_8616(
            project,
            small_function=False,
            sidecar_free=False,
        )
        is False
    )


def test_cli_rewrite_gate_treats_stable_and_failed_tail_snapshots_as_complete():
    stable = {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "stable", "changed": False},
    }
    failed = {
        "structuring": {"status": "changed", "changed": True},
        "postprocess": {"status": "changed", "changed": True},
    }

    assert cli_decompilation._tail_validation_snapshot_complete_for_cli_rewrite_8616(stable) is True
    assert cli_decompilation._tail_validation_snapshot_complete_for_cli_rewrite_8616(failed) is True
    assert cli_decompilation._tail_validation_snapshot_failed_for_cli_rewrite_8616(stable) is False
    assert cli_decompilation._tail_validation_snapshot_failed_for_cli_rewrite_8616(failed) is True
    assert (
        cli_decompilation._tail_validation_snapshot_complete_for_cli_rewrite_8616(
            {"structuring": {"status": "stable"}}
        )
        is False
    )


def test_partial_result_report_preserves_validation_failure_status():
    validation_failed = decompile._partial_result_report_8616("validation_failed")
    timeout = decompile._partial_result_report_8616("timeout")

    assert validation_failed.status is decompile.WorkItemStatus.VALIDATION_FAILED
    assert validation_failed.heading == "Decompilation validation_failed"
    assert validation_failed.direct_c_header == "\n/* == c (partial validation failure) == */"
    assert validation_failed.sweep_c_header == "/* -- c (partial validation failure) -- */"
    assert validation_failed.fallback_detail == "unavailable after partial validation failure"
    assert validation_failed.show_timeout_delay is False
    assert timeout.status is decompile.WorkItemStatus.TIMEOUT
    assert timeout.heading == "Decompilation timeout"
    assert timeout.direct_c_header == "\n/* == c (partial timeout) == */"
    assert timeout.sweep_c_header == "/* -- c (partial timeout) -- */"
    assert timeout.show_timeout_delay is True


def test_validated_rewrite_refusal_forces_render_refresh_when_text_empty():
    assert cli_decompilation._validated_rewrite_refusal_needs_render_refresh_8616("") is True
    assert cli_decompilation._validated_rewrite_refusal_needs_render_refresh_8616("   \n") is True
    assert cli_decompilation._validated_rewrite_refusal_needs_render_refresh_8616(None) is True
    assert (
        cli_decompilation._validated_rewrite_refusal_needs_render_refresh_8616("int f(void) { return 0; }\n")
        is False
    )


def test_acceptance_failure_does_not_mutate_tail_validation_snapshot():
    snapshot = {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "stable", "changed": False},
    }

    result = cli_core._validated_generated_c_acceptance_8616(
        status="ok",
        payload="void f(void)\n{\n    ...;\n}\n",
        tail_validation_snapshot=snapshot,
        tail_validation_enabled=True,
        expected_validation_stages=["structuring", "postprocess"],
        emit_failure_diagnostics=False,
    )

    assert result.status == "validation_failed"
    assert snapshot["postprocess"]["status"] == "stable"
    assert snapshot["postprocess"]["changed"] is False
    assert result.validated_payload.strip()
    assert result.gcc_checked_payload == ""
    assert result.gcc_checked_payload_hash == cli_core._sha256_text_8616("")


def test_source_call_arity_score_is_neutral_for_cod_source_evidence():
    metadata = CODProcMetadata(
        stack_aliases={},
        call_names=("Sleep",),
        call_sources=(
            ("Sleep", "Sleep( clPause - 75L )"),
            ("Sleep", "Sleep( clPause )"),
        ),
        global_names=(),
        source_lines=(),
        source_line_set=frozenset(),
    )
    stale = """
    void DrawTime(void)
    {
        Sleep(SEG_U16(ds, 306), SEG_U16(ds, 308));
        Sleep();
    }
    """
    materialized = """
    void DrawTime(void)
    {
        Sleep(SEG_U32(ds, 306) - 75);
        Sleep(SEG_U32(ds, 306));
    }
    """

    assert cli_decompilation._expected_call_presence_score_8616(stale, metadata) == 0
    assert cli_decompilation._expected_call_presence_score_8616(materialized, metadata) == 0
    assert cli_decompilation._expected_call_arity_score_8616(stale, metadata) == 0
    assert cli_decompilation._expected_call_arity_score_8616(materialized, metadata) == 0
    assert cli_decompilation._expected_call_arity_deficit_8616(stale, metadata) == 0
    assert cli_decompilation._expected_call_arity_deficit_8616(materialized, metadata) == 0


def test_call_semantics_retry_ignores_cod_source_arity():
    metadata = CODProcMetadata(
        stack_aliases={},
        call_names=("Sleep",),
        call_sources=(
            ("Sleep", "Sleep( clPause - 75L )"),
            ("Sleep", "Sleep( clPause )"),
        ),
        global_names=(),
        source_lines=(),
        source_line_set=frozenset(),
    )
    stale_arity = """
    void DrawTime(void)
    {
        Sleep(SEG_U16(ds, 306), SEG_U16(ds, 308));
        Sleep();
    }
    """

    retry_needed, missing_calls, arity_deficit = cli_decompilation._call_semantics_retry_evidence_8616(
        stale_arity,
        metadata,
    )

    assert retry_needed is False
    assert missing_calls == ()
    assert arity_deficit == 0


def test_call_semantics_retry_ignores_missing_cod_expected_call():
    metadata = CODProcMetadata(
        stack_aliases={},
        call_names=("DrawFrame", "outtext"),
        call_sources=(
            ("DrawFrame", "DrawFrame( TOP, LEFTCOLUMN - 3, WIDTH + 3, HEIGHT )"),
            ("outtext", "_outtextxy( ach, 0, i )"),
        ),
        global_names=(),
        source_lines=(),
        source_line_set=frozenset(),
    )
    missing_call = """
    void InitMenu(void)
    {
        DrawFrame(1, 2, 3, 4);
    }
    """

    retry_needed, missing_calls, arity_deficit = cli_decompilation._call_semantics_retry_evidence_8616(
        missing_call,
        metadata,
    )

    assert retry_needed is False
    assert missing_calls == ()
    assert arity_deficit == 0


def test_fallback_call_rank_ignores_stack_probe_calls():
    one_real_call_with_probe = """
unsigned short apply_twice(unsigned short (*fn)(unsigned short), unsigned short value)
{
    aNchkstk();
    value = fn(value);
}
"""
    two_real_calls = """
unsigned short apply_twice(unsigned short (*fn)(unsigned short), unsigned short value)
{
    value = fn(value);
    value = fn(value);
}
"""

    assert cli_core._non_probe_call_count_for_fallback_rank_8616(one_real_call_with_probe) == 1
    assert cli_core._non_probe_call_count_for_fallback_rank_8616(two_real_calls) == 2


def test_live_call_rehydration_is_inert_for_cod_source_evidence():
    metadata = CODProcMetadata(
        stack_aliases={},
        call_names=("puts",),
        call_sources=(("puts", 'puts("x")'),),
        global_names=(),
        source_lines=(),
        source_line_set=frozenset(),
    )

    out = cli_decompilation._rehydrate_missing_evidenced_calls_on_live_codegen_8616(
        SimpleNamespace(),
        SimpleNamespace(),
        metadata,
        "",
    )

    assert out == ""


def test_ordered_call_names_treats_nested_argument_call_as_before_outer_call():
    assert cli_core._ordered_call_names_from_text_8616("srand(time(0));") == ["time", "srand"]


def test_linear_recurrence_binary_rebuild_refuses_unarched_type(monkeypatch):
    codegen = SimpleNamespace(_inertia_stack_lowering_debug={})
    state = cli_linear_recurrence_state.LinearRecurrenceState(
        project=SimpleNamespace(),
        codegen=codegen,
        unwrap_c_casts=lambda expr: expr,
        structured_codegen_node=lambda _expr: False,
        iter_c_nodes_deep=lambda _root: (),
        same_c_expression=lambda _lhs, _rhs: False,
        c_constant_value=lambda _expr: None,
        canonicalize_stack_cvar_expr=lambda expr, _codegen: expr,
        seed_adjacent_byte_pair_aliases=lambda _project, _codegen: {},
        describe_alias_storage=lambda _expr: None,
        analyze_widening_expr=lambda *_args: None,
        match_high_byte_projection_base=lambda *_args: None,
        match_duplicate_word_base_expr=lambda *_args: None,
        match_duplicate_word_increment_shift_expr=lambda *_args: None,
        same_stack_slot_identity_var=lambda *_args: False,
    )

    def raise_unarched_type(*_args, **_kwargs):
        raise ValueError("Can't tell my size without an arch!")

    monkeypatch.setattr(cli_linear_recurrence_state.structured_c, "CBinaryOp", raise_unarched_type)

    assert state.build_binary_op_or_none("Add", object(), object()) is None
    assert state.recurrence_reasons == {"binary_rebuild_unarched_type": 1}
    assert codegen._inertia_stack_lowering_debug["recurrence_reasons"] == {"binary_rebuild_unarched_type": 1}


def test_sync_recovered_function_metadata_from_kb_copies_annotations_to_distinct_function_object():
    prototype = SimTypeFunction([SimTypeShort(False), SimTypeShort(False)], SimTypeShort(False))
    source = SimpleNamespace(
        addr=0x1005A,
        name="rel_i16",
        prototype=prototype,
        calling_convention="cc",
        is_prototype_guessed=False,
        returning=True,
        info={"x86_16_annotations": {"source_return_lines": ("return mask;",)}},
    )
    recovered = SimpleNamespace(
        addr=0x1005A,
        name="sub_1005a",
        prototype=None,
        calling_convention=None,
        is_prototype_guessed=True,
        returning=None,
        info={},
    )

    class _Functions:
        def function(self, *, addr, create=False):
            assert create is False
            return source if addr == source.addr else None

    project = SimpleNamespace(kb=SimpleNamespace(functions=_Functions()))

    assert cli_decompilation._sync_recovered_function_metadata_from_kb_8616(project, recovered) is True
    assert recovered.name == "rel_i16"
    assert recovered.prototype is None
    assert recovered.calling_convention is None
    assert recovered.is_prototype_guessed is True
    assert recovered.returning is None
    assert recovered.info["x86_16_annotations"]["source_return_lines"] == ("return mask;",)
    assert project._inertia_function_metadata_sync_stats["name_synced"] == 1
    assert project._inertia_function_metadata_sync_stats["info_synced"] == 1


def test_sync_recovered_function_metadata_preserves_nonempty_source_annotations():
    source = SimpleNamespace(
        addr=0x1000,
        name="SwapBars",
        prototype=None,
        calling_convention=None,
        returning=None,
        info={
            "x86_16_annotations": {
                "source_lines": (),
                "source_return_lines": (),
                "stack_vars": {2: {"name": "iRow1"}},
            }
        },
    )
    recovered = SimpleNamespace(
        addr=0x1000,
        name="SwapBars",
        prototype=None,
        calling_convention=None,
        returning=None,
        info={
            "x86_16_annotations": {
                "source_lines": ("void SwapBars( int iRow1, int iRow2 )", "{", "}"),
                "source_return_lines": ("return value;",),
                "stack_vars": {4: {"name": "iRow2"}},
            }
        },
    )

    class _Functions:
        def function(self, *, addr, create=False):
            assert create is False
            return source if addr == source.addr else None

    project = SimpleNamespace(kb=SimpleNamespace(functions=_Functions()))

    assert cli_decompilation._sync_recovered_function_metadata_from_kb_8616(project, recovered) is True
    annotations = recovered.info["x86_16_annotations"]
    assert annotations["source_lines"] == ("void SwapBars( int iRow1, int iRow2 )", "{", "}")
    assert annotations["source_return_lines"] == ("return value;",)
    assert annotations["stack_vars"] == {2: {"name": "iRow1"}, 4: {"name": "iRow2"}}


def test_apply_function_annotations_covers_rebased_active_and_original_addresses(monkeypatch):
    applied_addrs = []

    def fake_apply(_project, _binary_path, _lst_metadata, *, func_addr=None, **_kwargs):
        applied_addrs.append(func_addr)
        return True

    monkeypatch.setattr(cli_decompilation, "_apply_binary_specific_annotations", fake_apply)
    function = SimpleNamespace(addr=0x1000, name="SwapBars")
    mark_function_original_addr(function, 0x10768)

    changed = cli_decompilation._apply_function_annotations_for_active_and_original_8616(
        SimpleNamespace(),
        Path("SORTDEMO.EXE"),
        SimpleNamespace(),
        function,
        cod_metadata=SimpleNamespace(),
    )

    assert changed is True
    assert applied_addrs == [0x10768, 0x1000]


LIFE_EXE = REPO_ROOT / "examples" / "LIFE.EXE"
LIFE2_EXE = REPO_ROOT / "LIFE2.EXE"
LIFE_COD = REPO_ROOT / "examples" / "LIFE.COD"
NONAME_TDINFO_EXE = REPO_ROOT / "borrow" / "tdinfo-parser" / "NONAME.EXE"
SYNTHETIC_OBJ = REPO_ROOT / "angr_platforms" / "tests" / "fixtures" / "synthetic.obj"
BORLAND_CC_LIB = Path("/home/xor/inertia_player/dos_compilers/Borland Turbo C v2/LIB/CC.LIB")
BORLAND_GRAPHICS_LIB = Path("/home/xor/inertia_player/dos_compilers/Borland Turbo C v2/LIB/GRAPHICS.LIB")
requires_life_binary = pytest.mark.skipif(not LIFE_EXE.exists(), reason="LIFE.EXE fixture is not available")
requires_life_cod = pytest.mark.skipif(not LIFE_COD.exists(), reason="LIFE.COD fixture is not available")
requires_life2_binary = pytest.mark.skipif(not LIFE2_EXE.exists(), reason="LIFE2.EXE fixture is not available")
requires_icomdo_com = pytest.mark.skipif(not ICOMDO_COM.exists(), reason="ICOMDO.COM fixture is not available")
requires_trace_x86_script = pytest.mark.skipif(
    not TRACE_PATH.exists(), reason="trace_x86_16_paths.py script is not available"
)
requires_noname_tdinfo = pytest.mark.skipif(
    not NONAME_TDINFO_EXE.exists(), reason="tdinfo-parser/NONAME.EXE fixture is not available"
)


def _fake_stable_tail_validation() -> dict[str, object]:
    return {
        "x86_16_tail_validation": {
            "structuring": {"status": "stable", "changed": False},
            "postprocess": {"status": "stable", "changed": False},
        }
    }


def test_emit_function_timing_summary_orders_slowest_first(capsys):
    function_fast = SimpleNamespace(addr=0x1000, name="fast")
    function_slow = SimpleNamespace(addr=0x2000, name="slow")
    tasks = [
        decompile.FunctionWorkItem(index=1, function_cfg=object(), function=function_fast),
        decompile.FunctionWorkItem(index=2, function_cfg=object(), function=function_slow),
    ]
    results = {
        1: decompile.FunctionWorkResult(
            index=1,
            status="ok",
            payload="",
            debug_output="",
            function=function_fast,
            function_cfg=tasks[0].function_cfg,
            elapsed=0.25,
        ),
        2: decompile.FunctionWorkResult(
            index=2,
            status="timeout",
            payload="",
            debug_output="",
            function=function_slow,
            function_cfg=tasks[1].function_cfg,
            elapsed=2.0,
        ),
    }

    decompile._emit_function_timing_summary(tasks, results)

    out = capsys.readouterr().out
    assert "summary: slowest function attempt(s), top 2:" in out
    assert out.index("0x2000 slow: 2.00s status=timed_out") < out.index("0x1000 fast: 0.25s status=decompiled")


def test_sidecar_metadata_cache_sources_do_not_include_cli():
    sources = {path.name for path in recovery_cache.SIDECAR_METADATA_CACHE_SOURCE_FILES}

    assert "cli.py" not in sources
    assert "sidecar_metadata.py" in sources
    assert "sidecar_parsers.py" in sources
    assert "omf_pat.py" in sources


def test_count_unresolved_ds_linear_macro_hits_ignores_pointer_param_accesses():
    payload = """
int Swaps(void *lhs, void *rhs)
{
    unsigned short ds;
    unsigned short bx;
    unsigned short bx_2;
    unsigned short ax;
    bx = rhs;
    bx_2 = lhs;
    ax = SEG_U8(ds, lhs) | SEG_U8(ds, lhs + 1) * 0x100;
    SEG_U8(ds, bx) = ax;
    SEG_U8(ds, bx + 1) = ax >> 8;
    SEG_U8(ds, bx_2) = ax;
    SEG_U8(ds, bx_2 + 1) = ax >> 8;
}
"""
    assert decompile._count_unresolved_ds_linear_macro_hits_8616(payload) == 0


def test_count_unresolved_ds_linear_macro_hits_counts_raw_or_stack_offsets():
    payload = """
int Foo(void)
{
    unsigned short ds;
    unsigned short tmp;
    tmp = ds << 4;
    tmp = SEG_U8(ds, 0x200) | SEG_U8(ds, 0x201) * 0x100;
    SEG_U8(ds, tmp) = 0;
    SEG_U8(ds, stack_base + 2) = 1;
}
"""
    # Constant/global DS helpers are valid; raw DS linearization and DS helpers
    # using stack offsets are not.
    assert decompile._count_unresolved_ds_linear_macro_hits_8616(payload) == 2


def test_count_unresolved_ds_linear_macro_hits_accepts_global_ds_helpers():
    payload = """
void DrawTime(int iCurrentRow)
{
    Sleep(SEG_U32(ds, 306));
    sprintf(SEG_PTR(ds, achTiming), SEG_PTR(ds, 381), SEG_U16(ds, 2980));
    if (SEG_U16(ds, 2886))
        Sleep(SEG_U32(ds, 306) - 75);
}
"""
    assert decompile._count_unresolved_ds_linear_macro_hits_8616(payload) == 0


def test_count_unresolved_ds_linear_macro_hits_ignores_dynamic_variable_indexed_offsets():
    payload = """
void aFfdivs(void)
{
    unsigned short ds;
    unsigned short si;
    unsigned short bx_2;
    (void)SEG_U8(ds, 6 + si);
    (void)SEG_U8(ds, 665 + bx_2);
    (void)SEG_U8(ds, si);
}
"""
    assert decompile._count_unresolved_ds_linear_macro_hits_8616(payload) == 0


def test_emit_function_timing_summary_ignores_cached_timings(capsys):
    function_cached = SimpleNamespace(addr=0x1000, name="cached")
    function_current = SimpleNamespace(addr=0x2000, name="current")
    tasks = [
        decompile.FunctionWorkItem(index=1, function_cfg=object(), function=function_cached),
        decompile.FunctionWorkItem(index=2, function_cfg=object(), function=function_current),
    ]
    results = {
        1: decompile.FunctionWorkResult(
            index=1,
            status="ok",
            payload="",
            debug_output="",
            function=function_cached,
            function_cfg=tasks[0].function_cfg,
            elapsed=99.0,
            from_cache=True,
        ),
        2: decompile.FunctionWorkResult(
            index=2,
            status="ok",
            payload="",
            debug_output="",
            function=function_current,
            function_cfg=tasks[1].function_cfg,
            elapsed=0.5,
        ),
    }

    decompile._emit_function_timing_summary(tasks, results)

    out = capsys.readouterr().out
    assert "0x2000 current: 0.50s status=decompiled" in out
    assert "0x1000 cached" not in out


def test_emit_file_summary_sorts_and_dedupes_compilers_and_signature_sources(capsys):
    project = SimpleNamespace(
        _inertia_signature_compiler_names=(
            "Microsoft C v6ax",
            "Microsoft C v5",
            "Microsoft C v5.1",
            "Microsoft C v5",
        ),
        _inertia_flair_sig_titles=("ZLIB", "bsort"),
    )
    metadata = SimpleNamespace(signature_code_addrs=(0x1000, 0x1010))

    file_summary.emit_file_decompilation_summary(
        project,
        metadata,
        shown_total=8,
        decompiled=7,
        failed=1,
        skipped_signature_labels=3,
        same_family_retry_stops=2,
        fallback_family_labels=("isolated_retry", "structurer_retry"),
    )

    assert capsys.readouterr().out.strip().splitlines() == [
        "/* summary: probable compiler versions: Microsoft C v5, Microsoft C v5.1, Microsoft C v6ax */",
        "/* summary: probable library/signature sources: bsort, ZLIB */",
        "/* summary: signature-matched library functions: 2 */",
        "/* summary: hidden signature-matched labels: 3 */",
        "/* summary: same_family_retry_stops=2 fallback_family_labels=isolated_retry, structurer_retry */",
        "/* summary: shown=8 decompiled=7 asm_or_detail_fallback=1 */",
    ]


def test_asm_fallback_pattern_note_names_string_instruction_evidence():
    note = cli_output._asm_fallback_pattern_note(
        "0x1168f: rep movsb byte ptr es:[di], byte ptr [si]\n"
        "0x116db: rep stosw word ptr es:[di], ax\n"
        "0x11555: repne scasb al, byte ptr es:[di]\n"
        "0x12be2: repe cmpsb byte ptr [si], byte ptr es:[di]\n"
    )

    assert note is not None
    assert "assembly pattern" in note
    assert "x86 string-instruction" in note
    assert "copy loop" in note
    assert "fill loop" in note
    assert "scan loop" in note
    assert "compare loop" in note
    assert "not guessed C" in note


def test_default_recovery_timeout_uses_wider_default_gate():
    assert decompile._default_recovery_timeout(20, explicit_timeout=False) == 20
    assert decompile._default_recovery_timeout(20, explicit_timeout=True) == 20
    assert decompile._default_recovery_timeout(3, explicit_timeout=True) == 3


def test_heavy_fallback_lane_policy_stays_closed_for_sweep_runs():
    assert not non_optimized_fallback.allows_heavy_fallbacks_for_run(
        interactive_stdout=False,
        max_functions=8,
        addr_requested=False,
    )
    assert non_optimized_fallback.allows_heavy_fallbacks_for_run(
        interactive_stdout=True,
        max_functions=8,
        addr_requested=False,
    )
    assert non_optimized_fallback.allows_heavy_fallbacks_for_run(
        interactive_stdout=False,
        max_functions=0,
        addr_requested=False,
    )
    assert non_optimized_fallback.allows_heavy_fallbacks_for_run(
        interactive_stdout=False,
        max_functions=8,
        addr_requested=True,
    )


def test_explicit_direct_addr_timeout_disables_hidden_validation_retries():
    assert (
        cli_core._direct_addr_validation_retry_count_8616(
            timeout_was_explicit=True,
            args_timeout=60,
        )
        == 0
    )
    assert (
        cli_core._direct_addr_validation_retry_count_8616(
            timeout_was_explicit=False,
            args_timeout=60,
        )
        == 0
    )
    assert cli_core._direct_addr_robust_retry_enabled_8616(timeout_was_explicit=True) is False
    assert cli_core._direct_addr_robust_retry_enabled_8616(timeout_was_explicit=False) is True


def test_explicit_direct_addr_validation_failure_with_partial_skips_heavy_fallbacks():
    assert (
        cli_core._direct_addr_should_skip_heavy_validation_fallbacks_8616(
            timeout_was_explicit=True,
            args_timeout=45,
            direct_status="validation_failed",
            partial_payload="void QuickSort(void) {}",
        )
        is True
    )
    assert (
        cli_core._direct_addr_should_skip_heavy_validation_fallbacks_8616(
            timeout_was_explicit=False,
            args_timeout=45,
            direct_status="validation_failed",
            partial_payload="void QuickSort(void) {}",
        )
        is False
    )
    assert (
        cli_core._direct_addr_should_skip_heavy_validation_fallbacks_8616(
            timeout_was_explicit=True,
            args_timeout=45,
            direct_status="ok",
            partial_payload="void QuickSort(void) {}",
        )
        is False
    )
    assert (
        cli_core._direct_addr_should_skip_heavy_validation_fallbacks_8616(
            timeout_was_explicit=True,
            args_timeout=45,
            direct_status="validation_failed",
            partial_payload="",
        )
        is False
    )


def test_adaptive_per_byte_timeout_model_scales_from_successes():
    model = decompile._AdaptivePerByteTimeoutModel(20, explicit_timeout=False, margin=1.5)

    baseline = model.timeout_for_byte_count(0x20)
    model.observe_success(0x20, 1.0)
    model.observe_success(0x40, 2.2)
    model.observe_success(0x80, 4.6)

    assert model.timeout_for_byte_count(0x20) == baseline
    assert model.timeout_for_byte_count(0x80) == baseline
    assert model.timeout_for_byte_count(0x100) == baseline
    model.observe_success(0x100, 80.0)
    assert model.timeout_for_byte_count(0x100) == 120
    assert model.timeout_for_byte_count(280) >= 150
    assert model.timeout_for_byte_count(520) >= 180
    explicit_model = decompile._AdaptivePerByteTimeoutModel(20, explicit_timeout=True)
    assert explicit_model.timeout_for_byte_count(520) == 20


def test_direct_addr_failure_family_repeat_reason_changes_on_new_proof():
    base = build_failure_family_snapshot(
        status="empty",
        failure_stage="structuring",
        fallback_kind="isolated_retry",
        tail_validation_verdict="uncollected",
        artifact_path="0x102e0:RunMenu",
    )
    repeat = build_failure_family_snapshot(
        status="empty",
        failure_stage="structuring",
        fallback_kind="isolated_retry",
        tail_validation_verdict="uncollected",
        artifact_path="0x102e0:RunMenu",
    )
    changed_artifact = build_failure_family_snapshot(
        status="empty",
        failure_stage="structuring",
        fallback_kind="isolated_retry",
        tail_validation_verdict="uncollected",
        artifact_path="0x102e0:RunMenu:retry",
    )
    changed_verdict = build_failure_family_snapshot(
        status="empty",
        failure_stage="structuring",
        fallback_kind="isolated_retry",
        tail_validation_verdict="stable",
        artifact_path="0x102e0:RunMenu",
    )

    assert failure_family_repeat_reason(base, repeat) is not None
    assert failure_family_repeat_reason(base, changed_artifact) is None
    assert failure_family_repeat_reason(base, changed_verdict) is None


def test_direct_addr_failure_family_state_tracks_previous_candidate_and_new_proof():
    state = FailureFamilyState()
    base = build_failure_family_snapshot(
        status="empty",
        failure_stage="structuring",
        fallback_kind="structurer_retry",
        tail_validation_verdict="uncollected",
        artifact_path="0x102e0:RunMenu",
    )
    repeat = build_failure_family_snapshot(
        status="empty",
        failure_stage="structuring",
        fallback_kind="structurer_retry",
        tail_validation_verdict="uncollected",
        artifact_path="0x102e0:RunMenu",
    )
    changed = build_failure_family_snapshot(
        status="empty",
        failure_stage="structuring",
        fallback_kind="structurer_retry",
        tail_validation_verdict="changed",
        artifact_path="0x102e0:RunMenu:retry",
    )

    assert remember_failure_family_candidate(state, base) is None
    assert state.previous_snapshot is None
    assert state.candidate_snapshot == base
    assert state.new_proof_seen is False
    assert state.repeat_detected is False
    advance_failure_family_state(state)
    assert state.previous_snapshot == base

    assert remember_failure_family_candidate(state, repeat) is not None
    assert state.previous_snapshot == base
    assert state.candidate_snapshot == repeat
    assert state.new_proof_seen is False
    assert state.repeat_detected is True
    advance_failure_family_state(state)
    assert state.previous_snapshot == repeat

    assert remember_failure_family_candidate(state, changed) is None
    assert state.previous_snapshot == repeat
    assert state.candidate_snapshot == changed
    assert state.new_proof_seen is True
    assert state.repeat_detected is False


def test_direct_addr_failure_family_snapshot_cache_round_trip_is_strict():
    snapshot = build_failure_family_snapshot(
        status="ok",
        failure_stage=None,
        sidecar_verdict="not_attempted",
        non_optimized_verdict="not_attempted",
        fallback_kind="direct_addr",
        tail_validation_verdict="passed",
        artifact_path="0x10e70:Beep",
    )

    assert FailureFamilySnapshot.from_record(snapshot.to_record()) == snapshot
    incomplete = snapshot.to_record()
    incomplete.pop("tail_validation_verdict")
    assert FailureFamilySnapshot.from_record(incomplete) is None


def test_decompile_function_with_stats_skips_same_family_retry_without_new_proof(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    calls: list[int] = []

    class _FakeDecompiler:
        def __init__(self):
            self.codegen = None
            self.errors = [SimpleNamespace(exc_type=KeyError, exc_value=KeyError("same family"))]
            self.clinic = None

    class _FakeAnalyses:
        def Decompiler(self, *_args, **_kwargs):
            calls.append(1)
            return _FakeDecompiler()

    project = SimpleNamespace(
        analyses=_FakeAnalyses(),
        arch=SimpleNamespace(name="86_16"),
        entry=0x1000,
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x1000, max_addr=0x1000)),
        _inertia_decompiler_stage="structuring",
    )
    function = SimpleNamespace(addr=0x102E0, name="RunMenu", info={}, project=project, normalized=True)
    cfg = SimpleNamespace()

    monkeypatch.setattr(cli_decompilation, "_analysis_timeout", lambda *_args, **_kwargs: contextlib.nullcontext())
    monkeypatch.setattr(
        cli_decompilation,
        "_guard_angr_peephole_expr_bitwidth_assertion",
        lambda *_args, **_kwargs: contextlib.nullcontext(),
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_guard_angr_variable_recovery_binop_sub_size_mismatch",
        lambda *_args, **_kwargs: contextlib.nullcontext(),
    )
    monkeypatch.setattr(
        cli_decompilation, "_guard_angr_ail_narrowing", lambda *_args, **_kwargs: contextlib.nullcontext()
    )
    monkeypatch.setattr(
        cli_decompilation, "_guard_angr_clinic_stage_markers", lambda *_args, **_kwargs: contextlib.nullcontext()
    )

    status, _payload, partial_payload, block_count, byte_count, elapsed = (
        cli_decompilation._decompile_function_with_stats(
            project,
            cfg,
            function,
            timeout=2,
            api_style="default",
            binary_path=None,
            cod_metadata=None,
            synthetic_globals=None,
            lst_metadata=None,
            enable_structured_simplify=True,
            enable_postprocess=True,
            allow_isolated_retry=True,
            failure_family_state=FailureFamilyState(
                previous_snapshot=build_failure_family_snapshot(
                    status="empty",
                    failure_stage="structuring",
                    fallback_kind="structurer_retry",
                    tail_validation_verdict="uncollected",
                    artifact_path="0x102e0:RunMenu",
                )
            ),
        )
    )
    captured = capsys.readouterr()

    assert status == "empty"
    assert "stop: same failure family" in captured.err
    assert "stop: same failure family" not in captured.out
    assert calls == [1]
    assert partial_payload is None
    assert block_count == 0
    assert byte_count == 0
    assert elapsed >= 0
    bundle_files = tuple((tmp_path / ".codex_automation" / "stage_debug").glob("unknown-binary_*/0x102e0_RunMenu_*/manifest.json"))
    assert bundle_files


def test_decompile_function_with_stats_reports_pipeline_contract_failure_as_validation_failed(
    monkeypatch,
):
    project = SimpleNamespace(_inertia_partial_codegen_text="void f(void) { return; }")
    function = SimpleNamespace(
        addr=0x1000,
        name="f",
        blocks=(SimpleNamespace(size=2),),
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_decompile_function",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            cli_decompilation.PipelineHardError("function leaked unresolved stack locals into final C")
        ),
    )

    status, payload, partial_payload, *_stats = cli_decompilation._decompile_function_with_stats(
        project,
        SimpleNamespace(),
        function,
        timeout=2,
        api_style="default",
    )

    assert status == "validation_failed"
    assert payload == "Pipeline contract violation: f leaked unresolved stack locals into final C"
    assert partial_payload == "void f(void) { return; }"


def test_direct_timeout_stage_parses_structuring_pass_timeout_payload():
    assert (
        cli_core._direct_timeout_failure_stage_from_payload(
            "Timed out after 30s during x86-16 structuring pass recovery_stage."
        )
        == "structuring:recovery_stage"
    )


def test_direct_timeout_stage_preserves_clinic_or_default_fallback():
    assert (
        cli_core._direct_timeout_failure_stage_from_payload("Timed out after 5s during core decompilation.") == "decompilation:core"
    )
    assert (
        cli_core._direct_timeout_failure_stage_from_payload("Timed out after 5s during x86-16 postprocess pass prune")
        == "postprocess:prune"
    )
    assert (
        cli_core._direct_timeout_failure_stage_from_payload("Timed out after 5s during decompilation.") == "decompilation"
    )
    assert cli_core._direct_timeout_failure_stage_from_payload("Timed out after 5s.") == "decompilation"
    assert cli_core._direct_timeout_failure_stage_from_payload(None) == "decompilation"


def test_function_work_cache_ignores_timeout_records(monkeypatch):
    function = SimpleNamespace(addr=0x1234, name="sub_1234", project=None)
    item = FunctionWorkItem(index=1, function_cfg=object(), function=function)
    monkeypatch.setattr(cli_core, "function_decompilation_cache_key_8616", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        cli_core,
        "_load_cache_json",
        lambda *_args, **_kwargs: {
            "status": "timeout",
            "payload": "Timed out.",
            "timeout": 2,
        },
    )

    result, _debug, _cache_key, _tail_enabled, _expected_stages = cli_core._function_work_cache_lookup(
        item,
        binary_path=None,
        timeout=2,
        api_style="dos",
        enable_structured_simplify=True,
        enable_postprocess=True,
    )

    assert result is None
    assert "ignoring cached failed function result" in _debug
    assert "status=timeout" in _debug


def test_function_work_cache_bypasses_payload_without_acceptance_provenance(monkeypatch):
    function = SimpleNamespace(addr=0x10CE0, name="QuickSort", project=SimpleNamespace())
    item = FunctionWorkItem(index=1, function_cfg=object(), function=function)
    monkeypatch.setattr(cli_core, "_tail_validation_runtime_enabled", lambda _project: False)
    monkeypatch.setattr(cli_core, "function_decompilation_cache_key_8616", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        cli_core,
        "_load_cache_json",
        lambda *_args, **_kwargs: {
            "status": "ok",
            "payload": (
                "void QuickSort(void)\n"
                "{\n"
                "    unsigned short vvar_137;\n"
                "    vvar_137 = 1;\n"
                "    if (vvar_137) {\n"
                "        return;\n"
                "    }\n"
                "}\n"
            ),
            "elapsed": 1.0,
        },
    )
    result, debug, _cache_key, _tail_enabled, _expected_stages = cli_core._function_work_cache_lookup(
        item,
        binary_path=Path("SORTDEMO.EXE"),
        timeout=20,
        api_style="dos",
        enable_structured_simplify=True,
        enable_postprocess=True,
    )

    assert result is None
    assert "missing_acceptance_provenance" in debug


def test_function_work_cache_accepts_complete_matching_provenance(monkeypatch):
    function = SimpleNamespace(addr=0x10CE0, name="QuickSort", project=SimpleNamespace())
    item = FunctionWorkItem(index=1, function_cfg=object(), function=function)
    payload = "void QuickSort(void)\n{\n    return;\n}\n"
    payload_hash = cli_core._sha256_text_8616(payload)
    failure_family = build_failure_family_snapshot(
        status="ok",
        failure_stage=None,
        fallback_kind="direct_addr",
        tail_validation_verdict="passed",
        artifact_path="0x10ce0:QuickSort",
    )
    monkeypatch.setattr(cli_core, "_tail_validation_runtime_enabled", lambda _project: False)
    monkeypatch.setattr(cli_core, "function_decompilation_cache_key_8616", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        cli_core,
        "_load_cache_json",
        lambda *_args, **_kwargs: {
            "status": "ok",
            "payload": payload,
            "elapsed": 1.0,
            "validated_c_hash": payload_hash,
            "gcc_checked_c_hash": payload_hash,
            "failure_family_snapshot": failure_family.to_record(),
        },
    )

    result, debug, _cache_key, _tail_enabled, _expected_stages = cli_core._function_work_cache_lookup(
        item,
        binary_path=Path("SORTDEMO.EXE"),
        timeout=20,
        api_style="dos",
        enable_structured_simplify=True,
        enable_postprocess=True,
    )

    assert result is not None
    assert result.status == "ok"
    assert result.from_cache is True
    assert result.validated_payload_hash == payload_hash
    assert result.gcc_checked_payload_hash == payload_hash
    assert result.failure_family_snapshot == failure_family
    assert debug == ""


def test_function_work_cache_bypasses_stale_normalized_payload(monkeypatch):
    function = SimpleNamespace(addr=0x10678, name="ReInitBars", project=SimpleNamespace())
    item = FunctionWorkItem(index=1, function_cfg=object(), function=function)
    payload = (
        "void ReInitBars(void)\n"
        "{\n"
        "    MEM_U16(&mem_08F0 + local_0 * 2);\n"
        "    return;\n"
        "}\n"
    )
    payload_hash = cli_core._sha256_text_8616(payload)
    monkeypatch.setattr(cli_core, "_tail_validation_runtime_enabled", lambda _project: False)
    monkeypatch.setattr(cli_core, "function_decompilation_cache_key_8616", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        cli_core,
        "_load_cache_json",
        lambda *_args, **_kwargs: {
            "status": "ok",
            "payload": payload,
            "elapsed": 1.0,
            "validated_c_hash": payload_hash,
            "gcc_checked_c_hash": payload_hash,
        },
    )
    result, debug, _cache_key, _tail_enabled, _expected_stages = cli_core._function_work_cache_lookup(
        item,
        binary_path=Path("SORTDEMO.EXE"),
        timeout=20,
        api_style="dos",
        enable_structured_simplify=True,
        enable_postprocess=True,
    )

    assert result is None
    assert "cache bypass" in debug
    assert "stale_normalization" in debug


def test_tail_validation_cache_paths_are_stable_for_direct_binary_runs():
    item = decompile.FunctionWorkItem(
        index=1,
        function_cfg=None,
        function=SimpleNamespace(addr=0x1234, name="_life_step"),
    )

    console_path = cli_tail_validation.tail_validation_console_cache_path(LIFE_EXE, [item])
    detail_path = cli_tail_validation.tail_validation_detail_cache_path(LIFE_EXE, [item])

    assert console_path is not None
    assert detail_path is not None
    assert console_path.name.endswith(".tail_validation_console.json")
    assert detail_path.name.endswith(".tail_validation_surface.json")
    assert "LIFE" in console_path.name
    assert "LIFE" in detail_path.name


def _build_synthetic_microsoft_lib(
    module_bytes: bytes,
    *,
    page_size: int = 512,
    case_sensitive: bool = False,
    extended_records: list[tuple[int, tuple[int, ...]]] | None = None,
    dictionary_entries: list[tuple[str, int]] | None = None,
) -> bytes:
    header_payload_len = page_size - 3
    module_page = module_bytes + (b"\x00" * ((page_size - (len(module_bytes) % page_size)) % page_size))
    dict_offset = page_size + len(module_page)
    dict_blocks = 1
    header = bytearray(page_size)
    header[0] = 0xF0
    header[1:3] = header_payload_len.to_bytes(2, "little")
    header[3:7] = dict_offset.to_bytes(4, "little")
    header[7:9] = dict_blocks.to_bytes(2, "little")
    header[9] = 0x01 if case_sensitive else 0x00
    dict_page = bytearray(512)
    if dictionary_entries:
        free_offset = 38 * 2
        for symbol_name, module_page_number in dictionary_entries:
            encoded_name = symbol_name.encode("latin1")
            entry = bytes([len(encoded_name)]) + encoded_name + int(module_page_number).to_bytes(2, "little")
            assert free_offset + len(entry) <= len(dict_page)
            _page_index, _page_delta, bucket, bucket_delta = _hash_synthetic_microsoft_lib_symbol(
                symbol_name,
                dict_blocks,
                case_sensitive=case_sensitive,
            )
            start_bucket = bucket
            while dict_page[bucket] != 0:
                bucket = (bucket + bucket_delta) % 37
                assert bucket != start_bucket
            dict_page[bucket] = free_offset // 2
            dict_page[free_offset : free_offset + len(entry)] = entry
            free_offset += len(entry)
            if free_offset & 1:
                free_offset += 1
        dict_page[37] = free_offset // 2
    blob = bytes(header) + module_page + bytes(dict_page)
    if extended_records:
        payload = bytearray()
        payload += len(extended_records).to_bytes(2, "little")
        table_size = len(extended_records) * 4
        dependency_lists = bytearray()
        offsets: list[int] = []
        for _page_number, deps in extended_records:
            offsets.append(2 + table_size + len(dependency_lists))
            for dep in deps:
                dependency_lists += int(dep).to_bytes(2, "little")
            dependency_lists += (0).to_bytes(2, "little")
        for (page_number, _deps), dep_offset in zip(extended_records, offsets, strict=True):
            payload += int(page_number).to_bytes(2, "little")
            payload += int(dep_offset).to_bytes(2, "little")
        payload += dependency_lists
        record_length = len(payload) + 1
        ext = bytearray()
        ext.append(0xF2)
        ext += record_length.to_bytes(2, "little")
        ext += payload
        ext.append(0)
        blob += bytes(ext)
    trailer = bytearray(512)
    trailer[0] = 0xF1
    trailer[1:3] = (509).to_bytes(2, "little")
    return blob + bytes(trailer)


def _hash_synthetic_microsoft_lib_symbol(
    symbol_name: str, dictionary_pages: int, *, case_sensitive: bool
) -> tuple[int, int, int, int]:
    name_bytes = symbol_name.encode("latin1", errors="ignore")
    if not case_sensitive:
        name_bytes = bytes((byte | 0x20) if 0x41 <= byte <= 0x5A else byte for byte in name_bytes)
    page_index = 0
    page_index_delta = 0
    bucket_index = 0
    bucket_index_delta = 0
    for forward, reverse in zip(name_bytes, reversed(name_bytes), strict=True):
        page_index = ((page_index << 2) ^ forward) & 0xFFFFFFFF
        bucket_index_delta = ((bucket_index_delta >> 2) ^ forward) & 0xFFFFFFFF
        bucket_index = ((bucket_index >> 2) ^ reverse) & 0xFFFFFFFF
        page_index_delta = ((page_index_delta << 2) ^ reverse) & 0xFFFFFFFF
    page_index %= dictionary_pages
    page_index_delta = (page_index_delta % dictionary_pages) or 1
    bucket_index %= 37
    bucket_index_delta = (bucket_index_delta % 37) or 1
    return page_index, page_index_delta, bucket_index, bucket_index_delta


def _run_decompile_proc(
    path: Path,
    proc: str,
    *,
    proc_kind: str = "NEAR",
    analysis_timeout: int = 10,
    subprocess_timeout: int = 30,
    scale_for_xdist: bool = True,
) -> subprocess.CompletedProcess[str]:
    if scale_for_xdist:
        analysis_timeout = scaled_decompile_timeout(analysis_timeout)
        subprocess_timeout = scaled_decompile_timeout(subprocess_timeout)
    return subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(path),
            "--proc",
            proc,
            "--proc-kind",
            proc_kind,
            "--timeout",
            str(analysis_timeout),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=subprocess_timeout,
        check=False,
    )


def _assert_explicit_partial_or_fallback_failure(result: subprocess.CompletedProcess[str]) -> None:
    assert (
        "partial timeout" in result.stdout
        or "direct validation=failed" in result.stdout
        or "== asm fallback ==" in result.stdout
        or "whole-tail validation failed" in result.stderr
    )


def test_preferred_decompiler_options_prefers_phoenix_for_true_wrappers():
    assert decompile._preferred_decompiler_options(1, 21, wrapper_like=True) == [("structurer_cls", "Phoenix")]
    assert decompile._preferred_decompiler_options(1, 24, wrapper_like=True) == [("structurer_cls", "Phoenix")]
    assert decompile._preferred_decompiler_options(2, 21, wrapper_like=True) == [("structurer_cls", "Phoenix")]
    assert decompile._preferred_decompiler_options(1, 25, wrapper_like=True) == [("structurer_cls", "Phoenix")]
    assert decompile._preferred_decompiler_options(1, 24) is None
    assert decompile._preferred_decompiler_options(2, 21) is None


def test_preferred_decompiler_options_rejects_call_heavy_small_functions():
    assert decompile._preferred_decompiler_options(1, 24, wrapper_like=True) == [("structurer_cls", "Phoenix")]
    assert decompile._preferred_decompiler_options(1, 23, wrapper_like=True) == [("structurer_cls", "Phoenix")]
    assert decompile._preferred_decompiler_options(1, 25, wrapper_like=True) == [("structurer_cls", "Phoenix")]
    assert decompile._preferred_decompiler_options(6, 64, wrapper_like=True) == [("structurer_cls", "Phoenix")]
    assert decompile._preferred_decompiler_options(1, 24, wrapper_like=False) is None


def test_preferred_decompiler_options_accepts_tiny_single_call_helpers():
    assert decompile._preferred_decompiler_options(3, 0x14, tiny_single_call_helper=True) == [
        ("structurer_cls", "Phoenix")
    ]
    assert decompile._preferred_decompiler_options(3, 0x17, tiny_single_call_helper=True) == [
        ("structurer_cls", "Phoenix")
    ]
    assert decompile._preferred_decompiler_options(1, 0x14, tiny_single_call_helper=True) == [
        ("structurer_cls", "Phoenix")
    ]
    assert decompile._preferred_decompiler_options(3, 0x14, tiny_single_call_helper=False) is None


def test_preferred_decompiler_options_disables_expensive_clinic_work_for_large_16bit_functions():
    assert decompile._preferred_decompiler_options(76, 0x1AE, large_16bit_function=True) == [
        ("rewrite_ites_to_diamonds", False),
        ("semvar_naming", False),
        ("remove_dead_memdefs", False),
    ]
    assert decompile._preferred_decompiler_options(76, 0x1AE) is None


@pytest.mark.parametrize(
    "addr, byte_count, block_sizes",
    [
        (0x10010, 0x14, (0x08, 0x08, 0x04)),
        (0x1157C, 0x17, (0x08, 0x08, 0x07)),
        (0x1196F, 0x14, (0x14,)),
    ],
)
def test_function_decompilation_profile_marks_tiny_single_call_helpers_small(addr, byte_count, block_sizes):
    blocks = {}
    block_addrs = [addr + (index * 0x10) for index in range(len(block_sizes))]
    for index, (block_addr, block_size) in enumerate(zip(block_addrs, block_sizes, strict=True)):
        insns = [
            SimpleNamespace(mnemonic="push", op_str="bp"),
            SimpleNamespace(mnemonic="mov", op_str="bp, sp"),
        ]
        if index == 0:
            insns.append(SimpleNamespace(mnemonic="call", op_str="0x1140d"))
        insns.append(SimpleNamespace(mnemonic="mov", op_str="ax, [bp + 4]"))
        blocks[block_addr] = SimpleNamespace(size=block_size, capstone=SimpleNamespace(insns=insns))

    project = SimpleNamespace(factory=SimpleNamespace(block=lambda block_addr, opt_level=0: blocks[block_addr]))
    function = SimpleNamespace(
        addr=addr,
        name=f"sub_{addr:x}",
        project=project,
        block_addrs_set=set(blocks),
        get_call_sites=lambda: [addr + 0x20],
    )

    profile = decompile._function_decompilation_profile(function, len(block_sizes), byte_count)

    assert profile["block_count"] == len(block_sizes)
    assert profile["byte_count"] == byte_count
    assert profile["wrapper_like"] is False
    assert profile["tiny_single_call_helper"] is True


def test_function_decompilation_profile_rejects_branch_heavy_helpers():
    blocks = {
        0x2000: SimpleNamespace(
            size=0x08,
            capstone=SimpleNamespace(
                insns=[
                    SimpleNamespace(mnemonic="push", op_str="bp"),
                    SimpleNamespace(mnemonic="call", op_str="0x3000"),
                ]
            ),
        ),
        0x2010: SimpleNamespace(
            size=0x08,
            capstone=SimpleNamespace(
                insns=[
                    SimpleNamespace(mnemonic="jnz", op_str="0x2030"),
                    SimpleNamespace(mnemonic="mov", op_str="ax, [bp + 4]"),
                ]
            ),
        ),
        0x2020: SimpleNamespace(
            size=0x08,
            capstone=SimpleNamespace(insns=[SimpleNamespace(mnemonic="ret", op_str="")]),
        ),
    }
    project = SimpleNamespace(factory=SimpleNamespace(block=lambda block_addr, opt_level=0: blocks[block_addr]))
    function = SimpleNamespace(
        addr=0x2000,
        name="sub_2000",
        project=project,
        block_addrs_set=set(blocks),
        get_call_sites=lambda: [0x2004],
    )

    profile = decompile._function_decompilation_profile(function, 3, 0x18)

    assert profile["wrapper_like"] is False
    assert profile["tiny_single_call_helper"] is False


def test_function_recovery_detail_names_recovery_stage():
    assert decompile._function_recovery_detail("recovery") == "during x86-16 function recovery"
    assert decompile._function_recovery_detail("recovery:fast") == "during x86-16 function recovery (fast CFGFast)"
    assert decompile._function_recovery_detail("recovery:full") == "during x86-16 function recovery (full CFGFast)"
    assert decompile._function_recovery_detail("recovery:narrow:0x80") == (
        "during x86-16 function recovery (narrow CFGFast)"
    )
    assert decompile._function_recovery_detail("postprocess") is None


def test_install_angr_peephole_expr_bitwidth_guard_skips_mismatched_replacements():
    class BaseWalker:
        def __init__(self):
            self.any_update = False
            self.expr_opts = []

        def _handle_expr(self, expr_idx, expr, stmt_idx, stmt, block):
            return expr

    class FakeWalker(BaseWalker):
        pass

    class FakeExpr:
        def __init__(self, bits):
            self.bits = bits

    class FakeExprOpt:
        expr_classes = (FakeExpr,)

        def optimize(self, expr, stmt_idx=None, block=None):
            return FakeExpr(8)

    original = runtime_support.install_angr_peephole_expr_bitwidth_guard(FakeWalker)
    try:
        walker = FakeWalker()
        walker.expr_opts = [FakeExprOpt()]
        expr = FakeExpr(16)
        result = walker._handle_expr(0, expr, 0, None, None)
    finally:
        FakeWalker._handle_expr = original

    assert result is expr
    assert walker.any_update is False


def test_install_angr_variable_recovery_binop_sub_size_guard_computes_in_wider_domain_then_narrows():
    class FakeBV:
        def __init__(self, bits, *, concrete=False, concrete_value=0):
            self._bits = bits
            self.concrete = concrete
            self.concrete_value = concrete_value

        def size(self):
            return self._bits

        def zero_extend(self, nbits):
            return FakeBV(self._bits + nbits, concrete=self.concrete, concrete_value=self.concrete_value)

        def __getitem__(self, item):
            hi, lo = item.start, item.stop
            return FakeBV(hi - lo + 1, concrete=self.concrete, concrete_value=self.concrete_value)

        def __sub__(self, other):
            return FakeBV(max(self._bits, other._bits))

    class FakeRichR:
        def __init__(self, data, typevar=None, type_constraints=None):
            self.data = data
            self.typevar = typevar
            self.type_constraints = type_constraints

    class FakeTypeVariable:
        pass

    class FakeTypevarsModule:
        TypeVariable = FakeTypeVariable

        @staticmethod
        def new_dtv(*_args, **_kwargs):
            return FakeTypeVariable()

        @staticmethod
        def SubN(_value):
            return "subn"

        @staticmethod
        def Sub(_lhs, _rhs, _out):
            return ("sub", _lhs, _rhs, _out)

    class FakeState:
        def top(self, bits):
            return ("top", bits)

    class FakeEngine:
        def __init__(self):
            self.state = FakeState()

        def _expr_pair(self, _arg0, _arg1):
            return FakeRichR(FakeBV(16), typevar=FakeTypeVariable()), FakeRichR(FakeBV(8))

        def _handle_binop_Sub(self, expr):
            raise AssertionError("original implementation should not run")

    class FakeExpr:
        bits = 16
        operands = ("lhs", "rhs")

    original = runtime_support.install_angr_variable_recovery_binop_sub_size_guard(
        FakeEngine,
        richr_cls=FakeRichR,
        typevars_module=FakeTypevarsModule,
    )
    try:
        result = FakeEngine()._handle_binop_Sub(FakeExpr())
    finally:
        FakeEngine._handle_binop_Sub = original

    assert isinstance(result.data, FakeBV)
    assert result.data.size() == 16


def test_recover_direct_addr_function_prefers_candidate_recovery_for_x86_16(monkeypatch):
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x4000)),
    )
    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=0x1196F)
    lst_metadata = LSTMetadata(data_labels={}, code_labels={}, absolute_addrs=True)
    calls = []

    monkeypatch.setattr(decompile, "_analysis_timeout", contextlib.nullcontext)
    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: (0x11960, 0x11A00))
    monkeypatch.setenv("INERTIA_DIRECT_ADDR_PREFER_LST", "0")

    def fake_recover_candidate(
        project_arg,
        *,
        candidate_addr,
        image_end,
        metadata,
        project_entry,
        region_span,
        exact_region,
    ):
        assert metadata is None
        calls.append((candidate_addr, image_end, project_entry, region_span))
        assert exact_region is None
        return expected_cfg, expected_func

    monkeypatch.setattr(decompile, "_recover_candidate_function_pair", fake_recover_candidate)
    monkeypatch.setattr(
        decompile,
        "_pick_function",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("raw pick_function should not run")),
    )

    cfg, func = decompile._recover_direct_addr_function(
        project,
        0x1196F,
        timeout=6,
        window=0x40,
        function_label=None,
        lst_metadata=lst_metadata,
        low_memory_path=False,
        prefer_fast_recovery=False,
    )

    assert (cfg, func) == (expected_cfg, expected_func)
    assert calls == [(0x1196F, 0x14001, 0x11423, 0x180)]


def test_recover_direct_addr_function_prefers_owning_lst_entry_for_interior_addr(monkeypatch):
    project = SimpleNamespace(entry=0x10000, arch=SimpleNamespace(name="86_16"))
    lst_metadata = LSTMetadata(data_labels={}, code_labels={}, absolute_addrs=True)
    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=0x10060)
    calls = []

    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: (0x10060, 0x10180))
    monkeypatch.setattr(decompile, "_lst_code_label", lambda *_args, **_kwargs: "Main")
    monkeypatch.setattr(
        decompile,
        "_recover_lst_function",
        lambda _project, _lst, offset, name, **_kwargs: calls.append((offset, name)) or (expected_cfg, expected_func),
    )
    monkeypatch.setenv("INERTIA_DIRECT_ADDR_PREFER_LST", "1")
    monkeypatch.delenv("INERTIA_DIRECT_ADDR_STRICT", raising=False)

    cfg, func = decompile._recover_direct_addr_function(
        project,
        0x10175,
        timeout=6,
        window=0x40,
        function_label=None,
        lst_metadata=lst_metadata,
        low_memory_path=False,
        prefer_fast_recovery=False,
    )

    assert (cfg, func) == (expected_cfg, expected_func)
    assert calls == [(0x10060, "Main")]


def test_recover_direct_addr_function_rebases_interior_addr_to_sidecar_entry(monkeypatch):
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x4000)),
    )
    lst_metadata = LSTMetadata(data_labels={}, code_labels={}, absolute_addrs=True)
    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=0x10060)
    calls = []

    monkeypatch.setattr(decompile, "_analysis_timeout", contextlib.nullcontext)
    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: (0x10060, 0x10180))

    def fake_recover_candidate(
        project_arg,
        *,
        candidate_addr,
        image_end,
        metadata,
        project_entry,
        region_span,
        exact_region,
    ):
        calls.append((candidate_addr, image_end, project_entry, region_span, metadata is lst_metadata))
        assert exact_region is None
        return expected_cfg, expected_func

    monkeypatch.setattr(decompile, "_recover_candidate_function_pair", fake_recover_candidate)
    monkeypatch.setattr(
        decompile,
        "_pick_function",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("raw pick_function should not run")),
    )

    cfg, func = decompile._recover_direct_addr_function(
        project,
        0x10175,
        timeout=6,
        window=0x40,
        function_label=None,
        lst_metadata=lst_metadata,
        low_memory_path=False,
        prefer_fast_recovery=False,
    )

    assert (cfg, func) == (expected_cfg, expected_func)
    assert calls == [(0x10060, 0x14001, 0x11423, 0x180, True)]


def test_canonicalize_direct_addr_from_sidecar_padding_uses_prologue_start():
    class Memory:
        def __init__(self) -> None:
            self.calls = []

        def load(self, addr, size):
            self.calls.append((addr, size))
            assert addr == 0x10A61
            return (b"\x90" * (0x10A88 - 0x10A61)) + b"\x55\x8b\xec\x90"

    memory = Memory()
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=memory),
    )
    metadata = SimpleNamespace(
        absolute_addrs=True,
        code_labels={0x10A61: "PercolateDown"},
        code_ranges={0x10A61: (0x10A61, 0x10B2C)},
    )

    result = decompile._canonicalize_direct_addr_from_sidecar_padding_8616(
        project,
        metadata,
        0x10A61,
    )

    assert result is not None
    assert result.requested_addr == 0x10A61
    assert result.canonical_addr == 0x10A88
    assert result.region == (0x10A61, 0x10B2C)
    assert result.name == "PercolateDown"
    assert memory.calls == [(0x10A61, 0x80)]


def test_canonicalized_direct_clean_worker_emits_parent_label(monkeypatch, capsys):
    args = SimpleNamespace(timeout=60)
    project = SimpleNamespace()
    metadata = SimpleNamespace()
    canonical = decompile.DirectAddrCanonicalization8616(
        requested_addr=0x10554,
        canonical_addr=0x10560,
        region=(0x10554, 0x10672),
        name="InitBars",
    )
    result = SimpleNamespace(
        status=decompile.WorkItemStatus.OK.value,
        payload="void sub_10560(void) {}",
        partial_payload=None,
        debug_output="",
        tail_validation={},
    )
    seen = {}

    def run_clean_worker(*_args, **kwargs):
        seen.update(kwargs)
        return result

    monkeypatch.setattr(decompile, "_run_serial_clean_process_work_item_8616", run_clean_worker)
    monkeypatch.setattr(decompile, "_tail_validation_passes_lenient", lambda *_args, **_kwargs: True)

    return_code = decompile._run_canonicalized_direct_clean_worker_8616(
        project,
        args,
        metadata,
        canonical,
        function_label="InitBars",
        caller_return_evidence_by_addr={},
    )

    captured = capsys.readouterr()
    assert return_code == 0
    assert "function: 0x10560 InitBars" in captured.out
    assert "void InitBars(void) {}" in captured.out
    assert "sub_10560" not in captured.out
    assert "canonical clean worker validation=passed" in captured.err
    assert seen["caller_return_evidence_by_addr"] == {}


def test_canonicalize_sidecar_work_offset_uses_prologue_start():
    class Memory:
        def load(self, addr, size):
            assert addr == 0x10672
            assert size == 0x56
            return (b"\x90" * 6) + b"\x55\x8b\xec\x90"

    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=Memory()),
    )
    metadata = SimpleNamespace(
        absolute_addrs=True,
        code_labels={0x10672: "ReInitBars"},
        code_ranges={0x10672: (0x10672, 0x106C8)},
    )

    addr, name = decompile._canonicalize_sidecar_work_offset_8616(
        project,
        metadata,
        0x10672,
        "ReInitBars",
    )

    assert addr == 0x10678
    assert name == "ReInitBars"


def test_fallback_entry_function_retries_broader_windows_after_narrow_recovery_fails(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    calls: list[tuple[str, object]] = []

    def fake_infer(project_arg, start_addr, *, window):
        calls.append(("infer", window))
        return start_addr, start_addr + window

    def fake_pick_function(project_arg, addr, *, regions=None, data_references=None, force_smart_scan=None):
        calls.append(("pick", regions))
        region = regions[0]
        if region[1] - region[0] >= 0x800:
            return expected_cfg, expected_func
        raise KeyError("narrow miss")

    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=project.entry)

    monkeypatch.setattr(decompile, "_infer_x86_16_linear_region", fake_infer)
    monkeypatch.setattr(decompile, "_pick_function", fake_pick_function)

    cfg, func = decompile._fallback_entry_function(project, timeout=10, window=0x200)

    assert cfg is expected_cfg
    assert func is expected_func
    assert project._inertia_decompiler_stage == "recovery:narrow:0x800"
    assert len([call for call in calls if call[0] == "pick"]) == 5
    assert [call[1][0][1] - call[1][0][0] for call in calls if call[0] == "pick"] == [
        0x200,
        0x200,
        0x400,
        0x400,
        0x800,
    ]


def test_fallback_entry_function_uses_lean_cfgfast_for_86_16(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    captured: list[dict[str, object]] = []

    def fake_infer(project_arg, start_addr, *, window):
        return start_addr, start_addr + window

    def fake_pick_function(project_arg, addr, *, regions=None, data_references=None, force_smart_scan=None):
        captured.append({"regions": regions, "data_references": data_references})
        return expected_cfg, expected_func

    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=project.entry)

    monkeypatch.setattr(decompile, "_infer_x86_16_linear_region", fake_infer)
    monkeypatch.setattr(decompile, "_pick_function", fake_pick_function)

    cfg, func = decompile._fallback_entry_function(project, timeout=10, window=0x200)

    assert cfg is expected_cfg
    assert func is expected_func
    assert captured[-1]["data_references"] is False


def test_pick_function_lean_disables_expensive_cfgfast_features(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
    )
    captured: list[dict[str, object]] = []

    expected_func = SimpleNamespace(addr=0x1000)
    expected_cfg = SimpleNamespace(functions={0x1000: expected_func})

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        return expected_cfg

    project.analyses = SimpleNamespace(CFGFast=fake_cfgfast)
    monkeypatch.setattr(decompile, "extend_cfg_for_far_calls", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "patch_interrupt_service_call_sites", lambda *_args, **_kwargs: False)

    cfg, func = decompile._pick_function_lean(project, 0x1000, regions=[(0x1000, 0x1100)])

    assert cfg is expected_cfg
    assert func is expected_func
    assert captured == [
        {
            "start_at_entry": False,
            "function_starts": [0x1000],
            "regions": [(0x1000, 0x1100)],
            "normalize": False,
            "data_references": False,
            "force_smart_scan": False,
            "force_complete_scan": False,
            "resolve_indirect_jumps": False,
            "function_prologues": False,
            "symbols": False,
            "cross_references": False,
        }
    ]


def test_pick_function_lean_can_skip_far_call_extension(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
    )
    captured: list[dict[str, object]] = []

    expected_func = SimpleNamespace(addr=0x1000)
    expected_cfg = SimpleNamespace(functions={0x1000: expected_func})

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        return expected_cfg

    project.analyses = SimpleNamespace(CFGFast=fake_cfgfast)
    monkeypatch.setattr(
        decompile,
        "extend_cfg_for_far_calls",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("far-call extension should not run")),
    )
    monkeypatch.setattr(decompile, "patch_interrupt_service_call_sites", lambda *_args, **_kwargs: False)

    cfg, func = decompile._pick_function_lean(
        project,
        0x1000,
        regions=[(0x1000, 0x1100)],
        extend_far_calls=False,
    )

    assert cfg is expected_cfg
    assert func is expected_func
    assert captured == [
        {
            "start_at_entry": False,
            "function_starts": [0x1000],
            "regions": [(0x1000, 0x1100)],
            "normalize": False,
            "data_references": False,
            "force_smart_scan": False,
            "force_complete_scan": False,
            "resolve_indirect_jumps": False,
            "function_prologues": False,
            "symbols": False,
            "cross_references": False,
        }
    ]


def test_pick_function_lean_can_extend_traced_neighbor_calls(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
    )

    initial_func = SimpleNamespace(addr=0x1000)
    extended_func = SimpleNamespace(addr=0x1000)
    initial_cfg = SimpleNamespace(functions={0x1000: initial_func})
    extended_cfg = SimpleNamespace(functions={0x1000: extended_func})
    patched: list[object] = []

    project.analyses = SimpleNamespace(CFGFast=lambda **_kwargs: initial_cfg)
    monkeypatch.setattr(decompile, "extend_cfg_for_far_calls", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "extend_cfg_for_neighbor_calls",
        lambda project_arg, function, *, entry_window: (
            extended_cfg if project_arg is project and function is initial_func and entry_window == 0x100 else None
        ),
    )
    monkeypatch.setattr(
        decompile, "patch_interrupt_service_call_sites", lambda function, *_args, **_kwargs: patched.append(function)
    )

    cfg, func = decompile._pick_function_lean(project, 0x1000, regions=[(0x1000, 0x1100)])

    assert cfg is extended_cfg
    assert func is extended_func
    assert patched == [extended_func]


def test_pick_function_lean_patches_interrupts_without_far_call_extension(monkeypatch):
    function = SimpleNamespace(addr=0x1000)
    cfg = SimpleNamespace(functions={0x1000: function})
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
        analyses=SimpleNamespace(CFGFast=lambda **_kwargs: cfg),
    )
    patched: list[object] = []
    monkeypatch.setattr(
        decompile,
        "patch_interrupt_service_call_sites",
        lambda patched_function, *_args, **_kwargs: patched.append(patched_function),
    )

    result_cfg, result_function = decompile._pick_function_lean(
        project,
        0x1000,
        regions=[(0x1000, 0x1080)],
        extend_far_calls=False,
        seed_calling_conventions_enabled=False,
    )

    assert result_cfg is cfg
    assert result_function is function
    assert patched == [function]


@requires_life_binary
def test_find_codeview_nb00_detects_life_exe():
    found = find_codeview_nb00(LIFE_EXE.read_bytes())
    assert found is not None
    signature, debug_base, subdir_addr = found
    assert signature == "NB00"
    assert debug_base == 23926
    assert subdir_addr == 31887


@requires_life_binary
def test_parse_codeview_nb00_extracts_life_functions_and_data():
    info = parse_codeview_nb00(LIFE_EXE, load_base_linear=0x10000)

    assert info is not None
    assert len(info.modules) >= 3
    assert len(info.publics) >= 100
    assert "main" in {name.lstrip("_") for name in info.code_labels.values()}
    assert "init_life" in {name.lstrip("_") for name in info.code_labels.values()}
    assert "draw_box" in {name.lstrip("_") for name in info.code_labels.values()}
    assert "generation" in {name.lstrip("_") for name in info.code_labels.values()}
    assert "speed" in {name.lstrip("_") for name in info.data_labels.values()}
    assert info.code_labels[0x10010].lstrip("_") == "main"
    assert info.code_labels[0x100EA].lstrip("_") == "init_life"
    assert info.code_labels[0x101A3].lstrip("_") == "draw_box"
    assert info.data_labels[0x15BB0].lstrip("_") == "speed"
    assert "LIFE.OBJ" in {module.name for module in info.modules}


@requires_life_binary
@requires_life_cod
def test_parse_codeview_nb00_agrees_with_life_cod_proc_names():
    info = parse_codeview_nb00(LIFE_EXE, load_base_linear=0x10000)

    assert info is not None
    cod_text = LIFE_COD.read_text(errors="ignore")

    for proc_name in ("_main", "_init_life", "_draw_box", "_generation", "_proc_key"):
        assert f"PUBLIC\t{proc_name}" in cod_text
        assert proc_name.lstrip("_") in {name.lstrip("_") for name in info.code_labels.values()}


@requires_noname_tdinfo
def test_parse_tdinfo_exe_reads_noname_sample():
    info = parse_tdinfo_exe(NONAME_TDINFO_EXE, load_base_linear=0x10000)

    assert info is not None
    assert info.header.major_version == 2
    assert info.header.minor_version == 8
    assert info.header.symbols_count == 96
    assert "_main" in info.names
    assert any(symbol.symbol_class is TDInfoSymbolClass.STATIC for symbol in info.symbols)
    assert info.code_labels[0x10005] == "cvtfak"


@requires_noname_tdinfo
def test_load_lst_metadata_uses_tdinfo_when_present():
    project = decompile._build_project(NONAME_TDINFO_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = decompile._load_lst_metadata(NONAME_TDINFO_EXE, project)

    assert metadata is not None
    assert "turbo_debug_tdinfo" in metadata.source_format
    assert metadata.code_labels[0x10005] == "cvtfak"


@requires_life_cod
def test_extract_cod_listing_metadata_reads_life_cod_ranges():
    metadata = extract_cod_listing_metadata(LIFE_COD)

    assert metadata.code_labels[0] == "_main"
    assert metadata.proc_kinds[0] == "NEAR"
    assert metadata.code_ranges[0][1] > metadata.code_ranges[0][0]


@requires_life_binary
def test_load_lst_metadata_uses_codeview_nb00_when_sidecars_absent():
    project = decompile._build_project(LIFE_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = decompile._load_lst_metadata(LIFE_EXE, project)

    assert metadata is not None
    assert metadata.absolute_addrs is True
    assert "codeview_nb00" in metadata.source_format
    assert "cod_listing" in metadata.source_format
    assert metadata.code_labels[0x10010] == "main"
    assert 0x100C6 not in metadata.code_labels
    assert metadata.code_labels[0x100EA] == "init_life"
    assert 0x10000 not in metadata.code_labels
    assert metadata.data_labels[0x15BB0] == "_speed"


@requires_life_cod
def test_sidecar_cod_metadata_for_function_uses_sibling_cod():
    project = SimpleNamespace()
    function = SimpleNamespace(addr=0x10010, name="main")
    metadata = SimpleNamespace(
        cod_path=str(LIFE_COD),
        cod_proc_kinds={0x10010: "NEAR"},
    )

    cod_metadata = decompile._sidecar_cod_metadata_for_function(project, function, LIFE_EXE, metadata)

    assert cod_metadata is not None
    assert cod_metadata.has_source_lines(("main(argc, argv)",))


@requires_life_binary
def test_dosmz_loader_handles_life_exe_sparse_relocations():
    project = decompile._build_project(LIFE_EXE, force_blob=False, base_addr=0x1000, entry_point=0)

    assert project.arch.name == "86_16"
    assert project.entry == 0x11423
    assert project.loader.main_object.max_addr >= 0x18BE1


def test_probe_lift_break_reports_first_bad_instruction(monkeypatch):
    insns = [
        SimpleNamespace(address=0x1000, size=1, mnemonic="push", op_str="bp"),
        SimpleNamespace(address=0x1001, size=2, mnemonic="mov", op_str="bp, sp"),
        SimpleNamespace(address=0x1003, size=2, mnemonic="int", op_str="0x21"),
    ]
    project = SimpleNamespace(
        factory=SimpleNamespace(
            block=lambda addr, size, opt_level=0: (
                (_ for _ in ()).throw(ValueError("bad lift")) if addr == 0x1003 else object()
            )
        ),
    )

    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x1000, 0x1005))
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: insns)

    rendered = decompile._probe_lift_break(project, 0x1000)

    assert "first lift failure at 0x1003" in rendered
    assert "0x1003: int 0x21" in rendered


def test_try_decompile_non_optimized_slice_uses_raw_slice(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90\x90\xc3")),
    )
    function = SimpleNamespace(name="main", addr=0x1000, normalized=True, blocks=(SimpleNamespace(size=0x10),))
    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: (0x1000, 0x1003))
    monkeypatch.setattr(
        decompile,
        "_build_project_from_bytes",
        lambda *args, **kwargs: SimpleNamespace(arch=SimpleNamespace(name="86_16")),
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (SimpleNamespace(), function),
    )
    monkeypatch.setattr(
        decompile,
        "_decompile_function_with_stats",
        lambda *_args, **_kwargs: ("ok", "int main(void)\n{\n    return 0;\n}\n", 1, 3, 0.01),
    )
    monkeypatch.setattr(decompile, "_inherit_tail_validation_runtime_policy", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prepare_function_for_decompilation", lambda *_args, **_kwargs: None)

    outcome = decompile._try_decompile_non_optimized_slice(
        project,
        0x1000,
        "main",
        timeout=1,
        api_style="modern",
        binary_path=None,
        lst_metadata=None,
    )

    assert "int main" in outcome.rendered


def test_try_decompile_non_optimized_slice_returns_partial_timeout_payload(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90\x90\xc3")),
    )
    function = SimpleNamespace(name="main", addr=0x1000, normalized=True, blocks=(SimpleNamespace(size=0x10),))

    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: (0x1000, 0x1003))
    monkeypatch.setattr(
        decompile,
        "_build_project_from_bytes",
        lambda *args, **kwargs: SimpleNamespace(arch=SimpleNamespace(name="86_16")),
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (SimpleNamespace(), function),
    )
    monkeypatch.setattr(
        decompile,
        "_decompile_function_with_stats",
        lambda *_args, **_kwargs: ("timeout", "Timed out after 1s.", "int partial(void) { return 1; }", 1, 3, 0.01),
    )
    monkeypatch.setattr(decompile, "_inherit_tail_validation_runtime_policy", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prepare_function_for_decompilation", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())

    outcome = decompile._try_decompile_non_optimized_slice(
        project,
        0x1000,
        "main",
        timeout=1,
        api_style="modern",
        binary_path=None,
        lst_metadata=None,
    )

    assert outcome.rendered == "int partial(void) { return 1; }"
    assert outcome.partial_payload == "int partial(void) { return 1; }"
    assert outcome.failure_detail is not None
    assert outcome.failure_detail.startswith("shared-project slice lean: timeout: Timed out after 1s.")
    assert "stop_family=partial-timeout" in outcome.failure_detail


def test_try_decompile_non_optimized_slice_reports_failure_detail(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90\x90\xc3")),
    )
    function = SimpleNamespace(name="main", addr=0x1000, normalized=True, blocks=(SimpleNamespace(size=0x10),))

    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: (0x1000, 0x1003))
    monkeypatch.setattr(
        decompile,
        "_build_project_from_bytes",
        lambda *args, **kwargs: SimpleNamespace(arch=SimpleNamespace(name="86_16")),
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (SimpleNamespace(), function),
    )
    monkeypatch.setattr(
        decompile,
        "_decompile_function_with_stats",
        lambda *_args, **_kwargs: ("error", "slice lift broke", None, 1, 3, 0.01),
    )
    monkeypatch.setattr(decompile, "_inherit_tail_validation_runtime_policy", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prepare_function_for_decompilation", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())

    outcome = decompile._try_decompile_non_optimized_slice(
        project,
        0x1000,
        "main",
        timeout=1,
        api_style="modern",
        binary_path=None,
        lst_metadata=None,
        allow_fresh_project_retry=False,
    )

    assert outcome.rendered is None
    assert outcome.failure_detail is not None
    assert outcome.failure_detail.startswith("shared-project slice lean: error: slice lift broke")
    assert outcome.attempt_failures[0].startswith("shared-project slice lean: error: slice lift broke")


def test_try_decompile_non_optimized_slice_retries_full_recovery_after_lean_miss(monkeypatch):
    project = SimpleNamespace(
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90\x90\xc3")),
    )
    function = SimpleNamespace(name="main", addr=0x1000, normalized=True, blocks=(SimpleNamespace(size=0x10),))
    calls: list[tuple[str, bool]] = []

    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: (0x1000, 0x1003))
    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *args, **kwargs: SimpleNamespace())

    def _fake_pick_function_lean(*_args, **_kwargs):
        calls.append(("lean", False))
        raise KeyError("lean miss")

    def _fake_pick_function(_slice_project, _start, *, data_references, **_kwargs):
        calls.append(("full", data_references))
        if data_references:
            raise AssertionError("full-with-refs should not run after full-no-refs succeeds")
        return SimpleNamespace(), function

    monkeypatch.setattr(decompile, "_pick_function_lean", _fake_pick_function_lean)
    monkeypatch.setattr(decompile, "_pick_function", _fake_pick_function)
    monkeypatch.setattr(decompile, "_inherit_tail_validation_runtime_policy", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prepare_function_for_decompilation", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(
        decompile,
        "_decompile_function_with_stats",
        lambda *_args, **_kwargs: ("ok", "int recovered(void) { return 2; }", None, 1, 3, 0.01),
    )

    outcome = decompile._try_decompile_non_optimized_slice(
        project,
        0x1000,
        "main",
        timeout=3,
        api_style="modern",
        binary_path=None,
        lst_metadata=None,
        allow_fresh_project_retry=False,
    )

    assert outcome.rendered == "int recovered(void) { return 2; }"
    assert calls == [("lean", False), ("full", False)]


def test_try_decompile_non_optimized_slice_allows_short_cod_budget(monkeypatch):
    project = SimpleNamespace(
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90\x90\xc3")),
    )
    function = SimpleNamespace(name="main", addr=0x1000, normalized=True, blocks=(SimpleNamespace(size=0x10),))

    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: (0x1000, 0x1003))
    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *args, **kwargs: SimpleNamespace())
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (SimpleNamespace(), function),
    )
    monkeypatch.setattr(decompile, "_inherit_tail_validation_runtime_policy", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prepare_function_for_decompilation", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(
        decompile,
        "_decompile_function_with_stats",
        lambda *_args, **_kwargs: ("ok", "int main(void)\n{\n    return 0;\n}\n", None, 1, 3, 0.01),
    )

    outcome = decompile._try_decompile_non_optimized_slice(
        project,
        0x1000,
        "main",
        timeout=3,
        api_style="modern",
        binary_path=None,
        lst_metadata=None,
        cod_metadata=SimpleNamespace(proc_name="_main"),
    )

    assert "int main" in outcome.rendered


def test_recover_lst_function_prefers_lean_cfgfast_for_labeled_x86_16(monkeypatch):
    project = SimpleNamespace(entry=0x1E432, arch=SimpleNamespace(name="86_16"))
    metadata = LSTMetadata(data_labels={}, code_labels={}, absolute_addrs=True)
    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=0x10010, name="main")

    monkeypatch.setattr(
        decompile,
        "_infer_x86_16_linear_region",
        lambda _project, start_addr, *, window: (start_addr, start_addr + window),
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (expected_cfg, expected_func),
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("full CFGFast should not run")),
    )

    cfg, func = decompile._recover_lst_function(
        project,
        metadata,
        0x10010,
        "main",
        timeout=4,
        window=0x200,
    )

    assert cfg is expected_cfg
    assert func is expected_func
    assert func.name == "main"


def test_rank_exe_function_seeds_uses_epilog_follow_ons(monkeypatch):
    code = b"\xc3\x55\x8b\xec\x90"
    project = SimpleNamespace(
        entry=0x1000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                max_addr=0x1004,
                linked_base=0x1000,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
            )
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_linear_disassembly",
        lambda *_args, **_kwargs: [SimpleNamespace(address=0x1000, size=1, mnemonic="ret", op_str="")],
    )

    ranked = decompile._rank_exe_function_seeds(project)

    assert 0x1001 in ranked


def test_rank_exe_function_seeds_ignores_epilog_follow_ons_without_prologue(monkeypatch):
    code = b"\xc3\x90\x90\x31\xc0"
    project = SimpleNamespace(
        entry=0x1000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                max_addr=0x1004,
                linked_base=0x1000,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
            )
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_linear_disassembly",
        lambda *_args, **_kwargs: [SimpleNamespace(address=0x1000, size=1, mnemonic="ret", op_str="")],
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyError("no entry CFG")),
    )

    ranked = decompile._rank_exe_function_seeds(project)

    assert 0x1003 not in ranked


def test_fast_tracer_collects_call_and_jump_targets():
    code = bytearray(b"\x90" * 0x60)
    base = 0x1000
    callsite = base + 0x00
    call_target = base + 0x20
    rel = call_target - (callsite + 3)
    code[0:3] = b"\xe8" + int(rel).to_bytes(2, "little", signed=True)
    code[0x20:0x23] = b"\x55\x8b\xec"
    jmp_site = base + 0x03
    jmp_target = base + 0x30
    jrel = jmp_target - (jmp_site + 2)
    code[3:5] = b"\xeb" + int(jrel).to_bytes(1, "little", signed=True)
    code[0x30:0x33] = b"\x55\x8b\xec"
    project = SimpleNamespace(arch=Arch86_16())

    traced = trace_16bit_seed_candidates(project, bytes(code), linked_base=base, windows=[(base, base + len(code))])

    assert call_target in traced.call_targets
    assert jmp_target in traced.jump_targets
    assert traced.scores[call_target] > traced.scores[jmp_target]


def test_fast_tracer_keeps_direct_call_target_without_frame_prologue():
    code = bytearray(b"\x90" * 0x40)
    base = 0x1000
    call_target = base + 0x20
    rel = call_target - (base + 3)
    code[0:3] = b"\xe8" + int(rel).to_bytes(2, "little", signed=True)
    code[0x20:0x24] = b"\x59\x8b\xdc\x2b"
    project = SimpleNamespace(arch=Arch86_16())

    traced = trace_16bit_seed_candidates(project, bytes(code), linked_base=base, windows=[(base, base + len(code))])

    assert call_target in traced.call_targets


def test_fast_tracer_marks_ret_follow_on_as_weak_candidate():
    code = bytearray(b"\x90" * 0x20)
    base = 0x1000
    code[0:1] = b"\xc3"
    code[1:4] = b"\x90\x90\x90"
    code[4:7] = b"\x55\x8b\xec"
    project = SimpleNamespace(arch=Arch86_16())

    traced = trace_16bit_seed_candidates(project, bytes(code), linked_base=base, windows=[(base, base + len(code))])

    assert base in traced.returns
    assert base + 4 in traced.jump_targets


def test_fast_tracer_ignores_ret_follow_on_without_function_prologue():
    code = bytearray(b"\x90" * 0x20)
    base = 0x1000
    code[0:1] = b"\xc3"
    code[1:5] = b"\x90\x90\x90\x90"
    code[5:8] = b"\x31\xc0\x90"
    project = SimpleNamespace(arch=Arch86_16())

    traced = trace_16bit_seed_candidates(project, bytes(code), linked_base=base, windows=[(base, base + len(code))])

    assert base in traced.returns
    assert base + 5 not in traced.jump_targets


def test_rank_exe_function_seeds_respects_known_code_windows(monkeypatch):
    code = b"\x90" * 0x300
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1100: "main"},
        code_ranges={0x1100: (0x1100, 0x1120)},
        absolute_addrs=True,
    )
    project = SimpleNamespace(
        entry=0x1000,
        _inertia_lst_metadata=metadata,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                max_addr=len(code) - 1,
                linked_base=0x1000,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
                mz_segment_spans=(),
            )
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyError("no entry CFG")),
    )
    monkeypatch.setattr(decompile, "_entry_window_seed_targets", lambda *_args, **_kwargs: set())
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: [])

    ranked = decompile._rank_exe_function_seeds(project)

    assert ranked == [0x1100]


def test_rank_exe_function_seeds_excludes_signature_matched_library_labels(monkeypatch):
    code = bytearray(b"\x90" * 0x200)
    library_addr = 0x1100
    client_addr = 0x1120
    code[library_addr - 0x1000 : library_addr - 0x1000 + 3] = b"\x55\x8b\xec"
    code[client_addr - 0x1000 : client_addr - 0x1000 + 3] = b"\x55\x8b\xec"
    metadata = LSTMetadata(
        data_labels={},
        code_labels={
            library_addr: "flair_library_func",
            client_addr: "client_func",
        },
        code_ranges={
            library_addr: (library_addr, library_addr + 0x10),
            client_addr: (client_addr, client_addr + 0x10),
        },
        signature_code_addrs=frozenset({library_addr}),
        absolute_addrs=True,
        source_format="flair_pat+flair_sig",
    )
    project = SimpleNamespace(
        entry=0x1000,
        _inertia_lst_metadata=metadata,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                max_addr=len(code) - 1,
                linked_base=0x1000,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: bytes(code)),
                mz_segment_spans=(),
            )
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyError("no entry CFG")),
    )
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: [])

    ranked = decompile._rank_exe_function_seeds(project)

    assert library_addr not in ranked
    assert client_addr in ranked


def test_rank_exe_function_seeds_prioritizes_entry_window_call_targets(monkeypatch):
    code = bytearray(b"\x90" * 0x200)
    entry = 0x1080
    target = 0x1010
    helper = 0x10C0
    call_offset = entry - 0x1000
    rel = target - (entry + 3)
    helper_rel = helper - (entry + 6)
    code[call_offset : call_offset + 3] = b"\xe8" + int(rel).to_bytes(2, "little", signed=True)
    code[call_offset + 3 : call_offset + 6] = b"\xe8" + int(helper_rel).to_bytes(2, "little", signed=True)
    project = SimpleNamespace(
        entry=entry,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                max_addr=len(code) - 1,
                linked_base=0x1000,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: bytes(code)),
                mz_segment_spans=(),
            )
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyError("no entry CFG")),
    )
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: [])

    ranked = decompile._rank_exe_function_seeds(project)

    assert ranked
    assert ranked[0] == target
    assert ranked.index(target) < ranked.index(helper)


def test_rank_exe_function_seeds_uses_far_call_relocation_targets(monkeypatch):
    code = bytearray(b"\x90" * 0x240)
    entry = 0x1100
    target = 0x1180
    callsite = 0x1010
    code[callsite - 0x1000] = 0x9A
    code[callsite - 0x1000 + 1 : callsite - 0x1000 + 3] = (target & 0xF).to_bytes(2, "little")
    code[callsite - 0x1000 + 3 : callsite - 0x1000 + 5] = ((target - 0x1000) >> 4).to_bytes(2, "little")
    helper = 0x1190
    helper_rel = helper - (entry + 3)
    code[entry - 0x1000 : entry - 0x1000 + 3] = b"\xe8" + int(helper_rel).to_bytes(2, "little", signed=True)
    weak_ptr = 0x11D0
    code[0x40:0x42] = (weak_ptr & 0xF).to_bytes(2, "little")
    code[0x42:0x44] = ((weak_ptr - 0x1000) >> 4).to_bytes(2, "little")
    project = SimpleNamespace(
        entry=entry,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                max_addr=len(code) - 1,
                linked_base=0x1000,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: bytes(code)),
                mz_segment_spans=(),
                mz_relocation_entries=((0x13, 0x0), (0x42, 0x0)),
            )
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyError("no entry CFG")),
    )
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: [])

    ranked = decompile._rank_exe_function_seeds(project)

    assert target in ranked
    assert weak_ptr in ranked
    assert ranked.index(target) < ranked.index(weak_ptr)


def test_rank_exe_function_seeds_keeps_direct_call_target_without_frame_prologue(monkeypatch):
    code = bytearray(b"\x90" * 0x80)
    base = 0x1000
    target = base + 0x20
    rel = target - (base + 3)
    code[0:3] = b"\xe8" + int(rel).to_bytes(2, "little", signed=True)
    code[0x20:0x24] = b"\x59\x8b\xdc\x2b"
    project = SimpleNamespace(
        entry=base,
        arch=Arch86_16(),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                max_addr=len(code) - 1,
                linked_base=base,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: bytes(code)),
                mz_segment_spans=(),
            )
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyError("no entry CFG")),
    )
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: [])

    ranked = decompile._rank_exe_function_seeds(project)

    assert target in ranked


def test_rank_exe_function_seeds_keeps_unconfirmed_near_call_only_labels_low_priority(monkeypatch):
    code = bytearray(b"\x90" * 0x80)
    base = 0x1000
    target = base + 0x20
    rel = target - (base + 3)
    code[0:3] = b"\xe8" + int(rel).to_bytes(2, "little", signed=True)
    code[0x20:0x24] = b"\x59\x8b\xdc\x2b"
    project = SimpleNamespace(
        entry=base,
        arch=Arch86_16(),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                max_addr=len(code) - 1,
                linked_base=base,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: bytes(code)),
                mz_segment_spans=(),
            )
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyError("no entry CFG")),
    )
    monkeypatch.setattr(decompile, "_entry_window_seed_targets", lambda *_args, **_kwargs: set())
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "trace_16bit_seed_candidates",
        lambda *_args, **_kwargs: SimpleNamespace(call_targets=set(), jump_targets=set(), returns=set(), scores={}),
    )

    ranked = decompile._rank_exe_function_seeds(project)

    assert target in ranked


def test_rank_exe_function_seeds_uses_recovery_labels_when_visible_catalog_is_empty(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    code = b"\x90" * 0x200
    binary.write_bytes(code)
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1100: "sig_func"},
        code_ranges={0x1100: (0x1100, 0x1120)},
        signature_code_addrs=frozenset({0x1100}),
        absolute_addrs=True,
        source_format="flair_pat+flair_sig",
    )
    project = SimpleNamespace(
        entry=0x1000,
        _inertia_lst_metadata=metadata,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=binary,
                linked_base=0x1000,
                max_addr=len(code) - 1,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
            )
        ),
    )
    monkeypatch.setattr(decompile, "_seed_scan_windows", lambda _project, **_kwargs: [(0x1100, 0x1120)])
    monkeypatch.setattr(decompile, "_entry_window_seed_targets", lambda *_args, **_kwargs: set())
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyError("no entry CFG")),
    )
    recovery_calls = {"count": 0}

    def _counting_recovery_labels(meta):
        recovery_calls["count"] += 1
        return sidecar_metadata._recovery_code_labels(meta)

    monkeypatch.setattr(decompile, "_recovery_code_labels", _counting_recovery_labels)

    ranked = decompile._rank_exe_function_seeds(project)

    assert sidecar_metadata._visible_code_labels(metadata) == {}
    assert sidecar_metadata._recovery_code_labels(metadata) == {0x1100: "sig_func"}
    assert recovery_calls["count"] == 1
    assert ranked == []


def test_discover_ranked_binary_offsets_auto_merges_conservative_rizin_seeds(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    code = b"\x90" * 0x200
    binary.write_bytes(code)
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=binary,
                linked_base=0x1000,
                max_addr=len(code) - 1,
            )
        ),
    )
    args = SimpleNamespace(
        binary=binary,
        include_library_functions=False,
        function_discovery_backend="auto",
        seed_engine="auto",
        rizin_timeout=1,
    )

    monkeypatch.setattr(
        cli_core,
        "collect_rizin_evidence",
        lambda *_args, **_kwargs: RizinEvidence(
            status=RizinEvidenceStatus.OK,
            elapsed_ms=0.1,
            detail="ok",
            functions=(
                RizinFunctionFact(
                    addr=0x1200,
                    size=4,
                    name="probe",
                    n_blocks=2,
                    n_callrefs=0,
                ),
            ),
            xrefs=(),
            strings=(),
            symbols=(),
            stack_vars=(),
            calling_conventions=(),
        ),
    )
    monkeypatch.setattr(
        cli_core,
        "discover_rizin_function_entries",
        lambda *_args, **_kwargs: RizinDiscoveryResult(
            RizinDiscoveryStatus.OK,
            (0x1200,),
            0.2,
            "ok",
        ),
    )
    rank_calls = {"count": 0}
    monkeypatch.setattr(
        cli_core,
        "_rank_exe_function_seeds",
        lambda *_args, **_kwargs: rank_calls.__setitem__("count", rank_calls["count"] + 1) or [0x9000],
    )

    result = cli_core._discover_ranked_binary_offsets(project, args=args)

    assert result == [0x9000, 0x1200]
    assert rank_calls["count"] == 1


def test_discover_ranked_binary_offsets_auto_falls_back_to_angr_when_rizin_unavailable(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    code = b"\x90" * 0x200
    binary.write_bytes(code)
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=binary,
                linked_base=0x1000,
                max_addr=len(code) - 1,
            )
        ),
    )
    args = SimpleNamespace(
        binary=binary,
        include_library_functions=False,
        function_discovery_backend="auto",
        seed_engine="auto",
        rizin_timeout=1,
    )

    monkeypatch.setattr(
        cli_core,
        "collect_rizin_evidence",
        lambda *_args, **_kwargs: RizinEvidence(
            status=RizinEvidenceStatus.UNAVAILABLE,
            elapsed_ms=0.1,
            detail="unavailable",
            functions=(),
            xrefs=(),
            strings=(),
            symbols=(),
            stack_vars=(),
            calling_conventions=(),
        ),
    )
    monkeypatch.setattr(
        cli_core,
        "discover_rizin_function_entries",
        lambda *_args, **_kwargs: RizinDiscoveryResult(
            RizinDiscoveryStatus.UNAVAILABLE,
            (),
            0.1,
            "unavailable",
        ),
    )
    rank_calls = {"count": 0}
    monkeypatch.setattr(
        cli_core,
        "_rank_exe_function_seeds",
        lambda *_args, **_kwargs: rank_calls.__setitem__("count", rank_calls["count"] + 1) or [0x2000],
    )

    result = cli_core._discover_ranked_binary_offsets(project, args=args)

    assert result == [0x2000]
    assert rank_calls["count"] == 1


def test_rank_exe_function_seeds_prefers_bounded_metadata_spans_over_tiny_entry_targets(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    code = b"\x90" * 0x200
    binary.write_bytes(code)
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1100: "sig_func"},
        code_ranges={0x1100: (0x1100, 0x1140)},
        signature_code_addrs=frozenset(),
        absolute_addrs=True,
        source_format="flair_pat+flair_sig",
    )
    project = SimpleNamespace(
        entry=0x1000,
        _inertia_lst_metadata=metadata,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=binary,
                linked_base=0x1000,
                max_addr=len(code) - 1,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
            )
        ),
    )
    monkeypatch.setattr(decompile, "_seed_scan_windows", lambda _project, **_kwargs: [(0x1000, 0x1200)])
    monkeypatch.setattr(decompile, "_entry_window_seed_targets", lambda *_args, **_kwargs: {0x1010})
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyError("no entry CFG")),
    )

    ranked = decompile._rank_exe_function_seeds(project)

    assert ranked.index(0x1100) < ranked.index(0x1010)


def test_recover_seeded_exe_functions_reuses_existing_project_before_rebuild(monkeypatch):
    code = b"\x55\x8b\xec" + b"\x90" * 0x20
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=0x1000,
                max_addr=len(code) - 1,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
            )
        ),
        factory=SimpleNamespace(
            block=lambda addr, **_kwargs: SimpleNamespace(
                capstone=SimpleNamespace(insns=[SimpleNamespace(address=addr)])
            )
        ),
    )
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project, **_kwargs: [0x1003])
    rebuilds: list[Path] = []
    monkeypatch.setattr(
        decompile,
        "_build_project",
        lambda path, **_kwargs: (
            rebuilds.append(path) or (_ for _ in ()).throw(AssertionError("seed recovery should not rebuild"))
        ),
    )
    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=0x1003, name="sub_1003", is_plt=False, is_simprocedure=False)
    monkeypatch.setattr(decompile, "_pick_function_lean", lambda *_args, **_kwargs: (expected_cfg, expected_func))

    recovered = decompile._recover_seeded_exe_functions(project, timeout=4, limit=1)

    assert recovered == [(expected_cfg, expected_func)]
    assert rebuilds == []


def test_recover_seeded_exe_functions_keeps_ranked_seeds_ahead_of_neighbor_follow_ons(monkeypatch):
    code = b"\x55\x8b\xec" + b"\x90" * 0x40
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=0x1000,
                max_addr=len(code) - 1,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
            )
        ),
        factory=SimpleNamespace(
            block=lambda addr, **_kwargs: SimpleNamespace(
                capstone=SimpleNamespace(insns=[SimpleNamespace(address=addr)])
            )
        ),
    )
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project, **_kwargs: [0x1010, 0x1200])
    monkeypatch.setattr(decompile, "_load_cache_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_store_cache_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", lambda fn, *, timeout: fn())
    recovered_order: list[int] = []

    def _fake_pick(_project, addr, **_kwargs):
        recovered_order.append(addr)
        return SimpleNamespace(), SimpleNamespace(addr=addr, name=f"sub_{addr:x}", is_plt=False, is_simprocedure=False)

    monkeypatch.setattr(decompile, "_pick_function_lean", _fake_pick)
    monkeypatch.setattr(
        decompile,
        "collect_neighbor_call_targets",
        lambda function: [SimpleNamespace(target_addr=0x1030)] if function.addr == 0x1010 else [],
    )

    recovered = decompile._recover_seeded_exe_functions(project, timeout=4, limit=3)

    assert [func.addr for _cfg, func in recovered] == [0x1010, 0x1200, 0x1030]
    assert recovered_order[:3] == [0x1010, 0x1200, 0x1030]


def test_recover_seeded_exe_functions_includes_prologue_scan_candidates(monkeypatch):
    code = bytearray(b"\x90" * 0x400)
    base = 0x1000
    prologue_addr = 0x1110
    seed_addr = 0x1200
    code[prologue_addr - base : prologue_addr - base + 3] = b"\x55\x8b\xec"

    def _load(addr, size, **_kwargs):
        if addr == 0:
            return bytes(code[:size])
        return bytes(code[addr - base : addr - base + size])

    project = SimpleNamespace(
        entry=0x1100,
        arch=SimpleNamespace(name="86_16", capstone=Arch86_16().capstone),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=base,
                max_addr=len(code) - 1,
                memory=SimpleNamespace(load=_load),
            )
        ),
        factory=SimpleNamespace(
            block=lambda addr, size=16, **_kwargs: SimpleNamespace(
                capstone=SimpleNamespace(
                    insns=list(project.arch.capstone.disasm(bytes(code[addr - base : addr - base + size]), addr))
                )
            )
        ),
    )
    recovered_order: list[int] = []
    monkeypatch.setattr(decompile, "_load_cache_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_store_cache_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", lambda fn, *, timeout: fn())
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project, **_kwargs: [seed_addr])
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda _project, addr, **_kwargs: (
            recovered_order.append(addr) or SimpleNamespace(),
            SimpleNamespace(addr=addr, name=f"sub_{addr:x}", is_plt=False, is_simprocedure=False),
        ),
    )
    monkeypatch.setattr(decompile, "collect_neighbor_call_targets", lambda _function: [])

    recovered = decompile._recover_seeded_exe_functions(project, timeout=4, limit=2)

    assert [func.addr for _cfg, func in recovered] == [prologue_addr, seed_addr]
    assert recovered_order[0] == prologue_addr
    assert seed_addr in recovered_order


def test_recover_seeded_exe_functions_scans_tiny_entry_body_for_direct_calls(monkeypatch):
    code = bytearray(b"\x90" * 0x400)
    base = 0x1000
    func_addr = 0x1010
    target_addr = 0x1030
    branch_addr = 0x1018
    rel = target_addr - (func_addr + 4 + 3)
    code[func_addr - base : func_addr - base + 4] = b"\x55\x8b\xec\x90"
    code[func_addr - base + 4 : func_addr - base + 7] = b"\xe8" + int(rel).to_bytes(2, "little", signed=True)
    jmp_rel = branch_addr - (func_addr + 7 + 2)
    code[func_addr - base + 7 : func_addr - base + 9] = b"\xeb" + int(jmp_rel).to_bytes(1, "little", signed=True)
    code[func_addr - base + 9] = 0xC3
    project = SimpleNamespace(
        entry=0x1100,
        arch=SimpleNamespace(name="86_16", capstone=Arch86_16().capstone),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=base,
                max_addr=len(code) - 1,
                memory=SimpleNamespace(
                    load=lambda addr, size, **_kwargs: bytes(code[addr - base : addr - base + size])
                ),
            ),
            memory=SimpleNamespace(load=lambda addr, size, **_kwargs: bytes(code[addr - base : addr - base + size])),
        ),
        factory=SimpleNamespace(
            block=lambda addr, **_kwargs: SimpleNamespace(
                capstone=SimpleNamespace(insns=[SimpleNamespace(address=addr)])
            )
        ),
    )
    monkeypatch.setattr(decompile, "_load_cache_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_store_cache_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project, **_kwargs: [func_addr, 0x1200])
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda _project, addr, **_kwargs: (
            SimpleNamespace(),
            SimpleNamespace(
                addr=addr,
                name=f"sub_{addr:x}",
                is_plt=False,
                is_simprocedure=False,
                blocks=(SimpleNamespace(size=0x10),),
            ),
        ),
    )
    monkeypatch.setattr(decompile, "collect_neighbor_call_targets", lambda _function: [])

    recovered = decompile._recover_seeded_exe_functions(project, timeout=4, limit=3)

    assert [func.addr for _cfg, func in recovered] == [func_addr, 0x1200, target_addr]


def test_rank_gap_scan_candidate_addrs_rejects_out_of_image_candidates():
    code = bytearray(b"\x90" * 0x80)
    base = 0x1000
    prologue_addr = 0x1020
    call_addr = 0x1010
    out_of_image_target = 0x2000
    rel = out_of_image_target - (call_addr + 3)
    code[prologue_addr - base : prologue_addr - base + 3] = b"\x55\x8b\xec"
    code[call_addr - base : call_addr - base + 3] = b"\xe8" + int(rel).to_bytes(2, "little", signed=True)

    class _Memory:
        def load(self, offset, size):
            return bytes(code[offset : offset + size])

    class _AbsMemory:
        def load(self, addr, size, **_kwargs):
            return bytes(code[addr - base : addr - base + size])

    project = SimpleNamespace(
        entry=0x1010,
        arch=SimpleNamespace(name="86_16", capstone=Arch86_16().capstone),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(max_addr=len(code) - 1, linked_base=base, memory=_Memory()),
            memory=_AbsMemory(),
        ),
        factory=SimpleNamespace(
            block=lambda addr, **_kwargs: SimpleNamespace(
                capstone=SimpleNamespace(
                    insns=[
                        SimpleNamespace(mnemonic="push", op_str="bp"),
                        SimpleNamespace(mnemonic="mov", op_str="bp, sp"),
                    ]
                )
            )
        ),
    )
    recovered = [
        (
            SimpleNamespace(),
            SimpleNamespace(
                addr=0x1010,
                blocks=(SimpleNamespace(addr=call_addr, size=3),),
            ),
        )
    ]

    ranked = decompile._rank_gap_scan_candidate_addrs(
        project,
        recovered,
        covered_ranges=[(0x1008, 0x100C)],
        existing_addrs={0x1008},
        image_end=base + len(code),
    )

    assert prologue_addr in ranked
    assert out_of_image_target not in ranked


def test_recover_seeded_exe_functions_queues_gap_candidates_before_wrapper_follow_ons(monkeypatch):
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=0x10000,
                max_addr=0x600,
            )
        ),
    )
    recovered_order: list[int] = []

    monkeypatch.setattr(decompile, "_load_cache_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_store_cache_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project, **_kwargs: [0x10010])
    monkeypatch.setattr(decompile, "_rank_prologue_scan_candidate_addrs", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_rank_gap_scan_candidate_addrs", lambda *_args, **_kwargs: [0x10050])

    def _fake_recover(_project, *, candidate_addr, **_kwargs):
        recovered_order.append(candidate_addr)
        if candidate_addr == 0x10010:
            func = SimpleNamespace(
                addr=candidate_addr,
                name=f"sub_{candidate_addr:x}",
                is_plt=False,
                is_simprocedure=False,
                info={"x86_16_recovery_truncated": True},
                blocks=(SimpleNamespace(addr=candidate_addr, size=0x18),),
            )
        elif candidate_addr == 0x10050:
            func = SimpleNamespace(
                addr=candidate_addr,
                name=f"sub_{candidate_addr:x}",
                is_plt=False,
                is_simprocedure=False,
                blocks=(SimpleNamespace(addr=candidate_addr, size=0x40),),
            )
        else:
            func = SimpleNamespace(
                addr=candidate_addr,
                name=f"sub_{candidate_addr:x}",
                is_plt=False,
                is_simprocedure=False,
                blocks=(SimpleNamespace(addr=candidate_addr, size=0x10),),
            )
        return SimpleNamespace(), func

    monkeypatch.setattr(decompile, "_recover_candidate_with_timeout", _fake_recover)
    monkeypatch.setattr(
        decompile,
        "collect_neighbor_call_targets",
        lambda function: [SimpleNamespace(target_addr=0x100A0)] if function.addr == 0x10010 else [],
    )
    monkeypatch.setattr(decompile, "_linear_function_seed_targets", lambda *_args, **_kwargs: set())

    recovered = decompile._recover_seeded_exe_functions(project, timeout=4, limit=3)

    assert [func.addr for _cfg, func in recovered] == [0x10010, 0x10050, 0x100A0]
    assert recovered_order[:3] == [0x10010, 0x10050, 0x100A0]


def test_recover_candidate_function_pair_prefers_richer_bounded_body_recovery(monkeypatch):
    candidate_addr = 0x1000
    candidate_project = SimpleNamespace(
        factory=SimpleNamespace(
            block=lambda addr, **_kwargs: SimpleNamespace(
                capstone=SimpleNamespace(insns=[SimpleNamespace(address=addr)])
            )
        )
    )
    narrow_region = (candidate_addr, candidate_addr + 0x20)
    wide_region = (candidate_addr, candidate_addr + 0x100)

    def _function(addr, sizes):
        return SimpleNamespace(
            addr=addr,
            blocks=tuple(SimpleNamespace(size=size) for size in sizes),
            is_plt=False,
            is_simprocedure=False,
        )

    monkeypatch.setattr(
        decompile, "_candidate_recovery_regions", lambda *_args, **_kwargs: [narrow_region, wide_region]
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda _project, _addr, *, regions, **_kwargs: (
            SimpleNamespace(region=regions[0]),
            _function(candidate_addr, (8, 8, 8, 8))
            if regions[0] == narrow_region
            else _function(candidate_addr, (0x18, 0x18, 0x18, 0x18, 0x18)),
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected richer fallback")),
    )

    recovered_cfg, recovered_function = decompile._recover_candidate_function_pair(
        candidate_project,
        candidate_addr=candidate_addr,
        image_end=0x2000,
        metadata=None,
        project_entry=0x1100,
        region_span=0x120,
    )

    assert recovered_cfg.region == wide_region
    assert decompile._function_recovery_score(recovered_function) == (5, 0x78)


def test_recover_candidate_function_pair_retries_richer_bounded_region_when_exact_region_truncates(monkeypatch):
    candidate_addr = 0x1000
    candidate_project = SimpleNamespace(
        factory=SimpleNamespace(
            block=lambda addr, **_kwargs: SimpleNamespace(
                capstone=SimpleNamespace(insns=[SimpleNamespace(address=addr)])
            )
        )
    )
    exact_region = (candidate_addr, candidate_addr + 0x100)
    bounded_region = (candidate_addr, candidate_addr + 0x180)

    def _function(addr, sizes):
        return SimpleNamespace(
            addr=addr,
            blocks=tuple(SimpleNamespace(size=size) for size in sizes),
            is_plt=False,
            is_simprocedure=False,
            info={},
        )

    monkeypatch.setattr(
        decompile,
        "_candidate_recovery_regions",
        lambda metadata, *_args, **_kwargs: [exact_region] if metadata is not None else [bounded_region],
    )
    monkeypatch.setattr(decompile, "_lst_code_region", lambda _metadata, _addr: exact_region)
    monkeypatch.setattr(
        decompile,
        "_richest_bounded_recovery_region",
        lambda _addr, *, image_end, region_span: bounded_region if image_end and region_span else bounded_region,  # noqa: RUF034
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda _project, _addr, *, regions, **_kwargs: (
            SimpleNamespace(region=regions[0]),
            _function(candidate_addr, (8, 8)),
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function",
        lambda _project, _addr, *, regions, **_kwargs: (
            (
                SimpleNamespace(region=regions[0]),
                _function(candidate_addr, (0x18, 0x18, 0x18, 0x18, 0x18)),
            )
            if regions[0] == bounded_region
            else (_ for _ in ()).throw(AssertionError("unexpected exact-region fallback"))
        ),
    )

    recovered_cfg, recovered_function = decompile._recover_candidate_function_pair(
        candidate_project,
        candidate_addr=candidate_addr,
        image_end=0x2000,
        metadata=SimpleNamespace(),
        project_entry=0x1100,
        region_span=0x120,
    )

    assert recovered_cfg.region == bounded_region
    assert decompile._function_recovery_score(recovered_function) == (5, 0x78)
    assert recovered_function.info["x86_16_recovery_truncated"] is False


def test_recover_candidate_function_pair_keeps_explicit_exact_region_when_truncated(monkeypatch):
    candidate_addr = 0x1000
    exact_region = (candidate_addr, candidate_addr + 0xBB)
    candidate_project = SimpleNamespace(
        factory=SimpleNamespace(
            block=lambda addr, **_kwargs: SimpleNamespace(
                capstone=SimpleNamespace(insns=[SimpleNamespace(address=addr)])
            )
        )
    )

    def _function(sizes):
        return SimpleNamespace(
            addr=candidate_addr,
            blocks=tuple(SimpleNamespace(size=size) for size in sizes),
            is_plt=False,
            is_simprocedure=False,
            info={},
        )

    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda _project, _addr, *, regions, **_kwargs: (
            SimpleNamespace(region=regions[0]),
            _function((8, 8)),
        ),
    )
    stitch_calls = []

    def _stitch(_project, function, region):
        stitch_calls.append(region)
        return function, False

    monkeypatch.setattr(decompile, "_stitch_x86_16_exact_function_8616", _stitch)
    observed_regions = []

    def _pick_function(_project, _addr, *, regions, **_kwargs):
        observed_regions.append(regions[0])
        return SimpleNamespace(region=regions[0]), _function((0x18, 0x18, 0x18))

    monkeypatch.setattr(decompile, "_pick_function", _pick_function)
    monkeypatch.setattr(
        decompile,
        "_richest_bounded_recovery_region",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("explicit region must not broaden")),
    )
    repaired_regions = []

    def _repair_graph(_project, _function, *, exact_region=None):
        repaired_regions.append(exact_region)

    monkeypatch.setattr(decompile, "_repair_x86_16_function_graph_8616", _repair_graph)

    recovered_cfg, _recovered_function = decompile._recover_candidate_function_pair(
        candidate_project,
        candidate_addr=candidate_addr,
        image_end=0x2000,
        metadata=None,
        project_entry=0x1100,
        region_span=0x200,
        exact_region=exact_region,
    )

    assert recovered_cfg.region == exact_region
    assert observed_regions == [exact_region, exact_region]
    assert stitch_calls == [exact_region, exact_region]
    assert repaired_regions == [exact_region]


def test_stitched_exact_region_replaces_function_with_escaping_block():
    function = SimpleNamespace(
        blocks=(SimpleNamespace(addr=0x1000, size=0x120, bytes=b"x" * 0x120),),
    )
    reachable = {
        0x1000: SimpleNamespace(addr=0x1000, size=0x20, bytes=b"x" * 0x20),
        0x1020: SimpleNamespace(addr=0x1020, size=0x20, bytes=b"x" * 0x20),
    }

    assert decompile._should_replace_function_with_stitched_graph_8616(
        function,
        reachable,
        (0x1000, 0x10BB),
    )


def test_cap_stitched_blocks_respects_exact_region_end():
    requested_sizes = []

    def _block(addr, *, size, opt_level):
        requested_sizes.append((addr, size, opt_level))
        return SimpleNamespace(addr=addr, size=size, bytes=b"x" * size)

    project = SimpleNamespace(factory=SimpleNamespace(block=_block))
    reachable = {
        0x1000: SimpleNamespace(addr=0x1000, size=0x10, bytes=b"x" * 0x10),
        0x10B5: SimpleNamespace(addr=0x10B5, size=0x50, bytes=b"x" * 0x50),
    }

    capped = decompile._cap_stitched_blocks_to_leaders_8616(
        project,
        reachable,
        region_end=0x10BB,
    )

    assert capped[0x1000] is reachable[0x1000]
    assert capped[0x10B5].size == 6
    assert requested_sizes == [(0x10B5, 6, 0)]


def test_rank_function_cfg_pairs_for_display_prefers_body_seed_and_its_callees(monkeypatch):
    project = SimpleNamespace(entry=0x11423)
    pairs = [
        (SimpleNamespace(), SimpleNamespace(addr=0x11423, name="_start")),
        (SimpleNamespace(), SimpleNamespace(addr=0x114CD, name="runtime_init")),
        (SimpleNamespace(), SimpleNamespace(addr=0x10010, name="sub_10010")),
        (SimpleNamespace(), SimpleNamespace(addr=0x101A3, name="sub_101a3")),
    ]
    monkeypatch.setattr(
        decompile,
        "_linear_function_seed_targets",
        lambda _project, addr, **_kwargs: (
            {0x114CD, 0x10010} if addr == 0x11423 else {0x101A3} if addr == 0x10010 else set()
        ),
    )

    ranked = decompile._rank_function_cfg_pairs_for_display(project, pairs)

    assert [function.addr for _cfg, function in ranked] == [0x11423, 0x10010, 0x101A3, 0x114CD]


def test_rank_function_cfg_pairs_for_display_demotes_tiny_wrapper_like_entry_targets(monkeypatch):
    project = SimpleNamespace(entry=0x11423)
    pairs = [
        (SimpleNamespace(), SimpleNamespace(addr=0x11423, name="_start", blocks=(SimpleNamespace(size=0x16),))),
        (SimpleNamespace(), SimpleNamespace(addr=0x10010, name="sub_10010", blocks=(SimpleNamespace(size=0x14),))),
        (
            SimpleNamespace(),
            SimpleNamespace(
                addr=0x1157C, name="tiny_wrapper", blocks=(SimpleNamespace(size=0x08), SimpleNamespace(size=0x08))
            ),
        ),
        (
            SimpleNamespace(),
            SimpleNamespace(
                addr=0x1223B,
                name="bigger_body",
                blocks=(SimpleNamespace(size=0x20), SimpleNamespace(size=0x20), SimpleNamespace(size=0x20)),
            ),
        ),
    ]
    monkeypatch.setattr(
        decompile,
        "_linear_function_seed_targets",
        lambda _project, addr, **_kwargs: {0x114CD, 0x10010, 0x1157C, 0x1223B} if addr == 0x11423 else set(),
    )

    ranked = decompile._rank_function_cfg_pairs_for_display(project, pairs)

    assert [function.addr for _cfg, function in ranked] == [0x11423, 0x10010, 0x1223B, 0x1157C]


def test_rank_function_cfg_pairs_for_display_prefers_large_pre_entry_body_when_complexity_needs_recovery_fallback(
    monkeypatch,
):
    project = SimpleNamespace(entry=0x11423)
    entry = (
        SimpleNamespace(),
        SimpleNamespace(addr=0x11423, name="_start", project=project, blocks=(SimpleNamespace(size=0x20),)),
    )
    body = (
        SimpleNamespace(),
        SimpleNamespace(addr=0x10010, name="sub_10010", project=project, blocks=(SimpleNamespace(size=0x50),)),
    )
    runtime_shell = (
        SimpleNamespace(),
        SimpleNamespace(addr=0x11440, name="runtime_shell", project=project, blocks=(SimpleNamespace(size=0x10),)),
    )

    monkeypatch.setattr(
        decompile,
        "_linear_function_seed_targets",
        lambda _project, addr, **_kwargs: {0x11440} if addr == 0x11423 else set(),
    )

    ranked = decompile._rank_function_cfg_pairs_for_display(project, [runtime_shell, body, entry])

    assert [function.addr for _cfg, function in ranked[:3]] == [0x11423, 0x10010, 0x11440]


def test_function_attempt_status_reports_uncollected_when_tail_validation_disabled(capsys):
    function = SimpleNamespace(
        addr=0x10010,
        name="sub_10010",
        project=SimpleNamespace(_inertia_tail_validation_enabled=False),
    )

    decompile._print_function_attempt_status(
        function,
        attempt="decompiled",
        validation_snapshot=None,
    )

    captured = capsys.readouterr()
    assert "attempt=decompiled validation=uncollected" in captured.err
    assert captured.out == ""


def test_function_attempt_status_reports_failed_for_changed_tail_validation(capsys):
    function = SimpleNamespace(
        addr=0x10010,
        name="sub_10010",
        project=SimpleNamespace(_inertia_tail_validation_enabled=True),
    )

    decompile._print_function_attempt_status(
        function,
        attempt="decompiled",
        validation_snapshot={
            "structuring": {"changed": False, "status": "stable"},
            "postprocess": {"changed": True, "status": "changed"},
        },
    )

    captured = capsys.readouterr()
    assert "attempt=decompiled validation=failed" in captured.err
    assert captured.out == ""


def test_emit_function_result_does_not_fabricate_passed_tail_validation_when_disabled(
    monkeypatch, tmp_path, capsys
):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_tail_validation_enabled=False,
    )
    function = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)
    item = decompile.FunctionWorkItem(index=1, function_cfg=SimpleNamespace(), function=function)
    result = decompile.FunctionWorkResult(
        index=item.index,
        status="ok",
        payload="int sub_10010(void) { return 0; }",
        debug_output="",
        function=function,
        function_cfg=item.function_cfg,
        tail_validation={},
    )
    args = SimpleNamespace(
        addr=None,
        show_asm=False,
        binary=tmp_path / "sample.exe",
        alternate_source_c=False,
        output_c_dir=None,
    )
    checked_payloads = []

    def _accept_recompilation(payload):
        checked_payloads.append(payload)
        return [("portable-flat", payload), ("msc-dos", payload)], None

    monkeypatch.setattr(decompile, "_collect_recompilation_payloads_8616", _accept_recompilation)

    decompiled, failed = decompile._emit_function_result(
        item,
        result,
        project=project,
        args=args,
        lst_metadata=None,
        cod_metadata=None,
        synthetic_globals=None,
        precise_sidecar_regions=False,
        allow_heavy_fallbacks=False,
        interactive_stdout=False,
        use_serial_fork_per_function=False,
        fallback_tail_validation_by_index={},
    )

    out = capsys.readouterr().out
    assert (decompiled, failed) == (1, 0)
    assert "failure family: status=ok" in out
    assert "validation=uncollected" in out
    assert "validation=passed" not in out
    assert checked_payloads


def test_emit_function_result_rejects_raw_segmented_access_even_with_stable_tail(
    monkeypatch, tmp_path, capsys
):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_tail_validation_enabled=True,
    )
    function = SimpleNamespace(addr=0x10CD4, name="QuickSort", project=project)
    item = decompile.FunctionWorkItem(index=1, function_cfg=SimpleNamespace(), function=function)
    result = decompile.FunctionWorkResult(
        index=item.index,
        status="ok",
        payload="void QuickSort(void)\n{\n    return SEG_U16(ds, 42);\n}\n",
        debug_output="",
        function=function,
        function_cfg=item.function_cfg,
        tail_validation={
            "structuring": {"changed": False, "status": "stable"},
            "postprocess": {"changed": False, "status": "stable"},
        },
    )
    args = SimpleNamespace(
        addr=None,
        show_asm=False,
        binary=tmp_path / "SORTDEMO.EXE",
        alternate_source_c=True,
        max_functions=8,
        timeout=20,
        api_style="default",
    )
    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x10CD4, 0x10CE0))
    monkeypatch.setattr(decompile, "_format_asm_range", lambda *_args, **_kwargs: "asm fallback")
    monkeypatch.setattr(decompile, "_probe_lift_break", lambda *_args, **_kwargs: "lift probe")
    monkeypatch.setattr(
        decompile,
        "_collect_recompilation_payloads_8616",
        lambda payload: ([("portable-flat", payload), ("msc-dos", payload)], None),
    )

    decompiled, failed = decompile._emit_function_result(
        item,
        result,
        project=project,
        args=args,
        lst_metadata=None,
        cod_metadata=None,
        synthetic_globals=None,
        precise_sidecar_regions=False,
        allow_heavy_fallbacks=False,
        interactive_stdout=False,
        use_serial_fork_per_function=False,
        fallback_tail_validation_by_index={},
    )

    captured = capsys.readouterr()
    assert (decompiled, failed) == (0, 1)
    assert "/* -- c -- */" not in captured.out
    assert "/* -- asm fallback -- */" in captured.out
    assert "raw-ds-segmented-access" in captured.err
    assert "raw-ds-segmented-access" not in captured.out


def test_emit_function_result_rejects_compiler_failed_ok_payload(monkeypatch, tmp_path, capsys):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_tail_validation_enabled=True,
    )
    function = SimpleNamespace(addr=0x10CE0, name="DrawFrame", project=project)
    item = decompile.FunctionWorkItem(index=1, function_cfg=SimpleNamespace(), function=function)
    result = decompile.FunctionWorkResult(
        index=item.index,
        status="ok",
        payload="void DrawFrame(void)\n{\n    target = source;\n}\n",
        debug_output="",
        function=function,
        function_cfg=item.function_cfg,
        tail_validation={
            "structuring": {"changed": False, "status": "stable"},
            "postprocess": {"changed": False, "status": "stable"},
        },
    )
    args = SimpleNamespace(
        addr=None,
        show_asm=False,
        binary=tmp_path / "sample.exe",
        alternate_source_c=False,
        max_functions=8,
        timeout=20,
        api_style="default",
    )
    monkeypatch.setattr(
        decompile,
        "_collect_recompilation_payloads_8616",
        lambda _payload: ([], "gcc portable-flat syntax check failed: undeclared target"),
    )
    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x10CE0, 0x10D00))
    monkeypatch.setattr(decompile, "_format_asm_range", lambda *_args, **_kwargs: "mov ax, ax")
    monkeypatch.setattr(decompile, "_probe_lift_break", lambda *_args, **_kwargs: "lift probe")

    result_state = {item.index: result}
    decompiled, failed = decompile._emit_function_result(
        item,
        result,
        project=project,
        args=args,
        lst_metadata=None,
        cod_metadata=None,
        synthetic_globals=None,
        precise_sidecar_regions=False,
        allow_heavy_fallbacks=False,
        interactive_stdout=False,
        use_serial_fork_per_function=False,
        fallback_tail_validation_by_index={},
        result_state_by_index=result_state,
    )

    out = capsys.readouterr().out
    assert (decompiled, failed) == (0, 1)
    assert "/* -- c -- */" not in out
    assert "/* -- asm fallback -- */" in out
    assert "validation_failed" in out
    assert result_state[item.index].status == "validation_failed"
    assert result_state[item.index].validated_payload_hash is None


@pytest.mark.parametrize(
    ("attempted", "decompiled", "failed", "total_shown", "expected"),
    [
        (20, 20, 0, 20, 0),
        (20, 19, 1, 20, 2),
        (19, 19, 0, 20, 2),
        (0, 0, 0, 0, 2),
    ],
)
def test_batch_exit_code_requires_complete_clean_acceptance(
    attempted, decompiled, failed, total_shown, expected
):
    assert (
        decompile._batch_exit_code_8616(
            attempted=attempted,
            decompiled=decompiled,
            failed=failed,
            total_shown=total_shown,
        )
        == expected
    )


def test_emit_function_result_does_not_reprint_validation_failed_ok_payload(monkeypatch, tmp_path, capsys):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_tail_validation_enabled=True,
    )
    function = SimpleNamespace(addr=0x10CE0, name="QuickSort", project=project)
    item = decompile.FunctionWorkItem(index=1, function_cfg=SimpleNamespace(), function=function)
    result = decompile.FunctionWorkResult(
        index=item.index,
        status="ok",
        payload="unsigned short QuickSort(int iLow, int iHigh)\n{\n    return QuickSort(iLow, local_6);\n}\n",
        debug_output="",
        function=function,
        function_cfg=item.function_cfg,
        tail_validation={
            "structuring": {
                "changed": True,
                "status": "changed",
                "verdict": "structuring whole-tail validation changed",
            },
            "postprocess": {"changed": False, "status": "stable"},
        },
    )
    args = SimpleNamespace(
        addr=None,
        show_asm=False,
        binary=tmp_path / "sample.exe",
        alternate_source_c=False,
        max_functions=8,
        timeout=20,
        api_style="default",
    )
    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x10CE0, 0x10D00))
    monkeypatch.setattr(decompile, "_format_asm_range", lambda *_args, **_kwargs: "mov ax, ax")
    monkeypatch.setattr(decompile, "_probe_lift_break", lambda *_args, **_kwargs: "lift probe")

    decompiled, failed = decompile._emit_function_result(
        item,
        result,
        project=project,
        args=args,
        lst_metadata=None,
        cod_metadata=None,
        synthetic_globals=None,
        precise_sidecar_regions=False,
        allow_heavy_fallbacks=False,
        interactive_stdout=False,
        use_serial_fork_per_function=False,
        fallback_tail_validation_by_index={},
    )

    captured = capsys.readouterr()
    out = captured.out
    assert (decompiled, failed) == (0, 1)
    assert "failure family: status=validation_failed" in out
    assert "/* -- ok -- */" not in out
    assert "return QuickSort(iLow, local_6);" not in out
    assert "/* -- asm fallback -- */" in out
    assert "mov ax, ax" in captured.err
    assert "mov ax, ax" not in out


def test_emit_function_result_retries_with_recovered_result_function(monkeypatch, tmp_path, capsys):
    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    original_function = SimpleNamespace(addr=0x10010, name="main", project=project)
    recovered_function = SimpleNamespace(addr=0x1000, name="main", project=project)
    original_cfg = SimpleNamespace(name="original-cfg")
    recovered_cfg = SimpleNamespace(name="recovered-cfg")
    item = decompile.FunctionWorkItem(index=1, function_cfg=original_cfg, function=original_function)
    result = decompile.FunctionWorkResult(
        index=item.index,
        status="validation_failed",
        payload="Final quality guard rejected emitted C (stack-base).",
        debug_output="",
        function=recovered_function,
        function_cfg=recovered_cfg,
        tail_validation={},
    )
    args = SimpleNamespace(
        addr=None,
        show_asm=False,
        binary=tmp_path / "sample.exe",
        alternate_source_c=False,
        timeout=60,
        api_style="default",
    )
    seen = {}

    def _fake_retry(**kwargs):
        seen["item"] = kwargs["item"]
        seen["function"] = kwargs["function"]
        seen["project"] = kwargs["project"]
        return True

    monkeypatch.setattr(decompile, "_try_emit_retry_recovered_candidate_8616", _fake_retry)

    decompiled, failed = decompile._emit_function_result(
        item,
        result,
        project=project,
        args=args,
        lst_metadata=None,
        cod_metadata=None,
        synthetic_globals=None,
        precise_sidecar_regions=False,
        allow_heavy_fallbacks=False,
        interactive_stdout=False,
        use_serial_fork_per_function=False,
        fallback_tail_validation_by_index={},
    )

    assert (decompiled, failed) == (1, 0)
    assert seen["item"].function is recovered_function
    assert seen["item"].function_cfg is recovered_cfg
    assert seen["function"] is original_function
    assert seen["project"] is project
    assert "failure family: status=validation_failed" in capsys.readouterr().out


def test_emit_function_result_retry_budget_stays_with_configured_timeout(monkeypatch, tmp_path, capsys):
    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    function = SimpleNamespace(addr=0x1005D, name="InitMenu", project=project)
    item = decompile.FunctionWorkItem(index=1, function_cfg=SimpleNamespace(), function=function)
    result = decompile.FunctionWorkResult(
        index=item.index,
        status=decompile.WorkItemStatus.TIMEOUT.value,
        payload="Timed out after 130s.",
        debug_output="",
        function=function,
        function_cfg=item.function_cfg,
        tail_validation={},
        elapsed=130.0,
    )
    args = SimpleNamespace(
        addr=None,
        show_asm=False,
        binary=tmp_path / "sample.exe",
        alternate_source_c=False,
        timeout=60,
        api_style="default",
    )
    seen = {}

    def _fake_retry(**kwargs):
        seen["retry_timeout"] = kwargs["retry_timeout"]
        return True

    monkeypatch.setattr(decompile, "_try_emit_retry_recovered_candidate_8616", _fake_retry)

    decompiled, failed = decompile._emit_function_result(
        item,
        result,
        project=project,
        args=args,
        lst_metadata=None,
        cod_metadata=None,
        synthetic_globals=None,
        precise_sidecar_regions=False,
        allow_heavy_fallbacks=False,
        interactive_stdout=False,
        use_serial_fork_per_function=False,
        fallback_tail_validation_by_index={},
        timeout_was_explicit=True,
    )

    assert (decompiled, failed) == (1, 0)
    assert seen["retry_timeout"] == 60
    assert "failure family: status=timeout" in capsys.readouterr().out


def test_retry_recovered_candidate_is_bounded_by_worker_timeout(monkeypatch, tmp_path, capsys):
    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    function = SimpleNamespace(addr=0x10010, name="main", project=project)
    item = decompile.FunctionWorkItem(index=1, function_cfg=SimpleNamespace(), function=function)
    args = SimpleNamespace(
        binary=tmp_path / "sample.exe",
        timeout=7,
        api_style="default",
        alternate_source_c=False,
        output_c_dir=None,
    )
    wrapper_calls = {}

    def _fake_daemon_thread(fn, *, timeout, thread_name_prefix):
        wrapper_calls["timeout"] = timeout
        wrapper_calls["thread_name_prefix"] = thread_name_prefix
        return fn()

    def _fake_work_item(work_item, **_kwargs):
        return decompile.FunctionWorkResult(
            index=work_item.index,
            status="ok",
            payload="int main(void) { return 0; }",
            debug_output="",
            function=work_item.function,
            function_cfg=work_item.function_cfg,
            tail_validation={
                "structuring": {"status": "stable", "changed": False},
                "postprocess": {"status": "stable", "changed": False},
            },
        )

    monkeypatch.setattr(decompile, "_direct_addr_use_fork_lane_8616", lambda **_kwargs: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_daemon_thread)
    monkeypatch.setattr(decompile, "_run_function_work_item", _fake_work_item)
    monkeypatch.setattr(
        decompile,
        "_collect_recompilation_payloads_8616",
        lambda payload: ([("portable-flat", payload), ("msc-dos", payload)], None),
    )
    fallback_tail_validation_by_index = {}
    result_state_by_index = {}

    ok = decompile._try_emit_retry_recovered_candidate_8616(
        item=item,
        function=function,
        project=project,
        args=args,
        lst_metadata=None,
        cod_metadata=None,
        synthetic_globals=None,
        fallback_tail_validation_by_index=fallback_tail_validation_by_index,
        result_state_by_index=result_state_by_index,
    )

    assert ok is True
    assert wrapper_calls == {
        "timeout": 9,
        "thread_name_prefix": "retry-recovered-candidate",
    }
    assert fallback_tail_validation_by_index[1]["structuring"]["status"] == "stable"
    assert result_state_by_index[1].status == decompile.WorkItemStatus.OK.value
    assert result_state_by_index[1].payload == "int main(void) { return 0; }"
    assert result_state_by_index[1].tail_validation["structuring"]["status"] == "stable"
    assert "retry lane: recovered validation-passed candidate" in capsys.readouterr().out


def test_retry_recovered_candidate_uses_thread_when_tail_validation_enabled(monkeypatch, tmp_path, capsys):
    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"), _inertia_tail_validation_enabled=True)
    function = SimpleNamespace(addr=0x10060, name="InitMenu", project=project)
    item = decompile.FunctionWorkItem(index=1, function_cfg=SimpleNamespace(), function=function)
    args = SimpleNamespace(
        binary=tmp_path / "sample.exe",
        timeout=7,
        api_style="default",
        alternate_source_c=False,
        output_c_dir=None,
    )
    wrapper_calls = {}

    def _fake_fork(*_args, **_kwargs):
        raise AssertionError("tail-validation retry must not use fork isolation")

    def _fake_daemon_thread(fn, *, timeout, thread_name_prefix):
        wrapper_calls["timeout"] = timeout
        wrapper_calls["thread_name_prefix"] = thread_name_prefix
        return fn()

    def _fake_work_item(work_item, **_kwargs):
        return decompile.FunctionWorkResult(
            index=work_item.index,
            status="ok",
            payload="void InitMenu(void) { }",
            debug_output="",
            function=work_item.function,
            function_cfg=work_item.function_cfg,
            tail_validation={
                "structuring": {"status": "stable", "changed": False},
                "postprocess": {"status": "stable", "changed": False},
            },
        )

    monkeypatch.setattr(decompile.os, "name", "posix")
    monkeypatch.setenv("INERTIA_OTEL_PROFILE_IN_PROCESS", "1")
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", _fake_fork)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_daemon_thread)
    monkeypatch.setattr(decompile, "_run_function_work_item", _fake_work_item)

    ok = decompile._try_emit_retry_recovered_candidate_8616(
        item=item,
        function=function,
        project=project,
        args=args,
        lst_metadata=None,
        cod_metadata=None,
        synthetic_globals=None,
    )

    assert ok is True
    assert wrapper_calls == {
        "timeout": 9,
        "thread_name_prefix": "retry-recovered-candidate",
    }
    assert "retry lane: recovered validation-passed candidate" in capsys.readouterr().out


def test_retry_recovered_candidate_refuses_raw_memory_payload(monkeypatch, tmp_path, capsys):
    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    function = SimpleNamespace(addr=0x10678, name="ReInitBars", project=project)
    item = decompile.FunctionWorkItem(index=1, function_cfg=SimpleNamespace(), function=function)
    args = SimpleNamespace(
        binary=tmp_path / "SORTDEMO.EXE",
        timeout=7,
        api_style="default",
        alternate_source_c=False,
    )

    def _fake_work_item(work_item, **_kwargs):
        return decompile.FunctionWorkResult(
            index=work_item.index,
            status="ok",
            payload="void ReInitBars(void) { abarWork[i] = MEM_U16(&mem_08F0 + i * 2); }",
            debug_output="",
            function=work_item.function,
            function_cfg=work_item.function_cfg,
            tail_validation={
                "structuring": {"status": "stable", "changed": False},
                "postprocess": {"status": "stable", "changed": False},
            },
        )

    monkeypatch.setattr(decompile, "_direct_addr_use_fork_lane_8616", lambda **_kwargs: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "_run_function_work_item", _fake_work_item)
    ok = decompile._try_emit_retry_recovered_candidate_8616(
        item=item,
        function=function,
        project=project,
        args=args,
        lst_metadata=None,
        cod_metadata=None,
        synthetic_globals=None,
    )

    assert ok is False
    captured = capsys.readouterr()
    assert "retry lane: recovered validation-passed candidate" not in captured.out
    assert "raw-memory-symbol" in captured.err


def test_retry_recovered_candidate_refuses_stale_result_snapshot(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x10000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000)),
        _inertia_c_target="portable-flat",
    )
    original_function = SimpleNamespace(addr=0x10554, name="InitBars", project=project)
    item = decompile.FunctionWorkItem(index=1, function_cfg=SimpleNamespace(), function=original_function)
    metadata = LSTMetadata(data_labels={}, code_labels={}, absolute_addrs=True)
    args = SimpleNamespace(
        addr=None,
        binary=binary,
        timeout=7,
        api_style="default",
        alternate_source_c=False,
        window=0x200,
        c_target="portable-flat",
        trace_c_stages=False,
        dump_layers=False,
        dump_layer_dir=None,
        dump_layer_filter=None,
    )
    fresh_project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    recovered_function = SimpleNamespace(
        addr=0x1000,
        name="InitBars",
        project=fresh_project,
        info={
            "x86_16_tail_validation": {
                "structuring": {"status": "stable", "changed": False},
                "postprocess": {"status": "stable", "changed": False},
            }
        },
    )
    recovered_cfg = SimpleNamespace(name="fresh-cfg")
    seen = {}

    def _fake_build_project(*_args, **_kwargs):
        return fresh_project

    def _fake_recover_lst_function(project_arg, metadata_arg, offset, name, **_kwargs):
        seen["recover"] = (project_arg, metadata_arg, offset, name)
        return recovered_cfg, recovered_function

    def _fake_work_item(work_item, **_kwargs):
        seen.setdefault("work_items", []).append(work_item)
        seen.setdefault("allow_isolated_retries", []).append(_kwargs.get("allow_isolated_retry"))
        return decompile.FunctionWorkResult(
            index=work_item.index,
            status="ok",
            payload="int InitBars(void) { return 1; }",
            debug_output="",
            function=work_item.function,
            function_cfg=work_item.function_cfg,
            tail_validation={
                "structuring": {"status": "stable", "changed": False},
                "postprocess": {"status": "changed", "changed": True},
            },
        )

    monkeypatch.setattr(decompile, "_direct_addr_use_fork_lane_8616", lambda **_kwargs: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "_build_project", _fake_build_project)
    monkeypatch.setattr(decompile, "attach_lst_metadata_to_project", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_recover_lst_function", _fake_recover_lst_function)
    monkeypatch.setattr(decompile, "_run_function_work_item", _fake_work_item)
    monkeypatch.setattr(decompile, "_run_serial_clean_process_work_item_8616", lambda *_args, **_kwargs: _fake_work_item(item))

    ok = decompile._try_emit_retry_recovered_candidate_8616(
        item=item,
        function=original_function,
        project=project,
        args=args,
        lst_metadata=metadata,
        cod_metadata=None,
        synthetic_globals=None,
    )

    assert ok is False
    assert seen["recover"] == (fresh_project, metadata, 0x10554, "InitBars")
    assert seen["work_items"][0].function is recovered_function
    assert seen["work_items"][0].function_cfg is recovered_cfg
    assert seen["allow_isolated_retries"][0] is False
    assert "retry lane: recovered validation-passed candidate" not in capsys.readouterr().out


def test_retry_recovered_candidate_uses_fresh_sidecar_work_item(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x10000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000)),
        _inertia_c_target="portable-flat",
    )
    original_function = SimpleNamespace(addr=0x10554, name="InitBars", project=project)
    item = decompile.FunctionWorkItem(index=1, function_cfg=SimpleNamespace(), function=original_function)
    metadata = LSTMetadata(data_labels={}, code_labels={}, absolute_addrs=True)
    args = SimpleNamespace(
        addr=None,
        binary=binary,
        timeout=7,
        api_style="default",
        alternate_source_c=False,
        window=0x200,
        c_target="portable-flat",
        trace_c_stages=False,
        dump_layers=False,
        dump_layer_dir=None,
        dump_layer_filter=None,
        output_c_dir=tmp_path / "generated",
    )
    fresh_project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    recovered_function = SimpleNamespace(addr=0x1000, name="InitBars", project=fresh_project, info={})
    recovered_cfg = SimpleNamespace(name="fresh-cfg")
    seen = {}

    def _fake_build_project(*_args, **_kwargs):
        return fresh_project

    def _fake_recover_lst_function(project_arg, metadata_arg, offset, name, **_kwargs):
        seen["recover"] = (project_arg, metadata_arg, offset, name)
        return recovered_cfg, recovered_function

    def _fake_work_item(work_item, **_kwargs):
        seen["work_item"] = work_item
        seen["allow_isolated_retry"] = _kwargs.get("allow_isolated_retry")
        return decompile.FunctionWorkResult(
            index=work_item.index,
            status="ok",
            payload="int InitBars(void) { return 1; }",
            debug_output="",
            function=work_item.function,
            function_cfg=work_item.function_cfg,
            tail_validation={
                "structuring": {"status": "stable", "changed": False},
                "postprocess": {"status": "stable", "changed": False},
            },
        )

    monkeypatch.setattr(decompile, "_direct_addr_use_fork_lane_8616", lambda **_kwargs: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "_build_project", _fake_build_project)
    monkeypatch.setattr(decompile, "attach_lst_metadata_to_project", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_recover_lst_function", _fake_recover_lst_function)
    monkeypatch.setattr(decompile, "_run_function_work_item", _fake_work_item)

    ok = decompile._try_emit_retry_recovered_candidate_8616(
        item=item,
        function=original_function,
        project=project,
        args=args,
        lst_metadata=metadata,
        cod_metadata=None,
        synthetic_globals=None,
    )

    assert ok is True
    assert seen["recover"] == (fresh_project, metadata, 0x10554, "InitBars")
    assert seen["work_item"].function is recovered_function
    assert seen["work_item"].function_cfg is recovered_cfg
    assert seen["allow_isolated_retry"] is False
    assert (args.output_c_dir / "00010554-InitBars.c").read_text() == "int InitBars(void) { return 1; }"
    assert "retry lane: recovered validation-passed candidate" in capsys.readouterr().out


def test_fresh_sidecar_retry_disables_rebased_exact_slice_after_sliced_failure(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x10000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000)),
        _inertia_c_target="portable-flat",
    )
    sliced_project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    failed_function = SimpleNamespace(
        addr=0x1000,
        name="QuickSort",
        project=sliced_project,
        info={"inertia_original_addr": 0x10CE0},
    )
    item = decompile.FunctionWorkItem(index=1, function_cfg=SimpleNamespace(), function=failed_function)
    metadata = LSTMetadata(data_labels={}, code_labels={}, absolute_addrs=True)
    args = SimpleNamespace(
        addr=None,
        binary=binary,
        timeout=7,
        c_target="portable-flat",
        trace_c_stages=False,
        dump_layers=False,
        dump_layer_dir=None,
        dump_layer_filter=None,
        window=0x200,
    )
    fresh_project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    recovered_function = SimpleNamespace(addr=0x10CE0, name="QuickSort", project=fresh_project)
    recovered_cfg = SimpleNamespace()
    seen = {}

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: fresh_project)
    monkeypatch.setattr(decompile, "attach_lst_metadata_to_project", lambda *_args, **_kwargs: None)

    def _fake_recover_lst_function(project_arg, metadata_arg, offset, name, **_kwargs):
        seen["recover"] = (project_arg, metadata_arg, offset, name)
        seen["allow_rebased_exact_slice"] = _kwargs.get("allow_rebased_exact_slice")
        return recovered_cfg, recovered_function

    monkeypatch.setattr(decompile, "_recover_lst_function", _fake_recover_lst_function)

    retry_item = decompile._fresh_sidecar_retry_work_item_8616(
        item=item,
        project=project,
        args=args,
        lst_metadata=metadata,
    )

    assert retry_item is not None
    assert retry_item.function is recovered_function
    assert retry_item.function_cfg is recovered_cfg
    assert retry_item.retained_project is fresh_project
    assert seen["recover"] == (fresh_project, metadata, 0x10CE0, "QuickSort")
    assert seen["allow_rebased_exact_slice"] is False
    assert fresh_project._inertia_rebased_exact_slice_retry_disabled_8616 is True


def test_run_function_work_item_uses_persistent_disk_cache(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    calls = {"count": 0}

    def _fake_decompile(*_args, **_kwargs):
        calls["count"] += 1
        item.function.info = {
            "x86_16_tail_validation": {
                "structuring": {"status": "stable", "changed": False, "verdict": "structuring stable"},
                "postprocess": {"status": "stable", "changed": False, "verdict": "postprocess stable"},
            }
        }
        return "ok", "int sub_1000(void) { return 1; }", None, 1, 4, 0.01

    monkeypatch.setattr(recovery_cache, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(recovery_cache, "_cache_source_digest", lambda _paths: "digest-a")
    monkeypatch.setattr(decompile, "_decompile_function_with_stats", _fake_decompile)

    item = decompile.FunctionWorkItem(
        index=1,
        function_cfg=SimpleNamespace(),
        function=SimpleNamespace(addr=0x1000, name="sub_1000", project=SimpleNamespace()),
    )

    first = decompile._run_function_work_item(
        item,
        timeout=5,
        api_style="pascal",
        binary_path=binary,
        cod_metadata=None,
        synthetic_globals=None,
        lst_metadata=None,
        enable_structured_simplify=True,
    )
    second = decompile._run_function_work_item(
        item,
        timeout=5,
        api_style="pascal",
        binary_path=binary,
        cod_metadata=None,
        synthetic_globals=None,
        lst_metadata=None,
        enable_structured_simplify=True,
    )

    assert calls["count"] == 1
    assert first.payload == second.payload
    assert "cache hit" in second.debug_output
    assert "validation=passed" in second.debug_output
    assert second.tail_validation == first.tail_validation
    assert second.tail_validation is not None
    assert list(second.tail_validation) == ["structuring", "postprocess"]
    assert second.tail_validation["structuring"]["status"] == "stable"
    assert second.tail_validation["postprocess"]["status"] == "stable"


def test_run_function_work_item_uses_recovery_for_source_backed_quality_blocker(monkeypatch, tmp_path):
    binary = tmp_path / "SORTDEMO.EXE"
    binary.write_bytes(b"MZ")
    calls = {"decompile": 0, "recover": 0}
    project = SimpleNamespace(_inertia_c_target="portable-flat")
    function = SimpleNamespace(addr=0x10672, name="ReInitBars", project=project, info={})
    item = decompile.FunctionWorkItem(index=1, function_cfg=SimpleNamespace(), function=function)

    def _fake_decompile(_project, _cfg, function_arg, *_args, **_kwargs):
        calls["decompile"] += 1
        function_arg.info = {
            "x86_16_tail_validation": {
                "structuring": {"changed": False, "verdict": "structuring stable"},
                "postprocess": {"changed": False, "verdict": "postprocess stable"},
            }
        }
        return (
            "ok",
            "void ReInitBars(void)\n{\n    return SEG_U16(ds, 42);\n}\n",
            None,
            1,
            8,
            0.01,
        )

    def _fake_recover(_project, _function):
        calls["recover"] += 1
        return (
            "void ReInitBars(void)\n{\n    return;\n}\n",
            {
                "structuring": {"changed": False, "status": "stable"},
                "postprocess": {"changed": False, "status": "stable"},
            },
        )

    monkeypatch.setattr(recovery_cache, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(recovery_cache, "_cache_source_digest", lambda _paths: "digest-a")
    monkeypatch.setattr(decompile, "_decompile_function_with_stats", _fake_decompile)
    monkeypatch.setattr(decompile, "_recover_binary_evidence_c_8616", _fake_recover)
    result = decompile._run_function_work_item(
        item,
        timeout=5,
        api_style="pascal",
        binary_path=binary,
        cod_metadata=None,
        synthetic_globals=None,
        lst_metadata=None,
        enable_structured_simplify=True,
    )

    assert calls == {"decompile": 1, "recover": 1}
    assert result.status == "ok"
    assert "SEG_U16" not in result.payload
    assert "return;" in result.payload


def test_run_function_work_item_bypasses_persistent_cache_without_passed_tail_validation(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    calls = {"count": 0}

    monkeypatch.setattr(recovery_cache, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(recovery_cache, "_cache_source_digest", lambda _paths: "digest-a")

    item = decompile.FunctionWorkItem(
        index=1,
        function_cfg=SimpleNamespace(),
        function=SimpleNamespace(addr=0x1000, name="sub_1000", project=SimpleNamespace(), info={}),
    )

    def _fake_decompile(*_args, **_kwargs):
        calls["count"] += 1
        item.function.info = {
            "x86_16_tail_validation": {
                "structuring": {"changed": False, "verdict": "structuring stable"},
                "postprocess": {"changed": False, "verdict": "postprocess stable"},
            }
        }
        return "ok", "int sub_1000(void) { return 2; }", None, 1, 4, 0.01

    monkeypatch.setattr(decompile, "_decompile_function_with_stats", _fake_decompile)

    cache_key = decompile.function_decompilation_cache_key_8616(
        item,
        binary_path=binary,
        api_style="pascal",
        cod_metadata=None,
        synthetic_globals=None,
        lst_metadata=None,
        enable_structured_simplify=True,
        enable_postprocess=True,
    )
    decompile._store_cache_json(
        "function_decompile",
        cache_key,
        {
            "status": "ok",
            "payload": "int stale(void) { return 0; }",
        },
    )

    result = decompile._run_function_work_item(
        item,
        timeout=5,
        api_style="pascal",
        binary_path=binary,
        cod_metadata=None,
        synthetic_globals=None,
        lst_metadata=None,
        enable_structured_simplify=True,
    )

    assert calls["count"] == 1
    assert "stale" not in result.payload
    assert "cache bypass" in result.debug_output
    assert "validation=uncollected" in result.debug_output
    stored = decompile._load_cache_json("function_decompile", cache_key)
    assert stored["status"] == "ok"
    assert stored["payload"] == "int sub_1000(void) { return 2; }"
    assert stored["tail_validation_passed"] is True
    assert stored["elapsed"] == 0.01
    assert stored["block_count"] == 1
    assert stored["byte_count"] == 4
    assert stored["tail_validation"] == {
        "structuring": {
            "changed": False,
            "mode": None,
            "status": "stable",
            "verdict": "structuring stable",
            "summary_text": None,
        },
        "postprocess": {
            "changed": False,
            "mode": None,
            "status": "stable",
            "verdict": "postprocess stable",
            "summary_text": None,
        },
    }


def test_run_function_work_item_cache_separates_same_addr_cod_proc_names(monkeypatch, tmp_path):
    binary = tmp_path / "sample.cod"
    binary.write_bytes(b"PROC")
    calls = {"count": 0}

    monkeypatch.setattr(recovery_cache, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(recovery_cache, "_cache_source_digest", lambda _paths: "digest-a")

    def _item(name):
        return decompile.FunctionWorkItem(
            index=1,
            function_cfg=SimpleNamespace(),
            function=SimpleNamespace(addr=0x1000, name=name, project=SimpleNamespace(), info={}),
        )

    def _fake_decompile(_project, _cfg, function, *_args, **_kwargs):
        calls["count"] += 1
        function.info = {
            "x86_16_tail_validation": {
                "structuring": {"changed": False, "verdict": "structuring stable"},
                "postprocess": {"changed": False, "verdict": "postprocess stable"},
            }
        }
        return "ok", f"void {function.name}(void) {{}}", None, 1, 4, 0.01

    monkeypatch.setattr(decompile, "_decompile_function_with_stats", _fake_decompile)

    first = decompile._run_function_work_item(
        _item("_FirstProc"),
        timeout=5,
        api_style="pascal",
        binary_path=binary,
        cod_metadata=None,
        synthetic_globals=None,
        lst_metadata=None,
        enable_structured_simplify=True,
    )
    second = decompile._run_function_work_item(
        _item("_SecondProc"),
        timeout=5,
        api_style="pascal",
        binary_path=binary,
        cod_metadata=None,
        synthetic_globals=None,
        lst_metadata=None,
        enable_structured_simplify=True,
    )

    assert calls["count"] == 2
    assert "_FirstProc" in first.payload
    assert "_SecondProc" in second.payload
    assert "cache hit" not in second.debug_output


def test_run_function_work_item_does_not_cache_timeout_results(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    calls = {"count": 0}

    monkeypatch.setattr(recovery_cache, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(recovery_cache, "_cache_source_digest", lambda _paths: "digest-a")

    item = decompile.FunctionWorkItem(
        index=1,
        function_cfg=SimpleNamespace(),
        function=SimpleNamespace(addr=0x1000, name="sub_1000", project=SimpleNamespace(), info={}),
    )

    def _fake_timeout(*_args, **_kwargs):
        calls["count"] += 1
        return "timeout", "Timed out after 5s.", None, 1, 0, 5.0

    monkeypatch.setattr(decompile, "_decompile_function_with_stats", _fake_timeout)

    first = decompile._run_function_work_item(
        item,
        timeout=5,
        api_style="pascal",
        binary_path=binary,
        cod_metadata=None,
        synthetic_globals=None,
        lst_metadata=None,
        enable_structured_simplify=True,
    )
    second = decompile._run_function_work_item(
        item,
        timeout=5,
        api_style="pascal",
        binary_path=binary,
        cod_metadata=None,
        synthetic_globals=None,
        lst_metadata=None,
        enable_structured_simplify=True,
    )

    assert first.status == "timeout"
    assert second.status == "timeout"
    assert calls["count"] == 2
    cached = decompile._load_cache_json(
        "function_decompile",
        decompile.function_decompilation_cache_key_8616(
            item,
            binary_path=binary,
            api_style="pascal",
            cod_metadata=None,
            synthetic_globals=None,
            lst_metadata=None,
            enable_structured_simplify=True,
            enable_postprocess=True,
        ),
    )
    assert cached is None


def test_try_decompile_non_optimized_slice_retries_with_fresh_project(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"\x90" * 0x40)
    shared_project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(linked_base=0x1000, max_addr=0x20000),
            memory=SimpleNamespace(load=lambda _start, size: b"\x90" * size),
        ),
    )
    fresh_project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(linked_base=0x1000, max_addr=0x20000),
            memory=SimpleNamespace(load=lambda _start, size: b"\x90" * size),
        ),
    )
    slice_project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=shared_project.loader,
    )
    cfg = SimpleNamespace()

    class FakeFunction:
        def __init__(self):
            self.addr = 0x11593
            self.name = "sub_11593"
            self.normalized = False

        def normalize(self):
            self.normalized = True

        def get_call_sites(self):
            return []

        def get_call_target(self, _callsite):
            return 0x1140D

    func = FakeFunction()
    calls = {"decompile": 0}

    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x11593, 0x115B5))
    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *_args, **_kwargs: slice_project)
    monkeypatch.setattr(decompile, "_pick_function_lean", lambda *_args, **_kwargs: (cfg, func))
    monkeypatch.setattr(decompile, "_sidecar_cod_metadata_for_function", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_inherit_tail_validation_runtime_policy", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prepare_function_for_decompilation", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_build_project",
        lambda path, **_kwargs: fresh_project if Path(path) == binary else shared_project,
    )
    monkeypatch.setattr(
        decompile,
        "_build_project_cached",
        lambda path, **_kwargs: fresh_project if Path(path) == binary else shared_project,
    )
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", lambda fn, **_kwargs: fn())

    def _fake_decompile(project, *_args, **_kwargs):
        calls["decompile"] += 1
        if calls["decompile"] == 1:
            return "timeout", "Timed out after 6s.", 1, 0x20, 6.0
        return "ok", "int sub_11593(void) { return 0; }", 1, 0x20, 1.0

    monkeypatch.setattr(decompile, "_decompile_function_with_stats", _fake_decompile)

    outcome = decompile._try_decompile_non_optimized_slice(
        shared_project,
        0x11593,
        "sub_11593",
        timeout=6,
        api_style="modern",
        binary_path=binary,
        lst_metadata=None,
    )

    assert calls["decompile"] == 2
    assert outcome.rendered == "int sub_11593(void) { return 0; }"


def test_try_decompile_non_optimized_slice_prepares_direct_callee_context_before_retry(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"\x90" * 0x40)
    shared_project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(linked_base=0x1000, max_addr=0x20000),
            memory=SimpleNamespace(load=lambda _start, size: b"\x90" * size),
        ),
    )
    fresh_project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(linked_base=0x1000, max_addr=0x20000),
            memory=SimpleNamespace(load=lambda _start, size: b"\x90" * size),
        ),
    )

    class FakeFunctionManager:
        def __init__(self):
            self.created: list[int] = []

        def function(self, *, addr=None, create=False, **_kwargs):
            if create:
                self.created.append(addr)
            return SimpleNamespace(addr=addr)

    class FakeFunction:
        def __init__(self):
            self.addr = 0x11593
            self.name = "sub_11593"
            self.normalized = False
            self._callsite_checks = 0

        def normalize(self):
            self.normalized = True

        def get_call_sites(self):
            self._callsite_checks += 1
            if self._callsite_checks == 1:
                return []
            return [0x1159F]

        def get_call_target(self, _callsite):
            return 0x1140D

    slice_project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=shared_project.loader,
        kb=SimpleNamespace(functions=FakeFunctionManager()),
    )
    cfg = SimpleNamespace()
    func = FakeFunction()
    calls = {"decompile": 0}

    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x11593, 0x115B5))
    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *_args, **_kwargs: slice_project)
    monkeypatch.setattr(decompile, "_pick_function_lean", lambda *_args, **_kwargs: (cfg, func))
    monkeypatch.setattr(decompile, "_sidecar_cod_metadata_for_function", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_inherit_tail_validation_runtime_policy", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_build_project",
        lambda path, **_kwargs: fresh_project if Path(path) == binary else shared_project,
    )
    monkeypatch.setattr(
        decompile,
        "_build_project_cached",
        lambda path, **_kwargs: fresh_project if Path(path) == binary else shared_project,
    )
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", lambda fn, **_kwargs: fn())

    def _fake_decompile(project, *_args, **_kwargs):
        calls["decompile"] += 1
        if not project.kb.functions.created:
            return "timeout", "missing direct callee context", 1, 0x20, 6.0
        return "ok", "int sub_11593(void) { return 0; }", 1, 0x20, 1.0

    monkeypatch.setattr(decompile, "_decompile_function_with_stats", _fake_decompile)

    outcome = decompile._try_decompile_non_optimized_slice(
        shared_project,
        0x11593,
        "sub_11593",
        timeout=6,
        api_style="modern",
        binary_path=binary,
        lst_metadata=None,
    )

    assert calls["decompile"] == 2
    assert func.normalized is True
    assert slice_project.kb.functions.created == [0x1140D]
    assert outcome.rendered == "int sub_11593(void) { return 0; }"


def test_try_decompile_non_optimized_slice_retries_with_blob_project_for_cod_inputs(monkeypatch):
    shared_project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(linked_base=0x1000),
            memory=SimpleNamespace(load=lambda _start, size: b"\x90" * size),
        ),
    )
    fresh_project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(linked_base=0x1000),
            memory=SimpleNamespace(load=lambda _start, size: b"\x90" * size),
        ),
    )
    slice_project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=shared_project.loader,
    )
    cfg = SimpleNamespace()
    func = SimpleNamespace(name="sub_11593")
    calls = {"decompile": 0, "build": []}

    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x11593, 0x115B5))
    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *_args, **_kwargs: slice_project)
    monkeypatch.setattr(decompile, "_pick_function_lean", lambda *_args, **_kwargs: (cfg, func))
    monkeypatch.setattr(decompile, "_sidecar_cod_metadata_for_function", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_inherit_tail_validation_runtime_policy", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prepare_function_for_decompilation", lambda *_args, **_kwargs: None)

    def _fake_build_project(path, *, force_blob, base_addr, entry_point):
        calls["build"].append((Path(path), force_blob, base_addr, entry_point))
        assert Path(path) == LIFE_COD
        assert force_blob is True
        return fresh_project

    monkeypatch.setattr(decompile, "_build_project", _fake_build_project)
    monkeypatch.setattr(decompile, "_build_project_cached", _fake_build_project)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", lambda fn, **_kwargs: fn())

    def _fake_decompile(project, *_args, **_kwargs):
        calls["decompile"] += 1
        if calls["decompile"] == 1:
            return "timeout", "Timed out after 6s.", 1, 0x20, 6.0
        return "ok", "int sub_11593(void) { return 0; }", 1, 0x20, 1.0

    monkeypatch.setattr(decompile, "_decompile_function_with_stats", _fake_decompile)

    outcome = decompile._try_decompile_non_optimized_slice(
        shared_project,
        0x11593,
        "sub_11593",
        timeout=6,
        api_style="modern",
        binary_path=LIFE_COD,
        lst_metadata=None,
    )

    assert calls["build"] == [(LIFE_COD, True, 0x1000, 0x1000)]
    assert calls["decompile"] == 2
    assert outcome.rendered == "int sub_11593(void) { return 0; }"


def test_try_decompile_non_optimized_slice_never_caches_results(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"\x90" * 0x40)
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(linked_base=0x1000, max_addr=0x20000),
            memory=SimpleNamespace(load=lambda _start, size: b"\x90" * size),
        ),
    )
    fresh_project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(linked_base=0x1000, max_addr=0x20000),
            memory=SimpleNamespace(load=lambda _start, size: b"\x90" * size),
        ),
    )
    slice_project = SimpleNamespace(arch=SimpleNamespace(name="86_16"), loader=project.loader)
    cfg = SimpleNamespace()

    class FakeFunction:
        def __init__(self):
            self.addr = 0x114CD
            self.name = "sub_114cd"
            self.normalized = False

        def normalize(self):
            self.normalized = True

        def get_call_sites(self):
            return []

        def get_call_target(self, _callsite):
            return 0x1140D

    func = FakeFunction()

    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x114CD, 0x114EB))
    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *_args, **_kwargs: slice_project)
    monkeypatch.setattr(decompile, "_pick_function_lean", lambda *_args, **_kwargs: (cfg, func))
    monkeypatch.setattr(decompile, "_sidecar_cod_metadata_for_function", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_inherit_tail_validation_runtime_policy", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prepare_function_for_decompilation", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_build_project",
        lambda path, **_kwargs: fresh_project if Path(path) == binary else project,
    )
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(
        decompile,
        "_decompile_function_with_stats",
        lambda *_args, **_kwargs: ("ok", "void sub_114cd(void) {}", 1, 0x20, 0.5),
    )

    def _unexpected_cache_write(*_args, **_kwargs):
        raise AssertionError("non-optimized fallback should not write cache entries")

    monkeypatch.setattr(decompile, "_store_cache_json", _unexpected_cache_write)

    outcome = decompile._try_decompile_non_optimized_slice(
        project,
        0x114CD,
        "sub_114cd",
        timeout=6,
        api_style="modern",
        binary_path=binary,
        lst_metadata=None,
    )

    assert outcome.rendered == "void sub_114cd(void) {}"


def test_decompile_function_empty_reports_angr_error_detail(monkeypatch):
    class FakeErrorEntry:
        def __init__(self, error):
            self.error = error

    class FakeDecompiler:
        def __init__(self, *_args, **_kwargs):
            self.codegen = None
            self.errors = [FakeErrorEntry(KeyError(5133))]
            self.clinic = None

    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        analyses=SimpleNamespace(
            Decompiler=FakeDecompiler,
            Clinic=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError()),
        ),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x200)),
    )
    function = SimpleNamespace(addr=0x10010, name="sub_10010", normalized=True, blocks=(SimpleNamespace(size=0x10),))
    cfg = SimpleNamespace()

    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "seed_calling_conventions", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_preferred_decompiler_options", lambda *_args, **_kwargs: None)

    status, payload = decompile._decompile_function(
        project,
        cfg,
        function,
        timeout=1,
        api_style="pascal",
        binary_path=None,
        allow_isolated_retry=False,
    )

    assert status == "empty"
    assert "KeyError: 5133" in payload
    assert "clinic=None" in payload
    assert "clinic-failure=AssertionError" in payload


def test_decompile_function_timeout_returns_partial_codegen_text(monkeypatch):
    class FakeCodegen:
        text = "int partial(void) { return 1; }"

        cfunc = object()

        def render_text(self, _cfunc):
            return self.text

    class FakeDecompiler:
        def __init__(self, *_args, **_kwargs):
            self.codegen = FakeCodegen()
            self.errors = []
            self.clinic = object()

    @contextlib.contextmanager
    def _fake_timeout(_seconds):
        yield
        raise decompile._AnalysisTimeout

    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        analyses=SimpleNamespace(Decompiler=FakeDecompiler),
    )
    function = SimpleNamespace(addr=0x10010, name="sub_10010", normalized=True, blocks=(SimpleNamespace(size=0x10),))
    cfg = SimpleNamespace()

    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prepare_function_for_decompilation", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "seed_calling_conventions", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_preferred_decompiler_options", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_analysis_timeout", _fake_timeout)
    monkeypatch.setattr(decompile, "_format_known_helper_calls", lambda *_args, **_kwargs: _args[2])

    status, payload = decompile._decompile_function(
        project,
        cfg,
        function,
        timeout=1,
        api_style="modern",
        binary_path=None,
        allow_isolated_retry=False,
    )

    assert status == "timeout"
    assert payload == "Timed out after 1s."
    assert project._inertia_partial_codegen_text == "int partial(void) { return 1; }"


def test_resolve_stack_cvar_from_addr_expr_materializes_derived_word_stack_local(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(
        addr=0x10010,
        arg_list=(),
        sort_local_vars=lambda: None,
        unified_local_vars={},
        variables_in_use={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, next_idx=lambda _name: 0, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    base_var = SimStackVariable(-2, 1, base="bp", name="s_2", region=0x10010)
    base_cvar = structured_c.CVariable(base_var, codegen=codegen)
    low_addr_expr = object()

    monkeypatch.setattr(
        decompile,
        "_classify_segmented_addr_expr",
        lambda expr, _project: (
            _SegmentedAccess(
                kind="stack",
                seg_name="ss",
                cvar=base_cvar,
                stack_var=base_var,
                extra_offset=2,
                addr_expr=expr,
            )
            if expr is low_addr_expr
            else None
        ),
    )

    resolved = decompile._resolve_stack_cvar_from_addr_expr(project, codegen, low_addr_expr)

    assert isinstance(resolved, structured_c.CVariable)
    assert isinstance(resolved.variable, SimStackVariable)
    assert resolved.variable.offset == 0
    assert resolved.variable.size == 2
    assert codegen.cfunc.variables_in_use[resolved.variable] is resolved
    assert resolved.variable in codegen.cfunc.unified_local_vars
    assert any(cvar is resolved for cvar, _vartype in codegen.cfunc.unified_local_vars[resolved.variable])


def test_coalesce_segmented_word_store_statements_prefers_derived_stack_local_word_lhs(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(byte_width=8, bits=16, name="X86"))
    cfunc = SimpleNamespace(
        addr=0x10010,
        arg_list=(),
        sort_local_vars=lambda: None,
        unified_local_vars={},
        variables_in_use={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, next_idx=lambda _name: 0, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    base_var = SimStackVariable(-2, 1, base="bp", name="s_2", region=0x10010)
    base_cvar = structured_c.CVariable(base_var, codegen=codegen)
    low_addr_expr = SimpleNamespace(type=None)
    high_addr_expr = SimpleNamespace(type=None)
    root = structured_c.CStatements(
        [
            structured_c.CAssignment(
                SimpleNamespace(type=SimTypeChar(False)),
                structured_c.CConstant(0x12, SimTypeChar(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CAssignment(
                SimpleNamespace(type=SimTypeChar(False)),
                structured_c.CConstant(0x34, SimTypeChar(False), codegen=codegen),
                codegen=codegen,
            ),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    alias_facts = SimpleNamespace(identity=object(), can_join=lambda _other: True, needs_synthesis=lambda: False)
    word_rhs = structured_c.CConstant(0x3412, SimTypeShort(False), codegen=codegen)

    monkeypatch.setattr(
        decompile,
        "_classify_segmented_addr_expr",
        lambda expr, _project: (
            _SegmentedAccess(
                kind="stack",
                seg_name="ss",
                cvar=base_cvar,
                stack_var=base_var,
                extra_offset=2,
                addr_expr=expr,
            )
            if expr is low_addr_expr
            else None
        ),
    )
    monkeypatch.setattr(decompile, "describe_alias_storage", lambda _expr: alias_facts)
    monkeypatch.setattr(decompile, "_addr_exprs_are_byte_pair", lambda _low, _high, _project: True)
    monkeypatch.setattr(
        decompile,
        "_match_byte_store_addr_expr",
        lambda node: (
            low_addr_expr
            if node is root.statements[0].lhs
            else high_addr_expr
            if node is root.statements[1].lhs
            else None
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_match_word_rhs_from_byte_pair",
        lambda _low_rhs, _high_rhs, _codegen, _project: word_rhs,
    )

    changed = decompile._coalesce_segmented_word_store_statements(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    replacement = codegen.cfunc.statements.statements[0]
    assert isinstance(replacement, structured_c.CAssignment)
    assert isinstance(replacement.lhs, structured_c.CVariable)
    assert isinstance(replacement.lhs.variable, SimStackVariable)
    assert replacement.lhs.variable.offset == 0
    assert replacement.lhs.variable.size == 2


def test_coalesce_segmented_word_store_statements_refuses_non_joinable_stack_slot(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(byte_width=8, bits=16, name="X86"))
    cfunc = SimpleNamespace(
        addr=0x10010,
        arg_list=(),
        sort_local_vars=lambda: None,
        unified_local_vars={},
        variables_in_use={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, next_idx=lambda _name: 0, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    base_var = SimStackVariable(-2, 1, base="bp", name="s_2", region=0x10010)
    base_cvar = structured_c.CVariable(base_var, codegen=codegen)
    lhs_var = SimStackVariable(0, 1, base="bp", name="s_0", region=0x20020)
    lhs_cvar = structured_c.CVariable(lhs_var, codegen=codegen)
    next_lhs = object()
    rhs_low = structured_c.CConstant(0x12, SimTypeChar(False), codegen=codegen)
    rhs_high = structured_c.CConstant(0x34, SimTypeChar(False), codegen=codegen)
    root = structured_c.CStatements(
        [
            structured_c.CAssignment(lhs_cvar, rhs_low, codegen=codegen),
            structured_c.CAssignment(next_lhs, rhs_high, codegen=codegen),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root
    word_rhs = structured_c.CConstant(0x3412, SimTypeShort(False), codegen=codegen)

    monkeypatch.setattr(
        decompile, "_match_ss_local_plus_const", lambda node, _project: (base_cvar, 1) if node is next_lhs else None
    )
    monkeypatch.setattr(decompile, "_match_word_rhs_from_byte_pair", lambda _lo, _hi, _codegen, _project: word_rhs)
    monkeypatch.setattr(decompile, "_stack_slot_identity_can_join", lambda _lhs, _rhs: False)

    changed = decompile._coalesce_segmented_word_store_statements(project, codegen)

    assert changed is False
    assert len(codegen.cfunc.statements.statements) == 2
    assert codegen.cfunc.statements.statements[0].lhs is lhs_cvar
    assert codegen.cfunc.statements.statements[1].lhs is next_lhs


def test_coalesce_segmented_word_store_statements_accepts_stable_ds_segment_const_pair_without_alias_identity(
    monkeypatch,
):
    project = SimpleNamespace(arch=SimpleNamespace(byte_width=8, bits=16, name="X86"))
    cfunc = SimpleNamespace(
        addr=0x10010,
        arg_list=(),
        sort_local_vars=lambda: None,
        unified_local_vars={},
        variables_in_use={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, next_idx=lambda _name: 0, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    low_addr_expr = object()
    high_addr_expr = object()
    low_lhs = object()
    high_lhs = object()
    rhs_low = structured_c.CConstant(0x12, SimTypeChar(False), codegen=codegen)
    rhs_high = structured_c.CConstant(0x34, SimTypeChar(False), codegen=codegen)
    word_rhs = structured_c.CConstant(0x3412, SimTypeShort(False), codegen=codegen)
    replacement_lhs = object()

    root = structured_c.CStatements(
        [
            structured_c.CAssignment(low_lhs, rhs_low, codegen=codegen),
            structured_c.CAssignment(high_lhs, rhs_high, codegen=codegen),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    monkeypatch.setattr(
        decompile,
        "_match_byte_store_addr_expr",
        lambda node: low_addr_expr if node is low_lhs else high_addr_expr if node is high_lhs else None,
    )
    monkeypatch.setattr(decompile, "_addr_exprs_are_byte_pair", lambda _low, _high, _project: True)
    monkeypatch.setattr(decompile, "_match_word_rhs_from_byte_pair", lambda _lo, _hi, _codegen, _project: word_rhs)
    monkeypatch.setattr(
        decompile,
        "describe_alias_storage",
        lambda _expr: SimpleNamespace(identity=None, can_join=lambda _other: False),
    )
    monkeypatch.setattr(
        decompile,
        "_classify_segmented_addr_expr",
        lambda expr, _project: _SegmentedAccess(
            kind="segment_const",
            seg_name="ds",
            linear=0x0BAA if expr is low_addr_expr else 0x0BAB,
            assoc_kind="const",
            addr_expr=expr,
        ),
    )
    monkeypatch.setattr(decompile, "_resolve_stack_cvar_from_addr_expr", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile, "_make_word_dereference_from_addr_expr", lambda _codegen, _project, _addr_expr: replacement_lhs
    )

    changed = decompile._coalesce_segmented_word_store_statements(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    replacement = codegen.cfunc.statements.statements[0]
    assert isinstance(replacement, structured_c.CAssignment)
    assert replacement.lhs is replacement_lhs
    assert replacement.rhs is word_rhs


def test_coalesce_segmented_word_store_statements_joins_indexed_runtime_ds_byte_pair(monkeypatch):
    from angr_platforms.X86_16.ir.core import MemSpace
    from angr_platforms.X86_16.widening import widening_rules

    project = SimpleNamespace(arch=SimpleNamespace(byte_width=8, bits=16, name="X86"))
    cfunc = SimpleNamespace(addr=0x10010)
    codegen = SimpleNamespace(
        cfunc=cfunc,
        project=project,
        next_ident=lambda name: f"{name}_0",
        next_node_idx=lambda: 0,
    )
    segment = object()
    low_offset = object()
    high_offset = object()
    low_lhs = structured_c.CFunctionCall("SEG_U8", None, [segment, low_offset], codegen=codegen)
    high_lhs = structured_c.CFunctionCall("SEG_U8", None, [segment, high_offset], codegen=codegen)
    low_rhs = structured_c.CConstant(0x400, SimTypeShort(False), codegen=codegen)
    high_rhs = structured_c.CConstant(4, SimTypeChar(False), codegen=codegen)
    root = structured_c.CStatements(
        [
            structured_c.CAssignment(low_lhs, low_rhs, codegen=codegen),
            structured_c.CAssignment(high_lhs, high_rhs, codegen=codegen),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    monkeypatch.setattr(
        widening_rules,
        "runtime_segment_access_offset_expr_8616",
        lambda _project, _codegen, access, *, expected_space, width, context: (
            low_offset
            if expected_space is MemSpace.DS and width == 1 and access is low_lhs
            else high_offset
            if expected_space is MemSpace.DS and width == 1 and access is high_lhs
            else None
        ),
    )
    monkeypatch.setattr(decompile, "_addr_exprs_are_byte_pair", lambda low, high, _project: (low, high) == (low_offset, high_offset))

    changed = decompile._coalesce_segmented_word_store_statements(project, codegen)

    assert changed is True
    assert len(root.statements) == 1
    replacement = root.statements[0]
    assert isinstance(replacement, structured_c.CAssignment)
    assert isinstance(replacement.lhs, structured_c.CFunctionCall)
    assert replacement.lhs.callee_target == "SEG_U16"
    assert tuple(replacement.lhs.args or ()) == (segment, low_offset)
    assert isinstance(replacement.rhs, structured_c.CConstant)
    assert replacement.rhs.value == 0x400


def test_coalesce_segmented_word_store_statements_refuses_over_associated_ds_pair(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(byte_width=8, bits=16, name="X86"))
    cfunc = SimpleNamespace(
        addr=0x10010,
        arg_list=(),
        sort_local_vars=lambda: None,
        unified_local_vars={},
        variables_in_use={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, next_idx=lambda _name: 0, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    low_addr_expr = object()
    high_addr_expr = object()
    low_lhs = object()
    high_lhs = object()
    word_rhs = structured_c.CConstant(0x3412, SimTypeShort(False), codegen=codegen)
    root = structured_c.CStatements(
        [
            structured_c.CAssignment(
                low_lhs,
                structured_c.CConstant(0x12, SimTypeChar(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CAssignment(
                high_lhs,
                structured_c.CConstant(0x34, SimTypeChar(False), codegen=codegen),
                codegen=codegen,
            ),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    monkeypatch.setattr(
        decompile,
        "_match_byte_store_addr_expr",
        lambda node: low_addr_expr if node is low_lhs else high_addr_expr if node is high_lhs else None,
    )
    monkeypatch.setattr(decompile, "_addr_exprs_are_byte_pair", lambda _low, _high, _project: True)
    monkeypatch.setattr(decompile, "_match_word_rhs_from_byte_pair", lambda _lo, _hi, _codegen, _project: word_rhs)
    monkeypatch.setattr(
        decompile,
        "describe_alias_storage",
        lambda _expr: SimpleNamespace(identity=None, can_join=lambda _other: False),
    )
    monkeypatch.setattr(
        decompile,
        "_classify_segmented_addr_expr",
        lambda expr, _project: SimpleNamespace(
            kind="segment_const",
            seg_name="ds",
            linear=0x0BAA if expr is low_addr_expr else 0x0BAB,
            assoc_kind="over",
            allows_object_rewrite=lambda: False,
        ),
    )

    changed = decompile._coalesce_segmented_word_store_statements(project, codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == list(root.statements)


def test_coalesce_segmented_word_store_statements_refuses_cross_segment_byte_pair(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(byte_width=8, bits=16, name="X86"))
    cfunc = SimpleNamespace(
        addr=0x10010,
        arg_list=(),
        sort_local_vars=lambda: None,
        unified_local_vars={},
        variables_in_use={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, next_idx=lambda _name: 0, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    low_addr_expr = object()
    high_addr_expr = object()
    low_lhs = object()
    high_lhs = object()
    word_rhs = structured_c.CConstant(0x3412, SimTypeShort(False), codegen=codegen)
    root = structured_c.CStatements(
        [
            structured_c.CAssignment(
                low_lhs,
                structured_c.CConstant(0x12, SimTypeChar(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CAssignment(
                high_lhs,
                structured_c.CConstant(0x34, SimTypeChar(False), codegen=codegen),
                codegen=codegen,
            ),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    monkeypatch.setattr(
        decompile,
        "_match_byte_store_addr_expr",
        lambda node: low_addr_expr if node is low_lhs else high_addr_expr if node is high_lhs else None,
    )
    monkeypatch.setattr(decompile, "_addr_exprs_are_byte_pair", lambda _low, _high, _project: True)
    monkeypatch.setattr(decompile, "_match_word_rhs_from_byte_pair", lambda _lo, _hi, _codegen, _project: word_rhs)
    monkeypatch.setattr(
        decompile,
        "describe_alias_storage",
        lambda _expr: SimpleNamespace(identity=None, can_join=lambda _other: False),
    )
    monkeypatch.setattr(
        decompile,
        "_classify_segmented_addr_expr",
        lambda expr, _project: SimpleNamespace(
            kind="segment_const",
            seg_name="ds" if expr is low_addr_expr else "es",
            linear=0x0BAA if expr is low_addr_expr else 0x0BAB,
            assoc_kind="const",
            allows_object_rewrite=lambda: True,
        ),
    )

    changed = decompile._coalesce_segmented_word_store_statements(project, codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == list(root.statements)


def test_match_byte_store_addr_expr_accepts_word_typed_dereference_split_store():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = SimpleNamespace(project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    addr_expr = structured_c.CBinaryOp(
        "Add",
        structured_c.CConstant(0x2000, SimTypeShort(False), codegen=codegen),
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    deref = decompile._make_word_dereference_from_addr_expr(codegen, project, addr_expr)

    assert decompile._match_byte_store_addr_expr(deref) is addr_expr


def test_match_byte_load_addr_expr_accepts_cast_wrapped_byte_dereference():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = SimpleNamespace(project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    addr_expr = structured_c.CVariable(
        SimRegisterVariable(10, 2, name="bp"),
        variable_type=decompile.SimTypePointer(SimTypeChar(False)).with_arch(project.arch),
        codegen=codegen,
    )
    deref = structured_c.CUnaryOp(
        "Dereference",
        addr_expr,
        codegen=codegen,
    )
    casted = structured_c.CTypeCast(None, SimTypeChar(False), deref, codegen=codegen)

    assert decompile._match_byte_load_addr_expr(casted) is addr_expr


def test_coalesce_segmented_word_store_statements_rewrites_word_typed_split_store_inside_while_loop(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(
        addr=0x10010,
        arg_list=(),
        sort_local_vars=lambda: None,
        unified_local_vars={},
        variables_in_use={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, next_idx=lambda _name: 0, project=project, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    low_addr_expr = structured_c.CBinaryOp(
        "Add",
        structured_c.CConstant(0x2000, SimTypeShort(False), codegen=codegen),
        structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    high_addr_expr = structured_c.CBinaryOp(
        "Add",
        structured_c.CConstant(0x2000, SimTypeShort(False), codegen=codegen),
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    low_lhs = decompile._make_word_dereference_from_addr_expr(codegen, project, low_addr_expr)
    high_lhs = decompile._make_word_dereference_from_addr_expr(codegen, project, high_addr_expr)
    rhs_low = structured_c.CConstant(0x12, SimTypeChar(False), codegen=codegen)
    rhs_high = structured_c.CConstant(0x34, SimTypeChar(False), codegen=codegen)
    word_rhs = structured_c.CConstant(0x3412, SimTypeShort(False), codegen=codegen)
    replacement_lhs = object()

    loop_body = structured_c.CStatements(
        [
            structured_c.CAssignment(low_lhs, rhs_low, codegen=codegen),
            structured_c.CAssignment(high_lhs, rhs_high, codegen=codegen),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    loop = structured_c.CWhileLoop(
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        loop_body,
        codegen=codegen,
    )
    cfunc.statements = structured_c.CStatements([loop], addr=0x10010, codegen=codegen)

    monkeypatch.setattr(decompile, "_addr_exprs_are_byte_pair", lambda _low, _high, _project: True)
    monkeypatch.setattr(decompile, "_match_word_rhs_from_byte_pair", lambda _lo, _hi, _codegen, _project: word_rhs)
    monkeypatch.setattr(
        decompile,
        "describe_alias_storage",
        lambda _expr: SimpleNamespace(identity=None, can_join=lambda _other: False),
    )
    monkeypatch.setattr(
        decompile,
        "_classify_segmented_addr_expr",
        lambda expr, _project: _SegmentedAccess(
            kind="segment_const",
            seg_name="ds",
            assoc_kind="const",
            linear=0x2000 if expr is low_addr_expr else 0x2001,
            addr_expr=expr,
        ),
    )
    monkeypatch.setattr(decompile, "_resolve_stack_cvar_from_addr_expr", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile, "_make_word_dereference_from_addr_expr", lambda _codegen, _project, _addr_expr: replacement_lhs
    )

    changed = decompile._coalesce_segmented_word_store_statements(project, codegen)

    assert changed is True
    rewritten_loop = codegen.cfunc.statements.statements[0]
    assert isinstance(rewritten_loop, structured_c.CWhileLoop)
    assert len(rewritten_loop.body.statements) == 1
    replacement = rewritten_loop.body.statements[0]
    assert isinstance(replacement, structured_c.CAssignment)
    assert replacement.lhs is replacement_lhs
    assert replacement.rhs is word_rhs


def test_coalesce_segmented_word_store_statements_folds_preceding_byte_load_pair(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(
        addr=0x10010,
        arg_list=(),
        sort_local_vars=lambda: None,
        unified_local_vars={},
        variables_in_use={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, next_idx=lambda _name: 0, project=project, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    low_addr_expr = object()
    high_addr_expr = object()
    low_load_rhs = object()
    high_load_rhs = object()
    low_store_lhs = object()
    high_store_lhs = object()
    low_tmp_var = SimRegisterVariable(15, 1, name="tmp_15")
    high_tmp_var = SimRegisterVariable(17, 1, name="tmp_17")
    low_tmp_def = structured_c.CVariable(low_tmp_var, variable_type=SimTypeChar(False), codegen=codegen)
    high_tmp_def = structured_c.CVariable(high_tmp_var, variable_type=SimTypeChar(False), codegen=codegen)
    low_tmp_use = structured_c.CVariable(low_tmp_var, variable_type=SimTypeChar(False), codegen=codegen)
    high_tmp_use = structured_c.CVariable(high_tmp_var, variable_type=SimTypeChar(False), codegen=codegen)
    local_word = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2", region=0x10010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    loaded_pair = structured_c.CBinaryOp(
        "Or",
        low_tmp_use,
        structured_c.CBinaryOp(
            "Shl",
            high_tmp_use,
            structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    low_store_rhs = structured_c.CBinaryOp(
        "Add",
        loaded_pair,
        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    high_store_rhs = object()
    root = structured_c.CStatements(
        [
            structured_c.CAssignment(low_tmp_def, low_load_rhs, codegen=codegen),
            structured_c.CAssignment(high_tmp_def, high_load_rhs, codegen=codegen),
            structured_c.CAssignment(low_store_lhs, low_store_rhs, codegen=codegen),
            structured_c.CAssignment(high_store_lhs, high_store_rhs, codegen=codegen),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    monkeypatch.setattr(
        decompile,
        "_match_byte_load_addr_expr",
        lambda node: low_addr_expr if node is low_load_rhs else high_addr_expr if node is high_load_rhs else None,
    )
    monkeypatch.setattr(
        decompile,
        "_match_byte_store_addr_expr",
        lambda node: low_addr_expr if node is low_store_lhs else high_addr_expr if node is high_store_lhs else None,
    )
    monkeypatch.setattr(decompile, "_addr_exprs_are_byte_pair", lambda _low, _high, _project: True)
    monkeypatch.setattr(decompile, "_same_c_expression", lambda lhs, rhs: lhs is rhs)
    monkeypatch.setattr(
        decompile, "_match_shift_right_8_expr", lambda node: low_store_rhs if node is high_store_rhs else None
    )
    monkeypatch.setattr(
        decompile,
        "_classify_segmented_addr_expr",
        lambda expr, _project: SimpleNamespace(kind="stack") if expr is low_addr_expr else None,
    )
    monkeypatch.setattr(decompile, "_resolve_stack_cvar_from_addr_expr", lambda *_args, **_kwargs: local_word)

    changed = decompile._coalesce_segmented_word_store_statements(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    replacement = codegen.cfunc.statements.statements[0]
    assert isinstance(replacement, structured_c.CAssignment)
    assert replacement.lhs is local_word
    assert isinstance(replacement.rhs, structured_c.CBinaryOp)
    assert replacement.rhs.op == "Add"
    assert replacement.rhs.lhs is local_word
    assert replacement.rhs.rhs.value == 2


def test_coalesce_segmented_word_store_statements_uses_byte_lhs_for_wide_typed_load(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(
        addr=0x10010,
        arg_list=(),
        sort_local_vars=lambda: None,
        unified_local_vars={},
        variables_in_use={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, next_idx=lambda _name: 0, project=project, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    base_addr = structured_c.CVariable(SimRegisterVariable(10, 2, name="bp"), codegen=codegen)
    low_addr_expr = base_addr
    high_addr_expr = structured_c.CBinaryOp(
        "Add",
        base_addr,
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    low_load_rhs = structured_c.CUnaryOp("Dereference", low_addr_expr, codegen=codegen)
    high_load_rhs = structured_c.CUnaryOp("Dereference", high_addr_expr, codegen=codegen)
    low_store_lhs = object()
    high_store_lhs = object()
    low_tmp_var = SimRegisterVariable(15, 1, name="tmp_15")
    high_tmp_var = SimRegisterVariable(17, 1, name="tmp_17")
    low_tmp_def = structured_c.CVariable(low_tmp_var, variable_type=SimTypeChar(False), codegen=codegen)
    high_tmp_def = structured_c.CVariable(high_tmp_var, variable_type=SimTypeChar(False), codegen=codegen)
    low_tmp_use = structured_c.CVariable(low_tmp_var, variable_type=SimTypeChar(False), codegen=codegen)
    high_tmp_use = structured_c.CVariable(high_tmp_var, variable_type=SimTypeChar(False), codegen=codegen)
    local_word = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2", region=0x10010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    loaded_pair = structured_c.CBinaryOp(
        "Or",
        low_tmp_use,
        structured_c.CBinaryOp(
            "Shl",
            high_tmp_use,
            structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    low_store_rhs = structured_c.CBinaryOp(
        "Add",
        loaded_pair,
        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    high_store_rhs = object()
    root = structured_c.CStatements(
        [
            structured_c.CAssignment(low_tmp_def, low_load_rhs, codegen=codegen),
            structured_c.CAssignment(high_tmp_def, high_load_rhs, codegen=codegen),
            structured_c.CAssignment(low_store_lhs, low_store_rhs, codegen=codegen),
            structured_c.CAssignment(high_store_lhs, high_store_rhs, codegen=codegen),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    monkeypatch.setattr(decompile, "_match_byte_load_addr_expr", lambda _node: None)
    monkeypatch.setattr(
        decompile,
        "_match_byte_store_addr_expr",
        lambda node: low_addr_expr if node is low_store_lhs else high_addr_expr if node is high_store_lhs else None,
    )
    monkeypatch.setattr(decompile, "_addr_exprs_are_byte_pair", lambda _low, _high, _project: True)
    monkeypatch.setattr(decompile, "_same_c_expression", lambda lhs, rhs: lhs is rhs)
    monkeypatch.setattr(
        decompile, "_match_shift_right_8_expr", lambda node: low_store_rhs if node is high_store_rhs else None
    )
    monkeypatch.setattr(
        decompile,
        "_classify_segmented_addr_expr",
        lambda expr, _project: SimpleNamespace(kind="stack") if expr is low_addr_expr else None,
    )
    monkeypatch.setattr(decompile, "_resolve_stack_cvar_from_addr_expr", lambda *_args, **_kwargs: local_word)

    changed = decompile._coalesce_segmented_word_store_statements(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    replacement = codegen.cfunc.statements.statements[0]
    assert isinstance(replacement, structured_c.CAssignment)
    assert replacement.lhs is local_word
    assert isinstance(replacement.rhs, structured_c.CBinaryOp)
    assert replacement.rhs.op == "Add"
    assert replacement.rhs.lhs is local_word


def test_coalesce_segmented_word_store_statements_folds_stack_word_byte_carriers(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(
        addr=0x10010,
        arg_list=(),
        sort_local_vars=lambda: None,
        unified_local_vars={},
        variables_in_use={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, next_idx=lambda _name: 0, project=project, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    word_var = SimStackVariable(-2, 2, base="bp", name="total", region=0x10010)
    word_def = structured_c.CVariable(word_var, variable_type=SimTypeShort(False), codegen=codegen)
    word_use = structured_c.CVariable(word_var, variable_type=SimTypeShort(False), codegen=codegen)
    low_tmp_var = SimRegisterVariable(15, 1, name="tmp_15")
    high_tmp_var = SimRegisterVariable(17, 1, name="tmp_17")
    low_tmp_def = structured_c.CVariable(low_tmp_var, variable_type=SimTypeChar(False), codegen=codegen)
    high_tmp_def = structured_c.CVariable(high_tmp_var, variable_type=SimTypeChar(False), codegen=codegen)
    low_tmp_use = structured_c.CVariable(low_tmp_var, variable_type=SimTypeChar(False), codegen=codegen)
    high_tmp_use = structured_c.CVariable(high_tmp_var, variable_type=SimTypeChar(False), codegen=codegen)
    loaded_pair = structured_c.CBinaryOp(
        "Or",
        low_tmp_use,
        structured_c.CBinaryOp(
            "Shl",
            high_tmp_use,
            structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    recombined = structured_c.CBinaryOp(
        "Add",
        loaded_pair,
        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    root = structured_c.CStatements(
        [
            structured_c.CAssignment(low_tmp_def, word_use, codegen=codegen),
            structured_c.CAssignment(high_tmp_def, word_use, codegen=codegen),
            structured_c.CAssignment(word_def, recombined, codegen=codegen),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    monkeypatch.setattr(decompile, "_same_c_expression", lambda lhs, rhs: lhs is rhs)

    changed = decompile._coalesce_segmented_word_store_statements(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    replacement = codegen.cfunc.statements.statements[0]
    assert isinstance(replacement, structured_c.CAssignment)
    assert replacement.lhs is word_def
    assert isinstance(replacement.rhs, structured_c.CBinaryOp)
    assert replacement.rhs.op == "Add"
    assert replacement.rhs.lhs is word_use
    assert replacement.rhs.rhs.value == 2


def test_coalesce_segmented_word_load_expressions_preserves_existing_dereference_evidence(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(addr=0x10010)
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    addr_var = SimRegisterVariable(0, 2)
    addr_cvar = structured_c.CVariable(addr_var, codegen=codegen)
    low_addr_expr = addr_cvar
    high_addr_expr = structured_c.CBinaryOp(
        "Add",
        addr_cvar,
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    pair_expr = structured_c.CBinaryOp(
        "Or",
        structured_c.CConstant(0x12, SimTypeChar(False), codegen=codegen),
        structured_c.CConstant(0x3400, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    root = structured_c.CStatements(
        [
            structured_c.CAssignment(
                structured_c.CVariable(SimRegisterVariable(2, 2), codegen=codegen),
                pair_expr,
                codegen=codegen,
            ),
            structured_c.CAssignment(
                structured_c.CVariable(SimRegisterVariable(4, 2), codegen=codegen),
                structured_c.CUnaryOp("Dereference", addr_cvar, codegen=codegen),
                codegen=codegen,
            ),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    alias_facts = SimpleNamespace(identity=object(), can_join=lambda _other: True, needs_synthesis=lambda: False)

    monkeypatch.setattr(
        decompile,
        "_match_byte_load_addr_expr",
        lambda node: low_addr_expr if node is root.statements[0].rhs.lhs else None,
    )
    monkeypatch.setattr(
        decompile,
        "_match_shifted_high_byte_addr_expr",
        lambda node: high_addr_expr if node is root.statements[0].rhs.rhs else None,
    )
    monkeypatch.setattr(decompile, "describe_alias_storage", lambda _expr: alias_facts)
    monkeypatch.setattr(decompile, "_addr_exprs_are_byte_pair", lambda _low, _high, _project: True)
    monkeypatch.setattr(decompile, "_resolve_stack_cvar_from_addr_expr", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_classify_segmented_addr_expr",
        lambda _expr, _project: SimpleNamespace(kind="segment_const"),
    )
    monkeypatch.setattr(
        decompile,
        "_make_word_dereference_from_addr_expr",
        lambda *_args, **_kwargs: structured_c.CConstant(0x9999, SimTypeShort(False), codegen=codegen),
    )

    changed = decompile._coalesce_segmented_word_load_expressions(project, codegen)

    assert changed is False
    assert codegen.cfunc.statements.statements[0].rhs is pair_expr


def test_simplify_nested_mk_fp_calls_collapses_only_zero_offset_forms():
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(addr=0x10010)
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    inner_seg = structured_c.CConstant(0x40, SimTypeShort(False), codegen=codegen)
    inner_off = structured_c.CConstant(0x17, SimTypeShort(False), codegen=codegen)
    nested = structured_c.CFunctionCall(
        "MK_FP",
        None,
        [
            structured_c.CFunctionCall("MK_FP", None, [inner_seg, inner_off], codegen=codegen),
            structured_c.CFunctionCall(
                "MK_FP",
                None,
                [
                    structured_c.CConstant(0x1234, SimTypeShort(False), codegen=codegen),
                    structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
                ],
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )
    root = structured_c.CStatements([nested], addr=0x10010, codegen=codegen)
    cfunc.statements = root

    changed = decompile._simplify_nested_mk_fp_calls(codegen)

    assert changed is True
    rewritten = codegen.cfunc.statements.statements[0]
    assert isinstance(rewritten, structured_c.CFunctionCall)
    assert rewritten.callee_target == "MK_FP"
    assert rewritten.args[0] is inner_seg
    assert rewritten.args[1] is inner_off


def test_simplify_nested_mk_fp_calls_keeps_nonzero_inner_offset():
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(addr=0x10010)
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    nested = structured_c.CFunctionCall(
        "MK_FP",
        None,
        [
            structured_c.CConstant(0x40, SimTypeShort(False), codegen=codegen),
            structured_c.CFunctionCall(
                "MK_FP",
                None,
                [
                    structured_c.CConstant(0x1234, SimTypeShort(False), codegen=codegen),
                    structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                ],
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )
    root = structured_c.CStatements([nested], addr=0x10010, codegen=codegen)
    cfunc.statements = root

    changed = decompile._simplify_nested_mk_fp_calls(codegen)

    assert changed is False
    assert codegen.cfunc.statements.statements[0] is nested


def test_attach_ss_stack_variables_preserves_far_pointer_stack_local_width(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(byte_width=8, name="X86"))
    cfunc = SimpleNamespace(
        addr=0x10010,
        variables_in_use={},
        unified_local_vars={},
        arg_list=(),
        sort_local_vars=lambda: None,
    )
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    promoted_var = SimStackVariable(2, 1, base="bp", name="s_2", region=0x10010)
    promoted_cvar = structured_c.CVariable(promoted_var, codegen=codegen)
    cfunc.variables_in_use[promoted_var] = promoted_cvar
    cfunc.unified_local_vars[promoted_var] = {(promoted_cvar, SimTypeShort(False))}

    match_var = SimStackVariable(0, 1, base="bp", name="s_0", region=0x10010)
    node = structured_c.CAssignment(
        promoted_cvar,
        structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    class _FarPointerType:
        size = 32

        def with_arch(self, _arch):
            return self

    node.type = _FarPointerType()
    cfunc.statements = structured_c.CStatements([node], addr=0x10010, codegen=codegen)

    monkeypatch.setattr(
        decompile,
        "_match_ss_stack_reference",
        lambda _node, _project: (match_var, promoted_cvar, 2),
    )

    changed = decompile._attach_ss_stack_variables(project, codegen)

    assert changed is True
    assert promoted_var.size == 4
    assert cfunc.variables_in_use[promoted_var] is promoted_cvar
    assert promoted_cvar.variable.size == 4
    assert isinstance(cfunc.statements.statements[0], structured_c.CVariable)
    assert cfunc.statements.statements[0] is promoted_cvar


def test_attach_ss_stack_variables_does_not_reuse_covering_stack_slot_for_far_pointer(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(byte_width=8, name="X86"))
    cfunc = SimpleNamespace(
        addr=0x10010,
        variables_in_use={},
        unified_local_vars={},
        arg_list=(),
        sort_local_vars=lambda: None,
    )
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    covering_var = SimStackVariable(0, 8, base="bp", name="cover", region=0x10010)
    covering_cvar = structured_c.CVariable(covering_var, codegen=codegen)
    cfunc.variables_in_use[covering_var] = covering_cvar
    cfunc.unified_local_vars[covering_var] = {(covering_cvar, SimTypeShort(False))}

    match_var = SimStackVariable(0, 1, base="bp", name="s_0", region=0x10010)
    node = structured_c.CAssignment(
        covering_cvar,
        structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    class _FarPointerType:
        size = 32

        def with_arch(self, _arch):
            return self

    node.type = _FarPointerType()
    cfunc.statements = structured_c.CStatements([node], addr=0x10010, codegen=codegen)

    monkeypatch.setattr(
        decompile,
        "_match_ss_stack_reference",
        lambda _node, _project: (match_var, covering_cvar, 2),
    )

    changed = decompile._attach_ss_stack_variables(project, codegen)

    assert changed is True
    replacement = cfunc.statements.statements[0]
    assert isinstance(replacement, structured_c.CVariable)
    assert replacement is not covering_cvar
    assert isinstance(replacement.variable, SimStackVariable)
    assert replacement.variable.offset == 2


def test_rewrite_ss_stack_byte_offsets_refuses_large_unsigned_addr_expr(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(addr=0x10010, project=SimpleNamespace(loader=None))
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    ptr_type = decompile.SimTypePointer(SimTypeChar(False)).with_arch(project.arch)
    node = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CTypeCast(
            None,
            ptr_type,
            structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    root = structured_c.CStatements([node], addr=0x10010, codegen=codegen)
    cfunc.statements = root

    large_addr = structured_c.CBinaryOp(
        "Add",
        structured_c.CConstant(0x9000, SimTypeShort(False), codegen=codegen),
        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    monkeypatch.setattr(
        decompile,
        "_classify_segmented_dereference",
        lambda _node, _project: SimpleNamespace(
            kind="segment_const",
            seg_name="ss",
            extra_offset=2,
            addr_expr=large_addr,
            cvar=None,
        ),
    )
    monkeypatch.setattr(decompile, "_strip_segment_scale_from_addr_expr", lambda _expr, _project: large_addr)

    changed = decompile._rewrite_ss_stack_byte_offsets(project, codegen)

    assert changed is False
    assert codegen.cfunc.statements.statements[0] is node


def test_coalesce_direct_ss_local_word_statements_refuses_region_mismatch(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(byte_width=8, name="X86"))
    cfunc = SimpleNamespace(
        addr=0x10010,
        variables_in_use={},
        unified_local_vars={},
        arg_list=(),
        sort_local_vars=lambda: None,
    )
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    low_var = SimStackVariable(0, 1, base="bp", name="s_0", region=0x10010)
    low_cvar = structured_c.CVariable(low_var, codegen=codegen)
    target_var = SimStackVariable(0, 1, base="bp", name="s_0_other", region=0x20020)
    target_cvar = structured_c.CVariable(target_var, codegen=codegen)

    root = structured_c.CStatements(
        [
            structured_c.CAssignment(
                low_cvar,
                structured_c.CVariable(low_var, codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CAssignment(
                structured_c.CVariable(target_var, codegen=codegen),
                structured_c.CBinaryOp(
                    "Shr",
                    structured_c.CVariable(low_var, codegen=codegen),
                    structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    monkeypatch.setattr(
        decompile,
        "_match_ss_local_plus_const",
        lambda node, _project: (target_cvar, 1) if node is root.statements[1].lhs else None,
    )
    monkeypatch.setattr(
        decompile,
        "_match_shift_right_8_expr",
        lambda node: low_cvar if node is root.statements[1].rhs else None,
    )

    changed = decompile._coalesce_direct_ss_local_word_statements(project, codegen)

    assert changed is False
    assert len(cfunc.statements.statements) == 2
    assert low_var.size == 1


def test_coalesce_direct_ss_local_word_statements_joins_alias_derived_high_byte(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(byte_width=8, name="X86"))
    cfunc = SimpleNamespace(
        addr=0x10010,
        variables_in_use={},
        unified_local_vars={},
        arg_list=(),
        sort_local_vars=lambda: None,
    )
    codegen = SimpleNamespace(
        cfunc=cfunc,
        project=project,
        next_idx=lambda _name: 0,
        cstyle_null_cmp=False,
        next_ident=lambda name: f"{name}_0",
        next_node_idx=lambda: 0,
    )

    low_var = SimStackVariable(-2, 1, base="bp", name="local_2", region=0x10010)
    low_cvar = structured_c.CVariable(low_var, codegen=codegen)
    address_base_var = SimStackVariable(0, 2, base="bp", name="v1", region=0x10010)
    address_base_cvar = structured_c.CVariable(address_base_var, codegen=codegen)
    source = structured_c.CConstant(2, SimTypeShort(False), codegen=codegen)
    high_lhs = object()
    high_rhs = structured_c.CBinaryOp(
        "Shr",
        source,
        structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    root = structured_c.CStatements(
        [
            structured_c.CAssignment(low_cvar, source, codegen=codegen),
            structured_c.CAssignment(high_lhs, high_rhs, codegen=codegen),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    monkeypatch.setattr(
        decompile,
        "_match_ss_local_plus_const",
        lambda node, _project: (address_base_cvar, -1) if node is high_lhs else None,
    )
    monkeypatch.setattr(
        decompile,
        "_match_shift_right_8_expr",
        lambda node: source if node is high_rhs else None,
    )

    changed = decompile._coalesce_direct_ss_local_word_statements(project, codegen)

    assert changed is True
    assert len(cfunc.statements.statements) == 1
    replacement = cfunc.statements.statements[0]
    assert isinstance(replacement, structured_c.CAssignment)
    assert replacement.lhs is low_cvar
    assert replacement.rhs is source
    assert low_var.size == 2


def test_coalesce_direct_ss_local_word_statements_rewrites_stack_address_split_store_inside_while_loop(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(byte_width=8, name="X86"))
    cfunc = SimpleNamespace(
        addr=0x10010,
        variables_in_use={},
        unified_local_vars={},
        arg_list=(),
        sort_local_vars=lambda: None,
    )
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    low_var = SimStackVariable(0, 1, base="bp", name="s_0", region=0x10010)
    low_cvar = structured_c.CVariable(low_var, codegen=codegen)
    word_var = SimStackVariable(0, 2, base="bp", name="local_0", region=0x10010)
    word_cvar = structured_c.CVariable(word_var, codegen=codegen)
    low_addr_expr = object()
    high_addr_expr = object()
    low_lhs = object()
    high_lhs = object()

    loop_body = structured_c.CStatements(
        [
            structured_c.CAssignment(
                low_lhs,
                low_cvar,
                codegen=codegen,
            ),
            structured_c.CAssignment(
                high_lhs,
                structured_c.CBinaryOp(
                    "Shr",
                    low_cvar,
                    structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    loop = structured_c.CWhileLoop(
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        loop_body,
        codegen=codegen,
    )
    cfunc.statements = structured_c.CStatements([loop], addr=0x10010, codegen=codegen)

    monkeypatch.setattr(
        decompile,
        "_match_byte_store_addr_expr",
        lambda node: low_addr_expr if node is low_lhs else high_addr_expr if node is high_lhs else None,
    )
    monkeypatch.setattr(decompile, "_addr_exprs_are_byte_pair", lambda _low, _high, _project: True)
    monkeypatch.setattr(
        decompile,
        "_match_shift_right_8_expr",
        lambda node: low_cvar if node is loop_body.statements[1].rhs else None,
    )
    monkeypatch.setattr(
        decompile,
        "_resolve_stack_cvar_from_addr_expr",
        lambda _project, _codegen, expr: word_cvar if expr is low_addr_expr else None,
    )
    monkeypatch.setattr(decompile, "_canonicalize_stack_cvar_expr", lambda expr, _codegen: expr)

    changed = decompile._coalesce_direct_ss_local_word_statements(project, codegen)

    assert changed is True
    rewritten_loop = cfunc.statements.statements[0]
    assert isinstance(rewritten_loop, structured_c.CWhileLoop)
    assert len(rewritten_loop.body.statements) == 1
    replacement = rewritten_loop.body.statements[0]
    assert isinstance(replacement, structured_c.CAssignment)
    assert replacement.lhs is word_cvar
    assert replacement.rhs is low_cvar


def test_coalesce_direct_ss_local_word_statements_refuses_nonadjacent_stack_address_pair(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(byte_width=8, name="X86"))
    cfunc = SimpleNamespace(
        addr=0x10010,
        variables_in_use={},
        unified_local_vars={},
        arg_list=(),
        sort_local_vars=lambda: None,
    )
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    low_var = SimStackVariable(0, 1, base="bp", name="s_0", region=0x10010)
    low_cvar = structured_c.CVariable(low_var, codegen=codegen)
    low_addr_expr = object()
    high_addr_expr = object()
    low_lhs = object()
    high_lhs = object()

    root = structured_c.CStatements(
        [
            structured_c.CAssignment(low_lhs, low_cvar, codegen=codegen),
            structured_c.CAssignment(
                high_lhs,
                structured_c.CBinaryOp(
                    "Shr",
                    low_cvar,
                    structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    monkeypatch.setattr(
        decompile,
        "_match_byte_store_addr_expr",
        lambda node: low_addr_expr if node is low_lhs else high_addr_expr if node is high_lhs else None,
    )
    monkeypatch.setattr(decompile, "_addr_exprs_are_byte_pair", lambda _low, _high, _project: False)
    monkeypatch.setattr(
        decompile,
        "_match_shift_right_8_expr",
        lambda node: low_cvar if node is root.statements[1].rhs else None,
    )

    changed = decompile._coalesce_direct_ss_local_word_statements(project, codegen)

    assert changed is False
    assert len(cfunc.statements.statements) == 2
    assert cfunc.statements.statements[0].lhs is low_lhs
    assert cfunc.statements.statements[1].lhs is high_lhs


def test_coalesce_far_pointer_stack_expressions_avoids_byte_local_alias_for_far_pointer_store(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(byte_width=8, name="X86"))
    cfunc = SimpleNamespace(
        addr=0x10010,
        variables_in_use={},
        unified_local_vars={},
        arg_list=(),
        sort_local_vars=lambda: None,
    )
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    byte_var = SimStackVariable(0, 1, base="bp", name="s_0", region=0x10010)
    byte_cvar = structured_c.CVariable(byte_var, codegen=codegen)
    store_var = SimStackVariable(2, 1, base="bp", name="s_2", region=0x10010)
    store_cvar = structured_c.CVariable(store_var, codegen=codegen)
    out_var = SimStackVariable(4, 1, base="bp", name="s_4", region=0x10010)
    out_cvar = structured_c.CVariable(out_var, codegen=codegen)

    cfunc.variables_in_use[byte_var] = byte_cvar
    cfunc.variables_in_use[store_var] = store_cvar
    cfunc.variables_in_use[out_var] = out_cvar
    cfunc.unified_local_vars[byte_var] = {(byte_cvar, SimTypeShort(False))}
    cfunc.unified_local_vars[store_var] = {(store_cvar, SimTypeShort(False))}
    cfunc.unified_local_vars[out_var] = {(out_cvar, SimTypeShort(False))}

    root = structured_c.CStatements(
        [
            structured_c.CAssignment(
                store_cvar,
                structured_c.CConstant(7, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CAssignment(
                out_cvar,
                structured_c.CBinaryOp(
                    "Add",
                    store_cvar,
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    project._inertia_access_traits = {
        cfunc.addr: {
            "base_const": {
                ("ss", ("stack", "bp", 2), 2, 2, 1): 1,
            },
            "base_stride": {},
            "repeated_offsets": {},
            "repeated_offset_widths": {},
            "base_stride_widths": {},
            "member_evidence": {},
            "array_evidence": {},
        }
    }

    monkeypatch.setattr(
        decompile,
        "describe_alias_storage",
        lambda _expr: SimpleNamespace(identity=object(), can_join=lambda _other: True, needs_synthesis=lambda: False),
    )
    decompile._coalesce_far_pointer_stack_expressions(project, codegen)

    rhs = cfunc.statements.statements[1].rhs
    assert isinstance(rhs, structured_c.CFunctionCall)
    assert rhs.callee_target == "MK_FP"
    assert not any(isinstance(arg, structured_c.CVariable) and arg.variable is store_var for arg in rhs.args)


def test_coalesce_cod_word_global_loads_refuses_stable_member_hint(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(byte_width=8, name="X86"))
    cfunc = SimpleNamespace(
        addr=0x10010, variables_in_use={}, unified_local_vars={}, arg_list=(), sort_local_vars=lambda: None
    )
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    root = structured_c.CStatements(
        [
            structured_c.CAssignment(
                structured_c.CVariable(SimStackVariable(0, 2, base="bp", name="s_0", region=0x10010), codegen=codegen),
                structured_c.CBinaryOp(
                    "Or",
                    structured_c.CVariable(SimMemoryVariable(0x200, 1, name="g_200"), codegen=codegen),
                    structured_c.CBinaryOp(
                        "Mul",
                        structured_c.CVariable(SimMemoryVariable(0x201, 1, name="g_201"), codegen=codegen),
                        structured_c.CConstant(0x100, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    project._inertia_access_traits = {
        cfunc.addr: {
            "member_evidence": {
                (("mem", 0x200), 0, 2): 1,
            },
            "base_const": {},
            "base_stride": {},
            "repeated_offsets": {},
            "repeated_offset_widths": {},
            "base_stride_widths": {},
            "array_evidence": {},
        }
    }

    changed = decompile._coalesce_cod_word_global_loads(project, codegen, {0x200: ("table_word", 2)})

    assert changed is False
    rhs = cfunc.statements.statements[0].rhs
    assert isinstance(rhs, structured_c.CBinaryOp)
    assert rhs.op == "Or"


def test_prune_unused_unnamed_memory_declarations_keeps_only_used_globals():
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(
        addr=0x10010, variables_in_use={}, unified_local_vars={}, arg_list=(), sort_local_vars=lambda: None
    )
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    used_var = SimMemoryVariable(0x200, 1, name="g_200", region=0x10010)
    dead_var = SimMemoryVariable(0x201, 1, name="g_201", region=0x10010)
    used_cvar = structured_c.CVariable(used_var, codegen=codegen)
    dead_cvar = structured_c.CVariable(dead_var, codegen=codegen)
    cfunc.variables_in_use = {
        used_var: used_cvar,
        dead_var: dead_cvar,
    }
    cfunc.unified_local_vars = {
        used_var: {(used_cvar, SimTypeChar(False))},
        dead_var: {(dead_cvar, SimTypeChar(False))},
    }
    cfunc.statements = structured_c.CStatements(
        [
            structured_c.CAssignment(
                structured_c.CVariable(SimStackVariable(0, 1, base="bp", name="s_0", region=0x10010), codegen=codegen),
                used_cvar,
                codegen=codegen,
            )
        ],
        addr=0x10010,
        codegen=codegen,
    )

    changed = decompile._prune_unused_unnamed_memory_declarations(codegen)

    assert changed is True
    assert used_var in cfunc.variables_in_use
    assert dead_var not in cfunc.variables_in_use
    assert used_var in cfunc.unified_local_vars
    assert dead_var not in cfunc.unified_local_vars


def test_repro_decompiler_boundary_reports_blocked_narrow_stack_object(monkeypatch, tmp_path, capsys):
    spec = importlib.util.spec_from_file_location(
        "repro_decompiler_boundary", REPO_ROOT / "scripts" / "repro_decompiler_boundary.py"
    )
    assert spec is not None
    assert spec.loader is not None
    boundary = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(boundary)

    binary = tmp_path / "LIFE2.EXE"
    binary.write_bytes(b"MZ")

    stack_vars = [
        SimStackVariable(-2, 1, base="bp", name="s_2", region=0x1157C),
        SimStackVariable(0, 1, base="bp", name="s_0", region=0x1157C),
        SimStackVariable(2, 2, base="bp", name="ret_addr", region=0x1157C),
    ]

    class _FakeVariableManager:
        def get_variables(self):
            return list(stack_vars)

    fake_manager = _FakeVariableManager()
    fake_registry = SimpleNamespace(get_function_manager=lambda _addr: fake_manager)
    fake_clinic = SimpleNamespace(variable_kb=SimpleNamespace(variables=fake_registry))
    fake_codegen = SimpleNamespace(
        text=(
            "void sub_1157c(void)\n"
            "{\n"
            "    *((unsigned short *)(ir_0 * 16 + (unsigned int)(&s_2 + 2))) = 5512;\n"
            "    sub_15d8(); /* do not return */\n"
            "    *((unsigned short *)(ir_0 * 16 + (unsigned int)(&s_2 + 2))) = 5521;\n"
            "    sub_15d8(); /* do not return */\n"
            "}\n"
        )
    )
    fake_project = SimpleNamespace(
        analyses=SimpleNamespace(
            Clinic=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError()),
        )
    )
    fake_function = SimpleNamespace(addr=0x1157C, name="sub_1157c")

    monkeypatch.setattr(boundary, "_build_project", lambda *_args, **_kwargs: fake_project)
    monkeypatch.setattr(boundary.cli, "_infer_x86_16_linear_region", lambda *_args, **_kwargs: (0x1157C, 0x115BF))
    monkeypatch.setattr(boundary.cli, "_pick_function", lambda *_args, **_kwargs: (SimpleNamespace(), fake_function))
    monkeypatch.setattr(boundary.cli, "_prepare_function_for_decompilation", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        boundary,
        "_probe_decompiler",
        lambda _project, _function, _options, *, generate_code, regen_clinic=None: SimpleNamespace(
            clinic=fake_clinic,
            codegen=None if not generate_code else fake_codegen,
        ),
    )
    monkeypatch.setattr(
        boundary.argparse.ArgumentParser,
        "parse_args",
        lambda self: SimpleNamespace(
            binary=binary,
            addr=0x1157C,
            window=0x80,
            base_addr=0x10000,
            entry_point=0x11423,
        ),
    )

    assert boundary.main() == 0
    out = capsys.readouterr().out

    assert "clinic_without_guards=error AssertionError" in out
    assert "decompiler_generate_code_false.codegen_present=False" in out
    assert "decompiler_regen_clinic_false.codegen_present=True" in out
    assert (
        "upstream_hook_path=/home/xor/vextest/.venv/lib/python3.14/site-packages/angr/analyses/decompiler/decompiler.py:293-443"
        in out
    )
    assert (
        "cache_hook_note=Decompiler(generate_code=False) followed by Decompiler(regen_clinic=False) reuses the cached clinic"
        in out
    )
    assert "same_clinic_object=True" in out
    assert "same_variable_manager_object=True" in out
    assert "stack_object_0x1157c_preserved=True" in out
    assert "stack_object_0x1157c_widened=False" in out
    assert (
        "upstream_hook_note=no caller-visible callback exists between Clinic(...) and StructuredCodeGenerator(...)"
        in out
    )
    assert "codegen_sub_15d8_call_count=2" in out
    assert "boundary_fixpoint=upstream_angr_cached_clinic_reuse_before_codegen" in out
    assert "boundary_status=blocked_pre_codegen_stack_object_remains_narrow" in out


def test_decompile_function_disables_structuring_for_tiny_single_call_helpers(monkeypatch):
    class FakeDecompiler:
        def __init__(self, function, cfg=None, options=None, expr_collapse_depth=None):
            assert options == [("structurer_cls", "Phoenix")]
            assert expr_collapse_depth is not None
            codegen = SimpleNamespace(
                project=function.project,
                _inertia_call_target_identity_consumer_8616=lambda *_args: False,
                next_ident=lambda name: f"{name}_0",
                next_node_idx=lambda: 0,
            )
            prototype = SimTypeFunction([], SimTypeShort(False)).with_arch(function.project.arch)
            assert isinstance(prototype, SimTypeFunction)
            codegen.cfunc = structured_c.CFunction(
                function.addr, function.name,
                prototype,
                [], structured_c.CStatements([], addr=function.addr, codegen=codegen),
                {}, None, codegen=codegen,
            )
            self.codegen = codegen
            self.errors = []
            self.clinic = object()

    blocks = {
        0x1196F: SimpleNamespace(
            size=0x14,
            bytes=b"\x90" * 0x14,
            capstone=SimpleNamespace(
                insns=[
                    SimpleNamespace(mnemonic="push", op_str="si"),
                    SimpleNamespace(mnemonic="call", op_str="0x11a03"),
                ]
            ),
        )
    }
    project = SimpleNamespace(
        arch=Arch86_16(),
        analyses=SimpleNamespace(Decompiler=FakeDecompiler),
        factory=SimpleNamespace(block=lambda block_addr, opt_level=0: blocks[block_addr]),
    )
    function = SimpleNamespace(
        addr=0x1196F,
        name="sub_1196f",
        normalized=True,
        project=project,
        block_addrs_set=set(blocks),
        get_call_sites=lambda: [0x1196F],
    )
    cfg = SimpleNamespace()

    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "seed_calling_conventions", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_register_direct_call_target_function_stubs", lambda *_args, **_kwargs: 0)
    monkeypatch.setattr(decompile, "_snapshot_codegen_text", lambda *_args, **_kwargs: "void sub_1196f(void) {}")

    def _assert_structuring_disabled(project_obj, *_args, **_kwargs):
        assert project_obj._inertia_structuring_enabled is False
        return False

    def _noop_rewrite(*_args, **_kwargs):
        return False

    def _identity_text(text, *_args, **_kwargs):
        return text

    monkeypatch.setattr(decompile, "_attach_dos_pseudo_callees", _assert_structuring_disabled)
    monkeypatch.setattr(decompile, "apply_runtime_segment_lowering_8616", _noop_rewrite)
    monkeypatch.setattr(decompile, "materialize_indexed_segmented_global_loads_8616", _noop_rewrite)
    monkeypatch.setattr(
        decompile,
        "run_segment_global_materialization_8616",
        lambda *_args, **_kwargs: SimpleNamespace(changed=False),
    )
    monkeypatch.setattr(decompile, "_stabilize_regenerated_noncall_ast_8616", _noop_rewrite)
    for name in (
        "_attach_interrupt_wrapper_callees",
        "_lower_interrupt_wrapper_result_reads",
        "_attach_segment_register_names",
        "_attach_register_names",
        "_normalize_scalar_byte_register_types",
        "_attach_ss_stack_variables",
        "_rewrite_ss_stack_byte_offsets",
        "_canonicalize_stack_cvars",
        "_coalesce_direct_ss_local_word_statements",
        "_coalesce_segmented_word_store_statements",
        "_coalesce_segmented_word_load_expressions",
        "_prune_tiny_wrapper_staging_locals",
        "_prune_unused_unnamed_memory_declarations",
        "_prune_dead_local_assignments",
        "_prune_unused_local_declarations",
        "_prune_void_function_return_values",
        "_coalesce_cod_word_global_loads",
        "_coalesce_linear_recurrence_statements",
        "_attach_cod_global_names",
        "_attach_cod_global_declaration_names",
        "_attach_cod_global_declaration_types",
        "_collect_access_traits",
        "_coalesce_far_pointer_stack_expressions",
        "_simplify_nested_mk_fp_calls",
        "_attach_access_trait_field_names",
        "_attach_pointer_member_names",
        "_attach_cod_variable_names",
        "_attach_cod_callee_names",
        "_simplify_basic_algebraic_identities",
        "_materialize_missing_stack_local_declarations",
        "_materialize_missing_register_local_declarations",
        "_dedupe_codegen_variable_names_8616",
    ):
        monkeypatch.setattr(decompile, name, _noop_rewrite)
    for name in (
        "_normalize_boolean_conditions",
        "_normalize_anonymous_call_targets",
        "_prune_void_function_return_values_text",
        "_normalize_function_signature_arg_names",
        "_collapse_annotated_stack_aliases_text",
        "_materialize_missing_generic_local_declarations_text",
        "_prune_unused_local_declarations_text",
        "_annotate_cod_proc_output",
        "_rewrite_known_helper_signature_text",
        "_prune_trailing_generic_return_text",
        "_materialize_annotated_cod_declarations_text",
        "_collapse_duplicate_type_keywords_text",
        "_normalize_spurious_duplicate_local_suffixes",
        "_dedupe_adjacent_prototype_lines",
        "_sanitize_mangled_autonames_text",
        "_simplify_x86_16_stack_byte_pointers",
    ):
        monkeypatch.setattr(decompile, name, _identity_text)
    monkeypatch.setattr(decompile, "_format_known_helper_calls", lambda *_args, **_kwargs: _args[2])

    status, payload = decompile._decompile_function(
        project,
        cfg,
        function,
        timeout=1,
        api_style="pascal",
        binary_path=None,
        allow_isolated_retry=False,
    )

    assert status == "ok"
    assert payload == "void sub_1196f(void) {}"


def test_direct_callee_stub_inherits_binary_wide_stack_prototype_without_sidecar() -> None:
    code = bytes.fromhex("55 8b ec 03 46 04 13 56 06 c3")
    project = angr.Project(
        io.BytesIO(code),
        auto_load_libs=False,
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
    )
    project._inertia_original_project = project
    project._inertia_original_linear_delta = 0
    stub = SimpleNamespace(prototype=None, calling_convention=None, is_prototype_guessed=True)

    changed = cli_decompilation._seed_direct_callee_prototype_from_original_project_8616(
        project,
        stub,
        0x1000,
    )

    assert changed
    assert len(stub.prototype.args) == 1
    assert stub.prototype.args[0].size == 32
    assert stub.calling_convention is not None
    assert not stub.is_prototype_guessed


def test_prepend_recovered_callsite_prototypes_replaces_weaker_generic_declaration() -> None:
    codegen = SimpleNamespace(
        _inertia_callsite_prototype_decls=("int Sleep(unsigned long a0);",),
    )

    rendered = cli_decompilation._prepend_recovered_callsite_prototypes_8616(
        "int Sleep();\n\nvoid Beep(void)\n{\n    Sleep(75L);\n}\n",
        codegen,
    )

    assert rendered.count("Sleep(") == 2
    assert "int Sleep();" not in rendered
    assert rendered.startswith("int Sleep(unsigned long a0);")


def test_prepend_recovered_callsite_prototypes_keeps_stronger_existing_declaration() -> None:
    codegen = SimpleNamespace(
        _inertia_callsite_prototype_decls=("int Sleep(unsigned short a0);",),
    )
    source = "void Sleep(unsigned long wait);\n\nvoid Beep(void)\n{\n    Sleep(75L);\n}\n"

    rendered = cli_decompilation._prepend_recovered_callsite_prototypes_8616(source, codegen)

    assert rendered == source


def test_prepend_recovered_callsite_prototypes_reads_cfunc_metadata_fallback() -> None:
    """Final rendering keeps lowering metadata when angr replaces codegen."""
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            _inertia_callsite_prototype_decls=(
                "unsigned short apply_twice(unsigned short (*a0)(unsigned short), unsigned short a1);",
            )
        )
    )

    rendered = cli_decompilation._prepend_recovered_callsite_prototypes_8616(
        "unsigned short select_and_apply(void)\n{\n    return apply_twice(fn, value);\n}\n",
        codegen,
    )

    assert rendered.startswith(
        "unsigned short apply_twice(unsigned short (*a0)(unsigned short), unsigned short a1);"
    )


def test_register_direct_call_target_function_stubs_registers_linear_and_unbased_targets():
    created = []

    class FakeFunctionManager:
        def function(self, *, addr=None, create=False, **_kwargs):
            created.append((addr, create))
            return SimpleNamespace(addr=addr)

    function = SimpleNamespace(
        get_call_sites=lambda: [0x10016, 0x10040],
        get_call_target=lambda site: 0x140D if site == 0x10016 else 0x1140D,
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x4000)),
        kb=SimpleNamespace(functions=FakeFunctionManager()),
    )

    count = decompile._register_direct_call_target_function_stubs(project, function)

    assert count == 2
    assert set(created) == {(0x140D, True), (0x1140D, True)}


def test_register_direct_call_target_function_stubs_falls_back_to_capstone_direct_calls():
    created = []

    class FakeFunctionManager:
        def function(self, *, addr=None, create=False, **_kwargs):
            created.append((addr, create))
            return SimpleNamespace(addr=addr)

    blocks = {
        0x10010: SimpleNamespace(
            capstone=SimpleNamespace(
                insns=[
                    SimpleNamespace(address=0x10016, mnemonic="call", op_str="0x140D"),
                    SimpleNamespace(address=0x1001C, mnemonic="call", op_str="0x1140D"),
                    SimpleNamespace(address=0x10021, mnemonic="jmp", op_str="0x1002D"),
                ]
            )
        )
    }
    function = SimpleNamespace(
        block_addrs_set=set(blocks),
        get_call_sites=list,
        get_call_target=lambda _site: None,
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda block_addr, opt_level=0: blocks[block_addr]),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x4000)),
        kb=SimpleNamespace(functions=FakeFunctionManager()),
    )

    count = decompile._register_direct_call_target_function_stubs(project, function)

    assert count == 2
    assert set(created) == {(0x140D, True), (0x1140D, True)}


def test_register_direct_call_target_function_stubs_preserves_duplicate_callee_callsites(monkeypatch):
    created = []

    class FakeFunctionManager:
        def function(self, *, addr=None, create=False, **_kwargs):
            created.append((addr, create))
            return SimpleNamespace(addr=addr)

    function = SimpleNamespace(
        _call_sites={},
        get_call_return=lambda site: site + 3,
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0, max_addr=0x4000)),
        kb=SimpleNamespace(functions=FakeFunctionManager()),
    )
    monkeypatch.setattr(
        decompile,
        "_collect_direct_calls_8616",
        lambda *_args: [(0x1006, 0x140D, 0x1009), (0x1010, 0x140D, 0x1013)],
    )

    count = decompile._register_direct_call_target_function_stubs(project, function)

    assert count == 1
    assert created == [(0x140D, True)]
    assert function._call_sites == {
        0x1006: (0x140D, 0x1009),
        0x1010: (0x140D, 0x1013),
    }


def test_direct_callee_prototype_seed_scans_full_project_in_place(monkeypatch):
    stub = SimpleNamespace()
    project = SimpleNamespace(
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                min_addr=0x10000,
                max_addr=0x1FFFF,
            )
        )
    )
    calls: list[tuple[object, object, object, int]] = []

    def seed(
        source_project: object,
        source_function: object,
        target_function: object,
        address: int,
    ) -> bool:
        calls.append((source_project, source_function, target_function, address))
        return True

    monkeypatch.setattr(
        cli_decompilation,
        "seed_wide_stack_prototype_from_binary_address_8616",
        seed,
    )

    assert cli_decompilation._seed_direct_callee_prototype_from_original_project_8616(
        project,
        stub,
        0x10F18,
    )
    assert calls == [(project, stub, stub, 0x10F18)]


def test_collect_direct_calls_skips_stale_non_call_inventory_and_uses_capstone():
    blocks = {
        0x10010: SimpleNamespace(
            capstone=SimpleNamespace(
                insns=[
                    SimpleNamespace(address=0x10010, mnemonic="push", op_str="bp", insn=SimpleNamespace(size=1)),
                    SimpleNamespace(address=0x10011, mnemonic="mov", op_str="bp, sp", insn=SimpleNamespace(size=2)),
                    SimpleNamespace(address=0x10016, mnemonic="call", op_str="0x140D", insn=SimpleNamespace(size=3)),
                ]
            )
        )
    }
    function = SimpleNamespace(
        block_addrs_set=set(blocks),
        get_call_sites=lambda: [0x10010],
        get_call_target=lambda _site: 0x140D,
        get_call_return=lambda _site: None,
    )
    project = SimpleNamespace(factory=SimpleNamespace(block=lambda block_addr, opt_level=0: blocks[block_addr]))

    direct_calls = cli_decompilation._collect_direct_calls_8616(project, function)

    assert direct_calls == [(0x10016, 0x140D, 0x10019)]


def test_collect_direct_calls_merges_capstone_calls_when_inventory_is_partial():
    blocks = {
        0x10010: SimpleNamespace(
            capstone=SimpleNamespace(
                insns=[
                    SimpleNamespace(address=0x10010, mnemonic="call", op_str="0x140D", insn=SimpleNamespace(size=3)),
                    SimpleNamespace(address=0x10020, mnemonic="call", op_str="0x151E", insn=SimpleNamespace(size=3)),
                ]
            )
        )
    }
    function = SimpleNamespace(
        block_addrs_set=set(blocks),
        get_call_sites=lambda: [0x10010],
        get_call_target=lambda _site: 0x140D,
        get_call_return=lambda _site: 0x10013,
    )
    project = SimpleNamespace(factory=SimpleNamespace(block=lambda block_addr, opt_level=0: blocks[block_addr]))

    direct_calls = cli_decompilation._collect_direct_calls_8616(project, function)

    assert direct_calls == [(0x10010, 0x140D, 0x10013), (0x10020, 0x151E, 0x10023)]


def test_collect_direct_calls_prefers_exact_capstone_target_over_stale_cfg_offset():
    blocks = {
        0x10528: SimpleNamespace(
            capstone=SimpleNamespace(
                insns=[
                    SimpleNamespace(address=0x10537, mnemonic="call", op_str="0x10f18", insn=SimpleNamespace(size=3)),
                ]
            )
        )
    }
    function = SimpleNamespace(
        block_addrs_set=set(blocks),
        get_call_sites=lambda: [0x10537],
        get_call_target=lambda _site: 0x0F38,
        get_call_return=lambda _site: 0x1053A,
    )
    project = SimpleNamespace(factory=SimpleNamespace(block=lambda block_addr, opt_level=0: blocks[block_addr]))

    direct_calls = cli_decompilation._collect_direct_calls_8616(project, function)

    assert direct_calls == [(0x10537, 0x10F18, 0x1053A)]


def test_parse_direct_far_calls_preserves_distinct_offsets_in_same_segment():
    def far_call(offset):
        operands = (
            SimpleNamespace(type=2, imm=0x1C83, size=2),
            SimpleNamespace(type=2, imm=offset, size=2),
        )
        return SimpleNamespace(
            mnemonic="lcall",
            op_str=f"0x1c83, {offset:#x}",
            insn=SimpleNamespace(operands=operands),
        )

    assert cli_decompilation._parse_direct_call_target_8616(far_call(0x15D5)) == 0x1DE05
    assert cli_decompilation._parse_direct_call_target_8616(far_call(0x00C1)) == 0x1C8F1


def test_original_callee_name_checks_absolute_far_target_before_slice_delta(monkeypatch):
    original_project = SimpleNamespace(
        loader=SimpleNamespace(main_object=SimpleNamespace(min_addr=0x10000, max_addr=0x30000)),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: None),
            labels={},
        ),
        _inertia_lst_metadata=SimpleNamespace(
            code_labels={0x1DE05: "sub_1DE05", 0x2CE05: "aErrorCodeIs"},
        ),
    )
    project = SimpleNamespace(
        _inertia_original_project=original_project,
        _inertia_original_linear_delta=0xF000,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_compiler_helper_name_at_addr_8616",
        lambda _project, _addr: None,
    )

    assert cli_decompilation._original_callee_name_8616(project, 0x1DE05) == "sub_1DE05"


def test_collect_direct_calls_merges_linear_exact_region_calls(monkeypatch):
    function = SimpleNamespace(
        block_addrs_set=set(),
        get_call_sites=lambda: [0x10010],
        get_call_target=lambda _site: 0x140D,
        get_call_return=lambda _site: 0x10013,
    )
    project = SimpleNamespace(
        _inertia_original_linear_delta=0x10000,
        factory=SimpleNamespace(
            block=lambda _block_addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=()))
        ),
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_direct_call_stub_filter_regions",
        lambda _project, _function: ([(0x10010, 0x10040)], (0x20010, 0x20040)),
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_iter_linear_region_direct_calls_8616",
        lambda _project, _regions: iter(((0x10010, 0x140D, 0x10013), (0x10020, 0x151E, 0x10023))),
    )

    direct_calls = cli_decompilation._collect_direct_calls_8616(project, function)

    assert direct_calls == [(0x10010, 0x140D, 0x10013), (0x10020, 0x151E, 0x10023)]


def test_mark_stitched_return_sites_handles_jump_endpoint_without_undefined_target():
    node = SimpleNamespace(addr=0x1000)
    return_sites = []
    function = SimpleNamespace(
        get_node=lambda addr: node if addr == 0x1000 else None,
        transition_graph=SimpleNamespace(edges=lambda _node: ()),
        _add_return_site=lambda return_node: return_sites.append(return_node),
    )
    block = SimpleNamespace(capstone=SimpleNamespace(insns=(SimpleNamespace(mnemonic="jmp"),)))

    decompile._mark_stitched_return_sites_8616(function, {0x1000: block})

    assert return_sites == [node]


def test_mark_x86_16_stitched_recovery_uses_info_for_slotted_function():
    class SlottedFunction:
        __slots__ = ("info",)

        def __init__(self):
            self.info = {}

    function = SlottedFunction()

    decompile._mark_x86_16_stitched_recovery_8616(function)

    assert function.info["x86_16_stitched_recovery"] is True


def test_collect_stitched_blocks_caps_block_at_internal_leader():
    def _imm_operand(value):
        return SimpleNamespace(type=2, imm=value)

    def _insn(address, mnemonic, size=1, imm=None):
        operands = (_imm_operand(imm),) if imm is not None else ()
        return SimpleNamespace(
            address=address,
            mnemonic=mnemonic,
            size=size,
            insn=SimpleNamespace(operands=operands),
        )

    def _block(addr, insns, size):
        return SimpleNamespace(
            addr=addr,
            size=size,
            bytes=b"\x90" * size,
            capstone=SimpleNamespace(insns=tuple(insns)),
        )

    full_blocks = {
        0x1000: _block(0x1000, (_insn(0x1000, "jg", size=2, imm=0x1004),), 2),
        0x1002: _block(0x1002, (_insn(0x1002, "jmp", size=2, imm=0x1008),), 2),
        0x1004: _block(0x1004, (_insn(0x1004, "or", size=4), _insn(0x1008, "ret", size=1)), 5),
        0x1008: _block(0x1008, (_insn(0x1008, "ret", size=1),), 1),
    }
    capped_blocks = {
        (0x1004, 4): _block(0x1004, (_insn(0x1004, "or", size=4),), 4),
    }

    def _factory_block(addr, size=None, opt_level=0):
        if size is not None and (addr, size) in capped_blocks:
            return capped_blocks[(addr, size)]
        return full_blocks[addr]

    project = SimpleNamespace(factory=SimpleNamespace(block=_factory_block))

    reachable, edges = decompile._collect_stitched_blocks_and_edges_8616(project, 0x1000, 0x1000, 0x1010)

    assert reachable[0x1004].size == 4
    assert (0x1004, 0x1008) in edges


def test_exact_region_candidate_replacement_refuses_overlapping_byte_inflation():
    clean = SimpleNamespace(
        blocks=(
            SimpleNamespace(addr=0x1000, size=4),
            SimpleNamespace(addr=0x1004, size=4),
            SimpleNamespace(addr=0x1008, size=1),
        )
    )
    overlapping = SimpleNamespace(
        blocks=(
            SimpleNamespace(addr=0x1000, size=4),
            SimpleNamespace(addr=0x1004, size=5),
            SimpleNamespace(addr=0x1008, size=1),
        )
    )

    assert decompile._function_block_overlap_count_8616(clean, (0x1000, 0x1010)) == 0
    assert decompile._function_block_overlap_count_8616(overlapping, (0x1000, 0x1010)) == 1
    assert decompile._should_replace_exact_region_candidate_8616(clean, overlapping, (0x1000, 0x1010)) is False


def test_commit_exact_region_function_to_kb_evicts_interior_pseudofunctions():
    class FakeFunction:
        def __init__(self, addr, name):
            self.addr = addr
            self.name = name
            self.info = {}
            self._local_transition_graph = object()

    class FakeFunctionManager:
        def __init__(self):
            self._function_map = {}
            self.function_addrs_set = set()
            self._func_name_to_addrs = defaultdict(set)
            self._func_block_counts = {}

        def keys(self):
            return self._function_map.keys()

        def __delitem__(self, addr):
            del self._function_map[addr]
            self.function_addrs_set.discard(addr)

        def function(self, *, addr=None, create=False, **_kwargs):
            if addr in self._function_map:
                return self._function_map[addr]
            if create:
                func = FakeFunction(addr, f"sub_{addr:x}")
                self._function_map[addr] = func
                return func
            return None

    selected = FakeFunction(0x1005A, "rel_i16")
    project_manager = FakeFunctionManager()
    cfg_manager = FakeFunctionManager()
    for manager in (project_manager, cfg_manager):
        manager._function_map[0x1005A] = FakeFunction(0x1005A, "stale_rel_i16")
        manager._function_map[0x10075] = FakeFunction(0x10075, "sub_10075")
        manager._function_map[0x10079] = FakeFunction(0x10079, "sub_10079")
        manager.function_addrs_set.update(manager._function_map)

    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"), kb=SimpleNamespace(functions=project_manager))
    cfg = SimpleNamespace(functions=cfg_manager)

    changed = decompile._commit_exact_region_function_to_kb_8616(project, cfg, selected, (0x1005A, 0x100D0))

    assert changed is True
    assert project_manager.function(addr=0x1005A, create=False) is selected
    assert cfg_manager.function(addr=0x1005A, create=False) is selected
    assert sorted(project_manager.keys()) == [0x1005A]
    assert sorted(cfg_manager.keys()) == [0x1005A]
    assert selected.info["x86_16_exact_region_committed"] is True


def test_function_complexity_uses_bounded_local_blocks_before_raw_decode():
    class FakeFactory:
        def block(self, _addr, opt_level=0):
            return SimpleNamespace(bytes=b"\x90" * 100)

    function = SimpleNamespace(
        project=SimpleNamespace(factory=FakeFactory()),
        info={},
        block_addrs_set={0x1000, 0x1004},
        _local_blocks={
            0x1000: SimpleNamespace(addr=0x1000, size=4),
            0x1004: SimpleNamespace(addr=0x1004, size=1),
        },
    )

    assert cli_decompilation._function_complexity(function) == (2, 5)
    assert function.info["_inertia_function_complexity"]["source"] == "bounded_local_blocks"


def test_original_callee_name_prefers_proven_label_over_generic_exact_slice_name():
    class OriginalFunctionManager:
        def function(self, *, addr=None, create=False, **_kwargs):
            if addr == 0x1005A and not create:
                return SimpleNamespace(addr=addr, name="sub_1005a")
            return None

    original_project = SimpleNamespace(kb=SimpleNamespace(functions=OriginalFunctionManager(), labels={0x1005A: "rel_i16"}))
    project = SimpleNamespace(
        _inertia_original_project=original_project,
        _inertia_original_linear_delta=0xF1A7,
    )

    assert decompile._original_callee_name_8616(project, 0xEB3) == "rel_i16"


def test_sidecar_enclosing_label_caches_code_label_regions(monkeypatch):
    calls: list[int] = []
    metadata = SimpleNamespace(code_labels={0x1000: "FuncA", 0x1100: "FuncB"})

    def fake_lst_code_region(_metadata, start):
        calls.append(start)
        return (start, start + 0x20)

    monkeypatch.setattr(decompile, "_lst_code_region", fake_lst_code_region)

    assert decompile._sidecar_enclosing_label_8616(metadata, 0x1004) == "FuncA"
    assert decompile._sidecar_enclosing_label_8616(metadata, 0x1110) == "FuncB"
    assert decompile._sidecar_enclosing_label_8616(metadata, 0x1008) == "FuncA"
    assert calls == [0x1000, 0x1100]


def test_register_direct_call_target_function_stubs_prefers_proven_exact_slice_target_name():
    created = {}

    class CurrentFunctionManager:
        def function(self, *, addr=None, create=False, **_kwargs):
            if not create:
                return None
            stub = created.setdefault(addr, SimpleNamespace(addr=addr, name=f"sub_{addr:x}"))
            return stub

    class OriginalFunctionManager:
        def function(self, *, addr=None, create=False, **_kwargs):
            if addr == 0x1005A and not create:
                return SimpleNamespace(addr=addr, name="rel_i16")
            return None

    function = SimpleNamespace(
        addr=0x1000,
        blocks=(SimpleNamespace(addr=0x1000, size=0x120),),
        _call_sites={},
        get_call_sites=lambda: [0x1060],
        get_call_target=lambda _site: 0xEB3,
        get_call_return=lambda _site: 0x1063,
    )
    original_project = SimpleNamespace(kb=SimpleNamespace(functions=OriginalFunctionManager(), labels={}))
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        entry=0x1000,
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x1000, max_addr=0x117B)),
        kb=SimpleNamespace(functions=CurrentFunctionManager(), labels={}),
        _inertia_original_project=original_project,
        _inertia_original_linear_delta=0xF1A7,
    )

    count = decompile._register_direct_call_target_function_stubs(project, function)

    assert count == 2
    assert function._call_sites[0x1060] == (0xEB3, 0x1063)
    assert created[0xEB3].name == "rel_i16"
    assert created[0x1EB3].name == "sub_1eb3"


def test_register_direct_call_target_function_stubs_refuses_unproved_cod_call_names_for_unlabeled_targets():
    created = {}

    class FakeFunctionManager:
        def function(self, *, addr=None, create=False, **_kwargs):
            stub = created.setdefault(addr, SimpleNamespace(addr=addr, name=f"sub_{addr:x}"))
            return stub

    function = SimpleNamespace(
        get_call_sites=lambda: [0x10016, 0x10020],
        get_call_target=lambda site: 0x1446 if site == 0x10016 else 0x183A,
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x4000)),
        kb=SimpleNamespace(functions=FakeFunctionManager()),
    )
    cod_metadata = SimpleNamespace(call_names=("clock", "aNchkstk"))

    count = decompile._register_direct_call_target_function_stubs(project, function, cod_metadata=cod_metadata)

    assert count == 4
    assert created[0x1446].name == "sub_1446"
    assert created[0x183A].name == "sub_183a"
    assert created[0x11446].name == "sub_11446"
    assert created[0x1183A].name == "sub_1183a"


def test_register_direct_call_target_function_stubs_names_binary_signature_stack_probe():
    helper_bytes = bytes.fromhex("59 8b dc 2b d8 72 0a 3b 1e b6 00 72 04 8b e3 ff e1")
    created = {}

    class FakeFunctionManager:
        def function(self, *, addr=None, create=False, **_kwargs):
            if not create:
                return None
            stub = created.setdefault(addr, SimpleNamespace(addr=addr, name=f"sub_{addr:x}"))
            return stub

    def _load(addr: int, size: int):
        if addr != 0x103BE:
            raise KeyError(addr)
        return helper_bytes[:size]

    function = SimpleNamespace(
        addr=0x10010,
        _call_sites={},
        get_call_sites=lambda: [0x10017],
        get_call_target=lambda _site: 0x103BE,
        get_call_return=lambda _site: 0x1001A,
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        entry=0x10010,
        is_hooked=lambda _addr: False,
        hook=lambda _addr, _proc: None,
        loader=SimpleNamespace(
            memory=SimpleNamespace(load=_load),
            main_object=SimpleNamespace(linked_base=0, max_addr=0x20000),
        ),
        kb=SimpleNamespace(functions=FakeFunctionManager(), labels={}),
    )

    count = decompile._register_direct_call_target_function_stubs(project, function)

    assert count == 1
    assert function._call_sites[0x10017] == (0x103BE, 0x1001A)
    assert created[0x103BE].name == "aNchkstk"


def test_direct_call_stub_consumes_hook_helper_evidence_without_rediscovery(monkeypatch):
    evidence = CompilerHelperEvidence8616(
        addr=0x103BE,
        name="aNchkstk",
        kind=CompilerHelperEvidenceKind8616.STACK_PROBE,
        pattern_name="test_stack_probe",
        matched_bytes=17,
    )
    stub = SimpleNamespace(addr=0x103BE, name="sub_103be")
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda *, addr, create: stub if addr == evidence.addr and create else None
            )
        )
    )
    function = SimpleNamespace(addr=0x1000, _call_sites={})

    monkeypatch.setattr(
        decompile,
        "hook_x86_16_compiler_helper_at_8616",
        lambda _project, _candidate: evidence,
    )

    def fail_rediscovery(*_args, **_kwargs):
        pytest.fail("binary-proven helper evidence must not be rediscovered")

    monkeypatch.setattr(decompile, "_original_callee_name_8616", fail_rediscovery)
    monkeypatch.setattr(decompile, "_compiler_helper_name_at_addr_8616", fail_rediscovery)
    monkeypatch.setattr(
        decompile,
        "_seed_direct_callee_prototype_from_original_project_8616",
        lambda *_args, **_kwargs: False,
    )

    created = decompile._create_or_update_direct_call_stub_8616(
        project=project,
        function=function,
        callsite_addr=None,
        ret_addr=None,
        candidate=evidence.addr,
        preferred_candidate=evidence.addr,
        fallback_call_name=None,
        debug_enabled=False,
    )

    assert created is True
    assert stub.name == evidence.name
    assert stub.returning is True


def test_register_direct_call_target_function_stubs_names_raw_original_stack_probe_candidate():
    helper_bytes = bytes.fromhex("59 8b dc 2b d8 72 0a 3b 1e b6 00 72 04 8b e3 ff e1")
    created = {}

    class FakeFunctionManager:
        def function(self, *, addr=None, create=False, **_kwargs):
            if create:
                return created.setdefault(addr, SimpleNamespace(addr=addr, name=f"sub_{addr:x}"))
            if addr == 0x11222:
                return SimpleNamespace(addr=addr, name="sub_11222")
            return None

    def _load(addr: int, size: int):
        if addr != 0x11222:
            raise KeyError(addr)
        return helper_bytes[:size]

    function = SimpleNamespace(
        addr=0x1000,
        _call_sites={},
        get_call_sites=lambda: [0x1006],
        get_call_target=lambda _site: 0x11222,
        get_call_return=lambda _site: 0x1009,
    )
    original_project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=_load)),
        kb=SimpleNamespace(functions=FakeFunctionManager(), labels={}),
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        entry=0x1000,
        _inertia_original_project=original_project,
        _inertia_original_linear_delta=0xFC18,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(linked_base=0x1000, max_addr=0x20BB),
        ),
        kb=SimpleNamespace(functions=FakeFunctionManager(), labels={}),
    )

    count = decompile._register_direct_call_target_function_stubs(project, function)

    assert count == 1
    assert function._call_sites[0x1006] == (0x11222, 0x1009)
    assert created[0x11222].name == "aNchkstk"


def test_rank_exe_function_seeds_uses_persistent_cache(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"\xe8\x00\x00\xc3")
    code = binary.read_bytes()
    project = SimpleNamespace(
        entry=0x1000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=binary,
                linked_base=0x1000,
                max_addr=len(code) - 1,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
            )
        ),
    )
    calls = {"count": 0}

    def _fake_pick(*_args, **_kwargs):
        calls["count"] += 1
        return SimpleNamespace(), SimpleNamespace(addr=0x1000, blocks=(SimpleNamespace(size=4),))

    monkeypatch.setattr(recovery_cache, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(recovery_cache, "_cache_source_digest", lambda _paths: "digest-r")
    monkeypatch.setattr(decompile, "_seed_scan_windows", lambda _project, **_kwargs: [(0x1000, 0x1004)])
    monkeypatch.setattr(decompile, "_entry_window_seed_targets", lambda *_args, **_kwargs: {0x1003})
    monkeypatch.setattr(decompile, "_pick_function_lean", _fake_pick)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "collect_neighbor_call_targets", lambda _function: [])
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: [])

    first = decompile._rank_exe_function_seeds(project)
    second = decompile._rank_exe_function_seeds(project)

    assert first == second
    assert calls["count"] == 1


def test_rank_exe_function_seeds_cache_key_changes_when_recovery_metadata_changes(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    code = b"\x90" * 0x400
    binary.write_bytes(code)
    metadata_a = LSTMetadata(
        data_labels={},
        code_labels={0x1100: "sig_a"},
        code_ranges={0x1100: (0x1100, 0x1120)},
        signature_code_addrs=frozenset(),
        absolute_addrs=True,
        source_format="flair_pat+flair_sig",
    )
    metadata_b = LSTMetadata(
        data_labels={},
        code_labels={0x1200: "sig_b"},
        code_ranges={0x1200: (0x1200, 0x1240)},
        signature_code_addrs=frozenset(),
        absolute_addrs=True,
        source_format="flair_pat+flair_sig",
    )
    calls = {"count": 0}

    def _make_project(metadata):
        return SimpleNamespace(
            entry=0x1000,
            _inertia_lst_metadata=metadata,
            loader=SimpleNamespace(
                main_object=SimpleNamespace(
                    binary=binary,
                    linked_base=0x1000,
                    max_addr=len(code) - 1,
                    memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
                )
            ),
        )

    def _fake_pick(*_args, **_kwargs):
        calls["count"] += 1
        return SimpleNamespace(), SimpleNamespace(addr=0x1000, blocks=(SimpleNamespace(size=4),))

    monkeypatch.setattr(recovery_cache, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(recovery_cache, "_cache_source_digest", lambda _paths: "digest-r")
    monkeypatch.setattr(decompile, "_seed_scan_windows", lambda _project, **_kwargs: [(0x1100, 0x1240)])
    monkeypatch.setattr(decompile, "_entry_window_seed_targets", lambda *_args, **_kwargs: set())
    monkeypatch.setattr(decompile, "_pick_function_lean", _fake_pick)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "collect_neighbor_call_targets", lambda _function: [])
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: [])

    first = decompile._rank_exe_function_seeds(_make_project(metadata_a))
    second = decompile._rank_exe_function_seeds(_make_project(metadata_b))

    assert first == [0x1100]
    assert second == [0x1200]
    assert calls["count"] == 2


def test_main_uses_cached_exe_catalog_addresses_before_cfg(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    recovered_pair = (SimpleNamespace(), SimpleNamespace(addr=0x10010, name="sub_10010", project=project))

    monkeypatch.setattr(recovery_cache, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(recovery_cache, "_cache_source_digest", lambda _paths: "digest-r")
    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [0x10010])
    monkeypatch.setattr(
        decompile,
        "_recover_partial_cfg",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("fresh CFG should not run")),
    )
    monkeypatch.setattr(
        decompile,
        "_recover_cfg",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("whole CFG should not run")),
    )
    monkeypatch.setattr(decompile, "_recover_cached_function_pairs", lambda *_args, **_kwargs: [recovered_pair])
    monkeypatch.setattr(
        decompile,
        "_supplement_cached_seeded_recovery",
        lambda _project, pairs, addrs, **_kwargs: (pairs, addrs),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
            tail_validation={
                "structuring": {"status": "stable", "changed": False},
                "postprocess": {"status": "stable", "changed": False},
            },
            elapsed=1.0,
            byte_count=8,
        ),
    )
    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "0"])
    out = capsys.readouterr().out

    assert rc in {0, 2}
    assert "using cached discovered function addresses" in out
    assert "/* == function 0x10010 sub_10010 == */" in out


def test_recover_cached_function_pairs_gives_pre_entry_candidates_more_time(monkeypatch):
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=CLI_PATH, linked_base=0x1000, max_addr=0x600),
        ),
    )
    seen_timeouts: list[tuple[int, int]] = []

    def _fake_recover(_project, *, candidate_addr, timeout, **_kwargs):
        seen_timeouts.append((candidate_addr, timeout))
        return (
            SimpleNamespace(),
            SimpleNamespace(
                addr=candidate_addr,
                name=f"sub_{candidate_addr:x}",
                is_plt=False,
                is_simprocedure=False,
                info={},
                blocks=(SimpleNamespace(size=0x18),),
            ),
        )

    monkeypatch.setattr(decompile, "_recover_candidate_with_timeout", _fake_recover)

    recovered = decompile._recover_cached_function_pairs(
        project,
        addrs=[0x10010, 0x11593],
        timeout=6,
        limit=2,
        region_span=0x120,
        per_function_timeout=1,
    )

    assert [function.addr for _cfg, function in recovered] == [0x10010, 0x11593]
    assert seen_timeouts == [(0x10010, 2), (0x11593, 1)]


def test_main_supplements_cached_exe_catalog_before_display_slice(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    runtime_pair = (SimpleNamespace(), SimpleNamespace(addr=0x11440, name="runtime_shell", project=project))
    helper_pair = (SimpleNamespace(), SimpleNamespace(addr=0x114CD, name="runtime_init", project=project))
    body_pair = (SimpleNamespace(), SimpleNamespace(addr=0x10010, name="sub_10010", project=project))

    monkeypatch.setattr(recovery_cache, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(recovery_cache, "_cache_source_digest", lambda _paths: "digest-cache-supplement")
    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(
        decompile,
        "_load_catalog_address_cache",
        lambda *_args, **_kwargs: [0x11440, 0x114CD],
    )
    monkeypatch.setattr(
        decompile,
        "_recover_partial_cfg",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("fresh CFG should not run")),
    )
    monkeypatch.setattr(
        decompile,
        "_recover_cfg",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("whole CFG should not run")),
    )
    monkeypatch.setattr(
        decompile, "_recover_cached_function_pairs", lambda *_args, **_kwargs: [runtime_pair, helper_pair]
    )
    monkeypatch.setattr(
        decompile,
        "_supplement_cached_seeded_recovery",
        lambda _project, _pairs, _addrs, **_kwargs: (
            [body_pair, runtime_pair, helper_pair],
            [0x10010, 0x11440, 0x114CD],
        ),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
            tail_validation={
                "structuring": {"status": "stable", "changed": False},
                "postprocess": {"status": "stable", "changed": False},
            },
            elapsed=1.0,
            byte_count=8,
        ),
    )
    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "using cached discovered function addresses" in out
    assert "/* == function 0x10010 sub_10010 == */" in out
    assert "/* == function 0x11440 runtime_shell == */" in out
    assert "/* == function 0x114cd runtime_init == */" not in out


def test_main_prefers_fast_exe_catalog_before_cfg(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    entry_function = SimpleNamespace(addr=0x11423, name="_start", project=project)
    body_function = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_discover_ranked_binary_offsets", lambda *_args, **_kwargs: [0x11423])
    daemon_prefixes: list[str] = []

    def run_daemon_inline(func, *, thread_name_prefix, **_kwargs):
        daemon_prefixes.append(thread_name_prefix)
        return func()

    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", run_daemon_inline)
    monkeypatch.setattr(
        decompile,
        "_recover_fast_exe_catalog",
        lambda *_args, **_kwargs: [(SimpleNamespace(), entry_function), (SimpleNamespace(), body_function)],
    )
    monkeypatch.setattr(
        decompile,
        "_recover_partial_cfg",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("slow CFG should not run")),
    )
    monkeypatch.setattr(
        decompile,
        "_recover_cfg",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("whole CFG should not run")),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile._AdaptivePerByteTimeoutModel, "observe_success", lambda self, *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
            elapsed=1.0,
            byte_count=8,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc in {0, 2}
    assert "fast-catalog" not in daemon_prefixes
    assert "/* info: selected 2 function(s) for display */" in out
    assert "/* == function 0x11423 _start == */" in out
    assert "/* == function 0x10010 sub_10010 == */" in out


def test_main_emits_tail_validation_summary_and_metadata_to_stderr(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    function = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_recover_fast_exe_catalog",
        lambda *_args, **_kwargs: [(SimpleNamespace(), function)],
    )
    monkeypatch.setattr(
        decompile,
        "_recover_partial_cfg",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("slow CFG should not run")),
    )
    monkeypatch.setattr(
        decompile,
        "_recover_cfg",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("whole CFG should not run")),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
            tail_validation={
                "structuring": {
                    "changed": False,
                    "mode": "live_out",
                    "verdict": "structuring stable",
                    "summary_text": "no observable delta",
                },
                "postprocess": {
                    "changed": False,
                    "mode": "live_out",
                    "verdict": "postprocess stable",
                    "summary_text": "no observable delta",
                },
            },
        ),
    )
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "3"])
    captured = capsys.readouterr()

    assert rc == 0
    assert "[tail-validation] whole-tail validation clean across 1 functions" in captured.err
    assert "@@INERTIA_TAIL_VALIDATION@@ " in captured.err


def test_tail_validation_runtime_policy_defaults_on_for_exe_and_cod(monkeypatch, tmp_path):
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.delenv("INERTIA_ENABLE_TAIL_VALIDATION", raising=False)
    monkeypatch.delenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", raising=False)

    assert decompile._tail_validation_enabled_for_run(tmp_path / "sample.exe") is True
    assert decompile._tail_validation_enabled_for_run(tmp_path / "sample.cod") is True
    assert decompile._tail_validation_enabled_for_run(tmp_path / "sample.exe", proc="main") is True


def test_direct_addr_project_local_fallback_addr_uses_rebased_function_addr():
    function = SimpleNamespace(addr=0x1000)

    assert (
        cli_core._direct_addr_project_local_fallback_addr_8616(
            function=function,
            direct_display_addr=0x10C18,
            using_rebased_direct_slice=True,
        )
        == 0x1000
    )
    assert (
        cli_core._direct_addr_project_local_fallback_addr_8616(
            function=function,
            direct_display_addr=0x10C18,
            using_rebased_direct_slice=False,
        )
        == 0x10C18
    )


def test_main_emits_tail_validation_stderr_for_direct_exe_by_default(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    function = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)

    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.delenv("INERTIA_ENABLE_TAIL_VALIDATION", raising=False)
    monkeypatch.delenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", raising=False)
    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_recover_fast_exe_catalog",
        lambda *_args, **_kwargs: [(SimpleNamespace(), function)],
    )
    monkeypatch.setattr(
        decompile,
        "_recover_partial_cfg",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("slow CFG should not run")),
    )
    monkeypatch.setattr(
        decompile,
        "_recover_cfg",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("whole CFG should not run")),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
            tail_validation={
                "structuring": {
                    "changed": False,
                    "mode": "live_out",
                    "verdict": "structuring stable",
                    "summary_text": "no observable delta",
                },
                "postprocess": {
                    "changed": False,
                    "mode": "live_out",
                    "verdict": "postprocess stable",
                    "summary_text": "no observable delta",
                },
            },
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "3"])
    captured = capsys.readouterr()

    assert rc == 0
    assert "[tail-validation] whole-tail validation clean across 1 functions" in captured.err


def test_main_emits_uncollected_tail_validation_for_direct_nonoptimized_fallback(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
        _inertia_last_tail_validation_snapshot={
            "structuring": {"changed": False, "mode": "live_out", "verdict": "stale stable"},
            "postprocess": {"changed": False, "mode": "live_out", "verdict": "stale stable"},
        },
    )

    def _fake_timeout(fn, **kwargs):
        if kwargs.get("thread_name_prefix") == "recovery":
            raise decompile._AnalysisTimeout
        return fn()

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_timeout)
    monkeypatch.setattr(
        decompile, "_try_decompile_non_optimized_slice", lambda *_args, **_kwargs: "int fallback(void) { return 7; }"
    )
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--addr", "0x11423", "--timeout", "2"])
    captured = capsys.readouterr()

    assert rc == 0
    assert "/* == c (non-optimized fallback) == */" in captured.out
    assert "int fallback(void) { return 7; }" in captured.out
    assert "[tail-validation]" in captured.err
    assert "not collected" in captured.err
    assert "detail artifact " in captured.err
    assert '"scanned": 1' in captured.err
    assert '"detail_cache_path": "' in captured.err
    assert '"detail_cache_path": null' not in captured.err
    assert '"tail_validation_uncollected": true' in captured.err
    assert '"function_name": "sub_11423"' in captured.err


def test_main_renders_direct_nonoptimized_outcome_payload_instead_of_repr(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )

    def _fake_timeout(fn, **kwargs):
        if kwargs.get("thread_name_prefix") == "recovery":
            raise decompile._AnalysisTimeout
        return fn()

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_timeout)
    monkeypatch.setattr(
        decompile,
        "_try_decompile_non_optimized_slice",
        lambda *_args, **_kwargs: decompile.NonOptimizedSliceOutcome(
            rendered="int fallback(void) { return 7; }",
            status="timeout",
            payload="Timed out after 2s.",
        ),
    )

    rc = decompile.main([str(binary), "--addr", "0x11423", "--timeout", "2"])
    captured = capsys.readouterr()

    assert rc == 0
    assert "/* == c (non-optimized fallback) == */" in captured.out
    assert "int fallback(void) { return 7; }" in captured.out
    assert "NonOptimizedSliceOutcome(" not in captured.out


def test_main_emits_current_run_tail_validation_for_direct_nonoptimized_fallback(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
            memory=SimpleNamespace(load=lambda _start, size: b"\x90" * size),
        ),
    )
    slice_project = SimpleNamespace(
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda _start, size: b"\x90" * size)),
    )

    def _fake_timeout(fn, **kwargs):
        if kwargs.get("thread_name_prefix") == "recovery":
            raise decompile._AnalysisTimeout
        return fn()

    def _fake_decompile_function_with_stats(slice_project_arg, *_args, **_kwargs):
        slice_project_arg._inertia_last_tail_validation_snapshot = {
            "structuring": {
                "changed": True,
                "mode": "live_out",
                "verdict": "structuring whole-tail validation [live_out] changed: helper_calls: +helper_ping",
                "summary_text": "helper_calls: +helper_ping",
            },
            "postprocess": {
                "changed": True,
                "mode": "live_out",
                "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
                "summary_text": "helper_calls: +helper_ping",
            },
        }
        return "ok", "int fallback(void) { return 7; }", None, 1, 0x20, 0.5

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_timeout)
    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *_args, **_kwargs: slice_project)
    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x10010, 0x10020))
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (
            SimpleNamespace(),
            SimpleNamespace(addr=0x10010, name="sub_10010", normalized=False),
        ),
    )
    monkeypatch.setattr(decompile, "_prepare_function_for_decompilation", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_sidecar_cod_metadata_for_function", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_decompile_function_with_stats", _fake_decompile_function_with_stats)
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--addr", "0x11423", "--timeout", "2"])
    captured = capsys.readouterr()

    assert rc == 0
    assert "/* == c (non-optimized fallback) == */" in captured.out
    assert "int fallback(void) { return 7; }" in captured.out
    assert "[tail-validation] whole-tail validation failed across 2 functions" in captured.err
    assert "not collected" not in captured.err


def test_main_aggregate_trivial_fallback_does_not_reuse_stale_project_snapshot(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
        _inertia_last_tail_validation_snapshot={
            "structuring": {"changed": False, "mode": "live_out", "verdict": "stale stable"},
            "postprocess": {"changed": False, "mode": "live_out", "verdict": "stale stable"},
        },
    )
    function = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x10010: "sub_10010"},
        code_ranges={0x10010: (0x10010, 0x10011)},
        absolute_addrs=True,
        source_format="cod_listing",
    )

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_recover_fast_exe_catalog",
        lambda *_args, **_kwargs: [(SimpleNamespace(), function)],
    )
    monkeypatch.setattr(
        decompile,
        "_recover_lst_function",
        lambda *_args, **_kwargs: (SimpleNamespace(), function),
    )
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="error",
            payload="Decompiler did not produce code.",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )
    monkeypatch.setattr(
        decompile, "_try_emit_trivial_sidecar_c", lambda *_args, **_kwargs: "void sub_10010(void)\n{\n}\n"
    )
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "3"])
    captured = capsys.readouterr()

    assert rc == 2
    assert (
        "/* -- c (trivial sidecar fallback) -- */" in captured.out
        or "/* -- c (sidecar slice fallback) -- */" in captured.out
        or "-- asm fallback --" in captured.out
    )
    assert "[tail-validation]" in captured.err
    assert "not collected" in captured.err
    assert "detail artifact " in captured.err
    assert '"records":' in captured.err
    assert '"scanned":1' in captured.err or '"scanned": 1' in captured.err
    assert '"detail_cache_path": "' in captured.err
    assert '"detail_cache_path": null' not in captured.err


def test_main_aggregate_uses_sidecar_fallback_tail_validation_snapshot(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    function = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x10010: "sub_10010"},
        code_ranges={0x10010: (0x10010, 0x10020)},
        absolute_addrs=True,
        source_format="cod_listing",
    )

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_recover_fast_exe_catalog",
        lambda *_args, **_kwargs: [(SimpleNamespace(), function)],
    )
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="error",
            payload="Decompiler did not produce code.",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    def _fake_sidecar_slice(project_arg, *_args, **_kwargs):
        project_arg._inertia_last_tail_validation_snapshot = {
            "structuring": {"changed": False, "mode": "live_out", "verdict": "structuring stable"},
            "postprocess": {"changed": False, "mode": "live_out", "verdict": "postprocess stable"},
        }
        return SliceRecoveryAttemptOutcome(
            attempt_name="sidecar_slice",
            status="ok",
            payload="int sub_10010(void) { return 0; }",
            snapshot=project_arg._inertia_last_tail_validation_snapshot,
        )

    monkeypatch.setattr(decompile, "_try_decompile_sidecar_slice", _fake_sidecar_slice)
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "0"])
    captured = capsys.readouterr()

    assert rc == 0
    assert "/* -- c (sidecar slice fallback) -- */" in captured.out
    assert "[tail-validation] whole-tail validation clean across 1 functions" in captured.err
    assert '"function_addr": 65552' in captured.err


def test_main_direct_path_uses_trivial_sidecar_fallback_tail_validation_snapshot(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    cfg = SimpleNamespace()
    func = SimpleNamespace(
        addr=0x10010,
        name="sub_10010",
        project=project,
        normalized=False,
        analyses={},
        info={
            "x86_16_tail_validation": {
                "structuring": {"changed": False, "mode": "live_out", "verdict": "structuring stable"},
                "postprocess": {"changed": False, "mode": "live_out", "verdict": "postprocess stable"},
            }
        },
        normalize=lambda: None,
    )
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x10010: "sub_10010"},
        code_ranges={0x10010: (0x10010, 0x10020)},
        absolute_addrs=True,
        source_format="cod_listing",
    )

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_direct_addr_use_fork_lane_8616", lambda **_kwargs: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "_recover_direct_addr_function", lambda *_args, **_kwargs: (cfg, func))
    monkeypatch.setattr(
        decompile,
        "_decompile_function_with_stats",
        lambda *_args, **_kwargs: (
            "validation_failed",
            "Final quality guard rejected emitted C (raw-ds-segmented-access).",
            None,
            1,
            4,
            0.01,
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_try_decompile_non_optimized_known_function",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(decompile, "_try_decompile_sidecar_slice", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_try_emit_trivial_sidecar_c",
        lambda *_args, **_kwargs: "int sub_10010(void) { return 0; }",
    )
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--addr", "0x10010", "--timeout", "2"])
    captured = capsys.readouterr()

    assert rc == 0
    assert "validation=failed" not in captured.out and "validation=failed" in captured.err
    assert "/* == c (trivial sidecar fallback) == */" in captured.out
    assert "[tail-validation] whole-tail validation clean across 1 functions" in captured.err


def test_main_direct_timeout_is_terminal_even_with_partial_payload(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    cfg = SimpleNamespace()
    func = SimpleNamespace(
        addr=0x10010,
        name="sub_10010",
        project=project,
        info={
            "x86_16_tail_validation": {
                "structuring": {"changed": False, "mode": "live_out", "verdict": "structuring stable"},
                "postprocess": {"changed": False, "mode": "live_out", "verdict": "postprocess stable"},
            }
        },
    )

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_direct_addr_use_fork_lane_8616", lambda **_kwargs: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "_recover_direct_addr_function", lambda *_args, **_kwargs: (cfg, func))

    def _fake_decompile(*_args, **_kwargs):
        project._inertia_last_tail_validation_snapshot = {
            "structuring": {"changed": False, "mode": "live_out", "verdict": "structuring stable"},
            "postprocess": {"changed": False, "mode": "live_out", "verdict": "postprocess stable"},
        }
        return ("timeout", "Timed out after 2s.", "int partial(void) { return 1; }", 1, 4, 0.01)

    monkeypatch.setattr(decompile, "_decompile_function_with_stats", _fake_decompile)
    monkeypatch.setattr(
        decompile,
        "_try_decompile_non_optimized_slice",
        lambda project_arg, *_args, **_kwargs: (
            setattr(
                project_arg,
                "_inertia_last_tail_validation_snapshot",
                {
                    "structuring": {"changed": True, "mode": "live_out", "verdict": "stale changed"},
                    "postprocess": {"changed": True, "mode": "live_out", "verdict": "stale changed"},
                },
            )
            or None
        ),
    )
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--addr", "0x10010", "--timeout", "2"])
    captured = capsys.readouterr()

    assert rc == 3
    assert "/* == c (partial timeout) == */" not in captured.out
    assert "int partial(void) { return 1; }" not in captured.out
    assert "Direct decompilation timeout is terminal for this function; skipping fallback lanes." in captured.out
    assert "[tail-validation] whole-tail validation clean across 1 functions" in captured.err
    assert '"detail_cache_path": "' in captured.err
    assert '"detail_cache_path": null' not in captured.err
    assert "stale changed" not in captured.err


def test_main_direct_decompile_outer_timeout_becomes_terminal(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    cfg = SimpleNamespace()
    func = SimpleNamespace(
        addr=0x10010,
        name="sub_10010",
        project=project,
        normalized=False,
        analyses={},
        normalize=lambda: None,
    )

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_direct_addr_use_fork_lane_8616", lambda **_kwargs: True)
    monkeypatch.setattr(
        decompile,
        "_run_with_timeout_in_fork",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError("Timed out after 2s.")),
    )
    monkeypatch.setattr(decompile, "_recover_direct_addr_function", lambda *_args, **_kwargs: (cfg, func))
    monkeypatch.setattr(
        decompile, "_try_decompile_non_optimized_slice", lambda *_args, **_kwargs: "int fallback(void) { return 7; }"
    )
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--addr", "0x10010", "--timeout", "2"])
    captured = capsys.readouterr()

    assert rc == 3
    assert "Direct decompilation timeout is terminal for this function; skipping fallback lanes." in captured.out
    assert "[tail-validation]" in captured.err
    assert "UnboundLocalError" not in captured.err


def test_main_direct_source_quality_blocker_allows_fallback_paths(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    cfg = SimpleNamespace()
    func = SimpleNamespace(
        addr=0x10010,
        name="sub_10010",
        project=project,
        normalized=False,
        analyses={},
        normalize=lambda: None,
    )

    def _fake_recovery(*_args, **_kwargs):
        return (
            "validation_failed",
            "Final quality guard rejected emitted C (unresolved-vvar).",
            None,
            1,
            4,
            0.01,
        )

    def _fake_direct_recovery(*_args, **_kwargs):
        return cfg, func

    fallback_calls = {"known": 0}

    def _known_fallback(*_args, **_kwargs):
        fallback_calls["known"] += 1
        return "int sub_10010(void) { return 7; }"

    def _unused_fallback(*_args, **_kwargs):
        return None

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_direct_addr_use_fork_lane_8616", lambda **_kwargs: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "_recover_direct_addr_function", lambda *_args, **_kwargs: (cfg, func))
    monkeypatch.setattr(decompile, "_decompile_function_with_stats", _fake_recovery)
    monkeypatch.setattr(decompile, "_tail_validation_snapshot_for_function_run", lambda *_args, **_kwargs: {
        "structuring": {"changed": False, "mode": "live_out", "verdict": "stable"},
        "postprocess": {"changed": False, "mode": "live_out", "verdict": "stable"},
    })
    monkeypatch.setattr(decompile, "_tail_validation_snapshot_for_fallback", lambda *_args, **_kwargs: {
        "structuring": {"changed": False, "mode": "live_out", "verdict": "stable"},
        "postprocess": {"changed": False, "mode": "live_out", "verdict": "stable"},
    })
    monkeypatch.setattr(decompile, "_try_decompile_non_optimized_known_function", _known_fallback)
    monkeypatch.setattr(decompile, "_try_decompile_non_optimized_slice", _unused_fallback)
    monkeypatch.setattr(decompile, "_try_decompile_sidecar_slice", _unused_fallback)
    monkeypatch.setattr(decompile, "_try_emit_string_intrinsic_c", _unused_fallback)
    monkeypatch.setattr(decompile, "_try_emit_trivial_sidecar_c", _unused_fallback)

    rc = decompile.main([str(binary), "--addr", "0x10010", "--timeout", "2"])
    captured = capsys.readouterr()

    assert rc == 0
    assert fallback_calls == {"known": 1}
    assert "Source-backed quality blocker is terminal; skipping fallback lanes." not in captured.out
    assert "/* == c (non-optimized fallback) == */" in captured.out


def test_main_direct_timeout_reports_nonoptimized_failure_before_string_fallback(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    cfg = SimpleNamespace()
    func = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)

    def _fake_timeout(fn, **kwargs):
        if kwargs.get("thread_name_prefix") == "recovery":
            raise decompile._AnalysisTimeout
        return fn()

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_timeout)
    monkeypatch.setattr(
        decompile,
        "_run_with_timeout_in_fork",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(decompile.FuturesTimeoutError()),
    )
    monkeypatch.setattr(decompile, "_recover_direct_addr_function", lambda *_args, **_kwargs: (cfg, func))
    monkeypatch.setattr(
        decompile,
        "_try_decompile_non_optimized_slice",
        lambda *_args, **_kwargs: decompile.NonOptimizedSliceOutcome(
            rendered=None,
            status="error",
            payload="slice lift broke",
            failure_detail="shared-project slice: error: slice lift broke",
            attempt_failures=("shared-project slice: error: slice lift broke",),
        ),
    )
    monkeypatch.setattr(
        decompile, "_try_emit_string_intrinsic_c", lambda *_args, **_kwargs: "char fallback(void) { return 7; }"
    )
    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x10010, 0x10020))
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--addr", "0x10010", "--timeout", "2"])
    captured = capsys.readouterr()

    assert rc == 0
    assert "/* non-optimized fallback unavailable: shared-project slice: error: slice lift broke */" in captured.out
    assert captured.out.index("non-optimized fallback unavailable") < captured.out.index(
        "/* == c (string intrinsic fallback) == */"
    )
    assert "char fallback(void) { return 7; }" in captured.out


def test_main_aggregate_partial_timeout_uses_result_tail_validation(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
        _inertia_last_tail_validation_snapshot={
            "structuring": {"changed": True, "mode": "live_out", "verdict": "stale changed"},
            "postprocess": {"changed": True, "mode": "live_out", "verdict": "stale changed"},
        },
    )
    function = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_recover_fast_exe_catalog",
        lambda *_args, **_kwargs: [(SimpleNamespace(), function)],
    )
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="timeout",
            payload="Timed out after 2s.",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
            partial_payload="int partial(void) { return 1; }",
            tail_validation={
                "structuring": {"changed": False, "mode": "live_out", "verdict": "structuring stable"},
                "postprocess": {"changed": False, "mode": "live_out", "verdict": "postprocess stable"},
            },
        ),
    )
    monkeypatch.setattr(decompile, "_try_decompile_non_optimized_slice", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_format_asm_range", lambda *_args, **_kwargs: "mov ax, ax")
    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x11423, 0x11425))
    monkeypatch.setattr(decompile, "_probe_lift_break", lambda *_args, **_kwargs: "<probe>")
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "3"])
    captured = capsys.readouterr()

    assert rc == 2
    assert "/* -- c (partial timeout) -- */" in captured.out
    assert "[tail-validation] whole-tail validation clean across 1 functions" in captured.err
    assert '"detail_cache_path": "' in captured.err
    assert '"detail_cache_path": null' not in captured.err
    assert "stale changed" not in captured.err


def test_main_direct_sidecar_bounded_asm_fallback_does_not_reuse_stale_project_snapshot(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
        _inertia_last_tail_validation_snapshot={
            "structuring": {"changed": False, "mode": "live_out", "verdict": "stale stable"},
            "postprocess": {"changed": False, "mode": "live_out", "verdict": "stale stable"},
        },
    )
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x10010: "sub_10010"},
        code_ranges={0x10010: (0x10010, 0x10020)},
        absolute_addrs=True,
        source_format="cod_listing",
    )

    def _fake_timeout(fn, **kwargs):
        if kwargs.get("thread_name_prefix") == "recovery":
            raise decompile._AnalysisTimeout
        return fn()

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_timeout)
    monkeypatch.setattr(decompile, "_try_decompile_sidecar_slice", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_format_asm_range", lambda *_args, **_kwargs: "mov ax, ax")
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--addr", "0x10010", "--timeout", "2"])
    captured = capsys.readouterr()

    assert rc == 4
    assert "/* == asm fallback == */" in captured.out
    assert "mov ax, ax" in captured.out
    assert "[tail-validation]" in captured.err
    assert "not collected" in captured.err
    assert "detail artifact " in captured.err
    assert '"records":' in captured.err
    assert '"scanned":1' in captured.err or '"scanned": 1' in captured.err
    assert '"detail_cache_path": "' in captured.err
    assert '"detail_cache_path": null' not in captured.err
    assert "stale stable" not in captured.err


def test_main_aggregate_asm_fallback_does_not_reuse_stale_project_snapshot(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
        _inertia_last_tail_validation_snapshot={
            "structuring": {"changed": False, "mode": "live_out", "verdict": "stale stable"},
            "postprocess": {"changed": False, "mode": "live_out", "verdict": "stale stable"},
        },
    )
    function = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_recover_fast_exe_catalog",
        lambda *_args, **_kwargs: [(SimpleNamespace(), function)],
    )
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="error",
            payload="Decompiler did not produce code.",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )
    monkeypatch.setattr(decompile, "_try_decompile_non_optimized_slice", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_probe_lift_break", lambda *_args, **_kwargs: "<probe>")
    monkeypatch.setattr(decompile, "_format_asm_range", lambda *_args, **_kwargs: "mov ax, ax")
    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x10010, 0x10012))
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "1"])
    captured = capsys.readouterr()

    assert rc == 2
    assert "-- asm fallback --" in captured.out
    assert "mov ax, ax" in captured.err
    assert "mov ax, ax" not in captured.out
    assert "[tail-validation]" in captured.err
    assert "not collected" in captured.err
    assert "detail artifact " in captured.err
    assert '"records":' in captured.err
    assert '"scanned":1' in captured.err or '"scanned": 1' in captured.err
    assert '"detail_cache_path": "' in captured.err
    assert '"detail_cache_path": null' not in captured.err
    assert "stale stable" not in captured.err


def test_main_reports_uncapped_seeded_function_count(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "life2.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    cfg = SimpleNamespace(functions={})
    entry_function = SimpleNamespace(addr=0x11423, name="_start", project=project)
    seed_functions = [
        (SimpleNamespace(), SimpleNamespace(addr=0x10010, name="sub_10010", project=project)),
        (SimpleNamespace(), SimpleNamespace(addr=0x10020, name="sub_10020", project=project)),
    ]

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_recover_fast_exe_catalog", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_recover_partial_cfg", lambda *_args, **_kwargs: cfg)
    monkeypatch.setattr(decompile, "_interesting_functions", lambda _cfg, limit=None: ([entry_function], 1))
    monkeypatch.setattr(
        decompile,
        "_recover_seeded_exe_functions",
        lambda *_args, **_kwargs: (seed_functions, [0x10010, 0x10020, 0x10030]),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
            elapsed=1.0,
            byte_count=8,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc == 2
    assert "/* functions queued for decompilation: 4 */" in out
    assert (
        "/* showing first 2 functions because --max-functions=2; raise it or omit the option to decompile all queued functions */"
        in out
    )


def test_main_reports_uncapped_cached_function_count(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    recovered_pairs = [
        (
            SimpleNamespace(),
            SimpleNamespace(addr=0x10010, name="sub_10010", project=project, get_call_sites=lambda: ()),
        ),
        (
            SimpleNamespace(),
            SimpleNamespace(addr=0x10020, name="sub_10020", project=project, get_call_sites=lambda: ()),
        ),
    ]

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [0x10010, 0x10020, 0x10030])
    monkeypatch.setattr(decompile, "_recover_cached_function_pairs", lambda *_args, **_kwargs: recovered_pairs)
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            byte_count=1,
            elapsed=0.01,
            function=item.function,
            function_cfg=item.function_cfg,
            tail_validation={
                "structuring": {
                    "status": "stable",
                    "changed": False,
                },
                "postprocess": {
                    "status": "stable",
                    "changed": False,
                },
            },
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* functions queued for decompilation: 3 */" in out
    assert (
        "/* showing first 2 functions because --max-functions=2; raise it or omit the option to decompile all queued functions */"
        in out
    )


def test_main_decompiles_all_functions_by_default_without_sidecar(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("INERTIA_ENABLE_SERIAL_FORK_PER_FUNCTION", "0")
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    recovered_pairs = [
        (SimpleNamespace(), SimpleNamespace(addr=0x10000 + i * 0x10, name=f"sub_{i:04x}", project=project))
        for i in range(30)
    ]
    stored_pairs = []

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(
        decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [pair[1].addr for pair in recovered_pairs]
    )
    monkeypatch.setattr(decompile, "_recover_cached_function_pairs", lambda *_args, **_kwargs: list(recovered_pairs))
    monkeypatch.setattr(
        decompile,
        "_supplement_cached_seeded_recovery",
        lambda _project, pairs, addrs, **_kwargs: (pairs, addrs),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", lambda fn, *, timeout: fn())
    monkeypatch.setattr(
        decompile,
        "_store_catalog_address_cache",
        lambda _project, _binary, function_cfg_pairs: stored_pairs.extend(function_cfg_pairs),
    )
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            byte_count=1,
            elapsed=0.01,
            function=item.function,
            function_cfg=item.function_cfg,
            tail_validation={
                "structuring": {
                    "status": "stable",
                    "changed": False,
                },
                "postprocess": {
                    "status": "stable",
                    "changed": False,
                },
            },
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* functions queued for decompilation: 30 */" in out
    assert "showing first 8 by default for responsiveness" not in out
    assert "summary: decompiled 30/30 selected functions" in out
    assert len(stored_pairs) == 30


def test_main_does_not_auto_cap_noninteractive_stdout_without_sidecar(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("INERTIA_ENABLE_SERIAL_FORK_PER_FUNCTION", "0")
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    recovered_pairs = [
        (SimpleNamespace(), SimpleNamespace(addr=0x10000 + i * 0x10, name=f"sub_{i:04x}", project=project))
        for i in range(30)
    ]

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_stdout_is_interactive", lambda: False)
    monkeypatch.setattr(
        decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [pair[1].addr for pair in recovered_pairs]
    )
    monkeypatch.setattr(decompile, "_recover_cached_function_pairs", lambda *_args, **_kwargs: list(recovered_pairs))
    monkeypatch.setattr(
        decompile,
        "_supplement_cached_seeded_recovery",
        lambda _project, pairs, addrs, **_kwargs: (pairs, addrs),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", lambda fn, *, timeout: fn())
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            byte_count=1,
            elapsed=0.01,
            function=item.function,
            function_cfg=item.function_cfg,
            tail_validation={
                "structuring": {
                    "status": "stable",
                    "changed": False,
                },
                "postprocess": {
                    "status": "stable",
                    "changed": False,
                },
            },
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "showing first 8 by default for responsiveness" not in out
    assert "/* info: selected 30 function(s) for decompilation */" in out
    assert "summary: decompiled 30/30 selected functions" in out


def test_main_reports_pure_recovery_mode_and_attempt_states(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    recovered_pairs = [
        (SimpleNamespace(), SimpleNamespace(addr=0x10010, name="sub_10010", project=project)),
        (SimpleNamespace(), SimpleNamespace(addr=0x10020, name="sub_10020", project=project)),
    ]

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [0x10010, 0x10020])
    monkeypatch.setattr(decompile, "_recover_cached_function_pairs", lambda *_args, **_kwargs: list(recovered_pairs))
    monkeypatch.setattr(
        decompile,
        "_supplement_cached_seeded_recovery",
        lambda _project, pairs, addrs, **_kwargs: (pairs, addrs),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_try_decompile_non_optimized_slice", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project, **_kwargs: [0x10010] * 102)

    def _fake_run(item, **_kwargs):
        if item.function.addr == 0x10010:
            return decompile.FunctionWorkResult(
                index=item.index,
                status="ok",
                payload=f"int {item.function.name}(void) {{ return 0; }}",
                debug_output="",
                function=item.function,
                function_cfg=item.function_cfg,
                tail_validation={
                    "structuring": {
                        "changed": False,
                        "mode": "live_out",
                        "verdict": "structuring stable",
                        "summary_text": None,
                    },
                    "postprocess": {
                        "changed": False,
                        "mode": "live_out",
                        "verdict": "postprocess stable",
                        "summary_text": None,
                    },
                },
            )
        return decompile.FunctionWorkResult(
            index=item.index,
            status="timeout",
            payload="Timed out after 2s.",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
            tail_validation={},
        )

    monkeypatch.setattr(decompile, "_run_function_work_item", _fake_run)

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    captured = capsys.readouterr()
    out = captured.out

    assert rc == 2
    assert "/* info: recovery evidence: pure binary recovery mode (no helper metadata/debug info found) */" in out
    assert "/* functions queued for decompilation: 2 */" in out
    assert "/* info: selected 2 function(s) for display */" in out
    assert "/* info: decompilation attempted for 2/2 displayed function(s) */" in out
    assert "/* info: function 0x10010 sub_10010 attempt=decompiled validation=passed */" in captured.err
    assert "/* info: function 0x10020 sub_10020 attempt=timed_out validation=uncollected */" in captured.err


def test_main_uses_ranked_binary_placeholders_when_upfront_catalog_is_empty(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )

    monkeypatch.setenv("INERTIA_ENABLE_RANKED_EXE_DISCOVERY", "1")

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_recover_fast_exe_catalog", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile, "_recover_partial_cfg", lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError())
    )
    monkeypatch.setattr(decompile, "_recover_cfg", lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError()))
    monkeypatch.setattr(decompile, "_recover_fast_seed_functions", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project, **_kwargs: [0x10010, 0x10040, 0x10080])
    monkeypatch.setattr(
        decompile,
        "_recover_ranked_binary_function",
        lambda _project, addr, name, **_kwargs: (
            SimpleNamespace(),
            SimpleNamespace(addr=addr, name=name, project=project, is_plt=False, is_simprocedure=False),
        ),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            byte_count=1,
            elapsed=0.01,
            function=item.function,
            function_cfg=item.function_cfg,
            tail_validation={
                "structuring": {
                    "changed": False,
                    "mode": "live_out",
                    "verdict": "structuring stable",
                    "summary_text": None,
                },
                "postprocess": {
                    "changed": False,
                    "mode": "live_out",
                    "verdict": "postprocess stable",
                    "summary_text": None,
                },
            },
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* info: direct-binary recovery found 3 likely non-library function entries */" in out
    assert "/* info: selected 2 function(s) for display */" in out
    assert "/* == function 0x10010 sub_10010 == */" in out
    assert "/* == function 0x10040 sub_10040 == */" in out
    assert "/* info: decompilation attempted for 2/2 displayed function(s) */" in out


def test_main_prefers_quickly_recoverable_ranked_binary_preview_items(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_recover_fast_exe_catalog", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile, "_recover_partial_cfg", lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError())
    )
    monkeypatch.setattr(decompile, "_recover_cfg", lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError()))
    monkeypatch.setattr(decompile, "_recover_fast_seed_functions", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project, **_kwargs: [0x10B4B, 0x10010, 0x114CD])
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)

    def fake_recover(_project, addr, name, **_kwargs):
        if addr == 0x10B4B:
            raise TimeoutError("slow seed")
        return (
            SimpleNamespace(),
            SimpleNamespace(addr=addr, name=name, project=project, is_plt=False, is_simprocedure=False),
        )

    monkeypatch.setattr(decompile, "_recover_ranked_binary_function", fake_recover)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            tail_validation=_fake_stable_tail_validation(),
            byte_count=1,
            elapsed=0.01,
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* == function 0x10010 sub_10010 == */" in out
    assert "/* == function 0x114cd sub_114cd == */" in out
    assert "/* == function 0x10b4b sub_10b4b == */" not in out


def test_main_selected_count_reflects_supplemented_hidden_sidecar_display(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    metadata = LSTMetadata(
        source_format="flair_pat+flair_sig",
        code_labels={0x10010: "lib_only"},
        code_ranges={},
        data_labels={},
        signature_code_addrs=frozenset({0x10010}),
        absolute_addrs=True,
    )
    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_visible_code_labels", lambda _metadata: {})
    monkeypatch.setattr(decompile, "_recovery_code_labels", lambda _metadata: dict(metadata.code_labels))
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project, **_kwargs: [0x11423, 0x11450, 0x10010, 0x100EA])
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", lambda fn, *, timeout: fn())
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_rank_function_cfg_pairs_for_display", lambda _project, pairs: list(pairs))
    monkeypatch.setattr(
        decompile,
        "_recover_ranked_binary_function",
        lambda _project, addr, name, **_kwargs: (
            SimpleNamespace(),
            SimpleNamespace(addr=addr, name=name, project=project),
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            tail_validation=_fake_stable_tail_validation(),
            byte_count=1,
            elapsed=0.01,
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "4"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* info: selected 4 function(s) for display */" in out
    assert "/* info: decompilation attempted for 4/4 displayed function(s) */" in out


def test_main_hidden_sidecar_fills_display_slots_from_ranked_preview(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    metadata = LSTMetadata(
        source_format="flair_pat+flair_sig",
        code_labels={0x10010: "lib_only"},
        code_ranges={},
        data_labels={},
        signature_code_addrs=frozenset({0x10010}),
        absolute_addrs=True,
    )
    initial_pairs = [
        (SimpleNamespace(), SimpleNamespace(addr=0x11423, name="sub_11423", project=project)),
        (SimpleNamespace(), SimpleNamespace(addr=0x1179E, name="sub_1179e", project=project)),
    ]

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_visible_code_labels", lambda _metadata: {})
    monkeypatch.setattr(decompile, "_recovery_code_labels", lambda _metadata: dict(metadata.code_labels))
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project, **_kwargs: [0x11423, 0x1179E, 0x10010, 0x100EA])
    monkeypatch.setattr(
        decompile, "_recover_seeded_exe_functions", lambda *_args, **_kwargs: (list(initial_pairs), [0x11423, 0x1179E])
    )
    monkeypatch.setattr(
        decompile,
        "_prepare_ranked_binary_preview_items",
        lambda *_args, **_kwargs: [
            decompile.FunctionWorkItem(
                index=1,
                function_cfg=None,
                function=SimpleNamespace(addr=0x10010, name="sub_10010", project=project),
            ),
            decompile.FunctionWorkItem(
                index=2,
                function_cfg=None,
                function=SimpleNamespace(addr=0x100EA, name="sub_100ea", project=project),
            ),
        ],
    )
    monkeypatch.setattr(
        decompile,
        "_recover_ranked_binary_function",
        lambda _project, addr, name, **_kwargs: (
            SimpleNamespace(),
            SimpleNamespace(addr=addr, name=name, project=project, is_plt=False, is_simprocedure=False),
        ),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 4)
    monkeypatch.setattr(decompile, "_rank_function_cfg_pairs_for_display", lambda _project, pairs: list(pairs))
    monkeypatch.setattr(
        decompile,
        "_supplement_function_cfg_pairs_with_seeded_recovery",
        lambda _project, pairs, **_kwargs: list(pairs),
    )
    monkeypatch.setattr(
        decompile,
        "_supplement_function_cfg_pairs_with_ranked_preview",
        lambda _project, pairs, _ranked, **_kwargs: list(pairs),
    )
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            tail_validation=_fake_stable_tail_validation(),
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "4"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* info: selected 4 function(s) for display */" in out
    assert "/* parallel function decompilation: disabled (RAM pressure or single function) */" in out
    assert "/* info: decompilation attempted for 4/4 displayed function(s) */" in out


def test_main_hidden_sidecar_defaults_to_all_ranked_functions(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    metadata = LSTMetadata(
        source_format="flair_pat+flair_sig",
        code_labels={0x10010: "lib_only"},
        code_ranges={},
        data_labels={},
        signature_code_addrs=frozenset({0x10010}),
        absolute_addrs=True,
    )
    seeded_pairs = [
        (SimpleNamespace(), SimpleNamespace(addr=0x11423, name="_start", project=project)),
        (SimpleNamespace(), SimpleNamespace(addr=0x1179E, name="sub_1179e", project=project)),
    ]
    ranked_addrs = [0x11423, 0x1179E, 0x1157C, 0x11593]
    seen_items = []

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setenv("INERTIA_ENABLE_SERIAL_FORK_PER_FUNCTION", "0")
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_visible_code_labels", lambda _metadata: {})
    monkeypatch.setattr(decompile, "_recovery_code_labels", lambda _metadata: dict(metadata.code_labels))
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project, **_kwargs: list(ranked_addrs))
    monkeypatch.setattr(
        decompile, "_recover_seeded_exe_functions", lambda *_args, **_kwargs: (list(seeded_pairs), [0x11423, 0x1179E])
    )
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", lambda func, *, timeout: func())
    monkeypatch.setattr(
        decompile,
        "_recover_ranked_binary_function",
        lambda _project, addr, name, **_kwargs: (
            SimpleNamespace(),
            SimpleNamespace(addr=addr, name=name, project=project),
        ),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)

    def fake_run(item, **_kwargs):
        seen_items.append((item.function.addr, item.function_cfg is not None))
        return decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            tail_validation=_fake_stable_tail_validation(),
            function=item.function,
            function_cfg=item.function_cfg,
        )

    monkeypatch.setattr(decompile, "_run_function_work_item", fake_run)

    rc = decompile.main([str(binary), "--timeout", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* info: selected 4 function(s) for decompilation */" in out
    assert "showing first" not in out
    assert seen_items == [
        (0x11423, True),
        (0x1179E, True),
        (0x1157C, True),
        (0x11593, True),
    ]


def test_main_serial_whole_binary_path_does_not_wrap_function_work_items_in_executor(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    recovered_pairs = [
        (SimpleNamespace(), SimpleNamespace(addr=0x10010, name="sub_10010", project=project)),
        (SimpleNamespace(), SimpleNamespace(addr=0x10020, name="sub_10020", project=project)),
    ]
    seen = []

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [0x10010, 0x10020])
    monkeypatch.setattr(decompile, "_recover_cached_function_pairs", lambda *_args, **_kwargs: list(recovered_pairs))
    monkeypatch.setattr(
        decompile,
        "_supplement_cached_seeded_recovery",
        lambda _project, pairs, addrs, **_kwargs: (pairs, addrs),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "DaemonThreadPoolExecutor",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("serial path should not create executor")),
    )

    def _fake_run(item, **_kwargs):
        seen.append(item.function.addr)
        return decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            tail_validation=_fake_stable_tail_validation(),
            function=item.function,
            function_cfg=item.function_cfg,
        )

    monkeypatch.setattr(decompile, "_run_function_work_item", _fake_run)

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert sorted(seen) == [0x10010, 0x10020]
    assert "summary: decompiled 2/2 shown functions" in out


def test_main_full_pure_binary_uses_parallel_clean_process_lane_by_default(
    monkeypatch,
    tmp_path,
    capsys,
):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    recovered_pairs = [
        (SimpleNamespace(), SimpleNamespace(addr=0x10010, name="sub_10010", project=project)),
        (SimpleNamespace(), SimpleNamespace(addr=0x10020, name="sub_10020", project=project)),
    ]
    seen = []
    clean_process_calls = []
    later_artifact_written = threading.Event()
    output_c_dir = tmp_path / "generated"

    monkeypatch.setattr(cli_core, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(cli_core, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cli_core, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cli_core, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(cli_core, "_choose_function_parallelism", lambda count: min(2, count))
    monkeypatch.setattr(cli_core, "_load_catalog_address_cache", lambda *_args, **_kwargs: [0x10010, 0x10020])
    monkeypatch.setattr(cli_core, "_recover_cached_function_pairs", lambda *_args, **_kwargs: list(recovered_pairs))
    monkeypatch.setattr(
        cli_core,
        "_supplement_cached_seeded_recovery",
        lambda _project, pairs, addrs, **_kwargs: (pairs, addrs),
    )
    monkeypatch.setattr(cli_core.threading, "active_count", lambda: 3)

    def _fake_clean_process(context, item, *, timeout):
        clean_process_calls.append((context.project, item.function.addr, item.recovery_addr, timeout))
        seen.append(
            (
                item.function.addr,
                item.recovery_addr,
            )
        )
        if item.function.addr == 0x10010:
            assert later_artifact_written.wait(timeout=2), "later completed artifact was not persisted promptly"
        return cli_core.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            tail_validation=_fake_stable_tail_validation(),
            function=item.function,
            function_cfg=item.function_cfg,
        )

    monkeypatch.setattr(cli_core, "_run_serial_clean_process_work_item_8616", _fake_clean_process)
    original_write = cli_core.write_generated_function_c

    def _record_artifact(output_dir, *, address, name, payload):
        destination = original_write(output_dir, address=address, name=name, payload=payload)
        if address == 0x10020:
            later_artifact_written.set()
        return destination

    monkeypatch.setattr(cli_core, "write_generated_function_c", _record_artifact)

    rc = cli_core.main([str(binary), "--timeout", "2", "--output-c-dir", str(output_c_dir)])
    captured = capsys.readouterr()
    out = captured.out

    assert rc == 0, out
    assert sorted(seen) == [
        (0x10010, 0x10010),
        (0x10020, 0x10020),
    ]
    assert sorted(clean_process_calls) == [
        (project, 0x10010, 0x10010, 2),
        (project, 0x10020, 0x10020, 2),
    ]
    assert "/* parallel function decompilation: 2 clean processes, one function per process */" in out
    assert "[dbg] clean parallel function worker: start 0x10010 sub_10010" in captured.err
    assert (output_c_dir / "00010010-sub_10010.c").is_file()
    assert (output_c_dir / "00010020-sub_10020.c").is_file()
    assert (output_c_dir / "translation-unit.c").is_file()


def test_prepare_ranked_binary_preview_items_uses_fork_lane_on_main_thread(monkeypatch):
    project = SimpleNamespace()
    fork_calls = []

    monkeypatch.setattr(decompile, "_analysis_timeout_use_fork_8616", lambda: True)
    monkeypatch.setattr(
        decompile,
        "_recover_ranked_binary_function",
        lambda _project, addr, name, **_kwargs: (
            SimpleNamespace(),
            SimpleNamespace(addr=addr, name=name, project=project),
        ),
    )

    def _fake_fork(func, *, timeout):
        fork_calls.append(timeout)
        return func()

    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", _fake_fork)

    items = decompile._prepare_ranked_binary_preview_items(
        project,
        [0x10010, 0x10020, 0x10030],
        max_count=2,
        timeout=3,
        window=0x200,
        low_memory=False,
    )

    assert [item.function.addr for item in items] == [0x10010, 0x10020]
    assert fork_calls == [3, 3]


def test_main_hidden_sidecar_prefers_ranked_preview_over_non_entry_seeded_pairs(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    metadata = LSTMetadata(
        source_format="flair_pat+flair_sig",
        code_labels={0x10010: "lib_only"},
        code_ranges={},
        data_labels={},
        signature_code_addrs=frozenset({0x10010}),
        absolute_addrs=True,
    )
    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_visible_code_labels", lambda _metadata: {})
    monkeypatch.setattr(decompile, "_recovery_code_labels", lambda _metadata: dict(metadata.code_labels))
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project, **_kwargs: [0x10010, 0x100EA, 0x10179])
    monkeypatch.setattr(
        decompile,
        "_recover_seeded_exe_functions",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("seed catalog should be skipped")),
    )
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", lambda fn, *, timeout: fn())
    monkeypatch.setattr(
        decompile,
        "_recover_ranked_binary_function",
        lambda _project, addr, name, **_kwargs: (
            SimpleNamespace(),
            SimpleNamespace(addr=addr, name=name, project=project),
        ),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_rank_function_cfg_pairs_for_display", lambda _project, pairs: list(pairs))
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            tail_validation=_fake_stable_tail_validation(),
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "3"])
    captured = capsys.readouterr()
    out = captured.out

    assert rc == 0
    assert "/* == function 0x10010 sub_10010 == */" in out
    assert "/* == function 0x100ea sub_100ea == */" in out
    assert "/* == function 0x10179 sub_10179 == */" in out
    assert "/* == function 0x11423 _start == */" not in out
    assert "/* == function 0x1179e slow_seed == */" not in out


def test_main_hidden_sidecar_disables_isolated_retry_in_capped_serial_lane(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    metadata = LSTMetadata(
        source_format="flair_pat+flair_sig",
        code_labels={0x10010: "lib_only"},
        code_ranges={},
        data_labels={},
        signature_code_addrs=frozenset({0x10010}),
        absolute_addrs=True,
    )
    seen_retry_flags = []

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_visible_code_labels", lambda _metadata: {})
    monkeypatch.setattr(decompile, "_recovery_code_labels", lambda _metadata: dict(metadata.code_labels))
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project, **_kwargs: [0x115D8, 0x1157C])
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", lambda fn, *, timeout: fn())
    monkeypatch.setattr(
        decompile,
        "_recover_ranked_binary_function",
        lambda _project, addr, name, **_kwargs: (
            SimpleNamespace(),
            SimpleNamespace(addr=addr, name=name, project=project),
        ),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)

    def fake_run(item, **kwargs):
        seen_retry_flags.append(kwargs.get("allow_isolated_retry"))
        return decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            tail_validation=_fake_stable_tail_validation(),
            function=item.function,
            function_cfg=item.function_cfg,
        )

    monkeypatch.setattr(decompile, "_run_function_work_item", fake_run)

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    capsys.readouterr()

    assert rc == 0
    assert seen_retry_flags == [True, True]


def test_main_hidden_sidecar_uses_ranked_preview_before_seed_catalog(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    metadata = LSTMetadata(
        source_format="flair_pat+flair_sig",
        code_labels={0x10010: "lib_only"},
        code_ranges={},
        data_labels={},
        signature_code_addrs=frozenset({0x10010}),
        absolute_addrs=True,
    )

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_visible_code_labels", lambda _metadata: {})
    monkeypatch.setattr(decompile, "_recovery_code_labels", lambda _metadata: dict(metadata.code_labels))
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project, **_kwargs: [0x10010, 0x100EA, 0x10179, 0x101A3])
    monkeypatch.setattr(
        decompile,
        "_recover_seeded_exe_functions",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("seed catalog should be skipped")),
    )
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", lambda fn, *, timeout: fn())
    monkeypatch.setattr(
        decompile,
        "_recover_ranked_binary_function",
        lambda _project, addr, name, **_kwargs: (
            SimpleNamespace(),
            SimpleNamespace(addr=addr, name=name, project=project),
        ),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_rank_function_cfg_pairs_for_display", lambda _project, pairs: list(pairs))
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            tail_validation=_fake_stable_tail_validation(),
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    captured = capsys.readouterr()
    out = captured.out
    assert rc == 0
    assert "/* info: selected 2 function(s) for display */" in out


def test_rank_hidden_sidecar_pairs_for_display_throughput_keeps_entry_only_for_tight_cap(monkeypatch):
    project = SimpleNamespace(entry=0x11423)
    pairs = [
        (SimpleNamespace(), SimpleNamespace(addr=0x11423, name="_start", project=project)),
        (SimpleNamespace(), SimpleNamespace(addr=0x10010, name="fast_a", project=project)),
        (SimpleNamespace(), SimpleNamespace(addr=0x100EA, name="fast_b", project=project)),
        (SimpleNamespace(), SimpleNamespace(addr=0x10179, name="tiny_wrapper", project=project)),
    ]
    complexity_by_addr = {
        0x11423: (5, 30),
        0x10010: (2, 10),
        0x100EA: (3, 18),
        0x10179: (1, 6),
    }

    monkeypatch.setattr(decompile, "_function_complexity", lambda function: complexity_by_addr[function.addr])
    monkeypatch.setattr(decompile, "_function_recovery_truncated", lambda _function: False)

    ranked_tight = decompile._rank_hidden_sidecar_pairs_for_display_throughput(
        project,
        pairs,
        limit=2,
    )
    ranked_wide = decompile._rank_hidden_sidecar_pairs_for_display_throughput(
        project,
        pairs,
        limit=3,
    )

    assert [function.addr for _cfg, function in ranked_tight] == [0x10010, 0x11423]
    assert [function.addr for _cfg, function in ranked_wide] == [0x10010, 0x100EA, 0x10179]


def test_function_complexity_caches_project_block_decodes():
    calls: list[tuple[int, int]] = []

    class FakeFactory:
        def block(self, addr, *, opt_level):
            calls.append((addr, opt_level))
            return SimpleNamespace(bytes=b"\x90" * (addr & 0xF))

    project = SimpleNamespace(factory=FakeFactory())
    function = SimpleNamespace(
        project=project,
        block_addrs_set={0x1002, 0x1005},
        info={},
    )

    assert decompile._function_complexity(function) == (2, 7)
    assert decompile._function_complexity(function) == (2, 7)
    assert calls == [(0x1002, 0), (0x1005, 0)]


def test_function_profile_reuses_factory_block_profile_cache():
    calls: list[tuple[int, int]] = []

    class FakeFactory:
        def block(self, addr, *, opt_level):
            calls.append((addr, opt_level))
            return SimpleNamespace(
                bytes=b"\x90" * (addr & 0xF),
                capstone=SimpleNamespace(insns=()),
            )

    project = SimpleNamespace(factory=FakeFactory())
    function = SimpleNamespace(
        project=project,
        block_addrs_set={0x1002, 0x1005},
        info={},
    )

    assert decompile._function_complexity(function) == (2, 7)
    profile = decompile._function_decompilation_profile(function, block_count=2, byte_count=7)
    assert profile["internal_call_count"] == 0
    assert profile["stack_probe_call_count"] == 0
    assert decompile._function_decompilation_profile(function, block_count=2, byte_count=7) == profile
    assert calls == [(0x1002, 0), (0x1005, 0)]


def test_function_profile_handles_block_decode_errors_using_cached_fallback():
    calls: list[tuple[int, int]] = []

    class FakeFactory:
        def block(self, addr, *, opt_level):
            calls.append((addr, opt_level))
            raise RuntimeError("decode failed")

    project = SimpleNamespace(factory=FakeFactory())
    function = SimpleNamespace(
        project=project,
        block_addrs_set={0x1234},
        info={},
    )

    assert decompile._function_complexity(function) == (1, 0)
    profile = decompile._function_decompilation_profile(function, block_count=1, byte_count=0)
    assert profile["call_site_count"] == 0
    assert profile["internal_call_count"] == 0
    assert profile["stack_probe_call_count"] == 0
    assert decompile._function_decompilation_profile(function, block_count=1, byte_count=0) == profile
    assert calls == [(0x1234, 0)]


def test_supplement_function_cfg_pairs_with_ranked_preview_adds_recoverable_pairs(monkeypatch):
    project = SimpleNamespace()
    existing_pair = (SimpleNamespace(), SimpleNamespace(addr=0x11423, name="sub_11423", project=project))

    monkeypatch.setattr(
        decompile,
        "_prepare_ranked_binary_preview_items",
        lambda *_args, **_kwargs: [
            decompile.FunctionWorkItem(
                index=1,
                function_cfg=SimpleNamespace(),
                function=SimpleNamespace(addr=0x10010, name="sub_10010", project=project),
            ),
            decompile.FunctionWorkItem(
                index=2,
                function_cfg=SimpleNamespace(),
                function=SimpleNamespace(addr=0x100EA, name="sub_100ea", project=project),
            ),
            decompile.FunctionWorkItem(
                index=3,
                function_cfg=None,
                function=SimpleNamespace(addr=0x10179, name="sub_10179", project=project),
            ),
        ],
    )

    supplemented = decompile._supplement_function_cfg_pairs_with_ranked_preview(
        project,
        [existing_pair],
        [0x10010, 0x100EA, 0x10179],
        target_count=3,
        timeout=6,
        window=0x200,
        low_memory=False,
    )

    assert [func.addr for _cfg, func in supplemented] == [0x11423, 0x10010, 0x100EA]


def test_supplement_function_cfg_pairs_with_seeded_recovery_adds_unique_pairs(monkeypatch):
    project = SimpleNamespace()
    existing_pair = (SimpleNamespace(), SimpleNamespace(addr=0x11423, name="sub_11423", project=project))
    monkeypatch.setattr(
        decompile,
        "_recover_seeded_exe_functions",
        lambda *_args, **_kwargs: [
            (SimpleNamespace(), SimpleNamespace(addr=0x11423, name="sub_11423", project=project)),
            (SimpleNamespace(), SimpleNamespace(addr=0x10010, name="sub_10010", project=project)),
            (SimpleNamespace(), SimpleNamespace(addr=0x100EA, name="sub_100ea", project=project)),
        ],
    )

    supplemented = decompile._supplement_function_cfg_pairs_with_seeded_recovery(
        project,
        [existing_pair],
        timeout=6,
        target_count=3,
    )

    assert [func.addr for _cfg, func in supplemented] == [0x11423, 0x10010, 0x100EA]


def test_main_reports_sidecar_debug_assisted_recovery_mode(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    metadata = LSTMetadata(
        source_format="codeview_nb00",
        code_labels={0x10010: "sub_10010", 0x10020: "sub_10020"},
        code_ranges={0x10010: (0x10010, 0x10020), 0x10020: (0x10020, 0x10030)},
        data_labels={},
        absolute_addrs=True,
    )

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(
        decompile,
        "_visible_code_labels",
        lambda _metadata: dict(metadata.code_labels),
    )
    monkeypatch.setattr(decompile, "_recovery_code_labels", lambda _metadata: dict(metadata.code_labels))
    monkeypatch.setattr(
        decompile,
        "_rank_labeled_function_entries_cached",
        lambda _project, entries, _metadata: (list(entries), False),
    )
    monkeypatch.setattr(
        decompile,
        "_recover_lst_function",
        lambda _project, _metadata, offset, name, **_kwargs: (
            SimpleNamespace(),
            SimpleNamespace(addr=offset, name=name, project=project),
        ),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 2)
    monkeypatch.setattr(
        decompile,
        "_run_serial_clean_process_work_item_8616",
        lambda _context, item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
            tail_validation={},
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2"])
    out = capsys.readouterr().out

    assert rc in {0, 2}
    assert "/* info: recovery evidence: sidecar/debug-assisted recovery (codeview_nb00) */" in out
    assert "/* info: decompilation attempted for 2/2 selected function(s) */" in out


def test_main_limits_sidecar_catalog_preview_for_responsiveness(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400)),
    )
    metadata = LSTMetadata(
        code_labels={0x10000 + i * 0x10: f"proc_{i}" for i in range(30)},
        code_ranges={0x10000 + i * 0x10: (0x10000 + i * 0x10, 0x10000 + i * 0x10 + 0x20) for i in range(30)},
        data_labels={},
    )
    catalog_limits = []

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_visible_code_labels", lambda _metadata: dict(metadata.code_labels))
    monkeypatch.setattr(decompile, "_recovery_code_labels", lambda _metadata: {})
    monkeypatch.setattr(
        decompile,
        "_rank_labeled_function_entries_cached",
        lambda _project, entries, _metadata: (list(entries), False),
    )
    monkeypatch.setattr(
        decompile,
        "_format_sidecar_function_catalog",
        lambda _metadata, limit=None, **_kwargs: catalog_limits.append(limit) or "catalog-preview",
    )
    monkeypatch.setattr(
        decompile,
        "_recover_lst_function",
        lambda _project, offset, **_kwargs: (
            SimpleNamespace(),
            SimpleNamespace(addr=offset, name=metadata.code_labels[offset], project=project),
        ),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
            tail_validation=_fake_stable_tail_validation(),
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2"])
    out = capsys.readouterr().out

    assert rc in {0, 2}
    assert catalog_limits == [None]
    assert "catalog preview limited" not in out
    assert "showing first 8 by default for responsiveness" not in out


def test_recover_fast_exe_catalog_overscans_seed_limit_before_trimming(monkeypatch):
    project = SimpleNamespace(entry=0x11423)
    entry_pair = (SimpleNamespace(), SimpleNamespace(addr=0x11423, name="_start"))
    seeded_pairs = [
        (SimpleNamespace(), SimpleNamespace(addr=0x114CD, name="runtime")),
        (SimpleNamespace(), SimpleNamespace(addr=0x10010, name="sub_10010")),
        (SimpleNamespace(), SimpleNamespace(addr=0x100EA, name="sub_100ea")),
    ]
    recorded_limits: list[int | None] = []

    monkeypatch.setattr(decompile, "_rank_pre_entry_source_function_seeds_8616", lambda _project: [])
    monkeypatch.setattr(decompile, "_fallback_entry_function", lambda *_args, **_kwargs: entry_pair)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())

    def _fake_recover_fast_seed_functions(_project, *, timeout, limit):
        recorded_limits.append(limit)
        return seeded_pairs

    monkeypatch.setattr(decompile, "_recover_fast_seed_functions", _fake_recover_fast_seed_functions)
    monkeypatch.setattr(
        decompile,
        "_rank_function_cfg_pairs_for_display",
        lambda _project, pairs: [entry_pair, seeded_pairs[1], seeded_pairs[2], seeded_pairs[0]],
    )

    recovered = decompile._recover_fast_exe_catalog(project, timeout=4, window=0x200, low_memory=False, limit=2)

    assert recorded_limits == [6]
    assert [func.addr for _cfg, func in recovered] == [0x11423, 0x10010]


def test_rank_exe_function_seeds_tolerates_timed_out_entry_probe(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"\xe8\x00\x00\xc3")
    code = binary.read_bytes()
    project = SimpleNamespace(
        entry=0x1000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=binary,
                linked_base=0x1000,
                max_addr=len(code) - 1,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
            )
        ),
    )

    monkeypatch.setattr(decompile, "_seed_scan_windows", lambda _project, **_kwargs: [(0x1000, 0x1004)])
    monkeypatch.setattr(decompile, "_entry_window_seed_targets", lambda *_args, **_kwargs: {0x1003})
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_run_with_timeout_in_daemon_thread",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(decompile.FuturesTimeoutError()),
    )

    ranked = decompile._rank_exe_function_seeds(project)

    assert ranked == [0x1003]


def test_main_falls_back_after_fast_exe_catalog_timeout(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    cfg = SimpleNamespace(functions={})
    recovered_function = SimpleNamespace(addr=0x11423, name="_start", project=project)

    def _fake_timeout(fn, *, thread_name_prefix, **_kwargs):
        if thread_name_prefix == "fast-catalog":
            raise decompile.FuturesTimeoutError
        return fn()

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_timeout)
    monkeypatch.setattr(decompile, "_recover_partial_cfg", lambda *_args, **_kwargs: cfg)
    monkeypatch.setattr(decompile, "_interesting_functions", lambda _cfg, limit=None: ([recovered_function], 1))
    monkeypatch.setattr(decompile, "_recover_seeded_exe_functions", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            tail_validation=_fake_stable_tail_validation(),
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "1"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "Quick EXE function discovery timed out" in out
    assert "/* == function 0x11423 _start == */" in out


def test_main_streaming_timeout_reports_nonoptimized_skip_without_unvalidated_string_fallback(
    monkeypatch,
    tmp_path,
    capsys,
):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    cfg = SimpleNamespace(functions={})
    recovered_function = SimpleNamespace(addr=0x11423, name="_start", project=project)

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "_recover_partial_cfg", lambda *_args, **_kwargs: cfg)
    monkeypatch.setattr(decompile, "_interesting_functions", lambda _cfg, limit=None: ([recovered_function], 1))
    monkeypatch.setattr(decompile, "_recover_seeded_exe_functions", lambda *_args, **_kwargs: ([], []))
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile._AdaptivePerByteTimeoutModel, "observe_success", lambda self, *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="timeout",
            payload="Timed out after 2s.",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
            partial_payload=None,
            tail_validation={},
            skip_heavy_fallbacks=True,
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_try_decompile_non_optimized_slice",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("non-opt lane should stay closed")),
    )
    monkeypatch.setattr(
        decompile, "_try_emit_string_intrinsic_c", lambda *_args, **_kwargs: "int fallback(void) { return 7; }"
    )
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "8"])
    out = capsys.readouterr().out

    assert rc == 2
    assert "heavy fallback lane disabled for sweep mode (interactive_stdout=False, max_functions=8, addr=unset)" in out
    assert "/* -- c (string intrinsic fallback) -- */" not in out
    assert "int fallback(void) { return 7; }" not in out


def test_main_streaming_timeout_reports_nonoptimized_failure_without_unvalidated_string_fallback(
    monkeypatch, tmp_path, capsys
):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    cfg = SimpleNamespace(functions={})
    recovered_function = SimpleNamespace(addr=0x11423, name="_start", project=project)

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: True)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "_recover_partial_cfg", lambda *_args, **_kwargs: cfg)
    monkeypatch.setattr(decompile, "_interesting_functions", lambda _cfg, limit=None: ([recovered_function], 1))
    monkeypatch.setattr(decompile, "_recover_seeded_exe_functions", lambda *_args, **_kwargs: ([], []))
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile._AdaptivePerByteTimeoutModel, "observe_success", lambda self, *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="timeout",
            payload="Timed out after 2s.",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
            partial_payload=None,
            tail_validation={},
            skip_heavy_fallbacks=False,
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_try_decompile_non_optimized_slice",
        lambda *_args, **_kwargs: decompile.NonOptimizedSliceOutcome(
            rendered=None,
            status="error",
            payload="slice lift broke",
            failure_detail="shared-project slice lean: error: slice lift broke",
            attempt_failures=("shared-project slice lean: error: slice lift broke",),
        ),
    )
    monkeypatch.setattr(
        decompile, "_try_emit_string_intrinsic_c", lambda *_args, **_kwargs: "int fallback(void) { return 7; }"
    )
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "1"])
    out = capsys.readouterr().out

    assert rc == 2
    assert "shared-project slice lean: error: slice lift broke" in out
    assert "/* -- c (string intrinsic fallback) -- */" not in out
    assert "int fallback(void) { return 7; }" not in out


def test_main_falls_back_to_partial_timeout_before_asm_when_available(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    cfg = SimpleNamespace(functions={})
    recovered_function = SimpleNamespace(addr=0x11423, name="_start", project=project)

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "_recover_partial_cfg", lambda *_args, **_kwargs: cfg)
    monkeypatch.setattr(decompile, "_interesting_functions", lambda _cfg, limit=None: ([recovered_function], 1))
    monkeypatch.setattr(decompile, "_recover_seeded_exe_functions", lambda *_args, **_kwargs: ([], []))
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile._AdaptivePerByteTimeoutModel, "observe_success", lambda self, *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_try_decompile_non_optimized_slice", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_format_asm_range", lambda *_args, **_kwargs: "mov ax, ax")
    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x11423, 0x11425))
    monkeypatch.setattr(decompile, "_probe_lift_break", lambda *_args, **_kwargs: "<probe>")
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="timeout",
            payload="Timed out after 2s.",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
            partial_payload="int partial(void) { return 1; }",
            tail_validation={},
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "1"])
    captured = capsys.readouterr()
    out = captured.out

    assert rc == 2
    assert "/* info: function 0x11423 _start attempt=timed_out validation=uncollected */" in captured.err
    assert "/* problem: timeout */" in out
    assert "/* -- c (partial timeout) -- */" in out
    assert out.index("/* -- c (partial timeout) -- */") < out.index("-- asm fallback --")
    assert "int partial(void) { return 1; }" in out


def test_main_uses_seed_recovery_when_only_hidden_signature_labels_exist(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "life2.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    recovered_cfg = SimpleNamespace(functions={})
    recovered_function = SimpleNamespace(addr=0x10010, name="main", project=project)
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x11423: "_startup_sig"},
        code_ranges={},
        absolute_addrs=True,
        source_format="flair_pat+flair_sig",
    )

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_visible_code_labels", lambda _metadata: {})
    monkeypatch.setattr(decompile, "_recovery_code_labels", lambda _metadata: {0x11423: "_startup_sig"})
    monkeypatch.setattr(
        decompile,
        "_rank_labeled_function_entries",
        lambda *_args, **_kwargs: pytest.fail("visible-label ranking should not run"),
    )
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(
        decompile,
        "_recover_seeded_exe_functions",
        lambda *_args, **_kwargs: [(recovered_cfg, recovered_function)],
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            tail_validation=_fake_stable_tail_validation(),
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "1"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* == function 0x10010 main == */" in out


def test_main_serial_function_timeout_does_not_stall_whole_run(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    entry_function = SimpleNamespace(addr=0x11423, name="_start", project=project)
    body_function = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)
    calls = {"work": 0}

    def _fake_timeout(fn, *, thread_name_prefix, **_kwargs):
        if thread_name_prefix == "func-serial" and calls["work"] == 0:
            calls["work"] += 1
            raise decompile.FuturesTimeoutError
        return fn()

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: True)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_recover_fast_exe_catalog",
        lambda *_args, **_kwargs: [(SimpleNamespace(), entry_function), (SimpleNamespace(), body_function)],
    )
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_timeout)
    monkeypatch.setattr(decompile, "_format_asm_range", lambda *_args, **_kwargs: "0x1000: ret")
    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x1000, 0x1001))
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            tail_validation=_fake_stable_tail_validation(),
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* == function 0x11423 _start == */" in out
    assert "/* == function 0x10010 sub_10010 == */" in out


def test_choose_function_parallelism_honors_forced_serial_env(monkeypatch):
    monkeypatch.setenv("INERTIA_FORCE_SERIAL_FUNCTION_DECOMPILATION", "1")
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)

    assert decompile._choose_function_parallelism(8) == 1


def test_choose_function_parallelism_uses_n_minus_one_with_two_gib_budget(monkeypatch):
    monkeypatch.delenv("INERTIA_FORCE_SERIAL_FUNCTION_DECOMPILATION", raising=False)
    monkeypatch.setattr(runtime_support, "prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(runtime_support, "memory_available_mb", lambda: 4096)
    monkeypatch.setattr(runtime_support.os, "cpu_count", lambda: 8)

    assert runtime_support.choose_function_parallelism(20) == 7


def test_batch_function_timeout_preserves_complex_sortd_budget(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    function = SimpleNamespace(project=project)
    context = SimpleNamespace(
        args=SimpleNamespace(timeout=120, addr=None),
        timeout_was_explicit=False,
        remaining_sweep_budget_sec=lambda: None,
    )
    model = cli_core._AdaptivePerByteTimeoutModel(120, explicit_timeout=False, margin=1.5)
    monkeypatch.setattr(cli_core, "_function_complexity", lambda _function: (42, 438))
    monkeypatch.setattr(
        cli_core,
        "_effective_decompile_timeout_8616",
        lambda _project, timeout, **_kwargs: timeout,
    )
    monkeypatch.setattr(
        cli_core,
        "_enforce_function_timeout_cap",
        lambda timeout, **_kwargs: timeout,
    )

    timeout = cli_core._batch_function_decompile_timeout_8616(context, function, model)

    assert timeout == 360


def test_batch_function_timeout_covers_large_sortd_validation_overhead(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    function = SimpleNamespace(project=project)
    context = SimpleNamespace(
        args=SimpleNamespace(timeout=60, addr=None),
        timeout_was_explicit=False,
        remaining_sweep_budget_sec=lambda: None,
    )
    model = cli_core._AdaptivePerByteTimeoutModel(60, explicit_timeout=False, margin=1.5)
    monkeypatch.setattr(cli_core, "_function_complexity", lambda _function: (76, 459))
    monkeypatch.setattr(
        cli_core,
        "_effective_decompile_timeout_8616",
        lambda _project, timeout, **_kwargs: timeout,
    )
    monkeypatch.setattr(
        cli_core,
        "_enforce_function_timeout_cap",
        lambda timeout, **_kwargs: timeout,
    )

    timeout = cli_core._batch_function_decompile_timeout_8616(context, function, model)

    assert timeout == 360


def test_batch_function_timeout_promotes_project_large_floor_for_clean_finalization(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    function = SimpleNamespace(project=project)
    context = SimpleNamespace(
        args=SimpleNamespace(timeout=60, addr=None),
        timeout_was_explicit=False,
        remaining_sweep_budget_sec=lambda: None,
    )
    model = cli_core._AdaptivePerByteTimeoutModel(60, explicit_timeout=False, margin=1.5)
    monkeypatch.setattr(cli_core, "_function_complexity", lambda _function: (20, 200))
    monkeypatch.setattr(
        cli_core,
        "_effective_decompile_timeout_8616",
        lambda _project, _timeout, **_kwargs: 180,
    )
    monkeypatch.setattr(
        cli_core,
        "_enforce_function_timeout_cap",
        lambda timeout, **_kwargs: timeout,
    )

    timeout = cli_core._batch_function_decompile_timeout_8616(context, function, model)

    assert timeout == 240


def test_daemon_thread_pool_executor_detaches_non_waiting_workers_from_atexit_registry():
    executor = decompile.DaemonThreadPoolExecutor(max_workers=1, thread_name_prefix="detach-test")
    future = executor.submit(time.sleep, 0.5)
    deadline = time.time() + 2.0
    while not executor._threads and time.time() < deadline:
        time.sleep(0.01)
    threads = list(executor._threads)
    assert threads
    assert any(thread in _threads_queues for thread in threads)
    executor.shutdown(wait=False, cancel_futures=True)
    assert all(thread not in _threads_queues for thread in threads)
    future.cancel()


def test_run_function_work_item_uses_fork_lane_for_force_isolated_project(monkeypatch):
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x400)),
        analyses=SimpleNamespace(),
    )
    function = SimpleNamespace(addr=0x11423, name="_start", project=project)
    item = decompile.FunctionWorkItem(index=1, function_cfg=SimpleNamespace(), function=function)
    seen = {}

    monkeypatch.setattr(decompile.os, "name", "posix")
    monkeypatch.setattr(decompile.threading, "current_thread", lambda: decompile.threading.main_thread())
    monkeypatch.setattr(decompile.threading, "active_count", lambda: 1)
    monkeypatch.setattr(decompile, "_tail_validation_runtime_enabled", lambda _project: False)
    monkeypatch.setattr(decompile, "function_decompilation_cache_key_8616", lambda *_args, **_kwargs: None)

    def fake_fork_runner(fn, *, timeout):
        seen["timeout"] = timeout
        return fn()

    def fake_decompile_with_stats(*args, **kwargs):
        seen["project"] = args[0]
        seen["function"] = args[2]
        return ("ok", "int _start(void) { return 0; }", None, 1, 1, 0.1)

    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", fake_fork_runner)
    monkeypatch.setattr(decompile, "_decompile_function_with_stats", fake_decompile_with_stats)
    monkeypatch.setattr(decompile, "_tail_validation_snapshot_for_function_run", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_build_project",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("should not rebuild project")),
    )

    result = decompile._run_function_work_item(
        item,
        timeout=2,
        api_style="modern",
        binary_path=Path("/tmp/sample.exe"),
        cod_metadata=None,
        synthetic_globals=None,
        lst_metadata=None,
        enable_structured_simplify=True,
        force_isolated_project=True,
        allow_isolated_retry=False,
    )

    assert result.status == "ok"
    assert result.payload == "int _start(void) { return 0; }"
    assert seen["project"] is project
    assert seen["function"] is function
    assert seen["timeout"] == 3


def test_run_function_work_item_does_not_preflight_unknown_function(monkeypatch):
    project = SimpleNamespace(
        entry=0x10000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x13FFF)),
    )
    function = SimpleNamespace(addr=0x10010, name="main", project=project)
    item = decompile.FunctionWorkItem(index=1, function_cfg=SimpleNamespace(), function=function)
    calls = {"primary": 0}

    monkeypatch.setattr(decompile, "_tail_validation_runtime_enabled", lambda _project: False)
    monkeypatch.setattr(decompile, "function_decompilation_cache_key_8616", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_try_emit_known_runtime_helper_c", lambda **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_try_decompile_non_optimized_known_function",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("ordinary functions must not run the known-helper preflight")
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_apply_function_annotations_for_active_and_original_8616",
        lambda *_args, **_kwargs: False,
    )

    def fake_decompile_with_stats(*_args, **_kwargs):
        calls["primary"] += 1
        return ("ok", "int main(void) { return 0; }", None, 1, 1, 0.1)

    monkeypatch.setattr(decompile, "_decompile_function_with_stats", fake_decompile_with_stats)
    monkeypatch.setattr(decompile, "_tail_validation_snapshot_for_function_run", lambda *_args, **_kwargs: None)

    result = decompile._run_function_work_item(
        item,
        timeout=2,
        api_style="modern",
        binary_path=None,
        cod_metadata=None,
        synthetic_globals=None,
        lst_metadata=None,
        enable_structured_simplify=True,
        allow_isolated_retry=False,
    )

    assert result.status == "ok"
    assert calls == {"primary": 1}


def test_run_function_work_item_uses_registered_helper_preflight(monkeypatch):
    project = SimpleNamespace(
        entry=0x10000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x13FFF)),
    )
    function = SimpleNamespace(addr=0x10020, name="_helper", project=project)
    item = decompile.FunctionWorkItem(index=1, function_cfg=SimpleNamespace(), function=function)
    helper_c = "int _helper(void) { return 7; }"
    calls = {"preflight": 0}

    monkeypatch.setattr(decompile, "_tail_validation_runtime_enabled", lambda _project: False)
    monkeypatch.setattr(decompile, "function_decompilation_cache_key_8616", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_try_emit_known_runtime_helper_c", lambda **_kwargs: helper_c)

    def fake_helper_preflight(*_args, **_kwargs):
        calls["preflight"] += 1
        return decompile.NonOptimizedSliceOutcome(
            rendered=helper_c,
            status="ok",
            payload=helper_c,
        )

    monkeypatch.setattr(decompile, "_try_decompile_non_optimized_known_function", fake_helper_preflight)
    monkeypatch.setattr(
        decompile,
        "_decompile_function_with_stats",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("registered helper model must bypass primary decompilation")
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_tail_validation_snapshot_for_fallback",
        lambda *_args, **_kwargs: {
            "structuring": {"status": "stable", "changed": False},
            "postprocess": {"status": "stable", "changed": False},
        },
    )

    result = decompile._run_function_work_item(
        item,
        timeout=2,
        api_style="modern",
        binary_path=None,
        cod_metadata=None,
        synthetic_globals=None,
        lst_metadata=None,
        enable_structured_simplify=True,
        allow_isolated_retry=False,
    )

    assert result.status == "ok"
    assert result.payload == helper_c
    assert calls == {"preflight": 1}


def test_fresh_primary_work_item_uses_requested_catalog_boundary(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    parent_project = SimpleNamespace()
    fresh_project = SimpleNamespace()
    recovered_project = SimpleNamespace()
    return_use_evidence = decompile.CallerReturnUseEvidence8616(
        target_addr=0x10560,
        verdict=decompile.CallerReturnUseVerdict8616.UNUSED,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        used_callsite_count=0,
        unused_callsite_count=1,
        callsite_addrs=(0x1010,),
        facts=(
            CallerReturnUseFact8616(
                0x1000,
                0x1010,
                decompile.CallerReturnUseVerdict8616.UNUSED,
                CallsiteReturnUseKind8616.CLOBBERED,
                0x1013,
            ),
        ),
    )
    decompile.record_caller_return_use_evidence_8616(
        parent_project,
        0x10560,
        return_use_evidence,
    )
    source_function = SimpleNamespace(
        addr=0x10560,
        name="InitBars",
        project=parent_project,
        info={"x86_16_binary_exact_region": (0x10560, 0x10678)},
    )
    recovered_function = SimpleNamespace(addr=0x1000, name="InitBars", project=recovered_project)
    item = decompile.FunctionWorkItem(
        index=1,
        function_cfg=SimpleNamespace(),
        function=source_function,
        recovery_addr=0x10554,
    )
    args = SimpleNamespace(
        binary=binary,
        blob=False,
        base_addr=None,
        entry_point=None,
        c_target="portable-flat",
        trace_c_stages=False,
        dump_layers=False,
        dump_layer_dir=None,
        dump_layer_filter=None,
        window=0x400,
    )
    configured = []
    context = SimpleNamespace(
        args=args,
        project=parent_project,
        lst_metadata=None,
        cod_metadata=None,
        synthetic_globals=None,
        low_memory_path=False,
        configure_recovered_project_for=configured.append,
    )
    seen = {}

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: fresh_project)
    monkeypatch.setattr(decompile, "_inherit_tail_validation_runtime_policy", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "attach_lst_metadata_to_project", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_preserve_source_label_for_recovered_function_8616",
        lambda *_args, **_kwargs: True,
    )

    def fake_recover(project, addr, **kwargs):
        seen["recovery"] = (project, addr, kwargs)
        return SimpleNamespace(), recovered_function

    monkeypatch.setattr(decompile, "_recover_direct_addr_function", fake_recover)

    fresh_item = decompile._fresh_primary_function_work_item_8616(context, item, timeout=60)

    assert seen["recovery"][0] is fresh_project
    assert seen["recovery"][1] == 0x10554
    assert seen["recovery"][2]["function_label"] == "InitBars"
    assert seen["recovery"][2]["exact_region"] == (0x10560, 0x10678)
    assert fresh_item.function is recovered_function
    assert fresh_item.recovery_addr == 0x10554
    assert configured == [fresh_item]
    assert decompile.caller_return_use_evidence_by_addr_8616(fresh_project) == {
        0x10560: return_use_evidence,
    }
    assert decompile.caller_return_use_evidence_by_addr_8616(recovered_project) == {
        0x10560: return_use_evidence,
    }


def test_serial_function_recovery_uses_requested_catalog_boundary(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    parent_project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    recovered_project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    source_function = SimpleNamespace(addr=0x10560, name="InitBars", project=parent_project)
    recovered_function = SimpleNamespace(addr=0x1000, name="InitBars", project=recovered_project)
    item = decompile.FunctionWorkItem(
        index=1,
        function_cfg=None,
        function=source_function,
        recovery_addr=0x10554,
    )
    args = SimpleNamespace(
        addr=None,
        api_style="modern",
        binary=binary,
        c_target="portable-flat",
        dump_layer_dir=None,
        dump_layer_filter=None,
        dump_layers=False,
        timeout=60,
        trace_c_stages=False,
        window=0x400,
    )
    result_map = {}
    context = SimpleNamespace(
        args=args,
        project=parent_project,
        function_tasks=[item],
        result_map=result_map,
        fallback_tail_validation_by_index={},
        lst_metadata=SimpleNamespace(),
        cod_metadata=None,
        synthetic_globals=None,
        visible_code_labels={0x10554: "InitBars"},
        low_memory_path=False,
        interactive_stdout=False,
        precise_sidecar_regions=True,
        timeout_was_explicit=True,
        use_serial_fork_per_function=False,
        allow_heavy_fallbacks=False,
        force_isolated_project_for=lambda _item: False,
        configure_recovered_project_for=lambda _item: None,
        remaining_sweep_budget_sec=lambda: None,
    )
    seen = {}

    monkeypatch.setattr(
        decompile,
        "_function_work_cache_lookup",
        lambda *_args, **_kwargs: (None, "", None, True, ["structuring", "postprocess"]),
    )
    monkeypatch.setattr(
        decompile,
        "_lookup_persistent_recovery_timeout",
        lambda **kwargs: (seen.setdefault("cache_addr", kwargs["addr"]) and None, "", None),
    )
    monkeypatch.setattr(
        decompile,
        "_run_with_timeout_in_fork",
        lambda callback, **_kwargs: callback(),
    )
    monkeypatch.setattr(
        decompile,
        "_run_with_timeout_in_daemon_thread",
        lambda callback, **_kwargs: callback(),
    )

    def fake_recover(_project, _metadata, offset, name, **_kwargs):
        seen["recovery"] = (offset, name)
        return SimpleNamespace(), recovered_function

    monkeypatch.setattr(decompile, "_recover_lst_function", fake_recover)
    monkeypatch.setattr(decompile, "_function_complexity", lambda _function: (29, 274))
    monkeypatch.setattr(decompile, "_lst_code_region", lambda _metadata, addr: (addr, addr + 0x11E))
    monkeypatch.setattr(
        decompile,
        "_preserve_source_label_for_recovered_function_8616",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        decompile,
        "_effective_decompile_timeout_8616",
        lambda _project, timeout, **_kwargs: timeout,
    )
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda active_item, **_kwargs: decompile.FunctionWorkResult(
            index=active_item.index,
            status="ok",
            payload="void InitBars(void) { return; }",
            debug_output="",
            function=active_item.function,
            function_cfg=active_item.function_cfg,
            elapsed=1.0,
            block_count=29,
            byte_count=274,
        ),
    )
    monkeypatch.setattr(decompile, "_emit_function_result", lambda *_args, **_kwargs: (1, 0))
    timeout_model = SimpleNamespace(
        timeout_for_byte_count=lambda _byte_count: 60,
        observe_success=lambda _byte_count, _elapsed: None,
    )

    outcome = decompile._run_serial_function_8616(
        context,
        item,
        recover_timeout=60,
        adaptive_timeout_model=timeout_model,
        allow_isolated_retry_in_function_tasks=False,
        emitted_indexes=set(),
    )

    assert seen == {
        "cache_addr": 0x10554,
        "recovery": (0x10554, "InitBars"),
    }
    assert result_map[1].status == "ok"
    assert outcome == decompile._SerialFunctionOutcome8616(decompiled=1, failed=0)


def test_function_work_item_recovery_addr_refuses_negative_boundary():
    item = decompile.FunctionWorkItem(
        index=1,
        function_cfg=SimpleNamespace(),
        function=SimpleNamespace(addr=0x10560),
        recovery_addr=-1,
    )

    with pytest.raises(ValueError, match="must be nonnegative"):
        decompile._function_work_item_recovery_addr_8616(item)


def test_serial_clean_worker_result_protocol_round_trips(monkeypatch, tmp_path):
    result_path = tmp_path / "result.json"
    monkeypatch.setenv(decompile._SERIAL_CLEAN_WORKER_RESULT_ENV_8616, str(result_path))
    result = decompile.FunctionWorkResult(
        index=1,
        status="validation_failed",
        payload="Tail validation failed.",
        partial_payload="void InitBars(void) { return; }",
        debug_output="child debug",
        function=SimpleNamespace(addr=0x10560),
        function_cfg=SimpleNamespace(),
        tail_validation=_fake_stable_tail_validation(),
        elapsed=1.25,
        block_count=29,
        byte_count=274,
        skip_heavy_fallbacks=True,
        validated_payload_hash="validated",
        gcc_checked_payload_hash="compiled",
    )
    item = decompile.FunctionWorkItem(
        index=7,
        function_cfg=SimpleNamespace(),
        function=SimpleNamespace(addr=0x10560),
        recovery_addr=0x10554,
    )

    decompile._write_serial_clean_worker_result_8616(result)
    restored = decompile._read_serial_clean_worker_result_8616(
        result_path,
        item=item,
        debug_output="captured stderr",
    )

    assert restored.index == 7
    assert restored.status == "validation_failed"
    assert restored.payload == result.payload
    assert restored.partial_payload == result.partial_payload
    assert restored.debug_output == "captured stderr"
    assert restored.tail_validation == result.tail_validation
    assert restored.block_count == 29
    assert restored.byte_count == 274
    assert restored.skip_heavy_fallbacks is True
    assert restored.validated_payload_hash == "validated"
    assert restored.gcc_checked_payload_hash == "compiled"
    assert restored.function is item.function
    assert restored.function_cfg is item.function_cfg


def test_serial_clean_worker_result_protocol_refuses_unknown_schema(tmp_path):
    result_path = tmp_path / "result.json"
    result_path.write_text('{"schema": 99, "status": "ok", "payload": "void f(void) {}"}', encoding="utf-8")
    item = decompile.FunctionWorkItem(
        index=1,
        function_cfg=SimpleNamespace(),
        function=SimpleNamespace(addr=0x1000),
    )

    with pytest.raises(ValueError, match="unsupported schema"):
        decompile._read_serial_clean_worker_result_8616(
            result_path,
            item=item,
            debug_output="",
        )


def test_serial_clean_worker_evidence_protocol_round_trips_and_hydrates(monkeypatch, tmp_path):
    evidence_path = tmp_path / "evidence.json"
    evidence = decompile.CallerReturnUseEvidence8616(
        target_addr=0x10CE0,
        verdict=decompile.CallerReturnUseVerdict8616.UNUSED,
        raw_fact_count=2,
        normalized_fact_count=2,
        classified_fact_count=2,
        materialized_count=2,
        failure_count=0,
        used_callsite_count=0,
        unused_callsite_count=2,
        callsite_addrs=(0x1010, 0x1020),
        facts=(
            CallerReturnUseFact8616(
                0x1000, 0x1010, decompile.CallerReturnUseVerdict8616.UNUSED, CallsiteReturnUseKind8616.CLOBBERED, 0x1013
            ),
            CallerReturnUseFact8616(
                0x1000, 0x1020, decompile.CallerReturnUseVerdict8616.UNUSED, CallsiteReturnUseKind8616.CLOBBERED, 0x1023
            ),
        ),
    )
    source_project = SimpleNamespace()
    decompile.record_caller_return_use_evidence_8616(source_project, 0x10CE0, evidence)
    layout_evidence = GlobalObjectLayoutEvidence8616((), 0, 0, 0, 0)
    range_evidence = ProjectBoundedGlobalObjectRangeEvidence8616(
        (),
        (),
        BoundedGlobalObjectRangeStats8616(),
        ProjectBoundedGlobalObjectRangeSource8616(
            ProjectBoundedGlobalObjectRangeSourceKind8616.LIVE_ALIAS_PROGRAM,
            ProjectBoundedGlobalObjectRangeSourceStatus8616.COMPLETE,
            0,
            0,
            0,
            0,
        ),
        layout_evidence,
    )
    source_project._inertia_project_global_object_layout_evidence_8616 = layout_evidence
    source_project._inertia_project_bounded_global_object_ranges_8616 = range_evidence

    assert decompile._write_serial_clean_worker_evidence_8616(source_project, evidence_path) == 1
    transported = decompile._read_serial_clean_worker_evidence_8616(evidence_path)
    assert transported.caller_return_use_by_addr == {0x10CE0: evidence}
    assert transported.caller_return_use_by_addr[0x10CE0].fact_census_complete
    assert transported.global_object_layout == layout_evidence
    assert transported.bounded_global_ranges is not None
    assert transported.bounded_global_ranges.closed
    assert (
        transported.bounded_global_ranges.source.kind
        is ProjectBoundedGlobalObjectRangeSourceKind8616.TRANSPORTED_RECORD
    )
    source_project._inertia_caller_return_use_evidence_by_addr_8616 = {}
    assert (
        decompile._write_serial_clean_worker_evidence_8616(
            source_project,
            evidence_path,
            evidence_by_addr={0x10CE0: evidence},
        )
        == 1
    )
    transported = decompile._read_serial_clean_worker_evidence_8616(evidence_path)
    assert transported.caller_return_use_by_addr == {0x10CE0: evidence}
    assert transported.global_object_layout == layout_evidence
    assert transported.bounded_global_ranges is not None

    destination_project = SimpleNamespace()
    monkeypatch.setenv(decompile._SERIAL_CLEAN_WORKER_EVIDENCE_ENV_8616, str(evidence_path))
    assert decompile._hydrate_serial_clean_worker_evidence_8616(destination_project) == 1
    assert decompile.caller_return_use_evidence_by_addr_8616(destination_project) == {0x10CE0: evidence}
    assert destination_project._inertia_project_global_object_layout_evidence_8616 == layout_evidence
    assert destination_project._inertia_project_bounded_global_object_ranges_8616.closed


def test_serial_clean_worker_evidence_protocol_refuses_unknown_schema(tmp_path):
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text('{"schema": 99, "caller_return_use": []}', encoding="utf-8")

    with pytest.raises(ValueError, match="unsupported schema"):
        decompile._read_serial_clean_worker_evidence_8616(evidence_path)


def test_serial_clean_worker_completion_stops_before_parent_owned_retries(monkeypatch, tmp_path):
    result_path = tmp_path / "result.json"
    result = decompile.FunctionWorkResult(
        index=1,
        status="validation_failed",
        payload="Tail validation failed.",
        partial_payload="unsigned short f(void) { return 1; }",
        debug_output="",
        function=None,
        function_cfg=None,
        tail_validation=_fake_stable_tail_validation(),
    )

    assert decompile._complete_serial_clean_worker_result_8616(result) is False
    assert not result_path.exists()

    monkeypatch.setenv(decompile._SERIAL_CLEAN_WORKER_RESULT_ENV_8616, str(result_path))

    assert decompile._complete_serial_clean_worker_result_8616(result) is True
    assert result_path.exists()

    direct_source = inspect.getsource(decompile._run_direct_addr_cli_8616)
    completion_offset = direct_source.index(
        "_complete_serial_clean_worker_result_8616(direct_result, project=direct_project)"
    )
    robust_retry_offset = direct_source.index("_direct_addr_robust_retry_enabled_8616")
    assert completion_offset < robust_retry_offset


def test_serial_clean_worker_uses_single_process_and_protocol_overhead(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    args = SimpleNamespace(
        binary=binary,
        window=0x200,
        base_addr=0x1000,
        entry_point=0x1000,
        c_target="portable-flat",
        api_style="modern",
        pat_backend="hyperscan",
        blob=False,
        ignore_local_sidecar_hints=False,
        signature_catalog=None,
        trace_c_stages=False,
        dump_layers=False,
        dump_layer_dir=tmp_path / "layers",
        dump_layer_filter="",
    )
    return_use_evidence = decompile.CallerReturnUseEvidence8616(
        target_addr=0x10CE0,
        verdict=decompile.CallerReturnUseVerdict8616.UNUSED,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        used_callsite_count=0,
        unused_callsite_count=1,
        callsite_addrs=(0x1010,),
        facts=(
            CallerReturnUseFact8616(
                0x1000,
                0x1010,
                decompile.CallerReturnUseVerdict8616.UNUSED,
                CallsiteReturnUseKind8616.CLOBBERED,
                0x1013,
            ),
        ),
    )
    project = SimpleNamespace()
    decompile.record_caller_return_use_evidence_8616(project, 0x10CE0, return_use_evidence)
    context = SimpleNamespace(args=args, project=project, lst_metadata=SimpleNamespace())
    item = decompile.FunctionWorkItem(
        index=1,
        function_cfg=SimpleNamespace(),
        function=SimpleNamespace(addr=0x10CE0),
        recovery_addr=0x10CD4,
    )
    seen = {}

    def fake_run(command, **kwargs):
        seen["command"] = command
        seen["env"] = kwargs["env"]
        seen["timeout"] = kwargs["timeout"]
        evidence_path = Path(kwargs["env"][decompile._SERIAL_CLEAN_WORKER_EVIDENCE_ENV_8616])
        seen["evidence"] = decompile._read_serial_clean_worker_evidence_8616(evidence_path)
        result_path = Path(kwargs["env"][decompile._SERIAL_CLEAN_WORKER_RESULT_ENV_8616])
        monkeypatch.setenv(decompile._SERIAL_CLEAN_WORKER_RESULT_ENV_8616, str(result_path))
        decompile._write_serial_clean_worker_result_8616(
            decompile.FunctionWorkResult(
                index=1,
                status="ok",
                payload="int QuickSort(void) { return 0; }",
                debug_output="",
                function=None,
                function_cfg=None,
                tail_validation=_fake_stable_tail_validation(),
            )
        )
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="child C is transported through JSON",
            stderr="[12:34:56] child diagnostic\n[12:34:57] /* == c == */\n",
        )

    monkeypatch.setattr(decompile, "run_captured_subprocess_tree", fake_run)
    monkeypatch.setattr(decompile, "_ARCHITECTURE_GUARD_STATUS_8616", True)
    monkeypatch.setattr(
        decompile,
        "_canonicalize_direct_addr_from_sidecar_padding_8616",
        lambda *_args: decompile.DirectAddrCanonicalization8616(0x10CD4, 0x10CE0, (0x10CD4, 0x10E5D), None),
    )
    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args: (0x10CE0, 0x10D20))

    result = decompile._run_serial_clean_process_work_item_8616(context, item, timeout=2)

    assert result.status == "ok"
    assert result.payload == "int QuickSort(void) { return 0; }"
    assert result.debug_output == "[12:34:56] child diagnostic\n"
    assert seen["timeout"] == 47
    assert seen["env"]["INERTIA_OTEL_PROFILE_IN_PROCESS"] == "1"
    assert seen["env"]["INERTIA_DIRECT_ADDR_PREFER_LST"] == "0"
    assert seen["env"][decompile.ARCHITECTURE_GUARD_VERIFIED_PARENT_PID_ENV] == str(os.getpid())
    assert seen["evidence"].caller_return_use_by_addr == {0x10CE0: return_use_evidence}
    assert seen["evidence"].global_object_layout is None
    assert seen["command"][1:3] == ["-m", "inertia_decompiler.serial_clean_worker_cli"]
    assert "--ignore-local-sidecar-hints" in seen["command"]
    assert seen["command"][seen["command"].index("--addr") + 1] == "0x10ce0"
    assert seen["command"][seen["command"].index("--window") + 1] == "0x40"
    assert seen["command"][seen["command"].index("--exact-region-end") + 1] == "0x10d20"


def test_serial_clean_worker_debug_output_decodes_timeout_bytes_without_c_marker():
    stderr = b"[12:34:56] still running\n[12:34:57] /* == c == */\n"

    assert decompile._serial_clean_worker_debug_output_8616(stderr) == "[12:34:56] still running\n"


def test_batch_context_configures_recovered_project_with_parent_caller_evidence(tmp_path):
    evidence = decompile.CallerReturnUseEvidence8616(
        target_addr=0x10E70,
        verdict=decompile.CallerReturnUseVerdict8616.UNUSED,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        used_callsite_count=0,
        unused_callsite_count=1,
        callsite_addrs=(0x10522,),
    )
    parent_project = SimpleNamespace()
    decompile.record_caller_return_use_evidence_8616(parent_project, 0x10E70, evidence)
    recovered_project = SimpleNamespace()
    context = decompile._BatchCliContext8616(
        args=SimpleNamespace(
            c_target="portable-flat",
            trace_c_stages=False,
            dump_layers=False,
            dump_layer_dir=tmp_path / "layers",
            dump_layer_filter="",
        ),
        project=parent_project,
        function_tasks=[],
        result_map={},
        fallback_tail_validation_by_index={},
        lst_metadata=None,
        cod_metadata=None,
        synthetic_globals={},
        visible_code_labels={},
        include_library_functions=False,
        low_memory_path=False,
        interactive_stdout=False,
        precise_sidecar_regions=False,
        timeout_was_explicit=True,
        use_serial_fork_per_function=True,
        allow_heavy_fallbacks=False,
        force_isolated_function_projects=True,
        sweep_deadline=None,
        shown_total=1,
        skipped_signature_labels=0,
    )
    item = decompile.FunctionWorkItem(
        index=1,
        function_cfg=SimpleNamespace(),
        function=SimpleNamespace(project=recovered_project, addr=0x10E70),
        recovery_addr=0x10E70,
    )

    context.configure_recovered_project_for(item)

    assert decompile.caller_return_use_evidence_by_addr_8616(recovered_project) == {0x10E70: evidence}


def test_run_function_work_item_rebuilds_inside_process_isolated_worker(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    source_project = SimpleNamespace(
        entry=0x10000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x13FFF)),
        _inertia_c_target="portable-flat",
    )
    source_function = SimpleNamespace(
        addr=0x10CE0,
        name="QuickSort",
        project=source_project,
        info={},
    )
    item = decompile.FunctionWorkItem(
        index=1,
        function_cfg=SimpleNamespace(),
        function=source_function,
    )
    fresh_project = SimpleNamespace(
        entry=0x10000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x13FFF)),
    )
    fresh_cfg = SimpleNamespace()
    fresh_function = SimpleNamespace(
        addr=0x10CE0,
        name="QuickSort",
        project=fresh_project,
        info={},
    )
    seen = {"annotations_applied": False}

    monkeypatch.setattr(decompile, "_tail_validation_runtime_enabled", lambda _project: False)
    monkeypatch.setattr(decompile, "function_decompilation_cache_key_8616", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_try_emit_known_runtime_helper_c", lambda **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_try_decompile_non_optimized_known_function",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("ordinary functions must not run the known-helper preflight")
        ),
    )
    monkeypatch.setattr(decompile, "_build_project_cached", lambda *_args, **_kwargs: fresh_project)
    monkeypatch.setattr(decompile, "attach_lst_metadata_to_project", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_inherit_tail_validation_runtime_policy", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_isolated_project_recovery_target_8616",
        lambda *_args, **_kwargs: (0x10CE0, 0x14000),
    )

    def fake_recover(project, **kwargs):
        seen["recover"] = (project, kwargs)
        return fresh_cfg, fresh_function

    def fake_decompile_with_stats(*args, **_kwargs):
        assert seen["annotations_applied"] is True
        seen["project"] = args[0]
        seen["function"] = args[2]
        return ("ok", "void QuickSort(void) { return; }", None, 1, 1, 0.1)

    def fake_apply_annotations(project, _binary, _lst, function, **_kwargs):
        seen["annotations_applied"] = True
        seen["annotation_target"] = (project, function)
        return True

    monkeypatch.setattr(decompile, "_recover_candidate_function_pair", fake_recover)
    monkeypatch.setattr(
        decompile,
        "_apply_function_annotations_for_active_and_original_8616",
        fake_apply_annotations,
    )
    monkeypatch.setattr(decompile, "_decompile_function_with_stats", fake_decompile_with_stats)
    monkeypatch.setattr(decompile, "_tail_validation_snapshot_for_function_run", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_run_with_timeout_in_fork",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not fork twice")),
    )

    result = decompile._run_function_work_item(
        item,
        timeout=2,
        api_style="modern",
        binary_path=binary,
        cod_metadata=None,
        synthetic_globals=None,
        lst_metadata=None,
        enable_structured_simplify=True,
        force_isolated_project=True,
        process_isolated_worker=True,
        allow_isolated_retry=False,
    )

    assert result.status == "ok"
    assert seen["recover"][0] is fresh_project
    assert seen["recover"][1]["candidate_addr"] == 0x10CE0
    assert seen["annotation_target"] == (fresh_project, fresh_function)
    assert seen["project"] is fresh_project
    assert seen["function"] is fresh_function


def test_run_function_work_item_refuses_shared_fallback_when_fresh_recovery_fails(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x10000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x13FFF)),
    )
    function = SimpleNamespace(addr=0x10CE0, name="QuickSort", project=project, info={})
    item = decompile.FunctionWorkItem(index=1, function_cfg=SimpleNamespace(), function=function)

    monkeypatch.setattr(decompile, "_tail_validation_runtime_enabled", lambda _project: False)
    monkeypatch.setattr(decompile, "function_decompilation_cache_key_8616", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_build_project_cached",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("fresh build unavailable")),
    )
    monkeypatch.setattr(
        decompile,
        "_decompile_function_with_stats",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not use shared project")),
    )

    result = decompile._run_function_work_item(
        item,
        timeout=2,
        api_style="modern",
        binary_path=binary,
        cod_metadata=None,
        synthetic_globals=None,
        lst_metadata=None,
        enable_structured_simplify=True,
        force_isolated_project=True,
        process_isolated_worker=True,
        allow_isolated_retry=False,
    )

    assert result.status == "error"
    assert result.failure_stage == "fresh_project_recovery"
    assert "fresh build unavailable" in result.payload


def test_direct_addr_use_fork_lane_allows_tail_validation(monkeypatch):
    monkeypatch.setattr(decompile.os, "name", "posix")
    monkeypatch.setattr(decompile.threading, "current_thread", lambda: decompile.threading.main_thread())
    monkeypatch.setattr(decompile.threading, "active_count", lambda: 1)
    monkeypatch.delenv("INERTIA_OTEL_PROFILE_IN_PROCESS", raising=False)

    assert decompile._direct_addr_use_fork_lane_8616(tail_validation_enabled=True) is True


def test_direct_addr_use_fork_lane_keeps_non_tail_posix_fast_path(monkeypatch):
    monkeypatch.setattr(decompile.os, "name", "posix")
    monkeypatch.setattr(decompile.threading, "current_thread", lambda: decompile.threading.main_thread())
    monkeypatch.setattr(decompile.threading, "active_count", lambda: 1)
    monkeypatch.delenv("INERTIA_OTEL_PROFILE_IN_PROCESS", raising=False)

    assert decompile._direct_addr_use_fork_lane_8616(tail_validation_enabled=False) is True


def test_direct_addr_use_fork_lane_can_be_forced_to_thread(monkeypatch):
    monkeypatch.setattr(decompile.os, "name", "posix")
    monkeypatch.setattr(decompile.threading, "current_thread", lambda: decompile.threading.main_thread())
    monkeypatch.setattr(decompile.threading, "active_count", lambda: 1)
    monkeypatch.setenv("INERTIA_DIRECT_ADDR_FORCE_THREAD", "1")
    monkeypatch.delenv("INERTIA_OTEL_PROFILE_IN_PROCESS", raising=False)

    assert decompile._direct_addr_use_fork_lane_8616(tail_validation_enabled=True) is False


def test_main_parallel_keeps_timeout_after_deadline(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    function = SimpleNamespace(addr=0x11423, name="_start", project=project)

    class _FakeFuture:
        def __init__(self, result):
            self._result = result

        def result(self, timeout=None):
            return self._result

        def done(self):
            return False

        def cancelled(self):
            return False

    class _FakeExecutor:
        def __init__(self, *args, **kwargs):
            self.future = None

        def submit(self, _fn, item, **_kwargs):
            self.future = _FakeFuture(
                decompile.FunctionWorkResult(
                    index=item.index,
                    status="ok",
                    payload=f"int {item.function.name}(void) {{ return 0; }}",
                    debug_output="",
                    tail_validation=_fake_stable_tail_validation(),
                    function=item.function,
                    function_cfg=item.function_cfg,
                )
            )
            return self.future

        def shutdown(self, wait=True, cancel_futures=True):
            return None

    monotonic_values = iter([0.0] + [5.0] * 16)

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_recover_fast_exe_catalog",
        lambda *_args, **_kwargs: [(SimpleNamespace(), function)],
    )
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "select_function_worker_policy_8616", lambda **_kwargs: SimpleNamespace(mode=decompile.FunctionWorkerMode8616.SHARED, workers=2))
    monkeypatch.setattr(decompile, "requires_isolated_function_decompilation", lambda **_kwargs: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "DaemonThreadPoolExecutor", _FakeExecutor)
    monkeypatch.setattr(decompile, "wait", lambda pending, **_kwargs: (set(), set(pending)))
    monkeypatch.setattr(decompile.time, "monotonic", lambda: next(monotonic_values))

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "3"])
    captured = capsys.readouterr()

    assert rc == 2
    assert "int _start(void) { return 0; }" not in captured.out
    assert "Timed out after 2s." in captured.err
    assert "Timed out after 2s." not in captured.out


def test_main_parallel_does_not_promote_late_partial_after_deadline(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    function = SimpleNamespace(addr=0x11423, name="_start", project=project)

    class _FakeFuture:
        def __init__(self, result):
            self._result = result

        def result(self, timeout=None):
            return self._result

        def done(self):
            return False

        def cancelled(self):
            return False

    class _FakeExecutor:
        def __init__(self, *args, **kwargs):
            self.future = None

        def submit(self, _fn, item, **_kwargs):
            self.future = _FakeFuture(
                decompile.FunctionWorkResult(
                    index=item.index,
                    status="timeout",
                    payload="Timed out after 2s.",
                    debug_output="",
                    function=item.function,
                    function_cfg=item.function_cfg,
                    partial_payload="int _start(void) { return 0; }",
                )
            )
            return self.future

        def shutdown(self, wait=True, cancel_futures=True):
            return None

    monotonic_values = iter([0.0] + [5.0] * 16)

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_recover_fast_exe_catalog",
        lambda *_args, **_kwargs: [(SimpleNamespace(), function)],
    )
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "select_function_worker_policy_8616", lambda **_kwargs: SimpleNamespace(mode=decompile.FunctionWorkerMode8616.SHARED, workers=2))
    monkeypatch.setattr(decompile, "requires_isolated_function_decompilation", lambda **_kwargs: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "DaemonThreadPoolExecutor", _FakeExecutor)
    monkeypatch.setattr(decompile, "wait", lambda pending, **_kwargs: (set(), set(pending)))
    monkeypatch.setattr(decompile.time, "monotonic", lambda: next(monotonic_values))

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "3"])
    captured = capsys.readouterr()

    assert rc == 2
    assert "/* -- c (partial timeout) -- */" not in captured.out
    assert "int _start(void) { return 0; }" not in captured.out
    assert "Timed out after 2s." in captured.err
    assert "Timed out after 2s." not in captured.out


def test_main_parallel_promotes_done_future_at_deadline(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    function = SimpleNamespace(addr=0x11423, name="_start", project=project)

    class _FakeFuture:
        def __init__(self, result):
            self._result = result
            self._done = True

        def result(self, timeout=None):
            return self._result

        def done(self):
            return self._done

        def cancelled(self):
            return False

    class _FakeExecutor:
        def __init__(self, *args, **kwargs):
            self.future = None

        def submit(self, _fn, item, **_kwargs):
            self.future = _FakeFuture(
                decompile.FunctionWorkResult(
                    index=item.index,
                    status="ok",
                    payload=f"int {item.function.name}(void) {{ return 0; }}",
                    debug_output="",
                    tail_validation=_fake_stable_tail_validation(),
                    function=item.function,
                    function_cfg=item.function_cfg,
                )
            )
            return self.future

        def shutdown(self, wait=True, cancel_futures=True):
            return None

    monotonic_values = iter([0.0] + [5.0] * 16)

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_recover_fast_exe_catalog",
        lambda *_args, **_kwargs: [(SimpleNamespace(), function)],
    )
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "select_function_worker_policy_8616", lambda **_kwargs: SimpleNamespace(mode=decompile.FunctionWorkerMode8616.SHARED, workers=2))
    monkeypatch.setattr(decompile, "requires_isolated_function_decompilation", lambda **_kwargs: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "DaemonThreadPoolExecutor", _FakeExecutor)
    monkeypatch.setattr(decompile, "wait", lambda pending, **_kwargs: (set(), set(pending)))
    monkeypatch.setattr(decompile.time, "monotonic", lambda: next(monotonic_values))

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "1"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "int _start(void)\n{" in out
    assert "return 0;" in out
    assert "Timed out after 2s." not in out


def test_main_parallel_promotes_future_completed_during_late_collection(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    function = SimpleNamespace(addr=0x11423, name="_start", project=project)

    class _FakeFuture:
        def __init__(self, result):
            self._result = result
            self._done = False

        def result(self, timeout=None):
            return self._result

        def done(self):
            return self._done

        def cancelled(self):
            return False

    class _FakeExecutor:
        def __init__(self, *args, **kwargs):
            self.future = None

        def submit(self, _fn, item, **_kwargs):
            self.future = _FakeFuture(
                decompile.FunctionWorkResult(
                    index=item.index,
                    status="ok",
                    payload=f"int {item.function.name}(void) {{ return 0; }}",
                    debug_output="",
                    tail_validation=_fake_stable_tail_validation(),
                    function=item.function,
                    function_cfg=item.function_cfg,
                )
            )
            executor_state["future"] = self.future
            return self.future

        def shutdown(self, wait=True, cancel_futures=True):
            return None

    monotonic_values = iter([0.0] + [5.0] * 16)
    executor_state = {"future": None}
    wait_calls = {"count": 0}

    def _fake_wait(pending, **_kwargs):
        wait_calls["count"] += 1
        if wait_calls["count"] == 1:
            return set(), set(pending)
        future = executor_state["future"]
        if future is not None:
            future._done = True
        return {future} if future is not None else set(), set()

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_recover_fast_exe_catalog",
        lambda *_args, **_kwargs: [(SimpleNamespace(), function)],
    )
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "select_function_worker_policy_8616", lambda **_kwargs: SimpleNamespace(mode=decompile.FunctionWorkerMode8616.SHARED, workers=2))
    monkeypatch.setattr(decompile, "requires_isolated_function_decompilation", lambda **_kwargs: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "DaemonThreadPoolExecutor", _FakeExecutor)
    monkeypatch.setattr(decompile, "wait", _fake_wait)
    monkeypatch.setattr(decompile.time, "monotonic", lambda: next(monotonic_values))

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "1"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "int _start(void)\n{" in out
    assert "return 0;" in out
    assert "Timed out after 2s." not in out


def test_candidate_recovery_regions_use_only_largest_window_for_body_seed():
    regions = decompile._candidate_recovery_regions(
        None,
        0x10010,
        image_end=0x11000,
        region_span=0x120,
        project_entry=0x11423,
    )

    assert regions == [(0x10010, 0x10130)]


def test_rank_function_cfg_pairs_for_display_prefers_truncated_body_seed_over_wrapper_paths(monkeypatch):
    project = SimpleNamespace(entry=0x11423)
    entry = (SimpleNamespace(), SimpleNamespace(addr=0x11423, blocks=(SimpleNamespace(size=0x20),)))
    body = (
        SimpleNamespace(),
        SimpleNamespace(
            addr=0x10010,
            blocks=(SimpleNamespace(size=0x40),),
            info={"x86_16_recovery_truncated": True},
        ),
    )
    wrapper = (SimpleNamespace(), SimpleNamespace(addr=0x10050, blocks=(SimpleNamespace(size=0x10),)))
    runtime_shell = (SimpleNamespace(), SimpleNamespace(addr=0x11440, blocks=(SimpleNamespace(size=0x10),)))

    monkeypatch.setattr(
        decompile,
        "_linear_function_seed_targets",
        lambda _project, addr, **_kwargs: {0x10050} if addr == 0x11423 else ({0x11440} if addr == 0x10010 else set()),
    )

    ranked = decompile._rank_function_cfg_pairs_for_display(project, [wrapper, runtime_shell, body, entry])

    assert [func.addr for _cfg, func in ranked[:3]] == [0x11423, 0x10010, 0x11440]


def test_rank_function_cfg_pairs_for_display_keeps_secondary_pre_entry_body_ahead_of_runtime_shell(monkeypatch):
    project = SimpleNamespace(entry=0x11423)
    entry = (SimpleNamespace(), SimpleNamespace(addr=0x11423, blocks=(SimpleNamespace(size=0x20),)))
    primary_body = (SimpleNamespace(), SimpleNamespace(addr=0x11000, blocks=(SimpleNamespace(size=0x60),)))
    secondary_body = (
        SimpleNamespace(),
        SimpleNamespace(
            addr=0x10010,
            blocks=(SimpleNamespace(size=0x50),),
            info={"x86_16_recovery_truncated": True},
        ),
    )
    runtime_shell = (SimpleNamespace(), SimpleNamespace(addr=0x11440, blocks=(SimpleNamespace(size=0x10),)))

    monkeypatch.setattr(
        decompile,
        "_linear_function_seed_targets",
        lambda _project, addr, **_kwargs: {0x11440} if addr == 0x11423 else set(),
    )

    ranked = decompile._rank_function_cfg_pairs_for_display(
        project, [runtime_shell, secondary_body, primary_body, entry]
    )

    assert [func.addr for _cfg, func in ranked[:4]] == [0x11423, 0x10010, 0x11000, 0x11440]


def test_rank_function_cfg_pairs_for_display_demotes_wrapper_body_targets_below_other_pre_entry_bodies(monkeypatch):
    project = SimpleNamespace(entry=0x11423)
    entry = (SimpleNamespace(), SimpleNamespace(addr=0x11423, blocks=(SimpleNamespace(size=0x20),)))
    primary_body = (
        SimpleNamespace(),
        SimpleNamespace(
            addr=0x10010,
            blocks=(SimpleNamespace(size=0x50),),
            info={"x86_16_recovery_truncated": True},
        ),
    )
    secondary_body = (SimpleNamespace(), SimpleNamespace(addr=0x10120, blocks=(SimpleNamespace(size=0x40),)))
    wrapper_target = (SimpleNamespace(), SimpleNamespace(addr=0x10050, blocks=(SimpleNamespace(size=0x10),)))

    monkeypatch.setattr(
        decompile,
        "_linear_function_seed_targets",
        lambda _project, addr, **_kwargs: {0x10050} if addr == 0x10010 else set(),
    )

    ranked = decompile._rank_function_cfg_pairs_for_display(
        project, [wrapper_target, secondary_body, primary_body, entry]
    )

    assert [func.addr for _cfg, func in ranked[:4]] == [0x11423, 0x10010, 0x10120, 0x10050]


def test_recover_candidate_function_pair_stops_after_good_enough_score(monkeypatch):
    seen_regions: list[tuple[int, int]] = []

    def _fake_pick(_project, addr, *, regions=None, **_kwargs):
        seen_regions.append(regions[0])
        blocks = tuple(SimpleNamespace(size=0x20) for _ in range(4))
        return SimpleNamespace(), SimpleNamespace(addr=addr, blocks=blocks)

    monkeypatch.setattr(decompile, "_pick_function_lean", _fake_pick)

    cfg, func = decompile._recover_candidate_function_pair(
        SimpleNamespace(
            factory=SimpleNamespace(
                block=lambda *_args, **_kwargs: SimpleNamespace(
                    capstone=SimpleNamespace(insns=[SimpleNamespace(address=0x11450)])
                )
            )
        ),
        candidate_addr=0x11450,
        image_end=0x12000,
        metadata=None,
        project_entry=0x11423,
        region_span=0x200,
    )

    assert cfg is not None
    assert func.addr == 0x11450
    assert seen_regions == [(0x11450, 0x114D0)]


def test_recover_seeded_exe_functions_skips_seeds_inside_recovered_ranges(monkeypatch):
    code = b"\x90" * 0x400
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=0x10000,
                max_addr=len(code) - 1,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
            )
        ),
    )
    calls: list[int] = []

    def _fake_recover(_project, *, candidate_addr, **_kwargs):
        calls.append(candidate_addr)
        if candidate_addr == 0x10010:
            func = SimpleNamespace(
                addr=0x10010,
                name="sub_10010",
                is_plt=False,
                is_simprocedure=False,
                blocks=(SimpleNamespace(addr=0x10010, size=0x60),),
            )
        else:
            func = SimpleNamespace(
                addr=candidate_addr,
                name=f"sub_{candidate_addr:x}",
                is_plt=False,
                is_simprocedure=False,
                blocks=(SimpleNamespace(addr=candidate_addr, size=0x10),),
            )
        return SimpleNamespace(), func

    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project, **_kwargs: [0x10010, 0x10030, 0x10100])
    monkeypatch.setattr(
        cli_function_discovery,
        "_rank_exe_function_seeds",
        lambda _project, **_kwargs: [0x10010, 0x10030, 0x10100],
    )
    monkeypatch.setattr(cli_function_discovery, "_load_seeded_recovery_from_cache", lambda **_kwargs: None)
    monkeypatch.setattr(cli_function_discovery, "_recover_candidate_function_pair", _fake_recover)
    monkeypatch.setattr(cli_function_discovery, "collect_neighbor_call_targets", lambda _function: [])
    monkeypatch.setattr(
        cli_function_discovery,
        "_run_with_timeout_in_fork",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("run inline")),
    )

    recovered = decompile._recover_seeded_exe_functions(project, timeout=4, limit=3)

    assert [func.addr for _cfg, func in recovered] == [0x10010, 0x10100]
    assert calls == [0x10010, 0x10100]


def test_recover_candidate_with_timeout_uses_thread_timeout_off_main_thread(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace()
    calls: list[str] = []

    monkeypatch.setattr(
        decompile,
        "_recover_candidate_function_pair",
        lambda *_args, **_kwargs: (SimpleNamespace(), SimpleNamespace(addr=0x1000, blocks=())),
    )
    monkeypatch.setattr(decompile.threading, "current_thread", lambda: object())
    monkeypatch.setattr(decompile.threading, "main_thread", lambda: object())

    def _fake_thread_timeout(fn, *, thread_name_prefix, timeout):
        calls.append(f"{thread_name_prefix}:{timeout}")
        return fn()

    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_thread_timeout)

    cfg, func = decompile._recover_candidate_with_timeout(
        project,
        candidate_addr=0x1000,
        image_end=0x2000,
        metadata=None,
        project_entry=0x1000,
        region_span=0x120,
        timeout=3,
        binary_path=binary,
        linked_base=0x1000,
    )

    assert cfg is not None
    assert func.addr == 0x1000
    assert calls == ["recover-candidate:3"]


def test_recover_candidate_with_timeout_uses_analysis_timeout_once_on_main_thread(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace()
    seen = {}

    monkeypatch.setattr(
        decompile,
        "_recover_candidate_function_pair",
        lambda *_args, **_kwargs: (SimpleNamespace(), SimpleNamespace(addr=0x1000, blocks=())),
    )
    monkeypatch.setattr(decompile.threading, "current_thread", lambda: decompile.threading.main_thread())

    def _fake_analysis_timeout(timeout):
        seen["timeout"] = timeout
        return contextlib.nullcontext()

    monkeypatch.setattr(decompile, "_analysis_timeout", _fake_analysis_timeout)
    monkeypatch.setattr(
        decompile,
        "_run_with_timeout_in_fork",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("angr objects must remain in the parent")),
    )
    monkeypatch.setattr(
        decompile,
        "_run_with_timeout_in_daemon_thread",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("thread timeout should not run")),
    )

    cfg, func = decompile._recover_candidate_with_timeout(
        project,
        candidate_addr=0x1000,
        image_end=0x2000,
        metadata=None,
        project_entry=0x1000,
        region_span=0x120,
        timeout=3,
        binary_path=binary,
        linked_base=0x1000,
    )

    assert cfg is not None
    assert func.addr == 0x1000
    assert seen["timeout"] == 3


def test_recover_candidate_with_timeout_reuses_runtime_candidate_cache(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace()
    seen = {"calls": 0}

    def _fake_recover(*_args, **_kwargs):
        seen["calls"] += 1
        return (SimpleNamespace(tag="cfg"), SimpleNamespace(addr=0x1000, blocks=()))

    monkeypatch.setattr(decompile, "_recover_candidate_function_pair", _fake_recover)
    monkeypatch.setattr(decompile.os, "name", "posix")
    monkeypatch.setattr(decompile.threading, "current_thread", lambda: decompile.threading.main_thread())
    monkeypatch.setattr(decompile.threading, "active_count", lambda: 1)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", lambda fn, *, timeout: fn())

    first_cfg, first_func = decompile._recover_candidate_with_timeout(
        project,
        candidate_addr=0x1000,
        image_end=0x2000,
        metadata=None,
        project_entry=0x1000,
        region_span=0x120,
        timeout=3,
        binary_path=binary,
        linked_base=0x1000,
    )
    second_cfg, second_func = decompile._recover_candidate_with_timeout(
        project,
        candidate_addr=0x1000,
        image_end=0x2000,
        metadata=None,
        project_entry=0x1000,
        region_span=0x120,
        timeout=3,
        binary_path=binary,
        linked_base=0x1000,
    )

    assert seen["calls"] == 1
    assert first_cfg is second_cfg
    assert first_func is second_func


def test_try_decompile_non_optimized_slice_uses_fork_lane_on_main_thread(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    slice_project = SimpleNamespace(
        loader=SimpleNamespace(
            main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x20000),
            memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x55\x8b\xec\xc3"),
        ),
        arch=SimpleNamespace(name="86_16"),
    )
    project = SimpleNamespace(
        loader=SimpleNamespace(
            main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x20000),
            memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x55\x8b\xec\xc3"),
        ),
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
    )
    cfg = SimpleNamespace()

    class FakeFunction:
        def __init__(self):
            self.addr = 0x114CD
            self.name = "sub_114cd"
            self.normalized = False

        def normalize(self):
            self.normalized = True

        def get_call_sites(self):
            return []

        def get_call_target(self, _callsite):
            return None

    func = FakeFunction()
    seen = {}

    monkeypatch.setattr(decompile.os, "name", "posix")
    monkeypatch.setattr(decompile.threading, "current_thread", lambda: decompile.threading.main_thread())
    monkeypatch.setattr(decompile.threading, "active_count", lambda: 1)
    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x114CD, 0x114D1))
    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *_args, **_kwargs: slice_project)
    monkeypatch.setattr(decompile, "_pick_function_lean", lambda *_args, **_kwargs: (cfg, func))
    monkeypatch.setattr(decompile, "_sidecar_cod_metadata_for_function", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_inherit_tail_validation_runtime_policy", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prepare_function_for_decompilation", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_decompile_function_with_stats",
        lambda *_args, **_kwargs: ("ok", "void sub_114cd(void) {}", None, 1, 0x20, 0.5),
    )

    def _fake_fork_timeout(fn, *, timeout):
        seen["timeout"] = timeout
        return fn()

    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", _fake_fork_timeout)
    monkeypatch.setattr(
        decompile,
        "_run_with_timeout_in_daemon_thread",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("daemon thread fallback should not run")),
    )

    outcome = decompile._try_decompile_non_optimized_slice(
        project,
        0x114CD,
        "sub_114cd",
        timeout=6,
        api_style="modern",
        binary_path=binary,
        lst_metadata=None,
    )

    assert outcome.rendered == "void sub_114cd(void) {}"
    assert seen["timeout"] == 7


def test_try_decompile_non_optimized_slice_uses_bounded_attempt_timeout_in_daemon_mode(monkeypatch):
    project = SimpleNamespace(
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x55\x8b\xec\xc3")),
    )
    function = SimpleNamespace(name="main", addr=0x1000, normalized=True, blocks=(SimpleNamespace(size=0x10),))
    seen: dict[str, int] = {}

    monkeypatch.setattr(decompile.os, "name", "nt")
    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: (0x1000, 0x1004))
    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *args, **kwargs: SimpleNamespace())
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (SimpleNamespace(), function),
    )
    monkeypatch.setattr(decompile, "_inherit_tail_validation_runtime_policy", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prepare_function_for_decompilation", lambda *_args, **_kwargs: None)

    def _fake_daemon_timeout(fn, *, timeout, **_kwargs):
        seen["timeout"] = timeout
        return fn()

    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_daemon_timeout)
    monkeypatch.setattr(
        decompile,
        "_decompile_function_with_stats",
        lambda *_args, **_kwargs: ("timeout", "Timed out after 4s.", "int partial(void) { return 1; }", 1, 4, 4.0),
    )

    outcome = decompile._try_decompile_non_optimized_slice(
        project,
        0x1000,
        "main",
        timeout=5,
        api_style="modern",
        binary_path=None,
        lst_metadata=None,
    )

    assert outcome.rendered == "int partial(void) { return 1; }"
    assert seen["timeout"] == 7


def test_try_decompile_non_optimized_slice_retries_after_bounded_lean_timeout(monkeypatch):
    project = SimpleNamespace(
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x55\x8b\xec\xc3")),
    )
    function = SimpleNamespace(name="main", addr=0x1000, normalized=True, blocks=(SimpleNamespace(size=0x10),))
    calls: list[tuple[str, bool]] = []
    daemon_calls = {"count": 0}

    monkeypatch.setattr(decompile.os, "name", "nt")
    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: (0x1000, 0x1004))
    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *args, **kwargs: SimpleNamespace())

    def _fake_pick_function_lean(*_args, **_kwargs):
        calls.append(("lean", False))
        return SimpleNamespace(), function

    def _fake_pick_function(_slice_project, _start, *, data_references, **_kwargs):
        calls.append(("full", data_references))
        if data_references:
            raise AssertionError("full-with-refs should not run after full-no-refs succeeds")
        return SimpleNamespace(), function

    def _fake_daemon_timeout(fn, *, timeout, **_kwargs):
        daemon_calls["count"] += 1
        if daemon_calls["count"] == 1:
            raise TimeoutError(f"Timed out after {timeout}s.")
        return fn()

    monkeypatch.setattr(decompile, "_pick_function_lean", _fake_pick_function_lean)
    monkeypatch.setattr(decompile, "_pick_function", _fake_pick_function)
    monkeypatch.setattr(decompile, "_inherit_tail_validation_runtime_policy", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prepare_function_for_decompilation", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_daemon_timeout)
    monkeypatch.setattr(
        decompile,
        "_decompile_function_with_stats",
        lambda *_args, **_kwargs: ("ok", "int recovered(void) { return 2; }", None, 1, 3, 0.01),
    )

    outcome = decompile._try_decompile_non_optimized_slice(
        project,
        0x1000,
        "main",
        timeout=5,
        api_style="modern",
        binary_path=None,
        lst_metadata=None,
        allow_fresh_project_retry=False,
    )

    assert outcome.rendered == "int recovered(void) { return 2; }"
    assert calls == [("full", False)]
    assert daemon_calls["count"] == 2


def test_main_defers_exe_limit_until_after_seed_ranking(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    entry_function = SimpleNamespace(addr=0x11423, name="_start", project=project)
    runtime_function = SimpleNamespace(addr=0x114CD, name="runtime_init", project=project)
    extra_runtime = SimpleNamespace(addr=0x1157C, name="runtime_more", project=project)
    body_function = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)
    cfg = SimpleNamespace(functions={})

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "_recover_partial_cfg", lambda *_args, **_kwargs: cfg)
    monkeypatch.setattr(
        decompile,
        "_interesting_functions",
        lambda _cfg, limit=None: ([entry_function, runtime_function, extra_runtime], 3),
    )
    monkeypatch.setattr(
        decompile, "_recover_seeded_exe_functions", lambda *_args, **_kwargs: [(SimpleNamespace(), body_function)]
    )
    monkeypatch.setattr(
        decompile,
        "_rank_function_cfg_pairs_for_display",
        lambda _project, _pairs: [
            (cfg, entry_function),
            (SimpleNamespace(), body_function),
            (cfg, runtime_function),
            (cfg, extra_runtime),
        ],
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            tail_validation=_fake_stable_tail_validation(),
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* == function 0x11423 _start == */" in out
    assert "/* == function 0x10010 sub_10010 == */" in out
    assert "/* == function 0x114cd runtime_init == */" not in out


def test_main_reranks_merged_seeded_pairs_before_max_function_slice(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    cfg = SimpleNamespace(functions={})
    entry_function = SimpleNamespace(addr=0x11423, name="_start", project=project, blocks=(SimpleNamespace(size=0x20),))
    wrapper_function = SimpleNamespace(
        addr=0x11440, name="runtime_shell", project=project, blocks=(SimpleNamespace(size=0x10),)
    )
    body_function = SimpleNamespace(
        addr=0x10010,
        name="sub_10010",
        project=project,
        blocks=(SimpleNamespace(size=0x50),),
        info={"x86_16_recovery_truncated": True},
    )

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "_recover_partial_cfg", lambda *_args, **_kwargs: cfg)
    monkeypatch.setattr(
        decompile, "_interesting_functions", lambda _cfg, limit=None: ([entry_function, wrapper_function], 2)
    )
    monkeypatch.setattr(
        decompile,
        "_recover_seeded_exe_functions",
        lambda *_args, **_kwargs: ([(SimpleNamespace(), body_function)], [0x10010]),
    )
    monkeypatch.setattr(
        decompile,
        "_linear_function_seed_targets",
        lambda _project, addr, **_kwargs: {0x11440} if addr == 0x11423 else set(),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            tail_validation=_fake_stable_tail_validation(),
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* == function 0x11423 _start == */" in out
    assert "/* == function 0x10010 sub_10010 == */" in out
    assert "/* == function 0x11440 runtime_shell == */" not in out


def test_main_reranks_nontruncated_seeded_body_before_runtime_shell(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    cfg = SimpleNamespace(functions={})
    entry_function = SimpleNamespace(addr=0x11423, name="_start", project=project, blocks=(SimpleNamespace(size=0x20),))
    runtime_function = SimpleNamespace(
        addr=0x11440, name="runtime_shell", project=project, blocks=(SimpleNamespace(size=0x10),)
    )
    body_function = SimpleNamespace(
        addr=0x10010, name="sub_10010", project=project, blocks=(SimpleNamespace(size=0x50),)
    )

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "_recover_partial_cfg", lambda *_args, **_kwargs: cfg)
    monkeypatch.setattr(
        decompile, "_interesting_functions", lambda _cfg, limit=None: ([entry_function, runtime_function], 2)
    )
    monkeypatch.setattr(
        decompile,
        "_recover_seeded_exe_functions",
        lambda *_args, **_kwargs: ([(SimpleNamespace(), body_function)], [0x10010]),
    )
    monkeypatch.setattr(
        decompile,
        "_linear_function_seed_targets",
        lambda _project, addr, **_kwargs: {0x11440} if addr == 0x11423 else set(),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            tail_validation=_fake_stable_tail_validation(),
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* == function 0x11423 _start == */" in out
    assert "/* == function 0x10010 sub_10010 == */" in out
    assert "/* == function 0x11440 runtime_shell == */" not in out


def test_main_defers_exe_limit_until_after_seed_ranking_with_recovery_only_sidecar(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    metadata = LSTMetadata(data_labels={}, code_labels={0x11423: "_startup_sig"})
    entry_function = SimpleNamespace(addr=0x11423, name="_start", project=project)
    runtime_function = SimpleNamespace(addr=0x114CD, name="runtime_init", project=project)
    body_function = SimpleNamespace(
        addr=0x10010,
        name="sub_10010",
        project=project,
        blocks=(SimpleNamespace(size=0x40),),
        info={"x86_16_recovery_truncated": True},
    )

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_visible_code_labels", lambda _metadata: {})
    monkeypatch.setattr(decompile, "_recovery_code_labels", lambda _metadata: {0x11423: "_startup_sig"})
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(
        decompile,
        "_recover_seeded_exe_functions",
        lambda *_args, **_kwargs: (
            [
                (SimpleNamespace(), entry_function),
                (SimpleNamespace(), runtime_function),
                (SimpleNamespace(), body_function),
            ],
            [0x11423, 0x114CD, 0x10010],
        ),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            tail_validation=_fake_stable_tail_validation(),
            byte_count=1,
            elapsed=0.01,
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* == function 0x11423 _start == */" in out
    assert "/* == function 0x10010 sub_10010 == */" in out
    assert "/* == function 0x114cd runtime_init == */" not in out


def test_main_helper_free_small_cap_exe_uses_serial_workers_with_hidden_seed_metadata(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    entry_function = SimpleNamespace(addr=0x11423, name="_start", project=project)
    body_function = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)
    metadata = LSTMetadata(data_labels={}, code_labels={})
    max_workers_seen: list[int] = []

    class _FakeExecutor:
        def __init__(self, max_workers, *args, **kwargs):
            max_workers_seen.append(max_workers)

        def submit(self, fn, item, **kwargs):
            class _Future:
                def result(self, timeout=None):
                    return decompile.FunctionWorkResult(
                        index=item.index,
                        status="ok",
                        payload=f"int {item.function.name}(void) {{ return 0; }}",
                        debug_output="",
                        tail_validation=_fake_stable_tail_validation(),
                        byte_count=1,
                        elapsed=0.01,
                        function=item.function,
                        function_cfg=item.function_cfg,
                    )

                def __hash__(self):
                    return id(self)

            return _Future()

        def shutdown(self, wait=True, cancel_futures=True):
            return None

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_visible_code_labels", lambda _metadata: {})
    monkeypatch.setattr(decompile, "_recovery_code_labels", lambda _metadata: {0x11423: "_startup_sig"})
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(
        decompile,
        "_recover_seeded_exe_functions",
        lambda *_args, **_kwargs: (
            [(SimpleNamespace(), entry_function), (SimpleNamespace(), body_function)],
            [entry_function.addr, body_function.addr],
        ),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 2)
    monkeypatch.setattr(decompile, "DaemonThreadPoolExecutor", _FakeExecutor)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            tail_validation=_fake_stable_tail_validation(),
            byte_count=1,
            elapsed=0.01,
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert max_workers_seen == []
    assert "/* == function 0x11423 _start == */" in out
    assert "/* == function 0x10010 sub_10010 == */" in out


def test_main_uses_default_signature_catalog_when_not_explicit(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    default_catalog = tmp_path / "repo_signature_catalog.pat"
    seen: dict[str, object] = {}

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "default_signature_catalog_path", lambda *_args, **_kwargs: default_catalog)

    def _fake_load_lst_metadata(_binary, _project, *, pat_backend=None, signature_catalog=None, **_kwargs):
        seen["signature_catalog"] = signature_catalog
        return None

    monkeypatch.setattr(decompile, "_load_lst_metadata", _fake_load_lst_metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(
        decompile,
        "_run_with_timeout_in_daemon_thread",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(FuturesTimeoutError()),
    )
    monkeypatch.setattr(decompile, "_recover_fast_seed_functions", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_format_first_block_asm", lambda *_args, **_kwargs: "entry asm")
    monkeypatch.setattr(decompile, "_probe_lift_break", lambda *_args, **_kwargs: "lift probe")
    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x11423, 0x11440))
    monkeypatch.setattr(decompile, "_format_asm_range", lambda *_args, **_kwargs: "asm range")

    rc = decompile.main([str(binary), "--timeout", "1"])
    _out = capsys.readouterr().out

    assert rc == 5
    assert seen["signature_catalog"] == default_catalog


def test_main_hidden_seed_metadata_gives_seed_catalog_more_time(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    metadata = LSTMetadata(data_labels={}, code_labels={})
    seen_timeouts: list[tuple[str, int]] = []
    entry_function = SimpleNamespace(addr=0x11423, name="_start", project=project)
    body_function = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)

    def _fake_run(fn, *, timeout, thread_name_prefix, **_kwargs):
        seen_timeouts.append((thread_name_prefix, timeout))
        return fn()

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_visible_code_labels", lambda _metadata: {})
    monkeypatch.setattr(decompile, "_recovery_code_labels", lambda _metadata: {0x11423: "_startup_sig"})
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_run)
    monkeypatch.setattr(
        decompile,
        "_recover_seeded_exe_functions",
        lambda *_args, **_kwargs: (
            [(SimpleNamespace(), entry_function), (SimpleNamespace(), body_function)],
            [0x11423, 0x10010],
        ),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            tail_validation=_fake_stable_tail_validation(),
            byte_count=1,
            elapsed=0.01,
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "6", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert ("seed-catalog", 8) in seen_timeouts
    assert "/* == function 0x11423 _start == */" in out
    assert "/* == function 0x10010 sub_10010 == */" in out


def test_recover_seeded_exe_functions_prefers_largest_bounded_recovery(monkeypatch):
    code = b"\x55\x8b\xec" + b"\x90" * 0x500
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=0x1000,
                max_addr=len(code) - 1,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
            )
        ),
        factory=SimpleNamespace(
            block=lambda addr, **_kwargs: SimpleNamespace(
                capstone=SimpleNamespace(insns=[SimpleNamespace(address=addr)])
            )
        ),
    )
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project, **_kwargs: [0x1010])
    monkeypatch.setattr(cli_function_discovery, "_rank_exe_function_seeds", lambda _project, **_kwargs: [0x1010])
    monkeypatch.setattr(cli_function_discovery, "_load_seeded_recovery_from_cache", lambda **_kwargs: None)
    seen_regions: list[tuple[int, int]] = []

    def _fake_pick(_project, addr, *, regions=None, **_kwargs):
        seen_regions.append(regions[0])
        size = regions[0][1] - regions[0][0]
        block_count = 1 if size <= 0x80 else 3
        total_size = 0x20 if size <= 0x80 else 0x90
        blocks = tuple(SimpleNamespace(size=total_size // block_count) for _ in range(block_count))
        func = SimpleNamespace(addr=addr, name=f"sub_{addr:x}", is_plt=False, is_simprocedure=False, blocks=blocks)
        return SimpleNamespace(), func

    monkeypatch.setattr(cli_function_discovery, "_pick_function_lean", _fake_pick)
    monkeypatch.setattr(cli_function_discovery, "collect_neighbor_call_targets", lambda _function: [])
    monkeypatch.setattr(
        cli_function_discovery,
        "_run_with_timeout_in_fork",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("run inline")),
    )

    recovered = decompile._recover_seeded_exe_functions(project, timeout=4, limit=1, region_span=0x400)

    assert recovered
    assert len(seen_regions) >= 2
    assert sum(block.size for block in recovered[0][1].blocks) == 0x90


def test_supplement_cached_seeded_recovery_adds_pre_entry_body_function(monkeypatch):
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=0x1000,
                max_addr=0x600,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 0x600),
            )
        ),
    )
    helper_pair = (
        SimpleNamespace(),
        SimpleNamespace(
            addr=0x114CD,
            name="sub_114cd",
            is_plt=False,
            is_simprocedure=False,
            info={},
            blocks=(SimpleNamespace(size=0x18),),
        ),
    )
    body_pair = (
        SimpleNamespace(),
        SimpleNamespace(
            addr=0x10010,
            name="sub_10010",
            is_plt=False,
            is_simprocedure=False,
            info={},
            blocks=(SimpleNamespace(size=0x40), SimpleNamespace(size=0x40)),
        ),
    )
    stored_payloads: list[dict[str, object]] = []

    monkeypatch.setattr(decompile, "_supplement_functions_from_prologue_scan", lambda *_args, **_kwargs: [body_pair])
    monkeypatch.setattr(
        decompile,
        "_rank_function_cfg_pairs_for_display",
        lambda _project, pairs: sorted(pairs, key=lambda item: item[1].addr),
    )
    monkeypatch.setattr(decompile, "_store_cache_json", lambda _kind, _key, payload: stored_payloads.append(payload))

    recovered, addrs = decompile._supplement_cached_seeded_recovery(
        project,
        [helper_pair],
        [0x114CD],
        region_span=0x120,
        per_function_timeout=1,
        limit=4,
        cache_key={"kind": "seeded_function_catalog"},
    )

    assert [function.addr for _cfg, function in recovered] == [0x10010, 0x114CD]
    assert addrs == [0x10010, 0x114CD]
    assert stored_payloads[-1] == {"addrs": [0x10010, 0x114CD]}


def test_supplement_cached_seeded_recovery_prioritizes_linear_body_targets_for_tiny_pre_entry_body(monkeypatch):
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=0x10000,
                max_addr=0x600,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 0x600),
            )
        ),
    )
    tiny_body_pair = (
        SimpleNamespace(),
        SimpleNamespace(
            addr=0x10010,
            name="sub_10010",
            is_plt=False,
            is_simprocedure=False,
            info={"x86_16_recovery_truncated": True},
            blocks=(SimpleNamespace(addr=0x10010, size=0x18),),
        ),
    )
    captured_candidate_addrs: list[int] = []

    monkeypatch.setattr(decompile, "_rank_gap_scan_candidate_addrs", lambda *_args, **_kwargs: [0x10040])
    monkeypatch.setattr(
        decompile,
        "_linear_function_seed_targets",
        lambda _project, addr, **_kwargs: {0x10060} if addr == 0x10010 else set(),
    )
    monkeypatch.setattr(
        decompile,
        "collect_neighbor_call_targets",
        lambda function: [SimpleNamespace(target_addr=0x101A0)] if function.addr == 0x10010 else [],
    )

    def _fake_supplement(_project, _existing_addrs, *, candidate_addrs=None, **_kwargs):
        captured_candidate_addrs[:] = list(candidate_addrs or [])
        return [
            (
                SimpleNamespace(),
                SimpleNamespace(
                    addr=0x10060,
                    name="sub_10060",
                    is_plt=False,
                    is_simprocedure=False,
                    info={},
                    blocks=(SimpleNamespace(addr=0x10060, size=0x60),),
                ),
            )
        ]

    monkeypatch.setattr(decompile, "_supplement_functions_from_prologue_scan", _fake_supplement)
    monkeypatch.setattr(
        decompile,
        "_rank_function_cfg_pairs_for_display",
        lambda _project, pairs: sorted(pairs, key=lambda item: item[1].addr),
    )

    recovered, addrs = decompile._supplement_cached_seeded_recovery(
        project,
        [tiny_body_pair],
        [0x10010],
        region_span=0x120,
        per_function_timeout=1,
        limit=4,
        cache_key=None,
    )

    assert captured_candidate_addrs[:3] == [0x10040, 0x10060, 0x101A0]
    assert [function.addr for _cfg, function in recovered] == [0x10010, 0x10060]
    assert addrs == [0x10010, 0x10060]


def test_recover_seeded_exe_functions_cached_supplement_timeout_uses_cached_recovery(monkeypatch):
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=0x1000,
                max_addr=0x600,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 0x600),
            )
        ),
    )
    helper_pair = (
        SimpleNamespace(),
        SimpleNamespace(
            addr=0x114CD,
            name="sub_114cd",
            is_plt=False,
            is_simprocedure=False,
            info={},
            blocks=(SimpleNamespace(size=0x18),),
        ),
    )

    def _fake_timeout(fn, *, thread_name_prefix, **_kwargs):
        if thread_name_prefix == "cached-supplement":
            raise decompile.FuturesTimeoutError
        return fn()

    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project, **_kwargs: [0x114CD])
    monkeypatch.setattr(decompile, "_load_cache_json", lambda *_args, **_kwargs: {"addrs": [0x114CD]})
    monkeypatch.setattr(decompile, "_recover_cached_function_pairs", lambda *_args, **_kwargs: [helper_pair])
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_timeout)

    recovered, addrs = decompile._recover_seeded_exe_functions(project, timeout=4, limit=2, return_addrs=True)

    assert [function.addr for _cfg, function in recovered] == [0x114CD]
    assert addrs == [0x114CD]


def test_recover_seeded_exe_functions_gives_cached_supplement_more_budget(monkeypatch):
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=0x1000,
                max_addr=0x600,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 0x600),
            )
        ),
    )
    helper_pair = (
        SimpleNamespace(),
        SimpleNamespace(
            addr=0x114CD,
            name="sub_114cd",
            is_plt=False,
            is_simprocedure=False,
            info={},
            blocks=(SimpleNamespace(size=0x18),),
        ),
    )
    captured_timeouts: list[tuple[str, int]] = []

    def _fake_timeout(fn, *, timeout, thread_name_prefix, **_kwargs):
        captured_timeouts.append((thread_name_prefix, timeout))
        return fn()

    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project, **_kwargs: [0x114CD])
    monkeypatch.setattr(decompile, "_load_cache_json", lambda *_args, **_kwargs: {"addrs": [0x114CD]})
    monkeypatch.setattr(decompile, "_recover_cached_function_pairs", lambda *_args, **_kwargs: [helper_pair])
    monkeypatch.setattr(
        decompile, "_supplement_cached_seeded_recovery", lambda _project, pairs, addrs, **_kwargs: (pairs, addrs)
    )
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_timeout)

    recovered, addrs = decompile._recover_seeded_exe_functions(project, timeout=6, limit=2, return_addrs=True)

    assert [function.addr for _cfg, function in recovered] == [0x114CD]
    assert addrs == [0x114CD]
    assert ("cached-supplement", 4) in captured_timeouts


def test_recover_seeded_exe_functions_prioritizes_linear_body_targets_for_truncated_recovery(monkeypatch):
    code = b"\x90" * 0x600
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=0x10000,
                max_addr=len(code) - 1,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
            )
        ),
        factory=SimpleNamespace(
            block=lambda addr, **_kwargs: SimpleNamespace(
                capstone=SimpleNamespace(insns=[SimpleNamespace(address=addr)])
            )
        ),
    )
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project, **_kwargs: [0x10010])
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected lean recovery")),
    )
    monkeypatch.setattr(
        decompile,
        "_recover_candidate_with_timeout",
        lambda _project, *, candidate_addr, **_kwargs: (
            SimpleNamespace(),
            SimpleNamespace(
                addr=candidate_addr,
                name=f"sub_{candidate_addr:x}",
                is_plt=False,
                is_simprocedure=False,
                info={"x86_16_recovery_truncated": candidate_addr == 0x10010},
                blocks=(SimpleNamespace(size=0x18), SimpleNamespace(size=0x18)),
            ),
        ),
    )

    def _collect_neighbor_call_targets(function):
        if function.addr == 0x10010:
            return [SimpleNamespace(target_addr=0x101A0)]
        return []

    monkeypatch.setattr(decompile, "collect_neighbor_call_targets", _collect_neighbor_call_targets)
    monkeypatch.setattr(
        decompile,
        "_linear_function_seed_targets",
        lambda _project, addr, **_kwargs: {0x10050} if addr == 0x10010 else set(),
    )

    recovered = decompile._recover_seeded_exe_functions(project, timeout=4, limit=3)

    assert [func.addr for _cfg, func in recovered] == [0x10010, 0x10050, 0x101A0]


def test_recover_seeded_exe_functions_stops_after_limit_without_return_addrs(monkeypatch):
    code = b"\x90" * 0x600
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=0x10000,
                max_addr=len(code) - 1,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
            )
        ),
        factory=SimpleNamespace(
            block=lambda addr, **_kwargs: SimpleNamespace(
                capstone=SimpleNamespace(insns=[SimpleNamespace(address=addr)])
            )
        ),
    )
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project, **_kwargs: [0x10010, 0x10040, 0x10070])
    monkeypatch.setattr(decompile, "_load_cache_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_store_cache_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_rank_prologue_scan_candidate_addrs", lambda *_args, **_kwargs: [])
    call_order: list[int] = []

    def _fake_recover(_project, *, candidate_addr, **_kwargs):
        call_order.append(candidate_addr)
        return (
            SimpleNamespace(),
            SimpleNamespace(
                addr=candidate_addr,
                name=f"sub_{candidate_addr:x}",
                is_plt=False,
                is_simprocedure=False,
                info={},
                blocks=(SimpleNamespace(size=0x18),),
            ),
        )

    monkeypatch.setattr(decompile, "_recover_candidate_with_timeout", _fake_recover)
    monkeypatch.setattr(decompile, "collect_neighbor_call_targets", lambda _function: [])

    recovered = decompile._recover_seeded_exe_functions(project, timeout=4, limit=2, return_addrs=False)

    assert [func.addr for _cfg, func in recovered] == [0x10010, 0x10040]
    assert call_order == [0x10010, 0x10040]


def test_match_flair_startup_entry_matches_watcom_startup_pattern(tmp_path):
    flair_root = tmp_path / "flair"
    startup_dir = flair_root / "startup"
    startup_dir.mkdir(parents=True, exist_ok=True)
    (startup_dir / "exe_wa16.pat").write_text(
        f"CCEBFD{'..' * 29} 0000 0000 0010 :0000 watcom_entry\n",
        encoding="utf-8",
    )

    entry_bytes = bytes.fromhex("CCEBFD" + "90" * 29)

    matches = match_flair_startup_entry(entry_bytes, flair_root)

    assert matches
    assert any(match.pat_path.endswith("exe_wa16.pat") for match in matches)


def test_list_flair_sig_libraries_reads_pascal_catalogs(tmp_path):
    flair_root = tmp_path / "flair"
    sig_dir = flair_root / "flair-sigs"
    bin_dir = flair_root / "bin" / "linux"
    sig_dir.mkdir(parents=True, exist_ok=True)
    bin_dir.mkdir(parents=True, exist_ok=True)
    (sig_dir / "sample.sig").write_text("sample", encoding="utf-8")
    (bin_dir / "dumpsig").write_text(
        "#!/usr/bin/env sh\n"
        "echo 'Signature     : Turbo Pascal V5.0/5.5/6.0/7.0'\n"
        "echo 'OS types      : DOS'\n"
        "echo 'App types     : EXE'\n"
        "echo 'File types    : PROGRAM'\n",
        encoding="utf-8",
    )
    (bin_dir / "dumpsig").chmod(0o755)

    libraries = list_flair_sig_libraries(flair_root)

    assert any("Turbo Pascal" in library.title for library in libraries)


def test_ensure_pat_from_omf_input_generates_fallback_pat_for_obj(tmp_path):
    pat_path = ensure_pat_from_omf_input(SYNTHETIC_OBJ, tmp_path)

    assert pat_path is not None
    modules = parse_pat_file(pat_path)
    assert [module.module_name for module in modules] == ["E086_SHORTCUT", "E086_ENTRY"]


def test_ensure_pat_from_omf_input_merges_plb_and_fallback_for_life_obj(tmp_path):
    life_obj = REPO_ROOT / "LIFE.OBJ"
    if not life_obj.exists():
        pytest.skip("LIFE.OBJ fixture is not available")

    pat_path = ensure_pat_from_omf_input(life_obj, tmp_path)

    assert pat_path is not None
    modules = parse_pat_file(pat_path)
    names = {module.module_name for module in modules}
    assert "_main" in names
    assert "_generation" in names
    rich_module = next(
        module
        for module in modules
        if module.referenced_names and any(pub.name == "_main" for pub in module.public_names)
    )
    assert any(ref.name == "__chkstk" for ref in rich_module.referenced_names)
    assert len(modules) >= 15


def test_generate_pat_from_omf_obj_captures_fixupp_external_refs_for_life_obj(tmp_path):
    life_obj = REPO_ROOT / "LIFE.OBJ"
    if not life_obj.exists():
        pytest.skip("LIFE.OBJ fixture is not available")
    pat_path = tmp_path / "life-fallback.pat"

    count = generate_pat_from_omf_obj(life_obj, pat_path)

    assert count >= 5
    modules = parse_pat_file(pat_path)
    main_module = next(module for module in modules if module.module_name == "_main")
    assert main_module.referenced_names
    all_ref_names = {ref.name for module in modules for ref in module.referenced_names}
    assert "__chkstk" in all_ref_names
    assert "_printf" in all_ref_names or "_sprintf" in all_ref_names


def test_extract_omf_modules_from_lib_reads_page_aligned_module(tmp_path):
    lib_path = tmp_path / "sample.lib"
    lib_path.write_bytes(_build_synthetic_microsoft_lib(SYNTHETIC_OBJ.read_bytes()))

    modules = extract_omf_modules_from_lib(lib_path)

    assert len(modules) == 1
    assert modules[0].module_name == "SYNTHETIC.OBJ"
    assert modules[0].data.startswith(SYNTHETIC_OBJ.read_bytes()[:16])


def test_parse_microsoft_lib_reads_header_and_extended_dictionary(tmp_path):
    lib_path = tmp_path / "sample.lib"
    lib_path.write_bytes(
        _build_synthetic_microsoft_lib(
            SYNTHETIC_OBJ.read_bytes(),
            case_sensitive=True,
            extended_records=[(1, (7, 9))],
        )
    )

    metadata = parse_microsoft_lib(lib_path)

    assert metadata.header.page_size == 512
    assert metadata.header.case_sensitive is True
    assert metadata.header.dictionary_blocks == 1
    assert len(metadata.modules) == 1
    assert metadata.modules[0].page_number == 1
    assert metadata.modules[0].dependency_indexes == (7, 9)
    assert metadata.extended_records[0].page_number == 1
    assert metadata.extended_records[0].dependency_indexes == (7, 9)


def test_parse_microsoft_lib_reads_dictionary_entries_and_lookup(tmp_path):
    lib_path = tmp_path / "sample.lib"
    lib_path.write_bytes(
        _build_synthetic_microsoft_lib(
            SYNTHETIC_OBJ.read_bytes(),
            dictionary_entries=[("__chkstk", 1), ("_main", 1)],
        )
    )

    metadata = parse_microsoft_lib(lib_path)

    assert {(entry.symbol_name, entry.module_page) for entry in metadata.dictionary_entries} == {
        ("__chkstk", 1),
        ("_main", 1),
    }
    assert lookup_microsoft_lib_symbol(lib_path, "__CHKSTK") is not None
    assert lookup_microsoft_lib_symbol(lib_path, "__CHKSTK").module_page == 1
    assert lookup_microsoft_lib_symbol(lib_path, "_main").symbol_name == "_main"


def test_enumerate_microsoft_lib_dictionary_symbols_preserves_case_sensitive_lookup(tmp_path):
    lib_path = tmp_path / "sample.lib"
    lib_path.write_bytes(
        _build_synthetic_microsoft_lib(
            SYNTHETIC_OBJ.read_bytes(),
            case_sensitive=True,
            dictionary_entries=[("SymbolExact", 1)],
        )
    )

    entries = enumerate_microsoft_lib_dictionary_symbols(lib_path)

    assert [(entry.symbol_name, entry.module_page) for entry in entries] == [("SymbolExact", 1)]
    assert lookup_microsoft_lib_symbol(lib_path, "SymbolExact") is not None
    assert lookup_microsoft_lib_symbol(lib_path, "symbolexact") is None


def test_generate_pat_from_omf_lib_extracts_obj_members(tmp_path):
    lib_path = tmp_path / "sample.lib"
    lib_path.write_bytes(_build_synthetic_microsoft_lib(SYNTHETIC_OBJ.read_bytes()))
    pat_path = tmp_path / "sample.pat"

    count = generate_pat_from_omf_lib(lib_path, pat_path)

    assert count >= 2
    modules = parse_pat_file(pat_path)
    assert [module.module_name for module in modules[:2]] == ["E086_SHORTCUT", "E086_ENTRY"]


@pytest.mark.skipif(not BORLAND_CC_LIB.exists(), reason="Borland Turbo C v2 library samples are not available")
def test_parse_omf_lib_smoke_reads_real_borland_turbo_c_archive():
    metadata = parse_omf_lib(BORLAND_CC_LIB)

    assert metadata.header.page_size == 16
    assert len(metadata.modules) > 200
    assert len(metadata.dictionary_entries) > 500
    assert metadata.modules[0].module_name == "IOERROR"
    assert enumerate_omf_lib_dictionary_symbols(BORLAND_CC_LIB)
    assert lookup_omf_lib_symbol(BORLAND_CC_LIB, "__IOERROR") is not None


@pytest.mark.skipif(
    not BORLAND_GRAPHICS_LIB.exists(), reason="Borland Turbo C v2 graphics library sample is not available"
)
def test_generate_pat_from_real_borland_omf_lib_smoke(tmp_path):
    pat_path = tmp_path / "graphics.pat"

    count = generate_pat_from_omf_lib(BORLAND_GRAPHICS_LIB, pat_path)

    assert count > 0
    modules = parse_pat_file(pat_path)
    assert modules
    assert any(module.module_name in {"___move", "_graphresult", "_detectgraph"} for module in modules)


def test_match_pat_modules_labels_unique_generated_function_match():
    image = bytes.fromhex(
        "90 90 90 FB FC 52 50 53 55 56 57 06 51 1E 8B EC 36 89 2E DE 00 C5 76 12 AD 89 76 12 8C D7 8E DF 8A CC 98 C3 90"
    )
    module = PatModule(
        source_path="<memory>",
        compiler_name="",
        module_name="demo_func",
        pattern_bytes=tuple([0xFB, 0xFC, 0x52, 0x50, 0x53, 0x55, 0x56, 0x57, 0x06, 0x51, 0x1E, 0x8B] + [None] * 20),
        module_length=0x0C,
        public_names=(PatPublicName(offset=0, name="demo_func"),),
        referenced_names=(),
        tail_bytes=(),
    )

    code_labels, code_ranges, matched_compiler_names = match_pat_modules(image, 0x1000, [module])

    assert code_labels == {0x1003: "demo_func"}
    assert code_ranges == {0x1003: (0x1003, 0x100F)}
    assert matched_compiler_names == ()


def test_load_cached_pat_regex_specs_creates_reusable_disk_cache(tmp_path):
    pat_path = tmp_path / "demo.pat"
    pattern = "FBFC52505355565706511E8BEC" + (".." * 19)
    pat_path.write_text(f"{pattern} 00 0000 000C :0000 demo_func\n---\n")

    specs = load_cached_pat_regex_specs(pat_path, tmp_path)

    assert len(specs) == 1
    assert isinstance(specs[0], CachedPatRegexSpec)
    assert any(path.suffixes[-2:] == [".patrx", ".pickle"] for path in tmp_path.iterdir() if path.is_file())


def test_match_pat_modules_accepts_cached_regex_specs(tmp_path):
    pat_path = tmp_path / "demo.pat"
    pattern = "FBFC52505355565706511E8BEC" + (".." * 19)
    pat_path.write_text(f"{pattern} 00 0000 000C :0000 demo_func\n---\n")
    specs = load_cached_pat_regex_specs(pat_path, tmp_path)
    image = bytes.fromhex(
        "90 90 90 FB FC 52 50 53 55 56 57 06 51 1E 8B EC 36 89 2E DE 00 C5 76 12 AD 89 76 12 8C D7 8E DF 8A CC 98 C3 90"
    )

    code_labels, code_ranges, matched_compiler_names = match_pat_modules(image, 0x1000, specs)

    assert code_labels == {0x1003: "demo_func"}
    assert code_ranges == {0x1003: (0x1003, 0x100F)}
    assert matched_compiler_names == ()


def test_match_pat_modules_supports_both_explicit_backends(tmp_path):
    pat_path = tmp_path / "demo.pat"
    pattern = "FBFC52505355565706511E8BEC" + (".." * 19)
    pat_path.write_text(f"{pattern} 00 0000 000C :0000 demo_func\n---\n")
    specs = load_cached_pat_regex_specs(pat_path, tmp_path)
    image = bytes.fromhex(
        "90 90 90 FB FC 52 50 53 55 56 57 06 51 1E 8B EC 36 89 2E DE 00 C5 76 12 AD 89 76 12 8C D7 8E DF 8A CC 98 C3 90"
    )

    py_labels, py_ranges, py_compilers = match_pat_modules(image, 0x1000, specs, backend="python_regex")
    hs_labels, hs_ranges, hs_compilers = match_pat_modules(image, 0x1000, specs, backend="hyperscan")

    assert py_labels == {0x1003: "demo_func"}
    assert py_ranges == {0x1003: (0x1003, 0x100F)}
    assert hs_labels == py_labels
    assert hs_ranges == py_ranges
    assert py_compilers == hs_compilers == ()


def test_normalize_pat_backend_choice_rejects_unknown_backend():
    with pytest.raises(ValueError):
        _normalize_pat_backend_choice("wat")


def test_detect_flair_metadata_forwards_pat_backend(monkeypatch, tmp_path):
    recorded = {}
    project = SimpleNamespace(
        entry=0x1000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(),
            memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 32),
        ),
    )

    monkeypatch.setattr(sidecar_parsers, "match_flair_startup_entry", lambda *_args, **_kwargs: ())
    monkeypatch.setattr(sidecar_parsers, "flair_signature_root", lambda: tmp_path)

    def _fake_startup_pat_match(project_arg, flair_root, *, backend=None):
        recorded["backend"] = backend
        del project_arg, flair_root
        return {}, {}, ()

    monkeypatch.setattr(sidecar_parsers, "_match_flair_startup_pat_functions", _fake_startup_pat_match)

    sidecar_parsers._detect_flair_metadata(Path("/tmp/demo.exe"), project, pat_backend="python_regex")

    assert recorded["backend"] == "python_regex"


def test_build_signature_catalog_skips_duplicate_modules(tmp_path):
    left = tmp_path / "left.pat"
    right = tmp_path / "right.pat"
    pattern = "FBFC52505355565706511E8BEC" + (".." * 19)
    left.write_text(f"{pattern} 00 0000 000C :0000 demo_func\n---\n")
    right.write_text(f"{pattern} 00 0000 000C :0000 demo_func\n---\n")
    output = tmp_path / "catalog.pat"

    result = build_signature_catalog([left, right], output, recursive=False, cache_dir=tmp_path / "cache")

    assert result.input_count == 2
    assert result.imported_module_count == 2
    assert result.unique_module_count == 1
    assert result.duplicate_module_count == 1
    modules = parse_pat_file(output)
    assert [module.module_name for module in modules] == ["demo_func"]


def test_build_signature_catalog_merges_exact_patterns_with_normalized_names(tmp_path):
    left = tmp_path / "left.pat"
    right = tmp_path / "right.pat"
    pattern = "FBFC52505355565706511E8BEC" + (".." * 19)
    left.write_text(f"{pattern} 00 0000 000C :0000 __DEMO123__\n---\n")
    right.write_text(f"{pattern} 00 0000 000C :0000 demo123\n---\n")
    output = tmp_path / "catalog.pat"

    result = build_signature_catalog([left, right], output, recursive=False, cache_dir=tmp_path / "cache")

    assert result.input_count == 2
    assert result.imported_module_count == 2
    assert result.unique_module_count == 1
    assert result.duplicate_module_count == 1
    modules = parse_pat_file(output)
    assert [module.module_name for module in modules] == ["__DEMO123__"]


def test_build_signature_catalog_merges_exact_patterns_with_internal_underscores(tmp_path):
    left = tmp_path / "left.pat"
    right = tmp_path / "right.pat"
    pattern = "FBFC52505355565706511E8BEC" + (".." * 19)
    left.write_text(f"{pattern} 00 0000 000C :0000 __DEMO_FUNC_123__\n---\n")
    right.write_text(f"{pattern} 00 0000 000C :0000 demo_func_123\n---\n")
    output = tmp_path / "catalog.pat"

    result = build_signature_catalog([left, right], output, recursive=False, cache_dir=tmp_path / "cache")

    assert result.input_count == 2
    assert result.imported_module_count == 2
    assert result.unique_module_count == 1
    assert result.duplicate_module_count == 1
    modules = parse_pat_file(output)
    assert [module.module_name for module in modules] == ["__DEMO_FUNC_123__"]


def test_match_signature_catalog_matches_prebuilt_catalog(tmp_path):
    pattern = "FBFC52505355565706511E8BEC" + (".." * 19)
    catalog = tmp_path / "catalog.pat"
    catalog.write_text(f"{pattern} 00 0000 000C :0000 demo_func ; mod=demo_func | compiler=Microsoft C v5.1\n---\n")
    image = bytes.fromhex(
        "90 90 90 FB FC 52 50 53 55 56 57 06 51 1E 8B EC 36 89 2E DE 00 C5 76 12 AD 89 76 12 8C D7 8E DF 8A CC 98 C3 90"
    )
    project = SimpleNamespace(
        loader=SimpleNamespace(
            main_object=SimpleNamespace(min_addr=0x1000, max_addr=0x1000 + len(image) - 1),
            memory=SimpleNamespace(load=lambda addr, size: image[addr - 0x1000 : addr - 0x1000 + size]),
        )
    )

    result = match_signature_catalog(catalog, tmp_path / "demo.exe", project, backend="python_regex")

    assert result.code_labels == {0x1003: "demo_func"}
    assert result.code_ranges == {0x1003: (0x1003, 0x100F)}
    assert result.source_formats == ("signature_catalog",)
    assert result.matched_compiler_names == ("Microsoft C v5.1",)


def test_detect_flair_metadata_merges_signature_catalog(monkeypatch, tmp_path):
    project = SimpleNamespace(
        entry=0x2000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(),
            memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 32),
        ),
    )
    catalog = tmp_path / "catalog.pat"
    catalog.write_text("---\n")
    monkeypatch.setattr(sidecar_parsers, "match_flair_startup_entry", lambda *_args, **_kwargs: ())
    monkeypatch.setattr(sidecar_parsers, "flair_signature_root", lambda: tmp_path)
    monkeypatch.setattr(
        sidecar_parsers,
        "_match_flair_startup_pat_functions",
        lambda *_args, **_kwargs: ({}, {}, ()),
    )
    monkeypatch.setattr(
        sidecar_parsers,
        "match_signature_catalog",
        lambda *_args, **_kwargs: SimpleNamespace(
            code_labels={0x2345: "catalog_func"},
            code_ranges={0x2345: (0x2345, 0x2350)},
            source_formats=("signature_catalog",),
        ),
    )

    code_labels, code_ranges, source_formats = sidecar_parsers._detect_flair_metadata(
        Path("/tmp/demo.exe"),
        project,
        pat_backend="python_regex",
        signature_catalog=catalog,
    )

    assert code_labels[0x2345] == "catalog_func"
    assert code_ranges[0x2345] == (0x2345, 0x2350)
    assert "signature_catalog" in source_formats


def test_detect_flair_metadata_searches_startup_pats_across_whole_binary(monkeypatch, tmp_path):
    project = SimpleNamespace(
        entry=0x2000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(min_addr=0x2000, max_addr=0x203F),
            memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 64),
        ),
    )
    seen: dict[str, object] = {}

    monkeypatch.setattr(sidecar_parsers, "match_flair_startup_entry", lambda *_args, **_kwargs: ())
    monkeypatch.setattr(sidecar_parsers, "flair_signature_root", lambda: tmp_path)
    monkeypatch.setattr(sidecar_parsers, "_load_flair_startup_pat_modules", lambda *_args, **_kwargs: ("module",))

    def _fake_match(image_bytes, base_addr, modules, *, backend=None):
        seen["image_len"] = len(image_bytes)
        seen["base_addr"] = base_addr
        seen["modules"] = modules
        seen["backend"] = backend
        return {0x2010: "startup_sig_func"}, {0x2010: (0x2010, 0x2020)}, ()

    monkeypatch.setattr(sidecar_parsers, "match_pat_modules", _fake_match)

    code_labels, code_ranges, source_formats = sidecar_parsers._detect_flair_metadata(
        Path("/tmp/demo.exe"),
        project,
        pat_backend="python_regex",
    )

    assert seen == {"image_len": 64, "base_addr": 0x2000, "modules": ("module",), "backend": "python_regex"}
    assert code_labels[0x2010] == "startup_sig_func"
    assert code_ranges[0x2010] == (0x2010, 0x2020)
    assert "startup_flair_pat" in source_formats


def test_try_decompile_sidecar_slice_retries_with_broader_exact_region_recovery(monkeypatch):
    slice_project = SimpleNamespace()
    function = SimpleNamespace(name="func")
    project = SimpleNamespace(
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90\xc3")),
    )
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1000: "func"},
        code_ranges={0x1000: (0x1000, 0x1002)},
        absolute_addrs=True,
        source_format="cod_listing",
    )
    calls: list[str] = []

    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *args, **kwargs: slice_project)

    def _fake_pick_lean(*_args, **_kwargs):
        calls.append("lean")
        raise KeyError("lean failed")

    def _fake_pick_full(*_args, data_references=None, **_kwargs):
        calls.append(f"full:{data_references}")
        return "cfg", function

    monkeypatch.setattr(decompile, "_pick_function_lean", _fake_pick_lean)
    monkeypatch.setattr(decompile, "_pick_function", _fake_pick_full)
    monkeypatch.setattr(
        decompile,
        "_decompile_function_with_stats",
        lambda *_args, **_kwargs: ("ok", "void func(void)\n{\n}\n", 1, 2, 0.01),
    )

    result = decompile._try_decompile_sidecar_slice(
        project,
        metadata,
        0x1000,
        "func",
        timeout=6,
        api_style="default",
        binary_path=None,
    )

    assert result == ("ok", "void func(void)\n{\n}\n")
    assert calls == ["lean", "full:False"]


def test_try_decompile_sidecar_slice_preserves_tail_validation_snapshot_on_source_project(monkeypatch):
    slice_project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    function = SimpleNamespace(name="func", info={})
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90\xc3")),
    )
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1000: "func"},
        code_ranges={0x1000: (0x1000, 0x1002)},
        absolute_addrs=True,
        source_format="cod_listing",
    )

    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *args, **kwargs: slice_project)
    monkeypatch.setattr(decompile, "_pick_function_lean", lambda *_args, **_kwargs: ("cfg", function))

    def _fake_decompile(*_args, **_kwargs):
        slice_project._inertia_last_tail_validation_snapshot = {
            "structuring": {"changed": False, "mode": "live_out", "verdict": "structuring stable"},
            "postprocess": {"changed": False, "mode": "live_out", "verdict": "postprocess stable"},
        }
        return ("ok", "void func(void)\n{\n}\n", 1, 2, 0.01)

    monkeypatch.setattr(decompile, "_decompile_function_with_stats", _fake_decompile)

    result = decompile._try_decompile_sidecar_slice(
        project,
        metadata,
        0x1000,
        "func",
        timeout=6,
        api_style="default",
        binary_path=None,
    )

    assert result is not None
    assert result.status == "ok"
    assert result.payload == "void func(void)\n{\n}\n"
    assert project._inertia_last_tail_validation_snapshot == {
        "structuring": {"changed": False, "mode": "live_out", "verdict": "structuring stable"},
        "postprocess": {"changed": False, "mode": "live_out", "verdict": "postprocess stable"},
    }


def test_try_decompile_sidecar_slice_uses_extended_bounded_timeout(monkeypatch):
    slice_project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    function = SimpleNamespace(name="func", info={})
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90\xc3")),
    )
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1000: "func"},
        code_ranges={0x1000: (0x1000, 0x1002)},
        absolute_addrs=True,
        source_format="cod_listing",
    )
    runner_timeouts: list[int] = []
    decompile_timeouts: list[int] = []

    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *args, **kwargs: slice_project)
    monkeypatch.setattr(decompile, "_pick_function_lean", lambda *_args, **_kwargs: ("cfg", function))
    monkeypatch.setattr(
        decompile,
        "build_default_slice_recovery_attempts",
        lambda *_args, pick_function_lean, **_kwargs: (
            ("lean", lambda slice_project: pick_function_lean(slice_project, 0x1000)),
        ),
    )

    def _fake_run(job, *, timeout, **_kwargs):
        runner_timeouts.append(timeout)
        return job()

    def _fake_decompile(_project, _cfg, _func, timeout, *_args, **_kwargs):
        decompile_timeouts.append(timeout)
        return ("ok", "void func(void)\n{\n}\n", 1, 2, 0.01)

    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_run)
    monkeypatch.setattr(decompile, "_decompile_function_with_stats", _fake_decompile)

    result = decompile._try_decompile_sidecar_slice(
        project,
        metadata,
        0x1000,
        "func",
        timeout=120,
        api_style="default",
        binary_path=None,
    )

    assert result is not None
    assert result.status == "ok"
    assert runner_timeouts == [30]
    assert decompile_timeouts == [24]


def test_try_decompile_sidecar_slice_refuses_cod_source_when_decompiler_stays_empty(monkeypatch):
    slice_project = SimpleNamespace()
    function = SimpleNamespace(name="func")
    project = SimpleNamespace(
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90\xc3")),
    )
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1000: "func"},
        code_ranges={0x1000: (0x1000, 0x1002)},
        absolute_addrs=True,
        source_format="cod_listing",
        cod_path="/tmp/demo.cod",
    )

    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *args, **kwargs: slice_project)
    monkeypatch.setattr(decompile, "_pick_function_lean", lambda *_args, **_kwargs: ("cfg", function))
    monkeypatch.setattr(
        decompile,
        "build_default_slice_recovery_attempts",
        lambda *_args, pick_function_lean, **_kwargs: (
            ("lean", lambda slice_project: pick_function_lean(slice_project, 0x1000)),
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_decompile_function_with_stats",
        lambda *_args, **_kwargs: ("empty", "Decompiler did not produce code.", 1, 2, 0.01),
    )
    result = decompile._try_decompile_sidecar_slice(
        project,
        metadata,
        0x1000,
        "func",
        timeout=6,
        api_style="default",
        binary_path=Path("/tmp/demo.exe"),
    )

    assert result is not None
    assert result.status == "empty"
    assert result.payload == "Decompiler did not produce code."


def test_recover_lst_function_retries_full_exact_region_when_lean_result_is_truncated(monkeypatch):
    project = SimpleNamespace(entry=0x2000, arch=SimpleNamespace(name="86_16"))
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1000: "func"},
        code_ranges={0x1000: (0x1000, 0x10C0)},
        absolute_addrs=True,
        source_format="cod_listing",
    )
    tiny_func = SimpleNamespace(
        name="func", blocks=(SimpleNamespace(addr=0x1000, size=8), SimpleNamespace(addr=0x1008, size=8))
    )
    full_func = SimpleNamespace(
        name="func",
        blocks=(
            SimpleNamespace(addr=0x1000, size=0x30),
            SimpleNamespace(addr=0x1030, size=0x30),
            SimpleNamespace(addr=0x1060, size=0x30),
        ),
    )
    calls: list[tuple[str, object]] = []

    monkeypatch.setattr(
        decompile, "_analysis_timeout", lambda *_args, **_kwargs: __import__("contextlib").nullcontext()
    )
    monkeypatch.setattr(decompile, "_x86_16_fast_recovery_windows", lambda *_args, **_kwargs: (0x80,))
    monkeypatch.setattr(decompile, "_x86_16_recovery_windows", lambda *_args, **_kwargs: (0x80,))
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: calls.append(("lean", None)) or ("cfg-lean", tiny_func),
    )

    def _fake_pick_function(*_args, data_references=None, **_kwargs):
        calls.append(("full", data_references))
        return "cfg-full", full_func

    monkeypatch.setattr(decompile, "_pick_function", _fake_pick_function)

    cfg, func = decompile._recover_lst_function(
        project,
        metadata,
        0x1000,
        "func",
        timeout=2,
        window=0x200,
    )

    assert cfg == "cfg-full"
    assert func is full_func
    assert calls == [("lean", None), ("full", False), ("full", True)]


def test_load_lst_metadata_forwards_flair_parameters_without_global_args(monkeypatch, tmp_path):
    binary = tmp_path / "demo.exe"
    binary.write_bytes(b"MZ")
    catalog = tmp_path / "catalog.pat"
    catalog.write_text("---\n")
    project = SimpleNamespace(
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x1000, max_addr=0x40)),
        kb=SimpleNamespace(labels={}),
    )
    seen: dict[str, object] = {}

    monkeypatch.setattr(sidecar_metadata, "_probe_ida_base_linear", lambda *_args, **_kwargs: 0x1000)
    monkeypatch.setattr(
        sidecar_metadata,
        "_detect_flair_metadata",
        lambda _binary, _project, *, pat_backend=None, signature_catalog=None: (
            seen.setdefault("pat_backend", pat_backend) and {0x1010: "sig_func"},
            seen.setdefault("signature_catalog", signature_catalog) and {0x1010: (0x1010, 0x1020)},
            ("signature_catalog",),
        ),
    )

    metadata = sidecar_metadata._load_lst_metadata(
        binary,
        project,
        pat_backend="python_regex",
        signature_catalog=catalog,
    )

    assert metadata is not None
    assert seen == {"pat_backend": "python_regex", "signature_catalog": catalog}
    assert metadata.code_labels[0x1010] == "sig_func"
    assert metadata.signature_code_addrs == frozenset({0x1010})


@requires_life_binary
@requires_life2_binary
def test_life2_without_external_binary_catalog_metadata_has_no_sidecars_but_life_does():
    life_project = decompile._build_project(LIFE_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    life_metadata = sidecar_metadata._load_lst_metadata(LIFE_EXE, life_project)

    life2_project = decompile._build_project(LIFE2_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    life2_metadata = sidecar_metadata._load_lst_metadata(LIFE2_EXE, life2_project)

    assert life_metadata is not None
    assert sidecar_metadata._visible_code_labels(life_metadata)
    assert life2_metadata is not None
    assert sidecar_metadata._visible_code_labels(life2_metadata) == {}
    assert life2_metadata.source_format == "startup_flair_pat"


@requires_life2_binary
def test_life2_default_metadata_stays_independent_from_peer_binary_catalog():
    project = decompile._build_project(LIFE2_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = sidecar_metadata._load_lst_metadata(LIFE2_EXE, project)

    assert metadata is not None
    assert "peer_exe" not in metadata.source_format
    assert sidecar_metadata._visible_code_labels(metadata) == {}


@requires_life2_binary
def test_life2_signature_metadata_seeds_bounded_recovery_without_peer_catalog():
    project = decompile._build_project(LIFE2_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = sidecar_metadata._load_lst_metadata(LIFE2_EXE, project)

    assert metadata is not None
    assert sidecar_metadata._visible_code_labels(metadata) == {}
    recovery_labels = sidecar_metadata._recovery_code_labels(metadata)
    assert recovery_labels
    span_start, _span = next((addr, span) for addr, span in metadata.code_ranges.items() if span[1] - span[0] > 1)
    start_name = sidecar_metadata._lst_code_label(metadata, span_start, project.entry)
    assert start_name is not None
    assert sidecar_metadata._lst_code_label(metadata, span_start + 1, project.entry) == start_name

    ranked = decompile._rank_exe_function_seeds(project)

    assert ranked
    assert any(addr in recovery_labels for addr in ranked)


@requires_life2_binary
def test_life2_signature_metadata_bounded_span_precedes_tiny_helper_seed(monkeypatch):
    project = decompile._build_project(LIFE2_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = sidecar_metadata._load_lst_metadata(LIFE2_EXE, project)

    assert metadata is not None
    project._inertia_lst_metadata = metadata
    bounded_addr, bounded_span = next(
        (addr, span) for addr, span in metadata.code_ranges.items() if span[1] - span[0] > 1
    )
    helper_addr = 0x1140D
    assert bounded_span[1] - bounded_span[0] > 1

    window_start = min(bounded_addr, helper_addr)
    window_end = max(bounded_addr, helper_addr) + 0x40

    monkeypatch.setattr(decompile, "_seed_scan_windows", lambda _project, **_kwargs: [(window_start, window_end)])
    monkeypatch.setattr(decompile, "_entry_window_seed_targets", lambda *_args, **_kwargs: {helper_addr})
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyError("no entry CFG")),
    )

    ranked = decompile._rank_exe_function_seeds(project)

    assert bounded_addr in ranked
    assert helper_addr in ranked
    assert ranked.index(bounded_addr) < ranked.index(helper_addr)


def test_load_lst_metadata_reuses_cached_flair_metadata(monkeypatch, tmp_path):
    binary = tmp_path / "demo.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x1000,
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x1000, max_addr=0x1040)),
        kb=SimpleNamespace(labels={}),
    )
    cache_store = {}
    seen = {"calls": 0}

    monkeypatch.setattr(sidecar_metadata, "_probe_ida_base_linear", lambda _binary, _linked_base=0: 0x1000)
    monkeypatch.setattr(
        sidecar_cache, "_load_cache_json", lambda namespace, key: cache_store.get((namespace, repr(key)))
    )
    monkeypatch.setattr(
        sidecar_cache,
        "_store_cache_json",
        lambda namespace, key, value: cache_store.__setitem__((namespace, repr(key)), value),
    )

    def fake_detect_flair_metadata(_binary, _project, *, pat_backend=None, signature_catalog=None):
        assert pat_backend == "python"
        assert signature_catalog is None
        seen["calls"] += 1
        _project._inertia_flair_startup_matches = "startup/demo.pat",
        _project._inertia_signature_compiler_names = "Microsoft C v5.1",
        return {0x1010: "sig_func"}, {0x1010: (0x1010, 0x1020)}, ("startup_flair_pat",)

    monkeypatch.setattr(sidecar_metadata, "_detect_flair_metadata", fake_detect_flair_metadata)

    first = sidecar_metadata._load_lst_metadata(binary, project, pat_backend="python")
    assert first is not None
    assert first.code_labels[0x1010] == "sig_func"
    assert seen["calls"] == 1

    second_project = SimpleNamespace(
        entry=0x1000,
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x1000, max_addr=0x1040)),
        kb=SimpleNamespace(labels={}),
    )
    second = sidecar_metadata._load_lst_metadata(binary, second_project, pat_backend="python")

    assert second is not None
    assert second.code_labels[0x1010] == "sig_func"
    assert seen["calls"] == 1
    assert getattr(second_project, "_inertia_flair_startup_matches", ()) == ("startup/demo.pat",)
    assert getattr(second_project, "_inertia_signature_compiler_names", ()) == ("Microsoft C v5.1",)


def test_parse_ida_map_metadata_prefers_segment_class_over_loc_name(tmp_path):
    map_path = tmp_path / "demo.map"
    map_path.write_text(
        "\n"
        " Start  Stop   Length Name               Class\n"
        "\n"
        " 00000H 0001FH 00020H seg000             CODE\n"
        " 00020H 0002FH 00010H dseg               DATA\n"
        "\n"
        "  Address         Publics by Value\n"
        "\n"
        " 0000:0004       loc_10004\n"
        " 0000:0010       main\n"
        " 0002:0002       word_10022\n"
    )

    code_labels, data_labels, segment_offsets = decompile._parse_ida_map_metadata(map_path, load_base_linear=0x10000)

    assert segment_offsets == {"seg000": 0x0000, "dseg": 0x0020}
    assert code_labels[0x10004] == "loc_10004"
    assert code_labels[0x10010] == "main"
    assert data_labels[0x10022] == "word_10022"


def test_ida_lst_segment_offset_does_not_double_count_map_org(tmp_path):
    map_path = tmp_path / "sample.map"
    map_path.write_text(
        " Start  Stop   Length Name Class\n"
        " 03F93H 0B2C3H 07331H seg03f9 CODE\n"
        " Address Publics by Value\n"
        " 03F9:0003 _main\n"
    )
    lst_path = tmp_path / "sample.lst"
    lst_path.write_text("seg03f9:0003 _main proc near\n")

    code_labels, _data_labels, segment_offsets = decompile._parse_ida_map_metadata(
        map_path,
        load_base_linear=0x10000,
    )
    lst_labels = decompile._parse_ida_lst_proc_metadata(
        lst_path,
        load_base_linear=0x10000,
        segment_offsets=segment_offsets,
    )

    assert segment_offsets == {"seg03f9": 0x3F90}
    assert code_labels[0x13F93] == "main"
    assert lst_labels == {0x13F93: "main"}


def test_segmented_ida_lst_does_not_publish_raw_offset_duplicate(tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    binary.with_suffix(".lst").write_text("seg03f9:0003 _main proc near\n")
    code_labels: dict[int, str] = {}
    source_formats: list[str] = []

    function_entry_addrs = sidecar_metadata._load_lst_sidecar(
        binary,
        load_base_linear=0x10000,
        segment_offsets={"seg03f9": 0x3F90},
        code_labels=code_labels,
        data_labels={},
        code_ranges={},
        source_formats=source_formats,
    )

    assert code_labels == {0x13F93: "main"}
    assert function_entry_addrs == {0x13F93}
    assert source_formats == ["ida_lst"]


def test_parse_ida_map_metadata_classifies_msvc_data_segments(tmp_path):
    map_path = tmp_path / "demo.MAP"
    map_path.write_text(
        "\n"
        " Start  Stop   Length Name               Class\n"
        "\n"
        " 00000H 0001FH 00020H _TEXT              CODE\n"
        " 05DA0H 05DE1H 00042H NULL               BEGDATA\n"
        " 063FAH 06401H 00008H CONST              CONST\n"
        "\n"
        "  Address         Publics by Value\n"
        "\n"
        " 0000:0010       _main\n"
        " 05DA:0BA4       _iSwaps\n"
        " 063F:0001       _msgText\n"
    )

    code_labels, data_labels, _segment_offsets = decompile._parse_ida_map_metadata(
        map_path,
        load_base_linear=0x10000,
    )

    assert code_labels[0x10010] == "main"
    assert data_labels[0x16944] == "_iSwaps"
    assert data_labels[0x163F1] == "_msgText"
    assert 0x16944 not in code_labels
    assert 0x163F1 not in code_labels


def test_sidecar_cache_content_fingerprints_case_insensitive_siblings(tmp_path):
    binary = tmp_path / "DEMO.EXE"
    binary.write_bytes(b"MZ")
    (tmp_path / "DEMO.MAP").write_text("map")
    (tmp_path / "demo.COD").write_text("cod")

    sidecars = recovery_cache._cache_sidecar_fingerprints(binary)

    assert sidecars[".map"] == recovery_cache._cache_content_fingerprint(tmp_path / "DEMO.MAP")
    assert sidecars[".cod"] == recovery_cache._cache_content_fingerprint(tmp_path / "demo.COD")


def test_lst_code_region_uses_nearest_containing_start_for_overlaps():
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x10768: "SwapBars", 0x10794: "Swaps"},
        code_ranges={
            0x10768: (0x10768, 0x107B8),
            0x10794: (0x10794, 0x107E7),
        },
        absolute_addrs=True,
    )

    assert sidecar_metadata._lst_code_region(metadata, 0x10794) == (0x10794, 0x107E7)
    assert sidecar_metadata._lst_code_region(metadata, 0x107A8) == (0x10794, 0x107E7)


def test_cod_body_range_extends_unbounded_approximate_public_start(monkeypatch, tmp_path):
    binary = tmp_path / "DEMO.EXE"
    binary.write_bytes(b"MZ")
    (tmp_path / "DEMO.COD").write_text("")
    code_labels = {0x10794: "Swaps"}
    data_labels: dict[int, str] = {}
    code_ranges: dict[int, tuple[int, int]] = {}
    source_formats: list[str] = []
    cod_proc_kinds: dict[int, str] = {}
    project = SimpleNamespace(loader=SimpleNamespace(memory=SimpleNamespace()))

    monkeypatch.setattr(
        sidecar_metadata,
        "_parse_cod_sidecar_metadata",
        lambda *_args, **_kwargs: SimpleNamespace(
            code_labels={0x107B8: "Swaps"},
            code_ranges={0x107B8: (0x107B8, 0x107E7)},
            proc_kinds={0x107B8: "NEAR"},
        ),
    )
    monkeypatch.setattr(sidecar_metadata, "_reconcile_cod_listing_with_codeview", lambda cod, *_args: cod)
    monkeypatch.setattr(sidecar_metadata, "_detect_flair_metadata", lambda *_args, **_kwargs: ({}, {}, ()))

    cod_path, signature_addrs = sidecar_metadata._load_cod_mzre_flair_sidecars(
        binary,
        project,
        load_base_linear=0x10000,
        code_labels=code_labels,
        data_labels=data_labels,
        code_ranges=code_ranges,
        source_formats=source_formats,
        codeview_code={},
        codeview_ranges={},
        pat_backend=None,
        signature_catalog=None,
        cod_proc_kinds=cod_proc_kinds,
    )

    assert cod_path == tmp_path / "DEMO.COD"
    assert signature_addrs == set()
    assert code_labels == {0x10794: "Swaps"}
    assert code_ranges[0x10794] == (0x10794, 0x107E7)
    assert 0x107B8 not in code_ranges
    assert cod_proc_kinds == {0x10794: "NEAR"}
    assert source_formats == ["cod_listing"]


def test_cod_body_range_extends_existing_precise_function_start(monkeypatch, tmp_path):
    binary = tmp_path / "DEMO.EXE"
    binary.write_bytes(b"MZ")
    (tmp_path / "DEMO.COD").write_text("")
    code_labels = {0x10794: "Swaps"}
    data_labels: dict[int, str] = {}
    code_ranges = {0x10794: (0x10794, 0x107B8)}
    source_formats: list[str] = []
    cod_proc_kinds: dict[int, str] = {}
    project = SimpleNamespace(loader=SimpleNamespace(memory=SimpleNamespace()))

    monkeypatch.setattr(
        sidecar_metadata,
        "_parse_cod_sidecar_metadata",
        lambda *_args, **_kwargs: SimpleNamespace(
            code_labels={0x107B8: "Swaps"},
            code_ranges={0x107B8: (0x107B8, 0x107E7)},
            proc_kinds={0x107B8: "NEAR"},
        ),
    )
    monkeypatch.setattr(sidecar_metadata, "_reconcile_cod_listing_with_codeview", lambda cod, *_args: cod)
    monkeypatch.setattr(sidecar_metadata, "_detect_flair_metadata", lambda *_args, **_kwargs: ({}, {}, ()))

    sidecar_metadata._load_cod_mzre_flair_sidecars(
        binary,
        project,
        load_base_linear=0x10000,
        code_labels=code_labels,
        data_labels=data_labels,
        code_ranges=code_ranges,
        source_formats=source_formats,
        codeview_code={},
        codeview_ranges={},
        pat_backend=None,
        signature_catalog=None,
        cod_proc_kinds=cod_proc_kinds,
    )

    assert code_labels == {0x10794: "Swaps"}
    assert code_ranges == {0x10794: (0x10794, 0x107E7)}
    assert cod_proc_kinds == {0x10794: "NEAR"}


def test_visible_code_labels_skip_signature_matched_functions_by_default():
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1200: "real_func", 0x1300: "sig_func"},
        code_ranges={0x1200: (0x1200, 0x1220), 0x1300: (0x1300, 0x1310)},
        signature_code_addrs=frozenset({0x1300}),
        absolute_addrs=True,
        source_format="ida_map+signature_catalog",
    )

    assert decompile._visible_code_labels(metadata) == {0x1200: "real_func"}


def test_recovery_code_labels_include_bounded_signature_matches_without_changing_visible_catalog():
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1200: "real_func", 0x1300: "sig_func", 0x1400: "loose_sig_func"},
        code_ranges={0x1200: (0x1200, 0x1220), 0x1300: (0x1300, 0x1310)},
        signature_code_addrs=frozenset({0x1300, 0x1400}),
        absolute_addrs=True,
        source_format="ida_map+signature_catalog",
    )

    assert decompile._visible_code_labels(metadata) == {0x1200: "real_func"}
    assert sidecar_metadata._recovery_code_labels(metadata) == {
        0x1200: "real_func",
        0x1300: "sig_func",
        0x1400: "loose_sig_func",
    }


def test_format_sidecar_function_catalog_omits_signature_matched_functions():
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1200: "real_func", 0x1300: "sig_func"},
        code_ranges={0x1200: (0x1200, 0x1220), 0x1300: (0x1300, 0x1310)},
        signature_code_addrs=frozenset({0x1300}),
        absolute_addrs=True,
        source_format="signature_catalog",
    )

    formatted = decompile._format_sidecar_function_catalog(metadata)

    assert "real_func" in formatted
    assert "sig_func" not in formatted


def test_parse_ida_lst_proc_ranges_excludes_foreign_function_chunk(tmp_path):
    listing = tmp_path / "sample.lst"
    listing.write_text(
        "\n".join(
            (
                "seg000:0DBA sub_10DBA proc near",
                "seg000:0E30 mov ax, 4C00h",
                "seg000:0E33 int 21h",
                "seg000:0E33 sub_10DBA endp",
                "seg000:0E35 loc_10E35: call sub_16546",
                "seg000:0E85 sub_10E85 proc near",
            )
        )
    )

    ranges = sidecar_metadata._parse_ida_lst_proc_ranges(
        listing,
        load_base_linear=0x10000,
        segment_offsets={"seg000": 0},
    )

    assert ranges[0x10DBA] == (0x10DBA, 0x10E35)


def test_build_project_from_bytes_keeps_real_mode_capstone_defaults():
    project = decompile._build_project_from_bytes(
        b"\xb8\x00\x4c\xcd\x21",
        base_addr=0x1000,
        entry_point=0x0,
    )

    instructions = tuple(project.arch.capstone.disasm(b"\xb8\x00\x4c\xcd\x21", 0x1000))

    assert project.arch.bits == 32
    assert [(instruction.mnemonic, instruction.op_str) for instruction in instructions] == [
        ("mov", "ax, 0x4c00"),
        ("int", "0x21"),
    ]


def test_extract_lst_metadata_supports_uasm_proc_ranges_from_snake_listing():
    listing = REPO_ROOT / "examples" / "snake.lst"
    if not listing.exists():
        pytest.skip("snake.lst fixture is not available")
    metadata = extract_lst_metadata(listing)

    assert metadata.source_format == "uasm_lst"
    assert metadata.data_labels[0x00] == "msg"
    assert metadata.code_labels[0x00] == "main"
    assert metadata.code_labels[0x92] == "delay"
    assert metadata.code_ranges[0x00] == (0x00, 0x92)
    assert metadata.code_ranges[0x92] == (0x92, 0xA3)


def test_extract_lst_metadata_supports_uasm_entry_labels_in_com_listing():
    listing = REPO_ROOT / "angr_platforms" / "x16_samples" / "ICOMDO.LST"
    if not listing.exists():
        pytest.skip("ICOMDO.LST fixture is not available")
    metadata = extract_lst_metadata(listing)

    assert metadata.source_format == "uasm_lst"
    assert metadata.code_labels[0x100] == "start"
    assert metadata.data_labels[0x110] == "msg"


def test_extract_lst_metadata_supports_masm_snow_listing():
    metadata = extract_lst_metadata(REPO_ROOT / "snow.lst")

    assert metadata.source_format == "masm_lst"
    assert metadata.code_labels[0x0000] == "start"
    assert metadata.code_ranges[0x0000] == (0x0000, 0x00B8)
    assert metadata.data_labels[0x00B8] == "const005"


def test_extract_lst_metadata_supports_ida_prefixed_listing(tmp_path):
    listing = """seg000:0000 seg000          segment byte public 'CODE' use16\nseg000:0010 main            proc near\nseg000:0010                 push    bp\nseg000:0012 main            endp\nseg001:0000 seg001          segment word public 'DATA' use16\nseg001:0004 value           db 1\n"""
    tmp = tmp_path / "ida_style.lst"
    tmp.write_text(listing)
    metadata = extract_lst_metadata(tmp)

    assert metadata.source_format == "ida_lst"
    assert metadata.code_labels[0x0010] == "main"
    assert metadata.code_ranges[0x0010] == (0x0010, 0x0012)
    assert metadata.data_labels[0x0004] == "value"


def test_rank_labeled_function_entries_prefers_entry_and_main(monkeypatch):
    project = SimpleNamespace(entry=0x1E432)
    monkeypatch.setattr(decompile, "_is_zero_filled_region", lambda *_args, **_kwargs: False)
    metadata = SimpleNamespace(
        code_ranges={
            0x10000: (0x10000, 0x10010),
            0x10010: (0x10010, 0x10147),
            0x1E432: (0x1E432, 0x1E4E4),
            0x1E4C6: (0x1E4C6, 0x1E4D5),
        }
    )

    ranked = decompile._rank_labeled_function_entries(
        project,
        [
            (0x10000, "padding"),
            (0x10010, "main"),
            (0x1E432, "start"),
            (0x1E4C6, "cintDIV"),
        ],
        metadata,
    )

    assert ranked[:4] == [
        (0x1E432, "start"),
        (0x10010, "main"),
        (0x1E4C6, "cintDIV"),
        (0x10000, "padding"),
    ]


def test_rank_labeled_function_entries_cached_reuses_recovery_cache(monkeypatch, tmp_path):
    monkeypatch.setattr(recovery_cache, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x1E432,
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=binary)),
    )
    metadata = SimpleNamespace(
        source_format="codeview_nb00",
        function_entry_addrs=frozenset(),
        code_ranges={
            0x10000: (0x10000, 0x10010),
            0x10010: (0x10010, 0x10147),
            0x1E432: (0x1E432, 0x1E4E4),
        },
    )
    entries = [(0x10000, "padding"), (0x10010, "main"), (0x1E432, "start")]

    monkeypatch.setattr(decompile, "_is_zero_filled_region", lambda *_args, **_kwargs: False)

    first, first_hit = decompile._rank_labeled_function_entries_cached(project, entries, metadata)
    second, second_hit = decompile._rank_labeled_function_entries_cached(project, entries, metadata)

    assert first_hit is False
    assert second_hit is True
    assert first == second


def test_dosmz_loader_widens_linear_address_space_without_widening_near_words(tmp_path):
    mz = bytearray(0x20)
    mz[0:2] = b"MZ"
    mz[0x08:0x0A] = (2).to_bytes(2, "little")
    mz[0x10:0x12] = (0x200).to_bytes(2, "little")
    sample = tmp_path / "sample.exe"
    sample.write_bytes(bytes(mz) + b"\x90" * 32)

    with sample.open("rb") as fp:
        obj = DOSMZ(str(sample), fp, base_addr=0x10000)

    assert obj.arch.bits == 32
    assert obj.arch.bytes == 2
    assert obj.linked_base == 0x10000


def test_parse_mzre_map_metadata_extracts_code_ranges(tmp_path):
    map_path = tmp_path / "sample.map"
    map_path.write_text(
        "seg000 CODE 0000\nmain: seg000 NEAR 0010-0146 R0010-0146\n",
        encoding="utf-8",
    )

    code_labels, data_labels, code_ranges = decompile._parse_mzre_map_metadata(
        map_path,
        load_base_linear=0x10000,
    )

    assert data_labels == {}
    assert code_labels == {0x10010: "main"}
    assert code_ranges == {0x10010: (0x10010, 0x10147)}


def test_lst_code_region_prefers_exact_or_containing_sidecar_span():
    metadata = LSTMetadata(
        data_labels={},
        code_labels={},
        code_ranges={
            0x10010: (0x10010, 0x10147),
            0x10147: (0x10147, 0x10211),
        }
    )

    assert decompile._lst_code_region(metadata, 0x10010) == (0x10010, 0x10147)
    assert decompile._lst_code_region(metadata, 0x10080) == (0x10010, 0x10147)
    assert decompile._lst_code_region(metadata, 0x10147) == (0x10147, 0x10211)
    assert decompile._lst_code_region(metadata, 0x20000) is None


def test_lst_code_label_uses_containing_sidecar_span_name():
    metadata = SimpleNamespace(
        absolute_addrs=True,
        code_labels={0x10010: "main", 0x10147: "drawCockpit"},
        code_ranges={
            0x10010: (0x10010, 0x10147),
            0x10147: (0x10147, 0x10211),
        },
    )

    assert decompile._lst_code_label(metadata, 0x10010, 0x1000) == "main"
    assert decompile._lst_code_label(metadata, 0x10080, 0x1000) == "main"
    assert decompile._lst_code_label(metadata, 0x10147, 0x1000) == "drawCockpit"
    assert decompile._lst_code_label(metadata, 0x20000, 0x1000) is None


def test_format_sidecar_function_catalog_includes_ranges_and_sizes():
    metadata = LSTMetadata(
        data_labels={},
        code_labels={
            0x10010: "main",
            0x10147: "drawCockpit",
        },
        code_ranges={
            0x10010: (0x10010, 0x10147),
            0x10147: (0x10147, 0x10211),
        },
    )

    rendered = decompile._format_sidecar_function_catalog(metadata)

    assert "0x10010 main size=0x137 range=[0x10010, 0x10147)" in rendered
    assert "0x10147 drawCockpit size=0xca range=[0x10147, 0x10211)" in rendered


def test_parse_idc_metadata_filters_control_flow_labels(tmp_path):
    idc_path = tmp_path / "sample.idc"
    idc_path.write_text(
        'set_name(0X10010, "main");\nset_name(0X1008C, "cond_1008C");\nset_name(0X1009D, "else_1009D");\n',
        encoding="utf-8",
    )

    code_labels, data_labels = decompile._parse_idc_metadata(idc_path)

    assert code_labels == {0x10010: "main"}
    assert data_labels == {
        0x1008C: "cond_1008C",
        0x1009D: "else_1009D",
    }


def test_label_looks_like_function_filters_internal_hex_suffixed_flow_labels():
    assert decompile._label_looks_like_function("main")
    assert decompile._label_looks_like_function("MainGameLoop")
    assert decompile._label_looks_like_function("cintDIV")
    assert not decompile._label_looks_like_function("cond_1008C")
    assert not decompile._label_looks_like_function("innerCond_12D71")
    assert not decompile._label_looks_like_function("nextInner2_12D9E")
    assert not decompile._label_looks_like_function("out_12C7D")


def test_fallback_entry_function_uses_fast_recovery_for_call_heavy_cod_helpers(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    calls: list[tuple[str, object]] = []

    def fake_pick_function_lean(
        project_arg,
        addr,
        *,
        regions=None,
        data_references=None,
        extend_far_calls=None,
    ):
        calls.append(("lean", regions, data_references, extend_far_calls))
        return expected_cfg, expected_func

    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=project.entry)

    monkeypatch.setattr(decompile, "_pick_function_lean", fake_pick_function_lean)
    monkeypatch.setattr(
        decompile,
        "_pick_function",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("slow path should not run")),
    )
    monkeypatch.setattr(
        decompile,
        "_infer_x86_16_linear_region",
        lambda project_arg, start_addr, *, window: (start_addr, start_addr + window),
    )

    cfg, func = decompile._fallback_entry_function(project, timeout=10, window=0x200, prefer_fast_recovery=True)

    assert cfg is expected_cfg
    assert func is expected_func
    assert project._inertia_decompiler_stage == "recovery:fast"
    assert calls == [("lean", [(0x1000, 0x1080)], False, False)]


def test_fallback_entry_function_uses_full_timeout_budget_for_fast_cod_helpers(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    budgets: list[int] = []

    def fake_analysis_timeout(timeout):
        budgets.append(timeout)

        class _Ctx:
            def __enter__(self):
                return None

            def __exit__(self, exc_type, exc, tb):
                return False

        return _Ctx()

    monkeypatch.setattr(decompile, "_analysis_timeout", fake_analysis_timeout)
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (SimpleNamespace(), SimpleNamespace(addr=project.entry)),
    )
    monkeypatch.setattr(
        decompile,
        "_infer_x86_16_linear_region",
        lambda project_arg, start_addr, *, window: (start_addr, start_addr + window),
    )

    decompile._fallback_entry_function(project, timeout=20, window=0x200, prefer_fast_recovery=True)

    assert budgets == [20]


def test_fallback_entry_function_falls_back_after_fast_recovery_error(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    calls: list[tuple[str, object]] = []

    def fake_pick_function_lean(
        project_arg,
        addr,
        *,
        regions=None,
        data_references=None,
        extend_far_calls=None,
    ):
        calls.append(("lean", regions, data_references, extend_far_calls))
        raise ValueError("fast recovery failed")

    def fake_pick_function(project_arg, addr, *, regions=None, data_references=None, force_smart_scan=None):
        calls.append(("pick", regions, data_references, force_smart_scan))
        return expected_cfg, expected_func

    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=project.entry)

    monkeypatch.setattr(decompile, "_pick_function_lean", fake_pick_function_lean)
    monkeypatch.setattr(decompile, "_pick_function", fake_pick_function)
    monkeypatch.setattr(
        decompile,
        "_infer_x86_16_linear_region",
        lambda project_arg, start_addr, *, window: (start_addr, start_addr + window),
    )

    cfg, func = decompile._fallback_entry_function(project, timeout=20, window=0x200, prefer_fast_recovery=True)

    assert cfg is expected_cfg
    assert func is expected_func
    assert calls[0][0] == "lean"
    assert calls[-1][0] == "pick"


def test_fallback_entry_function_propagates_timeout_without_retrying(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    calls: list[tuple[str, object]] = []

    def fake_infer(project_arg, start_addr, *, window):
        calls.append(("infer", window))
        return start_addr, start_addr + window

    def fake_pick_function(project_arg, addr, *, regions=None, data_references=None, force_smart_scan=None):
        calls.append(("pick", regions, data_references, force_smart_scan))
        raise decompile._AnalysisTimeout

    monkeypatch.setattr(decompile, "_infer_x86_16_linear_region", fake_infer)
    monkeypatch.setattr(decompile, "_pick_function", fake_pick_function)

    with pytest.raises(decompile._AnalysisTimeout):
        decompile._fallback_entry_function(project, timeout=10, window=0x200)

    assert calls == [("infer", 0x200), ("pick", [(0x1000, 0x1200)], False, False)]


def test_recover_lst_function_uses_exact_sidecar_region_without_broad_window_retry(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    lst_metadata = LSTMetadata(data_labels={}, code_labels={0x0: "helper"})
    calls: list[tuple[str, object]] = []

    def fake_infer(project_arg, start_addr, *, window):
        calls.append(("infer", window))
        return start_addr, start_addr + window

    def fake_pick_function_lean(
        project_arg,
        addr,
        *,
        regions=None,
        data_references=None,
        extend_far_calls=None,
    ):
        calls.append(("lean", regions, data_references, extend_far_calls))
        region = regions[0]
        if region == (0x0, 0x200):
            return expected_cfg, expected_func
        raise KeyError("unexpected region")

    def fake_pick_function(project_arg, addr, *, regions=None, data_references=None, force_smart_scan=None):
        calls.append(("pick", regions, data_references, force_smart_scan))
        return expected_cfg, expected_func

    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=project.entry, blocks=())

    monkeypatch.setattr(decompile, "_infer_x86_16_linear_region", fake_infer)
    monkeypatch.setattr(decompile, "_pick_function_lean", fake_pick_function_lean)
    monkeypatch.setattr(decompile, "_pick_function", fake_pick_function)

    cfg, func = decompile._recover_lst_function(
        project,
        lst_metadata,
        0x0,
        "helper",
        timeout=10,
        window=0x200,
    )

    assert cfg is expected_cfg
    assert func is expected_func
    assert [call for call in calls if call[0] == "infer"] == []
    assert [call for call in calls if call[0] == "lean"] == [("lean", [(0x0, 0x200)], False, False)]


def test_pick_function_retries_smart_scan_before_complete_scan_after_narrow_cfgfast_miss(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
    )
    captured: list[dict[str, object]] = []

    expected_func = SimpleNamespace(addr=0x1000)
    expected_cfgs = [
        SimpleNamespace(functions={}),
        SimpleNamespace(functions={}),
        SimpleNamespace(functions={}),
        SimpleNamespace(functions={0x1000: expected_func}),
    ]

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        return expected_cfgs[len(captured) - 1]

    project.analyses = SimpleNamespace(CFGFast=fake_cfgfast)
    monkeypatch.setattr(decompile, "extend_cfg_for_far_calls", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "patch_interrupt_service_call_sites", lambda *_args, **_kwargs: False)

    cfg, func = decompile._pick_function(project, 0x1000, regions=[(0x1000, 0x1100)], data_references=True)

    assert cfg is expected_cfgs[-1]
    assert func is expected_func
    assert len(captured) == 4
    assert [entry.get("force_complete_scan", False) for entry in captured] == [False, False, True, True]
    assert [entry["data_references"] for entry in captured] == [True, True, True, True]
    assert [entry["force_smart_scan"] for entry in captured] == [False, True, False, True]


def test_pick_function_continues_after_cfgfast_exception(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
    )
    captured: list[dict[str, object]] = []

    expected_func = SimpleNamespace(addr=0x1000)

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        if len(captured) < 3:
            raise ValueError("CFGFast temporarily failed")
        return SimpleNamespace(functions={0x1000: expected_func})

    project.analyses = SimpleNamespace(CFGFast=fake_cfgfast)
    monkeypatch.setattr(decompile, "extend_cfg_for_far_calls", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "patch_interrupt_service_call_sites", lambda *_args, **_kwargs: False)

    cfg, func = decompile._pick_function(project, 0x1000, regions=[(0x1000, 0x1100)], data_references=True)

    assert cfg.functions[0x1000] is expected_func
    assert func is expected_func
    assert len(captured) == 3


def test_pick_function_disables_smart_scan_for_bounded_x86_16_regions(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
    )
    captured: list[dict[str, object]] = []

    expected_func = SimpleNamespace(addr=0x1000)
    expected_cfg = SimpleNamespace(functions={0x1000: expected_func})

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        return expected_cfg

    project.analyses = SimpleNamespace(CFGFast=fake_cfgfast)
    monkeypatch.setattr(decompile, "extend_cfg_for_far_calls", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "patch_interrupt_service_call_sites", lambda *_args, **_kwargs: False)

    cfg, func = decompile._pick_function(project, 0x1000, regions=[(0x1000, 0x1100)])

    assert cfg is expected_cfg
    assert func is expected_func
    assert captured[0]["force_smart_scan"] is False
    assert captured[0]["data_references"] is True


def test_describe_exception_keeps_type_when_message_is_empty():
    assert decompile._describe_exception(AssertionError()) == "AssertionError"
    assert decompile._describe_exception(ValueError("bad cfg")) == "ValueError: bad cfg"


def test_detect_packed_mz_executable_recognizes_lzexe(tmp_path):
    path = tmp_path / "packed.exe"
    header = bytearray(0x40)
    header[0:2] = b"MZ"
    header[0x1C:0x20] = b"LZ91"
    path.write_bytes(bytes(header))

    assert decompile._detect_packed_mz_executable(path) == "LZEXE 0.91"


def test_recover_partial_cfg_uses_bounded_cfgfast_and_returns_entry_cfg(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
    )
    captured: list[dict[str, object]] = []
    expected_func = SimpleNamespace(addr=0x1000)
    expected_cfg = SimpleNamespace(functions={0x1000: expected_func})

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        return expected_cfg

    project.analyses = SimpleNamespace(CFGFast=fake_cfgfast)
    monkeypatch.setattr(
        decompile,
        "_infer_x86_16_linear_region",
        lambda project_arg, start_addr, *, window: (start_addr, start_addr + window),
    )
    monkeypatch.setattr(decompile, "extend_cfg_for_far_calls", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "patch_interrupt_service_call_sites", lambda *_args, **_kwargs: False)

    cfg = decompile._recover_partial_cfg(project, window=0x200)

    assert cfg is expected_cfg
    assert captured == [
        {
            "start_at_entry": False,
            "function_starts": [0x1000],
            "regions": [(0x1000, 0x1200)],
            "normalize": True,
            "force_complete_scan": False,
            "data_references": False,
            "force_smart_scan": False,
        }
    ]


def test_supplement_functions_from_prologue_scan_adds_confirmed_recoveries(monkeypatch):
    code = bytearray(0x2000)
    for addr in (0x1750, 0x1770):
        offset = addr - 0x1000
        code[offset : offset + 3] = b"\x55\x8b\xec"

    class _Memory:
        def load(self, offset, size):
            return bytes(code[offset : offset + size])

    project = SimpleNamespace(
        entry=0x1500,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(max_addr=len(code) - 1, linked_base=0x1000, memory=_Memory())
        ),
    )

    class _Block:
        def __init__(self):
            self.capstone = SimpleNamespace(
                insns=[
                    SimpleNamespace(mnemonic="push", op_str="bp"),
                    SimpleNamespace(mnemonic="mov", op_str="bp, sp"),
                ]
            )

    project.factory = SimpleNamespace(block=lambda *_args, **_kwargs: _Block())

    expected = {
        0x1770: (SimpleNamespace(), SimpleNamespace(addr=0x1770, name="sub_1770")),
        0x1750: (SimpleNamespace(), SimpleNamespace(addr=0x1750, name="sub_1750")),
    }

    def fake_pick_function_lean(project_arg, addr, **_kwargs):
        return expected[addr]

    monkeypatch.setattr(decompile, "_pick_function_lean", fake_pick_function_lean)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda func, **_kwargs: func())

    supplemental = decompile._supplement_functions_from_prologue_scan(project, existing_addrs={0x1500})

    assert [function.addr for _, function in supplemental] == [0x1750]


def test_dedupe_adjacent_prototype_lines_removes_only_consecutive_duplicates():
    source = "int dos_int21(void);\nint dos_int21(void);\nint other(void);\n\nint dos_int21(void);\n"

    assert decompile._dedupe_adjacent_prototype_lines(source) == (
        "int dos_int21(void);\nint other(void);\n\nint dos_int21(void);\n"
    )


def test_sanitize_mangled_autonames_text_fixes_repeated_autonames():
    source = "long sub_6c5sub_6()\n{\n    dos_int2sub_1();\n}\n"

    assert decompile._sanitize_mangled_autonames_text(source) == ("long sub_6c5()\n{\n    dos_int2();\n}\n")


def test_cleanup_text_preserves_dos_int21_numeric_helper_name():
    source = (
        "int dos_int21(void);\n"
        "int dos_int21_2(void);\n"
        "\n"
        "void sub_114cd(void)\n"
        "{\n"
        "    dos_int21();\n"
        "    dos_int21sub_1();\n"
        "    dos_int21_2();\n"
        "}\n"
    )

    cleaned = decompile._normalize_anonymous_call_targets(source)
    cleaned = decompile._normalize_spurious_duplicate_local_suffixes(cleaned)
    cleaned = decompile._dedupe_adjacent_prototype_lines(cleaned)
    cleaned = decompile._sanitize_mangled_autonames_text(cleaned)

    assert "dos_int2sub_1();" not in cleaned
    assert "dos_int2();" not in cleaned
    assert "dos_int21sub_1();" not in cleaned
    assert cleaned.count("dos_int21();") == 3


def test_recover_blob_entry_function_enables_data_references(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
        analyses=SimpleNamespace(),
    )
    captured: list[dict[str, object]] = []

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        return expected_cfgs[len(captured) - 1]

    expected_func = SimpleNamespace(addr=0x1000)
    expected_cfgs = [
        SimpleNamespace(functions={}),
        SimpleNamespace(functions={0x1000: expected_func}),
    ]
    project.analyses.CFGFast = fake_cfgfast

    cfg, func = decompile._recover_blob_entry_function(project, 0x1000, timeout=10)

    assert cfg is expected_cfgs[-1]
    assert func is expected_func
    assert [entry["data_references"] for entry in captured] == [False, True]


def test_decompile_cli_reports_monoprin_partial_validation_without_source_fallback():
    result = _run_decompile_proc(
        MONOPRIN_COD,
        "_mset_pos",
        analysis_timeout=10,
        subprocess_timeout=30,
    )

    assert result.returncode in (0, 4), result.stderr + result.stdout
    assert "function: 0x1000 _mset_pos" in result.stdout
    assert "/* COD annotations:" not in result.stdout
    if result.returncode == 4:
        assert "partial validation failure" in result.stdout
        assert "direct validation=failed" in result.stdout
    assert "mono_x =" in result.stdout
    assert "mono_y =" in result.stdout
    assert "&v1" not in result.stdout
    assert "return" in result.stdout


def test_decompile_cli_can_extract_and_name_cod_procedure():
    result = _run_decompile_proc(
        NHORZ_COD,
        "_ChangeWeather",
        analysis_timeout=10,
        subprocess_timeout=30,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _ChangeWeather" in result.stdout
    assert "void _ChangeWeather(void)" in result.stdout
    assert "globals =" not in result.stdout
    assert "extern char g_" not in result.stdout
    assert "if (" in result.stdout
    assert "if (!(...))" not in result.stdout
    assert "if (!(!" not in result.stdout
    assert "BadWeather = 0;" in result.stdout
    assert "CLOUDHEIGHT = 8150;" in result.stdout
    assert "CLOUDTHICK = 500;" in result.stdout
    assert "0x7000" not in result.stdout
    assert "_start" not in result.stdout


def test_normalize_function_signature_arg_names_deduplicates_duplicate_parameters():
    text = "unsigned short _strlen(unsigned short s, unsigned short s)\n"

    assert decompile._normalize_function_signature_arg_names(text) == (
        "unsigned short _strlen(unsigned short s, unsigned short s_2)\n"
    )


def test_normalize_function_signature_arg_names_does_not_rewrite_control_conditions():
    text = "        else if (v15 > local_4)\n"

    assert decompile._normalize_function_signature_arg_names(text) == text


def test_prune_void_function_return_values_text_handles_multiline_headers():
    text = "void _dos_free()\n{\n    if (rout.x.cflag != 0) {\n        return err;\n    }\n    return 0;\n}\n"

    assert decompile._prune_void_function_return_values_text(text) == (
        "void _dos_free()\n{\n    if (rout.x.cflag != 0) {\n        return;\n    }\n}\n"
    )


def test_prune_void_function_return_values_text_drops_bare_returns_from_nonvoid_functions():
    text = "unsigned short _dos_getProcessId(void)\n{\n    return;\n}\n"

    assert decompile._prune_void_function_return_values_text(text) == ("unsigned short _dos_getProcessId(void)\n{\n}\n")


def test_prune_void_function_return_values_text_keeps_nonvoid_return_with_forward_decl() -> None:
    text = "void helper(void);\n\nint rel_i16(int a, int b)\n\n{\n    int sp_0;\n    return sp_0;\n}\n"

    assert decompile._prune_void_function_return_values_text(text) == text


def test_dedupe_duplicate_local_declarations_text_keeps_nonvoid_return_value() -> None:
    text = (
        "void helper(void);\n\n"
        "int rel_i16(int a, int b)\n\n"
        "{\n"
        "    int sp_0;\n"
        "    unsigned int b;\n"
        "    if (a < b)\n"
        "    {\n"
        "        return sp_0;\n"
        "    }\n"
        "    return b;\n"
        "}\n"
    )
    deduped = decompile._dedupe_duplicate_local_declarations_text(text)

    assert "return sp_0;" in deduped
    assert "return b;" in deduped


def test_simplify_x86_16_stack_byte_pointers_ignores_cod_stack_aliases():
    metadata = SimpleNamespace(stack_aliases={0xA: "cs", 0xC: "ss"})
    text = "    *((unsigned short *)(ds * 16 + (unsigned int)cs_2)) = ir_3_2;\n"

    simplified = decompile._simplify_x86_16_stack_byte_pointers(text, metadata)

    assert "*cs =" not in simplified
    assert "MK_FP(ds, (unsigned int)cs_2)" in simplified


def test_simplify_x86_16_stack_byte_pointers_keeps_const_pointer_inputs_stable():
    metadata = SimpleNamespace(stack_aliases={0x4: "file"})
    text = (
        "unsigned short demo(const char *file, const char *cmdline, unsigned short *cs, unsigned short *ss)\n"
        "{\n"
        "    *((unsigned short *)(ds * 16 + (unsigned int)file)) = ir_4_2;\n"
        "}\n"
    )

    simplified = decompile._simplify_x86_16_stack_byte_pointers(text, metadata)

    assert "*file =" not in simplified
    assert "MK_FP(ds, (unsigned int)file)" in simplified


def test_simplify_x86_16_stack_byte_pointers_ignores_adjacent_source_backed_stores():
    metadata = SimpleNamespace(
        stack_aliases={},
        global_names=("exeLoadParams",),
        source_lines=(
            "if (err) return err;",
            "*cs = exeLoadParams.cs;",
            "*ss = exeLoadParams.ss;",
            "return 0;",
        ),
    )
    text = (
        "unsigned short demo(const char *file, const char *cmdline, unsigned short *cs, unsigned short *ss)\n"
        "{\n"
        "    err = loadprog(file, 0, DOS_LOAD_NOEXEC, cmdline);\n"
        "    if (err) return err;\n"
        "    ir_3_2 = exeLoadParams.cs;\n"
        "    *cs = ir_3_2;\n"
        "    *ss = exeLoadParams.ss;\n"
        "    return 0;\n"
        "}\n"
    )

    simplified = decompile._simplify_x86_16_stack_byte_pointers(text, metadata)

    assert "    *cs = exeLoadParams.cs;\n" not in simplified
    assert "    *cs = ir_3_2;\n" in simplified
    assert "    *ss = exeLoadParams.ss;\n" in simplified
    assert simplified.index("    *cs = ir_3_2;\n") < simplified.index("    *ss = exeLoadParams.ss;\n")


def test_simplify_x86_16_stack_byte_pointers_keeps_reused_temp_windows_without_source_rewrite():
    metadata = SimpleNamespace(
        stack_aliases={},
        global_names=("exeLoadParams",),
        source_lines=(
            "if (err) return err;",
            "*cs = exeLoadParams.cs;",
            "*ss = exeLoadParams.ss;",
            "return 0;",
        ),
    )
    text = (
        "unsigned short demo(const char *file, const char *cmdline, unsigned short *cs, unsigned short *ss)\n"
        "{\n"
        "    err = loadprog(file, 0, DOS_LOAD_NOEXEC, cmdline);\n"
        "    if (err) return err;\n"
        "    ir_3_2 = exeLoadParams.cs;\n"
        "    *cs = ir_3_2;\n"
        "    ir_3_2 = exeLoadParams.ss;\n"
        "    *ss = ir_3_2;\n"
        "    return 0;\n"
        "}\n"
    )

    simplified = decompile._simplify_x86_16_stack_byte_pointers(text, metadata)

    assert "    *cs = exeLoadParams.cs;\n" not in simplified
    assert "    *cs = ir_3_2;\n" in simplified
    assert "    *ss = exeLoadParams.ss;\n" not in simplified
    assert "    *ss = ir_3_2;\n" in simplified
    assert simplified.index("    *cs = ir_3_2;\n") < simplified.index("    *ss = ir_3_2;\n")


def test_simplify_x86_16_stack_byte_pointers_ignores_source_lvalue_rewrite_candidates():
    metadata = SimpleNamespace(
        stack_aliases={},
        global_names=("exeLoadParams",),
        source_lines=(
            "vvar_4 - 2 = exeLoadParams.cs;",
            "*cs = exeLoadParams.cs;",
        ),
    )
    text = (
        "unsigned short demo(const char *file, unsigned short *cs)\n"
        "{\n"
        "    ir_3_2 = exeLoadParams.cs;\n"
        "    *cs = ir_3_2;\n"
        "    return 0;\n"
        "}\n"
    )

    simplified = decompile._simplify_x86_16_stack_byte_pointers(text, metadata)

    assert "vvar_4 - 2 = exeLoadParams.cs;" not in simplified
    assert "ir_3_2 = exeLoadParams.cs;" in simplified
    assert "    *cs = exeLoadParams.cs;\n" not in simplified
    assert "    *cs = ir_3_2;\n" in simplified


def test_simplify_x86_16_stack_byte_pointers_keeps_source_lvalue_candidates_inert():
    metadata = SimpleNamespace(
        stack_aliases={},
        global_names=("exeLoadParams",),
        source_lines=(
            "vvar_4 - 2 = exeLoadParams.cs;",
            "*cs = exeLoadParams.cs;",
            "field[7] = exeLoadParams.ss;",
        ),
    )
    text = (
        "unsigned short demo(const char *file, unsigned short *cs, unsigned short *field)\n"
        "{\n"
        "    ir_3_2 = exeLoadParams.cs;\n"
        "    *cs = ir_3_2;\n"
        "    ir_3_3 = exeLoadParams.ss;\n"
        "    field[7] = ir_3_3;\n"
        "    return 0;\n"
        "}\n"
    )

    simplified = decompile._simplify_x86_16_stack_byte_pointers(text, metadata)

    assert "vvar_4 - 2 = exeLoadParams.cs;" not in simplified
    assert "    *cs = exeLoadParams.cs;\n" not in simplified
    assert "    *cs = ir_3_2;\n" in simplified
    assert "    field[7] = exeLoadParams.ss;\n" not in simplified
    assert "    field[7] = ir_3_3;\n" in simplified


def test_dedupe_codegen_variable_names_tolerates_none_sort_fields():
    from angr.analyses.decompiler.structured_codegen.c import CVariable
    from angr.sim_variable import SimMemoryVariable

    class _Codegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name: str) -> int:
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _Codegen()
    mem_var = SimMemoryVariable(addr=None, size=2)
    cvar = CVariable(mem_var, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        variables_in_use={mem_var: cvar},
        unified_local_vars={},
        arg_list=(),
        sort_local_vars=lambda: None,
    )

    changed = decompile._dedupe_codegen_variable_names_8616(codegen)

    assert changed is True
    assert isinstance(mem_var.name, str) and mem_var.name


def test_dedupe_codegen_variable_names_normalizes_mixed_ident_sort_fields():
    from angr.analyses.decompiler.structured_codegen.c import CVariable
    from angr.sim_variable import SimRegisterVariable

    class _Codegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name: str) -> int:
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _Codegen()
    reg_a = SimRegisterVariable(0, 2, name="alpha", ident=None)
    reg_b = SimRegisterVariable(2, 2, name="beta", ident="r1")
    cvar_a = CVariable(reg_a, codegen=codegen)
    cvar_b = CVariable(reg_b, codegen=codegen)

    def sort_local_vars():
        sorted(codegen.cfunc.variables_in_use, key=lambda v: v.ident)

    codegen.cfunc = SimpleNamespace(
        variables_in_use={reg_a: cvar_a, reg_b: cvar_b},
        unified_local_vars={},
        arg_list=(),
        sort_local_vars=sort_local_vars,
    )

    changed = decompile._dedupe_codegen_variable_names_8616(codegen)

    assert changed is False
    assert isinstance(reg_a.ident, str)
    assert isinstance(reg_b.ident, str)


def test_format_known_helper_calls_handles_missing_cod_metadata(monkeypatch):
    monkeypatch.setattr(decompile, "collect_dos_int21_calls", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "collect_interrupt_service_calls", lambda *_args, **_kwargs: [])

    project = SimpleNamespace(_sim_procedures={})
    function = SimpleNamespace(addr=0x1000, name="demo")

    assert (
        decompile._format_known_helper_calls(project, function, "int demo(void)\n{\n    return 0;\n}\n", "cdecl", None)
        == "int demo(void)\n{\n    return 0;\n}"
    )


def test_decompile_cli_prunes_void_returns_for_multiline_headers(tmp_path):
    result = _run_decompile_proc(DOSFUNC_COD, "_dos_free")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _dos_free" in result.stdout
    assert "/* COD annotations:" not in result.stdout
    assert "rin.h.ah = 73;" in result.stdout
    assert "sreg.es = segment;" in result.stdout
    assert_dos_free_behavior(result.stdout, tmp_path)
    assert "if (rout.x.cflag)" in result.stdout
    assert result.stdout.count("typedef union REGS {") == 1
    assert result.stdout.count("typedef struct SREGS {") == 1
    assert "extern REGS rin;" in result.stdout
    assert "extern REGS rout;" in result.stdout
    assert "extern SREGS sreg;" in result.stdout
    assert "extern REGS rin[" not in result.stdout
    assert "return err;" in result.stdout
    assert "return;" not in result.stdout


@pytest.mark.parametrize(
    ("proc_name", "header_anchor"),
    (
        ("_dos_getProcessId", "unsigned short _dos_getProcessId(void)"),
        ("_dos_setProcessId", "int _dos_setProcessId(const unsigned short pid)"),
    ),
)
def test_decompile_cli_recovers_dos_process_id_helpers(proc_name: str, header_anchor: str):
    result = _run_decompile_proc(DOSFUNC_COD, proc_name)

    assert result.returncode in (0, 4), result.stderr + result.stdout
    if result.returncode == 4:
        _assert_explicit_partial_or_fallback_failure(result)
        return
    assert header_anchor in result.stdout
    assert "return ir_1;" not in result.stdout
    assert "return;" not in result.stdout


def test_decompile_cli_recovers_dos_load_program_pointer_stores():
    try:
        result = _run_decompile_proc(DOSFUNC_COD, "_dos_loadProgram")
    except subprocess.TimeoutExpired as exc:
        pytest.skip(f"_dos_loadProgram exceeds bounded live subprocess budget: {exc}")

    if result.returncode == 3:
        assert "Direct decompilation timeout is terminal for this function" in result.stdout
        return
    assert result.returncode == 0, result.stderr + result.stdout
    # The binary proves file/cmdline widths but not character-pointer classes.
    # Keep their honest scalar types while requiring the two dereferenced output
    # parameters that are proven by register-indirect stores.
    assert "unsigned short file, unsigned long cmdline, unsigned short *cs, unsigned short *ss" in result.stdout
    assert "if (err)" in result.stdout
    assert "return err;" in result.stdout
    assert "cs[0] = exeLoadParams[10];" in result.stdout
    assert "ss[0] = exeLoadParams[8];" in result.stdout
    assert "return 0;" in result.stdout
    assert "cs[1]" not in result.stdout
    assert "ss[1]" not in result.stdout
    assert "SEG_U" not in result.stdout[result.stdout.index("short _dos_loadProgram") :]
    assert "g_0000" not in result.stdout
    assert "ds * 16 +" not in result.stdout
    assert "*file =" not in result.stdout
    assert "ds * 16 +" not in result.stdout
    assert "if (&err)" not in result.stdout
    assert "ax = exeLoadParams" not in result.stdout


def test_decompile_cli_skips_chkstk_thunk_for_small_cod_logic():
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(MAX_COD), "--proc", "_max", "--timeout", "10"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _max" in result.stdout
    assert "UnresolvableJumpTarget" not in result.stdout
    assert "/* COD annotations:" not in result.stdout
    assert "aNchkstk" not in result.stdout
    assert "short _max(" in result.stdout
    assert "return" in result.stdout


def test_decompile_cli_recovers_small_cod_byte_condition_logic():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "BILLASM.COD", "_MousePOS")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _MousePOS" in result.stdout
    assert "short _MousePOS(unsigned short x, unsigned short y)" in result.stdout
    assert "globals =" not in result.stdout
    assert "if (!MOUSE)" in result.stdout
    assert "&v1" not in result.stdout
    assert "MouseX = x << 1;" in result.stdout
    assert "MouseY = y;" in result.stdout
    assert "interrupt_int33(4, x << 1, y);\n    return 4;" in result.stdout
    assert "vvar_" not in result.stdout


def test_decompile_cli_recovers_configcrts_copy_loop():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "COCKPIT.COD", "_ConfigCrts")

    assert "UnboundLocalError" not in result.stderr + result.stdout
    assert result.returncode == 0, result.stderr + result.stdout
    assert "whole-tail validation clean" in result.stderr
    assert "function: 0x1000 _ConfigCrts" in result.stdout
    assert "unsigned short _ConfigCrts(void)" in result.stdout
    assert "i = 0;" in result.stdout
    assert "tmp_4112 = CrtConfig[i];" in result.stdout
    assert "do" in result.stdout
    assert "return tmp_4112;" in result.stdout


def test_decompile_cli_recovers_rotate_pt_logic():
    try:
        result = _run_decompile_proc(
            REPO_ROOT / "cod" / "f14" / "BILLASM.COD",
            "_rotate_pt",
            scale_for_xdist=False,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.skip(f"_rotate_pt exceeds bounded live subprocess budget: {exc}")

    if result.returncode == 3:
        assert "Direct decompilation timeout is terminal for this function" in result.stdout
        return
    if result.returncode == 4:
        assert "partial validation failure" in result.stdout
        return
    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _rotate_pt" in result.stdout
    assert "void _rotate_pt(unsigned short s, unsigned short d, unsigned short ang)" in result.stdout
    assert "/* COD annotations:" not in result.stdout
    assert "y_4 = *((char *)MK_FP(ds, (unsigned int)s))" in result.stdout
    assert "CosB(OurRoll);" in result.stdout


def test_decompile_cli_recovers_sethook_branch_logic():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "CARR.COD", "_SetHook")

    assert result.returncode in (0, 4), result.stderr + result.stdout
    assert "function: 0x1000 _SetHook" in result.stdout
    if result.returncode == 4:
        assert "direct validation=failed" in result.stdout
        assert "partial validation failure" in result.stdout
        return
    assert "unsigned short _SetHook(unsigned short Hook)" in result.stdout
    assert "/* COD annotations:" not in result.stdout
    assert "HookDown" in result.stdout
    assert "HookDown !=" in result.stdout or "HookDown ==" in result.stdout
    assert "g_7000 =" in result.stdout or "HookDown =" in result.stdout
    assert "return 1;" in result.stdout
    assert "return 0;" in result.stdout
    assert "Message(ax_2, 5);" in result.stdout
    assert "Message(28674, 28674)" not in result.stdout
    assert "Message(28676, 28676)" not in result.stdout
    assert "if (!(...))" not in result.stdout
    assert "v2 = &v3;" not in result.stdout
    assert "return" in result.stdout
    assert "s_" not in result.stdout


def test_decompile_cli_recovers_setgear_guard_logic():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "CARR.COD", "_SetGear")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _SetGear" in result.stdout
    assert "void _SetGear(unsigned short G)" in result.stdout or "void _SetGear(int G)" in result.stdout
    assert "/* COD annotations:" not in result.stdout
    assert "if (!ejected)" in result.stdout
    assert result.stdout.count("if (!G)") == 1
    assert "else if (G == 1)" in result.stdout
    assert "else if (Knots <= 350)" in result.stdout
    assert "Status = Status | 1;" in result.stdout and "Status = Status & -2;" in result.stdout
    assert "28674" not in result.stdout
    assert "28682" not in result.stdout
    assert "\n        sub_102f();" not in result.stdout
    assert "asm fallback" not in result.stdout
    assert "Message(ax, 2);" in result.stdout
    assert "whole-tail validation clean" in result.stderr


def test_decompile_cli_recovers_setdlc_state_store():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "CARR.COD", "_SetDLC")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _SetDLC" in result.stdout
    assert "short _SetDLC(" in result.stdout
    assert "unsigned short DLC" in result.stdout
    assert "/* COD annotations:" not in result.stdout
    assert "DirectLiftControl = DLC;" in result.stdout
    assert "DLC >> 8" not in result.stdout
    assert "return DLC;" in result.stdout


def test_decompile_cli_keeps_query_interrupts_wrapper_calls_classified_in_matrix_corpus():
    if not IMOD_COD.exists():
        pytest.skip("IMOD.COD fixture is not available")
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(IMOD_COD),
            "--proc",
            "query_interrupts",
            "--proc-kind",
            "FAR",
            "--timeout",
            "60",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 query_interrupts" in result.stdout
    assert "calls = _int86, _int86x" in result.stdout
    assert "int86(0x21, &inregs, &outregs);" in result.stdout
    assert "info = outregs;" in result.stdout
    assert "return outregs;" in result.stdout


def test_decompile_cli_recovers_tidshowrange_layout_logic():
    result = _run_decompile_proc(
        REPO_ROOT / "cod" / "f14" / "COCKPIT.COD",
        "_TIDShowRange",
        analysis_timeout=240,
        subprocess_timeout=300,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _TIDShowRange" in result.stdout
    assert "_TIDShowRange(void)" in result.stdout
    body = result.stdout.split("_TIDShowRange(void)", maxsplit=1)[1]
    for required_call, expected_count in {
        "RectFill(": 1,
        "itoa(": 1,
        "pstrlen(": 1,
        "RpPrint(": 1,
        "RectCopy(": 2,
        "MapInEMSSprite(": 1,
        "ScaleRotate(": 2,
    }.items():
        assert body.count(required_call) == expected_count
    assert "mseg = MapInEMSSprite(2, 0);" in body
    assert "if (mseg)" in body
    assert "Timed out while recovering" not in result.stdout
    assert "== asm fallback ==" not in result.stdout
    assert "validation=passed" in result.stderr
    assert "whole-tail validation clean" in result.stderr


def test_decompile_cli_recovers_drawradaralt_branch_logic():
    try:
        result = _run_decompile_proc(
            REPO_ROOT / "cod" / "f14" / "COCKPIT.COD",
            "_DrawRadarAlt",
            scale_for_xdist=False,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.skip(f"_DrawRadarAlt exceeds bounded live subprocess budget: {exc}")

    if result.returncode == 3:
        assert "Timed out while recovering a function after 10s." in result.stdout
        return

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _DrawRadarAlt" in result.stdout
    assert "void _DrawRadarAlt(void)" in result.stdout
    assert "[bp-0xc] = newalt" in result.stdout
    assert "[bp-0xa] = y2" in result.stdout
    assert "[bp-0x8] = soffset" in result.stdout
    assert "[bp-0x2] = b" in result.stdout
    assert "calls = _MapInEMSSprite, _TransRectCopy, _MDiv, _Rotate2D, _scaley, _DrawLine, _RectCopy" in result.stdout
    assert "if (!(View))" in result.stdout
    assert "unsigned short y2;  // [bp-0xa] y2" in result.stdout
    assert "unsigned short b;  // [bp-0x2] b" in result.stdout
    assert "y2 = 0;" in result.stdout
    assert "y2 = 112;" in result.stdout
    assert "s_12 = 0;" in result.stdout
    assert "s_14 = 2;" in result.stdout
    assert "MapInEMSSprite(MISCSPRTSEG,0);" in result.stdout


@pytest.mark.parametrize(
    ("path", "proc_kind", "shape_tokens"),
    [
        (ISOD_COD, "NEAR", ("& 0xff00 |", "return ")),
        (ISOT_COD, "NEAR", ("& 0xff00 |", "return ")),
        (ISOX_COD, "NEAR", ("& 0xff00 |", "return ")),
        (IMOD_COD, "FAR", ("& 0xff00 |", "return ")),
        (IMOT_COD, "FAR", ("sub_1004();", "v3 >> 8;")),
        (IMOX_COD, "FAR", ("sub_1004();", "v3 >> 8;")),
        (IHOD_COD, "FAR", ("& 0xff00 |", "return ")),
        (IHOT_COD, "FAR", ("sub_1004();", "v3 >> 8;")),
        (ILOD_COD, "FAR", ("& 0xff00 |", "return ")),
        (ILOT_COD, "FAR", ("sub_1004();", "v3 >> 8;")),
    ],
)
def test_decompile_cli_main_matrix(path: Path, proc_kind: str, shape_tokens: tuple[str, str]):
    if not path.exists():
        pytest.skip(f"{path.name} fixture is not available")
    result = _run_decompile_proc(path, "_main", proc_kind=proc_kind, analysis_timeout=20, subprocess_timeout=60)

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _main" in result.stdout
    assert "int _main(void)" in result.stdout
    for token in shape_tokens:
        assert token in result.stdout
    assert "Decompiler timeout" not in result.stdout


@pytest.mark.parametrize(
    ("path", "proc_kind"),
    [
        (ISOD_COD, "NEAR"),
        (ISOT_COD, "NEAR"),
        (ISOX_COD, "NEAR"),
        (IMOD_COD, "FAR"),
        (IMOT_COD, "FAR"),
        (IMOX_COD, "FAR"),
        (IHOD_COD, "FAR"),
        (IHOT_COD, "FAR"),
        (ILOD_COD, "FAR"),
        (ILOT_COD, "FAR"),
    ],
)
def test_decompile_cli_show_summary_matrix(path: Path, proc_kind: str):
    if not path.exists():
        pytest.skip(f"{path.name} fixture is not available")
    result = _run_decompile_proc(path, "show_summary", proc_kind=proc_kind, analysis_timeout=20, subprocess_timeout=60)

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 show_summary" in result.stdout
    assert "int show_summary(void)" in result.stdout
    assert "info >> 8;" in result.stdout
    assert "*((" in result.stdout
    assert "Decompiler timeout" not in result.stdout


@pytest.mark.parametrize(
    ("path", "proc", "proc_kind", "analysis_timeout", "subprocess_timeout", "expected_tokens", "forbidden_tokens"),
    [
        (
            MAX_COD,
            "_max",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _max", "if (x > y)", "return x;", "return y;"),
            ("UnresolvableJumpTarget",),
        ),
        (
            NHORZ_COD,
            "_ChangeWeather",
            "NEAR",
            10,
            30,
            (
                "function: 0x1000 _ChangeWeather",
                "if (BadWeather)",
                "CLOUDHEIGHT = 8150;",
                "CLOUDTHICK = 500;",
                "CLOUDTHICK = 1000;",
            ),
            ("if (!(...))", "if (!(!"),
        ),
        (
            MONOPRIN_COD,
            "_mset_pos",
            "NEAR",
            10,
            30,
            (
                "function: 0x1000 _mset_pos",
                "% 80",
                "% 25",
                "int _mset_pos(int x, int y)",
            ),
            ("&v1",),
        ),
        (
            REPO_ROOT / "cod" / "f14" / "BILLASM.COD",
            "_MousePOS",
            "NEAR",
            10,
            30,
            (
                "function: 0x1000 _MousePOS",
                "if (!MOUSE)",
                "MouseX = x << 1;",
                "MouseY = y;",
                "unsigned short interrupt_int33(unsigned short ax, unsigned short cx, unsigned short dx);",
                "interrupt_int33(4, x << 1, y);\n    return 4;",
            ),
            ("if (...)", "28675", "28677", "vvar_"),
        ),
        (
            REPO_ROOT / "cod" / "f14" / "PLANES3.COD",
            "_Ready5",
            "NEAR",
            10,
            30,
            (
                "function: 0x1000 _Ready5",
                "short _Ready5(void)",
                "planecnt",
                "droll",
                "pdest",
                "bx = planecnt * 46;",
                "SEG_U16(inertia_ds, 18 + bx) = 0;",
                "return 0;",
            ),
            (),
        ),
        (
            REPO_ROOT / "cod" / "f14" / "COCKPIT.COD",
            "_LookDown",
            "NEAR",
            10,
            30,
            (
                "function: 0x1000 _LookDown",
                "if (!BackSeat)",
                "SEG_U8(inertia_ds, 8 + Rp3D) = 50;",
                "SEG_U8(inertia_ds, 9 + Rp3D) = 0;",
                "SEG_U8(inertia_ds, 4 + RpCRT1) = 27;",
                "SEG_U8(inertia_ds, 4 + RpCRT2) = 25;",
                "SEG_U8(inertia_ds, 4 + RpCRT4) = 39;",
                "SEG_U16(SEG_U16(inertia_ds, 28682), 2) = 27;",
                "SEG_U16(SEG_U16(inertia_ds, 28684), 2) = 25;",
                "SEG_U16(SEG_U16(inertia_ds, 28686), 2) = 39;",
            ),
            ("SEG_U16(inertia_es, 2)",),
        ),
        (
            REPO_ROOT / "cod" / "f14" / "COCKPIT.COD",
            "_LookUp",
            "NEAR",
            10,
            30,
            (
                "function: 0x1000 _LookUp",
                "if (!BackSeat)",
                "SEG_U8(inertia_ds, 8 + Rp3D) = 150;",
                "SEG_U8(inertia_ds, 9 + Rp3D) = 0;",
                "SEG_U8(inertia_ds, 4 + RpCRT1) = 138;",
                "SEG_U8(inertia_ds, 4 + RpCRT2) = 136;",
                "SEG_U8(inertia_ds, 4 + RpCRT4) = 150;",
                "SEG_U16(SEG_U16(inertia_ds, 28682), 2) = 138;",
                "SEG_U16(SEG_U16(inertia_ds, 28684), 2) = 136;",
                "SEG_U16(SEG_U16(inertia_ds, 28686), 2) = 150;",
                "SEG_U8(inertia_ds, 8 + Rp3D) = 139;",
            ),
            ("SEG_U16(inertia_es, 2)",),
        ),
        (
            REPO_ROOT / "cod" / "f14" / "CARR.COD",
            "_InBox",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _InBox", "return 1;", "xl <=", "xh >=", "zl <=", "zh >="),
            ("if (...)", "!(zh >=", "xl >", "xh <", "zl >"),
        ),
        (
            REPO_ROOT / "cod" / "f14" / "CARR.COD",
            "_InBoxLng",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _InBoxLng", "if (x < xl || x > xh || z < zl || z > zh)", "return 0;", "return 1;"),
            ("if (...)", "!(v4", "& &"),
        ),
        (
            REPO_ROOT / "cod" / "f14" / "CARR.COD",
            "_SetDLC",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _SetDLC", "DirectLiftControl = DLC;", "return DLC;"),
            ("DLC >> 8",),
        ),
        (
            ISOD_COD,
            "fold_values",
            "NEAR",
            20,
            60,
            ("function: 0x1000 fold_values", "1000", "return"),
            (),
        ),
        (
            IMOD_COD,
            "fold_values",
            "FAR",
            20,
            60,
            ("function: 0x1000 fold_values", "1000", "return"),
            (),
        ),
        (
            ISOT_COD,
            "fold_values",
            "NEAR",
            20,
            60,
            ("function: 0x1000 fold_values", "1000", "return"),
            (),
        ),
        (
            ISOX_COD,
            "fold_values",
            "NEAR",
            20,
            60,
            ("function: 0x1000 fold_values", "1000", "return"),
            (),
        ),
        (
            IHOD_COD,
            "fold_values",
            "FAR",
            20,
            60,
            ("function: 0x1000 fold_values", "1000", "return"),
            (),
        ),
        (
            IHOT_COD,
            "fold_values",
            "FAR",
            20,
            60,
            ("function: 0x1000 fold_values", "1000", "return"),
            (),
        ),
        (
            ILOD_COD,
            "fold_values",
            "FAR",
            20,
            60,
            ("function: 0x1000 fold_values", "1000", "return"),
            (),
        ),
        (
            ILOT_COD,
            "fold_values",
            "FAR",
            20,
            60,
            ("function: 0x1000 fold_values", "1000", "return"),
            (),
        ),
        (
            IMOT_COD,
            "fold_values",
            "FAR",
            20,
            60,
            ("function: 0x1000 fold_values", "1000", "return"),
            (),
        ),
        (
            IMOX_COD,
            "fold_values",
            "FAR",
            20,
            60,
            ("function: 0x1000 fold_values", "1000", "return"),
            (),
        ),
    ],
)
def test_decompile_cli_small_cod_logic_batch(
    path, proc, proc_kind, analysis_timeout, subprocess_timeout, expected_tokens, forbidden_tokens
):
    if not path.exists():
        pytest.skip(f"{path.name} fixture is not available")
    try:
        result = _run_decompile_proc(
            path,
            proc,
            proc_kind=proc_kind,
            analysis_timeout=analysis_timeout,
            subprocess_timeout=subprocess_timeout,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.skip(f"{proc} exceeds bounded live subprocess budget: {exc}")

    if result.returncode == 3:
        assert "timeout" in result.stdout.lower()
        return
    if result.returncode == 4:
        if proc == "_InBoxLng":
            pytest.fail("_InBoxLng must pass whole-tail validation after wide predicate recovery")
        _assert_explicit_partial_or_fallback_failure(result)
        return

    assert result.returncode == 0, result.stderr + result.stdout
    for token in expected_tokens:
        assert token in result.stdout, result.stdout
    for token in forbidden_tokens:
        assert token not in result.stdout, result.stdout


@requires_icomdo_com
def test_decompile_cli_names_known_dos_interrupt_helpers_in_com_output():
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(ICOMDO_COM), "--timeout", "10", "--window", "0x80", "--max-functions", "2"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "int get_dos_version(void);" in result.stdout
    assert "void print_dos_string(const char *s);" in result.stdout
    assert "void exit(int status);" in result.stdout
    assert "void _start(void)" in result.stdout
    assert "get_dos_version();" in result.stdout
    assert 'print_dos_string("DOS sample");' in result.stdout
    assert "exit(0);" in result.stdout
    assert "1044513();" not in result.stdout
    assert "dos_int21();" not in result.stdout


@requires_icomdo_com
def test_decompile_cli_supports_dos_api_style_for_known_helpers():
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(ICOMDO_COM),
            "--timeout",
            "10",
            "--window",
            "0x80",
            "--max-functions",
            "2",
            "--api-style",
            "dos",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "unsigned short _dos_get_version(void);" in result.stdout
    assert "void _dos_print_dollar_string(const char far *s);" in result.stdout
    assert "void _dos_exit(unsigned char status);" in result.stdout
    assert "_dos_get_version();" in result.stdout
    assert '_dos_print_dollar_string("DOS sample");' in result.stdout
    assert "_dos_exit(0);" in result.stdout


@requires_icomdo_com
def test_decompile_cli_supports_raw_api_style_for_known_helpers():
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(ICOMDO_COM),
            "--timeout",
            "10",
            "--window",
            "0x80",
            "--max-functions",
            "2",
            "--api-style",
            "raw",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "dos_int21();" in result.stdout


@requires_icomdo_com
def test_decompile_cli_supports_pseudo_api_style_for_known_helpers():
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(ICOMDO_COM),
            "--timeout",
            "10",
            "--window",
            "0x80",
            "--max-functions",
            "2",
            "--api-style",
            "pseudo",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "int dos_get_version(void);" in result.stdout
    assert "void dos_print_dollar_string(const char *s);" in result.stdout
    assert "void dos_exit(int status);" in result.stdout
    assert "dos_get_version();" in result.stdout
    assert 'dos_print_dollar_string("DOS sample");' in result.stdout
    assert "dos_exit(0);" in result.stdout


@requires_icomdo_com
def test_decompile_cli_supports_msc_api_style_alias_for_known_helpers():
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(ICOMDO_COM),
            "--timeout",
            "10",
            "--window",
            "0x80",
            "--max-functions",
            "2",
            "--api-style",
            "msc",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "_dos_get_version();" in result.stdout
    assert '_dos_print_dollar_string("DOS sample");' in result.stdout
    assert "_dos_exit(0);" in result.stdout


@requires_icomdo_com
@requires_trace_x86_script
def test_trace_x86_16_paths_cli_traces_small_com_stub():
    result = subprocess.run(
        [sys.executable, str(TRACE_PATH), str(ICOMDO_COM), "--mode", "exec", "--max-steps", "6"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "mode: exec" in result.stdout
    assert "== step 0 @ 0x1000 ==" in result.stdout
    assert "mov ah, 0x30" in result.stdout
    assert "== step 2 @ 0xf021 ==" in result.stdout
    assert "helper=DOSInt21 ; get_dos_version()" in result.stdout
    assert "== step 3 @ 0x1004 ==" in result.stdout
    assert "mov ah, 9" in result.stdout
    assert "== step 5 @ 0x1009 ==" in result.stdout
    assert "int 0x21" in result.stdout


@requires_icomdo_com
@requires_trace_x86_script
def test_trace_x86_16_paths_cli_exec_supports_helper_annotations():
    result = subprocess.run(
        [sys.executable, str(TRACE_PATH), str(ICOMDO_COM), "--mode", "exec", "--max-steps", "8"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert 'helper=DOSInt21 ; print_dos_string("DOS sample")' in result.stdout


@requires_icomdo_com
@requires_trace_x86_script
def test_trace_x86_16_paths_cli_recovers_cfg_for_small_com_stub():
    result = subprocess.run(
        [sys.executable, str(TRACE_PATH), str(ICOMDO_COM), "--mode", "cfg", "--max-blocks", "4"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "mode: cfg" in result.stdout
    assert "function: 0x1000 _start" in result.stdout
    assert "== block 0x1000 ==" in result.stdout
    assert "0x1000: mov ah, 0x30" in result.stdout
    assert "0x1002: int 0x21 ; get_dos_version()" in result.stdout
    assert '0x1009: int 0x21 ; print_dos_string("DOS sample")' in result.stdout


@requires_icomdo_com
@requires_trace_x86_script
def test_trace_x86_16_paths_cli_supports_msc_helper_annotations():
    result = subprocess.run(
        [
            sys.executable,
            str(TRACE_PATH),
            str(ICOMDO_COM),
            "--mode",
            "cfg",
            "--max-blocks",
            "4",
            "--api-style",
            "msc",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "0x1002: int 0x21 ; _dos_get_version()" in result.stdout
    assert '0x1009: int 0x21 ; _dos_print_dollar_string("DOS sample")' in result.stdout


@requires_icomdo_com
@requires_trace_x86_script
def test_trace_x86_16_paths_cli_supports_pseudo_helper_annotations():
    result = subprocess.run(
        [
            sys.executable,
            str(TRACE_PATH),
            str(ICOMDO_COM),
            "--mode",
            "cfg",
            "--max-blocks",
            "4",
            "--api-style",
            "pseudo",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "0x1002: int 0x21 ; dos_get_version()" in result.stdout
    assert '0x1009: int 0x21 ; dos_print_dollar_string("DOS sample")' in result.stdout
