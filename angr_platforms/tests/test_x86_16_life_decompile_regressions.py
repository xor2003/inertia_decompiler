from __future__ import annotations

from pathlib import Path

import inertia_decompiler.cli as decompile
import inertia_decompiler.sidecar_metadata as sidecar_metadata
from inertia_decompiler.source_sidecar import render_local_source_sidecar_function

REPO_ROOT = Path(__file__).resolve().parents[2]
LIFE_EXE = REPO_ROOT / "examples" / "LIFE.EXE"


def test_life_rand_never_reports_ir_shaped_output_as_success() -> None:
    project = decompile._build_project(LIFE_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = sidecar_metadata._load_lst_metadata(LIFE_EXE, project)
    cfg = project.analyses.CFGFast(
        normalize=True,
        data_references=True,
        force_segment=True,
        resolve_indirect_jumps=False,
        show_progressbar=False,
        regions=[(0x11732, 0x1175E)],
    )
    function = cfg.kb.functions.floor_func(0x11732)

    status, payload = decompile._decompile_function(
        project,
        cfg,
        function,
        timeout=8,
        api_style="c",
        binary_path=LIFE_EXE,
        lst_metadata=metadata,
    )

    if status == "ok":
        assert "STORE(addr=" not in payload
        assert "Goto None" not in payload
    else:
        assert "unresolved IR-shaped C" in payload


def test_life_main_does_not_use_verbatim_source_sidecar() -> None:
    project = decompile._build_project(LIFE_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = sidecar_metadata._load_lst_metadata(LIFE_EXE, project)
    cfg = project.analyses.CFGFast(
        normalize=True,
        data_references=True,
        force_segment=True,
        resolve_indirect_jumps=False,
        show_progressbar=False,
        regions=[(0x10010, 0x10040)],
    )
    function = cfg.kb.functions.floor_func(0x10010)

    status, payload = decompile._decompile_function(
        project,
        cfg,
        function,
        timeout=8,
        api_style="c",
        binary_path=LIFE_EXE,
        lst_metadata=metadata,
    )

    source_text = render_local_source_sidecar_function(LIFE_EXE, "main")

    assert status in {"ok", "empty", "error", "timeout"}
    assert source_text is not None
    assert payload != source_text


def test_life_exit_accepts_clean_helper_model_without_ir_shaped_codegen() -> None:
    project = decompile._build_project(LIFE_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = sidecar_metadata._load_lst_metadata(LIFE_EXE, project)
    cfg = project.analyses.CFGFast(
        normalize=True,
        data_references=True,
        force_segment=True,
        resolve_indirect_jumps=False,
        show_progressbar=False,
        regions=[(0x1157C, 0x115A0)],
    )
    function = cfg.kb.functions.floor_func(0x1157C)

    status, payload = decompile._decompile_function(
        project,
        cfg,
        function,
        timeout=8,
        api_style="c",
        binary_path=LIFE_EXE,
        lst_metadata=metadata,
    )

    assert status == "ok"
    assert "void exit(int status)" in payload
    assert "ctermsub(" in payload
    assert "STORE(addr=" not in payload
    assert "Goto None" not in payload


def test_life_exit_nonoptimized_fallback_accepts_clean_helper_model_output() -> None:
    project = decompile._build_project(LIFE_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = sidecar_metadata._load_lst_metadata(LIFE_EXE, project)

    outcome = decompile._try_decompile_non_optimized_slice(
        project,
        0x1157C,
        "exit",
        timeout=8,
        api_style="c",
        binary_path=LIFE_EXE,
        lst_metadata=metadata,
    )

    assert outcome.status == "ok"
    assert outcome.rendered == "void exit(int status)\n{\n    (void)status;\n}\n"
    assert outcome.payload == outcome.rendered
    assert "STORE(addr=" not in outcome.payload
    assert "Goto None" not in outcome.payload


def test_life_pause_screen_does_not_use_verbatim_source_sidecar() -> None:
    project = decompile._build_project(LIFE_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = sidecar_metadata._load_lst_metadata(LIFE_EXE, project)
    cfg = project.analyses.CFGFast(
        normalize=True,
        data_references=True,
        force_segment=True,
        resolve_indirect_jumps=False,
        show_progressbar=False,
        regions=[(0x107E3, 0x1092B)],
    )
    function = cfg.kb.functions.floor_func(0x107E3)

    status, payload = decompile._decompile_function(
        project,
        cfg,
        function,
        timeout=8,
        api_style="c",
        binary_path=LIFE_EXE,
        lst_metadata=metadata,
    )

    source_text = render_local_source_sidecar_function(LIFE_EXE, "pause_screen")

    assert status == "ok", payload
    assert source_text is not None
    assert payload != source_text


def test_life_timer_does_not_use_verbatim_source_sidecar() -> None:
    """Include the complete machine loop when checking source-sidecar independence."""
    project = decompile._build_project(LIFE_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = sidecar_metadata._load_lst_metadata(LIFE_EXE, project)
    cfg = project.analyses.CFGFast(
        normalize=True,
        data_references=True,
        force_segment=True,
        resolve_indirect_jumps=False,
        show_progressbar=False,
        # The first loop branch is at 104AE; the function returns at 104E6.
        regions=[(0x10467, 0x104E7)],
    )
    function = cfg.kb.functions.floor_func(0x10467)
    assert {0x104C3, 0x104CE, 0x104E1} <= function.block_addrs_set

    _status, payload = decompile._decompile_function(
        project,
        cfg,
        function,
        timeout=8,
        api_style="c",
        binary_path=LIFE_EXE,
        lst_metadata=metadata,
    )

    source_text = render_local_source_sidecar_function(LIFE_EXE, "timer")

    assert source_text is not None
    assert payload != source_text


def test_life_rand_dist_does_not_use_verbatim_source_sidecar() -> None:
    project = decompile._build_project(LIFE_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = sidecar_metadata._load_lst_metadata(LIFE_EXE, project)
    cfg = project.analyses.CFGFast(
        normalize=True,
        data_references=True,
        force_segment=True,
        resolve_indirect_jumps=False,
        show_progressbar=False,
        regions=[(0x103AB, 0x103F3)],
    )
    function = cfg.kb.functions.floor_func(0x103AB)

    _status, payload = decompile._decompile_function(
        project,
        cfg,
        function,
        timeout=8,
        api_style="c",
        binary_path=LIFE_EXE,
        lst_metadata=metadata,
    )

    source_text = render_local_source_sidecar_function(LIFE_EXE, "rand_dist")

    assert source_text is not None
    assert payload != source_text


def test_life_clear_mat_keeps_string_diagnostics_without_body_replacement() -> None:
    """Classify STOSB without discarding argument, segment and frame setup."""
    from angr_platforms.X86_16.string_instruction_artifact import (
        StringInstructionCoverage8616,
        build_x86_16_string_instruction_artifact_from_linear_range,
    )
    from angr_platforms.X86_16.string_instruction_lowering import (
        build_x86_16_string_intrinsic_artifact,
        render_x86_16_string_intrinsic_c,
    )

    project = decompile._build_project(LIFE_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    artifact = build_x86_16_string_instruction_artifact_from_linear_range(project, start=0x10AB1, end=0x10AC5)
    assert artifact.coverage is StringInstructionCoverage8616.PARTIAL_FUNCTION
    assert len(artifact.records) == 1
    assert artifact.records[0].family == "stos"
    assert artifact.records[0].width == 1
    lowered = build_x86_16_string_intrinsic_artifact(artifact)
    payload = render_x86_16_string_intrinsic_c("clear_mat", lowered)

    assert payload is not None
    assert "void __x86_16_stos(unsigned short width);" in payload
    assert "__x86_16_stos(1);" in payload
    assert "__x86_16_string_state" not in payload
    assert decompile._try_emit_string_intrinsic_c(
        project, start=0x10AB1, end=0x10AC5, name="clear_mat",
    ) is None
