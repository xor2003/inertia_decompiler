from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from x86_16_initmenu_execution import assert_initmenu_pause_guard_behavior
from x86_16_reinitbars_execution import assert_reinitbars_loop_behavior
from x86_16_telemetry_support import diagnostic_payloads, telemetry_integer
from x86_16_timeout_support import scaled_decompile_timeout as _scaled_timeout

from inertia_decompiler.acceptance_scorecard import build_acceptance_scorecard
from inertia_decompiler.recompile_check import check_c_recompiles_8616
from inertia_decompiler.source_sidecar import render_local_source_sidecar_function
from scripts.check_sortd_sidecar_free import mz_executable_image

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "decompile.py"
SORTDEMO_EXE = REPO_ROOT / "SORTDEMO.EXE"

def _run_decompile_addr(
    path: Path,
    addr: int,
    *,
    analysis_timeout: int = 6,
    subprocess_timeout: int = 90,
    extra_args: tuple[str, ...] = (),
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.setdefault("INERTIA_ENABLE_TAIL_VALIDATION", "1")
    if extra_env is not None:
        env.update(extra_env)
    scaled_analysis_timeout = _scaled_timeout(analysis_timeout)
    scaled_subprocess_timeout = _scaled_timeout(subprocess_timeout)
    return subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(path),
            "--addr",
            hex(addr),
            "--timeout",
            str(scaled_analysis_timeout),
            *extra_args,
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=scaled_subprocess_timeout,
        check=False,
    )


def _run_decompile_proc(
    path: Path,
    proc_name: str,
    *,
    proc_kind: str = "NEAR",
    analysis_timeout: int = 60,
    subprocess_timeout: int = 180,
    extra_args: tuple[str, ...] = (),
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.setdefault("INERTIA_ENABLE_TAIL_VALIDATION", "1")
    if extra_env is not None:
        env.update(extra_env)
    scaled_analysis_timeout = _scaled_timeout(analysis_timeout)
    scaled_subprocess_timeout = _scaled_timeout(subprocess_timeout)
    return subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "--alternate-source-c",
            "--proc",
            proc_name,
            "--proc-kind",
            proc_kind,
            "--timeout",
            str(scaled_analysis_timeout),
            str(path),
            *extra_args,
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=scaled_subprocess_timeout,
        check=False,
    )


def _combined_output(result: subprocess.CompletedProcess[str]) -> str:
    return f"{result.stderr}{result.stdout}"


def _assert_clean_decompilation_output(combined_output: str) -> None:
    forbidden_markers = (
        "Traceback (most recent call last):",
        " TIMEOUT stage=",
        "/* -- timeout -- */",
        "/* -- asm fallback -- */",
        "attempt=timed_out",
        "Decompilation empty",
    )
    for marker in forbidden_markers:
        assert marker not in combined_output, combined_output


def test_sortd_sidecar_free_swapbars_recovers_binary_stack_arguments(tmp_path):
    sortd_exe = tmp_path / "SORTD.EXE"
    sortd_exe.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))

    result = _run_decompile_addr(
        sortd_exe,
        0x10768,
        analysis_timeout=60,
        subprocess_timeout=120,
        extra_args=(
            "--no-alternate-source-c",
            "--window",
            "0x50",
            "--c-target",
            "portable-flat",
        ),
    )
    output = _combined_output(result)

    assert result.returncode == 0, output
    assert "no helper metadata (.lst/.map/.cod/debug info) found" in output
    assert "validation=passed" in output
    # SORTDEMO.C declares SwapBars as void; the binary output must preserve
    # that source-backed contract while recovering both stack arguments.
    assert re.search(r"void sub_10768\(unsigned short \w+, unsigned short \w+\)", result.stdout)
    assert "local_4" not in result.stdout
    assert "local_6" not in result.stdout
    assert result.stdout.count("sub_106c8(") == 3


def test_sortd_sidecar_free_initbars_preserves_binary_stack_array(tmp_path: Path) -> None:
    sortd_exe = tmp_path / "SORTD.EXE"
    sortd_exe.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))

    result = _run_decompile_addr(
        sortd_exe,
        0x10560,
        analysis_timeout=180,
        subprocess_timeout=420,
        extra_args=(
            "--no-alternate-source-c",
            "--c-target",
            "portable-flat",
        ),
        extra_env={"INERTIA_DISABLE_TIMING": "1"},
    )
    output = _combined_output(result)

    assert result.returncode == 0, output
    assert "no helper metadata (.lst/.map/.cod/debug info) found" in output
    assert "validation=passed" in output
    assert "whole-tail validation clean across 1 functions" in output
    assert "gcc portable-flat syntax check failed" not in output
    assert "unsigned short local_5a[43];" in result.stdout
    assert "unsigned short local_5a;" not in result.stdout
    assert "local_5a[local_2] = local_2 + 1;" in result.stdout
    assert "local_72 = local_5a[local_76];" in result.stdout
    assert "local_5a[local_76] = local_5a[local_4];" in result.stdout
    assert "SEG_U16(inertia_ds, 2886) = 1;" in result.stdout
    raw_pause_store = (
        "SEG_U16(inertia_ds, 306) = 30;" in result.stdout
        and "SEG_U16(inertia_ds, 308) = 0;" in result.stdout
    )
    typed_pause_store = (
        "g_0132 = (g_0132 & 0xffff0000) | 30;" in result.stdout
        and any(f"g_0132 = g_0132 & {mask};" in result.stdout for mask in ("65535", "0xffff"))
    )
    assert raw_pause_store or typed_pause_store or "g_0132 = 30;" in result.stdout
    assert result.stdout.count("sub_10678();") == 1
    assert "sub_10672();" not in result.stdout and "unsigned short sub_11414(void);" in result.stdout
    assert "mem_" not in result.stdout
    assert "_INSERT(" not in result.stdout


def _typed_switch_replacement_safety_payloads(combined_output: str) -> tuple[dict[str, object], ...]:
    return diagnostic_payloads(combined_output, "[typed-switch-replacement-safety] ")


def _typed_switch_seqnode_replacement_payloads(combined_output: str) -> tuple[dict[str, object], ...]:
    return diagnostic_payloads(combined_output, "[typed-switch-seqnode-replacement] ")


def _typed_switch_pre_codegen_seqnode_payloads(combined_output: str) -> tuple[dict[str, object], ...]:
    return diagnostic_payloads(combined_output, "[typed-switch-pre-codegen-seqnode] ")


def _function_body_from_stdout(stdout: str, signature: str) -> str:
    if signature not in stdout:
        name_match = re.search(r"([A-Za-z_]\w*)\s*\(?$", signature)
        if name_match is not None:
            function_name = re.escape(name_match.group(1))
            definitions = tuple(
                re.finditer(
                    rf"(?m)^[^;\n]*\b{function_name}\([^;\n]*\)\n\{{",
                    stdout,
                )
            )
            if definitions:
                return stdout[definitions[-1].start() :]
        return stdout
    return signature + stdout.rsplit(signature, 1)[-1]


def _run_decompile_file(
    path: Path,
    *,
    max_functions: int = 8,
    analysis_timeout: int = 60,
    subprocess_timeout: int = 240,
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.setdefault("INERTIA_ENABLE_TAIL_VALIDATION", "1")
    env.setdefault("INERTIA_DISABLE_TIMING", "1")
    scaled_analysis_timeout = _scaled_timeout(analysis_timeout)
    scaled_subprocess_timeout = _scaled_timeout(subprocess_timeout)
    return subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(path),
            "--timeout",
            str(scaled_analysis_timeout),
            "--max-functions",
            str(max_functions),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=scaled_subprocess_timeout,
        check=False,
    )


def test_sortdemo_sleep_anchor_eliminates_raw_flag_guard_and_keeps_validation_clean():
    result = _run_decompile_addr(SORTDEMO_EXE, 0x10F38, analysis_timeout=30)
    scorecard = build_acceptance_scorecard(
        "Sleep",
        _combined_output(result),
        source_text=render_local_source_sidecar_function(SORTDEMO_EXE, "Sleep"),
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert (
        ("function: 0x10f18 Sleep" in result.stdout)
        or ("function: 0x10f28 Sleep" in result.stdout)
        or ("function: 0x10f38 Sleep" in result.stdout)
    )
    signature = re.search(
        r"(?:void|(?:unsigned )?short) Sleep\((?:clock_t|uint32_t|unsigned long|long) wait\)",
        result.stdout,
    )
    assert signature is not None
    assert "clock() + wait" in result.stdout
    assert "flags_2 = ...;" not in result.stdout
    assert "flags_2 =" not in result.stdout
    assert "if (...)" not in result.stdout
    assert "if (!(...))" not in result.stdout
    assert "(flags_3 & 128) == (flags_3 & 0x800)" not in result.stdout
    assert result.stdout.count("clock()") == 2
    sleep_body = result.stdout[signature.start() :]
    assert "clock() > goal" in sleep_body
    assert "local_2" not in sleep_body
    assert not re.search(r"\b(?:ax|dx)(?:_\d+)?\b", sleep_body)
    assert re.search(r"\b(?:clock_t|unsigned long|long)\s+goal\b", result.stdout)
    assert not re.search(r"\b(?:unsigned\s+)?short\s+goal\b", result.stdout)
    assert "ss << 4" not in result.stdout
    assert "(&s_" not in result.stdout
    assert "*(&" not in result.stdout
    assert not re.search(r"\breturn (?!0;)[^;]+;", sleep_body)
    assert scorecard.source_present is True
    assert scorecard.raw_ss_linear_count == 0
    assert scorecard.validation_verdict == "stable"
    assert "else if" not in result.stdout
    assert "if (clock() <= goal)" not in result.stdout


def test_sortdemo_sleep_proc_pipeline_declares_lowered_runtime_calls() -> None:
    result = _run_decompile_proc(
        SORTDEMO_EXE,
        "Sleep",
        extra_args=("--no-alternate-source-c", "--c-target", "portable-flat"),
    )
    combined = _combined_output(result)

    assert result.returncode == 0, combined
    assert "clock_t clock(void);" in result.stdout
    assert result.stdout.count("clock()") == 2
    assert "acceptance-gate detail:" not in combined
    assert "validation=failed" not in combined
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined


def test_sortdemo_reinitbars_preserves_clock_store_loop_and_validation_contract(tmp_path):
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10678,
        analysis_timeout=30,
        subprocess_timeout=180,
        extra_args=("--c-target", "portable-flat"),
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    assert "function: 0x10678 ReInitBars" in result.stdout
    assert "whole-tail validation clean across 1 functions" in combined
    assert "gcc syntax check failed:" not in combined
    assert "void ReInitBars(void)" in result.stdout
    assert "clStart = clock();" in result.stdout
    assert_reinitbars_loop_behavior(
        _function_body_from_stdout(result.stdout, "void ReInitBars"), tmp_path,
    )
    assert "abarWork[iRow] = abarPerm[iRow];" in result.stdout
    assert "DrawBar(iRow);" in result.stdout
    assert "local_3" not in result.stdout
    assert "local_4" not in result.stdout
    assert "return iRow" not in result.stdout
    assert result.stdout.count("return;") == 1
    assert "ds << 4" not in combined
    assert "es << 4" not in combined
    assert "ss << 4" not in combined
    scorecard = build_acceptance_scorecard(
        "ReInitBars",
        combined,
        source_text=render_local_source_sidecar_function(SORTDEMO_EXE, "ReInitBars"),
    )
    assert scorecard.source_present is True
    assert scorecard.recovery_mode == "decompiled"
    assert scorecard.validation_verdict == "stable"
    assert scorecard.raw_ds_linear_count == 0
    assert scorecard.raw_ss_linear_count == 0


def test_sortdemo_drawtime_materializes_clock_return_to_clfinish_once():
    result = _run_decompile_proc(
        SORTDEMO_EXE,
        "DrawTime",
        proc_kind="NEAR",
        analysis_timeout=90,
        subprocess_timeout=240,
        extra_args=("--c-target", "portable-flat"),
        extra_env={"INERTIA_DISABLE_TIMING": "1"},
    )

    combined = _combined_output(result)
    drawtime_signature = re.search(
        r"(?:void|short) (?:DrawTime|sub_10498)\((?:unsigned short|int) \w+\)",
        result.stdout,
    )
    assert drawtime_signature is not None
    body = _function_body_from_stdout(result.stdout, drawtime_signature.group(0))
    assert result.returncode == 0, combined
    assert "validation=passed" in combined
    assert "Missing source-evidenced calls" not in combined
    assert "SEG_PTR(ds, 381)" not in body
    assert "SEG_PTR(15, 381)" not in body
    assert re.search(r"(?m)^\s*if \([^\n]+\)\n\s*else\b", body) is None
    assert re.search(r"(?:Beep|sub_10e70)\([^;]+, 75\);", body) is not None
    assert re.search(r"(?:Sleep|sub_10f38)\([^;]+ - 75\);", body) is not None
    assert re.search(r"(?:Sleep|sub_10f38)\([^;]+\);", body) is not None
    assert body.count("Sleep(") + body.count("sub_10f38(") >= 2
    assert (
        "int Sleep();" in result.stdout
        or "int Sleep(unsigned long a0);" in result.stdout
        or "sub_10f38" in result.stdout
    )
    assert "Sleep(unsigned short" not in result.stdout
    assert "[tail-validation] whole-tail validation clean" in combined


def test_sortdemo_swapbars_materializes_arguments_without_dead_setup_artifacts():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10768,
        analysis_timeout=60,
        subprocess_timeout=180,
        extra_args=("--c-target", "portable-flat"),
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    assert "function: 0x10768 SwapBars" in result.stdout
    assert "validation=passed" in combined
    assert "gcc syntax check failed:" not in combined
    _assert_clean_decompilation_output(combined)
    assert "void SwapBars(int iRow1, int *iRow2)" not in result.stdout
    assert "s_2 = &s_2 + 2;" not in result.stdout
    assert "vvar_16 = &s_6;" not in result.stdout
    scorecard = build_acceptance_scorecard(
        "SwapBars",
        combined,
        source_text=render_local_source_sidecar_function(SORTDEMO_EXE, "SwapBars"),
    )
    assert scorecard.source_present is True
    assert scorecard.recovery_mode == "decompiled"
    assert scorecard.validation_verdict == "stable"
    assert scorecard.raw_ds_linear_count == 0
    assert scorecard.anonymous_sub_count == 0


def test_sortdemo_swaps_preserves_binary_proven_global_increment_and_pointer_swap():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x107B8,
        analysis_timeout=30,
        subprocess_timeout=60,
        extra_args=("--c-target", "portable-flat"),
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    _assert_clean_decompilation_output(combined)
    assert "function: 0x107b8 Swaps" in result.stdout
    assert "validation=passed" in combined
    assert "gcc syntax check failed:" not in combined
    assert "void Swaps(g_08F0_entry *bar1, g_08F0_entry *bar2)" in result.stdout
    final_body = _function_body_from_stdout(result.stdout, "void Swaps")
    assert "chkstk" not in final_body.lower()
    assert "iSwaps += 1;" in final_body
    assert "barTmp = bar1[0];" in final_body or "local_2 = bar1[0];" in final_body
    assert final_body.count("barTmp = bar1[0];") + final_body.count("local_2 = bar1[0];") == 1
    assert final_body.index("iSwaps += 1;") < max(
        final_body.index("barTmp = bar1[0];") if "barTmp = bar1[0];" in final_body else -1,
        final_body.index("local_2 = bar1[0];") if "local_2 = bar1[0];" in final_body else -1,
    )
    assert "bar1[0] = bar2[0];" in final_body
    assert "bar2[0] = local_2;" in final_body or "bar2[0] = barTmp;" in final_body
    scorecard = build_acceptance_scorecard(
        "Swaps",
        combined,
        source_text=render_local_source_sidecar_function(SORTDEMO_EXE, "Swaps"),
    )
    assert scorecard.source_present is True
    assert scorecard.recovery_mode == "decompiled"
    assert scorecard.validation_verdict == "stable"
    assert scorecard.raw_ds_linear_count == 0


def test_sortdemo_bubblesort_direct_path_validates_and_preserves_array_calls():
    result = _run_decompile_proc(
        SORTDEMO_EXE,
        "BubbleSort",
        analysis_timeout=120,
        subprocess_timeout=180,
        extra_env={"INERTIA_DISABLE_TIMING": "1"},
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    assert "function: 0x108d0 BubbleSort" in result.stdout
    assert "whole-tail validation clean across 1 functions" in combined or "validation=passed" in combined
    assert "rejected direct partial payload" not in combined
    assert "sidecar slice fallback" not in combined
    if "short BubbleSort" in result.stdout:
        final_body = _function_body_from_stdout(result.stdout, "short BubbleSort")
    else:
        assert "void BubbleSort" in result.stdout, combined
        final_body = _function_body_from_stdout(result.stdout, "void BubbleSort")
    assert "abarWork[iRow + 1].field_0 < abarWork[iRow].field_0" in final_body
    assert re.search(
        r"Swaps\(&abarWork\[(?:\(unsigned short\))?iRow\], "
        r"&abarWork\[(?:\(unsigned short\))?iRow \+ 1\]\);",
        final_body,
    )
    assert re.search(r"SwapBars\(iRow, (?:\(unsigned short\))?iRow \+ 1\);", final_body)
    assert "Swaps();" not in final_body
    assert "SwapBars();" not in final_body
    assert "SEG_U8(" not in final_body
    assert "SEG_PTR(" not in final_body
    assert "mem_0BA2" not in final_body
    assert "mem_0BAB" not in final_body
    assert final_body.count("iLimit = cRow;") == 1
    assert final_body.count("iLimit = iSwitch;") == 1
    initial_limit = final_body.index("iLimit = cRow;")
    outer_loop = final_body.index("do", initial_limit)
    for_headers = (
        "for (iRow = 0; iLimit > iRow; iRow = iRow + 1)",
        "for (iRow = 0; iLimit > iRow; iRow += 1)",
    )
    for_header = next((header for header in for_headers if header in final_body), None)
    if for_header is not None:
        inner_loop = final_body.index(for_header, outer_loop)
        next_limit = final_body.index("iLimit = iSwitch;", inner_loop)
    else:
        inner_loop = min(
            final_body.index(marker, outer_loop)
            for marker in ("while (true)", "while (1)")
            if marker in final_body[outer_loop:]
        )
        row_update = final_body.index("iRow += 1;", inner_loop)
        next_limit = final_body.index("iLimit = iSwitch;", row_update)
    outer_condition = final_body.index("} while", next_limit)
    assert initial_limit < outer_loop < inner_loop < next_limit < outer_condition


def test_sortd_bubblesort_sidecar_free_preserves_direct_ds_row_count(tmp_path: Path):
    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))

    result = _run_decompile_addr(
        isolated_binary,
        0x108D0,
        analysis_timeout=60,
        subprocess_timeout=120,
        extra_args=("--ignore-local-sidecar-hints", "--c-target", "portable-flat"),
        extra_env={"INERTIA_DISABLE_TIMING": "1"},
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    _assert_clean_decompilation_output(combined)
    assert "function: 0x108d0 sub_108d0" in result.stdout
    assert "validation=passed" in combined
    final_body = _function_body_from_stdout(result.stdout, "void sub_108d0")
    assert "local_4 = g_0BA2;" in final_body
    assert "SEG_U16(inertia_ds, 2978)" not in final_body
    assert "mem_0BA2" not in final_body
    assert re.search(r"extern g_08F0_entry g_0B4C\[\d*\];", result.stdout) is not None
    assert "g_0B4E" not in result.stdout
    assert re.search(
        r"sub_107b8\(&g_0B4C\[(?:\(unsigned short\))?local_2\], "
        r"&g_0B4C\[(?:\(unsigned short\))?local_2 \+ 1\]\);",
        final_body,
    )
    assert re.search(
        r"sub_10768\(local_2, (?:\(unsigned short\))?local_2 \+ 1\);",
        final_body,
    )


def test_sortd_exchangesort_sidecar_free_folds_alias_proven_high_byte(tmp_path: Path):
    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))

    result = _run_decompile_addr(
        isolated_binary,
        0x10B50,
        analysis_timeout=90,
        subprocess_timeout=150,
        extra_args=("--ignore-local-sidecar-hints", "--c-target", "portable-flat"),
        extra_env={"INERTIA_DISABLE_TIMING": "1"},
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    _assert_clean_decompilation_output(combined)
    assert "function: 0x10b50 sub_10b50" in result.stdout
    assert "validation=passed" in combined
    final_body = result.stdout.rsplit("sub_10b50(", 1)[-1]
    assert "local_3" not in final_body
    assert "local_2 = local_2 + 1" in final_body or "local_2 += 1" in final_body
    comparison_guard = "if (g_0B4C[local_2].field_0 < g_0B4C[local_4].field_0)"
    assert comparison_guard in final_body
    guard_start = final_body.index("{", final_body.index(comparison_guard))
    guard_end = final_body.index("}", guard_start)
    guarded_body = final_body[guard_start:guard_end]
    assert "local_4 = local_2;" in guarded_body
    draw_call = re.search(r"sub_10498\((?:\(unsigned short\))?local_2\);", guarded_body)
    assert draw_call is not None
    assert guarded_body.index("local_4 = local_2;") < draw_call.start()
    assert final_body.count("local_4 = local_2;") == 1
    assert re.search(
        r"sub_107b8\(&g_0B4C\[(?:\(unsigned short\))?local_6\], "
        r"&g_0B4C\[(?:\(unsigned short\))?local_4\]\);",
        final_body,
    )
    assert "sub_10768(local_6, local_4);" in final_body


def test_sortd_drawbar_sidecar_free_materializes_stack_buffer_and_conservative_return(
    tmp_path: Path,
) -> None:
    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))

    result = _run_decompile_addr(
        isolated_binary,
        0x106C8,
        analysis_timeout=120,
        subprocess_timeout=240,
        extra_args=(
            "--no-alternate-source-c",
            "--window",
            "0x93",
            "--c-target",
            "portable-flat",
        ),
        extra_env={"INERTIA_DISABLE_TIMING": "1"},
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    _assert_clean_decompilation_output(combined)
    assert "no helper metadata (.lst/.map/.cod/debug info) found" in combined
    assert "function: 0x106c8 sub_106c8" in result.stdout
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "gcc syntax check failed:" not in combined
    signature = re.search(
        r"(?P<return_type>void|(?:unsigned )?short) sub_106c8\(unsigned short \w+\)",
        result.stdout,
    )
    assert signature is not None
    final_body = _function_body_from_stdout(result.stdout, signature.group(0))
    assert "char local_2c[44];" in final_body
    assert "unsigned short local_2c;" not in final_body
    assert final_body.count("sub_113d4(") == 2
    assert "local_2c[g_0BA2] = 0;" in final_body
    assert "sub_12756(local_2c, inertia_ss);" in final_body
    return_exprs = re.findall(r"\breturn(?:\s+([^;]+))?;", final_body)
    assert return_exprs in ([""], ["0"], ["sub_12756(local_2c, inertia_ss)"])
    assert "inertia_ss] - 44" not in final_body


def test_sortd_drawframe_sidecar_free_materializes_segmented_buffer_calls(
    tmp_path: Path,
) -> None:
    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))

    result = _run_decompile_addr(
        isolated_binary,
        0x101F0,
        analysis_timeout=120,
        subprocess_timeout=240,
        extra_args=(
            "--no-alternate-source-c",
            "--window",
            "0xf0",
            "--c-target",
            "portable-flat",
        ),
        extra_env={"INERTIA_DISABLE_TIMING": "1"},
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    _assert_clean_decompilation_output(combined)
    assert "no helper metadata (.lst/.map/.cod/debug info) found" in combined
    assert "function: 0x101f0 sub_101f0" in result.stdout
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    compile_result = check_c_recompiles_8616(result.stdout)
    assert compile_result.passed, compile_result.stderr
    assert "gcc syntax check failed:" not in combined
    assert re.search(r"void sub_101f0\([^)]*,[^)]*,[^)]*,[^)]*\)", result.stdout)
    final_body = _function_body_from_stdout(result.stdout, "void sub_101f0")
    assert "char local_52[80];" in final_body
    assert "unsigned short local_2;" in final_body
    assert "unsigned long local_2;" not in final_body
    assert final_body.count("sub_113d4(local_52,") == 3
    assert final_body.count("sub_128e4(") == 3
    assert final_body.count("sub_12756(local_52, inertia_ss);") == 3
    assert re.search(r"local_2 = \w+ \+ 1;\s+while \(\(short\)local_2 <= \w+\)", final_body)
    assert final_body.count("local_2 += 1;") == 1
    assert "break;" not in final_body
    assert "SEG_U" not in final_body
    assert "vvar_" not in final_body
    assert re.search(r"\breturn\s*;", final_body)
    assert not re.search(r"\breturn\s+[^;]+;", final_body)


def test_sortd_reinitbars_sidecar_free_materializes_indexed_global_copy(
    tmp_path: Path,
) -> None:
    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))

    result = _run_decompile_addr(
        isolated_binary,
        0x10678,
        analysis_timeout=120,
        subprocess_timeout=240,
        extra_args=(
            "--no-alternate-source-c",
            "--window",
            "0x50",
            "--c-target",
            "portable-flat",
        ),
        extra_env={"INERTIA_DISABLE_TIMING": "1"},
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    _assert_clean_decompilation_output(combined)
    assert "no helper metadata (.lst/.map/.cod/debug info) found" in combined
    assert "function: 0x10678 sub_10678" in result.stdout
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "gcc syntax check failed:" not in combined
    assert "unsigned long sub_1137e(void);" in result.stdout
    assert "extern unsigned long g_0BA6;" in result.stdout
    final_body = _function_body_from_stdout(result.stdout, "void sub_10678")
    assert final_body.count("unsigned short local_2;") == 1
    assert final_body.count("sub_1137e();") == 1
    assert final_body.count("g_0BA6 = sub_1137e();") == 1
    assert re.search(r"(?m)^\s*sub_1137e\(\);\s*$", final_body) is None
    assert "g_0B4C[local_2] = g_08F0[local_2];" in final_body
    assert len(
        re.findall(
            r"sub_106c8\((?:\(unsigned short\))?local_2\);",
            final_body,
        )
    ) == 1
    assert re.search(
        r"g_0BA2 > (?:\(short\))?local_2|(?:\(short\))?local_2 < g_0BA2",
        final_body,
    )
    assert final_body.count("local_2 += 1;") == 1
    assert "mem_" not in final_body
    assert "vvar_" not in final_body
    assert final_body.count("return;") == 1 or final_body.count("return 0;") == 1


def test_sortd_drawtime_sidecar_free_materializes_wide_delay_arguments(
    tmp_path: Path,
) -> None:
    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))

    result = _run_decompile_addr(
        isolated_binary,
        0x10498,
        analysis_timeout=120,
        subprocess_timeout=240,
        extra_args=(
            "--no-alternate-source-c",
            "--window",
            "0xc2",
            "--c-target",
            "portable-flat",
        ),
        extra_env={"INERTIA_DISABLE_TIMING": "1"},
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    _assert_clean_decompilation_output(combined)
    assert "no helper metadata (.lst/.map/.cod/debug info) found" in combined
    assert "function: 0x10498 sub_10498" in result.stdout
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "gcc syntax check failed:" not in combined
    assert re.search(r"\bsub_10f38\(unsigned long \w+\);", result.stdout)
    function_signature = re.search(r"(?:short|void) sub_10498\(unsigned short \w+\)", result.stdout)
    assert function_signature is not None
    final_body = _function_body_from_stdout(result.stdout, function_signature.group(0))
    signature = re.search(r"(?:short|void) sub_10498\(unsigned short (\w+)\)", final_body)
    assert signature is not None
    argument_name = signature.group(1)
    assert re.search(rf"sub_10e70\((?:\(unsigned short\))?{re.escape(argument_name)} \* 60, 75\);", final_body)
    assert "[bp+0x4]" not in final_body
    assert "g_0B48 = sub_1137e();" in final_body
    assert "sub_12756(local_50, inertia_ss);" in final_body
    assert final_body.count("sub_10f38(SEG_U32(inertia_ds, 306));") == 1
    assert final_body.count("sub_10f38(SEG_U32(inertia_ds, 306) - 75);") == 1
    assert final_body.count("return 0;") + final_body.count("return;") >= 1
    assert "return v" not in final_body
    assert "sub_10f18(" not in final_body
    assert "mem_" not in final_body
    assert "flags" not in final_body
    assert "vvar_" not in final_body


def test_sortd_insertionsort_sidecar_free_splits_header_and_rebases_source(
    tmp_path: Path,
) -> None:
    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))

    result = _run_decompile_addr(
        isolated_binary,
        0x10808,
        analysis_timeout=120,
        subprocess_timeout=240,
        extra_args=(
            "--no-alternate-source-c",
            "--window",
            "0xc8",
            "--c-target",
            "portable-flat",
        ),
        extra_env={"INERTIA_DISABLE_TIMING": "1"},
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    _assert_clean_decompilation_output(combined)
    assert "no helper metadata (.lst/.map/.cod/debug info) found" in combined
    assert "function: 0x10808 sub_10808" in result.stdout
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "gcc syntax check failed:" not in combined
    final_body = _function_body_from_stdout(result.stdout, "void sub_10808")
    loop_header = "for (local_4 = local_2; local_4; local_4 -= 1)"
    guard = re.compile(
        r"if \((?:\(g_0B4C\[local_4 - 1\]\.field_0 & (?:255|0xff)\) <= (?:\(short\))?local_6|"
        r"!\(\(g_0B4C\[local_4 - 1\]\.field_0 & (?:255|0xff)\) > (?:\(short\))?local_6\))\)"
    )
    source_copy = "g_0B4C[local_4] = g_0B4C[local_4 - 1];"
    row_load = "local_8 = g_0B4C[local_2];"
    assert loop_header in final_body
    assert final_body.count("g_0BAA += 1;") == 1
    assert final_body.count(row_load) == 1
    assert "local_6 = (signed char)local_8.field_0;" in final_body
    assert "local_6 = local_8;" not in final_body
    assert len(guard.findall(final_body)) == 1
    assert final_body.count("g_0BA4 += 1;") == 1
    assert final_body.count(source_copy) == 1
    guard_match = guard.search(final_body)
    assert guard_match is not None
    assert final_body.index("for (local_2 = 0;") < final_body.index(row_load)
    assert final_body.index(row_load) < final_body.index("local_6 = (signed char)local_8.field_0;")
    assert final_body.index("g_0BAA += 1;") < guard_match.start()
    assert guard_match.start() < final_body.index("g_0BA4 += 1;")
    assert final_body.index("g_0BA4 += 1;") < final_body.index(source_copy)
    assert len(
        re.findall(r"sub_106c8\((?:\(unsigned short\))?local_4\);", final_body)
    ) == 2
    assert len(
        re.findall(r"sub_10498\((?:\(unsigned short\))?local_4\);", final_body)
    ) == 2
    assert "sub_10491(" not in final_body
    assert "g_0B4C[local_4] = g_0B4A[local_4];" not in final_body
    assert "vvar_" not in final_body
    assert "reg+" not in combined


@pytest.mark.xdist_group("sortd-initmenu")
def test_sortd_initmenu_sidecar_free_preserves_calls_and_compiles(
    tmp_path: Path,
) -> None:
    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))

    result = _run_decompile_addr(
        isolated_binary,
        0x10060,
        analysis_timeout=120,
        subprocess_timeout=240,
        extra_args=(
            "--no-alternate-source-c",
            "--window",
            "0x17b",
            "--c-target",
            "portable-flat",
        ),
        extra_env={"INERTIA_DISABLE_TIMING": "1"},
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    _assert_clean_decompilation_output(combined)
    assert "no helper metadata (.lst/.map/.cod/debug info) found" in combined
    assert "void sub_10060(void)" in result.stdout
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "gcc portable-flat syntax check failed:" not in combined
    assert re.search(r"(?:int|void) sub_12756\(char \*a0, unsigned short a1\);", result.stdout)
    assert "extern char * g_0136[];" in result.stdout
    final_body = _function_body_from_stdout(result.stdout, "void sub_10060")
    assert "char local_12[16];" in final_body and "// [bp+0x2]" not in final_body
    assert final_body.count("sub_12b24(15);") == 1
    assert final_body.count("sub_12b3e(0, 0);") == 1
    assert final_body.count("sub_101f0(") == 1
    assert "sub_101db(" not in final_body
    assert final_body.count("sub_12756(") == 5
    assert "sub_12756(g_0136[local_2], inertia_ds);" in final_body
    assert final_body.count("sub_128e4(") == 5
    assert final_body.count("sub_1123a(") == 3
    assert "aNldiv(SEG_U32(inertia_ds, 306), 30)" in final_body
    assert "sub_1143a(" not in final_body
    assert "vvar_" not in final_body
    assert "return 0;" not in final_body


def test_sortd_quicksort_sidecar_free_preserves_typed_control_flow_and_compiles(
    tmp_path: Path,
) -> None:
    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))

    result = _run_decompile_addr(
        isolated_binary,
        0x10CE0,
        analysis_timeout=240,
        subprocess_timeout=360,
        extra_args=(
            "--no-alternate-source-c",
            "--window",
            "0x190",
            "--c-target",
            "portable-flat",
        ),
        extra_env={"INERTIA_DISABLE_TIMING": "1"},
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    _assert_clean_decompilation_output(combined)
    assert "no helper metadata (.lst/.map/.cod/debug info) found" in combined
    assert "function: 0x10ce0 sub_10ce0" in result.stdout
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "gcc portable-flat syntax check failed:" not in combined
    final_body = _function_body_from_stdout(result.stdout, "void sub_10ce0")
    assert "vvar_" not in final_body
    signature = re.search(r"void sub_10ce0\(short (\w+), short (\w+)\)", final_body)
    assert signature is not None
    low_arg, high_arg = signature.groups()
    # Braces and an else after an unconditional return do not change the guard.
    # Match both guards together so intervening work cannot bypass the return.
    assert re.search(
        rf"if \((?:\(short\)\s*)?{low_arg} >= (?:\(short\)\s*)?{high_arg}\)\s*"
        rf"(?:\{{\s*return;\s*\}}|return;)\s*(?:else\s+)?"
        rf"if \((?:\(unsigned short\)\s*)?{high_arg}\s*-\s*"
        rf"(?:\(unsigned short\)\s*)?{low_arg}\s*==\s*1\)",
        final_body,
    ) is not None
    assert f"if (g_0B4C[{low_arg}].field_0 <= g_0B4C[{high_arg}].field_0)" in final_body
    assert re.search(
        r"while \((?:(?:\(short\)\s*)?local_6 < (?:\(short\)\s*)?local_2|"
        r"(?:\(short\)\s*)?local_2 > (?:\(short\)\s*)?local_6)\);",
        final_body,
    ) is not None
    assert len(
        re.findall(
            r"if \((?:\(short\)\s*)?local_2 <= (?:\(short\)\s*)?local_6\)\s*break;",
            final_body,
        )
    ) == 2
    assert re.search(
        r"if \(g_0B4C\[local_6\]\.field_0 > (?:\(short\)\s*)?local_4\)\s*break;",
        final_body,
    ) is not None
    assert re.search(
        r"if \(g_0B4C\[local_2\]\.field_0 < (?:\(short\)\s*)?local_4\)\s*break;",
        final_body,
    ) is not None
    assert re.search(
        rf"if \((?:\(short\)\s*)?local_6\s*-\s*(?:\(short\)\s*)?{low_arg}\s*>=\s*"
        rf"(?:\(short\)\s*)?{high_arg}\s*-\s*(?:\(short\)\s*)?local_6\)",
        final_body,
    ) is not None
    assert final_body.count("sub_107b8(") == 3
    assert re.search(
        rf"sub_107b8\(&g_0B4C\[(?:\(unsigned short\))?{low_arg}\], "
        rf"&g_0B4C\[(?:\(unsigned short\))?{high_arg}\]\);",
        final_body,
    ) is not None
    assert final_body.count("sub_10768(") == 3
    assert "sub_1075b(" not in final_body
    assert final_body.count("sub_10ce0(") == 5
    assert len(
        re.findall(
            rf"sub_10ce0\((?:\(unsigned short\))?{low_arg}, "
            rf"(?:\(unsigned short\))?local_6 - 1\);",
            final_body,
        )
    ) == 2
    assert len(
        re.findall(
            rf"sub_10ce0\((?:\(unsigned short\))?local_6 \+ 1, "
            rf"(?:\(unsigned short\))?{high_arg}\);",
            final_body,
        )
    ) == 2
    do_body = final_body[final_body.index("do\n") :]
    pre_loop_body = final_body[: final_body.index("do\n")]
    pivot_match = re.search(rf"(\w+) = g_0B4C\[{high_arg}\]\.field_0;", pre_loop_body)
    assert pivot_match is not None
    assert re.search(r"\b\w+\s*=\s*local_6;", pre_loop_body) is None
    assert do_body.count(pivot_match.group(1)) >= 2
    first_scan_match = re.search(r"while \((?:true|1)\)", do_body)
    assert first_scan_match is not None
    first_scan = first_scan_match.start()
    assert do_body.index(f"local_6 = {low_arg};") < first_scan
    assert do_body.index(f"local_2 = {high_arg};") < first_scan


def test_sortdemo_exchangesort_preserves_inner_loop_setup_and_guarded_minimum_update():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10B50,
        analysis_timeout=90,
        subprocess_timeout=120,
        extra_args=("--c-target", "portable-flat"),
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    assert "function: 0x10b50 ExchangeSort" in result.stdout
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "gcc syntax check failed:" not in combined
    assert re.search(r"(?:short|void) ExchangeSort\(void\)", result.stdout)
    final_body = result.stdout.rsplit("ExchangeSort(void)", 1)[-1]
    assert "for (iRowCur = 0;" in final_body or "for (local_6 = 0;" in final_body
    assert (
        "iRowMin = iRowCur;\n        for (iRowNext = iRowCur;" in final_body
        or "iRowMin = iRowCur;\n        iRowNext = iRowCur;\n        while (true)" in final_body
        or "local_4 = local_6;\n        for (local_2 = local_6;" in final_body
        or "local_4 = local_6;\n        local_2 = local_6;\n        while (true)" in final_body
    )
    next_row = "iRowNext" if "iRowNext" in final_body else "local_2"
    current_row = "iRowCur" if "iRowCur" in final_body else "local_6"
    # Preserve the signed machine comparison when storage is declared unsigned.
    next_comparison = f"(short){next_row}" if f"unsigned short {next_row};" in final_body else next_row
    assert any(
        f"for ({next_row} = {current_row}; {next_comparison} < {bound};" in final_body
        or f"if ({next_comparison} >= {bound})" in final_body
        for bound in ("cRow", "g_ba2", "SEG_U16(inertia_ds, 2978)")
    )
    comparison_guards = (
        "if (abarWork[iRowNext] < abarWork[iRowMin])",
        "if (abarWork[iRowNext].field_0 < abarWork[iRowMin].field_0)",
        "if (abarWork[local_2] < abarWork[local_4])",
        "if (SEG_U8(inertia_ds, 2892 + (iRowNext << 1)) < abarWork[iRowMin].field_0)",
        "if (SEG_U8(ds, 2892 + (local_2 << 1)) < SEG_U8(ds, 2892 + (local_4 << 1)))",
    )
    comparison_guard = next((guard for guard in comparison_guards if guard in final_body), None)
    assert comparison_guard is not None
    guard_start = final_body.index("{", final_body.index(comparison_guard))
    guard_end = final_body.index("}", guard_start)
    guarded_body = final_body[guard_start:guard_end]
    minimum_update = "iRowMin = iRowNext;" if "iRowMin" in comparison_guard else "local_4 = local_2;"
    draw_time_arg = "iRowNext" if "iRowNext" in comparison_guard else "local_2"
    draw_time = next(
        (call for call in (f"DrawTime({draw_time_arg});", f"DrawTime((unsigned short){draw_time_arg});") if call in guarded_body),
        None,
    )
    assert minimum_update in guarded_body
    assert draw_time is not None
    assert guarded_body.index(minimum_update) < guarded_body.index(draw_time)
    assert final_body.count(minimum_update) == 1
    assert "v15 & 128" not in final_body
    assert "v15 & 0x800" not in final_body
    assert "return local_6;" not in final_body
    assert "return (local_6 << 1) + 2892;" not in final_body
    assert "\n    iRowMin = iRowCur;\n    iRowNext = iRowCur;\n    return" not in final_body


def test_sortdemo_percolateup_materializes_parent_once_and_preserves_calls():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x109E8,
        analysis_timeout=60,
        subprocess_timeout=90,
        extra_args=("--c-target", "portable-flat"),
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    assert "function: 0x109e8 PercolateUp" in result.stdout
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "gcc syntax check failed:" not in combined
    final_body = "void PercolateUp" + result.stdout.rsplit("void PercolateUp", 1)[-1]
    executable_lines = tuple(
        line.strip() for line in final_body.splitlines() if line.startswith(("        ", "    "))
    )
    assert "iParent = i / 2;" in executable_lines or "iParent = (short)i / 2;" in executable_lines
    assert executable_lines.count("iCompares += 1;") == 1
    assert (
        "if (abarWork[i] > abarWork[iParent])" in executable_lines
        or "if (abarWork[i].field_0 > abarWork[iParent].field_0)" in executable_lines
        or "if (MEM_U8(&abarWork[i]) > MEM_U8(&abarWork[iParent]))" in executable_lines
        or "if (abarWork[i].field_0 <= abarWork[iParent].field_0)" in executable_lines
    )
    assert re.search(
        r"Swaps\(&abarWork\[(?:\(unsigned short\))?iParent\], "
        r"&abarWork\[(?:\(unsigned short\))?i\]\);",
        "\n".join(executable_lines),
    )
    assert "SwapBars(iParent, i);" in executable_lines
    assert "SEG_U8(ds," not in final_body
    assert "SEG_PTR(ds," not in final_body
    assert "stack_bp_" not in final_body
    assert "(&s_fffa)[" not in final_body
    assert "flags & 64" not in final_body
    assert sum(1 for line in executable_lines if line.startswith("Swaps(")) == 1
    assert sum(1 for line in executable_lines if line.startswith("SwapBars(")) == 1
    assert "flsbuf" not in final_body
    assert "Non-constant VexValue has no value property" not in combined
    assert "Function recovery failed" not in combined
    assert "arg_6" not in final_body
    assert "SwapBars(arg_6" not in final_body
    scorecard = build_acceptance_scorecard(
        "PercolateUp",
        combined,
        source_text=render_local_source_sidecar_function(SORTDEMO_EXE, "PercolateUp"),
    )
    assert scorecard.source_present is True
    assert scorecard.raw_ds_linear_count == 0
    assert scorecard.raw_ss_linear_count == 0
    assert scorecard.validation_verdict == "stable"


def test_sortdemo_main_uses_portable_flat_int_main_signature():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10010,
        extra_args=("--c-target", "portable-flat"),
        analysis_timeout=12,
        subprocess_timeout=60,
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    assert "function: 0x10010 main" in result.stdout
    assert "validation=passed" in combined
    assert "gcc syntax check failed:" not in combined
    assert "void main(void)" not in result.stdout
    assert "int main(void)" in result.stdout
    assert re.search(r"setvideomode\((?:65535|0xffff)\);", result.stdout)
    assert not re.search(
        r"return setvideomode\((?:65535|0xffff)\);",
        result.stdout,
    )
    assert result.stdout.count("return 0;") == 1
    assert "InitMenu(" in result.stdout
    scorecard = build_acceptance_scorecard(
        "main",
        combined,
        source_text=render_local_source_sidecar_function(SORTDEMO_EXE, "main"),
    )
    assert scorecard.source_present is True
    assert scorecard.raw_ss_linear_count == 0
    assert scorecard.anonymous_sub_count == 0
    assert scorecard.validation_verdict == "stable"


def test_sortdemo_nfree_does_not_emit_undeclared_vvar_carrier():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x125E6,
        extra_args=("--c-target", "portable-flat"),
        analysis_timeout=12,
        subprocess_timeout=120,
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    assert "function: 0x125e6 nfree" in combined
    assert "validation=passed" in combined
    assert "gcc syntax check failed:" not in combined
    assert "undeclared" not in combined
    assert "void nfree(void *ptr)" in result.stdout
    assert "vvar_" not in result.stdout


def test_sortdemo_heapsort_materializes_call_arguments_without_stack_leaks():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10970,
        extra_args=("--c-target", "portable-flat"),
        analysis_timeout=30,
        subprocess_timeout=120,
    )

    combined = result.stderr + result.stdout
    assert result.returncode == 0, combined
    assert "function: 0x10970 HeapSort" in result.stdout
    assert "validation=passed" in combined
    final_body = _function_body_from_stdout(result.stdout, "void HeapSort")
    assert "PercolateUp(local_2);" in final_body or "PercolateUp(i);" in final_body
    assert "Swaps(&abarWork[0], &abarWork[local_2]);" in final_body or "Swaps(&abarWork[0], &abarWork[i]);" in final_body
    assert (
        "SwapBars(0, i);" in final_body
        or "SwapBars( 0, i );" in final_body
        or "SwapBars(0, local_2);" in final_body
        or "SwapBars( 0, local_2 );" in final_body
    )
    assert (
        "PercolateDown(i - 1);" in final_body
        or "PercolateDown( i - 1 );" in final_body
        or "PercolateDown(local_2 - 1);" in final_body
        or "PercolateDown( local_2 - 1 );" in final_body
    )
    assert "SEG_PTR(ds" not in final_body
    assert "SwapBars(i, 0);" not in final_body
    assert "SwapBars(local_2, 0);" not in final_body
    assert "PercolateDown((i << 1) + 2892);" not in final_body
    assert "PercolateDown((local_2 << 1) + 2892);" not in final_body
    assert "*(&(&v0)[4])" not in final_body
    assert "SEG_PTR(ds, &s_4 + 2)" not in final_body
    assert "(i << 1) + 2892);" not in final_body
    assert "(local_2 << 1) + 2892);" not in final_body
    assert "SwapBars(i, 0)" not in final_body
    assert "SwapBars(local_2, 0)" not in final_body
    assert "PercolateDown((i << 1) + 2892)" not in final_body
    assert "PercolateDown((local_2 << 1) + 2892)" not in final_body
    assert "SEG_PTR(ds, &s_" not in final_body
    assert "SEG_PTR(ds, &v" not in final_body
    assert "Swaps(SEG_PTR(ds, 2892), SEG_PTR(ds, &s_4 + 2))" not in final_body
    call_lines = "\n".join(
        line.strip()
        for line in final_body.splitlines()
        if any(name in line for name in ("PercolateUp(", "Swaps(", "SwapBars(", "PercolateDown("))
    )
    assert "PercolateUp(local_2);" in call_lines or "PercolateUp(i);" in call_lines
    assert "SwapBars(0, local_2);" in call_lines or "SwapBars(0, i);" in call_lines
    assert (
        "PercolateDown(i - 1);" in call_lines
        or "PercolateDown(local_2 - 1);" in call_lines
    )
    assert "Swaps(&abarWork[0], &abarWork[local_2]);" in call_lines or "Swaps(&abarWork[0], &abarWork[i]);" in call_lines
    assert "PercolateDown(3)" not in call_lines
    assert "PercolateDown((i << 1) + 2892)" not in call_lines
    assert "SEG_PTR(ds" not in call_lines
    assert "SEG_PTR(ds, &s_" not in call_lines
    assert "&s_4" not in call_lines
    assert "arg_1" not in call_lines
    assert "&s_" not in final_body
    assert "s_ff" not in final_body
    assert "*(&v" not in final_body
    assert "stack[" not in final_body


def test_sortdemo_file_summary_lines_are_stable_and_sorted():
    first = _run_decompile_file(SORTDEMO_EXE, max_functions=2)
    second = _run_decompile_file(SORTDEMO_EXE, max_functions=2)

    assert first.returncode in {0, 2}, first.stderr + first.stdout
    assert second.returncode in {0, 2}, second.stderr + second.stdout

    def _summary_lines(text: str) -> list[str]:
        return [line for line in text.splitlines() if "summary:" in line]

    first_summary = _summary_lines(_combined_output(first))
    second_summary = _summary_lines(_combined_output(second))
    _assert_clean_decompilation_output(_combined_output(first))
    _assert_clean_decompilation_output(_combined_output(second))
    # Summary should remain deterministic across repeated runs even when
    # timeout/fallback accounting changes the exact mix of lines.
    assert first_summary == second_summary
    assert any("same_family_retry_stops=" in line for line in first_summary)
    assert any("shown=2 decompiled=2 asm_or_detail_fallback=0" in line for line in first_summary)


def test_sortdemo_heapsort_anchor_no_longer_prunes_local_lane_after_repeated_empty_results():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x109D8,
        analysis_timeout=30,
        subprocess_timeout=120,
    )
    combined = result.stderr + result.stdout

    assert result.returncode in {0, 1, 4}, combined
    assert "function: 0x10970 HeapSort" in result.stdout
    assert "pruned local lane" not in result.stdout
    if result.returncode == 1:
        assert "Swaps missing argument 1" in combined
        assert "validation=passed" not in combined
        return
    scorecard = build_acceptance_scorecard(
        "HeapSort",
        result.stdout,
        source_text=render_local_source_sidecar_function(SORTDEMO_EXE, "HeapSort"),
    )
    assert scorecard.source_present is True
    assert scorecard.recovery_mode in {"asm_fallback", "decompiled"}
    assert scorecard.validation_verdict in {"changed", "stable", "unknown", "uncollected"}
    if scorecard.recovery_mode == "decompiled":
        assert "ss << 4" not in result.stdout
        assert "!(!(" not in result.stdout
        assert scorecard.raw_ss_linear_count == 0
        assert scorecard.anonymous_sub_count == 0
    else:
        assert (
            "shared-project slice full-with-refs: empty" in result.stdout
            or "Function recovery timed out; using sidecar-bounded asm fallback." in result.stdout
        )
        assert "/* == asm fallback == */" in result.stdout


def test_sortdemo_quicksort_preserves_pivot_swaps_and_recursive_calls():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10CE0,
        analysis_timeout=180,
        subprocess_timeout=300,
        extra_args=("--no-alternate-source-c", "--c-target", "portable-flat"),
        extra_env={"INERTIA_DISABLE_TIMING": "1"},
    )

    combined = _combined_output(result)

    assert result.returncode == 0, combined
    assert "Non-constant VexValue has no value property" not in combined
    assert "function: 0x10ce0 QuickSort" in result.stdout
    assert "validation=passed" in combined
    assert "Function recovery failed" not in combined
    body = _function_body_from_stdout(result.stdout, "void QuickSort")
    assert "vvar_" not in body
    assert "MK_FP(" not in body
    assert "iBreak = abarWork[iHigh].field_0;" in body
    assert body.count("Swaps(") == 3
    index_view = r"(?:\(unsigned short\))?"
    assert re.search(
        rf"Swaps\(&abarWork\[{index_view}iLow\], &abarWork\[{index_view}iHigh\]\);",
        body,
    )
    assert re.search(
        rf"Swaps\(&abarWork\[{index_view}iUp\], &abarWork\[{index_view}iDown\]\);",
        body,
    )
    assert re.search(
        rf"Swaps\(&abarWork\[{index_view}iUp\], &abarWork\[{index_view}iHigh\]\);",
        body,
    )
    assert body.count("SwapBars(") == 3
    assert re.search(r"if \(\(?(?:\(short\))?iUp - iLow\)? < \(?iHigh - (?:\(short\))?iUp\)?\)", body), "binary partition-size comparison was not preserved"
    assert len(
        re.findall(
            rf"QuickSort\({index_view}iLow, {index_view}iUp - 1\);",
            body,
        )
    ) == 2
    assert len(
        re.findall(
            rf"QuickSort\({index_view}iUp \+ 1, {index_view}iHigh\);",
            body,
        )
    ) == 2
    assert re.search(
        rf"QuickSort\({index_view}iLow, {index_view}iUp\);",
        body,
    ) is None
    assert re.search(
        rf"QuickSort\({index_view}iUp, {index_view}iHigh\);",
        body,
    ) is None
    do_body = body[body.index("do\n") :]
    first_scan_match = re.search(r"while \((?:true|1)\)", do_body)
    assert first_scan_match is not None
    first_scan = first_scan_match.start()
    assert do_body.index("iUp = iLow;") < first_scan
    assert do_body.index("iDown = iHigh;") < first_scan
    scorecard = build_acceptance_scorecard(
        "QuickSort",
        combined,
        source_text=render_local_source_sidecar_function(SORTDEMO_EXE, "QuickSort"),
    )
    assert scorecard.source_present is True
    assert scorecard.recovery_mode == "decompiled"
    assert scorecard.validation_verdict == "stable"
    assert scorecard.raw_flags_count == 0


def test_sortdemo_runmenu_typed_switch_artifacts_are_safe_and_materialized():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x102E0,
        analysis_timeout=300,
        subprocess_timeout=420,
        extra_args=("--alternate-source-c", "--c-target", "portable-flat"),
        extra_env={
            "INERTIA_DISABLE_TIMING": "1",
            "INERTIA_ENABLE_TYPED_SWITCH_AST_ARTIFACTS": "1",
        },
    )
    combined = _combined_output(result)

    assert result.returncode == 0, combined
    pre_codegen_payloads = _typed_switch_pre_codegen_seqnode_payloads(combined)
    assert pre_codegen_payloads, combined
    pre_codegen_payload = pre_codegen_payloads[-1]
    assert telemetry_integer(pre_codegen_payload, "node_count") >= 1
    assert pre_codegen_payload["switch_case_node_count"] == 1
    assert telemetry_integer(pre_codegen_payload, "condition_edge_evidence_count") >= 1
    assert pre_codegen_payload["condition_edge_block_addrs"]
    edge_summaries = pre_codegen_payload["condition_edge_summaries"]
    assert isinstance(edge_summaries, list)
    edge_switch_values = {
        summary["condition"]["rhs"]["const"]
        for summary in edge_summaries
        if summary["condition"]["op"] == "eq"
        and summary["condition"]["lhs"]["space"] == "reg"
        and summary["condition"]["lhs"]["name"] == "ax"
    }
    assert {27, 69, 72}.issubset(edge_switch_values)
    assert all(isinstance(value, int) for value in edge_switch_values)
    edge_producer_semantics = [
        summary.get("producer_semantics", ())
        for summary in edge_summaries
        if summary.get("producer_semantics")
    ]
    assert ["normalized_cmp_reg_imm16", "ax", 69, ["cmp_reg_imm16", "ax", 69]] in edge_producer_semantics
    assert pre_codegen_payload["pre_codegen_grouped_switch_artifact_count"] == 1
    assert pre_codegen_payload["pre_codegen_grouped_switch_error"] is None
    mappings = pre_codegen_payload["pre_codegen_grouped_switch_artifact_mappings"]
    assert isinstance(mappings, list)
    [mapping] = mappings
    assert mapping["expanded_root_mapped_case_count"] == 9
    assert mapping["expanded_root_normalization_ready"] is True
    assert mapping["expanded_root_normalization_status"] == "branch_splits_ready"
    assert set(mapping["expanded_root_normalized_case_region_ids"]) == {
        4177,
        4202,
        4227,
        4252,
        4277,
        4302,
        4338,
        4366,
        4408,
    }
    assert set(mapping["expanded_root_normalized_case_values"]) == {60, 62, 66, 69, 72, 73, 81, 83, 84}
    payloads = _typed_switch_replacement_safety_payloads(combined)
    assert payloads, combined
    payload = payloads[-1]
    assert telemetry_integer(payload, "attempted_count") == (
        telemetry_integer(payload, "safe_count") + telemetry_integer(payload, "refused_count")
    )
    assert payload["attempted_count"] == 0
    assert payload["status"] == "no_candidates"
    assert "clPause[" not in result.stdout
    assert "clPause >> 16" in result.stdout and "clPause & 0xffff" in result.stdout
    replacement_payloads = _typed_switch_seqnode_replacement_payloads(combined)
    assert replacement_payloads, combined
    replacement_payload = replacement_payloads[-1]
    history = replacement_payload["attempt_history"]
    assert isinstance(history, list) and history
    assert all(isinstance(record, dict) for record in history)
    successes = [record for record in history if record["changed"]]
    assert successes, history
    for success in successes:
        assert success["attempted_count"] == success["replaced_count"] == 1
        assert success["case_count"] == 9
        assert success["default_target_addr"] == 4523
        assert success["refusal_reasons"] == []
    assert history[-1]["stage"] == "pre_codegen"
    assert replacement_payload["attempted_count"] == replacement_payload["replaced_count"] == 0
    assert replacement_payload["changed"] is False
    assert replacement_payload["refusal_reasons"] == {"already_structured": 1}
    assert replacement_payload["case_runtime_segment_helper_unresolved_count"] == 0
    assert replacement_payload["case_unresolved_linear_segment_count"] == 0
    assert telemetry_integer(replacement_payload, "runtime_helper_segment_carrier_candidate_count") > 0
    assert (
        telemetry_integer(replacement_payload, "runtime_helper_segment_carrier_materialized_count")
        + telemetry_integer(replacement_payload, "runtime_helper_segment_carrier_refused_count")
        == telemetry_integer(replacement_payload, "runtime_helper_segment_carrier_candidate_count")
    )
    assert replacement_payload["runtime_helper_segment_carrier_refused_count"] == 0
    assert (
        replacement_payload["runtime_helper_sp_segment_proof_count"]
        == replacement_payload["runtime_helper_sp_offset_ss_proof_count"]
    )
    assert replacement_payload["runtime_helper_segment_replay_error"] is None
    pre_codegen_payloads = _typed_switch_pre_codegen_seqnode_payloads(combined)
    assert pre_codegen_payloads, combined
    assert pre_codegen_payloads[-1]["switch_case_node_count"] == 1
    assert "whole-tail validation clean across 1 functions" in combined
    assert "Source-backed quality guard rejected emitted C (unresolved-vvar)" not in combined
    assert "unresolved-vvar" not in combined
    assert "raw-ds-segmented-access" not in combined
    assert "raw-ss-segmented-access" not in combined


def test_sortdemo_runmenu_default_direct_path_validates_without_temp_carrier_fallback():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x102E0,
        analysis_timeout=180,
        subprocess_timeout=300,
        extra_args=("--no-alternate-source-c", "--c-target", "portable-flat"),
        extra_env={"INERTIA_DISABLE_TIMING": "1"},
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    _assert_clean_decompilation_output(combined)
    assert "function: 0x102e0 RunMenu" in result.stdout
    assert "validation=passed" in combined
    assert "Source-backed quality guard rejected" not in combined
    assert "after exhausting direct-address fallback budget" not in combined
    body = _function_body_from_stdout(result.stdout, "void RunMenu")
    assert "vvar_" not in body
    assert "switch (toupper(ch))" in body
    for case_value in (27, 60, 62, 66, 69, 72, 73, 81, 83, 84):
        assert f"case {case_value}:" in body
    assert "ch = getch();" in body
    assert "QuickSort(0, cRow);" in body
    assert "fSound = fSound < 1;" in body
    assert body.count("fSound =") == 1
    assert body.count("displaycursor(") == 2
    assert body.count("toupper(") == 1
    assert body.count("InitMenu(") == 3
    scorecard = build_acceptance_scorecard(
        "RunMenu",
        combined,
        source_text=render_local_source_sidecar_function(SORTDEMO_EXE, "RunMenu"),
    )
    assert scorecard.source_present is True
    assert scorecard.recovery_mode == "decompiled"
    assert scorecard.validation_verdict == "stable"
    assert scorecard.raw_ss_linear_count == 0


def test_sortd_runmenu_sidecar_free_preserves_binary_escape_exit(tmp_path: Path) -> None:
    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))

    result = _run_decompile_addr(
        isolated_binary,
        0x102E0,
        analysis_timeout=180,
        subprocess_timeout=300,
        extra_args=(
            "--no-alternate-source-c",
            "--ignore-local-sidecar-hints",
            "--c-target",
            "portable-flat",
        ),
        extra_env={"INERTIA_DISABLE_TIMING": "1"},
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    _assert_clean_decompilation_output(combined)
    assert "no helper metadata (.lst/.map/.cod/debug info) found" in combined
    assert "function: 0x102e0 sub_102e0" in result.stdout
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    body = _function_body_from_stdout(result.stdout, "sub_102e0(")
    assert "inertia_esp" not in body
    assert re.search(r"local_2\s*=\s*sub_11292\(\);", body)
    assert body.count("sub_11278(") == 1
    assert "sub_11278(local_2)" in body
    assert body.index("while") < body.index("sub_11278(local_2)") < body.index("case 69:")
    assert re.search(r"case 27:\s*return;", body)
    assert "LABEL_10488" not in body
    for case_value in (27, 60, 62, 66, 69, 72, 73, 81, 83, 84):
        assert f"case {case_value}:" in body


def test_initbars_getvideoconfig_far_pointer_call_has_no_stack_setup_remnants():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10554,
        extra_args=("--no-alternate-source-c", "--c-target", "portable-flat"),
        analysis_timeout=240,
        subprocess_timeout=300,
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    assert "function: 0x10560 InitBars" in combined
    assert "void InitBars(void)" in result.stdout
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "Source-backed quality guard rejected" not in combined
    body = _function_body_from_stdout(result.stdout, "void InitBars")
    assert "fSound = 1;" in body
    assert "clPause = 30;" in body
    assert "getvideoconfig(&vc);" in body
    assert body.count("ReInitBars();") == 1
    assert "vc.field_18 == 1 || vc.field_14 == 2 || !vc.field_14" in body
    assert "local_5e" not in body
    assert "local_62" not in body
    assert "local_5e != 1 || local_5e == 1 && local_62" not in body
    assert "typedef struct inertia_stack_object_22_14w2_18w2" in result.stdout
    struct_definition = "typedef struct inertia_stack_object_22_14w2_18w2"
    assert result.stdout.index(struct_definition) < result.stdout.index("void InitBars(void)")
    assert "int getvideoconfig(void *config);" in result.stdout
    assert "int rand(void);" in result.stdout
    assert "void srand(unsigned int seed);" in result.stdout
    assert "time_t time(time_t *out);" in result.stdout
    assert "extern unsigned short a0;" not in result.stdout
    assert "extern unsigned short inertia_stack_object_22_14w2_18w2;" not in result.stdout
    assert "vvar_51" not in body
    assert "vvar_53" not in body
    assert "SEG_U8(" not in body
    assert "_INSERT(" not in body
    assert "7860();" not in body
    assert "sub_1eb4();" not in body
    assert body.count("rand()") == 1
    assert "unsigned short aTemp[43]" in body
    assert "aTemp[iRow] = iRow + 1;" in body
    assert "iRowMax = cRow - 1;" in body
    assert "iLength = aTemp[iRand];" in body
    assert "abarPerm[iRow].field_0 = iLength;" in body
    assert "abarPerm[iRow].field_1 = (short)iLength % (short)iColorMax + 1;" in body
    assert "local_73" not in body
    assert body.count("for (iRow = 0; cRow > iRow;") == 2
    aggregate_copy = "aTemp[iRand] = aTemp[iRowMax];"
    aggregate_update = "iRowMax -= 1;"
    assert aggregate_copy in body
    assert aggregate_update in body
    assert body.index(aggregate_copy) < body.index(aggregate_update)


@pytest.mark.xdist_group("sortd-initmenu")
def test_initmenu_pause_zero_guard_has_no_raw_flag_carrier(tmp_path):
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10060,
        extra_args=("--c-target", "portable-flat", "--no-alternate-source-c"),
        analysis_timeout=150,
        subprocess_timeout=300,
        extra_env={"INERTIA_DISABLE_TIMING": "1"},
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    _assert_clean_decompilation_output(combined)
    assert "function: 0x10060 InitMenu" in result.stdout
    assert "validation=passed" in combined or "whole-tail validation clean across 1 functions" in combined
    assert "unary-not shift precedence leaked" not in combined
    assert "Source-backed quality guard rejected" not in combined
    assert "Decompilation empty" not in combined
    assert "asm fallback" not in combined
    assert "gcc portable-flat syntax check failed:" not in combined
    assert "int32_t setbkcolor(int32_t color);" in result.stdout
    assert "int sprintf(char *buf, const char *fmt, ...);" in result.stdout
    assert "void InitMenu" in result.stdout
    body = _function_body_from_stdout(result.stdout, "void InitMenu")
    tail_after_pause_text = body.rsplit('strcpy(ach, "            ");', 1)[-1]
    assert "vvar_" not in body
    assert "SEG_U" not in body
    assert "&ach" not in body
    assert "char ach[16]" in body
    assert body.count("settextcolor(15);") == 1
    assert 'strcpy(ach, "ON ");' in body
    assert 'strcpy(ach, "OFF");' in body
    assert 'strcpy(ach, "            ");' in body
    assert "if (i >= cszMenu)" not in body
    iterator_lines = tuple(line.strip() for line in body.splitlines() if line.lstrip().startswith("for ("))
    # An unsigned declaration needs the binary's signed comparison conversion.
    comparison_index = "(short)i" if "unsigned short i;" in body else "i"
    assert iterator_lines == (f"for (i = 0; {comparison_index} < cszMenu; i += 1)",)
    assert "DrawFrame(1, 45, 35, cszMenu + 2);" in body
    assert "settextposition(i + 2, 48);" in body
    assert "outtext(aszMenu[i]);" in body
    assert 'sprintf(ach, "%3.3u", aNldiv(clPause, 30));' in body
    assert "& 64" not in tail_after_pause_text
    assert "SEG_U" not in tail_after_pause_text
    zero_output = r"settextposition\(cszMenu - 3, 48\);\s*outtext\(ach\);"
    assert re.search(
        rf"if \(!clPause\)\s*\{{\s*{zero_output}\s*\}}|"
        rf"if \(clPause\)\s*\{{\s*return;\s*\}}\s*{zero_output}\s*return;",
        tail_after_pause_text,
    )
    assert "outtext(ach);" in tail_after_pause_text
    assert_initmenu_pause_guard_behavior(body, tmp_path)


def test_drawframe_stack_array_and_memset_calls_survive_regeneration():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x101F0,
        extra_args=("--alternate-source-c", "--c-target", "portable-flat"),
        analysis_timeout=120,
        subprocess_timeout=300,
        extra_env={"INERTIA_DISABLE_TIMING": "1"},
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    assert "function: 0x101f0 DrawFrame" in result.stdout
    assert "validation=passed" in combined
    compile_result = check_c_recompiles_8616(result.stdout)
    assert compile_result.passed, compile_result.stderr
    assert "Source-backed quality guard rejected" not in combined
    body = _function_body_from_stdout(result.stdout, "void DrawFrame")
    assert "char achTmp[80];" in body
    assert "unsigned short iRow;" in body
    assert "unsigned long iRow;" not in body
    assert "iRow = iTop + 1;" in body
    assert len(re.findall(r"memset\(achTmp, 205, (?:\(unsigned short\))?iWidth\);", body)) == 2
    assert len(re.findall(r"memset\(achTmp, 32, (?:\(unsigned short\))?iWidth\);", body)) == 1
    assert "memset(&achTmp" not in body
    assert re.search(r"settextposition\((?:\(unsigned short\))?iTop, (?:\(unsigned short\))?iLeft\);", body)
    assert body.count("outtext(achTmp);") == 3
    assert "outtext(&achTmp);" not in body
    assert "void * memset(void *dst, int value, unsigned short count);" in result.stdout
    assert "void * memset(char a0[80], unsigned short a1, unsigned short a2);" not in result.stdout
    assert "void outtext(char *a0);" in result.stdout
    assert "void outtext(char a0[80]);" not in result.stdout
    assert "SEG_PTR(ds" not in body
    assert "unsigned short achTmp;" not in body


def test_beep_direct_path_validates_without_high_byte_contract_fallback():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10E70,
        extra_args=("--alternate-source-c", "--c-target", "portable-flat"),
        analysis_timeout=90,
        subprocess_timeout=180,
        extra_env={"INERTIA_DISABLE_TIMING": "1"},
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    assert "function: 0x10e70 Beep" in result.stdout
    assert "validation=passed" in combined or "whole-tail validation clean across 1 functions" in combined
    assert "stack_arg_high_byte_projection" not in combined
    assert "Decompilation empty" not in combined
    assert "asm fallback" not in combined
    assert "sidecar slice fallback" not in combined
    assert "direct failure family: status=ok" in combined
    assert "Sleep(duration);" in result.stdout
    assert "Sleep(duration," not in result.stdout
    assert result.stdout.count("if (frequency)") in {1, 2}
    first_guard = result.stdout.index("if (frequency)")
    control_definition = result.stdout.index("control = inp(97);")
    sleep_call = result.stdout.index("Sleep(duration);")
    control_read = result.stdout.index("outp(97, control);")
    if result.stdout.count("if (frequency)") == 2:
        second_guard = result.stdout.index("if (frequency)", first_guard + 1)
        assert first_guard < control_definition < sleep_call < second_guard < control_read
    else:
        zero_guard = result.stdout.index("if (!frequency)", first_guard + 1)
        assert re.search(r"if \(!frequency\)\s*(?:return(?: 0)?;|\{\s*return(?: 0)?;\s*\})", result.stdout)
        assert first_guard < control_definition < sleep_call < zero_guard < control_read
    assert re.search(r"(?m)^(?:void|int|unsigned short) Sleep\((?:(?:unsigned )?long|clock_t) \w+\);$", result.stdout)
    scorecard = build_acceptance_scorecard(
        "Beep",
        combined,
        source_text=render_local_source_sidecar_function(SORTDEMO_EXE, "Beep"),
    )
    assert scorecard.source_present is True
    assert scorecard.recovery_mode == "decompiled"
    assert scorecard.validation_verdict == "stable"
    assert scorecard.raw_ss_linear_count == 0


def test_insertionsort_word_stores_materialized_without_raw_high_byte_memory():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x107E7,
        extra_args=("--alternate-source-c", "--c-target", "portable-flat"),
        analysis_timeout=60,
        subprocess_timeout=180,
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    _assert_clean_decompilation_output(combined)
    assert "function: 0x10808 InsertionSort" in result.stdout
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "Source-backed quality guard rejected" not in combined
    if "void InsertionSort" in result.stdout:
        body = _function_body_from_stdout(result.stdout, "void InsertionSort")
    else:
        body = _function_body_from_stdout(result.stdout, "short InsertionSort")
    assert "barTemp = abarWork[" in body
    assert "iLength = (signed char)barTemp.field_0;" in body
    assert "iLength = (char)barTemp;" not in body
    assert "iRowTmp = iRow;" in body
    assert body.index("for (") < body.index("iRowTmp = iRow;")
    assert body.index("iRowTmp = iRow;") < body.index("iCompares += 1;")
    guard = re.search(
        r"if \(\s*abarWork\[(?:iRowTmp|local_4) - 1\]\.field_0 <= \(short\)iLength\s*\)"
        r"\s*break;",
        body,
    )
    assert guard is not None, body
    assert ("abarWork[iRowTmp] = abarWork[iRowTmp - 1];" in body) or (
        "abarWork[local_4] = abarWork[local_4 - 1];" in body
    )
    assert guard.end() < body.index("iSwaps += 1;")
    assert ("abarWork[iRowTmp] = barTemp;" in body) or ("abarWork[local_4] = barTemp;" in body)
    assert re.search(r"DrawBar\((?:\(unsigned short\))?(?:iRowTmp|local_4)\);", body)
    assert re.search(r"DrawTime\((?:\(unsigned short\))?(?:iRowTmp|local_4)\);", body)
    assert "mem_0B4D" not in body
    assert "MEM_U8(" not in body
    assert "SEG_U8(" not in body
    assert "SEG_U16(" not in body
    assert "*(&" not in body


def test_drawbar_word_stride_byte_fields_validate_without_indexed_mem_helper_syntax() -> None:
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x106C8,
        extra_args=("--c-target", "portable-flat"),
        analysis_timeout=60,
        subprocess_timeout=120,
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    assert "function: 0x106c8 DrawBar" in result.stdout
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert re.search(r"\b(?:void|(?:unsigned )?short) DrawBar\(", result.stdout) is not None
    assert "asm fallback" not in combined.lower()
    assert "sidecar slice fallback" not in combined.lower()
    assert "non-optimized fallback" not in combined.lower()
    assert "extern unsigned short g_0BA2;" in result.stdout or "extern unsigned short cRow;" in result.stdout
    final_body = _function_body_from_stdout(result.stdout, "DrawBar(unsigned short iRow)")
    assert "char achT[44];" in final_body
    assert "abarWork[iRow].field_0" in final_body or "abarWork[iRow] & 255" in final_body
    assert "abarWork[iRow].field_1" in final_body or "abarWork[iRow] >> 8 & 255" in final_body
    assert (
        "memset(achT, 223, abarWork[iRow].field_0);" in final_body
        or "memset(achT, 223, abarWork[iRow] & 255);" in final_body
    )
    assert (
        "memset(achT + abarWork[iRow].field_0, 32," in final_body
        or "memset(achT + (abarWork[iRow] & 255), 32," in final_body
    )
    assert re.search(r"\bachT\[(?:g_0BA2|cRow)\]\s*=\s*0;", final_body) is not None
    assert "settextcolor(" in final_body
    assert "settextposition(" in final_body
    assert "outtext(achT);" in final_body
    assert "&achT" not in final_body
    assert "void * memset(void *dst, int value, unsigned short count);" in result.stdout
    assert "local_2" not in final_body
    assert "dst =" not in final_body
    assert "return 0;" in final_body or "return;" in final_body
    assert "memset(&iRow" not in final_body
    assert "memset(iRow +" not in final_body
    assert "MEM_U8(&abarWork[iRow))]" not in final_body
    assert "SEG_U8(ds" not in final_body
    assert "SEG_PTR(ds" not in final_body


def test_percolatedown_direct_global_increment_materialized():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10A61,
        extra_args=("--c-target", "portable-flat", "--no-alternate-source-c"),
        analysis_timeout=120,
        subprocess_timeout=360,
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    assert "function: 0x10a88 PercolateDown" in result.stdout
    assert "validation=passed" in combined
    if "void PercolateDown" in result.stdout:
        final_body = _function_body_from_stdout(result.stdout, "void PercolateDown")
    else:
        final_body = _function_body_from_stdout(result.stdout, "unsigned short PercolateDown")
    assert final_body.count("iCompares += 1;") == 2
    assert re.search(
        r"(?:Swaps|sub_107b8)\([^;]+;\s*(?:SwapBars|sub_10768)\([^;]+;"
        r"\s*(?:local_2 = local_4|i = iChild);",
        final_body,
    )
    assert "mem_0BAA" not in final_body
    assert "mem_0BAB" not in final_body
    assert "SEG_U" not in final_body
    assert "SEG_PTR" not in final_body
