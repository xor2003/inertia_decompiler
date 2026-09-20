from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

from x86_16_heapsort_behavior import assert_heapsort_behavior
from x86_16_timeout_support import scaled_decompile_timeout as _scaled_timeout

from scripts.check_sortd_sidecar_free import mz_executable_image
from scripts.generated_c_contracts import (
    BranchBodyEffectsRequirement,
    GeneratedCContract,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "decompile.py"
SORTDEMO_EXE = REPO_ROOT / "SORTDEMO.EXE"


def _run_decompile_addr(
    path: Path,
    addr: int,
    *,
    analysis_timeout: int = 12,
    subprocess_timeout: int = 120,
    extra_args: tuple[str, ...] = (),
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.setdefault("INERTIA_ENABLE_TAIL_VALIDATION", "1")
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


def test_sortdemo_heapsort_uses_widened_word_access_for_crow_anchor(tmp_path: Path) -> None:
    result = _run_decompile_addr(SORTDEMO_EXE, 0x10970, analysis_timeout=30, subprocess_timeout=120)

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x10970 HeapSort" in result.stdout
    assert "whole-tail validation clean" in f"{result.stderr}{result.stdout}"
    assert "| ir_" not in result.stdout
    assert "validation=passed" in result.stderr + result.stdout
    assert_heapsort_behavior(result.stdout, tmp_path, named=True)
    assert "SEG_PTR(ds" not in result.stdout


def test_sortd_heapsort_sidecar_free_accepts_typed_segment_live_in(tmp_path: Path) -> None:
    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))

    result = _run_decompile_addr(
        isolated_binary,
        0x10970,
        analysis_timeout=60,
        subprocess_timeout=120,
        extra_args=("--ignore-local-sidecar-hints", "--c-target", "portable-flat"),
    )

    combined = result.stderr + result.stdout
    assert result.returncode == 0, combined
    assert "function: 0x10970 sub_10970" in result.stdout
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "uninitialized-read:segment-carrier" not in combined
    assert_heapsort_behavior(result.stdout, tmp_path)
    assert "SEG_PTR(inertia_ds, 2892)" not in result.stdout
    assert re.search(r"^\s+sub_1075b\(", result.stdout, re.MULTILINE) is None


def test_sortd_shellsort_sidecar_free_accepts_typed_segment_live_in(tmp_path: Path) -> None:
    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))

    result = _run_decompile_addr(
        isolated_binary,
        0x10C18,
        analysis_timeout=60,
        subprocess_timeout=120,
        extra_args=("--ignore-local-sidecar-hints", "--c-target", "portable-flat"),
    )

    combined = result.stderr + result.stdout
    assert result.returncode == 0, combined
    assert "function: 0x10c18 sub_10c18" in result.stdout
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "uninitialized-read:segment-carrier" not in combined
    # The source initializes iOffset before its loop.  Require that dataflow,
    # while allowing Structuring to spell the loop itself as ``for`` or ``while``.
    offset_loop = re.search(
        r"local_2 = \(short\)g_0BA2 / 2;\s+(?:for \(; local_2; \)|while \(local_2\))",
        result.stdout,
    )
    assert offset_loop is not None, result.stdout
    assert "SEG_U16(inertia_ds, 2978)" not in result.stdout
    assert re.search(
        r"sub_107b8\(&g_0B4C\[(?:\(unsigned short\))?local_4\], "
        r"&g_0B4C\[(?:\(unsigned short\))?local_4 \+ "
        r"(?:\(unsigned short\))?local_2\]\);",
        result.stdout,
    )
    assert re.search(
        r"sub_10768\(local_4, (?:\(unsigned short\))?local_4 \+ "
        r"(?:\(unsigned short\))?local_2\);",
        result.stdout,
    )
    assert "while (local_8);" in result.stdout
    assert "while (local_6);" not in result.stdout
    generated_c_marker = "/* == c == */"
    assert generated_c_marker in result.stdout
    generated_c = result.stdout.split(generated_c_marker, 1)[1]
    contract = GeneratedCContract(
        required_fragments=(
            "(signed char)g_0B4C[local_4 + local_2].field_0 < "
            "(signed char)g_0B4C[local_4].field_0",
        ),
        forbidden_fragments=("g_0B4C[local_4 + local_4]",),
        branch_body_effects=(
            BranchBodyEffectsRequirement(
                function_name="sub_10c18",
                required_calls=("sub_107b8", "sub_10768"),
                assignment_name="local_8",
                assignment_source_name="local_4",
            ),
        ),
    )
    contract_result = contract.assess(generated_c)
    assert contract_result.passed, contract_result.to_json()


def test_sortd_swaps_sidecar_free_materializes_aggregate_interface(
    tmp_path: Path,
) -> None:
    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))

    result = _run_decompile_addr(
        isolated_binary,
        0x107B8,
        analysis_timeout=60,
        subprocess_timeout=120,
        extra_args=(
            "--ignore-local-sidecar-hints",
            "--c-target",
            "portable-flat",
            "--no-alternate-source-c",
            "--window",
            "0x50",
        ),
    )

    combined = result.stderr + result.stdout
    assert result.returncode == 0, combined
    assert "function: 0x107b8 sub_107b8" in result.stdout
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "typedef struct g_08F0_entry" in result.stdout
    # Sidecar-free parameter names remain storage-derived. Source-like
    # ``left``/``right`` names were a legacy postprocess guess, not evidence.
    assert (
        "void sub_107b8(g_08F0_entry *arg_4, g_08F0_entry *arg_6)"
        in result.stdout
    )
    assert "g_08F0_entry local_2;" in result.stdout
    assert "g_0BA4 += 1;" in result.stdout
    assert "local_2 = arg_4[0];" in result.stdout
    assert "arg_4[0] = arg_6[0];" in result.stdout
    assert "arg_6[0] = local_2;" in result.stdout
    assert "return;" in result.stdout
    assert "short sub_107b8" not in result.stdout
    assert "return 0;" not in result.stdout
    assert "unsigned short *left" not in result.stdout
    assert "validation_failed" not in combined


def test_sortd_swaps_caller_uses_one_proven_aggregate_family(
    tmp_path: Path,
) -> None:
    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))

    result = _run_decompile_addr(
        isolated_binary,
        0x108D0,
        analysis_timeout=60,
        subprocess_timeout=120,
        extra_args=(
            "--ignore-local-sidecar-hints",
            "--c-target",
            "portable-flat",
            "--no-alternate-source-c",
        ),
    )

    combined = result.stderr + result.stdout
    assert result.returncode == 0, combined
    assert "function: 0x108d0 sub_108d0" in result.stdout
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    # SORTDEMO.C declares Swaps as void and every caller uses it for side
    # effects only.  A raw AX value left by the binary is not a value-return
    # contract, so the generated aggregate interface must remain void.
    assert (
        "void sub_107b8(struct g_08F0_entry *a0, struct g_08F0_entry *a1);"
        in result.stdout
    )
    assert "int sub_107b8" not in result.stdout
    assert "extern g_08F0_entry g_0B4C[];" in result.stdout
    assert re.search(
        r"sub_107b8\(&g_0B4C\[(?:\(unsigned short\))?local_2\], "
        r"&g_0B4C\[(?:\(unsigned short\))?local_2 \+ 1\]\);",
        result.stdout,
    )
    assert "g_0B4E" not in result.stdout


def test_sortd_percolate_down_uses_canonical_shifted_global_view(
    tmp_path: Path,
) -> None:
    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))

    result = _run_decompile_addr(
        isolated_binary,
        0x10A88,
        analysis_timeout=60,
        subprocess_timeout=120,
        extra_args=(
            "--ignore-local-sidecar-hints",
            "--c-target",
            "portable-flat",
            "--no-alternate-source-c",
        ),
    )

    combined = result.stderr + result.stdout
    assert result.returncode == 0, combined
    assert "function: 0x10a88 sub_10a88" in result.stdout
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "extern g_08F0_entry g_0B4C[];" in result.stdout
    signature = re.search(r"void sub_10a88\(short (?P<bound>[A-Za-z_]\w*)\)", result.stdout)
    assert signature is not None, result.stdout
    bound = signature.group("bound")
    assert re.search(
        rf"if \(\(short\)\(\(short\)local_4 \+ 1\) <= {re.escape(bound)}\)",
        result.stdout,
    )
    assert f"if ((short)local_4 > {bound})" in result.stdout
    assert (
        "(signed char)g_0B4C[local_4 + 1].field_0 > "
        "(signed char)g_0B4C[local_4].field_0"
        in result.stdout
    )
    assert re.search(
        r"sub_107b8\(&g_0B4C\[(?:\(unsigned short\))?local_2\], "
        r"&g_0B4C\[(?:\(unsigned short\))?local_4\]\);",
        result.stdout,
    )
    assert "g_0B4E" not in result.stdout


def test_sortd_percolate_up_sidecar_free_preserves_heap_updates_and_compiles(
    tmp_path: Path,
) -> None:
    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))

    result = _run_decompile_addr(
        isolated_binary,
        0x109E8,
        analysis_timeout=60,
        subprocess_timeout=120,
        extra_args=(
            "--ignore-local-sidecar-hints",
            "--c-target",
            "portable-flat",
            "--no-alternate-source-c",
        ),
    )

    combined = result.stderr + result.stdout
    assert result.returncode == 0, combined
    assert "function: 0x109e8 sub_109e8" in result.stdout
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "g_0BAA += 1;" in result.stdout
    assert "g_0B4C[local_4].field_0 <= g_0B4C[local_2].field_0" in result.stdout
    assert re.search(
        r"sub_107b8\(&g_0B4C\[(?:\(unsigned short\))?local_2\], "
        r"&g_0B4C\[(?:\(unsigned short\))?local_4\]\);",
        result.stdout,
    )
    assert "sub_10768(local_2, local_4);" in result.stdout
    assert "vvar_" not in result.stdout
    assert "stack_base" not in result.stdout
    assert "ir_" not in result.stdout
