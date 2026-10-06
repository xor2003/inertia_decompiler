from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SORT_PATTERNS_EXE = REPO_ROOT / "examples" / "build_msc6" / "SORTPAT.EXE"
CLI_PATH = REPO_ROOT / "decompile.py"


def _decompile_sort_pattern(function_name: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.setdefault("INERTIA_ENABLE_TAIL_VALIDATION", "1")
    return subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "--alternate-source-c",
            "--proc",
            function_name,
            "--proc-kind",
            "NEAR",
            "--timeout",
            "60",
            str(SORT_PATTERNS_EXE),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=90,
        check=False,
    )


@pytest.mark.requires_kvm
@pytest.mark.skipif(
    not SORT_PATTERNS_EXE.is_file(),
    reason="SORTPAT MS C example binary is not available in this workspace.",
)
def test_msc6_sortdemo_global_pair_sum_joins_split_word_load() -> None:
    result = _decompile_sort_pattern("sortdemo_global_pair_sum")
    combined = f"{result.stderr}\n{result.stdout}"

    assert result.returncode == 0, combined
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined
    assert re.search(
        r"return (?:g_work\[0\] \+ g_work\[5\]|g_work\[5\] \+ g_work\[0\]);",
        combined,
    )
    assert not re.search(r"\+ g_work;", combined)


@pytest.mark.requires_kvm
@pytest.mark.skipif(
    not SORT_PATTERNS_EXE.is_file(),
    reason="SORTPAT MS C example binary is not available in this workspace.",
)
def test_msc6_sortdemo_single_pass_swap_rejects_wrapped_local_arguments() -> None:
    result = _decompile_sort_pattern("sortdemo_single_pass_swap")
    combined = f"{result.stderr}\n{result.stdout}"

    assert result.returncode == 0, combined
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined
    assert "short sortdemo_single_pass_swap(void)" in combined
    assert "for (i = 1; i < g_rows; i = i + 1)" in combined
    assert "if (g_work[i - 1] > g_work[i])" in combined
    assert "g_work[i - 1] = g_work[i];" in combined
    assert "g_work[i] = tmp;" in combined
    assert "changed = 1;" in combined
    assert re.search(
        r"return (?:g_work\[5\] \+ g_work\[0\] \+ changed|changed \+ g_work\[0\] \+ g_work\[5\]);",
        combined,
    )
    assert not re.search(r"\b(?:v8|v9|v10|arg)\b", combined)


@pytest.mark.requires_kvm
@pytest.mark.skipif(
    not SORT_PATTERNS_EXE.is_file(),
    reason="SORTPAT MS C example binary is not available in this workspace.",
)
def test_msc6_sortdemo_exchange_sort_keeps_indexed_word_condition() -> None:
    result = _decompile_sort_pattern("sortdemo_exchange_sort")
    combined = f"{result.stderr}\n{result.stdout}"
    function_text = combined.rsplit("short sortdemo_exchange_sort(void)", maxsplit=1)[-1]

    assert result.returncode == 0, combined
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined
    assert "short sortdemo_exchange_sort(void)" in combined
    assert re.search(
        r"if \(g_demo_len\[iRowMin\] > g_demo_len\[iRowNext\]\)",
        combined,
    )
    assert "iRowMin = iRowNext;" in combined
    assert "DrawTime(iRowNext);" in combined
    assert "Swaps(&g_demo_len[iRowCur], &g_demo_len[iRowMin]);" in combined
    assert "SwapBars(iRowCur, iRowMin);" in combined
    assert not re.search(r"\b(?:flags|v13|v14|v15|SEG_U16)\b", function_text)


@pytest.mark.requires_kvm
@pytest.mark.skipif(
    not SORT_PATTERNS_EXE.is_file(),
    reason="SORTPAT MS C example binary is not available in this workspace.",
)
def test_msc6_sortdemo_heap_percolate_up_keeps_loop_tail_dependency() -> None:
    result = _decompile_sort_pattern("sortdemo_heap_percolate_up")
    combined = f"{result.stderr}\n{result.stdout}"

    assert result.returncode == 0, combined
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined
    assert re.search(
        r"void sortdemo_heap_percolate_up\((?:unsigned )?short max_level\)",
        combined,
    )
    assert "for (i = max_level; i; )" in combined
    assert "parent = (short)i / 2;" in combined
    condition = "if (g_demo_len[parent] < g_demo_len[i])"
    assert condition in combined
    assert "Swaps(&g_demo_len[i], &g_demo_len[parent]);" in combined
    assert "SwapBars(i, parent);" in combined
    assert combined.index(condition) < combined.index("i = parent;", combined.index(condition))
    assert "g_demo_len[parent] < g_demo_len[parent]" not in combined
    assert not re.search(r"\b(?:ax|local_2)\b", combined)
