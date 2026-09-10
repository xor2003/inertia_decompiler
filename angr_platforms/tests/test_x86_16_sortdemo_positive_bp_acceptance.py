from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

from scripts.check_sortd_sidecar_free import mz_executable_image

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "decompile.py"
SORTDEMO_EXE = REPO_ROOT / "SORTDEMO.EXE"


def _run_sidecar_free_function(tmp_path: Path, address: int) -> subprocess.CompletedProcess[str]:
    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))
    env = dict(os.environ)
    env.setdefault("INERTIA_ENABLE_TAIL_VALIDATION", "1")
    env["INERTIA_DISABLE_TIMING"] = "1"
    return subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(isolated_binary),
            "--addr",
            hex(address),
            "--timeout",
            "90",
            "--no-alternate-source-c",
            "--c-target",
            "portable-flat",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=180,
        check=False,
    )


def test_sortd_beep_sidecar_free_materializes_both_value_arguments(tmp_path: Path) -> None:
    result = _run_sidecar_free_function(tmp_path, 0x10E70)
    combined = f"{result.stderr}{result.stdout}"
    assert result.returncode == 0, combined
    assert "no helper metadata (.lst/.map/.cod/debug info) found" in combined
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "gcc syntax check failed:" not in combined
    signature = re.search(
        r"void sub_10e70\((?:unsigned )?short (\w+), (?:unsigned )?short (\w+)\)",
        result.stdout,
    )
    assert signature is not None, combined
    frequency, duration = signature.groups()
    assert f"if ({duration} < 75)" in result.stdout
    assert f"sub_10f38({duration});" in result.stdout
    assert re.search(rf"aNldiv\([^;]*\b{frequency}\b[^;]*\);", result.stdout)
    assert "sub_1143a(" not in result.stdout
    assert "[bp+0x4]" not in result.stdout
    assert "[bp+0x6]" not in result.stdout
    assert "local_4" not in result.stdout
    assert "local_6" not in result.stdout


def test_sortd_drawbar_uses_binary_proven_void_callee_contracts(tmp_path: Path) -> None:
    result = _run_sidecar_free_function(tmp_path, 0x10768)
    combined = f"{result.stderr}{result.stdout}"

    assert result.returncode == 0, combined
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "gcc syntax check failed:" not in combined
    assert re.search(r"\bvoid sub_10498\(unsigned short \w+\);", result.stdout)
    assert re.search(r"\bvoid sub_106c8\(unsigned short \w+\);", result.stdout)
    assert "int sub_10498(" not in result.stdout
    assert "int sub_106c8(" not in result.stdout


def test_sortd_drawtime_proves_forwarded_wide_runtime_return(tmp_path: Path) -> None:
    result = _run_sidecar_free_function(tmp_path, 0x10498)
    combined = f"{result.stderr}{result.stdout}"

    assert result.returncode == 0, combined
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "gcc syntax check failed:" not in combined
    assert "int32_t aNldiv(int32_t dividend, int32_t divisor);" in result.stdout
    assert "unsigned long sub_12b24(" not in result.stdout
    assert re.search(r"sub_112ba\([^;]*aNldiv\([^;]+\)[^;]*, g_0BA4, g_0BAA\);", result.stdout)
    signature = re.search(r"void sub_10498\(unsigned short (\w+)\)", result.stdout)
    assert signature is not None, combined
    assert re.search(
        rf"sub_10e70\(\s*(?:\(unsigned short\)\s*)?{re.escape(signature.group(1))}\s*\*\s*60\s*,\s*75\s*\);",
        result.stdout,
    )
    assert not re.search(r"(?m)^\s+aNldiv\(", result.stdout)
    assert not re.search(r"\b(?:unsupported|unknown)\s+instruction\b", result.stdout, re.IGNORECASE)
    assert not re.search(r"\b(?:e?flags|cc_op|cc_dep[12]?)\b", result.stdout, re.IGNORECASE)
    assert not re.search(r"\bif\s*\([^{};]*\)\s*\{\s*\}\s*else\s*\{\s*\}", result.stdout)
    assert not re.search(r"\binertia_ss\s*<<\s*4\b", result.stdout)


def test_sortd_shellsort_uses_alias_proven_zero_argument_interface(tmp_path: Path) -> None:
    result = _run_sidecar_free_function(tmp_path, 0x10C18)
    combined = f"{result.stderr}{result.stdout}"

    assert result.returncode == 0, combined
    assert "no helper metadata (.lst/.map/.cod/debug info) found" in combined
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "gcc syntax check failed:" not in combined
    assert "void sub_10c18(void)" in result.stdout
    assert re.search(r"sub_107b8\(&g_0B4C\[[^;]+\], &g_0B4C\[[^;]+\]\);", result.stdout)
    assert re.search(r"sub_10768\([^;]+, [^;]+\);", result.stdout)
    assert "[bp+0x4]" not in result.stdout
