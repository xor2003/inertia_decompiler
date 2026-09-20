from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from scripts.check_sortd_sidecar_free import mz_executable_image

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "decompile.py"
SORTD_EXE = REPO_ROOT / "SORTD.EXE"


def test_sortd_indexed_aggregate_load_and_store_recompile_sidecar_free(
    tmp_path: Path,
) -> None:
    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTD_EXE.read_bytes()))
    env = dict(os.environ)
    env.update(
        {
            "INERTIA_DISABLE_TIMING": "1",
            "INERTIA_ENABLE_TAIL_VALIDATION": "1",
        }
    )

    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(isolated_binary),
            "--addr",
            "0x10808",
            "--timeout",
            "120",
            "--ignore-local-sidecar-hints",
            "--no-alternate-source-c",
            "--window",
            "0xc8",
            "--c-target",
            "portable-flat",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=240,
        check=False,
    )

    combined = f"{result.stdout}\n{result.stderr}"
    assert result.returncode == 0, combined
    assert "no helper metadata (.lst/.map/.cod/debug info) found" in combined
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "gcc portable-flat syntax check failed:" not in combined
    assert "g_08F0_entry local_8;" in result.stdout
    assert "local_8 = g_0B4C[local_2];" in result.stdout
    assert "local_6 = (signed char)local_8.field_0;" in result.stdout
    assert "g_0B4C[local_4] = g_0B4C[local_4 - 1];" in result.stdout
    assert "g_0B4C[local_4] = local_8;" in result.stdout
    assert sum(
        result.stdout.count(f"sub_106c8({cast}local_4);")
        for cast in ("", "(unsigned short)")
    ) == 2
    assert sum(
        result.stdout.count(f"sub_10498({cast}local_4);")
        for cast in ("", "(unsigned short)")
    ) == 2
