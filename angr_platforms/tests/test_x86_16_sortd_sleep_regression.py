"""Executable-only regression for the SORTD Sleep function."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

from x86_16_sleep_behavior import SLEEP_REGISTER_STATE_PRELUDE, assert_sleep_behavior

from scripts.check_sortd_sidecar_free import mz_executable_image

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "decompile.py"
SORTDEMO_EXE = REPO_ROOT / "SORTDEMO.EXE"
EXPECTED_CLOCK_SITES = 2


def test_sortd_sleep_preserves_both_wide_clock_calls_sidecar_free(
    tmp_path: Path,
) -> None:
    """Require canonical calls, typed wide comparison, validation, and C."""
    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))
    env = dict(os.environ)
    env.update(INERTIA_DISABLE_TIMING="1", INERTIA_ENABLE_TAIL_VALIDATION="1")

    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(isolated_binary),
            "--addr",
            "0x10f38",
            "--timeout",
            "120",
            "--ignore-local-sidecar-hints",
            "--no-alternate-source-c",
            "--window",
            "0x80",
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

    combined = result.stdout + result.stderr
    assert result.returncode == 0, combined
    assert "no helper metadata (.lst/.map/.cod/debug info) found" in combined
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "gcc syntax check failed:" not in combined
    signature = re.search(r"void sub_10f38\(([^()]*)\)", result.stdout)
    assert signature is not None, result.stdout
    parameters = tuple(parameter.strip() for parameter in signature.group(1).split(",") if parameter.strip())
    assert len(parameters) == 1, signature.group(0)
    assert "long" in parameters[0]
    function_start = result.stdout.rfind(signature.group(0))
    assert function_start >= 0
    body = result.stdout[function_start:]
    assert body.count("sub_1137e()") == EXPECTED_CLOCK_SITES
    assert "local_4 = sub_1137e() +" in body
    assert_sleep_behavior(result.stdout, tmp_path, harness_prelude=(
        "#define Sleep sub_10f38\n#define clock sub_1137e\n#define clock_t unsigned long\n"
        + SLEEP_REGISTER_STATE_PRELUDE
    ))
    assert "sub_137e" not in combined
    # Saved SI/DI bytes are legitimate locals; test their ABI effect above
    # instead of banning a name that previously denoted a stale clock word.
    assert "vvar_" not in body
    assert "stack_base" not in body
    assert "flags" not in body
