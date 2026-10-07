from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_typed_condition_then_jcc_order_regression_stays_idempotent():
    """Run the real order that exposed JCC rematerialization drift."""

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "tests/postprocess/test_x86_16_decompiler_postprocess_typed_conditions.py",
            "tests/postprocess/test_x86_16_decompiler_postprocess_jcc.py",
        ],
        cwd=REPO_ROOT,
        check=False,
        stderr=subprocess.STDOUT,
        stdout=subprocess.PIPE,
        text=True,
    )

    assert completed.returncode == 0, completed.stdout
