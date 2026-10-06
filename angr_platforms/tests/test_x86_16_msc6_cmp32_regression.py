from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "msc6" / "compare32"
CMP32_EXE = FIXTURE_ROOT / "COMP32.EXE"
CLI_PATH = REPO_ROOT / "decompile.py"


@pytest.mark.parametrize("artifact", ("COMP32.C", "COMP32.EXE", "COMP32.COD", "COMP32.MAP"))
def test_compare32_fixture_identity(artifact: str) -> None:
    """Keep fixed-address regression inputs independent of local build outputs."""
    expected = json.loads((FIXTURE_ROOT / "sha256.json").read_text(encoding="utf-8"))
    assert hashlib.sha256((FIXTURE_ROOT / artifact).read_bytes()).hexdigest() == expected[artifact]


@pytest.mark.requires_kvm
@pytest.mark.parametrize(
    ("address", "argument_type"),
    ((0x1004E, "long"), (0x100C3, "unsigned long")),
)
def test_msc6_compare_functions_sidecar_free_preserve_scalar_types(
    tmp_path: Path,
    address: int,
    argument_type: str,
) -> None:
    isolated_exe = tmp_path / "CMP32_NO_SIDECARS.EXE"
    shutil.copyfile(CMP32_EXE, isolated_exe)
    env = dict(os.environ)
    env.setdefault("INERTIA_ENABLE_TAIL_VALIDATION", "1")
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "--no-alternate-source-c",
            "--addr",
            hex(address),
            "--window",
            "0x75",
            "--timeout",
            "60",
            str(isolated_exe),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=90,
        check=False,
    )
    combined = f"{result.stderr}\n{result.stdout}"

    assert result.returncode == 0, combined
    assert "pure binary recovery mode" in combined
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined
    assert "validation=passed" in combined
    assert re.search(
        rf"\bint sub_{address:x}\({argument_type} a, {argument_type} b\)",
        combined,
    )
    assert "if (a < b)" in combined
    assert "if (a > b)" in combined
    assert "if (a == b)" in combined
    assert "return -1;" in combined
    assert "return 1;" in combined
    assert "return 0;" in combined
    assert "return 2;" in combined
    assert "local_" not in combined


@pytest.mark.requires_kvm
def test_msc6_select_max_materializes_direct_wide_comparison() -> None:
    env = dict(os.environ)
    env.setdefault("INERTIA_ENABLE_TAIL_VALIDATION", "1")
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "--no-alternate-source-c",
            "--proc",
            "select_max",
            "--proc-kind",
            "NEAR",
            "--timeout",
            "60",
            str(CMP32_EXE),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=90,
        check=False,
    )
    combined = f"{result.stderr}\n{result.stdout}"

    assert result.returncode == 0, combined
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined
    assert re.search(r"\blong select_max\(long a, long b\)", combined)
    assert re.search(r"\bif \((?:b <= a|a >= b)\)", combined)
    assert "local_6" not in combined
    assert "local_a" not in combined
    assert "return a;" in combined
    assert "return b;" in combined


@pytest.mark.requires_kvm
def test_msc6_clamp_window_sidecar_free_preserves_every_return(
    tmp_path: Path,
) -> None:
    isolated_exe = tmp_path / "CMP32_NO_SIDECARS.EXE"
    shutil.copyfile(CMP32_EXE, isolated_exe)
    env = dict(os.environ)
    env.setdefault("INERTIA_ENABLE_TAIL_VALIDATION", "1")
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "--no-alternate-source-c",
            "--addr",
            "0x10138",
            "--window",
            "0x62",
            "--timeout",
            "60",
            str(isolated_exe),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=90,
        check=False,
    )
    combined = f"{result.stderr}\n{result.stdout}"

    assert result.returncode == 0, combined
    assert "pure binary recovery mode" in combined
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined
    assert re.search(r"\blong sub_10138\(long value, long low, long high\)", combined)
    assert "if (value < low)" in combined
    assert "if (value > high)" in combined
    assert "return low;" in combined
    assert "return high;" in combined
    assert "return value;" in combined
    assert "local_" not in combined
    assert "unsigned long value" not in combined
    assert "return v6 << 16 | v5;" not in combined
