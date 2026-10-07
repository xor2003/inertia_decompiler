"""Persist original-program evidence before potentially long decompilation.

Layer: Tooling/gates.
Responsibility: retain completed compiler/emulator observations on timeout.
This checkpoint never claims generated-C validation or behavioral equivalence.
"""

from __future__ import annotations

import json
from pathlib import Path

from tools.compiler_toolchain.compiler_coverage_provenance import input_fingerprint
from tools.compiler_toolchain.msc6_memory_model import MSCMemoryModel


def record_original_execution(
    source: Path, *, memory_model: MSCMemoryModel, build_ok: bool,
    expected_exit_code: int, returncode: int | None, stdout: str, stderr: str,
    compile_output: tuple[str, str], link_output: tuple[str, str],
    expected_stdout_contains: str | None = None,
) -> Path:
    """Write original observations without waiting for a decompiler result."""
    stdout_ok = expected_stdout_contains is None or expected_stdout_contains in stdout
    report = source.with_suffix(".original.json")
    payload = {
        "schema": 1, "source": input_fingerprint(source),
        "memory_model": memory_model.value, "build_ok": build_ok,
        "expected_exit_code": expected_exit_code,
        "expected_stdout_contains": expected_stdout_contains,
        "run_exit_code": returncode,
        "run_ok": build_ok and returncode == expected_exit_code and stdout_ok,
        "run_stdout": stdout, "run_stderr": stderr,
        "compile_stdout": compile_output[0], "compile_stderr": compile_output[1],
        "link_stdout": link_output[0], "link_stderr": link_output[1],
        "decompilation_evidence": "not_collected",
    }
    report.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return report
