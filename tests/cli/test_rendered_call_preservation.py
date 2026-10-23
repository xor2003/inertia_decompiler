"""Rendered C must preserve observable calls even when validation refuses.

Layer: CLI regression tests.
Responsibility: execute emitted C to detect call loss during text formatting.
This is an emission check, not acceptance of the binary's unresolved stack ABI.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.decompiler


def test_cli_text_formatting_preserves_call_execution(tmp_path: Path) -> None:
    """All signed-byte inputs retain their sum and exactly one emitted call."""
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.skip("gcc is required to execute generated C")
    root = Path(__file__).resolve().parents[2]
    binary = root / "examples/build_msc6_tiny/scalar_types_io/TYPES.EXE"
    if not binary.exists():
        pytest.skip("the compiler-construct binary is unavailable")
    result = subprocess.run(
        [sys.executable, "decompile.py", str(binary), "--proc", "add_sc", "--timeout", "30"],
        cwd=root, env=os.environ.copy(), capture_output=True, text=True, check=False,
    )
    (tmp_path / "cli.c").write_text(result.stdout)
    (tmp_path / "cli.stderr.log").write_text(result.stderr)
    (tmp_path / "cli.exit").write_text(str(result.returncode))
    # A typed refusal may emit diagnostic C. It must retain its actual calls.
    assert result.returncode in (0, 4), result.stderr[-2000:]
    harness = tmp_path / "call_observation.c"
    harness.write_text(
        "void aNchkstk(void);\n" + result.stdout + "\n" + r"""
static unsigned int observed_calls;
inertia_gp_lane inertia_gp_edi = {0};
inertia_gp_lane inertia_gp_esi = {0};
void aNchkstk(void) { ++observed_calls; }
int main(void) {
    for (int a = -128; a < 128; ++a) {
        for (int b = -128; b < 128; ++b) {
            if (add_sc((signed char)a, (signed char)b) != (signed char)(a + b))
                return 1;
        }
    }
    return observed_calls == 65536U ? 0 : 2;
}
"""
    )
    executable = tmp_path / "call_observation"
    compiled = subprocess.run(
        [compiler, "-std=c11", "-O0", "-Wall", "-Wextra", "-Werror=implicit-function-declaration",
         str(harness), "-o", str(executable)],
        capture_output=True, text=True, check=False,
    )
    (tmp_path / "gcc.stdout.log").write_text(compiled.stdout)
    (tmp_path / "gcc.stderr.log").write_text(compiled.stderr)
    assert compiled.returncode == 0, compiled.stderr
    executed = subprocess.run([str(executable)], capture_output=True, text=True, check=False)
    (tmp_path / "execution.exit").write_text(str(executed.returncode))
    (tmp_path / "execution.stdout.log").write_text(executed.stdout)
    (tmp_path / "execution.stderr.log").write_text(executed.stderr)
    assert executed.returncode == 0, "emission lost a call or changed a signed-byte sum"
