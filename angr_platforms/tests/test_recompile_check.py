from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import inertia_decompiler.recompile_check as recompile_check
from inertia_decompiler.recompile_check import check_c_recompiles_8616


def _completed_process(
    returncode: int,
    *,
    stdout: str = "",
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    """Return a typed fake compiler result."""

    return subprocess.CompletedProcess(
        args=("gcc",),
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def _install_fake_portable_compiler(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    result: subprocess.CompletedProcess[str],
) -> None:
    """Install one deterministic portable compiler result."""

    monkeypatch.setattr(recompile_check.shutil, "which", lambda _name: "/usr/bin/gcc")
    monkeypatch.setattr(recompile_check.tempfile, "mkdtemp", lambda **_kwargs: str(tmp_path))
    monkeypatch.setattr(recompile_check.subprocess, "run", lambda *_args, **_kwargs: result)


def test_portable_recompile_rejects_nonzero_exit_without_diagnostic_keyword(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _install_fake_portable_compiler(
        monkeypatch,
        tmp_path,
        _completed_process(1, stderr="compiler stopped without a classified diagnostic\n"),
    )

    result = check_c_recompiles_8616("int demo(void) { return 0; }\n")

    assert result.passed is False
    assert result.exit_code == 1
    assert result.source_path is not None


def test_portable_recompile_rejects_nonzero_exit_with_gcc_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _install_fake_portable_compiler(
        monkeypatch,
        tmp_path,
        _completed_process(1, stderr="generated.c:1:1: error: invalid generated C\n"),
    )

    result = check_c_recompiles_8616("int demo(void) { return 0; }\n")

    assert result.passed is False
    assert result.exit_code == 1


def test_portable_recompile_accepts_zero_exit_with_warning(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _install_fake_portable_compiler(
        monkeypatch,
        tmp_path,
        _completed_process(0, stderr="generated.c:1:1: warning: unused variable\n"),
    )

    result = check_c_recompiles_8616("int demo(void) { return 0; }\n")

    assert result.passed is True
    assert result.exit_code == 0
    assert result.source_path is None


def test_portable_recompile_timeout_is_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(recompile_check.shutil, "which", lambda _name: "/usr/bin/gcc")
    monkeypatch.setattr(recompile_check.tempfile, "mkdtemp", lambda **_kwargs: str(tmp_path))

    def _raise_timeout(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(("gcc",), timeout=20, output="partial output\n")

    monkeypatch.setattr(recompile_check.subprocess, "run", _raise_timeout)

    result = check_c_recompiles_8616("int demo(void) { return 0; }\n")

    assert result.passed is False
    assert result.exit_code == 124
    assert "recompile timeout" in result.stderr


@pytest.mark.parametrize(
    "source",
    (
        "void demo(void) { int values[1]; values = 3; }\n",
        "void demo(void) { struct missing value; value = 1; }\n",
        "int demo(void) { return undeclared_value; }\n",
    ),
)
def test_portable_recompile_rejects_real_invalid_c(source: str) -> None:
    result = check_c_recompiles_8616(source)

    assert result.compiler is not None
    assert result.passed is False
    assert result.exit_code != 0


@pytest.mark.parametrize(
    ("source", "expected_pass"),
    [
        pytest.param("unsigned short demo(void) {}", False, id="missing-return"),
        pytest.param("int demo(int x) { if (x) return 1; }", False, id="partial-return"),
        pytest.param("int demo(void) { return; }", False, id="bare-return"),
        pytest.param("int demo(void) { int value; return value; }", False, id="uninitialized-return"),
        pytest.param("int demo(void) { return 1; }", True, id="value-return"),
        pytest.param("void demo(void) {}", True, id="void-fallthrough"),
        pytest.param("int demo(void) { for (;;) {} }", True, id="no-fallthrough"),
        pytest.param(
            "extern int target(void); int demo(void) { return target(); }",
            True,
            id="external-return-no-link-required",
        ),
    ],
)
def test_portable_recompile_checks_return_paths(source: str, expected_pass: bool) -> None:
    """A syntax-only pass is not evidence that value-returning C compiles."""
    result = check_c_recompiles_8616(source)

    assert result.compiler is not None
    assert result.passed is expected_pass, result.stderr
    if not expected_pass:
        assert "return" in result.stderr
        assert result.source_path is not None


def test_msc_recompile_rejects_nonzero_exit_without_diagnostic_keyword(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kvikdos = tmp_path / "kvikdos"
    kvikdos.write_text("", encoding="utf-8")
    msc_root = tmp_path / "msc51"
    (msc_root / "BIN").mkdir(parents=True)
    monkeypatch.setattr(recompile_check, "_resolve_kvikdos_path", lambda: kvikdos)
    monkeypatch.setattr(recompile_check, "_resolve_msc51_root", lambda: msc_root)
    monkeypatch.setattr(
        recompile_check.subprocess,
        "run",
        lambda *_args, **_kwargs: _completed_process(1, stderr="compilation stopped\n"),
    )

    result = check_c_recompiles_8616("int demo(void) { return 0; }\n", target="msc-dos")

    assert result.passed is False
    assert result.exit_code == 1


def test_msc_compile_payload_uses_dos_header_aggregate_definitions() -> None:
    payload = recompile_check._compile_input_payload_8616(
        "typedef union REGS {\n"
        "    struct { unsigned short ax, cflag; } x;\n"
        "} REGS;\n"
        "typedef struct SREGS {\n"
        "    unsigned short es, cs, ss, ds;\n"
        "} SREGS;\n"
        "extern REGS rin;\n"
        "extern SREGS sreg;\n",
        target="msc-dos",
    )

    assert "#include <DOS.H>" in payload
    assert "typedef union REGS {" not in payload
    assert "typedef struct SREGS {" not in payload
    assert "typedef union REGS REGS;" in payload
    assert "typedef struct SREGS SREGS;" in payload
    assert "extern REGS rin;" in payload
    assert "extern SREGS sreg;" in payload
