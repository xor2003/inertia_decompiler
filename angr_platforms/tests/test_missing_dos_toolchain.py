"""Unavailable required tools must remain failures with actionable setup hints."""

import pytest

from inertia_decompiler import recompile_check


@pytest.mark.parametrize("tool", ["kvikdos", "compiler"])
def test_missing_dos_toolchain_reports_installation_source(monkeypatch, tmp_path, tool):
    monkeypatch.setattr(recompile_check, "_resolve_kvikdos_path",
                        lambda: None if tool == "kvikdos" else tmp_path / "kvikdos")
    monkeypatch.setattr(recompile_check, "_resolve_msc51_root", lambda: None)
    result = recompile_check._check_c_recompiles_msc51_8616("int f(void) { return 0; }", target="msc-dos")
    assert result.outcome is recompile_check.RecompileCheckOutcome.TOOLCHAIN_UNAVAILABLE
    assert not result.passed
    repository = "xor2003/kvikdos" if tool == "kvikdos" else "davidly/dos_compilers"
    setting = "INERTIA_KVIKDOS_PATH" if tool == "kvikdos" else "INERTIA_MSC51_ROOT"
    assert f"https://github.com/{repository}" in result.stderr
    assert setting in result.stderr
