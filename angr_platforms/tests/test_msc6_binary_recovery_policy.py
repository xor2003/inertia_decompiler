"""Ensure compiler round trips cannot substitute alternate source recovery."""

import subprocess

import pytest

from scripts import batch_decompile_procs, build_msc6_examples


@pytest.mark.parametrize("mode", ["focused", "main", "functions"])
def test_roundtrip_commands_disable_alternate_source(monkeypatch, tmp_path, mode):
    commands = []

    def capture_timeout(command, **kwargs):
        commands.append(command)
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(build_msc6_examples, "_run", capture_timeout)
    options = {
        "decompile_py": tmp_path / "decompile.py",
        "decompile_timeout": 1,
        "decompile_function_discovery_backend": "auto",
        "decompile_seed_engine": "auto",
        "decompile_rizin_timeout": 1,
        "decompile_force_rizin_8616": False,
        "decompile_pat_backend": None,
        "decompile_signature_catalog": None,
    }
    binary = tmp_path / "TEST.EXE"
    if mode == "focused":
        build_msc6_examples._decompile_function_with_options(
            binary, function_name="probe", **options,
        )
    else:
        monkeypatch.setattr(build_msc6_examples, "_resolve_main_candidates_from_metadata", lambda *_: [])
        build_msc6_examples._decompile(
            binary, tmp_path, decompile_run_timeout=1, decompile_mode=mode,
            decompile_cod_path=None, decompile_max_functions=0,
            decompile_ignore_local_sidecar_hints=False, **options,
        )
    assert len(commands) == 1
    assert "--no-alternate-source-c" in commands[0]
    assert "--alternate-source-c" not in commands[0]


def test_batch_proc_commands_disable_alternate_source(monkeypatch, tmp_path):
    commands = []

    def capture(command):
        commands.append(command)
        return 0

    monkeypatch.setattr(batch_decompile_procs.decompiler_cli, "main", capture)
    assert batch_decompile_procs.main([
        str(tmp_path / "TEST.EXE"), "--out-dir", str(tmp_path / "batch"),
        "--proc", "probe",
    ]) == 0
    assert len(commands) == 1
    assert "--no-alternate-source-c" in commands[0]
    assert "--alternate-source-c" not in commands[0]
