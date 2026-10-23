"""Static DPMI profile controls: commands, evidence and frozen identities."""
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import tools.compiler_toolchain.build_msc6_examples as harness
import tools.compiler_toolchain.compiler_profile as profile_owner
from tools.compiler_toolchain.compiler_profile import load_compiler_profiles, msc6_ax_toolchain, resolve_case_toolchain
from tools.compiler_toolchain.msc6_memory_model import MSCMemoryModel
from tools.compiler_toolchain.tests.test_compiler_coverage_profile import (
    _borland_record,
    _msc51_record,
    _probe_entry,
    _registry,
)


def test_kvikdos_program_run_keeps_the_legacy_argv_without_a_profile(tmp_path, monkeypatch):
    commands = []
    monkeypatch.setattr(
        harness, "_run",
        lambda command, **kwargs: commands.append((command, kwargs))
        or SimpleNamespace(returncode=5, stdout="guest", stderr=""),
    )
    result = harness._run_example(tmp_path / "CASE.EXE", tmp_path, kvikdos=tmp_path / "kvikdos")
    assert result == (False, 5, "guest", "")
    command, kwargs = commands[0]
    assert command == [
        str(tmp_path / "kvikdos"), f"--mount=c:{tmp_path}/", "--drive=c",
        "--cwd-dos=c:\\", "--prog=c:\\CASE.EXE", "c:\\CASE.EXE",
    ]
    assert kwargs == {"timeout": 30}

@pytest.mark.parametrize("mode", ["auto", "off"])
def test_kvikdos_dpmi_profile_controls_compile_link_and_run(tmp_path, monkeypatch, mode):
    """Selected host DPMI policy applies to every kvikdos invocation."""
    registry = _registry(tmp_path, [_msc51_record(tmp_path / "msc51", kvikdos_dpmi_mode=mode)])
    toolchain = resolve_case_toolchain("msc51-small", evidence_path=registry)
    assert toolchain.kvikdos_dpmi_mode.value == mode
    for program in (toolchain.compiler_program, toolchain.linker_program):
        command = profile_owner._kvikdos_toolchain_command(
            tmp_path / "kvikdos", tmp_path, toolchain,
            path_dos=(), environment=(), program=program,
        )
        assert ("--dpmi=off" in command) == (mode == "off")
        if mode == "off":
            assert command.index("--dpmi=off") < command.index(program)
    commands = []
    monkeypatch.setattr(
        harness, "_run", lambda command, **kwargs: commands.append(command)
        or SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    assert harness._run_example(
        tmp_path / "CASE.EXE", tmp_path, kvikdos=tmp_path / "kvikdos", toolchain=toolchain,
    )[0]
    command = commands[0]
    assert ("--dpmi=off" in command) == (mode == "off")
    if mode == "off":
        assert command.index("--dpmi=off") < command.index("c:\\CASE.EXE")

def test_kvikdos_dpmi_mode_changes_frozen_profile_fingerprint():
    """A mode change invalidates proof contexts even with identical compiler pins."""
    automatic = msc6_ax_toolchain(root=Path("/fixture/msc6"), memory_model=MSCMemoryModel.SMALL)
    disabled = replace(automatic, kvikdos_dpmi_mode=profile_owner.KvikdosDPMIMode.OFF)
    assert automatic.to_dict()["kvikdos_dpmi_mode"] == "auto"
    assert disabled.to_dict()["kvikdos_dpmi_mode"] == "off"
    assert profile_owner.FrozenCompilerContext.create(automatic, None).profile_sha256 != (
        profile_owner.FrozenCompilerContext.create(disabled, None).profile_sha256
    )

@pytest.mark.parametrize("mode", ["on", "OFF", "", None, 1])
def test_kvikdos_dpmi_registry_rejects_invalid_modes(tmp_path, mode):
    """Unsupported or malformed DPMI settings cannot silently select auto."""
    registry = _registry(tmp_path, [_msc51_record(tmp_path / "msc51", kvikdos_dpmi_mode=mode)])
    with pytest.raises(ValueError):
        load_compiler_profiles(registry)

def test_kvikdos_dpmi_registry_rejects_unmeasured_mode(tmp_path):
    """An off selection needs a probe that actually used the same setting."""
    record = _msc51_record(tmp_path / "msc51", kvikdos_dpmi_mode="off")
    registry = _registry(tmp_path, [record], [_probe_entry(record, kvikdos_dpmi_mode="auto")])
    with pytest.raises(ValueError, match="does not match probe"):
        load_compiler_profiles(registry)

def test_kvikdos_dpmi_off_does_not_modify_dosbox_commands(tmp_path, monkeypatch):
    """DPMI settings belong to kvikdos, not DOSBox guest command lines."""
    record = _borland_record(tmp_path / "bc31", run_backend="dosbox")
    registry = _registry(tmp_path, [record])
    automatic = resolve_case_toolchain("bc31-small", evidence_path=registry)
    disabled = replace(automatic, kvikdos_dpmi_mode=profile_owner.KvikdosDPMIMode.OFF)
    arguments = {"source_name": "CASE.C", "obj_name": "CASE.OBJ"}
    assert disabled.compile_dos_command(**arguments) == automatic.compile_dos_command(**arguments)
    captured = []
    monkeypatch.setattr(
        harness, "_run_dosbox_example",
        lambda *args, **kwargs: captured.append(kwargs) or (True, 0, "guest", ""),
    )
    monkeypatch.setattr(harness, "_run", Mock(side_effect=AssertionError("unexpected kvikdos")))
    assert harness._run_example(
        tmp_path / "CASE.EXE", tmp_path, kvikdos=tmp_path / "unused", toolchain=disabled,
    ) == (True, 0, "guest", "")
    assert captured[0]["toolchain"] is disabled

def test_kvikdos_dpmi_requires_a_typed_owned_mode():
    """Direct owned construction cannot sneak a raw string past enum guards."""
    automatic = msc6_ax_toolchain(root=Path("/fixture/msc6"), memory_model=MSCMemoryModel.SMALL)
    with pytest.raises(ValueError, match="typed KvikdosDPMIMode"):
        replace(automatic, kvikdos_dpmi_mode="off")
