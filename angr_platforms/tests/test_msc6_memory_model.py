"""All compile and link phases must agree on the selected DOS memory model."""

from types import SimpleNamespace

import pytest

from scripts import build_msc6_examples as harness
from scripts.msc6_memory_model import MSCMemoryModel


@pytest.mark.parametrize("model", list(MSCMemoryModel))
def test_model_reaches_application_runtime_and_linker(tmp_path, monkeypatch, model):
    commands = []

    def run(command, *, timeout):
        commands.append(command)
        (tmp_path / "CASE.EXE").write_bytes(b"test")
        (tmp_path / "INERTIA.OBJ").write_bytes(b"test")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(harness, "_run", run)
    result = harness._compile_and_link_unlocked(
        tmp_path / "CASE.C", tmp_path, kvikdos=tmp_path / "kvikdos",
        msc6_root=tmp_path / "compiler", obj_name="CASE.OBJ", exe_name="CASE.EXE",
        map_name="CASE.MAP", runtime_support=True, memory_model=model,
    )
    assert result[0]
    assert len(commands) == 3
    assert model.compiler_flag in commands[0]
    assert model.compiler_flag in commands[1]
    assert model.runtime_library in commands[2][-1]
    other = MSCMemoryModel.LARGE if model is MSCMemoryModel.SMALL else MSCMemoryModel.SMALL
    assert other.compiler_flag not in commands[0] + commands[1]
    assert other.runtime_library not in commands[2][-1]
