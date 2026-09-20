"""All compile and link phases must agree on the selected DOS memory model."""

import subprocess
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


@pytest.mark.parametrize("model,kind", [(MSCMemoryModel.SMALL, "NEAR"), (MSCMemoryModel.LARGE, "FAR")])
def test_model_reaches_batch_and_focused_procedure_selection(tmp_path, monkeypatch, model, kind):
    commands = []
    focused = []
    binary = tmp_path / "CASE.EXE"
    binary.write_bytes(b"test")
    monkeypatch.delenv("INERTIA_DISABLE_MSC6_BATCH_FALLBACK", raising=False)

    def batch_timeout(command, **kwargs):
        commands.append(command)
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    def failed_function(*args, **kwargs):
        focused.append(kwargs)
        return False, "", "", {"timeout": True, "acceptance_reason": "timeout"}, "", "probe"

    monkeypatch.setattr(harness, "_run", batch_timeout)
    monkeypatch.setattr(harness, "_decompile_function_with_options", failed_function)
    result = harness._build_from_function_decompiles(
        binary, tmp_path, decompile_py=tmp_path / "decompile.py",
        decompile_timeout=1, decompile_run_timeout=1,
        decompile_function_discovery_backend="auto", decompile_seed_engine="auto",
        decompile_rizin_timeout=1, decompile_force_rizin_8616=False,
        decompile_pat_backend=None, decompile_signature_catalog=None,
        fallback_functions=("probe",), fallback_harness="", fallback_prefix="",
        decompile_c_name="OUT.C", decompile_obj_name="OUT.OBJ",
        decompile_exe_name="OUT.EXE", decompile_map_name="OUT.MAP",
        kvikdos=tmp_path / "kvikdos", msc6_root=tmp_path / "compiler", memory_model=model,
    )
    assert result[0] is False
    assert len(commands) == 1
    assert len(focused) == 2
    assert "--proc-kind" in commands[0]
    assert commands[0][commands[0].index("--proc-kind") + 1] == kind
    assert all(attempt["proc_kind"] == kind for attempt in focused)
