"""MS C 6 compile invocations must select a writable DOS TMP.

Layer: tests.
Responsibility: pin the kvikdos ``--env=TMP=C:\\`` override on the harness
compile commands; C1043 followed by LINK L1093 is the observed failure chain
when the compiler cannot open intermediate files.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts import build_msc6_examples as harness
from scripts.msc6_memory_model import MSCMemoryModel

DOS_TMP_OVERRIDE = "--env=TMP=C:\\"
C1043 = "fatal error C1043: cannot open compiler intermediate file\n"
L1093 = "LINK : fatal error L1093"


def _completed(
    command: list[str], returncode: int, stdout: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr="")


def _observed_toolchain(commands: list[list[str]], out_dir: Path):
    """Replay the real failure chain at the ``_run`` boundary.

    Without a DOS TMP on the writable C: mount, CL.EXE fails with C1043 and
    emits no object; LINK then fails with L1093 for the missing object. With
    the override, intermediates land on C: and artifacts materialize.
    """

    def run(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(list(cmd))
        prog = next(arg for arg in cmd if arg.startswith("--prog="))
        if prog.endswith("CL.EXE"):
            if DOS_TMP_OVERRIDE not in cmd:
                return _completed(cmd, 4, C1043)
            obj_arg = next(arg for arg in cmd if arg.startswith("/Fo"))
            (out_dir / obj_arg.removeprefix("/Foc:\\")).write_bytes(b"OBJ")
            return _completed(cmd, 0)
        fields = cmd[-1].split(",")
        objects = [item.removeprefix("c:\\") for item in fields[0].split("+")]
        missing = next((name for name in objects if not (out_dir / name).exists()), None)
        if missing is not None:
            return _completed(cmd, 2, f"{L1093} : {missing} : object not found\n")
        (out_dir / fields[1].removeprefix("c:\\")).write_bytes(b"EXE")
        (out_dir / fields[2].removeprefix("c:\\")).write_text("", encoding="utf-8")
        return _completed(cmd, 0)

    return run


@pytest.mark.parametrize("memory_model", [MSCMemoryModel.SMALL, MSCMemoryModel.LARGE])
@pytest.mark.parametrize("inherited_tmp", ["/tmp", "E:\\READONLY"])
def test_msc6_compile_commands_select_writable_dos_tmp(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    memory_model: MSCMemoryModel,
    inherited_tmp: str,
) -> None:
    """An inherited host/compiler-tree TMP cannot name writable DOS storage."""
    kvikdos = tmp_path / "kvikdos"
    msc6_root = tmp_path / "msc6"
    (msc6_root / "BIN").mkdir(parents=True)
    out_dir = tmp_path / "case"
    out_dir.mkdir()
    source_path = tmp_path / "MAIN.C"
    source_path.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    monkeypatch.setenv("TMP", inherited_tmp)
    commands: list[list[str]] = []
    monkeypatch.setattr(harness, "_run", _observed_toolchain(commands, out_dir))

    built, *_ = harness._compile_and_link_unlocked(
        source_path,
        out_dir,
        kvikdos=kvikdos,
        msc6_root=msc6_root,
        obj_name="MAIN.OBJ",
        exe_name="MAIN.EXE",
        map_name="MAIN.MAP",
        runtime_support=True,
        memory_model=memory_model,
    )

    compile_commands = [cmd for cmd in commands if "e:\\BIN\\CL.EXE" in cmd]
    link_commands = [cmd for cmd in commands if "e:\\BIN\\LINK.EXE" in cmd]
    assert len(compile_commands) == 2
    assert len(link_commands) == 1
    for cmd in compile_commands:
        assert cmd.count(DOS_TMP_OVERRIDE) == 1
        assert f"--mount=c:{out_dir}/" in cmd
        assert f"--mount=e:{msc6_root}/" in cmd
        assert "--env=INCLUDE=E:\\INCLUDE" in cmd
        assert "--env=LIB=E:\\LIB" in cmd
        assert "--path-dos=e:\\BIN" in cmd
        assert "/Ic:\\" in cmd
        assert "/nologo" in cmd
        assert "/Od" in cmd
        assert memory_model.compiler_flag in cmd
        assert "/c" in cmd
    source_cmd, runtime_cmd = compile_commands
    assert source_cmd[-1] == f"c:\\{source_path.name}"
    assert "/Foc:\\MAIN.OBJ" in source_cmd
    assert runtime_cmd[-1] == "c:\\INERTIA.C"
    assert "/Foc:\\INERTIA.OBJ" in runtime_cmd
    # TMP is a compiler requirement; the linker invocation stays unchanged.
    assert DOS_TMP_OVERRIDE not in link_commands[0]
    assert built, "writable DOS TMP must clear the C1043/L1093 failure chain"
