"""Require caller-observed segment effects to survive native decompilation."""

import ctypes
import subprocess
from pathlib import Path

import pytest
from test_x86_16_cod_samples import _project_from_bytes


@pytest.mark.parametrize("segment,read,write", [("es", "8cc0", "8ec3"), ("ds", "8cd8", "8edb")])
@pytest.mark.parametrize("initial_write", ["", "bb7856"])
def test_callee_es_write_reaches_callers_return(
    tmp_path: Path, segment: str, read: str, write: str, initial_write: str,
) -> None:
    """A caller must observe the last callee segment write, not its input state."""
    caller_address, callee_address = 0x1000, 0x1010
    overwritten = initial_write + write if initial_write else ""
    code = bytes.fromhex("e80d00" + read + "c3") + b"\x90" * 10 + bytes.fromhex(overwritten + "31db" + write + "c3")
    project = _project_from_bytes(code)
    cfg = project.analyses.CFGFast(normalize=True)
    caller = project.analyses.Decompiler(cfg.functions[caller_address], cfg=cfg)
    callee = project.analyses.Decompiler(cfg.functions[callee_address], cfg=cfg)
    source = tmp_path / "segment_effect.c"
    library = tmp_path / "segment_effect.so"
    source.write_text(
        f"unsigned short inertia_{segment} = 0x1234;\nvoid sub_1010(void);\n"
        + caller.codegen.text + "\n" + callee.codegen.text,
        encoding="ascii",
    )
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Werror", "-shared", "-fPIC", str(source), "-o", str(library)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stderr
    loaded = ctypes.CDLL(str(library))
    loaded._start.restype = ctypes.c_ushort
    assert loaded._start() == 0, f"callee's {segment} write disappeared before its caller read it"
