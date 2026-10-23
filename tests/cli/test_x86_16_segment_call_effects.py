"""Require caller-observed segment effects to survive native decompilation."""

import ctypes
import subprocess
from pathlib import Path

import pytest

from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from tests.cli.test_x86_16_cod_samples import _project_from_bytes

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize("segment,read,write", [("es", "8cc0", "8ec3"), ("ds", "8cd8", "8edb")])
@pytest.mark.parametrize("prefix,expected_return", [("", None), ("bb7856", None), ("snapshot", 0x1234)])
def test_standalone_segment_write_updates_runtime_state(
    tmp_path: Path, segment: str, read: str, write: str,
    prefix: str, expected_return: int | None,
) -> None:
    """Publish segment writes while preserving values read before the write."""
    initial = read if prefix == "snapshot" else prefix + write if prefix else ""
    apply_x86_16_bootstrap()
    project = _project_from_bytes(bytes.fromhex(initial + "31db" + write + "c3"))
    cfg = project.analyses.CFGFast(normalize=True)
    result = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)
    source = tmp_path / "standalone_segment.c"
    library = tmp_path / "standalone_segment.so"
    source.write_text(
        f"unsigned short inertia_{segment} = 0x1234;\n" + result.codegen.text,
        encoding="ascii",
    )
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Werror", "-shared", "-fPIC", str(source), "-o", str(library)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stderr
    loaded = ctypes.CDLL(str(library))
    loaded._start.restype = ctypes.c_uint16 if expected_return is not None else None
    returned = loaded._start()
    assert ctypes.c_uint16.in_dll(loaded, f"inertia_{segment}").value == 0
    if expected_return is not None:
        assert returned == expected_return


@pytest.mark.parametrize("segment,read,write", [("es", "8cc0", "8ec3"), ("ds", "8cd8", "8edb")])
@pytest.mark.parametrize("initial_write", ["", "bb7856"])
@pytest.mark.parametrize("initial_esp", [0, 0x12340001, 0xFFFFFFFF])
def test_callee_es_write_reaches_callers_return(
    tmp_path: Path, segment: str, read: str, write: str, initial_write: str,
    initial_esp: int,
) -> None:
    """A caller must observe the last callee segment write, not its input state."""
    caller_address, callee_address = 0x1000, 0x1010
    overwritten = initial_write + write if initial_write else ""
    code = bytes.fromhex("e80d00" + read + "c3") + b"\x90" * 10 + bytes.fromhex(overwritten + "31db" + write + "c3")
    apply_x86_16_bootstrap()
    project = _project_from_bytes(code)
    cfg = project.analyses.CFGFast(normalize=True)
    caller = project.analyses.Decompiler(cfg.functions[caller_address], cfg=cfg)
    callee = project.analyses.Decompiler(cfg.functions[callee_address], cfg=cfg)
    source = tmp_path / "segment_effect.c"
    library = tmp_path / "segment_effect.so"
    source.write_text(
        f"unsigned short inertia_{segment} = 0x1234;\n"
        f"unsigned int inertia_esp = {initial_esp}U;\nvoid sub_1010(void);\n"
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

    assert ctypes.c_uint32.in_dll(loaded, "inertia_esp").value == initial_esp
