"""Focused contracts for cached CLI project probes.

Layer: CLI/fallback/reporting tests.
Responsibility: keep normalized cache keys compatible with filesystem path operations.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from inertia.cli.project_loading import (
    _find_sidecar_file,
    _find_sidecar_file_cached,
    _probe_ida_base_linear,
    _probe_ida_base_linear_cached,
)


def test_cached_sidecar_and_ida_base_probes_accept_normalized_string_keys(tmp_path: Path) -> None:
    binary = tmp_path / "SAMPLE.EXE"
    listing = tmp_path / "SAMPLE.lst"
    binary.write_bytes(b"MZ")
    listing.write_text("Base Address: 1234h\n", encoding="utf-8")

    _find_sidecar_file_cached.cache_clear()
    _probe_ida_base_linear_cached.cache_clear()
    try:
        assert _find_sidecar_file_cached(binary.as_posix(), ".lst") == listing
        assert _find_sidecar_file(binary, ".LST") == listing
        assert _probe_ida_base_linear(binary, 0x10000) == 0x12340
        assert _probe_ida_base_linear(binary, 0x10000) == 0x12340
    finally:
        _find_sidecar_file_cached.cache_clear()
        _probe_ida_base_linear_cached.cache_clear()


_COLD_PROJECT_SCRIPT = """
import sys
from pathlib import Path
import pyvex
from inertia.cli import serial_clean_worker_cli as worker
from inertia.cli import project_loading

kind, path = sys.argv[1:]
code = bytes.fromhex('b80700c3')
base = 0x4000
if kind == 'bytes':
    project = project_loading._build_project_from_bytes(code, base_addr=base, entry_point=base)
else:
    project = project_loading._build_project(Path(path), force_blob=kind == 'blob',
                                            base_addr=base, entry_point=base)
assert pyvex.lifting.lifters.get('86_16'), 'cold project has no registered x86-16 lifter'
block = project.factory.block(project.entry, size=len(code), opt_level=0)
assert block.vex.jumpkind == 'Ijk_Ret'
assert len(block.instruction_addrs) == 2
cfg = project.analyses.CFGFast(start_at_entry=False, function_starts=[project.entry],
    regions=[(project.entry, project.entry + len(code))], normalize=False,
    data_references=False, force_smart_scan=False, force_complete_scan=False,
    resolve_indirect_jumps=False, function_prologues=False, symbols=False,
    cross_references=False)
assert project.entry in cfg.functions
"""


def _run_cold_project_script(script: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    """Start a fresh interpreter without inheriting pytest's frontend registry."""
    root = Path(__file__).resolve().parents[2]
    environment = os.environ.copy()
    environment["PYTHON_JIT"] = "1"
    environment["PYTHONPATH"] = str(root)
    return subprocess.run(
        [sys.executable, "-c", script, *arguments],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


@pytest.mark.parametrize("kind", ["bytes", "blob", "mz"])
def test_cold_project_construction_registers_lifter_before_cfg(
    tmp_path: Path, kind: str
) -> None:
    """Every x86-16 builder must lift and recover a CFG in a clean worker."""
    sample = tmp_path / ("sample.exe" if kind == "mz" else "sample.bin")
    code = bytes.fromhex("b80700c3")
    if kind == "mz":
        header = bytearray(0x40)
        header[:2] = b"MZ"
        header[8:10] = (4).to_bytes(2, "little")
        sample.write_bytes(header + code)
    else:
        sample.write_bytes(code)

    result = _run_cold_project_script(_COLD_PROJECT_SCRIPT, kind, str(sample))

    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("kind", ["bytes", "blob", "mz"])
def test_cold_project_lifter_import_failure_propagates(tmp_path: Path, kind: str) -> None:
    """A missing verified backend must fail rather than produce an empty CFG."""
    script = """
import builtins
import sys
from pathlib import Path
from inertia.cli import serial_clean_worker_cli as worker
from inertia.cli.project_loading import _build_project, _build_project_from_bytes

kind, path = sys.argv[1:]

ordinary_import = builtins.__import__
def refuse_lifter(name, *args, **kwargs):
    if name == 'inertia.frontend.x86_16.lift_86_16':
        raise ImportError('verified native lifter unavailable')
    return ordinary_import(name, *args, **kwargs)
builtins.__import__ = refuse_lifter
try:
    if kind == 'bytes':
        _build_project_from_bytes(bytes.fromhex('b80700c3'), base_addr=0x4000, entry_point=0x4000)
    else:
        _build_project(Path(path), force_blob=kind == 'blob', base_addr=0x4000, entry_point=0x4000)
except ImportError as error:
    assert str(error) == 'verified native lifter unavailable'
else:
    raise AssertionError('project construction suppressed the missing backend')
"""

    sample = tmp_path / ("sample.exe" if kind == "mz" else "sample.bin")
    header = bytearray(0x40) if kind == "mz" else bytearray()
    if kind == "mz":
        header[:2] = b"MZ"
        header[8:10] = (4).to_bytes(2, "little")
    sample.write_bytes(header + bytes.fromhex("b80700c3"))
    result = _run_cold_project_script(script, kind, str(sample))

    assert result.returncode == 0, result.stdout + result.stderr


def test_actual_cold_serial_worker_has_lifter_at_direct_recovery(tmp_path: Path) -> None:
    """Exercise worker.main through CLI project construction to direct recovery."""
    sample = tmp_path / "worker.exe"
    header = bytearray(0x40)
    header[:2] = b"MZ"
    header[8:10] = (4).to_bytes(2, "little")
    sample.write_bytes(header + bytes.fromhex("b80700c3"))
    # Exercise cold worker startup without rebuilding the repository-wide catalog.
    catalog = tmp_path / "empty.pat"
    catalog.write_text("---\n", encoding="utf-8")
    script = """
import sys
import pyvex
from inertia.cli import serial_clean_worker_cli as worker
from inertia.cli import cli_core as core
from inertia.cli.cli_function_discovery import _pick_function_lean

def checkpoint(project, addr, **kwargs):
    assert 'inertia.frontend.x86_16.lift_86_16' in sys.modules
    assert pyvex.lifting.lifters.get('86_16')
    cfg, function = _pick_function_lean(project, addr, regions=[(addr, addr + 4)],
        data_references=False, extend_far_calls=False)
    assert function.addr == addr
    assert addr in cfg.functions
    print('COLD_WORKER_RECOVERY_REACHED')
    raise SystemExit(0)

core._recover_direct_addr_function = checkpoint
sys.argv = ['serial_clean_worker_cli', sys.argv[1], '--addr', '0x10000', '--base-addr',
    '0x1000', '--entry-point', '0x1000', '--timeout', '6', '--window', '0x200',
    '--c-target', 'portable-flat', '--api-style', 'modern', '--no-alternate-source-c',
    '--ignore-local-sidecar-hints', '--signature-catalog', sys.argv[2]]
raise SystemExit(worker.main(sys.argv[1:]))
"""
    result = _run_cold_project_script(script, str(sample), str(catalog))

    assert result.returncode == 0, result.stdout + result.stderr
    assert "COLD_WORKER_RECOVERY_REACHED" in result.stdout
