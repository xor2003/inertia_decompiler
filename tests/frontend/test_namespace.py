"""Cold imports preserve architecture registration and serialized identities."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


def test_frontend_namespace_identity_and_registration() -> None:
    """Canonical imports preserve registration and pickle identities."""
    root = Path(__file__).resolve().parents[2]
    code = f"""
import sys, importlib, pickle
sys.path.insert(0, {str(root)!r})
for name in ('control_coordinates', 'arch_86_16', 'load_dos_mz', 'ne_resources', 'load_dos_ne', 'interrupt_contract', 'simos_86_16', 'lifter_backend', 'lift_86_16', 'direction_step', 'vex_value_contract'):
    qualified = 'inertia.frontend.x86_16.' + name
    module = importlib.import_module(qualified)
    assert importlib.import_module(qualified) is module
    assert module.__name__ == qualified
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.control_coordinates import ControlAddressDomain
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16
from pyvex.lifting import lifters
from archinfo import arch_from_id
from inertia.frontend.x86_16.load_dos_mz import DOSMZ
from inertia.frontend.x86_16.load_dos_ne import DOSNE
from cle.backends import ALL_BACKENDS
from inertia.frontend.x86_16.simos_86_16 import SimDOS86_16
from angr.simos import os_mapping
assert type(arch_from_id('86_16')) is Arch86_16
assert ALL_BACKENDS['dos_mz'] is DOSMZ
assert ALL_BACKENDS['dos_ne'] is DOSNE
assert os_mapping['DOS'] is SimDOS86_16
assert sum(lifter is Lifter86_16 for lifter in lifters['86_16']) == 1
assert pickle.loads(b'cinertia.frontend.x86_16.lift_86_16\\nLifter86_16\\n.') is Lifter86_16
assert pickle.loads(b'cinertia.frontend.x86_16.simos_86_16\\nSimDOS86_16\\n.') is SimDOS86_16
assert pickle.loads(b'cinertia.frontend.x86_16.load_dos_ne\\nDOSNE\\n.') is DOSNE
assert pickle.loads(b'cinertia.frontend.x86_16.load_dos_mz\\nDOSMZ\\n.') is DOSMZ
assert pickle.loads(b'cinertia.frontend.x86_16.arch_86_16\\nArch86_16\\n.') is Arch86_16
assert pickle.loads(b'cinertia.frontend.x86_16.control_coordinates\\nControlAddressDomain\\n.') is ControlAddressDomain
assert pickle.loads(pickle.dumps(ControlAddressDomain.LOADER_LINEAR)) is ControlAddressDomain.LOADER_LINEAR
assert Arch86_16().registers['ax'] == (0, 2)
from inertia.ir import vex_bit_source
assert importlib.import_module('inertia.ir.vex_bit_source') is vex_bit_source
assert pickle.loads(b'cinertia.ir.vex_bit_source\\nBitSourceProjection8616\\n.') is vex_bit_source.BitSourceProjection8616
"""
    result = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("module", [
    "inertia.ir.vex_bit_source",
    "inertia.frontend.x86_16.direction_step",
    "inertia.frontend.x86_16.vex_value_contract",
])
def test_qualified_helper_import_does_not_start_legacy_pipeline(module: str) -> None:
    """Pure helper owners are usable without starting the full lifter/decompiler."""
    root = Path(__file__).resolve().parents[2]
    code = f"""
import sys, importlib
sys.path.insert(0, {str(root)!r})
importlib.import_module({module!r})
assert 'inertia.frontend.x86_16.public_api' not in sys.modules
assert 'inertia.frontend.x86_16.lift_86_16' not in sys.modules
"""
    result = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
