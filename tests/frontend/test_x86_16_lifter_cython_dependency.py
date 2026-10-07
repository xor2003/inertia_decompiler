"""The Python lifter requires Cython for its pure-mode annotations."""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

SAMPLES = [
    "b8ffff83c001c3",
    "b8ffff89c1d1e819c0c3",
    "f7f1c3",
]

_LIFT_SCRIPT = """
import json
import pyvex
from inertia.frontend.x86_16.public_api import VEX_BACKEND, lift_86_16
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
samples = json.loads(SAMPLES_JSON)
blocks = [str(pyvex.IRSB(bytes.fromhex(data), 0x1000, Arch86_16(), opt_level=0)) for data in samples]
print(json.dumps({'backend': VEX_BACKEND.value, 'cython_version': lift_86_16.cython.__version__, 'blocks': blocks}))
"""

_BLOCK_CYTHON = """
import builtins
original_import = builtins.__import__
def import_without_cython(name, *args, **kwargs):
    if name == 'cython':
        raise ModuleNotFoundError('Cython intentionally unavailable', name='cython')
    return original_import(name, *args, **kwargs)
builtins.__import__ = import_without_cython
import sys
assert 'cython' not in sys.modules
"""

_BREAK_CYTHON = """
import builtins
original_import = builtins.__import__
def import_broken_cython(name, *args, **kwargs):
    if name == 'cython':
        raise ModuleNotFoundError('nested dependency missing', name='cython._nested_missing')
    return original_import(name, *args, **kwargs)
builtins.__import__ = import_broken_cython
"""


def _env():
    return dict(
        os.environ,
        INERTIA_VEX_BACKEND="python",
        PYTHONPATH=str(ROOT),
    )


def _lift(prefix):
    script = prefix + _LIFT_SCRIPT.replace("SAMPLES_JSON", repr(json.dumps(SAMPLES)))
    return subprocess.run(
        [sys.executable, "-c", script], cwd=ROOT, env=_env(), capture_output=True, text=True, timeout=180
    )


def test_python_backend_uses_required_cython_annotations():
    """Real instruction blocks lift using the installed Cython annotation runtime."""
    baseline = _lift("")
    assert baseline.returncode == 0, baseline.stderr
    available = json.loads(baseline.stdout)
    assert available["backend"] == "python"
    assert available["cython_version"]
    assert len(available["blocks"]) == len(SAMPLES)


def test_python_backend_refuses_when_cython_package_is_absent():
    """A missing mandatory dependency must fail loudly instead of using a shim."""
    result = _lift(_BLOCK_CYTHON)
    assert result.returncode != 0
    assert "ModuleNotFoundError: Cython intentionally unavailable" in result.stderr


def test_nested_cython_dependency_failure_is_not_swallowed():
    """A missing import inside a real cython package must propagate, not fall back."""
    result = _lift(_BREAK_CYTHON)
    assert result.returncode != 0
    assert "cython._nested_missing" in result.stderr
