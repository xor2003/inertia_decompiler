"""Cold canonical imports preserve module and contract identity."""
import os
import subprocess
import sys
from pathlib import Path


def test_cold_import_identity() -> None:
    """Canonical owners retain Python import metadata and reload identity."""
    root = Path(__file__).resolve().parents[2]
    code = f"""
import sys, importlib
sys.path.insert(0, {str(root)!r})
for name in ('inertia.frontend.x86_16.public_api',
             'inertia.ir.segment_contract',
             'inertia.semantics.segment_call_preservation_stage',
             'inertia.frontend.x86_16.bootstrap'):
    module = importlib.import_module(name)
    assert importlib.import_module(name) is module, name
    assert sys.modules[name] is module, name
    assert module.__name__ == name, name
    assert module.__spec__.name == name, name
    assert module.__loader__ is module.__spec__.loader, name
    assert module.__file__ == module.__spec__.origin, name
    if name.endswith('.bootstrap'):
        assert importlib.reload(module) is module
"""
    result = subprocess.run([sys.executable, "-I", "-c", code],
                            capture_output=True, text=True, timeout=90,
                            env=os.environ.copy())
    assert result.returncode == 0, result.stdout + result.stderr
