"""Cold-process compatibility imports must preserve module and contract identity."""
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("legacy_first", [False, True])
@pytest.mark.parametrize("inner_layout", [False, True])
def test_cold_import_identity(legacy_first: bool, inner_layout: bool) -> None:
    root = Path(__file__).resolve().parents[2]
    entry = root / "angr_platforms" if inner_layout else root
    code = f"""
import sys, importlib
sys.path.insert(0, {str(root)!r})
sys.path.insert(0, {str(entry)!r})
canonical = 'angr_platforms.X86_16'
legacy = 'angr_platforms.angr_platforms.X86_16'
for suffix in ('', '.ir.segment_contract', '.segment_call_preservation_stage', '.bootstrap'):
    names = [canonical + suffix, legacy + suffix]
    if {legacy_first!r}:
        names.reverse()
    first = importlib.import_module(names[0])
    second = importlib.import_module(names[1])
    assert first is second, suffix
    assert sys.modules[names[0]] is sys.modules[names[1]], suffix
    assert importlib.import_module(names[0]) is first, suffix
    assert first.__name__ == canonical + suffix, suffix
    assert first.__spec__.name == canonical + suffix, suffix
    assert first.__loader__ is first.__spec__.loader, suffix
    assert first.__file__ == first.__spec__.origin, suffix
    if suffix:
        parent, _, child = names[1].rpartition('.')
        assert getattr(sys.modules[parent], child) is first, suffix
    if suffix == '.ir.segment_contract':
        assert first.SegmentFunctionContract is second.SegmentFunctionContract
    if suffix == '.bootstrap':
        assert importlib.reload(first) is first
        assert importlib.import_module(legacy + suffix) is first
"""
    result = subprocess.run([sys.executable, "-I", "-c", code],
                            capture_output=True, text=True, timeout=90,
                            env=os.environ.copy())
    assert result.returncode == 0, result.stdout + result.stderr
