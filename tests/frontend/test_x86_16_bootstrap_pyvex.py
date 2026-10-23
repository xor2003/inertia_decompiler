"""Canonical CLI bootstrap installs lazy Gymrat logging in a fresh process."""
from __future__ import annotations

import subprocess
import sys

import pytest

pytestmark = pytest.mark.decompiler


def test_canonical_bootstrap_order_matches_declared_hooks(monkeypatch):
    """The compatibility adapter precedes every consuming frontend hook."""
    from inertia.frontend.x86_16 import bootstrap

    observed = []
    expected = bootstrap.describe_x86_16_bootstrap()
    for name in expected:
        monkeypatch.setattr(bootstrap, name, lambda name=name: observed.append(name))
    bootstrap.apply_x86_16_bootstrap()
    assert tuple(observed) == expected
    assert observed[0] == "apply_pyvex_runtime_compatibility"


def test_canonical_bootstrap_installs_lazy_gymrat_logging():
    """Direct bootstrap imports must not depend on the historical public facade."""
    program = '''
import io
import logging
import sys
import archinfo
import pyvex
from pyvex.lifting.util import GymratLifter, Instruction
from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap

assert "inertia.frontend.x86_16.public_api" not in sys.modules
apply_x86_16_bootstrap()
assert GymratLifter._lift.__module__ == "pyvex_compat"
assert "inertia.frontend.x86_16.public_api" not in sys.modules

class Nop(Instruction):
    bin_format = "00000000"
    name = "logging_nop"
    def compute_result(self):
        return None

class TinyLifter(GymratLifter):
    instrs = [Nop]

logger = logging.getLogger("pyvex.lifting.util.lifter_helper")
stream = io.StringIO()
logger.addHandler(logging.StreamHandler(stream))
original_str = pyvex.IRSB.__str__
for debug_enabled in (False, True):
    logger.setLevel(logging.DEBUG if debug_enabled else logging.WARNING)
    if not debug_enabled:
        def forbidden(self):
            raise AssertionError("disabled debug stringified IRSB")
        pyvex.IRSB.__str__ = forbidden
    else:
        pyvex.IRSB.__str__ = original_str
    block = TinyLifter(archinfo.ArchX86(), 0x1000).lift(b"\\x00")
    assert block.size == 1
    if debug_enabled:
        assert "IRSB" in stream.getvalue()
'''
    result = subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
