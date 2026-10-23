"""Native PEP 810 lazy facade behavior controls.

Each case runs in a fresh subprocess so lazy bindings, module identity, and
legacy monkeypatch write-through are observed without shared state.
"""

from __future__ import annotations

import subprocess
import sys


def _run(script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


def test_cli_facade_defers_cli_core_and_resolves_main() -> None:
    """Cold CLI import leaves cli_core unloaded; main resolves canonically."""
    result = _run(
        """
import sys
import inertia.cli.cli as facade
assert "inertia.cli.cli_core" not in sys.modules
assert not hasattr(type(facade), "__getattr__")
main = facade.main
import inertia.cli.cli_core as cli_core
assert main is cli_core.main
"""
    )
    assert result.returncode == 0, result.stderr


def test_ir_facade_defers_public_api_and_resolves_exports() -> None:
    """Cold IR import leaves public_api unloaded; IRValue binds its owner."""
    result = _run(
        """
import sys
import inertia.ir as ir
assert "inertia.ir.public_api" not in sys.modules
value = ir.IRValue
assert "inertia.ir.public_api" in sys.modules
from inertia.ir.core import IRValue
assert value is IRValue
try:
    ir.not_an_export_8616
except AttributeError:
    pass
else:
    raise AssertionError("unknown attribute must raise AttributeError")
"""
    )
    assert result.returncode == 0, result.stderr


def test_alias_facade_defers_child_modules() -> None:
    """Cold Alias import leaves the four child modules unloaded."""
    result = _run(
        """
import sys
import inertia.alias as alias
for name in ("alias_model", "domains", "state", "transfer"):
    assert f"inertia.alias.{name}" not in sys.modules, name
state = alias.state
import inertia.alias.state as canonical
assert state is canonical
"""
    )
    assert result.returncode == 0, result.stderr


def test_frontend_public_api_defers_corpus_scan_module() -> None:
    """The frontend surface defers reporting modules until first access."""
    result = _run(
        """
import sys
import inertia.frontend.x86_16.public_api as public_api
assert "inertia.cli.corpus_scan" not in sys.modules
corpus_scan = public_api.corpus_scan
import inertia.cli.corpus_scan as owner
assert corpus_scan is owner
"""
    )
    assert result.returncode == 0, result.stderr


def test_cli_write_before_first_lazy_read_reaches_owner() -> None:
    """Monkeypatching a compat export before any read lands on its owner."""
    result = _run(
        """
import sys
import inertia.cli.cli as facade
assert "inertia.cli.cli_function_discovery" not in sys.modules
def replacement(*args, **kwargs):
    return None
facade._recover_fast_exe_catalog = replacement
import inertia.cli.cli_function_discovery as owner
assert owner._recover_fast_exe_catalog is replacement
"""
    )
    assert result.returncode == 0, result.stderr


def test_cli_override_and_restore_reaches_owner() -> None:
    """Facade writes mirror into loaded owners and restore them."""
    result = _run(
        """
import inertia.cli.cli as facade
import inertia.cli.cli_function_discovery as owner
original = owner._recover_fast_exe_catalog
def replacement(*args, **kwargs):
    return None
facade._recover_fast_exe_catalog = replacement
assert owner._recover_fast_exe_catalog is replacement
facade._recover_fast_exe_catalog = original
assert owner._recover_fast_exe_catalog is original
"""
    )
    assert result.returncode == 0, result.stderr
