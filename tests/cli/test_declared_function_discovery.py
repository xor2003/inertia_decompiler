"""Declared call-closure selection preserves incomplete native obligations."""
import pytest

from inertia.cli.declared_function_discovery import (
    DeclaredDiscoveryStatus8616,
    declared_discovery_from_index_8616,
    discover_declared_function_closure_8616,
)
from tests.cli.test_declared_entry_descendants import CALLEE, HELPER, ROOT, _index, _world

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize('helper, expected', [(b'\xc3', DeclaredDiscoveryStatus8616.CLOSED),
                                            (None, DeclaredDiscoveryStatus8616.INCOMPLETE)])
def test_declared_selection_keeps_pending_heads(helper, expected):
    world = _world(helper=helper)
    index, pending = _index(world)
    result = declared_discovery_from_index_8616(world[0], (ROOT,), index, pending)
    assert result.status is expected
    assert result.heads == (ROOT, CALLEE, HELPER)
    assert result.caller_targets == ((ROOT, (CALLEE,)), (CALLEE, (HELPER,)))
    assert result.pending_heads == (() if helper else (HELPER,))


def test_indirect_call_keeps_unknown_obligation():
    world = _world(callee=bytes.fromhex('ffd0c3'))
    index, pending = _index(world)
    result = declared_discovery_from_index_8616(world[0], (ROOT,), index, pending)
    assert result.status is DeclaredDiscoveryStatus8616.INCOMPLETE
    assert result.unresolved_callsites == ((CALLEE, CALLEE),)
    assert result.heads == (ROOT, CALLEE)


def test_absent_explicit_entries_preserves_ordinary_discovery():
    assert discover_declared_function_closure_8616(object()) is None


def test_declared_cli_selection_does_not_append_hybrid_candidates(monkeypatch):
    from types import SimpleNamespace

    from inertia.cli import cli_core

    world = _world(helper=b'\xc3')
    index, pending = _index(world)
    discovery = declared_discovery_from_index_8616(world[0], (ROOT,), index, pending)
    monkeypatch.setattr(cli_core, 'discover_declared_function_closure_8616', lambda project: discovery)
    run = cli_core._MainCliRun8616()
    run.project = world[0]
    run.args = SimpleNamespace(max_functions=0)
    run.function_cfg_pairs = []
    assert run._phase_seed_rank_dispatch_8616() is None
    assert run._phase_build_pairs_dispatch_8616() is None
    assert run._phase_configure_display_dispatch_8616() is None
    assert run._phase_build_tasks_dispatch_8616() is None
    assert tuple(item.recovery_addr for item in run.function_tasks) == (ROOT, CALLEE, HELPER)
    assert run.total_functions == 3


def test_declared_cli_incomplete_closure_refuses_visibly(monkeypatch, capsys):
    from inertia.cli import cli_core

    world = _world()
    index, pending = _index(world)
    discovery = declared_discovery_from_index_8616(world[0], (ROOT,), index, pending)
    monkeypatch.setattr(cli_core, 'discover_declared_function_closure_8616', lambda project: discovery)
    run = cli_core._MainCliRun8616()
    run.project = world[0]
    assert run._phase_seed_rank_dispatch_8616() == 5
    assert 'pending heads=' in capsys.readouterr().out
