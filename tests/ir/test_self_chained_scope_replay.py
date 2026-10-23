"""An identical chained scope authenticates its parent through one forced replay."""

import sys
from dataclasses import replace

import pytest

from inertia.ir import real16_invocation_domain as owner
from tests.ir.test_forward_declared_call_scope import _collect, _forward_world

pytestmark = pytest.mark.decompiler


@pytest.fixture
def chained_scope():
    world = _forward_world()
    records = _collect(world)
    assert all(row.failure is None for row in records)
    scope = records[0].callee.state.invocation_scope
    assert isinstance(scope.chain, owner.Real16CallChainLink8616)
    return world, scope


def test_identical_chain_replays_parent_only_after_native_entry_gates(chained_scope):
    _world, scope = chained_scope
    callers = []

    def observe(code, _offset):
        if code.co_name == "_derive_invocation_domain_8616":
            callers.append(sys._getframe(2).f_code.co_name)

    sys.monitoring.use_tool_id(4, "identical-chain-replay")
    sys.monitoring.register_callback(4, sys.monitoring.events.PY_START, observe)
    sys.monitoring.set_events(4, sys.monitoring.events.PY_START)
    try:
        assert owner.same_real16_entry_scope_8616(scope, scope)
    finally:
        sys.monitoring.set_events(4, 0)
        sys.monitoring.free_tool_id(4)
    assert callers == ["_replay_complete_8616", "_derive_parent_for_chain_8616"]


@pytest.mark.parametrize("address, replacement", [(0x1040, b"\x90"), (0x1051, bytes.fromhex("ffe2"))])
def test_identical_chain_refuses_changed_native_bytes(chained_scope, address, replacement):
    world, scope = chained_scope
    world[0].loader.memory.store(address, replacement)
    assert not owner.same_real16_entry_scope_8616(scope, scope)


def test_identical_chain_refuses_changed_parent_capture(chained_scope):
    _world, scope = chained_scope
    parent = replace(scope.chain.parent, callsite_call_state=())
    changed = replace(scope, chain=replace(scope.chain, parent=parent))
    assert not owner.same_real16_entry_scope_8616(changed, changed)


def test_identical_chain_keeps_structural_depth_limit(chained_scope):
    _world, scope = chained_scope
    assert not owner._same_scope_8616(scope, scope, owner._CHAIN_DEPTH_LIMIT_8616)


def test_identical_chain_refuses_missing_link(chained_scope):
    _world, scope = chained_scope
    changed = replace(scope, chain=None)
    assert not owner.same_real16_entry_scope_8616(changed, changed)


@pytest.mark.parametrize("mutation", ["native", "source", "frame", "frame_value", "declaration"])
def test_identical_chain_rechecks_inputs_after_native_callback(chained_scope, monkeypatch, mutation):
    from inertia.semantics import direct_near_call_target_binding as binding_owner

    world, scope = chained_scope
    project, boot, _artifact, _boundary, _resolver, admission = world
    original = binding_owner._target_bytes_bound_8616
    invoked = []

    def native_gate(*args):
        result = original(*args)
        invoked.append(True)
        if mutation == "native":
            project.loader.memory.store(0x1040, b"\x90")
        elif mutation == "source":
            object.__setattr__(boot, "source", b"\0" + boot.source[1:])
        elif mutation == "frame":
            object.__setattr__(scope.chain, "call_state", ())
        elif mutation == "frame_value":
            object.__setattr__(scope.chain, "call_state", tuple(
                (name, value ^ 1 if name == "sp" else value)
                for name, value in scope.chain.call_state
            ))
        else:
            object.__setattr__(admission, "spec", replace(admission.spec, entry_offset=0x41))
        return result

    monkeypatch.setattr(binding_owner, "_target_bytes_bound_8616", native_gate)
    assert not owner.same_real16_entry_scope_8616(scope, scope)
    assert invoked


def test_identical_boot_without_coverage_keeps_coterminality_refusal(chained_scope):
    _world, scope = chained_scope
    changed = replace(scope, chain=None, kind=owner.Real16InvocationKind8616.BOOT_ENTRY_PATH)
    assert not owner.same_real16_entry_scope_8616(changed, changed)


def test_identical_cyclic_chain_refuses(chained_scope):
    _world, scope = chained_scope
    object.__setattr__(scope.chain, "parent", scope)
    assert not owner.same_real16_entry_scope_8616(scope, scope)
