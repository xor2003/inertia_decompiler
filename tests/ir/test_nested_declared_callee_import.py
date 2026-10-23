"""Nested native caller evidence supports conditional helper frame proofs."""
import hashlib
import io
from dataclasses import replace

import angr
import pytest

from inertia.cli.declared_entry_index import build_declared_entry_index_8616
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.declared_function_entry import admit_declared_function_entry_8616
from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from inertia.ir import entry_domain_call_preservation as owner
from inertia.ir.real16_invocation_domain import real16_native_census_import_8616
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from tests.ir.test_declared_function_entry_domain import _recompute
from tests.ir.test_forward_declared_call_scope import _collect, _forward_world
from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.runtime.real16_replay_model import LinearRange

pytestmark = pytest.mark.decompiler


def _nested_world(*, guarded=False, body=b"\xe8\xed\xff\xc3", forward_helper=False):
    """Build a declared caller and one native intermediate call body."""
    _project, old_boot, _artifact, _boundary, _resolver, old_admission = _forward_world(guarded=guarded)
    source = bytearray(old_boot.source)
    caller = bytes.fromhex('b83412e80a00e81700c3')
    source[0x60:0x60+len(caller)] = caller
    source[0x80:0x80+len(body)] = body
    extra_ranges = ()
    if forward_helper:
        helper = bytes.fromhex('5985c07402ffe1cd21c3' if guarded else '59ffe1')
        source[0x94:0x94+len(helper)] = helper
        extra_ranges = (LinearRange(0x1074, len(helper)),)
    boot = program_from_mz_bytes(bytes(source), old_boot.environment, code_ranges=(
        *old_boot.image.code_ranges, LinearRange(0x1060, len(body)), *extra_ranges,
    ))
    module = boot.image.chunks[0][1]
    project = angr.Project(io.BytesIO(module), main_opts={
        'backend': 'blob', 'arch': Arch86_16(), 'base_addr': 0x1000, 'entry_point': 0x1000,
    }, auto_load_libs=False)
    spec = replace(old_admission.spec, source_sha256=hashlib.sha256(boot.source).hexdigest(),
                   relocated_sha256=hashlib.sha256(module).hexdigest(),
                   native_sha256=hashlib.sha256(caller).hexdigest())
    admission = admit_declared_function_entry_8616(
        spec, source=boot.source, loaded_module=module, environment_sha256=spec.environment_sha256,
    )
    assert admission is not None
    boundary = exact_function_range_boundary_8616(project, 0x1040, 0x1040+len(caller))
    assert boundary is not None
    artifact = real16_native_census_import_8616(project, boundary)
    assert artifact is not None

    def resolver(instruction):
        return resolve_direct_call_target_from_instruction_8616(project, instruction)

    index, pending = build_declared_entry_index_8616(project, (admission,), resolver, None)
    owner.install_real16_invocation_source_8616(project, owner.Real16InvocationSource8616(
        boot, _recompute, index, pending_targets=pending, function_entries=(admission,),
    ))
    return project, boot, artifact, boundary, resolver, admission


def test_nested_helper_consumes_declared_descendant_index():
    """A second-level near CALL binds its own frame, not its parent's frame."""
    records = _collect(_nested_world())
    assert len(records) == 2
    assert all(record.failure is None for record in records), [record.failure for record in records]


def test_nested_forward_helper_retains_its_entry_premise():
    """An unconditional forward target still needs a conditional callee entry."""
    world = _nested_world(body=bytes.fromhex('e81100c3'), forward_helper=True)
    records = _collect(world)
    assert len(records) == 2
    assert all(record.failure is None for record in records), [record.failure for record in records]
    callee = records[1].callee
    assert callee is not None
    nested, = callee.state.call_preservations
    assert nested.complete_for(callee.state.invocation_scope)
    world[0].loader.memory.store(0x1075, bytes.fromhex('ffe2'))
    assert not nested.complete_for(callee.state.invocation_scope)


def test_prior_nested_calls_remain_in_the_transported_prefix():
    """The second inner call consumes the first inner call's completed proof."""
    records = _collect(_nested_world(body=bytes.fromhex('e8edffe8eaffc3')))
    assert len(records) == 2 and all(record.failure is None for record in records)
    closure = records[1].callee
    assert closure is not None and len(closure.state.call_preservations) == 2
    assert closure.state.invocation_scope is not None
    assert all(proof.complete_for(closure.state.invocation_scope) for proof in closure.state.call_preservations)


def test_nested_guard_uses_inner_register_state():
    """Known nonzero outer AX cannot discharge an inner helper called with zero."""
    records = _collect(_nested_world(guarded=True, body=bytes.fromhex('b80000e8eaffc3')))
    assert records[0].failure is None
    assert records[1].failure is not None


def test_nested_proof_rejects_parent_scope_and_changed_native_bytes():
    """A successful nested proof is neither universal nor reusable after mutation."""
    world = _nested_world()
    records = _collect(world)
    outer = records[1]
    assert outer.failure is None and outer.callee is not None
    scope = outer.callee.state.invocation_scope
    nested, = outer.callee.state.call_preservations
    assert scope is not None and nested.complete_for(scope)
    assert not nested.complete_for(None)
    assert not nested.complete_for(records[0].required_scope)
    world[0].loader.memory.store(0x1050, bytes.fromhex('5affe2'))
    assert not outer.complete_for(outer.required_scope)


def test_revoked_parent_after_nested_replay_is_a_refusal(monkeypatch):
    """Do not submit a newly invalid invocation to the segment-state solver."""
    world = _nested_world()
    original = owner._nested_callsite_proof_8616
    revoked = False

    def revoke(*args, **kwargs):
        nonlocal revoked
        proof = original(*args, **kwargs)
        if proof is not None:
            world[0].loader.memory.store(0x1050, bytes.fromhex('5affe2'))
            revoked = True
        return proof

    monkeypatch.setattr(owner, '_nested_callsite_proof_8616', revoke)
    records = _collect(world)
    assert revoked
    assert records[1].failure is not None
