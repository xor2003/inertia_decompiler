"""Layer: IR tests.
Responsibility: bind declared CALL target projections to native bytes and exact scopes.
"""
import hashlib
import io
from dataclasses import replace

import angr
import pytest

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.frontend.x86_16.declared_function_entry import (
    DeclaredFunctionEntryAdmission8616,
    admit_declared_function_entry_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from inertia.ir import declared_entry_pipeline as pipeline
from inertia.ir import entry_jump_domain as jump
from inertia.ir.entry_domain_call_preservation import Real16InvocationSource8616
from inertia.ir.entry_projection_mode import EntryProjectionMode8616, entry_projection_mode_for_scope_8616
from inertia.ir.native_import_surface_cache import native_import_request_8616
from inertia.ir.real16_invocation_domain import DeclaredFunctionEntryLink8616, real16_native_census_import_8616
from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616
from tests.ir.test_declared_function_entry_domain import _world
from tests.ir.test_declared_function_entry_intake import _install
from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.runtime.real16_replay_model import LinearRange

pytestmark = pytest.mark.decompiler


def _native_entry_world() -> tuple[object, Real16InvocationSource8616, DeclaredFunctionEntryAdmission8616]:
    """Build a real declared CALL and paragraph-crossing native jump."""
    apply_x86_16_bootstrap()
    _, original, old_link = _world()
    body = bytes.fromhex('b83412e84a00') + b'\x90' * 14 + bytes.fromhex('ebea')
    raw = bytearray(original.source)
    raw[0x40:0x40+len(body)] = body
    boot = program_from_mz_bytes(bytes(raw), original.environment, code_ranges=(
        LinearRange(0x1000, 2), LinearRange(0x1020, len(body)), LinearRange(0x1070, 1)))
    module = boot.image.chunks[0][1]
    project = angr.Project(io.BytesIO(module), main_opts={
        'backend': 'blob', 'arch': Arch86_16(), 'base_addr': 0x1000, 'entry_point': 0x1000}, auto_load_libs=False)
    spec = replace(old_link.admission.spec, source_sha256=hashlib.sha256(boot.source).hexdigest(),
                   relocated_sha256=hashlib.sha256(module).hexdigest(), native_sha256=hashlib.sha256(body).hexdigest(),
                   range_end=0x1020+len(body))
    admission = admit_declared_function_entry_8616(spec, source=boot.source, loaded_module=module,
                                                  environment_sha256=spec.environment_sha256)
    assert isinstance(admission, DeclaredFunctionEntryAdmission8616)
    boundary = exact_function_range_boundary_8616(project, 0x1020, 0x1020+len(body))
    assert boundary is not None
    artifact = real16_native_census_import_8616(project, boundary)
    assert artifact is not None
    source = _install(project, boot, DeclaredFunctionEntryLink8616(admission, artifact, boundary))
    return project, source, admission


@pytest.mark.parametrize('mutation', [None, 'foreign', 'native', 'binding'])
def test_declared_target_projection(mutation: str | None) -> None:
    """Use real native E8 authority and refuse changed roots, bytes and operands."""
    project, source, admission = _native_entry_world()
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
        result = pipeline._prepare_native_entry_8616(project, source, admission)
    proof = result.view.proof
    scope = result.scope
    record = proof.call_preservations[0]
    original_args = record.instruction.args
    if mutation == 'foreign':
        scope = replace(scope, chain=replace(scope.chain))
    elif mutation == 'native':
        project.loader.memory.store(record.callsite_addr, b'\x90')
    elif mutation == 'binding':
        object.__setattr__(record.binding, 'target_addr', record.target_addr + 1)
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
        application = jump.apply_entry_jump_domain_8616(
            result.bundle.artifact, proof, invocation_scope=scope,
            projection_mode=EntryProjectionMode8616.CALL_TARGETS)
    if mutation is not None:
        assert application.call_targets == ()
        assert application.call_target_status is not jump.ScopedCallTargetStatus8616.ADMITTED
    else:
        assert entry_projection_mode_for_scope_8616(scope) is EntryProjectionMode8616.CALL_TARGETS
        assert application.call_target_status is jump.ScopedCallTargetStatus8616.ADMITTED
        assert len(application.call_targets) == 1
        target = application.call_targets[0]
        assert target.scope is scope
        assert target.block is record.block and target.instruction is record.instruction
        assert target.target == record.target_addr == 0x1070
        assert target.next_addr == record.callsite_addr + 3
        assert record.instruction.args is original_args
        assert application.call_target_stats.failure_count == 0


@pytest.mark.parametrize('mutation', ['scope', 'binding', 'dependency'])
def test_late_target_batch_mutation_refuses(monkeypatch: pytest.MonkeyPatch, mutation: str) -> None:
    """Later target callbacks cannot revoke a previously admitted dependency."""
    from inertia.ir import entry_domain_call_preservation as owner

    project, source, admission = _native_entry_world()
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
        result = pipeline._prepare_native_entry_8616(project, source, admission)
    original = owner.consume_entry_selector_call_preservation_batch_8616
    count = 0

    def consume(records: tuple, selector: object) -> tuple[bool, ...]:
        nonlocal count
        admitted = original(records, selector)
        count += 1
        if count == 2:
            if mutation == 'scope':
                object.__setattr__(result.scope, 'failure_count', 1)
            elif mutation == 'binding':
                object.__setattr__(records[0].binding, 'target_addr', 0x1071)
            else:
                dependency = result.view.proof.admitted[0].call_dependencies[0]
                object.__setattr__(dependency, 'callsite_addr', dependency.callsite_addr + 1)
        return admitted

    monkeypatch.setattr(owner, 'consume_entry_selector_call_preservation_batch_8616', consume)
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
        application = jump.apply_entry_jump_domain_8616(
            result.bundle.artifact, result.view.proof, invocation_scope=result.scope,
            projection_mode=EntryProjectionMode8616.CALL_TARGETS)
    assert count == 2
    assert not application.call_targets
    assert application.call_target_status is not jump.ScopedCallTargetStatus8616.ADMITTED
