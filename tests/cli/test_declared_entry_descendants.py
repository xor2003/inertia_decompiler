"""Declared-entry index closes bounded direct near-call descendants.

A declared root keeps its explicit extent authority; each decoded direct
near-call target is attempted once through the mapped boundary producer
with no premise. Unclosed, indirect, unmapped, or far targets stay pending
instead of being silently dropped.
"""
import hashlib
import io
from dataclasses import replace

import angr
import pytest

from inertia.cli.declared_entry_index import build_declared_entry_index_8616
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.frontend.x86_16.declared_function_entry import (
    DeclaredEntryMemory8616,
    DeclaredEntryReturn8616,
    DeclaredEntryReturnKind8616,
    DeclaredFunctionEntryAdmission8616,
    DeclaredFunctionEntrySpec8616,
    admit_declared_function_entry_8616,
)
from inertia.frontend.x86_16.frontend_invocation_inventory import InvocationInventoryBudget8616
from inertia.ir.real16_declared_interrupt8616 import declared_environment_digest_8616
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from tests.ir import test_x86_16_declared_interrupt_boundary as native
from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.runtime.real16_replay_model import LinearRange

pytestmark = pytest.mark.decompiler

ROOT = 0x1020
CALLEE = 0x1030
HELPER = 0x1040


def _world(*, callee: bytes | None = None, helper: bytes | None = None):
    """Build a declared root that near-calls a RET callee which near-calls a helper."""
    apply_x86_16_bootstrap()
    root = bytes.fromhex('b83412') + b'\xe8' + (CALLEE - 0x1026).to_bytes(2, 'little', signed=True) + b'\xc3'
    body = (bytes.fromhex('40') + b'\xe8'
            + (HELPER - 0x1034).to_bytes(2, 'little', signed=True) + b'\xc3') if callee is None else callee
    tail = bytes.fromhex('59ffe1') if helper is None else helper  # pop cx; jmp cx
    image = bytearray(0x80)
    image[:2] = bytes.fromhex('0f0b')  # Header startup is deliberately unsupported.
    image[0x20:0x20 + len(root)] = root
    image[0x30:0x30 + len(body)] = body
    image[0x40:0x40 + len(tail)] = tail
    header = bytearray(32)
    header[:2] = b'MZ'
    for offset, value in ((2, 160), (4, 1), (8, 2), (10, 0x10), (12, 0x40),
                          (14, 0x10), (16, 0x100), (24, 0x1c)):
        header[offset:offset + 2] = value.to_bytes(2, 'little')
    source = bytes(header + image)
    environment = replace(native._environment(), psp_segment=0xf0, allocation=bytes(0x500))
    boot = program_from_mz_bytes(source, environment, code_ranges=(
        LinearRange(0x1000, 2), LinearRange(0x1020, len(root)),
        LinearRange(0x1030, len(body)), LinearRange(0x1040, len(tail)),
    ))
    module = boot.image.chunks[0][1]
    project = angr.Project(io.BytesIO(module), main_opts={
        'backend': 'blob', 'arch': Arch86_16(), 'base_addr': 0x1000, 'entry_point': 0x1000,
    }, auto_load_libs=False)
    digest = declared_environment_digest_8616(environment)
    spec = DeclaredFunctionEntrySpec8616(
        version=1, source_sha256=hashlib.sha256(source).hexdigest(),
        relocated_sha256=hashlib.sha256(module).hexdigest(), load_segment=0x100,
        entry_segment=0x100, entry_offset=0x20, range_start=ROOT,
        range_end=ROOT + len(root), native_sha256=hashlib.sha256(root).hexdigest(),
        environment_sha256=digest, use_environment_memory=False,
        registers=(('ds', 0x100), ('sp', 0x80), ('ss', 0x120)),
        memory=(DeclaredEntryMemory8616(0x1280, bytes.fromhex('7000')),),
        return_boundary=DeclaredEntryReturn8616(DeclaredEntryReturnKind8616.NEAR, 0x100, 0x70),
    )
    admission = admit_declared_function_entry_8616(
        spec, source=source, loaded_module=module, environment_sha256=digest,
    )
    assert isinstance(admission, DeclaredFunctionEntryAdmission8616)

    def resolver(instruction):
        return resolve_direct_call_target_from_instruction_8616(project, instruction)

    return project, admission, resolver


def _index(world, budget=None):
    project, admission, resolver = world
    return build_declared_entry_index_8616(project, (admission,), resolver, budget)


def test_descendant_census_indexes_nested_near_call_edges():
    index, pending = _index(_world())
    (root_edge,) = index.for_target(CALLEE)
    assert root_edge.caller_start == ROOT and not root_edge.is_far
    (inner_edge,) = index.for_target(HELPER)
    assert inner_edge.caller_start == CALLEE and not inner_edge.is_far
    # The popped-return helper cannot close without a transported premise.
    assert pending == (HELPER,)
    assert {census.entry_addr for census in index.caller_censuses} == {ROOT, CALLEE}


def test_descendant_mutated_into_plain_ret_closes():
    project, admission, resolver = _world()
    project.loader.memory.store(HELPER, b'\xc3')
    index, pending = build_declared_entry_index_8616(project, (admission,), resolver, None)
    assert index.for_target(HELPER) and pending == ()


def test_descendant_cycle_and_self_call_dedup():
    callee = (b'\xe8' + (ROOT - 0x1033).to_bytes(2, 'little', signed=True)
              + b'\xe8' + (CALLEE - 0x1036).to_bytes(2, 'little', signed=True) + b'\xc3')
    index, pending = _index(_world(callee=callee))
    assert index.for_target(CALLEE)  # root edge plus callee self-call
    assert index.for_target(ROOT)  # callee back edge into the declared head
    assert pending == ()


def test_descendant_boundary_cap_preserves_exhausted_heads_pending():
    index, pending = _index(_world(), InvocationInventoryBudget8616(
        max_boundaries=2, max_instructions=65536, max_root_inputs=4096,
    ))
    assert index.for_target(CALLEE) and index.for_target(HELPER)
    assert pending == (HELPER,)  # unattempted under the shared boundary cap


def test_descendant_instruction_cap_preserves_refused_head_pending():
    index, pending = _index(_world(), InvocationInventoryBudget8616(
        max_boundaries=64, max_instructions=3, max_root_inputs=4096,
    ))
    assert index.for_target(CALLEE)
    assert not index.for_target(HELPER)
    assert pending == (CALLEE,)


def test_far_and_out_of_image_targets_stay_pending():
    far_body = bytes.fromhex('9a5000 00f0'.replace(' ', '')) + b'\xc3'
    index, pending = _index(_world(callee=far_body))
    far_target = 0xF0000 + 0x50
    (edge,) = index.for_target(far_target)
    assert edge.caller_start == CALLEE
    assert far_target in pending and CALLEE not in pending
    assert all(census.entry_addr != far_target for census in index.caller_censuses)


def test_unmapped_near_target_stays_pending():
    body = (b'\xe8' + (0x9000 - 0x1033).to_bytes(2, 'little', signed=True) + b'\xc3')
    index, pending = _index(_world(callee=body))
    assert index.for_target(0x9000)
    assert pending == (0x9000,)


def test_in_image_far_call_does_not_traverse_its_destination():
    """An in-image FAR call is indexed without assuming a near-call context."""
    index, pending = _index(_world(callee=bytes.fromhex('9a40000001c3'), helper=b'\xc3'))
    assert index.for_target(HELPER)
    assert pending == (HELPER,)
    assert {census.entry_addr for census in index.caller_censuses} == {ROOT, CALLEE}


def test_one_boundary_budget_never_decodes_a_descendant(monkeypatch):
    """The shared cap gates decode itself, not merely publication afterward."""
    world = _world()

    def forbidden(*args, **kwargs):
        pytest.fail('descendant decoded after boundary budget exhaustion')

    monkeypatch.setattr('inertia.cli.declared_entry_index.mapped_entry_function_boundary_8616', forbidden)
    index, pending = _index(world, InvocationInventoryBudget8616(max_boundaries=1))
    assert index.for_target(CALLEE)
    assert pending == (CALLEE,)
