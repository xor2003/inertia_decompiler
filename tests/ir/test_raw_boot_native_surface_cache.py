"""Request-local raw imports must not reuse stale native authorities."""
import io
from dataclasses import replace

import angr
import pytest

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from inertia.ir import raw_boot_native_surface_cache as owner
from inertia.ir.core import IRFunctionArtifact


def _world():
    arch = Arch86_16()
    arch.bits = 32
    project = angr.Project(io.BytesIO(bytes.fromhex('e80000e80000c3')),
        main_opts={'backend': 'blob', 'arch': arch, 'base_addr': 0x10000,
                   'entry_point': 0x10000}, auto_load_libs=False)
    boundary = exact_function_range_boundary_8616(project, 0x10000, 0x10007)
    assert boundary is not None
    calls = []
    def importer(current, surface):
        calls.append(surface)
        return IRFunctionArtifact(surface.addr)
    return project, boundary, calls, importer


def test_two_callsite_requests_reuse_native_import_not_proof():
    project, boundary, calls, importer = _world()
    source = object()
    cache = owner.RawBootNativeSurfaceCache8616()
    first = owner.request_raw_boot_native_import_8616(cache, project, source, boundary, importer)
    second = owner.request_raw_boot_native_import_8616(cache, project, source, boundary, importer)
    assert first is second
    assert len(calls) == 1
    assert cache.reuse_count == 1
    fresh = owner.RawBootNativeSurfaceCache8616()
    owner.request_raw_boot_native_import_8616(fresh, project, source, boundary, importer)
    assert len(calls) == 2


@pytest.mark.parametrize('change', ['bytes', 'boundary', 'architecture', 'importer', 'metadata', 'registry', 'decoded'])
def test_changed_authority_reimports(change, monkeypatch):
    project, boundary, calls, importer = _world()
    source = object()
    cache = owner.RawBootNativeSurfaceCache8616()
    owner.request_raw_boot_native_import_8616(cache, project, source, boundary, importer)
    if change == 'bytes':
        project.loader.memory.store(0x10000, b'\x90')
    elif change == 'boundary':
        boundary = replace(boundary, successor_edges=())
    elif change == 'architecture':
        project.arch.cs_mode += 1
    elif change == 'importer':
        original = importer
        def importer(current, surface):
            return original(current, surface)
    elif change == 'metadata':
        boundary.info['different'] = True
    elif change == 'decoded':
        boundary.blocks[0].instructions[0].insn._raw.id += 1
    elif change == 'registry':
        monkeypatch.setattr(owner, '_existing_registry_8616', lambda current: {9: IRFunctionArtifact(9)})
    owner.request_raw_boot_native_import_8616(cache, project, source, boundary, importer)
    assert len(calls) == 2
    assert cache.reuse_count == 0


def test_refused_imports_are_never_retained():
    project, boundary, calls, _ = _world()
    cache = owner.RawBootNativeSurfaceCache8616()
    source = object()
    def refused(current, surface):
        calls.append(surface)
        return None
    for _ in range(2):
        assert owner.request_raw_boot_native_import_8616(cache, project, source, boundary, refused) is None
    assert len(calls) == 2
    assert not cache.records


def test_mutable_artifact_projection_revokes_reuse():
    project, boundary, calls, importer = _world()
    cache = owner.RawBootNativeSurfaceCache8616()
    source = object()
    artifact = owner.request_raw_boot_native_import_8616(cache, project, source, boundary, importer)
    artifact.summary['tampered'] = True
    owner.request_raw_boot_native_import_8616(cache, project, source, boundary, importer)
    assert len(calls) == 2


def test_raw_cache_binds_flag_policy_without_hit_counters():
    from inertia.ir import status_flag_lift_context as flags

    project, boundary, calls, importer = _world()
    source = object()
    cache = owner.RawBootNativeSurfaceCache8616()
    session = flags.StatusFlagLiftSession8616(
        boundary.addr, (), source_project=project,
        owned_instruction_addresses=boundary.reachable_instruction_addrs,
    )
    owner.request_raw_boot_native_import_8616(cache, project, source, boundary, importer)
    token = flags._active_session.set(session)
    try:
        owner.request_raw_boot_native_import_8616(cache, project, source, boundary, importer)
        assert len(calls) == 2
        session._materialized_addresses.add(boundary.addr)
        owner.request_raw_boot_native_import_8616(cache, project, source, boundary, importer)
        assert len(calls) == 2
        session.owned_instruction_addresses = frozenset()
        owner.request_raw_boot_native_import_8616(cache, project, source, boundary, importer)
        assert len(calls) == 3
        with flags.architectural_status_flag_replay_8616():
            owner.request_raw_boot_native_import_8616(cache, project, source, boundary, importer)
            assert len(calls) == 4
    finally:
        flags._active_session.reset(token)
