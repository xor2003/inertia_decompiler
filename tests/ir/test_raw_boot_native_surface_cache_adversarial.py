"""Adversarial identity-lifetime controls for request-local import reuse.

Identity-only key authorities (architecture, importer, builder, registry and
registry artifacts) must stay reachable while a record exists: a freed owner can
have its ``id()`` recycled by a different authority, colliding with the retained
key and serving stale imported evidence. Records must pin those owners, and
eviction must release them.
"""
import gc
import io
import weakref

import angr
import pytest

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from inertia.ir import raw_boot_native_surface_cache as owner
from inertia.ir.core import IRFunctionArtifact

pytestmark = pytest.mark.decompiler


def _world():
    arch = Arch86_16()
    arch.bits = 32
    project = angr.Project(io.BytesIO(bytes.fromhex('e80000e80000c3')),
        main_opts={'backend': 'blob', 'arch': arch, 'base_addr': 0x10000,
                   'entry_point': 0x10000}, auto_load_libs=False)
    boundary = exact_function_range_boundary_8616(project, 0x10000, 0x10007)
    assert boundary is not None
    return project, boundary


def _importer(calls):
    def importer(current, surface):
        calls.append(surface)
        return IRFunctionArtifact(surface.addr)
    return importer


def test_record_pins_importer_until_evicted():
    project, boundary = _world()
    source = object()
    cache = owner.RawBootNativeSurfaceCache8616()
    calls = []
    importer = _importer(calls)
    owner.request_raw_boot_native_import_8616(cache, project, source, boundary, importer)
    assert len(calls) == 1
    handle = weakref.ref(importer)
    del importer
    gc.collect()
    # The importer id is part of the retained key; dropping the only strong
    # reference frees it and lets a different callable recycle that identity.
    assert handle() is not None
    cache.records.clear()
    gc.collect()
    assert handle() is None


def test_record_pins_architecture_and_registry_artifact_authorities():
    project, boundary = _world()
    registry_artifact = IRFunctionArtifact(0x10000)
    registry = {0x10000: registry_artifact}
    project._inertia_function_ir_artifacts_8616 = registry
    source = object()
    cache = owner.RawBootNativeSurfaceCache8616()
    owner.request_raw_boot_native_import_8616(
        cache, project, source, boundary, _importer([]))
    record = cache.records[boundary.addr]
    pinned = record.pinned
    assert any(authority is registry for authority in pinned)
    assert any(authority is registry_artifact for authority in pinned)
    arch = project.arch
    assert any(authority is arch for authority in pinned)


def test_distinct_source_identity_reimports():
    project, boundary = _world()
    cache = owner.RawBootNativeSurfaceCache8616()
    calls = []
    importer = _importer(calls)
    owner.request_raw_boot_native_import_8616(cache, project, object(), boundary, importer)
    owner.request_raw_boot_native_import_8616(cache, project, object(), boundary, importer)
    assert len(calls) == 2
    assert cache.reuse_count == 0


@pytest.mark.parametrize("mutate", [False, True])
def test_unknown_registry_metadata_disables_reuse(mutate):
    """Opaque registry metadata cannot establish freshness, changed or not."""
    project, boundary = _world()
    artifact = IRFunctionArtifact(0x10000, summary={"opaque": object()})
    project._inertia_function_ir_artifacts_8616 = {artifact.function_addr: artifact}
    source = object()
    calls = []
    importer = _importer(calls)
    cache = owner.RawBootNativeSurfaceCache8616()
    owner.request_raw_boot_native_import_8616(cache, project, source, boundary, importer)
    if mutate:
        artifact.summary["opaque"] = object()
    owner.request_raw_boot_native_import_8616(cache, project, source, boundary, importer)
    assert len(calls) == 2
    assert cache.reuse_count == 0
    assert not cache.records


def test_registry_becoming_opaque_evicts_prior_native_import():
    """A formerly valid registry cannot retain imports after losing freshness."""
    project, boundary = _world()
    artifact = IRFunctionArtifact(0x10000)
    project._inertia_function_ir_artifacts_8616 = {artifact.function_addr: artifact}
    source = object()
    calls = []
    importer = _importer(calls)
    cache = owner.RawBootNativeSurfaceCache8616()
    owner.request_raw_boot_native_import_8616(cache, project, source, boundary, importer)
    assert cache.records
    artifact.summary["opaque"] = object()
    for _ in range(2):
        owner.request_raw_boot_native_import_8616(cache, project, source, boundary, importer)
        assert not cache.records
    assert len(calls) == 3
    assert cache.reuse_count == 0


@pytest.mark.parametrize("prime", [False, True])
def test_snapshot_exhausts_budget_without_import_or_reuse(monkeypatch, prime):
    """Freshness snapshots may expire, but cannot expose late artifacts."""
    project, boundary = _world()
    source = object()
    cache = owner.RawBootNativeSurfaceCache8616()
    calls = []
    importer = _importer(calls)
    if prime:
        assert owner.request_raw_boot_native_import_8616(cache, project, source, boundary, importer) is not None
    expired = [False]
    original = owner._surface_key_8616

    def snapshot(*args):
        result = original(*args)
        expired[0] = True
        return result

    monkeypatch.setattr(owner, "_surface_key_8616", snapshot)
    assert owner.request_raw_boot_native_import_8616(
        cache, project, source, boundary, importer, should_abort=lambda: expired[0],
    ) is None
    assert len(calls) == int(prime)
    assert cache.reuse_count == 0
    assert cache.records == {}


def test_expired_entry_evicts_without_snapshot(monkeypatch):
    project, boundary = _world()
    source = object()
    cache = owner.RawBootNativeSurfaceCache8616()
    calls = []
    importer = _importer(calls)
    owner.request_raw_boot_native_import_8616(cache, project, source, boundary, importer)
    monkeypatch.setattr(owner, "_surface_key_8616", lambda *_: pytest.fail("late snapshot"))
    assert owner.request_raw_boot_native_import_8616(
        cache, project, source, boundary, importer, should_abort=lambda: True,
    ) is None
    assert cache.records == {}
    assert len(calls) == 1


def test_live_abort_predicate_preserves_cache_hit():
    project, boundary = _world()
    source = object()
    cache = owner.RawBootNativeSurfaceCache8616()
    calls = []
    importer = _importer(calls)
    first = owner.request_raw_boot_native_import_8616(
        cache, project, source, boundary, importer, should_abort=lambda: False,
    )
    assert owner.request_raw_boot_native_import_8616(
        cache, project, source, boundary, importer, should_abort=lambda: False,
    ) is first
    assert len(calls) == 1
    assert cache.reuse_count == 1


def test_artifact_snapshot_expiry_evicts_hit(monkeypatch):
    """An artifact JSON check cannot return evidence after consuming its budget."""
    project, boundary = _world()
    source = object()
    cache = owner.RawBootNativeSurfaceCache8616()
    calls = []
    importer = _importer(calls)
    artifact = owner.request_raw_boot_native_import_8616(cache, project, source, boundary, importer)
    assert artifact is not None
    expired = [False]
    original = IRFunctionArtifact.to_dict

    def projection(current):
        result = original(current)
        if current is artifact:
            expired[0] = True
        return result

    monkeypatch.setattr(IRFunctionArtifact, "to_dict", projection)
    assert owner.request_raw_boot_native_import_8616(
        cache, project, source, boundary, importer, should_abort=lambda: expired[0],
    ) is None
    assert cache.records == {}
    assert cache.reuse_count == 0
    assert len(calls) == 1
