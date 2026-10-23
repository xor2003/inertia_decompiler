"""Native scoped-view requests reuse facts, reprove, and invalidate on mutation."""
import pytest

from inertia.ir import vex_import
from inertia.ir.scoped_function_ir_view import ScopedFunctionIRViewFailure8616
from tests.ir.test_declared_entry_scoped_view import native_scope as native_scope
from tests.ir.test_declared_function_entry_intake import _install

pytestmark = pytest.mark.decompiler


def test_raw_rebind_does_not_rebuild_unused_semantic_products(native_scope, monkeypatch):
    """Native rebind compares source facts without rebuilding discarded summaries."""
    project, link, _, _ = native_scope
    original = vex_import._finalize_x86_16_ir_artifact_8616
    finalized = []

    def finalize(*args, **kwargs):
        finalized.append(args)
        return original(*args, **kwargs)

    monkeypatch.setattr(vex_import, "_finalize_x86_16_ir_artifact_8616", finalize)
    bundle = vex_import.raw_x86_16_import_bundle_for_artifact_8616(
        project, link.boundary, link.artifact,
    )
    assert bundle is not None and bundle.artifact is link.artifact
    assert bundle.terminal_evidence
    assert not finalized


@pytest.mark.parametrize("expiry_stage", ["import", "comparison"])
def test_raw_rebind_checks_deadline_after_work(native_scope, monkeypatch, expiry_stage):
    """Expiring during native intake or graph comparison cannot produce a binding."""
    from inertia.ir import source_graph_binding

    project, link, _, _ = native_scope
    expired = False
    owner = vex_import if expiry_stage == "import" else source_graph_binding
    name = ("_import_x86_16_function_surface_8616" if expiry_stage == "import"
            else "source_graphs_equal_8616")
    original = (vex_import._import_x86_16_function_surface_8616 if expiry_stage == "import"
                else source_graph_binding.source_graphs_equal_8616)

    def expire_after_work(*args, **kwargs):
        nonlocal expired
        result = original(*args, **kwargs)
        expired = True
        return result

    monkeypatch.setattr(vex_import, "direct_evidence_deadline_expired_8616", lambda _: expired)
    monkeypatch.setattr(owner, name, expire_after_work)
    assert vex_import.raw_x86_16_import_bundle_for_artifact_8616(
        project, link.boundary, link.artifact,
    ) is None


def test_native_cfg_consumption_shares_lifts_only_inside_one_request(monkeypatch):
    """Repeated native proof checks share raw lifting, not proof or later requests."""
    from tests.ir.test_near_call_scoped_view import _native_pending_view_surface

    surface, scope = _native_pending_view_surface()
    bundle = vex_import.raw_x86_16_import_bundle_for_artifact_8616(
        surface.project, surface.boundary, surface.artifact,
    )
    assert bundle is not None
    view = vex_import.prove_scoped_x86_16_ir_function_view_8616(
        surface.project, bundle, surface.boundary, near_call_scope=scope,
    )
    assert view.failure is None
    original = vex_import._lift_x86_16_function_surface_8616
    root_lifts = 0

    def lift(project, function):
        nonlocal root_lifts
        if function.addr == surface.artifact.function_addr:
            root_lifts += 1
        return original(project, function)

    monkeypatch.setattr(vex_import, "_lift_x86_16_function_surface_8616", lift)
    for expected_lifts in (1, 2):
        projection = view.cfg_projection_for(scope)
        assert projection is not None and projection.scope is scope
        assert root_lifts == expected_lifts
    surface.project.loader.memory.store(0x1011, b"\x00")
    assert view.cfg_projection_for(scope) is None


def test_scoped_request_reuses_lifting_but_repeats_proofs_and_releases_cache(native_scope, monkeypatch):
    project, link, scope, _ = native_scope
    _install(project, scope.boot, link)
    bundle = vex_import.raw_x86_16_import_bundle_for_artifact_8616(project, link.boundary, link.artifact)
    assert bundle is not None
    counts = {'requests': 0, 'lifts': 0, 'proofs': 0}
    old_request = vex_import._import_x86_16_function_surface_8616
    old_lift = vex_import._lift_x86_16_function_surface_8616
    old_proof = vex_import.prove_entry_jump_domains_8616

    def request(*args, **kwargs):
        counts['requests'] += 1
        return old_request(*args, **kwargs)

    def lift(*args, **kwargs):
        counts['lifts'] += 1
        return old_lift(*args, **kwargs)

    def proof(*args, **kwargs):
        counts['proofs'] += 1
        # Real premise consumers can reimport the same native surface several
        # times; exercise that request pattern without substituting any proof.
        for _ in range(2):
            retained = vex_import.raw_x86_16_import_bundle_for_artifact_8616(
                project, link.boundary, link.artifact)
            assert retained is not None and retained.artifact is link.artifact
        return old_proof(*args, **kwargs)

    monkeypatch.setattr(vex_import, '_import_x86_16_function_surface_8616', request)
    monkeypatch.setattr(vex_import, '_lift_x86_16_function_surface_8616', lift)
    monkeypatch.setattr(vex_import, 'prove_entry_jump_domains_8616', proof)
    for index in (1, 2):
        view = vex_import.prove_scoped_x86_16_ir_function_view_8616(
            project, bundle, link.boundary, invocation_scope=scope)
        assert view.failure is None
        assert counts['proofs'] == index
        assert counts['lifts'] == index
        assert counts['requests'] > counts['lifts']


def test_scoped_request_refuses_native_bytes_changed_during_revalidation(native_scope, monkeypatch):
    project, link, scope, _ = native_scope
    _install(project, scope.boot, link)
    bundle = vex_import.raw_x86_16_import_bundle_for_artifact_8616(project, link.boundary, link.artifact)
    assert bundle is not None
    native = vex_import._lift_x86_16_function_surface_8616
    lifted = []

    def mutate_after_lifting(*args, **kwargs):
        surface = native(*args, **kwargs)
        lifted.append(surface)
        if len(lifted) == 1:
            project.loader.memory.store(0x1021, b'\x35')
        return surface

    monkeypatch.setattr(vex_import, '_lift_x86_16_function_surface_8616', mutate_after_lifting)
    view = vex_import.prove_scoped_x86_16_ir_function_view_8616(
        project, bundle, link.boundary, invocation_scope=scope)
    assert lifted
    assert view.failure is ScopedFunctionIRViewFailure8616.SCOPE_UNBOUND
