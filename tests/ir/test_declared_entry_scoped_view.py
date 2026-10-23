"""Declared entry domains transport only their identical native scoped surface."""
import hashlib
import io
from dataclasses import replace

import angr
import pytest

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.frontend.x86_16.declared_function_entry import admit_declared_function_entry_8616
from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from inertia.ir.entry_jump_domain import prove_entry_jump_domains_8616
from inertia.ir.function_ir_registry import registered_function_ir_artifact_8616
from inertia.ir.real16_invocation_domain import (
    DeclaredFunctionEntryLink8616,
    prove_real16_declared_function_entry_domain_8616,
    real16_native_census_import_8616,
)
from inertia.ir.scoped_function_ir_view import (
    ScopedFunctionIRViewFailure8616,
    _scope_surface_bound_8616,
    prove_scoped_function_ir_view_8616,
)
from inertia.ir.segment_state import build_x86_16_segment_state_artifact
from inertia.ir.vex_import import raw_x86_16_import_bundle_for_artifact_8616
from tests.ir.test_declared_function_entry_domain import _recompute, _world
from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.runtime.real16_replay_model import LinearRange

pytestmark = pytest.mark.decompiler


@pytest.fixture
def native_scope():
    """A native jump has an authenticated, explicitly declared entry prefix."""
    apply_x86_16_bootstrap()
    _project, original, old_link = _world()
    # Crossing a paragraph on the backward edge needs the declared CS proof.
    body = bytes.fromhex("b83412") + b"\x90" * 14 + bytes.fromhex("ebed")
    source = bytearray(original.source)
    source[0x40:0x40+len(body)] = body
    boot = program_from_mz_bytes(bytes(source), original.environment, code_ranges=(
        LinearRange(0x1000, 2), LinearRange(0x1020, len(body)), LinearRange(0x1070, 1),
    ))
    module = boot.image.chunks[0][1]
    project = angr.Project(io.BytesIO(module), main_opts={
        "backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000, "entry_point": 0x1000,
    }, auto_load_libs=False)
    boundary = exact_function_range_boundary_8616(project, 0x1020, 0x1020+len(body))
    assert boundary is not None
    artifact = real16_native_census_import_8616(project, boundary)
    assert artifact is not None
    spec = replace(old_link.admission.spec, source_sha256=hashlib.sha256(boot.source).hexdigest(),
                   relocated_sha256=hashlib.sha256(module).hexdigest(),
                   native_sha256=hashlib.sha256(body).hexdigest(), range_end=0x1020+len(body))
    admission = admit_declared_function_entry_8616(spec, source=boot.source, loaded_module=module,
                                                environment_sha256=spec.environment_sha256)
    link = DeclaredFunctionEntryLink8616(admission, artifact, boundary)
    scope = prove_real16_declared_function_entry_domain_8616(project, link, 0x1031, boot=boot, boot_recompute=_recompute)
    assert scope.complete, scope.failure
    bundle = raw_x86_16_import_bundle_for_artifact_8616(project, boundary, artifact)
    assert bundle is not None and bundle.artifact is artifact
    proof = prove_entry_jump_domains_8616(
        artifact, bundle.terminal_evidence, project=project,
        invocation_resolver=lambda site: prove_real16_declared_function_entry_domain_8616(
            project, link, site, boot=boot, boot_recompute=_recompute,
        ),
    )
    return project, link, scope, proof


def test_native_declared_entry_builds_scoped_segment_state_without_publication(native_scope):
    project, link, scope, proof = native_scope
    before = registered_function_ir_artifact_8616(project, link.artifact.function_addr)
    assert _scope_surface_bound_8616(scope, link.artifact, link.boundary)
    view = prove_scoped_function_ir_view_8616(link.artifact, link.boundary, proof, invocation_scope=scope)
    assert view.failure is None, (proof.to_dict(), view.to_dict())
    state = build_x86_16_segment_state_artifact(link.artifact, invocation_scope=scope, scoped_view=view)
    assert state.invocation_scope is scope
    assert state.source_artifact is link.artifact
    assert state.scoped_view is view
    assert registered_function_ir_artifact_8616(project, link.artifact.function_addr) == before


@pytest.mark.parametrize("mutation", ["artifact", "boundary", "declaration", "declaration_digest", "native"])
def test_changed_declared_scope_cannot_authorize_a_view(native_scope, mutation):
    project, link, scope, proof = native_scope
    artifact, boundary = link.artifact, link.boundary
    if mutation == "artifact":
        artifact = replace(artifact)
    elif mutation == "boundary":
        boundary = replace(boundary)
    elif mutation == "declaration":
        forged = replace(link.admission, spec=replace(link.admission.spec, entry_offset=0x21))
        scope = replace(scope, chain=replace(link, admission=forged))
    elif mutation == "declaration_digest":
        forged = replace(link.admission, declaration_sha256="0" * 64)
        scope = replace(scope, chain=replace(link, admission=forged))
    else:
        project.loader.memory.store(0x1022, b"\x90")
    view = prove_scoped_function_ir_view_8616(artifact, boundary, proof, invocation_scope=scope)
    assert view.failure is ScopedFunctionIRViewFailure8616.SCOPE_UNBOUND
