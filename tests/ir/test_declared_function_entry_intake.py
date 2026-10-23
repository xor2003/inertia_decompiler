"""Explicit function entries take precedence without inventing a boot path."""

from dataclasses import replace

import pytest

from inertia.frontend.x86_16.frontend_direct_callsite_index import build_boundary_direct_callsite_index_8616
from inertia.ir import entry_domain_call_preservation as owner
from inertia.ir.real16_invocation_domain import Real16InvocationKind8616
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from tests.ir import test_declared_function_entry_domain as native


@pytest.fixture(autouse=True, scope="module")
def _bootstrap():
    native.apply_x86_16_bootstrap()


def _install(project, boot, link):
    index = build_boundary_direct_callsite_index_8616(
        link.boundary,
        direct_target_resolver=lambda instruction: resolve_direct_call_target_from_instruction_8616(
            project, instruction,
        ),
    )
    source = owner.Real16InvocationSource8616(
        boot, native._recompute, index, function_entries=(link.admission,),
    )
    owner.install_real16_invocation_source_8616(project, source)
    return source


def _unexpected_boot(*args, **kwargs):
    pytest.fail("explicit application entry must not fall back to CRT proof")


def test_current_surface_uses_declared_entry_without_caller_search(monkeypatch):
    project, boot, link = native._world()
    _install(project, boot, link)
    monkeypatch.setattr(owner, "_edge_invocation_premise_8616", _unexpected_boot)
    premise = owner.entry_domain_invocation_premise_8616(
        project, link.artifact, link.boundary, 0x1023,
    )
    assert premise is not None and premise.complete
    assert premise.kind is Real16InvocationKind8616.DECLARED_FUNCTION_ENTRY
    assert premise.to_dict()["declared_function_entry"] == link.admission.to_dict()


def test_head_resolution_uses_raw_declared_extent_before_boot(monkeypatch):
    project, boot, link = native._world()
    source = _install(project, boot, link)
    monkeypatch.setattr(owner, "_request_raw_boot_premise_8616", _unexpected_boot)
    premise = owner._registered_invocation_premise_8616(
        project, 0x1020, 0x1023, source,
        owner._PremiseResolution8616(deadline=float("inf")),
    )
    assert premise is not None and premise.complete
    assert premise.kind is Real16InvocationKind8616.DECLARED_FUNCTION_ENTRY


def test_stale_declaration_refuses_without_trying_different_entry(monkeypatch):
    project, boot, link = native._world()
    admission = replace(link.admission, declaration_sha256="0" * 64)
    _install(project, boot, replace(link, admission=admission))
    monkeypatch.setattr(owner, "_edge_invocation_premise_8616", _unexpected_boot)
    assert owner.entry_domain_invocation_premise_8616(
        project, link.artifact, link.boundary, 0x1023,
    ) is None


def test_duplicate_function_entry_is_not_silently_selected():
    project, boot, link = native._world()
    source = _install(project, boot, link)
    duplicate = replace(source, function_entries=(link.admission, link.admission))
    with pytest.raises(TypeError, match="bound index and boot"):
        owner.install_real16_invocation_source_8616(project, duplicate)


def test_declared_entry_keeps_existing_resolution_deadline():
    project, boot, link = native._world()
    source = _install(project, boot, link)
    assert owner._registered_invocation_premise_8616(
        project, 0x1020, 0x1023, source,
        owner._PremiseResolution8616(deadline=0.0),
    ) is None


def test_reentrant_declared_entry_does_not_switch_to_boot(monkeypatch):
    project, boot, link = native._world()
    source = _install(project, boot, link)
    monkeypatch.setattr(owner, "_independent_reentrant_boot_premise_8616", _unexpected_boot)
    resolution = owner._PremiseResolution8616(deadline=float("inf"))
    resolution.in_flight = frozenset({0x1020})
    assert owner._registered_invocation_premise_8616(
        project, 0x1020, 0x1023, source, resolution,
    ) is None


def test_declared_entry_closure_uses_identical_bound_surface():
    project, boot, link = native._world()
    scope = native.prove_real16_declared_function_entry_domain_8616(
        project, link, 0x1023, boot=boot, boot_recompute=native._recompute,
    )
    assert scope.complete
    surface = owner._closure_scope_bound_8616(project, 0x1020, scope)
    assert surface is not None
    assert surface[0] is link.artifact
    assert surface[1] is link.boundary


@pytest.mark.parametrize("mutation", ["callee", "project"])
def test_declared_closure_selection_refuses_foreign_scope(mutation):
    """Surface selection rejects a different callee or project identity."""
    project, boot, link = native._world()
    scope = native.prove_real16_declared_function_entry_domain_8616(
        project, link, 0x1023, boot=boot, boot_recompute=native._recompute,
    )
    callee = 0x1020
    if mutation == "callee":
        callee += 1
    else:
        project = object()
    assert owner._closure_scope_bound_8616(project, callee, scope) is None


def test_declared_closure_selection_does_not_authenticate_stale_scope():
    """Selecting retained objects supplies no proof of their current authority."""
    project, boot, link = native._world()
    scope = native.prove_real16_declared_function_entry_domain_8616(
        project, link, 0x1023, boot=boot, boot_recompute=native._recompute,
    )
    assert scope.complete
    stale = replace(scope, chain=replace(
        link, admission=replace(link.admission, declaration_sha256="0" * 64),
    ))
    surface = owner._closure_scope_bound_8616(project, 0x1020, stale)
    assert surface is not None
    assert surface[0] is link.artifact and surface[1] is link.boundary
    assert not stale.complete


@pytest.mark.parametrize("fallback", ["mapped", "cfg"])
def test_declared_boundary_precedes_wider_discovery(monkeypatch, fallback):
    """Declared extents win over independently discovered broader boundaries."""
    from inertia.ir import function_ssa_registry as registry

    project, boot, link = native._world()
    _install(project, boot, link)
    wide = replace(link.boundary, size=0x60)
    monkeypatch.setattr(owner, "registered_decoded_callsite_index_8616", lambda *args: None)
    monkeypatch.setattr(registry, "function_boundary_at_address_8616", lambda *args: wide if fallback == "cfg" else None)
    monkeypatch.setattr(owner, "mapped_entry_function_boundary_8616", lambda *args: wide)
    boundary = owner._exact_boundary_for_8616(project, link.boundary.addr)
    assert boundary is not None
    assert (boundary.decode_start, boundary.decode_end) == (link.admission.spec.range_start, link.admission.spec.range_end)


def test_declared_boundary_refusal_never_falls_back(monkeypatch):
    """A declared extent that cannot decode never expands to another source."""
    project, boot, link = native._world()
    _install(project, boot, link)
    monkeypatch.setattr(owner, "registered_decoded_callsite_index_8616", lambda *args: None)
    monkeypatch.setattr(owner, "exact_function_range_boundary_8616", lambda *args: None)
    monkeypatch.setattr(owner, "mapped_entry_function_boundary_8616", _unexpected_boot)
    assert owner._exact_boundary_for_8616(project, link.boundary.addr) is None


@pytest.mark.parametrize("conflict", [False, True])
def test_retained_boundary_must_match_declared_extent(monkeypatch, conflict):
    """A retained index is reusable only within exactly the declared bounds."""
    project, boot, link = native._world()
    from inertia.frontend.x86_16.frontend_direct_callsite_index import RetainedDecodedCallsiteIndex8616

    source = _install(project, boot, link)
    retained = RetainedDecodedCallsiteIndex8616(link.boundary.addr, replace(link.boundary, size=0x60) if conflict else link.boundary, source.callsite_index)
    monkeypatch.setattr(owner, "registered_decoded_callsite_index_8616", lambda *args: retained)
    monkeypatch.setattr(owner, "exact_function_range_boundary_8616", _unexpected_boot)
    boundary = owner._exact_boundary_for_8616(project, link.boundary.addr)
    if conflict:
        assert boundary is None
    else:
        assert boundary is retained.boundary


def test_invalid_declared_range_never_falls_back(monkeypatch):
    """Malformed declaration bounds cannot inherit a retained or mapped extent."""
    project, boot, link = native._world()
    spec = replace(link.admission.spec, range_end=link.admission.spec.range_start)
    admission = replace(link.admission, spec=spec)
    _install(project, boot, replace(link, admission=admission))
    monkeypatch.setattr(owner, "mapped_entry_function_boundary_8616", _unexpected_boot)
    assert owner._exact_boundary_for_8616(project, link.boundary.addr) is None


@pytest.mark.parametrize("source_present", [False, True])
def test_absent_declaration_keeps_boundary_fallback(monkeypatch, source_present):
    """The ordinary mapped fallback remains available without matching admission."""
    from inertia.ir import function_ssa_registry as registry

    project, boot, link = native._world()
    source = replace(_install(project, boot, link), function_entries=()) if source_present else None
    monkeypatch.setattr(owner, "_invocation_premise_source_8616", lambda *args: source)
    monkeypatch.setattr(owner, "registered_decoded_callsite_index_8616", lambda *args: None)
    monkeypatch.setattr(registry, "function_boundary_at_address_8616", lambda *args: None)
    monkeypatch.setattr(owner, "mapped_entry_function_boundary_8616", lambda *args: link.boundary)
    assert owner._exact_boundary_for_8616(project, link.boundary.addr) is link.boundary
