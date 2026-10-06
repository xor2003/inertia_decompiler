"""Retained exact callsite census owns rediscovery of an already imported head."""
from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsiteIndex8616,
    DecodedDirectCallsiteIndexStats8616,
    retain_decoded_callsite_index_8616,
)
from angr_platforms.X86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
from angr_platforms.X86_16.ir import entry_domain_call_preservation as owner
from angr_platforms.X86_16.ir import function_ssa_registry as registry


def _retained():
    project = SimpleNamespace()
    boundary = ExactFunctionRangeBoundary8616(project, 0x1020, 0x80, frozenset({0x1020}), frozenset({0x1020}), (), decode_lower_bound=0x1000)
    index = DecodedDirectCallsiteIndex8616({}, DecodedDirectCallsiteIndexStats8616(0,0,0,0,0))
    record = retain_decoded_callsite_index_8616(project, boundary, index)
    return project, boundary, index, record


def test_exact_boundary_reuses_retained_authority_before_reframing(monkeypatch):
    project, boundary, _index, _record = _retained()
    def forbidden(*args):
        raise AssertionError("retained source must not be reframed")
    monkeypatch.setattr(registry, "function_boundary_at_address_8616", forbidden)
    assert owner._exact_boundary_for_8616(project, boundary.addr) is boundary


def test_no_retained_boundary_uses_existing_resolver(monkeypatch):
    project = SimpleNamespace()
    boundary = ExactFunctionRangeBoundary8616(project, 0x1020, 2, frozenset({0x1020}), frozenset({0x1020}), ())
    monkeypatch.setattr(registry, "function_boundary_at_address_8616", lambda *args: boundary)
    assert owner._exact_boundary_for_8616(project, boundary.addr) is boundary


@pytest.mark.parametrize("foreign", ["project", "head"])
def test_foreign_retained_surface_refuses(foreign):
    project, boundary, _index, record = _retained()
    forged = replace(boundary, project=object()) if foreign == "project" else replace(boundary, addr=0x1030)
    project._inertia_decoded_callsite_indexes_8616[boundary.addr] = replace(record, boundary=forged)
    assert owner._exact_boundary_for_8616(project, boundary.addr) is None


def test_changed_census_still_fails_loudly():
    project, boundary, index, _record = _retained()
    with pytest.raises(ValueError, match="conflicting decoded callsite census"):
        retain_decoded_callsite_index_8616(project, replace(boundary, successor_edges=((0x1020,0x1022),)), index)
