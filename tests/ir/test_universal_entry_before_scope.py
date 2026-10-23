"""Layer: IR tests.
Responsibility: try authenticated universal control before selecting a caller scope.
"""
from dataclasses import replace

import pytest

from inertia.ir import declared_entry_pipeline as owner
from inertia.ir import entry_domain_call_preservation as source_owner
from inertia.ir import vex_import
from inertia.ir.entry_domain_call_preservation import install_real16_invocation_source_8616
from inertia.pipeline.errors import PipelineHardError
from tests.ir.test_near_call_entry_pipeline import _installed

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize('kind', ['leaf', 'call', 'native_changed'])
def test_universal_control_avoids_irrelevant_caller_ambiguity(monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    """Only complete unchanged universal control bypasses conditional entry."""
    surface, source = _installed()
    index = source.callsite_index
    rows = index.for_target(surface.boundary.addr)
    index = replace(index, _entries_by_normalized_target={surface.boundary.addr: rows * 2})
    source = replace(source, callsite_index=index)
    install_real16_invocation_source_8616(surface.project, source)
    if kind != 'call':
        surface.project.loader.memory.store(surface.boundary.addr, bytes.fromhex('909090'))
    monkeypatch.setattr(source_owner, '_exact_boundary_for_8616', lambda *_args: surface.boundary)
    original = vex_import.raw_x86_16_function_bundle_8616

    def raw(project: object, boundary: object) -> object:
        bundle = original(project, boundary)
        if kind == 'native_changed':
            surface.project.loader.memory.store(0x1021, b'\x00')
        return bundle

    monkeypatch.setattr(vex_import, 'raw_x86_16_function_bundle_8616', raw)
    if kind == 'leaf':
        assert owner._prepare_pending_native_entry_8616(surface.project, source, surface.boundary.addr) is None
    else:
        with pytest.raises(PipelineHardError, match='native entry scoped CFG is unproved'):
            owner._prepare_pending_native_entry_8616(surface.project, source, surface.boundary.addr)
