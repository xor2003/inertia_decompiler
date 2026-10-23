"""Native conditional scope transport through the existing private IR view."""
from dataclasses import replace

import pytest

from inertia.ir.near_call_jump_scope import NearCallJumpScope8616
from inertia.ir.vex_import import (
    prove_scoped_x86_16_ir_function_view_8616,
    raw_x86_16_import_bundle_for_artifact_8616,
)
from tests.ir.test_near_call_preservation import _CODE, _prove_step, _resolver, _Surface, _surface

pytestmark = pytest.mark.decompiler


def _native_pending_view_surface() -> tuple[_Surface, NearCallJumpScope8616]:
    """Cross a paragraph with a real native pending jump after a preserving CALL."""
    surface = _surface(_CODE[:-1] + b"\x90" * 13 + bytes.fromhex("ebee"), root_end=0x1022)
    scope = NearCallJumpScope8616(
        surface.project, surface.artifact, surface.context,
        _resolver(surface.project), (_prove_step(surface),),
    )
    return surface, scope


def test_native_near_call_scoped_view_retains_conditional_cfg() -> None:
    """Only the identical explicit premise exposes the repaired native CFG."""
    surface, scope = _native_pending_view_surface()
    original = surface.artifact.blocks
    bundle = raw_x86_16_import_bundle_for_artifact_8616(
        surface.project, surface.boundary, surface.artifact,
    )
    assert bundle is not None
    view = prove_scoped_x86_16_ir_function_view_8616(
        surface.project, bundle, surface.boundary, near_call_scope=scope,
    )
    assert view.failure is None, view.detail
    assert view.source_artifact is surface.artifact
    assert view.near_call_scope is scope
    assert view.invocation_scope is None
    assert not view.complete
    assert not view.complete_for(None)
    assert not view.complete_for(replace(scope))
    assert view.effective_blocks_for(None) is None
    projection = view.cfg_projection_for(scope)
    assert projection is not None
    jump_block = next(block for block in original
                      if any(i.addr == 0x1020 and i.op == "JMP" for i in block.instrs))
    assert projection.successors_for(jump_block.addr) == (0x1010,)
    assert projection.scope is scope
    assert surface.artifact.blocks is original
    assert any(block.refusals for block in original)
    receipt = view.to_dict()
    assert receipt["authenticated"]
    assert receipt["near_call_scope"]["conditional_only"]
    surface.project.loader.memory.store(0x1011, b"\x00")
    assert not view.complete_for(scope)


@pytest.mark.parametrize("offering", ["missing", "foreign_context"])
def test_scoped_import_requires_exact_native_context(offering: str) -> None:
    """Import cannot repair a conditional native CFG from absent/foreign evidence."""
    surface, scope = _native_pending_view_surface()
    bundle = raw_x86_16_import_bundle_for_artifact_8616(
        surface.project, surface.boundary, surface.artifact,
    )
    assert bundle is not None
    offered = None if offering == "missing" else replace(scope, context=replace(scope.context))
    view = prove_scoped_x86_16_ir_function_view_8616(
        surface.project, bundle, surface.boundary, near_call_scope=offered,
    )
    assert view.failure is not None
    assert not view.complete
    assert view.cfg_projection_for(scope) is None
