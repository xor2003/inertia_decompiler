"""Native controls for near-call scoped IR boundary coverage.

Layer: tests.
Responsibility: pin ``IRBoundaryCoverageResult8616.complete_for`` under the
distinct ``NearCallJumpScope8616`` retained on a real
``ScopedFunctionIRView8616``: the conditional entry-jump admission over the
native backward-CALL loop must close coverage only under the exact scope
object while the raw pending body stays unpublished and ``complete`` stays
context-free-false. Copied or foreign scopes, mutated native bytes, a
missing CALL census, and an unadmitted pending jump all refuse through
typed non-results. No monkeypatched authority: scope, view, and coverage
authentication run the real native owners end to end.
"""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest

import inertia.ir.ir_boundary_cfg as cov_mod
from inertia.ir.core import MemSpace
from inertia.ir.entry_jump_domain import prove_entry_jump_domains_8616
from inertia.ir.near_call_jump_scope import NearCallJumpScope8616
from inertia.ir.real16_invocation_domain import Real16InvocationDomain8616
from inertia.ir.scoped_function_ir_view import (
    ScopedFunctionIRView8616,
    prove_scoped_function_ir_view_8616,
)
from tests.ir.test_near_call_jump_scope import _scoped_loop

if TYPE_CHECKING:
    from inertia.ir.core import IRFunctionArtifact

pytestmark = pytest.mark.decompiler

F = cov_mod.IRBoundaryCoverageFailure8616


def _world() -> SimpleNamespace:
    """Prove the near-call view and scoped coverage over the real loop."""
    surface, scope, pending = _scoped_loop()
    proof = prove_entry_jump_domains_8616(
        surface.artifact, pending,
        project=surface.project, near_call_scope=scope,
    )
    assert proof.admitted
    view = prove_scoped_function_ir_view_8616(
        surface.artifact, surface.boundary, proof, near_call_scope=scope,
    )
    assert type(view) is ScopedFunctionIRView8616
    assert view.failure is None, view.to_dict()
    coverage = cov_mod.prove_scoped_ir_boundary_coverage_8616(
        surface.project, surface.boundary, surface.artifact, view,
    )
    return SimpleNamespace(
        surface=surface, scope=scope, proof=proof, view=view,
        coverage=coverage,
    )


def _raw_surface_facts(artifact: IRFunctionArtifact) -> tuple[object, ...]:
    """Snapshot the raw block edge/refusal surface for mutation checks."""
    return tuple(
        (block.addr, block.successor_addrs, block.refusals)
        for block in artifact.blocks
    )


def test_near_call_coverage_closes_under_exact_scope() -> None:
    """Positive: authenticated scope + view + raw surface closes coverage."""
    world = _world()
    result = world.coverage
    assert result.failure is None
    assert (
        result.raw_fact_count,
        result.normalized_fact_count,
        result.classified_fact_count,
        result.materialized_count,
        result.failure_count,
    ) == (1, 1, 1, 1, 0)
    assert result.artifact is world.surface.artifact
    assert result.boundary is world.surface.boundary
    assert result.scoped_view is world.view
    # The scope stays a distinct near-call premise, never an invocation
    # domain and never copied onto the Real16 field.
    assert world.view.near_call_scope is world.scope
    assert world.view.invocation_scope is None
    assert type(world.scope) is NearCallJumpScope8616
    assert not isinstance(world.scope, Real16InvocationDomain8616)
    assert result.complete_for(world.scope)


def test_near_call_coverage_never_completes_context_free() -> None:
    """Retained scoped evidence cannot certify without an explicit entry."""
    result = _world().coverage
    assert not result.complete
    assert not result.complete_for(None)
    forged = replace(result, failure=None)
    assert not forged.complete
    assert not forged.complete_for(None)


def test_raw_source_surface_stays_pending() -> None:
    """The retained body keeps its pending refusal and unpublished rewrite."""
    world = _world()
    assert world.coverage.complete_for(world.scope)
    assert _raw_surface_facts(world.coverage.artifact) == _raw_surface_facts(
        world.surface.artifact
    )
    assert any(
        block.refusals for block in world.coverage.artifact.blocks
    )
    jump = next(
        instruction
        for block in world.coverage.artifact.blocks
        for instruction in block.instrs
        if instruction.op == "JMP"
    )
    assert all(arg.space is MemSpace.TMP for arg in jump.args)


def test_copied_or_foreign_scope_refuses() -> None:
    """Near-call authority is object identity, not field equality."""
    world = _world()
    result = world.coverage
    copied = replace(world.scope)
    assert copied is not world.scope
    assert not result.complete_for(copied)
    # A scope built for a second identical surface is still foreign: its
    # project and artifact identities never bind to this coverage.
    _surface_b, scope_b, _pending_b = _scoped_loop()
    assert scope_b.project is not world.surface.project
    assert not result.complete_for(scope_b)
    consumption = cov_mod.consume_scoped_ir_boundary_projection_8616(
        world.surface.project, world.surface.boundary,
        world.surface.artifact, world.view, copied,
    )
    assert consumption.projection is None
    assert consumption.coverage.failure is F.SCOPED_VIEW_REFUSED
    assert not consumption.coverage.complete_for(world.scope)


def test_untyped_scope_refuses() -> None:
    """An untyped entry is never admitted through the scoped gate."""
    world = _world()
    assert not world.coverage.complete_for(object())
    assert not world.coverage.complete_for(SimpleNamespace(project=world.surface.project))


def test_native_byte_mutation_revokes_coverage() -> None:
    """Mutating the proved CALL bytes revokes the sealed coverage verdict."""
    world = _world()
    assert world.coverage.complete_for(world.scope)
    world.surface.project.loader.memory.store(0x1011, b"\x00")
    assert not world.coverage.complete_for(world.scope)
    consumption = cov_mod.consume_scoped_ir_boundary_projection_8616(
        world.surface.project, world.surface.boundary,
        world.surface.artifact, world.view, world.scope,
    )
    assert consumption.projection is None
    assert consumption.coverage.failure is not None


def test_missing_call_census_refuses() -> None:
    """A scope without its full CALL preservation census cannot carry a view."""
    surface, scope, pending = _scoped_loop()
    proof = prove_entry_jump_domains_8616(
        surface.artifact, pending,
        project=surface.project, near_call_scope=scope,
    )
    assert proof.admitted
    stripped = replace(scope, preservations=())
    view = prove_scoped_function_ir_view_8616(
        surface.artifact, surface.boundary, proof, near_call_scope=stripped,
    )
    assert view.failure is not None
    result = cov_mod.prove_scoped_ir_boundary_coverage_8616(
        surface.project, surface.boundary, surface.artifact, view,
    )
    assert result.failure is F.SCOPED_VIEW_REFUSED
    assert not result.complete_for(stripped)


def test_unadmitted_pending_jump_refuses() -> None:
    """A conditional jump that stayed pending never certifies coverage."""
    surface, scope, pending = _scoped_loop()
    proof = prove_entry_jump_domains_8616(
        surface.artifact, pending, project=surface.project,
    )
    assert not proof.admitted
    view = prove_scoped_function_ir_view_8616(
        surface.artifact, surface.boundary, proof, near_call_scope=scope,
    )
    assert view.failure is not None
    result = cov_mod.prove_scoped_ir_boundary_coverage_8616(
        surface.project, surface.boundary, surface.artifact, view,
    )
    assert result.failure is F.SCOPED_VIEW_REFUSED
    assert not result.complete
    assert not result.complete_for(scope)


def test_forged_ledger_cannot_launder_coverage() -> None:
    """Only the closed 1/1/1/1/0 ledger can authenticate scoped evidence."""
    world = _world()
    forged = replace(world.coverage, materialized_count=0)
    assert not forged.complete_for(world.scope)
    forged = replace(world.coverage, failure_count=1)
    assert not forged.complete_for(world.scope)


def test_universal_route_stays_refused_for_pending_body() -> None:
    """A near-call scope cannot rescue the universal coverage route."""
    world = _world()
    raw = cov_mod.prove_ir_boundary_coverage_8616(
        world.surface.project, world.surface.boundary, world.surface.artifact,
    )
    assert raw.scoped_view is None
    assert raw.failure is not None
    assert not raw.complete
    assert not raw.complete_for(world.scope)


def test_consume_scoped_projection_returns_bounded_maps() -> None:
    """One synchronous consumption returns the authenticated CFG maps."""
    world = _world()
    consumption = cov_mod.consume_scoped_ir_boundary_projection_8616(
        world.surface.project, world.surface.boundary,
        world.surface.artifact, world.view, world.scope,
    )
    assert consumption.coverage.failure is None
    assert not consumption.coverage.complete
    projection = consumption.projection
    assert projection is not None
    assert projection.scope is world.scope
    assert projection.source_artifact is world.surface.artifact
    assert projection.function_addr == world.surface.artifact.function_addr
    assert not any(projection.pending.values())
    assert any(
        jump.target in projection.successors.get(jump.block_addr, ())
        for jump in projection.applied
    )
