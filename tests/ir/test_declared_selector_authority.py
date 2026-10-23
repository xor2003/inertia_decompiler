"""Canonical declared selector callsite: projection and consumption authority.

Layer: IR tests.

Responsibility: prove ``selector_callsite_8616`` projects only
identity-exact, selector-bound callsites from a proven canonical receipt,
and ``consume_declared_selector_callsite_8616`` revalidates current
authority, exact consumed surface identity, and the live native
CS/target/continuation — callback-free — while refusing every forged,
stale or foreign shape. Selector capability only: no stack, return, GP or
memory claim is asserted anywhere.
"""
from __future__ import annotations

import dataclasses
import time
from pathlib import Path
from typing import cast

import pytest

from inertia.cli.real16_declared_project import build_declared_project_8616
from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.frontend.x86_16.frontend_function_boundary import (
    exact_function_range_boundary_8616,
)
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr
from inertia.ir.declared_entry_pipeline import (
    _declared_source_8616,
    _function_entry_for_head_8616,
)
from inertia.ir.declared_selector_invariant import (
    DeclaredSegmentInvariant,
    DeclaredSelectorCallsite8616,
    InvariantStatus,
    Verdict,
    consume_declared_selector_callsite_8616,
    prove_declared_selector_invariant_8616,
    selector_callsite_8616,
)
from inertia.ir.direct_evidence_deadline import direct_evidence_deadline_scope_8616
from inertia.ir.native_import_surface_cache import native_import_request_8616
from inertia.ir.real16_invocation_domain import (
    DeclaredFunctionEntryLink8616,
    real16_native_census_import_8616,
)
from inertia.ir.segment_call_preservation import (
    segment_call_dependency_traversal_scope_8616,
)
from tools.dosunit.catalog.real16_declared_input import (
    read_declared_real16_input_8616,
)

_ROOT = Path(__file__).resolve().parents[2]
_BINARY = _ROOT / ".cache/bitfield-route/original-dosbox/BITNBR.EXE"
_DECLARED = _ROOT / ".cache/bitfield-route/main-declared-input.json"
_HEAD = 0x1D43

pytestmark = [
    pytest.mark.decompiler,
    pytest.mark.skipif(
        not (_BINARY.is_file() and _DECLARED.is_file()),
        reason="canonical BITNBR corpus not staged",
    ),
]


def _prove() -> tuple[object, object, DeclaredFunctionEntryLink8616,
                     DeclaredSegmentInvariant]:
    """One canonical proof over the real corpus."""
    apply_x86_16_bootstrap()
    declaration = read_declared_real16_input_8616(
        _DECLARED, _BINARY.read_bytes())
    boot = declaration.boot
    project = build_declared_project_8616(
        _BINARY, _DECLARED, force_blob=False,
        base_addr=boot.image.load_segment, entry_point=boot.entry.linear())
    deadline = time.monotonic() + 25
    with native_import_request_8616(), \
            segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.census_deadline = deadline
        with direct_evidence_deadline_scope_8616(project, deadline):
            source = _declared_source_8616(project, _HEAD)
            assert source is not None
            admission = _function_entry_for_head_8616(source, _HEAD)
            assert admission is not None
            spec = admission.spec
            boundary = exact_function_range_boundary_8616(
                project, spec.range_start, spec.range_end)
            assert boundary is not None
            artifact = real16_native_census_import_8616(project, boundary)
            assert type(artifact) is IRFunctionArtifact
            entry = DeclaredFunctionEntryLink8616(admission, artifact, boundary)
            receipt = prove_declared_selector_invariant_8616(
                project, source, entry)
    assert receipt.status is InvariantStatus.PROVEN_CONDITIONAL
    return project, source, entry, receipt


@pytest.fixture(scope="module")
def proven() -> tuple[object, object, DeclaredFunctionEntryLink8616,
                      DeclaredSegmentInvariant]:
    """Shared canonical proof for the module."""
    return _prove()


def _projection(
    receipt: DeclaredSegmentInvariant,
) -> DeclaredSelectorCallsite8616:
    """Project the first preserved call edge into a selector capability."""
    edge = next(
        item for item in receipt.call_edges
        if item.verdict is Verdict.PRESERVED
    )
    state = next(
        item for item in receipt.instruction_states
        if item.instruction.addr == edge.callsite_addr
        and item.instruction.op == "CALL"
    )
    row = next(
        item for item in receipt.geometry_rows
        if item.addr == edge.callsite_addr
    )
    assert row.fallthrough is not None and edge.target_addr is not None
    projected = selector_callsite_8616(
        receipt, state.block, state.instruction,
        edge.target_addr, row.fallthrough)
    assert projected is not None
    return projected


def test_selector_callsite_projects_exact_identity(proven) -> None:
    """A preserved edge projects with retained CS, target, continuation."""
    _project, _source, _entry, receipt = proven
    projected = _projection(receipt)
    assert projected.scope is receipt
    assert type(projected.incoming_cs) is int
    assert projected.next_addr > projected.callsite_addr
    edge = next(
        item for item in receipt.call_edges
        if item.callsite_addr == projected.callsite_addr
    )
    assert projected.target_addr == edge.target_addr
    # Selector capability only: no GP/stack/return fields exist at all.
    assert not hasattr(projected, "return_addr")
    assert not hasattr(projected, "stack")


def test_every_preserved_edge_projects(proven) -> None:
    """All four preserved callsites of the corpus projection-close."""
    _project, _source, _entry, receipt = proven
    preserved = [
        edge for edge in receipt.call_edges
        if edge.verdict is Verdict.PRESERVED
    ]
    assert len(preserved) == 4
    for edge in preserved:
        state = next(
            item for item in receipt.instruction_states
            if item.instruction.addr == edge.callsite_addr
        and item.instruction.op == "CALL"
        )
        row = next(
            item for item in receipt.geometry_rows
            if item.addr == edge.callsite_addr
        )
        assert edge.target_addr is not None and row.fallthrough is not None
        assert selector_callsite_8616(
            receipt, state.block, state.instruction,
            edge.target_addr, row.fallthrough) is not None


def test_projection_refuses_wrong_target_and_continuation(proven) -> None:
    """Forged target/continuation never projects."""
    _project, _source, _entry, receipt = proven
    projected = _projection(receipt)
    assert selector_callsite_8616(
        receipt, projected.block, projected.instruction,
        projected.target_addr + 1, projected.next_addr) is None
    assert selector_callsite_8616(
        receipt, projected.block, projected.instruction,
        projected.target_addr, projected.next_addr + 1) is None


def test_projection_refuses_foreign_identities(proven) -> None:
    """Foreign block/instruction objects never project."""
    _project, _source, _entry, receipt = proven
    projected = _projection(receipt)
    assert selector_callsite_8616(
        receipt, cast(IRBlock, object()), projected.instruction,
        projected.target_addr, projected.next_addr) is None
    assert selector_callsite_8616(
        receipt, projected.block, cast(IRInstr, object()),
        projected.target_addr, projected.next_addr) is None
    assert selector_callsite_8616(
        cast(DeclaredSegmentInvariant, object()), projected.block,
        projected.instruction, projected.target_addr,
        projected.next_addr) is None


def test_projection_refuses_without_retained_link(proven) -> None:
    """A scope missing the exact root link cannot project."""
    _project, _source, _entry, receipt = proven
    unlinked = dataclasses.replace(receipt, root_link=None)
    projected = _projection(receipt)
    assert selector_callsite_8616(
        unlinked, projected.block, projected.instruction,
        projected.target_addr, projected.next_addr) is None
    refused = dataclasses.replace(receipt, status=InvariantStatus.REFUSED)
    assert selector_callsite_8616(
        refused, projected.block, projected.instruction,
        projected.target_addr, projected.next_addr) is None


def test_consumption_accepts_current_authority(proven) -> None:
    """The real callsite consumes under unchanged authority."""
    project, _source, _entry, receipt = proven
    projected = _projection(receipt)
    with native_import_request_8616():
        assert consume_declared_selector_callsite_8616(
            project, projected) is True


def test_consumption_refuses_foreign_project(proven) -> None:
    """A different project object never satisfies exact source identity."""
    _project, _source, _entry, receipt = proven
    projected = _projection(receipt)
    with native_import_request_8616():
        assert consume_declared_selector_callsite_8616(
            object(), projected) is False


def test_consumption_refuses_forged_geometry(proven) -> None:
    """Tampered target/continuation/CS never consumes."""
    project, _source, _entry, receipt = proven
    projected = _projection(receipt)
    with native_import_request_8616():
        assert consume_declared_selector_callsite_8616(
            project,
            dataclasses.replace(
                projected, target_addr=projected.target_addr + 1)) is False
        assert consume_declared_selector_callsite_8616(
            project,
            dataclasses.replace(
                projected, next_addr=projected.next_addr + 1)) is False
        assert consume_declared_selector_callsite_8616(
            project,
            dataclasses.replace(
                projected, incoming_cs=0)) is False
        assert consume_declared_selector_callsite_8616(
            project, cast(DeclaredSelectorCallsite8616, object())) is False


def test_consumption_refuses_refused_scope(proven) -> None:
    """A receipt that lost its proven status cannot feed consumption."""
    project, _source, _entry, receipt = proven
    projected = _projection(receipt)
    refused = dataclasses.replace(
        projected,
        scope=dataclasses.replace(receipt, status=InvariantStatus.REFUSED))
    with native_import_request_8616():
        assert consume_declared_selector_callsite_8616(
            project, refused) is False


def test_consumption_refuses_stale_loader_bytes(
    proven, monkeypatch,
) -> None:
    """Live bytes that no longer decode the bound E8 target refuse."""
    import inertia.ir.declared_selector_invariant as invariant

    project, _source, _entry, receipt = proven
    projected = _projection(receipt)
    monkeypatch.setattr(
        invariant, "_loaded_bytes_8616",
        lambda project_arg, addr, size: b"\x90" * size)
    with native_import_request_8616():
        assert consume_declared_selector_callsite_8616(
            project, projected) is False


def test_consumption_refuses_stale_native_surface(
    proven, monkeypatch,
) -> None:
    """A consumed surface failing the live rebind never waives freshness."""
    import inertia.ir.declared_selector_invariant as invariant

    project, _source, _entry, receipt = proven
    projected = _projection(receipt)
    monkeypatch.setattr(
        invariant, "_scoped_native_rebind_failure_8616",
        lambda boundary, artifact, facts, before: object())
    with native_import_request_8616():
        assert consume_declared_selector_callsite_8616(
            project, projected) is False


def test_consumption_refuses_post_native_loader_mutation(proven, monkeypatch) -> None:
    """Producer callbacks cannot change authenticated bytes before acceptance."""
    import inertia.ir.declared_selector_invariant as invariant

    project, source, _entry, receipt = proven
    projected = _projection(receipt)
    base, module = source.boot.image.chunks[0]
    address = base + len(module) - 1
    prepare_native = invariant._prepare_scoped_native_rebind_8616

    def corrupt(current: object, boundary: object, *, caller: IRFunctionArtifact | None = None) -> object:
        """Forward the exact caller before simulating loader-byte corruption."""
        facts = prepare_native(current, boundary, caller=caller)
        project.loader.memory.store(address, bytes([module[-1] ^ 1]))
        return facts

    monkeypatch.setattr(invariant, "_prepare_scoped_native_rebind_8616", corrupt)
    try:
        with native_import_request_8616():
            accepted = consume_declared_selector_callsite_8616(project, projected)
            assert accepted is False
    finally:
        project.loader.memory.store(address, module[-1:])


def test_consumption_honors_existing_work_limit(proven) -> None:
    """A selector capability cannot restart the exhausted request ledger."""
    project, _source, _entry, receipt = proven
    projected = _projection(receipt)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.census_work_units = 20000
        with native_import_request_8616():
            accepted = consume_declared_selector_callsite_8616(project, projected)
            assert accepted is False


def test_consumption_honors_existing_deadline(proven) -> None:
    """A selector capability cannot renew an expired request deadline."""
    project, _source, _entry, receipt = proven
    projected = _projection(receipt)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.census_deadline = time.monotonic() - 1
        with native_import_request_8616():
            accepted = consume_declared_selector_callsite_8616(project, projected)
            assert accepted is False
