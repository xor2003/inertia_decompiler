"""Canonical declared selector invariant: exact-root factory controls.

Layer: IR tests.

Responsibility: prove the canonical factory consumes the exact supplied
``DeclaredFunctionEntryLink8616`` root pair, retains it with immutable
pre-CALL incoming selector states for later conditional consumption,
preserves every staged negative (authority, seed, decode, budget, deadline),
and keeps honest work charging. Focused on the new exact-root/state surface;
broader former regressions are adapted by the parent.
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
    ExactFunctionRangeBoundary8616,
    exact_function_range_boundary_8616,
)
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr
from inertia.ir.declared_entry_pipeline import (
    _declared_source_8616,
    _function_entry_for_head_8616,
)
from inertia.ir.declared_selector_invariant import (
    DeclaredSelectorInstructionState8616,
    InvariantStatus,
    ObligationKind,
    Verdict,
    _Budget,
    _record_fetch,
    _record_incoming_instruction_state,
    prove_declared_selector_invariant_8616,
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


def _entry_fixture() -> tuple[
    object, object, DeclaredFunctionEntryLink8616,
]:
    """Build the declared project, source, and exact consumed entry link."""
    apply_x86_16_bootstrap()
    declaration = read_declared_real16_input_8616(
        _DECLARED, _BINARY.read_bytes())
    boot = declaration.boot
    project = build_declared_project_8616(
        _BINARY, _DECLARED, force_blob=False,
        base_addr=boot.image.load_segment, entry_point=boot.entry.linear())
    with native_import_request_8616():
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
    return project, source, DeclaredFunctionEntryLink8616(
        admission, artifact, boundary)


@pytest.fixture(scope="module")
def proven() -> tuple[object, object, DeclaredFunctionEntryLink8616, object]:
    """One canonical proof over the real corpus, shared by the module."""
    project, source, entry = _entry_fixture()
    deadline = time.monotonic() + 25
    with native_import_request_8616(), \
            segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.census_deadline = deadline
        with direct_evidence_deadline_scope_8616(project, deadline):
            receipt = prove_declared_selector_invariant_8616(
                project, source, entry)
    return project, source, entry, receipt


def test_canonical_proof_retains_exact_link(proven) -> None:
    """The proven receipt keeps the identical supplied link and authority."""
    project, source, entry, receipt = proven
    assert receipt.status is InvariantStatus.PROVEN_CONDITIONAL
    assert receipt.root_link is entry
    assert receipt.project is project
    assert receipt.source is source
    assert receipt.admission is entry.admission
    assert receipt.declared_entry == _HEAD
    assert receipt.bound_entry_selectors == {"ss": 631, "ds": 631, "cs": 418}
    assert any(
        pair[0] is entry.boundary and pair[1] is entry.artifact
        for pair in receipt.consumed_pairs
    )


def test_instruction_states_identity_keyed(proven) -> None:
    """Every retained state belongs by identity to root/consumed surfaces."""
    _project, _source, entry, receipt = proven
    assert receipt.instruction_states
    surfaces = tuple(pair[1] for pair in receipt.consumed_pairs)
    keys = set()
    for state in receipt.instruction_states:
        assert type(state) is DeclaredSelectorInstructionState8616
        assert state.instruction.op == "CALL"
        assert (
            state.artifact is entry.artifact
            or any(state.artifact is surface for surface in surfaces)
        )
        assert any(block is state.block for block in state.artifact.blocks)
        assert any(
            instr is state.instruction for instr in state.block.instrs
        )
        key = (id(state.artifact), id(state.block), id(state.instruction))
        assert key not in keys
        keys.add(key)
        assert type(state.selectors) is tuple
        assert all(
            type(name) is str and type(value) is int
            for name, value in state.selectors
        )
    # CALL snapshots retain the root's proved CS before the call effect.
    root_calls = [
        state for state in receipt.instruction_states
        if state.artifact is entry.artifact
    ]
    assert root_calls
    assert all(dict(state.selectors)["cs"] == 418 for state in root_calls)


def test_call_snapshot_conflicting_revisit_refuses() -> None:
    """One exact CALL identity cannot carry two different incoming selectors."""
    row = IRInstr("CALL", None, (), addr=_HEAD)
    block = IRBlock(_HEAD, (row,))
    artifact = IRFunctionArtifact(_HEAD, (block,))
    states = {}
    obligations = []
    assert _record_incoming_instruction_state(
        _HEAD, artifact, block, row, {"cs": 418}, states, obligations)
    assert not _record_incoming_instruction_state(
        _HEAD, artifact, block, row, {"cs": 419}, states, obligations)
    assert len(states) == 1
    assert next(iter(states.values())).selectors == (("cs", 418),)
    assert obligations[0].kind is ObligationKind.INSTRUCTION_STATE_CONFLICT


def test_noncall_snapshot_is_not_retained() -> None:
    """Numeric non-call transfer does not allocate call-consumer state."""
    row = IRInstr("STORE", None, (), addr=_HEAD)
    block = IRBlock(_HEAD, (row,))
    artifact = IRFunctionArtifact(_HEAD, (block,))
    states = {}
    obligations = []
    assert _record_incoming_instruction_state(
        _HEAD, artifact, block, row, {"cs": 418}, states, obligations)
    assert not states and not obligations


def test_noncall_revisit_checks_changed_fetch_selector() -> None:
    """Omitting snapshots never skips a later invalid non-call fetch context."""
    row = IRInstr("NOP", None, (), addr=_HEAD)
    block = IRBlock(_HEAD, (row,))
    artifact = IRFunctionArtifact(_HEAD, (block,))
    states = {}
    obligations = []
    budget = _Budget(float("inf"), 100)
    for cs, expected in ((418, True), ((_HEAD >> 4) + 1, False)):
        assert _record_incoming_instruction_state(
            _HEAD, artifact, block, row, {"cs": cs}, states, obligations)
        assert _record_fetch(
            _HEAD, row, b"\x90", {"cs": cs}, set(), budget, obligations) is expected
    assert not states
    assert obligations[0].kind is ObligationKind.FETCH_OUT_OF_WINDOW


def test_store_and_call_cohorts_preserved(proven) -> None:
    """Staged store/call verdicts are unchanged under the canonical root."""
    _project, _source, _entry, receipt = proven
    assert receipt.stores.raw == receipt.stores.materialized == 57
    assert receipt.stores.failures == 0
    assert len(receipt.call_edges) == 4
    assert all(edge.verdict is Verdict.PRESERVED for edge in receipt.call_edges)
    assert receipt.controls.raw == 10 and receipt.controls.failures == 0
    assert all(
        row.verdict is not None for row in receipt.geometry_rows
    )


def test_foreign_entry_link_refuses(proven) -> None:
    """A non-typed entry object never reaches authority work."""
    project, source, _entry, _receipt = proven
    with segment_call_dependency_traversal_scope_8616():
        receipt = prove_declared_selector_invariant_8616(
            project, source, cast(DeclaredFunctionEntryLink8616, object()))
    assert receipt.status is InvariantStatus.REFUSED
    assert receipt.root_link is None
    assert any(
        obligation.kind is ObligationKind.DECLARED_AUTHORITY_STALE
        for obligation in receipt.obligations
    )


def test_substitute_root_surface_refuses(proven) -> None:
    """A link whose root pair is not the declared head's surface refuses."""
    project, source, entry, _receipt = proven
    forged = dataclasses.replace(
        entry, boundary=cast(ExactFunctionRangeBoundary8616, object()))
    deadline = time.monotonic() + 25
    with native_import_request_8616(), \
            segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.census_deadline = deadline
        with direct_evidence_deadline_scope_8616(project, deadline):
            receipt = prove_declared_selector_invariant_8616(
                project, source, forged)
    assert receipt.status is InvariantStatus.REFUSED
    assert any(
        obligation.kind is ObligationKind.DECLARED_AUTHORITY_STALE
        for obligation in receipt.obligations
    )


def test_forged_admission_refuses(proven) -> None:
    """Changed declaration digest stays stale authority."""
    project, source, entry, _receipt = proven
    forged = dataclasses.replace(
        entry,
        admission=dataclasses.replace(
            entry.admission, declaration_sha256="f" * 64))
    deadline = time.monotonic() + 25
    with native_import_request_8616(), \
            segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.census_deadline = deadline
        with direct_evidence_deadline_scope_8616(project, deadline):
            receipt = prove_declared_selector_invariant_8616(
                project, source, forged)
    assert receipt.status is InvariantStatus.REFUSED
    assert any(
        obligation.kind is ObligationKind.DECLARED_AUTHORITY_STALE
        for obligation in receipt.obligations
    )


def test_seedless_declaration_refuses(proven) -> None:
    """A declaration missing the ds lane is stale authority, not a seed."""
    project, source, entry, _receipt = proven
    seedless = dataclasses.replace(
        entry,
        admission=dataclasses.replace(
            entry.admission,
            spec=dataclasses.replace(
                entry.admission.spec,
                registers=tuple(
                    pair for pair in entry.admission.spec.registers
                    if pair[0] != "ds"))))
    deadline = time.monotonic() + 25
    with native_import_request_8616(), \
            segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.census_deadline = deadline
        with direct_evidence_deadline_scope_8616(project, deadline):
            receipt = prove_declared_selector_invariant_8616(
                project, source, seedless)
    assert receipt.status is InvariantStatus.REFUSED


def test_work_budget_and_deadline_refuse(proven) -> None:
    """Tight work limits and expired deadlines refuse with typed causes."""
    project, source, entry, receipt = proven
    assert receipt.work_units > 0
    assert receipt.shared_work_units > 0
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
        starved = prove_declared_selector_invariant_8616(
            project, source, entry, work_limit=1)
        assert starved.status is InvariantStatus.REFUSED
        assert any(
            obligation.kind is ObligationKind.BUDGET_EXCEEDED
            for obligation in starved.obligations
        )
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
        expired = prove_declared_selector_invariant_8616(
            project, source, entry, deadline_seconds=0.0)
        assert expired.status is InvariantStatus.REFUSED
        assert any(
            obligation.kind is ObligationKind.DEADLINE_EXCEEDED
            for obligation in expired.obligations
        )


def test_import_root_never_substitutes_supplied_link(
    proven, monkeypatch,
) -> None:
    """The canonical factory must not re-resolve the root by address."""
    import inertia.ir.declared_selector_invariant as invariant

    project, source, entry, _receipt = proven
    seen: list[int] = []
    real = invariant._exact_boundary_for_8616

    def spy(project_arg: object, head: int) -> object:
        seen.append(head)
        return real(project_arg, head)

    monkeypatch.setattr(invariant, "_exact_boundary_for_8616", spy)
    deadline = time.monotonic() + 25
    with native_import_request_8616(), \
            segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.census_deadline = deadline
        with direct_evidence_deadline_scope_8616(project, deadline):
            receipt = prove_declared_selector_invariant_8616(
                project, source, entry)
    assert receipt.status is InvariantStatus.PROVEN_CONDITIONAL
    assert _HEAD not in seen
