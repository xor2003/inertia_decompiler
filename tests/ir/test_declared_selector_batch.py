"""Shared batch admission for declared-selector callsite capabilities.

Layer: IR tests.

Responsibility: prove ``consume_declared_selector_callsite_batch_8616``
revalidates every projection under one fresh shared admission — authority
authenticates once before and once after all native/import/loader reads,
each distinct retained surface rebinds once, and a callback-free pure seal
compares the current retained graphs and pending identities against the
detached facts. The collector prepares every closure/dependency/index/
window/symbolic/target-byte obligation before that admission; no batch
verdict or token survives for later replay, public complete APIs still
re-authenticate fresh, and every forged, duplicated, mutated, or
budget-exhausted input refuses.
"""
from __future__ import annotations

import dataclasses
import time
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import tests.semantics.test_direct_near_call_target_binding as binding_tests
from inertia.cli.real16_declared_project import build_declared_project_8616
from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.frontend.x86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
    exact_function_range_boundary_8616,
)
from inertia.ir import declared_selector_call_preservation as collector
from inertia.ir import declared_selector_invariant as invariant
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from inertia.ir.declared_entry_pipeline import (
    _declared_source_8616,
    _function_entry_for_head_8616,
)
from inertia.ir.declared_selector_invariant import (
    Cohort,
    DeclaredSegmentInvariant,
    DeclaredSelectorCallsite8616,
    DeclaredSelectorInstructionState8616,
    InvariantStatus,
    Verdict,
    consume_declared_selector_callsite_batch_8616,
    selector_callsite_8616,
)
from inertia.ir.direct_evidence_deadline import direct_evidence_deadline_scope_8616
from inertia.ir.entry_domain_call_preservation import (
    EntryDomainCallPreservationFailure8616 as Failure,
)
from inertia.ir.entry_domain_call_preservation import (
    Real16InvocationSource8616,
)
from inertia.ir.ir_boundary_cfg import ScopedNativeRebindFacts8616
from inertia.ir.native_import_surface_cache import native_import_request_8616
from inertia.ir.real16_invocation_domain import (
    DeclaredFunctionEntryLink8616,
    real16_native_census_import_8616,
)
from inertia.ir.segment_call_preservation import (
    segment_call_dependency_traversal_scope_8616,
)
from inertia.ir.source_graph_binding import (
    capture_immutable_source_graph_facts_8616,
)
from inertia.semantics.direct_near_call_target_binding import (
    DirectNearCallCoordinates8616,
    DirectNearCallTargetBinding8616,
    DirectNearCallTargetBindingPending8616,
    DirectNearCallTargetBindingVerdict8616,
    _seal_declared_selector_binding_8616,
    prepare_declared_near_call_target_binding_pending_8616,
)
from tools.dosunit.catalog.real16_declared_input import (
    read_declared_real16_input_8616,
)

_ROOT = Path(__file__).resolve().parents[2]
_BINARY = _ROOT / ".cache/bitfield-route/original-dosbox/BITNBR.EXE"
_DECLARED = _ROOT / ".cache/bitfield-route/main-declared-input.json"
_HEAD = 0x1D43

pytestmark = pytest.mark.decompiler

_CORPUS_MARK = pytest.mark.skipif(
    not (_BINARY.is_file() and _DECLARED.is_file()),
    reason="canonical BITNBR corpus not staged",
)


def _synthetic() -> tuple[
    object, DeclaredSegmentInvariant, IRFunctionArtifact, IRBlock, IRInstr,
]:
    """Build a typed scope carrying one retained CALL state, never a proof."""
    project = object()
    row = IRInstr("CALL", None, (), addr=0x1000)
    block = IRBlock(0x1000, (row,))
    artifact = IRFunctionArtifact(0x1000, (block,))
    boundary = ExactFunctionRangeBoundary8616(
        project, 0x1000, 3, frozenset({0x1000}), frozenset({0x1000}), (),
    )
    link = DeclaredFunctionEntryLink8616(object(), artifact, boundary)
    state = DeclaredSelectorInstructionState8616(artifact, block, row, (("cs", 0x100),))
    cohort = Cohort(1, 1, 1, 0)
    scope = DeclaredSegmentInvariant(
        InvariantStatus.PROVEN_CONDITIONAL, cohort, cohort, cohort, (), (), (), (),
        1, {"cs": 0x100}, 1, 1, 0x1000, link.admission,
        project=project, root_link=link, instruction_states=(state,),
        consumed_pairs=((boundary, artifact),),
        source=Real16InvocationSource8616(object(), None, object()),
    )
    return project, scope, artifact, block, row


def _projection(
    scope: DeclaredSegmentInvariant, block: IRBlock, row: IRInstr,
) -> DeclaredSelectorCallsite8616:
    """Construct one capability claim for the synthetic retained CALL."""
    return DeclaredSelectorCallsite8616(scope, block, row, 0x1000, 0x1040, 0x1003, 0x100)


def _clean_native(
    monkeypatch: pytest.MonkeyPatch, scope: DeclaredSegmentInvariant,
) -> None:
    """Bind every native/authority surface so the batch exercises pure logic."""
    monkeypatch.setattr(invariant, "_authenticate_authority", lambda *args, **kwargs: None)
    def prepare(
        project_arg: object, boundary: object,
        caller: IRFunctionArtifact | None = None,
    ) -> ScopedNativeRebindFacts8616:
        assert project_arg is project
        return ScopedNativeRebindFacts8616(
            boundary,
            capture_immutable_source_graph_facts_8616(
                artifact.function_addr, artifact.blocks, artifact.refusals),
            frozenset({0x1000}), None,
        )

    assert scope.root_link is not None
    project, artifact = scope.project, scope.root_link.artifact
    monkeypatch.setattr(invariant, "_prepare_scoped_native_rebind_8616", prepare)
    monkeypatch.setattr(
        invariant, "_loaded_bytes_8616",
        lambda project, addr, size: b"\xe8\x3d\x00" if (addr, size) == (0x1000, 3) else None,
    )


def test_batch_consumes_each_projection_under_one_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Typed projections admit with one rebound surface and honest charging."""
    project, scope, _artifact, block, row = _synthetic()
    _clean_native(monkeypatch, scope)
    rebound: list[object] = []
    real_native = invariant._prepare_scoped_native_rebind_8616

    def spy(
        project_arg: object, boundary: object,
        caller: IRFunctionArtifact | None = None,
    ) -> ScopedNativeRebindFacts8616:
        rebound.append(boundary)
        return real_native(project_arg, boundary, caller=caller)

    monkeypatch.setattr(invariant, "_prepare_scoped_native_rebind_8616", spy)
    assert scope.root_link is not None
    with segment_call_dependency_traversal_scope_8616() as traversal:
        verdicts = consume_declared_selector_callsite_batch_8616(
            project, (_projection(scope, block, row),))
        assert verdicts == (True,)
        assert len(rebound) == 1
        assert traversal.census_work_units > 0


def test_batch_refuses_foreign_projection_and_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    """Foreign types, foreign scope objects, and stale scopes never admit."""
    project, scope, _artifact, block, row = _synthetic()
    _clean_native(monkeypatch, scope)
    foreign = dataclasses.replace(scope, project=object())
    twin = dataclasses.replace(scope, status=InvariantStatus.REFUSED)
    assert (
        consume_declared_selector_callsite_batch_8616(project, (cast(
            DeclaredSelectorCallsite8616, object()),)) == (False,)
    )
    assert consume_declared_selector_callsite_batch_8616(
        project, (dataclasses.replace(
            _projection(scope, block, row), scope=foreign),)) == (False,)
    assert consume_declared_selector_callsite_batch_8616(
        project, (dataclasses.replace(
            _projection(scope, block, row), scope=twin),)) == (False,)


def test_batch_refuses_duplicate_callsite_projection(monkeypatch: pytest.MonkeyPatch) -> None:
    """A callsite claimed twice is ambiguous; neither slot may admit."""
    project, scope, _artifact, block, row = _synthetic()
    _clean_native(monkeypatch, scope)
    projection = _projection(scope, block, row)
    assert consume_declared_selector_callsite_batch_8616(
        project, (projection, projection)) == (False, False)
    assert consume_declared_selector_callsite_batch_8616(
        project, (projection, dataclasses.replace(projection))) == (False, False)


@pytest.mark.parametrize("field,wrong", [
    ("incoming_cs", 0),
    ("incoming_cs", 0x10000),
    ("target_addr", 0x1041),
    ("next_addr", 0x1004),
    ("callsite_addr", 0x1004),
])
def test_batch_refuses_forged_projection_fields(
    monkeypatch: pytest.MonkeyPatch, field: str, wrong: int,
) -> None:
    """Changed CS, target, continuation, or callsite never consumes."""
    project, scope, _artifact, block, row = _synthetic()
    _clean_native(monkeypatch, scope)
    forged = dataclasses.replace(_projection(scope, block, row), **{field: wrong})
    assert consume_declared_selector_callsite_batch_8616(project, (forged,)) == (False,)


def test_batch_refuses_stale_callsite_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Live bytes that no longer decode the bound E8 target refuse."""
    project, scope, _artifact, block, row = _synthetic()
    _clean_native(monkeypatch, scope)
    monkeypatch.setattr(
        invariant, "_loaded_bytes_8616", lambda *args: b"\x90\x90\x90")
    assert consume_declared_selector_callsite_batch_8616(
        project, (_projection(scope, block, row),)) == (False,)


def test_batch_refuses_native_callback_mutating_retained_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A rebind callback that mutates the retained graph fails the seal."""
    project, scope, artifact, block, row = _synthetic()
    _clean_native(monkeypatch, scope)
    original = artifact.blocks

    real_native = invariant._prepare_scoped_native_rebind_8616

    def corrupt(
        project_arg: object, boundary: object,
        caller: IRFunctionArtifact | None = None,
    ) -> ScopedNativeRebindFacts8616:
        facts = real_native(project_arg, boundary, caller=caller)
        object.__setattr__(artifact, "blocks", ())
        return facts

    monkeypatch.setattr(invariant, "_prepare_scoped_native_rebind_8616", corrupt)
    try:
        assert consume_declared_selector_callsite_batch_8616(
            project, (_projection(scope, block, row),)) == (False,)
    finally:
        object.__setattr__(artifact, "blocks", original)


def test_batch_refuses_authority_read_mutating_ir(monkeypatch: pytest.MonkeyPatch) -> None:
    """The last authority read cannot mutate retained graphs past the seal."""
    project, scope, artifact, block, row = _synthetic()
    _clean_native(monkeypatch, scope)
    original = artifact.blocks
    reads: list[int] = []

    def corrupt(*args: object, **kwargs: object) -> None:
        reads.append(1)
        if len(reads) == 2:
            object.__setattr__(artifact, "blocks", ())

    monkeypatch.setattr(invariant, "_authenticate_authority", corrupt)
    try:
        assert consume_declared_selector_callsite_batch_8616(
            project, (_projection(scope, block, row),)) == (False,)
    finally:
        object.__setattr__(artifact, "blocks", original)


def test_batch_refuses_final_authority_stale(monkeypatch: pytest.MonkeyPatch) -> None:
    """A module byte that changed after native reads refuses at the last check."""
    project, scope, _artifact, block, row = _synthetic()
    _clean_native(monkeypatch, scope)
    reads: list[int] = []

    def stale(*args: object, **kwargs: object) -> object | None:
        reads.append(1)
        return None if len(reads) == 1 else object()

    monkeypatch.setattr(invariant, "_authenticate_authority", stale)
    assert consume_declared_selector_callsite_batch_8616(
        project, (_projection(scope, block, row),)) == (False,)


def test_batch_honors_shared_work_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """An exhausted shared ledger accounts a refusal, never a partial admit."""
    project, scope, _artifact, block, row = _synthetic()
    _clean_native(monkeypatch, scope)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.census_work_units = 20000
        assert consume_declared_selector_callsite_batch_8616(
            project, (_projection(scope, block, row),)) == (False,)


def _wrap_fixture() -> binding_tests.Fixture:
    """Build the high-address callsite whose window needs declared authority."""
    import io

    import angr

    from tools.dosunit.recursive_proofs.real16_loader_arch import real16_loader_arch

    head = 0x10020
    image = bytearray(0x11000)
    image[head:head + 4] = bytes.fromhex("e80001c3")
    image[0x10123] = 0xC3
    project = angr.Project(io.BytesIO(image), auto_load_libs=False, simos="DOS",
                           main_opts={"backend": "blob", "arch": real16_loader_arch(),
                                      "base_addr": 0, "entry_point": head})
    return binding_tests._fixture(project, head, head + 4, head)


def _wrap_projection(fixture: binding_tests.Fixture) -> DeclaredSelectorCallsite8616:
    """Construct the exact canonical projection type for the wrap callsite."""
    return DeclaredSelectorCallsite8616(
        scope=cast(invariant.DeclaredSegmentInvariant, SimpleNamespace(project=fixture.project)),
        block=fixture.block,
        instruction=fixture.call,
        callsite_addr=0x10020,
        target_addr=0x10123,
        next_addr=0x10023,
        incoming_cs=0x1002,
    )


def _pending(fixture: binding_tests.Fixture) -> DirectNearCallTargetBindingPending8616:
    """Run the shared analysis, leaving the selector window pending."""
    pending = prepare_declared_near_call_target_binding_pending_8616(
        fixture.project, block=fixture.block, instruction=fixture.call,
        coordinates=DirectNearCallCoordinates8616(0x10020, 0x10023, 0x10123),
        selector_binding=_wrap_projection(fixture),
    )
    assert type(pending) is DirectNearCallTargetBindingPending8616
    return pending


def test_pending_is_typed_analysis_never_a_proof() -> None:
    """The prepared result carries PENDING status, never PROVEN or complete."""
    pending = _pending(_wrap_fixture())
    assert pending.verdict is DirectNearCallTargetBindingVerdict8616.PENDING
    assert not isinstance(pending, DirectNearCallTargetBinding8616)
    assert pending.operand is pending.instruction.args[0]
    assert pending.selector_binding is not None


def test_prepare_refuses_foreign_projection_type() -> None:
    """Only the canonical projection type may enter the pending stage."""
    fixture = _wrap_fixture()
    refused = prepare_declared_near_call_target_binding_pending_8616(
        fixture.project, block=fixture.block, instruction=fixture.call,
        coordinates=DirectNearCallCoordinates8616(0x10020, 0x10023, 0x10123),
        selector_binding=cast(DeclaredSelectorCallsite8616, object()),
    )
    assert type(refused) is DirectNearCallTargetBinding8616
    assert refused.verdict is DirectNearCallTargetBindingVerdict8616.UNKNOWN_REFUSE


def test_seal_materializes_admitted_pending_without_callbacks() -> None:
    """The pure seal binds the identical projection it was admitted under."""
    pending = _pending(_wrap_fixture())
    sealed = _seal_declared_selector_binding_8616(pending, admitted=True)
    assert sealed.verdict is DirectNearCallTargetBindingVerdict8616.PROVEN
    assert sealed.selector_binding is pending.selector_binding
    assert sealed.stats.closed


def test_seal_refuses_unadmitted_or_foreign_pending() -> None:
    """No binding materializes without a fresh batch admission verdict."""
    pending = _pending(_wrap_fixture())
    refused = _seal_declared_selector_binding_8616(pending, admitted=False)
    assert refused.verdict is DirectNearCallTargetBindingVerdict8616.UNKNOWN_REFUSE
    foreign = _seal_declared_selector_binding_8616(
        cast(DirectNearCallTargetBindingPending8616, object()), admitted=True)
    assert foreign.verdict is DirectNearCallTargetBindingVerdict8616.UNKNOWN_REFUSE


@pytest.mark.parametrize("mutation", ["args", "origin", "membership", "projection"])
def test_seal_refuses_post_prepare_graph_mutation(mutation: str) -> None:
    """A later callback mutating operand, provenance, or identity fails the seal."""
    fixture = _wrap_fixture()
    pending = _pending(fixture)
    instruction, block = pending.instruction, pending.block
    if mutation == "args":
        object.__setattr__(
            instruction, "args", (IRValue(MemSpace.CONST, const=1),))
    elif mutation == "origin":
        assert instruction.origin is not None
        object.__setattr__(
            instruction, "origin",
            dataclasses.replace(
                instruction.origin,
                statement_index=(instruction.origin.statement_index or 0) + 1,
            ),
        )
    elif mutation == "membership":
        object.__setattr__(block, "instrs", ())
    else:
        assert pending.selector_binding is not None
        object.__setattr__(
            pending.selector_binding, "callsite_addr",
            pending.selector_binding.callsite_addr + 1,
        )
    sealed = _seal_declared_selector_binding_8616(pending, admitted=True)
    assert sealed.verdict is DirectNearCallTargetBindingVerdict8616.UNKNOWN_REFUSE


@_CORPUS_MARK
class TestCanonicalBatch:
    """Corpus-backed controls over the real BITNBR declared proof."""

    @staticmethod
    def _prove() -> tuple[object, object, DeclaredFunctionEntryLink8616,
                          DeclaredSegmentInvariant]:
        """Reproduce the canonical declared-selector proof for the module."""
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
                receipt = invariant.prove_declared_selector_invariant_8616(
                    project, source, entry)
        assert receipt.status is InvariantStatus.PROVEN_CONDITIONAL
        return project, source, entry, receipt

    @pytest.fixture(scope="class")
    @staticmethod
    def proven() -> tuple[object, object, DeclaredFunctionEntryLink8616,
                              DeclaredSegmentInvariant]:
        """One shared canonical proof for every corpus control."""
        return TestCanonicalBatch._prove()

    @staticmethod
    def _projections(
        receipt: DeclaredSegmentInvariant,
    ) -> tuple[DeclaredSelectorCallsite8616, ...]:
        """Project every preserved corpus call edge into its capability."""
        projected = []
        for edge in receipt.call_edges:
            if edge.verdict is not Verdict.PRESERVED:
                continue
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
            projection = selector_callsite_8616(
                receipt, state.block, state.instruction,
                edge.target_addr, row.fallthrough)
            assert projection is not None
            projected.append(projection)
        return tuple(projected)

    def test_batch_rebinds_root_once_for_all_callsites(self, proven, monkeypatch) -> None:
        """Four callsites share one root-surface rebind in a single admission."""
        project, _source, entry, receipt = proven
        projections = self._projections(receipt)
        assert len(projections) == 4
        real_native = invariant._prepare_scoped_native_rebind_8616
        rebound: list[object] = []

        def spy(
            project_arg: object, boundary: object,
            caller: IRFunctionArtifact | None = None,
        ) -> ScopedNativeRebindFacts8616:
            rebound.append(boundary)
            return real_native(project_arg, boundary, caller=caller)

        monkeypatch.setattr(invariant, "_prepare_scoped_native_rebind_8616", spy)
        with native_import_request_8616():
            verdicts = consume_declared_selector_callsite_batch_8616(project, projections)
        assert verdicts == (True,) * len(projections)
        assert len(rebound) == 1
        assert rebound[0] is entry.boundary

    def test_collection_materializes_every_call_under_batch(
        self, proven, monkeypatch,
    ) -> None:
        """All four calls materialize; single-call consume is never invoked."""
        project, _source, _entry, receipt = proven
        singles: list[object] = []
        real_single = invariant.consume_declared_selector_callsite_8616

        def spy(project_arg: object, projection: object) -> bool:
            singles.append(projection)
            return real_single(project_arg, projection)

        monkeypatch.setattr(
            invariant, "consume_declared_selector_callsite_8616", spy)
        deadline = time.monotonic() + 25
        with native_import_request_8616(), \
                segment_call_dependency_traversal_scope_8616() as traversal:
            traversal.census_deadline = deadline
            with direct_evidence_deadline_scope_8616(project, deadline):
                records = collector.collect_declared_selector_call_preservations_8616(
                    project, receipt)
        assert len(records) == 4
        assert all(record.failure is None for record in records)
        assert all(record.materialized_count == 1 for record in records)
        assert singles == []
        # Each later public use is an independent request. This checks freshness
        # of every materialized record; the main regression separately requires
        # the entire invocation to fit one shared production request budget.
        for record in records:
            with native_import_request_8616(), \
                    segment_call_dependency_traversal_scope_8616() as traversal:
                traversal.census_deadline = time.monotonic() + 25
                with direct_evidence_deadline_scope_8616(project, traversal.census_deadline):
                    assert record.complete_for_selector(receipt)

    def test_late_operand_and_provenance_mutation_refuses(
        self, proven, monkeypatch,
    ) -> None:
        """A later batch callback mutating an earlier CALL fails its seal."""
        project, _source, _entry, receipt = proven
        projections = self._projections(receipt)
        first = min(projections, key=lambda item: item.callsite_addr)
        victim = first.instruction
        original_args = victim.args
        surface = invariant._loaded_bytes_8616
        calls: list[int] = []

        def mutating(project_arg: object, addr: int, size: int) -> bytes | None:
            calls.append(1)
            if len(calls) == 2:
                object.__setattr__(victim, "args", ())
            return surface(project_arg, addr, size)

        monkeypatch.setattr(
            invariant, "_loaded_bytes_8616", mutating)
        deadline = time.monotonic() + 25
        try:
            with native_import_request_8616(), \
                    segment_call_dependency_traversal_scope_8616() as traversal:
                traversal.census_deadline = deadline
                with direct_evidence_deadline_scope_8616(project, deadline):
                    records = collector.collect_declared_selector_call_preservations_8616(
                        project, receipt)
        finally:
            object.__setattr__(victim, "args", original_args)
        assert len(records) == 4
        corrupted = next(
            record for record in records
            if record.callsite_addr == first.callsite_addr)
        assert corrupted.failure is Failure.CALLEE_INCOMPLETE
        # All rows consume the same root graph. A mutated root cannot provide
        # fresh native evidence even for an otherwise unchanged CALL.
        assert all(record.failure is not None for record in records)

    def test_final_native_callback_mutating_root_refuses(
        self, proven, monkeypatch,
    ) -> None:
        """The last surface rebind cannot replace the retained root blocks."""
        project, _source, entry, receipt = proven
        projections = self._projections(receipt)
        real_native = invariant._prepare_scoped_native_rebind_8616
        artifact = entry.artifact
        original = artifact.blocks

        def corrupt(
            project_arg: object, boundary: object,
            caller: IRFunctionArtifact | None = None,
        ) -> ScopedNativeRebindFacts8616:
            result = real_native(project_arg, boundary, caller=caller)
            if boundary is entry.boundary:
                object.__setattr__(artifact, "blocks", ())
            return result

        monkeypatch.setattr(invariant, "_prepare_scoped_native_rebind_8616", corrupt)
        try:
            with native_import_request_8616():
                verdicts = consume_declared_selector_callsite_batch_8616(
                    project, projections)
            assert verdicts == (False,) * len(projections)
        finally:
            object.__setattr__(artifact, "blocks", original)

    def test_unfetched_module_byte_mutation_refuses(self, proven) -> None:
        """Module bytes outside every fetched span are covered by authority."""
        project, source, _entry, receipt = proven
        projections = self._projections(receipt)
        base, module = source.boot.image.chunks[0]
        address = base + len(module) - 1
        original = project.loader.memory.load(address, 1)
        try:
            project.loader.memory.store(address, bytes([module[-1] ^ 1]))
            with native_import_request_8616():
                verdicts = consume_declared_selector_callsite_batch_8616(
                    project, projections)
            assert verdicts == (False,) * len(projections)
        finally:
            project.loader.memory.store(address, original)

    def test_budget_exhaustion_accounts_every_call(self, proven) -> None:
        """An exhausted ledger still produces one typed record per CALL."""
        project, _source, _entry, receipt = proven
        deadline = time.monotonic() + 25
        with segment_call_dependency_traversal_scope_8616() as traversal:
            traversal.census_deadline = deadline
            traversal.census_work_units = 19000
            with native_import_request_8616(), \
                    direct_evidence_deadline_scope_8616(project, deadline):
                records = collector.collect_declared_selector_call_preservations_8616(
                    project, receipt)
        assert len(records) == 4
        assert all(record.failure is not None for record in records)
        assert all(record.materialized_count == 0 for record in records)
        assert any(record.failure is Failure.BUDGET_EXHAUSTED for record in records)

    def test_public_complete_replays_after_later_mutation(self, proven) -> None:
        """Batch admission never waives fresh public consumption checks."""
        project, _source, _entry, receipt = proven
        deadline = time.monotonic() + 25
        with native_import_request_8616(), \
                segment_call_dependency_traversal_scope_8616() as traversal:
            traversal.census_deadline = deadline
            with direct_evidence_deadline_scope_8616(project, deadline):
                records = collector.collect_declared_selector_call_preservations_8616(
                    project, receipt)
        materialized = [record for record in records if record.failure is None]
        assert materialized
        record = materialized[0]
        original = bytes(project.loader.memory.load(record.callsite_addr, 3))
        try:
            project.loader.memory.store(record.callsite_addr, b"\x90" * 3)
            with native_import_request_8616(), \
                    segment_call_dependency_traversal_scope_8616() as traversal:
                traversal.census_deadline = time.monotonic() + 25
                with direct_evidence_deadline_scope_8616(
                    project, traversal.census_deadline,
                ):
                    assert not record.complete_for_selector(receipt)
                    if record.binding is not None:
                        assert not record.binding.complete
                    assert not record.complete
        finally:
            project.loader.memory.store(record.callsite_addr, original)
