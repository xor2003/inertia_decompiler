"""Staged call-record collection defers deep caller proof until the pool exists.

Layer: tests.
Responsibility: pin the collector's two-pass contract — the first pass assembles
the caller's record pool, so it must not invoke the caller-domain premise that
consumes that pool; the second pass retries selector-window refusals with the
assembled pool under the shared, never-reset deadline. Standalone
``prove_entry_domain_call_preservation_8616`` keeps its unconditional premise
behavior, and an undischarged selector-window refusal stays a typed refusal.
"""

from types import SimpleNamespace
from typing import cast

import pytest

import inertia.ir.direct_evidence_deadline as deadline_owner
import inertia.ir.entry_domain_call_preservation as owner
import inertia.semantics.direct_near_call_target_binding as binding_owner
from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
    DecodedDirectCallsiteIndex8616,
    DecodedDirectCallsiteIndexStats8616,
)
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace

pytestmark = pytest.mark.decompiler

_HEAD = 0x10000
_SELECTOR = binding_owner.DirectNearCallTargetBindingFailure8616.SELECTOR_WINDOW_UNPROVED
_UNRESOLVED = owner.EntryDomainCallPreservationFailure8616.CALLEE_UNRESOLVED


def _call_entry(callsite_addr: int, target_addr: int) -> DecodedDirectCallsite8616:
    """Build one decoded E8 near-call row whose raw target is its identity."""
    next_addr = callsite_addr + 3
    encoding = b"\xe8" + (target_addr - next_addr).to_bytes(2, "little", signed=True)
    decoded = SimpleNamespace(address=callsite_addr, size=3, bytes=encoding)
    return DecodedDirectCallsite8616(
        caller_start=_HEAD,
        instructions=(decoded,),
        instruction_index=0,
        callsite_addr=callsite_addr,
        target_addr=target_addr,
    )


def _symbolic_artifact(call_sites: tuple[int, ...]) -> IRFunctionArtifact:
    """Build a caller artifact whose CALL operands need the symbolic binder."""
    instrs = tuple(
        IRInstr("CALL", None, (IRValue(MemSpace.TMP, name=f"t{index}"),), addr=addr)
        for index, addr in enumerate(call_sites)
    )
    return IRFunctionArtifact(_HEAD, (IRBlock(_HEAD, instrs),))


def _closed_index(entries: tuple[DecodedDirectCallsite8616, ...]) -> DecodedDirectCallsiteIndex8616:
    """Index the retained rows by their normalized near-target identity."""
    grouped: dict[int, list[DecodedDirectCallsite8616]] = {}
    for entry in entries:
        grouped.setdefault(entry.target_addr & 0xFFFF, []).append(entry)
    total = len(entries)
    return DecodedDirectCallsiteIndex8616(
        {key: tuple(rows) for key, rows in grouped.items()},
        DecodedDirectCallsiteIndexStats8616(total, total, total, total, 0),
    )


def _selector_binding(
    callsite_addr: int,
) -> binding_owner.DirectNearCallTargetBinding8616:
    """One typed selector-window refusal carrying closed accounting."""
    return binding_owner.DirectNearCallTargetBinding8616(
        callsite_addr=callsite_addr,
        target_addr=None,
        verdict=binding_owner.DirectNearCallTargetBindingVerdict8616.UNKNOWN_REFUSE,
        failure=_SELECTOR,
        stats=binding_owner.DirectNearCallTargetBindingStats8616(1, 1, 1, 0, 1),
    )


def _install_world(
    monkeypatch: pytest.MonkeyPatch,
    artifact: IRFunctionArtifact,
    entries: tuple[DecodedDirectCallsite8616, ...],
    binder: object,
) -> tuple[object, object]:
    """Bind the collector to retained index/window evidence with refused callees."""
    project = SimpleNamespace()
    boundary = cast(
        owner.ExactFunctionRangeBoundary8616,
        SimpleNamespace(project=project, addr=artifact.function_addr),
    )
    decoded_by_addr = {entry.callsite_addr: entry for entry in entries}
    index = _closed_index(entries)
    monkeypatch.setattr(
        owner,
        "decoded_callsite_index_for_boundary_8616",
        lambda *args, **kwargs: SimpleNamespace(index=index),
    )
    monkeypatch.setattr(
        owner, "_decoded_instruction_map_8616", lambda *args: decoded_by_addr
    )
    monkeypatch.setattr(
        owner,
        "_callee_closure_8616",
        lambda *args, **kwargs: (None, _UNRESOLVED),
    )
    monkeypatch.setattr(
        owner, "_invocation_premise_source_8616",
        lambda *args: owner.Real16InvocationSource8616(object(), None, index),
    )
    monkeypatch.setattr(
        binding_owner,
        "prove_direct_near_call_target_binding_at_coordinates_8616",
        binder,
    )
    return project, boundary


def _resolver(entry: DecodedDirectCallsite8616) -> int:
    """Resolve the retained decoded row to its canonical target identity."""
    return entry.target_addr


def _collect(project: object, artifact: IRFunctionArtifact, boundary: object):
    """Run the real collector against the installed world."""
    return owner.collect_entry_domain_call_preservations_8616(
        project,
        artifact,
        cast(owner.ExactFunctionRangeBoundary8616, boundary),
        direct_target_resolver=_resolver,
    )


def test_collection_reauthenticates_independent_prefix_retries(monkeypatch):
    """Each sibling proof gets fresh verdicts so callbacks cannot leave stale truth."""
    from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616

    sites = (0x10000, 0x10010, 0x10020)
    artifact = _symbolic_artifact(sites)
    entries = tuple(_call_entry(addr, addr + 0x1003) for addr in sites)
    project, boundary = _install_world(
        monkeypatch, artifact, entries,
        lambda project, *, block, instruction, coordinates, invocation=None:
        _selector_binding(coordinates.callsite_addr),
    )
    traversals = []

    def observe(*_args):
        with segment_call_dependency_traversal_scope_8616() as traversal:
            traversals.append(traversal)
        return None

    monkeypatch.setattr(owner, "_caller_invocation_premise_8616", observe)
    _collect(project, artifact, boundary)
    _collect(project, artifact, boundary)
    assert len(traversals) == 6
    assert len({id(item) for item in traversals}) == len(traversals)


def test_first_pass_defers_caller_premise_until_pool_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Selector-window refusals invoke the premise once, with the full pool."""
    call_sites = (0x10000, 0x10010, 0x10020)
    entries = tuple(_call_entry(addr, addr + 0x1003) for addr in call_sites)
    artifact = _symbolic_artifact(call_sites)
    project, boundary = _install_world(
        monkeypatch,
        artifact,
        entries,
        lambda project, *, block, instruction, coordinates, invocation=None: (
            _selector_binding(coordinates.callsite_addr)
        ),
    )
    premise_calls: list[tuple[int, tuple[object, ...]]] = []
    monkeypatch.setattr(
        owner,
        "_caller_invocation_premise_8616",
        lambda project, artifact, boundary, callsite_addr, records: (
            premise_calls.append((callsite_addr, tuple(records))) or None
        ),
    )

    records = _collect(project, artifact, boundary)

    assert len(records) == len(call_sites)
    # The deferred first pass performs no caller-premise traversal at all;
    # exactly one premise attempt per refused callsite runs in the retry pass.
    assert [callsite for callsite, _pool in premise_calls] == list(call_sites)
    for _callsite, pool in premise_calls:
        assert len(pool) == len(call_sites)


def test_retry_pool_carries_exact_identity_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The second pass supplies the assembled pool bound to identical objects."""
    call_sites = (0x10000, 0x10010)
    entries = tuple(_call_entry(addr, addr + 0x1003) for addr in call_sites)
    artifact = _symbolic_artifact(call_sites)
    project, boundary = _install_world(
        monkeypatch,
        artifact,
        entries,
        lambda project, *, block, instruction, coordinates, invocation=None: (
            _selector_binding(coordinates.callsite_addr)
        ),
    )
    pools: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        owner,
        "_caller_invocation_premise_8616",
        lambda project, artifact, boundary, callsite_addr, records: (
            pools.append(tuple(records)) or None
        ),
    )

    _collect(project, artifact, boundary)

    block = artifact.blocks[0]
    for pool in pools:
        assert len(pool) == len(call_sites)
        for record, instruction in zip(pool, block.instrs, strict=True):
            assert record.artifact is artifact
            assert record.block is block
            assert record.instruction is instruction
            assert record.callsite_addr == instruction.addr


def test_refusal_remains_refusal_when_premise_cannot_discharge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed premise retry keeps the typed selector-window refusal."""
    call_sites = (0x10000,)
    entries = (_call_entry(0x10000, 0x11003),)
    artifact = _symbolic_artifact(call_sites)
    project, boundary = _install_world(
        monkeypatch,
        artifact,
        entries,
        lambda project, *, block, instruction, coordinates, invocation=None: (
            _selector_binding(coordinates.callsite_addr)
        ),
    )
    monkeypatch.setattr(
        owner, "_caller_invocation_premise_8616", lambda *args: None
    )

    records = _collect(project, artifact, boundary)

    assert len(records) == 1
    record = records[0]
    assert record.failure is not None
    assert record.binding is not None
    assert record.binding.failure is _SELECTOR


def test_premise_retry_rebinds_with_transport_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A proven premise reaches the second binder call as ``invocation``."""
    premise = object()
    entries = (_call_entry(0x10000, 0x11003),)
    artifact = _symbolic_artifact((0x10000,))
    invocations: list[object] = []

    def binder(
        project: object,
        *,
        block: object,
        instruction: object,
        coordinates: object,
        invocation: object = None,
    ) -> binding_owner.DirectNearCallTargetBinding8616:
        invocations.append(invocation)
        return _selector_binding(
            cast(binding_owner.DirectNearCallCoordinates8616, coordinates).callsite_addr
        )

    project, boundary = _install_world(monkeypatch, artifact, entries, binder)
    monkeypatch.setattr(
        owner, "_caller_invocation_premise_8616", lambda *args: premise
    )

    records = _collect(project, artifact, boundary)

    # Pass one binds once; the deferred premise runs in pass two and rebinds.
    assert invocations == [None, None, premise]
    assert len(records) == 1
    assert records[0].binding is not None
    assert records[0].binding.failure is _SELECTOR


def test_locally_bound_calls_never_enter_the_premise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-selector outcomes and CONST operands resolve without premise work."""
    call_sites = (0x10000, 0x10010, 0x10020)
    entries = tuple(_call_entry(addr, addr + 0x1003) for addr in call_sites)
    instrs = (
        IRInstr("CALL", None, (IRValue(MemSpace.CONST, const=0x11003),), addr=0x10000),
        IRInstr("CALL", None, (IRValue(MemSpace.TMP, name="t1"),), addr=0x10010),
        IRInstr("CALL", None, (IRValue(MemSpace.TMP, name="t2"),), addr=0x10020),
    )
    artifact = IRFunctionArtifact(_HEAD, (IRBlock(_HEAD, instrs),))
    other_failure = (
        binding_owner.DirectNearCallTargetBindingFailure8616.TARGET_UNRESOLVED
    )

    def binder(
        project: object,
        *,
        block: object,
        instruction: object,
        coordinates: object,
        invocation: object = None,
    ) -> binding_owner.DirectNearCallTargetBinding8616:
        callsite = cast(
            binding_owner.DirectNearCallCoordinates8616, coordinates
        ).callsite_addr
        if callsite == 0x10020:
            return _selector_binding(callsite)
        return binding_owner.DirectNearCallTargetBinding8616(
            callsite_addr=callsite,
            target_addr=None,
            verdict=binding_owner.DirectNearCallTargetBindingVerdict8616.UNKNOWN_REFUSE,
            failure=other_failure,
            stats=binding_owner.DirectNearCallTargetBindingStats8616(1, 1, 1, 0, 1),
        )

    project, boundary = _install_world(monkeypatch, artifact, entries, binder)
    premise_calls: list[int] = []
    monkeypatch.setattr(
        owner,
        "_caller_invocation_premise_8616",
        lambda project, artifact, boundary, callsite_addr, records: (
            premise_calls.append(callsite_addr) or None
        ),
    )

    records = _collect(project, artifact, boundary)

    # The CONST operand and the non-selector refusal are decided in pass one;
    # only the selector-window refusal reaches the premise retry.
    assert premise_calls == [0x10020]
    assert len(records) == 3
    assert records[0].binding is None
    assert records[1].binding is not None
    assert records[1].binding.failure is other_failure


def test_standalone_prove_still_attempts_caller_premise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without a collection phase the standalone proof is unchanged."""
    entries = (_call_entry(0x10000, 0x11003),)
    artifact = _symbolic_artifact((0x10000,))
    project, boundary = _install_world(
        monkeypatch,
        artifact,
        entries,
        lambda project, *, block, instruction, coordinates, invocation=None: (
            _selector_binding(coordinates.callsite_addr)
        ),
    )
    premise_calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        owner,
        "_caller_invocation_premise_8616",
        lambda project, artifact, boundary, callsite_addr, records: (
            premise_calls.append(tuple(records)) or None
        ),
    )
    block = artifact.blocks[0]

    record = owner.prove_entry_domain_call_preservation_8616(
        project,
        artifact,
        cast(owner.ExactFunctionRangeBoundary8616, boundary),
        block,
        block.instrs[0],
        index=_closed_index(entries),
        decoded_by_addr={entry.callsite_addr: entry for entry in entries},
        resolution=owner._CalleeResolution8616(_resolver),
    )

    assert premise_calls == [()]
    assert record.failure is not None
    assert record.binding is not None
    assert record.binding.failure is _SELECTOR


def test_pool_phase_defers_premise_in_standalone_prove(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The explicit collection phase defers even a standalone proof."""
    entries = (_call_entry(0x10000, 0x11003),)
    artifact = _symbolic_artifact((0x10000,))
    project, boundary = _install_world(
        monkeypatch,
        artifact,
        entries,
        lambda project, *, block, instruction, coordinates, invocation=None: (
            _selector_binding(coordinates.callsite_addr)
        ),
    )
    monkeypatch.setattr(
        owner,
        "_caller_invocation_premise_8616",
        lambda *args: pytest.fail("premise ran during record-pool assembly"),
    )
    block = artifact.blocks[0]

    record = owner.prove_entry_domain_call_preservation_8616(
        project,
        artifact,
        cast(owner.ExactFunctionRangeBoundary8616, boundary),
        block,
        block.instrs[0],
        index=_closed_index(entries),
        decoded_by_addr={entry.callsite_addr: entry for entry in entries},
        resolution=owner._CalleeResolution8616(_resolver),
        collection_phase=owner._CallCollectionPhase8616.RECORD_POOL,
    )

    assert record.failure is not None
    assert record.binding is not None
    assert record.binding.failure is _SELECTOR


def test_staged_passes_share_one_deadline_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both passes join one premise session that inherits, never resets."""
    call_sites = (0x10000, 0x10010)
    entries = tuple(_call_entry(addr, addr + 0x1003) for addr in call_sites)
    artifact = _symbolic_artifact(call_sites)
    project, boundary = _install_world(
        monkeypatch,
        artifact,
        entries,
        lambda project, *, block, instruction, coordinates, invocation=None: (
            _selector_binding(coordinates.callsite_addr)
        ),
    )
    deadline = deadline_owner.time.monotonic() + 60.0
    sessions: list[tuple[object, object]] = []

    def premise(
        project: object,
        artifact: object,
        boundary: object,
        callsite_addr: int,
        records: object,
    ) -> None:
        premise_session = owner._active_premise_resolution_8616(project)
        callee_session = owner._active_resolution_8616(project)
        sessions.append((callee_session, premise_session))
        return None

    monkeypatch.setattr(owner, "_caller_invocation_premise_8616", premise)

    with deadline_owner.direct_evidence_deadline_scope_8616(project, deadline):
        records = _collect(project, artifact, boundary)

    assert len(records) == 2
    assert len(sessions) == 2
    callee_sessions = {id(pair[0]) for pair in sessions}
    premise_sessions = {id(pair[1]) for pair in sessions}
    assert len(callee_sessions) == 1
    assert len(premise_sessions) == 1
    assert sessions[0][0].deadline == sessions[0][1].deadline == deadline
    assert owner._active_resolution_8616(project) is None
    assert owner._active_premise_resolution_8616(project) is None
