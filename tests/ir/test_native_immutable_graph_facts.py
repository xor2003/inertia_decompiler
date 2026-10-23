"""Immutable canonical graph facts for the scoped native seal.

Layer: IR tests.

Responsibility: prove the seal's detached evidence is an exact, deeply
immutable canonical capture — ``compare=False`` provenance mutations,
coordinated current/native mutations, omitted-row and boundary changes,
function-only refusal evidence, and malformed graphs are all observable,
while a fresh unchanged surface still seals. The final pure seal must
traverse the current graph exactly once and never re-walk detached graphs.
"""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import FrozenInstanceError

import pytest

import inertia.ir.real16_invocation_domain as native_owner
from inertia.frontend.x86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
)
from inertia.ir import ir_boundary_cfg as owner
from inertia.ir import source_graph_binding as graph
from inertia.ir.core import (
    IRBinaryValue,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRRefusal,
    IRValue,
    MemSpace,
)
from inertia.ir.instruction_origin import IRInstructionOrigin8616
from inertia.ir.source_graph_binding import (
    SourceGraphSerializationError8616,
    canonical_source_graph_8616,
    capture_immutable_source_graph_facts_8616,
)

pytestmark = pytest.mark.decompiler

INSTR_ADDRS = frozenset({0x1000, 0x1001})


def _surface() -> tuple[
    object,
    ExactFunctionRangeBoundary8616,
    IRFunctionArtifact,
    IRInstr,
    IRInstr,
]:
    """Build one synthetic owned surface with an extra non-selector row."""
    project = object()
    first = IRInstr(
        "MOV",
        IRValue(MemSpace.REG, name="ax", size=2),
        (IRValue(MemSpace.CONST, const=1, size=2),),
        size=2,
        addr=0x1000,
        origin=IRInstructionOrigin8616(0x1000, 0),
    )
    omitted = IRInstr(
        "MOV",
        IRValue(MemSpace.REG, name="dx", size=2),
        (IRValue(MemSpace.CONST, const=2, size=2),),
        size=2,
        addr=0x1001,
    )
    artifact = IRFunctionArtifact(0x1000, (IRBlock(0x1000, (first, omitted)),))
    boundary = ExactFunctionRangeBoundary8616(
        project, 0x1000, 2, frozenset({0x1000}), INSTR_ADDRS, ()
    )
    return project, boundary, artifact, first, omitted


def _native_return(
    monkeypatch: pytest.MonkeyPatch, artifact: IRFunctionArtifact,
) -> None:
    """Bind the native census import to return one controlled artifact."""
    monkeypatch.setattr(
        native_owner, "real16_native_census_import_8616",
        lambda project, boundary: artifact,
    )


def _seal(
    project: object,
    boundary: ExactFunctionRangeBoundary8616,
    artifact: IRFunctionArtifact,
    before: owner.ScopedNativeSurfaceSnapshot8616 | None,
) -> owner.IRBoundaryCoverageFailure8616 | None:
    """Run prepare plus the pure seal exactly as the scoped route composes them."""
    facts = owner._prepare_scoped_native_rebind_8616(project, boundary)
    return owner._scoped_native_rebind_failure_8616(
        boundary, artifact, facts, before
    )


def test_fresh_unchanged_surface_seals(monkeypatch: pytest.MonkeyPatch) -> None:
    """A structurally equal fresh native import seals the untouched surface."""
    project, boundary, artifact, _first, _omitted = _surface()
    before = owner._capture_scoped_native_surface_8616(boundary, artifact)
    _native_return(monkeypatch, deepcopy(artifact))
    assert _seal(project, boundary, artifact, before) is None


def test_before_none_route_keeps_full_native_comparison(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without a snapshot the seal still compares current against native."""
    project, boundary, artifact, _first, _omitted = _surface()
    _native_return(monkeypatch, deepcopy(artifact))
    assert _seal(project, boundary, artifact, None) is None
    altered = deepcopy(artifact)
    object.__setattr__(altered.blocks[0].instrs[1], "op", "STORE")
    _native_return(monkeypatch, altered)
    assert _seal(project, boundary, artifact, None) is (
        owner.IRBoundaryCoverageFailure8616.SCOPED_NATIVE_MISMATCH
    )


@pytest.mark.parametrize("mutation", ["source_tmp", "origin"])
def test_compare_false_provenance_mutation_refuses(
    monkeypatch: pytest.MonkeyPatch, mutation: str,
) -> None:
    """Mutating compare-excluded provenance revokes the pre-callback facts."""
    project, boundary, artifact, first, _omitted = _surface()
    before = owner._capture_scoped_native_surface_8616(boundary, artifact)
    _native_return(monkeypatch, deepcopy(artifact))
    if mutation == "source_tmp":
        assert first.dst is not None
        object.__setattr__(first.dst, "source_tmp", 99)
    else:
        assert first.origin is not None
        object.__setattr__(first.origin, "block_next_tmp", 7)
    assert _seal(project, boundary, artifact, before) is (
        owner.IRBoundaryCoverageFailure8616.SCOPED_NATIVE_MISMATCH
    )


def test_coordinated_mutation_with_matching_native_still_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Native returning the same altered graph cannot launder the mutation."""
    project, boundary, artifact, _first, omitted = _surface()
    before = owner._capture_scoped_native_surface_8616(boundary, artifact)
    object.__setattr__(omitted, "op", "STORE")
    _native_return(monkeypatch, artifact)
    assert _seal(project, boundary, artifact, before) is (
        owner.IRBoundaryCoverageFailure8616.SCOPED_NATIVE_MISMATCH
    )


def test_omitted_row_mutation_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    """A row outside any selector projection is still seal-covered."""
    project, boundary, artifact, _first, omitted = _surface()
    before = owner._capture_scoped_native_surface_8616(boundary, artifact)
    _native_return(monkeypatch, deepcopy(artifact))
    object.__setattr__(omitted, "op", "PUSH")
    assert _seal(project, boundary, artifact, before) is (
        owner.IRBoundaryCoverageFailure8616.SCOPED_NATIVE_MISMATCH
    )


def test_boundary_info_mutation_after_capture_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutating boundary metadata through its live dict revokes the seal."""
    project, boundary, artifact, _first, _omitted = _surface()
    boundary.info["lift"] = {"rows": [1, 2], "flagged": True}
    before = owner._capture_scoped_native_surface_8616(boundary, artifact)
    _native_return(monkeypatch, deepcopy(artifact))
    boundary.info["lift"] = {"rows": [1, 2], "flagged": False}
    assert _seal(project, boundary, artifact, before) is (
        owner.IRBoundaryCoverageFailure8616.SCOPED_NATIVE_MISMATCH
    )


@pytest.mark.parametrize(
    ("initial", "mutated"),
    [
        ([1], (list, (1,))),
        ((list, (1,)), [1]),
        ({"k": [1]}, {"k": (list, (1,))}),
    ],
)
def test_boundary_info_tagged_token_never_collides(
    monkeypatch: pytest.MonkeyPatch, initial: object, mutated: object,
) -> None:
    """Detached metadata compares exact containers; no encoding aliases."""
    project, boundary, artifact, _first, _omitted = _surface()
    boundary.info["x"] = initial
    before = owner._capture_scoped_native_surface_8616(boundary, artifact)
    _native_return(monkeypatch, deepcopy(artifact))
    boundary.info["x"] = mutated
    assert _seal(project, boundary, artifact, before) is (
        owner.IRBoundaryCoverageFailure8616.SCOPED_NATIVE_MISMATCH
    )


def test_function_only_refusal_census_survives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A function-level refusal absent from block mirroring still refuses."""
    project, boundary, artifact, _first, _omitted = _surface()
    refused = IRFunctionArtifact(
        0x1000, artifact.blocks, (IRRefusal("pending", "unmirrored"),)
    )
    _native_return(monkeypatch, deepcopy(refused))
    assert _seal(project, boundary, refused, None) is (
        owner.IRBoundaryCoverageFailure8616.SCOPED_REFUSAL
    )


def test_seal_walks_current_graph_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """The pure seal encodes only the current graph; detached graphs are facts."""
    project, boundary, artifact, _first, _omitted = _surface()
    before = owner._capture_scoped_native_surface_8616(boundary, artifact)
    _native_return(monkeypatch, deepcopy(artifact))
    facts = owner._prepare_scoped_native_rebind_8616(project, boundary)
    encoded: list[dict[str, object]] = []
    real_key = graph._record_key_8616

    def spy(
        record: dict[str, object],
        field_orders: dict[tuple[str, ...], tuple[str, ...]] | None = None,
    ) -> tuple[tuple[str, ...], tuple[object, ...]]:
        encoded.append(record)
        return real_key(record, field_orders)

    monkeypatch.setattr(graph, "_record_key_8616", spy)
    # Count actual encoding, including work hidden inside one capture call.
    # This remains observable when encoder methods are compiled C functions.
    graph.canonical_source_graph_8616(artifact.function_addr, artifact.blocks)
    expected = list(encoded)
    assert expected
    encoded.clear()
    assert owner._scoped_native_rebind_failure_8616(
        boundary, artifact, facts, before
    ) is None
    assert encoded == expected


def test_single_walk_oracle_rejects_actual_duplicate_capture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Duplicating internal work must fail the same single-walk assertion."""
    original = graph.capture_immutable_source_graph_facts_8616

    def twice(
        function_addr: int,
        blocks: tuple[IRBlock, ...],
        function_refusals: tuple[IRRefusal, ...] = (),
    ) -> graph.ImmutableSourceGraphFacts8616:
        original(function_addr, blocks, function_refusals)
        return original(function_addr, blocks, function_refusals)

    monkeypatch.setattr(graph, "capture_immutable_source_graph_facts_8616", twice)
    monkeypatch.setattr(owner, "capture_immutable_source_graph_facts_8616", twice)
    with pytest.raises(AssertionError):
        test_seal_walks_current_graph_once(monkeypatch)


def test_facts_replay_canonical_encoding_fields() -> None:
    """Frozen records carry the exact canonical node table, not a digest."""
    _project, _boundary, artifact, _first, _omitted = _surface()
    facts = capture_immutable_source_graph_facts_8616(
        artifact.function_addr, artifact.blocks, artifact.refusals
    )
    payload = json.loads(canonical_source_graph_8616(
        artifact.function_addr, artifact.blocks))
    assert payload["roots"] == list(facts.roots)
    assert len(payload["nodes"]) == len(facts.records)
    for node, record in zip(payload["nodes"], facts.records, strict=True):
        assert sorted(node) == list(record.names)
    copied = deepcopy(artifact)
    assert capture_immutable_source_graph_facts_8616(
        copied.function_addr, copied.blocks, copied.refusals
    ) == facts


def test_shared_and_deepcopied_dags_capture_equal_facts() -> None:
    """Structural interning gives shared and deep-copied DAGs identical facts."""
    leaf = IRValue(MemSpace.CONST, const=7, size=2)
    index = IRBinaryValue("Iop_Add16", leaf, leaf, size=2)
    shared = IRValue(MemSpace.REG, name="bx", size=2, index=index)
    block = IRBlock(
        0x1000,
        (
            IRInstr(
                "MOV", IRValue(MemSpace.REG, name="ax", size=2),
                (shared,), size=2, addr=0x1000,
            ),
            IRInstr(
                "ADD", IRValue(MemSpace.REG, name="cx", size=2),
                (shared,), size=2, addr=0x1001,
            ),
        ),
    )
    shared_facts = capture_immutable_source_graph_facts_8616(0x1000, (block,))
    copied = deepcopy((block,))
    assert capture_immutable_source_graph_facts_8616(0x1000, copied) == (
        shared_facts
    )
    assert capture_immutable_source_graph_facts_8616(0x1001, copied) != (
        shared_facts
    )


def test_detached_facts_do_not_traverse_or_share_live_graph() -> None:
    """Captured facts are deeply immutable and immune to later IR mutation."""
    _project, _boundary, artifact, first, _omitted = _surface()
    facts = capture_immutable_source_graph_facts_8616(
        artifact.function_addr, artifact.blocks
    )
    with pytest.raises(FrozenInstanceError):
        facts.function_addr = 0  # type: ignore[misc]
    with pytest.raises(TypeError):
        facts.records[0].values[0] = 0  # type: ignore[index]
    object.__setattr__(first, "op", "STORE")
    assert facts != capture_immutable_source_graph_facts_8616(
        artifact.function_addr, artifact.blocks
    )


def test_cyclic_and_malformed_graphs_reject() -> None:
    """Cycles and mutable child containers are typed refusals, not weak forms."""
    value = IRValue(MemSpace.REG, name="ax", size=2)
    binary = IRBinaryValue("Iop_Add16", value, value, size=2)
    object.__setattr__(value, "index", binary)
    cyclic = IRBlock(
        0x1000, (IRInstr("MOV", value, (), size=2, addr=0x1000),)
    )
    with pytest.raises(SourceGraphSerializationError8616):
        capture_immutable_source_graph_facts_8616(0x1000, (cyclic,))
    malformed = IRBlock(0x1000)
    object.__setattr__(malformed, "instrs", ["not-a-node"])
    with pytest.raises(SourceGraphSerializationError8616):
        capture_immutable_source_graph_facts_8616(0x1000, (malformed,))
