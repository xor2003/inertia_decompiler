"""IR/Alias lineage binding tests for the direct-call segment-entry proof.

Layer: Tests.
Responsibility: cover the in-process object-identity gate that binds one
proven DS==SS candidate to the raw IR artifact registered on its own project
and to the exact IR artifact its Alias restore source was built from.
Foreign IR, foreign Alias evidence, unbound sources, and equal-content copies
must all refuse even when addresses and CFGs match.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from types import SimpleNamespace
from typing import Any, cast

import pytest
from inertia.ir import IRFunctionArtifact
from inertia.ir.direct_call_segment_entry import (
    DirectCallSegmentEntryCandidate8616,
    DirectCallSegmentEntryProof8616,
    DirectCallSegmentEntryRefusal8616,
    DirectCallSegmentEntryVerdict8616,
    prove_x86_16_direct_call_segment_entry_8616,
)
from inertia.ir.function_ir_registry import (
    publish_function_ir_artifact_8616,
)
from inertia.ir.segment_state_transfer import SegmentRestoreSource
from inertia.ir.vex_import import build_x86_16_ir_function_artifact

from inertia.alias.segment_stack_restore import (
    build_x86_16_segment_stack_restore_artifact,
)
from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsiteIndex8616,
    build_decoded_direct_callsite_index_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
    exact_function_range_boundary_8616,
)
from inertia.lowering.analysis_helpers import (
    resolve_direct_call_target_from_instruction_8616,
)
from inertia.cli.project_loading import _build_project_from_bytes

_BASE = 0x1000
_CALLSITE = 0x1002
_CALLEE = 0x1007
# push ss; pop ds; call 0x1007; ret; nop; callee: ret
_A_BYTES = bytes.fromhex("16 1f e8 02 00 c3 90 c3")
# push ds; pop ds; call 0x1007; ret; nop; callee: ret
_B_BYTES = bytes.fromhex("1e 1f e8 02 00 c3 90 c3")


@dataclass(frozen=True, slots=True)
class _Evidence8616:
    """One project's boundary/IR/Alias/index bundle for the fixed candidate."""

    project: object
    caller: ExactFunctionRangeBoundary8616
    callee: ExactFunctionRangeBoundary8616
    artifact: IRFunctionArtifact
    restore_sources: tuple[SegmentRestoreSource, ...]
    index: DecodedDirectCallsiteIndex8616


def _evidence(code: bytes) -> _Evidence8616:
    """Build a full byte-backed evidence bundle for one blob project."""
    project = _build_project_from_bytes(code, base_addr=_BASE, entry_point=_BASE)
    caller = exact_function_range_boundary_8616(project, _BASE, 0x1006)
    callee = exact_function_range_boundary_8616(project, _CALLEE, 0x1008)
    assert caller is not None and callee is not None
    artifact = build_x86_16_ir_function_artifact(project, caller)
    restoration = build_x86_16_segment_stack_restore_artifact(artifact)
    # The Frontend boundary retains third-party angr block/Capstone wrappers.
    instructions = tuple(
        instruction
        for block in sorted(caller.blocks, key=lambda item: cast(Any, item).addr)
        for instruction in cast(Any, block).capstone.insns
    )
    index = build_decoded_direct_callsite_index_8616(
        {(caller.addr, caller.addr + caller.size): instructions},
        direct_target_resolver=lambda instruction: resolve_direct_call_target_from_instruction_8616(
            project, instruction,
        ),
        instruction_address_resolver=lambda instruction: cast(Any, instruction).address,
    )
    return _Evidence8616(
        project, caller, callee, artifact, restoration.restore_sources, index
    )


def _prove(
    evidence: _Evidence8616,
    *,
    artifact: IRFunctionArtifact,
    restore_sources: tuple[SegmentRestoreSource, ...],
) -> DirectCallSegmentEntryProof8616:
    """Evaluate the fixed candidate against one evidence bundle."""
    return prove_x86_16_direct_call_segment_entry_8616(
        DirectCallSegmentEntryCandidate8616(_BASE, _CALLSITE, _CALLEE),
        caller_boundary=evidence.caller,
        callee_boundary=evidence.callee,
        artifact=artifact,
        callsite_index=evidence.index,
        restore_sources=restore_sources,
    )


def _publish(evidence: _Evidence8616, artifact: IRFunctionArtifact) -> None:
    """Publish one exact raw artifact on the evidence's own project."""
    assert publish_function_ir_artifact_8616(evidence.project, artifact).artifact is artifact


def _assert_closed_refusal(
    proof: DirectCallSegmentEntryProof8616,
    refusal: DirectCallSegmentEntryRefusal8616,
) -> None:
    """Require one refused candidate with fully closed evidence counters."""
    assert proof.verdict is DirectCallSegmentEntryVerdict8616.UNKNOWN_REFUSE
    assert proof.refusal is refusal
    assert proof.stats.materialized_count == 0
    assert proof.stats.failure_count == 1
    assert proof.stats.closed


type _ProjectSnapshot8616 = tuple[dict[str, object], dict[int, IRFunctionArtifact] | None]


def _project_snapshot(project: object) -> _ProjectSnapshot8616:
    """Capture project extension identities and the raw registry's entries."""
    attributes = dict(vars(project))
    # angr's project extensions are a dynamic third-party boundary.
    registry = attributes.get("_inertia_function_ir_artifacts_8616")
    entries = dict(registry) if isinstance(registry, dict) else None
    return attributes, entries


def _assert_state_unchanged(project: object, before: _ProjectSnapshot8616) -> None:
    """Assert the proof wrote nothing into the project object's own state."""
    attributes, entries = before
    after = vars(project)
    assert set(after) == set(attributes)
    assert all(after[key] is attributes[key] for key in attributes)
    if entries is not None:
        registry = after["_inertia_function_ir_artifacts_8616"]
        assert isinstance(registry, dict) and set(registry) == set(entries)
        assert all(registry[address] is artifact for address, artifact in entries.items())


def test_same_project_registered_lineage_proves() -> None:
    """A candidate whose IR and Alias owner match the registry entry proves."""
    evidence = _evidence(_A_BYTES)
    _publish(evidence, evidence.artifact)
    before = _project_snapshot(evidence.project)

    proof = _prove(
        evidence,
        artifact=evidence.artifact,
        restore_sources=evidence.restore_sources,
    )

    assert proof.verdict is DirectCallSegmentEntryVerdict8616.PROVEN
    assert proof.refusal is None
    assert proof.stats.raw_fact_count == 1
    assert proof.stats.classified_fact_count == 1
    assert proof.stats.materialized_count == 1
    assert proof.stats.failure_count == 0
    assert proof.stats.closed
    _assert_state_unchanged(evidence.project, before)


def test_push_ds_pop_ds_control_keeps_alias_refusal() -> None:
    """A same-project PUSH DS / POP DS never carries an SS->DS copy to bind."""
    evidence = _evidence(_B_BYTES)
    _publish(evidence, evidence.artifact)
    before = _project_snapshot(evidence.project)

    proof = _prove(
        evidence,
        artifact=evidence.artifact,
        restore_sources=evidence.restore_sources,
    )

    _assert_closed_refusal(proof, DirectCallSegmentEntryRefusal8616.ALIAS_SOURCE_MISSING)
    _assert_state_unchanged(evidence.project, before)


def test_foreign_ir_with_foreign_alias_refuses_by_raw_identity() -> None:
    """Foreign IR cannot borrow the host project's registered artifact entry."""
    host = _evidence(_B_BYTES)
    foreign = _evidence(_A_BYTES)
    _publish(host, host.artifact)
    before = _project_snapshot(host.project)

    proof = _prove(
        host,
        artifact=foreign.artifact,
        restore_sources=foreign.restore_sources,
    )

    _assert_closed_refusal(proof, DirectCallSegmentEntryRefusal8616.IR_NOT_PROJECT_OWNED)
    _assert_state_unchanged(host.project, before)


def test_own_ir_with_foreign_alias_source_refuses() -> None:
    """Own registered IR cannot adopt Alias evidence built from foreign IR."""
    host = _evidence(_B_BYTES)
    foreign = _evidence(_A_BYTES)
    _publish(host, host.artifact)
    before = _project_snapshot(host.project)

    proof = _prove(
        host,
        artifact=host.artifact,
        restore_sources=foreign.restore_sources,
    )

    _assert_closed_refusal(proof, DirectCallSegmentEntryRefusal8616.ALIAS_SOURCE_FOREIGN)
    _assert_state_unchanged(host.project, before)


def test_unregistered_candidate_refuses_without_registry_state() -> None:
    """A valid but unpublished candidate refuses and creates no registry."""
    evidence = _evidence(_A_BYTES)
    before = _project_snapshot(evidence.project)

    proof = _prove(
        evidence,
        artifact=evidence.artifact,
        restore_sources=evidence.restore_sources,
    )

    _assert_closed_refusal(proof, DirectCallSegmentEntryRefusal8616.IR_NOT_REGISTERED)
    assert "_inertia_function_ir_artifacts_8616" not in vars(evidence.project)
    _assert_state_unchanged(evidence.project, before)


def test_unbound_restore_source_refuses() -> None:
    """A legacy SegmentRestoreSource without an owner cannot authorize proof."""
    evidence = _evidence(_A_BYTES)
    _publish(evidence, evidence.artifact)
    naked = SegmentRestoreSource(_BASE, 0x1001, "ds", _BASE, "ss")
    before = _project_snapshot(evidence.project)

    proof = _prove(
        evidence,
        artifact=evidence.artifact,
        restore_sources=(naked,),
    )

    _assert_closed_refusal(proof, DirectCallSegmentEntryRefusal8616.ALIAS_SOURCE_UNBOUND)
    _assert_state_unchanged(evidence.project, before)


def test_equal_content_distinct_artifact_refuses() -> None:
    """An equal rebuilt artifact is never the registered object itself."""
    evidence = _evidence(_A_BYTES)
    _publish(evidence, evidence.artifact)
    replica = replace(evidence.artifact)
    assert replica == evidence.artifact and replica is not evidence.artifact
    before = _project_snapshot(evidence.project)

    proof = _prove(
        evidence,
        artifact=replica,
        restore_sources=evidence.restore_sources,
    )

    _assert_closed_refusal(proof, DirectCallSegmentEntryRefusal8616.IR_NOT_PROJECT_OWNED)
    _assert_state_unchanged(evidence.project, before)


def test_source_bound_to_other_artifact_refuses() -> None:
    """A source owned by a different artifact object stays foreign."""
    evidence = _evidence(_A_BYTES)
    _publish(evidence, evidence.artifact)
    rebound = SegmentRestoreSource(
        _BASE, 0x1001, "ds", _BASE, "ss", source_artifact=replace(evidence.artifact)
    )
    before = _project_snapshot(evidence.project)

    proof = _prove(
        evidence,
        artifact=evidence.artifact,
        restore_sources=(rebound,),
    )

    _assert_closed_refusal(proof, DirectCallSegmentEntryRefusal8616.ALIAS_SOURCE_FOREIGN)
    _assert_state_unchanged(evidence.project, before)


def test_serialized_source_record_is_not_lineage() -> None:
    """Diagnostic serialization carries an address hint, never ownership."""
    evidence = _evidence(_A_BYTES)
    restoration = build_x86_16_segment_stack_restore_artifact(evidence.artifact)
    records = restoration.to_dict()["restore_sources"]
    assert isinstance(records, list) and len(records) == 1
    record = cast(dict[str, Any], records[0])
    assert record["source_function_addr"] == _BASE
    rebuilt = SegmentRestoreSource(
        block_addr=cast(int, record["block_addr"]),
        restore_instruction_addr=cast(int, record["restore_instruction_addr"]),
        restore_register=cast(str, record["restore_register"]),
        saved_instruction_addr=cast(int, record["saved_instruction_addr"]),
        saved_register=cast(str, record["saved_register"]),
    )
    _publish(evidence, evidence.artifact)
    before = _project_snapshot(evidence.project)

    proof = _prove(
        evidence,
        artifact=evidence.artifact,
        restore_sources=(rebuilt,),
    )

    _assert_closed_refusal(proof, DirectCallSegmentEntryRefusal8616.ALIAS_SOURCE_UNBOUND)
    _assert_state_unchanged(evidence.project, before)


@pytest.mark.parametrize("mutation", ("add-entry", "replace-object"))
def test_project_state_guard_rejects_inner_registry_changes(mutation: str) -> None:
    """The no-mutation oracle must detect edits inside the same registry dict."""
    artifact = IRFunctionArtifact(_BASE, ())
    registry = {_BASE: artifact}
    project = SimpleNamespace(_inertia_function_ir_artifacts_8616=registry)
    before = _project_snapshot(project)
    registry[_BASE + 1 if mutation == "add-entry" else _BASE] = replace(artifact)
    with pytest.raises(AssertionError):
        _assert_state_unchanged(project, before)


def test_corrupt_registered_entry_is_not_reported_missing() -> None:
    """Refused registered evidence is distinct from an absent registration."""
    evidence = _evidence(_A_BYTES)
    _publish(evidence, evidence.artifact)
    registry = cast(dict[int, IRFunctionArtifact], vars(evidence.project)[
        "_inertia_function_ir_artifacts_8616"
    ])
    registry[_BASE] = IRFunctionArtifact(_CALLEE, ())
    before = _project_snapshot(evidence.project)
    proof = _prove(evidence, artifact=evidence.artifact, restore_sources=evidence.restore_sources)
    assert proof.refusal is not DirectCallSegmentEntryRefusal8616.IR_NOT_REGISTERED
    _assert_closed_refusal(proof, DirectCallSegmentEntryRefusal8616.IR_REGISTRY_REFUSED)
    _assert_state_unchanged(evidence.project, before)
