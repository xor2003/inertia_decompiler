from __future__ import annotations

from types import SimpleNamespace

from inertia.semantics.callsite_summary import (
    CallerReturnUseEvidence8616,
    CallerReturnUseVerdict8616,
    caller_return_use_evidence_by_addr_8616,
    record_caller_return_use_evidence_8616,
)

from inertia.widening.global_object_layout import (
    GlobalObjectLayoutEvidence8616,
)
from inertia.widening.indexed_global_object_program_ranges import (
    ProjectBoundedGlobalObjectRangeEvidence8616,
    ProjectBoundedGlobalObjectRangeSource8616,
    ProjectBoundedGlobalObjectRangeSourceKind8616,
    ProjectBoundedGlobalObjectRangeSourceStatus8616,
)
from inertia.widening.indexed_global_object_ranges import (
    BoundedGlobalObjectRangeStats8616,
)
from inertia.cli.project_evidence_transport import (
    transfer_caller_return_use_evidence_8616,
    transfer_project_evidence_8616,
)


def _unused_evidence() -> CallerReturnUseEvidence8616:
    return CallerReturnUseEvidence8616(
        target_addr=0x104DC,
        verdict=CallerReturnUseVerdict8616.UNUSED,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        used_callsite_count=0,
        unused_callsite_count=1,
        callsite_addrs=(0x106BC,),
    )


def test_transfers_typed_caller_return_evidence_to_retry_project() -> None:
    source = SimpleNamespace()
    destination = SimpleNamespace()
    evidence = _unused_evidence()
    record_caller_return_use_evidence_8616(source, evidence.target_addr, evidence)

    copied = transfer_caller_return_use_evidence_8616(source, destination)

    assert copied == 1
    assert caller_return_use_evidence_by_addr_8616(destination) == {evidence.target_addr: evidence}
    assert caller_return_use_evidence_by_addr_8616(source) == {evidence.target_addr: evidence}


def test_same_project_transport_is_idempotent() -> None:
    project = SimpleNamespace()
    evidence = _unused_evidence()
    record_caller_return_use_evidence_8616(project, evidence.target_addr, evidence)

    assert transfer_caller_return_use_evidence_8616(project, project) == 1
    assert caller_return_use_evidence_by_addr_8616(project) == {evidence.target_addr: evidence}


def test_project_transport_preserves_binary_proven_compiler_helper_targets() -> None:
    source = SimpleNamespace(
        arch=SimpleNamespace(_inertia_stack_probe_helper_targets_8616=frozenset({0x11222, 0x1222}))
    )
    destination = SimpleNamespace(
        arch=SimpleNamespace(_inertia_stack_probe_helper_targets_8616=frozenset({0x1999}))
    )

    result = transfer_project_evidence_8616(source, destination)

    assert result.caller_return_use_count == 0
    assert result.compiler_helper_target_count == 2
    assert result.global_object_layout_artifact_count == 0
    assert destination.arch._inertia_stack_probe_helper_targets_8616 == frozenset({0x11222, 0x1222, 0x1999})


def test_project_transport_reuses_closed_global_object_widening() -> None:
    evidence = GlobalObjectLayoutEvidence8616((), 0, 0, 0, 0)
    ranges = ProjectBoundedGlobalObjectRangeEvidence8616(
        (),
        (),
        BoundedGlobalObjectRangeStats8616(),
        ProjectBoundedGlobalObjectRangeSource8616(
            ProjectBoundedGlobalObjectRangeSourceKind8616.LIVE_ALIAS_PROGRAM,
            ProjectBoundedGlobalObjectRangeSourceStatus8616.COMPLETE,
            0,
            0,
            0,
            0,
        ),
        evidence,
    )
    source = SimpleNamespace(
        arch=SimpleNamespace(_inertia_stack_probe_helper_targets_8616=frozenset()),
        _inertia_project_global_object_layout_evidence_8616=evidence,
        _inertia_project_bounded_global_object_ranges_8616=ranges,
    )
    destination = SimpleNamespace(
        arch=SimpleNamespace(_inertia_stack_probe_helper_targets_8616=frozenset())
    )

    result = transfer_project_evidence_8616(source, destination)

    assert result.global_object_layout_artifact_count == 1
    assert result.bounded_global_range_artifact_count == 1
    assert destination._inertia_project_global_object_layout_evidence_8616 is evidence
    assert destination._inertia_project_bounded_global_object_ranges_8616 is ranges
