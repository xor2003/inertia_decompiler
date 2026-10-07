"""Byte-backed positive and refusal tests for the near scaled-return candidate."""

from __future__ import annotations

import io
from dataclasses import dataclass, replace
from unittest.mock import patch

import angr
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir import (
    AddressStatus,
    IRAddress,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.function_ssa_registry import (
    FunctionSSAArtifactFailure8616,
    FunctionSSAArtifactResolution8616,
    FunctionSSAArtifactVerdict8616,
)
from inertia.ir.stack_argument_scaled_return import (
    ScaledReturnFailure8616,
)
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401
from inertia.lowering.near_scaled_return_candidate import (
    NearScaledReturnCandidateFailure8616,
    NearScaledReturnCandidateStats8616,
    NearScaledReturnCandidateVerdict8616,
    collect_near_scaled_return_candidate_8616,
)

from inertia.frontend.x86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
    exact_function_range_boundary_8616,
)
from inertia.semantics.call_stack_effect_pipeline import (
    semantic_function_ssa_artifact_at_address_8616,
)

_CODE = bytes.fromhex(
    "55 8b ec b8 00 00 e8 c2 04 57 56 8b 46 06 d1 e0 "
    "03 46 04 e9 00 00 5e 5f 8b e5 5d c3"
)
_FUNC_ADDR = 0x10F1
_FUNC_END = 0x110D
_BASE = IRAddress(
    space=MemSpace.SS, base=("bp",), offset=4, size=2,
    status=AddressStatus.STABLE, segment_origin=SegmentOrigin.PROVEN,
)
_INDEX = replace(_BASE, offset=6)


@dataclass(frozen=True, slots=True)
class _StubBlock8616:
    """Minimal third-party block surface for boundary capture tests."""

    addr: int
    size: int


@dataclass(frozen=True, slots=True)
class _StubFunction8616:
    """Minimal third-party function surface for boundary capture tests."""

    addr: int
    blocks: tuple[_StubBlock8616, ...]


def _project() -> angr.Project:
    image = bytearray(0x5BE)
    image[0xF1 : 0xF1 + len(_CODE)] = _CODE
    image[0x5BC] = 0xC3
    image[0x5BD] = 0xC3
    return angr.Project(
        io.BytesIO(image),
        main_opts={
            "backend": "blob", "arch": Arch86_16(),
            "base_addr": 0x1000, "entry_point": _FUNC_ADDR,
        },
        auto_load_libs=False,
        simos="DOS",
    )


def _boundary(project: angr.Project) -> ExactFunctionRangeBoundary8616:
    boundary = exact_function_range_boundary_8616(project, _FUNC_ADDR, _FUNC_END)
    assert boundary is not None
    return boundary


def _registered_project() -> tuple[angr.Project, ExactFunctionRangeBoundary8616]:
    """Build the rebased fixture and register its Semantics SSA artifact."""
    project = _project()
    boundary = _boundary(project)
    resolution = semantic_function_ssa_artifact_at_address_8616(
        project, _FUNC_ADDR, function=boundary,
    )
    assert resolution.verdict is FunctionSSAArtifactVerdict8616.PROVEN
    assert resolution.artifact is not None
    return project, boundary


def test_registered_semantic_ssa_proves_candidate_without_mutation() -> None:
    """With registered evidence the candidate adds nothing to the project."""
    project, boundary = _registered_project()
    project_before = dict(vars(project))
    info_before = dict(boundary.info)

    result = collect_near_scaled_return_candidate_8616(
        project, _FUNC_ADDR, _BASE, _INDEX, function=boundary,
    )

    assert result.verdict is NearScaledReturnCandidateVerdict8616.PROVEN
    assert result.failure is None
    assert result.complete
    assert result.proof is not None and result.proof.complete
    assert result.proof.return_instruction_addr == 0x110C
    assert result.proof.base_access_key is not None
    assert result.proof.index_access_key is not None
    assert result.proof.base_access_key.insn_addr == 0x1101
    assert result.proof.index_access_key.insn_addr == 0x10FC
    expression = result.offset_expression
    assert expression is not None
    assert expression is result.proof.offset_expression
    assert expression.width == 2 and expression.constant == 0
    assert sorted(term.coefficient for term in expression.terms) == [1, 2]
    refused = replace(
        result,
        verdict=NearScaledReturnCandidateVerdict8616.UNKNOWN_REFUSE,
        failure=NearScaledReturnCandidateFailure8616.INPUT_STORAGE_UNPROVEN,
    )
    assert refused.offset_expression is None
    unbound = replace(result, base_storage=_INDEX, index_storage=_BASE)
    assert not unbound.complete
    assert unbound.offset_expression is None
    assert result.stats == NearScaledReturnCandidateStats8616(1, 1, 1, 1, 0)
    assert result.base_storage == _BASE and result.index_storage == _INDEX
    project_after = vars(project)
    assert project_before.keys() == project_after.keys()
    assert all(project_before[key] is project_after[key] for key in project_before)
    assert boundary.info == info_before


def test_absent_semantic_ssa_refuses_without_registering_it() -> None:
    """A read-only candidate cannot build or register missing Semantics SSA."""
    project = _project()
    boundary = _boundary(project)
    before = dict(vars(project))

    result = collect_near_scaled_return_candidate_8616(
        project, _FUNC_ADDR, _BASE, _INDEX, function=boundary,
    )

    assert result.verdict is NearScaledReturnCandidateVerdict8616.UNKNOWN_REFUSE
    assert result.failure is NearScaledReturnCandidateFailure8616.CALLEE_SSA_UNPROVEN
    assert result.proof is None
    assert result.offset_expression is None
    assert not result.complete
    assert vars(project).keys() == before.keys()
    assert all(vars(project)[key] is value for key, value in before.items())


def test_range_inventory_boundary_proves_candidate() -> None:
    """A registered caller range resolves the exact boundary without a CFG."""
    project, _ = _registered_project()
    project._inertia_caller_function_ranges_8616 = ((_FUNC_ADDR, _FUNC_END),)

    result = collect_near_scaled_return_candidate_8616(
        project, _FUNC_ADDR, _BASE, _INDEX,
    )

    assert result.verdict is NearScaledReturnCandidateVerdict8616.PROVEN
    assert result.complete


def test_function_blocks_restore_exact_boundary() -> None:
    """A third-party function's block extents rebuild the exact boundary."""
    project, _ = _registered_project()
    stub = _StubFunction8616(
        _FUNC_ADDR, (_StubBlock8616(_FUNC_ADDR, _FUNC_END - _FUNC_ADDR),),
    )

    result = collect_near_scaled_return_candidate_8616(
        project, _FUNC_ADDR, _BASE, _INDEX, function=stub,
    )

    assert result.verdict is NearScaledReturnCandidateVerdict8616.PROVEN
    assert result.complete


def test_wrong_bp_slot_refuses_through_upstream_proof() -> None:
    """A BP word the binary never reads cannot become a scaled index."""
    project, boundary = _registered_project()

    result = collect_near_scaled_return_candidate_8616(
        project, _FUNC_ADDR, _BASE, replace(_BASE, offset=8),
        function=boundary,
    )

    assert result.verdict is NearScaledReturnCandidateVerdict8616.UNKNOWN_REFUSE
    assert result.failure is NearScaledReturnCandidateFailure8616.UPSTREAM_PROOF_REFUSED
    assert result.upstream_failure is ScaledReturnFailure8616.INDEX_USE_UNPROVEN
    assert result.proof is not None and not result.proof.complete
    assert result.offset_expression is None
    assert result.stats == NearScaledReturnCandidateStats8616(1, 1, 0, 0, 1)
    assert not result.complete


def test_identical_input_slots_refuse() -> None:
    """Two identical proven slots cannot form base-plus-scaled-index."""
    project, boundary = _registered_project()

    result = collect_near_scaled_return_candidate_8616(
        project, _FUNC_ADDR, _BASE, _BASE, function=boundary,
    )

    assert result.verdict is NearScaledReturnCandidateVerdict8616.UNKNOWN_REFUSE
    assert result.failure is NearScaledReturnCandidateFailure8616.UPSTREAM_PROOF_REFUSED
    assert result.upstream_failure is ScaledReturnFailure8616.INPUT_IDENTITY_CONFLICT
    assert result.stats.failure_count == 1
    assert not result.complete


def test_unproven_input_storage_refuses() -> None:
    """An unproven or non-SS:BP storage never reaches the IR proof."""
    project, boundary = _registered_project()
    unstable = replace(_BASE, offset=6, status=AddressStatus.UNKNOWN)
    foreign = replace(_BASE, offset=6, space=MemSpace.DS, base=("bx",))

    for bad in (unstable, foreign):
        result = collect_near_scaled_return_candidate_8616(
            project, _FUNC_ADDR, _BASE, bad, function=boundary,
        )
        assert result.verdict is NearScaledReturnCandidateVerdict8616.UNKNOWN_REFUSE
        assert result.failure is NearScaledReturnCandidateFailure8616.INPUT_STORAGE_UNPROVEN
        assert result.stats == NearScaledReturnCandidateStats8616(1, 0, 0, 0, 1)
        assert result.proof is None


def test_absent_boundary_refuses_without_inventing_range() -> None:
    """No CFG function and no registered range yields a typed refusal."""
    project = _project()

    result = collect_near_scaled_return_candidate_8616(
        project, _FUNC_ADDR, _BASE, _INDEX,
    )

    assert result.verdict is NearScaledReturnCandidateVerdict8616.UNKNOWN_REFUSE
    assert result.failure is NearScaledReturnCandidateFailure8616.CALLEE_BOUNDARY_UNPROVEN
    assert result.stats == NearScaledReturnCandidateStats8616(1, 1, 0, 0, 1)
    assert result.proof is None


def test_function_addr_mismatch_refuses() -> None:
    """A supplied boundary for a different entry cannot stand in."""
    project, boundary = _registered_project()

    result = collect_near_scaled_return_candidate_8616(
        project, 0x2000, _BASE, _INDEX, function=boundary,
    )

    assert result.verdict is NearScaledReturnCandidateVerdict8616.UNKNOWN_REFUSE
    assert result.failure is NearScaledReturnCandidateFailure8616.FUNCTION_MISMATCH


def test_foreign_project_boundary_refuses() -> None:
    """Matching addresses from another image cannot supply this project's CFG."""
    project, _ = _registered_project()
    foreign_boundary = _boundary(_project())

    result = collect_near_scaled_return_candidate_8616(
        project, _FUNC_ADDR, _BASE, _INDEX, function=foreign_boundary,
    )

    assert result.verdict is NearScaledReturnCandidateVerdict8616.UNKNOWN_REFUSE
    assert result.failure is NearScaledReturnCandidateFailure8616.BOUNDARY_PROJECT_MISMATCH
    assert result.proof is None


def test_invalid_callee_addr_refuses() -> None:
    """A non-address callee identity never reaches boundary discovery."""
    project, boundary = _registered_project()

    for bad in (-1, "0x10f1"):
        result = collect_near_scaled_return_candidate_8616(
            project, bad, _BASE, _INDEX, function=boundary,
        )
        assert result.verdict is NearScaledReturnCandidateVerdict8616.UNKNOWN_REFUSE
        assert result.failure is NearScaledReturnCandidateFailure8616.CALLEE_ADDR_INVALID
        assert result.stats == NearScaledReturnCandidateStats8616(1, 0, 0, 0, 1)


def test_missing_semantic_ssa_refuses() -> None:
    """An unavailable Semantics artifact surfaces as a typed refusal."""
    project, boundary = _registered_project()
    refused = FunctionSSAArtifactResolution8616(
        _FUNC_ADDR,
        FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE,
        None,
        FunctionSSAArtifactFailure8616.SEMANTIC_BUILD_FAILED,
        None,
    )

    with patch(
        "inertia.lowering.near_scaled_return_candidate."
        "registered_function_ssa_artifact_8616",
        return_value=refused,
    ):
        result = collect_near_scaled_return_candidate_8616(
            project, _FUNC_ADDR, _BASE, _INDEX, function=boundary,
        )

    assert result.verdict is NearScaledReturnCandidateVerdict8616.UNKNOWN_REFUSE
    assert result.failure is NearScaledReturnCandidateFailure8616.CALLEE_SSA_UNPROVEN
    assert result.upstream_failure is FunctionSSAArtifactFailure8616.SEMANTIC_BUILD_FAILED
    assert result.stats == NearScaledReturnCandidateStats8616(1, 1, 0, 0, 1)
    assert result.proof is None
