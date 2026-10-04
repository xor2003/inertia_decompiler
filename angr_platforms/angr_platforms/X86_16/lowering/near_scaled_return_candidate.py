"""Expose one binary scaled-return IR proof as a near-return candidate.

Layer: Types/Lowering.
Responsibility: resolve the exact callee boundary and Semantics SSA artifact,
run ``prove_stack_argument_scaled_return_8616``, and retain its typed result
as a nonpublishing near-return candidate with closed five-stage accounting.
The candidate carries only 16-bit modular offset-arithmetic evidence
(``AX = base + 2 * index``) plus exact input access identities. It does not
decide pointer type, pointee family, segment binding, source signedness, or
representable C, and it never mutates the project contract, codegen, callsite
state, C AST, or the accepted storage contract.
Consumes frontend, IR, and Semantics facts through owned typed interfaces only.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from ..frontend_boundary_transport import (
    capture_function_boundary_8616,
    restore_function_boundary_8616,
)
from ..frontend_function_boundary import ExactFunctionRangeBoundary8616
from ..ir import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from ..ir.function_ssa_registry import (
    FunctionSSAArtifactFailure8616,
    FunctionSSAArtifactStage8616,
    FunctionSSAArtifactVerdict8616,
    function_boundary_at_address_8616,
    registered_function_ssa_artifact_8616,
)
from ..ir.scalar_affine_contracts import ScalarAffineExpression8616
from ..ir.stack_argument_scaled_return import (
    ScaledReturnFailure8616,
    ScaledReturnResult8616,
    prove_stack_argument_scaled_return_8616,
)

__all__ = [
    "NearScaledReturnCandidateFailure8616",
    "NearScaledReturnCandidateResult8616",
    "NearScaledReturnCandidateStats8616",
    "NearScaledReturnCandidateVerdict8616",
    "collect_near_scaled_return_candidate_8616",
]


class _FunctionBoundary8616(Protocol):
    """Third-party recovered-function surface used for exact entry matching."""

    addr: object


class _ProjectSSARegistry8616(Protocol):
    """Third-party project carrying already-published Semantics SSA state."""

    _inertia_function_ssa_artifacts_8616: object
    _inertia_function_ssa_stages_8616: object


class NearScaledReturnCandidateVerdict8616(StrEnum):
    """Whether one exact near scaled-return candidate was proven."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


class NearScaledReturnCandidateFailure8616(StrEnum):
    """Stable reasons the near scaled-return candidate cannot publish."""

    CALLEE_ADDR_INVALID = "callee_addr_invalid"
    FUNCTION_MISMATCH = "function_mismatch"
    BOUNDARY_PROJECT_MISMATCH = "boundary_project_mismatch"
    INPUT_STORAGE_UNPROVEN = "input_storage_unproven"
    CALLEE_BOUNDARY_UNPROVEN = "callee_boundary_unproven"
    CALLEE_SSA_UNPROVEN = "callee_ssa_unproven"
    UPSTREAM_PROOF_REFUSED = "upstream_proof_refused"


@dataclass(frozen=True, slots=True)
class NearScaledReturnCandidateStats8616:
    """Closed five-stage evidence loop for one requested candidate."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class NearScaledReturnCandidateResult8616:
    """One proven near scaled-return candidate or a typed atomic refusal.

    ``proof`` retains the upstream IR result whenever the proof ran, so a
    refusal keeps the exact binary-derived failure instead of hiding it.
    This contract never authorizes a C return expression or pointer type.
    """

    callee_addr: int
    verdict: NearScaledReturnCandidateVerdict8616
    failure: NearScaledReturnCandidateFailure8616 | None
    stats: NearScaledReturnCandidateStats8616
    base_storage: IRAddress | None = None
    index_storage: IRAddress | None = None
    proof: ScaledReturnResult8616 | None = None
    upstream_failure: (
        ScaledReturnFailure8616 | FunctionSSAArtifactFailure8616 | None
    ) = None

    @property
    def complete(self) -> bool:
        """Require a complete retained IR proof and closed accounting."""
        return bool(
            self.verdict is NearScaledReturnCandidateVerdict8616.PROVEN
            and self.failure is None
            and type(self.callee_addr) is int
            and self.callee_addr >= 0
            and self.base_storage is not None
            and self.index_storage is not None
            and self.proof is not None
            and self.proof.complete
            and self.proof.matches_storage_inputs(self.base_storage, self.index_storage)
            and self.upstream_failure is None
            and self.stats == NearScaledReturnCandidateStats8616(1, 1, 1, 1, 0)
        )

    @property
    def offset_expression(self) -> ScalarAffineExpression8616 | None:
        """Read-only view of the proven modular affine offset value.

        The expression is owned by the upstream IR ``proof``; this candidate
        only projects it while that proof remains complete and never keeps a
        second field-level copy. Any refusal yields ``None``.
        """
        if not self.complete or self.proof is None:
            return None
        return self.proof.offset_expression


def _refuse_8616(
    callee_addr: int,
    failure: NearScaledReturnCandidateFailure8616,
    *,
    normalized: bool = False,
    base_storage: IRAddress | None = None,
    index_storage: IRAddress | None = None,
    proof: ScaledReturnResult8616 | None = None,
    upstream: ScaledReturnFailure8616 | FunctionSSAArtifactFailure8616 | None = None,
) -> NearScaledReturnCandidateResult8616:
    """Keep one failed candidate request as an atomic typed refusal."""
    return NearScaledReturnCandidateResult8616(
        callee_addr,
        NearScaledReturnCandidateVerdict8616.UNKNOWN_REFUSE,
        failure,
        NearScaledReturnCandidateStats8616(
            1, int(normalized), 0, 0, 1,
        ),
        base_storage,
        index_storage,
        proof,
        upstream,
    )


def _proven_bp_word_storage_8616(storage: object) -> bool:
    """Require one proven stable two-byte SS:BP storage identity."""
    return bool(
        isinstance(storage, IRAddress)
        and storage.space is MemSpace.SS
        and storage.base == ("bp",)
        and storage.size == 2
        and storage.status is AddressStatus.STABLE
        and storage.segment_origin is SegmentOrigin.PROVEN
    )


def _semantic_registry_exists_8616(project: object) -> bool:
    """Check cache presence without letting the registry lookup create it."""
    surface = cast(_ProjectSSARegistry8616, project)
    try:
        artifacts = surface._inertia_function_ssa_artifacts_8616
        stages = surface._inertia_function_ssa_stages_8616
    except AttributeError:
        return False
    if not isinstance(artifacts, dict) or not isinstance(stages, dict):
        raise TypeError("function SSA registries must be dicts")
    return True


def _restored_exact_boundary_8616(
    project: object,
    function: object,
) -> ExactFunctionRangeBoundary8616 | None:
    """Rebuild a byte-verified exact boundary from recovered block extents."""
    try:
        witness = capture_function_boundary_8616(project, function)
        boundary = (
            restore_function_boundary_8616(project, witness)
            if witness is not None
            else None
        )
    except ValueError:
        return None
    return boundary


def _exact_callee_boundary_8616(
    project: object,
    callee_addr: int,
    function: object | None,
) -> tuple[
    ExactFunctionRangeBoundary8616 | None,
    NearScaledReturnCandidateFailure8616 | None,
]:
    """Resolve the closed binary callee boundary or a typed refusal reason.

    An absent boundary stays absent: without a CFG function, a registered
    exact range, or byte-verified recovered extents, no range is invented.
    """
    resolved = function
    if resolved is None:
        resolved = function_boundary_at_address_8616(project, callee_addr)
    if resolved is None:
        return None, NearScaledReturnCandidateFailure8616.CALLEE_BOUNDARY_UNPROVEN
    if isinstance(resolved, ExactFunctionRangeBoundary8616):
        if resolved.addr != callee_addr:
            return None, NearScaledReturnCandidateFailure8616.FUNCTION_MISMATCH
        if resolved.project is not project:
            return None, NearScaledReturnCandidateFailure8616.BOUNDARY_PROJECT_MISMATCH
        return resolved, None
    try:
        resolved_addr = cast(_FunctionBoundary8616, resolved).addr
    except AttributeError:
        return None, NearScaledReturnCandidateFailure8616.CALLEE_BOUNDARY_UNPROVEN
    if resolved_addr != callee_addr:
        return None, NearScaledReturnCandidateFailure8616.FUNCTION_MISMATCH
    boundary = _restored_exact_boundary_8616(project, resolved)
    if boundary is None or boundary.addr != callee_addr:
        return None, NearScaledReturnCandidateFailure8616.CALLEE_BOUNDARY_UNPROVEN
    return boundary, None


def collect_near_scaled_return_candidate_8616(
    project: object,
    callee_addr: int,
    base_storage: IRAddress,
    index_storage: IRAddress,
    *,
    function: object | None = None,
) -> NearScaledReturnCandidateResult8616:
    """Prove ``AX = base + 2 * index`` for one exact callee, or refuse.

    ``function`` may supply an exact boundary or a recovered third-party
    function for ``callee_addr``; block extents are byte-verified before use.
    The result is a candidate only: it retains IR evidence and never installs
    a type, prototype, storage acceptance, or emitted C change.
    """
    if type(callee_addr) is not int or callee_addr < 0:
        return _refuse_8616(
            -1, NearScaledReturnCandidateFailure8616.CALLEE_ADDR_INVALID,
        )
    if not (
        _proven_bp_word_storage_8616(base_storage)
        and _proven_bp_word_storage_8616(index_storage)
    ):
        return _refuse_8616(
            callee_addr,
            NearScaledReturnCandidateFailure8616.INPUT_STORAGE_UNPROVEN,
        )
    boundary, boundary_failure = _exact_callee_boundary_8616(
        project, callee_addr, function,
    )
    if boundary is None:
        assert boundary_failure is not None, (
            "missing callee boundary lacks a typed refusal"
        )
        return _refuse_8616(
            callee_addr, boundary_failure, normalized=True,
            base_storage=base_storage, index_storage=index_storage,
        )
    if not _semantic_registry_exists_8616(project):
        return _refuse_8616(
            callee_addr,
            NearScaledReturnCandidateFailure8616.CALLEE_SSA_UNPROVEN,
            normalized=True,
            base_storage=base_storage,
            index_storage=index_storage,
            upstream=FunctionSSAArtifactFailure8616.ARTIFACT_NOT_REGISTERED,
        )
    resolution = registered_function_ssa_artifact_8616(project, callee_addr)
    artifact = resolution.artifact
    if (
        resolution.verdict is not FunctionSSAArtifactVerdict8616.PROVEN
        or resolution.stage is not FunctionSSAArtifactStage8616.SEMANTIC
        or artifact is None
        or artifact.function_addr != callee_addr
    ):
        return _refuse_8616(
            callee_addr,
            NearScaledReturnCandidateFailure8616.CALLEE_SSA_UNPROVEN,
            normalized=True,
            base_storage=base_storage,
            index_storage=index_storage,
            upstream=resolution.failure,
        )
    proof = prove_stack_argument_scaled_return_8616(
        boundary, artifact, base_storage, index_storage,
    )
    if not proof.complete:
        return _refuse_8616(
            callee_addr,
            NearScaledReturnCandidateFailure8616.UPSTREAM_PROOF_REFUSED,
            normalized=True,
            base_storage=base_storage,
            index_storage=index_storage,
            proof=proof,
            upstream=proof.failure,
        )
    result = NearScaledReturnCandidateResult8616(
        callee_addr,
        NearScaledReturnCandidateVerdict8616.PROVEN,
        None,
        NearScaledReturnCandidateStats8616(1, 1, 1, 1, 0),
        base_storage,
        index_storage,
        proof,
    )
    if not result.complete:
        raise RuntimeError("near scaled-return candidate lost owned evidence")
    return result
