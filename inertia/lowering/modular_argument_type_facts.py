"""Join callee-bound modular stack-word use proofs into input type evidence.

Layer: Types/Lowering.
Responsibility: lazily resolve one exact callee's byte-verified boundary and
registered Semantics SSA artifact, bind each refused census ``SS:BP`` stack
word to the artifact's own proven logical-memory access identity, and retain
the typed ``prove_stack_argument_modular_return_use_8616`` result. The input
classifier consumes one complete proof as ``SIGN_INSENSITIVE`` scalar ``VALUE``
evidence only when no branch-condition interpretation exists. Proofs are
cached per storage identity so repeated caller sites never re-run analysis.
This module does not infer original C signedness, pointer or pointee type,
segment identity, or a return expression, and it never mutates the project,
codegen, or emitted C. Consumes frontend, IR, and Semantics artifacts through
owned typed interfaces only.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, cast

from inertia.frontend.x86_16.frontend_boundary_transport import (
    capture_function_boundary_8616,
    restore_function_boundary_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
from inertia.ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from inertia.ir.function_ssa_registry import (
    FunctionSSAArtifactFailure8616,
    FunctionSSAArtifactStage8616,
    FunctionSSAArtifactVerdict8616,
    function_boundary_at_address_8616,
    registered_function_ssa_artifact_8616,
)
from inertia.ir.logical_memory_contracts import (
    IRLogicalMemoryAccess8616,
    IRLogicalMemoryAccessKey8616,
    IRMemoryAccessKind8616,
)
from inertia.ir.ssa_function import SSAFunctionArtifact
from inertia.ir.stack_argument_modular_use import (
    prove_stack_argument_modular_return_use_8616,
)
from inertia.ir.stack_argument_modular_use_contracts import (
    ModularArgumentUseFailure8616,
    ModularArgumentUseResult8616,
    ModularArgumentUseStats8616,
    ModularArgumentUseVerdict8616,
)

__all__ = [
    "ModularArgumentTypeFacts8616",
    "ModularInputProof8616",
    "ModularInputProofFailure8616",
    "ModularInputProofStats8616",
    "ModularInputProofVerdict8616",
]


class _FunctionBoundary8616(Protocol):
    """Third-party recovered-function surface used for exact entry matching."""

    addr: object


class _ProjectSSARegistry8616(Protocol):
    """Third-party project carrying already-published Semantics SSA state."""

    _inertia_function_ssa_artifacts_8616: object
    _inertia_function_ssa_stages_8616: object


class ModularInputProofVerdict8616(StrEnum):
    """Whether one exact callee stack word proved sign-insensitive use."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


class ModularInputProofFailure8616(StrEnum):
    """Stable reasons one modular input-use proof cannot classify."""

    INPUT_STORAGE_UNPROVEN = "input_storage_unproven"
    CALLEE_BOUNDARY_UNPROVEN = "callee_boundary_unproven"
    FUNCTION_MISMATCH = "function_mismatch"
    BOUNDARY_PROJECT_MISMATCH = "boundary_project_mismatch"
    CALLEE_SSA_UNPROVEN = "callee_ssa_unproven"
    ACCESS_IDENTITY_UNKNOWN = "access_identity_unknown"
    UPSTREAM_PROOF_REFUSED = "upstream_proof_refused"


@dataclass(frozen=True, slots=True)
class ModularInputProofStats8616:
    """Closed five-stage evidence loop for one requested input proof."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class _CalleeEvidence8616:
    """Boundary and Semantics SSA resolution shared by every storage proof."""

    boundary: ExactFunctionRangeBoundary8616 | None
    artifact: SSAFunctionArtifact | None
    failure: ModularInputProofFailure8616 | None
    upstream_failure: FunctionSSAArtifactFailure8616 | None = None


@dataclass(frozen=True, slots=True)
class ModularInputProof8616:
    """One callee-bound modular input-use proof or a typed atomic refusal.

    ``storage`` is the census-supplied callee stack identity being typed and
    ``proven_storage`` is the artifact-derived proven ``SS:BP`` access address
    the upstream proof ran on. ``boundary`` and ``artifact`` retain the exact
    source artifacts the proof consumed; ``proof`` retains the upstream IR
    result so a refusal keeps the binary-derived failure. This contract never
    authorizes source signedness, pointer typing, or a return expression.
    """

    callee_addr: int
    storage: IRAddress
    verdict: ModularInputProofVerdict8616
    failure: ModularInputProofFailure8616 | None
    stats: ModularInputProofStats8616
    proven_storage: IRAddress | None = None
    boundary: ExactFunctionRangeBoundary8616 | None = field(
        default=None,
        compare=False,
        repr=False,
    )
    artifact: SSAFunctionArtifact | None = field(
        default=None,
        compare=False,
        repr=False,
    )
    access_key: IRLogicalMemoryAccessKey8616 | None = None
    proof: ModularArgumentUseResult8616 | None = field(default=None, compare=False)
    upstream_failure: (
        ModularArgumentUseFailure8616 | FunctionSSAArtifactFailure8616 | None
    ) = None

    @property
    def complete(self) -> bool:
        """Require a fully bound proven proof, never a bare verdict flag."""
        proof = self.proof
        boundary = self.boundary
        artifact = self.artifact
        proven_storage = self.proven_storage
        if not (
            self.verdict is ModularInputProofVerdict8616.PROVEN
            and self.failure is None
            and self.upstream_failure is None
            and self.stats == ModularInputProofStats8616(1, 1, 1, 1, 0)
            and type(self.callee_addr) is int
            and proven_storage is not None
            and boundary is not None
            and artifact is not None
            and proof is not None
            and self.access_key is not None
        ):
            return False
        key = proof.input_access_key
        return bool(
            boundary.addr == self.callee_addr
            and artifact.function_addr == self.callee_addr
            and _same_storage_identity_8616(proven_storage, self.storage)
            and proven_storage.segment_origin is SegmentOrigin.PROVEN
            and proven_storage.status is AddressStatus.STABLE
            and proof.verdict is ModularArgumentUseVerdict8616.PROVEN
            and proof.failure is None
            and proof.stats == ModularArgumentUseStats8616(1, 1, 1, 1, 0)
            and key is not None
            and key == self.access_key
            and key.function_addr == self.callee_addr
            and isinstance(proof.return_instruction_addr, int)
        )


def _same_storage_identity_8616(left: IRAddress, right: IRAddress) -> bool:
    """Compare the storage-identity fields that name one stack slice."""
    return (
        left.space is right.space
        and left.base == right.base
        and left.offset == right.offset
        and left.size == right.size
    )


def _storage_key_8616(storage: IRAddress) -> tuple[object, ...]:
    """Dedupe proof requests by storage identity, not object identity."""
    return (storage.space, storage.base, storage.offset, storage.size)


def _supported_census_storage_8616(storage: object) -> bool:
    """Require a stable two-byte SS:BP census stack identity to query."""
    return bool(
        isinstance(storage, IRAddress)
        and storage.space is MemSpace.SS
        and storage.base == ("bp",)
        and storage.size == 2
        and storage.status is AddressStatus.STABLE
    )


def _refuse_8616(
    callee_addr: int,
    storage: IRAddress,
    failure: ModularInputProofFailure8616,
    *,
    normalized: bool = False,
    boundary: ExactFunctionRangeBoundary8616 | None = None,
    artifact: SSAFunctionArtifact | None = None,
    proven_storage: IRAddress | None = None,
    access_key: IRLogicalMemoryAccessKey8616 | None = None,
    proof: ModularArgumentUseResult8616 | None = None,
    upstream: (
        ModularArgumentUseFailure8616 | FunctionSSAArtifactFailure8616 | None
    ) = None,
) -> ModularInputProof8616:
    """Keep one failed proof request as an atomic typed refusal."""
    return ModularInputProof8616(
        callee_addr,
        storage,
        ModularInputProofVerdict8616.UNKNOWN_REFUSE,
        failure,
        ModularInputProofStats8616(1, int(normalized), 0, 0, 1),
        proven_storage,
        boundary,
        artifact,
        access_key,
        proof,
        upstream,
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
) -> tuple[
    ExactFunctionRangeBoundary8616 | None,
    ModularInputProofFailure8616 | None,
]:
    """Resolve the closed binary callee boundary or a typed refusal reason.

    An absent boundary stays absent: without a CFG function or a registered
    exact range, no range is invented.
    """
    resolved = function_boundary_at_address_8616(project, callee_addr)
    if resolved is None:
        return None, ModularInputProofFailure8616.CALLEE_BOUNDARY_UNPROVEN
    if isinstance(resolved, ExactFunctionRangeBoundary8616):
        if resolved.addr != callee_addr:
            return None, ModularInputProofFailure8616.FUNCTION_MISMATCH
        if resolved.project is not project:
            return None, ModularInputProofFailure8616.BOUNDARY_PROJECT_MISMATCH
        return resolved, None
    try:
        resolved_addr = cast(_FunctionBoundary8616, resolved).addr
    except AttributeError:
        return None, ModularInputProofFailure8616.CALLEE_BOUNDARY_UNPROVEN
    if resolved_addr != callee_addr:
        return None, ModularInputProofFailure8616.FUNCTION_MISMATCH
    boundary = _restored_exact_boundary_8616(project, resolved)
    if boundary is None or boundary.addr != callee_addr:
        return None, ModularInputProofFailure8616.CALLEE_BOUNDARY_UNPROVEN
    return boundary, None


def _proven_input_access_8616(
    artifact: SSAFunctionArtifact,
    callee_addr: int,
    storage: IRAddress,
) -> IRLogicalMemoryAccess8616 | None:
    """Find the artifact's unique proven read identity for one stack word.

    Census argument storage carries a defaulted segment; the proven query
    identity is taken from the callee's own closed logical-memory access, so
    the upstream proof binds to binary evidence rather than an asserted flag.
    """
    logical = artifact.logical_memory
    if (
        logical is None
        or not logical.closed
        or bool(logical.refusals)
        or logical.function_addr != callee_addr
    ):
        return None
    matches = tuple(
        access
        for access in logical.accesses
        if access.kind is IRMemoryAccessKind8616.READ
        and access.complete
        and access.key.function_addr == callee_addr
        and access.address.space is MemSpace.SS
        and access.address.base == storage.base
        and access.address.offset == storage.offset
        and access.address.size == storage.size
        and access.address.status is AddressStatus.STABLE
        and access.address.segment_origin is SegmentOrigin.PROVEN
    )
    if len(matches) != 1:
        return None
    return matches[0]


class ModularArgumentTypeFacts8616:
    """Per-callee lazy cache of modular input-use proofs shared per callsite.

    The owner binds ``project`` and ``callee_addr`` once at input collection;
    boundary and Semantics SSA resolution run on the first proof request and
    every ``SS:BP`` storage identity is proved at most once. Unproven,
    foreign, or stale evidence always returns a typed refusal, leaving the
    caller's original classification refusal intact.
    """

    __slots__ = ("_callee_addr", "_project", "_proofs", "_resolution")

    def __init__(self, project: object, callee_addr: int) -> None:
        """Bind one exact callee; no analysis runs until a proof is requested."""
        self._project = project
        self._callee_addr = callee_addr
        self._resolution: _CalleeEvidence8616 | None = None
        self._proofs: dict[tuple[object, ...], ModularInputProof8616] = {}

    @property
    def callee_addr(self) -> int:
        """Return the exact callee this owner is bound to."""
        return self._callee_addr

    @property
    def stats(self) -> ModularInputProofStats8616:
        """Aggregate five-stage counts across every requested proof."""
        results = tuple(self._proofs.values())
        return ModularInputProofStats8616(
            raw_fact_count=sum(item.stats.raw_fact_count for item in results),
            normalized_fact_count=sum(
                item.stats.normalized_fact_count for item in results
            ),
            classified_fact_count=sum(
                item.stats.classified_fact_count for item in results
            ),
            materialized_count=sum(item.stats.materialized_count for item in results),
            failure_count=sum(item.stats.failure_count for item in results),
        )

    def proof_for_8616(self, storage: IRAddress) -> ModularInputProof8616:
        """Return the cached or newly proven result for one stack word."""
        key = _storage_key_8616(storage)
        cached = self._proofs.get(key)
        if cached is not None:
            return cached
        result = self._prove_8616(storage)
        self._proofs[key] = result
        return result

    def _callee_evidence_8616(self) -> _CalleeEvidence8616:
        """Resolve the bound callee's boundary and SSA artifact once."""
        if self._resolution is not None:
            return self._resolution
        boundary, boundary_failure = _exact_callee_boundary_8616(
            self._project,
            self._callee_addr,
        )
        if boundary is None:
            self._resolution = _CalleeEvidence8616(
                None,
                None,
                boundary_failure
                or ModularInputProofFailure8616.CALLEE_BOUNDARY_UNPROVEN,
            )
            return self._resolution
        if not _semantic_registry_exists_8616(self._project):
            self._resolution = _CalleeEvidence8616(
                boundary,
                None,
                ModularInputProofFailure8616.CALLEE_SSA_UNPROVEN,
                FunctionSSAArtifactFailure8616.ARTIFACT_NOT_REGISTERED,
            )
            return self._resolution
        resolution = registered_function_ssa_artifact_8616(
            self._project,
            self._callee_addr,
        )
        artifact = resolution.artifact
        if (
            resolution.verdict is not FunctionSSAArtifactVerdict8616.PROVEN
            or resolution.stage is not FunctionSSAArtifactStage8616.SEMANTIC
            or artifact is None
            or artifact.function_addr != self._callee_addr
        ):
            self._resolution = _CalleeEvidence8616(
                boundary,
                None,
                ModularInputProofFailure8616.CALLEE_SSA_UNPROVEN,
                resolution.failure,
            )
            return self._resolution
        self._resolution = _CalleeEvidence8616(boundary, artifact, None)
        return self._resolution

    def _prove_8616(self, storage: IRAddress) -> ModularInputProof8616:
        """Prove one census stack word through the callee's own artifacts."""
        callee_addr = self._callee_addr
        if not _supported_census_storage_8616(storage):
            return _refuse_8616(
                callee_addr,
                storage,
                ModularInputProofFailure8616.INPUT_STORAGE_UNPROVEN,
            )
        evidence = self._callee_evidence_8616()
        if evidence.boundary is None or evidence.artifact is None:
            return _refuse_8616(
                callee_addr,
                storage,
                evidence.failure
                or ModularInputProofFailure8616.CALLEE_BOUNDARY_UNPROVEN,
                normalized=True,
                boundary=evidence.boundary,
                artifact=evidence.artifact,
                upstream=evidence.upstream_failure,
            )
        access = _proven_input_access_8616(evidence.artifact, callee_addr, storage)
        if access is None:
            return _refuse_8616(
                callee_addr,
                storage,
                ModularInputProofFailure8616.ACCESS_IDENTITY_UNKNOWN,
                normalized=True,
                boundary=evidence.boundary,
                artifact=evidence.artifact,
            )
        proof = prove_stack_argument_modular_return_use_8616(
            evidence.boundary,
            evidence.artifact,
            access.address,
        )
        if (
            proof.verdict is not ModularArgumentUseVerdict8616.PROVEN
            or proof.stats != ModularArgumentUseStats8616(1, 1, 1, 1, 0)
        ):
            return _refuse_8616(
                callee_addr,
                storage,
                ModularInputProofFailure8616.UPSTREAM_PROOF_REFUSED,
                normalized=True,
                boundary=evidence.boundary,
                artifact=evidence.artifact,
                proven_storage=access.address,
                access_key=access.key,
                proof=proof,
                upstream=proof.failure,
            )
        result = ModularInputProof8616(
            callee_addr,
            storage,
            ModularInputProofVerdict8616.PROVEN,
            None,
            ModularInputProofStats8616(1, 1, 1, 1, 0),
            access.address,
            evidence.boundary,
            evidence.artifact,
            access.key,
            proof,
        )
        if not result.complete:
            raise RuntimeError("modular input-use proof lost owned evidence")
        return result
