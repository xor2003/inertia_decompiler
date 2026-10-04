"""Layer: dosunit joint recursive proof contracts (staging).

Responsibility: bind every paired atomic transition and frame/dispatch/progress
obligation to a component, without treating an SCC or local frame as equality.
Physical execution/model obligations remain explicit conditional assumptions.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from tools.dosunit.proof_contracts import ContractIdentity, ObligationReport, ProofStatus
from tools.dosunit.recursive_proofs.recursive_call_components import FunctionId
from tools.dosunit.recursive_proofs.stack.recursive_stack_proofs import StackInvariantProof
from tools.dosunit.register_state_relations import MachineState


class JointStepKind(StrEnum):
    """Atomic native transitions used in a synchronized component simulation."""

    BRANCH = "branch"
    CALL = "call"
    RETURN = "return"


class JointReason(StrEnum):
    """Exact missing or refuted joint proof condition."""

    DISCHARGED = "joint_native_obligations_discharged"
    CONDITIONAL_MODEL = "joint_physical_model_not_closed"
    ADMISSION = "joint_call_graph_incomplete"
    COMPONENT = "joint_component_membership_mismatch"
    LAYOUT = "joint_matched_coordinates_required"
    MANIFEST = "joint_transition_manifest_incomplete"
    OUTPUTS = "joint_full_state_outputs_missing"
    DISPATCH = "joint_dispatch_mismatch"
    EXTERNAL = "joint_external_dependency_not_closed"
    COUNTERMODEL = "joint_cutpoint_countermodel"
    CALL_CONTINUATION = "joint_call_continuation_evidence_incomplete"
    UNKNOWN = "joint_native_solver_unknown"
    DEADLINE = "joint_deadline_exceeded"


class JointModelRequirement(StrEnum):
    """Unclosed physical/domain obligations; none may silently become a pass."""

    CALLER_ENTRY = "caller_frame_and_entry_domain"
    FAULT_DOMAIN = "normal_and_fault_outcomes"
    CODE_MEMORY = "immutable_code_and_physical_alias_domain"
    ADDRESS_MODEL = "physical_address_wrap_and_segment_operand_scope"
    ENVIRONMENT = "external_and_asynchronous_event_scope"


class EnvironmentScopeMember(StrEnum):
    """One declared asynchronous-machine exclusion; a premise, not a proof.

    Byte evidence can only prove the absence of supported synchronous
    instruction effects.  Whether the modeled machine contains external agents,
    asynchronous interrupt delivery, external memory mutation or host services
    is a domain declaration the caller must supply and the proof must bind.
    """

    NO_EXTERNAL_AGENTS = "no_external_agent_observes_or_mutates_state"
    NO_ASYNC_DELIVERY = "no_asynchronous_interrupt_or_trap_delivery"
    NO_EXTERNAL_MUTATION = "no_external_memory_or_device_mutation"
    NO_HOST_SERVICES = "no_dos_bios_or_host_service_availability"


@dataclass(frozen=True, slots=True)
class Real16EnvironmentScope:
    """Declared closed-machine premise content-bound to both input binaries.

    This is a caller-supplied machine premise, never inferred from decoded
    bytes.  ``original_hash``/``candidate_hash`` must equal the joint contract
    hashes: a premise bound to different content is a forgery and cannot close
    ENVIRONMENT.  Inside ``JointSystem`` the premise is part of the proposal, so
    changing it invalidates every retained receipt and proof artifact.
    """

    members: tuple[EnvironmentScopeMember, ...]
    original_hash: str
    candidate_hash: str
    provenance: str = ""

    def __post_init__(self) -> None:
        """Require the complete typed declaration bound to concrete binaries."""
        if (any(type(member) is not EnvironmentScopeMember for member in self.members)
                or len(set(self.members)) != len(self.members)
                or set(self.members) != set(EnvironmentScopeMember)):
            raise ValueError("environment scope requires every distinct typed member")
        if any(type(value) is not str or len(value) != 64
               for value in (self.original_hash, self.candidate_hash)):
            raise ValueError("environment scope requires both 64-hex binary hashes")


@dataclass(frozen=True, order=True, slots=True)
class JointNodeId:
    """One actual native block head inside a declared component member."""

    function: FunctionId
    delta: int

    def __post_init__(self) -> None:
        """Require a typed function and a nonnegative physical entry delta."""
        if not isinstance(self.function, FunctionId) or type(self.delta) is not int or self.delta < 0:
            raise ValueError("joint node requires a typed function and nonnegative delta")

    def key(self) -> str:
        """Return a stable diagnostic/obligation key without label semantics."""
        return f"{self.function.value}:{self.delta:x}"


@dataclass(frozen=True, slots=True)
class JointStepPair:
    """Two binary-derived effects with explicit complete static dispatch."""

    node: JointNodeId
    original_address: int
    candidate_address: int
    original_hash: str
    candidate_hash: str
    kind: JointStepKind
    original: MachineState
    candidate: MachineState
    successors: tuple[JointNodeId, ...]
    callee: JointNodeId | None = None
    continuation: JointNodeId | None = None


@dataclass(frozen=True, slots=True)
class JointSystem:
    """A finite closed component proposal; metadata grants no proof status."""

    contract: ContractIdentity
    root: JointNodeId
    members: tuple[FunctionId, ...]
    steps: tuple[JointStepPair, ...]
    required_outputs: tuple[str, ...]
    external_dependencies: tuple[FunctionId, ...] = ()
    expected_nodes: tuple[JointNodeId, ...] = ()
    initial_state: MachineState | None = None
    control_field: str = "control_ip"
    component_ranges: tuple[tuple[int, int], ...] = ()
    environment_scope: Real16EnvironmentScope | None = None


@dataclass(frozen=True, slots=True)
class JointStepEvidence:
    """Retain raw cutpoint SAT separately from whole-component admission."""

    node: JointNodeId
    status: ProofStatus
    reason: JointReason
    attempted: bool
    elapsed_ms: int
    detail: str = ""
    mismatches: tuple[object, ...] = ()


@dataclass(frozen=True, slots=True)
class JointComponentReport:
    """Joint proof accounting; physical/model scope still controls acceptance."""

    status: ProofStatus
    reason: JointReason
    proof: ObligationReport
    steps: tuple[JointStepEvidence, ...]
    model_requirements: tuple[JointModelRequirement, ...]
    detail: str = ""
    frames: tuple[StackInvariantProof, ...] = ()
