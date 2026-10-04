"""Layer: dosunit public PE32 recursive joint-proof adapter.

Responsibility: bridge the flat32 drivers' compare reports to the
reviewed image-bound PE32 recursive component checkers. Every proof input is
re-derived from the supplied executable bytes — real CLE loading, native
relifting and byte-bound source binding; caller-supplied machine states or
pre-proved receipts are never admitted. One absolute deadline covers image
binding, component construction, the initialized-byte relation and the
composed joint check, and every delegated stage additionally keeps its own
established millisecond budget rather than the whole remaining allowance.
A typed refusal replaces no selected-function obligation: ordinary rows,
statuses and dependencies stay untouched, and ``recursive_joint`` is a
separate initialized-entry component result that never discharges
arbitrary-entry member obligations. The declared access domain is a visible
caller premise bound to both actual images — never manufactured — and a
conditional outcome names its model requirements instead of passing.
"""
from __future__ import annotations

import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from tools.dosunit import straightline_ssa as S
from tools.dosunit.flat32_call_contracts import CallCompositionRefusal
from tools.dosunit.flat32_lifting import _flat32_seam
from tools.dosunit.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.recursive_proofs.flat32_image_bound_domain import Flat32AccessDomain
from tools.dosunit.recursive_proofs.flat32_image_bound_joint_proof import (
    ImageBoundFlat32JointProof,
    check_image_bound_flat32_joint,
)
from tools.dosunit.recursive_proofs.flat32_pe_component import (
    Flat32PeComponent,
    Flat32ProposalReason,
    Flat32ProposalRefusal,
    build_flat32_pe_component,
)
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import (
    BoundFlat32Load,
    ImageBindingRefusal,
    bind_flat32_file,
)
from tools.dosunit.recursive_proofs.loaded_byte_relation import (
    LoadedRelationLimits,
    LoadedRelationReason,
    LoadedRelationRefusal,
    propose_loaded_byte_relation,
)
from tools.dosunit.recursive_proofs.loaded_byte_relation_proof import prove_loaded_byte_relation
from tools.dosunit.recursive_proofs.recursive_joint_admission import JointRefusal
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointReason

REPORT_SCHEMA: str = "dosunit.pe32_compare.recursive_joint.v1"

# Each delegated owner keeps its own established millisecond budget. The
# request's total deadline is shared absolutely and never enlarges a child:
# every child call receives ``min(remaining, owner default)``.
_COMPONENT_BUDGET_MS: int = 30_000  # build_flat32_pe_component default
_LOADED_RELATION_BUDGET_MS: int = 10_000  # prove_loaded_byte_relation default
_JOINT_BUDGET_MS: int = 120_000  # check_image_bound_flat32_joint default
REQUEST_BUDGET_MS: int = 180_000

_PE32_LOADER: str = "InclusivePE"


class Pe32RecursiveReason(StrEnum):
    """Exact boundary where the public recursive attempt refused."""

    ADMISSION = "pe32_recursive_admission_incomplete"
    UNPAIRED = "pe32_recursive_function_not_selected_on_both_sides"
    COORDINATES = "pe32_recursive_function_coordinates_differ"
    DECLARATION = "pe32_recursive_function_declaration_invalid"
    FORMAT = "pe32_recursive_pe32_image_required"
    LOAD = "pe32_recursive_load_binding_refused"
    DOMAIN = "pe32_recursive_domain_receipt_refused"
    JOINT = "pe32_recursive_joint_proof_refused"
    DEADLINE = "pe32_recursive_deadline_exhausted"


@dataclass(frozen=True, slots=True)
class Pe32RecursiveRequest:
    """Typed opt-in for the image-bound PE32 recursive component path.

    ``access`` is the caller-declared entry stack window, admitted entry esp
    interval and recursion frame budget that the image-bound domain proof
    discharges against actual CLE permission mappings. The declaration is a
    premise, never an unconditional pass; it is bound to both actual image
    identities and stays visible as a named assumption. It is required and is
    never defaulted or manufactured.
    """

    access: Flat32AccessDomain
    timeout_ms: int = REQUEST_BUDGET_MS
    provenance: str = ""

    def __post_init__(self) -> None:
        """Reject untyped premises and budgets the adapter cannot honor."""
        if not isinstance(self.access, Flat32AccessDomain):
            raise ValueError("pe32 recursive request requires a typed declared access domain")
        if type(self.timeout_ms) is not int or self.timeout_ms < 0:
            raise ValueError("pe32 recursive request requires a nonnegative millisecond budget")
        if type(self.provenance) is not str:
            raise ValueError("pe32 recursive provenance must be a text tag")


@dataclass(frozen=True, slots=True)
class Pe32RecursiveAttempt:
    """One refused selected function retained for the public report."""

    name: str
    reason: Pe32RecursiveReason  # owned enum; serialized via ``.value`` only
    detail: str = ""


@dataclass(frozen=True, slots=True)
class Pe32SelectedMember:
    """One selected name admitted into the component's member closure."""

    name: str
    entry: int
    size: int
    member: str = ""

    def __post_init__(self) -> None:
        """Require a text name and nonnegative i386 coordinates."""
        if type(self.name) is not str or not self.name:
            raise ValueError("selected member requires a nonempty function name")
        if type(self.entry) is not int or not 0 <= self.entry < 1 << 32:
            raise ValueError("selected member requires an i386 entry coordinate")
        if type(self.size) is not int or self.size <= 0:
            raise ValueError("selected member requires a positive byte size")
        if type(self.member) is not str:
            raise ValueError("selected member requires a text member identity")


@dataclass(frozen=True, slots=True)
class Pe32DomainScope:
    """Immutable metadata from a consumed domain receipt, not a new theorem.

    Model/proposal/snapshot identities retain the exact receipt and remain
    visible in the public JSON projection for dependency auditing. The access
    domain is the caller-declared premise the receipt was discharged under.
    """

    original_sha256: str
    candidate_sha256: str
    entry_linear: tuple[int, int]
    root_linear: int
    access: Flat32AccessDomain
    snapshot_hashes: tuple[str, str]
    domain_model_hash: str
    proposal_hash: str
    provenance: str = ""

    def __post_init__(self) -> None:
        """Require typed domain metadata and immutable scalar identities."""
        if not isinstance(self.access, Flat32AccessDomain):
            raise ValueError("pe32 recursive scope requires a typed access domain")
        if type(self.entry_linear) is not tuple or len(self.entry_linear) != 2:
            raise ValueError("pe32 recursive scope requires two immutable entries")
        if any(type(value) is not int or not 0 <= value < 1 << 32
               for value in (*self.entry_linear, self.root_linear)):
            raise ValueError("pe32 recursive scope requires i386 linear entries")
        if type(self.snapshot_hashes) is not tuple or len(self.snapshot_hashes) != 2:
            raise ValueError("pe32 recursive scope requires two immutable snapshot identities")
        identities = (self.original_sha256, self.candidate_sha256, *self.snapshot_hashes,
                      self.domain_model_hash, self.proposal_hash)
        if any(type(value) is not str or not value for value in identities):
            raise ValueError("pe32 recursive scope requires nonempty receipt identities")
        if type(self.provenance) is not str:
            raise ValueError("pe32 recursive scope provenance must be a text tag")

    def to_document(self) -> dict[str, Any]:
        """Create a fresh JSON projection without exposing mutable owned state."""
        return {
            "kind": "initialized_pe32_image",
            "entry_linear": list(self.entry_linear),
            "root_linear": self.root_linear,
            "access_domain": {
                "stack_lo": self.access.stack_lo,
                "stack_hi": self.access.stack_hi,
                "esp_min": self.access.esp_min,
                "esp_max": self.access.esp_max,
                "max_frames": self.access.max_frames,
            },
            "initialized_loaded_relation": True,
            "arbitrary_entry_states_proved": False,
            "original_sha256": self.original_sha256,
            "candidate_sha256": self.candidate_sha256,
            "snapshot_hashes": list(self.snapshot_hashes),
            "domain_model_hash": self.domain_model_hash,
            "proposal_hash": self.proposal_hash,
            "declared_provenance": self.provenance or None,
        }


@dataclass(frozen=True, slots=True)
class Pe32RecursiveOutcome:
    """Complete recursive attempt state for the public report; never a boolean."""

    attempted: bool
    status: ProofStatus
    reason: Pe32RecursiveReason | JointReason  # owned enum; .value at serialization
    nested_reason: StrEnum | None = None  # delegated child's typed reason, if any
    member_ids: tuple[str, ...] = ()
    selected: tuple[Pe32SelectedMember, ...] = ()
    domain_scope: Pe32DomainScope | None = None
    assumptions: tuple[str, ...] = ()
    counters: FactCounters = field(default_factory=FactCounters)
    root: str = ""
    proposal_hash: str = ""
    model_hash: str = ""
    remaining: tuple[str, ...] = ()
    attempts: tuple[Pe32RecursiveAttempt, ...] = ()
    detail: str = ""
    proof: ImageBoundFlat32JointProof | None = None

    def __post_init__(self) -> None:
        """Reject mutable dictionaries at the owned scope boundary."""
        if self.status is ProofStatus.PROVED and self.assumptions:
            raise ValueError("premise-bearing recursive outcome cannot be unconditional")
        if self.domain_scope is not None and not isinstance(self.domain_scope, Pe32DomainScope):
            raise ValueError("pe32 recursive domain scope requires immutable typed metadata")
        if self.proof is not None and not isinstance(self.proof, ImageBoundFlat32JointProof):
            raise ValueError("pe32 recursive outcome requires a typed joint receipt")

    def to_document(self) -> dict[str, Any]:
        """Serialize the retained state; assumptions stay visible downstream."""
        return {
            "schema": REPORT_SCHEMA,
            "attempted": self.attempted,
            "status": self.status.value,
            "reason": self.reason.value,
            "nested_reason": self.nested_reason.value if self.nested_reason is not None else None,
            "root": self.root or None,
            "members": list(self.member_ids),
            "selected": [
                {"name": row.name, "entry": row.entry, "size": row.size, "member": row.member or None}
                for row in self.selected
            ],
            "assumptions": list(self.assumptions),
            "remaining_requirements": list(self.remaining),
            "proposal_hash": self.proposal_hash,
            "model_hash": self.model_hash,
            "counters": {
                "raw_fact_count": self.counters.raw_fact_count,
                "normalized_fact_count": self.counters.normalized_fact_count,
                "classified_fact_count": self.counters.classified_fact_count,
                "materialized_count": self.counters.materialized_count,
                "failure_count": self.counters.failure_count,
            },
            "attempts": [
                {"name": attempt.name, "reason": attempt.reason.value, "detail": attempt.detail}
                for attempt in self.attempts
            ],
            "domain_scope": self.domain_scope.to_document() if self.domain_scope is not None else None,
            "joint": (
                None
                if self.proof is None
                else {
                    "status": self.proof.status.value,
                    "reason": self.proof.reason.value,
                    "detail": self.proof.detail,
                    "binary_equivalence_proved": self.proof.binary_equivalence_proved,
                }
            ),
            "detail": self.detail,
        }


class _AdapterRefusal(Exception):
    """Internal typed boundary; never leaves this module as an exception."""

    def __init__(self, reason: Pe32RecursiveReason, detail: str,
                 nested: StrEnum | None = None) -> None:
        """Retain the typed reason, its detail and any delegated child reason."""
        super().__init__(detail)
        self.reason = reason
        self.detail = detail
        self.nested = nested


def _refuse(reason: Pe32RecursiveReason, detail: str,
            attempts: tuple[Pe32RecursiveAttempt, ...],
            nested: StrEnum | None = None,
            selected: tuple[Pe32SelectedMember, ...] = ()) -> Pe32RecursiveOutcome:
    """Assemble one refused outcome while retaining every selected attempt."""
    return Pe32RecursiveOutcome(
        attempted=True, status=ProofStatus.UNKNOWN, reason=reason,
        nested_reason=nested,
        counters=FactCounters(1, 1, 1, 1, 1), attempts=attempts, detail=detail,
        selected=selected,
    )


def _valid_range(value: object) -> bool:
    """Require one declared ``(start, size)`` integer pair per selected name."""
    return (isinstance(value, tuple) and len(value) == 2
            and all(type(item) is int for item in value)
            and 0 <= value[0] < 1 << 32
            and 0 < value[1] <= (1 << 32) - value[0])


def _same_coordinate_functions(
    oracle_functions: Mapping[str, tuple[int, int]],
    candidate_functions: Mapping[str, tuple[int, int]],
    unresolved_names: Iterable[str],
    attempts: list[Pe32RecursiveAttempt],
) -> tuple[dict[int, int], dict[str, tuple[int, int]]]:
    """Pair selected names into one shared coordinate declaration.

    The component proof is same-coordinate: only names whose declared byte
    range is identical on both sides may enter the member closure. Unpaired,
    malformed, unresolved and divergent selections stay as refused attempts
    so the public report accounts for every requested name.
    """
    for name in sorted(unresolved_names):
        attempts.append(Pe32RecursiveAttempt(
            name, Pe32RecursiveReason.UNPAIRED,
            "function has no declared range on either side"))
    declared: dict[int, int] = {}
    selected: dict[str, tuple[int, int]] = {}
    for name in sorted(set(oracle_functions) | set(candidate_functions)):
        oracle_range = oracle_functions.get(name)
        candidate_range = candidate_functions.get(name)
        if oracle_range is None or candidate_range is None:
            attempts.append(Pe32RecursiveAttempt(
                name, Pe32RecursiveReason.UNPAIRED, "function is not selected on both sides"))
            continue
        if not _valid_range(oracle_range) or not _valid_range(candidate_range):
            attempts.append(Pe32RecursiveAttempt(
                name, Pe32RecursiveReason.DECLARATION,
                "selected range is not a (start, size) integer pair"))
            continue
        if oracle_range != candidate_range:
            attempts.append(Pe32RecursiveAttempt(
                name, Pe32RecursiveReason.COORDINATES,
                f"oracle {oracle_range} != candidate {candidate_range}; rebased layouts are unpaired"))
            continue
        entry, size = oracle_range
        previous = declared.get(entry)
        if previous is not None and previous != size:
            attempts.append(Pe32RecursiveAttempt(
                name, Pe32RecursiveReason.DECLARATION,
                f"entry {entry:#x} is already declared with size {previous}"))
            continue
        if previous is None:
            declared[entry] = size
        selected[name] = (entry, size)
    if not declared:
        raise _AdapterRefusal(
            Pe32RecursiveReason.ADMISSION,
            "no selected functions share one same-coordinate declaration")
    return declared, selected


def _bind_pe32(path: Path, limits: LoadedRelationLimits) -> BoundFlat32Load:
    """Bind immutable actual bytes; PE32 only — ELF stays on the existing lane."""
    try:
        data = Path(path).read_bytes()
    except OSError as error:
        raise _AdapterRefusal(Pe32RecursiveReason.LOAD, f"executable unreadable: {error}") from error
    if data[:2] != b"MZ":
        raise _AdapterRefusal(Pe32RecursiveReason.FORMAT,
                              "image-bound recursive path requires a PE32 input")
    load = bind_flat32_file(data, limits=limits)
    if load.binding.loader != _PE32_LOADER:
        raise _AdapterRefusal(Pe32RecursiveReason.FORMAT,
                              "image-bound recursive path requires a PE32 input")
    return load


def _domain_scope(proof: ImageBoundFlat32JointProof,
                  loads: tuple[BoundFlat32Load, BoundFlat32Load],
                  access: Flat32AccessDomain, provenance: str) -> Pe32DomainScope:
    """Copy only proved, consistently bound receipt metadata; never prove a bridge."""
    receipt = proof.domain
    if receipt is None or receipt.status is not ProofStatus.PROVED:
        raise _AdapterRefusal(Pe32RecursiveReason.DOMAIN, "initialized domain receipt is not proved")
    counters = receipt.counters
    if not counters.closed() or counters.failure_count or not counters.materialized_count:
        raise _AdapterRefusal(Pe32RecursiveReason.DOMAIN, "initialized domain ledger is incomplete")
    if not isinstance(receipt.model_hash, str) or not receipt.model_hash:
        raise _AdapterRefusal(Pe32RecursiveReason.DOMAIN, "initialized domain identity is missing")
    original, candidate = (load.binding.file_sha256 for load in loads)
    snapshots = (loads[0].binding.snapshot.sparse_byte_sha256,
                 loads[1].binding.snapshot.sparse_byte_sha256)
    contract = receipt.system.contract
    if (contract.original_hash, contract.candidate_hash) != (original, candidate):
        raise _AdapterRefusal(Pe32RecursiveReason.DOMAIN, "initialized component image identity differs")
    if receipt.domain != access:
        raise _AdapterRefusal(Pe32RecursiveReason.DOMAIN, "initialized domain declaration differs")
    roots = tuple(step for step in receipt.system.steps if step.node == receipt.system.root)
    if len(roots) != 1 or roots[0].original_address != roots[0].candidate_address:
        raise _AdapterRefusal(Pe32RecursiveReason.DOMAIN, "initialized domain root identity differs")
    return Pe32DomainScope(original, candidate, (loads[0].binding.entry, loads[1].binding.entry),
                           roots[0].original_address, receipt.domain, snapshots, receipt.model_hash,
                           proof.proposal_hash, provenance)


def _domain_bridge(scope: Pe32DomainScope) -> tuple[str, ...]:
    """Describe the initialized component domain without asserting member implication."""
    bound = f"original={scope.original_sha256},candidate={scope.candidate_sha256}"
    access = scope.access
    return (
        f"supported_entry_domain:initialized_pe32_image({bound})",
        f"declared_access_domain(stack=0x{access.stack_lo:x}-0x{access.stack_hi:x},"
        f"esp=0x{access.esp_min:x}-0x{access.esp_max:x},"
        f"max_frames={access.max_frames},{bound})",
        f"pe32_entry_execution(entry=0x{scope.entry_linear[0]:x},"
        f"candidate_entry=0x{scope.entry_linear[1]:x})",
        f"initialized_loaded_byte_relation({bound})",
        f"arbitrary_entry_states_not_proved({bound})",
    )


def _outcome_from_proof(proof: ImageBoundFlat32JointProof, component: Flat32PeComponent,
                        loads: tuple[BoundFlat32Load, BoundFlat32Load],
                        selected: dict[str, tuple[int, int]],
                        attempts: tuple[Pe32RecursiveAttempt, ...],
                        request: Pe32RecursiveRequest) -> Pe32RecursiveOutcome:
    """Project the sealed joint result; conditional scope stays explicit."""
    remaining = tuple(item.value for item in proof.remaining)
    status = (ProofStatus.CONDITIONAL if proof.status in {ProofStatus.PROVED, ProofStatus.CONDITIONAL}
              else ProofStatus.UNKNOWN)
    domain_scope: Pe32DomainScope | None = None
    assumptions: tuple[str, ...] = ()
    member_ids: tuple[str, ...] = ()
    selected_rows = _selected_declarations(selected)
    if status is not ProofStatus.UNKNOWN:
        domain_scope = _domain_scope(proof, loads, request.access, request.provenance)
        assumptions = remaining + _domain_bridge(domain_scope)
        member_ids = tuple(str(member.value) for member in component.system.members)
        member_set = frozenset(member_ids)
        selected_rows = tuple(
            Pe32SelectedMember(name, entry, size,
                               f"flat32-{entry:x}" if f"flat32-{entry:x}" in member_set else "")
            for name, (entry, size) in selected.items()
        )
    return Pe32RecursiveOutcome(
        attempted=True, status=status, reason=proof.reason,
        member_ids=member_ids, selected=selected_rows,
        domain_scope=domain_scope, assumptions=assumptions,
        counters=proof.proof.counters, root=str(component.system.root.function.value),
        proposal_hash=proof.proposal_hash, model_hash=proof.model_hash,
        remaining=remaining, attempts=attempts, detail=proof.detail, proof=proof,
    )


def _selected_declarations(
    selected: Mapping[str, tuple[int, int]],
) -> tuple[Pe32SelectedMember, ...]:
    """Retain paired declarations without claiming admitted component membership."""
    return tuple(Pe32SelectedMember(name, entry, size)
                 for name, (entry, size) in selected.items())


def _request_limits(request: Pe32RecursiveRequest) -> LoadedRelationLimits:
    """Validate the public request and begin its single absolute deadline."""
    if not isinstance(request, Pe32RecursiveRequest):
        raise ValueError("pe32 recursive compare requires a typed request")
    return LoadedRelationLimits(deadline=time.monotonic() + request.timeout_ms / 1000)


def prove_pe32_recursive_compare(
    *,
    oracle_exe: Path,
    candidate_exe: Path,
    oracle_functions: Mapping[str, tuple[int, int]],
    candidate_functions: Mapping[str, tuple[int, int]],
    request: Pe32RecursiveRequest,
    unresolved_names: Iterable[str] = (),
) -> Pe32RecursiveOutcome:
    """Attempt the image-bound PE32 recursive component proof for selected functions.

    Selected name/range pairs must agree on both sides to enter the declared
    same-coordinate member closure; every refused name is retained as a typed
    attempt, including ``unresolved_names`` that carry no declared range at
    all. The shared ``request.timeout_ms`` deadline covers image binding,
    component construction, the initialized-byte relation and the composed
    joint check without replenishment. Only a PROVED or CONDITIONAL receipt
    exposes component ``member_ids``/``assumptions``/``domain_scope``; every
    conditional outcome names its open model requirements.
    """
    limits = _request_limits(request)
    attempts: list[Pe32RecursiveAttempt] = []
    selected: dict[str, tuple[int, int]] = {}

    def refused(reason: Pe32RecursiveReason, detail: str,
                nested: StrEnum | None = None) -> Pe32RecursiveOutcome:
        """Retain admitted declarations even when a later proof stage refuses."""
        rows = _selected_declarations(selected)
        return _refuse(reason, detail, tuple(attempts), nested=nested, selected=rows)

    def remaining_ms() -> int:
        limits.check_time()
        return max(0, int((limits.deadline - time.monotonic()) * 1000))

    try:
        declared, selected = _same_coordinate_functions(
            oracle_functions, candidate_functions, unresolved_names, attempts)
        loads = (_bind_pe32(oracle_exe, limits), _bind_pe32(candidate_exe, limits))
        # The component builder and joint check consume the shared flat32
        # register/expression model; entering the owned seam here keeps this
        # adapter self-contained for callers without an outer driver context.
        with _flat32_seam():
            component = build_flat32_pe_component(
                loads, declared,
                timeout_ms=min(remaining_ms(), _COMPONENT_BUDGET_MS), limits=limits)
            initialized = prove_loaded_byte_relation(
                propose_loaded_byte_relation(
                    loads[0].binding.snapshot, loads[1].binding.snapshot, limits=limits),
                timeout_ms=min(remaining_ms(), _LOADED_RELATION_BUDGET_MS), limits=limits)
            proof = check_image_bound_flat32_joint(
                component.system, loads, initialized, component.requests,
                component.bootstrap, request.access,
                timeout_ms=min(remaining_ms(), _JOINT_BUDGET_MS), limits=limits)
        return _outcome_from_proof(proof, component, loads, selected,
                                   tuple(attempts), request)
    except _AdapterRefusal as exc:
        return refused(exc.reason, exc.detail, nested=exc.nested)
    except Flat32ProposalRefusal as exc:
        reason = (Pe32RecursiveReason.DEADLINE if exc.reason is Flat32ProposalReason.DEADLINE
                  else Pe32RecursiveReason.ADMISSION)
        return refused(reason, f"{exc.reason.value}: {exc.detail}", nested=exc.reason)
    except ImageBindingRefusal as exc:
        return refused(Pe32RecursiveReason.LOAD, f"{exc.reason.value}: {exc.detail}", nested=exc.reason)
    except JointRefusal as exc:
        reason = (Pe32RecursiveReason.DEADLINE if exc.reason is JointReason.DEADLINE
                  else Pe32RecursiveReason.JOINT)
        return refused(reason, f"{exc.reason.value}: {exc.detail}", nested=exc.reason)
    except LoadedRelationRefusal as exc:
        reason = (Pe32RecursiveReason.DEADLINE if exc.reason is LoadedRelationReason.DEADLINE
                  else Pe32RecursiveReason.LOAD)
        return refused(reason, f"{exc.reason.value}: {exc.detail}", nested=exc.reason)
    except CallCompositionRefusal as exc:
        # CallCompositionRefusal carries its stable reason as str(exc).
        return refused(Pe32RecursiveReason.ADMISSION, str(exc))
    except S.LowerFailure as exc:
        return refused(Pe32RecursiveReason.ADMISSION, f"{exc.reason}: {exc.message}")


def parse_pe32_access_domain(value: str) -> Flat32AccessDomain:
    """Parse ``STACK_LO:STACK_HI:ESP_MIN:ESP_MAX:MAX_FRAMES`` base-0 integers.

    ``Flat32AccessDomain`` validation rejects non-integer, empty, reversed and
    out-of-uint32 declarations; this parser additionally rejects every shape
    that is not exactly five integer fields.
    """
    parts = value.split(":")
    if len(parts) != 5:
        raise ValueError(
            "pe32 recursive access domain requires exactly "
            "STACK_LO:STACK_HI:ESP_MIN:ESP_MAX:MAX_FRAMES")
    try:
        fields = tuple(int(part, 0) for part in parts)
    except ValueError as error:
        raise ValueError(
            f"pe32 recursive access domain fields must be base-0 integers: {error}") from error
    return Flat32AccessDomain(*fields)


def recursive_request_from_args(args: Any) -> Pe32RecursiveRequest | None:  # noqa: ANN401
    """Return the declared opt-in, or None when the option is absent.

    ``argparse.Namespace`` is a third-party stdlib boundary: programmatic
    namespaces may omit the attributes, so ``getattr`` with a default is the
    documented seam. ``args.recursive`` is ``None``/``False`` (absent), a
    :class:`Pe32RecursiveRequest` (programmatic opt-in), or ``True`` (the CLI
    flag) resolved against ``recursive_access_domain`` and
    ``recursive_timeout_ms``. A string domain is parsed exactly like CLI input;
    a missing or wrong-typed domain fails closed — the declared stack/esp
    premise is never guessed.
    """
    # Dynamic third-party boundary: programmatic namespaces omit these options.
    value = getattr(args, "recursive", None)
    if value is None or value is False:
        return None
    if isinstance(value, Pe32RecursiveRequest):
        return value
    if value is True:
        # Dynamic third-party argparse boundary: supplied Namespace may omit options.
        domain = getattr(args, "recursive_access_domain", None)
        if isinstance(domain, str):
            domain = parse_pe32_access_domain(domain)
        if not isinstance(domain, Flat32AccessDomain):
            raise ValueError(
                "--recursive requires --recursive-access-domain "
                "STACK_LO:STACK_HI:ESP_MIN:ESP_MAX:MAX_FRAMES")
        # Dynamic third-party argparse boundary: supplied Namespace may omit options.
        timeout = getattr(args, "recursive_timeout_ms", REQUEST_BUDGET_MS)
        return Pe32RecursiveRequest(domain, timeout_ms=timeout)
    raise ValueError("recursive must be a typed Pe32RecursiveRequest or boolean flag")


def add_recursive_arguments(parser: Any) -> None:  # noqa: ANN401
    """Install the shared opt-in options so both drivers accept identical syntax."""
    parser.add_argument(
        "--recursive", action="store_true",
        help="attempt the image-bound PE32 recursive component proof for the selected "
             "functions; the separate recursive_joint field keeps ordinary rows unchanged")
    parser.add_argument(
        "--recursive-timeout-ms", type=int, default=REQUEST_BUDGET_MS,
        help="shared deadline for image binding, component construction and both proof stages")
    parser.add_argument(
        "--recursive-access-domain", metavar="STACK_LO:STACK_HI:ESP_MIN:ESP_MAX:MAX_FRAMES",
        type=parse_pe32_access_domain, default=None,
        help="caller-declared stack window, admitted entry esp interval and recursion frame "
             "budget; required with --recursive and published as a visible assumption")


def check_recursive_request(parser: Any, args: Any) -> None:  # noqa: ANN401
    """Normalize the CLI flag pair into one typed request or fail the parse."""
    try:
        request = recursive_request_from_args(args)
    except ValueError as error:
        parser.error(str(error))
    args.recursive = request


__all__ = [
    "REPORT_SCHEMA",
    "REQUEST_BUDGET_MS",
    "Pe32DomainScope",
    "Pe32RecursiveAttempt",
    "Pe32RecursiveOutcome",
    "Pe32RecursiveReason",
    "Pe32RecursiveRequest",
    "Pe32SelectedMember",
    "add_recursive_arguments",
    "check_recursive_request",
    "parse_pe32_access_domain",
    "prove_pe32_recursive_compare",
    "recursive_request_from_args",
]
