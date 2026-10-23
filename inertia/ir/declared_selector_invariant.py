"""Canonical declared selector invariant over native-bound raw 16-bit IR.

Layer: IR.
Responsibility: promote the reviewed declared-entry selector induction into a
canonical, consumable certificate. Prove, by bounded CFG induction, that
declared CS/DS/SS (and any other declared segment) stay constant across the
declared entry's whole closed raw CFG and across direct-near CALL edges whose
callee carries an independently proven complete universal segment-effect
closure. The canonical factory consumes the exact supplied
:class:`DeclaredFunctionEntryLink8616` root pair — never a substitute root
import — and retains it together with project, source, the immutable
pre-CALL incoming selector states keyed on exact
artifact/block/instruction identities, and every consumed
``(boundary, artifact)`` pair for later conditional consumption. STORE rows
are judged against every authenticated fetched span, including callee code.
After the final boot/module authentication, every retained consumed pair —
induced surfaces and phase-A callee premise closures — is rebound through the
scoped native comparison against the producer bound *then*, so a post-work
producer swap cannot leave stale consumed evidence authenticated. The last
authentication is callback-free. Charged to the shared ledger, never free.
This receipt is declared-entry CONDITIONAL evidence for target selection
only; it is never a Real16InvocationDomain, a SegmentCallPreservationResult,
or a full-state call-chain authorization. GP/SP/memory/return effects stay
ordinary obligations. Anything the induction cannot close is a typed open
obligation, never a silently dropped fact.
"""
from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from collections.abc import Set as AbstractSet
from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Protocol, cast

from inertia.frontend.x86_16.control_transfer_geometry import (
    ControlCheck8616,
    ControlKind8616,
    ControlVerdict8616,
    check_block_fallthrough_8616,
)
from inertia.frontend.x86_16.declared_function_entry import (
    DeclaredFunctionEntryAdmission8616,
    DeclaredFunctionEntrySpec8616,
    revalidate_declared_function_entry_8616,
)
from inertia.frontend.x86_16.frontend_block_inventory import (
    decoded_block_instructions_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
)
from inertia.frontend.x86_16.instruction_fetch_geometry import (
    FetchVerdict8616,
    check_instruction_fetch_8616,
)
from inertia.ir.core import (
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.declared_selector_control_binding import (
    check_bound_control_8616,
    check_scoped_return_control_8616,
)
from inertia.ir.declared_selector_native_effects import (
    NativeEffectSurvey8616,
    NativeRowClass8616,
    classify_native_row_8616,
    survey_native_effects_8616,
)
from inertia.ir.declared_selector_scoped_callee import (
    ScopedSelectorCollection8616,
    scoped_selector_facts_work_8616,
    scoped_selector_records_current_8616,
    scoped_selector_records_facts_8616,
)
from inertia.ir.direct_evidence_deadline import direct_evidence_deadline_expired_8616
from inertia.ir.entry_domain_call_preservation import (
    EntryDomainCallPreservation8616,
    Real16InvocationSource8616,
    _callee_preserved_registers_8616,
    _caller_premise_surface_8616,
    _exact_boundary_for_8616,
)
from inertia.ir.ir_boundary_cfg import (
    IRBoundaryCoverageResult8616,
    ScopedNativeRebindFacts8616,
    ScopedNativeSurfaceSnapshot8616,
    _capture_scoped_native_surface_8616,
    _prepare_scoped_native_rebind_8616,
    _scoped_native_rebind_failure_8616,
    closed_ir_boundary_cfg_8616,
    prove_ir_boundary_coverage_8616,
)
from inertia.ir.near_return_continuation_view import (
    NEAR_RETURN_CONTINUATION_PENDING_KIND_8616,
    ScopedNearReturnContinuationView8616,
)
from inertia.ir.real16_invocation_domain import (
    DeclaredFunctionEntryLink8616,
    _address_domain16_8616,
    _BootEvidence8616,
    _BootImageSurface8616,
    _image_slice_8616,
    _instruction_bytes_8616,
    _invocation_boot_evidence_8616,
    _loaded_bytes_8616,
    _normalize_instruction_8616,
    real16_native_census_import_8616,
)
from inertia.ir.real16_path_memory8616 import SEGMENT_BASE_NAME_8616
from inertia.ir.segment_call_preservation import (
    segment_call_dependency_traversal_scope_8616,
)
from inertia.ir.segment_effect_closure import (
    SegmentEffectClosureResult8616,
    prove_segment_effect_closure_8616,
)
from inertia.ir.segment_state_transfer import SEGMENT_REGISTERS

_SHARED_WORK_LIMIT_8616 = 20000

_WORD_LIMIT = 0xFFFF
_OFFSET_DOMAIN = 0x10000
_CANONICAL_SEGMENT_CLOSURE_PRODUCER_8616 = prove_segment_effect_closure_8616

_SHIFT = 4
_PHYSICAL_LIMIT = 0x100000
_MAX_DEPTH = 8
_PENDING_TERMINAL = "terminal_jump_selector_window_unproved"
_LEGACY_PREFIXES = frozenset({0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3})
# Native opcodes whose architectural effect changes a segment register or
# crosses code segments without an explicit IR destination we can bind.
# Far transfer (implicit CS), segment loads (implicit DS/ES), privileged.
_SEGMENT_WRITE_OPCODES: Mapping[int, str] = {
    0x07: "es", 0x17: "ss", 0x1F: "ds",       # pop es/ss/ds
    0x8E: "sreg",                              # mov Sreg,r/m16
    0xC4: "es", 0xC5: "ds",                    # les/lds
    0xEA: "cs", 0x9A: "cs",                    # jmp far / call far
    0xCB: "cs", 0xCA: "cs",                    # retf
    0xCF: "cs",                                # iret
    0xCD: "cs", 0xCC: "cs", 0xCE: "cs", 0xF1: "cs",  # int/int3/into/int1
}
_POP_FSGS = {0xA1: "fs", 0xA9: "gs"}
_FAR_MODRM = {3: "cs", 5: "cs"}  # FF /3 call far, FF /5 jmp far


class Verdict(Enum):
    """Per-row and per-edge typed verdicts of the induction."""

    DISJOINT = "disjoint"
    REFUSED_RESOURCE_LIMIT = "refused_resource_limit"
    CLOSED = "closed"
    PRESERVED = "preserved"
    REFUSED_SHAPE = "refused_shape"
    REFUSED_ADDRESS_SIZE = "refused_address_size"
    REFUSED_SEGMENT = "refused_segment"
    REFUSED_WIDTH = "refused_width"
    REFUSED_A20_WRAP = "refused_a20_wrap"
    REFUSED_CODE_WRITE = "refused_code_write"
    REFUSED_UNCLOSED = "refused_unclosed"


class ObligationKind(Enum):
    """Typed structural obligation the invariant could not close."""

    SEGMENT_WRITE = "segment_write"
    IMPLICIT_SEGMENT_EFFECT = "implicit_segment_effect"
    CALL_TARGET_UNRESOLVED = "call_target_unresolved"
    CALL_TRANSFER_UNSUPPORTED = "call_transfer_unsupported"
    CALLEE_MISSING = "callee_missing"
    CALLEE_CLOSURE_INCOMPLETE = "callee_closure_incomplete"
    TERMINAL_SELECTOR_WINDOW = "terminal_selector_window"
    SEGMENT_UNBOUND = "segment_unbound"
    FETCH_OUT_OF_WINDOW = "fetch_out_of_window"
    FETCH_OUT_OF_CFG = "fetch_out_of_cfg"
    BUDGET_EXCEEDED = "budget_exceeded"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    NATIVE_MISMATCH = "native_mismatch"
    CFG_INCOMPLETE = "cfg_incomplete"
    FOREIGN_REFUSAL = "foreign_refusal"
    DECODE_MISMATCH = "decode_mismatch"
    ENTRY_SEED_UNBOUND = "entry_seed_unbound"
    DECLARED_AUTHORITY_STALE = "declared_authority_stale"
    BOOT_NOT_REPRODUCED = "boot_not_reproduced"
    NATIVE_EFFECT_UNPROVEN = "native_effect_unproven"
    INDUCTION_NONCONVERGED = "induction_nonconverged"
    CONSUMED_SURFACE_STALE = "consumed_surface_stale"
    INSTRUCTION_STATE_CONFLICT = "instruction_state_conflict"


class InvariantStatus(Enum):
    """Whole-invariant outcome; declared-entry conditional, never admission."""

    PROVEN_CONDITIONAL = "proven_conditional"
    REFUSED = "refused"


@dataclass(frozen=True, slots=True)
class Obligation:
    """One open typed obligation at an exact native coordinate."""

    kind: ObligationKind
    function_addr: int
    instruction_addr: int | None
    detail: str = ""


@dataclass(frozen=True, slots=True)
class StoreJudgement:
    """One raw STORE bound to its judged envelope and verdict."""

    function_addr: int
    instruction_addr: int
    space: MemSpace
    logical_segment: str | None
    width: int
    offset: int | None
    segment_value: int | None
    envelope: tuple[int, int] | None
    verdict: Verdict


@dataclass(frozen=True, slots=True)
class CallJudgement:
    """One near CALL edge and its discharged selector/closure obligations."""

    function_addr: int
    callsite_addr: int
    target_addr: int | None
    preserved: tuple[str, ...]
    verdict: Verdict


@dataclass(frozen=True, slots=True)
class Cohort:
    """Closed five-stage accounting for one evidence cohort."""

    raw: int
    classified: int
    materialized: int
    failures: int


@dataclass(frozen=True, slots=True)
class DeclaredSelectorInstructionState8616:
    """Incoming selector state recorded before one CALL's row effect.

    ``artifact``/``block``/``instruction`` are the exact retained object
    identities belonging to the root link or a consumed callee surface —
    never address-keyed copies. ``selectors`` is the sorted immutable
    ``(name, value)`` view of the converged incoming segment constants.
    """

    artifact: IRFunctionArtifact
    block: IRBlock
    instruction: IRInstr
    selectors: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class _SelectorIdentityIndex8616:
    """Immutable derived identity lookup; certificate tuples remain authoritative."""

    states: Mapping[tuple[int, int], DeclaredSelectorInstructionState8616 | None]
    surfaces: Mapping[int, tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact] | None]


@dataclass(frozen=True, slots=True)
class DeclaredSegmentInvariant:
    """Typed conditional selector invariant receipt, never an admission.

    ``project``/``source``/``root_link`` retain the exact supplied authority:
    a canonical proof keeps the consumed :class:`DeclaredFunctionEntryLink8616`
    so later callsite consumption revalidates current authority against the
    identical root surface. Refusals may leave them ``None`` (foreign input)
    or partially bound (refusal after authentication began).
    """

    status: InvariantStatus
    stores: Cohort
    controls: Cohort
    surfaces: Cohort
    obligations: tuple[Obligation, ...]
    store_rows: tuple[StoreJudgement, ...]
    call_edges: tuple[CallJudgement, ...]
    terminal_edges: tuple[CallJudgement, ...]
    fetched_span_count: int
    bound_entry_selectors: Mapping[str, int]
    work_units: int
    shared_work_units: int
    declared_entry: int
    admission: DeclaredFunctionEntryAdmission8616 | None
    control_geometry: Cohort = Cohort(0, 0, 0, 0)
    geometry_rows: tuple[ControlCheck8616, ...] = ()
    consumed_surfaces: int = 0
    project: object = None
    source: Real16InvocationSource8616 | None = None
    root_link: DeclaredFunctionEntryLink8616 | None = None
    instruction_states: tuple[DeclaredSelectorInstructionState8616, ...] = ()
    consumed_pairs: tuple[
        tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact], ...
    ] = ()
    scoped_call_preservations: tuple[EntryDomainCallPreservation8616, ...] = ()
    _identity_index: _SelectorIdentityIndex8616 | None = field(
        init=False, repr=False, compare=False, default=None,
    )

    def __post_init__(self) -> None:
        """Rebuild charged immutable lookup from the authoritative retained tuples."""
        units = len(self.instruction_states) + len(self.consumed_pairs) + int(self.root_link is not None)
        budget = _Budget(float("inf"), _SHARED_WORK_LIMIT_8616)
        if not budget.charge(units, self.declared_entry):
            object.__setattr__(self, "status", InvariantStatus.REFUSED)
            object.__setattr__(self, "obligations", self.obligations + tuple(budget.obligations))
        else:
            object.__setattr__(self, "_identity_index", _build_selector_identity_index_8616(self))
        object.__setattr__(self, "work_units", self.work_units + units)
        object.__setattr__(self, "shared_work_units", budget.shared_units())


@dataclass(frozen=True, slots=True)
class DeclaredSelectorCallsite8616:
    """Authenticated selector capability for one bound near-call edge.

    Carries pure selector evidence only — incoming CS, the decoded native
    target and the native continuation. It asserts nothing about stack,
    return offset, GP or memory effects; those stay ordinary obligations of
    the full invocation route.
    """

    scope: DeclaredSegmentInvariant
    block: IRBlock
    instruction: IRInstr
    callsite_addr: int
    target_addr: int
    next_addr: int
    incoming_cs: int


@dataclass(frozen=True, slots=True)
class _SharedNativeSurvey8616:
    """One canonical classification retained under the existing source snapshot."""

    boundary: ExactFunctionRangeBoundary8616
    artifact: IRFunctionArtifact
    survey: NativeEffectSurvey8616
    metadata: tuple[object, ...]


def _survey_metadata_8616(survey: NativeEffectSurvey8616) -> tuple[object, ...]:
    """Detach every survey field consumed by sparse solving and recording."""
    return (survey.instruction_addrs, survey.expected_addrs, survey.census_covered,
            survey.raw, survey.classified, survey.unclassified, survey.segment_writes,
            survey.segment_identity_transfer,
            tuple((id(row.block), tuple(id(item) for item in row.rows),
                   tuple(id(item) for item in row.record_rows)) for row in survey.selector_blocks))


def _survey_metadata_work_8616(survey: NativeEffectSurvey8616) -> int:
    """Count the actual sparse row/header visits needed for metadata capture."""
    return 9 + sum(1 + len(row.rows) + len(row.record_rows) for row in survey.selector_blocks)


def _shared_surveys_current_8616(budget: _Budget, head: int) -> bool:
    """Check all retained classifications without replacing their first snapshot."""
    for product in budget.surveys.values():
        if not budget.charge(_survey_metadata_work_8616(product.survey), head):
            return False
        if product.metadata != _survey_metadata_8616(product.survey):
            return False
    return True


class _Budget:
    """Local work ledger also charging the configured shared request."""

    def __init__(self, deadline: float, limit: int) -> None:
        self.surveys: dict[tuple[int, int], _SharedNativeSurvey8616] = {}
        self.deadline = deadline
        self.limit = limit
        self.units = 0
        self.obligations: list[Obligation] = []

    def charge(self, units: int, head: int) -> bool:
        """Charge structural units privately AND to the ambient census scope.

        Reuses the ambient ``segment_call_dependency_traversal_scope_8616``
        context: charges land on the shared ``census_work_units`` ledger,
        the configured shared cap is honored, and any earlier ambient
        ``census_deadline`` tightens (never renews) this budget's deadline.
        """
        self.units += units
        exceeded = self.units > self.limit
        ambient_deadline = None
        with segment_call_dependency_traversal_scope_8616() as traversal:
            traversal.census_work_units += units
            exceeded = exceeded or traversal.census_work_units > traversal.census_work_limit
            ambient_deadline = traversal.census_deadline
        if exceeded:
            self.obligations.append(Obligation(ObligationKind.BUDGET_EXCEEDED, head, None))
            return False
        effective = self.deadline
        if ambient_deadline is not None:
            effective = min(effective, ambient_deadline)
        if time.monotonic() > effective:
            self.obligations.append(Obligation(ObligationKind.DEADLINE_EXCEEDED, head, None))
            return False
        return True

    def shared_units(self) -> int:
        """Return the ambient shared work ledger for honest cost reporting."""
        with segment_call_dependency_traversal_scope_8616() as traversal:
            units: int = traversal.census_work_units
            return units


def _opcode(encoded: bytes) -> int | None:
    """Return the first non-legacy-prefix opcode byte, or ``None``."""
    index = 0
    while index < len(encoded) and encoded[index] in _LEGACY_PREFIXES:
        index += 1
    return encoded[index] if index < len(encoded) else None


def _implicit_segment_effect(encoded: bytes) -> str | None:
    """Return the implicitly affected segment register name, if any.

    Covers implicit CS transfer (far call/jump/ret, int, iret), implicit
    segment loads (lds/les), pop/mov segment forms, and FF /3,/5 far
    modrm forms. A 0x67 in the prefix run widens addressing: those rows
    are refused earlier by the STORE path, but a far call still lands
    here through its opcode. Anything not listed has no segment effect.
    """
    index = 0
    while index < len(encoded) and encoded[index] in _LEGACY_PREFIXES:
        index += 1
    if index >= len(encoded):
        return None
    opcode = encoded[index]
    if opcode == 0x0F and index + 1 < len(encoded):
        second = encoded[index + 1]
        if second in _POP_FSGS:
            return _POP_FSGS[second]
        if second == 0x34 or second == 0x35:  # sysenter/sysexit
            return "cs"
        return None
    if opcode == 0xFF and index + 1 < len(encoded):
        reg = (encoded[index + 1] >> 3) & 7
        return _FAR_MODRM.get(reg)
    return _SEGMENT_WRITE_OPCODES.get(opcode)


def _near_terminal_target(encoded: bytes, address: int) -> int | None:
    """Decode a direct near JMP/Jcc target from bound bytes, else ``None``."""
    size = len(encoded)
    if size == 3 and encoded[0] == 0xE9:
        return address + size + int.from_bytes(encoded[1:3], "little", signed=True)
    if size == 2 and (encoded[0] == 0xEB or 0x70 <= encoded[0] <= 0x7F):
        return address + size + int.from_bytes(encoded[1:2], "little", signed=True)
    if size == 4 and encoded[0] == 0x0F and 0x80 <= encoded[1] <= 0x8F:
        return address + size + int.from_bytes(encoded[2:4], "little", signed=True)
    return None


def _declared_seed(
    admission: DeclaredFunctionEntryAdmission8616,
) -> dict[str, int] | None:
    """Project the typed declaration's segment lanes; absent lanes unknown."""
    spec = admission.spec
    registers = spec.registers
    if not isinstance(registers, tuple):
        return None
    seed: dict[str, int] = {}
    for name, value in registers:
        if (
            type(name) is str and type(value) is int
            and 0 <= value <= _WORD_LIMIT and name in SEGMENT_REGISTERS
        ):
            seed[name] = value
    if type(spec.entry_segment) is not int or not 0 <= spec.entry_segment <= _WORD_LIMIT:
        return None
    seed["cs"] = spec.entry_segment
    return seed


def _authenticate_authority(
    project: object,
    source: Real16InvocationSource8616,
    admission: DeclaredFunctionEntryAdmission8616,
    head: int,
    *,
    recompute_boot: bool = True,
) -> Obligation | None:
    """Rebind the declared premise to current source/module/environment.

    Pure authentication subset of the canonical declared-entry seed owner:
    the retained admission must revalidate against the current single-chunk
    module bytes, the live loader must return identical module bytes, the
    declared load segment must match the evidence segment, an environment
    digest must exist, and the recompute callback must reproduce an equal
    boot object. Anything absent or stale is a typed refusal.
    """
    if type(admission) is not DeclaredFunctionEntryAdmission8616:
        return Obligation(ObligationKind.DECLARED_AUTHORITY_STALE, head, None,
                          "foreign admission type")
    recompute = source.boot_recompute
    if recompute is None or not callable(recompute):
        return Obligation(ObligationKind.BOOT_NOT_REPRODUCED, head, None)
    if recompute_boot:
        recomputed = recompute(source.boot)
        if type(recomputed) is not type(source.boot) or recomputed != source.boot:
            return Obligation(ObligationKind.BOOT_NOT_REPRODUCED, head, None)
    evidence = _invocation_boot_evidence_8616(source.boot)
    if not isinstance(evidence, _BootEvidence8616):
        return Obligation(ObligationKind.DECLARED_AUTHORITY_STALE, head, None,
                          f"boot evidence: {evidence}")
    spec = admission.spec
    chunks = evidence.image.chunks
    if len(chunks) != 1 or chunks[0][0] != evidence.load_segment << _SHIFT:
        return Obligation(ObligationKind.DECLARED_AUTHORITY_STALE, head, None,
                          "module chunk mismatch")
    base, module = chunks[0]
    if (
        evidence.environment_digest is None
        or not revalidate_declared_function_entry_8616(
            admission, source=evidence.source, loaded_module=module,
            environment_sha256=evidence.environment_digest,
        )
    ):
        return Obligation(ObligationKind.DECLARED_AUTHORITY_STALE, head, None,
                          "revalidation failed")
    if _loaded_bytes_8616(project, base, len(module)) != module:
        return Obligation(ObligationKind.DECLARED_AUTHORITY_STALE, head, None,
                          "live module bytes differ")
    if spec.load_segment != evidence.load_segment:
        return Obligation(ObligationKind.DECLARED_AUTHORITY_STALE, head, None,
                          "load segment mismatch")
    return None


def _supplied_root_surface_failure(
    head: int,
    boundary: ExactFunctionRangeBoundary8616,
    artifact: IRFunctionArtifact,
) -> Obligation | None:
    """Authenticate the supplied root's owned types and exact head identity."""
    if (
        type(boundary) is not ExactFunctionRangeBoundary8616
        or type(artifact) is not IRFunctionArtifact
        or boundary.addr != head
    ):
        return Obligation(ObligationKind.DECLARED_AUTHORITY_STALE, head, None,
                          "supplied root surface mismatch")
    return None


def _resolve_native_surface(
    project: object,
    head: int,
    supplied: tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact] | None = None,
) -> tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact] | Obligation:
    """Resolve fresh native input or authenticate the identical supplied root."""
    if supplied is None:
        boundary = _exact_boundary_for_8616(project, head)
        if boundary is None:
            return Obligation(ObligationKind.CALLEE_MISSING, head, None, "no closed boundary")
        artifact = real16_native_census_import_8616(project, boundary)
        if type(artifact) is not IRFunctionArtifact:
            return Obligation(ObligationKind.CALLEE_MISSING, head, None, "native import refused")
    else:
        boundary, artifact = supplied
        supplied_failure = _supplied_root_surface_failure(head, boundary, artifact)
        if supplied_failure is not None:
            return supplied_failure
    return boundary, artifact


def _scoped_native_projection_8616(
    head: int, artifact: IRFunctionArtifact, boundary: ExactFunctionRangeBoundary8616,
    scoped: EntryDomainCallPreservation8616 | None,
) -> bool | Obligation:
    """Authenticate a conditional CFG without changing its raw native census."""
    if scoped is None:
        return False
    callee = scoped.callee
    if callee is None or callee.coverage.artifact is not artifact or callee.coverage.boundary is not boundary:
        return Obligation(ObligationKind.CFG_INCOMPLETE, head, None, "foreign scoped callee")
    view = callee.coverage.scoped_view
    if not isinstance(view, ScopedNearReturnContinuationView8616) or not scoped.complete_for(scoped.required_scope):
        return Obligation(ObligationKind.CFG_INCOMPLETE, head, None, "unproved scoped callee")
    projection = view.cfg_projection_for(callee.state.invocation_scope)
    if projection is None or any(
            rows for addr, rows in projection.pending.items()
            if addr not in projection.unreachable_block_addrs):
        return Obligation(ObligationKind.CFG_INCOMPLETE, head, None, "unsupported scoped census")
    return True


def _prepare_selector_native_rebind_8616(
    project: object, boundary: ExactFunctionRangeBoundary8616,
    artifact: IRFunctionArtifact,
) -> ScopedNativeRebindFacts8616:
    """Reproduce the consumed representation through its canonical producer.

    Registry identity selects representation only; fresh native rederivation
    and the full subsequent graph/census seal supply its authority. Universal
    registry artifacts include proved control normalization. Raw
    declared/scoped surfaces keep their raw census producer; universal surfaces
    re-run ordinary native import and retain its complete detached graph.
    """
    from .function_ir_registry import FunctionIRArtifactVerdict8616, registered_function_ir_artifact_8616
    from .source_graph_binding import capture_immutable_source_graph_facts_8616
    from .vex_import import build_x86_16_ir_function_artifact

    registered = registered_function_ir_artifact_8616(project, artifact.function_addr)
    if (registered.artifact is not artifact
            or registered.verdict is not FunctionIRArtifactVerdict8616.PROVEN):
        return _prepare_scoped_native_rebind_8616(project, boundary, caller=artifact)
    rederived = build_x86_16_ir_function_artifact(project, boundary)
    return ScopedNativeRebindFacts8616(
        boundary, capture_immutable_source_graph_facts_8616(
            rederived.function_addr, rederived.blocks, rederived.refusals),
        boundary.reachable_instruction_addrs, None,
    )


def _native_blocks(
    project: object,
    head: int,
    budget: _Budget,
    declared_spec: DeclaredFunctionEntrySpec8616 | None = None,
    supplied: tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact] | None = None,
    scoped: EntryDomainCallPreservation8616 | None = None,
) -> tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact, ScopedNativeSurfaceSnapshot8616] | Obligation:
    """Resolve the closed native boundary and fresh-bound raw artifact.

    When ``supplied`` carries the canonical root pair, the exact consumed
    objects are used — never a substitute root import — while every native,
    fetch and CFG check below still rebinds them under the live producer.
    The full row census is deferred to ``_survey_prepared_blocks_8616`` so
    a callee refusal during machine preparation never pays classification
    units for rows no consumer reads; the earliest source snapshot is still
    captured here, before any callback can run.
    """
    surface = _resolve_native_surface(project, head, supplied)
    if isinstance(surface, Obligation):
        return surface
    boundary, artifact = surface
    if declared_spec is not None and (
        boundary.addr != declared_spec.range_start
        or boundary.addr + boundary.size != declared_spec.range_end
    ):
        return Obligation(ObligationKind.DECLARED_AUTHORITY_STALE, head, None,
                          "boundary outside declared range")
    snapshot = _capture_scoped_native_surface_8616(boundary, artifact)
    facts = _prepare_selector_native_rebind_8616(project, boundary, artifact)
    if _scoped_native_rebind_failure_8616(boundary, artifact, facts, snapshot) is not None:
        return Obligation(ObligationKind.NATIVE_MISMATCH, head, None)
    projection = _scoped_native_projection_8616(head, artifact, boundary, scoped)
    if isinstance(projection, Obligation):
        return projection
    if {block.addr for block in artifact.blocks} != boundary.block_addrs_set or (
        not projection and not closed_ir_boundary_cfg_8616(boundary, artifact)
    ):
        return Obligation(ObligationKind.CFG_INCOMPLETE, head, None)
    if any(
        refusal.kind != _PENDING_TERMINAL and not (
            projection and refusal.kind == NEAR_RETURN_CONTINUATION_PENDING_KIND_8616)
        for block in artifact.blocks for refusal in block.refusals
    ):
        return Obligation(ObligationKind.FOREIGN_REFUSAL, head, None)
    # Preserve admission before decode/callee callbacks without billing the
    # deferred row classification. It still shares both existing ledgers.
    if not budget.charge(0, head):
        return budget.obligations[-1]
    return boundary, artifact, snapshot


def _survey_prepared_blocks_8616(
    head: int,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    budget: _Budget,
) -> NativeEffectSurvey8616 | Obligation:
    """Charge and classify the full native census after machine preparation.

    Deferred from ``_native_blocks`` past ``_prepare_machine``: a refused
    callee premise aborts induction before this point, so classifying the
    rows earlier would charge work no consumer reads against the shared
    ledger. The census contract is unchanged — every block row classified,
    exact reachable-address coverage and zero unclassified rows required.
    The classified rows are the same retained artifact objects; a mutation
    a phase-A callback slipped in is still caught by the earliest snapshot
    and the final consumed-surface rebind, so deferral cannot weaken the
    mutation guard.
    """
    product = budget.surveys.get((id(boundary), id(artifact)))
    if product is not None:
        if not budget.charge(_survey_metadata_work_8616(product.survey), head):
            return budget.obligations[-1]
        if (product.boundary is not boundary or product.artifact is not artifact
                or product.metadata != _survey_metadata_8616(product.survey)):
            return Obligation(ObligationKind.CONSUMED_SURFACE_STALE, head, None, "shared survey changed")
        survey = product.survey
        if survey.census_covered is not True or survey.unclassified:
            return Obligation(ObligationKind.NATIVE_EFFECT_UNPROVEN, head, None, "shared census incomplete")
        return survey
    if not budget.charge(sum(len(block.instrs) for block in artifact.blocks), head):
        return budget.obligations[-1]
    survey = survey_native_effects_8616(
        artifact.blocks, boundary.reachable_instruction_addrs)
    if survey.census_covered is not True or survey.unclassified:
        return Obligation(ObligationKind.NATIVE_EFFECT_UNPROVEN, head, None,
                          "incomplete native row classification")
    return survey


def _decoded_block(
    project: object, head: int, block_addr: int,
    boundary: ExactFunctionRangeBoundary8616, budget: _Budget,
    image: _BootImageSurface8616,
) -> dict[int, tuple[int, bytes]] | Obligation:
    """Three-way bind one block's fetched instruction census."""
    decoded = decoded_block_instructions_8616(project, block_addr, opt_level=0)
    if not budget.charge(len(decoded), head):
        return budget.obligations[-1]
    machine: dict[int, tuple[int, bytes]] = {}
    for raw in decoded:
        normalized = _normalize_instruction_8616(raw)
        encoded = None if normalized is None else _instruction_bytes_8616(raw)
        if normalized is None or encoded is None or len(encoded) != normalized[1]:
            return Obligation(ObligationKind.DECODE_MISMATCH, head, block_addr)
        if normalized[0] in machine:
            return Obligation(ObligationKind.DECODE_MISMATCH, head, block_addr)
        machine[normalized[0]] = (normalized[1], encoded)
    partitioned = _partition_extent(machine, boundary, block_addr, head)
    if isinstance(partitioned, Obligation):
        return partitioned
    return _bind_bytes(project, partitioned, head, image)


class _NativeBlockExtent8616(Protocol):
    """Decoded third-party frontend block coordinates consumed by partitioning."""

    addr: int
    size: int


def _partition_extent(
    machine: Mapping[int, tuple[int, bytes]],
    boundary: ExactFunctionRangeBoundary8616,
    block_addr: int,
    head: int,
) -> dict[int, tuple[int, bytes]] | Obligation:
    """Select and require exact contiguous cover of the owned block extent."""
    # Frontend inventories retain third-party decoded block objects.
    native_extents = cast(tuple[_NativeBlockExtent8616, ...], boundary.blocks)
    extents = tuple(b for b in native_extents if b.addr == block_addr)
    if len(extents) != 1 or type(extents[0].size) is not int:
        return Obligation(ObligationKind.DECODE_MISMATCH, head, block_addr)
    if extents[0].size <= 0:
        return Obligation(ObligationKind.DECODE_MISMATCH, head, block_addr)
    end = block_addr + extents[0].size
    selected = {
        addr: row for addr, row in machine.items() if block_addr <= addr < end
    }
    cursor = block_addr
    for addr, (size, _encoded) in sorted(selected.items()):
        if addr != cursor:
            return Obligation(ObligationKind.DECODE_MISMATCH, head, block_addr)
        cursor = addr + size
    if cursor != end:
        return Obligation(ObligationKind.DECODE_MISMATCH, head, block_addr)
    return selected


def _bind_bytes(
    project: object,
    selected: Mapping[int, tuple[int, bytes]],
    head: int,
    image: _BootImageSurface8616,
) -> dict[int, tuple[int, bytes]] | Obligation:
    """Three-way bind: decoded bytes == image slice == live loader bytes."""
    for addr, (size, encoded) in sorted(selected.items()):
        if not any(r.contains(addr, size) for r in image.code_ranges):
            return Obligation(ObligationKind.DECODE_MISMATCH, head, addr, "outside code ranges")
        if _image_slice_8616(image, addr, size) != encoded:
            return Obligation(ObligationKind.NATIVE_MISMATCH, head, addr, "image bytes")
        if _loaded_bytes_8616(project, addr, size) != encoded:
            return Obligation(ObligationKind.NATIVE_MISMATCH, head, addr, "loader bytes")
    return dict(selected)


def _join_entry(
    head: int,
    block_addr: int,
    entry: Mapping[str, int],
    preds: list[int],
    block_exit: Mapping[int, dict[str, int]],
) -> dict[str, int]:
    """Must-meet incoming segment constants; disagreement or absence drops."""
    if block_addr == head:
        incoming = dict(entry)
        for name in tuple(incoming):
            for pred in preds:
                pred_state = block_exit.get(pred)
                if pred_state is not None and pred_state.get(name) != incoming[name]:
                    incoming.pop(name)
                    break
        return incoming
    incoming = {}
    for name in SEGMENT_REGISTERS:
        values = {
            block_exit[p][name]
            for p in preds
            if name in block_exit.get(p, {})
        }
        if len(values) == 1 and all(
            p in block_exit and name in block_exit[p] for p in preds
        ):
            incoming[name] = next(iter(values))
    return incoming


def _induction_cfg_8616(
    head: int, artifact: IRFunctionArtifact, boundary: ExactFunctionRangeBoundary8616,
    scoped: EntryDomainCallPreservation8616 | None, obligations: list[Obligation],
) -> tuple[dict[int, IRBlock], tuple[tuple[int, int], ...]] | None:
    """Consume authenticated live edges while retaining the complete raw source."""
    blocks = {b.addr: b for b in artifact.blocks}
    edges = boundary.successor_edges
    if scoped is not None:
        # Keep the complete raw census above. Only the authenticated effective
        # CFG controls which raw rows participate in this conditional induction.
        callee = scoped.callee
        assert callee is not None
        view = callee.coverage.scoped_view
        assert isinstance(view, ScopedNearReturnContinuationView8616)
        projection = view.cfg_projection_for(callee.state.invocation_scope)
        if projection is None or any(
            rows for addr, rows in projection.pending.items()
            if addr not in projection.unreachable_block_addrs):
            obligations.append(Obligation(ObligationKind.CFG_INCOMPLETE, head, None))
            return None
        active = set(projection.successors)
        if (active | projection.unreachable_block_addrs != blocks.keys()
                or active & projection.unreachable_block_addrs
                or head not in active):
            obligations.append(Obligation(ObligationKind.CFG_INCOMPLETE, head, None))
            return None
        blocks = {addr: block for addr, block in blocks.items() if addr in active}
        edges = tuple((source, target) for source, targets in projection.successors.items()
                      for target in targets)
    return blocks, tuple(edges)


def _induce(
    project: object,
    head: int,
    entry: Mapping[str, int],
    *,
    budget: _Budget,
    image: _BootImageSurface8616,
    fetched: set[tuple[int, int]],
    stores: list[StoreJudgement],
    calls: list[CallJudgement],
    terminals: list[CallJudgement],
    geometry: list[ControlCheck8616],
    obligations: list[Obligation],
    discovered: list[tuple[int, dict[str, int], int]],
    consumed: dict[tuple[int, int], tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact]],
    states: dict[tuple[int, int, int], DeclaredSelectorInstructionState8616],
    snapshots: dict[tuple[int, int], ScopedNativeSurfaceSnapshot8616],
    declared_spec: DeclaredFunctionEntrySpec8616 | None = None,
    supplied: tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact] | None = None,
    scoped_calls: ScopedSelectorCollection8616 | None = None,
    scoped: EntryDomainCallPreservation8616 | None = None,
) -> bool:
    """Run the constant-segment induction over one native-bound function.

    Every block's decoded census is byte-bound before any row is trusted;
    per-instruction transfer keeps only agreeing segment constants: explicit
    or implicit segment writes, unclosed transfers and unproven call edges
    kill the affected segment and record the precise typed obligation.
    Each consumed (boundary, artifact) pair is retained in ``consumed``
    keyed on exact object identity — never boundary address — so the
    post-callback rebind can re-derive it. Incoming per-instruction selector
    states land in ``states`` keyed on the same exact identities. The full
    native row census is charged and classified only after machine
    preparation succeeds, so a refused callee premise never pays for rows
    no consumer reads.
    """
    native = _native_blocks(
        project, head, budget, declared_spec=declared_spec, supplied=supplied, scoped=scoped)
    if isinstance(native, Obligation):
        obligations.append(native)
        return False
    boundary, artifact, snapshot = native
    # Different selector seeds may re-induce the same owned pair. Keep the
    # earliest source facts so a later callback cannot replace its baseline.
    snapshots.setdefault((id(boundary), id(artifact)), snapshot)
    consumed[id(boundary), id(artifact)] = (boundary, artifact)
    cfg = _induction_cfg_8616(head, artifact, boundary, scoped, obligations)
    if cfg is None:
        return False
    blocks, edges = cfg
    prepared = _prepare_machine(
        project, head, artifact, boundary, budget, image, fetched,
        obligations, consumed, scoped_calls=scoped_calls, active_blocks=frozenset(blocks),
        snapshots=snapshots)
    if prepared is None:
        return False
    block_machines, machine_bytes, resolved = prepared
    survey = _survey_prepared_blocks_8616(head, artifact, boundary, budget)
    if isinstance(survey, Obligation):
        obligations.append(survey)
        return False
    predecessors: dict[int, list[int]] = {addr: [] for addr in blocks}
    for source_addr, target_addr in edges:
        if source_addr in predecessors and target_addr in predecessors:
            predecessors[target_addr].append(source_addr)
    stabilized = _stabilize(
        head, entry, blocks, predecessors, machine_bytes, resolved, budget,
        survey=survey)
    if stabilized is None:
        # Preserve the original cause: a budget/deadline exhaustion recorded
        # by charge() must not be mislabeled as a convergence failure.
        if not budget.obligations:
            obligations.append(Obligation(
                ObligationKind.INDUCTION_NONCONVERGED, head, None,
                "bounded fixpoint exhausted without a verified solution"))
        return False
    block_exit, window_refused = stabilized
    if not budget.charge(sum(len(item.record_rows) for item in survey.selector_blocks), head):
        return False
    recorded = _record_instructions(
        head, blocks, predecessors, machine_bytes, resolved,
        window_refused, block_exit, entry,
        stores=stores, calls=calls, terminals=terminals, geometry=geometry,
        block_machines=block_machines, obligations=obligations, discovered=discovered, budget=budget,
        artifact=artifact, states=states, survey=survey, scoped=scoped,
    )
    return recorded


def _prepare_machine(
    project: object,
    head: int,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    budget: _Budget,
    image: _BootImageSurface8616,
    fetched: set[tuple[int, int]],
    obligations: list[Obligation],
    consumed: dict[tuple[int, int], tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact]],
    *, scoped_calls: ScopedSelectorCollection8616 | None = None,
    active_blocks: frozenset[int] | None = None,
    snapshots: dict[tuple[int, int], ScopedNativeSurfaceSnapshot8616] | None = None,
) -> tuple[
    dict[int, dict[int, tuple[int, bytes]]],
    dict[int, bytes],
    dict[int, tuple[int, frozenset[str]]],
] | None:
    """Byte-bound decoded census plus phase-A callsite closure resolution.

    Phase-A work is callsite-state independent, so it runs exactly once;
    the callsite-CS window check is deferred to the stabilized induction.
    Callee premise surfaces are retained in ``consumed`` alongside the
    induced surfaces so the final rebind covers them too. The decoded fetch
    census stays complete, but a refused callee stops further closure work:
    this whole-surface proof cannot succeed and must not consume the shared
    budget needed by subsequent invocation-local proof attempts — and the
    deferred row census is never charged for it either.
    """
    block_machines: dict[int, dict[int, tuple[int, bytes]]] = {}
    for block in artifact.blocks:
        decoded = _decoded_block(project, head, block.addr, boundary, budget, image)
        if isinstance(decoded, Obligation):
            obligations.append(decoded)
            return None
        block_machines[block.addr] = decoded
        for addr, (size, _encoded) in decoded.items():
            fetched.add((addr, size))
    machine_bytes = {
        addr: encoded
        for machine in block_machines.values()
        for addr, (_size, encoded) in machine.items()
    }
    resolved: dict[int, tuple[int, frozenset[str]]] = {}
    # Only universal selector effects can be shared across caller states.
    # This table dies with this preparation; the final native seal retains
    # each first consumed surface even if a later callback changes it.
    universal: dict[int, frozenset[str]] = {}
    for block in artifact.blocks:
        if active_blocks is not None and block.addr not in active_blocks:
            continue
        for instr in block.instrs:
            if instr.op == "CALL" and type(instr.addr) is int:
                resolved[instr.addr] = _resolve_callsite(
                    project, head, instr, machine_bytes.get(instr.addr),
                    budget, obligations, consumed, scoped_calls=scoped_calls,
                    universal=universal, snapshots=snapshots,
                )
                if obligations or budget.obligations:
                    return None
    return block_machines, machine_bytes, resolved


def _instruction_encoding(
    machine_bytes: Mapping[int, bytes], instruction: IRInstr,
) -> bytes | None:
    """Return bound native bytes or no evidence for an unbound row address."""
    address = instruction.addr
    return None if address is None else machine_bytes.get(address)


def _transfer_block(
    head: int,
    block_addr: int,
    rows: Mapping[int, tuple[IRInstr, ...]],
    predecessors: Mapping[int, list[int]],
    machine_bytes: Mapping[int, bytes],
    resolved: Mapping[int, tuple[int, frozenset[str]]],
    window_refused: AbstractSet[int],
    block_exit: Mapping[int, dict[str, int]],
    entry: Mapping[str, int],
) -> dict[str, int]:
    """Recompute one block's full induction equation from current exits."""
    state = dict(_join_entry(
        head, block_addr, entry, predecessors[block_addr], block_exit))
    for instr in rows[block_addr]:
        state = _transfer_skeleton(
            instr, state, _instruction_encoding(machine_bytes, instr),
            resolved, window_refused,
        )
    return state


def _selector_rows_from_survey_8616(
    head: int,
    blocks: Mapping[int, IRBlock],
    survey: NativeEffectSurvey8616,
    budget: _Budget,
) -> dict[int, tuple[IRInstr, ...]] | None:
    """Charge sparse block projection consumption without repeating the census."""
    if not budget.charge(len(survey.selector_blocks), head):
        return None
    selector_rows: dict[int, tuple[IRInstr, ...]] = {}
    for item in survey.selector_blocks:
        address = item.block.addr
        if address not in blocks:
            continue
        same_owner = blocks.get(address) is item.block
        if not same_owner or address in selector_rows:
            return None
        selector_rows[address] = item.rows
    return selector_rows if selector_rows.keys() == blocks.keys() else None


def _stabilize(
    head: int,
    entry: Mapping[str, int],
    blocks: Mapping[int, IRBlock],
    predecessors: Mapping[int, list[int]],
    machine_bytes: Mapping[int, bytes],
    resolved: Mapping[int, tuple[int, frozenset[str]]],
    budget: _Budget,
    *,
    survey: NativeEffectSurvey8616,
) -> tuple[dict[int, dict[str, int]], set[int]] | None:
    """Iterate the must-fixpoint plus callsite-window checks until stable.

    Each discovered window failure only drops facts, so the outer loop
    converges within ``call count + 1`` passes. The bounded inner round cap
    is NOT a proof: on exit the final equations are verified exactly —
    every block's join (including the root's backedges) replayed against
    the recorded exits — and ``None`` is returned when the candidate
    solution fails its own equations or the charge budget runs out.
    """
    # The mandatory full census already classified every row and emitted
    # this exact sparse projection. Traverse only its block headers here;
    # full STORE/fetch/control/call recording below remains unchanged.
    selector_rows = _selector_rows_from_survey_8616(head, blocks, survey, budget)
    if selector_rows is None:
        return None
    transfer_work = sum(1 + len(rows) for rows in selector_rows.values())
    window_refused: set[int] = set()
    block_exit: dict[int, dict[str, int]] = {}
    settled = False
    for _pass in range(len(resolved) + 2):
        if not _fixpoint(
            head, entry, selector_rows, predecessors, machine_bytes,
            resolved, window_refused, block_exit, transfer_work, budget,
        ):
            return None
        if not budget.charge(transfer_work, head):
            return None
        new_refusals = _window_failures(
            head, entry, selector_rows, predecessors, machine_bytes,
            resolved, window_refused, block_exit)
        if not new_refusals:
            settled = True
            break
        window_refused |= new_refusals
    if not settled:
        return None
    # Final equation verification: replay every block's induction equation
    # (join over predecessors — the root's backedge meet included — plus the
    # per-instruction transfer) and require exact agreement with the
    # recorded exits. Bounded iteration alone is not convergence evidence.
    if not budget.charge(transfer_work, head):
        return None
    for block_addr in sorted(blocks):
        replayed = _transfer_block(
            head, block_addr, selector_rows, predecessors, machine_bytes,
            resolved, window_refused, block_exit, entry)
        if replayed != block_exit.get(block_addr):
            return None
    return block_exit, window_refused


def _fixpoint(
    head: int,
    entry: Mapping[str, int],
    rows: Mapping[int, tuple[IRInstr, ...]],
    predecessors: Mapping[int, list[int]],
    machine_bytes: Mapping[int, bytes],
    resolved: Mapping[int, tuple[int, frozenset[str]]],
    window_refused: AbstractSet[int],
    block_exit: dict[int, dict[str, int]],
    transfer_work: int,
    budget: _Budget,
) -> bool:
    """Charged bounded rounds; ``False`` when the cap or budget is hit."""
    for _round in range(len(rows) * 2 + 2):
        if not budget.charge(transfer_work, head):
            return False
        changed = False
        for block_addr in sorted(rows):
            state = _transfer_block(
                head, block_addr, rows, predecessors, machine_bytes,
                resolved, window_refused, block_exit, entry)
            if block_exit.get(block_addr) != state:
                block_exit[block_addr] = state
                changed = True
        if not changed:
            return True
    return False


def _window_failures(
    head: int,
    entry: Mapping[str, int],
    rows: Mapping[int, tuple[IRInstr, ...]],
    predecessors: Mapping[int, list[int]],
    machine_bytes: Mapping[int, bytes],
    resolved: Mapping[int, tuple[int, frozenset[str]]],
    window_refused: AbstractSet[int],
    block_exit: Mapping[int, dict[str, int]],
) -> set[int]:
    """Return callsites whose E8 target leaves the converged callsite CS."""
    failures: set[int] = set()
    for block_addr in sorted(rows):
        state = dict(_join_entry(
            head, block_addr, entry, predecessors[block_addr], block_exit))
        for instr in rows[block_addr]:
            if instr.op == "CALL" and type(instr.addr) is int:
                site = instr.addr
                if site in resolved and site not in window_refused and resolved[site][1]:
                    target, _preserved = resolved[site]
                    cs = state.get("cs")
                    if cs is None or not (
                        (cs << _SHIFT) <= target <= (cs << _SHIFT) + _WORD_LIMIT
                    ):
                        failures.add(site)
            state = _transfer_skeleton(
                instr, state, _instruction_encoding(machine_bytes, instr),
                resolved, window_refused,
            )
    return failures


def _record_control_geometry(
    head: int, block: IRBlock, instr: IRInstr, encoded: bytes | None,
    state: Mapping[str, int], resolved: Mapping[int, tuple[int, frozenset[str]]],
    checked: set[int], census: AbstractSet[int], geometry: list[ControlCheck8616],
    terminals: list[CallJudgement], budget: _Budget, obligations: list[Obligation],
    scoped: EntryDomainCallPreservation8616 | None = None,
) -> bool:
    """Consume all native control rows, including both conditional edges."""
    lane = classify_native_row_8616(instr).row_class
    if lane not in (NativeRowClass8616.CALL_EDGE, NativeRowClass8616.CONTROL):
        return True
    address = instr.addr
    if address is None:
        obligations.append(Obligation(ObligationKind.FETCH_OUT_OF_CFG, head, None,
                                      "control instruction address unbound"))
        return False
    if address in checked:
        return True
    checked.add(address)
    if not budget.charge(1, head):
        return False
    target = resolved[address][0] if address in resolved else None
    result = check_bound_control_8616(
        block, instr, b"" if encoded is None else encoded, state.get("cs"), target, census)
    if (scoped is not None and scoped.callee is not None
            and isinstance(scoped.callee.coverage.scoped_view, ScopedNearReturnContinuationView8616)
            and scoped.callee.state.invocation_scope is not None
            and block.addr in scoped.callee.coverage.scoped_view.proven_block_addrs):
        result = check_scoped_return_control_8616(
            scoped.callee.coverage.scoped_view, scoped.callee.state.invocation_scope,
            block, instr, b"" if encoded is None else encoded, state.get("cs"), census)
    geometry.append(result)
    if block.refusals:
        terminals.append(CallJudgement(
            head, result.addr, result.target, (),
            Verdict.REFUSED_UNCLOSED if result.verdict is ControlVerdict8616.REFUSED
            else Verdict.CLOSED,
        ))
    return _record_geometry_result(head, result, obligations)


def _record_geometry_result(
    head: int, result: ControlCheck8616, obligations: list[Obligation],
) -> bool:
    """A closed coordinate is not a callee return-state proof."""
    if result.verdict is ControlVerdict8616.REFUSED:
        obligations.append(Obligation(ObligationKind.FETCH_OUT_OF_CFG, head,
                                      result.addr, result.detail))
        return False
    return True


def _record_block_fallthrough(
    head: int, block: IRBlock, machine_bytes: Mapping[int, bytes],
    state: Mapping[str, int], checked: AbstractSet[int], census: AbstractSet[int],
    geometry: list[ControlCheck8616], budget: _Budget, obligations: list[Obligation],
) -> bool:
    """Bind the sole implicit edge of a native noncontrol terminal."""
    last = block.instrs[-1]
    address = last.addr
    if address is None:
        obligations.append(Obligation(ObligationKind.FETCH_OUT_OF_CFG, head, None,
                                      "terminal instruction address unbound"))
        return False
    if address in checked:
        return True
    if not budget.charge(1, head):
        return False
    cs = state.get("cs")
    result = check_block_fallthrough_8616(
        last_addr=address, last_size=len(machine_bytes.get(address, b"")),
        successors=block.successor_addrs, census_addrs=census,
        known_cs=-1 if cs is None else cs,
    )
    geometry.append(result)
    return _record_geometry_result(head, result, obligations)


def _record_fetch(
    head: int, instr: IRInstr, encoded: bytes | None,
    state: Mapping[str, int], seen: set[int],
    budget: _Budget, obligations: list[Obligation],
    *,
    covered: set[int] | None = None,
) -> bool:
    """Check each fetched head once and fuse its global census collection."""
    addr = instr.addr
    if type(addr) is not int:
        obligations.append(Obligation(ObligationKind.FETCH_OUT_OF_WINDOW, head, None,
                                      "instruction address unbound"))
        return False
    if addr in seen:
        return True
    seen.add(addr)
    if not budget.charge(1, head):
        return False
    check = check_instruction_fetch_8616(addr, encoded, state.get("cs"))
    if check.verdict is FetchVerdict8616.REFUSED:
        obligations.append(Obligation(ObligationKind.FETCH_OUT_OF_WINDOW, head, addr,
                                      check.detail))
        return False
    if covered is not None:
        covered.add(addr)
    return True


def _record_unknown_effect(
    head: int, instr: IRInstr, state: dict[str, int], obligations: list[Obligation],
) -> None:
    """Unknown native effects erase selector facts and retain their exact cause."""
    row = classify_native_row_8616(instr)
    if row.row_class is NativeRowClass8616.UNCLASSIFIED:
        obligations.append(Obligation(ObligationKind.NATIVE_EFFECT_UNPROVEN,
                                      head, instr.addr, row.detail))
        state.clear()


def _record_fetch_census(
    head: int, block_addr: int, expected: AbstractSet[int], seen: AbstractSet[int],
    budget: _Budget, obligations: list[Obligation],
) -> bool:
    """Every decoded head must have a consumed native fetch, with no extras."""
    if not budget.charge(len(expected), head):
        return False
    if expected != seen:
        obligations.append(Obligation(ObligationKind.DECODE_MISMATCH, head, block_addr,
                                      "decoded heads differ from consumed IR heads"))
        return False
    return True


def _finish_recorded_block(
    head: int, block: IRBlock, expected: AbstractSet[int], seen: AbstractSet[int],
    machine_bytes: Mapping[int, bytes], state: Mapping[str, int],
    checked: AbstractSet[int], census: AbstractSet[int], geometry: list[ControlCheck8616],
    budget: _Budget, obligations: list[Obligation],
) -> bool:
    """Close the per-block native census before publishing its continuation."""
    if not _record_fetch_census(head, block.addr, expected, seen, budget, obligations):
        return False
    return _record_block_fallthrough(
        head, block, machine_bytes, state, checked, census, geometry, budget, obligations)


def _record_incoming_instruction_state(
    head: int,
    artifact: IRFunctionArtifact,
    block: IRBlock,
    instruction: IRInstr,
    incoming_state: Mapping[str, int],
    states: dict[tuple[int, int, int], DeclaredSelectorInstructionState8616],
    obligations: list[Obligation],
) -> bool:
    """Retain exact CALL input once and refuse conflicting CALL revisits.

    Non-call effects remain checked by the full instruction replay. They need
    no retained snapshot because only callsite consumers use this index.
    """
    if instruction.op != "CALL":
        return True
    incoming = tuple(sorted(incoming_state.items()))
    key = (id(artifact), id(block), id(instruction))
    prior = states.get(key)
    if prior is not None and prior.selectors != incoming:
        obligations.append(Obligation(
            ObligationKind.INSTRUCTION_STATE_CONFLICT, head, instruction.addr,
            "conflicting incoming selector state"))
        return False
    if prior is None:
        states[key] = DeclaredSelectorInstructionState8616(
            artifact=artifact, block=block, instruction=instruction,
            selectors=incoming)
    return True


def _record_noncall_effects(
    head: int,
    instruction: IRInstr,
    encoded: bytes | None,
    state: dict[str, int],
    stores: list[StoreJudgement],
    obligations: list[Obligation],
) -> None:
    """Record STORE evidence before erasing explicitly written selector facts."""
    if instruction.op == "STORE" and type(instruction.addr) is int:
        address = instruction.args[0] if len(instruction.args) == 2 else None
        stores.append(_store_row(head, instruction, address, state, encoded))
    dst = instruction.dst
    name = None if dst is None else dst.name
    if name is not None and name in SEGMENT_REGISTERS:
        obligations.append(Obligation(
            ObligationKind.SEGMENT_WRITE, head, instruction.addr, str(name)))
        state.pop(name, None)


def _record_instructions(
    head: int,
    blocks: Mapping[int, IRBlock],
    predecessors: Mapping[int, list[int]],
    machine_bytes: Mapping[int, bytes],
    resolved: Mapping[int, tuple[int, frozenset[str]]],
    window_refused: AbstractSet[int],
    block_exit: Mapping[int, dict[str, int]],
    entry: Mapping[str, int],
    *,
    stores: list[StoreJudgement],
    calls: list[CallJudgement],
    terminals: list[CallJudgement],
    geometry: list[ControlCheck8616],
    obligations: list[Obligation],
    discovered: list[tuple[int, dict[str, int], int]],
    budget: _Budget,
    block_machines: Mapping[int, Mapping[int, tuple[int, bytes]]],
    artifact: IRFunctionArtifact,
    states: dict[tuple[int, int, int], DeclaredSelectorInstructionState8616],
    survey: NativeEffectSurvey8616,
    scoped: EntryDomainCallPreservation8616 | None = None,
) -> bool:
    """Deterministic replay of the converged transfer emitting evidence once.

    Before any CALL effect runs, its incoming selector state is
    retained under the exact (artifact, block, instruction) identities. A
    repeated visit with a different incoming state is a typed conflict
    refusal — earlier evidence is never overwritten.
    """
    if not budget.charge(len(machine_bytes), head):
        return False
    recording = {item.block.addr: item.record_rows for item in survey.selector_blocks}
    census = frozenset(machine_bytes)
    covered_fetches: set[int] = set()
    for block_addr in sorted(blocks):
        block = blocks[block_addr]
        state = dict(_join_entry(
            head, block_addr, entry, predecessors[block_addr], block_exit))
        seen_fetches: set[int] = set()
        checked_controls: set[int] = set()
        for instr in recording[block_addr]:
            encoded = _instruction_encoding(machine_bytes, instr)
            if not _record_fetch(head, instr, encoded, state, seen_fetches,
                                 budget, obligations, covered=covered_fetches):
                return False
            if not _record_incoming_instruction_state(
                head, artifact, block, instr, state, states, obligations,
            ):
                return False
            _record_unknown_effect(head, instr, state, obligations)
            if not _record_control_geometry(
                head, block, instr, encoded, state, resolved, checked_controls,
                census, geometry, terminals, budget, obligations, scoped=scoped,
            ):
                return False
            if instr.op == "CALL":
                state = _record_call(
                    head, instr, state, resolved, window_refused,
                    calls, obligations, discovered)
                continue
            _record_noncall_effects(head, instr, encoded, state, stores, obligations)

        if not _finish_recorded_block(
            head, block, block_machines[block_addr].keys(), seen_fetches,
            machine_bytes, state, checked_controls, census,
            geometry, budget, obligations,
        ):
            return False
    active_census = frozenset(address for block_addr in blocks
                              for address in block_machines[block_addr])
    return _record_fetch_census(head, head, active_census, covered_fetches, budget, obligations)


def _record_call(
    head: int,
    instr: IRInstr,
    state: dict[str, int],
    resolved: Mapping[int, tuple[int, frozenset[str]]],
    window_refused: AbstractSet[int],
    calls: list[CallJudgement],
    obligations: list[Obligation],
    discovered: list[tuple[int, dict[str, int], int]],
) -> dict[str, int]:
    """Emit one CALL edge judgement and return the post-call state."""
    site = instr.addr
    if type(site) is not int:
        calls.append(CallJudgement(head, -1, None, (), Verdict.REFUSED_UNCLOSED))
        return {}
    if site not in resolved:
        calls.append(CallJudgement(head, site, None, (), Verdict.REFUSED_UNCLOSED))
        return {}
    target, preserved = resolved[site]
    if site in window_refused:
        calls.append(CallJudgement(head, site, target, (), Verdict.REFUSED_UNCLOSED))
        obligations.append(Obligation(
            ObligationKind.CALL_TARGET_UNRESOLVED, head, site,
            "target outside bound cs window" if state.get("cs") is not None
            else "callsite cs unbound"))
        return {}
    if not preserved:
        calls.append(CallJudgement(head, site, target, (), Verdict.REFUSED_UNCLOSED))
        return {}
    calls.append(CallJudgement(head, site, target, tuple(preserved),
                               Verdict.PRESERVED))
    state = {name: value for name, value in state.items() if name in preserved}
    discovered.append((target, dict(state), site))
    return state


def _transfer_skeleton(
    instr: IRInstr,
    state: dict[str, int],
    encoded: bytes | None,
    resolved: Mapping[int, tuple[int, frozenset[str]]],
    window_refused: AbstractSet[int],
) -> dict[str, int]:
    """Segment-constant skeleton transfer shared by fixpoint and check pass.

    Identical semantics to the recording pass without emitting evidence:
    implicit segment effects and explicit segment destinations drop the
    affected register, CALLs keep exactly the resolved preserved set (or
    clear everything when the edge refused or failed its window check).
    """
    row = classify_native_row_8616(instr)
    if row.row_class is NativeRowClass8616.UNCLASSIFIED:
        return {}
    if row.row_class is NativeRowClass8616.SEGMENT_WRITE:
        if row.segment is None:
            return {}
        state.pop(row.segment, None)
    if instr.op == "CALL":
        site = instr.addr
        kept = (
            frozenset()
            if site is None or site not in resolved or site in window_refused
            else resolved[site][1]
        )
        for segment_name in tuple(state):
            if segment_name not in kept:
                state.pop(segment_name)
        return state
    dst = instr.dst
    name = None if dst is None else dst.name
    if name is not None and name in SEGMENT_REGISTERS:
        state.pop(name, None)
    return state


def _resolve_callsite(
    project: object,
    head: int,
    instr: IRInstr,
    encoded: bytes | None,
    budget: _Budget,
    obligations: list[Obligation],
    consumed: dict[tuple[int, int], tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact]],
    *, scoped_calls: ScopedSelectorCollection8616 | None = None,
    active_blocks: frozenset[int] | None = None,
    universal: dict[int, frozenset[str]] | None = None,
    snapshots: dict[tuple[int, int], ScopedNativeSurfaceSnapshot8616] | None = None,
) -> tuple[int, frozenset[str]]:
    """Phase-A callsite resolution: E8 decode plus complete leaf closure.

    Returns ``(target, preserved_segments)``; an empty preserved set marks
    a structurally refused edge whose reason is recorded as an obligation.
    The consumed callee premise surface is retained for the post-callback
    rebind because closure evidence is only as fresh as its artifact.
    """
    callsite = instr.addr if type(instr.addr) is int else -1
    if encoded is None or len(encoded) != 3 or encoded[0] != 0xE8:
        obligations.append(Obligation(
            ObligationKind.CALL_TRANSFER_UNSUPPORTED, head, callsite,
            "non-E8 call encoding (far/indirect/malformed)"))
        return (callsite, frozenset())
    target = callsite + 3 + int.from_bytes(encoded[1:3], "little", signed=True)
    if not budget.charge(1, head):
        return (target, frozenset())
    if universal is not None and snapshots is not None and target in universal:
        return target, universal[target]
    surface = _caller_premise_surface_8616(project, target)
    if surface is None and scoped_calls is not None:
        scoped_calls.collect()
        record = scoped_calls.record(head, callsite)
        if record is not None and record.target_addr == target and record.callee is not None:
            callee = record.callee
            consumed[id(callee.coverage.boundary), id(callee.coverage.artifact)] = (
                callee.coverage.boundary, callee.coverage.artifact)
            return target, frozenset(record.preserved_registers_for(record.required_scope))
    if surface is None:
        obligations.append(Obligation(
            ObligationKind.CALLEE_MISSING, head, callsite, hex(target)))
        return (target, frozenset())
    return _resolve_universal_callee_8616(
        project, head, callsite, target, surface, budget, obligations,
        consumed, universal, snapshots)


def _fresh_universal_closure_complete_8616(
    closure: SegmentEffectClosureResult8616,
    producer: Callable[..., SegmentEffectClosureResult8616],
) -> bool:
    """Consume only the just-produced canonical verdict, with no intervening callback.

    The canonical constructor already ran the complete closure evidence.
    Replaced producers retain ordinary revalidation. Final source/native seals
    still bind the exact surfaces used by the enclosing selector induction.
    """
    if type(closure) is not SegmentEffectClosureResult8616:
        return False
    if (producer is not _CANONICAL_SEGMENT_CLOSURE_PRODUCER_8616
            or prove_segment_effect_closure_8616 is not producer):
        return closure.complete_for(None)
    counts = (closure.raw_fact_count, closure.normalized_fact_count,
              closure.classified_fact_count, closure.materialized_count, closure.failure_count)
    return (closure.state.invocation_scope is None and closure.failure is None
            and all(type(count) is int for count in counts)
            and counts == (1, 1, 1, 1, 0))


def _resolve_universal_callee_8616(
    project: object, head: int, callsite: int, target: int,
    surface: tuple[IRFunctionArtifact, ExactFunctionRangeBoundary8616, IRBoundaryCoverageResult8616 | None],
    budget: _Budget, obligations: list[Obligation],
    consumed: dict[tuple[int, int], tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact]],
    universal: dict[int, frozenset[str]] | None,
    snapshots: dict[tuple[int, int], ScopedNativeSurfaceSnapshot8616] | None,
) -> tuple[int, frozenset[str]]:
    """Build one universal selector summary and retain its first native facts."""
    artifact, boundary, coverage = surface
    consumed[id(boundary), id(artifact)] = (boundary, artifact)
    if snapshots is not None:
        snapshots.setdefault((id(boundary), id(artifact)),
                             _capture_scoped_native_surface_8616(boundary, artifact))
    from .segment_state import build_segment_state_with_native_survey_8616

    if type(coverage) is not IRBoundaryCoverageResult8616:
        coverage = prove_ir_boundary_coverage_8616(project, boundary, artifact)
    classification_rows = sum(len(block.instrs) for block in artifact.blocks)
    if not budget.charge(classification_rows + len(artifact.blocks), head):
        return (target, frozenset())
    state_artifact, survey, work = build_segment_state_with_native_survey_8616(
        artifact, boundary.reachable_instruction_addrs)
    if not budget.charge(work - classification_rows + _survey_metadata_work_8616(survey), head):
        return (target, frozenset())
    if snapshots is not None:
        budget.surveys[(id(boundary), id(artifact))] = _SharedNativeSurvey8616(
            boundary, artifact, survey, _survey_metadata_8616(survey))
    producer = prove_segment_effect_closure_8616
    closure = producer(coverage, state_artifact)
    if not _fresh_universal_closure_complete_8616(closure, producer):
        obligations.append(Obligation(
            ObligationKind.CALLEE_CLOSURE_INCOMPLETE, head, callsite,
            "" if type(closure) is not SegmentEffectClosureResult8616 or closure.failure is None else str(closure.failure)))
        return (target, frozenset())
    preserved = frozenset(_callee_preserved_registers_8616(closure))
    if universal is not None and snapshots is not None:
        universal[target] = preserved
    return target, preserved


def _store_row(
    head: int, instr: IRInstr, address: object,
    state: Mapping[str, int], encoded: bytes | None,
) -> StoreJudgement:
    """Bind and judge one raw STORE row immediately (envelope vs spans later)."""
    addr = instr.addr if type(instr.addr) is int else -1
    if not isinstance(address, IRAddress) or encoded is None:
        return StoreJudgement(head, addr, MemSpace.UNKNOWN, None, 0, None, None, None,
                              Verdict.REFUSED_SHAPE)
    if not _address_domain16_8616(encoded):
        return StoreJudgement(head, addr, address.space, None, 0, None, None, None,
                              Verdict.REFUSED_ADDRESS_SIZE)
    logical = SEGMENT_BASE_NAME_8616.get(address.space)
    if logical is None:
        return StoreJudgement(head, addr, address.space, None, 0, None, None, None,
                              Verdict.REFUSED_SEGMENT)
    if address.segment_origin is not SegmentOrigin.PROVEN:
        return StoreJudgement(head, addr, address.space, logical, 0, None, None, None,
                              Verdict.REFUSED_SEGMENT)
    width = address.size if type(address.size) is int and address.size > 0 else 0
    if not 0 < width <= _OFFSET_DOMAIN:
        return StoreJudgement(head, addr, address.space, logical, width, None, None, None,
                              Verdict.REFUSED_WIDTH)
    selector = state.get(logical)
    if selector is None:
        return StoreJudgement(head, addr, address.space, logical, width, None, None, None,
                              Verdict.REFUSED_SEGMENT)
    window_base = selector << _SHIFT
    offset = address.offset if type(address.offset) is int else None
    if address.base or offset is None:
        envelope = (window_base, _WORD_LIMIT + width)
    else:
        offset16 = offset & _WORD_LIMIT
        if offset16 + width > _OFFSET_DOMAIN:
            return StoreJudgement(head, addr, address.space, logical, width, offset,
                                  selector, None, Verdict.REFUSED_A20_WRAP)
        envelope = (window_base + offset16, width)
    if envelope[0] + envelope[1] > _PHYSICAL_LIMIT:
        return StoreJudgement(head, addr, address.space, logical, width, offset,
                              selector, None, Verdict.REFUSED_A20_WRAP)
    return StoreJudgement(head, addr, address.space, logical, width, offset,
                          selector, envelope, Verdict.DISJOINT)


def _consumed_surface_for_head_8616(
    consumed: Mapping[tuple[int, int], tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact]],
    head: int,
    budget: _Budget,
) -> tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact] | None:
    """Transport an exact phase-A surface into fresh callee induction.

    This selects source objects, never a preservation verdict. The receiving
    induction still applies all native, census, selector and STORE/control
    checks. Every distinct pair already consumed remains in the final seal.
    """
    for boundary, artifact in consumed.values():
        if not budget.charge(1, head):
            return None
        if boundary.addr == head and artifact.function_addr == head:
            return boundary, artifact
    return None


def _walk_surfaces(
    project: object,
    spec: DeclaredFunctionEntrySpec8616,
    head: int,
    seed: Mapping[str, int],
    budget: _Budget,
    image: _BootImageSurface8616,
    *,
    fetched: set[tuple[int, int]],
    stores: list[StoreJudgement],
    calls: list[CallJudgement],
    terminals: list[CallJudgement],
    geometry: list[ControlCheck8616],
    obligations: list[Obligation],
    consumed: dict[tuple[int, int], tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact]],
    states: dict[tuple[int, int, int], DeclaredSelectorInstructionState8616],
    snapshots: dict[tuple[int, int], ScopedNativeSurfaceSnapshot8616],
    supplied: tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact] | None = None,
    scoped_calls: ScopedSelectorCollection8616 | None = None,
) -> tuple[int, int]:
    """Depth-bounded walk over the declared entry and discovered callees.

    Each callee is keyed on ``(head, entry selectors)`` so a repeated leaf
    with identical transported selectors is induced exactly once; a new
    selector premise re-induces it as separate conditional evidence. Every
    consumed (boundary, artifact) pair lands in ``consumed`` keyed on
    exact retained object identities for the post-callback rebind. Distinct
    imports at the same address must not replace earlier consumed evidence.
    ``supplied`` binds only the first — root — induction to the exact
    consumed link pair; discovered callees always resolve by import.
    """
    queue: list[tuple[int, dict[str, int], int, EntryDomainCallPreservation8616 | None]] = [(head, dict(seed), 0, None)]
    done = failed = 0
    pending_supplied = supplied
    seen: set[tuple[int, frozenset[tuple[str, int]], int]] = set()
    while queue:
        if not budget.charge(1, head):
            obligations.extend(budget.obligations)
            budget.obligations = []
            failed += 1
            break
        target, entry, depth, scoped = queue.pop()
        key = (target, frozenset(entry.items()), id(scoped))
        if key in seen or depth > _MAX_DEPTH:
            if depth > _MAX_DEPTH and key not in seen:
                obligations.append(Obligation(
                    ObligationKind.CALLEE_MISSING, target, None, "call depth"))
                failed += 1
            continue
        seen.add(key)
        discovered: list[tuple[int, dict[str, int], int]] = []
        induction_surface = (pending_supplied if pending_supplied is not None
                             else _consumed_surface_for_head_8616(consumed, target, budget))
        if scoped is not None and scoped.callee is not None:
            induction_surface = (scoped.callee.coverage.boundary, scoped.callee.coverage.artifact)
        if budget.obligations:
            obligations.extend(budget.obligations)
            budget.obligations = []
            failed += 1
            break
        ok = _induce(project, target, entry, budget=budget, image=image,
                     fetched=fetched, stores=stores, calls=calls,
                     terminals=terminals, geometry=geometry,
                     obligations=obligations, discovered=discovered,
                     consumed=consumed, states=states, snapshots=snapshots,
                     declared_spec=spec if target == head else None,
                     supplied=induction_surface, scoped_calls=scoped_calls, scoped=scoped)
        pending_supplied = None
        obligations.extend(budget.obligations)
        budget.obligations = []
        if ok:
            done += 1
        else:
            failed += 1
        for callee, callee_entry, callsite in discovered:
            retained = None if scoped_calls is None else scoped_calls.record(target, callsite)
            queue.append((callee, callee_entry, depth + 1, retained))
    return done, failed


def prove_declared_selector_invariant_8616(
    project: object,
    source: Real16InvocationSource8616,
    entry: DeclaredFunctionEntryLink8616,
    *,
    deadline_seconds: float = 25.0,
    work_limit: int = 20000,
) -> DeclaredSegmentInvariant:
    """Prove the declared selector invariant over the exact consumed root.

    The supplied :class:`DeclaredFunctionEntryLink8616` is the canonical
    entry-domain root: its exact ``boundary``/``artifact`` pair binds the
    root induction — never a substitute import — while every native, fetch
    and CFG check still rebinds the pair under the live producer. On
    success the receipt retains project, source, the exact link, immutable
    per-instruction incoming selector states, and every consumed
    ``(boundary, artifact)`` pair for conditional callsite consumption.
    One ambient traversal scope covers the whole call; nested callers
    reuse the current shared ledger. A foreign link or admission refuses
    before any authority work.
    """
    if (
        type(entry) is not DeclaredFunctionEntryLink8616
        or type(entry.admission) is not DeclaredFunctionEntryAdmission8616
        or type(source) is not Real16InvocationSource8616
    ):
        with segment_call_dependency_traversal_scope_8616():
            return DeclaredSegmentInvariant(
                InvariantStatus.REFUSED, Cohort(0, 0, 0, 0), Cohort(0, 0, 0, 0),
                Cohort(1, 1, 0, 1),
                (Obligation(ObligationKind.DECLARED_AUTHORITY_STALE, -1, None,
                            "foreign entry link or source type"),),
                (), (), (), 0, {}, 0, 0, -1, None,
            )
    with segment_call_dependency_traversal_scope_8616():
        return _prove_invariant_inner(
            project, source, entry.admission,
            deadline_seconds=deadline_seconds, work_limit=work_limit,
            link=entry, supplied=(entry.boundary, entry.artifact),
        )


def prove_declared_segment_invariant(
    project: object,
    source: Real16InvocationSource8616,
    admission: DeclaredFunctionEntryAdmission8616,
    *,
    deadline_seconds: float = 25.0,
    work_limit: int = 20000,
) -> DeclaredSegmentInvariant:
    """Legacy helper: prove the invariant with the root resolved by import.

    Retained for staged regressions only; it shares the identical inner
    proof and never duplicates semantics. New consumers must use
    :func:`prove_declared_selector_invariant_8616`, which binds the exact
    supplied root link and retains it for callsite consumption.
    """
    with segment_call_dependency_traversal_scope_8616():
        return _prove_invariant_inner(
            project, source, admission,
            deadline_seconds=deadline_seconds, work_limit=work_limit,
        )


def _fetched_code_envelope(
    fetched: AbstractSet[tuple[int, int]], budget: _Budget, head: int,
) -> tuple[int, int] | None:
    """Charge one pass forming a conservative hull of every retained fetch."""
    lower: int | None = None
    upper = 0
    for start, length in fetched:
        if not budget.charge(1, head):
            return None
        lower = start if lower is None else min(lower, start)
        upper = max(upper, start + length)
    return None if lower is None else (lower, upper)


def _judge_store_fetch_separation(
    row: StoreJudgement,
    fetched: AbstractSet[tuple[int, int]],
    budget: _Budget,
    head: int,
    code_envelope: tuple[int, int] | None = None,
) -> StoreJudgement:
    """Use a charged disjoint hull, retaining exact checks inside its gaps."""
    if row.verdict is not Verdict.DISJOINT or row.envelope is None:
        return row
    base, extent = row.envelope
    verdict = Verdict.DISJOINT
    if budget.obligations or not budget.charge(1, head):
        verdict = Verdict.REFUSED_RESOURCE_LIMIT
    elif code_envelope is not None and (
        base + extent <= code_envelope[0] or base >= code_envelope[1]
    ):
        return row
    if verdict is Verdict.REFUSED_RESOURCE_LIMIT:
        return _store_verdict(row, verdict)
    for start, length in fetched:
        if not budget.charge(1, head):
            verdict = Verdict.REFUSED_RESOURCE_LIMIT
            break
        if base < start + length and base + extent > start:
            verdict = Verdict.REFUSED_CODE_WRITE
            break
    if verdict is Verdict.DISJOINT:
        return row
    return _store_verdict(row, verdict)


def _store_verdict(row: StoreJudgement, verdict: Verdict) -> StoreJudgement:
    """Retain full STORE provenance when replacing its separation verdict."""
    return StoreJudgement(
        row.function_addr, row.instruction_addr, row.space,
        row.logical_segment, row.width, row.offset, row.segment_value,
        row.envelope, verdict,
    )


def _rebind_consumed_surfaces(
    project: object,
    consumed: Mapping[tuple[int, int], tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact]],
    head: int,
    budget: _Budget,
    obligations: list[Obligation],
    snapshots: Mapping[tuple[int, int], ScopedNativeSurfaceSnapshot8616],
) -> None:
    """Re-derive every retained consumed pair under the live producer.

    Authentication proves boot/module/loader freshness, but a post-work
    callback may still replace the raw native census producer. Every
    retained (boundary, artifact) pair — induced surfaces and phase-A
    callee premise closures alike — must therefore rebind through the
    independent scoped comparison, which dynamically imports the producer
    bound *now*. The re-derivation is charged to the same shared ledger;
    the first stale pair or exhausted budget refuses, never waives.
    """
    for boundary, artifact in consumed.values():
        if not budget.charge(
            len(artifact.blocks)
            + sum(len(block.instrs) for block in artifact.blocks),
            head,
        ):
            obligations.extend(budget.obligations)
            budget.obligations = []
            return
        before = snapshots.get((id(boundary), id(artifact)))
        if before is None:
            before = _capture_scoped_native_surface_8616(boundary, artifact)
        facts = _prepare_selector_native_rebind_8616(project, boundary, artifact)
        if _scoped_native_rebind_failure_8616(boundary, artifact, facts, before) is not None:
            obligations.append(Obligation(
                ObligationKind.CONSUMED_SURFACE_STALE, boundary.addr, None,
                "consumed pair stale under post-callback producer"))
            return


def _seal_positive_receipt(
    project: object,
    source: Real16InvocationSource8616,
    admission: DeclaredFunctionEntryAdmission8616,
    head: int,
    budget: _Budget,
    obligations: list[Obligation],
    consumed: Mapping[tuple[int, int], tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact]],
    snapshots: Mapping[tuple[int, int], ScopedNativeSurfaceSnapshot8616],
) -> None:
    """Seal a candidate whose collected evidence can still close positive.

    Rebinds every retained consumed surface against the post-callback
    producer, then finishes with current declared authority without
    opening another callback. Every re-derivation and the final authority
    pass are charged to the same shared ledger; a stale pair, stale
    authority or an exhausted budget appends its typed obligation, which
    flips the receipt to REFUSED.
    """
    _rebind_consumed_surfaces(project, consumed, head, budget, obligations, snapshots)
    # Producer callbacks may alter live bytes even when their returned IR is
    # equal. Finish with current authority, without opening another callback.
    if budget.charge(1, head):
        final_authority = _authenticate_authority(
            project, source, admission, head, recompute_boot=False)
        if final_authority is not None:
            obligations.append(final_authority)
    if not _shared_surveys_current_8616(budget, head):
        obligations.append(Obligation(ObligationKind.CONSUMED_SURFACE_STALE, head, None,
                                      "shared survey changed after native callbacks"))


def _seal_scoped_receipt_8616(
    project: object, source: Real16InvocationSource8616, admission: DeclaredFunctionEntryAdmission8616,
    head: int, budget: _Budget, obligations: list[Obligation],
    consumed: dict[tuple[int, int], tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact]],
    snapshots: dict[tuple[int, int], ScopedNativeSurfaceSnapshot8616],
    scoped_calls: ScopedSelectorCollection8616,
) -> None:
    """Revalidate conditional records around native callbacks and seal facts."""
    if not scoped_calls.records:
        _seal_positive_receipt(project, source, admission, head, budget, obligations, consumed, snapshots)
        return
    if not budget.charge(5 * scoped_selector_facts_work_8616(scoped_calls.facts), head):
        obligations.extend(budget.obligations)
        return
    if (not scoped_selector_records_current_8616(scoped_calls.records)
                          or scoped_calls.facts != scoped_selector_records_facts_8616(scoped_calls.records)):
        obligations.append(Obligation(ObligationKind.CONSUMED_SURFACE_STALE, head, None,
                                      "scoped call proof changed"))
    if not obligations:
        _seal_positive_receipt(
            project, source, admission, head, budget, obligations,
            consumed, snapshots)
        if scoped_calls.facts != scoped_selector_records_facts_8616(scoped_calls.records):
            obligations.append(Obligation(ObligationKind.CONSUMED_SURFACE_STALE, head, None,
                                          "scoped call proof changed after native seal"))


def _prove_invariant_inner(
    project: object,
    source: Real16InvocationSource8616,
    admission: DeclaredFunctionEntryAdmission8616,
    *,
    deadline_seconds: float,
    work_limit: int,
    link: DeclaredFunctionEntryLink8616 | None = None,
    supplied: tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact] | None = None,
) -> DeclaredSegmentInvariant:
    """Shared proof innards under one ambient traversal scope."""
    deadline = time.monotonic() + deadline_seconds
    budget = _Budget(deadline, work_limit)
    empty = (Cohort(0, 0, 0, 0), Cohort(0, 0, 0, 0), Cohort(1, 1, 0, 1))
    # Zero-cost gate: a preconsumed ambient ledger or expired ambient
    # deadline must refuse before any authentication or import work runs.
    if not budget.charge(0, -1):
        return DeclaredSegmentInvariant(
            InvariantStatus.REFUSED, *empty, tuple(budget.obligations),
            (), (), (), 0, {}, budget.units, budget.shared_units(), -1, None,
        )
    # Foreign admission types must be refused before any attribute access.
    if (
        type(admission) is not DeclaredFunctionEntryAdmission8616
        or type(source) is not Real16InvocationSource8616
    ):
        return DeclaredSegmentInvariant(
            InvariantStatus.REFUSED, *empty,
            (Obligation(ObligationKind.DECLARED_AUTHORITY_STALE, -1, None,
                        "foreign admission type"),),
            (), (), (), 0, {}, budget.units, budget.shared_units(), -1, None,
        )
    evidence = _invocation_boot_evidence_8616(source.boot)
    if not isinstance(evidence, _BootEvidence8616):
        return DeclaredSegmentInvariant(
            InvariantStatus.REFUSED, *empty,
            (Obligation(ObligationKind.DECLARED_AUTHORITY_STALE, -1, None,
                        f"boot evidence: {evidence}"),),
            (), (), (), 0, {}, budget.units, budget.shared_units(), -1, None,
            project=project, source=source, root_link=link,
        )
    image = evidence.image
    seed = _declared_seed(admission)
    spec = admission.spec
    head = (spec.entry_segment << _SHIFT) + spec.entry_offset
    fetched: set[tuple[int, int]] = set()
    stores: list[StoreJudgement] = []
    calls: list[CallJudgement] = []
    terminals: list[CallJudgement] = []
    geometry: list[ControlCheck8616] = []
    obligations: list[Obligation] = []
    consumed: dict[tuple[int, int], tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact]] = {}
    states: dict[tuple[int, int, int], DeclaredSelectorInstructionState8616] = {}
    snapshots: dict[tuple[int, int], ScopedNativeSurfaceSnapshot8616] = {}
    if seed is None or "cs" not in seed:
        return DeclaredSegmentInvariant(
            InvariantStatus.REFUSED, *empty,
            (Obligation(ObligationKind.ENTRY_SEED_UNBOUND, head, None),),
            (), (), (), 0, seed or {}, budget.units, budget.shared_units(),
            head, admission,
            project=project, source=source, root_link=link,
        )
    authority = _authenticate_authority(project, source, admission, head)
    if authority is not None:
        return DeclaredSegmentInvariant(
            InvariantStatus.REFUSED, *empty, (authority,),
            (), (), (), 0, dict(seed), budget.units, budget.shared_units(),
            head, admission,
            project=project, source=source, root_link=link,
        )
    scoped_calls = ScopedSelectorCollection8616(project, source, link)
    surfaces_done, surfaces_failed = _walk_surfaces(
        project, spec, head, seed, budget, image,
        fetched=fetched, stores=stores, calls=calls, terminals=terminals,
        geometry=geometry, obligations=obligations, consumed=consumed,
        states=states, snapshots=snapshots, supplied=supplied, scoped_calls=scoped_calls)
    frozen = frozenset(fetched)
    code_envelope = _fetched_code_envelope(frozen, budget, head)
    judged = [
        _judge_store_fetch_separation(row, frozen, budget, head, code_envelope)
        for row in stores
    ]
    obligations.extend(budget.obligations)
    budget.obligations = []
    post = _authenticate_authority(project, source, admission, head)
    if post is not None:
        obligations.append(post)
    store_failures = sum(1 for r in judged if r.verdict is not Verdict.DISJOINT)
    terminal_refusals = sum(
        1 for t in terminals if t.verdict is not Verdict.CLOSED)
    control_raw = len(calls) + len(terminals)
    control_closed = sum(1 for c in calls if c.verdict is Verdict.PRESERVED) + (
        len(terminals) - terminal_refusals)
    control_failures = terminal_refusals + sum(
        1 for c in calls if c.verdict is not Verdict.PRESERVED)
    geometry_failed = sum(row.verdict is ControlVerdict8616.REFUSED for row in geometry)
    # A refused invariant grants no selector authority: once the collected
    # evidence already forces REFUSED, positive-result sealing cannot change
    # the verdict, so the consumed-surface rebind and the final authority
    # pass must not consume the shared ledger. The refused receipt keeps
    # its original obligations and only the work units actually collected.
    positive_open = (
        not obligations and store_failures == 0
        and control_failures == 0 and surfaces_failed == 0
        and bool(geometry) and geometry_failed == 0
    )
    if positive_open:
        _seal_scoped_receipt_8616(project, source, admission, head, budget, obligations,
                                 consumed, snapshots, scoped_calls)
    if not budget.charge(0, head):
        obligations.extend(budget.obligations)
    index_units = len(states) + len(consumed) + int(link is not None)
    _check_index_private_budget_8616(budget, index_units, head, obligations)
    status = (
        InvariantStatus.PROVEN_CONDITIONAL
        if not obligations and store_failures == 0
        and control_failures == 0 and surfaces_failed == 0
        and geometry and geometry_failed == 0
        else InvariantStatus.REFUSED
    )
    return DeclaredSegmentInvariant(
        status,
        Cohort(len(judged), len(judged),
               sum(1 for r in judged if r.verdict is Verdict.DISJOINT),
               store_failures),
        Cohort(control_raw, control_raw, control_closed, control_failures),
        Cohort(surfaces_done + surfaces_failed, surfaces_done + surfaces_failed,
               surfaces_done, surfaces_failed),
        tuple(obligations), tuple(judged), tuple(calls), tuple(terminals),
        len(frozen), dict(seed), budget.units, budget.shared_units(), head,
        admission,
        Cohort(len(geometry), len(geometry), len(geometry) - geometry_failed, geometry_failed),
        tuple(geometry),
        len(consumed),
        project=project,
        source=source,
        root_link=link,
        instruction_states=tuple(states.values()),
        consumed_pairs=tuple(consumed.values()),
        scoped_call_preservations=scoped_calls.records,
    )


def _check_index_private_budget_8616(
    budget: _Budget, units: int, head: int, obligations: list[Obligation],
) -> None:
    """Retain the factory's tighter private work bound before shared index charging."""
    if budget.units + units > budget.limit:
        obligations.append(Obligation(ObligationKind.BUDGET_EXCEEDED, head, None))


def _build_selector_identity_index_8616(scope: DeclaredSegmentInvariant) -> _SelectorIdentityIndex8616:
    """Derive exact identity maps; duplicate instruction owners stay ambiguous."""
    states: dict[tuple[int, int], DeclaredSelectorInstructionState8616 | None] = {}
    for state in scope.instruction_states:
        key = (id(state.block), id(state.instruction))
        states[key] = None if key in states else state
    surfaces: dict[int, tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact] | None] = {}
    pairs = scope.consumed_pairs
    link = scope.root_link
    if link is not None:
        pairs = ((link.boundary, link.artifact), *pairs)
    for boundary, artifact in pairs:
        artifact_key = id(artifact)
        if artifact_key in surfaces:
            previous = surfaces[artifact_key]
            if previous is None or previous[0] is not boundary:
                surfaces[artifact_key] = None
        else:
            surfaces[artifact_key] = (boundary, artifact)
    return _SelectorIdentityIndex8616(MappingProxyType(states), MappingProxyType(surfaces))


def _retained_instruction_state_8616(
    scope: DeclaredSegmentInvariant, block: IRBlock, instruction: IRInstr,
) -> DeclaredSelectorInstructionState8616 | None:
    """Look up one exact retained instruction without scanning unrelated surfaces."""
    index = scope._identity_index
    if index is None:
        return None
    state = index.states.get((id(block), id(instruction)))
    if state is None or state.block is not block or state.instruction is not instruction:
        return None
    return state


def _retained_surface_for(
    scope: DeclaredSegmentInvariant,
    artifact: IRFunctionArtifact,
) -> tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact] | None:
    """Look up the unique retained boundary owning this exact artifact identity."""
    index = scope._identity_index
    if index is None:
        return None
    pair = index.surfaces.get(id(artifact))
    return pair if pair is not None and pair[1] is artifact else None


def selector_callsite_8616(
    scope: DeclaredSegmentInvariant,
    block: IRBlock,
    instruction: IRInstr,
    target_addr: int,
    next_addr: int,
) -> DeclaredSelectorCallsite8616 | None:
    """Project one authenticated selector capability from a proven scope.

    Authentication is identity-exact: the instruction's retained incoming
    selector state (recorded before its row effect) must carry a bound CS,
    the callsite's CALL judgement must be preserved with the identical
    native target, and the retained coordinate row must close with the
    identical target and continuation. Anything unbound returns ``None`` —
    never a partial projection.
    """
    if (
        type(scope) is not DeclaredSegmentInvariant
        or scope.status is not InvariantStatus.PROVEN_CONDITIONAL
        or scope.root_link is None
        or type(block) is not IRBlock
        or type(instruction) is not IRInstr
    ):
        return None
    callsite = instruction.addr
    if (
        instruction.op != "CALL" or type(callsite) is not int
        or type(target_addr) is not int or type(next_addr) is not int
    ):
        return None
    state = _retained_instruction_state_8616(scope, block, instruction)
    if state is None:
        return None
    artifact = state.artifact
    if _retained_surface_for(scope, artifact) is None:
        return None
    if not any(
        member is block for member in artifact.blocks
    ) or not any(member is instruction for member in block.instrs):
        return None
    incoming_cs = dict(state.selectors).get("cs")
    if type(incoming_cs) is not int:
        return None
    edges = tuple(
        edge for edge in scope.call_edges
        if edge.callsite_addr == callsite and edge.verdict is Verdict.PRESERVED
    )
    if len(edges) != 1 or edges[0].target_addr != target_addr:
        return None
    rows = tuple(
        row for row in scope.geometry_rows
        if row.addr == callsite and row.kind is ControlKind8616.CALL
    )
    if (
        len(rows) != 1
        or rows[0].verdict is not ControlVerdict8616.CLOSED
        or rows[0].target != target_addr
        or rows[0].fallthrough != next_addr
    ):
        return None
    cs_base = incoming_cs << _SHIFT
    if not (cs_base <= target_addr <= cs_base + _WORD_LIMIT):
        return None
    return DeclaredSelectorCallsite8616(
        scope=scope,
        block=block,
        instruction=instruction,
        callsite_addr=callsite,
        target_addr=target_addr,
        next_addr=next_addr,
        incoming_cs=incoming_cs,
    )


def consume_declared_selector_callsite_8616(
    project: object,
    projection: DeclaredSelectorCallsite8616,
) -> bool:
    """Revalidate a selector capability against the current authority.

    The certificate's retained source must still
    authenticate (module bytes, loader, environment, load segment) and the
    exact consumed native surface owning the callsite — root link or
    retained callee pair — must rebind under the currently bound census
    producer via the bounded scoped request. The live bytes at the
    callsite must still decode to the identical E8 target and
    continuation, and the retained incoming CS window must still contain
    the target. Pure selector capability only; stack, return-offset, GP
    and memory effects are never claimed here. Native producer callbacks
    precede final callback-free authority authentication. The entire
    consumption shares the caller's work ledger and deadline.
    """
    with segment_call_dependency_traversal_scope_8616():
        budget = _Budget(float("inf"), _SHARED_WORK_LIMIT_8616)
        return _consume_selector_callsite_batch_8616(project, (projection,), budget)[0]


def consume_declared_selector_callsite_batch_8616(
    project: object,
    projections: tuple[DeclaredSelectorCallsite8616, ...],
    *, obligations: list[Obligation] | None = None,
) -> tuple[bool, ...]:
    """Revalidate a batch of selector capabilities under one shared admission.

    Verdicts align with the input order, one slot per supplied projection.
    Typed members must retain the identical proven scope and a unique
    callsite; any sibling failing either gate stays refused without
    poisoning the rest. Authority authenticates once before and once after
    every native, import and loader read; each distinct retained surface —
    the root link or a consumed callee pair — rebinds once under the
    currently bound census producer via the bounded scoped request, and
    every callsite's live bytes are detached before the final read. The
    closing stage runs no callbacks: it purely re-verifies the current
    retained graphs and projection identities against those detached byte
    facts. Each verdict is this collection's admission only — no token
    survives for later replay, and public consumption replays fresh.
    """
    with segment_call_dependency_traversal_scope_8616() as traversal:
        budget = _Budget(float("inf"), traversal.selector_batch_work_limit)
        verdicts = _consume_selector_callsite_batch_8616(project, projections, budget)
        if obligations is not None:
            obligations.extend(budget.obligations)
        return verdicts


class _SelectorConsumption8616(Enum):
    """Distinguish target coordinates from conditional CS preservation."""

    TARGET = "target"
    CS_PRESERVATION = "cs_preservation"


def consume_declared_selector_cs_preservation_batch_8616(
    project: object, projections: tuple[DeclaredSelectorCallsite8616, ...],
    *, obligations: list[Obligation] | None = None,
) -> tuple[bool, ...]:
    """Consume CS-only call effects with every retained native dependency rebound."""
    with segment_call_dependency_traversal_scope_8616() as traversal:
        budget = _Budget(float("inf"), traversal.selector_batch_work_limit)
        verdicts = _consume_selector_callsite_batch_8616(
            project, projections, budget, policy=_SelectorConsumption8616.CS_PRESERVATION)
        if obligations is not None:
            obligations.extend(budget.obligations)
        return verdicts


def consume_declared_selector_cs_preservation_8616(
    project: object, projection: DeclaredSelectorCallsite8616,
) -> bool:
    """Consume exactly one conditional CS effect; no other effects are implied."""
    return consume_declared_selector_cs_preservation_batch_8616(project, (projection,))[0]


def _selector_cs_judgement_8616(projection: DeclaredSelectorCallsite8616) -> bool:
    """Require one matching root call judgement that explicitly preserves CS."""
    scope = projection.scope
    link = scope.root_link
    state = _retained_instruction_state_8616(scope, projection.block, projection.instruction)
    if link is None or state is None or state.artifact is not link.artifact:
        return False
    edges = tuple(row for row in scope.call_edges
                  if row.function_addr == link.artifact.function_addr
                  and row.callsite_addr == projection.callsite_addr)
    return (len(edges) == 1 and edges[0].target_addr == projection.target_addr
            and edges[0].verdict is Verdict.PRESERVED and "cs" in edges[0].preserved)


_SelectorBatchPlan8616 = tuple[
    DeclaredSelectorInstructionState8616, ExactFunctionRangeBoundary8616, IRFunctionArtifact,
]


def _selector_source_facts_8616(source: Real16InvocationSource8616 | None) -> tuple[object, ...]:
    """Detach owned source authority; third-party boot data uses its typed evidence."""
    if source is None or type(source) is not Real16InvocationSource8616:
        return (id(source),)
    evidence = _invocation_boot_evidence_8616(source.boot)
    return (id(source), id(source.boot), id(source.boot_recompute),
            id(source.callsite_index), source.pending_targets,
            deepcopy(source.declared_services), deepcopy(source.function_entries),
            deepcopy(evidence))


def _selector_certificate_facts_8616(scope: DeclaredSegmentInvariant) -> tuple[object, ...]:
    """Detach proof provenance before callbacks can alter matching sides together."""
    root = scope.root_link
    root_facts = None if root is None else (
        id(root), id(root.artifact), id(root.boundary), id(root.admission),
        (deepcopy(root.admission) if type(root.admission) is DeclaredFunctionEntryAdmission8616
         else id(root.admission)),
    )
    return (id(scope.project), scope.status, root_facts, id(scope.admission),
            _selector_source_facts_8616(scope.source), scope.declared_entry,
            tuple(sorted(scope.bound_entry_selectors.items())),
            deepcopy((scope.stores, scope.controls, scope.surfaces, scope.obligations,
                      scope.store_rows, scope.call_edges, scope.terminal_edges,
                      scope.control_geometry, scope.geometry_rows)),
            scope.fetched_span_count, scope.consumed_surfaces,
            tuple((id(state), id(state.artifact), id(state.block), id(state.instruction),
                   state.selectors) for state in scope.instruction_states),
            tuple((id(boundary), id(artifact)) for boundary, artifact in scope.consumed_pairs),
            scoped_selector_records_facts_8616(scope.scoped_call_preservations))


def _selector_projection_facts_8616(projection: DeclaredSelectorCallsite8616) -> tuple[object, ...]:
    """Detach exact projection identities and all numeric control coordinates."""
    return (id(projection.scope), id(projection.block), id(projection.instruction),
            projection.callsite_addr, projection.target_addr,
            projection.next_addr, projection.incoming_cs)


def _selector_projection_batch_facts_8616(
    projections: tuple[DeclaredSelectorCallsite8616, ...],
    planned: Mapping[int, _SelectorBatchPlan8616],
) -> dict[int, tuple[object, ...]]:
    """Detach each selected callsite before any authority callback can change it."""
    return {index: _selector_projection_facts_8616(projections[index]) for index in planned}


def _selector_certificate_fact_work_8616(
    scope: DeclaredSegmentInvariant, projections: tuple[DeclaredSelectorCallsite8616, ...],
) -> int:
    """Count retained evidence rows traversed by each provenance snapshot pass."""
    return (1 + len(projections) + len(scope.instruction_states) + len(scope.consumed_pairs)
            + len(scope.store_rows) + len(scope.call_edges) + len(scope.terminal_edges)
            + len(scope.geometry_rows) + len(scope.obligations)
            + 3 * cast(int, scoped_selector_facts_work_8616(
                scoped_selector_records_facts_8616(scope.scoped_call_preservations))))


def _selector_batch_members_8616(
    projections: tuple[DeclaredSelectorCallsite8616, ...],
    scope: DeclaredSegmentInvariant,
) -> list[int]:
    """Select unique typed callsites under the identical required scope."""
    sites: dict[int, list[int]] = {}
    for index, projection in enumerate(projections):
        if (
            type(projection) is not DeclaredSelectorCallsite8616
            or type(projection.callsite_addr) is not int
        ):
            continue
        sites.setdefault(projection.callsite_addr, []).append(index)
    return [
        index for index, projection in enumerate(projections)
        if type(projection) is DeclaredSelectorCallsite8616
        and projection.scope is scope
        and type(projection.callsite_addr) is int
        and len(sites[projection.callsite_addr]) == 1
    ]


def _plan_selector_batch_8616(
    projections: tuple[DeclaredSelectorCallsite8616, ...],
    scope: DeclaredSegmentInvariant,
    members: list[int],
) -> tuple[dict[int, _SelectorBatchPlan8616],
           dict[int, tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact]]]:
    """Retain exact instruction states and deduplicate native callback surfaces."""
    planned: dict[
        int,
        tuple[
            DeclaredSelectorInstructionState8616,
            ExactFunctionRangeBoundary8616,
            IRFunctionArtifact,
        ],
    ] = {}
    surfaces: dict[
        int, tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact]
    ] = {}
    for index in members:
        projection = projections[index]
        if (
            type(projection.block) is not IRBlock
            or type(projection.instruction) is not IRInstr
            or projection.instruction.op != "CALL"
            or projection.instruction.addr != projection.callsite_addr
        ):
            continue
        state = _retained_instruction_state_8616(
            scope, projection.block, projection.instruction)
        if state is None or dict(state.selectors).get("cs") != projection.incoming_cs:
            continue
        surface = _retained_surface_for(scope, state.artifact)
        if surface is None:
            continue
        planned[index] = (state, surface[0], surface[1])
        surfaces.setdefault(id(surface[1]), surface)
    return planned, surfaces


def _seal_selector_batch_rows_8616(
    projections: tuple[DeclaredSelectorCallsite8616, ...],
    scope: DeclaredSegmentInvariant,
    planned: Mapping[int, _SelectorBatchPlan8616],
    detached: Mapping[int, bytes | None],
    sealed: Mapping[int, bool],
    verdicts: list[bool],
) -> tuple[bool, ...]:
    """Finalize callsite identities and coordinates after the pure graph seal."""
    for index, (plan_state, plan_boundary, plan_artifact) in planned.items():
        if not sealed[id(plan_artifact)]:
            continue
        projection = projections[index]
        state = _retained_instruction_state_8616(
            scope, projection.block, projection.instruction)
        if state is None or state is not plan_state:
            continue
        if dict(state.selectors).get("cs") != projection.incoming_cs:
            continue
        surface = _retained_surface_for(scope, state.artifact)
        if (
            surface is None
            or surface[0] is not plan_boundary
            or surface[1] is not plan_artifact
        ):
            continue
        if _selector_native_target_pure_8616(
            projection, plan_artifact, detached[index],
        ):
            verdicts[index] = True
    return tuple(verdicts)


def _selector_batch_scope_8616(
    project: object, projections: tuple[DeclaredSelectorCallsite8616, ...],
) -> DeclaredSegmentInvariant | None:
    """Require the identical authenticated owner before inspecting batch members."""
    typed = [
        projection for projection in projections
        if type(projection) is DeclaredSelectorCallsite8616
    ]
    if not typed:
        return None
    scope = typed[0].scope
    if (
        type(scope) is not DeclaredSegmentInvariant
        or scope.status is not InvariantStatus.PROVEN_CONDITIONAL
        or scope.source is None
        or scope.root_link is None
        or scope.project is not project
    ):
        return None
    return scope


def _plan_cs_dependencies_8616(
    project: object, scope: DeclaredSegmentInvariant,
    surfaces: dict[int, tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact]],
    budget: _Budget, policy: _SelectorConsumption8616,
) -> bool:
    """Enroll the complete retained dependency set without rebuilding its effects."""
    if policy is _SelectorConsumption8616.TARGET:
        return True
    if not budget.charge(len(scope.consumed_pairs), scope.declared_entry):
        return False
    for boundary, artifact in scope.consumed_pairs:
        if boundary.project is not project or boundary.addr != artifact.function_addr:
            return False
        prior = surfaces.setdefault(id(artifact), (boundary, artifact))
        if prior[0] is not boundary or prior[1] is not artifact:
            return False
    return _cs_dependency_set_current_8616(scope, surfaces, budget)


def _cs_dependency_set_current_8616(
    scope: DeclaredSegmentInvariant,
    surfaces: Mapping[int, tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact]],
    budget: _Budget,
) -> bool:
    """Reject loss or replacement of the original immutable dependency inventory."""
    index = scope._identity_index
    if index is None or not budget.charge(len(index.surfaces), scope.declared_entry):
        return False
    if len(surfaces) != len(index.surfaces):
        return False
    for key, original in index.surfaces.items():
        current = surfaces.get(key)
        if (original is None or current is None
                or current[0] is not original[0] or current[1] is not original[1]):
            return False
    return True


def _consume_selector_callsite_batch_8616(
    project: object,
    projections: tuple[DeclaredSelectorCallsite8616, ...],
    budget: _Budget,
    *, policy: _SelectorConsumption8616 = _SelectorConsumption8616.TARGET,
) -> tuple[bool, ...]:
    """Consume every admissible projection without renewing shared limits."""
    verdicts = [False] * len(projections)
    scope = _selector_batch_scope_8616(project, projections)
    if scope is None:
        return tuple(verdicts)
    members = _selector_batch_members_8616(projections, scope)
    if (
        not members
        or not budget.charge(len(members), scope.declared_entry)
        or direct_evidence_deadline_expired_8616(project)
    ):
        return tuple(verdicts)
    link = cast(DeclaredFunctionEntryLink8616, scope.root_link)
    planned, surfaces = _plan_selector_batch_8616(projections, scope, members)
    surfaces.setdefault(id(link.artifact), (link.boundary, link.artifact))
    fact_work = _selector_certificate_fact_work_8616(scope, projections)
    if (not _plan_cs_dependencies_8616(project, scope, surfaces, budget, policy)
            or not budget.charge(fact_work, scope.declared_entry)):
        return tuple(verdicts)
    certificate_before = _selector_certificate_facts_8616(scope)
    projection_before = _selector_projection_batch_facts_8616(projections, planned)
    snapshots = _capture_selector_batch_surfaces_8616(scope, surfaces, budget)
    if snapshots is None:
        return tuple(verdicts)
    if (
        scope.source is None
        or _authenticate_authority(
            project, scope.source, link.admission,
            scope.declared_entry, recompute_boot=False,
        )
        is not None
        or not scoped_selector_records_current_8616(scope.scoped_call_preservations)
    ):
        return tuple(verdicts)
    native_facts = _prepare_selector_batch_surfaces_8616(project, scope, surfaces, budget)
    if native_facts is None:
        return tuple(verdicts)
    detached = _selector_batch_call_bytes_8616(project, projections, planned)
    if scope.source is None or _authenticate_authority(
        project, scope.source, link.admission,
        scope.declared_entry, recompute_boot=False,
    ) is not None:
        return tuple(verdicts)
    if (
        not budget.charge(0, scope.declared_entry)
        or direct_evidence_deadline_expired_8616(project)
        or scope.status is not InvariantStatus.PROVEN_CONDITIONAL
    ):
        return tuple(verdicts)
    sealed = _seal_selector_batch_surfaces_8616(
        scope, surfaces, native_facts, budget, snapshots)
    fact_work += int(policy is _SelectorConsumption8616.CS_PRESERVATION) * (
        len(planned) * len(scope.call_edges) + len(surfaces))
    if not budget.charge(fact_work, scope.declared_entry):
        return tuple(verdicts)
    return _selector_batch_final_verdicts_8616(
        projections, scope, planned, detached, sealed, verdicts,
        certificate_before, projection_before, policy=policy,
    )


def _selector_batch_final_verdicts_8616(
    projections: tuple[DeclaredSelectorCallsite8616, ...],
    scope: DeclaredSegmentInvariant,
    planned: Mapping[int, _SelectorBatchPlan8616],
    detached: Mapping[int, bytes | None], sealed: Mapping[int, bool] | None,
    verdicts: list[bool], certificate_before: tuple[object, ...],
    projection_before: Mapping[int, tuple[object, ...]],
    *, policy: _SelectorConsumption8616 = _SelectorConsumption8616.TARGET,
) -> tuple[bool, ...]:
    """Materialize results only after graph and certificate seals both succeed."""
    if sealed is None or not _selector_batch_metadata_unchanged_8616(
        scope, projections, planned, certificate_before, projection_before,
    ):
        return tuple(verdicts)
    if policy is _SelectorConsumption8616.CS_PRESERVATION:
        if not all(sealed.values()):
            return tuple(verdicts)
        planned = {index: plan for index, plan in planned.items()
                   if _selector_cs_judgement_8616(projections[index])}
    return _seal_selector_batch_rows_8616(projections, scope, planned, detached, sealed, verdicts)


def _selector_batch_call_bytes_8616(
    project: object, projections: tuple[DeclaredSelectorCallsite8616, ...],
    planned: Mapping[int, _SelectorBatchPlan8616],
) -> dict[int, bytes | None]:
    """Finish all call-byte loader callbacks before the final authority seal."""
    return {index: _loaded_bytes_8616(project, projections[index].callsite_addr, 3)
            for index in planned}


def _selector_batch_metadata_unchanged_8616(
    scope: DeclaredSegmentInvariant,
    projections: tuple[DeclaredSelectorCallsite8616, ...],
    planned: Mapping[int, _SelectorBatchPlan8616],
    certificate_before: tuple[object, ...],
    projection_before: Mapping[int, tuple[object, ...]],
) -> bool:
    """Compare retained authority and selectors after every callback has finished."""
    return (certificate_before == _selector_certificate_facts_8616(scope)
            and all(projection_before[index] == _selector_projection_facts_8616(projections[index])
                    for index in planned))


def _prepare_selector_batch_surfaces_8616(
    project: object,
    scope: DeclaredSegmentInvariant,
    surfaces: Mapping[int, tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact]],
    budget: _Budget,
) -> dict[int, ScopedNativeRebindFacts8616] | None:
    """Charge fresh native preparation once for every exact retained surface."""
    native_facts: dict[int, ScopedNativeRebindFacts8616] = {}
    for boundary, artifact in surfaces.values():
        if not budget.charge(
            len(artifact.blocks) + sum(len(block.instrs) for block in artifact.blocks),
            scope.declared_entry,
        ):
            return None
        facts = _prepare_selector_native_rebind_8616(project, boundary, artifact)
        native_facts[id(artifact)] = facts
    return native_facts


def _capture_selector_batch_surfaces_8616(
    scope: DeclaredSegmentInvariant,
    surfaces: Mapping[int, tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact]],
    budget: _Budget,
) -> dict[int, ScopedNativeSurfaceSnapshot8616] | None:
    """Charge and capture current graphs before the first authority callback."""
    snapshots: dict[int, ScopedNativeSurfaceSnapshot8616] = {}
    for boundary, artifact in surfaces.values():
        units = len(artifact.blocks) + sum(len(block.instrs) for block in artifact.blocks)
        if not budget.charge(units, scope.declared_entry):
            return None
        snapshots[id(artifact)] = _capture_scoped_native_surface_8616(boundary, artifact)
    return snapshots


def _seal_selector_batch_surfaces_8616(
    scope: DeclaredSegmentInvariant,
    surfaces: Mapping[int, tuple[ExactFunctionRangeBoundary8616, IRFunctionArtifact]],
    native_facts: Mapping[int, ScopedNativeRebindFacts8616],
    budget: _Budget,
    snapshots: Mapping[int, ScopedNativeSurfaceSnapshot8616],
) -> dict[int, bool] | None:
    """Charge the final whole-surface comparison separately from fact preparation."""
    sealed: dict[int, bool] = {}
    for boundary, artifact in surfaces.values():
        units = len(artifact.blocks) + sum(len(block.instrs) for block in artifact.blocks)
        # Initial and fresh native graph captures are charged in their own
        # phases. The final immutable-fact seal walks current IR once; it
        # does not revisit either detached graph.
        if not budget.charge(units, scope.declared_entry):
            return None
        sealed[id(artifact)] = _scoped_native_rebind_failure_8616(
            boundary, artifact, native_facts[id(artifact)], snapshots[id(artifact)],
        ) is None
    if not budget.charge(0, scope.declared_entry):
        return None
    return sealed


def _selector_native_target_pure_8616(
    projection: DeclaredSelectorCallsite8616,
    artifact: IRFunctionArtifact,
    encoded: bytes | None,
) -> bool:
    """Purely compare retained identities and detached bytes — no callbacks."""
    if (
        projection.instruction.op != "CALL"
        or projection.instruction.addr != projection.callsite_addr
    ):
        return False
    if (
        not any(member is projection.block for member in artifact.blocks)
        or not any(member is projection.instruction for member in projection.block.instrs)
    ):
        return False
    if encoded is None or len(encoded) != 3 or encoded[0] != 0xE8:
        return False
    target = projection.callsite_addr + 3 + int.from_bytes(
        encoded[1:3], "little", signed=True)
    if (
        target != projection.target_addr
        or projection.next_addr != projection.callsite_addr + 3
    ):
        return False
    cs_base = projection.incoming_cs << _SHIFT
    return cs_base <= target <= cs_base + _WORD_LIMIT
