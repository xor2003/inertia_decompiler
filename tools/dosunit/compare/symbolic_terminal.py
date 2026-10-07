"""Bounded symbolic terminal-service comparison over actual MZ and PE32 bytes.

Layer: dosunit symbolic program proof.
Responsibility: consume the actual initialized program boot contracts of
``real16_program_boot`` and ``pe32_program_boot``, lift the executed native
region with the same PyVEX/SSA lowering the function comparator uses, and
compare the declared nonreturning terminal service — DOS ``INT 21h/AH=4Ch``
or the caller-declared flat32 exit gateway — under a content-bound
environment premise. The comparison proves equality of the terminal event
kind and payload plus all declared observable state, including prefix memory
effects and the modeled interrupt-entry frame. Returning continuations
exist only for the declared query contracts below and bounded PE32 no-argument
DWORD-returning services routed through genuine call/jmp dword ptr [IAT].
Import responses and clobbers are caller-declared synthetic contracts, not
proofs of Windows implementations. Ordered invocations remain observable, and
concrete replay receipts (``ProgramStatus`` / ``ProgramAgreement`` /
``ProgramEvent``) stay strictly separate from this symbolic verdict.

The bounded terminal outcome is typed: a lane either reaches its declared
service boundary or stops at a proved processor fault. The admitted fault
scope is the divide-error exception (``#DE``, vector 0) of decoded
``DIV``/``IDIV``/zero-``AAM`` instructions, decided at intake by
``terminal_fault`` against the complete architectural fault condition —
never only the subset of guards a VEX guest emits. A fault is a
nonreturning stop under the declared environment: no IVT/IDT handler
dispatch is modeled, the absence of a handler is an assumption carried in
the premises rather than proof of one, and the post-fault normal path is
never lowered or compared.

Scope is deliberately bounded: finite acyclic native regions ending at the
declared service or a proved fault, integer instruction scope, and a
service set of exactly one terminal contract per lane. The declared
``INT 21h/AH=30h AL=00`` version query and ``INT 10h/AH=0Fh`` video query
are the only returning services: each authenticates the live IVT slot
against its declared external entry, applies the modeled interrupt-entry
frame and the documented low-half register response, records an ordered
service event and continues at the exact fallthrough — a visible
environment premise, never real DOS/BIOS proof. Unknown DOS
services, changed gateway targets, ordinary calls, conditional/indirect
control, loops, port and machine-state effects, unproved pointers,
undeclared reads and writes, code writes, unproved or unadmitted fault
guards, other exception vectors and stale native bytes are typed refusals,
never silent outcomes. Every memory effect — live, intermediate or
discarded — is admitted at native intake by ``terminal_memory_effects``
before any output is trusted, and the joint proof's shared-initial premise
is verified against the concrete boot pair's declared bytes at every
proved read site. The synthetic PE ``exit_address`` gateway is an explicit
environment assumption — it is not Windows import coverage and proves
nothing about real ``ExitProcess``.
"""

from __future__ import annotations

import hashlib
import io
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

import angr
import capstone
import pyvex
import z3
from capstone import x86_const as decoded_ids

from tools.dosunit.architectures.flat32 import _FLAT32_REG_NAMES, flat32_register_architecture
from tools.dosunit.architectures.terminal_native_decode import (
    DEFAULT_NATIVE_LIMITS,
    TERMINAL_MAX_BLOCK_BYTES,
    TERMINAL_MAX_BLOCKS,
    TERMINAL_MAX_INSTRUCTIONS,
    NativeDecodeLimits,
    decode_terminal_block,
)
from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.symbolic_terminal_real16_services import (
    ReturningService,
    ServiceBlockEnding,
    TerminalServiceEvent,
    apply_version_effect,
    apply_video_effect,
    check_dos_vector,
    check_video_vector,
    declared_frame_aliases,
    verify_returning_receipts,
    version_answer,
    version_event,
    video_event,
)
from tools.dosunit.compare.terminal_fault import (
    FaultGate,
    FaultOutcome,
    TerminalOutcome,
    signal_fault_kind,
)
from tools.dosunit.compare.terminal_memory_effects import (
    InitialReadSite as InitialReadSite,
)
from tools.dosunit.compare.terminal_memory_effects import (
    MemoryReadAuditor as MemoryReadAuditor,
)
from tools.dosunit.compare.terminal_memory_effects import (
    TerminalRefusal as TerminalRefusal,
)
from tools.dosunit.compare.terminal_memory_effects import (
    TerminalRefusalKind as TerminalRefusalKind,
)
from tools.dosunit.compare.terminal_memory_effects import (
    check_memory_writes as _check_memory_writes,
)
from tools.dosunit.compare.terminal_memory_effects import (
    const_eval as _const_eval,
)
from tools.dosunit.compare.terminal_memory_effects import overlay_bytes
from tools.dosunit.contracts.binary_environment import (
    instruction_port_effect,
    instruction_requires_machine_state,
    requires_environment_contract,
)
from tools.dosunit.contracts.model import DosUnitError
from tools.dosunit.contracts.proof_contracts import Architecture, FactCounters, ProofStatus
from tools.dosunit.recursive_proofs.real16_loader_arch import real16_loader_arch
from tools.dosunit.reporting.proof_public_domain import (
    EnvironmentModel,
    InitialDataRelation,
    InstructionMemory,
    OutcomeAdmission,
)
from tools.dosunit.runtime.flat32_memory_permissions import DeclaredAccess
from tools.dosunit.runtime.flat32_replay import _instruction_scope
from tools.dosunit.runtime.pe32_import_service import (
    ImportResultKind,
    PeImportBinding,
    PeImportService,
    ServiceFlagsPolicy,
)
from tools.dosunit.runtime.pe32_program_boot import (
    PeProgramBoot,
    PeProgramEnvironment,
    pe_program_from_bytes,
)
from tools.dosunit.runtime.pe32_program_boot import (
    _environment_identity as _pe_environment_identity,
)
from tools.dosunit.runtime.pe32_program_boot import (
    _load_project as _pe_load_project,
)
from tools.dosunit.runtime.real16_program_boot import (
    ProgramBoot,
    ProgramEnvironment,
    program_from_mz_bytes,
)
from tools.dosunit.runtime.real16_program_interrupts import (
    INTERRUPT_ENTRY_MODEL,
    VIDEO_INTERRUPT_ENTRY_MODEL,
)
from tools.dosunit.runtime.real16_program_memory import ProgramMemoryLayout
from tools.dosunit.runtime.real16_program_model import ProgramEventKind
from tools.dosunit.runtime.real16_program_replay import _identities as _real16_identities
from tools.dosunit.runtime.real16_program_rom import readable_memory_contains
from tools.dosunit.runtime.real16_program_vectors import DOS_VECTOR, DOS_VECTOR_RANGE
from tools.dosunit.runtime.real16_program_version import VERSION_FUNCTION
from tools.dosunit.runtime.real16_program_video import VIDEO_FUNCTION, VIDEO_VECTOR
from tools.dosunit.runtime.real16_replay_model import LinearRange
from tools.dosunit.ssa.ssa_output_lemmas import prove_output_equalities

TERMINAL_MAX_ASSIGNMENTS: int = 8192

DOS_TERMINATE_FUNCTION: int = 0x4C
"""The admitted nonreturning DOS service selector (AH at the terminal site)."""

INTERRUPT_CORE_BASE: int = 0xFF000
INTERRUPT_CORE_LIMIT: int = INTERRUPT_CORE_BASE + 0x100


class TerminalService(StrEnum):
    """The single declared terminal contract each lane may prove."""

    DOS_TERMINATE = "dos_int21_ah4c"
    PE_DECLARED_EXIT = "pe32_declared_exit_gateway"


@dataclass(frozen=True, slots=True)
class TerminalBlockReceipt:
    """One admitted native block's bound byte and control evidence."""

    address: int
    size: int
    sha256: str
    jumpkind: str
    instructions: int
    next_target: int | None


@dataclass(frozen=True, slots=True)
class TerminalSite:
    """Binary-derived identity of the declared terminal boundary itself."""

    service: TerminalService
    address: int
    encoding: bytes
    target: int


@dataclass(frozen=True, slots=True)
class ImportedServiceEvent:
    """One consumed declared import-service invocation in execution order.

    ``service`` is the normalized ``dll!name`` binding identity — the
    observable the comparison sequences on. ``slot`` is the loaded IAT slot
    address the call routed through and ``site`` the call/jmp instruction's
    address; both are retained stale-evidence material for verification.
    ``sequence`` is the invocation's ordinal in the lane's dispatch order.
    """

    service: str
    slot: int
    site: int
    sequence: int


@dataclass(frozen=True, slots=True)
class SymbolicTerminalTrace:
    """One program's bounded symbolic terminal trace under its declared boot.

    ``source`` and ``environment`` are retained so verification can re-derive
    the boot identity and every block's byte digest before a comparison
    trusts the trace. ``document`` is the materialized SSA form of the
    complete terminal transition: prefix effects, the modeled
    interrupt-entry frame (real16), and the service payload under the
    declared concrete register seed. ``terminal_payload`` is the mandatory
    event payload output. ``initial_read_sites`` records every proved read
    that reached the shared initial memory — including dead and discarded
    reads, which remain concrete fault obligations — together with this
    lane's declared initial bytes at each site; the comparison re-derives
    the same resolver from the retained source so the boot pair's
    shared-initial premise is verified, never assumed.
    ``premises`` is the visible assumption set — the declared environment
    identity, the exact service or exception contract and the scope
    limitations — that a caller must propagate instead of treating the
    verdict as unconditional. ``outcome`` distinguishes the typed terminal
    boundary: a ``DECLARED_SERVICE`` trace carries ``site``; a
    ``PROCESSOR_FAULT`` trace carries ``fault`` — the retained kind/vector/
    site evidence — and ``site`` stays ``None`` because no service boundary
    was reached. ``service_events`` retains every returning declared
    service the region observed, in dispatch order and before the terminal
    outcome, so removed, reordered or repeated queries cannot disappear
    from the compared observables.
    """

    architecture: Architecture
    service: TerminalService
    event_kind: ProgramEventKind
    outcome: TerminalOutcome
    fault: FaultOutcome | None
    source: bytes
    environment: ProgramEnvironment | PeProgramEnvironment
    source_sha256: str
    boot_identity: str
    environment_identity: str
    entry: int
    site: TerminalSite | None
    blocks: tuple[TerminalBlockReceipt, ...]
    document: dict[str, Any]
    payload_bits: int
    initial_read_sites: tuple[InitialReadSite, ...]
    premises: tuple[Mapping[str, Any], ...]
    counters: FactCounters
    service_events: tuple[TerminalServiceEvent | ImportedServiceEvent, ...] = ()
    decode_limits: NativeDecodeLimits = field(default_factory=NativeDecodeLimits)
    """The exact finite native budget used at intake and evidence verification."""


@dataclass(frozen=True, slots=True)
class TerminalLaneResult:
    """Per-lane outcome: an admitted trace or a typed refusal."""

    trace: SymbolicTerminalTrace | None
    refusal: TerminalRefusal | None

    def __post_init__(self) -> None:
        """Require exactly one of trace or refusal, never both or neither."""
        if (self.trace is None) == (self.refusal is None):
            raise ValueError("a lane result carries exactly a trace or a typed refusal")


class TerminalComparisonStatus(StrEnum):
    """Verdict of the joint symbolic comparison, distinct from replay agreement."""

    EQUIVALENT = "equivalent"
    COUNTEREXAMPLE = "counterexample"
    UNKNOWN = "unknown"
    REFUSED = "refused"
    PREMISE_MISMATCH = "premise_mismatch"


@dataclass(frozen=True, slots=True)
class TerminalComparison:
    """Typed result of comparing two symbolic terminal-service traces.

    ``assumptions`` carries the complete service/environment premise set the
    verdict is conditional on; callers must propagate it through the shared
    proof domain instead of reading ``EQUIVALENT`` as unconditional proof.
    ``diverged`` names the compared outputs a countermodel distinguishes.
    """

    status: TerminalComparisonStatus
    architecture: Architecture | None
    service: TerminalService | None
    environment_identity: str | None
    detail: str
    oracle: TerminalLaneResult
    candidate: TerminalLaneResult
    counters: FactCounters
    assumptions: tuple[Mapping[str, Any], ...] = ()
    diverged: tuple[str, ...] = ()
    model: Mapping[str, Any] = field(default_factory=dict)
    solver_time_ms: int = 0

    def environment_model(self) -> EnvironmentModel:
        """Project the compared assumptions into the shared proof-domain type.

        External effects are declared ``COMPARED`` only when the verdict is
        ``EQUIVALENT`` — and then only for the terminal and ordered returning
        services recorded in ``assumptions``. Faults are declared ``COMPARED`` only
        when an ``EQUIVALENT`` verdict compared a processor-fault outcome;
        a service-boundary equivalence leaves the fault domain
        ``NOT_ESTABLISHED`` rather than claiming fault coverage it did not
        exercise, and any non-equivalent verdict establishes nothing. This
        does not weaken the public proof-domain guard; it is the
        caller-visible conditional premise for this bounded slice.
        """
        return EnvironmentModel(
            instruction_memory=InstructionMemory.IMMUTABLE,
            external_effects=OutcomeAdmission.COMPARED
            if self.status is TerminalComparisonStatus.EQUIVALENT
            else OutcomeAdmission.NOT_ESTABLISHED,
            faults=OutcomeAdmission.COMPARED
            if (
                self.status is TerminalComparisonStatus.EQUIVALENT
                and self.oracle.trace is not None
                and self.oracle.trace.outcome is TerminalOutcome.PROCESSOR_FAULT
            )
            else OutcomeAdmission.NOT_ESTABLISHED,
            initial_data=InitialDataRelation.SHARED_UNCONSTRAINED,
            premise=self.assumptions,
        )


@dataclass(frozen=True, slots=True)
class TerminalLimits:
    """Finite intake and solver budgets for the bounded terminal slice."""

    max_blocks: int = TERMINAL_MAX_BLOCKS
    max_block_bytes: int = TERMINAL_MAX_BLOCK_BYTES
    max_instructions: int = TERMINAL_MAX_INSTRUCTIONS
    max_assignments: int = TERMINAL_MAX_ASSIGNMENTS
    solver_timeout_ms: int = 15000

    def native_decode(self) -> NativeDecodeLimits:
        """Project the native limits without substituting independent default caps."""
        return NativeDecodeLimits(self.max_blocks, self.max_block_bytes, self.max_instructions)


# ---------------------------------------------------------------------------
# Shared intake helpers
# ---------------------------------------------------------------------------


def _decode_block(
    code: bytes, address: int, *, mode: int, limits: NativeDecodeLimits = DEFAULT_NATIVE_LIMITS,
) -> tuple[capstone.CsInsn, ...]:
    """Require complete instruction-boundary decode of the lifted extent."""
    return decode_terminal_block(code, address, mode=mode, limits=limits)


def _check_instruction_scope(instruction: capstone.CsInsn) -> None:
    """Apply the shared integer-scope admission to one decoded instruction."""
    reason = _instruction_scope(instruction)
    if reason is not None:
        raise TerminalRefusal(
            TerminalRefusalKind.INSTRUCTION_SCOPE,
            f"instruction at {hex(instruction.address)} outside integer scope: {reason.value}",
        )
    if instruction_port_effect(instruction) is not None:
        raise TerminalRefusal(
            TerminalRefusalKind.ENVIRONMENT_EFFECT,
            f"port effect at {hex(instruction.address)} requires an environment contract",
        )
    if instruction_requires_machine_state(instruction):
        raise TerminalRefusal(
            TerminalRefusalKind.ENVIRONMENT_EFFECT,
            f"machine-state instruction at {hex(instruction.address)} requires a system contract",
        )


def _check_flat32_instruction(instruction: capstone.CsInsn) -> None:
    """Mirror the PE replay per-instruction admission without executing it."""
    _check_instruction_scope(instruction)
    if instruction.id in {
        decoded_ids.X86_INS_IN, decoded_ids.X86_INS_OUT,
        decoded_ids.X86_INS_INSB, decoded_ids.X86_INS_INSW, decoded_ids.X86_INS_INSD,
        decoded_ids.X86_INS_OUTSB, decoded_ids.X86_INS_OUTSW, decoded_ids.X86_INS_OUTSD,
        decoded_ids.X86_INS_RDPMC, decoded_ids.X86_INS_XSETBV,
    }:
        raise TerminalRefusal(
            TerminalRefusalKind.ENVIRONMENT_EFFECT,
            f"undeclared external instruction at {hex(instruction.address)}",
        )
    _, written = instruction.regs_access()
    if {
        decoded_ids.X86_REG_CS, decoded_ids.X86_REG_SS, decoded_ids.X86_REG_DS,
        decoded_ids.X86_REG_ES, decoded_ids.X86_REG_FS, decoded_ids.X86_REG_GS,
    }.intersection(written):
        raise TerminalRefusal(
            TerminalRefusalKind.INSTRUCTION_SCOPE,
            f"segment-register write at {hex(instruction.address)} is unmodeled",
        )
    if any(
        operand.type == decoded_ids.X86_OP_MEM
        and operand.mem.segment in (decoded_ids.X86_REG_FS, decoded_ids.X86_REG_GS)
        for operand in instruction.operands
    ):
        raise TerminalRefusal(
            TerminalRefusalKind.ENVIRONMENT_EFFECT,
            f"fs/gs memory operand at {hex(instruction.address)} needs an environment contract",
        )


def _const_next(irsb: pyvex.IRSB) -> int | None:
    """Return the literal constant terminal target; ``None`` for symbolic next."""
    next_expr = irsb.next
    if isinstance(next_expr, pyvex.expr.Const):
        raw = next_expr.con.value
        return raw & 0xFFFFFFFF if isinstance(raw, int) else None
    return None


def _lowered_next(state: S._IrsbLowerState, irsb: pyvex.IRSB) -> S.SsaExpr:
    """Lower ``irsb.next`` through the block's temps into an SSA term.

    The real16 frontend leaves computed branch targets such as
    ``(cs << 4) + ip + disp`` in ``irsb.next``; under the declared concrete
    seed they still evaluate to constants. The returned term is the target
    evidence — call sites prove it constant or refuse indirect control.
    Must run after the block's statements are lowered into ``state``.
    """
    next_expr = irsb.next
    if isinstance(next_expr, pyvex.expr.Const):
        raw = next_expr.con.value
        if not isinstance(raw, int):
            import struct
            raw = int.from_bytes(
                struct.pack("<d" if int(next_expr.con.size) == 64 else "<f", float(raw)),
                "little")
        return S.SsaExpr("const", 32, value=raw & 0xFFFFFFFF)
    lowered = S._state_expression_lowerer(state)(
        next_expr,
        temp_defs=state.temp_defs,
        temp_failures=state.temp_failures,
        reg_versions=state.reg_versions,
        tyenv=irsb.tyenv,
        memory=state.mem_version,
        register_reader=state.architecture.reader if state.architecture else None,
    )
    if isinstance(lowered, S.LowerFailure):
        raise TerminalRefusal(
            TerminalRefusalKind.UNSUPPORTED_IR,
            f"block successor: {lowered.reason}: {lowered.message}",
        )
    return lowered


def _proved_next(
    state: S._IrsbLowerState, irsb: pyvex.IRSB, *, auditor: MemoryReadAuditor | None = None
) -> int:
    """Return the proved constant successor of a lowered block."""
    target_expr = _lowered_next(state, irsb)
    if auditor is not None:
        auditor.audit_term(target_expr)
    target = _const_eval(target_expr)
    if target is None:
        raise TerminalRefusal(
            TerminalRefusalKind.INDIRECT_CONTROL, "non-constant block successor"
        )
    return target


def _fault_gate(
    instructions: tuple[capstone.CsInsn, ...],
    *,
    dividend: Callable[[Mapping[str, S.SsaExpr], int], S.SsaExpr | None],
    initial_bytes: Callable[[int, int], bytes | None] | None = None,
) -> FaultGate:
    """Bind one lifted block's fault gate to its decoded instruction map."""
    return FaultGate(
        instructions={int(instruction.address): instruction for instruction in instructions},
        dividend=dividend,
        initial_bytes=initial_bytes,
    )


def _lower_into(
    state: S._IrsbLowerState,
    irsb: pyvex.IRSB,
    state_regs: tuple[str, ...],
    *,
    auditor: MemoryReadAuditor | None = None,
    fault_gate: FaultGate | None = None,
) -> FaultOutcome | None:
    """Lower one block into the running SSA state; stop at a proved fault.

    ``Ist_IMark`` markers carry no machine effect; when a ``fault_gate`` is
    bound it decides instruction-level faults the lifter leaves unguarded at
    each mark and admits every ``Ist_Exit`` as declared fault evidence —
    anything else exits as a typed refusal. A proved ``FaultOutcome`` ends
    the block's execution exactly where the exception fires: statements the
    signal exit guards — and every following instruction — are never lowered
    or compared, so a post-fault normal path cannot leak into the outcome.
    Without a gate, any ``Ist_Exit`` still lands in ``state.exits`` and
    fails closed below, preserving the prior unconditional-flow refusal.
    When an auditor is bound, every memory read the block introduced —
    live, intermediate or discarded — is admitted before the block
    completes, including on the faulting early return.
    """
    state.temp_defs = {}
    state.temp_failures = {}
    imark: int | None = None
    for statement in irsb.statements:
        if statement.tag == "Ist_IMark":
            imark = int(statement.addr)
            if fault_gate is not None:
                outcome = fault_gate.pre_check(imark)
                if outcome is not None:
                    if auditor is not None:
                        auditor.audit_state(state)
                    return outcome
            continue
        if statement.tag == "Ist_Exit" and fault_gate is not None:
            outcome = fault_gate.admit_exit(
                statement=statement,
                state=state,
                tyenv=irsb.tyenv,
                imark=imark,
                auditor=auditor,
            )
            if outcome is not None:
                if auditor is not None:
                    auditor.audit_state(state)
                return outcome
            continue
        failure = S._lower_irsb_statement(
            statement, state, tyenv=irsb.tyenv, output_regs=state_regs
        )
        if failure is not None:
            raise TerminalRefusal(
                TerminalRefusalKind.UNSUPPORTED_IR, f"{failure.reason}: {failure.message}"
            )
    _finish_lowered_block(state, fault_gate=fault_gate, auditor=auditor)
    return None


def _finish_lowered_block(
    state: S._IrsbLowerState,
    *,
    fault_gate: FaultGate | None,
    auditor: MemoryReadAuditor | None,
) -> None:
    """Complete one lowered block's admission checks.

    A bound gate must have seen fault evidence for every divide mark it
    tracked; retained conditional exits, external io events and — when an
    auditor is bound — every memory read the block introduced are checked
    before the block's effects are trusted.
    """
    if fault_gate is not None:
        fault_gate.finish()
    if state.exits:
        raise TerminalRefusal(
            TerminalRefusalKind.CONDITIONAL_CONTROL, "lowered state retained conditional exits"
        )
    if state.io_touched:
        raise TerminalRefusal(
            TerminalRefusalKind.ENVIRONMENT_EFFECT, "lowered block produced an external io event"
        )
    if auditor is not None:
        auditor.audit_state(state)


def _materialize_document(
    state: S._IrsbLowerState,
    *,
    payload: S.SsaExpr,
    compared: dict[str, S.SsaExpr],
    max_assignments: int,
    include_memory: bool = False,
) -> dict[str, Any]:
    """Materialize the complete observable terminal transition into SSA JSON."""
    assignments: list[dict[str, Any]] = []
    memo: dict[tuple[Any, ...], str] = {}
    object_memo: dict[int, dict[str, Any]] = {}
    terms: list[S.SsaExpr] = [payload, *compared.values()]
    if state.memory_touched or include_memory:
        terms.append(state.mem_version)
    for expr in terms:
        failure = S._expr_failure(expr)
        if failure is not None:
            raise TerminalRefusal(
                TerminalRefusalKind.UNSUPPORTED_IR,
                f"output term: {failure.reason}: {failure.message}",
            )
    outputs: dict[str, Any] = {}
    try:
        outputs["terminal_payload"] = S._materialize(
            payload,
            assignments=assignments,
            memo=memo,
            object_memo=object_memo,
            max_assignments_per_function=max_assignments,
        )
        if state.memory_touched or include_memory:
            outputs["memory"] = S._materialize(
                state.mem_version,
                assignments=assignments,
                memo=memo,
                object_memo=object_memo,
                max_assignments_per_function=max_assignments,
            )
        for name, expr in sorted(compared.items()):
            outputs[name] = S._materialize(
                expr,
                assignments=assignments,
                memo=memo,
                object_memo=object_memo,
                max_assignments_per_function=max_assignments,
            )
    except S.LowerFailure as failure:
        raise TerminalRefusal(
            TerminalRefusalKind.UNSUPPORTED_IR, f"{failure.reason}: {failure.message}"
        ) from failure
    inputs = S._collect_inputs(tuple(terms))
    items = S._irsb_input_items(state, inputs)
    emitted = {str(item["name"]) for item in items}
    return {
        "inputs": [*items, *_extra_input_items(terms, emitted)],
        "outputs": outputs,
        "assignments": assignments,
    }


def _extra_input_items(
    terms: list[S.SsaExpr], emitted: set[str]
) -> list[dict[str, Any]]:
    """Keep declared non-register inputs the register table does not name.

    Declared service effects introduce caller-named opaque inputs (service
    responses, volatile clobbers, flag clobbers) that share the comparison's
    input space. ``S._input_items`` only indexes modeled register names, so
    without this projection the declared terms would reach Z3 without a
    declared variable — a silent drop, never a premise.
    """
    found: dict[str, int] = {}
    seen: set[int] = set()
    stack = list(terms)
    while stack:
        expr = stack.pop()
        if id(expr) in seen:
            continue
        seen.add(id(expr))
        if expr.op == "input" and expr.name and expr.name not in emitted:
            found[expr.name] = max(int(expr.width), found.get(expr.name, 0))
        stack.extend(expr.args)
    return [{"name": name, "width": width} for name, width in sorted(found.items())]


def _chunk_bytes(chunks: tuple[tuple[int, bytes], ...], address: int) -> tuple[int, bytes] | None:
    """Locate the initialized byte chunk covering ``address``."""
    for start, data in chunks:
        if start <= address < start + len(data):
            return start, data
    return None


def _lift_block(
    project: angr.Project, address: int, window: bytes, num_inst: int | None = None
) -> pyvex.IRSB:
    """Lift one bounded window into a checked VEX block."""
    try:
        irsb = project.factory.block(
            address, byte_string=window, size=len(window), opt_level=0, num_inst=num_inst
        ).vex
    except (angr.errors.AngrError, pyvex.errors.PyVEXError) as error:
        raise TerminalRefusal(
            TerminalRefusalKind.LIFT, f"lift failed at {hex(address)}: {type(error).__name__}"
        ) from error
    if not isinstance(irsb, pyvex.IRSB) or irsb.size <= 0 or irsb.jumpkind == "Ijk_NoDecode":
        raise TerminalRefusal(TerminalRefusalKind.LIFT, f"incomplete VEX lift at {hex(address)}")
    return irsb


def _lift_window(
    project: angr.Project,
    chunks: tuple[tuple[int, bytes], ...],
    address: int,
    limits: TerminalLimits,
    *,
    mode: int,
    executable_extent: int | None = None,
) -> tuple[pyvex.IRSB, bytes, bytes, tuple[capstone.CsInsn, ...]]:
    """Fetch, lift and fully decode one block over the initialized bytes."""
    located = _chunk_bytes(chunks, address)
    if located is None:
        raise TerminalRefusal(
            TerminalRefusalKind.CONTROL_ESCAPE,
            f"successor {hex(address)} leaves initialized image bytes",
        )
    chunk_base, chunk = located
    end = min(chunk_base + len(chunk), address + limits.max_block_bytes)
    if executable_extent is not None:
        end = min(end, address + executable_extent)
    window = bytes(chunk[address - chunk_base : end - chunk_base])
    lifted = _lift_block(project, address, window)
    if lifted.size > len(window) or lifted.instructions > limits.max_instructions:
        raise TerminalRefusal(TerminalRefusalKind.LIFT, "lifted extent exceeds intake budget")
    code = window[: lifted.size]
    if requires_environment_contract(lifted):
        raise TerminalRefusal(
            TerminalRefusalKind.ENVIRONMENT_EFFECT,
            f"block at {hex(address)} contains an opaque dirty helper",
        )
    return lifted, code, window, _decode_block(code, address, mode=mode, limits=limits.native_decode())


# ---------------------------------------------------------------------------
# Real16 (MZ) intake: DOS INT 21h / AH=4Ch
# ---------------------------------------------------------------------------


def _real16_register_seed(boot: ProgramBoot) -> dict[str, S.SsaExpr]:
    """Seed the declared concrete register file the boot contract supplies.

    Environment registers are full 32-bit values split into the modeled
    16-bit register plus its 386 high half; header-owned CS/IP/SS/SP and the
    PSP-anchored DS/ES come from the binary-derived boot coordinates. The
    lifter's artificial ``dflag`` storage stays a shared symbolic input.
    """
    declared = dict(boot.environment.registers)
    seed: dict[str, S.SsaExpr] = dict(S._initial_reg_versions())
    paired = {
        "eax": ("ax", "eax_hi"), "ecx": ("cx", "ecx_hi"), "edx": ("dx", "edx_hi"),
        "ebx": ("bx", "ebx_hi"), "esp": ("sp", "esp_hi"), "ebp": ("bp", "ebp_hi"),
        "esi": ("si", "esi_hi"), "edi": ("di", "edi_hi"),
    }
    for name, value in declared.items():
        if name == "eflags":
            seed["flags"] = S.SsaExpr("const", 16, value=value & 0xFFFF)
            continue
        low, high = paired[name]
        if name == "esp":
            value = boot.stack.offset
        seed[low] = S.SsaExpr("const", 16, value=value & 0xFFFF)
        seed[high] = S.SsaExpr("const", 16, value=(value >> 16) & 0xFFFF)
    seed["cs"] = S.SsaExpr("const", 16, value=boot.entry.segment)
    seed["ip"] = S.SsaExpr("const", 16, value=boot.entry.offset)
    seed["ss"] = S.SsaExpr("const", 16, value=boot.stack.segment)
    seed["ds"] = S.SsaExpr("const", 16, value=boot.environment.psp_segment)
    seed["es"] = S.SsaExpr("const", 16, value=boot.environment.psp_segment)
    seed["fs"] = S.SsaExpr("const", 16, value=boot.environment.fs)
    seed["gs"] = S.SsaExpr("const", 16, value=boot.environment.gs)
    return seed


def _real16_dividend(
    registers: Mapping[str, S.SsaExpr], operand_bits: int
) -> S.SsaExpr | None:
    """Project the real16 implicit dividend of a divide operand width.

    ``DIV``/``IDIV`` take their dividend from ``AX`` (8-bit operand),
    ``DX:AX`` (16-bit) or ``EDX:EAX`` (32-bit); the 386 high halves live in
    the ``*_hi`` seed registers, so the 64-bit form concatenates both pairs.
    """
    if operand_bits == 8:
        return registers["ax"]
    if operand_bits == 16:
        return S.SsaExpr("concat", 32, (registers["dx"], registers["ax"]))
    if operand_bits == 32:
        edx = S.SsaExpr("concat", 32, (registers["edx_hi"], registers["dx"]))
        eax = S.SsaExpr("concat", 32, (registers["eax_hi"], registers["ax"]))
        return S.SsaExpr("concat", 64, (edx, eax))
    return None


def _check_dos_service_contract(environment: ProgramEnvironment) -> None:
    """Refuse vector-covered memory that no declared policy authenticates.

    Every real16 lane ends at ``INT 21h``, so the concrete ``POLICY_REQUIRED``
    boundary is decided eagerly here; ``check_dos_vector`` re-checks the
    identical gate at each dispatch and, with a declared policy,
    authenticates the live IVT bytes against it.
    """
    layout = environment.memory_layout()
    if environment.vector_policy is None and any(
        region.overlaps(DOS_VECTOR_RANGE.address, DOS_VECTOR_RANGE.size)
        for region in layout.ranges
    ):
        raise TerminalRefusal(
            TerminalRefusalKind.UNSUPPORTED_ENVIRONMENT,
            "declared memory covers the DOS vector without a vector policy",
        )


def _real16_admit_read(
    boot: ProgramBoot, layout: ProgramMemoryLayout
) -> Callable[[int, int], None]:
    """Build the real16 load admittance: declared RAM or declared ROM only.

    Reuses ``readable_memory_contains``, the same bounded owner the concrete
    replay uses for data reads — an unmapped or undeclared-range read is a
    real fault there and a typed refusal here.
    """
    rom = boot.environment.rom

    def admit(address: int, size: int) -> None:
        if not readable_memory_contains(layout, rom, address, size):
            raise TerminalRefusal(
                TerminalRefusalKind.UNDECLARED_READ,
                f"load at {hex(address)} lacks declared readable coverage",
            )

    return admit


def _real16_initial_bytes(boot: ProgramBoot) -> Callable[[int, int], bytes | None]:
    """Resolve declared initial bytes as the replay loader overlays them.

    The concrete ``_initialize`` writes the arena/extra chunks, overlays the
    relocated image, then maps ROM read-only — so ROM wins, then image, then
    the arena layer.
    """
    layout = boot.environment.memory_layout()
    rom = boot.environment.rom
    layers: list[tuple[tuple[int, bytes], ...]] = [boot.image.chunks, layout.chunks]
    if rom is not None:
        layers.insert(0, rom.chunks)
    return lambda address, size: overlay_bytes(layers, address, size)


def _storele16(memory: S.SsaExpr, address: int, value: S.SsaExpr) -> S.SsaExpr:
    """Apply one checked 16-bit little-endian store to the memory version."""
    return S.SsaExpr(
        "storele",
        0,
        (memory, S.SsaExpr("const", 32, value=address), S._coerce_width(value, 16)),
    )


def _apply_interrupt_frame(
    state: S._IrsbLowerState,
    *,
    site_address: int,
    layout: ProgramMemoryLayout,
    code_ranges: tuple[LinearRange, ...],
    aliased: tuple[tuple[LinearRange, str], ...] = (),
) -> int:
    """Apply the declared interrupt-entry stack effects; return the pushed IP.

    Mirrors the ``program_interrupt_frame`` predicates: six bytes at
    ``SS:SP-6`` — the post-instruction IP word, CS and FLAGS — with SP
    unchanged. Every predicate is checked against concrete register terms
    under the declared seed; symbolic stack or code-segment coordinates
    refuse as unproved pointers rather than guessing a frame address.
    ``aliased`` names the declared live-vector ranges the frame may never
    overlap, each paired with its concrete refusal detail — the same gate
    the concrete ``_service_frame`` runs before writing the bytes.
    """
    cs = _const_eval(state.reg_versions["cs"])
    sp = _const_eval(state.reg_versions["sp"])
    ss = _const_eval(state.reg_versions["ss"])
    if cs is None or sp is None or ss is None:
        raise TerminalRefusal(
            TerminalRefusalKind.UNPROVED_POINTER,
            "interrupt frame coordinates are not proved concrete",
        )
    return_ip = site_address - (cs << 4)
    if not 0 <= return_ip <= 0xFFFF or return_ip + 2 > 0xFFFF:
        raise TerminalRefusal(TerminalRefusalKind.INTERRUPT_FRAME, "service_fallthrough_wrap")
    if sp < 6:
        raise TerminalRefusal(TerminalRefusalKind.INTERRUPT_FRAME, "interrupt_frame_wrap")
    address = (ss << 4) + sp - 6
    if not layout.contains(address, 6):
        raise TerminalRefusal(TerminalRefusalKind.INTERRUPT_FRAME, "interrupt_frame_undeclared")
    if any(region.overlaps(address, 6) for region in code_ranges):
        raise TerminalRefusal(TerminalRefusalKind.INTERRUPT_FRAME, "interrupt_frame_code_write")
    for region, detail in aliased:
        if region.overlaps(address, 6):
            raise TerminalRefusal(TerminalRefusalKind.INTERRUPT_FRAME, detail)
    state.mem_version = _storele16(
        state.mem_version, address, S.SsaExpr("const", 16, value=(return_ip + 2) & 0xFFFF)
    )
    state.mem_version = _storele16(
        state.mem_version, address + 2, S.SsaExpr("const", 16, value=cs)
    )
    state.mem_version = _storele16(state.mem_version, address + 4, state.reg_versions["flags"])
    state.memory_touched = True
    return return_ip


def _service_selector(state: S._IrsbLowerState) -> int:
    """Prove the service selector ``AH`` under the declared register seed.

    The register state is bound to the declared concrete boot seed, so the
    selector term is either a provable constant or carries unseeded symbolic
    inputs — the latter is an honest ``service_guard_unproved`` refusal,
    never a guessed dispatch.
    """
    ax = state.reg_versions["ax"]
    selector = _const_eval(S.SsaExpr("lshr", 16, (ax, S.SsaExpr("const", 16, value=8))))
    if selector is None:
        raise TerminalRefusal(
            TerminalRefusalKind.SERVICE_GUARD_UNPROVED,
            "AH selector is not proved under the declared state",
        )
    return selector


def _prove_service_selector(state: S._IrsbLowerState, *, expected: int) -> None:
    """Require the proved service selector ``AH`` to equal ``expected``.

    A proved different selector is an ``undeclared_service`` refusal —
    the same gate ``_service_selector`` decides for dispatch.
    """
    selector = _service_selector(state)
    if selector != expected:
        raise TerminalRefusal(
            TerminalRefusalKind.UNDECLARED_SERVICE,
            f"INT 21h selector AH=0x{selector:02x} is not the declared 0x{expected:02x} service",
        )


def _real16_interrupt_site(
    state: S._IrsbLowerState,
    project: angr.Project,
    lifted: pyvex.IRSB,
    instructions: tuple[capstone.CsInsn, ...],
    code: bytes,
    window: bytes,
    *,
    address: int,
    environment: ProgramEnvironment,
    layout: ProgramMemoryLayout,
    code_ranges: tuple[LinearRange, ...],
    state_regs: tuple[str, ...],
    auditor: MemoryReadAuditor,
    initial_bytes: Callable[[int, int], bytes | None],
) -> TerminalSite | FaultOutcome | ReturningService:
    """Admit a lifted ``Ijk_Call`` as a decoded ``CD imm8`` service boundary.

    The boundary target must be the literal interrupt-core constant in the
    lifted ``next``, and the last decoded instruction must be ``INT imm8``
    whose operand byte equals that vector. Only the pre-interrupt prefix is
    lowered — the synthetic call's internal writes (``ip_at_syscall``,
    ``ip``) are never part of guest state. A proved fault inside that
    prefix preempts the boundary: the interrupt never executes on
    hardware, so the outcome is the fault. A proved selector then
    dispatches: ``INT 21h/AH=4Ch`` is the nonreturning terminal site, the
    declared ``AH=30h AL=00`` version query and ``INT 10h/AH=0Fh`` video
    query are returning services whose ordered event and exact
    register/frame effects are applied before the walk continues at the
    fallthrough, and every other vector or selector is an
    ``undeclared_service`` refusal.
    """
    target = _const_next(lifted)
    last = instructions[-1]
    terminal_bytes = bytes(code[len(code) - last.size :])
    if target is None or not INTERRUPT_CORE_BASE <= target < INTERRUPT_CORE_LIMIT:
        raise TerminalRefusal(
            TerminalRefusalKind.CALL_BOUNDARY,
            "call target "
            + ("<symbolic>" if target is None else hex(target))
            + " is not a declared service boundary",
        )
    vector = target - INTERRUPT_CORE_BASE
    if last.id != decoded_ids.X86_INS_INT or terminal_bytes != bytes((0xCD, vector)):
        raise TerminalRefusal(
            TerminalRefusalKind.SERVICE_ENCODING,
            "lifted interrupt boundary does not match decoded CD imm8 encoding",
        )
    if vector not in (DOS_VECTOR, VIDEO_VECTOR):
        raise TerminalRefusal(
            TerminalRefusalKind.UNDECLARED_SERVICE,
            f"interrupt vector 0x{vector:02x} is not a declared service",
        )
    for instruction in instructions[:-1]:
        _check_instruction_scope(instruction)
    if len(instructions) > 1:
        prefix = _lift_block(project, address, window, num_inst=len(instructions) - 1)
        outcome = _lower_into(
            state,
            prefix,
            state_regs,
            auditor=auditor,
            fault_gate=_fault_gate(
                instructions[:-1],
                dividend=_real16_dividend,
                initial_bytes=initial_bytes,
            ),
        )
        if outcome is not None:
            return outcome
    if vector == DOS_VECTOR:
        return _real16_dos_dispatch(
            state,
            last.address,
            terminal_bytes,
            target,
            environment=environment,
            layout=layout,
            code_ranges=code_ranges,
            initial_bytes=initial_bytes,
        )
    return _real16_video_dispatch(
        state,
        last.address,
        environment=environment,
        layout=layout,
        code_ranges=code_ranges,
        initial_bytes=initial_bytes,
    )


def _real16_call_block(
    state: S._IrsbLowerState,
    project: angr.Project,
    lifted: pyvex.IRSB,
    instructions: tuple[capstone.CsInsn, ...],
    code: bytes,
    window: bytes,
    *,
    address: int,
    jumpkind: str,
    environment: ProgramEnvironment,
    layout: ProgramMemoryLayout,
    code_ranges: tuple[LinearRange, ...],
    state_regs: tuple[str, ...],
    auditor: MemoryReadAuditor,
    initial_bytes: Callable[[int, int], bytes | None],
) -> tuple[TerminalBlockReceipt, TerminalSite | FaultOutcome | ReturningService, int | None]:
    """Dispatch one ``Ijk_Call`` block; return its receipt, outcome, continuation.

    The continuation is non-``None`` only for a returning declared service —
    its proved fallthrough after the code-scope gate — while the receipt's
    ``next_target`` records the interrupt core target (terminal), the
    fallthrough (returning) or ``None`` (fault).
    """
    boundary = _real16_interrupt_site(
        state,
        project,
        lifted,
        instructions,
        code,
        window,
        address=address,
        environment=environment,
        layout=layout,
        code_ranges=code_ranges,
        state_regs=state_regs,
        auditor=auditor,
        initial_bytes=initial_bytes,
    )
    next_target: int | None = None
    if isinstance(boundary, ReturningService):
        _require_code_scope(code_ranges, boundary.fallthrough)
        next_target = boundary.fallthrough
    elif isinstance(boundary, TerminalSite):
        next_target = boundary.target
    receipt = TerminalBlockReceipt(
        address, lifted.size, hashlib.sha256(code).hexdigest(),
        jumpkind, lifted.instructions, next_target,
    )
    return receipt, boundary, next_target


def _require_code_scope(code_ranges: tuple[LinearRange, ...], address: int) -> None:
    """Require a proved successor to stay inside declared code scope."""
    if not any(region.contains(address) for region in code_ranges):
        raise TerminalRefusal(
            TerminalRefusalKind.CONTROL_ESCAPE,
            f"service fallthrough {hex(address)} leaves declared code scope",
        )


def _real16_dos_dispatch(
    state: S._IrsbLowerState,
    site_address: int,
    terminal_bytes: bytes,
    target: int,
    *,
    environment: ProgramEnvironment,
    layout: ProgramMemoryLayout,
    code_ranges: tuple[LinearRange, ...],
    initial_bytes: Callable[[int, int], bytes | None],
) -> TerminalSite | ReturningService:
    """Dispatch a proved ``INT 21h`` boundary on its concrete ``AH`` selector.

    Mirrors the concrete service order — selector admission, live DOS
    vector authentication, then the declared entry frame — before either
    returning the terminal site (``AH=4Ch``) or applying the declared
    version response, recording its ordered event and publishing the exact
    fallthrough IP (``AH=30h AL=00``). Any other proved selector and a
    missing declared policy are ``undeclared_service`` refusals.
    """
    selector = _service_selector(state)
    if selector == DOS_TERMINATE_FUNCTION:
        check_dos_vector(
            environment=environment,
            layout=layout,
            mem_version=state.mem_version,
            initial_bytes=initial_bytes,
        )
        return TerminalSite(TerminalService.DOS_TERMINATE, site_address, terminal_bytes, target)
    if selector != VERSION_FUNCTION or environment.version_policy is None:
        raise TerminalRefusal(
            TerminalRefusalKind.UNDECLARED_SERVICE,
            f"INT 21h selector AH=0x{selector:02x} is not a declared service",
        )
    check_dos_vector(
        environment=environment,
        layout=layout,
        mem_version=state.mem_version,
        initial_bytes=initial_bytes,
    )
    return_ip = _apply_interrupt_frame(
        state,
        site_address=site_address,
        layout=layout,
        code_ranges=code_ranges,
        aliased=declared_frame_aliases(environment),
    )
    answered = version_answer(policy=environment.version_policy, state=state)
    apply_version_effect(state, answered)
    state.reg_versions["ip"] = S.SsaExpr("const", 16, value=(return_ip + 2) & 0xFFFF)
    return ReturningService(
        event=version_event(site_address, environment.version_policy),
        fallthrough=site_address + 2,
        fallthrough_ip=(return_ip + 2) & 0xFFFF,
    )


def _real16_video_dispatch(
    state: S._IrsbLowerState,
    site_address: int,
    *,
    environment: ProgramEnvironment,
    layout: ProgramMemoryLayout,
    code_ranges: tuple[LinearRange, ...],
    initial_bytes: Callable[[int, int], bytes | None],
) -> ReturningService:
    """Dispatch a proved ``INT 10h`` boundary to the declared video query.

    ``AH=0Fh`` under a declared ``video_policy`` is the only admitted BIOS
    service: the live IVT slot must still target the declared external
    entry, the entry frame applies with its alias gates, then the declared
    mode/columns/page bytes update AX and BH before the fallthrough.
    """
    if environment.video_policy is None:
        raise TerminalRefusal(
            TerminalRefusalKind.UNDECLARED_SERVICE,
            "INT 10h dispatched without a declared video policy",
        )
    selector = _service_selector(state)
    if selector != VIDEO_FUNCTION:
        raise TerminalRefusal(
            TerminalRefusalKind.UNDECLARED_SERVICE,
            f"INT 10h selector AH=0x{selector:02x} is not the declared 0x{VIDEO_FUNCTION:02x} service",
        )
    check_video_vector(
        policy=environment.video_policy,
        environment=environment,
        mem_version=state.mem_version,
        initial_bytes=initial_bytes,
    )
    return_ip = _apply_interrupt_frame(
        state,
        site_address=site_address,
        layout=layout,
        code_ranges=code_ranges,
        aliased=declared_frame_aliases(environment),
    )
    apply_video_effect(state, environment.video_policy)
    state.reg_versions["ip"] = S.SsaExpr("const", 16, value=(return_ip + 2) & 0xFFFF)
    return ReturningService(
        event=video_event(site_address, environment.video_policy),
        fallthrough=site_address + 2,
        fallthrough_ip=(return_ip + 2) & 0xFFFF,
    )


def _real16_advance(
    state: S._IrsbLowerState,
    lifted: pyvex.IRSB,
    instructions: tuple[capstone.CsInsn, ...],
    *,
    address: int,
    boot: ProgramBoot,
    state_regs: tuple[str, ...],
    auditor: MemoryReadAuditor,
    initial_bytes: Callable[[int, int], bytes | None],
) -> int | FaultOutcome:
    """Lower one nonterminal block; return its successor or a proved fault."""
    for instruction in instructions:
        _check_instruction_scope(instruction)
    jumpkind = str(lifted.jumpkind)
    if jumpkind == "Ijk_Ret":
        raise TerminalRefusal(
            TerminalRefusalKind.RETURN_NOT_TERMINAL,
            f"return instruction at {hex(address)} ends the region without the declared service",
        )
    if jumpkind != "Ijk_Boring" and not (
        jumpkind.startswith("Ijk_Sig") and signal_fault_kind(jumpkind) is not None
    ):
        if jumpkind.startswith("Ijk_Sig"):
            raise TerminalRefusal(
                TerminalRefusalKind.FAULT_BOUNDARY, f"trap outcome {jumpkind} at {hex(address)}"
            )
        raise TerminalRefusal(
            TerminalRefusalKind.CONTROL_ESCAPE,
            f"unsupported jumpkind {jumpkind} at {hex(address)}",
        )
    outcome = _lower_into(
        state,
        lifted,
        state_regs,
        auditor=auditor,
        fault_gate=_fault_gate(
            instructions,
            dividend=_real16_dividend,
            initial_bytes=initial_bytes,
        ),
    )
    if outcome is not None:
        return outcome
    if jumpkind.startswith("Ijk_Sig"):
        raise TerminalRefusal(
            TerminalRefusalKind.FAULT_BOUNDARY,
            f"block at {hex(address)} ends on {jumpkind} without decided fault evidence",
        )
    successor = _proved_next(state, lifted, auditor=auditor)
    if not any(region.contains(successor) for region in boot.image.code_ranges):
        raise TerminalRefusal(
            TerminalRefusalKind.CONTROL_ESCAPE,
            f"successor {hex(successor)} leaves declared code scope",
        )
    return successor


def trace_real16_terminal(
    data: bytes, environment: ProgramEnvironment, *, limits: TerminalLimits | None = None
) -> SymbolicTerminalTrace:
    """Trace one actual MZ program to its declared DOS termination boundary.

    The boot contract, image chunks, entry and stack are derived from the
    real serialized bytes by ``program_from_mz_bytes``; blocks are lifted
    from the relocated image bytes, never from caller-supplied offsets or
    rendered text. The trace ends at the first ``INT 21h`` whose decoded
    operand and lifted ``Ijk_Call`` target agree on vector ``0x21`` and
    whose ``AH`` selector is proved ``0x4C`` under the declared seed.
    """
    limits = limits or TerminalLimits()
    try:
        boot = program_from_mz_bytes(data, environment)
    except ValueError as error:
        raise TerminalRefusal(TerminalRefusalKind.BOOT_CONTRACT, str(error)) from error
    _check_dos_service_contract(environment)
    if len(boot.image.chunks) != 1:
        raise TerminalRefusal(
            TerminalRefusalKind.LIFT, "MZ program requires one contiguous relocated image chunk"
        )
    image_base, image_bytes = boot.image.chunks[0]
    project = angr.Project(
        io.BytesIO(image_bytes),
        auto_load_libs=False,
        main_opts={
            "backend": "blob",
            "arch": real16_loader_arch(),
            "base_addr": image_base,
            "entry_point": boot.entry.linear(),
        },
    )
    state = S._IrsbLowerState(
        reg_versions=_real16_register_seed(boot),
        mem_version=S.SsaExpr("mem_input", 0, name="mem"),
        io_version=S.SsaExpr("mem_input", 0, name="io"),
    )
    state_regs = S._internal_state_regs()
    layout = environment.memory_layout()
    initial_bytes = _real16_initial_bytes(boot)
    read_auditor = MemoryReadAuditor(
        admit=_real16_admit_read(boot, layout), initial_bytes=initial_bytes
    )
    blocks: list[TerminalBlockReceipt] = []
    events: list[TerminalServiceEvent] = []
    visited: set[int] = set()
    site: TerminalSite | None = None
    fault: FaultOutcome | None = None
    address = boot.entry.linear()
    while site is None and fault is None:
        if address in visited:
            raise TerminalRefusal(
                TerminalRefusalKind.LOOP_BOUNDARY, f"control revisited {hex(address)}"
            )
        visited.add(address)
        if len(blocks) >= limits.max_blocks:
            raise TerminalRefusal(TerminalRefusalKind.BLOCK_LIMIT, "bounded region limit reached")
        lifted, code, window, instructions = _lift_window(
            project, boot.image.chunks, address, limits, mode=capstone.CS_MODE_16
        )
        jumpkind = str(lifted.jumpkind)
        if jumpkind == "Ijk_Call":
            receipt, boundary, continuation = _real16_call_block(
                state,
                project,
                lifted,
                instructions,
                code,
                window,
                address=address,
                jumpkind=jumpkind,
                environment=environment,
                layout=layout,
                code_ranges=boot.image.code_ranges,
                state_regs=state_regs,
                auditor=read_auditor,
                initial_bytes=initial_bytes,
            )
            blocks.append(receipt)
            if isinstance(boundary, FaultOutcome):
                fault = boundary
            elif isinstance(boundary, ReturningService):
                events.append(boundary.event)
                assert continuation is not None
                address = continuation
            else:
                site = boundary
            continue
        advanced = _real16_advance(
            state,
            lifted,
            instructions,
            address=address,
            boot=boot,
            state_regs=state_regs,
            auditor=read_auditor,
            initial_bytes=initial_bytes,
        )
        if isinstance(advanced, FaultOutcome):
            fault = advanced
            blocks.append(
                TerminalBlockReceipt(
                    address, lifted.size, hashlib.sha256(code).hexdigest(),
                    jumpkind, lifted.instructions, None,
                )
            )
            continue
        blocks.append(
            TerminalBlockReceipt(
                address, lifted.size, hashlib.sha256(code).hexdigest(),
                jumpkind, lifted.instructions, advanced,
            )
        )
        address = advanced

    compared = {
        name: state.reg_versions[name]
        for name in state_regs
        if name in state.reg_versions and name not in {"ip", "control_ip"}
    }
    boot_identity, environment_identity = _real16_identities(boot)
    environment_premise = {
        "kind": "declared_environment_identity",
        "sha256": environment_identity,
        "boot_sha256": boot_identity,
    }
    boundary_doc = _real16_outcome_document(
        state,
        fault=fault,
        site=site,
        compared=compared,
        limits=limits,
        environment=environment,
        layout=layout,
        code_ranges=boot.image.code_ranges,
        admit_write=_real16_admit_write(layout, boot.image.code_ranges),
    )
    service_premise: Mapping[str, Any] = {
        "kind": "returning_service_contract",
        "services": ["int21_ah30_al00", "int10_ah0f"],
        "events": len(events),
        "entry_model": _real16_entry_model(environment),
        "detail": (
            "declared returning queries apply the caller-declared policy "
            "response and continue to the fallthrough; they are visible "
            "environment premises, never real DOS/BIOS proof"
        ),
    }
    premises = (
        environment_premise,
        boundary_doc.premise,
        service_premise,
        {"kind": "register_seed", "relation": "concrete_declared_boot_state"},
        {"kind": "initial_data", "relation": InitialDataRelation.SHARED_UNCONSTRAINED.value},
        {"kind": "scope_limitation", "detail": boundary_doc.scope_detail},
    )
    counters = FactCounters(
        raw_fact_count=len(blocks) + len(events),
        normalized_fact_count=len(blocks) + len(events),
        classified_fact_count=len(blocks) + len(events) + 1,
        materialized_count=len(boundary_doc.document["outputs"]) + len(events),
        failure_count=0,
    )
    return SymbolicTerminalTrace(
        architecture=Architecture.REAL16,
        service=TerminalService.DOS_TERMINATE,
        event_kind=boundary_doc.event_kind,
        outcome=boundary_doc.outcome,
        fault=fault,
        source=bytes(data),
        environment=environment,
        source_sha256=hashlib.sha256(bytes(data)).hexdigest(),
        boot_identity=boot_identity,
        environment_identity=environment_identity,
        entry=boot.entry.linear(),
        site=site,
        blocks=tuple(blocks),
        document=boundary_doc.document,
        payload_bits=boundary_doc.payload_bits,
        initial_read_sites=read_auditor.initial_sites(),
        premises=premises,
        counters=counters,
        service_events=tuple(events),
        decode_limits=limits.native_decode(),
    )


def _real16_entry_model(environment: ProgramEnvironment) -> str:
    """Return the interrupt-entry model the environment identity binds."""
    if environment.video_policy is not None or environment.video_state_policy is not None:
        return VIDEO_INTERRUPT_ENTRY_MODEL
    return INTERRUPT_ENTRY_MODEL


@dataclass(frozen=True, slots=True)
class _BoundaryDocument:
    """The materialized terminal transition and its boundary premise pair."""

    document: dict[str, Any]
    event_kind: ProgramEventKind
    outcome: TerminalOutcome
    payload_bits: int
    premise: Mapping[str, Any]
    scope_detail: str


def _real16_admit_write(
    layout: ProgramMemoryLayout, code_ranges: tuple[LinearRange, ...]
) -> Callable[[int, int], None]:
    """Build the real16 store admittance: declared non-code memory only.

    Proved store destinations must land inside the declared arena and never
    overwrite the image's declared code bytes — the same gates the concrete
    replay applies to the terminal transition's writes.
    """

    def admit(address: int, size: int) -> None:
        if not layout.contains(address, size):
            raise TerminalRefusal(
                TerminalRefusalKind.UNDECLARED_WRITE,
                f"store at {hex(address)} lacks declared memory coverage",
            )
        if any(region.overlaps(address, size) for region in code_ranges):
            raise TerminalRefusal(
                TerminalRefusalKind.CODE_WRITE,
                f"store at {hex(address)} overwrites declared code bytes",
            )

    return admit


def _real16_outcome_document(
    state: S._IrsbLowerState,
    *,
    fault: FaultOutcome | None,
    site: TerminalSite | None,
    compared: dict[str, S.SsaExpr],
    limits: TerminalLimits,
    environment: ProgramEnvironment,
    layout: ProgramMemoryLayout,
    code_ranges: tuple[LinearRange, ...],
    admit_write: Callable[[int, int], None],
) -> _BoundaryDocument:
    """Materialize the real16 boundary transition for either outcome class.

    Exactly one of ``fault``/``site`` is bound by the walk. A processor
    fault materializes the complete modeled prefix — registers, every
    audited read and the full memory version — with the vector as payload;
    a declared service proves the selector, applies the modeled interrupt
    frame under the declared alias gates and then admits the frame stores
    on the full memory chain before materializing, exactly as the concrete
    boundary executes them.
    """
    if fault is not None:
        _check_memory_writes(state.mem_version, admit_write)
        payload = S.SsaExpr("const", 32, value=fault.vector)
        document = _materialize_document(
            state,
            payload=payload,
            compared=compared,
            max_assignments=limits.max_assignments,
            include_memory=True,
        )
        premise, scope_detail = _exception_scope_premise(fault, "IVT")
        return _BoundaryDocument(
            document,
            ProgramEventKind.CPU_FAULT,
            TerminalOutcome.PROCESSOR_FAULT,
            32,
            premise,
            scope_detail,
        )
    assert site is not None
    _prove_service_selector(state, expected=DOS_TERMINATE_FUNCTION)
    _apply_interrupt_frame(
        state,
        site_address=site.address,
        layout=layout,
        code_ranges=code_ranges,
        aliased=declared_frame_aliases(environment),
    )
    _check_memory_writes(state.mem_version, admit_write)
    payload = S.SsaExpr("trunc", 8, (state.reg_versions["ax"],))
    document = _materialize_document(
        state, payload=payload, compared=compared, max_assignments=limits.max_assignments
    )
    premise = {
        "kind": "terminal_service_contract",
        "service": TerminalService.DOS_TERMINATE.value,
        "boundary": "decoded int 0x21 with Ijk_Call to the vector core",
        "selector": "ah == 0x4C proved under the declared register seed",
        "payload": "al — 8-bit exit code",
        "entry_model": _real16_entry_model(environment),
    }
    return _BoundaryDocument(
        document,
        ProgramEventKind.DOS_EXIT,
        TerminalOutcome.DECLARED_SERVICE,
        8,
        premise,
        (
            "one DOS INT21/AH4C terminal boundary per program; declared "
            "INT21/AH30 AL00 and INT10/AH0F returning queries are modeled "
            "environment premises; input, output, resize, vector-update, "
            "device-info and other video-state services stay outside this contract"
        ),
    )


def _exception_scope_premise(
    fault: FaultOutcome, handler_space: str
) -> tuple[Mapping[str, Any], str]:
    """Build the shared no-handler exception premise a faulting lane carries.

    ``handler_space`` names the architecture's real handler domain (``IVT``
    or ``IDT``) so the scope limitation states exactly what stays unmodeled;
    the premise itself is identical across lanes — a stop at the exception
    under an environment that declares no dispatch, an assumption callers
    must carry, never evidence that no handler exists.
    """
    premise: Mapping[str, Any] = {
        "kind": "exception_scope",
        "model": "stop_at_exception_no_handler",
        "admitted": [f"{fault.kind.value}:#DE vector {fault.vector}"],
        "site": hex(fault.site_address),
        "detail": (
            "the environment declares no exception-handler dispatch — a proved "
            "divide error stops the program exactly as the concrete replay's "
            "UC_HOOK_INTR stop does; the absence of a modeled handler is an "
            "environment assumption, not evidence that none exists"
        ),
    }
    scope_detail = (
        "one proved #DE divide-error stop per program at most; "
        f"{handler_space} handler dispatch, other vectors, asynchronous and "
        "x87 exceptions are outside this contract and refuse at intake"
    )
    return premise, scope_detail


# ---------------------------------------------------------------------------
# Flat32 (PE32) intake: declared synthetic exit gateway
# ---------------------------------------------------------------------------


def _flat32_register_seed(boot: PeProgramBoot) -> dict[str, S.SsaExpr]:
    """Seed the declared concrete flat32 register file.

    The ``cs``/``ss``/``ds``/``es``/``fs``/``gs`` selectors are the backend's
    flat zero bootstrap asserted by the replay initializer; lazy-flag
    ``cc_*`` storage and ``d``/``eip`` stay shared symbolic inputs.
    """
    declared = dict(boot.environment.registers)
    seed: dict[str, S.SsaExpr] = {
        name: S.SsaExpr("input", width, name=name)
        for name, width in flat32_register_architecture().registers
    }
    for name, value in declared.items():
        if name == "eflags":
            continue
        seed[name] = S.SsaExpr("const", 32, value=value & 0xFFFFFFFF)
    for selector in ("cs", "ds", "es", "fs", "gs", "ss"):
        seed[selector] = S.SsaExpr("const", 32, value=0)
    return seed


def _flat32_executable_contains(boot: PeProgramBoot, address: int, size: int) -> bool:
    """Require fetched bytes inside a file-declared executable range."""
    return any(region.contains(address, size) for region in boot.image.executable)


def _flat32_readable_contains(boot: PeProgramBoot, address: int, size: int) -> bool:
    """Require the exact declared bytes to be readable under the file/env plan."""
    for region in boot.image.declared:
        if (
            region.access & DeclaredAccess.READ
            and region.address <= address
            and address + size <= region.address + region.size
        ):
            return True
    for memory in boot.environment.memory:
        if memory.access & DeclaredAccess.READ and memory.contains(address, size):
            return True
    return False


def _flat32_dividend(
    registers: Mapping[str, S.SsaExpr], operand_bits: int
) -> S.SsaExpr | None:
    """Project the flat32 implicit dividend of a divide operand width.

    ``DIV``/``IDIV`` take their dividend from ``AX`` (8-bit operand),
    ``DX:AX`` (16-bit operand-prefix form) or ``EDX:EAX`` (32-bit); the
    flat32 register file stores the full dwords, so the narrower forms are
    truncations and the wide form a concatenation.
    """
    if operand_bits == 8:
        return S.SsaExpr("trunc", 16, (registers["eax"],))
    if operand_bits == 16:
        dx = S.SsaExpr("trunc", 16, (registers["edx"],))
        ax = S.SsaExpr("trunc", 16, (registers["eax"],))
        return S.SsaExpr("concat", 32, (dx, ax))
    if operand_bits == 32:
        return S.SsaExpr("concat", 64, (registers["edx"], registers["eax"]))
    return None


def _flat32_slot_routes(bindings: tuple[PeImportBinding, ...]) -> dict[int, PeImportService]:
    """Project the sealed bindings into a loaded-IAT-slot → service route map."""
    routes: dict[int, PeImportService] = {}
    for binding in bindings:
        for slot in binding.slots:
            routes[slot] = binding.service
    return routes


def _flat32_mem_term(
    memory: S.SsaExpr,
    address: int,
    size: int,
    initial_bytes: Callable[[int, int], bytes | None],
) -> S.SsaExpr | None:
    """Resolve the term a proved-const-address load reads through the store chain.

    Each earlier store must have a proved concrete address — a symbolic
    destination makes the read's provenance unprovable and refuses, exactly
    as the read auditor does. A store fully covering the read returns its
    (possibly narrowed) stored value; disjoint stores are skipped; a partial
    overlap or an unconstrained initial range returns ``None`` so the caller
    refuses honestly instead of guessing bytes.
    """
    expr = memory
    while expr.op in {"storele", "storebe"}:
        store_address = _const_eval(expr.args[1])
        if store_address is None:
            raise TerminalRefusal(
                TerminalRefusalKind.UNPROVED_POINTER,
                "cannot prove a read through a symbolic store destination",
            )
        store_size = expr.args[2].width // 8
        if address + size <= store_address or store_address + store_size <= address:
            expr = expr.args[0]
            continue
        if not (store_address <= address and address + size <= store_address + store_size):
            return None
        value = expr.args[2]
        shift = (
            (address - store_address) * 8
            if expr.op == "storele"
            else (store_address + store_size - (address + size)) * 8
        )
        if shift:
            value = S.SsaExpr(
                "lshr", value.width, (value, S.SsaExpr("const", value.width, value=shift))
            )
        return S._coerce_width(value, size * 8)
    if expr.op != "mem_input":
        return None
    data = initial_bytes(address, size)
    if data is None:
        return None
    return S.SsaExpr("const", size * 8, value=int.from_bytes(data, "little"))


def _flat32_iat_target(
    target_term: S.SsaExpr,
    routes: Mapping[int, PeImportService],
    initial_bytes: Callable[[int, int], bytes | None],
) -> int | None:
    """Prove a successor's routed IAT slot through the sealed loaded bytes.

    The lowered successor must be a load from a proved-constant address that
    is an admitted IAT slot, and the loaded bytes must resolve — through the
    current store chain — to exactly the slot's declared service address.
    Returns the proved slot; anything else returns ``None`` so the caller
    applies the ordinary indirect-control refusal.
    """
    if target_term.op != "loadle" or not routes:
        return None
    slot = _const_eval(target_term.args[1])
    if slot is None or slot not in routes:
        return None
    value = _flat32_mem_term(target_term.args[0], slot, 4, initial_bytes)
    target = None if value is None else _const_eval(value)
    if target is None:
        raise TerminalRefusal(
            TerminalRefusalKind.INDIRECT_CONTROL,
            f"IAT slot {hex(slot)} contents are not proved concrete",
        )
    if target != routes[slot].address:
        raise TerminalRefusal(
            TerminalRefusalKind.UNDECLARED_SERVICE,
            f"IAT slot {hex(slot)} holds {hex(target)}, not the declared service "
            f"{hex(routes[slot].address)} — mutated or misbound import state",
        )
    return int(slot)


def _check_iat_encoding(instruction: capstone.CsInsn, slot: int, jumpkind: str) -> None:
    """Require the genuine ``call/jmp dword ptr [disp32]`` absolute encoding.

    Only the exact ``FF 15`` (call) or ``FF 25`` (jmp) mod-00/rm-101 absolute
    memory form routes through the declared IAT — register, register+displace,
    SIB, segment-overridden and operand-size variants are unadmitted shapes
    and refuse instead of being claimed as import coverage.
    """
    expected = b"\xff\x15" if jumpkind == "Ijk_Call" else b"\xff\x25"
    if bytes(instruction.bytes[:2]) != expected or instruction.size != 6:
        raise TerminalRefusal(
            TerminalRefusalKind.SERVICE_ENCODING,
            f"{jumpkind} route at {hex(instruction.address)} is not an absolute "
            "call/jmp dword ptr [disp32]",
        )
    operands = instruction.operands
    if len(operands) != 1 or operands[0].type != decoded_ids.X86_OP_MEM:
        raise TerminalRefusal(
            TerminalRefusalKind.SERVICE_ENCODING,
            f"call/jmp operand at {hex(instruction.address)} is not a memory operand",
        )
    memory = operands[0].mem
    if (
        memory.base != decoded_ids.X86_REG_INVALID
        or memory.index != decoded_ids.X86_REG_INVALID
        or memory.segment not in (decoded_ids.X86_REG_INVALID, decoded_ids.X86_REG_DS)
    ):
        raise TerminalRefusal(
            TerminalRefusalKind.SERVICE_ENCODING,
            f"call/jmp operand at {hex(instruction.address)} is not an absolute "
            "disp32 memory reference",
        )
    if memory.disp != slot:
        raise TerminalRefusal(
            TerminalRefusalKind.SERVICE_ENCODING,
            f"call/jmp operand at {hex(instruction.address)} is not the bound "
            f"IAT slot {hex(slot)}",
        )


def _flat32_service_result(service: PeImportService, sequence: int) -> S.SsaExpr:
    """Return the declared DWORD response term: constant or opaque input.

    The opaque input name carries the invocation's execution ordinal so
    each occurrence is a fresh response — a repeated call is never forced
    to return an identical value. The same ordinal names the same input in
    both lanes, so the response is shared only between the corresponding
    oracle and candidate events of an aligned invocation sequence.
    """
    if service.result.kind is ImportResultKind.DECLARED_DWORD:
        assert service.result.value is not None
        return S.SsaExpr("const", 32, value=service.result.value)
    return S.SsaExpr("input", 32, name=f"svc_result_{service.label()}_{sequence}")


def _apply_flat32_service(
    state: S._IrsbLowerState,
    service: PeImportService,
    slot: int,
    site: int,
    sequence: int,
    events: list[ImportedServiceEvent],
    auditor: MemoryReadAuditor,
    initial_bytes: Callable[[int, int], bytes | None],
) -> int:
    """Consume one declared no-arg returning service; return the continuation.

    The model is exactly the declared contract: the top-of-stack return
    dword must resolve concretely under the same memory checker (the call's
    own pushed return address or the thunk caller's frame), ``esp`` is
    popped by four leaving every residual stack byte in the shared memory
    version, ``eax`` receives the declared response, each declared volatile
    register becomes its declared opaque input, and the declared flag policy
    either preserves the lazy flag state or makes it opaque. Nonvolatile
    registers are untouched. Every opaque input name carries the invocation
    ordinal ``sequence`` so each execution occurrence produces a fresh
    response, clobber and flag state shared only with the corresponding
    cross-lane event — an earlier call can never constrain a later one's
    results. An unproved stack pointer or return address is a typed
    refusal, never a guessed frame.
    """
    esp_term = S._coerce_width(state.reg_versions["esp"], 32)
    esp = _const_eval(esp_term)
    if esp is None:
        raise TerminalRefusal(
            TerminalRefusalKind.UNPROVED_POINTER,
            "imported service stack pointer is not proved concrete",
        )
    return_term = S.SsaExpr("loadle", 32, (state.mem_version, esp_term))
    auditor.audit_term(return_term)
    return_value = _flat32_mem_term(state.mem_version, esp, 4, initial_bytes)
    continuation = None if return_value is None else _const_eval(return_value)
    if continuation is None:
        raise TerminalRefusal(
            TerminalRefusalKind.UNPROVED_POINTER,
            "imported service return address is not proved concrete",
        )
    state.reg_versions["esp"] = S.SsaExpr(
        "add", 32, (esp_term, S.SsaExpr("const", 32, value=4))
    )
    state.reg_versions["eax"] = _flat32_service_result(service, sequence)
    for register in service.volatile:
        state.reg_versions[register] = S.SsaExpr(
            "input", 32, name=f"svc_vol_{service.label()}_{register}_{sequence}"
        )
    if service.flags is ServiceFlagsPolicy.OPAQUE:
        for register in ("cc_op", "cc_dep1", "cc_dep2", "cc_ndep"):
            state.reg_versions[register] = S.SsaExpr(
                "input", 32, name=f"svc_flags_{service.label()}_{register}_{sequence}"
            )
    events.append(ImportedServiceEvent(service.label(), slot, site, sequence))
    return int(continuation)


def _flat32_next_target(
    state: S._IrsbLowerState,
    lifted: pyvex.IRSB,
    instructions: tuple[capstone.CsInsn, ...],
    *,
    address: int,
    gateway: int,
    state_regs: tuple[str, ...],
    auditor: MemoryReadAuditor,
    initial_bytes: Callable[[int, int], bytes | None],
    routes: Mapping[int, PeImportService],
    events: list[ImportedServiceEvent],
) -> int | FaultOutcome:
    """Lower one flat32 block; return its control target or a proved fault.

    Refusals fire before or during lowering: returns end the region without
    the declared gateway, unadmitted trap outcomes stay fault boundaries,
    and calls must resolve to a proved constant target — anything else the
    environment did not declare is an undeclared service or
    indirect-control refusal. A genuine ``call/jmp dword ptr [IAT]`` whose
    loaded target is proved from the sealed IAT consumes its declared
    returning service and continues at the proved return address. A proved
    processor fault stops the region: the guarded post-fault path is never
    lowered or compared.
    """
    for instruction in instructions:
        _check_flat32_instruction(instruction)
    jumpkind = str(lifted.jumpkind)
    if jumpkind == "Ijk_Ret":
        raise TerminalRefusal(
            TerminalRefusalKind.RETURN_NOT_TERMINAL,
            f"return at {hex(address)} ends the region without the declared gateway",
        )
    if jumpkind.startswith("Ijk_Sig") and signal_fault_kind(jumpkind) is None:
        raise TerminalRefusal(
            TerminalRefusalKind.FAULT_BOUNDARY, f"trap outcome {jumpkind} at {hex(address)}"
        )
    if jumpkind not in {"Ijk_Call", "Ijk_Boring"} and not jumpkind.startswith("Ijk_Sig"):
        raise TerminalRefusal(
            TerminalRefusalKind.CONTROL_ESCAPE,
            f"unsupported jumpkind {jumpkind} at {hex(address)}",
        )
    outcome = _lower_into(
        state,
        lifted,
        state_regs,
        auditor=auditor,
        fault_gate=_fault_gate(
            instructions,
            dividend=_flat32_dividend,
            initial_bytes=initial_bytes,
        ),
    )
    if outcome is not None:
        return outcome
    if jumpkind.startswith("Ijk_Sig"):
        raise TerminalRefusal(
            TerminalRefusalKind.FAULT_BOUNDARY,
            f"block at {hex(address)} ends on {jumpkind} without decided fault evidence",
        )
    target_term = _lowered_next(state, lifted)
    auditor.audit_term(target_term)
    target = _const_eval(target_term)
    if target is None:
        slot = _flat32_iat_target(target_term, routes, initial_bytes)
        if slot is None:
            raise TerminalRefusal(
                TerminalRefusalKind.INDIRECT_CONTROL, "non-constant block successor"
            )
        _check_iat_encoding(instructions[-1], slot, jumpkind)
        return _apply_flat32_service(
            state,
            routes[slot],
            slot,
            int(instructions[-1].address),
            len(events),
            events,
            auditor,
            initial_bytes,
        )
    if jumpkind == "Ijk_Call" and target != gateway:
        raise TerminalRefusal(
            TerminalRefusalKind.UNDECLARED_SERVICE,
            f"call target {hex(target)} is not the declared gateway {hex(gateway)}",
        )
    return target


def _flat32_walk(
    project: angr.Project,
    boot: PeProgramBoot,
    gateway: int,
    state: S._IrsbLowerState,
    state_regs: tuple[str, ...],
    limits: TerminalLimits,
    auditor: MemoryReadAuditor,
    initial_bytes: Callable[[int, int], bytes | None],
) -> tuple[TerminalSite | FaultOutcome, tuple[TerminalBlockReceipt, ...], tuple[ImportedServiceEvent, ...]]:
    """Walk the bounded flat32 region to the declared gateway or a fault.

    Every fetched instruction must lie inside the file-declared executable
    image; every successor must be proved constant and in scope. Declared
    import services are consumed only through genuine ``call/jmp dword ptr
    [IAT]`` routes proved from the sealed loaded IAT; the walk then resumes
    at the proved return address under the same block and time caps. The
    walk ends only at the gateway or a proved processor fault.
    """
    routes = _flat32_slot_routes(boot.imports)
    events: list[ImportedServiceEvent] = []
    blocks: list[TerminalBlockReceipt] = []
    visited: set[int] = set()
    boundary: TerminalSite | FaultOutcome | None = None
    address = boot.entry
    while boundary is None:
        if address in visited:
            raise TerminalRefusal(
                TerminalRefusalKind.LOOP_BOUNDARY, f"control revisited {hex(address)}"
            )
        visited.add(address)
        if len(blocks) >= limits.max_blocks:
            raise TerminalRefusal(TerminalRefusalKind.BLOCK_LIMIT, "bounded region limit reached")
        executable_extent = max(
            (region.address + region.size - address for region in boot.image.executable
             if region.contains(address)), default=0,
        )
        if not executable_extent:
            raise TerminalRefusal(TerminalRefusalKind.CONTROL_ESCAPE, "successor leaves executable scope")
        lifted, code, _window, instructions = _lift_window(
            project, boot.image.chunks, address, limits, mode=capstone.CS_MODE_32,
            executable_extent=executable_extent,
        )
        for instruction in instructions:
            if not _flat32_executable_contains(boot, instruction.address, instruction.size):
                raise TerminalRefusal(
                    TerminalRefusalKind.CONTROL_ESCAPE,
                    f"fetched instruction at {hex(instruction.address)} leaves executable scope",
                )
        advanced = _flat32_next_target(
            state,
            lifted,
            instructions,
            address=address,
            gateway=gateway,
            state_regs=state_regs,
            auditor=auditor,
            initial_bytes=initial_bytes,
            routes=routes,
            events=events,
        )
        if isinstance(advanced, FaultOutcome):
            boundary = advanced
            blocks.append(
                TerminalBlockReceipt(
                    address, lifted.size, hashlib.sha256(code).hexdigest(),
                    str(lifted.jumpkind), lifted.instructions, None,
                )
            )
            continue
        last = instructions[-1]
        blocks.append(
            TerminalBlockReceipt(
                address, lifted.size, hashlib.sha256(code).hexdigest(),
                str(lifted.jumpkind), lifted.instructions, advanced,
            )
        )
        if advanced == gateway:
            boundary = TerminalSite(
                TerminalService.PE_DECLARED_EXIT,
                last.address,
                bytes(code[len(code) - last.size :]),
                advanced,
            )
            continue
        if not _flat32_executable_contains(boot, advanced, 1):
            raise TerminalRefusal(
                TerminalRefusalKind.CONTROL_ESCAPE,
                f"successor {hex(advanced)} leaves the declared executable image",
            )
        address = advanced
    return boundary, tuple(blocks), tuple(events)


def _flat32_writable_contains(boot: PeProgramBoot, address: int, size: int) -> bool:
    """Require the exact declared bytes to be writable under the file/env plan."""
    for region in boot.image.declared:
        if (
            region.access & DeclaredAccess.WRITE
            and region.address <= address
            and address + size <= region.address + region.size
        ):
            return True
    for memory in boot.environment.memory:
        if memory.access & DeclaredAccess.WRITE and memory.contains(address, size):
            return True
    return False


def _flat32_admit_read(boot: PeProgramBoot) -> Callable[[int, int], None]:
    """Build the flat32 load admittance: declared readable data or image only."""

    def admit(address: int, size: int) -> None:
        if not _flat32_readable_contains(boot, address, size):
            raise TerminalRefusal(
                TerminalRefusalKind.UNDECLARED_READ,
                f"load at {hex(address)} lacks declared readable coverage",
            )

    return admit


def _flat32_initial_bytes(boot: PeProgramBoot) -> Callable[[int, int], bytes | None]:
    """Resolve declared initial bytes as the replay loader overlays them.

    The concrete replay maps the image chunks, then writes every declared
    environment allocation — so environment data wins over image bytes.
    """
    layers: list[tuple[tuple[int, bytes], ...]] = [
        tuple((region.address, region.data) for region in boot.environment.memory),
        boot.image.chunks,
    ]
    return lambda address, size: overlay_bytes(layers, address, size)


def _flat32_admit_write(boot: PeProgramBoot) -> Callable[[int, int], None]:
    """Build the flat32 store admittance: writable declared data, never code."""

    def admit(address: int, size: int) -> None:
        if _flat32_executable_contains(boot, address, size):
            raise TerminalRefusal(
                TerminalRefusalKind.CODE_WRITE,
                f"store at {hex(address)} overwrites declared executable bytes",
            )
        if not _flat32_writable_contains(boot, address, size):
            raise TerminalRefusal(
                TerminalRefusalKind.UNDECLARED_WRITE,
                f"store at {hex(address)} lacks declared writable coverage",
            )

    return admit


def _flat32_exit_payload(state: S._IrsbLowerState, boot: PeProgramBoot) -> S.SsaExpr:
    """Derive the terminal payload: the proved-readable dword at ``ESP+4``."""
    esp = state.reg_versions["esp"]
    argument_address = _const_eval(
        S.SsaExpr("add", 32, (S._coerce_width(esp, 32), S.SsaExpr("const", 32, value=4)))
    )
    if argument_address is None:
        raise TerminalRefusal(
            TerminalRefusalKind.UNPROVED_POINTER,
            "exit argument address ESP+4 is not proved concrete under the declared state",
        )
    if not _flat32_readable_contains(boot, argument_address, 4):
        raise TerminalRefusal(
            TerminalRefusalKind.STACK_ARGUMENT,
            f"exit argument at {hex(argument_address)} lacks declared readable bytes",
        )
    return S.SsaExpr(
        "loadle",
        32,
        (state.mem_version, S.SsaExpr("const", 32, value=argument_address)),
    )


@dataclass(frozen=True, slots=True)
class _Flat32WalkEvidence:
    """Fresh native walk state and receipts before document materialization."""

    state: S._IrsbLowerState
    auditor: MemoryReadAuditor
    boundary: TerminalSite | FaultOutcome
    blocks: tuple[TerminalBlockReceipt, ...]
    events: tuple[ImportedServiceEvent, ...]


def _seeded_flat32_walk(data: bytes, boot: PeProgramBoot, limits: TerminalLimits) -> _Flat32WalkEvidence:
    """Run the shared native walk from its declared seed without invoking Z3.

    Intake and thunk continuation verification use this same fresh state,
    permission audit and bounded SSA walk; neither trusts a retained frame.
    """
    try:
        project = _pe_load_project(data)
    except ValueError as error:
        raise TerminalRefusal(TerminalRefusalKind.LIFT, str(error)) from error
    state = S._IrsbLowerState(
        reg_versions=_flat32_register_seed(boot),
        architecture=flat32_register_architecture(),
        mem_version=S.SsaExpr("mem_input", 0, name="mem"),
        io_version=S.SsaExpr("mem_input", 0, name="io"),
    )
    state_regs = tuple(_FLAT32_REG_NAMES)
    initial_bytes = _flat32_initial_bytes(boot)
    read_auditor = MemoryReadAuditor(
        admit=_flat32_admit_read(boot), initial_bytes=initial_bytes
    )
    boundary, blocks, events = _flat32_walk(
        project,
        boot,
        boot.environment.exit_address,
        state,
        state_regs,
        limits,
        read_auditor,
        initial_bytes,
    )
    _check_memory_writes(state.mem_version, _flat32_admit_write(boot))
    return _Flat32WalkEvidence(state, read_auditor, boundary, blocks, events)


def trace_flat32_terminal(
    data: bytes, environment: PeProgramEnvironment, *, limits: TerminalLimits | None = None
) -> SymbolicTerminalTrace:
    """Trace one actual PE32 program to its declared exit gateway.

    The gateway is the environment's explicit synthetic ``exit_address``
    outside image and data; the terminal transfer must be a lifted
    ``Ijk_Call`` or ``Ijk_Boring`` whose constant target is exactly that
    address, and the payload is the actual readable dword at ``ESP+4`` in
    the proved stack state. When the environment declares import services,
    genuine ``call/jmp dword ptr [IAT]`` routes proved from the sealed
    loaded IAT consume the declared returning-service summary and continue
    at the proved return address under the same caps — a visible synthetic
    contract, never Windows import coverage.
    """
    limits = limits or TerminalLimits()
    try:
        boot = pe_program_from_bytes(data, environment)
    except ValueError as error:
        raise TerminalRefusal(TerminalRefusalKind.BOOT_CONTRACT, str(error)) from error
    walk = _seeded_flat32_walk(data, boot, limits)
    state, read_auditor = walk.state, walk.auditor
    boundary, blocks, events = walk.boundary, walk.blocks, walk.events
    state_regs = tuple(_FLAT32_REG_NAMES)
    compared = {
        name: state.reg_versions[name]
        for name in state_regs
        if name in state.reg_versions and name != "eip"
    }
    if isinstance(boundary, FaultOutcome):
        fault: FaultOutcome | None = boundary
        site: TerminalSite | None = None
        payload = S.SsaExpr("const", 32, value=boundary.vector)
        document = _materialize_document(
            state,
            payload=payload,
            compared=compared,
            max_assignments=limits.max_assignments,
            include_memory=True,
        )
        event_kind = ProgramEventKind.CPU_FAULT
        outcome = TerminalOutcome.PROCESSOR_FAULT
    else:
        fault = None
        site = boundary
        payload = _flat32_exit_payload(state, boot)
        read_auditor.audit_term(payload)
        document = _materialize_document(
            state, payload=payload, compared=compared, max_assignments=limits.max_assignments
        )
        event_kind = ProgramEventKind.PE_EXIT
        outcome = TerminalOutcome.DECLARED_SERVICE
    environment_identity = hashlib.sha256(
        b"unicorn_pe32_flat_zero_selectors_stdcall_exit_u32_v1"
        + _pe_environment_identity(environment)
    ).hexdigest()
    environment_premise = {
        "kind": "declared_environment_identity",
        "sha256": environment_identity,
        "boot_sha256": boot.boot_sha256,
    }
    if fault is not None:
        boundary_premise, scope_detail = _exception_scope_premise(fault, "IDT")
    else:
        boundary_premise = {
            "kind": "terminal_service_contract",
            "service": TerminalService.PE_DECLARED_EXIT.value,
            "boundary": f"declared synthetic gateway {hex(environment.exit_address)}",
            "payload": "readable dword at esp+4 — 32-bit exit code",
            "entry_model": "stdcall-shaped argument; no return continuation",
        }
        scope_detail = (
            "the declared exit gateway is a synthetic environment boundary, "
            "not Windows import coverage; returning import services "
            "require separate explicit contracts"
        )
    service_premises: tuple[Mapping[str, Any], ...] = ()
    if boot.imports:
        service_premises = (
            {
                "kind": "imported_service_contract",
                "model": "declared synthetic no-argument DWORD-returning service; "
                "no Windows implementation or clobber is proved",
                "routing": "call/jmp dword ptr [iat_slot] proved from the sealed loaded IAT",
                "services": [binding.service.declared_fields() for binding in boot.imports],
                "events_compared": "ordered dll!name invocations; dead results still observed",
            },
        )
        scope_detail += (
            "; declared import services are caller-declared synthetic "
            "contracts consumed through genuine IAT routes only"
        )
    premises = (
        environment_premise,
        boundary_premise,
        *service_premises,
        {"kind": "register_seed", "relation": "concrete_declared_boot_state"},
        {"kind": "initial_data", "relation": InitialDataRelation.SHARED_UNCONSTRAINED.value},
        {"kind": "scope_limitation", "detail": scope_detail},
    )
    counters = FactCounters(
        raw_fact_count=len(blocks) + len(events),
        normalized_fact_count=len(blocks) + len(events),
        classified_fact_count=len(blocks) + len(events) + 1,
        materialized_count=len(document["outputs"]) + len(events),
        failure_count=0,
    )
    return SymbolicTerminalTrace(
        architecture=Architecture.FLAT32,
        service=TerminalService.PE_DECLARED_EXIT,
        event_kind=event_kind,
        outcome=outcome,
        fault=fault,
        source=bytes(data),
        environment=environment,
        source_sha256=hashlib.sha256(bytes(data)).hexdigest(),
        boot_identity=boot.boot_sha256,
        environment_identity=environment_identity,
        entry=boot.entry,
        site=site,
        blocks=tuple(blocks),
        document=document,
        payload_bits=32,
        initial_read_sites=read_auditor.initial_sites(),
        premises=premises,
        counters=counters,
        service_events=events,
        decode_limits=limits.native_decode(),
    )


# ---------------------------------------------------------------------------
# Trace verification and comparison
# ---------------------------------------------------------------------------


def verify_terminal_trace(trace: SymbolicTerminalTrace) -> TerminalRefusal | None:
    """Re-derive boot identity and block byte evidence before trusting a trace.

    A trace whose retained source or block digests no longer re-derive under
    the declared environment is stale evidence and refused, never compared.
    """
    if not isinstance(trace.outcome, TerminalOutcome) or (
        (trace.outcome is TerminalOutcome.PROCESSOR_FAULT) != (trace.fault is not None)
    ):
        return _stale_census("trace outcome and retained fault evidence disagree")
    derived = _verify_trace_boot(trace)
    if isinstance(derived, TerminalRefusal):
        return derived
    chunks, pe_boot = derived
    stale = _verify_block_receipts(trace.blocks, chunks)
    if stale is not None:
        return stale
    stale = (
        _verify_flat32_service_events(trace, pe_boot, chunks)
        if pe_boot is not None
        else _verify_service_events(trace, chunks)
    )
    if stale is not None:
        return stale
    if trace.outcome is TerminalOutcome.PROCESSOR_FAULT:
        return _verify_fault_site(trace, chunks)
    return None


def _verify_trace_boot(
    trace: SymbolicTerminalTrace,
) -> tuple[tuple[tuple[int, bytes], ...], PeProgramBoot | None] | TerminalRefusal:
    """Re-derive the retained source's boot identity and image chunks.

    Returns ``(chunks, pe_boot)`` where ``pe_boot`` is the re-derived flat32
    boot or ``None`` for the real16 lane.
    """
    try:
        if trace.architecture is Architecture.REAL16:
            if not isinstance(trace.environment, ProgramEnvironment):
                return TerminalRefusal(
                    TerminalRefusalKind.STALE_EVIDENCE, "real16 trace lost its declared environment"
                )
            boot = program_from_mz_bytes(trace.source, trace.environment)
            if boot.boot_sha256 != trace.boot_identity:
                return TerminalRefusal(
                    TerminalRefusalKind.STALE_EVIDENCE, "boot identity differs from retained source"
                )
            if trace.entry != boot.entry.linear() or not trace.blocks or trace.blocks[0].address != trace.entry:
                return _stale_census("retained trace does not begin at the re-derived native entry")
            return boot.image.chunks, None
        if not isinstance(trace.environment, PeProgramEnvironment):
            return TerminalRefusal(
                TerminalRefusalKind.STALE_EVIDENCE, "flat32 trace lost its declared environment"
            )
        pe_boot = pe_program_from_bytes(trace.source, trace.environment)
        if pe_boot.boot_sha256 != trace.boot_identity:
            return TerminalRefusal(
                TerminalRefusalKind.STALE_EVIDENCE, "boot identity differs from retained source"
            )
        if trace.entry != pe_boot.entry:
            return _stale_census("retained trace entry differs from the re-derived native entry")
        return pe_boot.image.chunks, pe_boot
    except ValueError as error:
        return TerminalRefusal(TerminalRefusalKind.STALE_EVIDENCE, str(error))




@dataclass(frozen=True, slots=True)
class Flat32ServiceBoundary:
    """One executed IAT-routed returning-service boundary in receipt order.

    The census re-derives each boundary from the authenticated block bytes
    and the real IAT bindings — site, slot and bound ``dll!name`` identity
    are native-decode facts, never trusted trace tags.
    """

    site: int
    slot: int
    service: str
    frame_bound: bool
    """Native JMP-IAT needs source-derived stack continuation replay."""


_FLAT32_CENSUS_TRANSFERS: tuple[int, ...] = (
    capstone.CS_GRP_INT,
    capstone.CS_GRP_CALL,
    capstone.CS_GRP_RET,
    capstone.CS_GRP_IRET,
    capstone.CS_GRP_JUMP,
)
"""Native transfer groups no admitted flat32 block may cross mid-block."""


def _stale_census(detail: str) -> TerminalRefusal:
    """Name a retained-evidence census failure consistently."""
    return TerminalRefusal(TerminalRefusalKind.STALE_EVIDENCE, detail)


def _flat32_decode_receipt(
    receipt: TerminalBlockReceipt, chunks: tuple[tuple[int, bytes], ...], limits: NativeDecodeLimits,
) -> tuple[capstone.CsInsn, ...] | TerminalRefusal:
    """Re-derive one receipt's complete instruction boundaries from bytes.

    Instruction boundaries come only from the shared bounded native decode
    of the authenticated block extent — suffix bytes that may be immediates
    are never scanned for opcodes, and no earlier control transfer may hide
    inside the receipt.
    """
    if not 0 < receipt.size <= limits.max_block_bytes:
        return _stale_census("block receipt exceeds native decoding budget")
    located = _chunk_bytes(chunks, receipt.address)
    if located is None:
        return _stale_census(
            f"block receipt at {hex(receipt.address)} is absent from the re-derived image"
        )
    base, data = located
    code = data[receipt.address - base : receipt.address - base + receipt.size]
    if len(code) != receipt.size:
        return _stale_census("block receipt lacks complete initialized bytes")
    try:
        instructions = decode_terminal_block(code, receipt.address, mode=capstone.CS_MODE_32, limits=limits)
    except TerminalRefusal as error:
        return _stale_census(f"block receipt cannot be decoded: {error.detail}")
    if len(instructions) != receipt.instructions:
        return _stale_census("block receipt instruction count does not re-derive")
    if any(
        instruction.group(group)
        for instruction in instructions[:-1]
        for group in _FLAT32_CENSUS_TRANSFERS
    ):
        return _stale_census("block receipt crosses an earlier native control transfer")
    return instructions


def _flat32_iat_route(instruction: capstone.CsInsn) -> int | None:
    """Project the absolute ``[disp32]`` route of a decoded last instruction.

    Only the exact ``FF 15``/``FF 25`` absolute memory forms route through
    the declared IAT; every other instruction shape returns ``None``.
    """
    if instruction.id not in (decoded_ids.X86_INS_CALL, decoded_ids.X86_INS_JMP):
        return None
    expected = b"\xff\x15" if instruction.id == decoded_ids.X86_INS_CALL else b"\xff\x25"
    encoding = bytes(instruction.bytes)
    if len(encoding) != 6 or encoding[:2] != expected:
        return None
    operands = instruction.operands
    if len(operands) != 1 or operands[0].type != decoded_ids.X86_OP_MEM:
        return None
    memory = operands[0].mem
    if (
        memory.base != decoded_ids.X86_REG_INVALID
        or memory.index != decoded_ids.X86_REG_INVALID
        or memory.segment not in (decoded_ids.X86_REG_INVALID, decoded_ids.X86_REG_DS)
    ):
        return None
    return int(memory.disp)


def _flat32_census_terminator(
    receipt: TerminalBlockReceipt,
    final: capstone.CsInsn,
    routes: Mapping[int, PeImportService],
    initial_bytes: Callable[[int, int], bytes | None],
) -> tuple[Flat32ServiceBoundary | None, int | None] | TerminalRefusal:
    """Classify one byte-authenticated block's decoded native terminator.

    Returns ``(boundary, expected_successor)``: ``boundary`` is the executed
    returning-service boundary the terminator proves, or ``None`` for an
    ordinary edge; ``expected_successor`` is the successor native semantics
    derive, or ``None`` when the continuation is frame-bound (``jmp
    [IAT]``), requiring an additional bounded source-derived frame replay.
    A ``TerminalRefusal`` names retained evidence no admitted walk could
    have produced — a routed transfer to no declared slot, a slot whose
    sealed bytes do not re-derive its service address, an unadmitted
    transfer form, or a forged retained transfer tag.
    """
    route = _flat32_iat_route(final)
    if route is not None:
        return _flat32_route_terminator(receipt, final, route, routes, initial_bytes)
    return _flat32_ordinary_terminator(receipt, final)


def _flat32_route_terminator(
    receipt: TerminalBlockReceipt,
    final: capstone.CsInsn,
    route: int,
    routes: Mapping[int, PeImportService],
    initial_bytes: Callable[[int, int], bytes | None],
) -> tuple[Flat32ServiceBoundary, int | None] | TerminalRefusal:
    """Authenticate a decoded ``call/jmp dword ptr [disp32]`` IAT route."""
    service = routes.get(route)
    if service is None:
        return _stale_census(
            f"routed transfer at {hex(final.address)} targets no declared IAT slot"
        )
    sealed = initial_bytes(route, 4)
    if sealed is None or int.from_bytes(sealed, "little") != service.address:
        return _stale_census(
            f"IAT slot {hex(route)} does not re-derive its declared service address"
        )
    expected_tag = "Ijk_Call" if final.id == decoded_ids.X86_INS_CALL else "Ijk_Boring"
    if receipt.jumpkind != expected_tag:
        return _stale_census("retained transfer tag disagrees with the decoded route")
    boundary = Flat32ServiceBoundary(
        final.address, route, service.label(), final.id == decoded_ids.X86_INS_JMP,
    )
    if final.id == decoded_ids.X86_INS_CALL:
        return boundary, final.address + final.size
    return boundary, None


def _flat32_ordinary_terminator(
    receipt: TerminalBlockReceipt, final: capstone.CsInsn
) -> tuple[None, int] | TerminalRefusal:
    """Authenticate a non-IAT terminator's native successor and tag."""
    if final.id in (decoded_ids.X86_INS_CALL, decoded_ids.X86_INS_JMP):
        operands = final.operands
        if len(operands) != 1 or operands[0].type != decoded_ids.X86_OP_IMM:
            return _stale_census(
                f"terminator at {hex(final.address)} is not an admitted native transfer"
            )
        expected_tag = "Ijk_Call" if final.id == decoded_ids.X86_INS_CALL else "Ijk_Boring"
        if receipt.jumpkind != expected_tag:
            return _stale_census("retained transfer tag disagrees with the decoded transfer")
        return None, int(operands[0].imm)
    if any(final.group(group) for group in _FLAT32_CENSUS_TRANSFERS):
        return _stale_census(
            f"terminator at {hex(final.address)} is not an admitted native transfer"
        )
    if receipt.jumpkind != "Ijk_Boring":
        return _stale_census("retained transfer tag disagrees with the decoded fallthrough")
    return None, final.address + final.size


def _flat32_returning_census(
    trace: SymbolicTerminalTrace,
    boot: PeProgramBoot,
    chunks: tuple[tuple[int, bytes], ...],
    routes: Mapping[int, PeImportService],
    initial_bytes: Callable[[int, int], bytes | None],
) -> tuple[Flat32ServiceBoundary, ...] | TerminalRefusal:
    """Derive every executed returning boundary from native decode in order.

    Retained jumpkind/site tags alone cannot admit or suppress a service.
    The census re-decodes each byte-authenticated receipt from the declared
    boot entry through its recorded successor chain, rejects hidden earlier
    transfers, forged tags, invented successors and non-admitted
    terminators, and requires the retained terminal/fault outcome to close
    the chain exactly — the re-derived declared exit target or the retained
    faulting instruction. Receipts are checked against this independently
    derived denominator.
    """
    receipts = trace.blocks
    if not receipts or len(receipts) > trace.decode_limits.max_blocks:
        return _stale_census("block census is empty or exceeds the existing block budget")
    if trace.fault is not None and trace.site is not None:
        return _stale_census("trace claims a processor fault and terminal site together")
    if receipts[0].address != boot.entry:
        return _stale_census("block census does not begin at the declared boot entry")
    boundaries: list[Flat32ServiceBoundary] = []
    for index, receipt in enumerate(receipts):
        successor = receipts[index + 1] if index + 1 < len(receipts) else None
        boundary = _flat32_census_block(
            receipt, successor, trace, boot, chunks, routes, initial_bytes
        )
        if isinstance(boundary, TerminalRefusal):
            return boundary
        if boundary is not None:
            boundaries.append(boundary)
    return tuple(boundaries)


def _flat32_census_block(
    receipt: TerminalBlockReceipt,
    successor: TerminalBlockReceipt | None,
    trace: SymbolicTerminalTrace,
    boot: PeProgramBoot,
    chunks: tuple[tuple[int, bytes], ...],
    routes: Mapping[int, PeImportService],
    initial_bytes: Callable[[int, int], bytes | None],
) -> Flat32ServiceBoundary | TerminalRefusal | None:
    """Classify one byte-authenticated receipt inside the census chain."""
    if successor is not None and receipt.next_target != successor.address:
        return _stale_census("block does not continue to its recorded successor")
    if not _flat32_executable_contains(boot, receipt.address, receipt.size):
        return _stale_census(
            f"block receipt at {hex(receipt.address)} leaves declared executable bytes"
        )
    decoded = _flat32_decode_receipt(receipt, chunks, trace.decode_limits)
    if isinstance(decoded, TerminalRefusal):
        return decoded
    final = decoded[-1]
    if successor is None and trace.fault is not None:
        return _flat32_census_fault_close(receipt, decoded, trace.fault)
    classified = _flat32_census_terminator(receipt, final, routes, initial_bytes)
    if isinstance(classified, TerminalRefusal):
        return classified
    boundary, expected = classified
    if successor is None:
        refusal = _flat32_census_terminal_close(
            receipt, final, trace.site, boot, expected
        )
        if refusal is not None:
            return refusal
        return boundary
    if expected is not None and receipt.next_target != expected:
        return _stale_census(
            "ordinary successor disagrees with native instruction semantics"
        )
    if boundary is None and final.id == decoded_ids.X86_INS_CALL:
        return _stale_census("middle block ends on a non-admitted direct call")
    return boundary


def _flat32_census_fault_close(
    receipt: TerminalBlockReceipt,
    decoded: tuple[capstone.CsInsn, ...],
    fault: FaultOutcome,
) -> TerminalRefusal | None:
    """Bind the early architectural fault to an exact native instruction.

    Intake stops at the proved fault but retains the entire VEX block. Its
    final instruction and jumpkind describe an unexecuted suffix, so neither
    is evidence of where the architectural fault occurred. Intake owns the
    architectural fault predicate; the fault verifier rebinds source bytes.
    """
    if receipt.next_target is not None:
        return _stale_census("fault boundary claims a successor")
    if not any(instruction.address == fault.site_address
               and bytes(instruction.bytes) == bytes(fault.encoding)
               for instruction in decoded):
        return _stale_census("fault boundary does not re-derive its faulting instruction")
    return None


def _flat32_census_terminal_close(
    receipt: TerminalBlockReceipt,
    final: capstone.CsInsn,
    site: TerminalSite | None,
    boot: PeProgramBoot,
    expected: int | None,
) -> TerminalRefusal | None:
    """Authenticate the closing receipt against the declared exit site."""
    if site is None:
        return _stale_census("trace closes on a boundary its outcome does not declare")
    if (
        site.service is not TerminalService.PE_DECLARED_EXIT
        or final.address != site.address
        or bytes(final.bytes) != bytes(site.encoding)
    ):
        return _stale_census("closing transfer does not re-derive the declared exit site")
    if site.target != boot.environment.exit_address:
        return _stale_census("closing transfer does not target the declared exit gateway")
    if receipt.next_target != site.target:
        return _stale_census("closing receipt successor disagrees with the declared exit")
    if expected is not None and expected != site.target:
        return _stale_census("closing successor disagrees with native instruction semantics")
    return None


def _verify_flat32_service_events(
    trace: SymbolicTerminalTrace,
    boot: PeProgramBoot,
    chunks: tuple[tuple[int, bytes], ...],
) -> TerminalRefusal | None:
    """Require the retained events to answer the executed-boundary census.

    The census — re-derived from the authenticated block evidence, the real
    IAT bindings and the declared boot entry — fixes the denominator:
    exactly one typed receipt per executed returning boundary, in execution
    order, with its site, slot, bound service identity and sequence ordinal
    all re-derived rather than trusted. Count equality plus positional
    binding refutes removed, subset, duplicated, reordered and foreign
    receipts alike. The closed fact counters must also re-derive from the
    admitted evidence — every block plus every boundary is a fact, the
    outcome is the one extra classified fact, every boundary and output
    must materialize, and nothing may fail silently — so a forged counter
    set refuses as ``STALE_EVIDENCE``.
    """
    routes = _flat32_slot_routes(boot.imports)
    census = _flat32_returning_census(
        trace, boot, chunks, routes, _flat32_initial_bytes(boot)
    )
    if isinstance(census, TerminalRefusal):
        return census
    events = trace.service_events
    if len(events) != len(census):
        return _stale_census(
            f"returning-service census admits {len(census)} executed boundaries "
            f"but the trace retains {len(events)} receipts"
        )
    for index, (event, boundary) in enumerate(zip(events, census, strict=True)):
        if not isinstance(event, ImportedServiceEvent):
            return _stale_census(
                "service event receipt is not a typed imported-service event"
            )
        if (
            event.site != boundary.site
            or event.slot != boundary.slot
            or event.service != boundary.service
            or event.sequence != index
        ):
            return _stale_census(
                f"receipt {index} does not bind the executed boundary at "
                f"{hex(boundary.site)}"
            )
    evidence = len(trace.blocks) + len(census)
    expected = FactCounters(
        raw_fact_count=evidence,
        normalized_fact_count=evidence,
        classified_fact_count=evidence + 1,
        materialized_count=len(trace.document["outputs"]) + len(census),
        failure_count=0,
    )
    if trace.counters != expected:
        return _stale_census(
            "trace fact counters do not re-derive from the admitted evidence census"
        )
    if any(boundary.frame_bound for boundary in census):
        return _verify_flat32_frame_continuations(trace, boot)
    return None


def _verify_flat32_frame_continuations(
    trace: SymbolicTerminalTrace, boot: PeProgramBoot,
) -> TerminalRefusal | None:
    """Re-derive thunk continuations from fresh source-bound native state.

    A coherent edit of successors, events and counters must not skip an
    executed service. Only decoded JMP-IAT routes pay for this additional
    bounded load/lift/lower pass. It uses no document materialization and
    no solver; ordinary CALL-IAT fallthroughs remain byte-authenticated.
    """
    native = trace.decode_limits
    limits = TerminalLimits(
        max_blocks=native.max_blocks, max_block_bytes=native.max_block_bytes,
        max_instructions=native.max_instructions,
    )
    try:
        replay = _seeded_flat32_walk(trace.source, boot, limits)
    except TerminalRefusal as error:
        return _stale_census(f"thunk continuation replay refused: {error.detail}")
    boundary = trace.fault if trace.fault is not None else trace.site
    if replay.blocks != trace.blocks or replay.events != trace.service_events or replay.boundary != boundary:
        return _stale_census("thunk continuations do not match the source-derived native walk")
    return None


def _chunk_read(
    chunks: tuple[tuple[int, bytes], ...]
) -> Callable[[int, int], bytes | None]:
    """Build a byte resolver over the re-derived image chunks."""

    def read(address: int, length: int) -> bytes | None:
        located = _chunk_bytes(chunks, address)
        if located is None:
            return None
        base, data = located
        offset = address - base
        if offset + length > len(data):
            return None
        return bytes(data[offset : offset + length])

    return read


def _verify_service_events(
    trace: SymbolicTerminalTrace, chunks: tuple[tuple[int, bytes], ...]
) -> TerminalRefusal | None:
    """Require the retained events to answer the executed-boundary census.

    The census — derived in ``verify_returning_receipts`` from the
    byte-authenticated block receipts and the declared selectors, never
    from the supplied events — fixes the complete ordered denominator of
    executed returning-service boundaries. Exactly one receipt must answer
    each census entry, so an empty or partial event list, a duplicated or
    reordered receipt, a forged site or a forged payload refuses as
    ``STALE_EVIDENCE``, while legitimate repeated dispatches keep one
    receipt per occurrence. The outcome/site coherence and the closed fact
    counters re-derive here too, so counter accounting cannot hide a
    boundary either.
    """
    assert isinstance(trace.environment, ProgramEnvironment)
    events: list[TerminalServiceEvent] = []
    for event in trace.service_events:
        if not isinstance(event, TerminalServiceEvent):
            return _stale_census("real16 trace carries a foreign service event")
        events.append(event)
    fault_outcome = trace.outcome is TerminalOutcome.PROCESSOR_FAULT
    if fault_outcome != (trace.fault is not None):
        return TerminalRefusal(
            TerminalRefusalKind.STALE_EVIDENCE,
            "trace outcome and retained fault evidence disagree",
        )
    endings = tuple(
        ServiceBlockEnding(
            receipt.address, receipt.size, receipt.jumpkind, receipt.next_target
        )
        for receipt in trace.blocks
    )
    terminal_site: int | None = None
    terminal_target: int | None = None
    if trace.outcome is TerminalOutcome.DECLARED_SERVICE:
        site = trace.site
        expected_target = INTERRUPT_CORE_BASE + DOS_VECTOR
        if (
            site is None
            or site.service is not TerminalService.DOS_TERMINATE
            or site.encoding != bytes((0xCD, DOS_VECTOR))
            or site.target != expected_target
        ):
            return TerminalRefusal(
                TerminalRefusalKind.STALE_EVIDENCE,
                "declared-service outcome lacks its bound DOS termination site",
            )
        terminal_site = site.address
        terminal_target = expected_target
    elif fault_outcome:
        if trace.site is not None:
            return TerminalRefusal(
                TerminalRefusalKind.STALE_EVIDENCE,
                "fault outcome carries a terminal site claim",
            )
    else:
        return TerminalRefusal(
            TerminalRefusalKind.STALE_EVIDENCE,
            f"untyped trace outcome {trace.outcome!r} cannot be verified",
        )
    outputs = trace.document.get("outputs")
    if not isinstance(outputs, dict):
        return TerminalRefusal(
            TerminalRefusalKind.STALE_EVIDENCE,
            "trace document lacks its materialized outputs",
        )
    return verify_returning_receipts(
        tuple(events),
        endings,
        _chunk_read(chunks),
        limits=trace.decode_limits,
        version_policy=trace.environment.version_policy,
        video_policy=trace.environment.video_policy,
        terminal_site=terminal_site,
        terminal_target=terminal_target,
        fault_outcome=fault_outcome,
        outputs=len(outputs),
        counters=trace.counters,
    )


def _verify_block_receipts(
    blocks: tuple[TerminalBlockReceipt, ...], chunks: tuple[tuple[int, bytes], ...]
) -> TerminalRefusal | None:
    """Re-derive every admitted block's bytes from the retained source image."""
    for receipt in blocks:
        located = _chunk_bytes(chunks, receipt.address)
        if located is None:
            return TerminalRefusal(
                TerminalRefusalKind.STALE_EVIDENCE,
                f"block at {hex(receipt.address)} is absent from the re-derived image",
            )
        base, data = located
        current = data[receipt.address - base : receipt.address - base + receipt.size]
        if len(current) != receipt.size or hashlib.sha256(current).hexdigest() != receipt.sha256:
            return TerminalRefusal(
                TerminalRefusalKind.STALE_EVIDENCE,
                f"block bytes at {hex(receipt.address)} changed after capture",
            )
    return None


def _verify_fault_site(
    trace: SymbolicTerminalTrace, chunks: tuple[tuple[int, bytes], ...]
) -> TerminalRefusal | None:
    """Re-derive the fault site's bytes and its place in the block receipt.

    A processor-fault outcome carries its typed fault evidence: the site
    must lie inside the terminating block's retained bytes and the encoded
    instruction must still re-derive from the retained source image —
    anything else is stale evidence, never compared.
    """
    if trace.fault is None or not trace.blocks:
        return TerminalRefusal(
            TerminalRefusalKind.STALE_EVIDENCE, "fault outcome lacks its site evidence"
        )
    last = trace.blocks[-1]
    site = trace.fault.site_address
    encoding = trace.fault.encoding
    if site < last.address or site + len(encoding) > last.address + last.size:
        return TerminalRefusal(
            TerminalRefusalKind.STALE_EVIDENCE,
            f"fault site {hex(site)} is outside the terminating block receipt",
        )
    located = _chunk_bytes(chunks, site)
    if located is None:
        return TerminalRefusal(
            TerminalRefusalKind.STALE_EVIDENCE,
            f"fault site {hex(site)} is absent from the re-derived image",
        )
    base, data = located
    current = data[site - base : site - base + len(encoding)]
    if bytes(current) != encoding:
        return TerminalRefusal(
            TerminalRefusalKind.STALE_EVIDENCE,
            f"fault site bytes at {hex(site)} changed after capture",
        )
    return None


def compare_symbolic_terminals(
    oracle_data: bytes,
    oracle_environment: ProgramEnvironment | PeProgramEnvironment,
    candidate_data: bytes,
    candidate_environment: ProgramEnvironment | PeProgramEnvironment,
    *,
    limits: TerminalLimits | None = None,
) -> TerminalComparison:
    """Compare two actual native programs' declared terminal transitions.

    Both lanes are traced from their real serialized bytes under their
    declared environments, then re-verified against those retained bytes.
    The joint verdict requires identical environment identity and service
    contract, then proves — under Z3 with the shared input space — equality
    of the event payload plus every compared register/memory output of the
    terminal transition. A SAT model is a counterexample; ``unknown`` or any
    lane refusal is never promoted to agreement.
    """
    limits = limits or TerminalLimits()
    started = time.monotonic()
    oracle = _trace_lane(oracle_data, oracle_environment, limits=limits)
    candidate = _trace_lane(candidate_data, candidate_environment, limits=limits)
    counters = FactCounters(
        raw_fact_count=_lane_counter(oracle, "raw") + _lane_counter(candidate, "raw"),
        normalized_fact_count=(
            _lane_counter(oracle, "normalized") + _lane_counter(candidate, "normalized")
        ),
        classified_fact_count=(
            _lane_counter(oracle, "classified") + _lane_counter(candidate, "classified")
        ),
        materialized_count=(
            _lane_counter(oracle, "materialized") + _lane_counter(candidate, "materialized")
        ),
        failure_count=sum(lane.refusal is not None for lane in (oracle, candidate)),
    )
    for lane in (oracle, candidate):
        if lane.refusal is not None:
            return TerminalComparison(
                TerminalComparisonStatus.REFUSED,
                None,
                None,
                None,
                f"{lane.refusal.kind.value}: {lane.refusal.detail}",
                oracle,
                candidate,
                counters,
            )
    assert oracle.trace is not None and candidate.trace is not None
    stale = verify_terminal_trace(oracle.trace) or verify_terminal_trace(candidate.trace)
    if stale is not None:
        return TerminalComparison(
            TerminalComparisonStatus.REFUSED,
            None,
            None,
            None,
            f"{stale.kind.value}: {stale.detail}",
            oracle,
            candidate,
            FactCounters(
                counters.raw_fact_count,
                counters.normalized_fact_count,
                counters.classified_fact_count,
                counters.materialized_count,
                counters.failure_count + 1,
            ),
        )
    left, right = oracle.trace, candidate.trace
    premise_verdict = _premise_verdict(left, right, oracle, candidate, counters)
    if premise_verdict is not None:
        return premise_verdict
    assumptions = (
        *left.premises,
        {
            "kind": "joint_premise",
            "environment_identity": left.environment_identity,
            "service": left.service.value,
            "outcome": left.outcome.value,
            "scope": "bounded acyclic terminal region with explicitly declared returning queries",
        },
        {
            "kind": "initial_data_relation",
            "relation": InitialDataRelation.SHARED_UNCONSTRAINED.value,
            "evidence": (
                "concrete declared initial bytes agree at every proved "
                "initial-memory read site; unread and program-written bytes "
                "stay an explicit unconstrained premise, not an "
                "initialized-program claim"
            ),
            "site_count": len(left.initial_read_sites) + len(right.initial_read_sites),
        },
    )
    if left.outcome is not right.outcome:
        return TerminalComparison(
            TerminalComparisonStatus.COUNTEREXAMPLE,
            left.architecture,
            left.service,
            left.environment_identity,
            (
                f"terminal outcomes differ: {left.outcome.value} versus "
                f"{right.outcome.value} — a normal service boundary and a "
                "processor fault are different events, never equivalent"
            ),
            oracle,
            candidate,
            counters,
            assumptions=assumptions,
            diverged=("terminal_outcome",),
        )
    outcome_verdict, assumptions = _compare_outcome_evidence(
        left, right, oracle, candidate, counters, assumptions
    )
    if outcome_verdict is not None:
        return outcome_verdict
    return _solved_terminal_verdict(
        left,
        right,
        oracle,
        candidate,
        counters,
        assumptions,
        limits,
        started,
    )


_FAULT_SITE_RELATION_PREMISE: Mapping[str, Any] = {
    "kind": "fault_site_relation",
    "relation": "entry_relative_instruction_offset",
    "evidence": (
        "fault sites compare as the faulting instruction's offset from each "
        "lane's declared entry; the absolute site address and encoding are "
        "retained stale-evidence material, and a different stream position "
        "is a different observable event"
    ),
}
"""The admitted fault-site relation, carried into verdict assumptions."""


def _premise_verdict(
    left: SymbolicTerminalTrace,
    right: SymbolicTerminalTrace,
    oracle: TerminalLaneResult,
    candidate: TerminalLaneResult,
    counters: FactCounters,
) -> TerminalComparison | None:
    """Require one shared declared premise before any equivalence attempt.

    Architecture, service contract, environment identity and the initial-data
    relation must all agree; differing declared contracts are a premise
    mismatch, never an invented relation between lanes.
    """
    premises = (*left.premises, *right.premises)
    if left.architecture is not right.architecture or left.service is not right.service:
        return TerminalComparison(
            TerminalComparisonStatus.PREMISE_MISMATCH,
            left.architecture,
            left.service,
            None,
            "lanes declare different architectures or service contracts",
            oracle,
            candidate,
            counters,
            assumptions=premises,
        )
    if left.environment_identity != right.environment_identity:
        return TerminalComparison(
            TerminalComparisonStatus.PREMISE_MISMATCH,
            left.architecture,
            left.service,
            None,
            "environment identities differ; no shared declared premise exists",
            oracle,
            candidate,
            counters,
            assumptions=premises,
        )
    initial_mismatch = _check_initial_data_relation(left, right)
    if initial_mismatch is not None:
        return TerminalComparison(
            TerminalComparisonStatus.PREMISE_MISMATCH,
            left.architecture,
            left.service,
            left.environment_identity,
            initial_mismatch,
            oracle,
            candidate,
            counters,
            assumptions=premises,
        )
    return None






def _compare_fault_outcome(
    left: SymbolicTerminalTrace,
    right: SymbolicTerminalTrace,
    oracle: TerminalLaneResult,
    candidate: TerminalLaneResult,
    counters: FactCounters,
    assumptions: tuple[Mapping[str, Any], ...],
) -> TerminalComparison | None:
    """Compare two processor-fault outcomes; ``None`` means all fields agree.

    A processor fault must carry its typed evidence to be compared at all;
    kind, exception vector and the entry-relative site relation each diverge
    as their own observable — a different fault is never an equivalent stop.
    """
    if left.fault is None or right.fault is None:
        return TerminalComparison(
            TerminalComparisonStatus.REFUSED,
            left.architecture,
            left.service,
            left.environment_identity,
            "processor-fault outcome lacks its typed fault evidence",
            oracle,
            candidate,
            counters,
            assumptions=assumptions,
        )
    if left.fault.kind is not right.fault.kind:
        return TerminalComparison(
            TerminalComparisonStatus.COUNTEREXAMPLE,
            left.architecture,
            left.service,
            left.environment_identity,
            f"fault kinds differ: {left.fault.kind.value} versus {right.fault.kind.value}",
            oracle,
            candidate,
            counters,
            assumptions=assumptions,
            diverged=("fault_kind",),
        )
    if left.fault.vector != right.fault.vector:
        return TerminalComparison(
            TerminalComparisonStatus.COUNTEREXAMPLE,
            left.architecture,
            left.service,
            left.environment_identity,
            f"fault vectors differ: {left.fault.vector} versus {right.fault.vector}",
            oracle,
            candidate,
            counters,
            assumptions=assumptions,
            diverged=("fault_vector",),
        )
    left_site = left.fault.site_address - left.entry
    right_site = right.fault.site_address - right.entry
    if left_site != right_site:
        return TerminalComparison(
            TerminalComparisonStatus.COUNTEREXAMPLE,
            left.architecture,
            left.service,
            left.environment_identity,
            (
                f"fault sites differ in entry-relative position: "
                f"+{hex(left_site)} versus +{hex(right_site)}"
            ),
            oracle,
            candidate,
            counters,
            assumptions=assumptions,
            diverged=("fault_site",),
        )
    return None


def _compare_outcome_evidence(
    left: SymbolicTerminalTrace,
    right: SymbolicTerminalTrace,
    oracle: TerminalLaneResult,
    candidate: TerminalLaneResult,
    counters: FactCounters,
    assumptions: tuple[Mapping[str, Any], ...],
) -> tuple[TerminalComparison | None, tuple[Mapping[str, Any], ...]]:
    """Return the early verdict and all premises required by the solver result."""
    if left.outcome is TerminalOutcome.PROCESSOR_FAULT:
        assumptions = (*assumptions, _FAULT_SITE_RELATION_PREMISE)
        fault_verdict = _compare_fault_outcome(
            left, right, oracle, candidate, counters, assumptions
        )
        if fault_verdict is not None:
            return fault_verdict, assumptions
    verdict = _compare_service_events(
        left, right, oracle, candidate, counters, assumptions
    )
    return verdict, assumptions


def _event_observation(event: TerminalServiceEvent | ImportedServiceEvent) -> tuple[str, bytes]:
    """Project the typed observable, excluding native receipt coordinates."""
    if isinstance(event, ImportedServiceEvent):
        return "pe32_import", event.service.encode("utf-8")
    return event.kind.value, event.data


def _compare_service_events(
    left: SymbolicTerminalTrace,
    right: SymbolicTerminalTrace,
    oracle: TerminalLaneResult,
    candidate: TerminalLaneResult,
    counters: FactCounters,
    assumptions: tuple[Mapping[str, Any], ...],
) -> TerminalComparison | None:
    """Compare the ordered returning-service receipts; ``None`` means equal.

    Declared query events are concrete observable interactions under the
    shared environment identity, so a different count, order or payload is
    a definite divergence — a counterexample, never a premise mismatch or
    solver question.
    """
    left_events = [_event_observation(event) for event in left.service_events]
    right_events = [_event_observation(event) for event in right.service_events]
    if left_events == right_events:
        return None
    return TerminalComparison(
        TerminalComparisonStatus.COUNTEREXAMPLE,
        left.architecture,
        left.service,
        left.environment_identity,
        (
            f"ordered returning-service events differ: {len(left_events)} "
            f"receipts versus {len(right_events)} — a removed, reordered "
            "or repeated declared query is a different observable history"
        ),
        oracle,
        candidate,
        counters,
        assumptions=assumptions,
        diverged=("service_events",),
    )


def _lane_initial_bytes(
    trace: SymbolicTerminalTrace,
) -> Callable[[int, int], bytes | None]:
    """Re-derive the lane's declared initial-byte resolver from retained bytes.

    The resolver is rebuilt from ``trace.source`` and ``trace.environment``
    the same way ``verify_terminal_trace`` re-derives the boot, so the
    initial-data check consumes retained evidence, not trace-supplied state.
    """
    if trace.architecture is Architecture.REAL16:
        assert isinstance(trace.environment, ProgramEnvironment)
        return _real16_initial_bytes(program_from_mz_bytes(trace.source, trace.environment))
    assert isinstance(trace.environment, PeProgramEnvironment)
    return _flat32_initial_bytes(pe_program_from_bytes(trace.source, trace.environment))


def _check_initial_data_relation(
    left: SymbolicTerminalTrace, right: SymbolicTerminalTrace
) -> str | None:
    """Verify the concrete boot pair satisfies the shared-initial premise.

    The joint proof uses one symbolic ``mem_input`` for both lanes; that is
    only sound where the concrete programs actually agree. For every proved
    read that reached initial memory, the re-derived declared bytes of both
    boots must resolve identically at that exact site — including identical
    unconstrained gaps. Any disagreement returns the mismatch detail; the
    caller reports it as a premise mismatch rather than claiming an
    initialized-program relation the boot pair does not satisfy.
    """
    left_bytes = _lane_initial_bytes(left)
    right_bytes = _lane_initial_bytes(right)
    for sites, own_bytes, foreign_bytes in (
        (left.initial_read_sites, left_bytes, right_bytes),
        (right.initial_read_sites, right_bytes, left_bytes),
    ):
        for site in sites:
            if own_bytes(site.address, site.size) != foreign_bytes(site.address, site.size):
                return (
                    f"initial bytes at {hex(site.address)} differ between boots "
                    f"at a proved {site.size}-byte initial-memory read site"
                )
    return None


def _solved_terminal_verdict(
    left: SymbolicTerminalTrace,
    right: SymbolicTerminalTrace,
    oracle: TerminalLaneResult,
    candidate: TerminalLaneResult,
    counters: FactCounters,
    assumptions: tuple[Mapping[str, Any], ...],
    limits: TerminalLimits,
    started: float,
) -> TerminalComparison:
    """Prove or disprove output equality over the shared input space.

    Every non-proof maps to a typed non-EQUIVALENT status; the lane evidence
    and assumptions stay attached so callers see exactly what is claimed.
    """
    deadline = started + limits.solver_timeout_ms / 1000
    try:
        if set(left.document["outputs"]) != set(right.document["outputs"]):
            return TerminalComparison(
                TerminalComparisonStatus.REFUSED,
                left.architecture,
                left.service,
                left.environment_identity,
                "compared output declarations differ between lanes",
                oracle,
                candidate,
                counters,
                assumptions=assumptions,
            )
        names = sorted(left.document["outputs"])
        inputs = S._z3_inputs(left.document, right.document, z3)
        solver = z3.Solver()
        solver.set("timeout", limits.solver_timeout_ms)
        pairs, skipped = S._z3_output_pairs(
            names,
            oracle=left.document,
            candidate=right.document,
            oracle_outputs=left.document["outputs"],
            candidate_outputs=right.document["outputs"],
            inputs=inputs,
            z3=z3,
            simplify_terms=False,
        )
        if not pairs or skipped or len(pairs) != len(names) or {name for name, _, _ in pairs} != set(names):
            return TerminalComparison(
                TerminalComparisonStatus.REFUSED,
                left.architecture,
                left.service,
                left.environment_identity,
                "terminal output projection omitted, skipped or duplicated required observations",
                oracle,
                candidate,
                FactCounters(
                    counters.raw_fact_count,
                    counters.normalized_fact_count,
                    counters.classified_fact_count,
                    counters.materialized_count,
                    counters.failure_count + 1,
                ),
                assumptions=assumptions,
            )
        checked = prove_output_equalities(pairs, solver, deadline=deadline)
    except (S.LowerFailure, KeyError, DosUnitError) as error:
        return TerminalComparison(
            TerminalComparisonStatus.REFUSED,
            left.architecture,
            left.service,
            left.environment_identity,
            f"comparison lowering failed: {error}",
            oracle,
            candidate,
            counters,
            assumptions=assumptions,
        )
    elapsed = int((time.monotonic() - started) * 1000)
    if checked.status is ProofStatus.PROVED:
        return TerminalComparison(
            TerminalComparisonStatus.EQUIVALENT,
            left.architecture,
            left.service,
            left.environment_identity,
            "terminal event payload and complete observable transition proved equal",
            oracle,
            candidate,
            counters,
            assumptions=assumptions,
            solver_time_ms=elapsed,
        )
    if checked.status is ProofStatus.COUNTEREXAMPLE and checked.model is not None:
        diverged = tuple(
            name
            for name, left_expr, right_expr in pairs
            if not z3.is_true(
                checked.model.eval(left_expr == right_expr, model_completion=True)
            )
        )
        model = {
            name: checked.model.eval(value, model_completion=True).as_long()
            for name, (value, width) in inputs.items()
            if width > 0
        }
        return TerminalComparison(
            TerminalComparisonStatus.COUNTEREXAMPLE,
            left.architecture,
            left.service,
            left.environment_identity,
            "solver found a shared input distinguishing the terminal transitions",
            oracle,
            candidate,
            counters,
            assumptions=assumptions,
            diverged=diverged,
            model=model,
            solver_time_ms=elapsed,
        )
    return TerminalComparison(
        TerminalComparisonStatus.UNKNOWN,
        left.architecture,
        left.service,
        left.environment_identity,
        checked.detail or "solver could not decide terminal equivalence",
        oracle,
        candidate,
        counters,
        assumptions=assumptions,
        solver_time_ms=elapsed,
    )


def _trace_lane(
    data: bytes,
    environment: ProgramEnvironment | PeProgramEnvironment,
    *,
    limits: TerminalLimits,
) -> TerminalLaneResult:
    """Trace one lane, translating typed refusals into lane evidence."""
    try:
        if isinstance(environment, ProgramEnvironment):
            trace = trace_real16_terminal(data, environment, limits=limits)
        elif isinstance(environment, PeProgramEnvironment):
            trace = trace_flat32_terminal(data, environment, limits=limits)
        else:
            raise TerminalRefusal(
                TerminalRefusalKind.BOOT_CONTRACT, "unknown environment contract type"
            )
    except TerminalRefusal as refusal:
        return TerminalLaneResult(None, refusal)
    return TerminalLaneResult(trace, None)


def _lane_counter(lane: TerminalLaneResult, which: str) -> int:
    """Project one lane's fact counters into the joint comparison counter."""
    if lane.trace is None:
        return 0
    counters = lane.trace.counters
    values = {
        "raw": int(counters.raw_fact_count),
        "normalized": int(counters.normalized_fact_count),
        "classified": int(counters.classified_fact_count),
        "materialized": int(counters.materialized_count),
    }
    return int(values[which])
