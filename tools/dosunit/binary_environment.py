"""Admission of external effects at binary proof boundaries.

Layer: dosunit machine-model contracts.
Responsibility: identify port events and machine-state instructions in decoded
binary instructions and structured SSA, and refuse their promotion under the
current environment-free whole-function proof contract even when lifting
substitutes constants or silently drops the machine effect.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Final

from capstone import CS_ARCH_X86, CS_MODE_16, CS_MODE_32, CS_MODE_64, Cs, CsInsn
from capstone.x86_const import (
    X86_INS_ARPL,
    X86_INS_CLTS,
    X86_INS_HLT,
    X86_INS_IN,
    X86_INS_INSB,
    X86_INS_INSD,
    X86_INS_INSW,
    X86_INS_INVD,
    X86_INS_INVLPG,
    X86_INS_INVPCID,
    X86_INS_LAR,
    X86_INS_LGDT,
    X86_INS_LIDT,
    X86_INS_LLDT,
    X86_INS_LMSW,
    X86_INS_LSL,
    X86_INS_LTR,
    X86_INS_MONITOR,
    X86_INS_MOV,
    X86_INS_MWAIT,
    X86_INS_OUT,
    X86_INS_OUTSB,
    X86_INS_OUTSD,
    X86_INS_OUTSW,
    X86_INS_RDMSR,
    X86_INS_RSM,
    X86_INS_SGDT,
    X86_INS_SIDT,
    X86_INS_SLDT,
    X86_INS_SMSW,
    X86_INS_STR,
    X86_INS_SWAPGS,
    X86_INS_SYSENTER,
    X86_INS_SYSEXIT,
    X86_INS_SYSRET,
    X86_INS_VERR,
    X86_INS_VERW,
    X86_INS_WBINVD,
    X86_INS_WRMSR,
    X86_INS_XSETBV,
    X86_OP_REG,
    X86_REG_CR0,
    X86_REG_CR1,
    X86_REG_CR2,
    X86_REG_CR3,
    X86_REG_CR4,
    X86_REG_CR5,
    X86_REG_CR6,
    X86_REG_CR7,
    X86_REG_CR8,
    X86_REG_CR9,
    X86_REG_CR10,
    X86_REG_CR11,
    X86_REG_CR12,
    X86_REG_CR13,
    X86_REG_CR14,
    X86_REG_CR15,
    X86_REG_DR0,
    X86_REG_DR1,
    X86_REG_DR2,
    X86_REG_DR3,
    X86_REG_DR4,
    X86_REG_DR5,
    X86_REG_DR6,
    X86_REG_DR7,
)

from tools.dosunit.ssa_io_retention import retained_io_event_terms

if TYPE_CHECKING:
    import angr
    import pyvex

    from tools.dosunit.ordered_io_environment import OrderedIoContract


class EnvironmentEffect(StrEnum):
    """External effects needing an explicit event/environment relation."""

    PORT_READ = 'summary_io_in'
    PORT_WRITE = 'summary_io_out'


_PORT_READ_IDS: Final[frozenset[int]] = frozenset({X86_INS_IN, X86_INS_INSB, X86_INS_INSD, X86_INS_INSW})
_PORT_WRITE_IDS: Final[frozenset[int]] = frozenset({X86_INS_OUT, X86_INS_OUTSB, X86_INS_OUTSD, X86_INS_OUTSW})

_MACHINE_STATE_IDS: Final[frozenset[int]] = frozenset({
    X86_INS_ARPL,
    X86_INS_CLTS,
    X86_INS_HLT,
    X86_INS_INVD,
    X86_INS_INVLPG,
    X86_INS_INVPCID,
    X86_INS_LAR,
    X86_INS_LGDT,
    X86_INS_LIDT,
    X86_INS_LLDT,
    X86_INS_LMSW,
    X86_INS_LSL,
    X86_INS_LTR,
    X86_INS_MONITOR,
    X86_INS_MWAIT,
    X86_INS_RDMSR,
    X86_INS_RSM,
    X86_INS_SGDT,
    X86_INS_SIDT,
    X86_INS_SLDT,
    X86_INS_SMSW,
    X86_INS_STR,
    X86_INS_SWAPGS,
    X86_INS_SYSENTER,
    X86_INS_SYSEXIT,
    X86_INS_SYSRET,
    X86_INS_VERR,
    X86_INS_VERW,
    X86_INS_WBINVD,
    X86_INS_WRMSR,
    X86_INS_XSETBV,
})
"""Instruction IDs touching machine state outside the integer register/memory model.

Descriptor-table, task-register, machine-status, control/debug register,
cache/machine-check, protection-ring and system-transfer instructions read or
write machine state the environment-free contract does not model. Several of
these are not tagged privileged by the decoder and are lifted as silent no-ops
or unsupported forms; identification must come from instruction identity,
never rendered text or lift coverage.
"""

_CONTROL_DEBUG_REGISTER_IDS: Final[frozenset[int]] = frozenset({
    X86_REG_CR0, X86_REG_CR1, X86_REG_CR2, X86_REG_CR3, X86_REG_CR4, X86_REG_CR5,
    X86_REG_CR6, X86_REG_CR7, X86_REG_CR8, X86_REG_CR9, X86_REG_CR10, X86_REG_CR11,
    X86_REG_CR12, X86_REG_CR13, X86_REG_CR14, X86_REG_CR15,
    X86_REG_DR0, X86_REG_DR1, X86_REG_DR2, X86_REG_DR3, X86_REG_DR4, X86_REG_DR5,
    X86_REG_DR6, X86_REG_DR7,
})
"""Control and debug register operands of an ordinary MOV are machine state."""


@dataclass(frozen=True)
class IoEvent:
    """One decoded port event bound to a binary instruction address.

    ``width_bits`` is the decoded scalar data width for scalar IN/OUT forms
    and ``None`` for string or otherwise non-scalar port effects.
    """

    address: int
    effect: EnvironmentEffect
    width_bits: int | None
    instruction_id: int


@dataclass(frozen=True)
class EnvironmentScan:
    """Binary-IR environment admission, including incomplete evidence.

    ``requires_contract`` retains its original meaning: external effects exist
    that no declared contract covers.  Under a declared ordered-I/O contract,
    covered scalar events are recorded in ``events`` instead of forcing a
    refusal; uncovered events, machine-state instructions, uncovered dirty
    helpers and decoded/SSA event mismatches still refuse.  With no contract
    bound the behavior is unchanged: any port effect or opaque dirty helper
    requires a contract.
    """

    complete: bool
    requires_contract: bool
    blocks_scanned: int
    events: tuple[IoEvent, ...] = ()
    uncovered: tuple[IoEvent, ...] = ()
    machine_state: tuple[int, ...] = ()
    helpers: tuple[str, ...] = ()
    mismatched: tuple[str, ...] = ()


def external_effects(document: Mapping[str, object]) -> frozenset[EnvironmentEffect]:
    """Collect port events from SSA operators, including unused lifted inputs.

    Inspect the assignments as well as outputs: reading a port is an event even
    if its returned value is dead. Rendered instructions and names are unused.
    """
    effects: set[EnvironmentEffect] = set()
    pending: list[object] = [document.get('assignments'), document.get('outputs')]
    operators = {effect.value: effect for effect in EnvironmentEffect}
    while pending:
        term = pending.pop()
        if isinstance(term, dict):
            operation = term.get('op')
            effect = operators.get(operation) if isinstance(operation, str) else None
            if effect is not None:
                effects.add(effect)
            pending.extend(term.values())
        elif isinstance(term, (list, tuple)):
            pending.extend(term)
    return frozenset(effects)


#: Scoped declared ordered-I/O binding.  ``installed_ordered_io`` is the only
#: writer; ``requires_environment_contract`` is the only reader, so gates in
#: unowned lowering code admit covered helpers only inside an explicit scope.
#: A ContextVar keeps the binding inside one logical execution context: an
#: independent thread never observes another comparison's environment.
_ACTIVE_IO_CONTRACT: ContextVar[OrderedIoContract | None] = ContextVar(
    "dosunit_ordered_io_environment", default=None
)


def _dirty_helper_name(statement: object) -> str:
    """Name of one VEX dirty callee; the pyvex boundary supplies ``cee``."""
    # Dynamic third-party pyvex boundary: helper records expose optional cee/name.
    callee = getattr(statement, "cee", None)
    # Dynamic third-party pyvex boundary: callees may carry a name or stringify.
    return str(getattr(callee, "name", "") or callee or "")


def active_ordered_io() -> OrderedIoContract | None:
    """Return the ordered-I/O contract bound to this execution context."""
    return _ACTIVE_IO_CONTRACT.get()


@contextmanager
def _retained_lifted_port_scope(contract: OrderedIoContract) -> Iterator[None]:
    """Match a REAL16 declared environment to frontend lifted event retention.

    The X86_16 frontend lifts ``IN`` from a concrete unregistered port as the
    canonical device-default constant, so a decoded port event would have no
    lifted dirty helper — and no retained SSA event — to compare against.
    The declared ordered-I/O contract models every scalar port access as an
    ordered event; its binding scope therefore also asks the frontend to
    retain the event helper while lifting.  Other lane architectures emit
    port events unconditionally and need no opt-in.
    """
    from tools.dosunit.proof_contracts import Architecture

    if contract.architecture is not Architecture.REAL16:
        yield
        return
    from angr_platforms.X86_16.io import retained_port_events

    with retained_port_events():
        yield


@contextmanager
def installed_ordered_io(contract: OrderedIoContract) -> Iterator[OrderedIoContract]:
    """Install a declared ordered-I/O contract for one bounded proof scope.

    Inside the scope, ``requires_environment_contract`` admits a VEX dirty
    helper only when its callee identity is covered by the contract; every
    other dirty helper still requires an environment contract.  A REAL16
    contract additionally scopes the frontend port-event retention so the
    lifted IR carries the same concrete-port IN events the decoder attests.
    The binding is context-local and restored by token, so a concurrent
    comparison in a different thread cannot observe — or be admitted by —
    this contract, and an exception inside the scope still releases it.
    Outside the scope (the default) behavior is unchanged.  Nested
    installation refuses: two simultaneous relations could never be told
    apart at the gate.
    """
    from tools.dosunit.ordered_io_environment import OrderedIoContract

    if not isinstance(contract, OrderedIoContract):
        raise ValueError("installed ordered-io binding must be an OrderedIoContract")
    if _ACTIVE_IO_CONTRACT.get() is not None:
        raise ValueError("nested ordered-io environment bindings refuse")
    token = _ACTIVE_IO_CONTRACT.set(contract)
    try:
        with _retained_lifted_port_scope(contract):
            yield contract
    finally:
        _ACTIVE_IO_CONTRACT.reset(token)


@contextmanager
def scoped_ordered_io(contract: OrderedIoContract | None) -> Iterator[OrderedIoContract | None]:
    """Bind ``contract`` for one scope, or reuse an equal ambient binding.

    A scope nested inside an enclosing ``installed_ordered_io`` succeeds only
    when the ambient contract is content-equal; a different relation under an
    active binding is a conflicting environment claim and refuses.
    ``None`` is a no-op scope preserving default closed-world behavior.
    """
    if contract is None:
        yield None
        return
    current = _ACTIVE_IO_CONTRACT.get()
    if current is not None:
        if current != contract:
            raise ValueError("conflicting ordered-io environment binding")
        yield current
        return
    with installed_ordered_io(contract):
        yield contract


def requires_environment_contract(irsb: pyvex.IRSB) -> bool:
    """Refuse opaque VEX dirty helpers under the environment-free proof model.

    Examine original IR before output liveness can drop an unused port read.
    Pure flag calculations are CCall expressions and remain admissible.
    Under an installed :class:`OrderedIoContract` binding, helpers whose
    callee identity is covered by the declared relation are admitted; all
    other dirty helpers still require an environment contract.
    """
    import pyvex

    helpers = [
        _dirty_helper_name(statement)
        for statement in irsb.statements
        if isinstance(statement, pyvex.stmt.Dirty)
    ]
    if not helpers:
        return False
    contract = _ACTIVE_IO_CONTRACT.get()
    if contract is None:
        return True
    return not all(contract.covers_helper(name) for name in helpers)


def decoded_port_effects(code: bytes, address: int, *, mode_bits: int) -> frozenset[EnvironmentEffect] | None:
    """Read instruction IDs from complete binary decoding, never rendered text.

    Unknown mode or incomplete decoding returns no evidence. Immediate bytes
    inside an ordinary instruction are not events. This independently retains
    port events that the lifter models as constants for unregistered devices.
    """
    mode = {16: CS_MODE_16, 32: CS_MODE_32, 64: CS_MODE_64}.get(mode_bits)
    if mode is None or not code:
        return None
    decoder = Cs(CS_ARCH_X86, mode)
    cursor = address
    effects: set[EnvironmentEffect] = set()
    for instruction in decoder.disasm(code, address):
        if instruction.address != cursor or instruction.size <= 0:
            return None
        cursor += instruction.size
        effect = instruction_port_effect(instruction)
        if effect is not None:
            effects.add(effect)
    return frozenset(effects) if cursor == address + len(code) else None


def instruction_port_effect(instruction: CsInsn) -> EnvironmentEffect | None:
    """Classify one decoded instruction without treating immediate bytes as opcodes."""
    if instruction.id in _PORT_READ_IDS:
        return EnvironmentEffect.PORT_READ
    if instruction.id in _PORT_WRITE_IDS:
        return EnvironmentEffect.PORT_WRITE
    return None


def instruction_requires_machine_state(instruction: CsInsn) -> bool:
    """Identify unmodeled machine state from a detailed decoded instruction.

    Decoder privilege tags omit instructions such as SMSW and SIDT. Check
    instruction identity and control/debug operands before trusting lifted
    integer effects; some real16 forms currently lift as silent no-ops.
    The caller owns complete decoding and enables Capstone detail.
    """
    return instruction.id in _MACHINE_STATE_IDS or (
        instruction.id == X86_INS_MOV and any(
            operand.type == X86_OP_REG and operand.reg in _CONTROL_DEBUG_REGISTER_IDS
            for operand in instruction.operands
        )
    )


def _scalar_port_width(instruction: CsInsn) -> int | None:
    """Decoded scalar data width of an IN/OUT, or ``None`` when non-scalar.

    Structured operand detail supplies the data register: the destination
    operand of IN, the source operand of OUT.  String I/O forms have no
    scalar data register and never yield a width here.
    """
    if instruction.id == X86_INS_IN:
        operand = instruction.operands[0] if instruction.operands else None
    elif instruction.id == X86_INS_OUT:
        operand = instruction.operands[1] if len(instruction.operands) > 1 else None
    else:
        return None
    if operand is None or operand.type != X86_OP_REG:
        return None
    # Dynamic third-party Capstone boundary: operand size availability varies.
    size = getattr(operand, "size", None)
    return size * 8 if type(size) is int and size > 0 else None


def decoded_io_events(code: bytes, address: int, *, mode_bits: int) -> tuple[IoEvent, ...] | None:
    """Decode the ordered port-event sequence of a complete byte range.

    Ordered decoding retains every event — repetition, order and direction —
    where a set of effects would collapse them.  Unknown mode or incomplete
    decoding returns no evidence, never a partial sequence.
    """
    mode = {16: CS_MODE_16, 32: CS_MODE_32, 64: CS_MODE_64}.get(mode_bits)
    if mode is None or not code:
        return None
    decoder = Cs(CS_ARCH_X86, mode)
    decoder.detail = True
    cursor = address
    events: list[IoEvent] = []
    for instruction in decoder.disasm(code, address):
        if instruction.address != cursor or instruction.size <= 0:
            return None
        cursor += instruction.size
        effect = instruction_port_effect(instruction)
        if effect is not None:
            events.append(
                IoEvent(
                    address=instruction.address,
                    effect=effect,
                    width_bits=_scalar_port_width(instruction),
                    instruction_id=int(instruction.id),
                )
            )
    return tuple(events) if cursor == address + len(code) else None


def decoded_machine_state(code: bytes, address: int, *, mode_bits: int) -> tuple[int, ...] | None:
    """Decode machine-state instruction addresses in a complete byte range."""
    mode = {16: CS_MODE_16, 32: CS_MODE_32, 64: CS_MODE_64}.get(mode_bits)
    if mode is None or not code:
        return None
    decoder = Cs(CS_ARCH_X86, mode)
    decoder.detail = True
    cursor = address
    found: list[int] = []
    for instruction in decoder.disasm(code, address):
        if instruction.address != cursor or instruction.size <= 0:
            return None
        cursor += instruction.size
        if instruction_requires_machine_state(instruction):
            found.append(instruction.address)
    return tuple(found) if cursor == address + len(code) else None


def _const_arg(term: object) -> int | None:
    """Read an inline materialized const argument; anything else is no literal."""
    if not isinstance(term, dict) or term.get("op") != "const":
        return None
    value = term.get("value")
    if type(value) is int:
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def part_io_events(part: Mapping[str, object]) -> tuple[tuple[int, EnvironmentEffect, int], ...] | None:
    """Ordered ``(index, effect, width_bits)`` events in one SSA part.

    Materialized terms record each event's declared sequence index, its
    effect and its scalar width.  A malformed shape — missing const index or
    width, duplicated or skipped indices — returns ``None`` rather than a
    guessed sequence: the ordered event relation cannot be checked against
    corrupt evidence.
    """
    assignments = part.get("assignments")
    outputs = part.get("outputs")
    if assignments is None:
        assignments = []
    if outputs is None:
        outputs = {}
    # Native materialized SSA publishes ``outputs`` as a name→term mapping —
    # the same shape ``real16_call_evidence._check_part_state`` requires.
    # A list-shaped ``outputs`` is a foreign/malformed receipt, not a
    # container to be reinterpreted.
    if not isinstance(assignments, list) or not isinstance(outputs, Mapping):
        return None
    events = _collect_io_event_terms(assignments, outputs.values())
    if events is None:
        return None
    if not events:
        return ()
    ordered = sorted(events)
    if ordered != list(range(len(ordered))):
        return None
    retained = retained_io_event_terms(assignments, outputs.get("io"))
    if retained is None or len(retained) != len(ordered):
        return None
    for index, event in enumerate(retained):
        if _io_term_index(event) != index or events[index] != event:
            return None
    return tuple(_io_term_record(events[index]) for index in ordered)


# Width operand position in ``summary_io_*`` args: read (io, index, port,
# width) and write (io, index, port, value, width) differ.
_IO_WIDTH_ARG: dict[str, int] = {
    EnvironmentEffect.PORT_READ.value: 3,
    EnvironmentEffect.PORT_WRITE.value: 4,
}


def _collect_io_event_terms(
    assignments: list[object], outputs: Iterable[object]
) -> dict[int, dict[str, object]] | None:
    """Map ordered-I/O event index to its materialized term, or ``None``.

    ``None`` means malformed evidence: a non-dict structural term, an event
    term without constant index/width operands, or two different terms
    claiming the same event index. A byte-identical term seen twice — as an
    assignment, again nested inside a ``summary_io_in_state`` chain, or
    aliased through an outputs mapping — is the same event materialized in
    two places and dedupes.

    A recorded event term still descends into its own arguments: its first
    operand is the prior ``io`` chain, which is exactly where an inline
    (unmaterialized) representation nests predecessor reads and writes.
    Stopping at the outermost event would silently drop those earlier
    events. Object-identity memoization bounds the walk on shared subgraphs.
    """
    pending: list[object] = []
    for term in (*assignments, *outputs):
        if not isinstance(term, dict):
            return None
        pending.append(term)
    events: dict[int, dict[str, object]] = {}
    seen: set[int] = set()
    while pending:
        item = pending.pop()
        if not isinstance(item, (dict, list)) or id(item) in seen:
            continue
        seen.add(id(item))
        if isinstance(item, list):
            pending.extend(item)
            continue
        operation = item.get("op")
        if isinstance(operation, str) and operation in _IO_WIDTH_ARG:
            index = _io_term_index(item)
            if index is None:
                return None
            known = events.get(index)
            if known is not None and known != item:
                return None
            events[index] = item
        pending.extend(item.values())
    return events


def _io_term_index(term: dict[str, object]) -> int | None:
    """Event index of one ``summary_io_*`` term, validating its width operand."""
    args = term.get("args")
    width_arg = _IO_WIDTH_ARG.get(str(term.get("op")), -1)
    if not isinstance(args, list) or len(args) <= width_arg:
        return None
    index = _const_arg(args[1])
    width = _const_arg(args[width_arg])
    if index is None or width is None:
        return None
    return index


def _io_term_record(term: dict[str, object]) -> tuple[int, EnvironmentEffect, int]:
    """``(index, effect, width_bits)`` record for a validated event term."""
    args = term["args"]
    assert isinstance(args, list)  # checked by _io_term_index
    operation = str(term["op"])
    index = _const_arg(args[1])
    width = _const_arg(args[_IO_WIDTH_ARG[operation]])
    assert index is not None and width is not None
    return (index, EnvironmentEffect(operation), width)


def _part_label(part: Mapping[str, object]) -> str:
    """Stable label for a part in a coverage-mismatch record."""
    value = part.get("id")
    if isinstance(value, str) and value:
        return value
    entry = part.get("entry")
    if isinstance(entry, dict) and isinstance(entry.get("linear"), str):
        return str(entry["linear"])
    return "<part>"


def _scan_block(
    project: angr.Project, address: int, size: int, *, io_model: OrderedIoContract | None = None
) -> EnvironmentScan:
    """Check original bytes and IR independently before narrowed SSA admission."""
    import pyvex

    block = project.factory.block(address, size=size, opt_level=0)
    irsb = block.vex
    if not isinstance(irsb, pyvex.IRSB):
        return EnvironmentScan(False, False, 0)
    code = block.bytes
    if code is None:
        return EnvironmentScan(False, False, 1)
    # The real16 VEX adapter may use 32-bit storage while retaining a 16-bit
    # instruction set. Architecture identity supplies ISA mode at this foreign
    # boundary; register-storage width alone cannot decode CALL/MOV immediates.
    mode_bits = 16 if project.arch.name == "86_16" else project.arch.bits
    events = decoded_io_events(code, address, mode_bits=mode_bits)
    if len(code) != size or events is None:
        return EnvironmentScan(False, False, 1)
    helpers = tuple(
        _dirty_helper_name(statement)
        for statement in irsb.statements
        if isinstance(statement, pyvex.stmt.Dirty)
    )
    if io_model is None:
        return EnvironmentScan(
            True,
            bool(events) or bool(helpers),
            1,
            events=tuple(event for event in events),
            helpers=helpers,
        )
    machine = decoded_machine_state(code, address, mode_bits=mode_bits)
    if machine is None:
        return EnvironmentScan(False, False, 1, helpers=helpers)
    uncovered = tuple(
        event
        for event in events
        if not io_model.covers_event(event.effect, event.instruction_id, event.width_bits)
    )
    covered = tuple(event for event in events if event not in uncovered)
    uncovered_helpers = tuple(name for name in helpers if not io_model.covers_helper(name))
    requires = bool(uncovered or uncovered_helpers or machine)
    return EnvironmentScan(
        True,
        requires,
        1,
        events=covered,
        uncovered=uncovered,
        machine_state=machine,
        helpers=helpers,
    )


def scan_lowered_parts(
    project: angr.Project, parts: list[dict[str, object]], *, io_model: OrderedIoContract | None = None
) -> EnvironmentScan:
    """Inspect each recorded block's binary IR before relying on narrowed SSA.

    Block locations and byte sizes are lowering facts, not instruction text.
    Missing facts cannot establish absence of external events.  Under a
    declared ``io_model`` every decoded event must be covered by the modeled
    event semantics and observed to match the retained SSA event sequence
    exactly; a dropped, duplicated or reordered lifted event is recorded as
    a mismatch and still refuses.  When the block decoded any event at all,
    a part without retained SSA evidence (``assignments``/``outputs``) also
    refuses: a bare byte range cannot attest that the events survived
    lowering, and ``receipt_bound=False`` marks retained evidence that
    failed its own source binding.  A part with no decoded events and no
    receipt retains nothing, so it needs no receipt to pass.
    """
    scanned = 0
    events: list[IoEvent] = []
    uncovered: list[IoEvent] = []
    machine: list[int] = []
    helpers: list[str] = []
    mismatched: list[str] = []
    for part in parts:
        entry, source = part.get('entry'), part.get('source')
        if not isinstance(entry, dict) or not isinstance(source, dict):
            return EnvironmentScan(False, False, scanned)
        location, size = entry.get('linear'), source.get('machine_code_size')
        if not isinstance(location, str) or type(size) is not int or size <= 0:
            return EnvironmentScan(False, False, scanned)
        try:
            address = int(location, 0)
        except ValueError:
            return EnvironmentScan(False, False, scanned)
        block_scan = _scan_block(project, address, size, io_model=io_model)
        scanned += block_scan.blocks_scanned
        events.extend(block_scan.events)
        uncovered.extend(block_scan.uncovered)
        machine.extend(block_scan.machine_state)
        helpers.extend(block_scan.helpers)
        requires_contract = block_scan.requires_contract
        if io_model is not None and block_scan.complete:
            decoded_sequence = [
                (event.effect, event.width_bits)
                for event in sorted(block_scan.events + block_scan.uncovered, key=lambda e: e.address)
            ]
            ssa_sequence: list[tuple[EnvironmentEffect, int | None]] | None
            if part.get("receipt_bound") is False:
                # Retained SSA existed but failed source binding: its
                # evidence cannot be tied to these compared bytes.
                ssa_sequence = None
            elif "assignments" in part or "outputs" in part:
                ssa_events = part_io_events(part)
                ssa_sequence = (
                    [(effect, width) for _, effect, width in ssa_events]
                    if ssa_events is not None else None
                )
            else:
                # No retained SSA receipt. A bare byte range attests nothing
                # about lowering survival; vacuous only when this block
                # decoded no events at all.
                ssa_sequence = None if decoded_sequence else []
            if ssa_sequence != decoded_sequence:
                mismatched.append(_part_label(part))
                requires_contract = True
        if not block_scan.complete or requires_contract:
            return EnvironmentScan(
                block_scan.complete, requires_contract, scanned,
                events=tuple(events), uncovered=tuple(uncovered),
                machine_state=tuple(machine), helpers=tuple(helpers),
                mismatched=tuple(mismatched),
            )
    return EnvironmentScan(
        bool(parts), False, scanned,
        events=tuple(events), uncovered=tuple(uncovered),
        machine_state=tuple(machine), helpers=tuple(helpers),
        mismatched=tuple(mismatched),
    )
