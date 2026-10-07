"""Independent initialized PE32 execution under a declared terminal service.

Layer: dosunit concrete execution.
Responsibility: start at the binary-derived PE entry with exact declared memory
and registers, preserving file permissions without a synthetic function frame.
The terminal gateway is an explicit environment assumption, not an inferred
Windows API or a complete Windows loader. Replay never establishes a Z3 proof.
"""

from __future__ import annotations

import gc
import hashlib
from dataclasses import dataclass, field

import capstone
import unicorn
from capstone import x86_const as decoded_ids
from unicorn.unicorn_py3.unicorn import Uc, UcError

from tools.dosunit.runtime.flat32_memory_permissions import (
    MAX_MAPPED_BYTES,
    MAX_PAGE_CLAIMS,
    PAGE_SIZE,
    DeclaredAccess,
    DeclaredRegion,
    MappingOrigin,
    PageGrant,
    plan_page_grants,
)
from tools.dosunit.runtime.flat32_replay import _instruction_scope, _written_bytes
from tools.dosunit.runtime.flat32_replay_model import OBSERVABLE_REGISTER_IDS, REGISTER_IDS, MemoryRange
from tools.dosunit.runtime.pe32_program_boot import PeProgramBoot, _environment_identity
from tools.dosunit.runtime.real16_program_model import ProgramEvent, ProgramEventKind, ProgramResult, ProgramStatus
from tools.dosunit.runtime.unicorn_engine import EngineArenaRefusal, make_guest

UNDECLARED_EXTERNAL_IDS: frozenset[int] = frozenset({
    decoded_ids.X86_INS_IN, decoded_ids.X86_INS_OUT,
    decoded_ids.X86_INS_INSB, decoded_ids.X86_INS_INSW, decoded_ids.X86_INS_INSD,
    decoded_ids.X86_INS_OUTSB, decoded_ids.X86_INS_OUTSW, decoded_ids.X86_INS_OUTSD,
    decoded_ids.X86_INS_RDPMC, decoded_ids.X86_INS_XSETBV,
})
"""Additional port/control inputs; shared machine-input admission runs first.

Clock, entropy and CPU-feature instructions belong to replay_machine_inputs,
consumed by _instruction_scope. This owner adds only its explicit PE process
port/performance/control boundaries instead of duplicating that common list.
"""


@dataclass(frozen=True, slots=True)
class PeProgramObservation:
    """One complete named memory output independent of physical correspondence."""

    name: str
    region: MemoryRange

    def __post_init__(self) -> None:
        """Require a positive flat32 range and nonempty output identity."""
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("PE program output requires a name")
        if not isinstance(self.region, MemoryRange):
            raise ValueError("PE program output requires a typed MemoryRange")
        if (type(self.region.address) is not int or type(self.region.size) is not int
                or self.region.address < 0 or self.region.size <= 0
                or self.region.address + self.region.size > 2**32):
            raise ValueError("invalid PE program output range")


@dataclass(slots=True)
class _State:
    """One guest's captured process events and finite execution state."""

    boot: PeProgramBoot
    decoder: capstone.Cs
    grants: dict[int, DeclaredAccess]
    status: ProgramStatus = ProgramStatus.BUDGET_EXHAUSTED
    exit_code: int | None = None
    instructions: int = 0
    detail: str = ""
    writes: set[int] = field(default_factory=set)
    events: list[ProgramEvent] = field(default_factory=list)


def _contains_bytes(boot: PeProgramBoot, address: int, size: int) -> bool:
    """Padding cannot supply bytes outside an image or exact declared allocation."""
    return any(start <= address and address + size <= start + len(data) for start, data in boot.image.chunks) or any(
        memory.address <= address and address + size <= memory.address + len(memory.data)
        for memory in boot.environment.memory
    )


def _access_allowed(state: _State, address: int, size: int, access: DeclaredAccess) -> bool:
    """Require exact initialized bytes and the existing page permission authority."""
    if size <= 0 or address < 0 or address + size > 2**32 or not _contains_bytes(state.boot, address, size):
        return False
    pages = range(address // PAGE_SIZE * PAGE_SIZE, (address + size - 1) // PAGE_SIZE * PAGE_SIZE + PAGE_SIZE, PAGE_SIZE)
    return all(state.grants.get(page, DeclaredAccess.NONE) & access == access for page in pages)


def _stop(guest: Uc, state: _State, kind: ProgramEventKind, address: int, data: bytes) -> None:
    """Stop with explicit missing environment evidence, never a complete outcome."""
    state.status = ProgramStatus.UNSUPPORTED
    state.detail = kind.value
    state.events.append(ProgramEvent(kind, address, data))
    guest.emu_stop()


def _terminate(guest: Uc, state: _State, address: int) -> None:
    """Consume the explicit stdcall-shaped exit argument without returning."""
    stack = int(guest.reg_read(REGISTER_IDS["esp"]))
    if not _access_allowed(state, stack + 4, 4, DeclaredAccess.READ):
        _stop(guest, state, ProgramEventKind.UNDECLARED_ACCESS, stack + 4, b"exit_argument")
        return
    state.exit_code = int.from_bytes(guest.mem_read(stack + 4, 4), "little")
    state.status = ProgramStatus.TERMINATED
    state.events.append(ProgramEvent(ProgramEventKind.PE_EXIT, address, state.exit_code.to_bytes(4, "little")))
    guest.emu_stop()


def _instruction(guest: Uc, address: int, size: int, state: _State) -> None:
    """Admit only modeled integer instructions and the explicitly declared gateway."""
    if address == state.boot.environment.exit_address:
        _terminate(guest, state, address)
        return
    state.instructions += 1
    if not any(region.contains(address, size) for region in state.boot.image.executable):
        _stop(guest, state, ProgramEventKind.CONTROL_ESCAPE, address, b"")
        return
    if not _access_allowed(state, address, size, DeclaredAccess.EXECUTE):
        _stop(guest, state, ProgramEventKind.UNDECLARED_ACCESS, address, b"fetch")
        return
    raw = bytes(guest.mem_read(address, size))
    decoded = next(state.decoder.disasm(raw, address), None)
    reason = _instruction_scope(decoded)
    if reason is not None or decoded is None or decoded.size != size:
        _stop(guest, state, ProgramEventKind.UNSUPPORTED_INSTRUCTION, address, raw)
        return
    if decoded.id in UNDECLARED_EXTERNAL_IDS:
        _stop(guest, state, ProgramEventKind.UNSUPPORTED_INSTRUCTION, address, raw)
        return
    _, written = decoded.regs_access()
    segment_registers = {decoded_ids.X86_REG_CS, decoded_ids.X86_REG_SS, decoded_ids.X86_REG_DS,
                         decoded_ids.X86_REG_ES, decoded_ids.X86_REG_FS, decoded_ids.X86_REG_GS}
    if segment_registers.intersection(written):
        _stop(guest, state, ProgramEventKind.UNSUPPORTED_INSTRUCTION, address, raw)
        return
    if any(operand.type == decoded_ids.X86_OP_MEM and operand.mem.segment in
           (decoded_ids.X86_REG_FS, decoded_ids.X86_REG_GS) for operand in decoded.operands):
        _stop(guest, state, ProgramEventKind.UNSUPPORTED_INSTRUCTION, address, raw)


def _memory(guest: Uc, access: int, address: int, size: int, _value: int, state: _State) -> None:
    """Observe permitted writes and reject exact-allocation gaps or code mutation."""
    permission = DeclaredAccess.WRITE if access == unicorn.UC_MEM_WRITE else DeclaredAccess.READ
    if not _access_allowed(state, address, size, permission):
        _stop(guest, state, ProgramEventKind.UNDECLARED_ACCESS, address, b"")
        return
    if access == unicorn.UC_MEM_WRITE:
        if any(region.address < address + size and address < region.address + region.size
               for region in state.boot.image.executable):
            _stop(guest, state, ProgramEventKind.CODE_WRITE, address, b"")
            return
        state.writes.update(range(address, address + size))


def _fault(guest: Uc, vector: int, state: _State) -> None:
    """Capture CPU exceptions separately from unsupported software services."""
    state.status = ProgramStatus.FAULTED
    state.events.append(ProgramEvent(ProgramEventKind.CPU_FAULT,
                                    int(guest.reg_read(OBSERVABLE_REGISTER_IDS["eip"])), vector.to_bytes(4, "little")))
    guest.emu_stop()


def _invalid(guest: Uc, _access: int, address: int, _size: int, _value: int, state: _State) -> bool:
    """Absent or denied memory is explicit environment incompleteness."""
    _stop(guest, state, ProgramEventKind.UNDECLARED_ACCESS, address, b"")
    return False


def _initialize(boot: PeProgramBoot) -> tuple[Uc, tuple[PageGrant, ...]]:
    """Seed exact declared bytes; install neither a caller frame nor stack defaults."""
    declared = (
        *boot.image.declared,
        *(DeclaredRegion(address, len(data), DeclaredAccess.NONE, MappingOrigin.UNSUPPORTED)
          for address, data in boot.image.chunks),
        *boot.environment.declared_regions(),
        DeclaredRegion(boot.environment.exit_address, 1, DeclaredAccess.EXECUTE, MappingOrigin.PROCESS_SERVICE),
    )
    grants = plan_page_grants(declared)
    gateway = boot.environment.exit_address // PAGE_SIZE * PAGE_SIZE
    if not any(grant.address == gateway and grant.access & DeclaredAccess.EXECUTE for grant in grants):
        raise ValueError("declared exit gateway has no executable page grant")
    guest = make_guest(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    for grant in grants:
        guest.mem_map(grant.address, PAGE_SIZE)
    for address, data in boot.image.chunks:
        guest.mem_write(address, data)
    for memory in boot.environment.memory:
        guest.mem_write(memory.address, memory.data)
    # One inert byte makes the declared service address fetchable. The hook
    # terminates before execution; it is never a guessed API implementation.
    guest.mem_write(boot.environment.exit_address, b"\x90")
    for grant in grants:
        guest.mem_protect(grant.address, PAGE_SIZE, int(grant.access))
    for name, value in boot.environment.registers:
        guest.reg_write(REGISTER_IDS[name], value)
    for name in ("cs", "ss", "ds", "es", "fs", "gs"):
        # Loading a null SS selector itself faults in protected mode. Admit
        # only the fresh backend's explicitly checked flat bootstrap state;
        # do not perform a segment-load instruction or invent a guest GDT.
        if int(guest.reg_read(OBSERVABLE_REGISTER_IDS[name])) != 0:
            raise ValueError("PE backend does not provide the required flat zero-selector bootstrap")
    return guest, grants


def validate_pe_observations(boot: PeProgramBoot, observations: tuple[PeProgramObservation, ...]) -> None:
    """Admit the complete bounded output denominator before any guest allocation."""
    if len(observations) > MAX_PAGE_CLAIMS or sum(item.region.size for item in observations) > MAX_MAPPED_BYTES:
        raise ValueError("PE program observation budget exceeded")
    names = [item.name for item in observations]
    if len(names) != len(set(names)):
        raise ValueError("PE program observation names must be unique")
    if any(not _contains_bytes(boot, item.region.address, item.region.size) for item in observations):
        raise ValueError("PE program observations require exact declared initialized bytes")


def replay_pe_program(
    boot: PeProgramBoot, *, observations: tuple[PeProgramObservation, ...] = (), instruction_limit: int = 100000,
) -> ProgramResult:
    """Execute one declared PE process state; equal replay remains concrete evidence."""
    if type(instruction_limit) is not int or instruction_limit <= 0:
        raise ValueError("PE program instruction limit must be a positive integer")
    validate_pe_observations(boot, observations)
    identity = hashlib.sha256(
        b"unicorn_pe32_flat_zero_selectors_stdcall_exit_u32_v1" + _environment_identity(boot.environment)
    ).hexdigest()
    try:
        guest, grants = _initialize(boot)
    except (UcError, EngineArenaRefusal) as error:
        return ProgramResult(
            ProgramStatus.UNAVAILABLE, None, (), (), tuple((item.name, item.region.size) for item in observations),
            (), (), 0, boot.boot_sha256, identity, f"backend_initialization_failed:{error}",
        )
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    state = _State(boot, decoder, {grant.address: grant.access for grant in grants})
    guest.hook_add(unicorn.UC_HOOK_CODE, _instruction, user_data=state)
    guest.hook_add(unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE, _memory, user_data=state)
    guest.hook_add(unicorn.UC_HOOK_INTR, _fault, user_data=state)
    guest.hook_add(unicorn.UC_HOOK_MEM_INVALID, _invalid, user_data=state)
    try:
        guest.emu_start(boot.entry, 0, count=instruction_limit)
    except UcError as error:
        if state.status is ProgramStatus.BUDGET_EXHAUSTED:
            state.status = ProgramStatus.UNSUPPORTED
            state.detail = f"unicorn_error:{error.errno}"
    result = ProgramResult(
        state.status, state.exit_code,
        tuple((name, int(guest.reg_read(identity))) for name, identity in OBSERVABLE_REGISTER_IDS.items()),
        tuple((item.name, bytes(guest.mem_read(item.region.address, item.region.size))) for item in observations),
        tuple((item.name, item.region.size) for item in observations), _written_bytes(guest, state.writes),
        tuple(state.events), state.instructions, boot.boot_sha256, identity, state.detail,
    )
    del guest
    gc.collect()
    return result
