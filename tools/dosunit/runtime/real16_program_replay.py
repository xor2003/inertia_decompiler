"""Independent execution of initialized MZ programs under explicit DOS scope.

Layer: dosunit concrete execution.
Responsibility: run binary-derived program entry/stack with a fully declared
initial allocation, intercept DOS process termination, and refuse every other
external service unless explicit input/output policies enable bounded file
read/seek, output streams, version/device-information queries, live IVT
operations or a declared final-block allocator.
No caller frame, return trap, or proof promotion is installed.
"""

from __future__ import annotations

import gc
import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from tools.dosunit.contracts.binary_environment import decoded_port_effects
from tools.dosunit.contracts.model import canonical_json_bytes
from tools.dosunit.reporting.real16_program_input_manifest import input_policy_document
from tools.dosunit.runtime.real16_guest import _high_ids, _segment_ids
from tools.dosunit.runtime.real16_program_boot import ProgramBoot
from tools.dosunit.runtime.real16_program_device_info import (
    DeviceInfoRefusal,
    device_info_event_data,
    device_info_policy_document,
    program_device_query,
)
from tools.dosunit.runtime.real16_program_file_receipts import FileOperation, FileReceipt
from tools.dosunit.runtime.real16_program_input import (
    InputRefused,
    InputRuntime,
    SeekOrigin,
    program_input_read,
    program_input_runtime,
    program_input_seek,
)
from tools.dosunit.runtime.real16_program_interrupts import (
    INTERRUPT_ENTRY_MODEL,
    VIDEO_INTERRUPT_ENTRY_MODEL,
    InterruptFrameRefusal,
    program_interrupt_frame,
)
from tools.dosunit.runtime.real16_program_memory import ProgramMemoryLayout, memory_regions_document
from tools.dosunit.runtime.real16_program_model import (
    ProgramEvent,
    ProgramEventKind,
    ProgramObservation,
    ProgramResult,
    ProgramStatus,
)
from tools.dosunit.runtime.real16_program_output import OutputRefused, program_output_call
from tools.dosunit.runtime.real16_program_resize import (
    MCB_BYTES,
    ResizeRefused,
    program_resize_call,
    resize_event_data,
    resize_policy_document,
)
from tools.dosunit.runtime.real16_program_rom import readable_memory_contains, rom_document
from tools.dosunit.runtime.real16_program_vectors import (
    DOS_VECTOR,
    DOS_VECTOR_RANGE,
    VECTOR_BYTES,
    VectorRefusal,
    vector_bytes,
    vector_event_data,
    vector_policy_document,
)
from tools.dosunit.runtime.real16_program_version import (
    VersionRefused,
    program_version_query,
    version_event_data,
    version_policy_document,
)
from tools.dosunit.runtime.real16_program_video import (
    VIDEO_FUNCTION,
    VIDEO_VECTOR,
    video_policy_document,
    video_query_event_data,
)
from tools.dosunit.runtime.real16_program_video_boundary import (
    VIDEO_VECTOR_RANGE,
    VideoDispatchRefusal,
    video_dispatch_refusal,
    video_entry_dispatch_refusal,
)
from tools.dosunit.runtime.real16_program_video_state import (
    VIDEO_STATE_FUNCTION,
    VIDEO_STATE_SELECTOR,
    video_state_document,
    video_state_event_data,
)
from tools.dosunit.runtime.real16_replay import (
    _classified,
    _coalesced_writes,
    _ReadbackGap,
    _result_registers,
    _snapshot_gap_detail,
    _try_read_span,
    backend_available,
)
from tools.dosunit.runtime.real16_replay_model import PAGE_SIZE, LinearRange, SegOffset
from tools.dosunit.runtime.real16_video_state_boundary import (
    VIDEO_BDA_MODE,
    VIDEO_BDA_ROWS,
    VIDEO_STATE_BYTES,
    video_state_buffer_refusal,
)
from tools.dosunit.runtime.unicorn_engine import make_guest

if TYPE_CHECKING:
    import capstone
    import unicorn
    from capstone import x86_const as x86_ids
    from unicorn import x86_const as registers
    from unicorn.unicorn_py3.unicorn import Uc, UcError
else:
    try:
        import capstone
        import unicorn
        from capstone import x86_const as x86_ids
        from unicorn import x86_const as registers
        from unicorn.unicorn_py3.unicorn import Uc, UcError
    except ImportError:
        capstone = None  # type: ignore[assignment]
        unicorn = None  # type: ignore[assignment]
        x86_ids = None  # type: ignore[assignment]
        registers = None  # type: ignore[assignment]
        Uc = None  # type: ignore[assignment, misc]
        UcError = RuntimeError  # type: ignore[assignment, misc]


@dataclass(slots=True)
class _ProgramState:
    """Mutable hook state owned by one fresh program execution."""

    boot: ProgramBoot
    decoder: capstone.Cs
    memory: ProgramMemoryLayout
    status: ProgramStatus = ProgramStatus.BUDGET_EXHAUSTED
    exit_code: int | None = None
    instructions: int = 0
    output_bytes: int = 0
    detail: str = ""
    writes: set[int] = field(default_factory=set)
    events: list[ProgramEvent] = field(default_factory=list)
    input_runtime: InputRuntime | None = None
    file_receipts: list[FileReceipt] = field(default_factory=list)
    interrupt_frame: LinearRange | None = None


def _stop(guest: Uc, state: _ProgramState, kind: ProgramEventKind, address: int, data: bytes) -> None:
    """Retain a typed refusal before stopping execution."""
    state.status = ProgramStatus.UNSUPPORTED
    state.detail = kind.value
    state.events.append(ProgramEvent(kind, address, data))
    guest.emu_stop()


def _code(guest: Uc, address: int, size: int, state: _ProgramState) -> None:
    """Classify fetched instructions under the explicitly declared service scope."""
    state.instructions += 1
    if not any(region.contains(address, size) for region in state.boot.image.code_ranges):
        _stop(guest, state, ProgramEventKind.CONTROL_ESCAPE, address, b"")
        return
    raw = bytes(guest.mem_read(address, size))
    port_effects = decoded_port_effects(raw, address, mode_bits=16)
    if port_effects is None or port_effects:
        _stop(guest, state, ProgramEventKind.UNSUPPORTED_INSTRUCTION, address, raw)
        return
    decoded = next(state.decoder.disasm(raw, address), None)
    if decoded is not None and decoded.size == size and decoded.id == x86_ids.X86_INS_INT:
        vector = decoded.operands[0].imm
        ax = int(guest.reg_read(registers.UC_X86_REG_AX))
        if _interrupt_service(guest, state, address, raw, vector, ax):
            return
    admitted, _, raw, _ = _classified(guest, state.decoder, address, size)
    if not admitted:
        _stop(guest, state, ProgramEventKind.UNSUPPORTED_INSTRUCTION, address, raw)


def _interrupt_service(guest: Uc, state: _ProgramState, address: int, raw: bytes, vector: int, ax: int) -> bool:
    """Consume only an explicitly declared DOS or BIOS service instruction."""
    if vector == 0x21 and _service_enabled(state, ax >> 8):
        if _dos_vector_intact(guest, state, address) and _service_frame(guest, state, address, raw):
            _dispatch_service(guest, state, address, len(raw), ax)
        return True
    if vector == VIDEO_VECTOR and ax >> 8 == VIDEO_FUNCTION and state.boot.environment.video_policy is not None:
        _video_query(guest, state, address, raw)
        return True
    if vector == VIDEO_VECTOR and ax >> 8 == VIDEO_STATE_FUNCTION and state.boot.environment.video_state_policy is not None:
        _video_state(guest, state, address, raw)
        return True
    return False


def _video_query(guest: Uc, state: _ProgramState, address: int, raw: bytes) -> None:
    """Apply a declared static BIOS answer after checking vector and frame effects."""
    environment = state.boot.environment
    policy = environment.video_policy
    assert policy is not None
    failure = video_dispatch_refusal(
        policy, bytes(guest.mem_read(VIDEO_VECTOR_RANGE.address, VIDEO_VECTOR_RANGE.size)),
        arena_start=environment.psp_segment * 16, arena_size=len(environment.allocation),
    )
    if failure is not None:
        _stop(guest, state, ProgramEventKind.UNSUPPORTED_INSTRUCTION, address, failure.value.encode())
        return
    if not _service_frame(guest, state, address, raw, vector=VIDEO_VECTOR):
        return
    eax = int(guest.reg_read(registers.UC_X86_REG_EAX))
    ebx = int(guest.reg_read(registers.UC_X86_REG_EBX))
    guest.reg_write(registers.UC_X86_REG_EAX, (eax & 0xFFFF0000) | (policy.columns << 8) | policy.mode)
    guest.reg_write(registers.UC_X86_REG_EBX, (ebx & 0xFFFF00FF) | (policy.page << 8))
    state.events.append(ProgramEvent(ProgramEventKind.BIOS_VIDEO_QUERY, address, video_query_event_data(policy)))
    guest.reg_write(registers.UC_X86_REG_IP, int(guest.reg_read(registers.UC_X86_REG_IP)) + len(raw))


def _video_state(guest: Uc, state: _ProgramState, address: int, raw: bytes) -> None:
    """Read live declared BIOS data and emit one guarded 64-byte state table."""
    environment = state.boot.environment
    policy = environment.video_state_policy
    assert policy is not None
    if int(guest.reg_read(registers.UC_X86_REG_BX)) != VIDEO_STATE_SELECTOR:
        _stop(guest, state, ProgramEventKind.UNSUPPORTED_INSTRUCTION, address, b"video_state_selector")
        return
    failure = video_entry_dispatch_refusal(
        policy.entry, bytes(guest.mem_read(VIDEO_VECTOR_RANGE.address, VIDEO_VECTOR_RANGE.size)),
        arena_start=environment.psp_segment * 16, arena_size=len(environment.allocation),
    )
    if failure is not None:
        _stop(guest, state, ProgramEventKind.UNSUPPORTED_INSTRUCTION, address, failure.value.encode())
        return
    if not _service_frame(guest, state, address, raw, vector=VIDEO_VECTOR):
        return
    assert state.interrupt_frame is not None
    destination = SegOffset(int(guest.reg_read(registers.UC_X86_REG_ES)),
                            int(guest.reg_read(registers.UC_X86_REG_DI)))
    boundary = video_state_buffer_refusal(destination, memory=state.memory,
                                         interrupt_frame=state.interrupt_frame,
                                         code_ranges=state.boot.image.code_ranges)
    if boundary is not None:
        _stop(guest, state, ProgramEventKind.UNSUPPORTED_INSTRUCTION, address, boundary.value.encode())
        return
    data = video_state_event_data(
        policy, bytes(guest.mem_read(VIDEO_BDA_MODE.address, VIDEO_BDA_MODE.size)),
        bytes(guest.mem_read(VIDEO_BDA_ROWS.address, VIDEO_BDA_ROWS.size)),
    )
    guest.mem_write(destination.linear(), data[-VIDEO_STATE_BYTES:])
    state.writes.update(range(destination.linear(), destination.linear() + VIDEO_STATE_BYTES))
    eax = int(guest.reg_read(registers.UC_X86_REG_EAX))
    guest.reg_write(registers.UC_X86_REG_EAX, (eax & 0xFFFFFF00) | VIDEO_STATE_FUNCTION)
    state.events.append(ProgramEvent(ProgramEventKind.BIOS_VIDEO_STATE, address, data))
    guest.reg_write(registers.UC_X86_REG_IP, int(guest.reg_read(registers.UC_X86_REG_IP)) + len(raw))


def _service_enabled(state: _ProgramState, function: int) -> bool:
    """Identify explicitly modeled services before applying their INT entry."""
    env = state.boot.environment
    enabled = {0x3F: env.input_policy is not None, 0x42: env.input_policy is not None,
               0x40: env.output_policy is not None, 0x30: env.version_policy is not None,
               0x4A: env.resize_policy is not None, 0x4C: True,
               0x25: env.vector_policy is not None, 0x35: env.vector_policy is not None,
               0x44: env.device_info_policy is not None}
    return enabled.get(function, False)


def _dispatch_service(guest: Uc, state: _ProgramState, address: int, size: int, ax: int) -> None:
    """Run one declared DOS response after its interrupt entry was admitted."""
    function = ax >> 8
    if function in (0x3F, 0x42):
        _input(guest, state, address, size, ax)
    elif function == 0x40:
        _output(guest, state, address, size)
    elif function == 0x30:
        _version(guest, state, address, size, ax)
    elif function == 0x4A:
        _resize(guest, state, address, size, ax)
    elif function in (0x25, 0x35):
        _vector(guest, state, address, size, ax)
    elif function == 0x44:
        _device_info(guest, state, address, size, ax)
    else:
        assert function == 0x4C
        state.status = ProgramStatus.TERMINATED
        state.exit_code = ax & 0xFF
        state.events.append(ProgramEvent(ProgramEventKind.DOS_EXIT, address, bytes((0x21, 0x4C, ax & 0xFF))))
        guest.emu_stop()


def _dos_vector_intact(guest: Uc, state: _ProgramState, address: int) -> bool:
    """Require the declared external DOS entry before intercepting any service."""
    policy = state.boot.environment.vector_policy
    if policy is None:
        if any(region.overlaps(DOS_VECTOR_RANGE.address, VECTOR_BYTES) for region in state.memory.ranges):
            _stop(guest, state, ProgramEventKind.UNSUPPORTED_INSTRUCTION, address,
                  VectorRefusal.POLICY_REQUIRED.value.encode())
            return False
        return True
    environment = state.boot.environment
    arena_start = environment.psp_segment * 16
    # A caller-supplied code-range projection cannot turn program RAM into an
    # external DOS implementation, including BSS or excluded loaded bytes.
    if arena_start <= policy.dos_entry.linear() < arena_start + len(environment.allocation):
        reason = VectorRefusal.OWNED_HANDLER
    elif bytes(guest.mem_read(DOS_VECTOR_RANGE.address, VECTOR_BYTES)) != vector_bytes(policy.dos_entry):
        reason = VectorRefusal.DOS_REDIRECTED
    else:
        return True
    _stop(guest, state, ProgramEventKind.UNSUPPORTED_INSTRUCTION, address, reason.value.encode())
    return False


def _service_frame(guest: Uc, state: _ProgramState, address: int, raw: bytes, *, vector: int = 0x21) -> bool:
    """Apply architectural stack bytes before any summarized service reads them.

    A returned service leaves SP unchanged; its memory writes persist. At exit
    registers remain callsite diagnostics, while named memory observes the
    interrupt entry. Refused services cannot yield a complete execution result.
    """
    frame = program_interrupt_frame(
        instruction=raw,
        instruction_pointer=SegOffset(int(guest.reg_read(registers.UC_X86_REG_CS)),
                                     int(guest.reg_read(registers.UC_X86_REG_IP))),
        stack=SegOffset(int(guest.reg_read(registers.UC_X86_REG_SS)),
                       int(guest.reg_read(registers.UC_X86_REG_SP))),
        flags=int(guest.reg_read(registers.UC_X86_REG_EFLAGS)),
        memory=state.memory, code_ranges=state.boot.image.code_ranges, vector=vector,
    )
    if isinstance(frame, InterruptFrameRefusal):
        kinds = {InterruptFrameRefusal.UNDECLARED: ProgramEventKind.UNDECLARED_ACCESS,
                 InterruptFrameRefusal.CODE_WRITE: ProgramEventKind.CODE_WRITE,
                 InterruptFrameRefusal.WRAP: ProgramEventKind.CONTROL_ESCAPE,
                 InterruptFrameRefusal.FALLTHROUGH_WRAP: ProgramEventKind.CONTROL_ESCAPE}
        _stop(guest, state, kinds.get(frame, ProgramEventKind.UNSUPPORTED_INSTRUCTION),
              address, frame.value.encode())
        return False
    if state.boot.environment.vector_policy is not None and DOS_VECTOR_RANGE.overlaps(frame.address, len(frame.data)):
        _stop(guest, state, ProgramEventKind.UNSUPPORTED_INSTRUCTION, address, VectorRefusal.FRAME_ALIAS.value.encode())
        return False
    video_enabled = (state.boot.environment.video_policy is not None
                     or state.boot.environment.video_state_policy is not None)
    if video_enabled and VIDEO_VECTOR_RANGE.overlaps(frame.address, len(frame.data)):
        _stop(guest, state, ProgramEventKind.UNSUPPORTED_INSTRUCTION, address,
              VideoDispatchRefusal.FRAME_ALIAS.value.encode())
        return False
    guest.mem_write(frame.address, frame.data)
    state.writes.update(range(frame.address, frame.address + len(frame.data)))
    state.interrupt_frame = LinearRange(frame.address, len(frame.data))
    return True


def _service_write(guest: Uc, state: _ProgramState, address: int, size: int) -> bool:
    """Keep summarized writes disjoint from fetched code and their live frame."""
    if not size:
        return True
    if any(region.overlaps(address, size) for region in state.boot.image.code_ranges):
        _stop(guest, state, ProgramEventKind.CODE_WRITE, address, b"")
        return False
    assert state.interrupt_frame is not None
    if state.interrupt_frame.overlaps(address, size):
        _stop(guest, state, ProgramEventKind.UNSUPPORTED_INSTRUCTION, address,
              InterruptFrameRefusal.SERVICE_WRITE.value.encode())
        return False
    return True


def _output(guest: Uc, state: _ProgramState, address: int, size: int) -> None:
    """Apply declared successful stream writes, preserving all unowned state."""
    policy = state.boot.environment.output_policy
    assert policy is not None
    result = program_output_call(
        policy, handle=int(guest.reg_read(registers.UC_X86_REG_BX)),
        segment=int(guest.reg_read(registers.UC_X86_REG_DS)),
        offset=int(guest.reg_read(registers.UC_X86_REG_DX)),
        count=int(guest.reg_read(registers.UC_X86_REG_CX)), allocation=state.memory,
        aggregate_remaining=policy.aggregate_bytes - state.output_bytes,
        read=lambda start, count: bytes(guest.mem_read(start, count)),
        rom=state.boot.environment.rom,
    )
    if isinstance(result, OutputRefused):
        _stop(guest, state, ProgramEventKind.UNSUPPORTED_INSTRUCTION, address, result.refusal.value.encode())
        return
    ip = int(guest.reg_read(registers.UC_X86_REG_IP))
    if ip + size > 0xFFFF:
        _stop(guest, state, ProgramEventKind.CONTROL_ESCAPE, address, b"service_fallthrough_wrap")
        return
    state.output_bytes += len(result.payload)
    state.events.append(ProgramEvent(ProgramEventKind.OUTPUT_WRITE, address, bytes((result.handle,)) + result.payload))
    guest.reg_write(registers.UC_X86_REG_AX, result.ax)
    guest.reg_write(registers.UC_X86_REG_EFLAGS, int(guest.reg_read(registers.UC_X86_REG_EFLAGS)) & ~1)
    guest.reg_write(registers.UC_X86_REG_IP, ip + size)


def _input(guest: Uc, state: _ProgramState, address: int, size: int, ax: int) -> None:
    """Commit a declared read/seek only after exact guest-effect admission."""
    policy = state.boot.environment.input_policy
    runtime = state.input_runtime
    assert policy is not None and runtime is not None
    ip = int(guest.reg_read(registers.UC_X86_REG_IP))
    if ip + size > 0xFFFF:
        _stop(guest, state, ProgramEventKind.CONTROL_ESCAPE, address, b"service_fallthrough_wrap")
        return
    handle = int(guest.reg_read(registers.UC_X86_REG_BX))
    before = runtime.cursors.get(handle)
    # Pure service mutation is staged until code-write and guest bounds pass.
    staged = InputRuntime(dict(runtime.cursors), runtime.served)
    cx, dx = (int(guest.reg_read(identity)) for identity in (registers.UC_X86_REG_CX, registers.UC_X86_REG_DX))
    if ax >> 8 == 0x3F:
        result = program_input_read(policy, staged, handle=handle,
                                    segment=int(guest.reg_read(registers.UC_X86_REG_DS)),
                                    offset=dx, count=cx, allocation=state.memory)
        if isinstance(result, InputRefused):
            _stop(guest, state, ProgramEventKind.UNSUPPORTED_INSTRUCTION, address, result.refusal.value.encode())
            return
        destination = result.destination.linear()
        if not _service_write(guest, state, destination, len(result.payload)):
            return
        assert before is not None
        receipt = FileReceipt(FileOperation.READ, handle, before, result.next_cursor, result.payload)
        if result.payload:
            guest.mem_write(destination, result.payload)
            state.writes.update(range(destination, destination + len(result.payload)))
        returned_ax = result.ax
    else:
        origins = (SeekOrigin.BEGIN, SeekOrigin.CURRENT, SeekOrigin.END)
        mode = ax & 0xFF
        if mode >= len(origins):
            _stop(guest, state, ProgramEventKind.UNSUPPORTED_INSTRUCTION, address, b"unsupported_seek_origin")
            return
        unsigned_distance = (cx << 16) | dx
        distance = unsigned_distance - 0x100000000 if unsigned_distance & 0x80000000 else unsigned_distance
        seek = program_input_seek(policy, staged, handle=handle, origin=origins[mode], distance=distance)
        if isinstance(seek, InputRefused):
            _stop(guest, state, ProgramEventKind.UNSUPPORTED_INSTRUCTION, address, seek.refusal.value.encode())
            return
        assert before is not None
        receipt = FileReceipt(FileOperation.SEEK, handle, before, seek.next_cursor)
        returned_ax = seek.ax
        guest.reg_write(registers.UC_X86_REG_DX, seek.dx)
    state.input_runtime = staged
    state.file_receipts.append(receipt)
    guest.reg_write(registers.UC_X86_REG_AX, returned_ax)
    guest.reg_write(registers.UC_X86_REG_EFLAGS, int(guest.reg_read(registers.UC_X86_REG_EFLAGS)) & ~1)
    guest.reg_write(registers.UC_X86_REG_IP, ip + size)


def _device_info(guest: Uc, state: _ProgramState, address: int, size: int, ax: int) -> None:
    """Apply one declared DX/CF response after checked INT entry and fallthrough."""
    policy = state.boot.environment.device_info_policy
    assert policy is not None
    ip = int(guest.reg_read(registers.UC_X86_REG_IP))
    if ip + size > 0xFFFF:
        _stop(guest, state, ProgramEventKind.CONTROL_ESCAPE, address, b"service_fallthrough_wrap")
        return
    answer = program_device_query(policy, selector=ax & 0xFF, handle=int(guest.reg_read(registers.UC_X86_REG_BX)))
    if isinstance(answer, DeviceInfoRefusal):
        _stop(guest, state, ProgramEventKind.UNSUPPORTED_INSTRUCTION, address, answer.value.encode())
        return
    state.events.append(ProgramEvent(ProgramEventKind.DOS_DEVICE_INFO, address, device_info_event_data(answer)))
    edx = int(guest.reg_read(registers.UC_X86_REG_EDX))
    flags = int(guest.reg_read(registers.UC_X86_REG_EFLAGS))
    guest.reg_write(registers.UC_X86_REG_EDX, (edx & 0xFFFF0000) | answer.information)
    guest.reg_write(registers.UC_X86_REG_EFLAGS, flags & ~1)
    guest.reg_write(registers.UC_X86_REG_IP, ip + size)


def _version(guest: Uc, state: _ProgramState, address: int, size: int, ax: int) -> None:
    """Commit the declared version response only after the wrap and admission checks.

    The bounded service updates only the documented AX/BX/CX low halves and
    the checked fallthrough IP; the upper halves of EAX/EBX/ECX, all flags,
    every segment are preserved. Only the common INT entry writes stack memory.
    The answered query is a
    report event so no declared environment effect is silent.
    """
    policy = state.boot.environment.version_policy
    assert policy is not None
    ip = int(guest.reg_read(registers.UC_X86_REG_IP))
    if ip + size > 0xFFFF:
        _stop(guest, state, ProgramEventKind.CONTROL_ESCAPE, address, b"service_fallthrough_wrap")
        return
    result = program_version_query(policy, selector=ax & 0xFF)
    if isinstance(result, VersionRefused):
        _stop(guest, state, ProgramEventKind.UNSUPPORTED_INSTRUCTION, address, result.refusal.value.encode())
        return
    state.events.append(ProgramEvent(ProgramEventKind.DOS_VERSION, address, version_event_data(policy)))
    eax = int(guest.reg_read(registers.UC_X86_REG_EAX))
    ebx = int(guest.reg_read(registers.UC_X86_REG_EBX))
    ecx = int(guest.reg_read(registers.UC_X86_REG_ECX))
    guest.reg_write(registers.UC_X86_REG_EAX, (eax & 0xFFFF0000) | result.ax)
    guest.reg_write(registers.UC_X86_REG_EBX, (ebx & 0xFFFF0000) | result.bx)
    guest.reg_write(registers.UC_X86_REG_ECX, (ecx & 0xFFFF0000) | result.cx)
    guest.reg_write(registers.UC_X86_REG_IP, ip + size)


def _resize(guest: Uc, state: _ProgramState, address: int, size: int, ax: int) -> None:
    """Commit a checked native tail resize with its complete metadata receipt."""
    policy = state.boot.environment.resize_policy
    assert policy is not None
    ip = int(guest.reg_read(registers.UC_X86_REG_IP))
    if ip + size > 0xFFFF:
        _stop(guest, state, ProgramEventKind.CONTROL_ESCAPE, address, b"service_fallthrough_wrap")
        return
    paragraphs = int(guest.reg_read(registers.UC_X86_REG_BX))
    before = bytes(guest.mem_read(policy.metadata_address, MCB_BYTES))
    result = program_resize_call(policy, segment=int(guest.reg_read(registers.UC_X86_REG_ES)),
                                 paragraphs=paragraphs, ax=ax, metadata=before)
    if isinstance(result, ResizeRefused):
        _stop(guest, state, ProgramEventKind.UNSUPPORTED_INSTRUCTION, address, result.reason.value.encode())
        return
    if result.metadata != before:
        if not _service_write(guest, state, policy.metadata_address + 3, 2):
            return
        guest.mem_write(policy.metadata_address + 3, result.metadata[3:5])
        state.writes.update(range(policy.metadata_address + 3, policy.metadata_address + 5))
    state.events.append(ProgramEvent(ProgramEventKind.DOS_RESIZE, address,
                                     resize_event_data(policy, paragraphs, ax, before, result)))
    eax, ebx = (int(guest.reg_read(identity)) for identity in (registers.UC_X86_REG_EAX, registers.UC_X86_REG_EBX))
    guest.reg_write(registers.UC_X86_REG_EAX, (eax & 0xFFFF0000) | result.ax)
    guest.reg_write(registers.UC_X86_REG_EBX, (ebx & 0xFFFF0000) | result.bx)
    flags = int(guest.reg_read(registers.UC_X86_REG_EFLAGS))
    guest.reg_write(registers.UC_X86_REG_EFLAGS, (flags & ~1) | int(result.carry))
    guest.reg_write(registers.UC_X86_REG_IP, ip + size)


def _vector(guest: Uc, state: _ProgramState, address: int, size: int, ax: int) -> None:
    """Read or update a live IVT slot with an exact retained before/after receipt."""
    function, number = ax >> 8, ax & 0xFF
    slot = number * VECTOR_BYTES
    before = bytes(guest.mem_read(slot, VECTOR_BYTES))
    after = before
    if function == 0x25:
        target = SegOffset(int(guest.reg_read(registers.UC_X86_REG_DS)),
                           int(guest.reg_read(registers.UC_X86_REG_DX)))
        after = vector_bytes(target)
        if number == DOS_VECTOR and after != before:
            _stop(guest, state, ProgramEventKind.UNSUPPORTED_INSTRUCTION, address, VectorRefusal.DOS_UPDATE.value.encode())
            return
        if not _service_write(guest, state, slot, VECTOR_BYTES):
            return
        guest.mem_write(slot, after)
        state.writes.update(range(slot, slot + VECTOR_BYTES))
    else:
        assert function == 0x35
        ebx = int(guest.reg_read(registers.UC_X86_REG_EBX))
        guest.reg_write(registers.UC_X86_REG_EBX, (ebx & 0xFFFF0000) | int.from_bytes(before[:2], "little"))
        guest.reg_write(registers.UC_X86_REG_ES, int.from_bytes(before[2:], "little"))
    state.events.append(ProgramEvent(ProgramEventKind.DOS_VECTOR, address,
                                     vector_event_data(function, number, before, after)))
    guest.reg_write(registers.UC_X86_REG_IP, int(guest.reg_read(registers.UC_X86_REG_IP)) + size)


def _access(guest: Uc, access: int, address: int, size: int, _value: int, state: _ProgramState) -> None:
    """Enforce the exact declared byte union; page padding grants no access."""
    rom = state.boot.environment.rom
    if access == unicorn.UC_MEM_WRITE and rom is not None and rom.contains(address, size):
        _stop(guest, state, ProgramEventKind.READ_ONLY_WRITE, address, b"")
        return
    if not readable_memory_contains(state.memory, rom, address, size):
        _stop(guest, state, ProgramEventKind.UNDECLARED_ACCESS, address, b"")
        return
    if access == unicorn.UC_MEM_WRITE:
        if any(region.overlaps(address, size) for region in state.boot.image.code_ranges):
            _stop(guest, state, ProgramEventKind.CODE_WRITE, address, b"")
            return
        state.writes.update(range(address, address + size))


def _invalid(guest: Uc, access_kind: int, address: int, size: int, _value: int, state: _ProgramState) -> bool:
    """Retain the first refusal and distinguish declared read-only protection."""
    if state.status is not ProgramStatus.BUDGET_EXHAUSTED:
        return False
    rom = state.boot.environment.rom
    readonly = access_kind == unicorn.UC_MEM_WRITE_PROT and rom is not None and rom.contains(address, size)
    kind = ProgramEventKind.READ_ONLY_WRITE if readonly else ProgramEventKind.UNDECLARED_ACCESS
    _stop(guest, state, kind, address, b"")
    return False


def _interrupt(guest: Uc, vector: int, state: _ProgramState) -> None:
    """CPU exceptions remain separate from intercepted software DOS exits."""
    state.status = ProgramStatus.FAULTED
    state.events.append(ProgramEvent(ProgramEventKind.CPU_FAULT, int(guest.reg_read(registers.UC_X86_REG_IP)),
                                     vector.to_bytes(4, "little")))
    guest.emu_stop()


def _initialize(boot: ProgramBoot) -> Uc:
    """Load declared RAM/code and read-only, non-executable ROM without a frame."""
    environment = boot.environment
    guest = make_guest(unicorn.UC_ARCH_X86, unicorn.UC_MODE_16)
    layout = environment.memory_layout()
    for address in layout.pages:
        guest.mem_map(address, PAGE_SIZE)
    for address, data in layout.chunks:
        guest.mem_write(address, data)
    for address, data in boot.image.chunks:
        guest.mem_write(address, data)
    if environment.rom is not None:
        for address in environment.rom.pages:
            guest.mem_map(address, PAGE_SIZE, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
        for address, data in environment.rom.chunks:
            guest.mem_write(address, data)
        for address in environment.rom.pages:
            guest.mem_protect(address, PAGE_SIZE, unicorn.UC_PROT_READ)
    initial = dict(boot.initial_registers())
    for name, identity in _high_ids().items():
        guest.reg_write(identity, initial[name])
    segments = {"cs": boot.entry.segment, "ss": boot.stack.segment,
                "ds": environment.psp_segment, "es": environment.psp_segment,
                "fs": environment.fs, "gs": environment.gs}
    for name, identity in _segment_ids().items():
        guest.reg_write(identity, segments[name])
    guest.reg_write(registers.UC_X86_REG_IP, boot.entry.offset)
    guest.reg_write(registers.UC_X86_REG_EFLAGS, initial["eflags"])
    return guest


def _identities(boot: ProgramBoot) -> tuple[str, str]:
    """Bind results to declared initial state and binary-derived boot coordinates."""
    environment = boot.environment
    environment_identity = hashlib.sha256(canonical_json_bytes({
        "psp": environment.psp_segment, "allocation": environment.allocation.hex(),
        "extra_memory": memory_regions_document(environment.extra_memory),
        "rom": rom_document(environment.rom),
        "registers": sorted(environment.registers), "fs": environment.fs, "gs": environment.gs,
        "services": {"termination": "int21_4c", "input": input_policy_document(environment.input_policy),
                     "version": version_policy_document(environment.version_policy),
                     "resize": resize_policy_document(environment.resize_policy),
                     "vectors": vector_policy_document(environment.vector_policy),
                     "device_info": device_info_policy_document(environment.device_info_policy),
                     "video": video_policy_document(environment.video_policy),
                     "video_state": video_state_document(environment.video_state_policy),
                     "output": None if environment.output_policy is None else {
            "handles": sorted(environment.output_policy.handles),
            "per_call_bytes": environment.output_policy.per_call_bytes,
            "aggregate_bytes": environment.output_policy.aggregate_bytes,
        }}, "architecture": "unicorn_real16",
        "interrupt_entry": (VIDEO_INTERRUPT_ENTRY_MODEL if environment.video_policy is not None
                            or environment.video_state_policy is not None else INTERRUPT_ENTRY_MODEL),
    })).hexdigest()
    return boot.boot_sha256, environment_identity


def _final_snapshot(
    guest: Uc, state: _ProgramState, observations: tuple[ProgramObservation, ...],
) -> tuple[tuple[tuple[str, bytes], ...], tuple[tuple[int, bytes], ...]]:
    """Read back declared outputs and recorded writes; disclose refused spans.

    A terminated or faulted program publishes complete declared evidence, so
    a named readback failure downgrades the outcome to ``UNSUPPORTED`` and
    retains the first refused span as a typed event; truncated or refused
    runs keep their typing. Only genuinely read bytes are emitted.
    """
    outputs: list[tuple[str, bytes]] = []
    gaps: list[_ReadbackGap] = []
    for item in observations:
        read = _try_read_span(guest, item.region.address, item.region.size)
        if isinstance(read, _ReadbackGap):
            gaps.append(read)
        else:
            outputs.append((item.name, read))
    snapshot = _coalesced_writes(guest, state.writes)
    gaps.extend(snapshot.gaps)
    if gaps:
        detail = _snapshot_gap_detail(tuple(gaps))
        state.events.append(ProgramEvent(ProgramEventKind.UNDECLARED_ACCESS, gaps[0].address,
                                         detail.encode()))
        if state.status in (ProgramStatus.TERMINATED, ProgramStatus.FAULTED):
            state.status = ProgramStatus.UNSUPPORTED
            state.detail = detail
        else:
            state.detail = state.detail or detail
    return tuple(outputs), snapshot.writes


def replay_program(
    boot: ProgramBoot, *, observations: tuple[ProgramObservation, ...] = (), instruction_limit: int = 100000,
) -> ProgramResult:
    """Execute one initialized program; observations never change guest state.

    The retained source evidence is re-verified before any state is consumed,
    so a boot object mutated past its constructor (frozen dataclasses remain
    reachable through ``object.__setattr__``) can never execute or publish a
    stale boot identity.
    """
    if instruction_limit <= 0:
        raise ValueError("program instruction budget must be positive")
    boot._check_against_source()
    arena = boot.environment.memory_layout()
    names = [observation.name for observation in observations]
    if len(set(names)) != len(names):
        raise ValueError("program output names must be unique")
    if any(not arena.contains(item.region.address, item.region.size) for item in observations):
        raise ValueError("program observations must lie inside the declared allocation")
    if dict(boot.environment.registers)["eflags"] & 2 == 0:
        raise ValueError("program EFLAGS must retain the architectural reserved bit1")
    boot_identity, environment_identity = _identities(boot)
    denominator = tuple((item.name, item.region.size) for item in observations)
    streams = () if boot.environment.output_policy is None else tuple(sorted(boot.environment.output_policy.handles))
    input_policy = boot.environment.input_policy
    requested_files = () if input_policy is None else tuple(sorted((item.handle, item.cursor) for item in input_policy.files))
    if not backend_available():
        return ProgramResult(ProgramStatus.UNAVAILABLE, None, (), (), denominator, (), (), 0,
                             boot_identity, environment_identity, "backend_unavailable", streams,
                             requested_files, requested_files)
    guest = _initialize(boot)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoder.detail = True
    state = _ProgramState(boot, decoder, arena)
    if input_policy is not None:
        state.input_runtime = program_input_runtime(input_policy)
    guest.hook_add(unicorn.UC_HOOK_CODE, _code, user_data=state)
    guest.hook_add(unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE, _access, user_data=state)
    guest.hook_add(unicorn.UC_HOOK_MEM_INVALID, _invalid, user_data=state)
    guest.hook_add(unicorn.UC_HOOK_INTR, _interrupt, user_data=state)
    try:
        guest.emu_start(boot.entry.linear(), 0, count=instruction_limit)
    except UcError as error:
        if state.status is ProgramStatus.BUDGET_EXHAUSTED:
            state.status = ProgramStatus.UNSUPPORTED
            state.detail = f"unicorn_error:{error.errno}"
    outputs, writes = _final_snapshot(guest, state, observations)
    result = ProgramResult(state.status, state.exit_code, _result_registers(guest), outputs, denominator,
                           writes, tuple(state.events), state.instructions,
                           boot_identity, environment_identity, state.detail, streams, requested_files,
                           () if state.input_runtime is None else tuple(sorted(state.input_runtime.cursors.items())),
                           tuple(state.file_receipts))
    del guest
    gc.collect()
    return result
