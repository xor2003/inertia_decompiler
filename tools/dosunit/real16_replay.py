"""Execute declared real-mode vectors in isolated Unicorn guests.

Layer: dosunit concrete execution.
Responsibility: replay relocated MZ images under explicit segmented-register
and caller-frame contracts with per-vector fresh guests. Interrupts, device
I/O, privileged instructions and writes into declared instruction bytes are
admitted by typed Capstone decode and produce ``UNSUPPORTED``; nothing is
classified from rendered assembly. Agreement on concrete observations is
test evidence and never promotes any proof status.

"""

from __future__ import annotations

import gc
from dataclasses import dataclass
from typing import TYPE_CHECKING

from tools.dosunit.real16_guest import (
    _high_ids,
    _initialize_guest,
    _low_ids,
    _seg_read,
    _segment_ids,
)
from tools.dosunit.real16_replay_compare import compare_executions as compare_executions
from tools.dosunit.real16_replay_compare import compare_replays as compare_replays
from tools.dosunit.real16_replay_model import (
    COMPLETE_OUTCOMES,
    ONE_MIB,
    A20Policy,
    Real16CaptureObservation,
    Real16CaptureResult,
    Real16Image,
    Real16ReplayPolicy,
    Real16ReplayResult,
    Real16ReplayStatus,
    Real16Vector,
    ReplayEvent,
    ReplayEventKind,
    SegOffset,
    _RunState,
    effective_flags_mask,
)
from tools.dosunit.replay_capture_model import (
    DEFAULT_TRACE_LIMIT,
    CaptureObservationStatus,
    CaptureStatus,
    _CaptureState,
    resolve_capture_status,
)
from tools.dosunit.replay_machine_inputs import MACHINE_INPUT_INSTRUCTION_IDS, ReplayInstructionReason

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
    except ImportError:  # pragma: no cover - exercised via monkeypatchable None
        capstone = None  # type: ignore[assignment]
        unicorn = None  # type: ignore[assignment]
        x86_ids = None  # type: ignore[assignment]
        registers = None  # type: ignore[assignment]
        Uc = None  # type: ignore[assignment, misc]
        UcError = Exception  # type: ignore[assignment, misc]

DEFAULT_INSTRUCTION_LIMIT: int = 100000

# Device I/O executes silently under the emulator's real-mode model, so it is
# refused at typed decode time rather than observed.
IO_INSTRUCTION_IDS: frozenset[int] = frozenset({
    x86_ids.X86_INS_IN, x86_ids.X86_INS_INSB, x86_ids.X86_INS_INSW,
    x86_ids.X86_INS_OUT, x86_ids.X86_INS_OUTSB, x86_ids.X86_INS_OUTSW,
}) if x86_ids is not None else frozenset()
# Real-mode-safe flag controls that the emulator models faithfully; every
# other privileged-group instruction refuses.
ADMITTED_PRIVILEGED_IDS: frozenset[int] = frozenset({
    x86_ids.X86_INS_CLI, x86_ids.X86_INS_STI,
}) if x86_ids is not None else frozenset()

# Floating/vector registers are outside the declared observation contract.
# Executing these groups would make agreement silently ignore live state.
UNOBSERVED_REGISTER_GROUPS: frozenset[int] = frozenset({
    x86_ids.X86_GRP_FPU, x86_ids.X86_GRP_MMX,
    x86_ids.X86_GRP_SSE1, x86_ids.X86_GRP_SSE2, x86_ids.X86_GRP_SSE3,
    x86_ids.X86_GRP_SSE41, x86_ids.X86_GRP_SSE42, x86_ids.X86_GRP_SSE4A,
    x86_ids.X86_GRP_AVX, x86_ids.X86_GRP_AVX2, x86_ids.X86_GRP_AVX512,
}) if x86_ids is not None else frozenset()


def backend_available() -> bool:
    """Return whether the concrete execution backend is importable."""
    return unicorn is not None and capstone is not None




def _unsupported_ids() -> frozenset[int]:
    """Instruction ids that are device I/O or silently terminal (HLT)."""
    return IO_INSTRUCTION_IDS | frozenset({x86_ids.X86_INS_HLT})


def _admitted_segment_transfer(decoded: capstone.CsInsn) -> bool:
    """Admit real-mode MOV/PUSH/POP segments despite Capstone's privilege tag.

    MOV to a data/stack segment or from a segment is ordinary real-mode
    execution, including loading DS/ES/SS through the stack. Control/debug
    register operands remain refused by the privilege gate.
    """
    segment_ids = {x86_ids.X86_REG_CS, x86_ids.X86_REG_DS, x86_ids.X86_REG_ES,
                   x86_ids.X86_REG_SS, x86_ids.X86_REG_FS, x86_ids.X86_REG_GS}
    transfer_ids = {x86_ids.X86_INS_MOV, x86_ids.X86_INS_PUSH, x86_ids.X86_INS_POP}
    return decoded.id in transfer_ids and any(
        operand.type == x86_ids.X86_OP_REG and operand.reg in segment_ids
        for operand in decoded.operands
    )


def _classified(guest: Uc, decoder: capstone.Cs, address: int, size: int) -> tuple[bool, str, bytes, int]:
    """Typed-decode one instruction; return (admitted, detail, raw, insn_id)."""
    raw = bytes(guest.mem_read(address, size))
    decoded = next(decoder.disasm(raw, address), None)
    if decoded is None:
        return False, "instruction_decode_failed", raw, -1
    if decoded.id in MACHINE_INPUT_INSTRUCTION_IDS:
        return False, ReplayInstructionReason.ENVIRONMENT.value, raw, decoded.id
    if decoded.id in _unsupported_ids():
        return False, "device_io_or_halt", raw, decoded.id
    groups = set(decoded.groups)
    if groups & UNOBSERVED_REGISTER_GROUPS:
        return False, "unmodeled_register_state", raw, decoded.id
    if groups & {capstone.CS_GRP_INT, capstone.CS_GRP_IRET}:
        return False, "interrupt_or_iret", raw, decoded.id
    if (groups & {capstone.CS_GRP_PRIVILEGE}
            and decoded.id not in ADMITTED_PRIVILEGED_IDS
            and not _admitted_segment_transfer(decoded)):
        return False, "privileged_instruction", raw, decoded.id
    return True, "", raw, decoded.id


@dataclass(frozen=True, slots=True)
class _ReadbackGap:
    """One recorded physical span whose final guest readback refused.

    ``cause`` names the backend error (the symbolic ``UC_ERR_*`` name when
    the backend exposes it); ``address``/``size`` bound the exact span that
    produced no bytes. A gap is evidence of lost observation and is never
    substituted with fabricated data.
    """

    address: int
    size: int
    cause: str


@dataclass(frozen=True, slots=True)
class _WriteSnapshot:
    """Coalesced real write bytes plus every span the readback refused.

    ``writes`` contains only bytes genuinely read from the guest; ``gaps``
    covers recorded addresses that produced no bytes, so consumers can
    refuse a complete outcome rather than publish partial evidence.
    """

    writes: tuple[tuple[int, bytes], ...]
    gaps: tuple[_ReadbackGap, ...]


def _readback_cause(error: UcError) -> str:
    """Name the backend cause of one refused readback symbolically."""
    errno = int(error.errno)
    names: dict[int, str] = (
        {value: name for name, value in vars(unicorn).items()
         if name.startswith("UC_ERR_") and isinstance(value, int)}
        if unicorn is not None else {}
    )
    return names.get(errno, f"uc_error:{errno}")


def _try_read_span(guest: Uc, address: int, size: int) -> bytes | _ReadbackGap:
    """Read one declared span; a named backend error returns a typed gap."""
    try:
        return bytes(guest.mem_read(address, size))
    except UcError as error:
        return _ReadbackGap(address, size, _readback_cause(error))


def _read_span(
    guest: Uc, start: int, size: int,
    pieces: list[tuple[int, bytes]], gaps: list[_ReadbackGap],
) -> None:
    """Read a recorded write span into accurately labeled pieces and gaps.

    A recorded write may straddle a mapped/unmapped boundary (the hook sees
    every touched address, including the half that faulted). Named backend
    errors bisect the span until the exact unreadable addresses are typed;
    each emitted piece covers only bytes genuinely read at its address,
    never substitutes. Any error that is not a named backend readback
    failure propagates.
    """
    try:
        data = bytes(guest.mem_read(start, size))
    except UcError as error:
        if size <= 1:
            gaps.append(_ReadbackGap(start, 1, _readback_cause(error)))
            return
        half = size // 2
        _read_span(guest, start, half, pieces, gaps)
        _read_span(guest, start + half, size - half, pieces, gaps)
        return
    if data:
        pieces.append((start, data))


def _merged_gaps(gaps: list[_ReadbackGap]) -> tuple[_ReadbackGap, ...]:
    """Merge adjacent equal-cause byte gaps into spans, preserving order."""
    merged: list[_ReadbackGap] = []
    for gap in gaps:
        last = merged[-1] if merged else None
        if last is not None and last.cause == gap.cause and last.address + last.size == gap.address:
            merged[-1] = _ReadbackGap(last.address, last.size + gap.size, last.cause)
        else:
            merged.append(gap)
    return tuple(merged)


def _merged_pieces(pieces: list[tuple[int, bytes]]) -> tuple[tuple[int, bytes], ...]:
    """Merge physically adjacent read pieces into coalesced groups."""
    groups: list[tuple[int, bytes]] = []
    for start, data in pieces:
        if groups and groups[-1][0] + len(groups[-1][1]) == start:
            groups[-1] = (groups[-1][0], groups[-1][1] + data)
        else:
            groups.append((start, data))
    return tuple(groups)


def _coalesced_writes(guest: Uc, addresses: set[int]) -> _WriteSnapshot:
    """Coalesce final written bytes in deterministic physical-address order.

    Spans the guest refuses to read back come back as typed gaps with cause
    and range; emitted groups cover only genuinely read bytes at their
    labeled address, so nothing is substituted or mislabeled.
    """
    pieces: list[tuple[int, bytes]] = []
    raw_gaps: list[_ReadbackGap] = []
    ordered = sorted(addresses)
    index = 0
    while index < len(ordered):
        start = ordered[index]
        end = index + 1
        while end < len(ordered) and ordered[end] == ordered[end - 1] + 1:
            end += 1
        _read_span(guest, start, end - index, pieces, raw_gaps)
        index = end
    return _WriteSnapshot(_merged_pieces(pieces), _merged_gaps(raw_gaps))


def _snapshot_gap_detail(gaps: tuple[_ReadbackGap, ...]) -> str:
    """Detail fragment naming the first refused snapshot span and its cause."""
    first = gaps[0]
    return f"snapshot_unreadable:{first.cause}:{first.address:#x}+{first.size:#x}"


def _apply_snapshot_gaps(state: _RunState, gaps: tuple[_ReadbackGap, ...]) -> str | None:
    """Disclose a partial final snapshot on the run state; return its detail.

    ``RETURNED``/``FAULTED`` publish complete declared state, so a partial
    readback downgrades them to ``UNSUPPORTED``; truncated or already
    refused outcomes keep their typing. Either way the first refused span
    is retained as a typed event and surfaced on ``detail`` when no earlier
    refusal claimed it.
    """
    if not gaps:
        return None
    detail = _snapshot_gap_detail(gaps)
    state.events.append(ReplayEvent(ReplayEventKind.UNMAPPED_ACCESS, detail, gaps[0].address))
    if state.status in COMPLETE_OUTCOMES:
        state.status = Real16ReplayStatus.UNSUPPORTED
        state.detail = detail
    else:
        state.detail = state.detail or detail
    return detail


def _result_registers(guest: Uc) -> tuple[tuple[str, int], ...]:
    """Snapshot the full observable register state, including 386 halves."""
    low_ids = _low_ids()
    high_ids = _high_ids()
    rows: list[tuple[str, int]] = [(name, int(guest.reg_read(identity))) for name, identity in low_ids.items()]
    rows += [(name, int(guest.reg_read(identity))) for name, identity in high_ids.items()]
    rows += [(name, int(guest.reg_read(identity))) for name, identity in _segment_ids().items()]
    rows.append(("ip", int(guest.reg_read(registers.UC_X86_REG_IP))))
    rows.append(("eflags", int(guest.reg_read(registers.UC_X86_REG_EFLAGS))))
    rows.append(("flags", int(guest.reg_read(registers.UC_X86_REG_EFLAGS)) & 0xFFFF))
    return tuple(rows)


@dataclass(slots=True)
class _HookCtx:
    """Hook context passed through ``user_data``; keeps hooks module-level."""

    image: Real16Image
    policy: Real16ReplayPolicy
    decoder: capstone.Cs
    trap: int
    state: _RunState
    capture: _CaptureState | None = None


def _boundary_stop(uc: Uc, address: int, capture: _CaptureState | None) -> bool:
    """Record one fetch; stop for a capture-local boundary or trace overflow.

    The boundary fetch is traced but never executed and never counted as an
    instruction; a full trace refuses further recording as ``TRACE_OVERFLOW``.
    """
    if capture is None:
        return False
    if len(capture.trace) >= capture.trace_limit:
        capture.overflow = True
        uc.emu_stop()
        return True
    capture.trace.append(address)
    if address == capture.boundary:
        capture.reached = True
        uc.emu_stop()
        return True
    return False


def _code_hook(uc: Uc, address: int, size: int, ctx: _HookCtx) -> None:
    """Stop at the return trap, capture boundary, control escape or unadmitted instruction."""
    if address == ctx.trap:
        ctx.state.status = Real16ReplayStatus.RETURNED
        uc.emu_stop()
        return
    if _boundary_stop(uc, address, ctx.capture):
        return
    ctx.state.instructions += 1
    if not any(region.contains(address, size) for region in ctx.image.code_ranges):
        ctx.state.status, ctx.state.detail = Real16ReplayStatus.CONTROL, "fetch_outside_declared_code"
        ctx.state.events.append(ReplayEvent(ReplayEventKind.CONTROL_ESCAPE, ctx.state.detail, address))
        uc.emu_stop()
        return
    admitted, detail, raw, insn_id = _classified(uc, ctx.decoder, address, size)
    if not admitted:
        kind = ReplayEventKind.DECODE_FAILED if insn_id < 0 else ReplayEventKind.UNSUPPORTED_INSTRUCTION
        ctx.state.status, ctx.state.detail = Real16ReplayStatus.UNSUPPORTED, detail
        ctx.state.events.append(ReplayEvent(kind, detail, address, raw))
        uc.emu_stop()


def _write_hook(uc: Uc, _access: int, address: int, size: int, _value: int, ctx: _HookCtx) -> None:
    """Record guest writes; mutation of declared code is unsupported."""
    if any(region.overlaps(address, size) for region in ctx.image.code_ranges):
        ctx.state.status, ctx.state.detail = Real16ReplayStatus.UNSUPPORTED, "instruction_memory_write"
        ctx.state.events.append(ReplayEvent(
            ReplayEventKind.INSTRUCTION_WRITE, ctx.state.detail, address,
            bytes(uc.mem_read(address, min(size, 16))),
        ))
        uc.emu_stop()
        return
    ctx.state.writes.update(range(address, address + size))


def _intr_hook(uc: Uc, number: int, ctx: _HookCtx) -> None:
    """Record a guest-raised interrupt (divide error, int, trap) as a fault."""
    ctx.state.status, ctx.state.detail = Real16ReplayStatus.FAULTED, f"interrupt:{number}"
    ctx.state.events.append(ReplayEvent(
        ReplayEventKind.INTERRUPT, ctx.state.detail, 0, number.to_bytes(1, "little"),
    ))
    uc.emu_stop()


def _invalid_hook(uc: Uc, access: int, address: int, _size: int, _value: int, ctx: _HookCtx) -> bool:
    """Classify unmapped accesses; A20-boundary accesses stay typed."""
    if ctx.policy.a20 is A20Policy.DISABLED_REFUSE and address >= ONE_MIB:
        ctx.state.status, ctx.state.detail = Real16ReplayStatus.UNSUPPORTED, "a20_wrap_access"
        ctx.state.events.append(ReplayEvent(ReplayEventKind.A20_BOUNDARY, ctx.state.detail, address))
    elif access == unicorn.UC_MEM_FETCH_UNMAPPED:
        ctx.state.status, ctx.state.detail = Real16ReplayStatus.CONTROL, "fetch_unmapped"
        ctx.state.events.append(ReplayEvent(ReplayEventKind.CONTROL_ESCAPE, ctx.state.detail, address))
    else:
        ctx.state.status, ctx.state.detail = Real16ReplayStatus.UNSUPPORTED, f"unmapped_access:{access}"
        ctx.state.events.append(ReplayEvent(ReplayEventKind.UNMAPPED_ACCESS, ctx.state.detail, address))
    uc.emu_stop()
    return False


def _install_hooks(guest: Uc, ctx: _HookCtx) -> None:
    """Bind the shared replay guard hooks to one initialized guest."""
    guest.hook_add(unicorn.UC_HOOK_CODE, _code_hook, user_data=ctx)
    guest.hook_add(unicorn.UC_HOOK_MEM_WRITE, _write_hook, user_data=ctx)
    guest.hook_add(unicorn.UC_HOOK_INTR, _intr_hook, user_data=ctx)
    guest.hook_add(unicorn.UC_HOOK_MEM_INVALID, _invalid_hook, user_data=ctx)


def _run_guest(guest: Uc, ctx: _HookCtx, entry: SegOffset, instruction_limit: int) -> None:
    """Start the guest; keep a hook-classified detail over the raw errno."""
    try:
        guest.emu_start(entry.linear(), 0, count=instruction_limit)
    except UcError as error:
        if ctx.state.status is Real16ReplayStatus.BUDGET_EXHAUSTED:
            ctx.state.status = Real16ReplayStatus.UNSUPPORTED
            ctx.state.detail = f"unicorn_error:{error.errno}"


def _capture_observation(guest: Uc, request: SegOffset, size: int) -> Real16CaptureObservation:
    """Read one declared observation; an unmapped range is a typed non-result."""
    try:
        data = _seg_read(guest, request, size)
    except UcError:
        return Real16CaptureObservation(
            request, size, request.linear(), CaptureObservationStatus.UNMAPPED, b""
        )
    return Real16CaptureObservation(request, size, request.linear(), CaptureObservationStatus.CAPTURED, data)


def replay(
    image: Real16Image, entry: SegOffset, vector: Real16Vector, *,
    policy: Real16ReplayPolicy | None = None, instruction_limit: int = DEFAULT_INSTRUCTION_LIMIT,
) -> Real16ReplayResult:
    """Run one vector to its return trap in a fresh segmented guest.

    The result records status, final registers, declared observations, written
    bytes, typed events and the effective declared flag mask independently;
    instruction count is a diagnostic and is never part of agreement.
    """
    mask = effective_flags_mask(vector.flags_mask)
    if not backend_available():
        return Real16ReplayResult(
            Real16ReplayStatus.UNAVAILABLE, (), (), (), (), 0, "backend_unavailable", mask
        )
    policy = policy or Real16ReplayPolicy()
    if instruction_limit <= 0:
        raise ValueError("instruction budget must be positive")
    guest = _initialize_guest(image, entry, vector, policy)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoder.detail = True
    state = _RunState()
    ctx = _HookCtx(image, policy, decoder, vector.frame.target.linear(), state)
    _install_hooks(guest, ctx)
    _run_guest(guest, ctx, entry, instruction_limit)
    observed: list[tuple[int, bytes]] = []
    gaps: list[_ReadbackGap] = []
    for obs, size in vector.observations:
        linear = obs.segment * 16 + obs.offset
        read = _try_read_span(guest, linear, size)
        if isinstance(read, _ReadbackGap):
            gaps.append(read)
        else:
            observed.append((linear, read))
    snapshot = _coalesced_writes(guest, state.writes)
    _apply_snapshot_gaps(state, (*gaps, *snapshot.gaps))
    result = Real16ReplayResult(
        state.status, _result_registers(guest), tuple(observed),
        snapshot.writes, tuple(state.events),
        state.instructions, state.detail, mask,
    )
    # Hook trampolines reference the guest; without a collection cycle each
    # live guest keeps a large translator reservation and replay runs exhaust
    # the address-space limit after a few vectors.
    del guest
    gc.collect()
    return result


def capture(
    image: Real16Image, entry: SegOffset, vector: Real16Vector, boundary: SegOffset, *,
    policy: Real16ReplayPolicy | None = None,
    instruction_limit: int = DEFAULT_INSTRUCTION_LIMIT,
    trace_limit: int = DEFAULT_TRACE_LIMIT,
) -> Real16CaptureResult:
    """Run one vector to a declared fetch boundary and snapshot real state.

    The run shares ``replay``'s initialization, guard hooks and budgets: the
    same typed decode, write, interrupt and invalid-access checks admit the
    executed prefix. Fetch reaching ``boundary`` before its instruction
    executes yields ``CAPTURED``; every earlier outcome maps to a typed
    non-result whose ``execution_status`` keeps the exact replay typing.
    A capture is concrete evidence about one executed prefix — never a
    replay agreement, a proof verdict, or an inference about entry domains,
    complete callee targets or caller continuation.
    """
    mask = effective_flags_mask(vector.flags_mask)
    if not backend_available():
        return Real16CaptureResult(
            CaptureStatus.UNAVAILABLE, entry, boundary, None, (), (), (), (), 0, (),
            vector.frame.target.linear(), "backend_unavailable", mask,
        )
    policy = policy or Real16ReplayPolicy()
    if instruction_limit <= 0 or trace_limit <= 0:
        raise ValueError("instruction and trace budgets must be positive")
    trap = vector.frame.target.linear()
    boundary_linear = boundary.linear()
    if boundary_linear == trap or not any(
        region.contains(boundary_linear) for region in image.code_ranges
    ):
        return Real16CaptureResult(
            CaptureStatus.BOUNDARY_INVALID, entry, boundary, None, (), (), (), (), 0, (),
            trap, "boundary_outside_declared_code", mask,
        )
    guest = _initialize_guest(image, entry, vector, policy)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoder.detail = True
    state = _RunState()
    capture_state = _CaptureState(boundary_linear, trace_limit)
    ctx = _HookCtx(image, policy, decoder, trap, state, capture_state)
    _install_hooks(guest, ctx)
    _run_guest(guest, ctx, entry, instruction_limit)
    snapshot = _coalesced_writes(guest, state.writes)
    detail = _apply_snapshot_gaps(state, snapshot.gaps)
    status = resolve_capture_status(
        capture_state, state.status,
        returned=Real16ReplayStatus.RETURNED, budget=Real16ReplayStatus.BUDGET_EXHAUSTED,
    )
    if detail is not None and status is CaptureStatus.CAPTURED:
        # Boundary resolution lets ``reached`` outrank the run state, so a
        # refused final snapshot must explicitly demote the capture-local
        # stop instead of publishing CAPTURED on partial evidence.
        status = CaptureStatus.EXECUTION_REFUSED
        state.status = Real16ReplayStatus.UNSUPPORTED
        state.detail = detail
    result = Real16CaptureResult(
        status, entry, boundary,
        state.status if status not in {CaptureStatus.CAPTURED, CaptureStatus.TRACE_OVERFLOW} else None,
        _result_registers(guest),
        tuple(_capture_observation(guest, obs, size) for obs, size in vector.observations),
        snapshot.writes, tuple(state.events),
        state.instructions, tuple(capture_state.trace), trap, state.detail, mask,
    )
    # Same guest-lifetime rule as replay: release the translator reservation.
    del guest
    gc.collect()
    return result
