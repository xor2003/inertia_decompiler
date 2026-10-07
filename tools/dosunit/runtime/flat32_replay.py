"""Execute declared flat-i386 vectors independently of symbolic comparison.

Layer: dosunit concrete execution.
Responsibility: replay initialized binary images with isolated guest state and
explicit observations; agreement is test evidence and never a symbolic proof.
"""

from __future__ import annotations

import gc
from dataclasses import dataclass, field

import capstone
import unicorn
from capstone import x86_const as decoded_registers
from unicorn.unicorn_py3.unicorn import Uc, UcError

from tools.dosunit.runtime.flat32_memory_permissions import PAGE_SIZE, DeclaredAccess, PageGrant
from tools.dosunit.runtime.flat32_replay_memory import _capture_observation, _initialize_guest
from tools.dosunit.runtime.flat32_replay_memory import image_from_project as image_from_project
from tools.dosunit.runtime.flat32_replay_model import (
    DEFAULT_OBSERVABLES as DEFAULT_OBSERVABLES,
)
from tools.dosunit.runtime.flat32_replay_model import (
    OBSERVABLE_REGISTER_IDS as OBSERVABLE_REGISTER_IDS,
)
from tools.dosunit.runtime.flat32_replay_model import (
    REGISTER_IDS as REGISTER_IDS,
)
from tools.dosunit.runtime.flat32_replay_model import (
    RETURN_TRAP as RETURN_TRAP,
)
from tools.dosunit.runtime.flat32_replay_model import (
    Flat32CaptureResult as Flat32CaptureResult,
)
from tools.dosunit.runtime.flat32_replay_model import (
    MemoryObservation as MemoryObservation,
)
from tools.dosunit.runtime.flat32_replay_model import (
    MemoryRange as MemoryRange,
)
from tools.dosunit.runtime.flat32_replay_model import (
    ObservationStatus as ObservationStatus,
)
from tools.dosunit.runtime.flat32_replay_model import (
    ReplayAgreement as ReplayAgreement,
)
from tools.dosunit.runtime.flat32_replay_model import (
    ReplayImage as ReplayImage,
)
from tools.dosunit.runtime.flat32_replay_model import (
    ReplayInstructionReason as ReplayInstructionReason,
)
from tools.dosunit.runtime.flat32_replay_model import (
    ReplayResult as ReplayResult,
)
from tools.dosunit.runtime.flat32_replay_model import (
    ReplayStatus as ReplayStatus,
)
from tools.dosunit.runtime.flat32_replay_model import (
    ReplayVector as ReplayVector,
)
from tools.dosunit.runtime.replay_capture_model import (
    DEFAULT_TRACE_LIMIT,
    CaptureStatus,
    _CaptureState,
    resolve_capture_status,
)
from tools.dosunit.runtime.replay_machine_inputs import MACHINE_INPUT_INSTRUCTION_IDS as UNDECLARED_MACHINE_INPUTS

UNMODELED_REGISTER_GROUPS: frozenset[int] = frozenset(
    {
        decoded_registers.X86_GRP_FPU,
        decoded_registers.X86_GRP_MMX,
        decoded_registers.X86_GRP_SSE1,
        decoded_registers.X86_GRP_SSE2,
        decoded_registers.X86_GRP_SSE3,
        decoded_registers.X86_GRP_SSSE3,
        decoded_registers.X86_GRP_SSE41,
        decoded_registers.X86_GRP_SSE42,
        decoded_registers.X86_GRP_AVX,
        decoded_registers.X86_GRP_AVX2,
        decoded_registers.X86_GRP_AVX512,
    }
)
"""Register files absent from this integer replay contract refuse visibly."""
_ACCESS_FAULTS: dict[int, str] = {
    unicorn.UC_MEM_WRITE_PROT: "write_protected",
    unicorn.UC_MEM_READ_PROT: "read_protected",
    unicorn.UC_MEM_FETCH_PROT: "fetch_protected",
    unicorn.UC_MEM_WRITE_UNMAPPED: "write_unmapped",
    unicorn.UC_MEM_READ_UNMAPPED: "read_unmapped",
    unicorn.UC_MEM_FETCH_UNMAPPED: "fetch_unmapped",
}
"""Unicorn invalid-access events to typed flat32 replay fault details."""


@dataclass(slots=True)
class _RunState:
    """Owned mutable hook state for a single isolated execution."""

    status: ReplayStatus = ReplayStatus.BUDGET_EXHAUSTED
    detail: str = ""
    instructions: int = 0
    writes: set[int] = field(default_factory=set)


def _page_access(grants: tuple[PageGrant, ...]) -> dict[int, DeclaredAccess]:
    """Index resolved page access for hook-time write permission checks."""
    return {grant.address: grant.access for grant in grants}


def _write_permitted(page_access: dict[int, DeclaredAccess], address: int, size: int) -> bool:
    """Whether every page covered by a write declares guest WRITE access."""
    pages = range(
        address // PAGE_SIZE * PAGE_SIZE, (address + size - 1) // PAGE_SIZE * PAGE_SIZE + PAGE_SIZE, PAGE_SIZE
    )
    return all(page_access.get(page, DeclaredAccess.NONE) & DeclaredAccess.WRITE for page in pages)


def _written_bytes(guest: Uc, addresses: set[int]) -> tuple[tuple[int, bytes], ...]:
    """Coalesce final written bytes in deterministic linear-address order."""
    groups: list[tuple[int, bytes]] = []
    ordered = sorted(addresses)
    index = 0
    while index < len(ordered):
        start = ordered[index]
        end = index + 1
        while end < len(ordered) and ordered[end] == ordered[end - 1] + 1:
            end += 1
        groups.append((start, bytes(guest.mem_read(start, end - index))))
        index = end
    return tuple(groups)


def _execute(guest: Uc, state: _RunState, entry: int, instruction_limit: int) -> None:
    """Start the guest; keep a hook-classified detail over the raw errno."""
    try:
        guest.emu_start(entry, 0, count=instruction_limit)
    except UcError as error:
        state.status = ReplayStatus.FAULTED
        state.detail = state.detail or f"unicorn_error:{error.errno}"


def _instruction_scope(decoded: capstone.CsInsn | None) -> ReplayInstructionReason | None:
    """Admit integer effects whose complete register state can be observed."""
    if decoded is None:
        return ReplayInstructionReason.DECODE
    if decoded.id in UNDECLARED_MACHINE_INPUTS:
        return ReplayInstructionReason.ENVIRONMENT
    external = (capstone.CS_GRP_INT, capstone.CS_GRP_IRET, capstone.CS_GRP_PRIVILEGE)
    if any(group in decoded.groups for group in external):
        return ReplayInstructionReason.EXTERNAL
    if UNMODELED_REGISTER_GROUPS.intersection(decoded.groups):
        return ReplayInstructionReason.REGISTER_FILE
    return None


def _boundary_stop(uc: Uc, address: int, boundary_state: _CaptureState | None) -> bool:
    """Record one fetch; stop for a capture-local boundary or trace overflow.

    The boundary fetch is traced but never executed and never counted as an
    instruction; a full trace refuses further recording as ``TRACE_OVERFLOW``.
    """
    if boundary_state is None:
        return False
    if len(boundary_state.trace) >= boundary_state.trace_limit:
        boundary_state.overflow = True
        uc.emu_stop()
        return True
    boundary_state.trace.append(address)
    if address == boundary_state.boundary:
        boundary_state.reached = True
        uc.emu_stop()
        return True
    return False


def _frame_or_boundary_stop(
    uc: Uc, address: int, state: _RunState, boundary_state: _CaptureState | None
) -> bool:
    """Stop at the return trap or a capture-local boundary; record the fetch."""
    if address == RETURN_TRAP:
        state.status = ReplayStatus.RETURNED
        uc.emu_stop()
        return True
    return _boundary_stop(uc, address, boundary_state)


def _run_guest(
    image: ReplayImage,
    entry: int,
    vector: ReplayVector,
    instruction_limit: int,
    boundary_state: _CaptureState | None = None,
) -> tuple[Uc, _RunState, tuple[PageGrant, ...]]:
    """Initialize one guest and run it under the full replay guard contract.

    The same instruction-scope, fetch, write/permission, interrupt and
    invalid-access hooks guard replay and capture runs. ``boundary_state``
    is ``None`` for ordinary replay; a bound state additionally records the
    bounded fetch trace and stops before the boundary instruction executes.
    """
    guest, grants = _initialize_guest(image, entry, vector, instruction_limit)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    state = _RunState()

    def instruction_hook(uc: Uc, address: int, size: int, _data: object) -> None:
        """Stop at return, capture boundary, unmodeled services, or execution outside code ranges."""
        if _frame_or_boundary_stop(uc, address, state, boundary_state):
            return
        state.instructions += 1
        if not any(region.contains(address, size) for region in image.executable):
            state.status, state.detail = ReplayStatus.UNSUPPORTED, "execution_outside_image"
            uc.emu_stop()
            return
        decoded = next(decoder.disasm(bytes(uc.mem_read(address, size)), address), None)
        reason = _instruction_scope(decoded)
        if reason is not None:
            state.status, state.detail = ReplayStatus.UNSUPPORTED, reason.value
            uc.emu_stop()

    page_access = _page_access(grants)

    def write_hook(uc: Uc, _access: int, address: int, size: int, _value: int, _data: object) -> None:
        """Capture guest writes and refuse mutation of stable executable bytes.

        The hook fires before Unicorn's own permission check, so a denied
        store reaches this callback too. Only pages whose declared grants
        include WRITE may be recorded; a denied access is classified by the
        invalid-access hook and never becomes an observed write.
        """
        if not _write_permitted(page_access, address, size):
            return
        if any(
            region.address < address + size and address < region.address + region.size for region in image.executable
        ):
            state.status, state.detail = ReplayStatus.UNSUPPORTED, "self_modifying_code"
            uc.emu_stop()
            return
        state.writes.update(range(address, address + size))

    def interrupt_hook(uc: Uc, number: int, _data: object) -> None:
        """Record an emulator-reported fault without treating equal faults as proof."""
        state.status, state.detail = ReplayStatus.FAULTED, f"interrupt:{number}"
        uc.emu_stop()

    def invalid_hook(uc: Uc, access: int, _address: int, _size: int, _value: int, _data: object) -> bool:
        """Classify a denied guest access by Unicorn's typed access event.

        Returning False propagates the fault: a denied access always refuses
        the run, matching the previous unmapped-write failure contract.
        """
        state.status = ReplayStatus.FAULTED
        state.detail = _ACCESS_FAULTS.get(access, f"memory_fault:{access}")
        return False

    guest.hook_add(unicorn.UC_HOOK_CODE, instruction_hook)
    guest.hook_add(unicorn.UC_HOOK_MEM_WRITE, write_hook)
    guest.hook_add(unicorn.UC_HOOK_INTR, interrupt_hook)
    guest.hook_add(unicorn.UC_HOOK_MEM_UNMAPPED | unicorn.UC_HOOK_MEM_PROT, invalid_hook)
    _execute(guest, state, entry, instruction_limit)
    return guest, state, grants


def replay(
    image: ReplayImage,
    entry: int,
    vector: ReplayVector,
    *,
    instruction_limit: int = 100000,
) -> ReplayResult:
    """Run a pure integer function to a return trap in a fresh Unicorn guest."""
    guest, state, grants = _run_guest(image, entry, vector, instruction_limit)
    grant_by_page = {grant.address: grant for grant in grants}
    observed = tuple(_capture_observation(guest, grant_by_page, region) for region in vector.observations)
    result = ReplayResult(
        state.status,
        tuple((name, int(guest.reg_read(identity))) for name, identity in OBSERVABLE_REGISTER_IDS.items()),
        observed,
        _written_bytes(guest, state.writes),
        state.instructions,
        state.detail,
        grants,
        vector.observations,
    )
    # Native hook trampolines form cycles through the guest. Each retained
    # guest owns a large translator reservation that ordinary Python object
    # counts do not reflect. Finish all observations, then collect before the
    # next independent vector, as the real16 backend already requires.
    del guest
    gc.collect()
    return result


def capture(
    image: ReplayImage,
    entry: int,
    vector: ReplayVector,
    boundary: int,
    *,
    instruction_limit: int = 100000,
    trace_limit: int = DEFAULT_TRACE_LIMIT,
) -> Flat32CaptureResult:
    """Run one vector to a declared fetch boundary and snapshot real state.

    The run shares ``replay``'s initialization, guard hooks and budgets: the
    same instruction-scope, fetch, write/permission, interrupt and
    invalid-access checks admit the executed prefix. Fetch reaching
    ``boundary`` before its instruction executes yields ``CAPTURED``; every
    earlier outcome maps to a typed non-result whose ``execution_status``
    keeps the exact replay typing. A capture is concrete evidence about one
    executed prefix — never a replay agreement, a proof verdict, or an
    inference about entry domains, complete callee targets or caller
    continuation.
    """
    if instruction_limit <= 0 or trace_limit <= 0:
        raise ValueError("instruction and trace budgets must be positive")
    if boundary == RETURN_TRAP or not any(
        region.contains(boundary) for region in image.executable
    ):
        return Flat32CaptureResult(
            CaptureStatus.BOUNDARY_INVALID, entry, boundary, None, (), (), (), 0, (),
            RETURN_TRAP, "boundary_outside_declared_executable",
        )
    capture_state = _CaptureState(boundary, trace_limit)
    guest, state, grants = _run_guest(image, entry, vector, instruction_limit, capture_state)
    grant_by_page = {grant.address: grant for grant in grants}
    observed = tuple(_capture_observation(guest, grant_by_page, region) for region in vector.observations)
    status = resolve_capture_status(
        capture_state, state.status,
        returned=ReplayStatus.RETURNED, budget=ReplayStatus.BUDGET_EXHAUSTED,
    )
    result = Flat32CaptureResult(
        status, entry, boundary,
        state.status if status not in {CaptureStatus.CAPTURED, CaptureStatus.TRACE_OVERFLOW} else None,
        tuple((name, int(guest.reg_read(identity))) for name, identity in OBSERVABLE_REGISTER_IDS.items()),
        observed,
        _written_bytes(guest, state.writes),
        state.instructions,
        tuple(capture_state.trace),
        RETURN_TRAP,
        state.detail,
        grants,
        vector.observations,
    )
    # Same guest-lifetime rule as replay: release the translator reservation.
    del guest
    gc.collect()
    return result


def compare_replays(
    oracle: ReplayResult,
    candidate: ReplayResult,
    *,
    observables: tuple[str, ...] = DEFAULT_OBSERVABLES,
) -> ReplayAgreement:
    """Compare complete returned observations; faults or missing evidence refuse.

    The default retains every admitted integer/control/segment field. Callers
    may declare a narrower ABI projection explicitly, while preserving the
    existing callee-save and stack observations. Missing or duplicate backend
    records remain INCOMPLETE rather than disappearing through dictionary
    conversion or a projection default. Observation evidence must also be
    complete on both sides: duplicate requests, divergent requested ranges,
    or any non-``CAPTURED`` observation keeps the verdict INCOMPLETE so
    absent evidence can never reach agreement.
    """
    if oracle.status != ReplayStatus.RETURNED or candidate.status != ReplayStatus.RETURNED:
        return ReplayAgreement.INCOMPLETE
    preserved = {"ebx", "ebp", "esi", "edi", "esp"}
    if not set(observables) <= OBSERVABLE_REGISTER_IDS.keys() or not preserved <= set(observables):
        raise ValueError("observables must name supported registers and retain preserved-register/ESP checking")
    left, right = dict(oracle.registers), dict(candidate.registers)
    if len(left) != len(oracle.registers) or len(right) != len(candidate.registers):
        return ReplayAgreement.INCOMPLETE
    if not set(observables) <= left.keys() or not set(observables) <= right.keys():
        return ReplayAgreement.INCOMPLETE
    oracle_observed = _observation_evidence(oracle)
    candidate_observed = _observation_evidence(candidate)
    if oracle_observed is None or candidate_observed is None or oracle_observed.keys() != candidate_observed.keys():
        return ReplayAgreement.INCOMPLETE
    for key in oracle_observed:
        if (
            oracle_observed[key].status is not ObservationStatus.CAPTURED
            or candidate_observed[key].status is not ObservationStatus.CAPTURED
        ):
            return ReplayAgreement.INCOMPLETE
    registers_equal = all(left[name] == right[name] for name in observables)
    if (
        registers_equal
        and all(oracle_observed[key].data == candidate_observed[key].data for key in oracle_observed)
        and oracle.writes == candidate.writes
    ):
        return ReplayAgreement.AGREED
    return ReplayAgreement.MISMATCHED


def _observation_evidence(result: ReplayResult) -> dict[tuple[int, int], MemoryObservation] | None:
    """Require every requested byte exactly once, even if both records lose it."""
    required = {(region.address, region.size) for region in result.requested_observations}
    if len(required) != len(result.requested_observations):
        return None
    by_range: dict[tuple[int, int], MemoryObservation] = {}
    for observation in result.observations:
        key = (observation.address, observation.size)
        if key in by_range or observation.size <= 0 or len(observation.data) != observation.size:
            return None
        by_range[key] = observation
    return by_range if by_range.keys() == required else None
