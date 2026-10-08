"""Typed contracts for independent real-mode concrete differential replay.

Layer: dosunit concrete execution.
Responsibility: segmented-address values, execution policies, caller-frame
contracts and observed results for real16 replay. Concrete agreement is test
evidence only; it is a typed enum kept strictly separate from
``tools.dosunit.contracts.proof_contracts.ProofStatus`` and can never discharge a proof
obligation.

"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from tools.dosunit.runtime.replay_capture_model import CaptureObservationStatus, CaptureStatus

PAGE_SIZE: int = 4096
ONE_MIB: int = 0x100000
# Highest real-mode physical address is FFFF:FFFF = 0x10FFEF; round up to a page.
LINEAR_LIMIT: int = 0x110000
MAX_MAPPED_BYTES: int = LINEAR_LIMIT

GENERAL_REGS: tuple[str, ...] = ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp")
HIGH_REGS: tuple[str, ...] = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
SEGMENT_REGS: tuple[str, ...] = ("cs", "ds", "es", "ss", "fs", "gs")
VECTOR_SEGMENTS: tuple[str, ...] = ("ds", "es", "ss", "fs", "gs")
FLAG_OBSERVABLES: frozenset[str] = frozenset({"flags", "eflags"})

# Flag bits this contract treats as architecturally defined in real mode:
# CF|PF|AF|ZF|SF|TF|IF|DF|OF. Reserved, IOPL/NT/RF/VM/AC/VIF/VIP/ID and all
# upper EFLAGS bits are outside the default admitted observation unless a
# vector's declared mask admits them explicitly.
DEFAULT_FLAGS_MASK: int = 0x0FD5

# Registers a real-mode near/far caller owns across the call and that must stay
# inside the observable set so a dropped callee-save is never invisible.
PRESERVED_OBSERVABLES: frozenset[str] = frozenset({"bx", "si", "di", "bp", "sp", "ds", "ss"})
# The default observation contract is the full admitted machine state: every
# general register and 386 high half, every segment register, the control IP
# reached at the outcome, and EFLAGS under the declared flag mask.
DEFAULT_OBSERVABLES: tuple[str, ...] = (
    "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
    "cs", "ds", "es", "ss", "fs", "gs",
    "ip", "eflags",
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
)


class Real16ReplayStatus(StrEnum):
    """Concrete execution outcome; unrelated to any semantic proof verdict."""

    RETURNED = "returned"
    CONTROL = "control"
    FAULTED = "faulted"
    BUDGET_EXHAUSTED = "budget_exhausted"
    UNSUPPORTED = "unsupported"
    UNAVAILABLE = "unavailable"


class Real16Agreement(StrEnum):
    """Agreement on declared concrete observations cannot establish a proof."""

    AGREED = "agreed"
    MISMATCHED = "mismatched"
    INCOMPLETE = "incomplete"


# Outcomes that describe an actually observed, fully determined execution.
# CONTROL is a declared-code coverage gap, BUDGET_EXHAUSTED is truncation,
# and UNSUPPORTED is a scope
# refusal, and UNAVAILABLE is no execution at all; none may compare as a
# known-unequal outcome.
COMPLETE_OUTCOMES: frozenset[Real16ReplayStatus] = frozenset(
    {Real16ReplayStatus.RETURNED, Real16ReplayStatus.FAULTED}
)


def effective_flags_mask(declared: int) -> int:
    """Resolve a vector's declared flag mask to the compared EFLAGS bit set.

    ``0`` is the sentinel for "no explicit declaration" and resolves to
    ``DEFAULT_FLAGS_MASK`` so the default contract always observes defined
    flag changes. A nonzero mask is the declared set of flag bits whose state
    is defined for that vector; bits outside it are treated as undefined and
    excluded from comparison.
    """
    if not 0 <= declared <= 0xFFFFFFFF:
        raise ValueError("flags_mask must fit the 32-bit EFLAGS domain")
    return DEFAULT_FLAGS_MASK if declared == 0 else declared


class A20Policy(StrEnum):
    """Declared handling of addresses at or above the 1 MiB line."""

    ENABLED = "enabled"
    DISABLED_REFUSE = "disabled_refuse"


class StraddlePolicy(StrEnum):
    """Declared semantics for an access whose 16-bit offset crosses 0xFFFF.

    ``LINEAR_CONTINUE`` records the emulator's 386-style model: effective
    offsets are computed modulo 2**16, but a multi-byte access continues
    linearly past the segment end. Declared setup writes and observations
    resolve their starting offset once and continue linearly as well.
    """

    LINEAR_CONTINUE = "linear_continue"


class FrameKind(StrEnum):
    """Caller frame installed at SS:SP before entry; other frames refuse."""

    NEAR16 = "near16"
    FAR16 = "far16"


class ReplayEventKind(StrEnum):
    """Typed reason an execution produced an event record."""

    INTERRUPT = "interrupt"
    UNSUPPORTED_INSTRUCTION = "unsupported_instruction"
    DECODE_FAILED = "decode_failed"
    UNMAPPED_ACCESS = "unmapped_access"
    INSTRUCTION_WRITE = "instruction_memory_write"
    A20_BOUNDARY = "a20_boundary"
    CONTROL_ESCAPE = "control_escape"


@dataclass(frozen=True, slots=True)
class SegOffset:
    """One real-mode logical address; physical resolution is explicit."""

    segment: int
    offset: int

    def __post_init__(self) -> None:
        """Reject logical addresses outside the 16-bit segmented domain."""
        if not 0 <= self.segment <= 0xFFFF or not 0 <= self.offset <= 0xFFFF:
            raise ValueError("segmented address requires 16-bit segment and offset")

    def linear(self) -> int:
        """Resolve to the physical address ``segment*16 + offset`` (<= 0x10FFEF)."""
        return self.segment * 16 + self.offset


@dataclass(frozen=True, slots=True)
class LinearRange:
    """One bounded physical byte range in the execution or observation contract."""

    address: int
    size: int

    def __post_init__(self) -> None:
        """Reject ranges outside the bounded real-mode physical domain."""
        if self.size <= 0 or self.address < 0 or self.address + self.size > LINEAR_LIMIT:
            raise ValueError("invalid real16 linear range")

    def contains(self, address: int, size: int = 1) -> bool:
        """Test containment of a physical access without any address wrap."""
        return self.address <= address and address + size <= self.address + self.size

    def overlaps(self, address: int, size: int) -> bool:
        """Test intersection with a physical access range."""
        return self.address < address + size and address < self.address + self.size


@dataclass(frozen=True, slots=True)
class CallerFrame:
    """Return frame the synthetic caller leaves on the stack at SS:SP.

    ``NEAR16`` installs a 2-byte IP; the target segment must equal the entry
    CS, which is what a near ``call`` implies. ``FAR16`` installs a 4-byte
    CS:IP pair. All other frame shapes are refused by this contract's type.

    ``sp_guard`` selects return detection by stack boundary instead of a
    fetch at ``target``: a ret-family instruction fetched while SP still
    points at this frame consumes the synthetic caller's return address —
    it is ``RETURNED`` before executing.  This is required when no offset
    in the entry segment can hold the trap (a loaded image >= 64K spans
    every reachable in-CS offset).  The target bytes are still pushed —
    the frame is real — but the target is never required to be fetchable,
    so the trap-overlap check does not apply.
    """

    kind: FrameKind
    target: SegOffset
    sp_guard: bool = False

    def push_bytes(self) -> bytes:
        """Return the stack bytes the corresponding call would have pushed."""
        if self.kind is FrameKind.NEAR16:
            return self.target.offset.to_bytes(2, "little")
        return self.target.offset.to_bytes(2, "little") + self.target.segment.to_bytes(2, "little")


@dataclass(frozen=True, slots=True)
class Real16Image:
    """Relocated loaded MZ bytes, declared code ranges and fingerprints.

    ``chunks`` are physical ``(address, bytes)`` backers seeded into every
    fresh guest. Fingerprints bind a replay result to the exact file bytes,
    the relocated loaded image and the relocation records.
    """

    chunks: tuple[tuple[int, bytes], ...]
    code_ranges: tuple[LinearRange, ...]
    load_segment: int
    image_size: int
    bss_size: int
    file_sha256: str
    image_sha256: str
    reloc_sha256: str
    code_scope: str = "declared"


@dataclass(frozen=True, slots=True)
class Real16Vector:
    """Concrete initial machine state, memory patches and declared observations.

    ``registers`` covers the 16-bit general registers and flags; ``segments``
    covers DS/ES/SS/FS/GS (CS/IP come from the entry contract, never the
    vector). ``high_halves`` supplies the explicit 386 upper halves of the
    general registers; any absent half defaults to zero and the policy records
    that default. Patches and observations are segmented addresses; physical
    aliasing between segments is preserved because all writes resolve through
    the same ``segment*16 + offset`` rule.

    ``flags_mask`` is the declared set of EFLAGS bits whose final state is
    defined for this vector; ``0`` resolves to ``DEFAULT_FLAGS_MASK`` so a
    defined flag change is never silently ignored. The mask is an execution
    observation contract only — it narrows what concrete comparison may
    declare equal, never a proof obligation.
    """

    registers: tuple[tuple[str, int], ...]
    segments: tuple[tuple[str, int], ...]
    frame: CallerFrame
    high_halves: tuple[tuple[str, int], ...] = ()
    memory: tuple[tuple[SegOffset, bytes], ...] = ()
    observations: tuple[tuple[SegOffset, int], ...] = ()
    flags_mask: int = 0

    def __post_init__(self) -> None:
        """Bound the declared flag mask to the 32-bit EFLAGS domain."""
        effective_flags_mask(self.flags_mask)


@dataclass(frozen=True, slots=True)
class ReplayEvent:
    """One typed execution event; raw bytes/ids, never rendered-text parsing."""

    kind: ReplayEventKind
    detail: str
    address: int = 0
    data: bytes = b""


@dataclass(frozen=True, slots=True)
class Real16ReplayResult:
    """Deterministic concrete observations plus the actual execution outcome.

    ``writes`` records every touched physical byte coalesced with final
    contents; ``observations`` records the declared ranges independently, so
    write records and observed contents stay distinct. ``flags_mask`` carries
    the vector's effective declared EFLAGS mask into the compare contract;
    ``instructions`` is diagnostic only and is never part of agreement.
    """

    status: Real16ReplayStatus
    registers: tuple[tuple[str, int], ...]
    observations: tuple[tuple[int, bytes], ...]
    writes: tuple[tuple[int, bytes], ...]
    events: tuple[ReplayEvent, ...]
    instructions: int
    detail: str = ""
    flags_mask: int = 0


@dataclass(frozen=True, slots=True)
class Real16Comparison:
    """Typed differential outcome for one oracle/candidate result pair.

    ``agreement`` is the verdict; ``flags_mask`` is the effective EFLAGS mask
    the register comparison was bound to (the union of both sides' declared
    masks, so a bit declared defined by either side is never ignored);
    ``observables`` is the exact register set compared; ``reason`` is a
    diagnostic explanation, never a status string to match on.
    """

    agreement: Real16Agreement
    observables: tuple[str, ...]
    flags_mask: int
    reason: str = ""


@dataclass(frozen=True, slots=True)
class Real16ReplayPolicy:
    """Explicit architectural policies; nothing about segmentation is silent."""

    a20: A20Policy = A20Policy.ENABLED
    straddle: StraddlePolicy = StraddlePolicy.LINEAR_CONTINUE
    high_half_default: str = "zero"
    max_patch_bytes: int = 0x10000
    max_observation_bytes: int = 0x10000


@dataclass(frozen=True, slots=True)
class Real16CaptureObservation:
    """Host bytes for one declared observation at the boundary, or a typed miss.

    ``request``/``size`` echo the vector declaration and ``linear`` records
    the resolved physical provenance under ``segment*16 + offset``. ``data``
    is empty unless the range read as ``CAPTURED``; ``UNMAPPED`` records a
    declared range without mapped page coverage instead of fabricating
    bytes.
    """

    request: SegOffset
    size: int
    linear: int
    status: CaptureObservationStatus
    data: bytes


@dataclass(frozen=True, slots=True)
class Real16CaptureResult:
    """Typed boundary capture: executed-prefix outcome plus real guest state.

    ``status`` is the capture taxonomy, never a proof or agreement verdict;
    ``execution_status`` carries the exact underlying replay outcome and is
    ``None`` for capture-local stops (boundary reached, trace overflow) and
    for runs that never executed. The register, observation, write and event
    projections are the same fields replay materializes after the shared
    guarded loop; they describe real guest state at the stop point.
    ``fetch_trace`` is the bounded physical fetch stream including the
    boundary fetch, ``trap_linear`` the exact caller-frame return target the
    run was bound to, and ``flags_mask`` the vector's effective declared
    EFLAGS mask. Nothing here infers a callable entry domain, a complete
    callee target set, or the caller's continuation from one trace.
    """

    status: CaptureStatus
    entry: SegOffset
    boundary: SegOffset
    execution_status: Real16ReplayStatus | None
    registers: tuple[tuple[str, int], ...]
    observations: tuple[Real16CaptureObservation, ...]
    writes: tuple[tuple[int, bytes], ...]
    events: tuple[ReplayEvent, ...]
    instructions: int
    fetch_trace: tuple[int, ...]
    trap_linear: int
    detail: str = ""
    flags_mask: int = 0


@dataclass(slots=True)
class _RunState:
    """Owned mutable hook state for one isolated guest execution."""

    status: Real16ReplayStatus = Real16ReplayStatus.BUDGET_EXHAUSTED
    detail: str = ""
    instructions: int = 0
    writes: set[int] = field(default_factory=set)
    events: list[ReplayEvent] = field(default_factory=list)
