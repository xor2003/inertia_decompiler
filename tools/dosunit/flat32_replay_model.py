"""Layer: dosunit concrete execution contracts.

Responsibility: own complete flat32 input, output, observation and execution
status contracts, independently of permission enforcement or proof verdicts.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from unicorn import x86_const as registers

from tools.dosunit.flat32_memory_permissions import DeclaredRegion, MappingOrigin, PageGrant
from tools.dosunit.replay_capture_model import CaptureStatus
from tools.dosunit.replay_machine_inputs import ReplayInstructionReason as ReplayInstructionReason

RETURN_TRAP: int = 0xFFFF0000


REGISTER_IDS: dict[str, int] = {
    "eax": registers.UC_X86_REG_EAX,
    "ebx": registers.UC_X86_REG_EBX,
    "ecx": registers.UC_X86_REG_ECX,
    "edx": registers.UC_X86_REG_EDX,
    "esi": registers.UC_X86_REG_ESI,
    "edi": registers.UC_X86_REG_EDI,
    "ebp": registers.UC_X86_REG_EBP,
    "esp": registers.UC_X86_REG_ESP,
    "eflags": registers.UC_X86_REG_EFLAGS,
}


OBSERVABLE_REGISTER_IDS: dict[str, int] = {
    **REGISTER_IDS,
    "eip": registers.UC_X86_REG_EIP,
    "cs": registers.UC_X86_REG_CS,
    "ss": registers.UC_X86_REG_SS,
    "ds": registers.UC_X86_REG_DS,
    "es": registers.UC_X86_REG_ES,
    "fs": registers.UC_X86_REG_FS,
    "gs": registers.UC_X86_REG_GS,
}


DEFAULT_OBSERVABLES: tuple[str, ...] = tuple(OBSERVABLE_REGISTER_IDS)
"""Default strict observation retains every admitted integer/control/segment field."""


class ReplayStatus(StrEnum):
    """Execution outcome, kept separate from a formal equivalence verdict."""

    RETURNED = "returned"
    FAULTED = "faulted"
    BUDGET_EXHAUSTED = "budget_exhausted"
    UNSUPPORTED = "unsupported"


class ReplayAgreement(StrEnum):
    """Agreement on declared concrete observations cannot establish a proof."""

    AGREED = "agreed"
    MISMATCHED = "mismatched"
    INCOMPLETE = "incomplete"


class ObservationStatus(StrEnum):
    """Whether one requested observation range produced host bytes.

    An observation is an output projection, never a guest memory or
    environment assumption: the status records evidence outcomes only and
    is kept separate from the guest's ``ReplayStatus``.
    """

    CAPTURED = "captured"
    """Every page of the range was declared mapped; host bytes were read."""
    UNMAPPED = "unmapped"
    """Some page had no declared mapping; no bytes were read."""


@dataclass(frozen=True, slots=True)
class MemoryRange:
    """One bounded flat byte range in the execution or observation contract."""

    address: int
    size: int

    def contains(self, address: int, size: int = 1) -> bool:
        """Test containment without wrapping an i386 linear address."""
        return self.address <= address and address + size <= self.address + self.size


@dataclass(frozen=True, slots=True)
class ReplayImage:
    """Immutable loaded bytes, declared executable ranges and file access.

    ``declared`` carries the actual file permission regions captured by
    ``image_from_project`` (main-object segments, or sections when the
    backend exposes no segments), including explicit no-access denials
    recorded as ``DeclaredAccess.NONE``. When empty, ``executable`` itself
    is the image's declared access contract: each executable range stands
    in as a file-level read+execute declaration. Other loaded bytes then
    have no declared access and are mapped without permission, never
    widened.
    """

    chunks: tuple[tuple[int, bytes], ...]
    executable: tuple[MemoryRange, ...]
    declared: tuple[DeclaredRegion, ...] = ()


@dataclass(frozen=True, slots=True)
class MemoryObservation:
    """Host-side byte projection of one requested observation range.

    ``status`` separates missing mapping evidence from the guest execution
    outcome, so an unreadable range is typed evidence rather than an absent
    or invented value. ``origins`` records the provenance of every covering
    page grant, keeping FILE-declared bytes distinct from UNSUPPORTED
    loaded bytes or caller scratch. ``data`` is empty unless the range was
    fully ``CAPTURED``.
    """

    address: int
    size: int
    status: ObservationStatus
    data: bytes
    origins: tuple[MappingOrigin, ...]


@dataclass(frozen=True, slots=True)
class ReplayVector:
    """Concrete registers, byte seeds, explicit scratch and observations.

    ``memory`` patches only seed host bytes inside already declared mapped
    pages; they never create a mapping or widen file permissions.
    ``mappings`` is the explicit caller scratch contract: each region must
    carry ``MappingOrigin.VECTOR`` and may not request ``EXECUTE``, and on
    pages without file coverage it supplies the declared guest access.
    ``observations`` are read-only host projections over declared mapped
    bytes and never contribute a declared region, so adding or removing an
    observation cannot change guest registers, writes, instruction count
    or execution outcome.
    """

    registers: tuple[tuple[str, int], ...]
    memory: tuple[tuple[int, bytes], ...] = ()
    observations: tuple[MemoryRange, ...] = ()
    mappings: tuple[DeclaredRegion, ...] = ()


@dataclass(frozen=True, slots=True)
class ReplayResult:
    """Full admitted integer state and concrete observations, never a proof.

    Integer registers, EFLAGS, loaded EIP and segment selectors are always
    captured. Explicit observation projections affect comparison only; they
    never remove fields from the backend result. ``observations`` records a
    typed ``MemoryObservation`` per requested range, including typed
    non-results for ranges without declared mapping coverage. ``pages`` is
    the typed per-page mapping evidence the guest actually enforced.
    """

    status: ReplayStatus
    registers: tuple[tuple[str, int], ...]
    observations: tuple[MemoryObservation, ...]
    writes: tuple[tuple[int, bytes], ...]
    instructions: int
    detail: str = ""
    pages: tuple[PageGrant, ...] = ()
    requested_observations: tuple[MemoryRange, ...] = ()
    """Required denominator copied from the vector, independently of results."""


@dataclass(frozen=True, slots=True)
class Flat32CaptureResult:
    """Typed boundary capture: executed-prefix outcome plus real guest state.

    ``status`` is the shared capture taxonomy, never a proof or agreement
    verdict; ``execution_status`` carries the exact underlying replay
    outcome and is ``None`` for capture-local stops (boundary reached,
    trace overflow) and for runs that never executed. Registers,
    observations and writes are the same projections replay materializes
    after the shared guarded loop. ``fetch_trace`` is the bounded fetch
    stream including the boundary fetch, ``trap`` the return-trap address
    the run was bound to, ``pages`` the resolved per-page grant evidence,
    and ``requested_observations`` the declared denominator copied from the
    vector. Nothing here infers a callable entry domain, a complete callee
    target set, or the caller's continuation from one trace.

    Page grants describe the configured emulator mapping, including padding.
    They do not establish byte-extent provenance for reusable vector patches;
    consumers must also check the original image and declared region extents.
    """

    status: CaptureStatus
    entry: int
    boundary: int
    execution_status: ReplayStatus | None
    registers: tuple[tuple[str, int], ...]
    observations: tuple[MemoryObservation, ...]
    writes: tuple[tuple[int, bytes], ...]
    instructions: int
    fetch_trace: tuple[int, ...]
    trap: int
    detail: str = ""
    pages: tuple[PageGrant, ...] = ()
    requested_observations: tuple[MemoryRange, ...] = ()
