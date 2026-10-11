"""Typed declared interrupt-service relation for the real16 invocation census.

Layer: IR — invocation-domain evidence contracts.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
Responsibility: carry one explicitly declared, source-bound conditional
interrupt-service relation between an authenticated adapter (dosunit) and the
invocation census. The relation declares the exact callsite, vector, proven
selectors, canonical service answer, architectural INT frame span, preserved
lanes, and live-IVT evidence bound to one declared environment digest. Version, resize and live-vector
declared kinds exist: the INT21/AH=30/AL=00 version relation carries fixed
response words, and the INT21/AH=4A resize relation carries a declared
allocator ``resize`` surface instead — its AX/BX/CF response and MCB writes
are computed at consumption from proven inputs through the shared canonical
owner, never declared as fixed answers. AH=35h/AH=25h relations bind the live
IVT model; proven AL selects the slot and query/update effects derive from
current path memory through the shared vector response owner. Nothing here re-implements DOS
semantics: the record is caller-declared evidence the census re-binds to
proven register state and rechecks structurally. A declared relation is
conditional evidence, never a universal DOS model.

"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from inertia.frontend.real16_dosbox_entry_policy import DosBoxInt21EntryPolicy8616, dosbox_entry_policy_matches
from inertia.frontend.real16_dosbox_resize import DosboxResizePolicy, DosboxResizeWrite
from inertia.frontend.real16_resize_response8616 import INT21_RESIZE_FUNCTION_8616, RESIZE_MCB_BYTES_8616
from inertia.frontend.real16_vector_response8616 import (
    INT21_GET_VECTOR_8616,
    INT21_SET_VECTOR_8616,
)
from inertia.frontend.real16_version_response8616 import (
    INT21_VERSION_FUNCTION_8616,
    INT21_VERSION_SELECTOR_8616,
    INT21_VERSION_VECTOR_8616,
    version_response_words_8616,
)
from inertia.frontend.x86_16.interrupt_contract import interrupt_vector_from_core_addr_8616

from .core import IRInstr, IRValue, MemSpace

__all__ = [
    "DECLARED_DOS_VECTOR_8616",
    "DECLARED_RESIZE_FUNCTION_8616",
    "DECLARED_VECTOR_FUNCTIONS_8616",
    "DECLARED_VERSION_FUNCTION_8616",
    "DECLARED_VERSION_SELECTOR_8616",
    "INT_FRAME_BYTES_8616",
    "IVT_IMAGE_BYTES_8616",
    "RESIZE_PRESERVED_LANES_8616",
    "VECTOR_GET_PRESERVED_LANES_8616",
    "VECTOR_SET_PRESERVED_LANES_8616",
    "VERSION_PRESERVED_LANES_8616",
    "DeclaredInterruptRefusal8616",
    "DeclaredInterruptService8616",
    "DeclaredResizeConsumption8616",
    "DeclaredResizeSurface8616",
    "DeclaredServiceConsumption8616",
    "DeclaredServiceExpectation8616",
    "DeclaredVectorConsumption8616",
    "DeclaredVectorSurface8616",
    "declared_environment_digest_8616",
    "declared_ivt_slot_bytes_8616",
    "declared_memory_span_8616",
    "declared_resize_consumption_8616",
    "declared_resize_expectation_8616",
    "declared_service_arena_8616",
    "declared_service_consumption_8616",
    "declared_service_expectation_8616",
    "declared_vector_consumption_8616",
    "declared_vector_expectation_8616",
    "interrupt_call_vector_8616",
    "service_relation_for_8616",
    "validated_declared_service_8616",
    "version_response_fields_8616",
]

# Architectural real-mode INT entry frame: pushed FLAGS, CS, IP (3 words).
INT_FRAME_BYTES_8616: int = 6

# The admitted declared services share the DOS vector: INT 21h / AH=30h /
# AL=00h (Get DOS Version) and INT 21h / AH=4Ah (Resize Memory Block).
# These names project the shared platform-neutral owners
# ``inertia.frontend.real16_version_response8616`` and
# ``inertia.frontend.real16_resize_response8616`` — the conditional contract
# shapes only; they do not assert any installed DOS.
DECLARED_DOS_VECTOR_8616: int = INT21_VERSION_VECTOR_8616
DECLARED_VERSION_FUNCTION_8616: int = INT21_VERSION_FUNCTION_8616
DECLARED_VERSION_SELECTOR_8616: int = INT21_VERSION_SELECTOR_8616
DECLARED_RESIZE_FUNCTION_8616: int = INT21_RESIZE_FUNCTION_8616

# INT21/AH=35h (Get Interrupt Vector) and INT21/AH=25h (Set Interrupt
# Vector) are the declared live-IVT services. These names project the shared
# platform-neutral owner ``inertia.frontend.real16_vector_response8616``.
DECLARED_VECTOR_FUNCTIONS_8616: tuple[int, int] = (
    INT21_GET_VECTOR_8616,
    INT21_SET_VECTOR_8616,
)

# The architectural IVT span every vector relation binds: all 256 slots.
IVT_IMAGE_BYTES_8616: int = 0x400

# Every 16-bit lane the canonical AH=35h contract leaves unchanged: the
# response writes only ES and BX, so ``ax`` (carrying the proven AL vector
# number) and every other lane are documented-preserved. ``sp`` is preserved
# across the answered service because the INT entry frame is popped by the
# architectural IRET.
VECTOR_GET_PRESERVED_LANES_8616: tuple[str, ...] = (
    "ax", "bp", "cs", "cx", "ds", "dx", "flags",
    "fs", "gs", "di", "si", "sp", "ss",
)

# AH=25h writes no registers at all — its only admitted effect is the four
# IVT slot bytes — so every 16-bit lane is documented-preserved.
VECTOR_SET_PRESERVED_LANES_8616: tuple[str, ...] = (
    "ax", "bp", "bx", "cs", "cx", "ds", "dx", "es",
    "flags", "fs", "gs", "di", "si", "sp", "ss",
)

# Every 16-bit lane the canonical version contract leaves unchanged: the
# response writes only the AX/BX/CX low halves; segments (CS/DS/ES/SS/FS/GS),
# pointers, DX/SI/DI/BP and FLAGS are documented-preserved. ``sp`` is
# preserved across the answered service because the INT entry frame is
# popped by the architectural IRET.
VERSION_PRESERVED_LANES_8616: tuple[str, ...] = (
    "bp", "cs", "ds", "dx", "es", "flags",
    "fs", "gs", "di", "si", "sp", "ss",
)

# Every 16-bit lane the canonical resize contract leaves unchanged: the
# response writes the AX/BX low halves and the carry flag bit, so ``cx``
# stays preserved but ``flags`` is a written lane — the consumption applies
# the canonical CF effect and never claims whole-word preservation.
RESIZE_PRESERVED_LANES_8616: tuple[str, ...] = (
    "bp", "cs", "cx", "ds", "dx", "es",
    "fs", "gs", "di", "si", "sp", "ss",
)


# Compatibility projection: the documented AH=30h response encoding is
# owned solely by ``version_response_words_8616`` in the shared
# platform-neutral contract — the same function object the dosunit
# canonical mint consumes. The census recomputes it from the boot's
# declared environment at consumption so a relation whose effect fields
# were replaced coherently under an unchanged environment cannot keep
# authority.
version_response_fields_8616: Callable[[int, int, int, int], tuple[int, int, int]] = (
    version_response_words_8616
)


class DeclaredInterruptRefusal8616(StrEnum):
    """Typed refusal reasons for declared interrupt-service evidence."""

    #: No relation bound this exact callsite/vector/selector environment.
    RELATION_ABSENT = "declared_service_absent"
    #: The presented record is untyped or carries out-of-domain fields.
    RELATION_MALFORMED = "declared_service_malformed"
    #: The relation's declared environment digest differs from the boot's.
    ENVIRONMENT_MISMATCH = "declared_service_environment_mismatch"
    #: The relation's declared IVT evidence is internally inconsistent.
    IVT_MISMATCH = "declared_service_ivt_mismatch"
    #: The declared DOS entry lies inside the loaded program image.
    OWNED_HANDLER = "declared_service_owned_handler"
    #: The architectural frame region aliases the declared IVT slot.
    FRAME_ALIAS = "declared_service_frame_alias"
    #: Proven AH/AL at the callsite does not equal the declared selectors.
    SELECTOR_MISMATCH = "declared_service_selector_mismatch"
    #: The declared environment cannot present a complete service surface.
    ENVIRONMENT_INCOMPLETE = "declared_service_environment_incomplete"


@dataclass(frozen=True, slots=True)
class DeclaredResizeSurface8616:
    """The declared allocator surface one INT21/AH=4A relation binds.

    ``block_segment`` is the declared tail-block owner segment,
    ``metadata_linear`` the physical start of its 16-byte MCB (always
    ``(block_segment - 1) << 4``), ``metadata`` the declared initial MCB
    bytes, and ``maximum`` the declared capacity in paragraphs. Every field
    is re-derived from the environment's declared resize policy at
    consumption, so a forged surface fails field equality.

    ``dosbox`` carries the complete declared DOSBox chain policy when the
    bound environment selected the ``dosbox_initial_owned_tail`` profile:
    the four legacy fields then project the chain's final block
    (``block_segment`` is ``final.data_segment``, ``metadata_linear`` is
    ``final.address``, ``metadata`` is ``final.image`` and ``maximum`` is
    ``final.size``), while ``dosbox`` binds the entire declared chain and
    its PSP. ``dosbox is None`` keeps the KvikDOS tail profile, where the
    four fields alone are authoritative.
    """

    block_segment: int
    metadata_linear: int
    metadata: bytes
    maximum: int
    dosbox: DosboxResizePolicy | None = None


@dataclass(frozen=True, slots=True)
class DeclaredVectorSurface8616:
    """The declared live-IVT surface one INT21/AH=35h or AH=25h relation binds.

    ``ivt`` is the complete declared initial 1024-byte interrupt vector
    table image, re-derived from the environment's declared memory layout
    at consumption — a forged surface fails field equality there. The
    surface binds no answers and no target vector: the proven AL lane at
    the callsite is the *number* input the shared canonical owner
    ``vector_response_8616`` consumes, and every effect derives from the
    live slot bytes at consumption, never from mint-time snapshots.
    """

    ivt: bytes


@dataclass(frozen=True, slots=True)
class DeclaredInterruptService8616:
    """One caller-declared conditional interrupt-service relation.

    The adapter mints this record only after authenticating the declared
    environment through the canonical dosunit service owners; the census
    re-binds it to *proven* selector state at the exact callsite and to the
    identical declared environment via ``environment_sha256``. All fields are
    plain bounded data — no object identities, no callbacks — so replay
    equality is field equality.

    ``ivt_slot_bytes`` is the declared 4-byte IVT content for ``vector`` at
    mint time; ``ivt_entry_segment``/``ivt_entry_offset`` name the far target
    those bytes encode. ``frame_bytes`` is the architectural entry-frame span
    the census accounts as a transient write below proven SP. ``preserved``
    lists the 16-bit lanes the declared service provably leaves unchanged.

    Three declared shapes exist. A *version* relation (``resize`` and
    ``vectors`` both ``None``) carries the admitted AL selector and the
    declared ``answer_*`` response words the census installs directly. A
    *resize* relation (``resize`` is a typed surface) declares no selector
    or fixed answers — AH=4A defines no AL contract, and the AX/BX/CF
    response plus the MCB write derive from proven ES/BX/AX inputs and
    current MCB bytes through the shared canonical owner at consumption.
    A *vector* relation (``vectors`` is a typed surface) likewise declares
    no selector or fixed answers — AH=35h reads the live IVT slot proven AL
    selects into ES:BX, and AH=25h writes proven DS:DX into that slot; both
    derive at consumption through the shared canonical owner
    ``vector_response_8616``.
    """

    caller_addr: int
    callsite_addr: int
    vector: int
    function: int
    selector: int | None
    answer_ax: int | None
    answer_bx: int | None
    answer_cx: int | None
    frame_bytes: int
    preserved: tuple[str, ...]
    ivt_entry_segment: int
    ivt_entry_offset: int
    ivt_slot_bytes: bytes
    environment_sha256: str
    resize: DeclaredResizeSurface8616 | None = None
    dosbox_int21_entry_policy: DosBoxInt21EntryPolicy8616 | None = None
    vectors: DeclaredVectorSurface8616 | None = None


@dataclass(frozen=True, slots=True)
class DeclaredServiceConsumption8616:
    """One census consumption of a declared version-service relation.

    Retained on the proven domain so the exact declared evidence consumed at
    the boundary stays visible and replays bit-identically:
    ``relation_sha256`` binds the consumed record fields, ``frame_linear`` the
    proven stack region the architectural frame transiently writes.
    """

    callsite_addr: int
    vector: int
    function: int
    selector: int
    answer_ax: int
    answer_bx: int
    answer_cx: int
    frame_linear: int
    frame_bytes: int
    relation_sha256: str


@dataclass(frozen=True, slots=True)
class DeclaredResizeConsumption8616:
    """One census consumption of a declared tail-resize relation.

    Retained on the proven domain so the conditional crossing stays public
    evidence: ``request_ax`` is the proven full AX input, ``answer_ax``/
    ``answer_bx``/``carry`` the canonical response installed on the lanes,
    ``metadata_linear``/``metadata_before``/``metadata_after`` the modeled
    MCB write evidence, and ``frame_linear`` the proven stack region the
    architectural frame transiently writes. ``relation_sha256`` binds the
    consumed record fields so the consumption replays bit-identically.

    ``dosbox_writes``/``dosbox_current_chain``/``dosbox_new_header_before``
    are the optional DOSBox consumption evidence: the ordered writes the
    reviewed ``dosbox_resize_response`` staged, the exact current MCB
    images the caller proved against the declared chain, and the complete
    16 bytes observed at the split-header paragraph when shrinking. All
    three stay ``None`` under the KvikDOS tail profile, where
    ``metadata_before``/``metadata_after`` remain authoritative.
    """

    callsite_addr: int
    vector: int
    function: int
    request_ax: int
    answer_ax: int
    answer_bx: int
    carry: bool
    metadata_linear: int
    metadata_before: bytes
    metadata_after: bytes
    frame_linear: int
    frame_bytes: int
    relation_sha256: str
    dosbox_writes: tuple[DosboxResizeWrite, ...] | None = None
    dosbox_current_chain: tuple[bytes, ...] | None = None
    dosbox_new_header_before: bytes | None = None


@dataclass(frozen=True, slots=True)
class DeclaredVectorConsumption8616:
    """One census consumption of a declared get/set-vector relation.

    Retained on the proven domain so the conditional crossing stays public
    evidence and replays bit-identically: ``number`` is the proven AL
    selector naming the live IVT slot, ``slot_before``/``slot_after`` the
    exact live bytes observed and committed (``slot_after`` is ``None`` for
    AH=35h, which writes no memory), ``answer_es``/``answer_bx`` the
    projected far pointer (``None`` for AH=25h, which writes no registers),
    and ``request_ds``/``request_dx`` the proven set-vector inputs
    (``None`` for AH=35h). ``frame_linear`` is the proven stack region the
    architectural frame transiently writes; ``relation_sha256`` binds the
    consumed record fields.
    """

    callsite_addr: int
    vector: int
    function: int
    number: int
    slot_linear: int
    slot_before: bytes
    slot_after: bytes | None
    answer_es: int | None
    answer_bx: int | None
    request_ds: int | None
    request_dx: int | None
    frame_linear: int
    frame_bytes: int
    relation_sha256: str


def _relation_sha256_8616(relation: DeclaredInterruptService8616) -> str:
    """Digest every field one consumed relation binds, including ``resize``."""
    return hashlib.sha256(
        "|".join(
            str(field_value)
            for field_value in (
                relation.caller_addr,
                relation.callsite_addr,
                relation.vector,
                relation.function,
                relation.selector,
                relation.answer_ax,
                relation.answer_bx,
                relation.answer_cx,
                relation.frame_bytes,
                relation.preserved,
                relation.ivt_entry_segment,
                relation.ivt_entry_offset,
                relation.ivt_slot_bytes,
                relation.environment_sha256,
                relation.resize,
                relation.dosbox_int21_entry_policy,
                relation.vectors,
            )
        ).encode("utf-8")
    ).hexdigest()


def declared_service_consumption_8616(
    relation: DeclaredInterruptService8616,
    *,
    frame_linear: int,
) -> DeclaredServiceConsumption8616:
    """Project one consumed version relation into the retained record."""
    return DeclaredServiceConsumption8616(
        callsite_addr=relation.callsite_addr,
        vector=relation.vector,
        function=relation.function,
        selector=relation.selector if relation.selector is not None else 0,
        answer_ax=relation.answer_ax if relation.answer_ax is not None else 0,
        answer_bx=relation.answer_bx if relation.answer_bx is not None else 0,
        answer_cx=relation.answer_cx if relation.answer_cx is not None else 0,
        frame_linear=frame_linear,
        frame_bytes=relation.frame_bytes,
        relation_sha256=_relation_sha256_8616(relation),
    )


def declared_resize_consumption_8616(
    relation: DeclaredInterruptService8616,
    *,
    frame_linear: int,
    request_ax: int,
    answer_ax: int,
    answer_bx: int,
    carry: bool,
    metadata_before: bytes,
    metadata_after: bytes,
    dosbox_writes: tuple[DosboxResizeWrite, ...] | None = None,
    dosbox_current_chain: tuple[bytes, ...] | None = None,
    dosbox_new_header_before: bytes | None = None,
) -> DeclaredResizeConsumption8616:
    """Project one consumed resize relation into the retained record.

    The ``dosbox_*`` arguments carry the DOSBox profile's ordered write,
    current-chain and split-header evidence; they stay ``None`` under the
    KvikDOS tail profile.
    """
    surface = relation.resize
    return DeclaredResizeConsumption8616(
        callsite_addr=relation.callsite_addr,
        vector=relation.vector,
        function=relation.function,
        request_ax=request_ax,
        answer_ax=answer_ax,
        answer_bx=answer_bx,
        carry=carry,
        metadata_linear=(
            surface.metadata_linear if surface is not None else 0
        ),
        metadata_before=metadata_before,
        metadata_after=metadata_after,
        frame_linear=frame_linear,
        frame_bytes=relation.frame_bytes,
        relation_sha256=_relation_sha256_8616(relation),
        dosbox_writes=dosbox_writes,
        dosbox_current_chain=dosbox_current_chain,
        dosbox_new_header_before=dosbox_new_header_before,
    )


def declared_vector_consumption_8616(
    relation: DeclaredInterruptService8616,
    *,
    frame_linear: int,
    number: int,
    slot_before: bytes,
    slot_after: bytes | None,
    answer_es: int | None,
    answer_bx: int | None,
    request_ds: int | None,
    request_dx: int | None,
) -> DeclaredVectorConsumption8616:
    """Project one consumed vector relation into the retained record."""
    return DeclaredVectorConsumption8616(
        callsite_addr=relation.callsite_addr,
        vector=relation.vector,
        function=relation.function,
        number=number,
        slot_linear=number * 4,
        slot_before=slot_before,
        slot_after=slot_after,
        answer_es=answer_es,
        answer_bx=answer_bx,
        request_ds=request_ds,
        request_dx=request_dx,
        frame_linear=frame_linear,
        frame_bytes=relation.frame_bytes,
        relation_sha256=_relation_sha256_8616(relation),
    )


class _ServiceEnvironmentSurface8616(Protocol):
    """Declared-environment fields the digest consumes.

    The canonical ``ProgramEnvironment`` satisfies this shape; the digest only
    reads, never mutates.
    """

    psp_segment: int
    allocation: bytes
    registers: tuple[tuple[str, int], ...]
    fs: int
    gs: int
    version_policy: object
    resize_policy: object
    vector_policy: object
    dosbox_int21_entry_policy: DosBoxInt21EntryPolicy8616 | None

    def memory_layout(self) -> object:
        """Return the declared initial memory layout."""


class _VersionPolicySurface8616(Protocol):
    """Typed fields of one declared version-response policy."""

    major: int
    minor: int
    oem: int
    serial: int


class _ResizePolicySurface8616(Protocol):
    """Typed fields of one declared tail-resize policy."""

    segment: int
    initial_mcb: bytes
    maximum: int
    metadata_address: int


class _VectorPolicySurface8616(Protocol):
    """Typed fields of one declared DOS vector policy."""

    dos_entry: object


class _SegOffsetSurface8616(Protocol):
    """Typed segmented coordinate used by declared policies."""

    segment: int
    offset: int


class _MemoryLayoutSurface8616(Protocol):
    """Declared initial-memory chunks as (linear, bytes) pairs."""

    chunks: tuple[tuple[int, bytes], ...]


@dataclass(frozen=True, slots=True)
class DeclaredServiceExpectation8616:
    """The canonical relation fields one declared environment authenticates.

    Derived at consumption from the environment's own declared policy
    fields — never from the presented relation — so a record whose effect
    fields were replaced coherently under an unchanged environment fails
    field equality here. ``caller_addr``/``callsite_addr`` are intentionally
    absent: site identity binds separately against the proven boundary.
    For a version expectation the selector and answers are bounded ints and
    ``resize``/``vectors`` are ``None``; for a resize expectation they are
    ``None`` and ``resize`` carries the derived allocator surface; for a
    vector expectation ``vectors`` carries the declared initial IVT image.
    """

    vector: int
    function: int
    selector: int | None
    answer_ax: int | None
    answer_bx: int | None
    answer_cx: int | None
    frame_bytes: int
    preserved: tuple[str, ...]
    ivt_entry_segment: int
    ivt_entry_offset: int
    ivt_slot_bytes: bytes
    resize: DeclaredResizeSurface8616 | None = None
    dosbox_int21_entry_policy: DosBoxInt21EntryPolicy8616 | None = None
    vectors: DeclaredVectorSurface8616 | None = None


def declared_service_arena_8616(environment: object) -> tuple[int, int] | None:
    """Return the declared arena ``[start, end)`` the environment grants.

    The DOS entry must lie outside it: a handler inside program-allocated
    memory is program-owned, not an external declared service. ``None``
    means the environment cannot present a well-formed allocation.
    """
    try:
        env = cast(_ServiceEnvironmentSurface8616, environment)
        psp_segment = env.psp_segment
        allocation = env.allocation
    except (AttributeError, TypeError):
        return None
    if (
        type(psp_segment) is not int
        or not 0 <= psp_segment <= 0xFFFF
        or not isinstance(allocation, bytes | bytearray)
        or not allocation
        or len(allocation) % 16
    ):
        return None
    start = psp_segment << 4
    end = start + len(allocation)
    if end > 0x100000:
        return None
    return start, end


def _ivt_expectation_surface_8616(
    environment: object,
) -> tuple[int, int, bytes] | DeclaredInterruptRefusal8616:
    """Re-derive the declared DOS entry and live slot bytes both kinds share.

    Returns ``(entry_segment, entry_offset, slot_bytes)`` on success. The
    entry must sit inside the architectural word domain, the declared layout
    must contain the 0x21 slot bytes, and they must equal the architectural
    offset-then-segment encoding of the declared entry.
    """
    entry = _vector_entry_fields_8616(environment)
    if entry is None:
        return DeclaredInterruptRefusal8616.ENVIRONMENT_INCOMPLETE
    entry_segment, entry_offset = entry
    if not (0 <= entry_segment <= 0xFFFF and 0 <= entry_offset <= 0xFFFF):
        return DeclaredInterruptRefusal8616.RELATION_MALFORMED
    slot = declared_ivt_slot_bytes_8616(environment, DECLARED_DOS_VECTOR_8616)
    if slot is None or len(slot) != 4:
        return DeclaredInterruptRefusal8616.IVT_MISMATCH
    expected_slot = (
        entry_offset.to_bytes(2, "little") + entry_segment.to_bytes(2, "little")
    )
    if slot != expected_slot:
        return DeclaredInterruptRefusal8616.IVT_MISMATCH
    return entry_segment, entry_offset, slot


def declared_service_expectation_8616(
    environment: object,
) -> DeclaredServiceExpectation8616 | DeclaredInterruptRefusal8616:
    """Derive the canonical declared-service fields from the environment.

    This is the consumption-side authority for the INT21/AH=30/AL=00 kind:
    the census recomputes the admitted surface — response words, preserved
    lanes, frame span, DOS entry and initial IVT slot bytes — from the
    boot's declared policies and layout. A presented relation must equal
    every field; anything the environment cannot supply refuses.
    """
    version_fields = _version_policy_fields_8616(environment)
    if version_fields is None:
        return DeclaredInterruptRefusal8616.ENVIRONMENT_INCOMPLETE
    major, minor, oem, serial = version_fields
    if not 0 <= serial <= 0xFFFFFF:
        return DeclaredInterruptRefusal8616.RELATION_MALFORMED
    ivt = _ivt_expectation_surface_8616(environment)
    if type(ivt) is not tuple:
        return cast(DeclaredInterruptRefusal8616, ivt)
    entry_segment, entry_offset, slot = ivt
    answer_ax, answer_bx, answer_cx = version_response_fields_8616(
        major, minor, oem, serial
    )
    return DeclaredServiceExpectation8616(
        vector=DECLARED_DOS_VECTOR_8616,
        function=DECLARED_VERSION_FUNCTION_8616,
        selector=DECLARED_VERSION_SELECTOR_8616,
        answer_ax=answer_ax,
        answer_bx=answer_bx,
        answer_cx=answer_cx,
        frame_bytes=INT_FRAME_BYTES_8616,
        preserved=VERSION_PRESERVED_LANES_8616,
        ivt_entry_segment=entry_segment,
        ivt_entry_offset=entry_offset,
        ivt_slot_bytes=slot,
        resize=None,
        dosbox_int21_entry_policy=cast(_ServiceEnvironmentSurface8616, environment).dosbox_int21_entry_policy,
    )


def _dosbox_resize_surface_8616(policy: DosboxResizePolicy) -> DeclaredResizeSurface8616:
    """Project the declared DOSBox chain's final block into the surface.

    The four legacy fields name the resizable final ``Z`` block; ``dosbox``
    binds the entire declared chain and its PSP so every chain byte is
    carried by surface equality and the environment digest.
    """
    final = policy.final_entry
    return DeclaredResizeSurface8616(
        block_segment=final.data_segment,
        metadata_linear=final.address,
        metadata=final.image,
        maximum=final.size,
        dosbox=policy,
    )


def _resize_policy_fields_8616(
    environment: object,
) -> DeclaredResizeSurface8616 | None:
    """Project the declared resize-policy surface, or ``None`` when absent.

    ``None`` covers an undeclared policy and a policy whose fields cannot
    present the bounded surface; the caller decides which refusal to name.
    The profile is dispatched on the declared policy's type, never on a
    segment value: a ``DosboxResizePolicy`` projects its final block and
    binds the whole chain, anything else is read as the legacy tail shape.
    """
    try:
        policy = cast(
            _ServiceEnvironmentSurface8616, environment
        ).resize_policy
    except (AttributeError, TypeError):
        return None
    if policy is None:
        return None
    if type(policy) is DosboxResizePolicy:
        return _dosbox_resize_surface_8616(policy)
    try:
        surface = cast(_ResizePolicySurface8616, policy)
        segment = surface.segment
        maximum = surface.maximum
        metadata = surface.initial_mcb
        metadata_linear = surface.metadata_address
    except (AttributeError, TypeError):
        return None
    if not (
        type(segment) is int
        and 0 <= segment <= 0xFFFF
        and type(maximum) is int
        and 0 <= maximum <= 0xFFFF
        and type(metadata_linear) is int
        and 0 <= metadata_linear <= 0xFFFFF
        and isinstance(metadata, bytes | bytearray)
        and len(metadata) == RESIZE_MCB_BYTES_8616
    ):
        return None
    return DeclaredResizeSurface8616(
        block_segment=segment,
        metadata_linear=metadata_linear,
        metadata=bytes(metadata),
        maximum=maximum,
    )


def declared_resize_expectation_8616(
    environment: object,
) -> DeclaredServiceExpectation8616 | DeclaredInterruptRefusal8616:
    """Derive the canonical declared-resize fields from the environment.

    The consumption-side authority for the INT21/AH=4A kind: the census
    recomputes the declared allocator surface — block segment, metadata
    linear, the complete initial MCB bytes and capacity — plus the shared
    DOS entry, slot bytes, frame span and preserved lanes. The declared
    layout must present the identical MCB bytes at the policy's metadata
    address; a missing or divergent span is an incomplete declaration, not
    allocator state to infer.
    """
    resize = _resize_policy_fields_8616(environment)
    if resize is None:
        return DeclaredInterruptRefusal8616.ENVIRONMENT_INCOMPLETE
    if resize.metadata_linear != (resize.block_segment - 1) << 4:
        return DeclaredInterruptRefusal8616.RELATION_MALFORMED
    env = cast(_ServiceEnvironmentSurface8616, environment)
    if resize.dosbox is not None and not dosbox_entry_policy_matches(
        env.dosbox_int21_entry_policy, resize.dosbox.psp_segment
    ):
        # The DOSBox allocator exists only under the explicitly declared
        # same-backend INT21 entry premise; an absent or foreign one is an
        # incomplete declaration, never an inferable default.
        return DeclaredInterruptRefusal8616.ENVIRONMENT_INCOMPLETE
    ivt = _ivt_expectation_surface_8616(environment)
    if type(ivt) is not tuple:
        return cast(DeclaredInterruptRefusal8616, ivt)
    entry_segment, entry_offset, slot = ivt
    declared = declared_memory_span_8616(
        environment, resize.metadata_linear, RESIZE_MCB_BYTES_8616
    )
    if declared is None or declared != resize.metadata:
        return DeclaredInterruptRefusal8616.ENVIRONMENT_INCOMPLETE
    if resize.dosbox is not None and not _dosbox_chain_declared_8616(environment, resize.dosbox):
        return DeclaredInterruptRefusal8616.ENVIRONMENT_INCOMPLETE
    return DeclaredServiceExpectation8616(
        vector=DECLARED_DOS_VECTOR_8616,
        function=DECLARED_RESIZE_FUNCTION_8616,
        selector=None,
        answer_ax=None,
        answer_bx=None,
        answer_cx=None,
        frame_bytes=INT_FRAME_BYTES_8616,
        preserved=RESIZE_PRESERVED_LANES_8616,
        ivt_entry_segment=entry_segment,
        ivt_entry_offset=entry_offset,
        ivt_slot_bytes=slot,
        resize=resize,
        dosbox_int21_entry_policy=cast(_ServiceEnvironmentSurface8616, environment).dosbox_int21_entry_policy,
    )


def declared_vector_expectation_8616(
    environment: object, function: int
) -> DeclaredServiceExpectation8616 | DeclaredInterruptRefusal8616:
    """Derive the canonical declared-vector fields from the environment.

    The consumption-side authority for the INT21/AH=35h and AH=25h kinds:
    the census recomputes the admitted surface — shared DOS entry, slot
    bytes, frame span, the per-function preserved lanes and the complete
    declared initial IVT image — from the boot's declared policies and
    layout. ``function`` is the proven AH constant at the callsite; only
    the two declared vector functions derive an expectation. The declared
    layout must present the complete 1024-byte IVT — a missing or truncated
    span is an incomplete declaration, never live table state to infer.
    """
    if type(function) is not int:
        return DeclaredInterruptRefusal8616.RELATION_MALFORMED
    if function == INT21_GET_VECTOR_8616:
        preserved = VECTOR_GET_PRESERVED_LANES_8616
    elif function == INT21_SET_VECTOR_8616:
        preserved = VECTOR_SET_PRESERVED_LANES_8616
    else:
        return DeclaredInterruptRefusal8616.RELATION_MALFORMED
    ivt = _ivt_expectation_surface_8616(environment)
    if type(ivt) is not tuple:
        return cast(DeclaredInterruptRefusal8616, ivt)
    entry_segment, entry_offset, slot = ivt
    declared_ivt = declared_memory_span_8616(environment, 0, IVT_IMAGE_BYTES_8616)
    if declared_ivt is None:
        return DeclaredInterruptRefusal8616.ENVIRONMENT_INCOMPLETE
    return DeclaredServiceExpectation8616(
        vector=DECLARED_DOS_VECTOR_8616,
        function=function,
        selector=None,
        answer_ax=None,
        answer_bx=None,
        answer_cx=None,
        frame_bytes=INT_FRAME_BYTES_8616,
        preserved=preserved,
        ivt_entry_segment=entry_segment,
        ivt_entry_offset=entry_offset,
        ivt_slot_bytes=slot,
        resize=None,
        dosbox_int21_entry_policy=cast(_ServiceEnvironmentSurface8616, environment).dosbox_int21_entry_policy,
        vectors=DeclaredVectorSurface8616(ivt=declared_ivt),
    )


def _dosbox_chain_declared_8616(environment: object, policy: DosboxResizePolicy) -> bool:
    """Require every declared DOSBox MCB image to be present initial memory."""
    return all(
        declared_memory_span_8616(environment, entry.address, RESIZE_MCB_BYTES_8616)
        == entry.image
        for entry in policy.chain
    )


def declared_memory_span_8616(
    environment: object, linear: int, size: int
) -> bytes | None:
    """Return the declared ``size`` bytes at ``linear`` or ``None``."""
    try:
        layout = cast(
            _ServiceEnvironmentSurface8616, environment
        ).memory_layout()
        chunks = cast(_MemoryLayoutSurface8616, layout).chunks
    except (AttributeError, TypeError):
        return None
    if (
        not isinstance(chunks, tuple)
        or type(linear) is not int
        or linear < 0
        or type(size) is not int
        or size <= 0
    ):
        return None
    for start, data in chunks:
        if type(start) is not int or not isinstance(data, bytes | bytearray):
            continue
        if start <= linear and linear + size <= start + len(data):
            return bytes(data[linear - start : linear - start + size])
    return None


def declared_ivt_slot_bytes_8616(environment: object, vector: int) -> bytes | None:
    """Return the declared 4 IVT bytes for ``vector`` or ``None``."""
    return declared_memory_span_8616(environment, vector * 4, 4)


def _version_policy_fields_8616(
    environment: object,
) -> tuple[int, int, int, int] | None:
    """Project the declared version-policy fields or ``None``."""
    try:
        policy = cast(
            _VersionPolicySurface8616,
            cast(_ServiceEnvironmentSurface8616, environment).version_policy,
        )
        fields = (policy.major, policy.minor, policy.oem, policy.serial)
    except (AttributeError, TypeError):
        return None
    if any(type(value) is not int or value < 0 for value in fields):
        return None
    return fields


def _vector_entry_fields_8616(environment: object) -> tuple[int, int] | None:
    """Project the declared DOS entry coordinates or ``None``."""
    try:
        dos_entry = cast(
            _SegOffsetSurface8616,
            cast(
                _VectorPolicySurface8616,
                cast(_ServiceEnvironmentSurface8616, environment).vector_policy,
            ).dos_entry,
        )
        fields = (dos_entry.segment, dos_entry.offset)
    except (AttributeError, TypeError):
        return None
    if any(type(value) is not int or value < 0 for value in fields):
        return None
    return fields


def _service_policy_fields_8616(environment: object) -> tuple[int, ...] | None:
    """Project the declared version/vector policy fields or ``None``."""
    version_fields = _version_policy_fields_8616(environment)
    entry_fields = _vector_entry_fields_8616(environment)
    if version_fields is None or entry_fields is None:
        return None
    return (*version_fields, *entry_fields)


def _resize_digest_part_8616(resize: DeclaredResizeSurface8616 | None) -> bytes:
    """Serialize the declared resize surface into the environment digest.

    The KvikDOS tail profile keeps its exact legacy ``R`` encoding; the
    DOSBox profile uses a distinct ``R\x02`` section binding the declared
    PSP, the chain length and every entry's segment plus exact 16-byte
    image — the whole chain, not only the projected final block.
    """
    if resize is None:
        return b"R\x00"
    common = (
        resize.block_segment.to_bytes(2, "little")
        + resize.maximum.to_bytes(4, "little")
        + resize.metadata_linear.to_bytes(4, "little")
        + resize.metadata
    )
    dosbox = resize.dosbox
    if dosbox is None:
        return b"R" + common
    return (
        b"R\x02"
        + common
        + dosbox.psp_segment.to_bytes(2, "little")
        + len(dosbox.chain).to_bytes(4, "little")
        + b"".join(
            entry.segment.to_bytes(2, "little") + entry.image
            for entry in dosbox.chain
        )
    )


def declared_environment_digest_8616(environment: object) -> str | None:
    """Digest the complete declared service surface of one environment.

    The digest binds every field a declared service relation may depend on:
    the PSP segment, the exact declared register file (including AL), FS/GS,
    the declared vector-policy DOS entry (required — ``None`` refuses), the
    declared version-policy response fields and the declared resize-policy
    allocator surface — for the DOSBox chain profile the declared PSP plus
    every chain entry's segment and exact image, not only the projected
    final block — each bound as present fields or an explicit absence
    marker, and the full declared initial-memory contents reachable through
    ``memory_layout`` — which includes every declared IVT and MCB byte.
    ``None`` means the environment cannot present the complete declared
    surface — any relation minted against it is unbindable.
    """
    try:
        env = cast(_ServiceEnvironmentSurface8616, environment)
        psp_segment = env.psp_segment
        entry_policy = env.dosbox_int21_entry_policy
        registers = env.registers
        fs = env.fs
        gs = env.gs
        layout = env.memory_layout()
        chunks = cast(_MemoryLayoutSurface8616, layout).chunks
    except (AttributeError, TypeError):
        return None
    if not isinstance(registers, tuple) or not isinstance(chunks, tuple):
        return None
    words = (psp_segment, fs, gs)
    if (any(type(value) is not int or not 0 <= value <= 0xFFFF for value in words)
            or not dosbox_entry_policy_matches(entry_policy, psp_segment)):
        return None
    parts = [
        b"D\x00" if entry_policy is None else b"D" + entry_policy.psp_segment.to_bytes(2, "little"),
        psp_segment.to_bytes(2, "little"),
        fs.to_bytes(2, "little"),
        gs.to_bytes(2, "little"),
    ]
    for pair in sorted(registers):
        if not isinstance(pair, tuple) or len(pair) != 2:
            return None
        name, value = pair
        if type(name) is not str or type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            return None
        parts.append(name.encode("ascii") + b"=" + value.to_bytes(4, "little"))
    entry_fields = _vector_entry_fields_8616(environment)
    if entry_fields is None:
        return None
    parts.append(b"E" + b"".join(field.to_bytes(2, "little") for field in entry_fields))
    version_fields = _version_policy_fields_8616(environment)
    parts.append(
        b"V\x00"
        if version_fields is None
        else b"V" + b"".join(field.to_bytes(4, "little") for field in version_fields)
    )
    parts.append(_resize_digest_part_8616(_resize_policy_fields_8616(environment)))
    for start, data in sorted(chunks):
        if type(start) is not int or not isinstance(data, bytes | bytearray):
            return None
        parts.append(start.to_bytes(8, "little") + bytes(data))
    return hashlib.sha256(b"|".join(parts)).hexdigest()


def interrupt_call_vector_8616(instruction: IRInstr) -> int | None:
    """Return the interrupt vector a CALL row lifts to, or ``None``.

    The lifter models ``int imm`` as a CALL to the synthetic core address for
    the vector; anything else is an ordinary near/far call row and returns
    ``None`` so the ordinary boundary-proof path owns it.
    """
    if instruction.op != "CALL" or len(instruction.args) != 1:
        return None
    target = instruction.args[0]
    if not isinstance(target, IRValue) or target.space is not MemSpace.CONST:
        return None
    if type(target.const) is not int:
        return None
    return interrupt_vector_from_core_addr_8616(target.const)


def _resize_surface_valid_8616(surface: object) -> bool:
    """Return whether one declared resize surface is structurally bounded.

    A DOSBox surface additionally requires its typed chain policy to be
    internally coherent with the projected final-block fields — a forged
    surface mixing a policy with divergent fields fails closed.
    """
    if type(surface) is not DeclaredResizeSurface8616:
        return False
    bounded = (
        type(surface.block_segment) is int
        and 0 <= surface.block_segment <= 0xFFFF
        and type(surface.metadata_linear) is int
        and 0 <= surface.metadata_linear <= 0xFFFFF
        and surface.metadata_linear == (surface.block_segment - 1) << 4
        and type(surface.maximum) is int
        and 0 <= surface.maximum <= 0xFFFF
        and type(surface.metadata) is bytes
        and len(surface.metadata) == RESIZE_MCB_BYTES_8616
    )
    if not bounded:
        return False
    dosbox = surface.dosbox
    if dosbox is None:
        return True
    if type(dosbox) is not DosboxResizePolicy:
        return False
    final = dosbox.final_entry
    return (
        dosbox.psp_segment == surface.block_segment
        and final.data_segment == surface.block_segment
        and final.address == surface.metadata_linear
        and final.image == surface.metadata
        and final.size == surface.maximum
    )


def _vector_surface_valid_8616(surface: object) -> bool:
    """Return whether one declared vector surface is structurally bounded."""
    return (
        type(surface) is DeclaredVectorSurface8616
        and type(surface.ivt) is bytes
        and len(surface.ivt) == IVT_IMAGE_BYTES_8616
    )


def _service_shape_fields_valid_8616(
    relation: DeclaredInterruptService8616,
) -> bool:
    """Enforce the exclusive version/resize/vector effect-field shapes.

    A version relation (``resize`` and ``vectors`` both absent) must carry
    a bounded selector and three word answers; a resize relation must
    carry a coherent ``resize`` surface with the selector and answers
    absent; a vector relation must carry a coherent ``vectors`` surface
    with the selector and answers absent — a record mixing shapes is
    malformed, never partially admitted.
    """
    if relation.dosbox_int21_entry_policy is not None and type(relation.dosbox_int21_entry_policy) is not DosBoxInt21EntryPolicy8616:
        return False
    if relation.resize is None and relation.vectors is None:
        if (
            type(relation.selector) is not int
            or not 0 <= relation.selector <= 0xFF
        ):
            return False
        return all(
            type(value) is int and 0 <= value <= 0xFFFF
            for value in (
                relation.answer_ax,
                relation.answer_bx,
                relation.answer_cx,
            )
        )
    if relation.vectors is not None:
        if not (
            relation.resize is None
            and relation.selector is None
            and relation.answer_ax is None
            and relation.answer_bx is None
            and relation.answer_cx is None
            and relation.function in DECLARED_VECTOR_FUNCTIONS_8616
            and _vector_surface_valid_8616(relation.vectors)
        ):
            return False
        expected_preserved = (
            VECTOR_GET_PRESERVED_LANES_8616
            if relation.function == INT21_GET_VECTOR_8616
            else VECTOR_SET_PRESERVED_LANES_8616
        )
        return relation.preserved == expected_preserved
    if relation.resize is None:
        return False
    if not (
        relation.selector is None
        and relation.answer_ax is None
        and relation.answer_bx is None
        and relation.answer_cx is None
        and _resize_surface_valid_8616(relation.resize)
    ):
        return False
    # A DOSBox allocator relation only exists under the explicitly
    # declared same-backend INT21 entry premise.
    return (
        relation.resize.dosbox is None
        or type(relation.dosbox_int21_entry_policy) is DosBoxInt21EntryPolicy8616
    )


def validated_declared_service_8616(
    relation: object,
) -> DeclaredInterruptService8616 | DeclaredInterruptRefusal8616:
    """Revalidate one declared relation's typed fields before consumption.

    This is the census-side structural check: every scalar inside its
    domain, the declared IVT slot bytes equal the architectural
    offset+segment encoding of the declared entry, the frame span is the
    architectural six bytes, preserved lanes are typed names, and the
    environment digest is a present SHA-256 hex string. The declared version, resize and vector
    shapes are enforced exclusively: a version relation must carry a
    bounded selector and three word answers with ``resize`` absent; a
    resize relation must carry a coherent ``resize`` surface with selector
    and answers absent; a vector relation carries only its initial IVT surface
    and per-function preservation fields. Field *truth* is bound at the site by
    selector/digest equality — this only rejects malformed records.
    """
    if type(relation) is not DeclaredInterruptService8616:
        return DeclaredInterruptRefusal8616.RELATION_MALFORMED
    address_fields = (relation.caller_addr, relation.callsite_addr)
    if any(
        type(value) is not int or not 0 <= value <= 0xFFFFF
        for value in address_fields
    ):
        return DeclaredInterruptRefusal8616.RELATION_MALFORMED
    word_fields = (
        relation.ivt_entry_segment,
        relation.ivt_entry_offset,
    )
    if any(type(value) is not int or not 0 <= value <= 0xFFFF for value in word_fields):
        return DeclaredInterruptRefusal8616.RELATION_MALFORMED
    if type(relation.vector) is not int or not 0 <= relation.vector <= 0xFF:
        return DeclaredInterruptRefusal8616.RELATION_MALFORMED
    if type(relation.function) is not int or not 0 <= relation.function <= 0xFF:
        return DeclaredInterruptRefusal8616.RELATION_MALFORMED
    if not _service_shape_fields_valid_8616(relation):
        return DeclaredInterruptRefusal8616.RELATION_MALFORMED
    return _service_evidence_fields_8616(relation)


def _service_evidence_fields_8616(
    relation: DeclaredInterruptService8616,
) -> DeclaredInterruptService8616 | DeclaredInterruptRefusal8616:
    """Validate the frame/preserved/IVT/digest fields of one relation."""
    if relation.frame_bytes != INT_FRAME_BYTES_8616:
        return DeclaredInterruptRefusal8616.RELATION_MALFORMED
    if not isinstance(relation.preserved, tuple) or not all(
        type(name) is str for name in relation.preserved
    ):
        return DeclaredInterruptRefusal8616.RELATION_MALFORMED
    expected_slot = (
        relation.ivt_entry_offset.to_bytes(2, "little")
        + relation.ivt_entry_segment.to_bytes(2, "little")
    )
    if type(relation.ivt_slot_bytes) is not bytes or relation.ivt_slot_bytes != expected_slot:
        return DeclaredInterruptRefusal8616.IVT_MISMATCH
    if (
        type(relation.environment_sha256) is not str
        or len(relation.environment_sha256) != 64
    ):
        return DeclaredInterruptRefusal8616.ENVIRONMENT_INCOMPLETE
    return relation


def _expectation_matches_8616(
    checked: DeclaredInterruptService8616,
    expectation: DeclaredServiceExpectation8616,
) -> bool:
    """Require every canonical effect field to equal the derived surface."""
    return (
        checked.vector == expectation.vector
        and checked.function == expectation.function
        and checked.selector == expectation.selector
        and checked.answer_ax == expectation.answer_ax
        and checked.answer_bx == expectation.answer_bx
        and checked.answer_cx == expectation.answer_cx
        and checked.frame_bytes == expectation.frame_bytes
        and checked.preserved == expectation.preserved
        and checked.ivt_entry_segment == expectation.ivt_entry_segment
        and checked.ivt_entry_offset == expectation.ivt_entry_offset
        and checked.ivt_slot_bytes == expectation.ivt_slot_bytes
        and checked.resize == expectation.resize
        and checked.dosbox_int21_entry_policy == expectation.dosbox_int21_entry_policy
        and checked.vectors == expectation.vectors
    )


def _relation_matches_site_8616(
    checked: DeclaredInterruptService8616,
    *,
    caller_addr: int,
    callsite_addr: int,
    vector: int,
    function: int,
    selector: int,
    environment_sha256: str | None,
    environment: object,
) -> DeclaredInterruptService8616 | DeclaredInterruptRefusal8616 | None:
    """Bind one validated relation to the proven site.

    Returns ``None`` when the record simply does not name this site
    (caller head, callsite or vector differ) — unmatched is not a
    refusal. Otherwise the declared kind picks its canonical
    expectation: the version shape also binds the proven AL selector,
    while the resize and vector shapes declare no AL contract — their
    selector is structurally absent; the full proven AX binds at
    consumption for resize, and the proven AL vector number binds for a
    vector relation.
    """
    if not (
        checked.caller_addr == caller_addr
        and checked.callsite_addr == callsite_addr
        and checked.vector == vector
    ):
        return None
    if checked.environment_sha256 != environment_sha256:
        return DeclaredInterruptRefusal8616.ENVIRONMENT_MISMATCH
    if checked.function != function:
        return DeclaredInterruptRefusal8616.SELECTOR_MISMATCH
    if checked.resize is not None:
        expectation = declared_resize_expectation_8616(environment)
    elif checked.vectors is not None:
        expectation = declared_vector_expectation_8616(environment, function)
    else:
        if checked.selector != selector:
            return DeclaredInterruptRefusal8616.SELECTOR_MISMATCH
        expectation = declared_service_expectation_8616(environment)
    if type(expectation) is not DeclaredServiceExpectation8616:
        return cast(DeclaredInterruptRefusal8616, expectation)
    if not _expectation_matches_8616(checked, expectation):
        return DeclaredInterruptRefusal8616.ENVIRONMENT_MISMATCH
    return checked


def service_relation_for_8616(
    relations: tuple[DeclaredInterruptService8616, ...],
    *,
    caller_addr: int,
    callsite_addr: int,
    vector: int,
    function: int,
    selector: int,
    environment_sha256: str | None,
    environment: object,
) -> DeclaredInterruptService8616 | DeclaredInterruptRefusal8616:
    """Bind exactly one authenticated relation to this exact boundary.

    A relation applies only when every declared identity field matches the
    *proven* site: identical caller head, identical callsite, identical
    vector, declared function equal to the proven AH constant, the
    declared environment digest equal to the boot's — AND every effect
    field equal to the canonical surface re-derived from that environment
    (``declared_service_expectation_8616`` for a version relation,
    ``declared_resize_expectation_8616`` for a resize relation). A version
    relation additionally requires declared selector equality against the
    proven AL constant; a resize relation declares no AL contract — AH=4A
    admits every proven selector, and the full proven AX is bound at
    consumption. A record replaced coherently under an unchanged
    environment refuses on the re-derived fields, not on mint provenance.
    Exactly-one matching wins; zero is ``RELATION_ABSENT``, two-or-more
    and malformed records refuse rather than pick.
    """
    matched: list[DeclaredInterruptService8616] = []
    malformed = False
    for candidate in relations:
        checked = validated_declared_service_8616(candidate)
        if type(checked) is not DeclaredInterruptService8616:
            malformed = True
            continue
        verdict = _relation_matches_site_8616(
            checked,
            caller_addr=caller_addr,
            callsite_addr=callsite_addr,
            vector=vector,
            function=function,
            selector=selector,
            environment_sha256=environment_sha256,
            environment=environment,
        )
        if verdict is None:
            continue
        if type(verdict) is not DeclaredInterruptService8616:
            return cast(DeclaredInterruptRefusal8616, verdict)
        matched.append(verdict)
    if len(matched) == 1:
        return matched[0]
    if malformed:
        return DeclaredInterruptRefusal8616.RELATION_MALFORMED
    return DeclaredInterruptRefusal8616.RELATION_ABSENT
