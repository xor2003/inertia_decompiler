"""Authenticated adapter: declared INT21 services → census relations.

Layer: dosunit concrete execution contracts.
Responsibility: mint the frontend's typed ``DeclaredInterruptService8616``
records only after authenticating a caller-declared ``ProgramEnvironment``
through the canonical DOS owners — ``program_version_query`` for the
AH=30/AL=00 selector admission and declared response, ``TailResizePolicy``
for the AH=4A allocator declaration, ``vector_bytes`` plus the declared
``ProgramMemoryLayout`` for live-IVT evidence, and arena containment for
the owned-handler refusal. This module performs no writes and invents no
state: every field of each record is declared environment data projected
through the canonical owners. Direction is tools → frontend, matching
``real16_program_boot``'s existing import of ``mz_invocation_source``; the
frontend never imports this adapter.

"""

from __future__ import annotations

from inertia.ir.real16_declared_interrupt8616 import (
    INT_FRAME_BYTES_8616,
    RESIZE_PRESERVED_LANES_8616,
    VERSION_PRESERVED_LANES_8616,
    DeclaredInterruptRefusal8616,
    DeclaredInterruptService8616,
    DeclaredResizeSurface8616,
    declared_environment_digest_8616,
    declared_ivt_slot_bytes_8616,
    declared_service_arena_8616,
)
from tools.dosunit.runtime.real16_program_boot import ProgramEnvironment
from tools.dosunit.runtime.real16_program_memory import ProgramMemoryLayout
from tools.dosunit.runtime.real16_program_resize import (
    RESIZE_FUNCTION,
    TailResizePolicy,
)
from tools.dosunit.runtime.real16_program_vectors import (
    DOS_VECTOR,
    VectorPolicy,
    vector_bytes,
)
from tools.dosunit.runtime.real16_program_version import (
    VERSION_FUNCTION,
    VERSION_SELECTOR,
    VersionAnswered,
    VersionPolicy,
    program_version_query,
)

__all__ = [
    "declared_int21_resize_service_8616",
    "declared_int21_version_service_8616",
]

# The preserved-lane surface stays owned by the frontend contract
# (``VERSION_PRESERVED_LANES_8616``); the response encoding is owned once by
# the shared platform-neutral contract ``real16_version_response8616``,
# which ``program_version_query`` itself consumes — so the minted answer
# and the census-side expectation derive from the same function object.


def _ivt_slot_bytes_8616(layout: ProgramMemoryLayout, vector: int) -> bytes | None:
    """Return the declared 4 IVT bytes for ``vector`` from the exact layout."""
    base = vector * 4
    for start, data in layout.chunks:
        if start <= base and base + 4 <= start + len(data):
            return bytes(data[base - start : base - start + 4])
    return None


def _arena_contains_8616(environment: ProgramEnvironment, linear: int) -> bool:
    """Return whether ``linear`` lies inside the declared allocation arena.

    Ownership is the whole granted arena — PSP, initialized image and the
    uninitialized BSS tail — never only the initialized layout chunks.
    """
    arena = declared_service_arena_8616(environment)
    return arena is not None and arena[0] <= linear < arena[1]


def _declared_ivt_evidence_8616(
    environment: ProgramEnvironment,
) -> bytes | DeclaredInterruptRefusal8616:
    """Authenticate the live 0x21 slot against the declared DOS entry.

    The declared layout must contain the slot bytes, they must equal the
    architectural far-pointer encoding of ``dos_entry``, and the entry must
    lie outside every program-owned byte. Returns the slot bytes on success.
    """
    vector_policy = environment.vector_policy
    if not isinstance(vector_policy, VectorPolicy):
        return DeclaredInterruptRefusal8616.ENVIRONMENT_INCOMPLETE
    layout = environment.memory_layout()
    slot = _ivt_slot_bytes_8616(layout, DOS_VECTOR)
    if (
        slot is None
        or slot != declared_ivt_slot_bytes_8616(environment, DOS_VECTOR)
        or slot != vector_bytes(vector_policy.dos_entry)
    ):
        return DeclaredInterruptRefusal8616.IVT_MISMATCH
    if _arena_contains_8616(environment, vector_policy.dos_entry.linear()):
        return DeclaredInterruptRefusal8616.OWNED_HANDLER
    return slot


def declared_int21_version_service_8616(
    environment: object,
    *,
    caller_addr: int,
    callsite_addr: int,
) -> DeclaredInterruptService8616 | DeclaredInterruptRefusal8616:
    """Mint the declared INT21/AH=30/AL=00 relation for one exact callsite.

    Authentication is canonical only:

    - ``environment`` must be a typed ``ProgramEnvironment`` carrying a
      ``VectorPolicy`` and a ``VersionPolicy`` — absent policies are an
      incomplete declaration, not a default;
    - ``program_version_query(policy, selector=VERSION_SELECTOR)`` must
      answer — the canonical owner owns selector admission, so a refused
      selector here can never reach the census;
    - the declared memory must contain the live 0x21 slot bytes equal to
      ``vector_bytes(dos_entry)`` — changed IVT bytes refuse;
    - ``dos_entry`` must lie outside every declared program-owned byte —
      a vector pointing into the loaded program is ``OWNED_HANDLER``.

    The minted record binds the exact caller head and callsite addresses the
    caller supplies; the census re-checks them against proven native site
    state. No register values, DOS version, or handler semantics are
    inferred from bytes, names, or opcodes here — only the explicit
    declaration is projected.
    """
    if not isinstance(environment, ProgramEnvironment):
        return DeclaredInterruptRefusal8616.ENVIRONMENT_INCOMPLETE
    if type(caller_addr) is not int or type(callsite_addr) is not int:
        return DeclaredInterruptRefusal8616.RELATION_MALFORMED
    if not (0 <= caller_addr <= 0xFFFFF and 0 <= callsite_addr <= 0xFFFFF):
        return DeclaredInterruptRefusal8616.RELATION_MALFORMED
    vector_policy = environment.vector_policy
    if not isinstance(vector_policy, VectorPolicy):
        return DeclaredInterruptRefusal8616.ENVIRONMENT_INCOMPLETE
    version_policy = environment.version_policy
    if not isinstance(version_policy, VersionPolicy):
        return DeclaredInterruptRefusal8616.ENVIRONMENT_INCOMPLETE
    answered = program_version_query(version_policy, selector=VERSION_SELECTOR)
    if not isinstance(answered, VersionAnswered):
        return DeclaredInterruptRefusal8616.SELECTOR_MISMATCH
    digest = declared_environment_digest_8616(environment)
    if digest is None:
        return DeclaredInterruptRefusal8616.ENVIRONMENT_INCOMPLETE
    slot = _declared_ivt_evidence_8616(environment)
    if not isinstance(slot, bytes):
        return slot
    return DeclaredInterruptService8616(
        caller_addr=caller_addr,
        callsite_addr=callsite_addr,
        vector=DOS_VECTOR,
        function=VERSION_FUNCTION,
        selector=VERSION_SELECTOR,
        answer_ax=answered.ax,
        answer_bx=answered.bx,
        answer_cx=answered.cx,
        frame_bytes=INT_FRAME_BYTES_8616,
        preserved=VERSION_PRESERVED_LANES_8616,
        ivt_entry_segment=vector_policy.dos_entry.segment,
        ivt_entry_offset=vector_policy.dos_entry.offset,
        ivt_slot_bytes=slot,
        environment_sha256=digest,
    )


def declared_int21_resize_service_8616(
    environment: object,
    *,
    caller_addr: int,
    callsite_addr: int,
) -> DeclaredInterruptService8616 | DeclaredInterruptRefusal8616:
    """Mint the declared INT21/AH=4A relation for one exact callsite.

    Authentication is canonical only:

    - ``environment`` must be a typed ``ProgramEnvironment`` carrying a
      ``VectorPolicy`` and a ``TailResizePolicy`` — an absent resize
      policy is an incomplete declaration, never a default allocator;
    - the declared memory must contain the live 0x21 slot bytes equal to
      ``vector_bytes(dos_entry)`` — changed IVT bytes refuse;
    - ``dos_entry`` must lie outside every declared program-owned byte —
      a vector pointing into the loaded program is ``OWNED_HANDLER``.

    The minted record declares no AL selector and no fixed answers — DOS
    AH=4A admits no selector byte, and the AX/BX/CF response plus the MCB
    write derive at consumption from proven ES/BX/AX inputs and the
    current metadata through the shared canonical owner
    ``resize_response_8616``. ``resize`` carries the declared allocator
    surface (block segment, metadata linear/bytes, capacity); the census
    re-derives it from the same environment digest. Site identity binds
    the exact caller head and callsite the caller supplies — never an
    address or name special case. No register values or handler
    semantics are inferred from bytes, names, or opcodes here.
    """
    if not isinstance(environment, ProgramEnvironment):
        return DeclaredInterruptRefusal8616.ENVIRONMENT_INCOMPLETE
    if type(caller_addr) is not int or type(callsite_addr) is not int:
        return DeclaredInterruptRefusal8616.RELATION_MALFORMED
    if not (0 <= caller_addr <= 0xFFFFF and 0 <= callsite_addr <= 0xFFFFF):
        return DeclaredInterruptRefusal8616.RELATION_MALFORMED
    vector_policy = environment.vector_policy
    if not isinstance(vector_policy, VectorPolicy):
        return DeclaredInterruptRefusal8616.ENVIRONMENT_INCOMPLETE
    resize_policy = environment.resize_policy
    if not isinstance(resize_policy, TailResizePolicy):
        return DeclaredInterruptRefusal8616.ENVIRONMENT_INCOMPLETE
    digest = declared_environment_digest_8616(environment)
    if digest is None:
        return DeclaredInterruptRefusal8616.ENVIRONMENT_INCOMPLETE
    slot = _declared_ivt_evidence_8616(environment)
    if not isinstance(slot, bytes):
        return slot
    return DeclaredInterruptService8616(
        caller_addr=caller_addr,
        callsite_addr=callsite_addr,
        vector=DOS_VECTOR,
        function=RESIZE_FUNCTION,
        selector=None,
        answer_ax=None,
        answer_bx=None,
        answer_cx=None,
        frame_bytes=INT_FRAME_BYTES_8616,
        preserved=RESIZE_PRESERVED_LANES_8616,
        ivt_entry_segment=vector_policy.dos_entry.segment,
        ivt_entry_offset=vector_policy.dos_entry.offset,
        ivt_slot_bytes=slot,
        environment_sha256=digest,
        resize=DeclaredResizeSurface8616(
            block_segment=resize_policy.segment,
            metadata_linear=resize_policy.metadata_address,
            metadata=resize_policy.initial_mcb,
            maximum=resize_policy.maximum,
        ),
    )
