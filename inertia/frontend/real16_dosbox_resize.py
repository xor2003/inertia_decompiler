"""Pure bounded DOSBox final-owned-MCB resize response contract.

Layer: Frontend/runtime package surface — shared service contract.
Responsibility: own once the DOSBox INT 21h / AH=4Ah resize response for
one explicitly declared, contiguous, nonwrapping MCB chain whose single
final ``Z`` block is owned by the declared PSP segment. The contract is
pure: it stages the low-register response and every modeled byte-span
write in native effect order for the calling environment to commit.
Program/native memory frames, arena bounds and executable/IVT overlap
checks are the consumer's obligation, never assumed here. The module
imports nothing beyond the standard library and the sibling
declared-resize owner for the shared INT 21h function identity, and must
stay importable without initializing angr or the ``X86_16`` platform
package.

Native anchors: ``dos.cpp`` dispatches AH=4Ah to ``DOS_ResizeMemory`` and
returns AX=ES with BX unchanged and CF clear on success — unlike the
KvikDOS profile, which preserves AX — while failure returns
AX=dos.errorcode, BX=clamped size and CF set. In ``dos_memory.cpp`` the
final-block paths are: equal size returns with no writes; shrink splits
off a new free ``Z`` header at ``(ES+BX)<<4`` carrying the old final
marker, owner 0 and size ``old-BX-1``, while the original header gains
an ``M`` marker, the requested size and the PSP owner; growth beyond the
final size fails with error 8 and BX=old size after writing the
unchanged size and PSP owner words. Both ``DOS_CompressMemory`` calls
are accounted for by declaration invariants, never modeled piecemeal:
the declared chain carries no adjacent free-owner pair, so the pre-call
compress cannot merge. Shrinking leaves the original block PSP-owned,
separating any free predecessor from the new final free block; the second
compress also cannot merge. A supplied current chain must equal every declared entry —
resizing from any later mutated state requires a new explicit authority
and otherwise refuses. Absent, incomplete or corrupted evidence produces
typed refusals, never DOS errors and never silent success.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from itertools import pairwise

from inertia.frontend.real16_resize_response8616 import INT21_RESIZE_FUNCTION_8616

__all__ = [
    "DOSBOX_ERR_INSUFFICIENT_MEMORY",
    "DOSBOX_MCB_BYTES",
    "DOSBOX_MCB_FINAL_MARKER",
    "DOSBOX_MCB_FREE_OWNER",
    "DOSBOX_MCB_MIDDLE_MARKER",
    "DOSBOX_RESIZE_FUNCTION",
    "DosboxMcbEntry",
    "DosboxResizePolicy",
    "DosboxResizeRefusal",
    "DosboxResizeResponse",
    "DosboxResizeWrite",
    "dosbox_resize_response",
]

# AH=4Ah is Resize Memory Block (SETBLOCK), projected once from the shared
# declared-service owner so both profiles name the same native function.
DOSBOX_RESIZE_FUNCTION: int = INT21_RESIZE_FUNCTION_8616

# Native MCB geometry and markers from DOS_MCB: one 16-byte paragraph
# holding marker byte 0, owner word at 1, size word at 3.
DOSBOX_MCB_BYTES: int = 16
DOSBOX_MCB_MIDDLE_MARKER: int = ord("M")
DOSBOX_MCB_FINAL_MARKER: int = ord("Z")
DOSBOX_MCB_FREE_OWNER: int = 0

# DOSERR_INSUFFICIENT_MEMORY is the only DOS error a validated final-block
# resize can reach; destroyed-MCB metadata is refused as corrupt evidence.
DOSBOX_ERR_INSUFFICIENT_MEMORY: int = 8

_WORD_MAXIMUM: int = 0xFFFF


def _require_word(value: int, field: str) -> None:
    """Reject truncated or Boolean machine-word declarations."""
    if type(value) is not int or not 0 <= value <= _WORD_MAXIMUM:
        raise ValueError(f"{field} must be a 16-bit integer")


def _require_chain_layout(chain: tuple[DosboxMcbEntry, ...]) -> None:
    """Prove strict contiguity, nonwrapping and no adjacent free pair.

    A chain with no adjacent free-owner blocks is a ``DOS_CompressMemory``
    no-op, which keeps both compress calls inside ``DOS_ResizeMemory``
    side-effect free on this declared state.
    """
    for previous, following in pairwise(chain):
        expected = previous.segment + previous.size + 1
        if expected > _WORD_MAXIMUM:
            raise ValueError("resize chain must not wrap the paragraph space")
        if following.segment != expected:
            raise ValueError("resize chain must be contiguous")
        if previous.owner == DOSBOX_MCB_FREE_OWNER and following.owner == DOSBOX_MCB_FREE_OWNER:
            raise ValueError("resize chain must not declare adjacent free blocks")


def _require_owned_final(chain: tuple[DosboxMcbEntry, ...], psp_segment: int) -> None:
    """Prove one final Z block owned by the declared PSP, inside range."""
    for entry in chain[:-1]:
        if entry.marker != DOSBOX_MCB_MIDDLE_MARKER:
            raise ValueError("resize chain must carry a single final Z block")
    final = chain[-1]
    if final.marker != DOSBOX_MCB_FINAL_MARKER:
        raise ValueError("resize chain must end in a final Z block")
    if final.data_segment > _WORD_MAXIMUM or final.segment + final.size > _WORD_MAXIMUM:
        raise ValueError("resize final block must not wrap the paragraph space")
    if final.owner != psp_segment:
        raise ValueError("resize final block must be owned by the declared PSP")


def _require_proven_inputs(segment: int, paragraphs: int, ax: int) -> None:
    """Require exact proven ES/BX words and the AH=4Ah service identity."""
    for field, value in (("ES", segment), ("BX", paragraphs), ("AX", ax)):
        _require_word(value, field)
    if ax >> 8 != DOSBOX_RESIZE_FUNCTION:
        raise ValueError("resize requires INT21/AH4A")


def _current_chain_refusal(
    policy: DosboxResizePolicy, current_chain: Sequence[bytes] | None
) -> DosboxResizeRefusal | None:
    """Bind supplied current MCB images to the declared initial entries.

    The admitted current chain must equal every declared entry: this model
    covers the initial resize only, so a mutated, truncated or extended
    chain refuses instead of silently passing corrupt metadata.
    """
    if current_chain is None:
        return DosboxResizeRefusal.CURRENT_CHAIN_ABSENT
    if len(current_chain) < len(policy.chain):
        return DosboxResizeRefusal.CURRENT_CHAIN_INCOMPLETE
    if len(current_chain) > len(policy.chain):
        return DosboxResizeRefusal.CURRENT_CHAIN_CHANGED
    current: list[bytes] = []
    for image in current_chain:
        if not isinstance(image, (bytes, bytearray, memoryview)):
            raise ValueError("current chain entries must be bytes")
        if len(image) != DOSBOX_MCB_BYTES:
            return DosboxResizeRefusal.CURRENT_CHAIN_INCOMPLETE
        current.append(bytes(image))
    # Validate the snapshots too: a mutable source or a non-byte memoryview
    # can have a different byte extent after conversion.
    if any(len(supplied) != DOSBOX_MCB_BYTES for supplied in current):
        return DosboxResizeRefusal.CURRENT_CHAIN_INCOMPLETE
    for supplied, declared in zip(current, policy.chain, strict=True):
        if supplied != declared.image:
            return DosboxResizeRefusal.CURRENT_CHAIN_CHANGED
    return None


def _growth_failure(policy: DosboxResizePolicy) -> DosboxResizeResponse:
    """Stage native error 8: clamped BX plus the same-value header writes."""
    final = policy.final_entry
    return DosboxResizeResponse(
        ax=DOSBOX_ERR_INSUFFICIENT_MEMORY, bx=final.size, carry=True, writes=(
            DosboxResizeWrite(final.address + 3, final.size.to_bytes(2, "little")),
            DosboxResizeWrite(final.address + 1, policy.psp_segment.to_bytes(2, "little")),
        ))


def _shrink_response(
    policy: DosboxResizePolicy, segment: int, paragraphs: int, new_header_before: bytes | None
) -> DosboxResizeResponse | DosboxResizeRefusal:
    """Stage the native split: shrunk block plus new free final header."""
    if new_header_before is None:
        return DosboxResizeRefusal.NEW_HEADER_UNPROVEN
    if not isinstance(new_header_before, (bytes, bytearray, memoryview)):
        raise ValueError("new header image must be bytes")
    if len(new_header_before) != DOSBOX_MCB_BYTES:
        return DosboxResizeRefusal.NEW_HEADER_UNPROVEN
    final = policy.final_entry
    base, header = final.address, (segment + paragraphs) << 4
    # Native effect order: old size, new type, old type, new size,
    # new owner, old owner. Only offsets 0/1..2/3..4 are ever written;
    # the new header's reserved bytes stay as ``new_header_before``.
    return DosboxResizeResponse(ax=segment, bx=paragraphs, carry=False, writes=(
        DosboxResizeWrite(base + 3, paragraphs.to_bytes(2, "little")),
        DosboxResizeWrite(header, bytes((DOSBOX_MCB_FINAL_MARKER,))),
        DosboxResizeWrite(base, bytes((DOSBOX_MCB_MIDDLE_MARKER,))),
        DosboxResizeWrite(header + 3, (final.size - paragraphs - 1).to_bytes(2, "little")),
        DosboxResizeWrite(header + 1, DOSBOX_MCB_FREE_OWNER.to_bytes(2, "little")),
        DosboxResizeWrite(base + 1, policy.psp_segment.to_bytes(2, "little")),
    ))


@dataclass(frozen=True, slots=True)
class DosboxMcbEntry:
    """One declared MCB paragraph and its exact current 16-byte image.

    ``segment`` is the MCB paragraph (the block's data segment is
    ``segment + 1``) and ``image`` is every byte of that paragraph.
    Ownership is never guessed: bytes 1..3 name the declared owner and
    bytes 3..5 the declared size in paragraphs.
    """

    segment: int
    image: bytes

    def __post_init__(self) -> None:
        """Require a word segment, complete image and native marker."""
        _require_word(self.segment, "MCB segment")
        if not isinstance(self.image, bytes):
            raise ValueError("MCB image must be immutable bytes")
        if len(self.image) != DOSBOX_MCB_BYTES:
            raise ValueError("MCB image must be exactly 16 bytes")
        if self.marker not in (DOSBOX_MCB_MIDDLE_MARKER, DOSBOX_MCB_FINAL_MARKER):
            raise ValueError("MCB image must carry a native M/Z marker")

    @property
    def marker(self) -> int:
        """MCB type byte: ``M`` middle or ``Z`` final."""
        return self.image[0]

    @property
    def owner(self) -> int:
        """Declared owner word; 0 marks a free block."""
        return int.from_bytes(self.image[1:3], "little")

    @property
    def size(self) -> int:
        """Declared block size in paragraphs, excluding this header."""
        return int.from_bytes(self.image[3:5], "little")

    @property
    def data_segment(self) -> int:
        """Paragraph of the block's first data byte."""
        return self.segment + 1

    @property
    def address(self) -> int:
        """Physical address of this MCB paragraph."""
        return self.segment << 4


@dataclass(frozen=True, slots=True)
class DosboxResizePolicy:
    """Explicit initial MCB chain authority for one DOSBox resize model.

    ``psp_segment`` is the declared nonzero PSP owner; ``chain`` is the
    entire initial MCB chain in address order, each entry carrying its
    paragraph and exact 16 bytes. Validation proves the chain is
    contiguous and nonwrapping in the 16-bit paragraph space, carries
    exactly one final ``Z`` entry, that final entry is owned by the PSP,
    and no adjacent pair of free blocks exists — so the
    ``DOS_CompressMemory`` calls inside ``DOS_ResizeMemory`` are provably
    no-ops on this declared state. The first MCB paragraph is read from
    the declared chain, never derived from the PSP segment.
    """

    psp_segment: int
    chain: tuple[DosboxMcbEntry, ...]

    def __post_init__(self) -> None:
        """Prove the declared chain's marker, contiguity and ownership invariants."""
        _require_word(self.psp_segment, "PSP segment")
        if self.psp_segment == 0:
            raise ValueError("resize PSP segment must be nonzero")
        if not isinstance(self.chain, tuple) or not self.chain:
            raise ValueError("resize requires the complete initial MCB chain")
        for entry in self.chain:
            if not isinstance(entry, DosboxMcbEntry):
                raise ValueError("resize chain entries must be declared MCB entries")
        _require_chain_layout(self.chain)
        _require_owned_final(self.chain, self.psp_segment)

    @property
    def final_entry(self) -> DosboxMcbEntry:
        """The single final ``Z`` block this policy may resize."""
        return self.chain[-1]


class DosboxResizeRefusal(StrEnum):
    """Missing or divergent allocator state, distinct from DOS errors."""

    #: No current chain was supplied at all.
    CURRENT_CHAIN_ABSENT = "current_chain_absent"
    #: The current chain is truncated or an entry is not a full 16 bytes.
    CURRENT_CHAIN_INCOMPLETE = "current_chain_incomplete"
    #: The current chain exists but differs from the declared initial
    #: entries — a later mutated allocator state needs new authority.
    CURRENT_CHAIN_CHANGED = "current_chain_changed"
    #: ES names anything other than the declared final block's data
    #: segment — other blocks and nonterminal resizes are undeclared.
    OTHER_BLOCK = "resize_other_block_undeclared"
    #: Shrinking needs the 16 preexisting bytes at the prospective new
    #: header paragraph; absent or incomplete bytes refuse.
    NEW_HEADER_UNPROVEN = "new_header_bytes_unproven"


@dataclass(frozen=True, slots=True)
class DosboxResizeWrite:
    """One exact modeled byte span, delivered in native effect order."""

    address: int
    data: bytes


@dataclass(frozen=True, slots=True)
class DosboxResizeResponse:
    """Complete low-register response plus every staged memory write."""

    ax: int
    bx: int
    carry: bool
    writes: tuple[DosboxResizeWrite, ...]


def dosbox_resize_response(
    policy: DosboxResizePolicy,
    *,
    segment: int,
    paragraphs: int,
    ax: int,
    current_chain: Sequence[bytes] | None,
    new_header_before: bytes | None = None,
) -> DosboxResizeResponse | DosboxResizeRefusal:
    """Stage a DOSBox final-block resize or an exact refusal without mutation.

    ``segment``/``paragraphs``/``ax`` are the proven ES/BX/AX inputs with
    AH required to be 4Ah. ``current_chain`` must supply every current MCB
    image in declared order and equal each declared entry; absent,
    incomplete or divergent state refuses. ``new_header_before`` must
    supply the complete 16 bytes at the prospective split header
    ``(ES+BX)<<4`` when shrinking — its reserved bytes are preserved by
    simply never being written. On success AX=ES, BX stays unchanged and
    CF clears; growth beyond the final size returns AX=8, BX=old size and
    CF set, still exposing the native same-value size/owner writes.
    """
    if not isinstance(policy, DosboxResizePolicy):
        raise ValueError("resize requires a declared DOSBox policy")
    _require_proven_inputs(segment, paragraphs, ax)
    refusal = _current_chain_refusal(policy, current_chain)
    if refusal is not None:
        return refusal
    final = policy.final_entry
    if segment != final.data_segment:
        return DosboxResizeRefusal.OTHER_BLOCK
    if paragraphs == final.size:
        # Equal size: native returns before any store.
        return DosboxResizeResponse(ax=segment, bx=paragraphs, carry=False, writes=())
    if paragraphs > final.size:
        return _growth_failure(policy)
    return _shrink_response(policy, segment, paragraphs, new_header_before)
