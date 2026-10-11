"""An explicit native-compatible tail-allocation resize contract.

Layer: dosunit concrete environment.
Responsibility: model INT21/AH4A for a declared single final Kvikdos MCB,
including metadata writes, carry/errors and preserved register halves, and
to carry the reviewed DOSBox declared initial MCB-chain profile as pure
declaration plumbing. Both are opt-in backend environment profiles, not
general DOS allocators. Other blocks and nonterminal chains require
additional state and refuse.
The KvikDOS service identity, native MCB invariants and the pure response
computation project the single shared platform-neutral owner
``inertia.frontend.real16_resize_response8616``; the DOSBox profile's
policy and response semantics project the reviewed
``inertia.frontend.real16_dosbox_resize`` owner — this module keeps its
public names and the policy/receipt/serialization plumbing but never
re-implements either canonical semantics.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.frontend.real16_dosbox_resize import DOSBOX_MCB_BYTES, DosboxMcbEntry, DosboxResizePolicy
from inertia.frontend.real16_resize_response8616 import (
    INT21_RESIZE_FUNCTION_8616,
    RESIZE_CONVENTIONAL_END_8616,
    RESIZE_MCB_BYTES_8616,
    RESIZE_NATIVE_PROCESS_ID_8616,
    RESIZE_NATIVE_PSP_SEGMENT_8616,
    RESIZE_NATIVE_SIGNATURE_8616,
    ResizeRefusal8616,
    resize_metadata_error_8616,
    resize_response_8616,
)
from tools.dosunit.runtime.real16_dosbox_resize_receipt import (
    DOSBOX_RESIZE_RECEIPT_PREFIX,
    dosbox_resize_receipt_complete,
)

MCB_BYTES: int = RESIZE_MCB_BYTES_8616
NATIVE_PROCESS_ID: int = RESIZE_NATIVE_PROCESS_ID_8616
NATIVE_PSP_SEGMENT: int = RESIZE_NATIVE_PSP_SEGMENT_8616
NATIVE_SIGNATURE: bytes = RESIZE_NATIVE_SIGNATURE_8616
CONVENTIONAL_END: int = RESIZE_CONVENTIONAL_END_8616
RECEIPT_BYTES: int = 45

# INT21/AH4A identity constant, projected once from the shared owner — the
# resize twin of ``VERSION_FUNCTION`` in real16_program_version.
RESIZE_FUNCTION: int = INT21_RESIZE_FUNCTION_8616

# Bound this runtime profile before decoding snapshots or comparing chunks.
# The frontend model supports broader declarations; this explicit runner
# applicability limit keeps initialization, census and receipts inexpensive.
DOSBOX_CHAIN_ENTRY_LIMIT: int = 64
DOSBOX_RESIZE_PROFILE: str = "dosbox_initial_owned_tail"


def _word(value: int, field: str) -> None:
    """Reject truncated or Boolean machine-word declarations."""
    if type(value) is not int or not 0 <= value <= 0xFFFF:
        raise ValueError(f"{field} must be a 16-bit integer")


def _metadata_error(mcb: bytes, maximum: int) -> bool:
    """Check the native first/final MCB invariants, before any update."""
    return bool(resize_metadata_error_8616(mcb, maximum))


@dataclass(frozen=True, slots=True)
class TailResizePolicy:
    """Exact initial metadata for one final block and its declared capacity.

    The physical arena remains readable after shrink, as in real mode. Only
    allocation ownership changes; no new physical bytes are invented. The
    supplied arena must reach the native conventional-memory ceiling so growth
    and insufficient-memory results have the same available-size denominator.
    """

    segment: int
    initial_mcb: bytes

    def __post_init__(self) -> None:
        """Validate an owned first/final block, preserving every reserved byte."""
        _word(self.segment, "resize segment")
        if self.segment != NATIVE_PSP_SEGMENT:
            raise ValueError("native resize profile requires its fixed loader PSP segment")
        if not isinstance(self.initial_mcb, bytes):
            raise ValueError("resize metadata must be immutable bytes")
        if _metadata_error(self.initial_mcb, self.maximum) or self.initial_mcb[0] != ord("Z"):
            raise ValueError("resize requires a valid first/final native MCB")

    @property
    def maximum(self) -> int:
        """Largest possible block, excluding its preceding metadata paragraph."""
        return CONVENTIONAL_END - self.segment

    @property
    def metadata_address(self) -> int:
        """Physical start of the explicitly supplied preceding MCB paragraph."""
        return (self.segment - 1) * 16

    def check_arena(self, segment: int, size: int) -> None:
        """Require exact agreement between declared allocation and metadata."""
        initial_size = int.from_bytes(self.initial_mcb[3:5], "little")
        if segment != self.segment or size != self.maximum * 16 or initial_size != self.maximum:
            raise ValueError("resize policy requires the complete initial tail allocation")


class ResizeRefusal(StrEnum):
    """Missing environment state, distinct from a modeled DOS error result."""

    OTHER_BLOCK = "resize_other_block_undeclared"
    CHAIN = "resize_nonterminal_chain_undeclared"


@dataclass(frozen=True, slots=True)
class ResizeRefused:
    """An operation whose required allocator state is outside this declaration."""

    reason: ResizeRefusal


@dataclass(frozen=True, slots=True)
class ResizeAccepted:
    """Complete low-register response and replacement MCB, staged before commit."""

    ax: int
    bx: int
    carry: bool
    metadata: bytes


def program_resize_call(
    policy: TailResizePolicy, *, segment: int, paragraphs: int, ax: int, metadata: bytes,
) -> ResizeAccepted | ResizeRefused:
    """Stage native final-block resize or an exact DOS error without mutation.

    The response itself is computed once by the shared platform-neutral
    owner ``resize_response_8616``; this adapter only binds the declared
    policy's block segment and capacity and wraps the shared records in
    the established public types.
    """
    result = resize_response_8616(
        block_segment=policy.segment,
        maximum=policy.maximum,
        segment=segment,
        paragraphs=paragraphs,
        ax=ax,
        metadata=metadata,
    )
    if isinstance(result, ResizeRefusal8616):
        return ResizeRefused(ResizeRefusal(result.value))
    return ResizeAccepted(
        ax=result.ax, bx=result.bx, carry=result.carry, metadata=result.metadata
    )


def resize_event_data(
    policy: TailResizePolicy, paragraphs: int, ax: int, before: bytes, result: ResizeAccepted,
) -> bytes:
    """Retain request, response and both metadata states for checked receipts."""
    return (b"\x21\x4a" + policy.segment.to_bytes(2, "little")
            + paragraphs.to_bytes(2, "little") + ax.to_bytes(2, "little")
            + result.ax.to_bytes(2, "little") + result.bx.to_bytes(2, "little")
            + bytes((result.carry,)) + before + result.metadata)


def resize_receipt_complete(data: bytes) -> bool:
    """Recompute a receipt's complete response; malformed effects never admit.

    DOSBox-profile events carry the explicit ``DOSBOX_RESIZE_RECEIPT_PREFIX``
    schema and dispatch to its canonical verifier; every other payload takes
    the unchanged legacy KvikDOS receipt path.
    """
    if isinstance(data, bytes) and data.startswith(DOSBOX_RESIZE_RECEIPT_PREFIX):
        return dosbox_resize_receipt_complete(data)
    if len(data) != RECEIPT_BYTES or data[:2] != b"\x21\x4a" or data[12] not in (0, 1):
        return False
    if data[7] != 0x4A:
        return False
    segment = int.from_bytes(data[2:4], "little")
    if segment != NATIVE_PSP_SEGMENT:
        return False
    # Rebuild only the immutable profile declaration. Current (possibly
    # corrupted) guest metadata is checked independently by the service owner.
    initial = (b"Z" + NATIVE_PROCESS_ID.to_bytes(2, "little")
               + (CONVENTIONAL_END - segment).to_bytes(2, "little") + b"\0\0" + NATIVE_SIGNATURE)
    policy = TailResizePolicy(segment, initial)
    before = data[13:29]
    result = program_resize_call(policy, segment=segment,
                                 paragraphs=int.from_bytes(data[4:6], "little"),
                                 ax=int.from_bytes(data[6:8], "little"), metadata=before)
    if isinstance(result, ResizeRefused):
        return False
    return (result.ax == int.from_bytes(data[8:10], "little")
            and result.bx == int.from_bytes(data[10:12], "little")
            and result.carry == bool(data[12]) and result.metadata == data[29:])


def resize_policy_document(
    policy: TailResizePolicy | DosboxResizePolicy | None,
) -> dict[str, object] | None:
    """Serialize every initial allocation field into boot and environment identity."""
    if policy is None:
        return None
    if isinstance(policy, TailResizePolicy):
        return {"profile": "kvikdos_single_tail", "segment": policy.segment, "mcb_hex": policy.initial_mcb.hex()}
    if isinstance(policy, DosboxResizePolicy):
        return {
            "profile": DOSBOX_RESIZE_PROFILE,
            "psp_segment": policy.psp_segment,
            "chain": [
                {"segment": entry.segment, "mcb_hex": entry.image.hex()}
                for entry in policy.chain
            ],
        }
    raise ValueError("resize policy requires a declared typed profile")


def _parse_dosbox_resize(document: dict[str, object]) -> DosboxResizePolicy:
    """Parse the bounded declared DOSBox initial owned-tail chain profile.

    The chain list is length-capped before any entry byte is decoded by the
    explicit runtime applicability budget. Every admissible entry precedes
    the PSP-owned final block, so ``psp_segment`` also tightens the bound.
    Each entry must carry its exact 32 hexadecimal characters —
    no whitespace, no partial bytes.
    """
    if set(document) != {"profile", "psp_segment", "chain"}:
        raise ValueError("dosbox resize requires profile, psp_segment and chain")
    psp_segment, chain = document["psp_segment"], document["chain"]
    if type(psp_segment) is not int or not isinstance(chain, list):
        raise ValueError("dosbox resize requires an integer PSP segment and a chain list")
    limit = min(psp_segment, DOSBOX_CHAIN_ENTRY_LIMIT)
    if not chain or len(chain) > limit:
        raise ValueError("dosbox resize chain exceeds the paragraph bound")
    entries: list[DosboxMcbEntry] = []
    for item in chain:
        if not isinstance(item, dict) or set(item) != {"segment", "mcb_hex"}:
            raise ValueError("dosbox resize chain entries require segment and mcb_hex")
        segment, text = item["segment"], item["mcb_hex"]
        if type(segment) is not int or not isinstance(text, str) or len(text) != DOSBOX_MCB_BYTES * 2:
            raise ValueError("dosbox resize requires an integer segment and 32 hexadecimal characters")
        image = bytes.fromhex(text)
        if len(image) * 2 != len(text):
            raise ValueError("dosbox resize hexadecimal bytes must not contain whitespace")
        entries.append(DosboxMcbEntry(segment, image))
    return DosboxResizePolicy(psp_segment, tuple(entries))


def parse_resize_policy(value: object) -> TailResizePolicy | DosboxResizePolicy | None:
    """Parse the opt-in native profile; absence retains the existing refusal."""
    if value is None:
        return None
    if not isinstance(value, dict) or not isinstance(value.get("profile"), str):
        raise ValueError("dos_resize requires a declared profile")
    if value["profile"] == DOSBOX_RESIZE_PROFILE:
        return _parse_dosbox_resize(value)
    if set(value) != {"profile", "segment", "mcb_hex"}:
        raise ValueError("dos_resize requires profile, segment and mcb_hex")
    if value["profile"] != "kvikdos_single_tail":
        raise ValueError("unsupported resize profile")
    segment, metadata = value["segment"], value["mcb_hex"]
    if type(segment) is not int or not isinstance(metadata, str) or len(metadata) != MCB_BYTES * 2:
        raise ValueError("resize requires an integer segment and hexadecimal metadata")
    return TailResizePolicy(segment, bytes.fromhex(metadata))
