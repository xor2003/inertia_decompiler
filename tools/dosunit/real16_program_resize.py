"""An explicit native-compatible tail-allocation resize contract.

Layer: dosunit concrete environment.
Responsibility: model INT21/AH4A for a declared single final Kvikdos MCB,
including metadata writes, carry/errors and preserved register halves. This
is an opt-in backend environment profile, not a general DOS allocator.
Other blocks and nonterminal chains require additional state and refuse.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

MCB_BYTES: int = 16
NATIVE_PROCESS_ID: int = 0x192
NATIVE_PSP_SEGMENT: int = 0x100
NATIVE_SIGNATURE: bytes = b"\xb2KV1KPR0G"
CONVENTIONAL_END: int = 0xA000
RECEIPT_BYTES: int = 45


def _word(value: int, field: str) -> None:
    """Reject truncated or Boolean machine-word declarations."""
    if type(value) is not int or not 0 <= value <= 0xFFFF:
        raise ValueError(f"{field} must be a 16-bit integer")


def _metadata_error(mcb: bytes, maximum: int) -> bool:
    """Check the native first/final MCB invariants, before any update."""
    return (
        len(mcb) != MCB_BYTES
        or mcb[7:] != NATIVE_SIGNATURE
        or int.from_bytes(mcb[1:3], "little") != NATIVE_PROCESS_ID
        or mcb[5:7] != b"\0\0"
        or int.from_bytes(mcb[3:5], "little") > maximum
        or mcb[0] not in (ord("Z"), ord("M"))
    )


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
    """Stage native final-block resize or an exact DOS error without mutation."""
    for field, value in (("ES", segment), ("BX", paragraphs), ("AX", ax)):
        _word(value, field)
    if ax >> 8 != 0x4A:
        raise ValueError("resize requires INT21/AH4A")
    if len(metadata) != MCB_BYTES:
        raise ValueError("resize requires every current MCB byte")
    if segment != policy.segment:
        return ResizeRefused(ResizeRefusal.OTHER_BLOCK)
    if _metadata_error(metadata, policy.maximum):
        return ResizeAccepted(7, paragraphs, True, metadata)
    if metadata[0] != ord("Z"):
        return ResizeRefused(ResizeRefusal.CHAIN)
    if paragraphs > policy.maximum:
        return ResizeAccepted(8, policy.maximum, True, metadata)
    changed = metadata[:3] + paragraphs.to_bytes(2, "little") + metadata[5:]
    return ResizeAccepted(ax, paragraphs, False, changed)


def resize_event_data(
    policy: TailResizePolicy, paragraphs: int, ax: int, before: bytes, result: ResizeAccepted,
) -> bytes:
    """Retain request, response and both metadata states for checked receipts."""
    return (b"\x21\x4a" + policy.segment.to_bytes(2, "little")
            + paragraphs.to_bytes(2, "little") + ax.to_bytes(2, "little")
            + result.ax.to_bytes(2, "little") + result.bx.to_bytes(2, "little")
            + bytes((result.carry,)) + before + result.metadata)


def resize_receipt_complete(data: bytes) -> bool:
    """Recompute a receipt's complete response; malformed effects never admit."""
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


def resize_policy_document(policy: TailResizePolicy | None) -> dict[str, object] | None:
    """Serialize every initial allocation field into boot and environment identity."""
    if policy is None:
        return None
    return {"profile": "kvikdos_single_tail", "segment": policy.segment, "mcb_hex": policy.initial_mcb.hex()}


def parse_resize_policy(value: object) -> TailResizePolicy | None:
    """Parse the opt-in native profile; absence retains the existing refusal."""
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"profile", "segment", "mcb_hex"}:
        raise ValueError("dos_resize requires profile, segment and mcb_hex")
    if value["profile"] != "kvikdos_single_tail":
        raise ValueError("unsupported resize profile")
    segment, metadata = value["segment"], value["mcb_hex"]
    if type(segment) is not int or not isinstance(metadata, str) or len(metadata) != MCB_BYTES * 2:
        raise ValueError("resize requires an integer segment and hexadecimal metadata")
    return TailResizePolicy(segment, bytes.fromhex(metadata))
