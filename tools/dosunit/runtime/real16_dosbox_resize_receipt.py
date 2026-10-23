"""Layer: dosunit concrete execution contracts.

Responsibility: encode bounded, canonical DOSBox AH4A event receipts and
independently re-run the frontend model to verify their exact ordered effects.
The checksum detects payload corruption; it supplies no semantic authority.
Boot/environment identity must bind the recorded premises externally. Receipt
limits are explicit applicability bounds, never limits on the frontend model.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from inertia.frontend.real16_dosbox_resize import (
    DOSBOX_MCB_BYTES,
    DosboxMcbEntry,
    DosboxResizePolicy,
    DosboxResizeRefusal,
    DosboxResizeResponse,
    DosboxResizeWrite,
    dosbox_resize_response,
)

DOSBOX_RESIZE_RECEIPT_PREFIX: bytes = b"DOSBOX-4A-v1\0"
DOSBOX_RESIZE_RECEIPT_MAX_CHAIN: int = 64
DOSBOX_RESIZE_RECEIPT_MAX_BYTES: int = 4096
DOSBOX_RESIZE_RECEIPT_MAX_WRITES: int = 6
_CHECKSUM_BYTES: int = 32


class DosboxResizeReceiptError(ValueError):
    """The concrete event cannot supply a bounded canonical resize receipt."""


@dataclass(slots=True)
class _Reader:
    """Read only exact bounded fields from an already capped payload."""

    data: bytes
    offset: int = 0

    def take(self, size: int) -> bytes:
        """Require every requested byte without admitting padded fields."""
        end = self.offset + size
        if end > len(self.data):
            raise DosboxResizeReceiptError("truncated DOSBox resize receipt")
        result = self.data[self.offset:end]
        self.offset = end
        return result

    def integer(self, size: int) -> int:
        """Decode an exact unsigned little-endian machine field."""
        return int.from_bytes(self.take(size), "little")


@dataclass(frozen=True, slots=True)
class _Receipt:
    """The complete typed premise and exact canonical response to retain."""

    policy: DosboxResizePolicy
    segment: int
    paragraphs: int
    ax: int
    current_chain: tuple[bytes, ...]
    new_header_before: bytes | None
    result: DosboxResizeResponse


def _checked_image(image: bytes) -> None:
    """Require exact immutable MCB snapshots before copying or encoding."""
    if type(image) is not bytes or len(image) != DOSBOX_MCB_BYTES:
        raise DosboxResizeReceiptError("receipt requires exactly sixteen immutable header bytes")


def _checked_policy(policy: DosboxResizePolicy) -> DosboxResizePolicy:
    """Reconstruct policy invariants without silently shrinking its chain."""
    if type(policy) is not DosboxResizePolicy or type(policy.chain) is not tuple:
        raise DosboxResizeReceiptError("receipt requires a typed immutable DOSBox policy")
    if not 1 <= len(policy.chain) <= DOSBOX_RESIZE_RECEIPT_MAX_CHAIN:
        raise DosboxResizeReceiptError("DOSBox resize receipt chain limit exceeded")
    entries: list[DosboxMcbEntry] = []
    for entry in policy.chain:
        if type(entry) is not DosboxMcbEntry:
            raise DosboxResizeReceiptError("receipt requires typed MCB entries")
        _checked_image(entry.image)
        entries.append(DosboxMcbEntry(entry.segment, entry.image))
    return DosboxResizePolicy(policy.psp_segment, tuple(entries))


def _checked_result(result: DosboxResizeResponse) -> None:
    """Require exact scalar types and finite immutable ordered write spans."""
    if type(result) is not DosboxResizeResponse or type(result.writes) is not tuple:
        raise DosboxResizeReceiptError("receipt requires a typed response with ordered writes")
    if type(result.carry) is not bool or len(result.writes) > DOSBOX_RESIZE_RECEIPT_MAX_WRITES:
        raise DosboxResizeReceiptError("receipt has malformed carry or excessive writes")
    if any(type(word) is not int or not 0 <= word <= 0xFFFF for word in (result.ax, result.bx)):
        raise DosboxResizeReceiptError("receipt response words must be exact unsigned words")
    for write in result.writes:
        if type(write) is not DosboxResizeWrite or type(write.address) is not int:
            raise DosboxResizeReceiptError("receipt writes require exact typed addresses")
        if type(write.data) is not bytes or not 1 <= len(write.data) <= 2:
            raise DosboxResizeReceiptError("receipt write must carry one or two exact bytes")
        if not 0 <= write.address < write.address + len(write.data) <= 0x100000:
            raise DosboxResizeReceiptError("receipt write address exceeds guest memory")


def _checked_receipt(receipt: _Receipt) -> _Receipt:
    """Bind every recorded effect to the canonical model under exact premises."""
    policy = _checked_policy(receipt.policy)
    current = receipt.current_chain
    if type(current) is not tuple or len(current) != len(policy.chain):
        raise DosboxResizeReceiptError("receipt requires the complete current chain")
    for image in current:
        _checked_image(image)
    if receipt.new_header_before is not None:
        _checked_image(receipt.new_header_before)
    _checked_result(receipt.result)
    expected = dosbox_resize_response(
        policy, segment=receipt.segment, paragraphs=receipt.paragraphs,
        ax=receipt.ax, current_chain=current, new_header_before=receipt.new_header_before,
    )
    if isinstance(expected, DosboxResizeRefusal):
        raise DosboxResizeReceiptError(f"canonical DOSBox resize refused: {expected.value}")
    if receipt.result != expected:
        raise DosboxResizeReceiptError("receipt response or ordered writes differ from canonical model")
    return receipt


def _encode(receipt: _Receipt) -> bytes:
    """Emit the single binary schema, retaining every premise and write."""
    policy = receipt.policy
    parts = [DOSBOX_RESIZE_RECEIPT_PREFIX, policy.psp_segment.to_bytes(2, "little"),
             len(policy.chain).to_bytes(2, "little")]
    parts.extend(entry.segment.to_bytes(2, "little") + entry.image for entry in policy.chain)
    parts.extend(word.to_bytes(2, "little") for word in (receipt.ax, receipt.segment, receipt.paragraphs))
    parts.extend(receipt.current_chain)
    parts.append(bytes((receipt.new_header_before is not None,)))
    if receipt.new_header_before is not None:
        parts.append(receipt.new_header_before)
    result = receipt.result
    parts.extend((result.ax.to_bytes(2, "little"), result.bx.to_bytes(2, "little"),
                  bytes((result.carry, len(result.writes)))))
    parts.extend(write.address.to_bytes(4, "little") + bytes((len(write.data),)) + write.data
                 for write in result.writes)
    payload = b"".join(parts)
    return payload + hashlib.sha256(payload).digest()


def dosbox_resize_event_data(
    policy: DosboxResizePolicy, *, segment: int, paragraphs: int, ax: int,
    current_chain: tuple[bytes, ...], result: DosboxResizeResponse,
    new_header_before: bytes | None = None,
) -> bytes:
    """Serialize only a bounded model-derived complete concrete resize event.

    Refusals and applicability limits raise ``DosboxResizeReceiptError`` so a
    caller can stop before publishing success. This does not authenticate the
    premises against a boot; that remains the enclosing replay's obligation.
    """
    receipt = _Receipt(policy, segment, paragraphs, ax, current_chain, new_header_before, result)
    try:
        data = _encode(_checked_receipt(receipt))
    except ValueError as error:
        if isinstance(error, DosboxResizeReceiptError):
            raise
        raise DosboxResizeReceiptError("malformed DOSBox resize receipt premise") from error
    if len(data) > DOSBOX_RESIZE_RECEIPT_MAX_BYTES:
        raise DosboxResizeReceiptError("DOSBox resize receipt byte limit exceeded")
    return data


def _read_policy(reader: _Reader) -> DosboxResizePolicy:
    """Reject an excessive chain count before allocating entry records."""
    psp, count = reader.integer(2), reader.integer(2)
    if not 1 <= count <= DOSBOX_RESIZE_RECEIPT_MAX_CHAIN:
        raise DosboxResizeReceiptError("DOSBox resize receipt chain limit exceeded")
    entries = tuple(DosboxMcbEntry(reader.integer(2), reader.take(DOSBOX_MCB_BYTES))
                    for _ in range(count))
    return DosboxResizePolicy(psp, entries)


def _read_result(reader: _Reader) -> DosboxResizeResponse:
    """Decode only bounded ordered write spans and an exact carry bit."""
    ax, bx = reader.integer(2), reader.integer(2)
    carry, count = reader.integer(1), reader.integer(1)
    if carry not in (0, 1) or count > DOSBOX_RESIZE_RECEIPT_MAX_WRITES:
        raise DosboxResizeReceiptError("malformed receipt response flags or write count")
    writes: list[DosboxResizeWrite] = []
    for _ in range(count):
        address, size = reader.integer(4), reader.integer(1)
        if size not in (1, 2):
            raise DosboxResizeReceiptError("malformed receipt write extent")
        writes.append(DosboxResizeWrite(address, reader.take(size)))
    return DosboxResizeResponse(ax, bx, bool(carry), tuple(writes))


def _decode(payload: bytes) -> _Receipt:
    """Decode the exact schema with no padding or alternate field shapes."""
    reader = _Reader(payload, len(DOSBOX_RESIZE_RECEIPT_PREFIX))
    policy = _read_policy(reader)
    ax, segment, paragraphs = reader.integer(2), reader.integer(2), reader.integer(2)
    current = tuple(reader.take(DOSBOX_MCB_BYTES) for _ in policy.chain)
    split_present = reader.integer(1)
    if split_present not in (0, 1):
        raise DosboxResizeReceiptError("malformed receipt split-header tag")
    split = reader.take(DOSBOX_MCB_BYTES) if split_present else None
    result = _read_result(reader)
    if reader.offset != len(payload):
        raise DosboxResizeReceiptError("noncanonical trailing receipt bytes")
    return _Receipt(policy, segment, paragraphs, ax, current, split, result)


def dosbox_resize_receipt_complete(data: bytes) -> bool:
    """Verify integrity, bounded schema and exact canonical modeled effects."""
    if type(data) is not bytes or not len(DOSBOX_RESIZE_RECEIPT_PREFIX) + _CHECKSUM_BYTES < len(data) <= DOSBOX_RESIZE_RECEIPT_MAX_BYTES:
        return False
    if not data.startswith(DOSBOX_RESIZE_RECEIPT_PREFIX):
        return False
    payload = data[:-_CHECKSUM_BYTES]
    if hashlib.sha256(payload).digest() != data[-_CHECKSUM_BYTES:]:
        return False
    try:
        receipt = _checked_receipt(_decode(payload))
        return _encode(receipt) == data
    except ValueError:
        return False
