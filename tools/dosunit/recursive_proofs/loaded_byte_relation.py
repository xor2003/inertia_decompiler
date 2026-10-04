"""Layer: dosunit initialized-memory relation (staging).

Responsibility: bind a finite bijective byte-value relation to complete immutable
loaded snapshots. A proposal grants no execution, alias or equivalence proof.
"""
from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from tools.dosunit.proof_contracts import Architecture

ADDRESS_WIDTH: int = 32
BYTE_WIDTH: int = 8
MAX_CHUNKS: int = 65_536
MAX_PATCHES: int = 4_096


class LoadedRelationReason(StrEnum):
    """Exact proposal or proof boundary; none denotes binary equality."""

    DISCHARGED = "initialized_byte_relation_discharged"
    MALFORMED = "loaded_byte_snapshot_malformed"
    OVERLAP = "loaded_byte_snapshot_overlap"
    DOMAIN = "loaded_byte_coordinate_domain_mismatch"
    MASK = "loaded_byte_mask_not_bound_to_snapshots"
    LIMIT = "loaded_byte_relation_resource_limit"
    DEADLINE = "loaded_byte_relation_deadline"
    COUNTERMODEL = "loaded_byte_relation_algebra_countermodel"
    UNKNOWN = "loaded_byte_relation_algebra_unknown"


class LoadedRelationRefusal(Exception):
    """Retain a named missing boundary instead of guessing a relation."""

    def __init__(self, reason: LoadedRelationReason, detail: str) -> None:
        """Preserve the exact typed reason and original explanatory detail."""
        self.reason = reason
        self.detail = detail
        super().__init__(detail)


@dataclass(frozen=True, slots=True)
class LoadedRelationLimits:
    """Finite snapshot intake, patch storage and original absolute deadline."""

    max_bytes: int = 1_048_576
    max_patches: int = MAX_PATCHES
    deadline: float = -1.0

    def __post_init__(self) -> None:
        """Reject Boolean, negative and unsupported finite resource declarations."""
        if type(self.max_bytes) is not int or self.max_bytes <= 0:
            raise ValueError("loaded byte budget must be a positive integer")
        if type(self.max_patches) is not int or not 0 <= self.max_patches <= MAX_PATCHES:
            raise ValueError("patch budget must be a nonnegative integer within the relation bound")
        if type(self.deadline) not in {int, float} or not math.isfinite(self.deadline):
            raise ValueError("loaded relation deadline must be a finite absolute time or negative sentinel")

    def check_time(self) -> None:
        """Check the caller's original deadline; never replenish it internally."""
        if self.deadline >= 0.0 and time.monotonic() >= self.deadline:
            raise LoadedRelationRefusal(LoadedRelationReason.DEADLINE, "original loaded-relation deadline exceeded")


@dataclass(frozen=True, slots=True)
class LoadedBytes:
    """Complete canonical sparse loaded bytes, distinct from a whole-file hash.

    Construction must use ``snapshot_loaded_bytes``. Proof consumption repeats
    validation, so direct construction cannot bypass snapshot or resource gates.
    The digest binds physical coordinates and bytes, without normalizing layout.
    """

    architecture: Architecture
    chunks: tuple[tuple[int, bytes], ...]
    byte_count: int
    sparse_byte_sha256: str


def snapshot_loaded_bytes(architecture: Architecture, chunks: tuple[tuple[int, bytes], ...],
                          *, limits: LoadedRelationLimits | None = None) -> LoadedBytes:
    """Canonicalize complete immutable loader backers with finite intake work."""
    selected = limits if limits is not None else LoadedRelationLimits()
    selected.check_time()
    if not isinstance(architecture, Architecture) or architecture not in {Architecture.REAL16, Architecture.FLAT32}:
        raise LoadedRelationRefusal(LoadedRelationReason.MALFORMED, "unsupported loaded architecture")
    if type(chunks) is not tuple or not chunks:
        raise LoadedRelationRefusal(LoadedRelationReason.MALFORMED, "snapshot requires nonempty immutable backers")
    if len(chunks) > MAX_CHUNKS:
        raise LoadedRelationRefusal(LoadedRelationReason.LIMIT, "raw backer count exceeds intake bound")
    count = 0
    address_limit = 0x10FFF0 if architecture is Architecture.REAL16 else 1 << ADDRESS_WIDTH
    for chunk in chunks:
        selected.check_time()
        if type(chunk) is not tuple or len(chunk) != 2:
            raise LoadedRelationRefusal(LoadedRelationReason.MALFORMED, "backer requires one address and byte string")
        address, data = chunk
        if type(address) is not int or type(data) is not bytes or not data:
            raise LoadedRelationRefusal(LoadedRelationReason.MALFORMED, "backer address/bytes are not immutable native values")
        if address < 0 or address + len(data) > address_limit:
            raise LoadedRelationRefusal(LoadedRelationReason.DOMAIN, "loaded bytes exceed the physical address domain")
        count += len(data)
        if count > selected.max_bytes:
            raise LoadedRelationRefusal(LoadedRelationReason.LIMIT, "complete loaded snapshot exceeds byte budget")
    canonical = _canonical_chunks(chunks, selected)
    digest = hashlib.sha256()
    for address, data in canonical:
        selected.check_time()
        digest.update(address.to_bytes(4, "little"))
        digest.update(len(data).to_bytes(8, "little"))
        digest.update(data)
    selected.check_time()
    return LoadedBytes(architecture, canonical, count, digest.hexdigest())


def _canonical_chunks(chunks: tuple[tuple[int, bytes], ...], limits: LoadedRelationLimits
                      ) -> tuple[tuple[int, bytes], ...]:
    """Merge adjacent backers once; overlapping bytes retain an explicit refusal."""
    result: list[tuple[int, bytes]] = []
    run_start: int | None = None
    run_parts: list[bytes] = []
    end = 0
    for address, data in sorted(chunks):
        limits.check_time()
        if run_start is not None and address < end:
            raise LoadedRelationRefusal(LoadedRelationReason.OVERLAP, "ambiguous overlapping loaded backers")
        if run_start is not None and address != end:
            result.append((run_start, b"".join(run_parts)))
            run_parts = []
            run_start = None
        if run_start is None:
            run_start = address
        run_parts.append(data)
        end = address + len(data)
    assert run_start is not None
    result.append((run_start, b"".join(run_parts)))
    return tuple(result)


@dataclass(frozen=True, slots=True)
class ByteXorMask:
    """One exact physical byte coordinate and nonzero eight-bit value mask."""

    address: int
    mask: int

    def __post_init__(self) -> None:
        """Reject wrapped addresses, Boolean numbers and empty patch facts."""
        if type(self.address) is not int or not 0 <= self.address < 1 << ADDRESS_WIDTH:
            raise ValueError("byte mask address must be an exact unsigned32 coordinate")
        if type(self.mask) is not int or not 0 < self.mask < 1 << BYTE_WIDTH:
            raise ValueError("byte mask must be an exact nonzero unsigned8 value")


@dataclass(frozen=True, slots=True)
class ByteXorRelation:
    """Sparse self-inverse full-array relation; all other bytes stay unchanged."""

    masks: tuple[ByteXorMask, ...] = ()

    def __post_init__(self) -> None:
        """Require bounded unique sorted physical coordinates before allocation."""
        if type(self.masks) is not tuple or len(self.masks) > MAX_PATCHES:
            raise ValueError("byte relation must be an immutable bounded mask tuple")
        previous = -1
        for patch in self.masks:
            if not isinstance(patch, ByteXorMask) or patch.address <= previous:
                raise ValueError("byte relation masks must have unique sorted coordinates")
            previous = patch.address

    def apply(self, memory: dict[str, Any], *, limits: LoadedRelationLimits | None = None) -> dict[str, Any]:
        """Express the full array map in raw SSA, preserving every unmasked byte.

        Every load reads the original array. Unique literal coordinates make
        this equivalent to evolving-array reads without an alias assumption.
        No proof status follows until algebra and native preservation discharge.
        """
        selected = limits if limits is not None else LoadedRelationLimits()
        selected.check_time()
        if len(self.masks) > selected.max_patches:
            raise LoadedRelationRefusal(LoadedRelationReason.LIMIT, "relation exceeds caller patch budget")
        if not isinstance(memory, dict) or memory.get("op") not in {"mem_input", "storele", "storebe", "ite"}:
            raise LoadedRelationRefusal(LoadedRelationReason.MALFORMED, "relation requires a native memory array term")
        result = memory
        for patch in self.masks:
            selected.check_time()
            address = {"op": "const", "width": ADDRESS_WIDTH, "value": hex(patch.address)}
            byte = {"op": "loadle", "width": BYTE_WIDTH, "args": [memory, address]}
            transformed = {"op": "xor", "width": BYTE_WIDTH, "args": [byte,
                           {"op": "const", "width": BYTE_WIDTH, "value": hex(patch.mask)}]}
            result = {"op": "storele", "width": 0, "args": [result, address, transformed]}
        selected.check_time()
        return result


@dataclass(frozen=True, slots=True)
class LoadedByteProposal:
    """Bind a proposed relation to both complete loaded byte snapshots."""

    original: LoadedBytes
    candidate: LoadedBytes
    relation: ByteXorRelation


def propose_loaded_byte_relation(original: LoadedBytes, candidate: LoadedBytes, *,
                                 limits: LoadedRelationLimits | None = None) -> LoadedByteProposal:
    """Derive exact fixed-coordinate masks from every loaded byte, without proof."""
    selected = limits if limits is not None else LoadedRelationLimits()
    left = snapshot_loaded_bytes(original.architecture, original.chunks, limits=selected)
    right = snapshot_loaded_bytes(candidate.architecture, candidate.chunks, limits=selected)
    if left != original or right != candidate:
        raise LoadedRelationRefusal(LoadedRelationReason.MALFORMED, "snapshot digest/count/canonical metadata mismatch")
    if left.architecture is not right.architecture:
        raise LoadedRelationRefusal(LoadedRelationReason.DOMAIN, "loaded architectures differ")
    if tuple((a, len(b)) for a, b in left.chunks) != tuple((a, len(b)) for a, b in right.chunks):
        raise LoadedRelationRefusal(LoadedRelationReason.DOMAIN, "complete sparse loaded coordinate domains differ")
    masks: list[ByteXorMask] = []
    for (address, original_data), (_, candidate_data) in zip(left.chunks, right.chunks, strict=True):
        for offset, (original_byte, candidate_byte) in enumerate(zip(original_data, candidate_data, strict=True)):
            selected.check_time()
            mask = original_byte ^ candidate_byte
            if mask:
                if len(masks) >= selected.max_patches:
                    raise LoadedRelationRefusal(LoadedRelationReason.LIMIT, "differing loaded bytes exceed patch budget")
                masks.append(ByteXorMask(address + offset, mask))
    selected.check_time()
    return LoadedByteProposal(left, right, ByteXorRelation(tuple(masks)))
