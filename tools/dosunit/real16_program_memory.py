"""Explicit sparse conventional RAM for initialized real-mode execution.

Layer: dosunit concrete environment.
Responsibility: validate disjoint initial byte declarations, derive exact
physical access coverage and mapping pages, and never treat page padding or
missing regions as supplied state. Segmented input coordinates stay explicit.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tools.dosunit.real16_program_resize import TailResizePolicy
from tools.dosunit.real16_replay_model import PAGE_SIZE, LinearRange, SegOffset

CONVENTIONAL_BYTES: int = 0xA0000
MAX_EXTRA_REGIONS: int = 32
SEGMENT_BYTES: int = 0x10000


@dataclass(frozen=True, slots=True)
class InitialMemoryRegion:
    """One exact RAM snapshot starting at explicit segment:offset coordinates."""

    start: SegOffset
    data: bytes

    def __post_init__(self) -> None:
        """Reject missing bytes, implicit offset wrap and device-memory claims."""
        if not isinstance(self.start, SegOffset):
            raise ValueError("initial memory requires a segmented address")
        if type(self.start.segment) is not int or type(self.start.offset) is not int:
            raise ValueError("initial memory coordinates must be integer words")
        if not isinstance(self.data, bytes) or not self.data:
            raise ValueError("initial memory requires immutable nonempty bytes")
        if self.start.offset + len(self.data) > SEGMENT_BYTES:
            raise ValueError("initial memory region wraps its segment offset")
        if self.start.linear() + len(self.data) > CONVENTIONAL_BYTES:
            raise ValueError("initial memory must be conventional RAM, not device memory")


@dataclass(frozen=True, slots=True)
class ProgramMemoryLayout:
    """Disjoint initialization chunks with derived exact coverage and page mapping.

    Adjacent chunks share access coverage; overlaps always reject, even when
    bytes agree. Page mapping is only a backend requirement, never evidence
    that its padding was initialized. Total bytes cannot exceed 640 KiB.
    """

    chunks: tuple[tuple[int, bytes], ...]
    ranges: tuple[LinearRange, ...] = field(init=False)
    pages: tuple[int, ...] = field(init=False)

    def __post_init__(self) -> None:
        """Derive bounded canonical coverage from the actual initialization bytes."""
        if not self.chunks or len(self.chunks) > MAX_EXTRA_REGIONS + 2:
            raise ValueError("initial memory chunk count exceeds the bounded declaration")
        ranges: list[LinearRange] = []
        chunks = tuple(sorted(self.chunks, key=lambda chunk: chunk[0]))
        for address, data in chunks:
            if type(address) is not int or not isinstance(data, bytes) or not data:
                raise ValueError("initial memory requires integer addresses and exact bytes")
            if address < 0 or address + len(data) > CONVENTIONAL_BYTES:
                raise ValueError("initial memory lies outside conventional RAM")
            region = LinearRange(address, len(data))
            if ranges and address < ranges[-1].address + ranges[-1].size:
                raise ValueError("initial memory declarations overlap or alias")
            if ranges and address == ranges[-1].address + ranges[-1].size:
                previous = ranges.pop()
                region = LinearRange(previous.address, previous.size + len(data))
            ranges.append(region)
        pages = {page for region in ranges for page in range(
            region.address // PAGE_SIZE * PAGE_SIZE,
            (region.address + region.size + PAGE_SIZE - 1) // PAGE_SIZE * PAGE_SIZE,
            PAGE_SIZE,
        )}
        object.__setattr__(self, "chunks", chunks)
        object.__setattr__(self, "ranges", tuple(ranges))
        object.__setattr__(self, "pages", tuple(sorted(pages)))

    def contains(self, address: int, size: int) -> bool:
        """Check exact byte coverage, including adjacent declarations but not gaps."""
        return size >= 0 and any(region.contains(address, size) for region in self.ranges)


def program_memory_layout(
    psp_segment: int, allocation: bytes, extra: tuple[InitialMemoryRegion, ...],
    resize: TailResizePolicy | None,
) -> ProgramMemoryLayout:
    """Unify allocation, optional allocator metadata and explicit extra RAM."""
    if not isinstance(extra, tuple) or len(extra) > MAX_EXTRA_REGIONS:
        raise ValueError("extra_memory must be a bounded immutable tuple")
    if any(not isinstance(region, InitialMemoryRegion) for region in extra):
        raise ValueError("extra_memory requires typed InitialMemoryRegion entries")
    chunks = [(psp_segment * 16, allocation)]
    chunks.extend((region.start.linear(), region.data) for region in extra)
    if resize is not None:
        chunks.append((resize.metadata_address, resize.initial_mcb))
    return ProgramMemoryLayout(tuple(chunks))


def memory_regions_document(regions: tuple[InitialMemoryRegion, ...]) -> list[dict[str, object]]:
    """Bind segmented coordinates and every supplied byte in public identities."""
    return [{"segment": region.start.segment, "offset": region.start.offset, "data_hex": region.data.hex()}
            for region in regions]


def parse_memory_regions(value: object) -> tuple[InitialMemoryRegion, ...]:
    """Parse exact extra-RAM declarations, bounding conversion before allocation."""
    if not isinstance(value, list) or len(value) > MAX_EXTRA_REGIONS:
        raise ValueError("extra_memory must be a list with at most 32 regions")
    regions: list[InitialMemoryRegion] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"segment", "offset", "data_hex"}:
            raise ValueError("extra memory requires segment, offset and data_hex")
        segment, offset, text = item["segment"], item["offset"], item["data_hex"]
        if type(segment) is not int or type(offset) is not int or not isinstance(text, str):
            raise ValueError("extra memory requires integer coordinates and hexadecimal bytes")
        if len(text) > SEGMENT_BYTES * 2:
            raise ValueError("extra memory region exceeds its segment byte bound")
        data = bytes.fromhex(text)
        if len(data) * 2 != len(text):
            raise ValueError("extra memory hexadecimal bytes must not contain whitespace")
        regions.append(InitialMemoryRegion(SegOffset(segment, offset), data))
    return tuple(regions)
