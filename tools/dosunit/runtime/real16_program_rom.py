"""Explicit caller-declared read-only firmware bytes for real16 program replay.

Layer: dosunit concrete environment contracts.
Responsibility: validate disjoint immutable byte declarations confined to
the physical firmware window, derive exact read coverage in canonical
physical order, and project every declared byte with its original segmented
coordinates into deterministic identity data.

The declared bytes are caller-supplied evidence only: this contract admits
no writes, grants no fetch or interrupt-handler scope, and proves nothing
about an installed BIOS. A returned static pointer is a declaration the
caller must back with exact bytes; it is never evidence on its own. The
executor owns page mapping, read admission and write refusal — this module
supplies the typed declaration and coverage oracle that enforcement is
built from, never a general writable-memory owner. ``None`` is the only
"no ROM" declaration; absent policy leaves the whole window unreadable.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tools.dosunit.runtime.real16_program_memory import SEGMENT_BYTES, ProgramMemoryLayout
from tools.dosunit.runtime.real16_replay_model import PAGE_SIZE, LinearRange, SegOffset

# Firmware window: the PC architecture reserves physical C0000-FFFFF for
# adapter and system ROM. A0000-BFFFF is video/MMIO and stays refused, as
# does every address outside the window. The upper bound is exclusive.
ROM_WINDOW_START: int = 0xC0000
ROM_WINDOW_END: int = 0x100000
ROM_WINDOW_BYTES: int = ROM_WINDOW_END - ROM_WINDOW_START
MAX_ROM_REGIONS: int = 16

_HEX_DIGITS: frozenset[str] = frozenset("0123456789abcdefABCDEF")


@dataclass(frozen=True, slots=True)
class RomRegion:
    """One exact read-only byte run at explicit segment:offset coordinates.

    ``start`` is a typed segmented address; several segmented coordinates
    may resolve to the same physical byte, and identity always keeps the
    declared coordinate, never a normalized form. ``data`` is the complete
    immutable byte run — no defaults, no zero-fill, no signature checks.
    The run must not wrap its 64 KiB logical offset and must lie entirely
    inside the physical firmware window 0xC0000..0xFFFFF; everything below
    the window (conventional RAM, A0000-BFFFF video/MMIO) and at or above
    0x100000 is refused.
    """

    start: SegOffset
    data: bytes

    def __post_init__(self) -> None:
        """Reject missing bytes, offset wrap and out-of-window claims."""
        if not isinstance(self.start, SegOffset):
            raise ValueError("ROM declaration requires a segmented address")
        if type(self.start.segment) is not int or type(self.start.offset) is not int:
            raise ValueError("ROM declaration coordinates must be integer words")
        if type(self.data) is not bytes or not self.data:
            raise ValueError("ROM declaration requires immutable nonempty bytes")
        if self.start.offset + len(self.data) > SEGMENT_BYTES:
            raise ValueError("ROM declaration wraps its segment offset")
        start = self.start.linear()
        if start < ROM_WINDOW_START or start + len(self.data) > ROM_WINDOW_END:
            raise ValueError("ROM declaration lies outside the C0000-FFFFF firmware window")


@dataclass(frozen=True, slots=True)
class ProgramRom:
    """Bounded disjoint ROM inventory with canonical order and exact read coverage.

    At most ``MAX_ROM_REGIONS`` typed regions totaling at most the 256 KiB
    window. ``regions`` is stored in canonical physical order while keeping
    each declared segmented coordinate verbatim. Overlaps and duplicate
    declarations always reject, including aliases that resolve to the same
    physical bytes, even when the supplied bytes agree. ``ranges`` merges
    only physically touching declarations, so adjacent chunks are readable
    together while gaps and mapping-page slack are never readable.
    ``chunks`` and ``pages`` are the executor's mapping evidence; page
    mapping is only a backend requirement, never proof that its padding is
    declared data.
    """

    regions: tuple[RomRegion, ...]
    ranges: tuple[LinearRange, ...] = field(init=False)
    chunks: tuple[tuple[int, bytes], ...] = field(init=False)
    pages: tuple[int, ...] = field(init=False)

    def __post_init__(self) -> None:
        """Canonicalize the bounded inventory and derive exact coverage."""
        if not isinstance(self.regions, tuple) or not self.regions or len(self.regions) > MAX_ROM_REGIONS:
            raise ValueError("ROM inventory must be a nonempty tuple of at most 16 regions")
        if any(not isinstance(region, RomRegion) for region in self.regions):
            raise ValueError("ROM inventory requires typed RomRegion entries")
        # Reconstruct nested coordinates to reject forged frozen declarations
        # before their derived chunks can influence an executor.
        for region in self.regions:
            if not isinstance(region.start, SegOffset):
                raise ValueError("ROM region has untyped coordinates")
            RomRegion(SegOffset(region.start.segment, region.start.offset), region.data)
        ordered = tuple(sorted(self.regions, key=lambda region: region.start.linear()))
        ranges: list[LinearRange] = []
        total = 0
        for region in ordered:
            start = region.start.linear()
            total += len(region.data)
            coverage = LinearRange(start, len(region.data))
            if ranges and start < ranges[-1].address + ranges[-1].size:
                raise ValueError("ROM declarations overlap or alias the same physical bytes")
            if ranges and start == ranges[-1].address + ranges[-1].size:
                previous = ranges.pop()
                coverage = LinearRange(previous.address, previous.size + len(region.data))
            ranges.append(coverage)
        if total > ROM_WINDOW_BYTES:
            raise ValueError("ROM inventory exceeds the 256 KiB firmware window")
        pages = {page for coverage in ranges for page in range(
            coverage.address // PAGE_SIZE * PAGE_SIZE,
            (coverage.address + coverage.size + PAGE_SIZE - 1) // PAGE_SIZE * PAGE_SIZE,
            PAGE_SIZE,
        )}
        object.__setattr__(self, "regions", ordered)
        object.__setattr__(self, "ranges", tuple(ranges))
        object.__setattr__(self, "chunks", tuple(
            (region.start.linear(), region.data) for region in ordered
        ))
        object.__setattr__(self, "pages", tuple(sorted(pages)))

    def contains(self, address: int, size: int) -> bool:
        """Check exact read coverage: adjacent declarations count, gaps and page slack never do."""
        return size >= 0 and any(coverage.contains(address, size) for coverage in self.ranges)


def check_rom(rom: ProgramRom | None) -> None:
    """Re-derive bounded projections without serializing or copying ROM bytes."""
    if rom is None:
        return
    if not isinstance(rom, ProgramRom):
        raise ValueError("ROM requires a declared ProgramRom or None")
    if ProgramRom(rom.regions) != rom:
        raise ValueError("ROM derived coverage, chunks or pages are stale")


def rom_document(rom: ProgramRom | None) -> list[dict[str, object]] | None:
    """Project every declared region into deterministic identity data.

    ``None`` declares "no ROM" and projects as ``None``. Otherwise each
    region contributes its original segmented coordinate and complete bytes
    in canonical physical order, so declarations equivalent up to order
    share one identity while changed coordinates or changed bytes never do.
    """
    check_rom(rom)
    if rom is None:
        return None
    return [
        {"segment": region.start.segment, "offset": region.start.offset,
         "data_hex": region.data.hex()}
        for region in rom.regions
    ]


def parse_rom(value: object) -> ProgramRom | None:
    """Read an explicit ROM declaration list; ``None`` keeps the window unreadable.

    The value must be a nonempty list of at most ``MAX_ROM_REGIONS``
    objects, each declaring exactly ``segment``, ``offset`` and
    ``data_hex``. Coordinates must be strict integers in the 16-bit word
    domain — never bool or float masquerades. ``data_hex`` must be
    nonempty even-length hexadecimal without whitespace and at most the
    64 KiB segment bound, all checked before conversion so oversized text never
    reaches allocation. Window confinement, overlap and duplicate refusals
    stay owned by the typed contracts; ``None`` is the only "no ROM"
    declaration and an empty list is malformed.
    """
    if value is None:
        return None
    if not isinstance(value, list) or not value or len(value) > MAX_ROM_REGIONS:
        raise ValueError("rom requires a nonempty list with at most 16 regions")
    regions: list[RomRegion] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"segment", "offset", "data_hex"}:
            raise ValueError("rom region requires exactly segment, offset and data_hex")
        segment, offset, text = item["segment"], item["offset"], item["data_hex"]
        if type(segment) is not int or type(offset) is not int:
            raise ValueError("rom region requires strict integer coordinates")
        if not isinstance(text, str) or not text:
            raise ValueError("rom region requires nonempty hexadecimal bytes")
        if len(text) > SEGMENT_BYTES * 2:
            raise ValueError("rom region exceeds its 64 KiB segment bound")
        if len(text) % 2 or any(char not in _HEX_DIGITS for char in text):
            raise ValueError("rom region requires even-length hexadecimal without whitespace")
        regions.append(RomRegion(SegOffset(segment, offset), bytes.fromhex(text)))
    return ProgramRom(tuple(regions))


def readable_memory_contains(
    memory: LinearRange | ProgramMemoryLayout, rom: ProgramRom | None,
    address: int, size: int,
) -> bool:
    """Admit complete RAM or declared ROM reads without enlarging write coverage.

    The firmware window and conventional RAM are separated by undeclared video
    memory. A single access crossing that gap never becomes a complete read.
    Consumers validate the ROM identity before using this bounded hot-path check.
    """
    return memory.contains(address, size) or (rom is not None and rom.contains(address, size))
