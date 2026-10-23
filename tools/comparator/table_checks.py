"""Layer: comparator structural evidence.

Responsibility: check serialized PE32 target tables against an explicit target
correspondence, without claiming function equivalence or changing proof verdicts.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from typing import Any

import pefile


class TableCheckStatus(StrEnum):
    """Structural check outcomes, deliberately separate from proof verdicts."""

    CHECKED = "checked"
    MISMATCH = "mismatch"
    INCOMPLETE = "incomplete"


@dataclass(frozen=True)
class TargetTable:
    """File-backed DWORD slots at preferred image addresses; extent is declared."""

    address: int
    targets: tuple[int, ...]
    image_sha256: str

    def __post_init__(self) -> None:
        """Prevent vacuous success from empty tables or invalid pointer values."""
        if not 0 < len(self.targets) <= 4096:
            raise ValueError("target table requires 1..4096 entries")
        if any(type(target) is not int or not 0 <= target <= 0xFFFFFFFF for target in self.targets):
            raise ValueError("table entries must be 32-bit integer addresses")


def read_target_table(image: bytes, address: int, count: int) -> TargetTable:
    """Read exactly the declared PE32 table, never padding missing file bytes.

    Addresses are preferred-image VAs. This checks serialized image contents,
    not runtime relocation or preservation of memory after loading.
    """
    if type(address) is not int or type(count) is not int or not 0 < count <= 4096:
        raise ValueError("table requires an integer VA and 1..4096 entries")
    size = count * 4
    raw = read_pe_bytes(image, address, size)
    return TargetTable(address, tuple(int.from_bytes(raw[i:i + 4], "little")
                                     for i in range(0, size, 4)), hashlib.sha256(image).hexdigest())


@dataclass(frozen=True)
class PeSectionLayout:
    """Immutable section coordinates and permissions, never cached read results."""

    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int


@lru_cache(maxsize=2)
def _pe_layout(image: bytes) -> tuple[int, tuple[PeSectionLayout, ...]]:
    """Parse one immutable PE image; retain at most the current image pair.

    The key is the complete byte string, not a path or timestamp. Changed bytes
    therefore cannot inherit stale coordinates or executable permissions.
    """
    pe = pefile.PE(data=image, fast_load=True)
    try:
        # pefile dynamically populates these third-party header structures.
        file_header: Any = pe.FILE_HEADER
        optional_header: Any = pe.OPTIONAL_HEADER
        if file_header is None or optional_header is None:
            raise ValueError("PE headers are missing")
        if file_header.Machine != 0x14C or optional_header.Magic != 0x10B:
            raise ValueError("target tables require i386 PE32")
        sections = tuple(PeSectionLayout(int(section.VirtualAddress), int(section.Misc_VirtualSize),
                                         int(section.PointerToRawData), int(section.SizeOfRawData),
                                         int(section.Characteristics)) for section in pe.sections)
        return int(optional_header.ImageBase), sections
    finally:
        pe.close()


def read_pe_bytes(image: bytes, address: int, size: int, *, executable: bool = False) -> bytes:
    """Read one exact file-backed PE32 extent, optionally requiring executable code."""
    if not 0 <= address < address + size <= 0x100000000:
        raise ValueError("extent exceeds the 32-bit address space")
    base, layout = _pe_layout(image)
    rva = address - base
    sections = [section for section in layout
                if section.virtual_address <= rva
                and rva + size <= section.virtual_address + section.virtual_size]
    if len(sections) != 1:
        raise ValueError("table must lie within one mapped section")
    section = sections[0]
    if executable and not section.characteristics & 0x20000000:
        raise ValueError("dispatch instruction is not in an executable section")
    relative = rva - section.virtual_address
    offset = section.raw_offset + relative
    if relative + size > section.raw_size or offset + size > len(image):
        raise ValueError("table is not fully file-backed")
    return image[offset:offset + size]



def read_pe_window(image: bytes, address: int, maximum_size: int, *, executable: bool = False) -> bytes:
    """Read a nonempty mapped file-backed prefix using the immutable layout cache.

    Unlike an exact extent request, a decoder window may end at a section or
    file boundary. It never pads bytes, crosses sections, or relaxes execution
    permissions. The exact decoded extent is still checked by the caller.
    """
    if type(address) is not int or not 0 <= address < 0x100000000:
        raise ValueError("window address must be a 32-bit integer")
    if type(maximum_size) is not int or maximum_size <= 0:
        raise ValueError("window size must be a positive integer")
    base, layout = _pe_layout(image)
    rva = address - base
    sections = [section for section in layout
                if section.virtual_address <= rva < section.virtual_address + section.virtual_size]
    if len(sections) != 1:
        raise ValueError("window must begin within one mapped section")
    section = sections[0]
    relative = rva - section.virtual_address
    size = min(maximum_size, section.virtual_size - relative, section.raw_size - relative,
               len(image) - section.raw_offset - relative, 0x100000000 - address)
    return read_pe_bytes(image, address, size, executable=executable)


def check_target_tables(
    original: TargetTable, candidate: TargetTable, correspondence: Mapping[int, int],
) -> dict[str, object]:
    """Check slot order, duplicates and nulls against declared target pairs.

    A pair identifies the intended correspondence only. It does not certify
    target behavior. Missing pairs are incomplete evidence; a contradictory
    slot is a structural mismatch, not a whole-function counterexample.
    Multiple original targets may map to one candidate after code folding.
    """
    if any(type(key) is not int or type(value) is not int
           or not 0 < key <= 0xFFFFFFFF or not 0 < value <= 0xFFFFFFFF
           for key, value in correspondence.items()):
        raise ValueError("target pairs must contain nonzero 32-bit integer addresses")
    entries: list[dict[str, object]] = []
    counts_equal = len(original.targets) == len(candidate.targets)
    for index, (left, right) in enumerate(zip(original.targets, candidate.targets, strict=False)):
        expected = 0 if left == 0 else correspondence.get(left)
        status = (TableCheckStatus.INCOMPLETE if expected is None else
                  TableCheckStatus.CHECKED if expected == right else TableCheckStatus.MISMATCH)
        entries.append({"index": index, "original_target": hex(left), "candidate_target": hex(right),
                        "expected_candidate_target": None if expected is None else hex(expected),
                        "status": status.value})
    status = TableCheckStatus.CHECKED
    if not counts_equal or any(row["status"] == TableCheckStatus.MISMATCH for row in entries):
        status = TableCheckStatus.MISMATCH
    elif any(row["status"] == TableCheckStatus.INCOMPLETE for row in entries):
        status = TableCheckStatus.INCOMPLETE
    return {
        "schema": "comparator.target_table_check.v1", "status": status.value,
        "scope": "declared_serialized_table", "function_equivalence_proved": False,
        "original": {"address": hex(original.address), "count": len(original.targets),
                     "image_sha256": original.image_sha256},
        "candidate": {"address": hex(candidate.address), "count": len(candidate.targets),
                      "image_sha256": candidate.image_sha256},
        "count_matches": counts_equal, "entries": entries,
        "checked_entries": sum(row["status"] == TableCheckStatus.CHECKED for row in entries),
        "target_correspondence": [{"original": hex(key), "candidate": hex(value)}
                                  for key, value in sorted(correspondence.items())],
        "pending_conditions": [
            "binary-derived table extent and binding to the actual indirect transfer",
            "target function or block behavioral equivalence, including ABI and external effects",
            "index computation equivalence and reachable index domain",
            "bounds checks and default or out-of-range behavior",
            "runtime relocation and table preservation through all preceding writes and calls",
            "pointer observations and aliases outside the table dispatch",
        ],
    }


def read_pe_initial_bytes(image: bytes, address: int, size: int) -> tuple[bytes, int]:
    """Read section initialization before relocations, including declared zero tail.

    Return bytes plus their file-backed count. Missing serialized bytes are
    malformed input, never BSS. This does not model relocations, imports, TLS
    initialization or program writes, and does not relax read_pe_bytes.
    """
    if type(address) is not int or type(size) is not int or not 0 < size <= 64:
        raise ValueError("initial extent requires an integer VA and 1..64 bytes")
    if not 0 <= address < address + size <= 0x100000000:
        raise ValueError("initial extent exceeds flat32 address space")
    base, layout = _pe_layout(image)
    rva = address - base
    sections = [section for section in layout if section.virtual_address <= rva
                and rva + size <= section.virtual_address + section.virtual_size]
    if len(sections) != 1:
        raise ValueError("initial extent must lie within one declared virtual section")
    section = sections[0]
    if section.raw_size and section.raw_offset + section.raw_size > len(image):
        raise ValueError("declared section data is truncated")
    relative = rva - section.virtual_address
    count = min(size, max(0, section.raw_size - relative))
    offset = section.raw_offset + relative
    return image[offset:offset + count] + bytes(size - count), count
