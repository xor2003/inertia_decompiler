"""Layer: validation input catalogs.

Responsibility: retain discontiguous IDA chunk boundaries as separately declared
dependency envelopes. Listings provide coordinates only; binary call/tail
composition must still validate every reachable instruction and return.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

from tools.comparator.msc8_catalog import ListingEndKind, listing_size
from tools.dosunit.catalog.flat32_catalog_admission import CatalogRangeStatus, check_function_extent

if TYPE_CHECKING:
    import angr


def listing_chunks(path: Path) -> tuple[tuple[str, int, int], ...]:
    """Read paired chunk-boundary metadata, rejecting ambiguous declarations.

    Like ordinary proc/endp metadata, END denotes the last instruction head.
    No instruction semantics are recovered from rendered listing text.
    """
    chunks: list[tuple[str, int, int]] = []
    opened: tuple[str, int] | None = None
    pattern = re.compile(r"\.text:([0-9A-Fa-f]+)\s+;\s+(START|END) OF FUNCTION CHUNK FOR (\S+)\s*$")
    with path.open(errors="replace") as stream:
        for line in stream:
            match = pattern.match(line)
            if match is None:
                continue
            raw_address, marker, owner = match.groups()
            address = int(raw_address, 16)
            if marker == "START":
                if opened is not None:
                    raise ValueError("nested listing chunk declarations")
                opened = owner, address
            else:
                if opened is None or opened[0] != owner or address < opened[1]:
                    raise ValueError("unmatched listing chunk boundary")
                chunks.append((owner, opened[1], address))
                opened = None
    if opened is not None:
        raise ValueError("unterminated listing chunk declaration")
    return tuple(chunks)


def with_listing_chunks(
    project: angr.Project, ranges: dict[str, tuple[int, int]], path: Path,
) -> dict[str, tuple[int, int]]:
    """Admit executable, nonoverlapping chunk envelopes for known owners.

    Chunks are dependency entries, never additional original-function proof
    obligations. A transfer to one still needs the existing binary-derived
    tail/CALL proof; declarations cannot discharge a verdict or widen a body.
    Non-code and undecodable final heads remain absent, so reaching them keeps
    the existing unmapped-target refusal.
    """
    result = dict(ranges)
    for owner, start, last in listing_chunks(path):
        if owner not in ranges:
            continue
        initial = check_function_extent(project, entry=start, size=last - start + 1)
        if initial.status is not CatalogRangeStatus.ADMITTED:
            continue
        size = listing_size(project, start, last, ListingEndKind.INSTRUCTION)
        if size <= last - start:
            continue
        evidence = check_function_extent(project, entry=start, size=size)
        if evidence.status is not CatalogRangeStatus.ADMITTED:
            continue
        if any(start < entry + length and entry < start + size for entry, length in result.values()):
            raise ValueError("overlapping listing chunk and dependency declarations")
        label = f"{owner}@chunk:{start:x}"
        if label in result:
            raise ValueError("duplicate listing chunk label")
        result[label] = start, size
    return result
