"""Layer: validation dependency catalogs.

Responsibility: collect each image's declared executable helpers independently
of root correspondence. A label selects bytes; only composition of those bytes
can prove the paired root, even when helper names or counts differ.
"""

from __future__ import annotations

from itertools import pairwise
from typing import TYPE_CHECKING

from tools.comparator.msc8_catalog import ListingEndKind, Symbol, listing_size
from tools.dosunit.catalog.flat32_catalog_admission import CatalogRangeStatus, check_function_extent
from tools.dosunit.catalog.pe32_link_map import LinkMapError, LinkMapRejection, MapPublic, Pe32LinkMap

if TYPE_CHECKING:
    import angr


def original_dependencies(
    project: angr.Project, boundaries: dict[str, tuple[int, int]],
) -> dict[str, tuple[int, int]]:
    """Admit original listing envelopes without requiring candidate labels.

    Validate the last instruction head before decoding it, then validate its
    complete byte extent. Undecodable and non-code declarations stay absent;
    any caller reaching them retains an unmapped dependency refusal.
    """
    ranges: dict[str, tuple[int, int]] = {}
    for name, (entry, last) in boundaries.items():
        head = check_function_extent(project, entry=entry, size=last - entry + 1)
        if head.status is not CatalogRangeStatus.ADMITTED:
            continue
        size = listing_size(project, entry, last, ListingEndKind.INSTRUCTION)
        if size <= last - entry:
            continue
        extent = check_function_extent(project, entry=entry, size=size)
        if extent.status is CatalogRangeStatus.ADMITTED:
            ranges[name] = entry, size
    return ranges


def candidate_dependencies(
    project: angr.Project, symbols: dict[str, Symbol], scan_limit: int,
) -> dict[str, tuple[int, int]]:
    """Admit candidate code symbols without requiring original counterparts.

    A zero-sized symbol provides an entry only; its bounded scan envelope
    cannot cross the loaded executable section. Neither a data symbol nor an
    unpaired label becomes a root correspondence by entering this catalog.
    """
    ranges: dict[str, tuple[int, int]] = {}
    delta = project.loader.main_object.mapped_base - project.loader.main_object.linked_base
    for name, symbol in symbols.items():
        if symbol.kind not in {"T", "t", "W", "w"}:
            continue
        entry = symbol.address + delta
        extent = check_function_extent(project, entry=entry, size=symbol.size)
        if extent.status is not CatalogRangeStatus.ADMITTED:
            continue
        size = symbol.size
        if size == 0:
            end = next(right for left, right in extent.executable_ranges if left <= entry < right)
            size = min(scan_limit, end - entry)
        if size > 0:
            ranges[name] = entry, size
    return ranges


def _segment_end_marker(project: angr.Project, link_map: Pe32LinkMap, symbol: MapPublic) -> bool:
    """Identify a verified one-past segment label without admitting code bytes.

    LINK can publish an arbitrary label at a contribution's exclusive end.
    It has no function body. Accept only that exact coordinate, bound to the
    actual loaded section; gaps, ambiguous containment and wrong addresses
    remain malformed declarations rather than ignored code entries.
    """
    records = [record for record in link_map.segments if record.index == symbol.segment]
    if any(record.offset <= symbol.offset < record.offset + record.length for record in records):
        return False
    endings = [record for record in records if record.offset + record.length == symbol.offset]
    if not endings:
        return False
    sections = project.loader.main_object.sections
    if not 1 <= symbol.segment <= len(sections):
        raise LinkMapError(LinkMapRejection.IMAGE_MISMATCH, "segment-end section index is outside image")
    section = sections[symbol.segment - 1]
    delta = project.loader.main_object.mapped_base - project.loader.main_object.linked_base
    entry = symbol.address + delta
    if (entry != section.min_addr + symbol.offset or entry > section.max_addr + 1
            or entry < section.min_addr or (any(record.is_code for record in endings) and not section.is_executable)):
        raise LinkMapError(LinkMapRejection.IMAGE_MISMATCH, f"segment-end address disagrees for {symbol.name}")
    return True


def _code_extent(project: angr.Project, link_map: Pe32LinkMap, symbol: MapPublic) -> tuple[int, int] | None:
    """Check the LINK segment coordinate against the actual executable section."""
    sections = project.loader.main_object.sections
    records = [record for record in link_map.segments if record.index == symbol.segment]
    if records and all(not record.is_code for record in records) and 1 <= symbol.segment <= len(sections):
        section = sections[symbol.segment - 1]
        if not section.is_executable:
            # LINK also lists absolute assembler aliases as wrapped offsets
            # from a DATA section. They do not declare function bytes. Data
            # relocation admission remains with link_map_global_map.
            return None
    segment = link_map.segment(symbol.segment, symbol.offset)
    if segment is None:
        if _segment_end_marker(project, link_map, symbol):
            return None
        raise LinkMapError(LinkMapRejection.UNDECLARED_SEGMENT, f"code map symbol {symbol.name} has no segment")
    if not segment.is_code:
        return None
    if not 1 <= symbol.segment <= len(sections):
        raise LinkMapError(LinkMapRejection.IMAGE_MISMATCH, "code map section index is outside image")
    section = sections[symbol.segment - 1]
    delta = project.loader.main_object.mapped_base - project.loader.main_object.linked_base
    entry = symbol.address + delta
    if not section.is_executable or entry != section.min_addr + symbol.offset:
        raise LinkMapError(LinkMapRejection.IMAGE_MISMATCH, f"code map address disagrees for {symbol.name}")
    end = section.min_addr + segment.offset + segment.length
    extent = check_function_extent(project, entry=entry, size=end - entry)
    if extent.status is not CatalogRangeStatus.ADMITTED:
        raise LinkMapError(LinkMapRejection.IMAGE_MISMATCH, f"code map extent disagrees for {symbol.name}")
    return entry, end


def with_code_map(
    project: angr.Project, ranges: dict[str, tuple[int, int]], link_map: Pe32LinkMap,
    *, partition_scan_envelopes: bool = False,
) -> dict[str, tuple[int, int]]:
    """Add image-verified code-symbol envelopes, including private helpers.

    Segment offsets must independently resolve to the claimed loaded address.
    A next-symbol or segment-end bound is only a scan envelope; the existing
    native CFG and return proofs remain mandatory. Explicit last-byte scan
    envelopes may be partitioned at newly declared entries; exact instruction
    bounds are never silently shortened. LINK names cannot create root pairs.
    """
    declarations: dict[int, tuple[str, int]] = {}
    for symbol in (*link_map.publics, *link_map.statics):
        extent = _code_extent(project, link_map, symbol)
        if extent is None:
            continue
        entry, end = extent
        if entry in declarations and declarations[entry][1] != end:
            raise LinkMapError(LinkMapRejection.MALFORMED_LINE, "conflicting code map segment extents")
        declarations.setdefault(entry, (symbol.name, end))
    result = dict(ranges)
    existing = {entry for entry, _size in ranges.values()}
    entries = sorted(declarations.keys() | existing | {end for _name, end in declarations.values()})
    next_entry = dict(pairwise(entries))
    if partition_scan_envelopes:
        result = {name: (entry, min(size, next_entry.get(entry, entry + size) - entry))
                  for name, (entry, size) in ranges.items()}
    for entry in sorted(declarations):
        if entry in existing:
            continue
        name, end = declarations[entry]
        end = min(end, next_entry.get(entry, end))
        result[f"link:{name}@{entry:x}"] = entry, end - entry
    return result


def refine_scan_symbols(
    project: angr.Project, symbols: dict[str, Symbol], link_map: Pe32LinkMap,
) -> dict[str, Symbol]:
    """Partition candidate last-byte envelopes before root extent admission.

    Only already selected code-symbol names are retained. A verified extra
    entry can shorten a coarse next-symbol scan range, including a range whose
    old endpoint crossed out of executable memory; actual native closure must
    still fit the resulting envelope. Data symbols and unknown extents remain
    unchanged, and this cannot establish a new root correspondence.
    """
    delta = project.loader.main_object.mapped_base - project.loader.main_object.linked_base
    ranges = {name: (symbol.address + delta, symbol.size) for name, symbol in symbols.items()
              if symbol.kind in {"T", "t", "W", "w"} and symbol.size > 0}
    refined = with_code_map(project, ranges, link_map, partition_scan_envelopes=True)
    result = dict(symbols)
    for name in ranges:
        symbol = symbols[name]
        result[name] = Symbol(symbol.address, refined[name][1], symbol.kind)
    return result
