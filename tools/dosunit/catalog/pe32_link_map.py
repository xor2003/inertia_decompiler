"""Layer: dosunit input verification.

Responsibility: bind a supplied MSVC LINK /MAP file to the PE32 candidate it
describes before trusting its public-symbol relocation evidence. Parsing is
bounded and strict: malformed structure, a header disagreeing with the
candidate's own timestamp or image base, or publics referencing undeclared
segments refuse instead of guessing. The map supplies relocation premise
evidence only; it never establishes pointer aliasing or data initialization.
"""

from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

#: Hard input bounds; a real /MAP file is far below every one of them.
MAX_MAP_BYTES: int = 64 * 1024 * 1024
MAX_MAP_LINES: int = 500_000
MAX_SEGMENTS: int = 4_096
MAX_PUBLICS: int = 250_000
MAX_HEADER_BYTES: int = 1 * 1024 * 1024

_TIMESTAMP_ROW = re.compile(r"^\s*Timestamp is ([0-9A-Fa-f]{1,8})\b")
_BASE_ROW = re.compile(r"^\s*Preferred load address is ([0-9A-Fa-f]{1,8})\s*$")
_SEGMENT_HEAD = re.compile(r"^\s*Start\s+Length\s+Name\s+Class\s*$")
_SEGMENT_ROW = re.compile(
    r"^\s*([0-9A-Fa-f]{4}):([0-9A-Fa-f]{8})\s+([0-9A-Fa-f]{1,12})H\s+(\S+)\s+(\S+)\s*$"
)
_PUBLIC_HEAD = re.compile(r"^\s*Address\s+Publics by Value\s+Rva\+Base\s+Lib:Object\s*$")
_PUBLIC_ROW = re.compile(
    r"^\s*([0-9A-Fa-f]{4}):([0-9A-Fa-f]{8})\s+(\S+)\s+([0-9A-Fa-f]{8})(?:\s+(.*\S))?\s*$"
)
_PUBLIC_TERMINATOR = re.compile(
    r"^\s*(?:entry point at|Static symbols|FIXUPS:|Exports|Imports|Line numbers)"
)
#: One canonical MSVC underscore decoration on an address-encoded data label;
#: ``__dword_x`` (two prefixes) and bare ``dword_x`` are not map data aliases.
_DATA_ALIAS = re.compile(r"^_(byte|word|dword|qword|off|unk)_([0-9A-Fa-f]+)$")


class LinkMapRejection(StrEnum):
    """Typed reason a supplied LINK map or image cannot serve as premise."""

    OVERSIZED_FILE = "oversized_file"
    BOUND_EXCEEDED = "bound_exceeded"
    MISSING_HEADER = "missing_header"
    MALFORMED_LINE = "malformed_line"
    UNDECLARED_SEGMENT = "undeclared_segment"
    NOT_PE32 = "not_pe32"
    IMAGE_MISMATCH = "image_mismatch"


class LinkMapError(ValueError):
    """A supplied map or image failed its bounded parse or binding check."""

    def __init__(self, reason: LinkMapRejection, detail: str) -> None:
        """Keep the typed refusal cause on the raised exception."""
        super().__init__(f"{reason}: {detail}")
        self.reason = reason


@dataclass(frozen=True)
class Pe32Identity:
    """The two header fields a LINK map header must agree with."""

    image_base: int
    timestamp: int


@dataclass(frozen=True)
class MapSegment:
    """One ``Start/Length/Name/Class`` record; ``is_code`` marks CODE class."""

    index: int
    offset: int
    length: int
    name: str
    is_code: bool


@dataclass(frozen=True)
class MapPublic:
    """One ``Publics by Value`` record; ``address`` is the linked ``Rva+Base``."""

    segment: int
    offset: int
    name: str
    address: int
    origin: str

    def data_alias(self) -> tuple[str, int] | None:
        """Canonical ``(name, encoded_va)`` for a data alias, else ``None``.

        Only the single-underscore decorated ``_dword_8A5EC`` form maps to the
        canonical ``dword_8A5EC`` oracle label; anything else is not claimed.
        """
        match = _DATA_ALIAS.fullmatch(self.name)
        if match is None:
            return None
        return f"{match.group(1)}_{int(match.group(2), 16):X}", int(match.group(2), 16)


@dataclass(frozen=True)
class Pe32LinkMap:
    """A bound LINK map: verified header plus declared segments and publics."""

    path: Path
    sha256: str
    module: str
    timestamp: int
    preferred_base: int
    segments: tuple[MapSegment, ...]
    publics: tuple[MapPublic, ...]
    _segment_index: dict[int, tuple[MapSegment, ...]]

    def segment(self, index: int, offset: int) -> MapSegment | None:
        """Return the declared segment record containing ``index:offset``.

        LINK reuses one section index for same-section contributions (for
        example ``.data`` and ``.CRT$XCA`` rows share ``0004:``), so a public
        resolves to the record whose ``[offset, offset+length)`` range covers
        its offset, not merely to the first row with its index.
        """
        candidates = [record for record in self._segment_index.get(index, ())
                      if record.offset <= offset < record.offset + record.length]
        return candidates[0] if len(candidates) == 1 else None

    def provenance(self) -> dict[str, object]:
        """Publish the exact map identity bound into a comparison premise."""
        return {
            "path": str(self.path),
            "sha256": self.sha256,
            "module": self.module,
            "timestamp": f"{self.timestamp:08x}",
            "preferred_base": f"{self.preferred_base:08x}",
            "segment_count": len(self.segments),
            "public_count": len(self.publics),
        }


def read_pe32_identity(path: Path) -> Pe32Identity:
    """Read image base and timestamp from a PE32 header without trusting size."""
    with path.open("rb") as stream:
        raw = stream.read(MAX_HEADER_BYTES)
    if len(raw) < 0x40 or raw[:2] != b"MZ":
        raise LinkMapError(LinkMapRejection.NOT_PE32, f"{path}: no MZ header")
    pe_offset = struct.unpack_from("<I", raw, 0x3C)[0]
    if pe_offset + 24 + 32 > len(raw) or raw[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise LinkMapError(LinkMapRejection.NOT_PE32, f"{path}: no PE signature")
    machine, _sections, timestamp, _symtab, _symbols, optional_size = struct.unpack_from(
        "<HHIIIH", raw, pe_offset + 4
    )
    if machine != 0x14C:
        raise LinkMapError(LinkMapRejection.NOT_PE32, f"{path}: not an i386 image")
    optional = pe_offset + 24
    if optional_size < 32 or optional + optional_size > len(raw):
        raise LinkMapError(LinkMapRejection.NOT_PE32, f"{path}: truncated optional header")
    magic = struct.unpack_from("<H", raw, optional)[0]
    if magic != 0x10B:
        raise LinkMapError(LinkMapRejection.NOT_PE32, f"{path}: not a PE32 optional header")
    return Pe32Identity(
        image_base=struct.unpack_from("<I", raw, optional + 28)[0], timestamp=timestamp
    )


def _scan_header(lines: list[str], path: Path) -> tuple[str, int, int, int]:
    """Consume the module, timestamp and base lines before the segment table.

    Returns ``(module, timestamp, preferred_base, next_line_index)`` with the
    index positioned at the ``Start/Length/Name/Class`` header.
    """
    module = ""
    timestamp: int | None = None
    preferred_base: int | None = None
    for index, line in enumerate(lines):
        text = line.strip()
        if not text:
            continue
        if not module:
            module = text
            continue
        field = _TIMESTAMP_ROW.match(text)
        if field is not None:
            if timestamp is not None:
                raise LinkMapError(LinkMapRejection.MALFORMED_LINE, f"{path}: duplicate timestamp")
            timestamp = int(field.group(1), 16)
            continue
        field = _BASE_ROW.match(text)
        if field is not None:
            if preferred_base is not None:
                raise LinkMapError(LinkMapRejection.MALFORMED_LINE, f"{path}: duplicate preferred base")
            preferred_base = int(field.group(1), 16)
            continue
        if _SEGMENT_HEAD.match(text):
            if timestamp is None or preferred_base is None:
                raise LinkMapError(
                    LinkMapRejection.MISSING_HEADER,
                    f"{path}: timestamp and preferred base are both required",
                )
            return module, timestamp, preferred_base, index
        raise LinkMapError(
            LinkMapRejection.MALFORMED_LINE, f"{path}:{index + 1}: unknown header line"
        )
    raise LinkMapError(LinkMapRejection.MISSING_HEADER, f"{path}: no segment table")


def _scan_segments(lines: list[str], start: int, path: Path) -> tuple[list[MapSegment], int]:
    """Consume ``seg:offset lengthH name class`` rows until the publics header."""
    segments: list[MapSegment] = []
    for index in range(start + 1, len(lines)):
        text = lines[index].rstrip()
        if not text.strip():
            continue
        if _PUBLIC_HEAD.match(text):
            if not segments:
                raise LinkMapError(LinkMapRejection.MISSING_HEADER, f"{path}: empty segment table")
            return segments, index
        match = _SEGMENT_ROW.match(text)
        if match is None:
            raise LinkMapError(
                LinkMapRejection.MALFORMED_LINE, f"{path}:{index + 1}: malformed segment row"
            )
        if len(segments) >= MAX_SEGMENTS:
            raise LinkMapError(LinkMapRejection.BOUND_EXCEEDED, f"{path}: too many segments")
        segments.append(
            MapSegment(
                index=int(match.group(1), 16),
                offset=int(match.group(2), 16),
                length=int(match.group(3), 16),
                name=match.group(4),
                is_code=match.group(5).upper() == "CODE",
            )
        )
    if not segments:
        raise LinkMapError(LinkMapRejection.MISSING_HEADER, f"{path}: empty segment table")
    return segments, len(lines)


def _scan_publics(lines: list[str], start: int, path: Path) -> list[MapPublic]:
    """Consume ``seg:offset name rvabase origin`` rows until a known trailer."""
    publics: list[MapPublic] = []
    for index in range(start + 1, len(lines)):
        text = lines[index].rstrip()
        if not text.strip():
            continue
        if _PUBLIC_TERMINATOR.match(text):
            break
        match = _PUBLIC_ROW.match(text)
        if match is None:
            raise LinkMapError(
                LinkMapRejection.MALFORMED_LINE, f"{path}:{index + 1}: malformed public row"
            )
        if len(publics) >= MAX_PUBLICS:
            raise LinkMapError(LinkMapRejection.BOUND_EXCEEDED, f"{path}: too many publics")
        publics.append(
            MapPublic(
                segment=int(match.group(1), 16),
                offset=int(match.group(2), 16),
                name=match.group(3),
                address=int(match.group(4), 16),
                origin=(match.group(5) or "").strip(),
            )
        )
    return publics


def parse_link_map(path: Path) -> Pe32LinkMap:
    """Parse one MSVC LINK /MAP file under explicit bounds, refusing ambiguity.

    Only the ``Publics by Value`` table supplies relocation evidence; static
    symbols, fixups and later sections are ignored once the publics table ends.
    Any unrecognized nonblank line inside a recognized section refuses rather
    than guessing a continuation.
    """
    with path.open("rb") as stream:
        blob = stream.read(MAX_MAP_BYTES + 1)
    if len(blob) > MAX_MAP_BYTES:
        raise LinkMapError(LinkMapRejection.OVERSIZED_FILE, f"{path}: >{MAX_MAP_BYTES} bytes")
    digest = hashlib.sha256(blob).hexdigest()
    lines = blob.decode("latin-1").splitlines()
    if len(lines) > MAX_MAP_LINES:
        raise LinkMapError(LinkMapRejection.BOUND_EXCEEDED, f"{path}: >{MAX_MAP_LINES} lines")
    module, timestamp, preferred_base, cursor = _scan_header(lines, path)
    segments, cursor = _scan_segments(lines, cursor, path)
    publics = _scan_publics(lines, cursor, path)
    grouped: dict[int, list[MapSegment]] = {}
    for record in segments:
        grouped.setdefault(record.index, []).append(record)
    segment_index = {index: tuple(records) for index, records in grouped.items()}
    for public in publics:
        if public.segment not in segment_index:
            raise LinkMapError(
                LinkMapRejection.UNDECLARED_SEGMENT,
                f"{path}: public {public.name} uses undeclared segment {public.segment:04x}",
            )
    return Pe32LinkMap(
        path=path,
        sha256=digest,
        module=module,
        timestamp=timestamp,
        preferred_base=preferred_base,
        segments=tuple(segments),
        publics=tuple(publics),
        _segment_index=segment_index,
    )


def load_candidate_link_map(map_path: Path, candidate_exe: Path) -> Pe32LinkMap:
    """Bind a LINK map to its exact PE32 image before trusting any record.

    The map's own ``Timestamp`` and ``Preferred load address`` must equal the
    candidate's ``TimeDateStamp`` and ``ImageBase``; a map produced for any
    other link refuses instead of silently applying another image's layout.
    """
    link_map = parse_link_map(map_path)
    identity = read_pe32_identity(candidate_exe)
    if link_map.timestamp != identity.timestamp:
        raise LinkMapError(
            LinkMapRejection.IMAGE_MISMATCH,
            f"{map_path}: timestamp {link_map.timestamp:08x} != image {identity.timestamp:08x}",
        )
    if link_map.preferred_base != identity.image_base:
        raise LinkMapError(
            LinkMapRejection.IMAGE_MISMATCH,
            f"{map_path}: preferred base {link_map.preferred_base:08x} != image "
            f"{identity.image_base:08x}",
        )
    return link_map
