"""Layer: optional disassembly CLI.

Responsibility: render the ada analysis database as an mzmap-format routine
map so the reconstruction toolchain (drv2asm, mzdiff, mzdup) can consume
ada's function discovery directly.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tools.ada_script.contracts import DatabaseView

_HEADER = """#
# Size of the executable's load module covered by the map
#
Size {size:x}
#
# Discovered segments, one per line, syntax is "SegmentName Type(CODE/DATA/STACK) Address [default]"
#
{segments}
#
# Discovered routines, one per line, syntax is "RoutineName: Segment Type(NEAR/FAR) Extents[DS] [R/U]Block1[DS]..."
#
{routines}
"""


@dataclass(frozen=True)
class _Segment:
    """One analysis segment with its map-format naming derived."""

    start: int
    end: int
    base: int
    kind: str
    name: str


def _segments(db: DatabaseView) -> list[_Segment]:
    """Load segments ordered by address; synthesize segNNN names like the LST."""
    rows = db.conn.execute(
        "SELECT start_addr, end_addr, base, class, type, executable, name "
        "FROM segments ORDER BY start_addr"
    ).fetchall()
    image_para = db.image_base >> 4
    out: list[_Segment] = []
    for i, (start, end, base, cls, typ, _exe, name) in enumerate(rows):
        kind = (cls or "").upper()
        if kind not in ("CODE", "DATA", "STACK"):
            kind = "CODE" if (typ or "") == "code" else "DATA"
        out.append(_Segment(start=start, end=end,
                            base=(base or (start >> 4)) - image_para,
                            kind=kind, name=name or f"seg{i:03d}"))
    return out


def _segment_of(segments: list[_Segment], addr: int) -> _Segment | None:
    """Return the segment containing addr, if any."""
    return next((s for s in segments if s.start <= addr < s.end), None)


def _contiguous_end(conn: sqlite3.Connection, start: int, bound: int) -> int:
    """Extent end (exclusive): instructions contiguous from start up to bound."""
    end = start
    for addr, size in conn.execute(
            "SELECT addr, size FROM instructions WHERE addr >= ? AND addr < ? "
            "ORDER BY addr", (start, bound)):
        if addr > end:
            break
        end = addr + (size or 1)
    return end


def _has_insn(conn: sqlite3.Connection, start: int, end: int) -> bool:
    """True when at least one decoded instruction lies inside [start, end)."""
    return conn.execute(
        "SELECT 1 FROM instructions WHERE addr >= ? AND addr < ? LIMIT 1",
        (start, end)).fetchone() is not None


def _far_targets(conn: sqlite3.Connection) -> set[int]:
    """Instruction-level far call/jmp targets; xrefs carry no far flag."""
    return {row[0] for row in conn.execute(
        "SELECT x.to_addr FROM xrefs x JOIN instructions i ON i.addr = x.from_addr "
        "WHERE x.type IN ('call', 'jmp') AND i.asm_str LIKE '%far%'")}


_FUNC_FAR = 0x2


def _is_far(conn: sqlite3.Connection, start: int, end: int, flags: int,
            far_targets: set[int]) -> bool:
    """FAR when flagged, far-called/jumped-to, or the extent has retf/iret."""
    if flags & _FUNC_FAR or start in far_targets:
        return True
    return conn.execute(
        "SELECT 1 FROM instructions WHERE addr >= ? AND addr < ? "
        "AND lower(mnem) IN ('retf', 'iret') LIMIT 1",
        (start, end)).fetchone() is not None


def write_map(db: DatabaseView, path: Path) -> int:
    """Write path as an mzmap-format map; return the routine count.

    Function extents come from the functions table; when a function has a
    degenerate end the extent is recovered as the contiguous instruction run
    bounded by the next function start in the same segment. Functions nested
    inside an already-claimed extent are labels, not routines -- they are
    skipped to keep the map non-overlapping. Functions in non-code segments
    carry no extent. NEAR/FAR is recovered from far call/jmp targets and
    retf/iret terminators since ada does not model proc distance.
    """
    conn = db.conn
    segments = _segments(db)
    funcs = conn.execute(
        "SELECT start, end, name, flags FROM functions ORDER BY start").fetchall()
    by_seg: dict[int, list[tuple[int, int, str, int]]] = {}
    for start, end, name, flags in funcs:
        seg = _segment_of(segments, start)
        if seg is not None:
            by_seg.setdefault(seg.start, []).append(
                (start, end, name or f"sub_{start:X}", flags or 0))

    far_targets = _far_targets(conn)
    claimed: list[tuple[int, int]] = []
    entries: list[tuple[int, int, str]] = []
    for seg in segments:
        claimed_end = seg.start
        seg_funcs = by_seg.get(seg.start, ())
        for i, (start, end, name, flags) in enumerate(seg_funcs):
            lo = start - seg.start
            if seg.kind != "CODE":
                entries.append((seg.base, lo, f"{name}: {seg.name} NEAR {lo:04x}-{lo:04x}"))
                continue
            if start < claimed_end:
                continue
            next_start = (seg_funcs[i + 1][0]
                          if i + 1 < len(seg_funcs) else seg.end)
            if end is None or end <= start:
                end = _contiguous_end(conn, start, min(next_start, seg.end))
            end = min(end, seg.end)
            claimed_end = max(claimed_end, end)
            claimed.append((start, end))
            hi = max(lo, end - 1 - seg.start)
            kind = ("FAR" if _is_far(conn, start, end, flags, far_targets)
                    else "NEAR")
            block = f" R{lo:04x}-{hi:04x}" if _has_insn(conn, start, end) else ""
            entries.append((seg.base, lo,
                            f"{name}: {seg.name} {kind} {lo:04x}-{hi:04x}{block}"))

    row = conn.execute(
        "SELECT value FROM config WHERE key='entry_addr'").fetchone()
    if row is not None:
        entry = int(row[0])
        seg = _segment_of(segments, entry)
        inside = any(f[0] <= entry < (f[1] or f[0] + 1) for f in claimed)
        if seg is not None and not inside:
            off = entry - seg.start
            entries.append((seg.base, off,
                            f"start: {seg.name} NEAR {off:04x}-{off:04x}"))

    lines = [line for _base, _lo, line in sorted(entries)]

    seg_lines = "\n".join(f"{s.name} {s.kind} {s.base:04x}" for s in segments)
    path.write_text(_HEADER.format(size=db.image_size, segments=seg_lines,
                                   routines="\n".join(lines)))
    return len(lines)
