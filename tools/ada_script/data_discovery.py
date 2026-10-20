"""Automatic db/dw/dd/string discovery for the ada_script analyzer.

Layer: disassembly-side evidence recovery (tools/ada_script).

Responsibility: turn collected memory references and unexplored
data-segment bytes into typed data items (byte/word/dword/qword/str)
and offset operand markings.

Two passes:

  * segment sweep: unexplored bytes inside non-executable segments are
    walked forward; each head is tested as a NUL-terminated C string or
    a length-prefixed (Pascal-style) string.  Relocation words and words
    loaded into segment registers become 'word' items unconditionally --
    they are declared evidence.

  * reference resolution: a data reference landing on unexplored bytes
    classifies the target as an offset word, a string literal, or a
    scalar item sized by the operand's access width -- in that order.
    `lea` produces an offset-style xref only; it never creates a data
    item at its target.

Item creation is conservative: nothing is created over decoded
instructions, existing items, relocation words, or segment boundaries.
"""

from __future__ import annotations

import bisect
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # avoid a module cycle; only the surface is used
    from tools.ada_script.analyzer import Analyzer

logger: logging.Logger = logging.getLogger(__name__)

# String character alphabet: printable ASCII plus the control characters
# accepted inside string literals (BEL BS TAB LF CR ESC).
_CTRL_OK = frozenset({0x07, 0x08, 0x09, 0x0A, 0x0D, 0x1B})

# Minimum content lengths: C strings need >=5 characters before the NUL;
# a length-prefixed candidate needs >=2; the segment sweep requires >=3
# for identifier-shaped length-prefixed strings.
_MIN_CSTR = 5
_MIN_PSTR = 2
_MIN_IDENT_PSTR = 3

# Bound on a single string scan; generous enough for long embedded text.
_MAX_SCAN = 4096

# Candidates >=16 bytes are rejected when they contain more than two
# distinct "unusual" character classes (ctrl / space / punct / high).
# Guards against binary runs that merely look textual.
_DIVERSITY_LEN = 16
_DIVERSITY_MAX_CLASSES = 2

# map access width -> item kind
_SIZE_KIND = {1: 'byte', 2: 'word', 4: 'dword', 8: 'qword'}


def _char_ok(b: int) -> bool:
    """True when byte b may appear inside a string candidate."""
    return 0x20 <= b <= 0x7E or b in _CTRL_OK


def _alnum(b: int) -> bool:
    """ASCII alphanumeric test (no locale/unicode surprises)."""
    return 0x30 <= b <= 0x39 or 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A


def _alpha(b: int) -> bool:
    """ASCII letter test."""
    return 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A


def _diversity_ok(data: bytes) -> bool:
    """Character-class diversity scorer for string candidates.

    Short candidates pass unconditionally; longer ones are rejected when
    more than two distinct non-alphanumeric classes appear.
    """
    if len(data) < _DIVERSITY_LEN:
        return True
    classes = set()
    for b in data:
        if _alnum(b):
            continue
        if b in _CTRL_OK:
            classes.add('ctrl')
        elif b == 0x20:
            classes.add('space')
        elif b < 0x80:
            classes.add('punct')
        else:
            classes.add('high')
        if len(classes) > _DIVERSITY_MAX_CLASSES:
            return False
    return True


@dataclass
class DiscoveryStats:
    """Evidence counters for one discovery run."""
    strings: int = 0          # str items (C-terminated)
    pascal_strings: int = 0   # str items (length-prefixed)
    utf16_strings: int = 0    # str items (UTF-16LE)
    byte_items: int = 0
    word_items: int = 0
    dword_items: int = 0
    qword_items: int = 0
    offset_words: int = 0     # word items marked `offset`
    offset_only_refs: int = 0 # lea targets (xref but no item)
    skipped_busy: int = 0
    skipped_unmapped: int = 0


class DataDiscovery:
    """Automatic data-item discovery over an analyzed binary.

    The constructor captures an Analyzer after its disassembly passes;
    run() creates data_items rows (in memory and in the database) and
    offset op_overrides, then reports evidence counters.
    """

    def __init__(self, an: Analyzer) -> None:
        """Capture a post-disassembly Analyzer; run() performs discovery."""
        self.an = an
        self.stats = DiscoveryStats()
        self._busy: list[list[int]] = []      # sorted [start, end) spans
        self._busy_starts: list[int] = []
        self._hard: list[int] = []            # relocs + seg-word addrs
        self._hard_set: set[int] = set()
        self._created: list[tuple[int, int, str]] = []   # (addr,size,kind)
        self._offsets: list[tuple[int, int]] = []        # (addr, base)

    # ------------------------------------------------------------ run --
    def run(self) -> DiscoveryStats:
        """Populate discovered data items; returns evidence counters."""
        self._build_spans()
        self._sweep_segments()
        self._resolve_refs()
        self._commit()
        return self.stats

    # ------------------------------------------------------- occupancy --
    def _build_spans(self) -> None:
        """Occupied byte ranges: instructions + existing data items."""
        spans: list[list[int]] = [
            [i['addr'], i['addr'] + i['size']] for i in self.an.instructions]
        spans += [
            [a, a + sz * max(cnt, 1)]
            for a, (sz, _k, cnt) in self.an.data_items.items()]
        spans.sort()
        self._busy = spans
        self._busy_starts = [s for s, _e in spans]
        self._hard = sorted(set(self.an.relocs) | set(self.an.seg_words))
        self._hard_set = set(self._hard)

    def _busy_span(self, ea: int) -> list[int] | None:
        """The occupied span containing ea, or None."""
        i = bisect.bisect_right(self._busy_starts, ea) - 1
        if i >= 0 and ea < self._busy[i][1]:
            return self._busy[i]
        return None

    def _mark_busy(self, ea: int, size: int) -> None:
        """Insert [ea, ea+size) into the occupied span set (ordered)."""
        idx = bisect.bisect_right(self._busy_starts, ea)
        self._busy.insert(idx, [ea, ea + size])
        self._busy_starts.insert(idx, ea)

    def _free_limit(self, ea: int) -> int:
        """Exclusive end of the unexplored run starting at ea.

        Bounded by the next occupied span, the next hard address
        (relocation word / segment word) and the containing segment end.
        """
        limit = 1 << 62
        i = bisect.bisect_right(self._busy_starts, ea)
        if i < len(self._busy_starts):
            limit = self._busy_starts[i]
        j = bisect.bisect_right(self._hard, ea)
        if j < len(self._hard):
            limit = min(limit, self._hard[j])
        seg = self.an.seg_of(ea)
        if seg is not None:
            limit = min(limit, seg['end'])
        return limit

    def _read(self, ea: int, size: int) -> bytes | None:
        """File-backed bytes at linear ea (None when unmapped)."""
        return self.an.db.read_bytes(ea, size)

    # -------------------------------------------------------- creation --
    def _create(self, ea: int, size: int, kind: str) -> None:
        """Register a data item in memory and in the database batch."""
        self.an.data_items[ea] = (size, kind, 1)
        self._created.append((ea, size, kind))
        self._mark_busy(ea, size)
        self.stats.byte_items += (kind == 'byte')
        self.stats.word_items += (kind == 'word')
        self.stats.dword_items += (kind == 'dword')
        self.stats.qword_items += (kind == 'qword')

    def _create_str(self, ea: int, size: int, pascal: bool = False,
                    utf16: bool = False) -> None:
        """Register a string literal item spanning `size` bytes."""
        self.an.data_items[ea] = (size, 'str', 1)
        self._created.append((ea, size, 'str'))
        self._mark_busy(ea, size)
        self.stats.strings += not (pascal or utf16)
        self.stats.pascal_strings += pascal
        self.stats.utf16_strings += utf16

    # ---------------------------------------------------- string tests --
    @staticmethod
    def _cstring_len(data: bytes) -> int:
        """Content length of a NUL-terminated ASCII candidate, or -1.

        Every character must be printable ASCII or an accepted control;
        the run must terminate within bounds and be at least _MIN_CSTR
        chars long.
        """
        n = 0
        while n < len(data):
            b = data[n]
            if b == 0:
                return n if n >= _MIN_CSTR else -1
            if not _char_ok(b):
                return -1
            n += 1
        return -1  # no terminator inside bounds

    @staticmethod
    def _pascal_len(data: bytes, ident_only: bool) -> int:
        """Content length of a 1-byte-length-prefixed candidate, or -1.

        ident_only selects the strict identifier validator (alpha/'_'
        head, alnum/'_' body); otherwise the looser printable-content
        rule applies.
        """
        if not data:
            return -1
        n = data[0]
        minlen = _MIN_IDENT_PSTR if ident_only else _MIN_PSTR
        if n < minlen or n + 1 > len(data):
            return -1
        body = data[1:1 + n]
        if ident_only:
            if not (_alpha(body[0]) or body[0] == 0x5F):
                return -1
            if not all(_alnum(b) or b == 0x5F for b in body):
                return -1
        elif not all(_char_ok(b) for b in body):
            return -1
        return n

    @staticmethod
    def _utf16_len(data: bytes) -> int:
        """Char count of a UTF-16LE candidate at an even ea, or -1.

        Wide-char promotion: pairs (char, 0x00) ending in a
        (0x00, 0x00) terminator, >= _MIN_CSTR wchars.
        """
        n = 0
        i = 0
        while i + 1 < len(data):
            lo, hi = data[i], data[i + 1]
            if lo == 0 and hi == 0:
                return n if n >= _MIN_CSTR else -1
            if hi != 0 or not _char_ok(lo):
                return -1
            n += 1
            i += 2
        return -1

    def _string_span(self, ea: int, data: bytes) -> tuple[int, str] | None:
        """Longest accepted string candidate at ea -> (span_bytes, which).

        "Keep the longer variant": C and Pascal candidates compete;
        UTF-16LE is only tried on even addresses (the aligned-candidate
        gate).
        """
        best: tuple[int, str] | None = None
        n = self._cstring_len(data)
        if n > 0 and _diversity_ok(data[:n]):
            best = (n + 1, 'c')
        n = self._pascal_len(data, ident_only=False)
        if n > 0 and _diversity_ok(data[1:1 + n]):
            cand = (n + 1, 'pascal')
            if best is None or cand[0] > best[0]:
                best = cand
        if ea % 2 == 0:
            n = self._utf16_len(data)
            if n > 0:
                cand = (2 * n + 2, 'utf16')
                if best is None or cand[0] > best[0]:
                    best = cand
        return best

    # ------------------------------------------------ segment sweep -----
    def _sweep_segments(self) -> None:
        """Walk unexplored bytes of non-executable segments.

        At every unexplored head, try a C string then a strict
        identifier-form Pascal string.  Relocation and segment-register
        words become 'word' items.  Anything else stays unexplored.
        """
        for seg in self.an.segments:
            if seg['exec'] or seg['type'] == 'stack':
                continue
            ea = seg['start']
            while ea < seg['end']:
                span = self._busy_span(ea)
                if span is not None:
                    ea = span[1]
                    continue
                if ea in self._hard_set:
                    # a declared fixup / segment word: real data, always
                    if ea + 2 <= self._free_limit(ea):
                        self._create(ea, 2, 'word')
                        ea += 2
                    else:
                        ea += 1
                    continue
                limit = min(self._free_limit(ea), ea + _MAX_SCAN)
                data = self._read(ea, limit - ea)
                if not data:
                    ea += 1
                    continue
                n = self._cstring_len(data)
                if n > 0 and _diversity_ok(data[:n]):
                    self._create_str(ea, n + 1)
                    ea += n + 1
                    continue
                n = self._pascal_len(data, ident_only=True)
                if n > 0:
                    self._create_str(ea, n + 1, pascal=True)
                    ea += n + 1
                    continue
                ea += 1

    # ------------------------------------------------- ref resolution ---
    def _offset_target(self, ea: int, seg: dict) -> tuple[int, int] | None:
        """If the word at ea is a plausible near offset, return
        (linear_target, segment_linear_base).  None otherwise.

        The value resolves via the tracked DS value (containing-segment
        base as fallback) and must land inside a known segment.
        """
        raw = self._read(ea, 2)
        if raw is None or len(raw) < 2:
            return None
        val = int.from_bytes(raw, 'little')
        if val == 0:
            return None
        sval = self.an.sreg_value(ea, 'ds')
        if sval is None or sval < 0:
            sval = seg['base']
        tgt = sval * 16 + val
        if self.an.seg_of(tgt) is None:
            return None
        return tgt, sval * 16

    def _fit_size(self, want: int, gap: int) -> int:
        """Access width clipped to what fits in the unexplored gap."""
        size = max((s for s in _SIZE_KIND if s <= want), default=1)
        while size > 1 and size > gap:
            size >>= 1
        return size

    def _resolve_refs(self) -> None:
        """Classify each referenced unexplored address as offset word,
        string, or sized scalar -- the classic dref-resolution order."""
        for ea in sorted(self.an.data_refs):
            kinds = self.an.data_refs[ea]
            if all(xt == 'o' for _sz, xt in kinds):
                # lea operands reference, never create
                self.stats.offset_only_refs += 1
                continue
            seg = self.an.seg_of(ea)
            if ea < self.an.base or seg is None or seg['exec']:
                self.stats.skipped_unmapped += 1
                continue
            if self._busy_span(ea) is not None:
                self.stats.skipped_busy += 1
                continue
            limit = self._free_limit(ea)
            if limit <= ea:
                continue
            if ea in self._hard_set:
                if ea + 2 <= limit:
                    self._create(ea, 2, 'word')
                continue
            sizes = {s for s, xt in kinds if xt != 'o'}
            # decision order on the referenced bytes:
            #   offset -> string -> plain item
            if 2 in sizes and limit - ea >= 2 and \
                    self._make_offset_word(ea, seg):
                continue
            data = self._read(ea, min(limit - ea, _MAX_SCAN)) or b''
            slen = self._string_span(ea, data)
            if slen is not None:
                self._create_str(ea, slen[0], pascal=slen[1] == 'pascal',
                                 utf16=slen[1] == 'utf16')
                continue
            size = self._fit_size(max(sizes, default=1), limit - ea)
            self._create(ea, size, _SIZE_KIND.get(size, 'byte'))

    def _make_offset_word(self, ea: int, seg: dict) -> bool:
        """Create an offset-marked word item when the word at ea resolves
        to a target inside a known segment.  Returns True when done."""
        off = self._offset_target(ea, seg)
        if off is None:
            return False
        tgt, base = off
        self._create(ea, 2, 'word')
        self._offsets.append((ea, base))
        self.an.xrefs.append((ea, tgt, 'o'))
        self._label_target(tgt)
        self.stats.offset_words += 1
        return True

    def _label_target(self, tgt: int) -> None:
        """Give an offset target an auto label so `dw offset X` renders."""
        if tgt in self.an.names:
            return
        if tgt in self.an.funcs or tgt in self.an.covered or \
                tgt in self.an.code_refs:
            self.an.label_at(tgt, 'loc')
        elif tgt in self.an.data_items:
            self.an.label_at(tgt, self.an.data_items[tgt][1])
        else:
            self.an.label_at(tgt, 'unk')

    # ------------------------------------------------------------ commit
    def _commit(self) -> None:
        """Persist created items and offset markings; refresh caches."""
        if self._created:
            self.an.db.conn.executemany(
                "INSERT OR REPLACE INTO data_items (addr, size, kind, count) "
                "VALUES (?, ?, ?, 1)", self._created)
            self.an._di_sorted = sorted(self.an.data_items)
        if self._offsets:
            self.an.db.conn.executemany(
                "INSERT OR IGNORE INTO op_overrides (addr, opnum, kind, arg, arg2) "
                "VALUES (?, 0, 'offset', ?, 0)", self._offsets)
        s = self.stats
        self.an.db.conn.executemany(
            "INSERT OR REPLACE INTO stats (key, value) VALUES (?, ?)",
            [('data_items_auto', self._scalar_count()),
             ('data_strings_auto',
              s.strings + s.pascal_strings + s.utf16_strings)])
        logger.info(
            "Data discovery: %d str (%d pascal, %d utf16), "
            "%d db/%d dw/%d dd/%d dq items, %d offset words, "
            "%d lea refs, %d busy skips",
            s.strings + s.pascal_strings + s.utf16_strings,
            s.pascal_strings, s.utf16_strings,
            s.byte_items, s.word_items, s.dword_items, s.qword_items,
            s.offset_words, s.offset_only_refs, s.skipped_busy)

    def _scalar_count(self) -> int:
        """Total non-string items created this run."""
        s = self.stats
        return (s.byte_items + s.word_items + s.dword_items
                + s.qword_items)


def discover_data_items(an: Analyzer) -> DiscoveryStats:
    """Run automatic data discovery on a finished Analyzer.

    Must be called after the disassembly passes so that instruction
    coverage and data_refs are final; before operand rendering so that
    discovered labels/items are usable.
    """
    return DataDiscovery(an).run()
