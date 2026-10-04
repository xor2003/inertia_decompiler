"""Layer: optional assembly output.

Responsibility: render analyzed DOS bytes as IDA-style listings and UASM source.

IDA-style listing (.lst) and assembly (.asm) generator.

Renders the analysis database into a flat listing closely following the
IDA Pro .lst format:

    seg000:0016
    seg000:0016 loc_10016:
    seg000:0016                 mov     word ptr [bp+var_4+2], 0

Column conventions (measured from IDA output):
  * "segname:offset" prefix where offset = addr - (seg_base << 4)
  * instruction/data text starts at absolute column 24 when unlabeled
  * labels occupy a 16-char field starting right after the prefix, so a
    labeled directive lands at len(prefix) + 17
  * mnemonics get an 8-char field; comments/xrefs start at prefix + 41
"""

from __future__ import annotations

import bisect
import hashlib
import re
import zlib
from typing import Any, ClassVar

from utils import logger

# IDA attribute flag bits -> "Attributes:" words
FUNC_ATTRS = [
    (0x01, 'noreturn'), (0x02, 'far'), (0x04, 'library function'),
    (0x08, 'static'), (0x10, 'bp-based frame'), (0x40, 'hidden'),
    (0x80, 'thunk'), (0x100, 'bp based frame'),
]

XREF_KIND = {'call': 'CODE', 'fcall': 'CODE', 'jmp': 'CODE', 'fjmp': 'CODE',
             'r': 'DATA', 'w': 'DATA', 'o': 'DATA'}
XREF_CHAR = {'call': 'p', 'fcall': 'P', 'jmp': 'j', 'fjmp': 'J',
             'r': 'r', 'w': 'w', 'o': 'o'}

BANNER = "=============== S U B R O U T I N E " + "=" * 39
SEP = "-" * 75
SEGLINE = "=" * 75

# near (intra-segment) branches: cannot reach a label in another physical
# segment chunk -> byte-exact `db` fallback
_NEAR_BRANCH = {
    'jmp', 'call', 'jo', 'jno', 'jb', 'jnae', 'jc', 'jnb', 'jae', 'jnc',
    'jz', 'je', 'jnz', 'jne', 'jbe', 'jna', 'ja', 'jnbe', 'js', 'jns',
    'jp', 'jpe', 'jnp', 'jpo', 'jl', 'jnge', 'jge', 'jnl', 'jle', 'jng',
    'jg', 'jnle', 'jcxz', 'jecxz', 'loop', 'loope', 'loopne', 'loopz',
    'loopnz'}


# element size implied by an auto-name prefix (byte_/word_/dword_/...)
_PREFIX_SZ = {'byte': 1, 'word': 2, 'dword': 4, 'qword': 8,
              'fword': 6, 'tbyte': 10}
_DECL_SZ = {'db': 1, 'dw': 2, 'dd': 4, 'dq': 8, 'dt': 10, 'df': 6}
_SZ_KW = {1: 'byte', 2: 'word', 4: 'dword', 8: 'qword',
          6: 'fword', 10: 'tbyte'}
# `equ $+n` aliases are typeless -- uasm sizes them as words, which
# breaks byte-typed references.  Give them the type their prefix encodes.
_EQU_TYPES = {'byte_': 'byte ptr', 'word_': 'word ptr',
              'dword_': 'dword ptr', 'qword_': 'qword ptr',
              'tbyte_': 'tbyte ptr', 'fword_': 'fword ptr'}


def ida_num(value, force_hex=False):
    if value < 0:
        return '-' + ida_num(-value, force_hex)
    if value < 10 and not force_hex:
        return str(value)
    s = f"{value:X}"
    if s[0].isalpha():
        s = '0' + s
    return s + 'h'


class OutputGenerator:
    def __init__(self, db, filename='input.exe'):
        self.db = db
        self.filename = filename
        self._load()

    # ------------------------------------------------------------------ load
    def _load(self):
        c = self.db.conn
        self.segments = [
            {'start': s, 'end': e, 'base': base or (s >> 4), 'class': cls or '',
             'type': typ, 'exec': exe, 'name': name or f"seg{i:03d}",
             'align': al or 1, 'comb': comb or 2}
            for i, (s, e, base, cls, typ, exe, name, al, comb) in enumerate(
                c.execute("SELECT start_addr, end_addr, base, class, type, "
                          "executable, name, align, comb FROM segments "
                          "ORDER BY start_addr"))]
        # image regions outside every declared segment still hold real
        # bytes (alignment gaps, overlay tails) -- synthesize data segments
        # for them so the emitted image is complete
        img_end = self.db.image_base + self.db.image_size
        self.img_hi = img_end
        if img_end and self.segments:
            gaps = []
            prev = self.db.image_base
            for s in self.segments:
                if s['start'] > prev:
                    gaps.append((prev, s['start']))
                prev = max(prev, s['end'])
            if prev < img_end:
                gaps.append((prev, img_end))
            used = {s['name'] for s in self.segments}
            for gs, ge in gaps:
                gi = 0
                while f"seg{gi:03d}" in used:
                    gi += 1
                nm = f"seg{gi:03d}"
                used.add(nm)
                self.segments.append(
                    {'start': gs, 'end': ge, 'base': gs >> 4,
                     'class': 'DATA', 'type': '', 'exec': False,
                     'name': nm, 'align': 1, 'comb': 2})
            self.segments.sort(key=lambda s: s['start'])
        self.funcs = {s: {'end': e, 'name': n or f"sub_{s:X}", 'flags': f or 0}
                      for s, e, n, f in c.execute(
                          "SELECT start, end, name, flags FROM functions")}
        self.func_starts = sorted(self.funcs)
        self.names = {a: n for a, n in c.execute(
            "SELECT addr, name FROM symbols WHERE auto=0")}
        self.labels = {a: n for a, n in c.execute(
            "SELECT addr, name FROM symbols")}  # explicit + auto
        self._label_addrs = sorted(self.labels)
        self._name2addr = {n: a for a, n in self.labels.items()}
        # func names are operands too (call sub_XXXX) but live in the
        # functions table, not symbols
        self._name2addr.update(
            {fv['name']: fa for fa, fv in self.funcs.items()})
        self.data_items = {a: (sz, k, cnt) for a, sz, k, cnt in c.execute(
            "SELECT addr, size, kind, count FROM data_items")}
        self.insns = {a: (sz, mn, ops, aops, dbh) for a, sz, mn, ops, aops, dbh
                      in c.execute(
                          "SELECT addr, size, mnem, op_str, asm_str, db_bytes "
                          "FROM instructions WHERE type='code'")}
        self.comments = {a: cm for a, cm in c.execute(
            "SELECT addr, comment FROM comments")}
        self.extra = {}
        for a, ln, cm in c.execute(
                "SELECT addr, line, comment FROM extra_comments "
                "ORDER BY addr, line"):
            self.extra.setdefault(a, []).append((ln, cm))
        self.xrefs_to = {}
        for fr, to, typ in c.execute(
                "SELECT from_addr, to_addr, type FROM xrefs ORDER BY from_addr"):
            self.xrefs_to.setdefault(to, []).append((fr, typ))
        self.frame_vars = {}
        for f, off, n, sz in c.execute(
                "SELECT func_start, offset, name, size FROM frame_vars"):
            self.frame_vars.setdefault(f, {})[off] = (n, sz or 2)
        self.relocs = {a: p for a, p in c.execute(
            "SELECT addr, offset FROM relocations")}
        self.strucs = {i: n for i, n in c.execute(
            "SELECT id, name FROM strucs")}
        self.struc_members = {}
        for sn, mo, msz, mn in c.execute(
                "SELECT s.name, m.offset, m.size, m.name FROM struc_members m "
                "JOIN strucs s ON s.id=m.struc_id"):
            self.struc_members.setdefault(sn, []).append((mo, msz, mn))
        self.enum_names = {}
        for en, mn, v in c.execute(
                "SELECT e.name, m.name, m.value FROM enum_members m "
                "JOIN enums e ON e.id=m.enum_id"):
            self.enum_names.setdefault(en, {})[mn] = v
        self.sregs = {(s, r): v for s, r, v in c.execute(
            "SELECT seg_start, reg, value FROM sregs")}
        # split_sreg_range events: (addr, reg, value) -> `assume reg:seg`
        # tracking, the way a hand-maintained MASM source does it
        self.sreg_events = sorted(
            (s, r, v) for s, e, r, v in c.execute(
                "SELECT start_addr, end_addr, reg, value "
                "FROM sreg_ranges")
            if r in ('cs', 'ds', 'es', 'ss'))  # fs/gs don't exist on .286
        self.para2seg = {s['base']: s['name'] for s in self.segments}
        row = c.execute("SELECT value FROM config WHERE key='entry_addr'"
                        ).fetchone()
        self.entry = int(row[0]) if row else self.db.image_base
        # names that appear as branch/jump operands -> in the .asm their
        # label must be code-typed (`name:`) or `jmp`/`jcc short` fails
        self.branch_lbls = set()
        for _s, mnem, ops, _aops, _dbh in self.insns.values():
            if not mnem or not (mnem[0] == 'j' or mnem in (
                    'loop', 'loope', 'loopne', 'jcxz', 'call')):
                continue
            for op in (ops, _aops):
                if not op:
                    continue
                op = op.strip()
                for kw in ('short ', 'near ptr ', 'far ptr '):
                    if op.startswith(kw):
                        op = op[len(kw):]
                        break
                else:
                    if 'ptr' in op or '[' in op or ':' in op:
                        continue  # indirect via data cell, not a code target
                if re.match(r'^[A-Za-z_?@$][\w?@$.]*$', op):
                    self.branch_lbls.add(op)

        # sorted structural boundaries for gap/align detection
        self.bounds = sorted(set(self.funcs) | set(self.data_items)
                             | set(self.labels))
        # instruction addr -> next insn addr (fallthrough check)
        self.insn_addrs = sorted(self.insns)
        # funcs whose start lies strictly inside another func's range cannot
        # be `proc` blocks (nested proc = invalid MASM); they render as labels
        self.nested = set()
        fitems = sorted(self.funcs.items())
        for fs_, _ in fitems:
            for gs, gv in fitems:
                if gs < fs_ < gv['end']:
                    self.nested.add(fs_)
                    break

    # ------------------------------------------------------------- helpers
    def seg_of(self, addr):
        for s in self.segments:
            if s['start'] <= addr < s['end']:
                return s
        return None

    def prefix(self, seg, addr):
        off = addr - ((seg['base'] or (seg['start'] >> 4)) << 4)
        return f"{seg['name']}:{off:04X}"

    def _func_of(self, addr):
        i = bisect.bisect_right(self.func_starts, addr) - 1
        if i < 0:
            return None
        f = self.func_starts[i]
        end = self.funcs[f]['end']
        if addr < end or end <= f:
            return f
        return None

    def _xref_src(self, fr):
        f = self._func_of(fr)
        if f is not None:
            lbl = self.labels.get(fr)
            if lbl and fr != f:
                return f"{self.funcs[f]['name']}:{lbl}"
            return f"{self.funcs[f]['name']}+{fr - f:X}"
        seg = self.seg_of(fr)
        lbl = self.labels.get(fr)
        if seg and lbl:
            return f"{seg['name']}:{lbl}"
        if seg:
            off = fr - ((seg['base'] or 0) << 4)
            return f"{seg['name']}+{off:X}"
        return f"{fr:X}"

    def _xref_texts(self, addr):
        """Return list of comment strings for xrefs pointing at addr."""
        refs = self.xrefs_to.get(addr)
        if not refs:
            return []
        out = []
        first_kind = None
        shown = refs[:2]
        for fr, typ in shown:
            arrow = '↑' if fr < addr else '↓'
            ch = XREF_CHAR.get(typ, 'r')
            kind = XREF_KIND.get(typ, 'DATA')
            first_kind = first_kind or kind
            out.append(f"{self._xref_src(fr)}{arrow}{ch}")
        lines = [f"; {first_kind} XREF: {out[0]}"]
        for s in out[1:]:
            lines.append(f"; {s}" + (" ..." if len(refs) > 2 else ""))
        return lines

    @staticmethod
    def _nf(name):
        """IDA name field: short names pad to column 16, long names get a
        separating space so the directive doesn't glue onto the name."""
        return f"{name:<16}" if len(name) < 16 else name + ' '

    @staticmethod
    def _cmt_lines(text):
        """Normalize a (possibly multi-line) comment into ';'-prefixed lines."""
        return [ln if ln.startswith(';') else '; ' + ln
                for ln in str(text).splitlines()]

    def _annotate(self, line, p, addr):
        """Append comments/xrefs to a built line (p = seg:off prefix)."""
        cmts = []
        if addr in self.comments:
            cmts += self._cmt_lines(self.comments[addr])
        cmts += self._xref_texts(addr)
        if cmts:
            col = len(p) + 41
            line = line.ljust(col) + cmts[0]
            for extra in cmts[1:]:
                line += '\n' + p.ljust(col) + extra
        return line

    def _tag(self, addr, size):
        """`; @IMG_OFF:LEN` marker for asmfix-style reassembly checks --
        image offset of the first byte + emitted byte count."""
        return f' ; @{addr - self.db.image_base:X}:{size}'

    # ------------------------------------------------------------- segments
    def _seg_decl(self, seg, name=None, asm=False):
        align = {0: 'abs', 1: 'byte', 2: 'word', 3: 'para',
                 4: 'page', 5: 'dword', 6: 'qword'}.get(seg['align'], 'byte')
        comb = {0: 'private', 2: 'public', 4: 'public', 5: 'stack',
                6: 'common'}.get(seg['comb'], 'public')
        if asm and comb == 'stack':
            # 'stack' combine makes LINK drop the contents as BSS -- the
            # original image stores those bytes, so keep it a plain data
            # segment
            comb = 'public'
        if asm:
            # LINK groups same-class segments together, which would reorder
            # interleaved CODE/STACK/DATA regions -- one class preserves
            # declaration order = original image order
            cls = 'CODE'
        else:
            cls = seg['class'] or ('CODE' if seg['exec'] else 'DATA')
        return (f"{self._nf(name or seg['name'])}segment {align} "
                f"{comb} '{cls}' use16")

    def _seg_type_comment(self, seg):
        if seg['type'] == 'stack' or seg['class'] == 'STACK':
            return 'Uninitialized'
        return 'Pure code' if seg['exec'] else 'Pure data'

    # ------------------------------------------------------------- data
    def _raw(self, addr, size):
        fo = self.db.file_offset(addr)
        if fo is None or fo >= len(self.db.binary):
            return None
        return self.db.binary[fo:fo + size]

    def _struc_init(self, raw, members):
        """Render one struc instance as `<v, v, ..>` from its raw bytes.
        Byte-array members become quoted strings (uasm zero-pads); returns
        None when a member's content can't be expressed in <>."""
        vals = []
        for mo, msz, _mn in members:
            mr = raw[mo:mo + msz]
            if len(mr) < msz:
                return None
            if msz in (1, 2, 4):
                vals.append(ida_num(int.from_bytes(mr, 'little')))
            else:
                body = mr.split(b'\0')[0]
                if body and all(32 <= b < 127 and b != 39 for b in body):
                    vals.append("'" + body.decode('ascii') + "'")
                elif not any(mr):
                    # array member needs a dup/brace list, not a scalar
                    vals.append(f"{msz} dup(0)")
                else:
                    vals.append('{' + ','.join(
                        ida_num(b) for b in mr) + '}')
        return '<' + ', '.join(vals) + '>'

    def _data_body(self, addr, size, kind, count, p='', asm=False):
        """Return the directive text (without label) for a data item.

        Strings split at non-printable runs onto continuation `db` lines the
        way IDA does; `p` is the seg:off prefix for those continuations.
        """
        raw = self._raw(addr, size * max(count, 1))
        uninit = raw is None
        if kind == 'str':
            data = raw or b''
            lines = []        # list of part-lists, one per db line
            cur = []
            sbuf = None
            for b in data:
                if 32 <= b < 127 and b != 39:
                    if sbuf is None:
                        if cur:          # new printable run -> new db line
                            lines.append(cur)
                            cur = []
                        sbuf = ''
                    sbuf += chr(b)
                else:
                    if sbuf is not None:
                        cur.append("'" + sbuf + "'")
                        sbuf = None
                    cur.append(ida_num(b))
            if sbuf is not None:
                cur.append("'" + sbuf + "'")
            if cur:
                lines.append(cur)
            if not lines:
                return 'db 0'
            out = 'db ' + ','.join(lines[0])
            for cont in lines[1:]:
                out += '\n' + p + ' ' * max(1, 26 - len(p)) + \
                    'db ' + ','.join(cont)
            return out
        if kind.startswith('struct:'):
            sname = kind.split(':', 1)[1]
            members = sorted(self.struc_members.get(sname) or [])
            if members and not uninit and raw:
                # real per-instance initializers, like IDA's `S <'x', 1, ..>`
                out = []
                for i in range(count):
                    init = self._struc_init(
                        raw[i * size:(i + 1) * size], members)
                    if init is None:        # non-expressible member content
                        out = None
                        break
                    out.append(f"{sname} {init}")
                if out is not None:
                    return ('\n' + p + ' ' * max(1, 26 - len(p))).join(out)
            # uasm: <0> fails when the struc has array members (initializer
            # must match field shape) -> emit <> (all-default fields)
            init = '<>' if asm else '<0>'
            if count > 1:
                return f"{sname} {count} dup({init})"
            return f"{sname} {init}"
        if count > 1:
            d = {1: 'db', 2: 'dw', 4: 'dd'}.get(size, 'db')
            if uninit:
                return f"{d} {ida_num(count, True)} dup(?)"
            elems = [int.from_bytes(raw[i * size:(i + 1) * size], 'little')
                     for i in range(count)]
            if len(set(elems)) == 1:
                return f"{d} {ida_num(count, True)} dup({ida_num(elems[0])})"
            # non-uniform array: list every element (dup would emit v1
            # only); wrap onto continuation lines like IDA does
            per = 16 if size == 1 else 8
            chunks = [elems[i:i + per] for i in range(0, count, per)]
            out = f"{d} " + ','.join(ida_num(v) for v in chunks[0])
            for cont in chunks[1:]:
                out += '\n' + p + ' ' * max(1, 26 - len(p)) + \
                    f"{d} " + ','.join(ida_num(v) for v in cont)
            return out
        d = {1: 'db', 2: 'dw', 4: 'dd', 8: 'dq'}.get(size, 'db')
        if uninit:
            return f"{d} ?"
        # word holding a relocated segment value -> 'dw seg name'
        if addr in self.relocs and size == 2:
            tgt = self.relocs[addr]
            seg = self.seg_of(tgt)
            if asm:
                # relocs[a] is the linear base the stored para points at --
                # a mandatory chunk boundary, so the chunk starting exactly
                # there reproduces the original stored value
                cn = self._chunk_for(tgt) or \
                    (self._nf(seg['name']) if seg else None)
                return f"dw seg {cn}" if cn else \
                    f"dw {ida_num(int.from_bytes(raw[:2], 'little'))}"
            return f"dw seg {seg['name']}" if seg else f"dw {ida_num(tgt)}"
        val = int.from_bytes(raw[:size], 'little')
        # explicit offset override: op_plain_offset(ea, n, base)
        if size in (2, 4):
            ovr = self.db.conn.execute(
                "SELECT arg FROM op_overrides WHERE addr=? AND kind='offset' "
                "LIMIT 1", (addr,)).fetchone()
            if ovr:
                if asm and size == 2:
                    # a near offset word is never relocated -- emitting the
                    # original value is byte-exact and needs no fixup frame
                    return f"dw {ida_num(val, True)}"
                tgt = (ovr[0] + val) & 0xFFFFFFFF
                nm = self.labels.get(tgt)
                return f"{d} offset {nm}" if nm else \
                    f"{d} offset {ida_num(val, True)}"
        # heuristic: word value + ds lands on a named location -> offset
        if size == 2:
            base = self._sreg_at(addr, 'ds')
            if base is not None:
                tgt = base * 16 + val
                if tgt in self.names:
                    if asm:
                        return f"dw {ida_num(val, True)}"
                    return f"dw offset {self.names[tgt]}"
        if size == 4:
            lo, hi = val & 0xFFFF, val >> 16
            # far pointer: stored high word is a para relative to load base
            seg = next((s for s in self.segments
                        if (s['base'] << 4) == self.db.image_base + hi * 16),
                       None)
            if seg:
                t = (seg['base'] << 4) + lo
                nm = self.labels.get(t)
                if asm:
                    # emit as offset-word + relocated seg word: the off
                    # word keeps the original group-relative value while
                    # `seg <chunk>` reproduces the original segment fixup;
                    # a `label dword` keeps the item's declared type so
                    # lds/les fixups still see a dword operand
                    cn = self._chunk_for(seg['start']) or \
                        self._nf(seg['name'])
                    head = 'label dword\n' + ' ' * 24 \
                        if self.labels.get(addr) else ''
                    return (f"{head}dw {ida_num(lo, True)}\n"
                            f"{'':24}dw seg {cn}")
                if nm:
                    return f"dd {nm}"
                if self.seg_of(t):
                    return f"dd {seg['name']}:{ida_num(lo, True)}"
            return f"dd {ida_num(val, True)}"
        return f"{d} {ida_num(val)}"

    def _sreg_at(self, addr, reg):
        seg = self.seg_of(addr)
        if seg and (seg['start'], reg) in self.sregs:
            return self.sregs[(seg['start'], reg)]
        row = self.db.conn.execute(
            "SELECT value FROM config WHERE key='default_ds'").fetchone()
        return int(row[0]) if row and reg == 'ds' else None

    def _byte_line(self, addr):
        raw = self._raw(addr, 1)
        if raw is None:
            return 'db ?'
        b = raw[0]
        line = 'db ' + ida_num(b).rjust(4)
        if 32 <= b < 127:
            line += f" ; {chr(b)}"
        return line

    # ------------------------------------------------------------- render
    def _func_header(self, seg, addr, fv):
        """Emit the subroutine banner block; returns list of lines."""
        p = self.prefix(seg, addr)
        lines = [p, f"{p} ; {BANNER}", p]
        attrs = [w for bit, w in FUNC_ATTRS if fv['flags'] & bit]
        typecmt = None
        for ln, cm in self.extra.get(addr, []):
            if ln == -1:
                typecmt = cm
        if attrs:
            lines.append(f"{p} ; Attributes: {' '.join(attrs)}")
            lines.append(p)
        if typecmt:
            for cl in self._cmt_lines(typecmt):
                lines.append(f"{p} {cl}")
        if not attrs and not typecmt:
            lines.append(p)
        if self._is_public(addr):
            lines.append(f"{p}{' ' * max(1, 24 - len(p))}public {fv['name']}")
        body = f"{self._nf(fv['name'])}proc {'far' if fv['flags'] & 2 else 'near'}"
        lines.append(self._annotate(f"{p} {body}", p, addr))
        # frame var equates
        fvmap = self.frame_vars.get(addr)
        if fvmap:
            lines.append(p)
            for off in sorted(fvmap):
                nm, vsz = fvmap[off]
                sz = {1: 'byte ptr', 2: 'word ptr', 4: 'dword ptr',
                      8: 'qword ptr'}.get(vsz, 'word ptr')
                sign = '-' if off < 0 else ' '
                lines.append(f"{p} {self._nf(nm)}= {sz} {sign}"
                             f"{ida_num(abs(off))}")
            lines.append(p)
        return lines

    def _is_public(self, addr):
        if addr == self.entry:
            return True
        if addr not in self.names:
            return False
        seg = self.seg_of(addr)
        if not seg:
            return False
        for fr, _typ in self.xrefs_to.get(addr, []):
            s2 = self.seg_of(fr)
            if s2 and s2 is not seg:
                return True
        return False

    def _seg_chunks(self, seg):
        """Split a >64K segment into <=64K chunks.

        MASM caps a segment at 64K; the original binary's oversized regions
        were many linker-packed physical segments.  Chunk bases must include
        every para the original code loaded into a segment register -- each
        `assume` then names the right physical chunk and label fixups store
        the same offsets the original did."""
        # mandatory bases: every para the original image used as a segment
        # base inside this region -- sreg values plus relocation targets
        # (each stored seg word points at an original physical segment)
        mand_set = {v << 4 for v in self._sreg_paras()}
        mand_set.update(t for t in self.relocs.values() if t)
        mand = sorted(b for b in mand_set
                      if seg['start'] < b < seg['end'])
        if seg['end'] - seg['start'] <= 0x10000 and not mand:
            return [(seg['name'], seg['start'], seg['end'])]
        # fill boundaries: instruction/data-item starts (labels can sit at
        # mid-item addrs where a boundary would leave the item straddling)
        bounds = sorted(set(self.insns) | set(self.data_items))
        points = set(mand)
        # every mandatory point must be a boundary; between them, add
        # splits so no chunk exceeds 64K
        queue = [seg['start']] + mand + [seg['end']]
        queue = sorted(set(queue))
        for i in range(len(queue) - 1):
            lo, hi = queue[i], queue[i + 1]
            while hi - lo > 0x10000:
                limit = lo + 0x10000
                j = bisect.bisect_right(bounds, limit) - 1
                nxt = bounds[j] if j >= 0 and bounds[j] > lo else limit
                points.add(nxt)
                lo = nxt
        points.add(seg['start'])
        pts = sorted(points)
        return [(f"{seg['name']}_{i}", s, e)
                for i, (s, e) in enumerate(zip(pts, pts[1:] + [seg['end']]), 1)]

    def _sreg_paras(self):
        """All paras loaded into segment registers anywhere (sreg ranges)."""
        ps = getattr(self, '_sreg_para_set', None)
        if ps is None:
            ps = self._sreg_para_set = {
                v for _a, r, v in self.sreg_events if v >= 0}
        return ps

    def _segname2chunk_map(self):
        """Logical segment name -> first physical chunk name, for
        >64K segments split into multiple asm segments."""
        m = getattr(self, '_segname2chunk', None)
        if m is None:
            m = self._segname2chunk = {
                sg['name']: self._nf(self._seg_chunks(sg)[0][0])
                for sg in self.segments
                if len(self._seg_chunks(sg)) > 1}
        return m

    def _chunk_for(self, lin):
        """Name of the physical chunk containing linear address `lin`
        (only inside >64K split segments); else None."""
        cr = getattr(self, '_chunk_ranges', None)
        if cr is None:
            cr = self._chunk_ranges = [
                (s, e, self._nf(n))
                for sg in self.segments
                for n, s, e in self._seg_chunks(sg)
                if n != sg['name']]
            self._segname2chunk_map()
        for s, e, n in cr:
            if s <= lin < e:
                return n
        return None

    def _chunk_seg_refs(self, text):
        """`seg segXXX` operand on a split segment: the big name doesn't
        exist in the .asm -- resolve to the first physical chunk so the
        stored para equals the original segment base."""
        def rep(m):
            cn = self._segname2chunk_map().get(m.group(1))
            return 'seg ' + cn if cn else m.group(0)
        return re.sub(r'seg (seg\w+)', rep, text)

    def _render_segment(
        self, seg: dict[str, Any], asm: bool = False, exact_code_bytes: bool = True,
    ) -> list[str]:
        """Render one segment with persistent ASSUME state and selected code spelling."""
        lines = []
        p0 = self.prefix(seg, seg['start'])
        chunks = self._seg_chunks(seg) if asm else \
            [(seg['name'], seg['start'], seg['end'])]
        chunk_i = 0
        if not asm:
            lines += [f"{p0} ; {SEGLINE}", p0,
                      f"{p0} ; Segment type: {self._seg_type_comment(seg)}",
                      f"{p0} {self._seg_decl(seg)}"]
        else:
            cname = chunks[0][0]
            lines.append(self._seg_decl(seg, cname, asm=True))
            if seg['exec']:
                lines.append(f"        assume cs:{self._nf(cname)}")
            lines.append("        assume ds:nothing, es:nothing, "
                         "ss:nothing")
        assume_state = {'ds': 'nothing', 'es': 'nothing', 'ss': 'nothing'}
        if asm and seg['exec']:
            assume_state['cs'] = self._nf(chunks[0][0])

        # sreg change events inside this segment -> `assume reg:seg` lines
        sreg_ev = [e for e in self.sreg_events
                   if seg['start'] <= e[0] < seg['end']]
        sreg_i = 0
        cur_func = None
        prev_break = False   # previous insn was jmp/ret (non-fallthrough)
        addr = seg['start']
        if asm and addr < self.db.image_base:
            # segment frame extends below the image start (e.g. an IDC
            # segment covering PSP space) -- those bytes are not in the
            # file image; emitting them would shift the whole stream
            addr = self.db.image_base
        last_addr = addr

        def close_func(at_addr):
            nonlocal cur_func
            fv = self.funcs[cur_func]
            ep = self.prefix(seg, at_addr)
            lines.append(f"{ep} {self._nf(fv['name'])}endp")
            lines.append(ep)
            cur_func = None

        while addr < seg['end']:
            # chunk boundary: close the current segment block and open the
            # next chunk (an open proc must close first -- proc/endp cannot
            # span two physical segments)
            if asm and chunk_i + 1 < len(chunks) and \
                    addr >= chunks[chunk_i][2]:
                if cur_func is not None:
                    close_func(addr)
                    prev_break = True
                lines.append(f"{self._nf(chunks[chunk_i][0])}ends")
                chunk_i += 1
                lines.append(self._seg_decl(seg, chunks[chunk_i][0], asm=True))
                if seg['exec']:
                    lines.append(
                        f"        assume cs:{self._nf(chunks[chunk_i][0])}")
                    assume_state['cs'] = self._nf(chunks[chunk_i][0])
            # function end reached -> endp before this address' items
            if cur_func is not None and self.funcs[cur_func]['end'] > cur_func \
                    and addr >= self.funcs[cur_func]['end']:
                close_func(addr)
                prev_break = True
            p = self.prefix(seg, addr)
            if asm:
                while sreg_i < len(sreg_ev) and sreg_ev[sreg_i][0] <= addr:
                    _, reg, val = sreg_ev[sreg_i]
                    sreg_i += 1
                    tgt = self.para2seg.get(val, 'nothing') \
                        if val is not None and val >= 0 else 'nothing'
                    if val is not None and val >= 0:
                        # inside a split segment the assume must name the
                        # physical chunk so label fixups resolve against
                        # the same base the original code used
                        cn = self._chunk_for(val << 4)
                        if cn:
                            tgt = cn
                    # ASSUME is persistent assembler state. Runtime traces
                    # repeat it at many consecutive instructions; emitting
                    # unchanged values only obscures the real transitions.
                    if assume_state.get(reg) != tgt:
                        lines.append(f"{p} assume {reg}:{tgt}")
                        assume_state[reg] = tgt
            # anterior extra comments (except the -1 type comment which is
            # emitted inside the function header; the 1000+ file header
            # comments at the first segment start are emitted in the banner)
            for ln, cm in self.extra.get(addr, []):
                if ln == -1 or (ln >= 1000 and addr == self.segments[0]['start']):
                    continue
                for cl in self._cmt_lines(cm):
                    lines.append(f"{p} {cl}")
            # function start: close a still-open function first (a func with
            # unknown end would otherwise swallow the next proc header)
            if addr in self.funcs and addr not in self.nested \
                    and cur_func is not None:
                close_func(addr)
                prev_break = True
            if addr in self.funcs and addr not in self.nested:
                fv = self.funcs[addr]
                lines += self._func_header(seg, addr, fv)
                cur_func = addr
                prev_break = False
            # label line for named/auto labels at code addrs (not func start)
            label = self.labels.get(addr)
            if addr in self.nested and not label:
                label = self.funcs[addr]['name']
            is_code = addr in self.insns
            if label and is_code and addr != cur_func:
                if prev_break:
                    lines.append(f"{p} ; {SEP}")
                lines.append(p)
                # `::` (not `:`) in .asm: a single-colon label inside a
                # proc is procedure-local in masm/uasm, which breaks
                # cross-proc self-modifying-code refs like `cs:loc_x+7`
                lines.append(self._annotate(
                    f"{p} {label}{'::' if asm else ':'}", p, addr))
            if asm and self.img_hi and addr >= self.img_hi:
                # beyond the file's image the bytes are uninitialized --
                # `db ?` still advances the segment (and uasm stores
                # zeros for it), which would overshoot the original size
                if label:
                    # labels into the uninitialized tail are still
                    # referenced by stored offsets -- define them
                    lines.append(f"{p} {self._nf(label)} equ "
                                 f"{self._equ_expr(label, addr - self.img_hi, addr in self.funcs)}")
                addr += 1
                continue
            # item body
            if is_code:
                size, mnem, ops, aops, dbh = self.insns[addr]
                if asm and not exact_code_bytes:
                    dbh = None
                if asm:
                    # labels at mid-instruction addrs (e.g. SMC targets in
                    # `ds:loc_x+N` refs) never get a line -- define them as
                    # relocatable `equ $+delta` before the insn
                    mid = {lb: self.labels[lb] for lb in self.labels
                           if addr < lb < addr + size}
                    # a function can start mid-insn too (an overlapping
                    # decode seeded it as a call target)
                    i = bisect.bisect_right(self.func_starts, addr)
                    while i < len(self.func_starts) and \
                            self.func_starts[i] < addr + size:
                        lb = self.func_starts[i]
                        mid.setdefault(lb, self.funcs[lb]['name'])
                        i += 1
                    for la in sorted(mid):
                        lines.append(
                            f"{p} {self._nf(mid[la])} equ "
                            f"{self._equ_expr(mid[la], la - addr, la in self.funcs)}")
                if asm and exact_code_bytes and not dbh and size == 5:
                    raw = self._raw(addr, size)
                    if raw and raw[0] in (0x9A, 0xEA):
                        # direct far call/jmp: with a relocated seg word
                        # re-emit the fixup against the target chunk;
                        # without one the stored seg is literal -- no
                        # symbol reproduces it, emit verbatim bytes
                        rc = self._chunk_for(self.relocs[addr + 3]) \
                            if addr + 3 in self.relocs else None
                        if rc:
                            pad = ' ' * max(1, 24 - len(p))
                            lines.append(self._annotate(
                                f"{p}{pad}db {ida_num(raw[0])} "
                                f"; {mnem} {ops}" + self._tag(addr, 1),
                                p, addr))
                            lines.append(
                                f"{p}{pad}dw "
                                f"{ida_num(raw[1] | (raw[2] << 8))}"
                                + self._tag(addr + 1, 2))
                            lines.append(f"{p}{pad}dw seg {rc}"
                                         + self._tag(addr + 3, 2))
                            prev_break = mnem in ('jmp', 'ljmp')
                            last_addr = addr
                            addr += size
                            continue
                        dbh = raw.hex()
                if asm and exact_code_bytes and not dbh and mnem in _NEAR_BRANCH:
                    # a near branch across a chunk or segment boundary
                    # cannot be encoded -- emit the original bytes verbatim
                    tgt = (aops or ops).split()[-1].rstrip(',')
                    ta = self._name2addr.get(tgt)
                    tseg = self.seg_of(ta) if ta is not None else None
                    tchunk = self._chunk_for(ta) if ta is not None else None
                    if not tchunk and tseg:
                        tchunk = self._nf(tseg['name'])
                    achunk = self._chunk_for(addr) or self._nf(seg['name'])
                    if tchunk is not None and tchunk != achunk:
                        raw = self._raw(addr, size)
                        if raw:
                            dbh = raw.hex()
                if asm and exact_code_bytes and not dbh:
                    # Capstone omits the source width on some MOVSX/MOVZX
                    # memory operands, and UASM rejects two-operand FXCH or
                    # unsized descriptor-table memory operands. Preserve the
                    # decoded instruction bytes rather than choosing a width.
                    ambiguous_memory_width = (
                        mnem in ('movsx', 'movzx') and '[' in ops
                        and 'ptr' not in ops
                    )
                    unsized_descriptor = mnem in ('lgdt', 'lidt') and ops.startswith('[')
                    two_operand_fxch = mnem == 'fxch' and ',' in ops
                    # a 66/67 size prefix is lost when neither operand text
                    # carries an explicit width or a 32-bit register (e.g.
                    # `push [bp-10h]` for 66 ff76f0) -- emit verbatim bytes
                    eff_ops = aops or ops or ''
                    raw = self._raw(addr, size)
                    size_prefix_loss = bool(
                        raw and raw[0] in (0x66, 0x67)
                        and 'dword' not in eff_ops
                        and not re.search(
                            r'\be(ax|bx|cx|dx|si|di|bp|sp)\b', eff_ops))
                    if (ambiguous_memory_width or unsized_descriptor
                            or two_operand_fxch or size_prefix_loss):
                        if raw:
                            dbh = raw.hex()
                if asm and dbh:
                    # uasm cannot reproduce the original encoding --
                    # emit the exact bytes, with the insn as a comment
                    raw = bytes.fromhex(dbh)
                    text = 'db ' + ','.join(
                        f"{'0' if b >= 0xA0 else ''}{b:02X}h" for b in raw
                    ) + f" ; {mnem} {ops}"
                else:
                    if asm and aops:
                        ops = aops
                    if ops:
                        # multiword mnemonics ('lock add', 'repne scasb')
                        # exceed the 8-char field -- don't glue operands on
                        text = (mnem.ljust(8) if len(mnem) < 8
                                else mnem + ' ') + ops
                    else:
                        text = mnem
                    if asm:
                        text = self._chunk_seg_refs(text)
                        # a `seg X` operand on a relocated imm field: the
                        # stored para is the chunk base at relocs[field] --
                        # resolve to that exact chunk, not the first one
                        ra = next((a for a in range(addr, addr + size)
                                   if a in self.relocs), None)
                        if ra is not None:
                            rc = self._chunk_for(self.relocs[ra])
                            if rc:
                                text = re.sub(r'seg \w+', 'seg ' + rc,
                                              text, count=1)
                        # a `far ptr X` operand with no fixup can still be
                        # emitted when X is a far symbol; near-label targets
                        # (`jmp far ptr start`) get full verbatim above
                line = f"{p}{' ' * max(1, 24 - len(p))}{text}"
                if asm:
                    line += self._tag(addr, size)
                lines.append(self._annotate(line, p, addr))
                prev_break = mnem in ('jmp', 'ljmp', 'retn', 'retf', 'ret',
                                      'iret', 'hlt', 'int3')
                last_addr = addr
                addr += size
                continue
            if addr in self.data_items:
                size, kind, count = self.data_items[addr]
                span = size * max(count, 1)
                if asm and self.img_hi and \
                        addr < self.img_hi < addr + span:
                    # item straddles the file's end -- emit only the
                    # stored head, the tail is uninitialized
                    raw = self._raw(addr, self.img_hi - addr) or b''
                    for off in range(0, len(raw), 16):
                        run = raw[off:off + 16]
                        body = ('db ' + ','.join(
                            ida_num(x) for x in run)
                            + self._tag(la := addr + off, len(run)))
                        lines += self._mid_equs(la, la + len(run), la, p)
                        lbl = self.labels.get(la)
                        if off == 0 and label:
                            lbl, label = label, None
                        if lbl:
                            lines.append(
                                f"{p} {self._nf(lbl)}{body}")
                        else:
                            lines.append(
                                f"{p}{' ' * max(1, 24 - len(p))}{body}")
                    last_addr = addr
                    addr = self.img_hi
                    continue
                if asm and chunk_i + 1 < len(chunks) and \
                        addr < chunks[chunk_i][2] < addr + span:
                    # a mandatory chunk boundary lands inside this item
                    # (an original segment base mid-array): emit the head
                    # as raw bytes; the remainder continues in the next
                    # chunk via the plain byte path
                    b = chunks[chunk_i][2]
                    raw = self._raw(addr, b - addr) or b''
                    for off in range(0, len(raw), 16):
                        run = raw[off:off + 16]
                        body = ('db ' + ','.join(
                            ida_num(x) for x in run)
                            + self._tag(la := addr + off, len(run)))
                        lines += self._mid_equs(la, la + len(run), la, p)
                        lbl = self.labels.get(la)
                        if off == 0 and label:
                            lbl, label = label, None
                        if lbl:
                            lines.append(
                                f"{p} {self._nf(lbl)}{body}")
                        else:
                            lines.append(
                                f"{p}{' ' * max(1, 24 - len(p))}{body}")
                    last_addr = addr
                    addr = b
                    continue
                if asm:
                    # labels inside a multi-byte item never got their own
                    # line -- define them as relocatable `equ $+delta` so
                    # dw/ds: references resolve to the correct offset
                    mid = {lb: self.labels[lb] for lb in self.labels
                           if addr < lb < addr + span}
                    i = bisect.bisect_right(self.func_starts, addr)
                    while i < len(self.func_starts) and \
                            self.func_starts[i] < addr + span:
                        lb = self.func_starts[i]
                        mid.setdefault(lb, self.funcs[lb]['name'])
                        i += 1
                    for la in sorted(mid):
                        lines.append(
                            f"{p} {self._nf(mid[la])} equ "
                            f"{self._equ_expr(mid[la], la - addr, la in self.funcs)}")
                if asm and label in self.branch_lbls:
                    # jump target on a db item: uasm needs a code-typed
                    # label, so emit `name::` then the unlabeled data
                    lines.append(f"{p} {label}::")
                    label = None
                body = self._data_body(addr, size, kind, count, p, asm=asm)
                if label and asm:
                    decl = self._decl_fix(label, body)
                    if decl:
                        lines.append(f"{p} {decl}")
                        label = None
                if label:
                    line = f"{p} {self._nf(label)}{body}"
                else:
                    line = f"{p}{' ' * max(1, 24 - len(p))}{body}"
                if asm and '\n' not in body:
                    line += self._tag(addr, span)
                lines.append(self._annotate(line, p, addr))
                prev_break = False
                last_addr = addr
                addr += size * max(count, 1)
                continue
            # undefined byte / padding before a function -> align directive
            if seg['exec']:
                i = bisect.bisect_right(self.bounds, addr)
                nxt = self.bounds[i] if i < len(self.bounds) else seg['end']
                nxt = min(nxt, seg['end'])
                gap = self._raw(addr, nxt - addr) or b''
                if gap and all(b in (0, 0x90) for b in gap) and \
                        len(gap) <= 32 and nxt in self.funcs:
                    if asm:
                        # uasm rejects `align`/`even` in use16 segments:
                        # emit the literal padding bytes instead
                        if len(set(gap)) == 1:
                            body = f"db {len(gap)} dup({ida_num(gap[0])})"
                        else:
                            body = 'db ' + ','.join(ida_num(b) for b in gap)
                        lines.append(
                            f"{p}{' ' * max(1, 24 - len(p))}{body}"
                            + self._tag(addr, len(gap)))
                    else:
                        lines.append(f"{p}{' ' * max(1, 24 - len(p))}align 2")
                    last_addr = nxt
                    addr = nxt
                    continue
            if asm and label in self.branch_lbls:
                lines.append(f"{p} {label}::")
                label = None
            if label and asm:
                decl = self._decl_fix(label, 'db')
                if decl:
                    lines.append(f"{p} {decl}")
                    label = None
            if label:
                line = f"{p} {self._nf(label)}{self._byte_line(addr)}"
            else:
                line = f"{p}{' ' * max(1, 24 - len(p))}{self._byte_line(addr)}"
            if asm:
                line += self._tag(addr, 1)
            lines.append(self._annotate(line, p, addr))
            prev_break = False
            last_addr = addr
            addr += 1

        # close open function
        if cur_func is not None:
            fv = self.funcs[cur_func]
            eaddr = fv['end'] if fv['end'] > cur_func else last_addr
            if not (seg['start'] <= eaddr <= seg['end']):
                eaddr = last_addr
            close_func(eaddr)
        lines.append(f"{self.prefix(seg, last_addr)} "
                     f"{self._nf(chunks[chunk_i][0])}ends")
        lines.append(self.prefix(seg, last_addr))
        return lines

    # ---------------------------------------------------------------- main
    def generate_lst(self, output_file='output.lst'):
        md5 = hashlib.md5(self.db.binary).hexdigest().upper()
        crc = zlib.crc32(self.db.binary) & 0xFFFFFFFF
        first = self.segments[0] if self.segments else {
            'start': self.db.image_base, 'base': self.db.image_base >> 4,
            'name': 'seg000'}
        p0 = f"{first['name']}:0000"
        last = self.segments[-1] if self.segments else first

        out = []
        out.append(f"{p0} ;")
        out.append(f"{p0} ; +{'-' * 73}+")
        out.append(f"{p0} ; |      This file was generated by Ada Script (IDA-style)      |")
        out.append(f"{p0} ; +{'-' * 73}+")
        out.append(f"{p0} ;")
        out.append(f"{p0} ; Input MD5    : {md5}")
        out.append(f"{p0} ; Input CRC32  : {crc:08X}")
        out.append(p0)
        # anterior comments at the first segment start carry the file info
        for ln, cm in self.extra.get(first['start'], []):
            if ln >= 1000:
                for cl in self._cmt_lines(cm):
                    out.append(f"{p0} {cl}")
        out.append(p0)
        cpu, mmx = self._cpu_level()
        out.append(f"{p0}                 {cpu}")
        if mmx:
            out.append(f"{p0}                 .mmx")
        out.append(f"{p0}                 .model large")
        out.append(p0)
        stem = re.sub(r'\W+', '_', self.filename.rsplit('.', 1)[0])
        out.append(f"{p0}                 include {stem}.inc")
        out.append(p0)

        for seg in self.segments:
            out += self._render_segment(seg)

        pe = self.prefix(last, last['start'])
        out.append(f"{pe}{' ' * max(1, 24 - len(pe))}"
                   f"end {self.labels.get(self.entry, 'start')}")
        out.append('')

        with open(output_file, 'w', encoding='utf-8', errors='replace') as f:
            f.write('\n'.join(out))
        logger.info(f"LST written: {output_file} ({len(out)} lines)")

    # --------------------------------------------------------------- asm
    # names uasm/MASM treat as reserved (regs, directives, mnemonics);
    # a label colliding with any of these must be renamed in the .asm
    _ASM_RESERVED: ClassVar[set] = {
        'ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp', 'ip',
        'al', 'ah', 'bl', 'bh', 'cl', 'ch', 'dl', 'dh',
        'cs', 'ds', 'es', 'ss', 'fs', 'gs',
        'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip',
        'proc', 'endp', 'segment', 'ends', 'struc', 'equ', 'end',
        'byte', 'word', 'dword', 'qword', 'fword', 'tbyte', 'ptr',
        'db', 'dw', 'dd', 'dq', 'dt', 'df', 'dup', 'offset', 'seg',
        'far', 'near', 'short', 'even', 'align', 'org', 'public',
        'extrn', 'extern', 'assume', 'model', 'include', 'comment',
        'para', 'page', 'stack', 'comm', 'code', 'data', 'use16',
        'use32', 'flat', 'label', 'local', 'macro', 'endm', 'group',
        'record', 'union', 'typedef', 'struct', 'if', 'else', 'endif',
        'call', 'jmp', 'ret', 'retn', 'retf', 'mov', 'int', 'nop',
        'push', 'pop', 'lea', 'xchg', 'test', 'cmp', 'add', 'sub',
        'mul', 'div', 'inc', 'dec', 'and', 'or', 'xor', 'not', 'neg',
        'shl', 'shr', 'sal', 'sar', 'rol', 'ror', 'rcl', 'rcr',
        'in', 'out', 'ins', 'outs', 'lods', 'stos', 'movs', 'cmps',
        'scas', 'xlat', 'rep', 'repe', 'repne', 'loop', 'loopne',
        'loope', 'jcxz', 'enter', 'leave', 'wait', 'hlt', 'lock',
        'cbw', 'cwd', 'clc', 'stc', 'cli', 'sti', 'cld', 'std',
        'cmc', 'lahf', 'sahf', 'pushf', 'popf', 'iret', 'into',
        'aa', 'saveregs', 'uses', 'vararg', 'cdecl', 'stdcall',
        'pascal', 'syscall', 'instr', 'echo', 'error', 'exit',
    }

    def _asm_renames(self):
        """Build name rewrites needed to keep the .asm assemblable.

        Two collision classes:
          * global label/func/struc names that equal a register/directive
            (uasm is case-insensitive): rename everywhere -> `name_1`
          * frame-var names that also exist as a global symbol (e.g. a data
            label `argc` plus `argc = word ptr 4` in main): rename the frame
            var -> `name$` and rewrite only `bp+name` operand contexts
        """
        label_rn, frame_rn = {}, {}
        used = set()
        global_names = list(dict.fromkeys(
            list(self.labels.values())
            + [f['name'] for f in self.funcs.values()]
            + [n for n in self.strucs.values()]
            + [mn for en in self.enum_names.values() for mn in en]))
        for nm in global_names:
            used.add(nm)
        funcnames = {f['name'] for f in self.funcs.values()}

        def fresh(base):
            i = 1
            new = f"{base}_{i}"
            while new in used:
                i += 1
                new = f"{base}_{i}"
            used.add(new)
            return new

        # uasm symbols are case-insensitive: two different spellings of the
        # same name collide.  Keep func names verbatim, rename the other.
        seen_ci = {}
        for nm in global_names:
            key = nm.lower()
            prev = seen_ci.get(key)
            if prev is None:
                seen_ci[key] = nm
                continue
            if nm in funcnames and prev not in funcnames:
                victim = prev
            else:
                victim = nm
            if victim not in label_rn:
                label_rn[victim] = fresh(victim)
        for nm in global_names:
            if nm.lower() in self._ASM_RESERVED and nm not in label_rn:
                label_rn[nm] = fresh(nm)
        # characters uasm can't take in an identifier (e.g. `RES_FRM1.HSQ`,
        # `sub_x.2Hz`) -> replace with '_' and keep it unique
        for nm in global_names:
            if nm in label_rn:
                continue
            sane = re.sub(r'[^A-Za-z0-9_$?@]', '_', nm)
            if sane != nm:
                label_rn[nm] = sane if sane not in used else fresh(sane)
                used.add(label_rn[nm])
        fvar_names = {nm for fv in self.frame_vars.values()
                      for nm, _ in fv.values()}
        for nm in sorted(fvar_names):
            if nm in global_names or nm.lower() in self._ASM_RESERVED:
                base = nm + '$'
                new = base
                i = 0
                while new in used:
                    i += 1
                    new = f"{base}{i}"
                used.add(new)
                frame_rn[nm] = new
        self._lbl_rn = label_rn
        self._frm_rn = frame_rn
        self._lbl_re = re.compile(
            r'\b(' + '|'.join(re.escape(n) for n in label_rn) + r')\b') \
            if label_rn else None
        self._frm_re = re.compile(
            r'(bp\s*\+)\s*(' +
            '|'.join(re.escape(n) for n in frame_rn) + r')\b') \
            if frame_rn else None

    def _asm_line(self, s):
        """Apply asm-only name rewrites to a stripped line."""
        m = re.match(r'(\s*)(\w+)(\s*=\s*(?:byte|word|dword|qword) ptr .*)', s)
        if m and m.group(2) in self._frm_rn:
            return m.group(1) + self._frm_rn[m.group(2)] + m.group(3)
        if self._frm_re is not None:
            s = self._frm_re.sub(
                lambda mo: mo.group(1) + self._frm_rn[mo.group(2)], s)
        if self._lbl_re is not None:
            # A renamed symbol at line start is a definition site
            # (`inc:`, `inc equ`, `inc proc`); the same word as an
            # instruction mnemonic (`inc bx`) must not be renamed.
            m2 = re.match(r'(\s*\w+)(.*)', s, re.S)
            if m2 and re.match(
                    r'\s*[:=]|\s+(equ|label|proc|endp|segment|ends|'
                    r'db|dw|dd|dq|dt|at|struc|union|record|group)\b',
                    m2.group(2), re.I):
                s = self._lbl_re.sub(
                    lambda mo: self._lbl_rn[mo.group(0)], s)
            elif m2:
                s = (m2.group(1) + self._lbl_re.sub(
                    lambda mo: self._lbl_rn[mo.group(0)], m2.group(2)))
        return s

    def _asm_preamble(self):
        """Equates/struc definitions needed by the .asm (enum constants,
        struct types used by `Name <0>` data declarations)."""
        out = []
        for sname, members in self.struc_members.items():
            out.append(f"{sname} struc")
            prev = 0
            for off, sz, mname in sorted(members):
                if off > prev:
                    out.append(f"    db {off - prev} dup(?)")
                d = {1: 'db', 2: 'dw', 4: 'dd'}.get(sz)
                if d is None:
                    # >4-byte member is a byte array (e.g. a name field):
                    # dq would store a quoted init big-endian/reversed
                    out.append(f"    {sname}_{mname} db {sz} dup(?)")
                    prev = off + sz
                    continue
                # struc member names are global in MASM -> namespace them
                out.append(f"    {sname}_{mname} {d} ?")
                prev = off + sz
            out.append(f"{sname} ends")
            out.append('')
        seen = set()
        rn = getattr(self, '_lbl_rn', {})
        for ename in self.enum_names:
            for nm, val in self.enum_names[ename].items():
                if nm in seen:
                    continue
                seen.add(nm)
                out.append(f"{rn.get(nm, nm)} equ {ida_num(val, True)}")
        if seen:
            out.append('')
        return out

    _RE_386 = re.compile(
        r'\b(?:e[abcd]x|e[sb]p|e[sd]i|movsxd?|movzx|cdq|cwde|shld|shrd|'
        r'bsf|bsr|set\w+|cmov\w+|pushad|popad|lfs|lgs|'
        r'lss|arpl|enter|leave|insd|outsd|lodsd|stosd|scasd|cmpsd|movsd|'
        r'iretd|jecxz)\b')
    _RE_486 = re.compile(r'\b(?:invd|wbinvd|invlpg|cmpxchg|xadd|bswap)\b')
    def _equ_expr(self, name, delta, is_code=False):
        d = f"$+{ida_num(delta)}"
        rn = getattr(self, '_lbl_rn', {})
        if is_code or rn.get(name, name) in self.branch_lbls or \
                name in self.branch_lbls or \
                name.startswith(('loc_', 'sub_', 'start')):
            return d
        # uasm rejects `mov ds:EQU, r` when the equ is untyped -- always
        # type data aliases (word matches uasm's own default for equs)
        t = _EQU_TYPES.get(name.split('_')[0] + '_', 'word ptr')
        return f"{t} ({d})"

    def _decl_fix(self, name, body):
        """`name label <type>` when the auto-name prefix (word_/byte_/...)
        disagrees with the emitted directive -- otherwise uasm resolves
        `seg:name` references at the directive's size, not the prefix's."""
        want = _PREFIX_SZ.get(name.split('_')[0])
        dsz = _DECL_SZ.get(body.strip().split()[0].lower())
        if want and dsz and want != dsz:
            return f"{self._nf(name)} label {_SZ_KW[want]}"
        return None

    def _mid_equs(self, lo, hi, base, p):
        """`equ $+delta` lines for labels/func-starts strictly inside
        (lo, hi); `base` is the address `$` resolves to at that point."""
        out = []
        i = bisect.bisect_right(self._label_addrs, lo)
        j = bisect.bisect_left(self._label_addrs, hi)
        mid = {lb: self.labels[lb] for lb in self._label_addrs[i:j]}
        k = bisect.bisect_right(self.func_starts, lo)
        while k < len(self.func_starts) and self.func_starts[k] < hi:
            lb = self.func_starts[k]
            mid.setdefault(lb, self.funcs[lb]['name'])
            k += 1
        for la in sorted(mid):
            out.append(f"{p} {self._nf(mid[la])} equ "
                       f"{self._equ_expr(mid[la], la - base, la in self.funcs)}")
        return out

    _RE_MMX = re.compile(
        r'\bmm[0-7]\b|\b(?:emms|movq|movd|padd|psub|pcmpeq|pcmpgt|packss|'
        r'packus|punpck|pmul|pmadd|psra|psrl|psll|por|pxor|pand|pandn)\w*\b|'
        r'\b(?:fcmov|fcomi|fucomi)\w*\b')

    def _cpu_level(self):
        """Minimum CPU directive for the decoded instruction set."""
        is386 = is486 = mmx = False
        for _s, mnem, ops, _a, _d in self.insns.values():
            text = f"{mnem} {ops}"
            if self._RE_MMX.search(text):
                mmx = True
            elif self._RE_486.search(text):
                is486 = True
            elif self._RE_386.search(text):
                is386 = True
        if mmx:
            return ('.686p', True)
        if is486:
            return ('.486', False)
        return ('.386', False) if is386 else ('.286', False)

    def generate_asm(
        self, output_file: str = 'output.asm', exact_code_bytes: bool = True,
    ) -> None:
        """Write MASM source; exact mode keeps original bytes where needed."""
        self._asm_renames()
        # use16 segments keep 16-bit addressing under any cpu directive;
        # emit the lowest level that covers the decoded instruction set
        # no .model: it creates an empty DGROUP and silently assumes
        # `ds:DGROUP`, so every ds:/seg fixup resolves against the wrong
        # frame and alink reports "offset out of range".  Explicit
        # `assume` tracking (below, from the sreg ranges) replaces it.
        cpu, mmx = self._cpu_level()
        out = ['; Generated by Ada Script', f'; Source: {self.filename}']
        if not exact_code_bytes:
            out.append('; Mnemonic view: instruction bytes may reassemble differently or fail')
        out += ['', cpu] + (['.mmx'] if mmx else []) + ['']
        out += self._asm_preamble()
        covered = []
        for seg in self.segments:
            if any(cs <= seg['start'] and seg['end'] <= ce
                   for cs, ce in covered):
                # logical alias of an already-emitted region (e.g. a stack
                # segment inside the code image): declaring it `at <para>`
                # keeps `assume ss:`/`dw seg` valid without re-emitting
                # the bytes
                out.append(f"{self._nf(seg['name'])} segment at "
                           f"{ida_num(seg['start'] >> 4)}")
                out.append(f"{self._nf(seg['name'])} ends")
                continue
            covered.append((seg['start'], seg['end']))
            for line in self._render_segment(seg, asm=True,
                                             exact_code_bytes=exact_code_bytes):
                # strip the "seg:off" prefix from every lst line
                for sub in line.split('\n'):
                    out.append(self._asm_line(
                        re.sub(r'^\w+:[0-9A-F]+\s?', '', sub)))
        out.append('')
        out.append(f"        end {self.labels.get(self.entry, 'start')}")
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(out))
        logger.info(f"ASM written: {output_file} ({len(out)} lines)")
