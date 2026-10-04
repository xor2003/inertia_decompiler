"""Capstone-based analyzer producing IDA-style labeled disassembly.

Pipeline inside this module:
  1. Load analysis context from the DB (segments, functions, names, data
     items, sreg defaults, op overrides, enums, relocations, frame vars).
  2. Discover code regions: IDC function ranges + create_insn seeds, or
     recursive descent from the entry point when nothing is known.
  3. Linear-disassemble each region with Capstone (16-bit).
  4. Collect references -> auto labels (loc_/sub_/byte_/word_/dword_/a*).
  5. Render operand text with labels resolved (capstone + label info).
  6. Store instructions and xrefs into the DB for the output generator.
"""

from __future__ import annotations

import bisect
import logging
import re

from capstone import CS_AC_WRITE, CS_ARCH_X86, CS_MODE_16, Cs
from capstone import x86_const as _cx86
from capstone.x86 import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_AH,
    X86_REG_AL,
    X86_REG_AX,
    X86_REG_BH,
    X86_REG_BL,
    X86_REG_BP,
    X86_REG_BX,
    X86_REG_CH,
    X86_REG_CL,
    X86_REG_CS,
    X86_REG_CX,
    X86_REG_DH,
    X86_REG_DI,
    X86_REG_DL,
    X86_REG_DS,
    X86_REG_DX,
    X86_REG_ES,
    X86_REG_FS,
    X86_REG_GS,
    X86_REG_SI,
    X86_REG_SP,
    X86_REG_SS,
)
from capstone.x86_const import (
    X86_GRP_FPU,
    X86_INS_BOUND,
    X86_INS_CALL,
    X86_INS_HLT,
    X86_INS_IRET,
    X86_INS_IRETD,
    X86_INS_JA,
    X86_INS_JAE,
    X86_INS_JB,
    X86_INS_JBE,
    X86_INS_JCXZ,
    X86_INS_JE,
    X86_INS_JECXZ,
    X86_INS_JG,
    X86_INS_JGE,
    X86_INS_JL,
    X86_INS_JLE,
    X86_INS_JMP,
    X86_INS_JNE,
    X86_INS_JNO,
    X86_INS_JNP,
    X86_INS_JNS,
    X86_INS_JO,
    X86_INS_JP,
    X86_INS_JS,
    X86_INS_LCALL,
    X86_INS_LDS,
    X86_INS_LEA,
    X86_INS_LES,
    X86_INS_LJMP,
    X86_INS_LOOP,
    X86_INS_LOOPE,
    X86_INS_LOOPNE,
    X86_INS_MOV,
    X86_INS_POP,
    X86_INS_PUSH,
    X86_INS_RET,
    X86_INS_RETF,
    X86_INS_RETFQ,
    X86_INS_XCHG,
)

logger = logging.getLogger(__name__)

SEG_PREFIX = {0x26: 'es', 0x2E: 'cs', 0x36: 'ss', 0x3E: 'ds', 0x64: 'fs', 0x65: 'gs'}
_PREFIX_BYTES = frozenset((0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65,
                           0x66, 0x67, 0xF0, 0xF2, 0xF3))

# modrm reg/rm field codes
_REG_CODE = {
    X86_REG_AL: 0, X86_REG_CL: 1, X86_REG_DL: 2, X86_REG_BL: 3,
    X86_REG_AH: 4, X86_REG_CH: 5, X86_REG_DH: 6, X86_REG_BH: 7,
    X86_REG_AX: 0, X86_REG_CX: 1, X86_REG_DX: 2, X86_REG_BX: 3,
    X86_REG_SP: 4, X86_REG_BP: 5, X86_REG_SI: 6, X86_REG_DI: 7,
}

# d=0 (r/m-dest) encodings of the two-way ALU/mov opcodes; uasm always
# canonicalizes reg,reg to the d=1 (reg-dest) encoding
_RM_DEST_OPS = frozenset((0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19,
                          0x20, 0x21, 0x28, 0x29, 0x30, 0x31, 0x38, 0x39,
                          0x88, 0x89))

# mnemonics capstone may emit that uasm cannot assemble at all
_ASM_NO_MNEM = frozenset((
    'int3', 'int1', 'salc', 'fcompi', 'fisttp',
    # Katmai/Athlon additions beyond .686p MMX
    'pavgb', 'pavgw', 'pextrw', 'pinsrw', 'pmaxsw', 'pmaxub', 'pminsw',
    'pminub', 'pmovmskb', 'pmulhuw', 'psadbw', 'pshufw', 'sfence',
    'maskmovq', 'movntq', 'femms', 'prefetchw', 'prefetchnta',
    'prefetcht0', 'prefetcht1', 'prefetcht2',
    # MMX insns uasm 2.57 lacks, MPX, CET and other oddballs
    'psubq', 'prefetch', 'getsec', 'endbr32', 'endbr64', 'bound',
    'bnd', 'bndcl', 'bndcn', 'bndcu', 'bndldx', 'bndmk', 'bndmov',
    'bndstx', 'nopw', 'nopd', 'notrack', 'pshufb',
    # SSE1/SSE2+ mnemonics uasm rejects at .686p (capstone groups are
    # empty for these on capstone 5, so deny by name)
    'addps', 'addss', 'andps', 'andnps', 'cmpps', 'cmpss', 'comiss',
    'cvtpi2ps', 'cvtps2pi', 'cvtsi2ss', 'cvtss2si', 'cvttps2pi',
    'cvttss2si', 'divps', 'divss', 'ldmxcsr', 'maxps', 'maxss',
    'minps', 'minss', 'movaps', 'movhps', 'movhlps', 'movlps',
    'movlhps', 'movmskps', 'movntps', 'movss', 'movups', 'mulps',
    'mulss', 'orps', 'rcpps', 'rcpss', 'rsqrtps', 'rsqrtss', 'shufps',
    'sqrtps', 'sqrtss', 'stmxcsr', 'subps', 'subss', 'ucomiss',
    'unpckhps', 'unpcklps', 'xorps', 'addpd', 'addsd', 'andpd',
    'andnpd', 'cmppd', 'comisd', 'cvtdq2pd', 'cvtdq2ps',
    'cvtpd2dq', 'cvtpd2pi', 'cvtpd2ps', 'cvtpi2pd', 'cvtps2dq',
    'cvtps2pd', 'cvtsd2si', 'cvtsd2ss', 'cvtsi2sd', 'cvtss2sd',
    'cvttpd2dq', 'cvttpd2pi', 'cvttps2dq', 'cvttsd2si', 'divpd',
    'divsd', 'maxpd', 'maxsd', 'minpd', 'minsd', 'movapd', 'movdqa',
    'movdqu', 'movhpd', 'movlpd', 'movmskpd', 'movntdq', 'movnti',
    'movntpd', 'movq2dq', 'movdq2q', 'movsd', 'movupd', 'mulpd',
    'mulsd', 'orpd', 'shufpd', 'sqrtpd', 'sqrtsd', 'subpd', 'subsd',
    'ucomisd', 'unpckhpd', 'unpcklpd', 'xorpd', 'movddup', 'movshdup',
    'movsldup', 'addsubpd', 'addsubps', 'haddpd', 'haddps', 'hsubpd',
    'hsubps', 'lddqu', 'monitor', 'mwait', 'fisttp', 'psignb',
    'psignw', 'psignd', 'pmulhrsw', 'pmaddubsw', 'phaddw', 'phaddd',
    'phaddsw', 'phsubw', 'phsubd', 'phsubsw', 'pabsb', 'pabsw',
    'pabsd', 'pshuflw', 'pshufhw', 'pshufd', 'pslldq', 'psrldq',
    # privileged / long-mode insns
    'syscall', 'sysenter', 'sysexit', 'sysret', 'swapgs', 'rdmsr',
    'wrmsr', 'rdtsc', 'rdtscp', 'rdpmc', 'ud0', 'ud1', 'ud2',
))

# capstone insn groups beyond what uasm accepts under .686p/.mmx
# (SSE and later ISA families) -- decoded bytes are emitted verbatim
_ASM_BAD_GROUPS = frozenset(
    getattr(_cx86, n) for n in (
        'X86_GRP_3DNOW', 'X86_GRP_SSE1', 'X86_GRP_SSE2', 'X86_GRP_SSE3',
        'X86_GRP_SSSE3', 'X86_GRP_SSE41', 'X86_GRP_SSE42', 'X86_GRP_SSE4A',
        'X86_GRP_AVX', 'X86_GRP_AVX2', 'X86_GRP_AVX512', 'X86_GRP_AES',
        'X86_GRP_SHA', 'X86_GRP_F16C', 'X86_GRP_FMA', 'X86_GRP_FMA4',
        'X86_GRP_BMI1', 'X86_GRP_BMI2', 'X86_GRP_ADX', 'X86_GRP_PFI',
        'X86_GRP_RTM', 'X86_GRP_TBM', 'X86_GRP_XOP', 'X86_GRP_CDI',
        'X86_GRP_DQI', 'X86_GRP_ERI', 'X86_GRP_BWI', 'X86_GRP_FSGSBASE',
        'X86_GRP_HLE', 'X86_GRP_NOVLX', 'X86_GRP_VLX', 'X86_GRP_SMAP',
        'X86_GRP_PCLMUL', 'X86_GRP_VM', 'X86_GRP_SGX')
    if hasattr(_cx86, n))
del _cx86

# `lock` is only legal on read-modify-write ops with a memory destination
_ASM_LOCKABLE = frozenset((
    'add', 'adc', 'and', 'btc', 'btr', 'bts', 'cmpxchg', 'dec', 'inc',
    'neg', 'not', 'or', 'sbb', 'sub', 'xadd', 'xchg', 'xor'))

# rep/repne/repe are only legal on string ops
_ASM_REPABLE = frozenset((
    'ins', 'insb', 'insw', 'insd', 'outs', 'outsb', 'outsw', 'outsd',
    'movs', 'movsb', 'movsw', 'movsd', 'lods', 'lodsb', 'lodsw', 'lodsd',
    'stos', 'stosb', 'stosw', 'stosd', 'scas', 'scasb', 'scasw', 'scasd',
    'cmps', 'cmpsb', 'cmpsw', 'cmpsd'))

# FPU arithmetic ops rendered by capstone as a single `st(n)` operand;
# uasm requires the explicit two-register form -> keep original bytes
_ASM_FPU_SINGLE = frozenset((
    'fadd', 'fmul', 'fsub', 'fsubr', 'fdiv', 'fdivr',
    'faddp', 'fmulp', 'fsubp', 'fsubrp', 'fdivp', 'fdivrp',
))

# operand-less mnemonics that legitimately carry a 66h/67h prefix
_DWORD_MNEMS = frozenset((
    'pushfd', 'popfd', 'iretd', 'pushad', 'popad',
))

# 32-bit general registers (used to test whether a 66h prefix is real --
# a bare prefix test can't distinguish `es` from `e`-register names)
_EREGS = frozenset((
    'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp'))

# system insns whose memory operand has a fixed layout -- a 66h prefix on
# them has no expressible asm form (sgdt always stores 6 bytes, etc.)
_SYS_FIXED_MNEMS = frozenset((
    'sgdt', 'sidt', 'lgdt', 'lidt', 'sldt', 'str', 'smsw', 'lmsw',
    'lldt', 'ltr', 'invd', 'invlpg', 'wbinvd', 'clts', 'verr', 'verw',
    'lar', 'lsl', 'arpl', 'cpuid', 'movntq', 'prefetchw'))

JCC_IDS = {X86_INS_JAE, X86_INS_JB, X86_INS_JBE, X86_INS_JA, X86_INS_JE,
           X86_INS_JNE, X86_INS_JS, X86_INS_JNS, X86_INS_JO, X86_INS_JNO,
           X86_INS_JP, X86_INS_JNP, X86_INS_JL, X86_INS_JLE, X86_INS_JGE,
           X86_INS_JG, X86_INS_JCXZ, X86_INS_JECXZ}
LOOP_IDS = {X86_INS_LOOP, X86_INS_LOOPE, X86_INS_LOOPNE}
RET_IDS = {X86_INS_RET, X86_INS_RETF, X86_INS_RETFQ, X86_INS_IRET,
           X86_INS_IRETD}
CALL_IDS = {X86_INS_CALL, X86_INS_LCALL}
JMP_IDS = {X86_INS_JMP, X86_INS_LJMP}
BRANCH_IDS = JCC_IDS | LOOP_IDS | JMP_IDS | CALL_IDS | {X86_INS_JCXZ}

# Opcodes that encode a short (rel8) displacement -> IDA prints "short".
SHORT_JMP_OPS = {0xEB} | set(range(0x70, 0x80))
LOOP_OPS = set(range(0xE0, 0xE4))

# mnemonics where an immediate may be an address offset (IDA only renders
# "offset X" when the value was provably used as an address)
OFFSET_MNEMS = {X86_INS_MOV, X86_INS_LEA, X86_INS_LES, X86_INS_LDS}

# segment registers (for `mov sreg, word` -> seg_XXXX auto labels)
SREG_REGS = {X86_REG_ES, X86_REG_CS, X86_REG_SS, X86_REG_DS,
             X86_REG_FS, X86_REG_GS}

# IDA's mnemonic spelling differs from capstone's for these; also capstone
# decodes opcode 99h as `cdq` even in 16-bit mode (it is `cwd`, and uasm
# .286 doesn't know `cdq`).  Same for `cwde`/`cbw`.
MNEM_MAP = {'ret': 'retn', 'jae': 'jnb', 'xlatb': 'xlat',
            'cdq': 'cwd', 'cwde': 'cbw'}

# string / implicit-operand instructions: IDA prints the bare mnemonic
# shift/rotate instructions with implicit count 1 (D0/D1 encodings)
SHIFT_IMPLICIT = {'rcl', 'rcr', 'rol', 'ror', 'shl', 'sal', 'shr', 'sar'}

_STRIP_BASES = {'lodsb', 'lodsw', 'lodsd', 'stosb', 'stosw', 'stosd',
                'movsb', 'movsw', 'movsd', 'scasb', 'scasw', 'scasd',
                'cmpsb', 'cmpsw', 'cmpsd', 'insb', 'insw', 'insd',
                'outsb', 'outsw', 'outsd', 'xlat', 'xlatb', 'pusha',
                'popa', 'pushaw', 'popaw'}

# string ops whose segment override can be expressed as an operand in asm
# (override applies to the [si] source side; stos/scas have an es-implicit
# dest so their override cannot be expressed -> db fallback)
_STRSEG_FORMS = {
    'lodsb': 'byte ptr {seg}:[si]', 'lodsw': 'word ptr {seg}:[si]',
    'movsb': 'byte ptr es:[di], byte ptr {seg}:[si]',
    'movsw': 'word ptr es:[di], word ptr {seg}:[si]',
    'cmpsb': 'byte ptr {seg}:[si], byte ptr es:[di]',
    'cmpsw': 'word ptr {seg}:[si], word ptr es:[di]',
}


def ida_num(value, force_hex=False):
    """Format a number like IDA: decimal <10, else 0-prefixed hex with h."""
    if value < 0:
        return '-' + ida_num(-value, force_hex)
    if value < 10 and not force_hex:
        return str(value)
    s = f"{value:X}"
    if s[0].isalpha():
        s = '0' + s
    return s + 'h'


def sanitize_str_name(data: bytes):
    """IDA-style a<Name> label from string bytes, or None for opaque strings
    (single chars / punctuation get asc_<addr> in IDA)."""
    out = []
    cap = True
    alnum = 0
    for b in data:
        c = chr(b)
        if c.isalnum():
            out.append(c.upper() if cap else c)
            cap = False
            alnum += 1
        else:
            cap = True
    if alnum < 2 or not data or not chr(data[0]).isalpha():
        return None
    return 'a' + ''.join(out)[:32]


class Analyzer:
    def __init__(self, binary, db, full=False, classify=False, xrefs=False):
        self.binary = binary
        self.db = db
        self.full = full
        self.classify = classify
        self.compute_xrefs = xrefs
        self.md = Cs(CS_ARCH_X86, CS_MODE_16)
        self.md.detail = True

        self.base = getattr(db, 'image_base', 0x10000)
        self.hdr = getattr(db, 'header_size', 0)
        self.image_size = getattr(db, 'image_size', len(binary))
        self.image_end = self.base + self.image_size

        self.segments = []        # dicts sorted by start
        self.funcs = {}           # start -> {'end','name','flags'}
        self.names = {}           # addr -> explicit name (symbols auto=0)
        self.auto_names = {}      # addr -> auto label name
        self.data_items = {}      # addr -> (size, kind, count)
        self.seeds = set()        # code seed addrs
        self.op_ovr = {}          # (addr, opnum) -> (kind, arg, arg2)
        self.op_ovr_any = {}      # addr -> list[(kind,arg)] for 0x80-flagged
        self.sregs = {}           # (seg_start, reg) -> value
        self.sreg_ranges = []     # (start, reg, value) sorted
        self.enum_members = {}    # enum_id -> {value: name}
        self.relocs = {}          # addr -> pointed seg base
        self.frame_vars = {}      # func -> {offset: name}
        self.comments = {}
        self.extra_comments = {}
        self.struc_members = {}   # struc name -> [(off,size,name)]
        self.reloc_words = set()  # addrs of relocated segment words
        self.char_hints = {}      # insn addr -> printable imm value
        self.seg_words = set()    # data words loaded into a segment register
        self.bp_use = {}          # func -> {bp disp -> max access size}
        self.frame_sz = {}        # func -> {offset: byte size} for vars
        self.frames = {}          # func -> (frsize, frregs, argsize)

        self.instructions = []    # decoded instruction dicts (code regions)
        self.covered = set()      # addrs covered by decoded instructions
        self.data_refs = {}       # data addr -> set of access kinds/sizes
        self.code_refs = set()    # addrs that are branch targets
        self.call_refs = set()    # addrs that are call targets
        self.xrefs = []

        self._load_context()

    # ------------------------------------------------------------------ ctx
    def _load_context(self):
        c = self.db.conn
        for s, e, base, cls, typ, exe, name in c.execute(
                "SELECT start_addr, end_addr, base, class, type, executable, name "
                "FROM segments ORDER BY start_addr"):
            self.segments.append({'start': s, 'end': e, 'base': base or (s >> 4),
                                  'class': cls or '', 'type': typ, 'exec': exe,
                                  'name': name})
        for i, seg in enumerate(self.segments):
            if not seg['name']:
                seg['name'] = f"seg{i:03d}"
        for s, e, n, f in c.execute("SELECT start, end, name, flags FROM functions"):
            self.funcs[s] = {'end': e, 'name': n or f"sub_{s:X}", 'flags': f or 0}
        for a, n in c.execute("SELECT addr, name FROM symbols WHERE auto=0"):
            self.names[a] = n
        for a, sz, k, cnt in c.execute("SELECT addr, size, kind, count FROM data_items"):
            self.data_items[a] = (sz, k, cnt)
        for (a,) in c.execute("SELECT addr FROM code_seeds"):
            self.seeds.add(a)
        for a, n, k, arg, arg2 in c.execute(
                "SELECT addr, opnum, kind, arg, arg2 FROM op_overrides"):
            if arg2 & 0x80:
                self.op_ovr_any.setdefault(a, []).append((k, arg))
            self.op_ovr[(a, n)] = (k, arg)
        for s, r, v in c.execute("SELECT seg_start, reg, value FROM sregs"):
            self.sregs[(s, r)] = v
        for s, r, v in c.execute(
                "SELECT start_addr, reg, value FROM sreg_ranges ORDER BY start_addr"):
            self.sreg_ranges.append((s, r, v))
        # sreg_value() is called per operand; keep per-reg sorted lists so a
        # lookup is a bisect instead of a full scan
        self._sreg_starts = {}
        self._sreg_vals = {}
        for s, r, v in self.sreg_ranges:
            self._sreg_starts.setdefault(r, []).append(s)
            self._sreg_vals.setdefault(r, []).append(v)
        for eid, nm, val in c.execute(
                "SELECT enum_id, name, value FROM enum_members"):
            self.enum_members.setdefault(eid, {})[val] = nm
        for a, off in c.execute("SELECT addr, offset FROM relocations"):
            self.relocs[a] = off
        for f, off, n in c.execute(
                "SELECT func_start, offset, name FROM frame_vars"):
            self.frame_vars.setdefault(f, {})[off] = n
        for f, fs, fr, ar in c.execute(
                "SELECT func_start, frsize, frregs, argsize FROM frames"):
            self.frames[f] = (fs or 0, fr or 0, ar or 0)
        for a, cm in c.execute("SELECT addr, comment FROM comments"):
            self.comments[a] = cm
        for a, ln, cm in c.execute(
                "SELECT addr, line, comment FROM extra_comments"):
            self.extra_comments.setdefault(a, []).append((ln, cm))
        for sn, mo, msz, mn in c.execute(
                "SELECT s.name, m.offset, m.size, m.name FROM struc_members m "
                "JOIN strucs s ON s.id=m.struc_id"):
            self.struc_members.setdefault(sn, []).append((mo, msz, mn))

        # default ds heuristic when IDC did not set one
        row = c.execute("SELECT value FROM config WHERE key='default_ds'").fetchone()
        self.default_ds = int(row[0]) if row else 0
        row = c.execute("SELECT value FROM config WHERE key='entry_addr'").fetchone()
        self.entry = int(row[0]) if row else self.base
        self._di_sorted = sorted(self.data_items)
        self.used_names = set(self.names.values()) | {
            f['name'] for f in self.funcs.values()}

    # ------------------------------------------------------------- segments
    def seg_of(self, addr):
        for s in self.segments:
            if s['start'] <= addr < s['end']:
                return s
        return None

    def _in_chunked(self, addr):
        """True when addr's segment is physically split in the .asm:
        either it exceeds 64K (uasm segment limit) or an interior para was
        used as a segment base (sreg value / relocation target) and becomes
        a chunk boundary.  Symbolic operands may then resolve against a
        frame the original did not use -- emit the original numeric."""
        s = self.seg_of(addr)
        if s is None:
            return False
        if s['end'] - s['start'] > 0x10000:
            return True
        ps = getattr(self, '_mand_bases', None)
        if ps is None:
            ps = self._mand_bases = {
                v << 4 for _a, _r, v in self.sreg_ranges if v >= 0
            } | set(self.relocs.values())
        return any(s['start'] < b < s['end'] for b in ps)

    def _fix_target(self, addr, raw):
        """Capstone computes near-branch targets without 16-bit IP wraparound.
        The real target wraps inside the current CS segment paragraph."""
        seg = self.seg_of(addr)
        if not seg:
            return raw
        csbase = (seg['base'] or (seg['start'] >> 4)) << 4
        return csbase + ((raw - csbase) & 0xFFFF)

    def seg_name(self, addr):
        s = self.seg_of(addr)
        return s['name'] if s else 'seg'

    def sreg_value(self, addr, reg):
        """Default/implied segment register value (paragraph) at addr."""
        # explicit split_sreg_range wins: ranges start at each row, run to the
        # next row for the same reg.
        starts = getattr(self, '_sreg_starts', None)
        if starts is None:
            best = None
            for s, r, v in self.sreg_ranges:
                if r == reg and s <= addr and (best is None or s > best[0]):
                    best = (s, v)
            if best is not None:
                return best[1]
        else:
            sl = starts.get(reg)
            if sl:
                i = bisect.bisect_right(sl, addr) - 1
                if i >= 0:
                    return self._sreg_vals[reg][i]
        seg = self.seg_of(addr)
        if seg and (seg['start'], reg) in self.sregs:
            return self.sregs[(seg['start'], reg)]
        if reg == 'ds' and self.default_ds:
            return self.default_ds
        if reg == 'ss':
            row = self.db.conn.execute(
                "SELECT value FROM config WHERE key='ss'").fetchone()
            if row:
                return 0x1000 + int(row[0])
        if reg == 'cs' and seg:
            return seg['base']
        return -1

    # ------------------------------------------------------------- labels
    def label_at(self, addr, kind=None):
        """Return the display name for addr, creating an auto label if needed."""
        if addr in self.names:
            return self.names[addr]
        if addr in self.auto_names:
            return self.auto_names[addr]
        if addr in self.funcs:
            return self.funcs[addr]['name']
        if kind is None:
            seg = self.seg_of(addr)
            kind = 'sub' if seg and seg['exec'] else 'unk'
        if addr in self.seg_words:
            nm = f"seg_{addr:X}"
        elif kind == 'loc':
            nm = f"loc_{addr:X}"
        elif kind == 'sub':
            nm = f"sub_{addr:X}"
        elif kind == 'byte':
            nm = f"byte_{addr:X}"
        elif kind == 'word':
            nm = f"word_{addr:X}"
        elif kind == 'dword':
            nm = f"dword_{addr:X}"
        elif kind == 'str':
            nm = None  # handled by caller with content
        else:
            nm = f"unk_{addr:X}"
        if nm:
            self.auto_names[addr] = self._unique(nm, addr)
            nm = self.auto_names[addr]
        return nm

    def _unique(self, nm, addr):
        """Ensure auto names are unique (uasm rejects duplicate symbols)."""
        if self.auto_names.get(addr) == nm:
            return nm
        base, i = nm, 0
        while nm in self.used_names:
            i += 1
            nm = f"{base}_{i}"
        self.used_names.add(nm)
        return nm

    def _register_data_ref(self, target, size, xtype, from_addr):
        self.data_refs.setdefault(target, set()).add((size, xtype))
        self.xrefs.append((from_addr, target, xtype))

    def _is_stringy(self, addr):
        fo = self.db.file_offset(addr)
        if fo is None:
            return False
        run = self.binary[fo:fo + 8]
        return len(run) >= 4 and all(32 <= b < 127 for b in run[:4])

    # ---------------------------------------------------------- discovery
    def _region_boundaries(self, seg):
        """Sorted set of addrs in segment that force an item boundary."""
        b = {seg['start'], seg['end']}
        for a, (sz, k, cnt) in self.data_items.items():
            if seg['start'] <= a < seg['end']:
                b.add(a)
                b.add(min(a + sz * max(cnt, 1), seg['end']))
        for f, fv in self.funcs.items():
            if seg['start'] <= f < seg['end']:
                b.add(f)
                if fv['end'] > f:
                    b.add(min(fv['end'], seg['end']))
        # NOTE: names are labels, not flow boundaries -- a set_name mid-code
        # (e.g. a function chunk entry) must not split a seeded code run.
        for a in self.seeds:
            if seg['start'] <= a < seg['end']:
                b.add(a)
        return sorted(b)

    def _estimate_func_end(self, start):
        """End of a function with unknown extent: next structural boundary."""
        seg = self.seg_of(start)
        if not seg:
            return start + 1
        heads = [seg['end']]
        heads += [a for a in self.data_items if start < a < seg['end']]
        heads += [f for f in self.funcs if start < f < seg['end']]
        heads += [a for a in self.names if start < a < seg['end']]
        return min(heads)

    def _compute_code_regions(self):
        """Return sorted list of [start, end) code intervals to disassemble."""
        regions = []
        covered = []  # sorted list of (start,end) occupied intervals

        # 1) function ranges are code
        for f, fv in sorted(self.funcs.items()):
            e = fv['end'] if fv['end'] > f else self._estimate_func_end(f)
            regions.append([f, e, f])
            covered.append((f, e))

        def in_covered(a):
            return any(s <= a < e for s, e in covered)

        # 2) each create_insn seed starts a code run ending at the next head
        for seg in self.segments:
            if not seg['exec']:
                continue
            bounds = self._region_boundaries(seg)
            for i, b in enumerate(bounds[:-1]):
                nxt = bounds[i + 1]
                if nxt <= b:
                    continue
                if in_covered(b):
                    continue
                if b in self.data_items:
                    continue
                # gap [b, nxt): code iff seeded, or nothing defined (linear sweep
                # only when we have no structural info at all)
                seeded = any(b <= s < nxt for s in self.seeds)
                if seeded or (not self.seeds and not self.data_items):
                    regions.append([b, nxt, None])
                    covered.append((b, nxt))

        # 3) the entry point is always code -- even when it sits inside a
        # segment marked non-executable (real-mode images mix them)
        if not any(s <= self.entry < e for s, e, _ in regions):
            for r in self._recursive_descent():
                if not in_covered(r[0]):
                    regions.append(r)
                    covered.append((r[0], r[1]))
        if not regions:
            regions = self._recursive_descent()

        regions.sort()
        return regions

    def _recursive_descent(self):
        """No IDC info: trace code from the entry point."""
        entry = self.entry
        regions = []
        visited = set()
        work = [entry]
        entry_seg = self.seg_of(entry)
        while work:
            a = work.pop()
            if a in visited:
                continue
            seg = self.seg_of(a)
            if not seg or (not seg['exec'] and
                           (entry_seg is None or
                            seg['start'] != entry_seg['start'])):
                continue
            visited.add(a)
            # linear sweep until a break in control flow
            cur = a
            start = a
            while True:
                fo = self.db.file_offset(cur)
                if fo is None or cur >= seg['end'] or cur in self.data_items:
                    break
                insn = next(self.md.disasm(self.binary[fo:fo + 16], cur, count=1), None)
                if insn is None:
                    break
                cur += insn.size
                visited.add(cur)
                iid = insn.id
                tgt = None
                if insn.operands and insn.operands[0].type == X86_OP_IMM:
                    tgt = self._fix_target(insn.address, insn.operands[0].imm)
                if iid in CALL_IDS:
                    if tgt and tgt >= self.base:
                        if tgt not in self.funcs:
                            self.funcs[tgt] = {'end': tgt, 'name': f"sub_{tgt:X}",
                                               'flags': 0, 'auto': True}
                            work.append(tgt)
                        self.call_refs.add(tgt)
                    continue
                if iid in RET_IDS or iid == X86_INS_HLT:
                    break
                if iid == X86_INS_JMP or iid == X86_INS_LJMP:
                    if tgt:
                        work.append(tgt)
                    break
                if iid in JCC_IDS or iid in LOOP_IDS:
                    if tgt:
                        work.append(tgt)
                    continue
            regions.append([start, cur, start])
        return regions

    # ---------------------------------------------------------- disassembly
    def _disasm_region(self, start, end, func_start):
        """Linear-capstone a region; store decoded insns."""
        stop_heads = sorted(set(self.data_items) | set(self.funcs))
        cur = start
        while cur < end:
            if cur in self.data_items:
                cur += self.data_items[cur][0] * max(self.data_items[cur][2], 1)
                continue
            if func_start is not None and cur in self.funcs and cur != func_start:
                break  # ran into the next function
            fo = self.db.file_offset(cur)
            if fo is None:
                break
            avail = min(16, end - cur, len(self.binary) - fo)
            if avail <= 0:
                break
            insn = next(self.md.disasm(self.binary[fo:fo + avail], cur, count=1), None)
            if insn is None:
                cur += 1  # undecodable byte -> emitted as db by the generator
                continue
            if cur + insn.size > end:
                break
            i = bisect.bisect_right(stop_heads, cur)
            nxt_head = stop_heads[i] if i < len(stop_heads) else end
            if cur + insn.size > nxt_head:
                # would overlap a known item: desynced, resume at boundary
                cur = nxt_head
                continue
            inst = {
                'addr': cur, 'size': insn.size, 'mnem': insn.mnemonic,
                'op_str': insn.op_str, 'id': insn.id, 'insn': insn,
                'func': func_start,
            }
            self.instructions.append(inst)
            self.covered.add(cur)
            cur += insn.size

    # ---------------------------------------------------------- references
    def _scan_refs(self):
        for inst in self.instructions:
            insn = inst['insn']
            addr = inst['addr']
            iid = insn.id
            ops = insn.operands
            tgt = None
            if iid in BRANCH_IDS and ops and ops[0].type == X86_OP_IMM:
                tgt = self._fix_target(addr, ops[0].imm)
            if iid in CALL_IDS:
                tseg = self.seg_of(tgt) if tgt is not None else None
                if tgt is not None and tgt >= self.base and tseg and tseg['exec']:
                    self.call_refs.add(tgt)
                    if tgt not in self.funcs:
                        self.funcs[tgt] = {'end': tgt, 'name': f"sub_{tgt:X}",
                                           'flags': 0, 'auto': True}
                    self.xrefs.append(
                        (addr, tgt, 'fcall' if iid == X86_INS_LCALL else 'call'))
            elif iid in JMP_IDS or iid in JCC_IDS or iid in LOOP_IDS:
                if tgt is not None and self.base <= tgt < 0x110000:
                    self.code_refs.add(tgt)
                    self.xrefs.append((addr, tgt, 'jmp'))
            # memory operands -> data refs
            sreg_dst = ops and ops[0].type == X86_OP_REG and \
                ops[0].reg in SREG_REGS and ops[0].reg != X86_REG_SP
            for opi, op in enumerate(ops):
                if op.type != X86_OP_MEM:
                    continue
                m = op.mem
                if m.base in (X86_REG_BP, X86_REG_SP):
                    continue
                seg = self._mem_seg(insn, op)
                sval = self.sreg_value(addr, seg)
                if sval is None or sval < 0:
                    continue
                target = sval * 16 + (m.disp & 0xFFFF)
                if target < self.base or target > 0x110000:
                    continue
                tseg = self.seg_of(target)
                if tseg and tseg['exec']:
                    continue  # points into code: could be jump table; skip
                size = op.size if getattr(op, 'size', 0) else 0
                xtype = 'w' if (op.access & CS_AC_WRITE) else 'r'
                self._register_data_ref(target, size or 1, xtype, addr)
                # word loaded into a segment register -> `seg_XXXX` label
                if iid == X86_INS_MOV and sreg_dst and opi == 1:
                    self.seg_words.add(target)
                elif iid in (X86_INS_LES, X86_INS_LDS) and opi == 1:
                    self.seg_words.add(target + 2)
            # remember which insn bytes hold relocated segment words
            for b in range(addr, addr + insn.size):
                if b in self.relocs:
                    self.reloc_words.add(b)

    def _mem_seg(self, insn, mem_op):
        for p in insn.prefix:
            if p in SEG_PREFIX:
                return SEG_PREFIX[p]
        if mem_op.mem.base == X86_REG_BP:
            return 'ss'
        return 'ds'

    # ------------------------------------------------------------ rendering
    def _op_num(self, value, ovr_kind):
        if ovr_kind == 'dec':
            return str(value)
        if ovr_kind == 'char' and 32 <= value < 127:
            return f"'{chr(value)}'"
        return ida_num(value)

    def _seg_by_para(self, para):
        for s in self.segments:
            if s['base'] == para or (s['start'] >> 4) == para:
                return s
        return None

    def _ptr_needed(self, insn, opi):
        """True when no register operand disambiguates the memory size."""
        # push/pop are inherently word-sized: IDA omits the ptr keyword
        if insn.id in (X86_INS_PUSH, X86_INS_POP):
            return False
        # a shift/rotate count operand (cl or imm) is not the accessed
        # data -- it never disambiguates the memory size
        if insn.mnemonic.split()[-1] in SHIFT_IMPLICIT or \
                insn.mnemonic.split()[-1] in ('shld', 'shrd'):
            return True
        return not any(
            o.type == X86_OP_REG for j, o in enumerate(insn.operands)
            if j != opi)

    def _acc_size(self, insn, op):
        """Access width in bytes; les/lds/lcall/ljmp read a far pointer."""
        acc = op.size if getattr(op, 'size', 0) else 0
        if insn.id in (X86_INS_LES, X86_INS_LDS, X86_INS_LCALL, X86_INS_LJMP):
            acc = 4
        return acc

    @staticmethod
    def _sz_kw(acc):
        return {1: 'byte', 2: 'word', 4: 'dword', 6: 'fword',
                8: 'qword', 10: 'tbyte'}.get(acc)

    def _asm_ptr(self, cur, acc, decl_sz):
        """uasm: ptr keyword is mandatory when access size differs from the
        declared item size (e.g. `push` of a byte var, word load of a db)."""
        if cur or not (decl_sz and acc and acc != decl_sz):
            return cur
        d = self._sz_kw(acc)
        return (d + ' ptr ') if d else cur

    def _mem_bp(self, inst, insn, opi, op, segname, ptr_kw):
        """[bp+..] operand: render stack var names and typed equate sizes."""
        m = op.mem
        disp = m.disp
        f = inst.get('func')
        fv = self.frame_vars.get(f, {}) if f is not None else {}
        finfo = self.funcs.get(f) if f is not None else None
        has_frame = bool(fv) or f in self.frames or \
            (finfo is not None and bool(finfo['flags'] & 0x10))
        fname = None
        if has_frame:
            fname = self._stkvar_name(f, disp)
        inner = 'bp'
        if fname:
            inner += '+' + fname
        elif disp:
            inner += ('+' if disp >= 0 else '-') + ida_num(abs(disp))
        if m.index:
            inner += '+' + insn.reg_name(m.index)
        # ptr keyword rules (IDA vs uasm): push/pop never show it;
        # `byte ptr` is dropped when a byte register pins the size;
        # the .asm must add it back whenever the access size differs
        # from the equate's declared size (typed `var = word ptr N`)
        acc = self._acc_size(insn, op)
        vsz = self._stkvar_size(f, disp) if fname else 0
        need = self._ptr_needed(insn, opi)
        txt = (segname or '') + '[' + inner + ']'
        atxt = txt
        if ptr_kw:
            if insn.id in (X86_INS_PUSH, X86_INS_POP):
                # push/pop never print a ptr keyword, but uasm still needs
                # one when the equate is declared wider than the access
                # (e.g. `push [bp+dwordarg+2]` -> 66h prefix without it)
                if acc and vsz and acc != vsz:
                    d = self._sz_kw(acc)
                    if d:
                        atxt = d + ' ptr ' + atxt
            elif ptr_kw == 'byte ptr' and not need:
                if acc and vsz and acc != vsz:
                    atxt = 'byte ptr ' + atxt
            elif need or ptr_kw != 'byte ptr':
                txt = ptr_kw + ' ' + txt
                atxt = txt
        elif acc and vsz and acc != vsz:
            d = self._sz_kw(acc)
            if d:
                atxt = d + ' ptr ' + atxt
        if atxt != txt:
            inst.setdefault('asm_ops_map', {})[opi] = atxt
        return txt

    def _mem_off_ovr(self, inst, insn, opi, m, base, index,
                     ovr, any_ovr, segname, ptr_kw):
        """op_plain_offset on the displacement: target = base + u16(disp).
        Returns the rendered operand or None when no offset override."""
        off_base = ovr[1] if ovr and ovr[0] == 'offset' else None
        if off_base is None:
            for k, a in any_ovr:
                if k == 'offset':
                    off_base = a
        if off_base is None:
            return None
        target = off_base + (m.disp & 0xFFFF)
        lbl = self._offset_expr(target)
        if lbl is None:
            return None
        inner0 = ''
        if base:
            inner0 += base
        if index:
            inner0 += ('+' if inner0 else '') + index
            if m.scale and m.scale != 1:
                inner0 += f"*{m.scale}"
        expr = f"{lbl}[{inner0}]" if inner0 else lbl
        # for the .asm: the expr denotes a ds-relative offset that is
        # not the encoded displacement -> emit the numeric form
        if inner0 or m.disp:
            inst.setdefault('asm_ops_map', {})[opi] = \
                self._numeric_mem(insn, opi, m, segname, ptr_kw)
            if not (m.base or m.index):
                # a pure-disp numeric (`es:[20h]`) assembles as a 32-bit
                # displacement -- never the original disp16
                inst['db_bytes'] = insn.bytes
        return (ptr_kw + ' ' if ptr_kw and self._ptr_needed(insn, opi)
                else '') + (segname or '') + expr

    def _mem_target(self, insn, op, addr):
        """(seg_name, linear target) of a displacement via sreg tracking."""
        seg = self._mem_seg(insn, op)
        sval = self.sreg_value(addr, seg)
        target = (sval * 16 + (op.mem.disp & 0xFFFF)) \
            if (sval is not None and sval >= 0) else None
        return seg, target

    def _mem_indexed(self, inst, insn, opi, op, seg, target, inner,
                     segname, ptr_kw):
        """`label[reg]` form for base/index+disp.  Returns text or None."""
        m = op.mem
        dsz = insn.encoding.disp_size if insn.encoding else 0
        # capstone may report a 32-bit base/index for an encoding that
        # carries no 67h prefix (misdecoded data) -- uasm would emit the
        # override, changing the bytes
        if insn.prefix[3] != 0x67 and (
                (m.base and insn.reg_name(m.base)[:1] == 'e') or
                (m.index and insn.reg_name(m.index)[:1] == 'e')):
            inst['db_bytes'] = insn.bytes
            return None
        lbl = decl_sz = None
        is_code = False
        if target is not None and target >= self.base:
            lbl, decl_sz, is_code = self._mem_label(target)
        if lbl is None:
            if dsz == 2:
                # disp16 that can't be expressed as `label[reg]` (no label
                # to carry the relocation) -- emit original bytes verbatim
                inst['db_bytes'] = insn.bytes
            return None
        acc = self._acc_size(insn, op)
        mism = decl_sz and acc and acc != decl_sz
        p = (ptr_kw + ' ') if (ptr_kw and (
            self._ptr_needed(insn, opi) or mism)) else ''
        ap = self._asm_ptr(p, acc, decl_sz)
        if is_code and not ap and acc:
            # a `::` near label is not a valid data operand for uasm even
            # when sizes match -- always qualify the access explicitly
            kw = self._sz_kw(acc)
            ap = (kw + ' ptr ') if kw else ap
        np = ap or (ptr_kw + ' ' if ptr_kw else '')
        if self.seg_of(target) is not None and dsz == 1:
            # A symbolic `label[reg]` disp is relocatable, so uasm must
            # encode disp16 -- but the original instruction used disp8.
            # Emit the numeric displacement to keep the byte-identical
            # modrm (the label form stays in the .lst).
            num = inner + ('+' if m.disp >= 0 else '-') + \
                ida_num(abs(m.disp))
            atxt = np + (segname or '') + f"[{num}]"
        elif self._in_chunked(target):
            # chunked-seg label: symbolic form resolves against the wrong
            # frame -- emit the stored displacement numerically
            num = inner + ('+' if m.disp >= 0 else '-') + \
                ida_num(abs(m.disp))
            atxt = np + (segname or '') + f"[{num}]"
        elif self.seg_of(target) is not None:
            tseg = self.seg_of(target)
            tstart = max(tseg['start'], self.base)
            dmask = 0xFFFFFFFF if insn.prefix[3] == 0x67 else 0xFFFF
            if (target - tstart) & dmask != m.disp & dmask:
                # uasm would emit the label's offset in its own frame,
                # which differs from the stored displacement -- numeric
                num = inner + ('+' if m.disp >= 0 else '-') + \
                    ida_num(abs(m.disp))
                atxt = np + (segname or '') + f"[{num}]"
            else:
                # uasm needs an explicit seg on a label operand; a
                # relocatable disp always encodes disp16, matching the
                # original mod=10
                aseg = segname or f"{seg}:"
                atxt = ap + aseg + f"{lbl}[{inner}]"
        elif dsz == 2:
            # original used disp16 for a small/zero disp -- neither the
            # numeric form (minimized to disp8/mod00) nor a label is
            # expressible -> emit the original bytes verbatim
            inst['db_bytes'] = insn.bytes
            atxt = None
        else:
            # label is beyond every segment: never declared,
            # so the .asm must use the numeric displacement
            num = inner + ('+' if m.disp >= 0 else '-') + \
                ida_num(abs(m.disp))
            atxt = np + (segname or '') + f"[{num}]"
        if atxt is not None:
            inst.setdefault('asm_ops_map', {})[opi] = atxt
        return p + (segname or '') + f"{lbl}[{inner}]"

    def _mem_disp(self, inst, insn, opi, op, segname, ptr_kw):
        """Pure [disp] operand: resolve through the effective segment."""
        m = op.mem
        addr = inst['addr']
        seg, target = self._mem_target(insn, op, addr)
        if target is not None and target >= self.base:
            lbl, decl_sz, is_code = self._mem_label(target)
            if lbl is not None:
                # IDA prints "X ptr" when access size differs from the
                # declared item size, or when size can't be inferred
                acc = self._acc_size(insn, op)
                ptr = ''
                if ptr_kw and acc in (1, 2, 4) and \
                        (self._ptr_needed(insn, opi)
                         or (decl_sz and acc != decl_sz)):
                    ptr = ptr_kw + ' '
                # uasm: bare label needs an explicit seg override, and
                # ptr when access size != declared item size; labels
                # outside every segment are never declared -> numeric
                ap = self._asm_ptr(ptr, acc, decl_sz)
                if is_code and not ap and acc:
                    # a `::` near label is not a valid data operand for
                    # uasm even when sizes match -- qualify explicitly
                    kw = self._sz_kw(acc)
                    ap = (kw + ' ptr ') if kw else ap
                # a numeric displacement carries no declared type --
                # keep capstone's size keyword if it printed one (e.g.
                # `shl word ptr ds:X, cl`, where cl is a count not a size)
                np = ap or (ptr_kw + ' ' if ptr_kw else '')
                if self._in_chunked(target):
                    # label sits in a physically split segment: uasm would
                    # resolve it chunk-relative, not against the frame the
                    # original used -- emit the stored displacement, exactly
                    # like IDA's `ds:3810h` numeric form
                    atxt = np + (segname or f"{seg}:") + \
                        ida_num(m.disp & 0xFFFF)
                    inst['db_bytes'] = insn.bytes
                elif self.seg_of(target) is not None:
                    tseg = self.seg_of(target)
                    tstart = max(tseg['start'], self.base)
                    dmask = 0xFFFFFFFF if insn.prefix[3] == 0x67 \
                        else 0xFFFF
                    if (target - tstart) & dmask != \
                            m.disp & dmask:
                        # label's offset in its own frame differs from
                        # the stored displacement -- numeric
                        atxt = np + (segname or '') + \
                            f"[{ida_num(m.disp & 0xFFFF)}]"
                        inst['db_bytes'] = insn.bytes
                    else:
                        atxt = ap + (segname or f"{seg}:") + lbl
                else:
                    atxt = np + (segname or '') + \
                        f"[{ida_num(m.disp & 0xFFFF)}]"
                    inst['db_bytes'] = insn.bytes
                inst.setdefault('asm_ops_map', {})[opi] = atxt
                return ptr + (segname or '') + lbl
        segp = segname or f"{seg}:"
        inst['db_bytes'] = insn.bytes
        return (ptr_kw + ' ' if ptr_kw else '') + \
            f"{segp}{ida_num(m.disp)}"

    def _render_mem(self, inst, insn, opi, op):
        m = op.mem
        addr = inst['addr']
        ovr = self.op_ovr.get((addr, opi))
        any_ovr = self.op_ovr_any.get(addr, [])

        # operand size keyword ("word ptr", ...) from capstone text
        ops_text = insn.op_str.split(', ')
        raw = ops_text[opi] if opi < len(ops_text) else ''
        pm = re.match(r'((?:byte|word|dword|fword|qword|tbyte|far|near) ptr)\s*', raw)
        ptr_kw = pm.group(1) if pm else ''

        segname = None
        for p in insn.prefix:
            if p in SEG_PREFIX:
                segname = SEG_PREFIX[p] + ':'
        base = insn.reg_name(m.base) if m.base else None
        index = insn.reg_name(m.index) if m.index else None

        # original encoded mod=10 disp16 but the value fits a signed byte:
        # uasm always minimizes a numeric/symbolic disp to mod=01 disp8
        # (one byte shorter) -- keep the original encoding verbatim
        if insn.encoding and insn.encoding.disp_size == 2 and \
                (base or index) and -128 <= m.disp <= 127:
            inst['db_bytes'] = insn.bytes
        elif insn.encoding and insn.encoding.disp_size == 1 and \
                m.disp == 0 and not (m.base == X86_REG_BP and not m.index):
            # mod=01 disp8=0: capstone drops the "+0" and uasm
            # re-encodes as mod=00 -- keep the original encoding.
            # (only a lone [bp] still forces a disp8 on reassembly)
            inst['db_bytes'] = insn.bytes

        if m.base == X86_REG_BP:
            return self._mem_bp(inst, insn, opi, op, segname, ptr_kw)

        r = self._mem_off_ovr(inst, insn, opi, m, base, index,
                              ovr, any_ovr, segname, ptr_kw)
        if r is not None:
            return r

        # enum on displacement?
        enum_nm = self.enum_members.get(ovr[1], {}).get(m.disp) \
            if ovr and ovr[0] == 'enum' else None
        if not enum_nm:
            for k, a in any_ovr:
                if k == 'enum':
                    enum_nm = self.enum_members.get(a, {}).get(m.disp)
        # struct member?
        struc_nm = self._struc_member_name(ovr[1], m.disp) \
            if ovr and ovr[0] == 'struct' else None

        inner = ''
        if base:
            inner += base
        if index:
            inner += ('+' if inner else '') + index
            if m.scale and m.scale != 1:
                inner += f"*{m.scale}"

        if enum_nm is not None:
            inner += ('+' if inner else '') + enum_nm
        elif struc_nm is not None:
            inner += ('+' if inner else '') + struc_nm
        elif base or index:
            dsz = insn.encoding.disp_size if insn.encoding else 0
            if m.disp or dsz == 2:
                # IDA renders a resolvable displacement as `label[reg]`
                seg, target = self._mem_target(insn, op, addr)
                r = self._mem_indexed(inst, insn, opi, op, seg, target,
                                      inner, segname, ptr_kw)
                if r is not None:
                    return r
                inner += ('+' if m.disp >= 0 else '-') + \
                    ida_num(abs(m.disp))
        else:
            return self._mem_disp(inst, insn, opi, op, segname, ptr_kw)

        ptr = ptr_kw + ' ' if ptr_kw and self._ptr_needed(insn, opi) else ''
        return ptr + (segname or '') + '[' + inner + ']'

    def _numeric_mem(self, insn, opi, m, segname, ptr_kw):
        """Numeric mem operand for the assemblable .asm output."""
        inner = ''
        if m.base:
            inner += insn.reg_name(m.base)
        if m.index:
            inner += ('+' if inner else '') + insn.reg_name(m.index)
            if m.scale and m.scale != 1:
                inner += f"*{m.scale}"
        if inner:
            if m.disp:
                inner += ('+' if m.disp >= 0 else '-') + ida_num(abs(m.disp))
        elif m.disp:
            inner = ida_num(m.disp & 0xFFFF)
        far_mem = insn.id in (X86_INS_LES, X86_INS_LDS,
                              X86_INS_LCALL, X86_INS_LJMP)
        if far_mem:
            return 'dword ptr ' + (segname or '') + '[' + inner + ']'
        # a bare numeric operand has no declared type -- keep capstone's
        # size keyword (`shl [x], cl` can't infer the width from cl)
        return ((ptr_kw + ' ') if ptr_kw else '') + \
            (segname or '') + '[' + inner + ']'

    def _stkvar_size(self, func, disp):
        """Size of the var enclosing disp (for ptr emission decisions)."""
        sizes = self.frame_sz.get(func, {})
        if disp in sizes:
            return sizes[disp]
        for off, sz in sizes.items():
            if off <= disp < off + sz:
                return sz
        return 0

    def _stkvar_name(self, func, disp):
        """Name for a bp-relative stack operand: declared or auto var."""
        fv = self.frame_vars.get(func, {})
        if disp in fv:
            return fv[disp]
        sizes = self.frame_sz.get(func, {})
        # find the smallest enclosing var for partial access (name+delta)
        for off in sorted(sizes):
            if off <= disp < off + sizes[off]:
                base = fv.get(off)
                if base:
                    d = disp - off
                    return base + (f"+{ida_num(d)}" if d else '')
        finfo = self.funcs.get(func)
        far = bool(finfo and finfo['flags'] & 2)
        args_base = 6 if far else 4
        if disp >= args_base:
            return f"arg_{disp - args_base:X}"
        if disp >= 0:
            # saved bp / return-address zone: IDA names it var_sN only for
            # slots covered by the frame's frregs (saved registers) size
            fr = self.frames.get(func)
            if fr and disp >= args_base - fr[1]:
                return f"var_s{disp:X}"
            return None
        return f"var_{-disp:X}"

    def _mem_label(self, target):
        """(label, declared_size, is_code) for an absolute memory target,
        or (None, 0, False).  is_code marks loc_/sub_-style labels that
        uasm emits as `::` near labels -- they always need an explicit
        `X ptr` when accessed as data."""
        # inside a known data item -> itemlabel+delta
        di = self._di_sorted
        i = bisect.bisect_right(di, target) - 1
        if i >= 0:
            a = di[i]
            sz, k, cnt = self.data_items[a]
            if a + sz * max(cnt, 1) > target:
                d = target - a
                lbl = self.label_at(a, k)
                if lbl is None:
                    lbl = self.auto_names.setdefault(a, f"asc_{a:X}")
                if d:
                    lbl = f"{lbl}+{ida_num(d, True)}"
                # 'str' size is the string length; the emitted element is db
                return lbl, (1 if k == 'str' else sz), False
        # labels not on a data item are emitted as `equ $+n`/`db` lines in
        # the .asm; the generator types them by name prefix (word_ -> word
        # ptr etc), so report that same size to size the access correctly
        if target in self.names or target in self.auto_names:
            code = target in self.funcs or target in self.covered
            nm = self.label_at(target)
            return nm, 2 if code else self._lbl_size(nm, target), code
        near = self._nearest_label_below(target)
        if near is not None:
            nm, off = near
            code = (target - off) in self.covered or \
                (target - off) in self.funcs
            if off:
                return f"{nm}+{ida_num(off, True)}", \
                    2 if code else self._lbl_size(nm, target), code
            return nm, 2 if code else self._lbl_size(nm, target), code
        return None, 0, False

    def _offset_expr(self, target):
        """Render a linear target for op_plain_offset: struct-member or label.

        Parenthesizes composite expressions the way IDA does:
        `(stru_X.member+d)[si]` vs plain `name[si]`.
        """
        di = self._di_sorted
        i = bisect.bisect_right(di, target) - 1
        if i >= 0:
            a = di[i]
            sz, kind, cnt = self.data_items[a]
            if kind.startswith('struct:') and a + sz * max(cnt, 1) > target:
                sname = kind.split(':', 1)[1]
                delta = target - a
                mname, rem = self._struc_member_at(sname, delta)
                if mname:
                    expr = f"{sname}.{mname}"
                else:
                    expr = sname
                    rem = delta
                if rem:
                    expr += f"+{ida_num(rem, True)}"
                return f"({expr})" if '+' in expr else expr
        lbl, _, _ = self._mem_label(target)
        if lbl is None:
            return None
        return f"({lbl})" if '+' in lbl else lbl

    def _struc_member_at(self, sname, delta):
        """(member_name, remainder) for byte delta inside struct sname."""
        best_off, best_name = -1, None
        for off, _sz, mname in self.struc_members.get(sname, []):
            if off <= delta and off > best_off:
                best_off, best_name = off, mname
        if best_name is None:
            return None, delta
        return best_name, delta - best_off

    def _struc_member_name(self, sid, off):
        row = self.db.conn.execute(
            "SELECT name FROM struc_members WHERE struc_id=? AND offset=?",
            (sid, off)).fetchone()
        return row[0] if row else None

    def _data_kind_for(self, size):
        return {1: 'byte', 2: 'word', 4: 'dword'}.get(size, 'byte')

    def _lbl_size(self, nm, target):
        """Size the generator will declare for a label: its name prefix
        (byte_/word_/...) if any, else word for `equ` aliases past the
        image end (uasm sizes untyped equs as words) and byte for `db`
        gap lines."""
        p = {'byte': 1, 'word': 2, 'dword': 4, 'qword': 8, 'fword': 6,
             'tbyte': 10}.get(nm.split('_')[0])
        if p:
            return p
        return 2 if target >= self.image_end else 1

    def _nearest_label_below(self, target):
        """Label for target inside a known data item (label+ofs form)."""
        key = len(self.names) + len(self.auto_names) + len(self.data_items)
        if getattr(self, '_lbl_key', None) != key:
            self._lbl_key = key
            self._lbl_sorted = sorted(
                set(self.names) | set(self.auto_names) | set(self.data_items))
        i = bisect.bisect_right(self._lbl_sorted, target) - 1
        if i < 0:
            return None
        a = self._lbl_sorted[i]
        if a in self.data_items:
            sz, _k, cnt = self.data_items[a]
            if a + sz * max(cnt, 1) <= target:
                return None
        elif target - a > 0x40:
            return None
        lbl = self.label_at(a)
        return (lbl, target - a) if lbl else None

    def _render_op(self, inst, insn, opi, op):
        addr = inst['addr']
        ovr = self.op_ovr.get((addr, opi))
        iid = insn.id

        if op.type == X86_OP_REG:
            return insn.reg_name(op.reg)

        if op.type == X86_OP_MEM:
            return self._render_mem(inst, insn, opi, op)

        if op.type == X86_OP_IMM:
            val = op.imm
            # branch / call target: wrap to 16-bit inside current CS
            if iid in BRANCH_IDS and opi == 0 and val >= 0:
                val = self._fix_target(addr, val)
                if iid in CALL_IDS:
                    fv = self.funcs.get(val)
                    lbl = fv['name'] if fv else self.label_at(val, 'sub')
                    # `call farproc` makes uasm emit `push cs; call near` --
                    # pin the original near form with an explicit qualifier
                    if lbl:
                        inst.setdefault('asm_ops_map', {})[opi] = \
                            'near ptr ' + lbl
                    return lbl or ida_num(val)
                fv = self.funcs.get(val)
                if fv is not None:
                    lbl = fv['name']
                else:
                    lbl = self.label_at(val, 'loc')
                short = bool(insn.bytes) and insn.bytes[0] in SHORT_JMP_OPS
                lbltxt = lbl or ida_num(val)
                # asm: bare label lets uasm auto-fit short/near (drift-safe),
                # `near ptr` pins the original near form so it can't shrink;
                # loop/jcxz are short-only -- no near form exists for them
                if lbl and insn.bytes and insn.bytes[0] not in LOOP_OPS:
                    inst.setdefault('asm_ops_map', {})[opi] = \
                        lbltxt if short else 'near ptr ' + lbltxt
                return ('short ' if short else '') + lbltxt
            if val < 0:
                return self._op_num(val, ovr[0] if ovr else None)
            # enum override (only this operand's override — never the sibling
            # operand's, which is a classic offset/enum leak)
            if ovr and ovr[0] == 'enum':
                nm = self.enum_members.get(ovr[1], {}).get(val)
                if nm:
                    return nm
            # segment value: a relocation on the imm word means the stored
            # value is relative to the load base -> the runtime paragraph is
            # val + image_base_para, e.g. stored 128Dh -> seg004 (228Dh)
            reloc = any(r in self.reloc_words
                        for r in range(addr + 1, addr + insn.size))
            is_seg = bool(ovr and ovr[0] == 'seg') or reloc
            if is_seg and getattr(op, 'size', 2) == 1:
                # an imm8 can't carry a word-sized `seg` fixup; the reloc
                # word runs into the next insn's bytes -- emit verbatim
                inst['db_bytes'] = insn.bytes
                return ida_num(val, True)
            if is_seg:
                seg = self._seg_by_para(val + (self.base >> 4)) or \
                    self._seg_by_para(val)
                if seg is None and reloc:
                    # the relocated word points at a paragraph that isn't
                    # a declared segment base -- emit a `seg` reference to
                    # the containing segment so the fixup stores the right
                    # paragraph instead of a plain numeric
                    rt = next((self.relocs[r] for r in
                               range(addr + 1, addr + insn.size)
                               if r in self.reloc_words), None)
                    if rt:
                        seg = self.seg_of(rt)
                return f"seg {seg['name']}" if seg else \
                    ida_num(val + (self.base >> 4), True)
            # explicit offset override: op_plain_offset(ea, n, base)
            off_ovr = ovr[1] if ovr and ovr[0] == 'offset' else None
            if off_ovr is not None:
                target = off_ovr + val
                lbl, delta = self._offset_label(target)
                if lbl:
                    if getattr(op, 'size', 0) == 1:
                        # an imm8 can't carry a word-sized offset fixup
                        # in uasm -- emit the original bytes verbatim
                        inst['db_bytes'] = insn.bytes
                    elif self._in_chunked(target):
                        # chunked-seg label: `offset` would resolve against
                        # the physical chunk base, not the segment frame the
                        # original stored -- emit the original imm verbatim
                        inst.setdefault('asm_ops_map', {})[opi] = \
                            ida_num(val, True)
                    if delta:
                        return f"(offset {lbl}+{ida_num(delta)})"
                    return f"offset {lbl}"
                return f"offset {ida_num(val, True)}"
            # heuristic offset: only for load/store-addr mnemonics, only for
            # word-sized operands (a byte imm can't hold a pointer), only
            # when the target is a named location or a string
            if iid in OFFSET_MNEMS | {X86_INS_PUSH} and \
                    0 < val < 0x10000 and getattr(op, 'size', 2) >= 2:
                ds = self.sreg_value(addr, 'ds')
                if ds is not None and ds >= 0:
                    t = ds * 16 + val
                    if self._offset_worthy(t):
                        if self._in_chunked(t):
                            inst.setdefault('asm_ops_map', {})[opi] = \
                                ida_num(val, True)
                        lbl = self.label_at(t)
                        return lbl if iid == X86_INS_PUSH \
                            else f"offset {lbl}"
            if (not ovr or ovr[0] not in ('dec', 'char')) and 32 <= val < 127:
                self.char_hints[addr] = val
            return self._op_num(val, ovr[0] if ovr else None)

        return insn.op_str

    def _offset_label(self, target):
        """(label, delta) for an `offset` operand: the exact name, else the
        containing data item's label plus a delta (`(offset item+600h)`)."""
        if target in self.names:
            return self.label_at(target), 0
        # inside a data item -> `itemname+delta` (IDA style); auto names at
        # mid-item addresses are synthetic and must not win over this form
        i = bisect.bisect_right(self._di_sorted, target) - 1
        if i >= 0:
            a = self._di_sorted[i]
            sz, k, cnt = self.data_items[a]
            if target < a + sz * max(cnt, 1):
                return self.label_at(a, k), target - a
        if target in self.auto_names:
            return self.label_at(target), 0
        return None, 0

    def _offset_worthy(self, target):
        """True when an immediate should render as `offset name`: the target
        must be an explicitly-named location or a string item."""
        if target in self.names:
            return True
        it = self.data_items.get(target)
        if it and it[1] == 'str':
            return True
        if target in self.auto_names:
            nm = self.auto_names[target]
            return nm.startswith(('a', 'asc_'))
        return False

    # opcodes for which uasm substitutes a shorter imm8 encoding when the
    # original imm16 operand happens to fit in a sign-extended byte
    _IMM16_OPT_OPS = frozenset(
        (0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D,  # acc-imm16 -> 83 ib
         0x68, 0x69, 0x81))                              # push/imul/grp1 iw->ib

    def render(self, inst):
        insn = inst['insn']
        ops = insn.operands
        iid = insn.id
        mnem = insn.mnemonic
        enc = insn.encoding
        # redundant prefixes (double lock, repeated seg override): capstone
        # reports each class once and uasm emits at most one -- a longer
        # prefix run in the original bytes is unexpressible
        if insn.bytes:
            lead = 0
            while lead < insn.size and insn.bytes[lead] in _PREFIX_BYTES:
                lead += 1
            if lead > sum(1 for p in insn.prefix if p):
                inst['db_bytes'] = insn.bytes
            elif lead < insn.size and insn.bytes[lead] == 0x82:
                # opcode 82h is the alias of group1-imm8 opcode 80h; uasm
                # always encodes 80h
                inst['db_bytes'] = insn.bytes
            elif len(ops) == 2 and ops[0].type == X86_OP_REG and \
                    ops[1].type == X86_OP_REG and lead + 1 < insn.size:
                opc, modrm = insn.bytes[lead], insn.bytes[lead + 1]
                if opc in _RM_DEST_OPS and modrm >= 0xC0:
                    # uasm canonicalizes reg,reg ALU/mov ops to the
                    # reg-dest encoding (opcode+2, swapped modrm fields)
                    inst['db_bytes'] = insn.bytes
                elif opc in (0x84, 0x85) and modrm >= 0xC0:
                    c0 = _REG_CODE.get(ops[0].reg)
                    c1 = _REG_CODE.get(ops[1].reg)
                    if c0 is not None and c1 is not None and \
                            modrm != 0xC0 | (c0 << 3) | c1:
                        # uasm encodes operand 0 into the modrm reg field
                        inst['db_bytes'] = insn.bytes
            if 'db_bytes' not in inst and lead + 1 < insn.size:
                opc, modrm = insn.bytes[lead], insn.bytes[lead + 1]
                regf = modrm & 0x38
                if opc == 0xFF and modrm >= 0xC0 and \
                        regf in (0x00, 0x08, 0x30) or \
                        opc == 0x8F and modrm >= 0xC0 and regf == 0 or \
                        opc in (0xC6, 0xC7) and modrm >= 0xC0 and \
                        regf == 0 or \
                        opc in (0xF6, 0xF7) and modrm >= 0xC0 and \
                        regf in (0x00, 0x08):
                    # uasm always picks the single-byte register form:
                    # inc/dec/push reg -> 40+/48+/50+, pop reg -> 58+,
                    # mov reg,imm -> B0+/B8+, test acc,imm -> A8/A9
                    inst['db_bytes'] = insn.bytes
                elif opc in (0x80, 0x81) and (modrm & 0xC7) == 0xC0:
                    # group-1 with an accumulator r/m operand: uasm emits
                    # the acc-imm opcodes (04/05/../3C/3D) or the 83h
                    # sign-extended form instead
                    inst['db_bytes'] = insn.bytes
                elif opc in (0x88, 0x89, 0x8A, 0x8B) and \
                        (modrm & 0xC7) == 0x06 and regf == 0:
                    # mov al/ax <-> [disp16] is always emitted in the
                    # moffs form (A0-A3), even for symbolic operands
                    inst['db_bytes'] = insn.bytes
                elif opc in (0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3) and \
                        regf == 0x30:
                    # the sal (/6) alias is emitted as shl (/4)
                    inst['db_bytes'] = insn.bytes
                elif opc in (0xF6, 0xF7) and modrm < 0xC0 and \
                        regf == 0x08:
                    # the test /1 memory alias is emitted as /0
                    inst['db_bytes'] = insn.bytes
                elif opc == 0x0F and 0x90 <= modrm <= 0x9F and \
                        lead + 2 < insn.size and insn.bytes[lead + 2] & 0x38:
                    # setcc modrm reg is a sub-opcode; aliases reemit as /0
                    inst['db_bytes'] = insn.bytes
                elif opc == 0xDC and modrm >= 0xC0 and (modrm & 7) == 0:
                    # fop st(0),st(0) has a D8/DC alias pair -- uasm
                    # always picks D8
                    inst['db_bytes'] = insn.bytes
                elif opc == 0xCD and insn.bytes[-1] == 3:
                    # `int 3` reencodes as the CC single-byte form
                    inst['db_bytes'] = insn.bytes
                elif opc in (0xC0, 0xC1) and insn.bytes[-1] == 1:
                    # `shift x, 1` reencodes as the D0/D1 implicit-count form
                    inst['db_bytes'] = insn.bytes
                elif opc == 0x0F and modrm in (0x20, 0x21, 0x22, 0x23) and \
                        lead + 2 < insn.size and insn.bytes[lead + 2] < 0xC0:
                    # mov to/from cr/dr with a memory-form modrm --
                    # capstone prints the reg form but uasm emits /C0
                    inst['db_bytes'] = insn.bytes
            if 'db_bytes' not in inst and lead:
                leadb = insn.bytes[:lead]
                # a 66h/67h prefix only survives reassembly when the insn
                # genuinely uses a 32-bit operand/address; a redundant one
                # is silently dropped by uasm
                if 0x66 in leadb and not (
                        mnem.split()[-1] in _DWORD_MNEMS or any(
                            o.type == X86_OP_REG and
                            (insn.reg_name(o.reg) or '') in _EREGS or
                            o.type == X86_OP_MEM and o.size in (4, 6)
                            for o in ops)) or \
                        0x66 in leadb and \
                        mnem.split()[-1] in _SYS_FIXED_MNEMS:
                    inst['db_bytes'] = insn.bytes
                # a call/jmp through a 32-bit operand loses its 66h --
                # uasm won't emit it for a control-flow instruction even
                # when capstone renders `dword ptr`
                if 'db_bytes' not in inst and 0x66 in leadb and \
                        iid in (X86_INS_LCALL, X86_INS_LJMP,
                                X86_INS_JMP, X86_INS_CALL) and \
                        any(o.type == X86_OP_MEM for o in ops):
                    inst['db_bytes'] = insn.bytes
                if 'db_bytes' not in inst and 0x67 in leadb and (
                        mnem.split()[-1] in _STRIP_BASES or not any(
                            o.type == X86_OP_MEM and (
                                (insn.reg_name(o.mem.base) or
                                 '')[:1] == 'e' or
                                (insn.reg_name(o.mem.index) or
                                 '')[:1] == 'e')
                            for o in ops)):
                    # string ops render as a bare mnemonic -- the addr32
                    # override has no asm form
                    inst['db_bytes'] = insn.bytes
                segb = [b for b in leadb if b in SEG_PREFIX]
                if 'db_bytes' not in inst and segb and \
                        any(b in (0x66, 0x67) for b in leadb) and \
                        min(leadb.index(b) for b in segb) < min(
                            leadb.index(b) for b in leadb
                            if b in (0x66, 0x67)):
                    # uasm emits 66h/67h before a seg override; an
                    # original seg-first prefix order is not reproducible
                    inst['db_bytes'] = insn.bytes
                if 'db_bytes' not in inst and len(segb) == 1:
                    mems = [o.mem for o in ops if o.type == X86_OP_MEM]
                    if mems:
                        # uasm elides an override that matches the
                        # operand's natural segment (ds, or ss for bp)
                        dflt = 'ss' if any(
                            m.base == X86_REG_BP
                            for m in mems) else 'ds'
                        if SEG_PREFIX[segb[0]] == dflt:
                            inst['db_bytes'] = insn.bytes
                    elif ops:
                        # seg prefix on a non-memory insn has no asm form
                        inst['db_bytes'] = insn.bytes
        bmnem = mnem.split()[-1]
        pmnem = mnem.split()[0] if ' ' in mnem else ''
        if bmnem in _ASM_NO_MNEM or \
                (bmnem in _ASM_FPU_SINGLE and len(ops) == 1 and
                 ops[0].type == X86_OP_REG) or \
                (bmnem in ('aam', 'aad') and ops) or \
                (pmnem == 'lock' and not (
                    bmnem in _ASM_LOCKABLE and ops and
                    ops[0].type == X86_OP_MEM)) or \
                (pmnem in ('rep', 'repe', 'repz', 'repne', 'repnz') and
                 bmnem not in _ASM_REPABLE) or \
                pmnem == 'notrack' or \
                (bmnem == 'nop' and ops) or \
                (bmnem == 'bswap' and ops and (ops[0].type != X86_OP_REG or
                 not insn.reg_name(ops[0].reg).startswith('e'))) or \
                set(insn.groups) & _ASM_BAD_GROUPS or \
                any(o.type == X86_OP_REG and
                    insn.reg_name(o.reg)[:3] in ('xmm', 'ymm', 'zmm')
                    for o in ops):
            # uasm has no such mnemonic/operand form at any cpu level
            # (misdecoded data, or an ISA extension beyond .686p) --
            # keep the original bytes
            inst['db_bytes'] = insn.bytes
        if enc is not None and enc.imm_size == 2 and ops and \
                ops[-1].type == X86_OP_IMM and insn.bytes:
            ld = 0
            while ld < len(insn.bytes) and insn.bytes[ld] in _PREFIX_BYTES:
                ld += 1
            iv = ops[-1].imm
            iv -= 0x10000 if iv >= 0x8000 else 0
            if ld < len(insn.bytes) and \
                    insn.bytes[ld] in self._IMM16_OPT_OPS and \
                    -128 <= iv <= 127:
                # uasm would shorten this imm16 form to the sign-extended
                # imm8 encoding -- keep the original bytes
                inst['db_bytes'] = insn.bytes
        if iid == X86_INS_XCHG and len(ops) == 2 and \
                all(o.type == X86_OP_REG for o in ops) and \
                insn.opcode and insn.opcode[0] in (0x86, 0x87):
            # capstone prints (r/m, reg) but uasm encodes operand 1 into
            # the modrm reg field -- swap to reproduce the original byte
            if X86_REG_AX in (ops[0].reg, ops[1].reg) or \
                    X86_REG_AL in (ops[0].reg, ops[1].reg):
                # uasm would emit the 90+r accumulator short form
                inst['db_bytes'] = insn.bytes
            else:
                inst['asm_ops'] = (insn.reg_name(ops[1].reg) + ', ' +
                                   insn.reg_name(ops[0].reg))
        # far indirect call/jmp through memory: IDA renders `call dword ptr X`
        if iid in (X86_INS_LCALL, X86_INS_LJMP) and len(ops) == 1 and \
                ops[0].type == X86_OP_MEM:
            inst['mnem'] = 'call' if iid == X86_INS_LCALL else 'jmp'
            mtxt = self._render_mem(inst, insn, 0, ops[0])
            if not mtxt.split()[0].endswith('ptr'):
                mtxt = 'dword ptr ' + mtxt
            atxt = inst.get('asm_ops_map', {}).get(0)
            if atxt:
                if not atxt.split()[0].endswith('ptr'):
                    atxt = 'dword ptr ' + atxt
                inst['asm_ops'] = atxt
            elif ':' not in mtxt and '[' not in mtxt:
                # uasm: bare label needs an explicit segment override
                inst['asm_ops'] = re.sub(r'^dword ptr ', 'dword ptr ds:',
                                         mtxt)
            return mtxt
        # far ptr16:16 call/jmp: two imm operands (seg, off)
        if iid in (X86_INS_LCALL, X86_INS_LJMP) and len(ops) >= 2 and \
                all(o.type == X86_OP_IMM for o in ops[:2]):
            segv, offv = ops[0].imm, ops[1].imm
            target = self.base + segv * 16 + offv
            inst['mnem'] = 'call' if iid == X86_INS_LCALL else 'jmp'
            fv = self.funcs.get(target)
            if fv is not None:
                return f"far ptr {fv['name']}"
            if target in self.names or target in self.auto_names or \
                    target in self.call_refs:
                return f"far ptr {self.label_at(target, 'sub')}"
            # uasm can't encode a numeric-seg far pointer -> raw bytes
            inst['db_bytes'] = insn.bytes
            return f"far ptr {ida_num(segv)}:{ida_num(offv)}"
        if not ops:
            inst['mnem'] = MNEM_MAP.get(mnem, mnem)
            if mnem == 'int1' or \
                    any(p in SEG_PREFIX for p in insn.prefix):
                # uasm rejects `int1`; `int 1` would encode CD 01 not F1.
                # a bare seg override on an operand-less insn (cs:xlatb)
                # is equally unexpressible -- keep the original bytes
                inst['db_bytes'] = insn.bytes
            return ''
        if mnem.split()[-1] in _STRIP_BASES:
            inst['mnem'] = mnem
            base = mnem.split()[-1]
            # a prefix byte can be rep (F0/F2/F3) or a seg override in any
            # position -- a lone `cs:xlat` has only the seg prefix
            repp = next((p for p in insn.prefix
                         if p in (0xF0, 0xF2, 0xF3)), 0)
            segp = next((p for p in insn.prefix if p in SEG_PREFIX), 0)
            if base.endswith('d'):
                # uasm has no movsd/lodsd/... mnemonic at all; the operand
                # form needs `movs dword ptr` + a 66h prefix -- keep the
                # original bytes verbatim instead
                inst['db_bytes'] = insn.bytes
            # uasm only allows repne (F2) on cmps/scas and rep (F3) elsewhere
            elif repp == 0xF2 and base not in ('cmpsb', 'cmpsw',
                                               'scasb', 'scasw'):
                inst['db_bytes'] = insn.bytes
            elif segp in SEG_PREFIX:
                form = _STRSEG_FORMS.get(base)
                if form is None or repp in (0xF0, 0xF2, 0xF3) or \
                        segp == 0x3E:
                    # can't express the override in uasm syntax, or it is
                    # the ds-default source (uasm elides a redundant ds:)
                    inst['db_bytes'] = insn.bytes
                else:
                    inst['asm_ops'] = form.format(seg=SEG_PREFIX[segp])
            return ''
        inst['mnem'] = MNEM_MAP.get(mnem, mnem)
        parts = [self._render_op(inst, insn, i, o) for i, o in enumerate(ops)]
        # shifts/rotates encode count 1 implicitly (capstone omits it, MASM
        # and IDA print it)
        if mnem.split()[-1] in SHIFT_IMPLICIT and len(parts) == 1:
            parts.append('1')
        amap = inst.get('asm_ops_map')
        if amap:
            inst['asm_ops'] = ', '.join(
                amap.get(i, p) for i, p in enumerate(parts))
        if iid == X86_INS_BOUND:
            # uasm rejects an explicit size on bound's memory operand
            # (it reads two words implicitly) -- drop the ptr keyword
            atxt = inst.get('asm_ops') or ', '.join(parts)
            inst['asm_ops'] = re.sub(
                r'(?:dword|qword|fword|word|byte) ptr ', '', atxt)
        if 'db_bytes' not in inst and ops and \
                X86_GRP_FPU in insn.groups and \
                any(o.type == X86_OP_MEM for o in ops):
            atxt = inst.get('asm_ops') or ', '.join(parts)
            if 'ptr' not in atxt and not any(
                    'ptr' in str(v)
                    for v in inst.get('asm_ops_map', {}).values()):
                # an FPU memory operand without a size keyword is
                # ambiguous to uasm (fld [bx] -> A2183)
                inst['db_bytes'] = insn.bytes
        return ', '.join(parts)

    # ---------------------------------------------------------------- main
    def _compute_frame_vars(self):
        """Derive stack variables for bp-frame functions and persist them.

        Declared (IDC) vars keep their names; undeclared accessed offsets get
        auto var_N/arg_N.  A var's size is the largest access touching it, so
        a dword-wide access like `les bx, [bp-4]` makes var_4 cover 4 bytes and
        a later word access at -2 renders as `var_4+2`.
        """
        for f, access in self.bp_use.items():
            finfo = self.funcs.get(f)
            flags = finfo['flags'] if finfo else 0
            declared = self.frame_vars.get(f) or {}
            if not declared and not (flags & 0x10) and f not in self.frames:
                continue  # not a bp frame -> leave [bp-N] numeric
            far = bool(flags & 2)
            args_base = 6 if far else 4
            fv = self.frame_vars.setdefault(f, {})
            szs = self.frame_sz.setdefault(f, {})
            spans = []  # (off, size) covering intervals

            # declared vars: extent reaches the next declared offset when the
            # declarations are adjacent, else the widest observed access
            doffs = sorted(declared)
            for i, off in enumerate(doffs):
                nxt = doffs[i + 1] if i + 1 < len(doffs) else None
                if nxt is not None and nxt - off <= 4:
                    sz = nxt - off
                else:
                    sz = min(4, max(2, access.get(off, 2)))
                szs[off] = sz
                spans.append((off, sz))

            def covered(d, spans=spans):
                return any(o <= d < o + s for o, s in spans)

            # locals (negative disp), most negative first so a dword at -4
            # absorbs a later word access at -2
            for d in sorted(a for a in access if a < 0):
                if covered(d):
                    continue
                sz = min(4, max(1, access[d]))
                fv[d] = f"var_{-d:X}"
                szs[d] = sz
                spans.append((d, sz))
            # arguments, ascending
            for d in sorted(a for a in access if a >= args_base):
                if covered(d):
                    continue
                sz = min(4, max(2, access[d]))
                fv[d] = f"arg_{d - args_base:X}"
                szs[d] = sz
                spans.append((d, sz))
            # saved-regs zone (IDA var_sN): accessed slots covered by frregs
            frregs = self.frames.get(f, (0, 0, 0))[1]
            for d in sorted(a for a in access if 0 <= a < args_base):
                if d >= args_base - frregs and not covered(d):
                    fv[d] = f"var_s{d:X}"
                    szs[d] = min(4, max(2, access[d]))
            for off, nm in fv.items():
                self.db.execute(
                    "INSERT OR REPLACE INTO frame_vars "
                    "(func_start, offset, name, size) VALUES (?, ?, ?, ?)",
                    (f, off, nm, szs.get(off, 2)))

    def analyze(self):
        # Iterate: call targets discovered while scanning become new regions.
        for _pass in range(4):
            regions = self._compute_code_regions()
            new = [r for r in regions if r[0] not in self.covered]
            if _pass == 0:
                logger.info(f"Code regions: {len(regions)}")
            if not new:
                break
            for start, end, fstart in new:
                self._disasm_region(start, end, fstart)
            self._scan_refs()
        logger.info(f"Disassembled {len(self.instructions)} instructions")

        # associate each instruction with its containing function (frame vars)
        franges = sorted(
            (f, fv['end'] if fv['end'] > f else self._estimate_func_end(f))
            for f, fv in self.funcs.items())
        fstarts = [f for f, _ in franges]
        for inst in self.instructions:
            if inst.get('func') is not None:
                pass
            else:
                i = bisect.bisect_right(fstarts, inst['addr']) - 1
                if i >= 0 and inst['addr'] < franges[i][1]:
                    inst['func'] = franges[i][0]
            # collect bp-relative accesses for stack-var inference
            f = inst.get('func')
            if f is not None:
                for op in inst['insn'].operands:
                    if op.type == X86_OP_MEM and op.mem.base == X86_REG_BP:
                        sz = op.size if getattr(op, 'size', 0) else 0
                        # les/lds/lcall/ljmp access seg:ptr (4 bytes) though
                        # capstone reports the destination register size
                        if inst['insn'].id in (X86_INS_LES, X86_INS_LDS,
                                               X86_INS_LCALL, X86_INS_LJMP):
                            sz = 4
                        d = op.mem.disp
                        cur = self.bp_use.setdefault(f, {})
                        cur[d] = max(cur.get(d, 0), sz)
        self._compute_frame_vars()

        # Auto-name call targets and string data referenced by name
        for t in sorted(self.call_refs):
            if t not in self.names and t not in self.funcs:
                self.auto_names[t] = f"sub_{t:X}"
        for t, kinds in sorted(self.data_refs.items()):
            if t in self.names:
                continue
            if t in self.data_items and self.data_items[t][1] == 'str':
                continue  # rendered via str item
            if t in self.relocs:
                self.auto_names[t] = f"seg_{t:X}"
                continue
            size = max(s for s, _ in kinds)
            kind = self._data_kind_for(size)
            self.label_at(t, kind)
        # auto-name string items (a<Name>)
        for a, (sz, k, cnt) in self.data_items.items():
            if k == 'str' and a not in self.names and a not in self.auto_names:
                data = self.db.read_bytes(a, min(sz, 60)) or b''
                nm = sanitize_str_name(data.split(b'\0')[0])
                self.auto_names[a] = self._unique(
                    nm or f"asc_{a:X}", a)

        # render + store instructions -- bulk inserts in one transaction;
        # db.execute() commits per call which turns 100k+ rows into an
        # fsync-per-row bottleneck
        conn = self.db.conn
        rows = []
        for inst in self.instructions:
            inst['op_str'] = self.render(inst)
            dbh = inst.get('db_bytes')
            rows.append(
                (inst['addr'], inst['size'], inst['mnem'], inst['op_str'],
                 inst.get('asm_ops'), dbh.hex() if dbh else None))
        conn.executemany(
            "INSERT OR REPLACE INTO instructions (addr, size, mnem, op_str, asm_str, type, db_bytes) "
            "VALUES (?, ?, ?, ?, ?, 'code', ?)", rows)

        # persist auto labels into symbols (auto=1, explicit wins)
        rows = [
            (a, nm, 'sub' if a in self.funcs else
             'loc' if a in self.code_refs else 'data')
            for a, nm in self.auto_names.items()
            if nm and a not in self.names]
        conn.executemany(
            "INSERT OR IGNORE INTO symbols (addr, name, auto, kind) "
            "VALUES (?, ?, 1, ?)", rows)
        # code refs as loc labels
        rows = [(a, f"loc_{a:X}") for a in self.code_refs
                if a not in self.names and a not in self.auto_names
                and a not in self.funcs]
        conn.executemany(
            "INSERT OR IGNORE INTO symbols (addr, name, auto, kind) "
            "VALUES (?, ?, 1, 'loc')", rows)

        if self.compute_xrefs:
            conn.executemany(
                "INSERT OR IGNORE INTO xrefs (from_addr, to_addr, type, instruction) "
                "VALUES (?, ?, ?, '')", self.xrefs)

        # functions discovered during analysis get written back
        rows = [(f, fv['end'], fv['name']) for f, fv in self.funcs.items()
                if fv.get('auto') and f not in self.names]
        conn.executemany(
            "INSERT OR IGNORE INTO functions (start, end, name, flags) "
            "VALUES (?, ?, ?, 0)", rows)
        conn.commit()

        total_code = sum(i['size'] for i in self.instructions)
        coverage = total_code / max(len(self.binary), 1) * 100
        self.db.execute("INSERT OR REPLACE INTO stats (key, value) VALUES ('code_coverage', ?)",
                        (coverage,))
        logger.info(f"Analysis complete: {len(self.instructions)} insts, "
                    f"{len(self.funcs)} funcs, {coverage:.1f}% coverage")
