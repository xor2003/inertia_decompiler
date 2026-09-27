#!/usr/bin/env python3
"""Layer: validation CLI.

Responsibility: cross-ABI SSA/Z3 function comparison between the reference
masm2c build ``ar_m2c`` (i386 ELF, ``_STATE*`` register model, -O0) and the
clean port ``ar_port`` (amd64 ELF, flat globals model, -O2).

Both sides are lowered from VEX into dosunit's compact ``SsaExpr`` domain
(``tools.dosunit.straightline_ssa`` internals, reused read-only). Each side's
machine-level accesses are normalized into one canonical game-state domain:

* ``eax..ebp``      -> canonical 32-bit game register cells
* ``cs..ss``        -> canonical 16-bit segment cells (``cs``/``eip`` excluded
  from outputs: masm2c rewrites them as bookkeeping on every statement)
* ``CF..TF``        -> canonical 8-bit 0/1 flag cells
* ``data``          -> the shared 1 MiB game memory array (``m2c::m`` image on
  the oracle side, ``mem[]`` on the candidate side)
* ``io``            -> the shared port-I/O byte array
* ``stk``           -> host stack (internal only, never an output)
* ``other``         -> all remaining host memory (internal only)

Calls are handled as summaries on the canonical domain: ``push``/``pop``/
``in``/``out`` have real models; calls to mapped game functions and to runtime
helpers become shared uninterpreted ``call_*`` terms so the caller-side
composition stays comparable. Indirect control flow and dispatch tails are
explicit terminals. A function that cannot terminate all paths inside the
loop-bound/path-cap budget is refused, never silently truncated.

Verdicts reuse ``S._compare_functions`` (Z3) on the canonical output record.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

VEXTEST = Path("/home/xor/vextest")
sys.path.insert(0, str(VEXTEST))

import angr  # noqa: E402
from angr.errors import SimError  # noqa: E402
import pyvex  # noqa: E402
from tools.dosunit import straightline_ssa as S  # noqa: E402
from tools.dosunit.model import DosUnitError  # noqa: E402

# Store/load chains nest linearly with store count; recursive passes over the
# SsaExpr DAG (merge, Z3 conversion) need headroom beyond the default 1000.
sys.setrecursionlimit(100_000)


# ---------------------------------------------------------------------------
# SsaExpr helpers
# ---------------------------------------------------------------------------

def E(op: str, width: int, args: tuple = (), value: int | None = None, name: str | None = None) -> S.SsaExpr:
    return S.SsaExpr(op, width, args, value, name)


def inp(name: str, width: int) -> S.SsaExpr:
    return E("input", width, name=name)


def arr(name: str) -> S.SsaExpr:
    return E("mem_input", 0, name=name)


def c32(v: int) -> S.SsaExpr:
    return E("const", 32, value=v & 0xFFFFFFFF)


def constval(e: S.SsaExpr) -> int | None:
    """Constant value of ``e``, evaluating trivially-const wrappers too."""
    if e.op == "const":
        return e.value
    if e.op in ("trunc", "zext") and e.args[0].op == "const":
        return e.args[0].value & ((1 << e.width) - 1)
    if e.op == "not" and e.args[0].op == "const":
        return (~e.args[0].value) & ((1 << e.width) - 1)
    return None


_FOLD_LEAVES = frozenset(("const", "input", "mem_input", "unsupported"))


def fold(e: S.SsaExpr, _memo: dict[int, S.SsaExpr] | None = None) -> S.SsaExpr:
    """Constant-fold add/sub/mul/logic and flatten additive chains.

    ``_memo`` is an ``id()``-keyed DAG cache; child exprs are referenced by
    their parents for the duration of the top-level call so ids stay stable.
    Iterative post-order so deep storele/loadle chains cannot exhaust the
    Python recursion stack.
    """
    if e.op in _FOLD_LEAVES:
        return e
    memo: dict[int, S.SsaExpr] = {} if _memo is None else _memo
    stack: list[tuple[S.SsaExpr, bool]] = [(e, False)]
    while stack:
        node, expanded = stack.pop()
        if node.op in _FOLD_LEAVES:
            memo.setdefault(id(node), node)
            continue
        if not expanded:
            if id(node) in memo:
                continue
            stack.append((node, True))
            for a in node.args:
                if a.op not in _FOLD_LEAVES and id(a) not in memo:
                    stack.append((a, False))
            continue
        args = tuple(memo.get(id(a), a) for a in node.args)
        cur = node
        if any(a is not b for a, b in zip(args, node.args)):
            cur = E(node.op, node.width, args, node.value, node.name)
        out = _fold_node(cur)
        # Rules may produce nodes that are themselves foldable
        # (e.g. trunc(and) -> and(trunc,trunc) -> and(x,0) -> 0):
        # re-apply to fixpoint, bounded.
        for _ in range(32):
            if out is cur or not out.args:
                break
            nxt = _fold_node(out)
            if nxt is out:
                break
            out = nxt
        memo[id(node)] = out
    return memo[id(e)]


def _same_expr(a: S.SsaExpr, b: S.SsaExpr) -> bool:
    """Bounded structural equality (identity fast path, then expr keys)."""
    if a is b:
        return True
    km: dict[int, tuple] = {}
    budget = [2048]
    return _expr_key(a, km, budget) == _expr_key(b, km, budget)


def _fold_node(e: S.SsaExpr) -> S.SsaExpr:
    vals = [constval(a) for a in e.args]
    if e.op in {"add", "sub", "and", "or", "xor", "mul", "shl", "lshr", "ashr"}:
        if all(v is not None for v in vals):
            m = (1 << e.width) - 1
            a, b = vals[0], vals[1]
            r = {
                "add": a + b, "sub": a - b, "and": a & b, "or": a | b, "xor": a ^ b,
                "mul": a * b, "shl": a << (b & 63), "lshr": a >> (b & 63),
                "ashr": ((a - (1 << e.width)) if (a >> (e.width - 1)) else a) >> (b & 63),
            }[e.op]
            return E("const", e.width, value=r & m)
        if e.op in ("add", "or", "xor") and vals[0] == 0:
            return e.args[1]
        if e.op in ("add", "sub", "or", "xor") and vals[1] == 0:
            return e.args[0]
        if e.op == "and" and (vals[0] == 0 or vals[1] == 0):
            return E("const", e.width, value=0)
        if e.op == "and" and vals[0] == (1 << e.width) - 1:
            return e.args[1]
        if e.op == "and" and vals[1] == (1 << e.width) - 1:
            return e.args[0]
        if e.op == "or" and (vals[0] == (1 << e.width) - 1
                             or vals[1] == (1 << e.width) - 1):
            return E("const", e.width, value=(1 << e.width) - 1)
        if e.op == "mul" and (vals[0] == 0 or vals[1] == 0):
            return E("const", e.width, value=0)
        if e.op in {"and", "or", "xor"} and _same_expr(e.args[0], e.args[1]):
            return e.args[0] if e.op != "xor" else E("const", e.width, value=0)
        if e.op in {"shl", "lshr", "ashr"} and vals[1] == 0:
            return e.args[0]
        if e.op == "lshr" and vals[1] is not None:
            a0 = e.args[0]
            # lshr(zext(x), k): shifts beyond the source width give 0;
            # smaller shifts distribute into the source.
            if a0.op in ("zext", "sext") and vals[1] >= a0.args[0].width:
                return E("const", e.width, value=0)
            if a0.op == "zext" and vals[1] < a0.args[0].width:
                return zext(E("lshr", a0.args[0].width,
                              (a0.args[0], E("const", a0.args[0].width, value=vals[1]))),
                            e.width)
        # x - x == 0, x ^ x == 0 (structural equality, incl. reloaded canaries)
        if e.op in {"sub", "xor"} and _same_expr(e.args[0], e.args[1]):
            return E("const", e.width, value=0)
    if e.op in {"eq", "ne", "ult", "ule", "slt", "sle"} and len(e.args) == 2:
        if _same_expr(e.args[0], e.args[1]):
            return E("const", 1, value=1 if e.op in {"eq", "ule", "sle"} else 0)
    if e.op == "not":
        a = e.args[0]
        if a.op == "const":
            return E("const", e.width, value=(~a.value) & ((1 << e.width) - 1))
        if a.op == "not":
            return a.args[0]
    if e.op in {"zext", "sext"}:
        a = e.args[0]
        if a.op == "const":
            v = a.value
            if e.op == "sext" and (v >> (a.width - 1)):
                v |= ((1 << e.width) - 1) ^ ((1 << a.width) - 1)
            return E("const", e.width, value=v & ((1 << e.width) - 1))
    if e.op == "trunc":
        a = e.args[0]
        if a.op == "const":
            return E("const", e.width, value=a.value & ((1 << e.width) - 1))
        # trunc(concat(hi, lo, ...)) keeps only the low bits: the high
        # concat parts are sliced away.  ``concat(0, x)`` is ``zext(x)``.
        if a.op == "concat":
            parts = list(a.args)
            kept: list[S.SsaExpr] = []
            w = 0
            for p in reversed(parts):
                if w >= e.width:
                    break
                kept.insert(0, p)
                w += p.width
            if w >= e.width:
                low = kept[-1]
                if len(kept) == 1:
                    return trunc(low, e.width) if low.width != e.width else low
                # rebuild concat of kept parts then truncate
                rec = E("concat", w, tuple(kept))
                return trunc(rec, e.width) if rec.width != e.width else rec
        if a.op in ("zext", "sext") and a.args[0].width >= e.width:
            return trunc(a.args[0], e.width)
        # trunc distributes over ops that are exact mod 2^n
        if a.op in ("and", "or", "xor", "add", "sub", "mul") and len(a.args) == 2:
            return E(a.op, e.width,
                     (trunc(a.args[0], e.width), trunc(a.args[1], e.width)))
        if a.op == "not":
            return E("not", e.width, (trunc(a.args[0], e.width),))
    if e.op == "ite":
        c, a, b = e.args
        if c.op == "const":
            return a if c.value else b
        if a is b:
            return a
    if e.op == "concat":
        if all(v is not None for v in vals):
            acc, w = 0, 0
            for a in reversed(e.args):
                acc |= (a.value << w)
                w += a.width
            return E("const", e.width, value=acc & ((1 << e.width) - 1))
        # concat(0,...,0, x) is a zero-extension of the low part
        if len(e.args) >= 2 and all(
                a.op == "const" and a.value == 0 for a in e.args[:-1]):
            low = e.args[-1]
            return low if low.width == e.width else zext(low, e.width)
    return e


def as_add(e: S.SsaExpr, _memo: dict[int, tuple[S.SsaExpr, int]] | None = None
           ) -> tuple[S.SsaExpr, int]:
    """Normalize ``e`` to ``base + const`` where possible (id-keyed DAG memo).

    Iterative post-order: add-chains nested to depth N must not consume N
    Python stack frames.
    """
    e = fold(e)
    if e.op == "const":
        return E("const", 32, value=0), e.value
    memo: dict[int, tuple[S.SsaExpr, int]] = {} if _memo is None else _memo
    stack: list[tuple[S.SsaExpr, bool]] = [(e, False)]
    while stack:
        node, expanded = stack.pop()
        if not expanded:
            if id(node) in memo:
                continue
            stack.append((node, True))
            descend = node.op == "add" or (
                node.op == "sub" and node.args[1].op == "const")
            if descend:
                for a in node.args:
                    if id(a) not in memo:
                        stack.append((a, False))
            continue
        out: tuple[S.SsaExpr, int] | None = None
        if node.op == "add":
            a, k1 = memo[id(node.args[0])]
            b, k2 = memo[id(node.args[1])]
            if b.op == "const" and b.value == 0:
                out = a, (k1 + k2) & 0xFFFFFFFF
            elif a.op == "const" and a.value == 0:
                out = b, (k1 + k2) & 0xFFFFFFFF
            else:
                out = E("add", node.width, (a, b)), (k1 + k2) & 0xFFFFFFFF
        elif node.op == "sub" and node.args[1].op == "const":
            a, k = memo[id(node.args[0])]
            out = a, (k - node.args[1].value) & 0xFFFFFFFF
        if out is None:
            out = ((_c(0, 32), node.value & 0xFFFFFFFF)
                   if node.op == "const" else (node, 0))
        memo[id(node)] = out
    return memo[id(e)]


def zext(e: S.SsaExpr, w: int) -> S.SsaExpr:
    if e.width == w:
        return e
    if e.op == "const":
        return E("const", w, value=e.value & ((1 << e.width) - 1))
    return E("zext", w, (e,))


def trunc(e: S.SsaExpr, w: int) -> S.SsaExpr:
    if e.width == w:
        return e
    if e.op == "const":
        return E("const", w, value=e.value & ((1 << w) - 1))
    return E("trunc", w, (e,))


def neq0(e: S.SsaExpr) -> S.SsaExpr:
    return E("ite", 8, (E("ne", 1, (e, E("const", e.width, value=0))),
                        E("const", 8, value=1), E("const", 8, value=0)))


# ---------------------------------------------------------------------------
# Canonical domain
# ---------------------------------------------------------------------------

CANON_REGS32 = ("eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp")
CANON_SEGS = ("ds", "es", "ss", "fs", "gs")
CANON_FLAGS = ("cf", "pf", "af", "zf", "sf", "df", "of", "if_", "tf")
CANON_OUTPUTS = (
    [f"g_{r}" for r in CANON_REGS32]
    + [f"s_{s}" for s in CANON_SEGS]
    + [f"f_{f}" for f in CANON_FLAGS]
    + ["data", "io"]
)
# cs/eip/kloc bookkeeping cells are tracked internally but never compared.
CANON_INTERNAL = ("cs", "eip")

STATE_BASE = 0x400000  # synthetic base for the m2c _STATE image
DATA_SYN = 0x40000000  # synthetic base for canonical data-space pointers
FRAME_BIAS = 0x100000  # stk-array key bias for frame-pointer (ebp) slots

# m2c _STATE field map: offset -> (canonical cell, cell width, field width)
M2C_STATE_FIELDS: dict[int, tuple[str, int]] = {
    0: ("eax", 32), 4: ("ebx", 32), 8: ("ecx", 32), 12: ("edx", 32),
    16: ("esi", 32), 20: ("edi", 32), 24: ("esp", 32), 28: ("ebp", 32),
    32: ("eip", 32),
    36: ("cs", 16), 38: ("ds", 16), 40: ("es", 16), 42: ("fs", 16),
    44: ("gs", 16), 46: ("ss", 16),
    48: ("cf", 8), 49: ("pf", 8), 50: ("af", 8), 51: ("zf", 8), 52: ("sf", 8),
    53: ("df", 8), 54: ("of", 8), 55: ("if_", 8), 56: ("tf", 8),
}


@dataclass
class SideConfig:
    """Per-binary normalization parameters."""

    name: str
    arch: str  # 'i386' | 'amd64'
    project: Any
    symbols: dict[str, tuple[int, int]]          # name -> (addr, end)
    addr2name: dict[int, str]
    m2c: bool
    data_base: int                              # host addr of game byte 0
    data_size: int
    reg_globals: dict[int, str] = field(default_factory=dict)   # port: addr -> canon reg
    seg_globals: dict[int, str] = field(default_factory=dict)
    flag_globals: dict[int, str] = field(default_factory=dict)
    refmap: dict[int, int] = field(default_factory=dict)        # m2c: ref storage addr -> data offset
    ksub_map: dict[int, str] = field(default_factory=dict)      # m2c: ksub_* token -> proc name
    src_lines: dict[str, int] = field(default_factory=dict)     # proc name -> label line in generated src
    dwarf_addr2line: Any = None                                 # callable addr -> (path, line)|None
    dispatch_addrs: frozenset[int] = frozenset()
    label_addr: dict[str, int] = field(default_factory=dict)    # internal proc name -> machine addr
    proc_syms: dict[str, int] = field(default_factory=dict)     # canonical proc name -> addr
    text_lo: int = 0
    text_hi: int = 0
    img_addr: int = 0            # port: host addr of the embedded guest image
    img_size: int = 0

    def classify_const(self, c: int) -> tuple[str, int] | None:
        """Classify a constant host address -> (space, key/offset)."""
        if self.m2c:
            off = c - STATE_BASE
            if 0 <= off < 64 and off in M2C_STATE_FIELDS:
                return ("state", off)
            if DATA_SYN <= c < DATA_SYN + self.data_size:
                return ("data", c - DATA_SYN)
        else:
            if c in self.reg_globals:
                return ("reg", c)
            if c in self.seg_globals:
                return ("seg", c)
            if c in self.flag_globals:
                return ("flag", c)
        if self.data_base <= c < self.data_base + self.data_size:
            return ("data", c - self.data_base)
        return ("other", c)


class LowerCtx:
    """Mutable canonical SSA state shared by the load/store routing hooks."""

    def __init__(self, cfg: SideConfig):
        self.cfg = cfg
        self.canon: dict[str, S.SsaExpr] = {
            r: inp(f"g_{r}", 32) for r in CANON_REGS32
        }
        for s in CANON_SEGS + ("cs",):
            self.canon[s] = inp(f"s_{s}", 16)
        # cs is fixed by the loader (load segment 0x1a2); binding it makes
        # `(cs<<16)|eip` dispatch tokens concrete after RETN_ pops eip.
        self.canon["cs"] = E("const", 16, value=0x1A2)
        for f in CANON_FLAGS:
            self.canon[f] = inp(f"f_{f}", 8)
        self.canon["eip"] = inp("s_eip", 32)
        self.arrays: dict[str, S.SsaExpr] = {
            "data": arr("data"), "io": arr("io"),
            "stk": arr("stk"), "other": arr("other"),
        }
        self.reg_versions: dict[str, S.SsaExpr] = {
            name: inp(name, width)
            for _off, (name, width) in REGMAP[cfg.arch].items()
        }
        self.temps: dict[int, S.SsaExpr] = {}
        self.temp_failures: dict[int, Any] = {}
        self.exits: list[tuple[S.SsaExpr, S.SsaExpr]] = []
        self.cur_stk: dict[int, S.SsaExpr] = {}         # stack writes in current block
        self.unmapped: list[str] = []
        self.error: Optional[S.LowerFailure] = None
        self.is_stack_base = "esp" if cfg.arch == "i386" else "rsp"
        self.is_frame_base = "ebp" if cfg.arch == "i386" else "rbp"
        self._hostunk: dict[int, str] = {}
        self.call_target: S.SsaExpr | None = None
        self.next_expr: S.SsaExpr | None = None
        self.inline_depth = 0
        self.last_disp: S.SsaExpr | None = None   # last stk-space store (`__disp =` token)
        # True once this path executed a guest RETN_/RETF_ pop — a following
        # unresolved `__dispatch_call` is then a return to an unknown caller.
        self.retn_popped = False
        self.bind_args = cfg.m2c
        # The trampoline's first dispatch routes INTO this function — it is
        # the entry, not a call, and must not hit the boundary-call model.
        self.disp_seen = False
        self.probe_stk: list[int] | None = None   # when set, record stk load keys

    # -- esp/arg helpers -----------------------------------------------------

    def _espish(self, e: S.SsaExpr) -> int | None:
        """Return const offset when ``e`` is ``esp_input + k``."""
        b, k = as_add(e)
        if b.op == "input" and b.name == self.is_stack_base:
            return k
        return None

    def _stkish(self, e: S.SsaExpr) -> int | None:
        """Return const offset when ``e`` is host stack-pointer/frame based.

        Frame-pointer (ebp) slots are biased so esp- and ebp-derived offsets
        never alias in the shared ``stk`` array.
        """
        b, k = as_add(e)
        if b.op == "input":
            if b.name == self.is_stack_base:
                return k
            if b.name == self.is_frame_base:
                return (k + FRAME_BIAS) & 0xFFFFFFFF
        return None

    def _arg_bind(self, e: S.SsaExpr) -> S.SsaExpr | None:
        """m2c: bind incoming stack args (arg1=_i=0, arg2=_state=STATE_BASE)."""
        if not self.bind_args:
            return None
        b, k = as_add(e)
        if b.op != "input":
            return None
        off = {self.is_stack_base: {8: STATE_BASE, 4: 0},
               self.is_frame_base: {0xC: STATE_BASE, 8: 0}}.get(b.name, {}).get(k)
        return c32(off) if off is not None else None

    # -- address classification ---------------------------------------------

    def _concretize(self, e: S.SsaExpr, depth: int = 0) -> S.SsaExpr:
        """Forward ``loadle`` subterms through their embedded store chains.

        Resolves spilled/reloaded pointers (e.g. ``*(*(ebp-slot)+k)``) to their
        stored constants so the surrounding address can be classified. Bounded
        depth; opaque loads are left untouched.
        """
        if depth > 5 or not e.args:
            return e
        if e.op in ("loadle", "loadbe") and len(e.args) >= 2:
            # Only the index is concretized — args[0] is the memory chain
            # itself and must be preserved verbatim.
            idx = self._concretize(e.args[1], depth + 1)
            hit = forward_load(e.args[0], fold(idx), e.width)
            if hit is not None:
                return self._concretize(hit, depth + 1)
            return E(e.op, e.width, (e.args[0], idx)) if idx is not e.args[1] else e
        args = tuple(self._concretize(a, depth + 1) for a in e.args)
        if any(a is not b for a, b in zip(args, e.args)):
            return E(e.op, e.width, args, value=e.value, name=e.name)
        return e

    def classify_addr(self, addr: S.SsaExpr) -> tuple[str, S.SsaExpr]:
        """Return (space, index-term). Spaces: data/state/reg/seg/flag/stk/other."""
        a = fold(addr)
        space, idx = self._classify(a)
        if space != "other":
            return space, idx
        # retry after forwarding spilled/reloaded pointers to constants
        a2 = fold(self._concretize(a))
        if a2 is not a:
            space, idx = self._classify(a2)
        return space, idx

    def _classify(self, a: S.SsaExpr) -> tuple[str, S.SsaExpr]:
        off = self._stkish(a)
        if off is not None:
            return ("stk", c32(off))
        if a.op == "const":
            space, key = self.cfg.classify_const(a.value)
            return (space, c32(key))
        base, k = as_add(a)
        if base.op == "const":
            space, key = self.cfg.classify_const(base.value)
            if space == "state":
                key += k
                if key not in M2C_STATE_FIELDS:
                    return ("other", trunc(zext(a, 32) if a.width < 32 else a, 32))
            return (space, c32(key))
        # expr + const where the const is a known base (e.g. amd64 `add64(mem_base, zext(off))`)
        if k:
            space, key = self.cfg.classify_const(k)
            if space == "data":
                return ("data", trunc(zext(base, 32) if base.width < 32 else base, 32) if key == 0
                        else E("add", 32, (c32(key), trunc(zext(base, 32) if base.width < 32 else base, 32))))
            if space == "state":
                return ("other", trunc(zext(a, 32) if a.width < 32 else a, 32))
        return ("other", trunc(zext(a, 32) if a.width < 32 else a, 32))

    # -- canonical register cell access --------------------------------------

    def canon_read(self, name: str, width: int, byteoff: int) -> S.SsaExpr:
        cell = self.canon[name]
        v = cell
        if byteoff:
            v = trunc(E("lshr", cell.width, (cell, E("const", cell.width, value=byteoff * 8))), cell.width - byteoff * 8)
        return trunc(v, width) if v.width != width else v

    def canon_write(self, name: str, width: int, byteoff: int, v: S.SsaExpr) -> None:
        cell = self.canon[name]
        if name in CANON_FLAGS:
            self.canon[name] = neq0(v)
            return
        if name == "eip":
            self.canon[name] = zext(v, 32) if v.width < 32 else v
            return
        if byteoff == 0 and width == cell.width:
            self.canon[name] = v
            return
        mask = ((1 << cell.width) - 1) ^ (((1 << width) - 1) << (byteoff * 8))
        keep = E("and", cell.width, (cell, E("const", cell.width, value=mask & ((1 << cell.width) - 1))))
        ins = zext(v, cell.width)
        if byteoff:
            ins = E("shl", cell.width, (ins, E("const", cell.width, value=byteoff * 8)))
        self.canon[name] = E("or", cell.width, (keep, ins))

    def flag_canon(self, addr_const: int) -> str:
        return self.cfg.flag_globals[addr_const]

    # -- routed load/store ----------------------------------------------------

    def load(self, memory: S.SsaExpr, addr: S.SsaExpr, width: int) -> S.SsaExpr:
        bound = self._arg_bind(addr)
        if bound is not None:
            return trunc(bound, width) if width < 32 else bound
        space, idx = self.classify_addr(addr)
        if space == "other" and idx.op == "const" and idx.value in self.cfg.refmap:
            # m2c db&/dw& reference object: value is a canonical data pointer.
            v = c32(DATA_SYN + self.cfg.refmap[idx.value])
            return trunc(v, width) if width < 32 else v
        if space == "state":
            if idx.value not in M2C_STATE_FIELDS:
                return E("loadle", width, (self.arrays["other"], idx))
            name, fw = M2C_STATE_FIELDS[idx.value]
            return self.canon_read(name, width, idx.value - _state_field_off(idx.value))
        if space == "reg":
            c = idx.value
            name = self.cfg.reg_globals[c & ~3]
            return self.canon_read(name, width, c & 3)
        if space == "seg":
            name = self.cfg.seg_globals[idx.value]
            return self.canon_read(name, width, 0)
        if space == "flag":
            name = self.cfg.flag_globals[idx.value]
            return zext(self.canon_read(name, 8, 0), width)
        if self.probe_stk is not None and space == "stk":
            k = constval(fold(idx))
            self.probe_stk.append(k if k is not None else -1)
        version = self.arrays[space]
        idx = trunc(zext(idx, 32) if idx.width < 32 else idx, 32)
        hit = forward_load(version, idx, width)
        if hit is not None:
            # A residual load rooted at the space's input is a forwarding
            # miss: for const host addresses outside the canonical spaces the
            # bytes live in the image — resolve them so PIC jump tables
            # (`jmp *(got + idx*4)`) fold to concrete targets.
            if (space == "other" and idx.op == "const"
                    and hit.op == "loadle" and len(hit.args) == 2
                    and hit.args[0].op == "mem_input"):
                try:
                    raw = bytes(self.cfg.project.loader.memory.load(
                        idx.value, width // 8))
                except KeyError:
                    raw = b""
                if len(raw) == width // 8:
                    return E("const", width, value=int.from_bytes(raw, "little"))
            return hit
        if space in ("stk", "other"):
            # Host-ABI memory: canonicalize unresolvable loads to the space's
            # root input so equal addresses compare equal across chains (e.g.
            # the gs:0x14 canary reload vs its stored entry value).
            return E("loadle", width, (arr(space), idx))
        return E("loadle", width, (version, idx))

    def store(self, memory: S.SsaExpr, addr: S.SsaExpr, data: S.SsaExpr) -> None:
        space, idx = self.classify_addr(addr)
        if space == "other" and idx.op == "const" and idx.value in self.cfg.refmap:
            space, idx = "other", idx  # stores through ref objects are unsupported
        if space == "state":
            if idx.value not in M2C_STATE_FIELDS:
                self.arrays["other"] = E("storele", 0, (self.arrays["other"], idx, data))
                return
            name, fw = M2C_STATE_FIELDS[idx.value]
            self.canon_write(name, data.width, idx.value - _state_field_off(idx.value), data)
            return
        if space == "reg":
            c = idx.value
            name = self.cfg.reg_globals[c & ~3]
            self.canon_write(name, data.width, c & 3, data)
            return
        if space == "seg":
            self.canon_write(self.cfg.seg_globals[idx.value], data.width, 0, data)
            return
        if space == "flag":
            self.canon_write(self.cfg.flag_globals[idx.value], 8, 0, data)
            return
        if space == "stk":
            # `__disp = <token>` writes are the only stores whose value is a
            # dispatch token const — recording them tracks the dispatch
            # variable even when the store chain can't forward later loads
            # (symbolic-alias gaps in the host frame).
            dv = constval(fold(data))
            if (dv is not None and self.cfg.ksub_map
                    and dv in self.cfg.ksub_map):
                self.last_disp = fold(data)
        self.arrays[space] = E("storele", 0,
                               (self.arrays[space], trunc(zext(idx, 32) if idx.width < 32 else idx, 32), data))


_KEY_CACHE: dict[int, tuple[tuple, S.SsaExpr]] = {}


def _expr_key(e: S.SsaExpr, memo: dict[int, tuple], budget: list[int]) -> tuple:
    """Structural key with a persistent id-keyed DAG cache.

    ``_KEY_CACHE`` maps ``id(node) -> (key, node)`` holding a strong ref so
    ids cannot be recycled while cached — cached keys stay sound.  ``budget``
    caps nodes visited per top-level call; once exhausted the key degenerates
    to a per-node unique token (equal exprs keep equal keys by identity,
    distinct deep exprs never falsely collide).
    """
    ghit = _KEY_CACHE.get(id(e))
    if ghit is not None and ghit[1] is e:
        return ghit[0]
    hit = memo.get(id(e))
    if hit is not None:
        _KEY_CACHE[id(e)] = (hit, e)
        return hit
    if budget[0] <= 0:
        k = (e.op, e.width, "__deep__", id(e))
        memo[id(e)] = k
        _KEY_CACHE[id(e)] = (k, e)
        return k
    budget[0] -= 1
    k = (e.op, e.width, e.value, e.name,
         tuple(_expr_key(a, memo, budget) for a in e.args))
    memo[id(e)] = k
    _KEY_CACHE[id(e)] = (k, e)
    return k


def forward_load(chain: S.SsaExpr, addr: S.SsaExpr, width: int, depth: int = 0) -> S.SsaExpr | None:
    """Store-to-load forwarding over a same-space storele chain.

    Returns the stored value when the target store is provably the last write
    to ``addr`` (syntactic equality) and no overlapping store intervenes;
    ``None`` when opaque. Only equal-start, >=width forwards are resolved.
    """
    kmemo: dict[int, tuple] = {}
    budget = [4096]
    akey = _expr_key(addr, kmemo, budget)
    node = chain
    seen = 0
    while node.op in ("storele", "storebe") and seen < 400:
        seen += 1
        _prev, a, v = node.args
        if _expr_key(a, kmemo, budget) == akey:
            if v.width == width:
                return v
            if v.width > width:
                return trunc(v, width)
            return None
        ac, bc = constval(a), constval(addr)
        if (ac is not None and bc is not None
                and (bc * 8 + width <= ac * 8 or ac * 8 + v.width <= bc * 8)):
            node = _prev
            continue
        # a is symbolic or partially overlapping: unknown alias -> opaque
        return None
    # Chain exhausted: the load observes the residual (root) chain.  Returning
    # it canonicalizes repeated loads of the same address — e.g. a stored
    # stack canary vs its reload — to structurally equal terms.
    return E("loadle", width, (node, addr))


def _idx(base: S.SsaExpr, k: int, key: int) -> S.SsaExpr:
    return E("add", 32, (c32(key), c32(k)))


def _state_field_off(off: int) -> int:
    """Largest field start <= off in the m2c _STATE map."""
    best = 0
    for o in M2C_STATE_FIELDS:
        if o <= off:
            best = o
    return best


# ---------------------------------------------------------------------------
# dosunit lowering hooks (patched at runtime, scoped per side)
# ---------------------------------------------------------------------------

REGMAP: dict[str, dict[int, tuple[str, int]]] = {}
IP_OFF: dict[str, int] = {}
_ORIG: dict[str, Any] = {}
CTX: LowerCtx | None = None
SPLITS: Counter = Counter()
DBG_ADDR: int | None = None


def _build_regmap() -> None:
    import archinfo

    a32 = archinfo.ArchX86()
    names32 = tuple(n for n in (
        "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
        "cc_op", "cc_dep1", "cc_dep2", "cc_ndep", "d", "eip",
        "cs", "ds", "es", "fs", "gs", "ss",
    ) if n in a32.registers)
    REGMAP["i386"] = {a32.registers[n][0]: (n, a32.registers[n][1] * 8) for n in names32}
    IP_OFF["i386"] = a32.registers["eip"][0]
    a64 = archinfo.ArchAMD64()
    names64 = tuple(n for n in (
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip",
        "cc_op", "cc_dep1", "cc_dep2", "cc_ndep", "d", "id", "ac",
        "fs", "gs", "ss",
    ) if n in a64.registers)
    REGMAP["amd64"] = {a64.registers[n][0]: (n, a64.registers[n][1] * 8) for n in names64}
    IP_OFF["amd64"] = a64.registers["rip"][0]


def _reg_access(offset: int, width: int | None, arch: str) -> tuple[str, int, int] | None:
    regmap = REGMAP[arch]
    for base, (name, bits) in regmap.items():
        if offset == base and (width is None or width == bits):
            return name, bits, 0
        if offset == base and width is not None and width < bits:
            return name, bits, 0
    if arch == "i386":
        for base, (name, bits) in regmap.items():
            if name in ("eax", "ecx", "edx", "ebx") and offset == base + 1 and width in (None, 8):
                return name, bits, 8
    return None


def hooked_read_register(versions, offset, width, *, source):
    access = _reg_access(offset, width, CTX.cfg.arch)
    if access is None:
        # tolerate unknown guest offsets as opaque host cells (fp/sse etc.)
        name = f"hostunk_{offset:x}"
        if offset not in CTX._hostunk:
            CTX._hostunk[offset] = name
            versions.setdefault(name, inp(name, width or 32))
        v = versions.get(name, inp(name, width or 32))
        return v if v.width == (width or v.width) else trunc(v, width or v.width)
    name, bits, shift = access
    value = versions.get(name, inp(name, bits))
    if shift:
        value = E("lshr", bits, (value, E("const", bits, value=shift)))
    return S._coerce_width(value, width)


def hooked_write_register(versions, offset, value):
    access = _reg_access(offset, value.width, CTX.cfg.arch)
    if access is None:
        name = f"hostunk_{offset:x}"
        CTX._hostunk[offset] = name
        versions[name] = value
        return None
    name, bits, shift = access
    if value.width == bits:
        versions[name] = value
        return None
    prev = versions.get(name, inp(name, bits))
    mask = ((1 << bits) - 1) ^ (((1 << value.width) - 1) << shift)
    kept = E("and", bits, (prev, E("const", bits, value=mask)))
    ins = S._coerce_width(value, bits)
    if shift:
        ins = E("shl", bits, (ins, E("const", bits, value=shift)))
    versions[name] = E("or", bits, (kept, ins))
    return None


def hooked_write_target(offset, width):
    access = _reg_access(offset, width, CTX.cfg.arch)
    return None if access is None else (access[0], access[1])


def hooked_load(expr, *, temp_defs, temp_failures, reg_versions, tyenv, memory):
    addr = S._lower_expr(expr.addr, temp_defs=temp_defs, temp_failures=temp_failures,
                         reg_versions=reg_versions, tyenv=tyenv, memory=memory)
    if isinstance(addr, S.LowerFailure):
        return addr
    endness = str(getattr(expr, "endness", "Iend_LE"))
    if endness != "Iend_LE":
        return S.LowerFailure("unsupported_ir", f"unsupported load endness {endness}")
    return CTX.load(memory, addr, int(expr.result_size(tyenv)))


def hooked_store(statement, state, *, tyenv):
    addr = S._lower_expr(statement.addr, temp_defs=state.temp_defs,
                         temp_failures=state.temp_failures,
                         reg_versions=state.reg_versions, tyenv=tyenv, memory=state.mem_version)
    if isinstance(addr, S.LowerFailure):
        return addr
    data = S._lower_expr(statement.data, temp_defs=state.temp_defs,
                         temp_failures=state.temp_failures,
                         reg_versions=state.reg_versions, tyenv=tyenv, memory=state.mem_version)
    if isinstance(data, S.LowerFailure):
        return data
    if str(getattr(statement, "endness", "Iend_LE")) != "Iend_LE":
        return S.LowerFailure("unsupported_ir", "unsupported store endness")
    CTX.store(state.mem_version, addr, data)
    # host-stack stores are also candidate call-arg writes for this block
    off = CTX._espish(fold(addr))
    if off is not None:
        CTX.cur_stk[off] = data
    state.memory_touched = True
    return None


# cc_op tables: VEX guests number ops as COPY=0 then groups per width.
# x86 widths B/W/L; amd64 widths B/W/L/Q.
_CC_X86_KIND = ("", "ADD", "ADD", "ADD", "SUB", "SUB", "SUB",
                "ADC", "ADC", "ADC", "SBB", "SBB", "SBB",
                "LOGIC", "LOGIC", "LOGIC", "INC", "INC", "INC",
                "DEC", "DEC", "DEC", "SHL", "SHL", "SHL",
                "SHR", "SHR", "SHR", "ROL", "ROL", "ROL",
                "ROR", "ROR", "ROR", "UMUL", "UMUL", "UMUL",
                "SMUL", "SMUL", "SMUL")
_CC_X86_W = (0,) + tuple(w for _ in range(13) for w in (8, 16, 32))
_CC_AMD64_KIND = ("", "ADD", "ADD", "ADD", "ADD", "SUB", "SUB", "SUB", "SUB",
                  "ADC", "ADC", "ADC", "ADC", "SBB", "SBB", "SBB", "SBB",
                  "LOGIC", "LOGIC", "LOGIC", "LOGIC", "INC", "INC", "INC", "INC",
                  "DEC", "DEC", "DEC", "DEC", "SHL", "SHL", "SHL", "SHL",
                  "SHR", "SHR", "SHR", "SHR", "ROL", "ROL", "ROL", "ROL",
                  "ROR", "ROR", "ROR", "ROR", "UMUL", "UMUL", "UMUL", "UMUL",
                  "SMUL", "SMUL", "SMUL", "SMUL")
_CC_AMD64_W = (0,) + tuple(w for _ in range(13) for w in (8, 16, 32, 64))


def _bit(e: S.SsaExpr, n: int) -> S.SsaExpr:
    """1-bit term: bit n of ``e``."""
    return E("ne", 1, (E("and", e.width, (E("lshr", e.width, (e, E("const", e.width, value=n))),
                                        E("const", e.width, value=1))),
                       E("const", e.width, value=0)))


def _pf(res: S.SsaExpr) -> S.SsaExpr:
    """Even-parity flag of the low byte of ``res``."""
    x = trunc(res, 8)
    x = E("xor", 8, (x, E("lshr", 8, (x, E("const", 8, value=4)))))
    x = E("xor", 8, (x, E("lshr", 8, (x, E("const", 8, value=2)))))
    x = E("xor", 8, (x, E("lshr", 8, (x, E("const", 8, value=1)))))
    return E("eq", 1, (E("and", 8, (x, E("const", 8, value=1))), E("const", 8, value=0)))


def _cc_flags(kind: str, width: int, dep1: S.SsaExpr, dep2: S.SsaExpr,
              ndep: S.SsaExpr) -> dict[str, S.SsaExpr] | None:
    """Compute the EFLAGS bits for a VEX lazy-flag op as 1-bit SsaExpr terms."""
    d1 = trunc(dep1, width)
    d2 = trunc(dep2, width)
    c32z = E("const", width, value=0)
    sign = width - 1
    zf_of = lambda r: E("eq", 1, (r, c32z))
    sf_of = lambda r: E("slt", 1, (r, c32z))
    if kind == "LOGIC":
        r = d1
        return {"cf": E("const", 1, value=0), "of": E("const", 1, value=0),
                "af": E("const", 1, value=0), "zf": zf_of(r),
                "sf": sf_of(r), "pf": _pf(r), "res": r}
    if kind in ("ADD", "ADC"):
        cin = zext(ndep, width) if kind == "ADC" else c32z
        r = E("add", width, (E("add", width, (d1, d2)), cin))
        cf = E("ult", 1, (r, d1)) if kind == "ADD" else E("or", 1, (
            E("ult", 1, (r, d1)), E("eq", 1, (r, d1))))
        # actually for ADC: cf = a+b+c overflowed = ule(r, a) when cin... use wide-free form:
        if kind == "ADC":
            cf = E("or", 1, (E("ult", 1, (E("add", width, (d1, d2)), d1)),
                             E("and", 1, (E("eq", 1, (E("add", width, (d1, d2)),
                                                     E("const", width, value=(1 << width) - 1))),
                                          E("ne", 1, (cin, c32z))))))
        t = E("xor", width, (d1, r))
        u = E("xor", width, (d1, d2))
        of = sf_of(E("and", width, (t, E("not", width, (u,)))))
        af = _bit(E("xor", width, (E("xor", width, (d1, d2)), r)), 4)
        return {"cf": cf, "of": of, "af": af, "zf": zf_of(r), "sf": sf_of(r),
                "pf": _pf(r), "res": r}
    if kind in ("SUB", "SBB"):
        cin = zext(ndep, width) if kind == "SBB" else c32z
        r = E("sub", width, (E("sub", width, (d1, d2)), cin))
        if kind == "SUB":
            cf = E("ult", 1, (d1, d2))
        else:
            cf = E("or", 1, (E("ult", 1, (d1, d2)),
                             E("and", 1, (E("eq", 1, (d1, d2)),
                                          E("ne", 1, (cin, c32z))))))
        of = sf_of(E("and", width, (E("xor", width, (d1, d2)),
                                    E("xor", width, (d1, r)))))
        af = _bit(E("xor", width, (E("xor", width, (d1, d2)), r)), 4)
        return {"cf": cf, "of": of, "af": af, "zf": zf_of(r), "sf": sf_of(r),
                "pf": _pf(r), "res": r}
    if kind == "INC":
        r = E("add", width, (d1, E("const", width, value=1)))
        of = E("eq", 1, (r, E("const", width, value=1 << sign)))
        af = _bit(E("xor", width, (d1, r)), 4)
        cf = trunc(ndep, 1) if ndep.width >= 1 else E("const", 1, value=0)
        cf = _bit(ndep, 0)
        return {"cf": cf, "of": of, "af": af, "zf": zf_of(r), "sf": sf_of(r),
                "pf": _pf(r), "res": r}
    if kind == "DEC":
        r = E("sub", width, (d1, E("const", width, value=1)))
        of = E("eq", 1, (r, E("const", width, value=(1 << sign) - 1)))
        af = _bit(E("xor", width, (d1, r)), 4)
        cf = _bit(ndep, 0)
        return {"cf": cf, "of": of, "af": af, "zf": zf_of(r), "sf": sf_of(r),
                "pf": _pf(r), "res": r}
    if kind == "SHL":
        # dep1 = value, dep2 = count (masked); cf = last bit shifted out.
        cnt = trunc(d2, 8)
        r = E("shl", width, (d1, zext(cnt, width)))
        # cf: bit (width - cnt) of d1 — only when 0 < cnt <= width; else keep 0
        sh = E("sub", width, (E("const", width, value=width), zext(cnt, width)))
        bitv = E("and", width, (E("lshr", width, (d1, sh)), E("const", width, value=1)))
        cf = E("and", 1, (E("ne", 1, (zext(cnt, width), c32z)),
                          E("ne", 1, (bitv, c32z))))
        of = E("xor", 1, (_bit(r, sign), cf))
        return {"cf": cf, "of": of, "af": E("const", 1, value=0),
                "zf": zf_of(r), "sf": sf_of(r), "pf": _pf(r), "res": r}
    if kind == "SHR":
        cnt = trunc(d2, 8)
        r = E("lshr", width, (d1, zext(cnt, width)))
        sh = E("sub", width, (zext(cnt, width), E("const", width, value=1)))
        bitv = E("and", width, (E("lshr", width, (d1, sh)), E("const", width, value=1)))
        cf = E("and", 1, (E("ne", 1, (zext(cnt, width), c32z)),
                          E("ne", 1, (bitv, c32z))))
        of = _bit(d1, sign)
        return {"cf": cf, "of": of, "af": E("const", 1, value=0),
                "zf": zf_of(r), "sf": sf_of(r), "pf": _pf(r), "res": r}
    return None


def _cc_condition(cond: int, f: dict[str, S.SsaExpr]) -> S.SsaExpr | None:
    """Evaluate an x86 condition code against computed 1-bit flags."""
    cf, of, zf, sf, pf = f["cf"], f["of"], f["zf"], f["sf"], f["pf"]
    one = E("const", 1, value=1)
    table = {
        0: of, 1: E("xor", 1, (of, one)), 2: cf, 3: E("xor", 1, (cf, one)),
        4: zf, 5: E("xor", 1, (zf, one)),
        6: E("or", 1, (cf, zf)), 7: E("not", 1, (E("or", 1, (cf, zf)),)),
        8: sf, 9: E("xor", 1, (sf, one)), 10: pf, 11: E("xor", 1, (pf, one)),
        12: E("xor", 1, (sf, of)), 13: E("eq", 1, (sf, of)),
        14: E("or", 1, (zf, E("xor", 1, (sf, of)))),
        15: E("and", 1, (E("xor", 1, (zf, one)), E("eq", 1, (sf, of)))),
    }
    return table.get(cond)


def _lower_ccall(expr, kwargs) -> S.SsaExpr | Any:
    """Give real semantics to the x86/amd64 lazy-flag helper CCalls."""
    name = expr.cee.name
    known = {"x86g_calculate_condition", "x86g_calculate_eflags_c",
             "x86g_calculate_eflags_all", "x86g_use_seg_selector",
             "x86g_load_seg",
             "amd64g_calculate_condition", "amd64g_calculate_eflags_c",
             "amd64g_calculate_eflags_all", "amd64g_calculate_rflags_all"}
    if name not in known:
        return None
    args = []
    for a in expr.args:
        la = hooked_expr(a, **kwargs)
        if isinstance(la, S.LowerFailure):
            return la
        args.append(fold(la))
    retw = int(expr.result_size(kwargs["tyenv"]))
    if name == "x86g_use_seg_selector":
        # (ldt, gdt, seg_selector, virtual_addr) -> 64-bit fat pointer.
        # VEX convention: [63:32] nonzero => raise SigSEGV side exit;
        # [31:0] = linear address.  For flat host-model usage (TLS/stack
        # canary loads via gs/fs) angr models base = selector<<16 when the
        # GDT register is null; that yields a fixed linear address which
        # classifies as host "other" memory (non-canonical).
        _ldt, _gdt, sel, vaddr = args
        linear = fold(E("add", 32, (E("shl", 32, (sel, E("const", 32, value=16))),
                                    zext(vaddr, 32))))
        if retw == 64:
            return fold(E("concat", 64, (E("const", 32, value=0), linear)))
        return linear
    if name == "x86g_load_seg":
        # (seg_selector, virtual_addr) -> linear addr; same flat model.
        sel, vaddr = args
        return fold(E("add", 32, (E("shl", 32, (sel, E("const", 32, value=4))),
                                  zext(vaddr, 32))))
    arch = "i386" if name.startswith("x86") else "amd64"
    kinds = _CC_X86_KIND if arch == "i386" else _CC_AMD64_KIND
    widths = _CC_X86_W if arch == "i386" else _CC_AMD64_W
    if name.endswith("calculate_condition"):
        cond_t, op_t, d1, d2, nd = args
        if cond_t.op != "const" or op_t.op != "const":
            return E("unsupported", retw, name="cc_dyn")
        opv = op_t.value
        if opv >= len(kinds) or kinds[opv] == "":
            flags = {"cf": inp("h_cf", 1), "of": inp("h_of", 1), "af": inp("h_af", 1),
                     "zf": inp("h_zf", 1), "sf": inp("h_sf", 1), "pf": inp("h_pf", 1)}
        else:
            flags = _cc_flags(kinds[opv], widths[opv], d1, d2, nd)
            if flags is None:
                return E("unsupported", retw, name=f"cc_op_{opv}")
        b = _cc_condition(cond_t.value, flags)
        if b is None:
            return E("unsupported", retw, name=f"cc_cond_{cond_t.value}")
        return zext(b, retw)
    # eflags_all / eflags_c -> full/partial flag word
    if len(args) != 4:
        return S.LowerFailure("unsupported_ir", f"bad arity for {name}")
    op_t, d1, d2, nd = args
    if op_t.op != "const" or op_t.value >= len(kinds) or kinds[op_t.value] == "":
        return E("unsupported", retw, name="cc_eflags_dyn")
    flags = _cc_flags(kinds[op_t.value], widths[op_t.value], d1, d2, nd)
    if flags is None:
        return E("unsupported", retw, name=f"cc_eflags_op_{op_t.value}")
    if name.endswith("eflags_c"):
        return zext(flags["cf"], retw)
    word = E("const", retw, value=0x2)
    for bit, key in ((0, "cf"), (2, "pf"), (4, "af"), (6, "zf"),
                     (7, "sf"), (11, "of")):
        word = E("or", retw, (word, E("shl", retw,
                                      (zext(flags[key], retw), E("const", retw, value=bit)))))
    return word


def hooked_expr(expr, **kwargs):
    """Extend dosunit lowering: flag CCalls get real semantics."""
    if isinstance(expr, pyvex.expr.Const) and not isinstance(expr.con.value, int):
        return S.LowerFailure("unsupported_ir", "non-integer const")
    if isinstance(expr, pyvex.expr.CCall):
        out = _lower_ccall(expr, kwargs)
        if out is not None:
            return out
        return S.LowerFailure("unsupported_ir", f"unsupported CCall {expr.cee.name}")
    return _ORIG["_lower_expr"](expr, **kwargs)


def hooked_finish(state, *, irsb, output_regs, max_assignments_per_function):
    """Materialize host regs + exits; canonical cells live in CTX."""
    address = hooked_expr(irsb.next, temp_defs=state.temp_defs,
                          temp_failures=state.temp_failures,
                          reg_versions=state.reg_versions, tyenv=irsb.tyenv,
                          memory=state.mem_version)
    if isinstance(address, S.LowerFailure):
        return address
    state.reg_versions["__ip__"] = address
    return {"outputs": {}, "assignments": [], "inputs": []}


def lower_block(irsb, ip_off: int, ip_name: str) -> S.LowerFailure | None:
    """Lower one IRSB into CTX using routed load/store semantics."""
    state = S._IrsbLowerState(
        reg_versions=CTX.reg_versions,
        mem_version=CTX.arrays["other"],
        io_version=CTX.arrays["io"],
    )
    state.temp_defs = CTX.temps
    state.temp_failures = CTX.temp_failures
    CTX.cur_stk = {}
    CTX.call_target = None
    for stmt in irsb.statements:
        if stmt.tag == "Ist_IMark":
            continue
        if stmt.tag == "Ist_Store":
            fail = hooked_store(stmt, state, tyenv=irsb.tyenv)
        else:
            fail = S._lower_irsb_statement(stmt, state, tyenv=irsb.tyenv,
                                           output_regs=tuple(state.reg_versions))
        if fail is not None:
            return fail
        if stmt.tag == "Ist_Put" and int(stmt.offset) == ip_off:
            CTX.call_target = state.reg_versions.get(ip_name)
    CTX.exits = list(state.exits)
    CTX.reg_versions = state.reg_versions
    CTX.temps = state.temp_defs
    nxt = hooked_expr(irsb.next, temp_defs=state.temp_defs,
                      temp_failures=state.temp_failures,
                      reg_versions=state.reg_versions, tyenv=irsb.tyenv,
                      memory=state.mem_version)
    if isinstance(nxt, S.LowerFailure):
        return nxt
    CTX.next_expr = nxt
    return None

# ---------------------------------------------------------------------------
# Call summaries on the canonical domain
# ---------------------------------------------------------------------------

HELPER_UF_PORT = {
    "swi": "swi", "indirect_jump": "indirect_jump",
}
BIOS_PORT_TO_INT = {
    "bios_video": "int10", "bios_set_mode": "int10", "bios_set_cursor": "int10",
    "bios_scroll": "int10", "bios_putc": "int10", "bios_palette": "int10",
    "bios_getch": "int16", "bios_kbhit": "int16", "bios_kbd": "int16",
    "bios_time": "int1a",
}


def _boundary_call(ctx: LowerCtx, name: str) -> None:
    """Compositional call model: callee effect = opaque named constants.

    Each canonical cell becomes ``summary_call_<name>_<cell>`` — a 0-arity
    uninterpreted function, i.e. a deterministic-per-name constant that is
    trivially equal across both sides.  This isolates the comparison to the
    caller's own observable semantics; the callee is verified by its own
    comparator entry.  ``esp``/``eip`` are preserved (retn/retf pops exactly
    the pushed frame → net-balanced), ``cs``/``ss`` too (callee contract —
    and ``ss`` drives stack addressing, so clobbering it would kill store
    forwarding for the rest of the caller).
    """
    for r in CANON_REGS32:
        if r == "esp":
            continue
        ctx.canon[r] = E(f"summary_call_{name}_g_{r}", 32, ())
    for f in CANON_FLAGS:
        ctx.canon[f] = E(f"summary_call_{name}_f_{f}", 8, ())
    for s in ("ds", "es", "fs", "gs"):
        ctx.canon[s] = E(f"summary_call_{name}_s_{s}", 16, ())
    ctx.arrays["data"] = E(f"summary_call_{name}_data", 0, ())
    ctx.arrays["io"] = E(f"summary_call_{name}_io", 0, ())


def _uf_call(ctx: LowerCtx, name: str) -> None:
    """Replace every canonical cell with a shared uninterpreted summary term.

    ``summary_*`` ops are uninterpreted Z3 functions in dosunit's backend, so
    identical (name, args) on both sides compare equal while remaining
    conservative (no assumed semantics).
    """
    args = tuple(ctx.canon[r] for r in CANON_REGS32) + \
        tuple(ctx.canon[s] for s in CANON_SEGS) + \
        tuple(ctx.canon[f] for f in CANON_FLAGS) + \
        (ctx.arrays["data"], ctx.arrays["io"])
    for r in CANON_REGS32:
        ctx.canon[r] = E(f"summary_call_{name}_g_{r}", 32, args)
    for s in CANON_SEGS:
        ctx.canon[s] = E(f"summary_call_{name}_s_{s}", 16, args)
    for f in CANON_FLAGS:
        ctx.canon[f] = E(f"summary_call_{name}_f_{f}", 8, args)
    ctx.arrays["data"] = E(f"summary_call_{name}_data", 0, args)
    # clobber caller-saved host regs so post-call reads stay comparable
    for reg in (["eax", "ecx", "edx"] if ctx.cfg.arch == "i386"
                else ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11",
                      "cc_op", "cc_dep1", "cc_dep2", "cc_ndep"]):
        if reg in ctx.reg_versions:
            ctx.reg_versions[reg] = E(f"summary_call_{name}_h_{reg}",
                                      ctx.reg_versions[reg].width, args)


def _seg_off_ptr(seg_term: S.SsaExpr, off_term: S.SsaExpr) -> S.SsaExpr:
    return E("add", 32, (E("shl", 32, (zext(seg_term, 32), E("const", 32, value=4))),
                         zext(trunc(off_term, 16), 32)))


def _do_push(ctx: LowerCtx, v: S.SsaExpr) -> None:
    sp = trunc(ctx.canon["esp"], 16)
    newsp = E("sub", 16, (sp, E("const", 16, value=2)))
    ctx.canon_write("esp", 16, 0, newsp)
    addr = E("add", 32, (E("shl", 32, (zext(ctx.canon["ss"], 32), E("const", 32, value=4))),
                         zext(newsp, 32)))
    ctx.arrays["data"] = E("storele", 0, (ctx.arrays["data"], addr, trunc(v, 16)))


def _do_pop(ctx: LowerCtx) -> S.SsaExpr:
    sp = trunc(ctx.canon["esp"], 16)
    addr = E("add", 32, (E("shl", 32, (zext(ctx.canon["ss"], 32), E("const", 32, value=4))),
                         zext(sp, 32)))
    v = E("loadle", 16, (ctx.arrays["data"], addr))
    ctx.canon_write("esp", 16, 0, E("add", 16, (sp, E("const", 16, value=2))))
    return v


def _flag_word(ctx: LowerCtx) -> S.SsaExpr:
    order = [("cf", 0), ("pf", 2), ("af", 4), ("zf", 6), ("sf", 7),
             ("tf", 8), ("if_", 9), ("df", 10), ("of", 11)]
    v = E("const", 16, value=0)
    for name, bit in order:
        part = zext(ctx.canon[name], 16)
        if bit:
            part = E("shl", 16, (part, E("const", 16, value=bit)))
        v = E("or", 16, (v, part))
    return v


def _set_flag_word(ctx: LowerCtx, v: S.SsaExpr) -> None:
    for name, bit in [("cf", 0), ("pf", 2), ("af", 4), ("zf", 6), ("sf", 7),
                      ("tf", 8), ("if_", 9), ("df", 10), ("of", 11)]:
        bitv = E("and", 16, (v, E("const", 16, value=1 << bit)))
        ctx.canon[name] = neq0(bitv)


def _host_arg(ctx: LowerCtx, idx: int) -> S.SsaExpr | None:
    """Best-effort call argument term (cdecl stack / SysV regs)."""
    if ctx.cfg.arch == "amd64":
        regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        t = ctx.reg_versions.get(regs[idx]) if idx < len(regs) else None
        return t
    # cdecl: call pushes ret addr at the lowest stack slot of the block;
    # arg i sits at ret+4*(i+1).
    if not ctx.cur_stk:
        return None
    base = min(ctx.cur_stk)
    return ctx.cur_stk.get(base + 4 * (idx + 1))


# ---------------------------------------------------------------------------
# m2c runtime canonical summaries (asm.h semantics, host ABI args)
# ---------------------------------------------------------------------------

_FLAG_CODE = {"C": "cf", "P": "pf", "A": "af", "Z": "zf", "S": "sf",
              "T": "tf", "I": "if_", "D": "df", "O": "of"}
_MANGLE_W = {"a": 8, "b": 8, "c": 8, "h": 8, "s": 16, "t": 16,
             "i": 32, "j": 32, "l": 32, "m": 32, "x": 64, "y": 64}
_DTYPE_W = {"char": 8, "signed char": 8, "unsigned char": 8, "bool": 8, "db": 8,
            "short": 16, "short int": 16, "unsigned short": 16, "dw": 16,
            "int": 32, "unsigned int": 32, "long": 32, "unsigned long": 32,
            "dd": 32, "long long": 64, "unsigned long long": 64, "dq": 64}
_MANGLED_OP = re.compile(
    r"(ADD_|ADC_|SUB_|SBB_|CMP_|AND_|OR_|XOR_|TEST_|SHL_|SHR_|SAR_|NEG_|INC_|DEC_|ROL_|ROR_)"
    r"I([a-z]+)E")


def _op_widths(tname: str) -> tuple[str, list[int]] | None:
    """Return (op, [D_bits, S_bits]) from a mangled or demangled helper name."""
    m = _MANGLED_OP.search(tname)
    if m:
        return m.group(1)[:-1], [_MANGLE_W[c] for c in m.group(2)]
    m = re.search(
        r"(ADD_|ADC_|SUB_|SBB_|CMP_|AND_|OR_|XOR_|TEST_|SHL_|SHR_|SAR_|NEG_|INC_|DEC_|ROL_|ROR_)"
        r"[^<]*<([^>]+)>", tname)
    if m:
        types = [t.strip() for t in m.group(2).split(",")]
        if all(t in _DTYPE_W for t in types):
            return m.group(1)[:-1], [_DTYPE_W[t] for t in types]
    return None


def _c(v: int, w: int) -> S.SsaExpr:
    return E("const", w, value=v & ((1 << w) - 1))


def _pf8(v8: S.SsaExpr) -> S.SsaExpr:
    """x86 PF for a byte value: 1 on even parity of the low byte."""
    n = E("and", 8, (E("xor", 8, (v8, E("lshr", 8, (v8, _c(4, 8))))), _c(0xF, 8)))
    bit = E("and", 16, (E("lshr", 16, (_c(0x6996, 16), zext(n, 16))), _c(1, 16)))
    return E("ite", 8, (E("eq", 1, (bit, _c(0, 16))), _c(1, 8), _c(0, 8)))


def _set_szp(ctx: LowerCtx, bits: int, v: S.SsaExpr) -> None:
    """set_szp_flags semantics: ZF/SF/PF from the truncated result."""
    v = trunc(v, bits) if v.width != bits else v
    ctx.canon["zf"] = E("ite", 8, (E("eq", 1, (v, _c(0, bits))), _c(1, 8), _c(0, 8)))
    ctx.canon["sf"] = trunc(E("lshr", bits, (v, _c(bits - 1, bits))), 8)
    ctx.canon["pf"] = _pf8(trunc(v, 8))


def _logic_flags(ctx: LowerCtx, bits: int, v: S.SsaExpr) -> None:
    ctx.canon["cf"] = _c(0, 8)
    ctx.canon["of"] = _c(0, 8)
    ctx.canon["af"] = _c(0, 8)
    _set_szp(ctx, bits, v)


def _m2c_ptr_load(ctx: LowerCtx, ptr: S.SsaExpr | None, bits: int) -> S.SsaExpr | None:
    if ptr is None:
        return None
    return ctx.load(ctx.arrays["other"], ptr, bits)


def _m2c_summary(ctx: LowerCtx, tname: str) -> str | None:
    """Exact canonical summary for an m2c:: runtime helper.

    Returns a diagnostic tag when the helper was modeled, ``None`` when it
    must fall through to generic handling.  Models asm.h semantics directly
    on canonical cells; a summarized helper never consumes inline budget.
    """
    # ---- eflags accessors: getZF()/setAF(b) etc. (eflags wraps _state) ------
    m = re.search(r"get([CPOZSTIDO])F\b", tname)
    if m:
        # host ABI return in al — NOT the guest-visible _state->eax.
        ctx.reg_versions["eax"] = E("or", 32, (
            E("and", 32, (ctx.reg_versions.get("eax", inp("host_eax", 32)),
                          _c(0xFFFFFF00, 32))),
            zext(ctx.canon[_FLAG_CODE[m.group(1)]], 32)))
        return "fget_" + _FLAG_CODE[m.group(1)]
    m = re.search(r"set([CPOZSTIDO])F", tname)
    if m:
        v = _host_arg(ctx, 1)  # this=arg0, bool=arg1
        if v is None:
            return "fset_unbound"
        ctx.canon[_FLAG_CODE[m.group(1)]] = neq0(trunc(v, 8))
        return "fset_" + _FLAG_CODE[m.group(1)]
    if re.search(r"eflags\d?(get|set)value", tname) or tname in ("getvalue", "setvalue"):
        if "getvalue" in tname:
            ctx.reg_versions["eax"] = zext(_flag_word(ctx), 32)
            return "fgetvalue"
        v = _host_arg(ctx, 1)
        if v is None:
            return "fsetvalue_unbound"
        _set_flag_word(ctx, trunc(v, 16))
        return "fsetvalue"

    # ---- flag bulk writers ---------------------------------------------------
    if "set_szp_flags" in tname or "set_logic_flags" in tname:
        bytesz = _host_arg(ctx, 0)
        vlo = _host_arg(ctx, 1)
        nb = constval(fold(bytesz)) if bytesz is not None else None
        if nb not in (1, 2, 4, 8) or vlo is None:
            return "szp_unbound"
        bits = nb * 8
        if "set_logic_flags" in tname:
            _logic_flags(ctx, bits, vlo)
        else:
            _set_szp(ctx, bits, vlo)
        return "szp"

    # ---- dispatch head -----------------------------------------------------
    if "dispatch_external_code" in tname:
        # dispatch_external_code(__disp, _state, &handled): no external
        # handler claims in-image tokens -> handled=false, execution falls
        # through to the normalization + switch.
        hp = _host_arg(ctx, 2)
        if hp is None:
            return "extdisp_unbound"
        ctx.store(ctx.arrays["other"], hp, _c(0, 8))
        ctx.reg_versions["eax"] = _c(0, 32)
        return "extdisp_false"

    # ---- stack / return-path -------------------------------------------------
    m = re.search(r"PUSH_I([a-z])E|PUSH_<([^>]+)>", tname)
    if m:
        w = _MANGLE_W.get(m.group(1) or "") or _DTYPE_W.get((m.group(2) or "").strip(), 0)
        ptr = _host_arg(ctx, 0)
        v = _m2c_ptr_load(ctx, ptr, w) if w else None
        if v is None:
            return "push_unbound"
        _do_push(ctx, v)
        return "push"
    m = re.search(r"POP_I([a-z])E|POP_<([^>]+)>", tname)
    if m:
        w = _MANGLE_W.get(m.group(1) or "") or _DTYPE_W.get((m.group(2) or "").strip(), 0)
        ptr = _host_arg(ctx, 0)
        if not w or ptr is None:
            return "pop_unbound"
        v = _do_pop(ctx)
        ctx.store(ctx.arrays["other"], ptr, v if w == 16 else zext(v, w))
        return "pop"
    if "RETN_" in tname:
        i = constval(fold(_host_arg(ctx, 0))) if _host_arg(ctx, 0) is not None else 0
        ctx.canon["eip"] = zext(_do_pop(ctx), 32)
        ctx.retn_popped = True
        if i:
            sp = trunc(ctx.canon["esp"], 16)
            ctx.canon_write("esp", 16, 0, E("add", 16, (sp, _c(i, 16))))
        return "retn"
    if "RETF_" in tname:
        i = constval(fold(_host_arg(ctx, 0))) if _host_arg(ctx, 0) is not None else 0
        ctx.canon["eip"] = zext(_do_pop(ctx), 32)
        ctx.retn_popped = True
        ctx.canon_write("cs", 16, 0, _do_pop(ctx))
        if i:
            sp = trunc(ctx.canon["esp"], 16)
            ctx.canon_write("esp", 16, 0, E("add", 16, (sp, _c(i, 16))))
        return "retf"
    if "CALL_" in tname:
        # m2c::CALL_(label, _state, _i, name, retaddr, has_ret): pushes the
        # guest return addr, calls the trampoline, and the callee's ret pops
        # the frame.  arg0 is the callee trampoline — resolve it to a proc
        # and apply the compositional boundary (opaque summary outputs plus
        # the stack accounting the callee's ret performs).
        carg = _host_arg(ctx, 0)
        if carg is not None:
            carg = ctx._concretize(carg)
        cv = constval(fold(carg)) if carg is not None else None
        cname = ctx.cfg.addr2name.get(cv) if cv is not None else None
        if cname is not None:
            cname = _demangle_local(cname)
            cm = re.match(r"^((?:sub|loc)_[0-9a-f]+)", cname)
            cname = cm.group(1) if cm else cname
        if cname is not None and cname.startswith("sub_"):
            # CALL_ pushes the guest retaddr AND the callee's retn/retf pops
            # it inside the host call — net zero stack effect at the site.
            _boundary_call(ctx, cname)
            ctx.reg_versions["eax"] = c32(1)  # CALL_ returns bool ok
            return f"call_boundary_{cname}"
        eip = ctx.canon.get("eip")
        _do_push(ctx, E("add", 16, (trunc(eip, 16), _c(2, 16))) if eip is not None
                 else inp("callret", 16))
        return "callpush"

    # ---- address computation -------------------------------------------------
    if "stack_raddr_" in tname or re.search(r"\braddr_\b", tname):
        seg = trunc(_host_arg(ctx, 0) or inp("seg", 16), 16)
        off = trunc(_host_arg(ctx, 1) or inp("off", 16), 16)
        # host ABI return in eax — not the guest-visible canon cell.
        ctx.reg_versions["eax"] = E("add", 32, (
            _c(DATA_SYN, 32),
            E("add", 32, (E("shl", 32, (zext(seg, 32), _c(4, 32))), zext(off, 32)))))
        return "raddr"

    # ---- ALU helpers -----------------------------------------------------------
    ow = _op_widths(tname)
    if ow is not None:
        op, widths = ow
        dbits = widths[0]
        sbits = widths[1] if len(widths) > 1 else dbits
        destp = _host_arg(ctx, 0)
        if destp is None:
            return "alu_unbound"
        dest = trunc(_m2c_ptr_load(ctx, destp, dbits), dbits)
        if dest is None:
            return "alu_unbound"
        two = op not in ("NEG", "INC", "DEC")
        byval = op in ("ROL", "ROR")
        srcp = _host_arg(ctx, 1)
        if two:
            src = (_host_arg(ctx, 1) if byval
                   else _m2c_ptr_load(ctx, srcp, sbits))
            if src is None:
                src = inp("alusrc", sbits)
            src = trunc(src, dbits)
        if op in ("SHL", "SHR", "SAR", "ROL", "ROR"):
            _alu_shift(ctx, op, dbits, dest, src, destp)
            return "alu_" + op.lower()
        res, fl = _alu_result(ctx, op, dbits, dest, src if two else None)
        for fname, fe in fl.items():
            ctx.canon[fname] = fe
        if op not in ("CMP", "TEST"):
            ctx.store(ctx.arrays["other"], destp, res)
        return "alu_" + op.lower()

    if re.search(r"eflags\d?C[12]E?\b|eflags\d?D[12]E?\b|eflags::eflags|~eflags", tname):
        return "nop"
    if re.search(r"native_return|mark_native|take_native|carry_native|NativeCallDepth|suppress_native", tname):
        return "nop"
    return None


def _alu_result(ctx: LowerCtx, op: str, bits: int, d: S.SsaExpr,
                s: S.SsaExpr | None) -> tuple[S.SsaExpr, dict[str, S.SsaExpr]]:
    """asm.h ALU flag semantics on canonical cells."""
    mask = (1 << bits) - 1
    sign = 1 << (bits - 1)
    fl: dict[str, S.SsaExpr] = {}
    res = d
    if op == "AND":
        res = E("and", bits, (d, s))
        _logic_flags(ctx, bits, res)
        return res, fl
    if op == "OR":
        res = E("or", bits, (d, s))
        _logic_flags(ctx, bits, res)
        return res, fl
    if op == "XOR":
        res = E("xor", bits, (d, s))
        _logic_flags(ctx, bits, res)
        return res, fl
    if op == "TEST":
        res = E("and", bits, (d, s))
        _logic_flags(ctx, bits, res)
        return res, fl
    wide = bits + 1
    if op in ("ADD", "ADC"):
        dw_ = zext(d, wide)
        sw_ = zext(s, wide)
        if op == "ADC":
            sw_ = E("add", wide, (sw_, zext(ctx.canon["cf"], wide)))
        r64 = E("add", wide, (dw_, sw_))
        res = trunc(r64, bits)
        fl["cf"] = trunc(E("lshr", wide, (r64, _c(bits, wide))), 8)
        # OF: ((d ^ res) & (s' ^ res) & sign)
        fl["of"] = neq0(E("and", bits, (
            E("and", bits, (E("xor", bits, (d, res)),
                            E("xor", bits, (trunc(sw_, bits), res)))),
            _c(sign, bits))))
        fl["af"] = neq0(E("and", bits, (
            E("xor", bits, (E("xor", bits, (d, trunc(sw_, bits))), res)),
            _c(0x10, bits))))
        _set_szp(ctx, bits, res)
        return res, fl
    if op in ("SUB", "SBB", "CMP"):
        sw_ = s
        if op == "SBB":
            sw_ = E("add", bits, (s, zext(ctx.canon["cf"], bits)))
        res = E("sub", bits, (d, sw_))
        # CF: left < right (unsigned)
        fl["cf"] = E("ite", 8, (E("ult", 1, (d, sw_)), _c(1, 8), _c(0, 8)))
        fl["of"] = neq0(E("and", bits, (
            E("and", bits, (E("xor", bits, (d, sw_)),
                            E("xor", bits, (d, res)))),
            _c(sign, bits))))
        fl["af"] = neq0(E("and", bits, (
            E("xor", bits, (E("xor", bits, (d, sw_)), res)),
            _c(0x10, bits))))
        _set_szp(ctx, bits, res)
        return res, fl
    if op == "NEG":
        res = E("sub", bits, (_c(0, bits), d))
        fl["cf"] = neq0(d)
        fl["of"] = E("ite", 8, (E("eq", 1, (d, _c(sign, bits))), _c(1, 8), _c(0, 8)))
        fl["af"] = neq0(E("and", bits, (E("xor", bits, (d, res)), _c(0x10, bits))))
        _set_szp(ctx, bits, res)
        return res, fl
    if op == "INC":
        res = E("add", bits, (d, _c(1, bits)))
        fl["of"] = E("ite", 8, (E("eq", 1, (res, _c(sign, bits))), _c(1, 8), _c(0, 8)))
        _set_szp(ctx, bits, res)
        return res, fl
    if op == "DEC":
        res = E("sub", bits, (d, _c(1, bits)))
        fl["of"] = E("ite", 8, (E("eq", 1, (res, _c(sign - 1, bits))), _c(1, 8), _c(0, 8)))
        _set_szp(ctx, bits, res)
        return res, fl
    return res, fl


def _alu_shift(ctx: LowerCtx, op: str, bits: int, d: S.SsaExpr, s: S.SsaExpr,
               destp: S.SsaExpr) -> None:
    """asm.h SHL/SHR/SAR/ROL/ROR: count&0x1f, no-op when count==0 (ite-guarded)."""
    cnt = E("and", 32, (zext(s, 32), _c(0x1F, 32)))
    ne = E("ne", 1, (cnt, _c(0, 32)))
    mask = (1 << bits) - 1
    sign = 1 << (bits - 1)
    v = zext(d, 32)
    cn = trunc(cnt, bits)
    if op == "SHL":
        res32 = E("and", 32, (E("shl", 32, (v, cnt)), _c(mask, 32)))
        cf = E("ite", 8, (E("ule", 1, (cnt, _c(bits, 32))),
                          trunc(E("lshr", 32, (v, E("sub", 32, (_c(bits, 32), cnt)))), 8),
                          _c(0, 8)))
        of = E("ite", 8, (E("eq", 1, (cnt, _c(1, 32))),
                          trunc(E("lshr", 32, (
                              E("and", 32, (E("xor", 32, (v, res32)), _c(sign, 32))),
                              _c(bits - 1, 32))), 8),
                          _c(0, 8)))
        res = trunc(res32, bits)
    elif op == "SHR":
        res32 = E("and", 32, (E("lshr", 32, (v, cnt)), _c(mask, 32)))
        cf = E("ite", 8, (E("ule", 1, (cnt, _c(bits, 32))),
                          trunc(E("lshr", 32, (v, E("sub", 32, (cnt, _c(1, 32))))), 8),
                          _c(0, 8)))
        of = E("ite", 8, (E("eq", 1, (cnt, _c(1, 32))),
                          trunc(E("lshr", 32, (v, _c(bits - 1, 32))), 8),
                          _c(0, 8)))
        res = trunc(res32, bits)
    elif op == "SAR":
        res32 = E("and", 32, (E("ashr", 32, (v, cnt)), _c(mask, 32)))
        cf = E("ite", 8, (E("ule", 1, (cnt, _c(bits, 32))),
                          trunc(E("lshr", 32, (v, E("sub", 32, (cnt, _c(1, 32))))), 8),
                          _c(0, 8)))
        of = _c(0, 8)
        res = trunc(res32, bits)
    else:  # ROL/ROR: rotate; CF = last bit rotated
        m = bits - 1
        cm = E("and", 32, (cnt, _c(m, 32)))
        if op == "ROR":
            rot = E("or", 32, (E("lshr", 32, (v, cm)),
                               E("shl", 32, (v, E("sub", 32, (_c(bits, 32), cm))))))
            cf = trunc(E("lshr", 32, (rot, _c(m, 32))), 8)
            of = E("ite", 8, (E("eq", 1, (cnt, _c(1, 32))),
                              trunc(E("xor", 32, (
                                  E("lshr", 32, (rot, _c(m, 32))),
                                  E("lshr", 32, (rot, _c(m - 1, 32))))), 8),
                              _c(0, 8)))
        else:
            rot = E("or", 32, (E("shl", 32, (v, cm)),
                               E("lshr", 32, (v, E("sub", 32, (_c(bits, 32), cm))))))
            cf = trunc(rot, 8)
            of = E("ite", 8, (E("eq", 1, (cnt, _c(1, 32))),
                              trunc(E("xor", 32, (
                                  rot, E("lshr", 32, (rot, _c(m, 32))))), 8),
                              _c(0, 8)))
        res = trunc(E("and", 32, (rot, _c(mask, 32))), bits)
    # count==0 -> dest and flags unchanged; guard every written cell.
    new_dest = E("ite", bits, (ne, res, d))
    ctx.store(ctx.arrays["other"], destp, new_dest)
    ctx.canon["cf"] = E("ite", 8, (ne, cf, ctx.canon["cf"]))
    ctx.canon["of"] = E("ite", 8, (ne, of, ctx.canon["of"]))
    ctx.canon["af"] = E("ite", 8, (ne, _c(0, 8), ctx.canon["af"]))
    zf = E("ite", 8, (E("eq", 1, (res, _c(0, bits))), _c(1, 8), _c(0, 8)))
    sf = trunc(E("lshr", bits, (res, _c(bits - 1, bits))), 8)
    pf = _pf8(trunc(res, 8))
    ctx.canon["zf"] = E("ite", 8, (ne, zf, ctx.canon["zf"]))
    ctx.canon["sf"] = E("ite", 8, (ne, sf, ctx.canon["sf"]))
    ctx.canon["pf"] = E("ite", 8, (ne, pf, ctx.canon["pf"]))


def apply_call(ctx: LowerCtx, target: S.SsaExpr | None) -> str:
    """Apply the canonical call summary; returns a tag for diagnostics."""
    tname = None
    if target is not None and target.op == "const":
        tname = ctx.cfg.addr2name.get(target.value)
    tname = tname or "unknown"

    if ctx.cfg.m2c:
        tag = _m2c_summary(ctx, tname)
        if tag is not None:
            return tag

    # ---- shared IO / stack helpers -----------------------------------------
    inw = "asm2C_INW" in tname or tname == "inw"
    ind = "asm2C_IND" in tname
    if tname in ("in",) or "asm2C_IN" in tname or inw or ind:
        width = 32 if ind else (16 if inw else 8)
        port = trunc(_host_arg(ctx, 0) or ctx.canon["edx"], 16)
        res = E("loadle", width, (ctx.arrays["io"], zext(port, 32)))
        if ctx.cfg.arch == "amd64":
            ctx.reg_versions["rax"] = zext(res, 64)
        else:
            # asm2C_IN returns int8/int16 in host eax; the caller then stores
            # al/ax through its regref pointer into _state->eax.  Writing canon
            # eax here would be overwritten by that store, so set the host
            # return register and let the caller's store do the canon write.
            ctx.reg_versions["eax"] = zext(res, 32)
        return f"io_in{width}"
    outw = "asm2C_OUTW" in tname or tname == "outw"
    outd = "asm2C_OUTD" in tname
    if tname in ("out",) or "asm2C_OUT" in tname or outw or outd:
        width = 32 if outd else (16 if outw else 8)
        port = trunc(_host_arg(ctx, 0) or ctx.canon["edx"], 16)
        val = trunc(_host_arg(ctx, 1) or ctx.canon["eax"], width)
        ctx.arrays["io"] = E("storele", 0, (ctx.arrays["io"], zext(port, 32), val))
        return f"io_out{width}"
    if tname == "push" or "PUSH_" in tname:
        v = _host_arg(ctx, 0)
        if v is None:
            _uf_call(ctx, "push")
            return "call_push"
        _do_push(ctx, v)
        return "push"
    if tname == "pop" or "POP_" in tname:
        v = _do_pop(ctx)
        if ctx.cfg.arch == "amd64":
            ctx.reg_versions["rax"] = zext(v, 64)
        else:
            # POP_(ref a, state): store result through arg0 pointer if known
            dst = _host_arg(ctx, 0)
            if dst is not None and dst.op == "const":
                space, key = ctx.cfg.classify_const(dst.value)
                if space == "state":
                    ctx.canon_write(M2C_STATE_FIELDS[key][0], 16, 0, v)
        return "pop"
    if tname == "pushf" or "PUSHF" in tname:
        _do_push(ctx, _flag_word(ctx))
        return "pushf"
    if tname == "popf" or "POPF" in tname:
        _set_flag_word(ctx, _do_pop(ctx))
        return "popf"
    if tname == "pushad" or "PUSHAD" in tname:
        for r in ("eax", "ecx", "edx", "ebx", "ebp", "esi", "edi"):
            _do_push(ctx, trunc(ctx.canon[r], 16))
        return "pushad"
    if tname == "popad" or "POPAD" in tname:
        for r in reversed(("eax", "ecx", "edx", "ebx", "ebp", "esi", "edi")):
            ctx.canon_write(r, 16, 0, _do_pop(ctx))
        return "popad"

    # ---- int/runtime calls --------------------------------------------------
    canon_name = None
    if "asm2C_INT" in tname or tname == "swi":
        arg = _host_arg(ctx, 1 if "asm2C_INT" in tname else 0)
        num = constval(fold(arg)) if arg is not None else None
        canon_name = f"int{num:x}" if num is not None else "int_unk"
    elif tname in BIOS_PORT_TO_INT:
        canon_name = BIOS_PORT_TO_INT[tname]
    elif tname.startswith("dos_"):
        canon_name = "int21"
    elif re.search(r"(?:^|_Z\d*|L?)(sub_[0-9a-f]+|loc_[0-9a-f]+|nullsub_\d+|seg000_[0-9a-f]+_proc)", tname):
        canon_name = re.search(r"(sub_[0-9a-f]+|loc_[0-9a-f]+|nullsub_\d+|seg000_[0-9a-f]+_proc)", tname).group(1)
    elif "CALL_" in tname or re.match(r"_group\d", tname):
        arg = _host_arg(ctx, 0)
        k = constval(fold(arg)) if arg is not None else None
        canon_name = ctx.cfg.ksub_map.get(k, "call_unk") if k is not None else "call_unk"
    else:
        canon_name = re.sub(r"[^A-Za-z0-9_]", "_", tname)
    _uf_call(ctx, canon_name)
    return f"call_{canon_name}"


# ---------------------------------------------------------------------------
# Bounded symbolic executor
# ---------------------------------------------------------------------------

@dataclass
class TermPath:
    kind: str
    cond: S.SsaExpr
    canon: dict[str, S.SsaExpr]
    arrays: dict[str, S.SsaExpr]


def _ret_boundary(cfg: SideConfig, ctx: LowerCtx) -> tuple[dict, dict]:
    """Snapshot canon/arrays at a guest-level return.

    Boundary convention: a near ``ret`` pops the caller-pushed word, so the
    guest esp rises by 2.  The m2c side performs that pop inside ``RETN_``;
    the port's host ``return`` elides it — model the pop on port-side ``ret``
    terminals so both sides share one guest-visible boundary.
    """
    canon = dict(ctx.canon)
    if not cfg.m2c:
        sp = canon.get("esp")
        if sp is not None:
            canon["esp"] = E("or", 32, (
                E("and", 32, (sp, _c(0xFFFF0000, 32))),
                zext(E("add", 16, (trunc(sp, 16), _c(2, 16))), 32)))
    return canon, dict(ctx.arrays)


def _clone_ctx(ctx: LowerCtx) -> LowerCtx:
    n = object.__new__(LowerCtx)
    n.cfg = ctx.cfg
    n.canon = dict(ctx.canon)
    n.arrays = dict(ctx.arrays)
    n.reg_versions = dict(ctx.reg_versions)
    n.temps = {}
    n.temp_failures = {}
    n.exits = []
    n.cur_stk = {}
    n.unmapped = ctx.unmapped
    n.error = None
    n.is_stack_base = ctx.is_stack_base
    n.is_frame_base = ctx.is_frame_base
    n._hostunk = ctx._hostunk
    n.call_target = None
    n.next_expr = None
    n.inline_depth = ctx.inline_depth
    n.last_disp = ctx.last_disp
    n.retn_popped = ctx.retn_popped
    n.bind_args = ctx.bind_args
    n.disp_seen = ctx.disp_seen
    n.probe_stk = None
    return n


_M2C_NOP = re.compile(
    r"log_regs_m2c|log_debug|log_error|stackDump|log_disasm|log_hex|"
    r"check_xm|trace_|debug_handler|record_error")
_M2C_RETTERM = re.compile(
    r"__dispatch_call|host_try_overlay|__dispatch_jump")
_M2C_RUNTIME = re.compile(
    r"memcpy|memmove|memset|memcmp|strlen|strcmp|malloc|calloc|realloc|free\b|"
    r"printf|fprintf|sprintf|snprintf|fwrite|fread|fopen|fclose|fflush|"
    r"SDL_|__cxa|_Unwind|__assert|abort\b|exit\b|operator new|operator delete|"
    r"std::|_ZNSt|_ZNKSt|__gnu|__libc|__builtin|vtable|__gxx|__static_initialization")
_M2C_GAMECALL = re.compile(
    r"(?:^|_Z\d*|L|[^A-Za-z0-9_])(sub_[0-9a-f]+|loc_[0-9a-f]+|nullsub_\d+|seg\d+_[0-9a-f]+_proc)\b")


_M2C_SUMMARIZED = re.compile(
    r"dispatch_external_code|"
    r"get[CPOZSTIDO]F\b|set[CPOZSTIDO]F|eflags\d?(?:get|set)value|^[gs]etvalue\b|"
    r"set_szp_flags|set_logic_flags|"
    r"PUSH_I[a-z]E|PUSH_<|POP_I[a-z]E|POP_<|RETN_|RETF_|CALL_|"
    r"stack_raddr_|\braddr_\b|"
    r"(?:ADD_|ADC_|SUB_|SBB_|CMP_|AND_|OR_|XOR_|TEST_|SHL_|SHR_|SAR_|NEG_|INC_|DEC_|ROL_|ROR_)I[a-z]+E|"
    r"(?:ADD_|ADC_|SUB_|SBB_|CMP_|AND_|OR_|XOR_|TEST_|SHL_|SHR_|SAR_|NEG_|INC_|DEC_|ROL_|ROR_)[^<]*<|"
    r"eflags\d?C[12]E|eflags\d?D[12]E|eflags::eflags|~eflags|"
    r"native_return|mark_native|take_native|carry_native|NativeCallDepth|suppress_native")


def _m2c_helper_kind(name: str) -> str:
    """Classify an m2c-side callee name (mangled or demangled).

    Summarized helpers (``_m2c_summary``) carry exact asm.h semantics on the
    canonical cells.  Remaining helpers default to ``inline``: they implement
    game semantics through ``_state`` and a UF would poison canonical outputs.
    Observers, the trampoline return-path, I/O helpers and libc/SDL runtime
    get special treatment.
    """
    for pat, kind in (("asm2C_INW", "io_inw"), ("asm2C_OUTW", "io_outw"),
                      ("asm2C_IND", "io_ind"), ("asm2C_OUTD", "io_outd"),
                      ("asm2C_IN", "io_in"), ("asm2C_OUT", "io_out"),
                      ("asm2C_INT", "int"), ("stack_chk_fail", "abort"),
                      ("abort", "abort"), ("__assert_fail", "abort"),
                      ("exit", "abort")):
        if pat in name:
            return kind
    if _M2C_RETTERM.search(name):
        return "retterm"
    if _M2C_NOP.search(name):
        return "nop"
    if _M2C_SUMMARIZED.search(name):
        return "summary"
    if _M2C_GAMECALL.search(name):
        return "gamecall"
    if _M2C_RUNTIME.search(name):
        return "uf"
    return "inline"


def _port_helper_kind(name: str) -> str:
    if name in ("in", "out"):
        return "io_" + name
    if name in ("push", "pop", "pushf", "popf"):
        return name
    if re.match(r"^sub_", name):
        return "gamecall"
    if re.match(r"^loc_", name):
        # Switch-case continuations — the oracle inlines the matching
        # label bodies, so the port side must inline them too.
        return "inline"
    if re.search(r"stack_chk_fail|__assert_fail|^abort$|^exit$", name):
        return "abort"
    # ``func_at`` maps a guest linear addr to a host fn ptr — model it as a
    # tagged value so the ``f_()`` indirect call can resolve the target.
    if re.search(r"(?:^|@)func_at(?:@|$)", name):
        return "funcat"
    # Host-side helpers: return an opaque host value and never touch guest
    # canonical state.  stdio prints only observe.  Memory-mutating calls
    # (memset/memcpy/fread) are excluded — they can write guest-visible
    # buffers.
    if re.search(r"(?:^|@)(rt_nullfn|rt_far|rt_flat|fprintf|vfprintf|printf|"
                 r"snprintf|vsnprintf|puts|putchar|fputs|fflush|perror|"
                 r"malloc|calloc|realloc|free|SDL_\w+)(?:@|$)", name):
        return "hostret"
    return "uf"


def _funcat_map(cfg: "SideConfig") -> dict[int, str]:
    """guest linear addr -> port fn name, built from (sub|loc)_<off> syms.

    ``func_at`` keys are ``0x1a20 + (file_off - 0x10000)`` i.e. ``off -
    0xE5E0`` for AR-segment names (fmap table in the port's memimg.c).
    """
    fm = getattr(cfg, "funcat_map", None)
    if fm is None:
        fm = {}
        for nm in cfg.proc_syms:
            m = re.match(r"^(?:sub|loc)_([0-9a-f]+)$", nm)
            if m:
                off = int(m.group(1), 16)
                if off >= 0x10000:
                    fm[off - 0xE5E0] = nm
        cfg.funcat_map = fm
        cfg.funcat_rev = {}
    return fm


def _funcat_tag(cfg: "SideConfig", name: str) -> int:
    for tag, nm in cfg.funcat_rev.items():
        if nm == name:
            return tag
    tag = 0xFCA70000 + len(cfg.funcat_rev)
    cfg.funcat_rev[tag] = name
    return tag


def _enum_jpt(cfg: "SideConfig", e: S.SsaExpr, limit: int = 48,
              valid=None):
    """Find a sym-indexed 16/32-bit load inside ``e`` sitting on a known
    jump table, and return ``(load_node, [unique entry values])``.

    Two table forms:
    - host tables: the load index carries a const naming an ELF symbol with
      a known extent (m2c ``jpt_*`` arrays, PIC switch tables) — entries
      come from file bytes, count = symbol size.
    - port guest tables: a ``data``-space load (guest ``mem[]``) whose index
      carries a const offset — bytes come from the embedded ``img[]`` at
      ``img_addr + (off - 0x1a20)``; extent unknown, so entries accumulate
      while ``valid(entry)`` holds (guest tables are contiguous).
    """
    # Every qualifying const leaf in a sym-indexed load index is a candidate
    # table base; the index often embeds *other* loads/vars whose offsets
    # also live in range (e.g. `jpt[word_1c96[si]]`). Try them all and keep
    # the first base whose entries survive ``valid``.
    cands: list[tuple[S.SsaExpr, str, int, int]] = []
    stack = [e]
    seen = 0
    while stack and seen < 512:
        n = stack.pop()
        seen += 1
        if (n.op in ("loadle", "loadbe") and n.width in (16, 32)
                and len(n.args) == 2 and n.args[1].op != "const"):
            w = n.width // 8
            idx = n.args[1]
            root = n.args[0]
            while root.op in ("storele", "storebe") and len(root.args) >= 1:
                root = root.args[0]
            is_data = (root.op == "mem_input" and root.name == "data")
            st = [idx]
            s2 = 0
            while st and s2 < 128:
                m = st.pop()
                s2 += 1
                if m.op == "const":
                    if (is_data and not cfg.m2c and cfg.img_addr
                            and 0x1A20 <= m.value
                            and m.value - 0x1A20 < cfg.img_size):
                        cands.append((n, "img", m.value, limit))
                    elif (not is_data and m.value in cfg.addr2name):
                        rng = cfg.symbols.get(cfg.addr2name[m.value])
                        if rng is not None:
                            sz = rng[1] - rng[0]
                            if 0 < sz <= limit * w and sz % w == 0:
                                cands.append((n, "sym", m.value, sz // w))
                st.extend(m.args)
        stack.extend(n.args)
    mem = cfg.project.loader.memory
    for node, kind, base, cnt in cands:
        w = node.width // 8
        mbase = cfg.img_addr + (base - 0x1A20) if kind == "img" else base
        entries: list[int] = []
        for i in range(cnt):
            try:
                raw = bytes(mem.load(mbase + i * w, w))
            except (KeyError, TypeError):
                break
            if len(raw) != w:
                break
            v = int.from_bytes(raw, "little")
            if kind == "img" and valid is not None and not valid(v):
                break
            if v not in entries:
                entries.append(v)
        if entries:
            return (node, entries)
    return None


def _disp_case_operand(g: S.SsaExpr, tokens: dict[int, str]) -> S.SsaExpr | None:
    """Find a dispatch-operand compare inside a guard; return the disp operand.

    Recognizes both compare-chain guards (`cmpl __disp, kTOKEN`) and PIC
    jump-table range checks (`sub(__disp, kMIN); cmp $span; ja default`).
    The token constant is what makes them recognizable.
    """
    stack = [g]
    seen = 0
    while stack and seen < 256:
        n = stack.pop()
        seen += 1
        if n.op in ("eq", "ne", "ult", "ule", "ugt", "uge") and len(n.args) == 2:
            a, b = n.args
            if b.op == "const" and b.value in tokens:
                return a
            if a.op == "const" and a.value in tokens:
                return b
            # calculate_condition / range-check form: cmp(sub(x, tok), k)
            for cand in (a, b):
                if cand.op in ("sub", "xor") and len(cand.args) == 2:
                    if cand.args[1].op == "const" and cand.args[1].value in tokens:
                        return cand.args[0]
                    if cand.args[0].op == "const" and cand.args[0].value in tokens:
                        return cand.args[1]
        if (n.op == "summary_x86g_calculate_condition"
                and len(n.args) == 5):
            # (cond, cc_op, dep1, dep2, nbits): dep1/dep2 are the raw
            # compare operands — a token const marks a dispatch case or
            # jump-table range check (`sub(disp,kMIN); cmp $span`).
            for i, j in ((2, 3), (3, 2)):
                lhs, rhs = n.args[i], n.args[j]
                if rhs.op == "const" and rhs.value in tokens:
                    return lhs
                if lhs.op in ("sub", "xor") and len(lhs.args) == 2:
                    if lhs.args[1].op == "const" and lhs.args[1].value in tokens:
                        return lhs.args[0]
                    if lhs.args[0].op == "const" and lhs.args[0].value in tokens:
                        return lhs.args[1]
        stack.extend(n.args)
    return None


def execute(cfg: SideConfig, entry: int, bound: tuple[int, int],
            *, seed: LowerCtx | None = None, stop_at: int | None = None,
            dispatch_addrs: frozenset[int] = frozenset(),
            max_paths: int = 48, unroll: int = 2, max_steps: int = 20000,
            max_inline: int = 8,
            ) -> tuple[list[TermPath], list[str], LowerCtx | None]:
    """Bounded symbolic execution.

    Returns (terminal paths, diagnostics, seed_ctx_at_stop_at). ``frames`` in a
    work item hold inline-callee resume addresses; a ``ret`` pops them, and the
    outermost ``ret``/indirect/dispatch edge is a terminal.
    """
    global CTX
    diagnostics: list[str] = []
    blocks: dict[int, Any] = {}
    init = seed if seed is not None else LowerCtx(cfg)
    work: list[tuple[int, LowerCtx, S.SsaExpr, dict[int, int], tuple[int, ...]]] = [
        (entry, init, E("const", 1, value=1), {}, ())]
    terminals: list[TermPath] = []
    seed_hit: LowerCtx | None = None
    steps = 0
    incomplete = 0
    ip_name = "eip" if cfg.arch == "i386" else "rip"
    ip_off = IP_OFF[cfg.arch]

    while work:
        if steps > max_steps:
            diagnostics.append("step_budget")
            break
        addr, ctx, cond, visits, frames = work.pop()
        steps += 1
        if addr == stop_at and not frames:
            seed_hit = ctx
            continue

        # visits key includes the inline-frame chain so re-entering a shared
        # helper (e.g. get_pc_thunk per call) isn't mistaken for a loop.
        # m2c dispatch hops re-traverse the same case-compare blocks on every
        # guest call/ret — a call sequence burns several revisits without any
        # data loop, so the effective cap is scaled for m2c.
        vkey = addr if not frames else (addr, frames)
        limit = unroll * 4 if cfg.m2c else unroll
        if visits.get(vkey, 0) >= limit:
            incomplete += 1
            continue
        visits = dict(visits)
        visits[vkey] = visits.get(vkey, 0) + 1
        if len(terminals) + len(work) > max_paths:
            diagnostics.append("path_budget")
            incomplete += 1
            continue
        if addr not in blocks:
            try:
                blocks[addr] = cfg.project.factory.block(addr, opt_level=0)
            except Exception as ex:
                diagnostics.append(f"lift_error:{addr:x}:{type(ex).__name__}")
                incomplete += 1
                continue
        blk = blocks[addr]
        CTX = ctx
        fail = lower_block(blk.vex, ip_off, ip_name)
        if fail is not None:
            diagnostics.append(f"lower:{addr:x}:{fail.reason}:{fail.message[:80]}")
            incomplete += 1
            continue
        jk = blk.vex.jumpkind
        nxt = fold(ctx.next_expr) if ctx.next_expr is not None else E("unsupported", 0, name="nonext")
        if jk == "Ijk_Ret":
            if frames:
                # arg binding is only valid at the outermost frame
                ctx.bind_args = cfg.m2c and len(frames) == 1
                work.append((frames[-1], ctx, cond, visits, frames[:-1]))
            else:
                terminals.append(TermPath("ret", cond, *_ret_boundary(cfg, ctx)))
            continue
        # Ijk_Call: irsb.next = callee target; fallthrough = end of block.
        if jk == "Ijk_Call":
            tconst = nxt if nxt.op == "const" else None
            tname = cfg.addr2name.get(tconst.value) if tconst is not None else None
            kind = _classify_call(cfg, tname)
            resume = addr + blk.size
            # funcat-tagged indirect call: `vfn f_ = func_at(lin); f_()`.
            # The tag encodes the resolved guest target — sub_* is a real
            # call (boundary UF + continue), loc_* is a tail-position
            # switch case (jump to its body — caller returns right after),
            # rt_nullfn is a no-op.
            frev = getattr(cfg, "funcat_rev", None)
            if (frev and tconst is not None
                    and tconst.value in frev):
                fname = frev[tconst.value]
                diagnostics.append(f"funcat:{addr:x}:{fname}")
                if fname == "rt_nullfn":
                    work.append((resume, ctx, cond, visits, frames))
                elif fname.startswith("sub_"):
                    _boundary_call(ctx, fname)
                    work.append((resume, ctx, cond, visits, frames))
                else:
                    ftgt = cfg.proc_syms.get(fname)
                    if ftgt is not None:
                        work.append((ftgt, ctx, cond, visits, frames))
                    else:
                        terminals.append(TermPath(
                            "indirect_call", cond, dict(ctx.canon),
                            dict(ctx.arrays)))
                continue
            if kind == "abort":
                terminals.append(TermPath("abort", cond, dict(ctx.canon), dict(ctx.arrays)))
                continue
            if kind == "retterm" and cfg.m2c and tname and "__dispatch_call" in tname:
                # `return __dispatch_call(__disp, _state)`: the host router
                # re-dispatches the pushed token.  sub_* tokens are callees
                # (compositional boundary + ret); loc_*/klocret_* tokens are
                # continuation labels (RETN resume) — jump to them.
                darg = _host_arg(ctx, 0)
                if darg is not None:
                    darg = ctx._concretize(darg)
                dval = constval(fold(darg)) if darg is not None else None
                if dval is None and ctx.last_disp is not None:
                    dval = constval(fold(ctx.last_disp))
                dname = cfg.ksub_map.get(dval) if dval is not None else None
                diagnostics.append(
                    f"disp_call:{addr:x}:{hex(dval) if dval is not None else 'sym'}:{dname}"
                    f":{repr(darg)[:100]}")
                if dname is not None and dname.startswith("sub_"):
                    # The callee returns through the guest frame our caller
                    # pushed: [sp]=eip, [sp+2]=cs(0x1a2) for CALLF frames.
                    _boundary_call(ctx, dname)
                    _do_pop(ctx)
                    sp16 = trunc(ctx.canon["esp"], 16)
                    sp32 = E("add", 32, (
                        E("shl", 32, (zext(ctx.canon["ss"], 32), _c(4, 32))),
                        zext(sp16, 32)))
                    probe = forward_load(ctx.arrays["data"], sp32, 16)
                    if probe is not None and constval(fold(probe)) == 0x1A2:
                        _do_pop(ctx)
                    terminals.append(TermPath("ret", cond, dict(ctx.canon), dict(ctx.arrays)))
                    continue
                rtgt = cfg.label_addr.get(dname) if dname else None
                if rtgt is not None:
                    work.append((rtgt, ctx, cond, visits, frames))
                    continue
                if dname is None and darg is not None:
                    # Sym-indexed guest jump table (jpt_*): enumerate the
                    # known-extent table — one path per entry under guard
                    # tbl[idx]==entry; token = (0x1a2<<16)|entry.
                    enum = _enum_jpt(
                        cfg, darg,
                        valid=lambda ev: (0x1A20000 | ev) in cfg.ksub_map)
                    if enum is not None:
                        lnode, entries = enum
                        diagnostics.append(
                            f"disp_enum:{addr:x}:{len(entries)}")
                        for ev in entries:
                            nm2 = cfg.ksub_map.get(0x1A20000 | ev)
                            if nm2 is None:
                                continue
                            nctx = _clone_ctx(ctx)
                            ng2 = fold(E("and", 1, (
                                cond, E("eq", 1, (lnode, _c(ev, 16))))))
                            if nm2.startswith("sub_"):
                                _boundary_call(nctx, nm2)
                                _do_pop(nctx)
                                sp16 = trunc(nctx.canon["esp"], 16)
                                sp32 = E("add", 32, (
                                    E("shl", 32, (zext(nctx.canon["ss"], 32),
                                                  _c(4, 32))),
                                    zext(sp16, 32)))
                                probe = forward_load(
                                    nctx.arrays["data"], sp32, 16)
                                if (probe is not None
                                        and constval(fold(probe)) == 0x1A2):
                                    _do_pop(nctx)
                                terminals.append(TermPath(
                                    "ret", ng2, dict(nctx.canon),
                                    dict(nctx.arrays)))
                            else:
                                rt2 = cfg.label_addr.get(nm2)
                                if rt2 is not None:
                                    work.append((rt2, nctx, ng2,
                                                 visits, frames))
                                else:
                                    terminals.append(TermPath(
                                        "ret", ng2, dict(nctx.canon),
                                        dict(nctx.arrays)))
                        continue
                # Dispatch token unresolvable.  If this path popped the
                # token via RETN_/RETF_, it is a return to an unknown
                # caller → `ret` terminal; otherwise it is a stale/foreign
                # `__disp` (entry arg, unmapped case) → `indirect_call`.
                diagnostics.append(
                    f"disp_unres:{addr:x}:{'ret' if ctx.retn_popped else 'fwd'}")
                terminals.append(TermPath(
                    "ret" if ctx.retn_popped else "indirect_call", cond,
                    dict(ctx.canon), dict(ctx.arrays)))
                continue
            if kind == "retterm":
                # Return-path trampoline: the game continuation is
                # re-dispatched by the runtime; function-level equivalent
                # of having returned.
                terminals.append(TermPath("ret", cond, dict(ctx.canon), dict(ctx.arrays)))
                continue
            if kind == "nop":
                work.append((resume, ctx, cond, visits, frames))
                continue
            if kind == "funcat":
                # func_at(lin): return a tagged fn ptr when the guest addr
                # resolves to a known (sub|loc)_* target; const 0 when the
                # addr is concrete but unmapped (func_at really returns
                # NULL → caller takes the else/return path); a
                # summary_funcat UF when the addr is symbolic.
                retreg = "eax" if cfg.arch == "i386" else "rax"
                rw = ctx.reg_versions[retreg].width
                arg = _host_arg(ctx, 0)
                aval = (constval(fold(ctx._concretize(arg)))
                        if arg is not None else None)
                fname = (_funcat_map(cfg).get(aval)
                         if aval is not None else None)
                if aval == 0:
                    fname = "rt_nullfn"
                if fname is not None:
                    ctx.reg_versions[retreg] = _c(_funcat_tag(cfg, fname), rw)
                elif aval is not None:
                    ctx.reg_versions[retreg] = _c(0, rw)
                else:
                    ctx.reg_versions[retreg] = E("summary_funcat", rw, (arg,))
                work.append((resume, ctx, cond, visits, frames))
                continue
            if kind == "hostret":
                # Host helper: opaque return value, no guest-state effect.
                retreg = "eax" if cfg.arch == "i386" else "rax"
                ctx.reg_versions[retreg] = inp(
                    f"hostret_{tname}", ctx.reg_versions[retreg].width)
                work.append((resume, ctx, cond, visits, frames))
                continue
            if tconst is None:
                # A summary_funcat(sym) callee: retry resolution — the arg
                # may concretize now even if it didn't at the call summary.
                if nxt.op == "summary_funcat" and len(nxt.args) == 1:
                    aval = constval(fold(ctx._concretize(nxt.args[0])))
                    fname = (_funcat_map(cfg).get(aval)
                             if aval is not None else None)
                    if aval == 0:
                        fname = "rt_nullfn"
                    if fname is None and aval is None:
                        # Sym-indexed jump table (jpt_*): enumerate the
                        # known-extent entries — path per table value
                        # under guard tbl[idx]==entry.
                        fmap = _funcat_map(cfg)
                        enum = _enum_jpt(
                            cfg, nxt.args[0],
                            valid=lambda ev: (0x1A20 + ev) in fmap)
                        if enum is not None:
                            lnode, entries = enum
                            diagnostics.append(
                                f"funcat_enum:{addr:x}:{len(entries)}")
                            for ev in entries:
                                nctx = _clone_ctx(ctx)
                                ng2 = fold(E("and", 1, (
                                    cond, E("eq", 1, (lnode, _c(ev, 16))))))
                                fname2 = _funcat_map(cfg).get(0x1A20 + ev)
                                if fname2 is None or fname2 == "rt_nullfn":
                                    # func_at returns NULL/rt_nullfn: the
                                    # caller's else path is `return`.
                                    terminals.append(TermPath(
                                        "ret", ng2,
                                        *_ret_boundary(cfg, nctx)))
                                elif fname2.startswith("sub_"):
                                    _boundary_call(nctx, fname2)
                                    work.append((resume, nctx, ng2,
                                                 visits, frames))
                                else:
                                    ftgt = cfg.proc_syms.get(fname2)
                                    if ftgt is not None:
                                        work.append((ftgt, nctx, ng2,
                                                     visits, frames))
                                    else:
                                        terminals.append(TermPath(
                                            "ret", ng2,
                                            *_ret_boundary(cfg, nctx)))
                            continue
                    if fname is not None:
                        tconst = _c(_funcat_tag(cfg, fname), nxt.width)
                        nxt = tconst
                        # Re-dispatch through the tag path above.
                        frev = cfg.funcat_rev
                        diagnostics.append(f"funcat:{addr:x}:{fname}")
                        if fname == "rt_nullfn":
                            work.append((resume, ctx, cond, visits, frames))
                        elif fname.startswith("sub_"):
                            _boundary_call(ctx, fname)
                            work.append((resume, ctx, cond, visits, frames))
                        else:
                            ftgt = cfg.proc_syms.get(fname)
                            if ftgt is not None:
                                work.append((ftgt, ctx, cond, visits, frames))
                            else:
                                terminals.append(TermPath(
                                    "indirect_call", cond, dict(ctx.canon),
                                    dict(ctx.arrays)))
                        continue
                # Indirect call to an unknown target (e.g. the port's
                # ``f_()`` far-vector dispatch): the callee and its return
                # are unmodeled — end the path honestly rather than
                # UF-clobbering canon and continuing.
                terminals.append(TermPath("indirect_call", cond,
                                          dict(ctx.canon), dict(ctx.arrays)))
                continue
            if kind == "gamecall":
                # Compositional boundary: callee verified by its own entry.
                _boundary_call(ctx, tname)
                if cfg.m2c and tname and tname.startswith("sub_"):
                    # Direct `sub_X(0,_state)` tramp calls (tail `return
                    # sub_X(..)`, dispatch-case `if(!sub_X(0))`) run the
                    # callee's guest retn, which pops one caller word.
                    # (`CALL_` pushes its own frame first — net 0 — and is
                    # summarized separately.)
                    _do_pop(ctx)
                work.append((resume, ctx, cond, visits, frames))
                continue
            if (kind in ("inline", "gamecall") and tconst is not None
                    and len(frames) < max_inline):
                nctx = _clone_ctx(ctx)
                nctx.bind_args = False  # callee args come via stk forwarding
                work.append((tconst.value, nctx, cond, visits,
                             frames + (resume,)))
                continue
            tag = apply_call(ctx, tconst)
            if tag.startswith("call_") or tag.endswith(("_unbound", "_unsupported")):
                diagnostics.append(f"call:{addr:x}:{tname or tname_const(tconst)}->{tag}")
            work.append((resume, ctx, cond, visits, frames))
            continue
        # Dispatch case-compare (`cmpl __disp, kTOKEN`): resolve __disp via
        # store forwarding and continue at the case's label body directly.
        # This collapses the whole compare chain into one edge; a symbolic
        # token (popped retaddr) is a return to an unknown caller.
        if cfg.m2c and cfg.ksub_map:
            disp_op = None
            for guard, _d in ctx.exits:
                # Match the *unfolded* guard: folding `sub(Ktok, Ktok)` to 0
                # would erase the token the match needs to recognize.
                t = _disp_case_operand(guard, cfg.ksub_map)
                if t is not None:
                    disp_op = t
                    break
            if disp_op is not None:
                dd = disp_op
                if dd.op in ("loadle", "loadbe") and len(dd.args) >= 2:
                    dd = forward_load(dd.args[0], fold(dd.args[1]), dd.width) or dd
                dd = fold(dd)
                name = cfg.ksub_map.get(dd.value) if dd.op == "const" else None
                if dd.op != "const" or name is not None:
                    # A real dispatch: operand resolved to a mapped token, or
                    # stayed symbolic (a popped retaddr to an unknown caller).
                    # An unmapped/zero operand is not a dispatch (e.g. the
                    # `if (__disp == 0)` entry check): leave disp_seen alone
                    # and take the block's normal edges.
                    first_dispatch = not ctx.disp_seen
                    ctx.disp_seen = True
                    diagnostics.append(
                        f"disp_hit:{addr:x}:{hex(dd.value) if dd.op=='const' else dd.op}")
                    if dd.op == "const":
                        if not first_dispatch and name.startswith("sub_"):
                            # Compositional call boundary: the callee gets
                            # opaque named outputs and "returns" by consuming
                            # the frame the caller pushed — [sp]=eip+2, plus
                            # cs at [sp+2] for CALLF frames (pushed cs is the
                            # const 0x1a2).
                            diagnostics.append(f"boundary:{name}")
                            _boundary_call(ctx, name)
                            sp16 = trunc(ctx.canon["esp"], 16)
                            sp32 = E("add", 32, (
                                E("shl", 32, (zext(ctx.canon["ss"], 32), _c(4, 32))),
                                zext(sp16, 32)))
                            eip_v = _do_pop(ctx)
                            up2 = E("add", 32, (sp32, _c(2, 32)))
                            probe = forward_load(ctx.arrays["data"], up2, 16)
                            cs_c = 0x1A2
                            if probe is not None and constval(fold(probe)) == 0x1A2:
                                cs_v = fold(_do_pop(ctx))
                                cs_c = constval(cs_v) or 0x1A2
                            e_c = constval(fold(eip_v))
                            rtok = ((cs_c << 16) | e_c) if e_c is not None else None
                            rname = cfg.ksub_map.get(rtok) if rtok is not None else None
                            rtgt = cfg.label_addr.get(rname) if rname else None
                            if rtgt is not None:
                                work.append((rtgt, ctx, cond, visits, frames))
                                continue
                            diagnostics.append(f"boundary_noresume:{name}")
                            terminals.append(TermPath("ret", cond, dict(ctx.canon), dict(ctx.arrays)))
                            continue
                        tgt = cfg.label_addr.get(name)
                        if tgt is not None:
                            work.append((tgt, ctx, cond, visits, frames))
                            continue
                        # Mapped token with no label: seed the slot so the
                        # compare chain folds to a linear walk to default:.
                        if disp_op.op in ("loadle", "loadbe") and len(disp_op.args) >= 2:
                            ctx.store(ctx.arrays["stk"], disp_op.args[1], dd)
                    elif ctx.retn_popped:
                        # Symbolic token popped by RETN_/RETF_: a return to
                        # an unknown caller — terminal `ret`, never a jump
                        # into a case body.
                        terminals.append(TermPath("ret", cond, dict(ctx.canon), dict(ctx.arrays)))
                        continue
                    else:
                        diagnostics.append(f"disp_sym:{addr:x}")
                        terminals.append(TermPath("indirect_call", cond, dict(ctx.canon), dict(ctx.arrays)))
                        continue
        edges: list[tuple[int, S.SsaExpr]] = []
        exit_guards: list[S.SsaExpr] = []
        for guard, dst in ctx.exits:
            d, g = fold(dst), fold(guard)
            if g.op == "const" and g.value == 0:
                continue
            if d.op == "const":
                edges.append((d.value, g))
                exit_guards.append(g)
            else:
                diagnostics.append(f"indirect_exit:{addr:x}")
        if nxt.op != "const":
            # Tail-position vfn call (`jmp *f_` where f_ = func_at(lin)):
            # dispatch the funcat target — sub_* = boundary + ret (the
            # callee returns on our behalf), loc_* = continuation jump.
            if nxt.op == "summary_funcat" and len(nxt.args) == 1:
                aval = constval(fold(ctx._concretize(nxt.args[0])))
                enum0 = None
                cands: list[tuple[S.SsaExpr, str]] = []
                if aval is not None:
                    nm = "rt_nullfn" if aval == 0 else _funcat_map(cfg).get(aval)
                    if nm is not None:
                        cands.append((E("const", 1, value=1), nm))
                else:
                    fmap0 = _funcat_map(cfg)
                    enum0 = _enum_jpt(
                        cfg, nxt.args[0],
                        valid=lambda ev: (0x1A20 + ev) in fmap0)
                    if enum0 is not None:
                        lnode, entries = enum0
                        for ev in entries:
                            nm = _funcat_map(cfg).get(0x1A20 + ev)
                            if nm is not None:
                                cands.append((E("eq", 1, (lnode, _c(ev, 16))), nm))
                if cands:
                    diagnostics.append(f"funcat_jmp:{addr:x}:{len(cands)}")
                    for g0, nm in cands:
                        nctx = _clone_ctx(ctx)
                        ng2 = fold(E("and", 1, (cond, g0)))
                        if nm == "rt_nullfn" or nm.startswith("sub_"):
                            if nm != "rt_nullfn":
                                _boundary_call(nctx, nm)
                            terminals.append(TermPath(
                                "ret", ng2, *_ret_boundary(cfg, nctx)))
                        else:
                            ft = cfg.proc_syms.get(nm)
                            if ft is not None:
                                work.append((ft, nctx, ng2, visits, frames))
                            else:
                                terminals.append(TermPath(
                                    "ret", ng2, *_ret_boundary(cfg, nctx)))
                    continue
                _dbg = nxt.args[0]
                _st = [_dbg]
                while _st:
                    _n = _st.pop()
                    if _n.op in ("loadle", "loadbe") and len(_n.args) == 2:
                        _dbg = _n.args[1]
                        break
                    _st.extend(_n.args)
                diagnostics.append(
                    f"funcat_unres:{addr:x}:idx={repr(_dbg)[:300]}"
                    f":enum={'none' if enum0 is None else enum0[1]}")
                terminals.append(TermPath("indirect", cond, dict(ctx.canon),
                                          dict(ctx.arrays)))
                continue
            # A symbolic jump target on a path that popped its return token
            # (m2c `switch(__disp)` over a popped retaddr) is a return to an
            # unknown caller — not a fan-in to arbitrary case bodies.
            if cfg.m2c and ctx.retn_popped:
                diagnostics.append(f"jpt_popped:{addr:x}")
                terminals.append(TermPath("ret", cond, dict(ctx.canon),
                                          dict(ctx.arrays)))
                continue
            # PIC jump table with symbolic index (`jmp *tbl[idx]`):
            # enumerate known-extent table entries — one edge per host
            # target under guard tbl[idx]==addr.
            enum = _enum_jpt(cfg, nxt)
            if enum is not None:
                lnode, entries = enum
                diagnostics.append(f"jpt_enum:{addr:x}:{len(entries)}")
                for ev in entries:
                    if not (cfg.text_lo <= ev < cfg.text_hi):
                        continue
                    nctx = _clone_ctx(ctx)
                    ng2 = fold(E("and", 1, (
                        cond, E("eq", 1, (lnode, _c(ev, lnode.width))))))
                    work.append((ev, nctx, ng2, visits, frames))
                continue
            diagnostics.append(f"indirect:{addr:x}:{repr(nxt)[:140]}")
            terminals.append(TermPath("indirect", cond, dict(ctx.canon), dict(ctx.arrays)))
            continue
        # The implicit fallthrough edge is reachable only when every
        # conditional Exit failed: guard it with ``not(or(exit_guards))``.
        if exit_guards:
            dg = (exit_guards[0] if len(exit_guards) == 1
                  else E("or", 1, tuple(exit_guards)))
            dg = fold(E("not", 1, (dg,)))
            if not (dg.op == "const" and dg.value == 0):
                edges.append((nxt.value, dg))
        else:
            edges.append((nxt.value, E("const", 1, value=1)))
        if len(edges) > 1:
            SPLITS[addr] += len(edges) - 1
            if DBG_ADDR is not None and addr == DBG_ADDR:
                for _d0, _g0 in edges:
                    def _sh(x, dep=0):
                        if dep > 9:
                            return
                        print("  " * dep + f"{x.op} w={x.width} "
                              f"v={hex(x.value) if x.op == 'const' else ''} {x.name or ''}")
                        for _a in x.args:
                            _sh(_a, dep + 1)
                    print(f"=== split guard @{addr:#x} -> {_d0:#x}")
                    _sh(_g0)
        for d, g in edges:
            ng = cond if g.op == "const" and g.value == 1 else E("and", 1, (cond, g))
            # Tail-position jump to another proc's entry (TCO `jmp sub_X` =
            # call + return): same contract as a near call — boundary-UF the
            # callee and end the path at the ret boundary.  loc_* targets
            # are in-function continuations and keep their inline path.
            tn_ = cfg.addr2name.get(d)
            if (tn_ is not None and tn_.startswith("sub_")
                    and cfg.proc_syms.get(tn_) == d and d != entry):
                nctx = _clone_ctx(ctx)
                diagnostics.append(f"tailcall:{addr:x}:{tn_}")
                _boundary_call(nctx, tn_)
                if cfg.m2c:
                    # Guest tail `jmp` — the callee's retn consumes the
                    # caller-pushed frame (same pop as a direct tramp call).
                    _do_pop(nctx)
                    terminals.append(TermPath("ret", ng, dict(nctx.canon),
                                              dict(nctx.arrays)))
                else:
                    terminals.append(TermPath("ret", ng,
                                              *_ret_boundary(cfg, nctx)))
                continue
            if cfg.text_lo <= d < cfg.text_hi:
                work.append((d, _clone_ctx(ctx), ng, visits, frames))
            elif d in cfg.addr2name:
                nctx = _clone_ctx(ctx)
                apply_call(nctx, E("const", 32, value=d))
                terminals.append(TermPath("tail", ng, dict(nctx.canon), dict(nctx.arrays)))
            else:
                terminals.append(TermPath("tail", ng, dict(ctx.canon), dict(ctx.arrays)))
    if incomplete:
        diagnostics.append(f"incomplete_paths:{incomplete}")
    return terminals, diagnostics, seed_hit


def _is_helper_addr(cfg: SideConfig, addr: int) -> bool:
    n = cfg.addr2name.get(addr)
    return bool(n and not n.startswith(("sub_", "loc_")))


def _classify_call(cfg: SideConfig, tname: str | None) -> str:
    if tname is None:
        return "uf"
    if cfg.m2c:
        return _m2c_helper_kind(tname)
    return _port_helper_kind(tname)


def tname_const(t: S.SsaExpr | None) -> str:
    return hex(t.value) if t is not None and t.op == "const" else "sym"


# ---------------------------------------------------------------------------
# Terminal merge + canonical output record
# ---------------------------------------------------------------------------

def merge_outputs(paths: list[TermPath]) -> dict[str, S.SsaExpr]:
    """Fold all terminal paths into one output dict via path-condition ites."""
    if not paths:
        return {}
    merged: dict[str, S.SsaExpr] = {}
    keys = CANON_OUTPUTS
    # Only normal-return paths contribute outputs: abort (stack-check,
    # assert), indirect, indirect_call, and tail (edge to an out-of-text
    # PLT/runtime target) terminals are exceptional exits whose canon does
    # not describe a function result.
    rets = [p for p in paths if p.kind == "ret"]
    if not rets:
        return {}
    for key in keys:
        term = None
        for p in rets:
            src = p.arrays[key] if key in ("data", "io") else p.canon[key[2:]]
            if term is None:
                term = src
            else:
                w = src.width
                # ite(cond, X, X) == X: skip when the path left the cell as the
                # same object — keeps unchanged outputs as plain inputs.
                if src is not term and term.width == w:
                    term = E("ite", w, (p.cond, src, term))
        if term is not None:
            merged[key] = fold(term)
    return merged


def materialize_outputs(merged: dict[str, S.SsaExpr]) -> dict[str, Any]:
    """Emit a dosunit-shaped function record for S._compare_functions."""
    assignments: list[dict[str, Any]] = []
    memo: dict[tuple[Any, ...], str] = {}
    outputs = {
        name: S._materialize(expr, assignments=assignments, memo=memo,
                             object_memo={}, max_assignments_per_function=200000)
        for name, expr in merged.items()
    }
    inputs = _collect_all_inputs(tuple(merged.values()))
    return {"outputs": outputs, "assignments": assignments,
            "inputs": inputs}


def _collect_all_inputs(exprs: tuple) -> list[dict[str, Any]]:
    """Collect input/mem_input leaves -> dosunit input items."""
    found: dict[str, int] = {}
    mems: set[str] = set()
    seen: set[int] = set()
    stack = list(exprs)
    while stack:
        e = stack.pop()
        if id(e) in seen:
            continue
        seen.add(id(e))
        if e.op == "input" and e.name:
            found[e.name] = max(e.width, found.get(e.name, 0))
        elif e.op == "mem_input" and e.name:
            mems.add(e.name)
        stack.extend(e.args)
    items = [{"name": n, "width": w} for n, w in sorted(found.items())]
    items += [{"kind": "memory", "name": n, "addr_width": 32, "value_width": 8}
              for n in sorted(mems)]
    return items


# ---------------------------------------------------------------------------
# Binary extraction (symbols, refs, DWARF lines, dispatch tails)
# ---------------------------------------------------------------------------

def _demangle_local(name: str) -> str:
    """Reduce a mangled C++ name to a comparable basename.

    The match must sit at a non-identifier boundary (start, digit length
    prefix, ``::``, ``@``): port symbols like ``tw_tnd_sub_106d7`` are
    TANDYSND-overlay thunks whose embedded ``sub_`` belongs to a different
    program and must not alias AR.EXE's ``sub_106d7``.
    """
    m = re.search(r"(?:^|[^A-Za-z_])(sub_[0-9a-f]+|loc_[0-9a-f]+|seg000_[0-9a-f]+_proc|nullsub_\d+|_group\d+|asm2C_\w+|eflagsC\d?|get[A-Z]{2}|PUSH_|POP_|CALL_|RETN_|RETF_|JMP_|INT_|IN_|OUT_)", name)
    if m:
        return m.group(1)
    return name


def _nm_symbols(path: str) -> tuple[dict[str, tuple[int, int]], set[str]]:
    """name -> (addr, end) from nm, plus the set of global-binding names.

    Local symbols matter for the port side: generated labels like
    ``sub_1040b:`` inside TANDYSND functions collide with AR.EXE proc names,
    so callers can restrict to globals when the name set must be AR-only.
    """
    out: dict[str, tuple[int, int]] = {}
    globals_: set[str] = set()
    syms: list[tuple[int, str]] = []
    p = subprocess.run(["nm", "-n", "--defined-only", path],
                       capture_output=True, text=True)
    for line in p.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and all(c in "0123456789abcdefABCDEF" for c in parts[0]):
            try:
                a = int(parts[0], 16)
            except ValueError:
                continue
            syms.append((a, parts[2]))
            if parts[1].isupper():
                globals_.add(parts[2])
    for i, (a, n) in enumerate(syms):
        end = syms[i + 1][0] if i + 1 < len(syms) else a + 0x400
        out.setdefault(n, (a, end))
    # PLT stubs carry the callee name only in the disassembly header
    # (`00003130 <abort@plt>:`); nm shows the import as undefined.
    p = subprocess.run(["objdump", "-d", "-j", ".plt", path],
                       capture_output=True, text=True)
    for m in re.finditer(r"(?m)^([0-9a-fA-F]+)\s*<([^>]+)>:", p.stdout):
        name = m.group(2).replace("@plt", "")
        out.setdefault(name, (int(m.group(1), 16), int(m.group(1), 16) + 0x10))
        globals_.add(name)
    return out, globals_


def _refmap_from_source(srcdir: Path) -> dict[str, int]:
    """Parse m2c data references -> canonical data (m2c::m) byte offsets.

    Handles the generated shapes::

        db& seg002 = *((db*)&m2c::m+0xe8a0);
        dw& word_20d4a = *((dw*)(&seg002+0x1c8aa));
        db (& arr)[5] = *((db(*)[5])(&seg002+0xc89c));
    """
    T = r"(?:db|dw|dd)"
    seg_pat = re.compile(
        rf"^{T}&\s*(\w+)\s*=\s*\*\(\s*\(\s*{T}\s*\*\s*\)\s*&?\s*m2c::m"
        rf"\s*\+\s*(0x[0-9a-fA-F]+|0)\s*\)")
    ref_pat = re.compile(
        rf"^{T}&\s*(\w+)\s*=\s*\*\(\s*\(\s*{T}\s*\*\s*\)\s*"
        rf"\(\s*&?(\w+)\s*([+-])\s*(0x[0-9a-fA-F]+)\s*\)\s*\)")
    arr_pat = re.compile(
        rf"^{T}\s*\(\s*&\s*(\w+)\s*\)\s*\[\d+\]\s*=\s*\*\(\s*\(\s*{T}\s*\(\s*\*\s*\)"
        rf"\s*\[\d+\]\s*\)\s*\(\s*&?(\w+)\s*([+-])\s*(0x[0-9a-fA-F]+)\s*\)\s*\)")
    segs: dict[str, int] = {}
    refs: dict[str, int] = {}
    files = sorted(srcdir.glob("_data_refs_*.cpp")) + [srcdir / "_data.cpp"]
    texts = []
    for f in files:
        if f.exists():
            texts.append(f.read_text(errors="replace").splitlines())
    for lines in texts:
        for line in lines:
            m = seg_pat.match(line.strip())
            if m:
                segs[m.group(1)] = int(m.group(2), 16)
    for lines in texts:
        for line in lines:
            s = line.strip()
            for pat in (ref_pat, arr_pat):
                m = pat.match(s)
                if m and m.group(2) in segs:
                    off = int(m.group(4), 16)
                    refs[m.group(1)] = segs[m.group(2)] + (-off if m.group(3) == "-" else off)
                    break
    refs.update(segs)
    return refs


def _ksub_map(srcdir: Path) -> dict[int, str]:
    out: dict[int, str] = {}
    for f in list(srcdir.glob("*.h")) + list(srcdir.glob("*.cpp")):
        try:
            txt = f.read_text(errors="replace")
        except OSError:
            continue
        for m in re.finditer(r"(ksub_|kloc_)(\w+)\s*=\s*\(?\s*(0x[0-9a-fA-F]+)", txt):
            pref = "sub_" if m.group(1) == "ksub_" else "loc_"
            v = int(m.group(3), 16)
            # Dispatch tokens are (seg<<16)|off (e.g. 0x1a21b84); the _offsets
            # enum also carries small ordinals for the same names — keep only
            # the token-form values.
            if v > 0xFFFF:
                out[v] = pref + m.group(2)
    return out


def load_side(path: str, m2c: bool, srcdir: Path | None = None) -> SideConfig:
    global CTX
    if not REGMAP:
        _build_regmap()
    install_hooks()
    project = angr.Project(path, auto_load_libs=False, load_debug_info=False)
    obj = project.loader.main_object
    base = obj.mapped_base if getattr(obj, "pic", False) else 0
    raw_syms, elf_globals = _nm_symbols(path)
    syms = {n: (a + base, e + base) for n, (a, e) in raw_syms.items()}
    addr2name: dict[int, str] = {a: _demangle_local(n) for n, (a, _e) in syms.items()}
    text_lo, text_hi = 0, 0
    for s in obj.sections:
        if s.name == ".text":
            text_lo, text_hi = s.vaddr, s.vaddr + s.memsize
    cfg = SideConfig(name=Path(path).name, arch="i386" if m2c else "amd64",
                     project=project, symbols=syms, addr2name=addr2name,
                     m2c=m2c, data_base=0, data_size=0,
                     text_lo=text_lo, text_hi=text_hi)
    for n, (a, _e) in syms.items():
        if not m2c and n not in elf_globals:
            # Port-side locals are internal labels (e.g. ``sub_1040b:`` inside
            # a TANDYSND function) that alias AR proc names — globals only.
            continue
        dm = _demangle_local(n)
        if re.match(r"^(sub|loc)_[0-9a-f]+$|^(sub|loc)_[0-9a-f]+\(.*", dm) or dm.startswith(("sub_", "loc_")):
            canon = re.match(r"^((?:sub|loc)_[0-9a-f]+)", dm)
            if canon:
                cfg.proc_syms.setdefault(canon.group(1), a)
    if m2c:
        m = syms.get("_ZN3m2c1mE")
        cfg.data_base = m[0] if m else 0
        cfg.data_size = 0x200000  # m2c::m spans the game image + scratch
        cfg.ksub_map = _ksub_map(srcdir) if srcdir else {}
        if srcdir:
            refsrc = _refmap_from_source(srcdir)
            for rname, off in refsrc.items():
                if rname in syms:
                    cfg.refmap[syms[rname][0]] = off
        a2l = {a + base: fl for a, fl in _dwarf_line_map(path).items()}
        cfg.dispatch_addrs = _dispatch_addrs(a2l, srcdir)
        cfg.label_addr = _label_addrs(a2l, srcdir)
    else:
        memsym = syms.get("mem")
        cfg.data_base = memsym[0] if memsym else 0
        cfg.data_size = 1 << 20
        im = syms.get("img")
        if im:
            cfg.img_addr, cfg.img_size = im[0], im[1] - im[0]
        for nm_, canon in (("eax", "eax"), ("ebx", "ebx"), ("ecx", "ecx"),
                           ("edx", "edx"), ("esi", "esi"), ("edi", "edi"),
                           ("esp", "esp"), ("ebp", "ebp")):
            if nm_ in syms:
                cfg.reg_globals[syms[nm_][0]] = canon
        for nm_, canon in (("cs", "cs"), ("ds", "ds"), ("es", "es"),
                           ("fs", "fs"), ("gs", "gs"), ("ss", "ss"), ("ip", "eip")):
            if nm_ in syms:
                cfg.seg_globals[syms[nm_][0]] = canon
        for nm_, canon in (("CF", "cf"), ("PF", "pf"), ("AF", "af"), ("ZF", "zf"),
                           ("SF", "sf"), ("DF", "df"), ("OF", "of"),
                           ("IF", "if_"), ("TF", "tf")):
            if nm_ in syms:
                cfg.flag_globals[syms[nm_][0]] = canon
    return cfg


def _dwarf_line_map(path: str) -> dict[int, tuple[str, int]]:
    """addr -> (file basename, source line) via `readelf --decodedline`."""
    out: dict[int, tuple[str, int]] = {}
    p = subprocess.run(["readelf", "-W", "--debug-dump=decodedline", path],
                       capture_output=True, text=True)
    for line in p.stdout.splitlines():
        m = re.match(r"^(\S+)\s+(\d+)\s+(0x[0-9a-fA-F]+)\b", line.strip())
        if m:
            out[int(m.group(3), 16)] = (m.group(1), int(m.group(2)))
    return out


def _dispatch_addrs(a2l: dict[int, tuple[str, int]], srcdir: Path | None) -> frozenset[int]:
    """Machine addr of the `switch(__disp)` head following each `__dispatch_call:` label.

    Only the label's head block is a dispatch point: it is reached while the
    recorded ``__disp`` store is still the last host-local write.  The case
    chain beyond it is ordinary code.
    """
    if srcdir is None:
        return frozenset()
    label_lines: dict[str, list[int]] = {}
    for f in srcdir.glob("*.cpp"):
        try:
            for i, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
                if re.match(r"^\s*__dispatch_call\w*:", line):
                    label_lines.setdefault(f.name, []).append(i)
        except OSError:
            continue
    if not label_lines:
        return frozenset()
    out: set[int] = set()
    for fname, lines in label_lines.items():
        for i in lines:
            win = {l for l in range(i + 1, i + 17)}
            cand = [a for a, (fn, l) in a2l.items() if fn == fname and l in win]
            if cand:
                out.add(min(cand))
    return frozenset(out)


def _label_addrs(a2l: dict[int, tuple[str, int]], srcdir: Path | None) -> dict[str, int]:
    """Machine addr of the first statement after each `name:` label."""
    if srcdir is None:
        return {}
    labels: dict[str, tuple[str, int]] = {}
    for f in srcdir.glob("*.cpp"):
        try:
            lines = f.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            m = re.match(r"^\s*((?:sub|loc)_[0-9a-f]+):", line)
            if m and m.group(1) not in labels:
                labels[m.group(1)] = (f.name, i)
    if not labels:
        return {}
    by_line: dict[tuple[str, int], int] = {}
    for a, (fn, l) in sorted(a2l.items()):
        by_line.setdefault((fn, l), a)
    out = {}
    for name, (fn, lno) in labels.items():
        for l in range(lno, lno + 8):
            if (fn, l) in by_line:
                out[name] = by_line[(fn, l)]
                break
    return out


# ---------------------------------------------------------------------------
# Per-function comparison driver
# ---------------------------------------------------------------------------

OUTPUT_KEYS = [f"g_{r}" for r in CANON_REGS32] + \
    [f"s_{s}" for s in CANON_SEGS] + [f"f_{f}" for f in CANON_FLAGS] + ["data", "io"]


def _has_op(e: S.SsaExpr, op: str, limit: int = 4096) -> bool:
    """True iff any node in ``e`` uses ``op`` (bounded structural walk)."""
    stack = [e]
    seen = 0
    while stack and seen < limit:
        n = stack.pop()
        seen += 1
        if n.op == op:
            return True
        stack.extend(n.args)
    return False


def compare_function(name: str, oracle_cfg: SideConfig, cand_cfg: SideConfig,
                     *, timeout_ms: int = 10000, budgets: dict | None = None) -> dict[str, Any]:
    """Run SE on both sides, materialize canonical outputs, invoke Z3."""
    budgets = budgets or {}
    rec: dict[str, Any] = {"function": name, "oracle": {}, "candidate": {}}
    docs: list[dict[str, Any] | None] = []
    merged_sides: list[dict[str, S.SsaExpr] | None] = []
    for side, cfg in (("oracle", oracle_cfg), ("candidate", cand_cfg)):
        entry = cfg.proc_syms.get(name) or cfg.label_addr.get(name)
        if entry is None:
            rec[side] = {"status": "refused", "reason": "no_symbol"}
            docs.append(None)
            merged_sides.append(None)
            continue
        terms, diags, _seed = execute(cfg, entry, (cfg.text_lo, cfg.text_hi),
                                      dispatch_addrs=cfg.dispatch_addrs,
                                      **budgets)
        merged = merge_outputs(terms)
        rec[side] = {"diagnostics": diags,
                     "terminals": len(terms),
                     "terminal_kinds": sorted({t.kind for t in terms})}
        if not merged:
            rec[side]["status"] = "refused"
            rec[side]["reason"] = "no_terminals"
            docs.append(None)
            merged_sides.append(None)
            continue
        merged_sides.append(merged)
        docs.append(None)
    if merged_sides[0] is None or merged_sides[1] is None:
        rec["status"] = "refused"
        rec["reason"] = "extraction_failed"
        return rec
    om, cm = merged_sides[0], merged_sides[1]
    # Flags the port never materializes (demand-driven flag model: e.g. `while
    # (al==0)` consumes `al` without storing ZF) stay `input[f_*]` on the
    # candidate side — they are unverifiable, not wrong.  Report them as
    # unmodeled rather than feeding the solver an unsatisfiable diff.
    # (Must run before neq0 normalization, which wraps `input` ops.)
    unmodeled = []
    for k in list(cm):
        if k.startswith("f_") and (cm[k].op == "input" and cm[k].name == k
                                   or om[k].op == "input" and om[k].name == k):
            unmodeled.append(k)
            del om[k]
            del cm[k]
    if unmodeled:
        rec["unmodeled_flag_outputs"] = sorted(unmodeled)
    # `unsupported` leaves mark IR the lifter could not model (dynamic cc_op,
    # exotic instructions). They cannot be translated to Z3 at all, so cells
    # containing them are unverifiable — quarantine and report, like flags.
    unsup = []
    for k in list(om):
        if k in cm and (_has_op(om[k], "unsupported")
                        or _has_op(cm[k], "unsupported")):
            unsup.append(k)
            del om[k]
            del cm[k]
    if unsup:
        rec["unsupported_outputs"] = sorted(unsup)
    # Flags are canonical booleans: a side that stores a truthy byte (0xff)
    # and a side that stores 1 mean the same thing.  Normalize both sides'
    # flag cells through !=0 before presolve/compare.
    for m in (om, cm):
        for k in list(m):
            if k.startswith("f_"):
                m[k] = fold(neq0(m[k]))
    # Pre-solve cheap equality: outputs whose SsaExpr is structurally identical
    # on both sides cannot contribute a counterexample — drop them so the
    # solver only sees genuinely different expressions.
    kmo: dict[int, tuple] = {}
    kmc: dict[int, tuple] = {}
    identical = []
    for k in om:
        if k in cm:
            kb = [4_000_000]
            if _expr_key(om[k], kmo, kb) == _expr_key(cm[k], kmc, kb):
                identical.append(k)
    for k in identical:
        del om[k]
        del cm[k]
    if identical:
        rec["identical_outputs"] = sorted(identical)
    odiag = rec["oracle"].get("diagnostics", [])
    cdiag = rec["candidate"].get("diagnostics", [])
    paths_incomplete = any(d.startswith(("incomplete_paths", "step_budget", "path_budget"))
                           for d in odiag + cdiag)
    if not om:
        rec["status"] = "incomplete" if paths_incomplete else "passed"
        rec["reason"] = "all_outputs_identical" + (" (paths truncated)" if paths_incomplete else "")
        return rec
    docs = [materialize_outputs(m) for m in (om, cm)]
    try:
        comparison = S._compare_functions(docs[0], docs[1], timeout_ms=timeout_ms)
    except (DosUnitError, KeyError, ValueError) as ex:
        rec["status"] = "refused"
        rec["reason"] = f"z3_error:{type(ex).__name__}:{str(ex)[:120]}"
        return rec
    rec["status"] = comparison.get("status")
    if rec["status"] == "passed" and paths_incomplete:
        rec["status"] = "incomplete"
        rec["reason"] = "outputs_equal_on_explored_paths"
    else:
        rec["reason"] = comparison.get("reason")
    rec["mismatches"] = comparison.get("mismatches", [])[:20]
    rec["solver_time_ms"] = comparison.get("solver_time_ms")
    rec["skipped_layout_outputs"] = comparison.get("skipped_layout_outputs")
    return rec


def main() -> int:
    ap = argparse.ArgumentParser(description="cross-ABI SSA/Z3 comparator ar_m2c <-> ar_port")
    ap.add_argument("--oracle", default="/home/xor/games/airborn/build_sdl/ar_m2c")
    ap.add_argument("--cand", default="/home/xor/games/airborn/port/ar_port")
    ap.add_argument("--srcdir", default="/home/xor/games/airborn",
                    help="masm2c generated-source dir (for ref/ksub maps)")
    ap.add_argument("--func", action="append", help="function name(s) to compare")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--timeout-ms", type=int, default=10000)
    ap.add_argument("-o", "--out", default="")
    args = ap.parse_args()

    _build_regmap()
    install_hooks()
    oracle = load_side(args.oracle, m2c=True, srcdir=Path(args.srcdir))
    cand = load_side(args.cand, m2c=False)
    if args.func:
        names = args.func
    else:
        common = sorted(set(oracle.proc_syms) & set(cand.proc_syms))
        names = common[: args.limit] if args.limit else common
    results = []
    for i, n in enumerate(names):
        rec = compare_function(n, oracle, cand, timeout_ms=args.timeout_ms)
        results.append(rec)
        print(f"[{i+1}/{len(names)}] {n}: {rec.get('status')} {rec.get('reason') or ''}",
              flush=True)
    summary = {"total": len(results),
               "passed": sum(1 for r in results if r.get("status") == "passed"),
               "failed": sum(1 for r in results if r.get("status") == "failed"),
               "incomplete": sum(1 for r in results if r.get("status") == "incomplete"),
               "refused": sum(1 for r in results if r.get("status") == "refused"),
               "results": results}
    out = args.out or "aircmp-results.json"
    Path(out).write_text(json.dumps(summary, indent=1, default=str))
    print(f"wrote {out}: {summary['passed']} passed / {summary['failed']} failed / "
          f"{summary['incomplete']} incomplete / {summary['refused']} refused")
    return 0


def install_hooks() -> None:
    if _ORIG:
        return
    for attr, fn in (("_lower_expr", hooked_expr),
                     ("_lower_vex_load", hooked_load),
                     ("_read_register", hooked_read_register),
                     ("_write_register", hooked_write_register),
                     ("_register_write_target", hooked_write_target)):
        _ORIG[attr] = getattr(S, attr)
        setattr(S, attr, fn)


if __name__ == "__main__":
    raise SystemExit(main())
