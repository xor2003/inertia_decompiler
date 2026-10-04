#!/usr/bin/env python3
"""Loader for libdosbox run-time info JSON.

libdosbox (inertia_player) records executed instructions, segment register
values, data accesses, pointer evidence and call/abi summaries while a DOS
program runs, then dumps them to <exe>.json on exit.  This module maps that
JSON into the same analysis tables the IDC engine populates:

    Code            -> code_seeds, sreg_ranges, comments (exec counts/edges)
    Code Edges/CALL -> functions (+ code_seeds for every edge target)
    Data            -> data_items, comments, strlit markers
    PointerEvidence -> data_items (word/dword), functions for code targets
    AccessSites     -> data_items arrays
    Jumps/FunctionSampling/Abi -> functions, comments

DOSBox addresses are absolute linear addresses; they are translated into the
image address space using Meta.DosboxLoadSeg (default 0x1A2):
    ada_addr = dbx_addr + (image_base - dosbox_load_seg * 16)
"""

import json
import logging

log = logging.getLogger(__name__)

_SEGS = ('cs', 'ds', 'es', 'ss', 'fs', 'gs')

# EdgeKinds / ValueTargetClasses bit flags (libdosbox custom.h)
_EDGE_JMP = 1 << 0
_EDGE_CALL = 1 << 1
_EDGE_RET = 1 << 2
_EDGE_JCC = 1 << 3
_RT_DATA_OFFSET = 1 << 0
_RT_CODE_OFFSET = 1 << 1
_RT_STRING = 1 << 2
_RT_FAR_POINTER = 1 << 4

_ITEM = {1: 'byte', 2: 'word', 4: 'dword', 8: 'qword'}


def _addr(v):
    """Parse a JSON address: int or '0x..'/'..' string."""
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v, 0)
        except ValueError:
            try:
                return int(v, 16)
            except ValueError:
                return None
    return None


def _int(v, default=0):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _pairs(v):
    """Yield (key, value) from a JSON object or a list of [key, value] pairs
    (nlohmann serializes maps with integer keys as pair arrays)."""
    if isinstance(v, dict):
        yield from v.items()
    elif isinstance(v, list):
        for item in v:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                yield item[0], item[1]


def load_runtime_json(path, db):
    """Apply a libdosbox run-time info JSON file to the analysis database.

    Returns the number of rows applied (seeds + sregs + funcs + data + cmts).
    """
    with open(path, 'r') as f:
        j = json.load(f)
    if not isinstance(j, dict):
        raise ValueError(f"{path}: runtime info must be a JSON object")

    meta = j.get('Meta') or {}
    loadseg = _int(meta.get('DosboxLoadSeg'), 0x1A2)
    delta = db.image_base - (loadseg << 4)      # linear-addr shift
    sdelta = (db.image_base >> 4) - loadseg     # segment-para shift
    lo, hi = db.image_base, db.image_base + db.image_size

    def lin(v):
        a = _addr(v)
        return None if a is None else a + delta

    def in_image(a):
        return a is not None and lo <= a < hi

    seeds, sregs, funcs, items, cmts = set(), [], set(), {}, {}

    # ---- executed code ------------------------------------------------
    for key, ins in (j.get('Code') or {}).items():
        a = lin(key)
        if not in_image(a) or not isinstance(ins, dict):
            continue
        seeds.add(a)
        for reg in _SEGS:
            vals = ins.get(reg)
            if isinstance(vals, list) and len(vals) == 1:
                sregs.append((a, -1, reg, _int(vals[0]) + sdelta))
        for dst, mask in _pairs(ins.get('EdgeKinds')):
            t = lin(dst)
            if not in_image(t):
                continue
            seeds.add(t)
            if _int(mask) & _EDGE_CALL:
                funcs.add(t)
        detail = []
        if ins.get('ExecCount'):
            detail.append(f"exec={_int(ins['ExecCount'])}")
        if ins.get('Video'):
            detail.append('video=1')
        if ins.get('Self'):
            detail.append('selfmod=1')
        if detail:
            cmts[a] = 'RT code: ' + ' '.join(detail)

    # ---- data accesses -------------------------------------------------
    for key, d in (j.get('Data') or {}).items():
        a = lin(key)
        if not in_image(a) or not isinstance(d, dict):
            continue
        sizes = (set(map(_int, d.get('Sizes') or ())) |
                 set(map(_int, d.get('ReadSizes') or ())) |
                 set(map(_int, d.get('WriteSizes') or ())))
        sizes &= {1, 2, 4}
        if len(sizes) == 1 and not d.get('Array'):
            sz = sizes.pop()
            items[a] = (sz, _ITEM[sz], 1)
        # pointers stored at this location
        cls_map = {str(_addr(k)): _int(v)
                   for k, v in _pairs(d.get('ValueTargetClasses'))}
        for tkey, _cnt in _pairs(d.get('ValueTargets')):
            t = lin(tkey)
            if not in_image(t):
                continue
            cls = _int(cls_map.get(str(_addr(tkey)), 0))
            if cls & _RT_CODE_OFFSET:
                seeds.add(t)
            elif cls & _RT_STRING:
                items.setdefault(t, (1, 'str', 1))
            elif cls & (_RT_DATA_OFFSET | _RT_FAR_POINTER):
                items.setdefault(t, (1, 'byte', 1))
        rc, wc = _int(d.get('ReadCount')), _int(d.get('WriteCount'))
        if rc or wc:
            cmts.setdefault(a, f"RT data: r={rc} w={wc} "
                               f"sizes={sorted(sizes)}")

    # ---- pointer evidence ----------------------------------------------
    for ev in (j.get('PointerEvidence') or {}).values():
        if not isinstance(ev, dict):
            continue
        src, tgt = lin(ev.get('SourceAddr')), lin(ev.get('TargetAddr'))
        flags = _int(ev.get('Flags'))
        if in_image(src):
            sz = 4 if flags & _RT_FAR_POINTER else min(_int(ev.get('Size'), 2), 4)
            items[src] = (sz, _ITEM[sz], 1)
        if in_image(tgt):
            if flags & _RT_CODE_OFFSET:
                seeds.add(tgt)
                funcs.add(tgt)
            elif flags & _RT_STRING:
                items.setdefault(tgt, (1, 'str', 1))
            else:
                items.setdefault(tgt, (1, 'byte', 1))

    # ---- compact array access sites -------------------------------------
    for site in (j.get('AccessSites') or {}).values():
        if not isinstance(site, dict):
            continue
        mn, mx = lin(site.get('MinAddr')), lin(site.get('MaxAddr'))
        mask = _int(site.get('SizeMask'))
        sizes = [s for s in (1, 2, 4, 8) if mask & (1 << s)]
        if not in_image(mn) or mx is None or mx <= mn or len(sizes) != 1:
            continue
        esz = sizes[0]
        if _int(site.get('GcdDelta')) not in (0, esz):
            continue
        count = (mx - mn) // esz + 1
        if 1 < count <= 0x10000 and esz in _ITEM:
            items[mn] = (esz, _ITEM[esz], count)

    # ---- entry points / abi ---------------------------------------------
    for raw in (j.get('Jumps') or []):
        a = lin(raw)
        if in_image(a):
            seeds.add(a)
            funcs.add(a)
    for table in ('FunctionSampling', 'Abi'):
        section = j.get(table) or {}
        if not isinstance(section, dict):
            continue
        for key, info in section.items():
            a = lin(key)
            if not in_image(a):
                continue
            seeds.add(a)
            funcs.add(a)
            if table == 'Abi' and isinstance(info, dict):
                parts = [f"{k}={info[k]}" for k in
                         ('CallConv', 'InRegs', 'OutRegs', 'Clobbers',
                          'Preserved', 'StackCleanup', 'Calls')
                         if info.get(k)]
                if parts:
                    cmts[a] = 'RT ABI: ' + ' '.join(str(p) for p in parts)

    # ---- write -----------------------------------------------------------
    # Instruction fetches are recorded as data reads by libdosbox; never let
    # them override executed code.
    for a in seeds:
        items.pop(a, None)

    conn = db.conn
    conn.execute("BEGIN")
    conn.executemany("INSERT OR IGNORE INTO code_seeds (addr) VALUES (?)",
                     [(a,) for a in seeds])
    conn.executemany("INSERT OR REPLACE INTO sreg_ranges "
                     "(start_addr, end_addr, reg, value) VALUES (?, ?, ?, ?)",
                     sregs)
    conn.executemany("INSERT INTO functions (start, end, name) "
                     "VALUES (?, ?, ?) ON CONFLICT(start) DO NOTHING",
                     [(a, a, f"sub_{a:X}") for a in funcs])
    conn.executemany("INSERT OR REPLACE INTO data_items (addr, size, kind, count) "
                     "VALUES (?, ?, ?, ?)",
                     [(a, s, k, c) for a, (s, k, c) in items.items()])
    conn.executemany("INSERT OR REPLACE INTO comments (addr, comment, repeatable) "
                     "VALUES (?, ?, 1)",
                     [(a, c) for a, c in cmts.items()])
    conn.commit()

    n = len(seeds) + len(sregs) + len(funcs) + len(items) + len(cmts)
    log.info("runtime info: %d code seeds, %d sreg ranges, %d funcs, "
             "%d data items, %d comments (loadseg=%04x)",
             len(seeds), len(sregs), len(funcs), len(items), len(cmts),
             loadseg)
    return n
