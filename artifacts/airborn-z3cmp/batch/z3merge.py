#!/usr/bin/env python3
"""Merge z3res_*.json worker outputs into aircmp-results.json + triage report."""
import json, glob, collections, sys

OUT = "/home/xor/vextest/artifacts/airborn-z3cmp/aircmp-results.json"
res = {}
for f in sorted(glob.glob("/home/xor/vextest/artifacts/airborn-z3cmp/batch/z3res_*.json")):
    res.update(json.load(open(f)))

EXC = {"indirect", "indirect_call", "tail", "abort"}
def cov_gap(v):
    kinds = set(v.get("cnd_kinds") or []) | set(v.get("orc_kinds") or [])
    return bool(kinds & EXC) or (v.get("cnd_kinds") == ["ret"]) != (v.get("orc_kinds") == ["ret"])

# classify mismatch cells
def klass(v):
    ms = [m[0] for m in (v.get("mismatches") or [])]
    s = set(ms)
    if not ms: return "unknown"
    flags = {m for m in s if m.startswith("f_")}
    real = s - flags
    if not real: return "flag-model"
    out = []
    if "data" in real or "io" in real: out.append("mem")
    if any(m.startswith("g_") for m in real): out.append("regs")
    if any(m.startswith("s_") for m in real): out.append("segs")
    if flags: out.append("flags")
    return "+".join(out)

stat = collections.Counter(v["status"] for v in res.values())
print(f"total {len(res)}: {dict(stat)}")
rows = []
for k, v in sorted(res.items()):
    if v["status"] == "failed":
        rows.append((k, klass(v), cov_gap(v), v.get("mismatches"),
                     v.get("orc_kinds"), v.get("cnd_kinds"), v.get("secs")))
kc = collections.Counter(r[1] for r in rows)
cg = sum(1 for r in rows if r[2])
print(f"failed {len(rows)} (coverage-gap suspect: {cg}): {dict(kc)}")
for r in rows:
    print(f"  {r[0]} [{r[1]}]{' GAP' if r[2] else ''} orc={r[4]} cnd={r[5]} {str(r[3])[:120]}")

# refused breakdown by reason prefix
rr = collections.Counter()
for k, v in sorted(res.items()):
    if v["status"] == "refused":
        rr[(v.get("reason") or "?").split(":")[0]] += 1
print(f"refused reasons: {dict(rr)}")
inc = [k for k, v in res.items() if v["status"] == "incomplete"]
if inc:
    print(f"incomplete ({len(inc)}): {sorted(inc)[:20]}")

# expected total from worker logs ("worker N: X fns")
import re
exp = 0
for lf in glob.glob("/home/xor/vextest/artifacts/airborn-z3cmp/batch/z3w*.log"):
    try:
        mm = re.search(r"worker \d+: (\d+) fns", open(lf).read())
        if mm:
            exp += int(mm.group(1))
    except OSError:
        pass
if exp:
    print(f"coverage: {len(res)}/{exp} functions processed"
          + ("" if len(res) >= exp else f"  MISSING {exp-len(res)}"))

summary = {"total": len(res), "status_counts": dict(stat),
           "refused_reasons": dict(rr),
           "failed_detail": [{"name": r[0], "class": r[1], "coverage_gap": r[2],
                              "mismatches": r[3]} for r in rows],
           "incomplete": sorted(inc),
           "results": res}
json.dump(summary, open(OUT, "w"), indent=1, default=str)
print(f"wrote {OUT}")
