import importlib.util
import json
import logging
import os
import signal
import sys
import time

logging.disable(logging.CRITICAL)
wid, nw = int(sys.argv[1]), int(sys.argv[2])
OUTDIR = "/home/xor/vextest/artifacts/airborn-z3cmp/batch"
spec = importlib.util.spec_from_file_location("aircmp", "/home/xor/vextest/artifacts/airborn-z3cmp/aircmp.py")
m = importlib.util.module_from_spec(spec); sys.modules["aircmp"]=m; spec.loader.exec_module(m)
orc = m.load_side("/home/xor/games/airborn/build_sdl/ar_m2c", m2c=True, srcdir=m.Path("/home/xor/games/airborn"))
cnd = m.load_side("/home/xor/games/airborn/port/ar_port", m2c=False)
def handler(s,f): raise TimeoutError
signal.signal(signal.SIGALRM, handler)
ar_names = set(orc.ksub_map.values())  # AR.EXE procs only (0x1a2-space tokens)
subs = sorted(n for n in orc.proc_syms if n.startswith("sub_")
              and n in cnd.proc_syms and n in ar_names)
mine = [n for i,n in enumerate(subs) if i % nw == wid]
print(f"worker {wid}: {len(mine)} fns", flush=True)
out = f"{OUTDIR}/z3res_{wid}.json"
results = json.load(open(out)) if os.path.exists(out) else {}
for name in mine:
    if name in results: continue
    t0=time.time()
    try:
        signal.setitimer(signal.ITIMER_REAL, 90)
        r = m.compare_function(name, orc, cnd, timeout_ms=20000)
        signal.setitimer(signal.ITIMER_REAL, 0)
        ms = [(x.get("reg"),x.get("oracle_value"),x.get("candidate_value")) for x in r.get("mismatches",[])][:4]
        print(name, r.get("status"), "|", (r.get("reason") or "")[:55], "|", round(time.time()-t0,1), "s",
              ("| mism "+str(ms) if ms else ""), flush=True)
        results[name]={"status":r.get("status"),"reason":r.get("reason"),
                       "mismatches":ms,"orc_terms":r["oracle"].get("terminals"),
                       "orc_kinds":r["oracle"].get("terminal_kinds"),
                       "cnd_terms":r["candidate"].get("terminals"),
                       "cnd_kinds":r["candidate"].get("terminal_kinds"),
                       "secs":round(time.time()-t0,1)}
    except TimeoutError:
        print(name,"WALLTIMEOUT",flush=True); results[name]={"status":"timeout"}
    except Exception as ex:
        print(name,"crash",f"{type(ex).__name__}:{str(ex)[:80]}",flush=True)
        results[name]={"status":"crash","err":f"{type(ex).__name__}:{str(ex)[:150]}"}
    json.dump(results, open(out,"w"), default=str, indent=1)
print(f"worker {wid} DONE", flush=True)
