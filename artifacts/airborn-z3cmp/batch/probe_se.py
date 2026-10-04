import collections
import importlib.util
import logging
import sys
import time

logging.disable(logging.CRITICAL)
spec = importlib.util.spec_from_file_location("aircmp", "/home/xor/vextest/artifacts/airborn-z3cmp/aircmp.py")
m = importlib.util.module_from_spec(spec); sys.modules["aircmp"]=m; spec.loader.exec_module(m)
orc = m.load_side("/home/xor/games/airborn/build_sdl/ar_m2c", m2c=True, srcdir=m.Path("/home/xor/games/airborn"))
name = sys.argv[1] if len(sys.argv)>1 else "sub_100ea"
t0=time.time()
terms, diag, sh = m.execute(orc, orc.proc_syms[name], (orc.text_lo, orc.text_hi), max_steps=int(sys.argv[2]) if len(sys.argv)>2 else 4000)
kinds = collections.Counter(t.kind for t in terms)
print("terms", dict(kinds), "time", round(time.time()-t0,1))
dc = collections.Counter(d.split(":")[0] for d in diag)
print("diag", dict(dc))
print("splits", sorted(m.SPLITS.items(), key=lambda x:-x[1])[:12])
