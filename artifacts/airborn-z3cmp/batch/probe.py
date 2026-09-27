import importlib.util, sys, logging, traceback, time
logging.disable(logging.CRITICAL)
spec = importlib.util.spec_from_file_location("aircmp", "/home/xor/vextest/artifacts/airborn-z3cmp/aircmp.py")
m = importlib.util.module_from_spec(spec); sys.modules["aircmp"]=m; spec.loader.exec_module(m)
orc = m.load_side("/home/xor/games/airborn/build_sdl/ar_m2c", m2c=True, srcdir=m.Path("/home/xor/games/airborn"))
cnd = m.load_side("/home/xor/games/airborn/port/ar_port", m2c=False)
for name in sys.argv[1:] or ["sub_100ea"]:
    t0 = time.time()
    try:
        r = m.compare_function(name, orc, cnd, timeout_ms=30000)
        ms = [(x.get("reg"),x.get("oracle_value"),x.get("candidate_value")) for x in r.get("mismatches",[])][:6]
        print(name, r.get("status"), "|", (r.get("reason") or "")[:60], "|", round(time.time()-t0,1), "s",
              "| orc", r["oracle"].get("terminals"), r["oracle"].get("terminal_kinds"),
              "| cnd", r["candidate"].get("terminals"), r["candidate"].get("terminal_kinds"),
              ("| mism "+str(ms) if ms else ""), flush=True)
    except Exception:
        traceback.print_exc()
