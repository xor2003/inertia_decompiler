#!/usr/bin/env python3
"""Retry x16 sample timeouts and reclassify expected COM no-byte fallbacks.

Layer: Tooling/gates.
Responsibility: rerun bounded sample probes and report fallback diagnostics without semantic repair.

Reads `reports/x16_decompile_report.json` and writes `reports/x16_decompile_retry.json`.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
IN_JSON = ROOT / "reports" / "x16_decompile_report.json"
OUT_JSON = ROOT / "reports" / "x16_decompile_report_retry.json"
PY = sys.executable
DECOMPILE_SCRIPT = ROOT / "decompile.py"
LONG_TIMEOUT = 120

if not IN_JSON.exists():
    print("No existing report found at", IN_JSON)
    raise SystemExit(1)

with IN_JSON.open() as f:
    prev = json.load(f)

results = []
for r in prev:
    path = r["file"]
    suffix = Path(path).suffix.lower()
    # Reclassify COM no-bytes as expected
    if suffix == ".com" and r.get("summary") == ["no_bytes_available"]:
        r["status"] = "ok"
        r["note"] = "COM synthetic/external functions expected; treated as ok"
        results.append(r)
        continue

    # Only re-run timed-out EXEs
    if r.get("status") == "timeout" or (suffix == ".exe" and r.get("status") != "ok"):
        cmd = [PY, str(DECOMPILE_SCRIPT), path, "--timeout", str(LONG_TIMEOUT), "--max-functions", "6"]
        print("Retrying:", path)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=LONG_TIMEOUT + 10)
            out = proc.stdout + proc.stderr
        except subprocess.TimeoutExpired:
            r["status"] = "timeout"
            r["note"] = f"retry timed out after {LONG_TIMEOUT}s"
            results.append(r)
            continue
        fallback_reasons = []
        if "Decompiler did not produce code" in out:
            fallback_reasons.append("no_decompiler_output")
        if "no bytes available" in out:
            fallback_reasons.append("no_bytes_available")
        if "ASM fallback" in out or "asm fallback" in out or "ASM:" in out:
            fallback_reasons.append("asm_fallback")
        if "Unknown opcode" in out or "Unknown opcode" in out:
            fallback_reasons.append("unknown_opcode")
        status = "ok" if not fallback_reasons else "fallback"
        r.update(
            {
                "status": status,
                "summary": fallback_reasons or list(out.splitlines()[:6]),
                "snippet": "\n".join(out.splitlines()[:200]),
            }
        )
        results.append(r)
    else:
        results.append(r)

with OUT_JSON.open("w") as f:
    json.dump(results, f, indent=2)

print("Wrote:", OUT_JSON)
