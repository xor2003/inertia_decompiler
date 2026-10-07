#!/usr/bin/env python3
"""Probe decompilation on x16 samples and report fallback/no-output cases.

Layer: Tooling/gates.
Responsibility: run bounded sample probes and report fallback diagnostics without semantic repair.

Writes results to `reports/x16_decompile_report.json` and `reports/x16_decompile_report.txt`.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "tests" / "fixtures" / "x16_samples"
REPORT_DIR = ROOT / "reports"
REPORT_DIR.mkdir(exist_ok=True)
OUT_JSON = REPORT_DIR / "x16_decompile_report.json"
OUT_TXT = REPORT_DIR / "x16_decompile_report.txt"

TIMEOUT_PER = 70  # seconds per sample
PY = sys.executable
DECOMPILE_SCRIPT = ROOT / "decompile.py"

EXTS = {".COM", ".EXE", ".COD", ".BIN"}

results: list[dict[str, object]] = []

for path in sorted(SAMPLES.rglob("*")):
    if path.is_dir():
        continue
    if path.suffix.upper() not in EXTS:
        # still try other files but prefer known sample types
        pass
    rel = path.relative_to(ROOT)
    cmd = [PY, str(DECOMPILE_SCRIPT), str(path), "--timeout", "60", "--max-functions", "6"]
    print(f"Running: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_PER)
        out = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        print(f"Timeout on {rel}")
        results.append({"file": str(rel), "status": "timeout", "summary": "timeout"})
        continue

    fallback_reasons = []
    # heuristics for detecting fallback/no-decompilation
    if "Decompiler did not produce code" in out:
        fallback_reasons.append("no_decompiler_output")
    if "no bytes available" in out:
        fallback_reasons.append("no_bytes_available")
    if "ASM fallback" in out or "asm fallback" in out or "ASM:" in out:
        fallback_reasons.append("asm_fallback")
    # catch generic ellipsis fallback used previously
    if "..." in out and "Decompiler" in out:
        fallback_reasons.append("ellipsis_fallback")

    status = "ok" if not fallback_reasons else "fallback"
    summary = fallback_reasons[:3] if fallback_reasons else list(out.splitlines()[:6])
    snippet = "\n".join(out.splitlines()[:200])
    results.append({"file": str(rel), "status": status, "summary": summary, "snippet": snippet})

# write JSON and text reports
with OUT_JSON.open("w") as f:
    json.dump(results, f, indent=2)

with OUT_TXT.open("w") as f:
    for r in results:
        f.write(f"File: {r['file']}\n")
        f.write(f"Status: {r['status']}\n")
        f.write(f"Summary: {r['summary']}\n")
        f.write("--- snippet ---\n")
        report_snippet = r.get("snippet", "")
        f.write(report_snippet[:800] if isinstance(report_snippet, str) else "")
        f.write("\n\n")

print(f"Wrote: {OUT_JSON}\nWrote: {OUT_TXT}")
