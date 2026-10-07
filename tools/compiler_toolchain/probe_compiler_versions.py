#!/usr/bin/env python3
"""Probe DOS compiler versions for fixture and signature-catalog metadata.

Layer: Tooling/gates.
Responsibility: collect optional compiler-version metadata for fixture and signature reporting.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

KVIKDOS = Path("/home/xor/kvikdos/kvikdos")
DOS_COMPILERS = Path("/home/xor/inertia_player/dos_compilers")
OUT_JSON = Path("/home/xor/vextest/signature_catalogs/compiler_aliases.json")
VERSION_RE = re.compile(r"\bVersion\s+([0-9]+(?:\.[0-9A-Za-z]+)*)", re.IGNORECASE)


def _pick_exe(root: Path) -> Path | None:
    for rel in ("CL.EXE", "BIN/CL.EXE", "QCL.EXE", "BIN/QCL.EXE", "CC.EXE", "BIN/CC.EXE"):
        p = root / rel
        if p.exists():
            return p
    return None


def _run_banner(root: Path, exe: Path) -> str:
    rel = exe.relative_to(root)
    dos_prog = "C:\\" + str(rel).replace("/", "\\")
    cwd = "C:\\" + str(rel.parent).replace("/", "\\") if str(rel.parent) not in {".", ""} else "C:\\"
    cmd = [
        str(KVIKDOS),
        f"--mount=c:{root}/",
        "--drive=c",
        f"--cwd-dos={cwd}",
        f"--path-dos={cwd}",
        f"--prog={dos_prog}",
        dos_prog,
    ]
    proc = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="latin1", errors="ignore"
    )
    return proc.stdout or ""


_MS_VERSION_PREFIXES_8616: tuple[tuple[str, str], ...] = (
    ("6.", "Microsoft C 6.x"),
    ("5.", "Microsoft C 5.x"),
    ("4.", "Microsoft C 4.x"),
    ("3.", "Microsoft C 3.x"),
    ("2.", "Microsoft C 2.x"),
)


def _canonical(root_name: str, banner: str) -> str | None:
    first = banner.splitlines()[0].strip().lower() if banner.splitlines() else ""
    m = VERSION_RE.search(banner)
    if "microsoft" in first and "c" in first and m:
        ver = m.group(1)
        if ver == "5.10":
            return "Microsoft C 5.1 (CL 5.10)"
        for prefix, label in _MS_VERSION_PREFIXES_8616:
            if ver.startswith(prefix):
                return label
        return f"Microsoft C {ver}"
    if "quick c" in root_name.lower():
        return "Microsoft QuickC family"
    if "borland" in root_name.lower():
        return "Borland C family"
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Probe compiler versions via kvikdos and write alias mapping JSON.")
    ap.add_argument("--output", type=Path, default=OUT_JSON)
    args = ap.parse_args()
    aliases: dict[str, str] = {
        "Microsoft C 5.10": "Microsoft C 5.1 (CL 5.10)",
        "Microsoft C 5.1": "Microsoft C 5.1 (CL 5.10)",
        "Microsoft C v5.1": "Microsoft C 5.1 (CL 5.10)",
    }
    for root in sorted(DOS_COMPILERS.iterdir()):
        if not root.is_dir():
            continue
        exe = _pick_exe(root)
        if exe is None:
            continue
        try:
            banner = _run_banner(root, exe)
        except Exception:
            continue
        canon = _canonical(root.name, banner)
        if canon:
            aliases[root.name] = canon
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"aliases": aliases}, indent=2, sort_keys=True))
    print(f"wrote {args.output} aliases={len(aliases)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
