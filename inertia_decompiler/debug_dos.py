"""Debug a DOS MZ executable via angr + GDB RSP + Textual TUI.

Usage:
    python -m inertia_decompiler.debug_dos LIFE.EXE [--port 1234]
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

def main() -> None:
    try:
        import angr
    except ModuleNotFoundError as exc:
        print(f"Error: missing Python module {exc.name!r} required for DOS debugging")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Debug DOS MZ executable")
    parser.add_argument("exe", help="Path to DOS .EXE file")
    parser.add_argument("--port", type=int, default=1234, help="GDB RSP port")
    parser.add_argument("--host", default="127.0.0.1", help="GDB RSP host")
    args = parser.parse_args()

    exe = Path(args.exe)
    if not exe.exists():
        print(f"Error: {exe} not found")
        sys.exit(1)

    print(f"[*] Loading {exe}...")

    # Load with angr's X86-16 support
    try:
        proj = angr.Project(
            str(exe),
            auto_load_libs=False,
        )
        print(f"[+] Project loaded: arch={proj.arch.name}")
    except Exception as e:
        print(f"[!] Load failed: {e}")
        print("[*] Trying with explicit MZ backend...")
        try:
            from angr_platforms.X86_16 import load_dos_mz  # noqa: F401
            proj = angr.Project(str(exe), auto_load_libs=False)
            print(f"[+] Project loaded: arch={proj.arch.name}")
        except Exception as e2:
            print(f"[!] Failed: {e2}")
            sys.exit(1)

    # Start GDB RSP server
    from inertia_decompiler.debugger_gdb import GDBServer

    server = GDBServer(proj, port=args.port, host=args.host)
    server.start()
    print(f"[+] GDB RSP server on {args.host}:{args.port}")

    try:
        while server.running:
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
        print("[+] Debugger exited")


if __name__ == "__main__":
    main()
