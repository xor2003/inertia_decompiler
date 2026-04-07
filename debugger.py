#!/usr/bin/env python3
"""Root-level debugger startup script.

Starts the GDB server (simulator environment) and launches the Textual TUI client.
Supports both libdosbox and angr-based x86-16 simulation backends.

Usage:
    python debugger.py LIFE.EXE [--port 1234] [--backend angr|dosbox]
    python debugger.py --connect 127.0.0.1:1234  # TUI only, connect to existing server
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_PORT = 0  # 0 = OS chooses a free port
DEFAULT_HOST = "127.0.0.1"
LIBDOSBOX_PATH = Path("/home/xor/inertia_player/libdosbox")
WORKSPACE_PATH = Path(__file__).parent
PROJECT_VENV_PYTHON = WORKSPACE_PATH / ".venv" / "bin" / "python"


# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------

def find_libdosbox_binary() -> Path | None:
    """Find the compiled libdosbox binary with GDB support."""
    candidates = [
        LIBDOSBOX_PATH / "build" / "dosbox",
        LIBDOSBOX_PATH / "cmake-build-debug" / "dosbox",
        LIBDOSBOX_PATH / "build" / "dosbox-x86_64",
        LIBDOSBOX_PATH / "build" / "dosbox.exe",
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def has_libdosbox_gdb_support() -> bool:
    """Check if libdosbox was built with GDB server support."""
    binary = find_libdosbox_binary()
    if not binary:
        return False
    # Check if binary has debug symbols and GDB-related strings
    try:
        result = subprocess.run(
            ["strings", str(binary)],
            capture_output=True, text=True, timeout=5
        )
        output = result.stdout
        return "gdb" in output.lower() or "debug" in output.lower()
    except Exception:
        return False


# ---------------------------------------------------------------------------
# GDB Server launchers
# ---------------------------------------------------------------------------

def find_free_port(host: str = "127.0.0.1") -> int:
    """Find a free TCP port."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def start_angr_gdb_server(exe_path: str, port: int, host: str) -> subprocess.Popen:
    """Start the angr-based GDB RSP server."""
    # If port is 0, find a free port
    if port == 0:
        port = find_free_port(host)
    cmd = [
        sys.executable, "-m", "inertia_decompiler.debug_dos",
        exe_path, "--port", str(port), "--host", host,
    ]
    print(f"[*] Starting angr GDB server on {host}:{port}: {' '.join(cmd)}")
    proc = subprocess.Popen(cmd, cwd=str(WORKSPACE_PATH))
    proc.debug_port = port
    return proc


def start_dosbox_gdb_server(exe_path: str, port: int, host: str) -> subprocess.Popen:
    """Start libdosbox with GDB server enabled."""
    binary = find_libdosbox_binary()
    if not binary:
        raise RuntimeError("libdosbox binary not found")

    # libdosbox typically uses -debug or -gdb flags
    cmd = [
        str(binary),
        "-c", f"mount c {Path(exe_path).parent}",
        "-c", f"c:",
        "-c", Path(exe_path).name,
        "-debug",
        "-gdbport", str(port),
    ]
    print(f"[*] Starting libdosbox GDB server: {' '.join(cmd)}")
    proc = subprocess.Popen(cmd, cwd=str(WORKSPACE_PATH))
    proc.debug_port = port
    return proc


def start_gdbserver_standalone(exe_path: str, port: int, host: str) -> subprocess.Popen:
    """Start gdbserver for native debugging (if available)."""
    cmd = ["gdbserver", f"{host}:{port}", exe_path]
    print(f"[*] Starting gdbserver: {' '.join(cmd)}")
    proc = subprocess.Popen(cmd, cwd=str(WORKSPACE_PATH))
    proc.debug_port = port
    return proc


def module_available(name: str) -> bool:
    """Return True when a Python module can be imported."""
    return importlib.util.find_spec(name) is not None


def ensure_project_venv() -> None:
    """Re-exec inside the project virtualenv when available."""
    if os.environ.get("INERTIA_DEBUGGER_VENV") == "1":
        return
    if not PROJECT_VENV_PYTHON.exists():
        return
    try:
        if PROJECT_VENV_PYTHON.samefile(sys.executable):
            return
    except FileNotFoundError:
        return

    env = os.environ.copy()
    env["INERTIA_DEBUGGER_VENV"] = "1"
    env["VIRTUAL_ENV"] = str(WORKSPACE_PATH / ".venv")
    current_path = env.get("PATH", "")
    env["PATH"] = f"{PROJECT_VENV_PYTHON.parent}:{current_path}" if current_path else str(PROJECT_VENV_PYTHON.parent)
    os.execvpe(str(PROJECT_VENV_PYTHON), [str(PROJECT_VENV_PYTHON), __file__, *sys.argv[1:]], env)


def wait_for_server(host: str, port: int, proc: subprocess.Popen, timeout: float = 5.0) -> None:
    """Wait until the GDB server socket is actually accepting connections."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"GDB server exited early with code {proc.returncode}")
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"GDB server did not become ready on {host}:{port}")


# ---------------------------------------------------------------------------
# TUI launcher
# ---------------------------------------------------------------------------

def launch_tui(host: str, port: int, arch: str) -> None:
    """Launch the Textual TUI client."""
    from inertia_decompiler.gdb_tui import GDBTUIApp

    app = GDBTUIApp(host=host, port=port, arch=arch)
    app.run()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ensure_project_venv()
    parser = argparse.ArgumentParser(
        description="DOS Debugger with GDB server and Textual TUI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s LIFE.EXE                    Debug with angr backend
  %(prog)s LIFE.EXE --backend dosbox   Debug with libdosbox
  %(prog)s --connect 127.0.0.1:1234    Connect TUI to existing server
  %(prog)s --list-backends             List available backends
        """,
    )
    parser.add_argument("exe", nargs="?", help="DOS executable to debug")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="GDB server port (0 = auto)")
    parser.add_argument("--host", default=DEFAULT_HOST, help="GDB server host")
    parser.add_argument("--arch", choices=["x86_16", "x86", "x86_64"], default="x86_16", help="Target architecture")
    parser.add_argument("--backend", choices=["angr", "dosbox", "gdbserver"], default=None, help="Simulator backend")
    parser.add_argument("--connect", metavar="HOST:PORT", help="Connect TUI to existing GDB server")
    parser.add_argument("--list-backends", action="store_true", help="List available backends")
    parser.add_argument("--tui-only", action="store_true", help="Only launch TUI (no server)")
    parser.add_argument("--no-tui", action="store_true", help="Only start server (no TUI)")

    args = parser.parse_args()

    # List backends
    if args.list_backends:
        print("Available backends:")
        print(f"  angr:    {'available' if WORKSPACE_PATH / 'angr_platforms' else 'not found'}")
        dosbox_bin = find_libdosbox_binary()
        print(f"  dosbox:  {'available ({})'.format(dosbox_bin) if dosbox_bin else 'not found'}")
        print(f"  gdbserver: {'available' if subprocess.run(['which', 'gdbserver'], capture_output=True).returncode == 0 else 'not found'}")
        return

    # Connect mode (TUI only)
    if args.connect:
        if not module_available("textual"):
            print("Error: missing Python module 'textual' required for the TUI")
            sys.exit(1)
        parts = args.connect.rsplit(":", 1)
        host = parts[0] if len(parts) == 2 else DEFAULT_HOST
        port = int(parts[1]) if len(parts) == 2 else DEFAULT_PORT
        print(f"[*] Connecting to {host}:{port}")
        launch_tui(host, port, args.arch)
        return

    # Validate executable
    if not args.exe:
        parser.error("executable required (or use --connect/--list-backends)")

    exe_path = Path(args.exe)
    if not exe_path.exists():
        print(f"Error: {exe_path} not found")
        sys.exit(1)

    # Determine backend
    backend = args.backend
    if backend is None:
        # Auto-detect: prefer angr for DOS MZ, dosbox if available
        if has_libdosbox_gdb_support():
            backend = "dosbox"
        else:
            backend = "angr"

    # Start GDB server
    server_proc = None
    try:
        if backend == "angr":
            if not module_available("angr"):
                print("Error: missing Python module 'angr' required for the angr backend")
                sys.exit(1)
            server_proc = start_angr_gdb_server(str(exe_path), args.port, args.host)
        elif backend == "dosbox":
            server_proc = start_dosbox_gdb_server(str(exe_path), args.port, args.host)
        elif backend == "gdbserver":
            server_proc = start_gdbserver_standalone(str(exe_path), args.port, args.host)
        else:
            print(f"Error: unknown backend '{backend}'")
            sys.exit(1)

        # Wait for server to start
        server_port = getattr(server_proc, "debug_port", args.port)
        print(f"[*] Waiting for GDB server on {args.host}:{server_port}...")
        wait_for_server(args.host, server_port, server_proc)

        # Launch TUI unless --no-tui
        if not args.no_tui:
            if not module_available("textual"):
                print("Error: missing Python module 'textual' required for the TUI")
                sys.exit(1)
            print(f"[*] Launching TUI...")
            launch_tui(args.host, server_port, args.arch)
        else:
            print(f"[*] Server running. Connect with:")
            print(f"    python {__file__} --connect {args.host}:{server_port}")
            # Wait for server to exit
            server_proc.wait()

    except KeyboardInterrupt:
        print("\n[*] Interrupted")
    finally:
        if server_proc:
            print("[*] Stopping GDB server...")
            server_proc.terminate()
            try:
                server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_proc.kill()
        print("[*] Debugger exited")


if __name__ == "__main__":
    main()
