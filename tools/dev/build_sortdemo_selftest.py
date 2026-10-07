#!/usr/bin/env python3
"""Build and run the SORTDEMO source selftest through MS C and kvikdos.

Layer: Tooling/gates.
Responsibility: verify the SORTDEMO source selftest without changing decompiler recovery behavior.
"""

from __future__ import annotations

import argparse
import contextlib
import shutil
import subprocess
import sys
from enum import Enum
from pathlib import Path

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DEFAULT_SOURCE: Path = REPO_ROOT / "SORTDEMO.C"
DEFAULT_OUT_DIR: Path = REPO_ROOT / "examples" / "build_msc6" / "sortdemo_selftest"
DEFAULT_KVIKDOS: Path = Path("/home/xor/kvikdos/kvikdos")
DEFAULT_MSC51_ROOT: Path = Path("/home/xor/inertia_player/dos_compilers/Microsoft C v5.1")
SORTDEMO_SELFTEST_SUCCESS_EXIT_CODE: int = 255


class SortdemoSelftestStage(Enum):
    """Pipeline stage reported by the SORTDEMO source selftest harness."""

    PREPARE = "prepare"
    COMPILE = "compile"
    RUN = "run"


def _fail(stage: SortdemoSelftestStage, message: str) -> int:
    print(f"[sortdemo-selftest] failed stage={stage.name.lower()} error={message}", file=sys.stderr)
    return 1


def _run(cmd: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _compile_and_link_sortdemo_selftest(
    source_path: Path,
    out_dir: Path,
    *,
    kvikdos: Path,
    msc_root: Path,
) -> tuple[bool, str, str, str, str]:
    for artifact_name in ("SORTTST.OBJ", "SORTTST.EXE", "SORTTST.MAP", "SORTTST.COD"):
        with contextlib.suppress(OSError):
            (out_dir / artifact_name).unlink()

    compile_cmd = [
        str(kvikdos),
        f"--mount=c:{out_dir}/",
        f"--mount=e:{msc_root}/",
        "--drive=c",
        "--cwd-dos=c:\\",
        "--path-dos=e:\\BIN",
        "--env=INCLUDE=E:\\INCLUDE",
        "--env=LIB=E:\\LIB",
        "--prog=e:\\BIN\\CL.EXE",
        "e:\\BIN\\CL.EXE",
        "/Ic:\\",
        "/nologo",
        "/Od",
        "/DSORTDEMO_FUNCTION_SELFTEST",
        "/c",
        "/Foc:\\SORTTST.OBJ",
        "/Fcc:\\SORTTST.COD",
        f"c:\\{source_path.name}",
    ]
    compile_proc = _run(compile_cmd, timeout=120)

    link_cmd = [
        str(kvikdos),
        f"--mount=c:{out_dir}/",
        f"--mount=e:{msc_root}/",
        "--drive=c",
        "--cwd-dos=c:\\",
        "--env=LIB=E:\\LIB",
        "--prog=e:\\BIN\\LINK.EXE",
        "e:\\BIN\\LINK.EXE",
        "c:\\SORTTST.OBJ,c:\\SORTTST.EXE,c:\\SORTTST.MAP,E:\\LIB\\SLIBCE.LIB;",
    ]
    link_proc = _run(link_cmd, timeout=120)

    map_text = ""
    map_path = out_dir / "SORTTST.MAP"
    if map_path.exists():
        with contextlib.suppress(OSError):
            map_text = map_path.read_text(encoding="utf-8", errors="replace")
    link_diagnostics = "\n".join((link_proc.stdout, link_proc.stderr, map_text))
    link_failed = "error L" in link_diagnostics or "unresolved external" in link_diagnostics.lower()
    built = (out_dir / "SORTTST.EXE").exists() and compile_proc.returncode == 0 and not link_failed
    return built, compile_proc.stdout, compile_proc.stderr, link_proc.stdout, link_proc.stderr


def _run_sortdemo_selftest(
    exe_path: Path,
    out_dir: Path,
    *,
    kvikdos: Path,
    timeout: int,
) -> tuple[int | None, str, str]:
    cmd = [
        str(kvikdos),
        f"--mount=c:{out_dir}/",
        "--drive=c",
        "--cwd-dos=c:\\",
        f"--prog=c:\\{exe_path.name}",
        f"c:\\{exe_path.name}",
    ]
    try:
        proc = _run(cmd, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        stdout_data = (
            exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        )
        stderr_data = (
            exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        )
        return None, stdout_data, stderr_data + "\nruntime timeout\n"
    return proc.returncode, proc.stdout, proc.stderr


def main() -> int:
    """Build SORTDEMO.C in selftest mode and require DOS exit code 255."""
    parser = argparse.ArgumentParser(
        description="Build SORTDEMO.C in source selftest mode and require DOS exit code 255."
    )
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--kvikdos", type=Path, default=DEFAULT_KVIKDOS)
    parser.add_argument("--msc-root", type=Path, default=DEFAULT_MSC51_ROOT)
    parser.add_argument("--expected-exit-code", type=int, default=SORTDEMO_SELFTEST_SUCCESS_EXIT_CODE)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--clean", action="store_true", help="Remove the selftest build directory first.")
    args = parser.parse_args()

    if not args.source.is_file():
        return _fail(SortdemoSelftestStage.PREPARE, f"missing source: {args.source}")
    if not args.kvikdos.is_file():
        return _fail(SortdemoSelftestStage.RUN, f"missing kvikdos executable: {args.kvikdos}")
    if not args.msc_root.is_dir():
        return _fail(SortdemoSelftestStage.COMPILE, f"missing MS C root: {args.msc_root}")

    if args.clean and args.out_dir.exists():
        shutil.rmtree(args.out_dir)
    args.out_dir.mkdir(parents=True, exist_ok=True)

    build_source = args.out_dir / "SORTDEMO.C"
    shutil.copyfile(args.source, build_source)

    built_ok, compile_stdout, compile_stderr, link_stdout, link_stderr = _compile_and_link_sortdemo_selftest(
        build_source,
        args.out_dir,
        kvikdos=args.kvikdos,
        msc_root=args.msc_root,
    )
    (args.out_dir / "SORTTST.compile.out.txt").write_text(compile_stdout, encoding="utf-8")
    (args.out_dir / "SORTTST.compile.err.txt").write_text(compile_stderr, encoding="utf-8")
    (args.out_dir / "SORTTST.link.out.txt").write_text(link_stdout, encoding="utf-8")
    (args.out_dir / "SORTTST.link.err.txt").write_text(link_stderr, encoding="utf-8")
    if not built_ok:
        return _fail(
            SortdemoSelftestStage.COMPILE,
            f"MS C rebuild failed; see {args.out_dir / 'SORTTST.compile.out.txt'}",
        )

    rebuilt_exe = args.out_dir / "SORTTST.EXE"
    run_exit, run_stdout, run_stderr = _run_sortdemo_selftest(
        rebuilt_exe,
        args.out_dir,
        kvikdos=args.kvikdos,
        timeout=args.timeout,
    )
    (args.out_dir / "SORTTST.run.out.txt").write_text(run_stdout, encoding="utf-8")
    (args.out_dir / "SORTTST.run.err.txt").write_text(run_stderr, encoding="utf-8")
    if run_exit != args.expected_exit_code:
        return _fail(
            SortdemoSelftestStage.RUN,
            f"rebuilt SORTDEMO exited {run_exit}, expected {args.expected_exit_code}",
        )

    print(f"[sortdemo-selftest] source={args.source} rebuilt={rebuilt_exe} run_exit={run_exit} status=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
