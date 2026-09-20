#!/usr/bin/env python3
"""Build debug-info corpus fixtures for decompiler evidence validation.

Layer: Tooling/gates.
Responsibility: build optional debug-info fixtures for validation without changing recovery semantics.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "angr_platforms"))
logging.getLogger("angr.state_plugins.unicorn_engine").disabled = True

from angr_platforms.X86_16.codeview_nb00 import parse_codeview_nb00  # noqa: E402
from angr_platforms.X86_16.codeview_nb02_nb04 import parse_codeview_nb0204  # noqa: E402
from angr_platforms.X86_16.turbo_debug_tdinfo import parse_tdinfo_exe  # noqa: E402

DEFAULT_KVIKDOS = Path("/home/xor/kvikdos/kvikdos")
DEFAULT_DOSBOX = Path("/usr/bin/dosbox") if Path("/usr/bin/dosbox").exists() else Path("/opt/dosbox-staging/dosbox")
DEFAULT_COMPILERS = Path("/home/xor/inertia_player/dos_compilers")
DEFAULT_OUTPUT = Path("/tmp/inertia_debug_info_corpus")

PROBE_SOURCE = """\
typedef struct pair_s {
    int left;
    int right;
} PAIR;

int global_counter = 3;
PAIR global_pair = { 4, 7 };

int helper(p, count)
PAIR *p;
int count;
{
    int i;
    int total;

    total = 0;
    for (i = 0; i < count; ++i) {
        total = total + p->left + p->right + i;
    }
    return total;
}

int main()
{
    PAIR local_pair;
    int result;

    local_pair.left = global_pair.left;
    local_pair.right = global_pair.right + global_counter;
    result = helper(&local_pair, 2);
    return result == 25 ? 0 : 1;
}
"""


@dataclass(frozen=True)
class CompilerSpec:
    name: str
    family: str
    root_rel: str
    runner: str = "kvikdos"
    bin_dir: str = ""
    include_dir: str = ""
    lib_dir: str = ""
    compiler: str = ""
    linker: str = ""
    library: str = ""
    compile_flags: tuple[str, ...] = ()
    link_flags: tuple[str, ...] = ()
    link_root_rel: str | None = None


COMPILERS: tuple[CompilerSpec, ...] = (
    CompilerSpec(
        name="msc4",
        family="ms",
        root_rel="Microsoft C v4",
        include_dir="INC",
        lib_dir="LIB",
        compiler="CL.EXE",
        linker="LINK.EXE",
        library="SLIBC.LIB",
        compile_flags=("/Zi", "/Od", "/AS"),
        link_flags=("/CO",),
    ),
    CompilerSpec(
        name="msc5",
        family="ms",
        root_rel="Microsoft C v5",
        include_dir="INC",
        lib_dir="LIB",
        compiler="CL.EXE",
        linker="LINK.EXE",
        library="SLIBCE.LIB",
        compile_flags=("/Zi", "/Od", "/AS"),
        link_flags=("/CO",),
    ),
    CompilerSpec(
        name="msc51",
        family="ms",
        root_rel="Microsoft C v5.1",
        bin_dir="bin",
        include_dir="INCLUDE",
        lib_dir="lib",
        compiler="CL.EXE",
        linker="LINK.EXE",
        library="SLIBCE.LIB",
        compile_flags=("/Zi", "/Od", "/AS"),
        link_flags=("/CO",),
    ),
    CompilerSpec(
        name="msc6",
        family="ms",
        root_rel="Microsoft C v6ax",
        bin_dir="BIN",
        include_dir="INCLUDE",
        lib_dir="LIB",
        compiler="CL.EXE",
        linker="LINK.EXE",
        library="SLIBCE.LIB",
        compile_flags=("/Zi", "/Od", "/AS"),
        link_flags=("/CO",),
    ),
    CompilerSpec(
        name="msc7",
        family="ms",
        root_rel="Microsoft C v7",
        runner="dosbox_hx",
        bin_dir="BIN",
        include_dir="INCLUDE",
        lib_dir="LIB",
        compiler="CL.EXE",
        linker="LINK.EXE",
        library="SLIBCE.LIB",
        compile_flags=("/Zi", "/Od", "/AS"),
        link_flags=("/CO",),
    ),
    CompilerSpec(
        name="msc8",
        family="ms",
        root_rel="Microsoft C v8",
        runner="wine",
        bin_dir="BIN",
        include_dir="INCLUDE",
        lib_dir="LIB",
        compiler="CL.EXE",
        linker="LINK.EXE",
        library="SLIBCE.LIB",
        compile_flags=("/Zi", "/Od", "/AS"),
        link_flags=("/CO",),
    ),
    CompilerSpec(
        name="qc1",
        family="ms",
        root_rel="Microsoft QuickC v1",
        bin_dir="BIN",
        include_dir="INCLUDE",
        lib_dir="LIB",
        compiler="QCL.EXE",
        linker="LINK.EXE",
        library="SLIBCE.LIB",
        compile_flags=("/Zi", "/Od", "/AS"),
        link_flags=("/CO",),
    ),
    CompilerSpec(
        name="qc2",
        family="ms",
        root_rel="Microsoft QuickC v2",
        include_dir="INCLUDE",
        lib_dir="LIB",
        compiler="QCL.EXE",
        linker="LINK.EXE",
        library="SLIBCE.LIB",
        compile_flags=("/Zi", "/Od", "/AS"),
        link_flags=("/CO",),
    ),
    CompilerSpec(
        name="qc251",
        family="ms",
        root_rel="Microsoft QuickC v251",
        bin_dir="BIN",
        include_dir="INCLUDE",
        lib_dir="LIB",
        compiler="QCL.EXE",
        linker="LINK.EXE",
        library="SLIBCE.LIB",
        compile_flags=("/Zi", "/Od", "/AS"),
        link_flags=("/CO",),
        link_root_rel="Microsoft QuickC v2",
    ),
    CompilerSpec(
        name="tc1",
        family="borland",
        root_rel="Borland Turbo C v1",
        compiler="TCC.EXE",
        linker="TLINK.EXE",
        compile_flags=("-y", "-ms"),
        link_flags=("/l",),
    ),
    CompilerSpec(
        name="tc2",
        family="borland",
        root_rel="Borland Turbo C v2",
        include_dir="INCLUDE",
        lib_dir="LIB",
        compiler="TCC.EXE",
        linker="TLINK.EXE",
        compile_flags=("-v", "-y", "-ms"),
        link_flags=("/v",),
    ),
    CompilerSpec(
        name="tcpp1",
        family="borland",
        root_rel="Borland Turbo C++ v1",
        bin_dir="BIN",
        include_dir="INCLUDE",
        lib_dir="LIB",
        compiler="TCC.EXE",
        linker="TLINK.EXE",
        compile_flags=("-v", "-y", "-ms"),
        link_flags=("/v",),
    ),
    CompilerSpec(
        name="bcpp30",
        family="borland",
        root_rel="Borland C++ v3.0",
        runner="dosbox",
        bin_dir="BIN",
        include_dir="INCLUDE",
        lib_dir="LIB",
        compiler="BCC.EXE",
        linker="TLINK.EXE",
        compile_flags=("-v", "-y", "-ms"),
        link_flags=("/v",),
    ),
    CompilerSpec(
        name="bcpp31",
        family="borland",
        root_rel="Borland C++ v3.1",
        runner="dosbox",
        bin_dir="BIN",
        include_dir="INCLUDE",
        lib_dir="LIB",
        compiler="BCC.EXE",
        linker="TLINK.EXE",
        compile_flags=("-v", "-y", "-ms"),
        link_flags=("/v",),
    ),
    CompilerSpec(
        name="tcpp3",
        family="borland",
        root_rel="Borland Turbo C++ v3",
        runner="dosbox",
        bin_dir="BIN",
        include_dir="INCLUDE",
        lib_dir="LIB",
        compiler="TCC.EXE",
        linker="TLINK.EXE",
        compile_flags=("-v", "-y", "-ms"),
        link_flags=("/v",),
    ),
)


def _dos_join(*parts: str) -> str:
    return "\\".join(part for part in parts if part)


def _run(cmd: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="latin1",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def _run_with_env(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 60,
) -> subprocess.CompletedProcess[str]:
    """Run an external tool and preserve timeouts as structured failures."""

    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    try:
        return subprocess.run(
            cmd,
            cwd=str(cwd) if cwd is not None else None,
            env=merged_env,
            capture_output=True,
            text=True,
            encoding="latin1",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode("latin1", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("latin1", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return subprocess.CompletedProcess(cmd, 124, stdout, f"{stderr}\ntimed out after {timeout} seconds\n")


def _run_dosbox(cmd: list[str], *, timeout: int = 90) -> subprocess.CompletedProcess[str]:
    exe = Path(cmd[0])
    video_driver = "x11" if "dosbox-staging" in str(exe) else "dummy"
    env = {
        "SDL_VIDEODRIVER": video_driver,
        "SDL_AUDIODRIVER": "dummy",
    }
    return _run_with_env(cmd, env=env, timeout=timeout)


def _kvikdos_base(kvikdos: Path, out_dir: Path, root: Path) -> list[str]:
    return [
        str(kvikdos),
        f"--mount=c:{out_dir}/",
        f"--mount=e:{root}/",
        "--drive=c",
        "--cwd-dos=c:\\",
    ]


def _env_args(spec: CompilerSpec) -> list[str]:
    args: list[str] = []
    if spec.include_dir:
        args.append(f"--env=INCLUDE=e:\\{spec.include_dir}")
    if spec.lib_dir:
        args.append(f"--env=LIB=e:\\{spec.lib_dir}")
    return args


def _build_ms(spec: CompilerSpec, out_dir: Path, *, kvikdos: Path, compilers_root: Path) -> tuple[bool, str, str]:
    root = compilers_root / spec.root_rel
    link_root = compilers_root / (spec.link_root_rel or spec.root_rel)
    compiler_dos = "e:\\" + _dos_join(spec.bin_dir, spec.compiler)
    linker_dos = "e:\\" + _dos_join(spec.bin_dir, spec.linker)
    if spec.link_root_rel is not None:
        linker_dos = "f:\\" + _dos_join(spec.linker)
    path_dos = "e:\\" + spec.bin_dir if spec.bin_dir else "e:\\"

    compile_cmd = (
        [*_kvikdos_base(kvikdos, out_dir, root), f"--path-dos={path_dos}", *_env_args(spec), f"--prog={compiler_dos}", compiler_dos, *spec.compile_flags, "/c", "/Foc:\\DBG.OBJ", "c:\\DBG.C"]
    )
    compile_proc = _run(compile_cmd, timeout=90)

    link_base = _kvikdos_base(kvikdos, out_dir, root)
    if spec.link_root_rel is not None:
        link_base.insert(3, f"--mount=f:{link_root}/")
    library = f"e:\\{spec.lib_dir}\\{spec.library}" if spec.lib_dir else f"e:\\{spec.library}"
    link_cmd = (
        link_base
        + _env_args(spec)
        + [
            f"--prog={linker_dos}",
            linker_dos,
            *spec.link_flags,
            f"c:\\DBG.OBJ,c:\\DBG.EXE,c:\\DBG.MAP,{library};",
        ]
    )
    link_proc = _run(link_cmd, timeout=90)
    built = (out_dir / "DBG.EXE").exists() and compile_proc.returncode == 0 and link_proc.returncode == 0
    return built, compile_proc.stdout + compile_proc.stderr, link_proc.stdout + link_proc.stderr


def _win_path(path: Path) -> str:
    return "Z:\\" + str(path.absolute()).lstrip("/").replace("/", "\\")


def _is_pe_executable(path: Path) -> bool:
    data = path.read_bytes()[:0x100]
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    pe_offset = int.from_bytes(data[0x3C:0x40], "little")
    with path.open("rb") as fp:
        fp.seek(pe_offset)
        return fp.read(4) == b"PE\x00\x00"


def _build_ms_wine(
    spec: CompilerSpec,
    out_dir: Path,
    *,
    kvikdos: Path,
    compilers_root: Path,
) -> tuple[bool, str, str]:
    """Build through a short staging path required by the legacy Win32 compiler."""

    with tempfile.TemporaryDirectory(prefix=f"inertia-{spec.name}-") as stage_name:
        stage_dir = Path(stage_name)
        shutil.copy2(out_dir / "DBG.C", stage_dir / "DBG.C")
        result = _build_ms_wine_in_stage(
            spec,
            stage_dir,
            kvikdos=kvikdos,
            compilers_root=compilers_root,
        )
        for artifact_name in ("DBG.OBJ", "DBG.EXE", "DBG.MAP"):
            artifact = stage_dir / artifact_name
            if artifact.exists():
                shutil.copy2(artifact, out_dir / artifact_name)
        return result


def _build_ms_wine_in_stage(
    spec: CompilerSpec,
    out_dir: Path,
    *,
    kvikdos: Path,
    compilers_root: Path,
) -> tuple[bool, str, str]:
    """Run the Win32 compiler inside an already-short staging directory."""

    real_root = compilers_root / spec.root_rel
    root = out_dir / "_toolchain"
    if root.exists() or root.is_symlink():
        root.unlink()
    root.symlink_to(real_root, target_is_directory=True)
    bin_dir = root / spec.bin_dir
    library = root / spec.lib_dir / spec.library
    env = {
        "WINEDEBUG": "-all",
        "INCLUDE": _win_path(root / spec.include_dir),
        "LIB": _win_path(root / spec.lib_dir),
    }
    compile_args = [
        "wine",
        f"./{spec.compiler}",
        *spec.compile_flags,
        "/c",
        f"/Fo{_win_path(out_dir / 'DBG.OBJ')}",
        _win_path(out_dir / "DBG.C"),
    ]
    compile_cmd = f"cd {shlex.quote(str(bin_dir))} && " + " ".join(shlex.quote(arg) for arg in compile_args)
    compile_proc = _run_with_env(["bash", "-lc", compile_cmd], env=env, timeout=90)
    if compile_proc.returncode != 0 or not (out_dir / "DBG.OBJ").exists():
        return False, compile_proc.stdout + compile_proc.stderr, "compile failed; link skipped\n"
    if _is_pe_executable(bin_dir / spec.linker):
        link_args = [
            "wine",
            f"./{spec.linker}",
            *spec.link_flags,
            ",".join(
                (
                    _win_path(out_dir / "DBG.OBJ"),
                    _win_path(out_dir / "DBG.EXE"),
                    _win_path(out_dir / "DBG.MAP"),
                    _win_path(library),
                )
            )
            + ";",
        ]
        link_cmd = f"cd {shlex.quote(str(bin_dir))} && " + " ".join(shlex.quote(arg) for arg in link_args)
        link_proc = _run_with_env(["bash", "-lc", link_cmd], env=env, timeout=90)
    else:
        linker_dos = "e:\\" + _dos_join(spec.bin_dir, spec.linker)
        library_dos = "e:\\" + _dos_join(spec.lib_dir, spec.library)
        link_command = (
            [*_kvikdos_base(kvikdos, out_dir, real_root), f"--prog={linker_dos}", linker_dos, *spec.link_flags, f"c:\\DBG.OBJ,c:\\DBG.EXE,c:\\DBG.MAP,{library_dos};"]
        )
        link_proc = _run(link_command, timeout=90)
    built = (out_dir / "DBG.EXE").exists() and compile_proc.returncode == 0 and link_proc.returncode == 0
    return built, compile_proc.stdout + compile_proc.stderr, link_proc.stdout + link_proc.stderr


def _build_ms_dosbox_hx(
    spec: CompilerSpec,
    out_dir: Path,
    *,
    dosbox: Path,
    compilers_root: Path,
) -> tuple[bool, str, str]:
    real_root = compilers_root / spec.root_rel
    root = out_dir / "_toolchain"
    if root.exists() or root.is_symlink():
        root.unlink()
    root.symlink_to(real_root, target_is_directory=True)
    compiler_dos = "e:\\" + _dos_join(spec.bin_dir, spec.compiler)
    linker_dos = "e:\\" + _dos_join(spec.bin_dir, spec.linker)
    hdpmi_dos = "e:\\" + _dos_join(spec.bin_dir, "HDPMI32.EXE")
    hxldr_dos = "e:\\" + _dos_join(spec.bin_dir, "HXLDR32.EXE")
    library_dos = "e:\\" + _dos_join(spec.lib_dir, spec.library)

    compile_cmd = [*_dosbox_mount_cmd(dosbox, out_dir, root), "-c", "set GOTNT=-NOPAGE", "-c", f"{hdpmi_dos} -r > c:\\hdpmi.log", "-c", f"{hxldr_dos} > c:\\hxldr.log", "-c", f"{compiler_dos} {' '.join(spec.compile_flags)} /c /Foc:\\DBG.OBJ c:\\DBG.C > c:\\compile.log"]
    if "dosbox-staging" in str(dosbox):
        compile_cmd.append("--exit")
    else:
        compile_cmd.extend(["-c", "exit"])
    compile_proc = _run_dosbox(compile_cmd, timeout=90)
    compile_log = (
        compile_proc.stdout
        + compile_proc.stderr
        + _read_dosbox_log(out_dir / "hdpmi.log")
        + _read_dosbox_log(out_dir / "hxldr.log")
        + _read_dosbox_log(out_dir / "compile.log")
    )
    if not (out_dir / "DBG.OBJ").exists():
        return False, compile_log, "compile failed; link skipped\n"

    link_cmd = [*_dosbox_mount_cmd(dosbox, out_dir, root), "-c", f"{linker_dos} {' '.join(spec.link_flags)} c:\\DBG.OBJ,c:\\DBG.EXE,c:\\DBG.MAP,{library_dos}; > c:\\link.log"]
    if "dosbox-staging" in str(dosbox):
        link_cmd.append("--exit")
    else:
        link_cmd.extend(["-c", "exit"])
    link_proc = _run_dosbox(link_cmd, timeout=90)
    link_log = link_proc.stdout + link_proc.stderr + _read_dosbox_log(out_dir / "link.log")
    built = (out_dir / "DBG.EXE").exists() and compile_proc.returncode == 0 and link_proc.returncode == 0
    return built, compile_log, link_log


def _build_borland(spec: CompilerSpec, out_dir: Path, *, kvikdos: Path, compilers_root: Path) -> tuple[bool, str, str]:
    root = compilers_root / spec.root_rel
    compiler_dos = "e:\\" + _dos_join(spec.bin_dir, spec.compiler)
    linker_dos = "e:\\" + _dos_join(spec.bin_dir, spec.linker)
    path_dos = "e:\\" + spec.bin_dir if spec.bin_dir else "e:\\"
    lib_prefix = "e:\\" + spec.lib_dir + "\\" if spec.lib_dir else "e:\\"

    compile_cmd = (
        [*_kvikdos_base(kvikdos, out_dir, root), f"--path-dos={path_dos}", *_env_args(spec), f"--prog={compiler_dos}", compiler_dos, *spec.compile_flags, "-c", "-oc:\\DBG.OBJ", "c:\\DBG.C"]
    )
    compile_proc = _run(compile_cmd, timeout=90)
    link_cmd = (
        _kvikdos_base(kvikdos, out_dir, root)
        + _env_args(spec)
        + [
            f"--prog={linker_dos}",
            linker_dos,
            *spec.link_flags,
            f"{lib_prefix}C0S+c:\\DBG.OBJ,c:\\DBG.EXE,c:\\DBG.MAP,{lib_prefix}CS;",
        ]
    )
    link_proc = _run(link_cmd, timeout=90)
    built = (out_dir / "DBG.EXE").exists() and compile_proc.returncode == 0 and link_proc.returncode == 0
    return built, compile_proc.stdout + compile_proc.stderr, link_proc.stdout + link_proc.stderr


def _read_dosbox_log(path: Path) -> str:
    for candidate in (path, path.with_name(path.name.upper())):
        if candidate.exists():
            return candidate.read_text(encoding="latin1", errors="replace")
    return ""


def _dosbox_mount_cmd(dosbox: Path, out_dir: Path, root: Path) -> list[str]:
    cmd = [str(dosbox)]
    if "dosbox-staging" in str(dosbox):
        cmd.extend(
            [
                "--noprimaryconf",
                "--nolocalconf",
                "--set",
                "output=surface",
                "--set",
                "startup_verbosity=quiet",
            ]
        )
    else:
        cmd.append("-noconsole")
    return [*cmd, "-c", f"mount c {out_dir}", "-c", f'mount e "{root}"', "-c", "c:", "-c", "set PATH=e:\\BIN", "-c", "set INCLUDE=e:\\INCLUDE", "-c", "set LIB=e:\\LIB"]


def _build_borland_dosbox(
    spec: CompilerSpec,
    out_dir: Path,
    *,
    dosbox: Path,
    compilers_root: Path,
) -> tuple[bool, str, str]:
    root = compilers_root / spec.root_rel
    compiler_dos = "e:\\" + _dos_join(spec.bin_dir, spec.compiler)
    linker_dos = "e:\\" + _dos_join(spec.bin_dir, spec.linker)
    lib_prefix = "e:\\" + spec.lib_dir + "\\" if spec.lib_dir else "e:\\"

    compile_cmd = [*_dosbox_mount_cmd(dosbox, out_dir, root), "-c", f"{compiler_dos} {' '.join(spec.compile_flags)} -c -oc:\\DBG.OBJ c:\\DBG.C > c:\\compile.log"]
    if "dosbox-staging" in str(dosbox):
        compile_cmd.append("--exit")
    else:
        compile_cmd.extend(["-c", "exit"])
    compile_proc = _run_dosbox(compile_cmd, timeout=90)
    compile_log = compile_proc.stdout + compile_proc.stderr + _read_dosbox_log(out_dir / "compile.log")
    if not (out_dir / "DBG.OBJ").exists():
        return False, compile_log, "compile failed; link skipped\n"

    link_cmd = [*_dosbox_mount_cmd(dosbox, out_dir, root), "-c", f"{linker_dos} {' '.join(spec.link_flags)} {lib_prefix}C0S+c:\\DBG.OBJ,c:\\DBG.EXE,c:\\DBG.MAP,{lib_prefix}CS; > c:\\link.log"]
    if "dosbox-staging" in str(dosbox):
        link_cmd.append("--exit")
    else:
        link_cmd.extend(["-c", "exit"])
    link_proc = _run_dosbox(link_cmd, timeout=90)
    link_log = link_proc.stdout + link_proc.stderr + _read_dosbox_log(out_dir / "link.log")
    built = (out_dir / "DBG.EXE").exists() and (out_dir / "DBG.OBJ").exists()
    return built, compile_log, link_log


def _debug_signatures(exe_path: Path) -> list[str]:
    data = exe_path.read_bytes()
    signatures: list[str] = []
    for signature in (b"NB00", b"NB02", b"NB04", b"NB05", b"NB08", b"NB09"):
        if signature in data:
            signatures.append(signature.decode("ascii"))
    if b"\xfb\x52" in data:
        signatures.append("TDINFO_MAGIC")
    return signatures


def _parse_debug_info(exe_path: Path, *, load_base_linear: int) -> dict[str, Any]:
    nb00 = parse_codeview_nb00(exe_path, load_base_linear=load_base_linear)
    nb0204 = parse_codeview_nb0204(exe_path, load_base_linear=load_base_linear)
    tdinfo = parse_tdinfo_exe(exe_path, load_base_linear=load_base_linear)

    def type_members(members: tuple[Any, ...]) -> list[dict[str, int | str]]:
        return [
            {
                "name": str(member.name),
                "offset": int(member.offset),
                "owner_type_index": int(member.owner_type_index),
            }
            for member in members
        ]

    return {
        "signatures": _debug_signatures(exe_path),
        "nb00": None
        if nb00 is None
        else {
            "code_labels": len(nb00.code_labels),
            "data_labels": len(nb00.data_labels),
            "source_files": list(nb00.source_files),
            "line_count": len(nb00.line_map),
            "type_record_names": list(nb00.type_record_names),
            "type_members": type_members(nb00.type_members),
            "debug_identifiers": list(nb00.debug_identifiers),
        },
        "nb0204": None
        if nb0204 is None
        else {
            "version": nb0204.version,
            "code_labels": len(nb0204.code_labels),
            "data_labels": len(nb0204.data_labels),
            "source_files": list(nb0204.source_files),
            "line_count": len(nb0204.line_map),
            "type_record_names": list(nb0204.type_record_names),
            "type_members": type_members(nb0204.type_members),
            "debug_identifiers": list(nb0204.debug_identifiers),
        },
        "tdinfo": None
        if tdinfo is None
        else {
            "source_files": list(tdinfo.source_files),
            "candidate_identifiers": list(tdinfo.candidate_identifiers),
            "type_names": list(tdinfo.type_names),
            "type_references": [
                {
                    "name": ref.name,
                    "type_index": ref.type_index,
                    "symbol_class": ref.symbol_class.name,
                }
                for ref in tdinfo.type_references
            ],
            "type_descriptors": [
                {
                    "type_index": descriptor.type_index,
                    "kind": descriptor.kind.name,
                    "name": descriptor.name,
                    "size": descriptor.size,
                    "base_type_index": descriptor.base_type_index,
                    "target_type_index": descriptor.target_type_index,
                    "return_type_index": descriptor.return_type_index,
                }
                for descriptor in tdinfo.type_descriptors
            ],
            "type_members": [
                {
                    "name": member.name,
                    "offset": member.offset,
                    "owner_type_index": member.owner_type_index,
                    "type_index": member.type_index,
                }
                for member in tdinfo.type_members
            ],
            "enum_members": [
                {
                    "name": member.name,
                    "owner_type_index": member.owner_type_index,
                    "value": member.value,
                }
                for member in tdinfo.enum_members
            ],
            "symbols": len(tdinfo.symbols),
            "raw_table_spans": [span.__dict__ for span in tdinfo.raw_table_spans],
        },
    }


def build_one(
    spec: CompilerSpec,
    output_root: Path,
    *,
    kvikdos: Path,
    dosbox: Path,
    compilers_root: Path,
    allow_visible_dosbox: bool = False,
    load_base_linear: int = 0x10000,
) -> dict[str, Any]:
    out_dir = output_root / spec.name
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    (out_dir / "DBG.C").write_text(PROBE_SOURCE, encoding="ascii")

    if spec.family == "ms" and spec.runner == "wine":
        built, compile_log, link_log = _build_ms_wine(
            spec,
            out_dir,
            kvikdos=kvikdos,
            compilers_root=compilers_root,
        )
    elif spec.family == "ms" and spec.runner == "dosbox_hx":
        built, compile_log, link_log = _build_ms_dosbox_hx(
            spec,
            out_dir,
            dosbox=dosbox,
            compilers_root=compilers_root,
        )
    elif spec.family == "ms":
        built, compile_log, link_log = _build_ms(spec, out_dir, kvikdos=kvikdos, compilers_root=compilers_root)
    elif spec.family == "borland" and spec.runner == "dosbox":
        if "dosbox-staging" in str(dosbox) and not allow_visible_dosbox:
            built, compile_log, link_log = (
                False,
                "skipped: dosbox-staging opens a visible GUI here; pass --allow-visible-dosbox to run it\n",
                "link skipped\n",
            )
        else:
            built, compile_log, link_log = _build_borland_dosbox(
                spec,
                out_dir,
                dosbox=dosbox,
                compilers_root=compilers_root,
            )
    elif spec.family == "borland":
        built, compile_log, link_log = _build_borland(spec, out_dir, kvikdos=kvikdos, compilers_root=compilers_root)
    else:
        raise ValueError(f"unknown compiler family: {spec.family}")

    result: dict[str, Any] = {
        "name": spec.name,
        "family": spec.family,
        "root": str(compilers_root / spec.root_rel),
        "built": built,
        "compile_log_tail": compile_log[-1200:],
        "link_log_tail": link_log[-1200:],
    }
    exe_path = out_dir / "DBG.EXE"
    if exe_path.exists():
        result["exe"] = str(exe_path)
        result["debug"] = _parse_debug_info(exe_path, load_base_linear=load_base_linear)
    return result


def selected_specs(names: str | None) -> tuple[CompilerSpec, ...]:
    if not names:
        return COMPILERS
    wanted = {name.strip() for name in names.split(",") if name.strip()}
    return tuple(spec for spec in COMPILERS if spec.name in wanted)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build and parse a DOS compiler debug-info corpus.")
    parser.add_argument("--kvikdos", type=Path, default=DEFAULT_KVIKDOS)
    parser.add_argument("--dosbox", type=Path, default=DEFAULT_DOSBOX)
    parser.add_argument(
        "--allow-visible-dosbox",
        action="store_true",
        help="allow dosbox-staging/X11 runs that may open visible GUI windows",
    )
    parser.add_argument("--compilers-root", type=Path, default=DEFAULT_COMPILERS)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--only", help="comma-separated compiler spec names")
    parser.add_argument("--load-base-linear", type=lambda value: int(value, 0), default=0x10000)
    args = parser.parse_args(argv)

    args.output_root.mkdir(parents=True, exist_ok=True)
    results = [
        build_one(
            spec,
            args.output_root,
            kvikdos=args.kvikdos,
            dosbox=args.dosbox,
            allow_visible_dosbox=args.allow_visible_dosbox,
            compilers_root=args.compilers_root,
            load_base_linear=args.load_base_linear,
        )
        for spec in selected_specs(args.only)
    ]
    payload = {
        "probe_source": "DBG.C",
        "load_base_linear": f"0x{args.load_base_linear:x}",
        "results": results,
    }
    report_path = args.output_root / "debug_info_corpus.json"
    report_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(f"wrote {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
