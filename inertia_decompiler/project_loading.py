"""Load angr projects and binary bytes for CLI orchestration.

Layer: CLI/fallback/reporting.
Responsibility: construct angr project objects and binary byte views without owning semantic recovery.
"""

from __future__ import annotations

import io
import os
import re
import sys
import time
from collections.abc import Callable
from functools import lru_cache
from pathlib import Path
from typing import Any, Protocol, cast

import angr
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.compiler_helpers import hook_x86_16_known_compiler_helpers_8616
from angr_platforms.X86_16.exepack import unpack_exepack
from angr_platforms.X86_16.mz_image import UnpackedMZImage
from angr_platforms.X86_16.packed_mz import (
    PackedMZError,
    PackerDetection,
    PackerType,
    detect_packer,
    unpack_lzexe_091,
)
from angr_platforms.X86_16.pklite import unpack_pklite

from inertia_decompiler.telemetry import trace_function

_IDA_BASE_ADDRESS_RE = re.compile(r"Base Address:\s*([0-9A-Fa-f]+)h", re.IGNORECASE)
_TRACE_FUNCTION: Any = cast(Any, trace_function)


def _debug_print(message: str) -> None:
    """Keep loader diagnostics off generated-C stdout, including subprocess tests."""
    if "PYTEST_CURRENT_TEST" in os.environ:
        print(message, file=sys.stderr)
        return
    print(f"{time.strftime('[%H:%M:%S]')} {message}", file=sys.stderr)


def _describe_exception(ex: Exception) -> str:
    detail = str(ex).strip()
    ex_type = type(ex).__name__
    if detail:
        return f"{ex_type}: {detail}"
    rep = repr(ex).strip()
    if rep and rep != f"{ex_type}()":
        return f"{ex_type}: {rep}"
    return ex_type


def _finalize_x86_16_project(project: angr.Project) -> angr.Project:
    hook_x86_16_known_compiler_helpers_8616(project)
    return project


def _find_sidecar_file(binary: Path, suffix: str) -> Path | None:
    """Find a companion sidecar path for a binary using an exact basename match when possible.

    Caching this lookup avoids repeated directory scans during multi-function runs where the same
    binary is consulted for the same sidecar types.
    """
    return _find_sidecar_file_cached(binary.as_posix(), suffix.lower())


@lru_cache(maxsize=256)
def _find_sidecar_file_cached(binary: str, suffix: str) -> Path | None:
    """Resolve one normalized string cache key to an existing sidecar path."""
    binary_path = Path(binary)
    direct = binary_path.with_suffix(suffix)
    if direct.exists():
        return direct
    direct_appended = binary_path.with_name(f"{binary_path.name}{suffix}")
    if direct_appended.exists():
        return direct_appended
    try:
        siblings = binary_path.parent.iterdir()
    except OSError:
        return None
    wanted = binary_path.name.lower() + suffix.lower()
    for sibling in siblings:
        if sibling.name.lower() == wanted:
            return sibling
    return None


def _probe_ida_base_linear(binary: Path, fallback_linear: int) -> int:
    """Return the IDA listing base for a binary, or the supplied fallback."""
    return _probe_ida_base_linear_cached(binary, fallback_linear)


@lru_cache(maxsize=256)
def _probe_ida_base_linear_cached(binary: Path, fallback_linear: int) -> int:
    """Cache the bounded IDA listing base probe for one binary path."""
    try:
        lst_path = _find_sidecar_file_cached(binary.as_posix(), ".lst")
        if lst_path is None:
            return fallback_linear
        with lst_path.open("r", encoding="utf-8", errors="ignore") as fp:
            for _ in range(64):
                line = fp.readline()
                if not line:
                    break
                match = _IDA_BASE_ADDRESS_RE.search(line)
                if match is not None:
                    return int(match.group(1), 16) << 4
    except OSError:
        return fallback_linear
    return fallback_linear


def _looks_like_ne_executable(path: Path) -> bool:
    """Return whether the executable carries an NE header signature."""
    return _looks_like_ne_executable_cached(path)


@lru_cache(maxsize=256)
def _looks_like_ne_executable_cached(path: Path) -> bool:
    """Cache the bounded NE signature probe for one executable path."""
    try:
        with path.open("rb") as fp:
            header = fp.read(0x40)
            if len(header) < 0x40 or header[:2] != b"MZ":
                return False
            new_header_offset = int.from_bytes(header[0x3C:0x40], "little")
            if new_header_offset < 0x40:
                return False
            fp.seek(new_header_offset)
            return fp.read(2) == b"NE"
    except OSError:
        return False


def _detect_packed_mz_executable(path: Path) -> str | None:
    """Return the recognized MZ packer name, when one is present."""
    detection = _detect_packed_mz_executable_cached(path)
    return None if detection is None else detection.label


@lru_cache(maxsize=256)
def _detect_packed_mz_executable_cached(path: Path) -> PackerDetection | None:
    """Cache the frontend's bounded, typed MZ packer detection."""
    return detect_packer(path)


def _is_blob_only_input(path: Path) -> bool:
    return path.suffix.lower() in {".bin", ".raw", ".cod"}


class PackedExecutableRefusedError(RuntimeError):
    """A recognized packed executable lacks a proven decoder."""

    def __init__(self, *, path: Path, packer: str, reason: str) -> None:
        """Record the input, packer label, and evidence-backed refusal reason."""
        self.path = path
        self.packer = packer
        self.reason = reason
        super().__init__(f"refused {packer}-packed executable {path}: {reason}")


class _PackedProjectMarker(Protocol):
    _inertia_packed_exe: str


def _decoded_packed_stream(path: Path, detection: PackerDetection) -> io.BytesIO:
    """Return a normal MZ stream only for a packer whose decoder is proven."""
    decoder: Callable[[bytes], UnpackedMZImage]
    if detection.packer_type is PackerType.LZEXE and detection.signature == "LZ91":
        decoder = unpack_lzexe_091
    elif detection.packer_type is PackerType.EXEPACK:
        decoder = unpack_exepack
    elif detection.packer_type is PackerType.PKLITE:
        decoder = unpack_pklite
    else:
        raise PackedExecutableRefusedError(
            path=path,
            packer=detection.label,
            reason="no evidence-backed decoder is implemented; unpack the executable first",
        )
    try:
        unpacked = decoder(path.read_bytes())
    except (OSError, PackedMZError) as ex:
        raise PackedExecutableRefusedError(path=path, packer=detection.label, reason=str(ex)) from ex
    _debug_print(
        f"[dbg] unpacked {detection.label}: entry={unpacked.entry_cs:04x}:{unpacked.entry_ip:04x} "
        f"size={len(unpacked.image)} relocations={len(unpacked.relocations)}"
    )
    return io.BytesIO(unpacked.to_mz_bytes())


def _project_source(source: Path | io.BytesIO) -> Path | io.BytesIO:
    """Rewind an in-memory executable before passing it to a third-party loader."""
    if isinstance(source, io.BytesIO):
        source.seek(0)
    return source


def _mark_packed_project(project: angr.Project, detection: PackerDetection | None) -> angr.Project:
    """Attach packer provenance without changing the normal project contract."""
    if detection is not None:
        cast(_PackedProjectMarker, project)._inertia_packed_exe = detection.label
    return project


def _build_project(path: Path, *, force_blob: bool, base_addr: int, entry_point: int) -> angr.Project:
    def _impl() -> angr.Project:
        suffix = path.suffix.lower()

        _debug_print(f"[dbg] build_project: path={path} suffix={suffix} force_blob={force_blob}")
        if force_blob or _is_blob_only_input(path):
            return _finalize_x86_16_project(
                angr.Project(
                    path,
                    auto_load_libs=False,
                    main_opts={
                        "backend": "blob",
                        "arch": Arch86_16(),
                        "base_addr": base_addr,
                        "entry_point": entry_point,
                    },
                )
            )

        if suffix == ".com":
            return _finalize_x86_16_project(
                angr.Project(
                    path,
                    auto_load_libs=False,
                    main_opts={
                        "backend": "blob",
                        "arch": Arch86_16(),
                        "base_addr": base_addr,
                        "entry_point": entry_point,
                    },
                    simos="DOS",
                )
            )

        packed_detection = _detect_packed_mz_executable_cached(path) if suffix == ".exe" else None
        project_input: Path | io.BytesIO = (
            _decoded_packed_stream(path, packed_detection) if packed_detection is not None else path
        )

        if suffix == ".exe":
            explicit_base = _probe_ida_base_linear(path, base_addr << 4 if base_addr < 0x10000 else base_addr)
            exe_backend = "dos_mz" if packed_detection is not None else (
                "dos_ne" if _looks_like_ne_executable(path) else "dos_mz"
            )
            try:
                proj = angr.Project(
                    _project_source(project_input),
                    auto_load_libs=False,
                    main_opts={
                        "backend": exe_backend,
                        "base_addr": explicit_base,
                    },
                    simos="DOS",
                )
                _debug_print(f"[dbg] {exe_backend} load base={hex(explicit_base)}")
                _debug_print(f"[dbg] project built: arch={proj.arch.name} entry={hex(proj.entry)}")
                return _finalize_x86_16_project(_mark_packed_project(proj, packed_detection))
            except Exception as ex:
                _debug_print(
                    f"[dbg] explicit {exe_backend} load failed at {hex(explicit_base)}: {_describe_exception(ex)}"
                )

        try:
            proj = angr.Project(_project_source(project_input), auto_load_libs=False)
        except Exception as ex:
            if suffix == ".exe" and "Position-DEPENDENT object" in str(ex):
                explicit_base = _probe_ida_base_linear(path, base_addr << 4 if base_addr < 0x10000 else base_addr)
                _debug_print(
                    f"[dbg] retrying DOS MZ load with explicit base_addr={hex(explicit_base)} after {type(ex).__name__}"
                )
                proj = angr.Project(
                    _project_source(project_input),
                    auto_load_libs=False,
                    main_opts={
                        "backend": "dos_mz",
                        "base_addr": explicit_base,
                    },
                )
            else:
                raise
        _debug_print(f"[dbg] project built: arch={proj.arch.name} entry={hex(proj.entry)}")
        return _finalize_x86_16_project(_mark_packed_project(proj, packed_detection))

    return _impl()


_build_project = cast(Callable[..., angr.Project], _TRACE_FUNCTION(name="project.build")(_build_project))


@lru_cache(maxsize=16)
def _build_project_cached_impl(
    path: str,
    *,
    force_blob: bool,
    base_addr: int,
    entry_point: int,
) -> angr.Project:
    return _build_project(
        Path(path),
        force_blob=force_blob,
        base_addr=base_addr,
        entry_point=entry_point,
    )

_build_project_cached = cast(
    Callable[..., angr.Project], _TRACE_FUNCTION(name="project.build_cached")(_build_project_cached_impl)
)

def _build_project_from_bytes(code: bytes, *, base_addr: int, entry_point: int) -> angr.Project:
    arch = Arch86_16()
    arch.bits = max(arch.bits, 32)
    arch.cs_mode = Arch86_16.cs_mode
    return _finalize_x86_16_project(
        angr.Project(
            io.BytesIO(code),
            auto_load_libs=False,
            main_opts={
                "backend": "blob",
                "arch": arch,
                "base_addr": base_addr,
                "entry_point": entry_point,
            },
            simos="DOS",
        )
    )


_build_project_from_bytes = cast(
    Callable[..., angr.Project], _TRACE_FUNCTION(name="project.build_from_bytes")(_build_project_from_bytes)
)
