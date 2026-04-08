from __future__ import annotations

import io
import os
import re
import sys
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import angr
from angr_platforms.X86_16.arch_86_16 import Arch86_16


_IDA_BASE_ADDRESS_RE = re.compile(r"Base Address:\s*([0-9A-Fa-f]+)h", re.IGNORECASE)


def _debug_print(message: str) -> None:
    if "PYTEST_CURRENT_TEST" in os.environ:
        print(message)
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


def _probe_ida_base_linear(binary: Path, fallback_linear: int) -> int:
    try:
        with binary.with_suffix(".lst").open("r", encoding="utf-8", errors="ignore") as fp:
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
    try:
        header = path.read_bytes()[:0x40]
    except OSError:
        return None
    if len(header) < 0x20 or header[:2] != b"MZ":
        return None
    signature = header[0x1C:0x20]
    if signature == b"LZ90":
        return "LZEXE 0.90"
    if signature == b"LZ91":
        return "LZEXE 0.91"
    if signature[:2] == b"PK":
        return "PKLITE"
    return None


def _is_blob_only_input(path: Path) -> bool:
    return path.suffix.lower() in {".bin", ".raw", ".cod"}


@dataclass(frozen=True)
class _UnpackedLZEXEImage:
    kind: str
    code: bytes
    entry_point: int


class _LZEXEBitStream:
    def __init__(self, data: bytes, offset: int):
        self._data = data
        self._pos = offset
        self._count = 0
        self._buffer = 0
        self._load_word()

    def _load_word(self) -> None:
        self._count = 0x10
        self._buffer = self._data[self._pos] | (self._data[self._pos + 1] << 8)
        self._pos += 2

    def bit(self) -> int:
        value = self._buffer & 1
        self._buffer >>= 1
        self._count -= 1
        if self._count == 0:
            self._load_word()
        return value

    def byte(self) -> int:
        value = self._data[self._pos]
        self._pos += 1
        return value


def _unpack_lzexe_image(data: bytes, *, base_addr: int) -> _UnpackedLZEXEImage:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("Not a DOS MZ executable.")
    signature = data[0x1C:0x20]
    if signature != b"LZ91":
        raise ValueError(f"Unsupported packed executable format: {signature!r}")

    header_paragraphs = int.from_bytes(data[0x08:0x0A], "little")
    initial_cs = int.from_bytes(data[0x16:0x18], "little")
    initial_ip = int.from_bytes(data[0x14:0x16], "little")
    lz_header_offset = (header_paragraphs + initial_cs) << 4
    lz_entry = lz_header_offset + initial_ip
    if data[lz_entry : lz_entry + 4] != b"\x06\x0e\x1f\x8b":
        raise ValueError("Packed executable entry does not match LZEXE 0.91 stub.")

    unpacked_ip = int.from_bytes(data[lz_header_offset : lz_header_offset + 2], "little")
    unpacked_cs = int.from_bytes(data[lz_header_offset + 2 : lz_header_offset + 4], "little")
    packed_paragraphs = int.from_bytes(data[lz_header_offset + 8 : lz_header_offset + 10], "little")
    unpacked_paragraphs = int.from_bytes(data[lz_header_offset + 10 : lz_header_offset + 12], "little")
    packed_stream_offset = lz_header_offset - (packed_paragraphs << 4)
    output = bytearray((unpacked_paragraphs * 2) << 4)

    stream = _LZEXEBitStream(data, packed_stream_offset)
    out_pos = 0
    while True:
        if stream.bit():
            output[out_pos] = stream.byte()
            out_pos += 1
            continue

        if stream.bit() == 0:
            length = (stream.bit() << 1) | stream.bit()
            length += 2
            span = stream.byte() | ~0xFF
        else:
            span = stream.byte()
            length = stream.byte()
            span |= ((length & ~0x07) << 5) | ~0x1FFF
            length = (length & 0x07) + 2
            if length == 2:
                length = stream.byte()
                if length == 0:
                    break
                if length == 1:
                    continue
                length += 1

        for _ in range(length):
            output[out_pos] = output[out_pos + span]
            out_pos += 1

    relocation_offset = lz_header_offset + 0x158
    rel_off = 0
    load_segment = base_addr >> 4
    while True:
        span = data[relocation_offset]
        relocation_offset += 1
        if span == 0:
            span = int.from_bytes(data[relocation_offset : relocation_offset + 2], "little")
            relocation_offset += 2
            if span == 0:
                rel_off += 0x0FFF0
                continue
            if span == 1:
                break
        rel_off += span
        patched = (int.from_bytes(output[rel_off : rel_off + 2], "little") + load_segment) & 0xFFFF
        output[rel_off : rel_off + 2] = patched.to_bytes(2, "little")

    return _UnpackedLZEXEImage(
        kind="LZEXE 0.91",
        code=bytes(output[:out_pos]),
        entry_point=base_addr + (unpacked_cs << 4) + unpacked_ip,
    )


def _build_project(path: Path, *, force_blob: bool, base_addr: int, entry_point: int) -> angr.Project:
    suffix = path.suffix.lower()

    _debug_print(f"[dbg] build_project: path={path} suffix={suffix} force_blob={force_blob}")
    if force_blob or _is_blob_only_input(path):
        return angr.Project(
            path,
            auto_load_libs=False,
            main_opts={
                "backend": "blob",
                "arch": Arch86_16(),
                "base_addr": base_addr,
                "entry_point": entry_point,
            },
        )

    if suffix == ".com":
        return angr.Project(
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

    packed_exe = _detect_packed_mz_executable(path)
    if packed_exe and suffix == ".exe":
        unpacked = _unpack_lzexe_image(path.read_bytes(), base_addr=base_addr)
        project = angr.Project(
            io.BytesIO(unpacked.code),
            auto_load_libs=False,
            main_opts={
                "backend": "blob",
                "arch": Arch86_16(),
                "base_addr": base_addr,
                "entry_point": unpacked.entry_point,
            },
            simos="DOS",
        )
        project._inertia_packed_exe = packed_exe
        _debug_print(
            f"[dbg] unpacked {packed_exe}: entry={hex(unpacked.entry_point)} size={len(unpacked.code)}"
        )
        return project

    if suffix == ".exe":
        explicit_base = _probe_ida_base_linear(path, base_addr << 4 if base_addr < 0x10000 else base_addr)
        exe_backend = "dos_ne" if _looks_like_ne_executable(path) else "dos_mz"
        try:
            proj = angr.Project(
                path,
                auto_load_libs=False,
                main_opts={
                    "backend": exe_backend,
                    "base_addr": explicit_base,
                },
                simos="DOS",
            )
            _debug_print(f"[dbg] {exe_backend} load base={hex(explicit_base)}")
            _debug_print(f"[dbg] project built: arch={proj.arch.name} entry={hex(proj.entry)}")
            return proj
        except Exception as ex:
            _debug_print(f"[dbg] explicit {exe_backend} load failed at {hex(explicit_base)}: {_describe_exception(ex)}")

    try:
        proj = angr.Project(path, auto_load_libs=False)
    except Exception as ex:
        if suffix == ".exe" and "Position-DEPENDENT object" in str(ex):
            explicit_base = _probe_ida_base_linear(path, base_addr << 4 if base_addr < 0x10000 else base_addr)
            _debug_print(f"[dbg] retrying DOS MZ load with explicit base_addr={hex(explicit_base)} after {type(ex).__name__}")
            proj = angr.Project(
                path,
                auto_load_libs=False,
                main_opts={
                    "backend": "dos_mz",
                    "base_addr": explicit_base,
                },
            )
        else:
            raise
    _debug_print(f"[dbg] project built: arch={proj.arch.name} entry={hex(proj.entry)}")
    return proj


@lru_cache(maxsize=16)
def _build_project_cached(
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


def _build_project_from_bytes(code: bytes, *, base_addr: int, entry_point: int) -> angr.Project:
    arch = Arch86_16()
    arch.bits = max(arch.bits, 32)
    return angr.Project(
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
